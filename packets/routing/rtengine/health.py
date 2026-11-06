# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Health: whether the engine is keeping up, measured rather than asserted.

The engine's whole runtime model -- one asyncio loop, Cython hot paths under
the GIL, bulk work sliced by time -- rests on one claim: that the loop always
gets control back quickly enough to service its timers. A routing speaker that
misses keepalives is dropped by its peers and has to relearn the table, so
that claim has to be checked continuously in production and not only in a
benchmark.

**Loop lag is the measurement that matters.** A callback is scheduled for a
known time and the drift between when it was due and when it ran is recorded.
That drift is exactly the time the loop was unable to run anything, whatever
the cause -- a long Cython call, a blocking plugin, the GIL held elsewhere,
the machine oversubscribed -- and it needs no cooperation from the code being
measured. Lag above the threshold degrades the engine's status and is also fed
back to the registered batchers, which shrink their slices in response: the
engine trades table-load throughput for responsiveness exactly when it is
falling behind.

**Status is the worst of everything.** ``ok``, ``degraded`` or ``down``, taken
across the loop, the event bus, the forwarding sink and every plugin. A
degradation anywhere is visible at the top, because an operator polling one
endpoint should not have to know which sub-document to read to find out that a
subscriber is losing events or that the kernel is refusing routes.
"""

import collections
import os
import sys
import time

_monotonic = time.monotonic

OK = 'ok'
DEGRADED = 'degraded'
DOWN = 'down'

# Worse-than ordering, so a roll-up is a max rather than a chain of ifs.
_SEVERITY = {OK: 0, DEGRADED: 1, DOWN: 2}

#: E-8 defaults. A session that flapped in the last five minutes degrades
#: the status for those five minutes: one flap is an event worth seeing on
#: a dashboard, and it ages out by itself. Lag ten times the threshold on
#: SUSTAIN_PROBES consecutive probes is a loop too busy to keep sessions
#: alive, which is down, not degraded; so is a probe overdue by
#: DEAD_PROBES intervals, which is a loop that has stopped running at all.
FLAP_WINDOW_S = 300.0
FLAP_THRESHOLD = 1
DOWN_LAG_FACTOR = 10.0
SUSTAIN_PROBES = 3
DEAD_PROBES = 3


def worst(*statuses):
    """Return the worst of several statuses.

    :param statuses: status strings; anything unrecognised counts as
        ``degraded``, because an unknown state is not a healthy one.
    :return: one of ``ok``, ``degraded``, ``down``.
    """
    found = OK
    for status in statuses:
        if status is None:
            continue
        level = _SEVERITY.get(status, _SEVERITY[DEGRADED])
        if level > _SEVERITY[found]:
            found = status if status in _SEVERITY else DEGRADED
    return found


def rss_bytes():
    """Return this process's resident set size in bytes, or 0.

    ``ru_maxrss`` is kilobytes on Linux and bytes on macOS -- the same field,
    different units, with nothing in the API to say which. Getting it wrong
    reports a thousandfold error in a memory metric that exists to be
    compared against a per-route budget.

    :return: peak RSS in bytes, or 0 where it cannot be read.
    """
    try:
        import resource
    except ImportError:
        return 0
    try:
        raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (OSError, ValueError):
        return 0
    if sys.platform == 'darwin':
        return int(raw)
    return int(raw) * 1024


class HealthMonitor(object):
    """Measures loop lag and rolls up the engine's health document.

    :param engine: the engine to report on. Read lazily, so the monitor can
        be constructed before the engine finishes wiring itself up.
    :param interval: seconds between loop-lag probes. One second is
        frequent enough to catch a stall inside a hold time and cheap
        enough to leave running forever.
    :param lag_threshold_ms: lag above which the engine is ``degraded``. 50
        ms by default, the figure the architecture gate is measured
        against.
    :param flap_window_s: how long a peer flap keeps the status degraded.
    :param flap_threshold: flaps inside the window that degrade it.
    :param down_factor: lag, as a multiple of the threshold, that makes
        the loop ``down`` once it has lasted ``SUSTAIN_PROBES`` probes.
    :param clock: the monotonic clock, injectable for the flap window.
    """

    def __init__(self, engine=None, interval=1.0, lag_threshold_ms=50.0,
                 flap_window_s=FLAP_WINDOW_S, flap_threshold=FLAP_THRESHOLD,
                 down_factor=DOWN_LAG_FACTOR, clock=None):
        self.engine = engine
        self.interval = float(interval)
        self.lag_threshold_ms = float(lag_threshold_ms)
        self.flap_window_s = float(flap_window_s)
        self.flap_threshold = int(flap_threshold)
        self.down_factor = float(down_factor)
        self._clock = clock or _monotonic
        # Flap times inside the window, oldest first. Bounded: past a few
        # hundred the count is not telling anybody anything new.
        self._flaps = collections.deque(maxlen=1024)
        # Consecutive probes over the down line, for "sustained".
        self.severe_run = 0
        # E-4: whether probing is wanted. _probe re-armed itself whenever
        # it had a loop, so a probe already running when stop() was
        # called -- or one stop() could not cancel -- kept the monitor
        # probing a loop that was being torn down.
        self._active = False
        self.lag_ms = 0.0
        self.max_lag_ms = 0.0
        # An exponentially weighted mean, so a single scheduling hiccup on a
        # busy machine does not look like a sustained problem while a real
        # stall still shows within a few probes.
        self.mean_lag_ms = 0.0
        self.probes = 0
        self.over_threshold = 0
        self.peer_flaps = 0
        self.started_at = None
        self._loop = None
        self._handle = None
        self._due = None
        self._batchers = []
        self._components = []

    # --- lifecycle ---------------------------------------------------------

    def start(self, loop):
        """Begin probing a loop. Idempotent.

        :param loop: the engine's event loop.
        """
        self._loop = loop
        self.started_at = _monotonic()
        self._active = True
        if self._handle is None:
            self._due = _monotonic() + self.interval
            self._handle = loop.call_later(self.interval, self._probe)

    def stop(self):
        """Stop probing. Idempotent."""
        self._active = False
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None
        self._due = None
        self.severe_run = 0

    def register_batcher(self, batcher):
        """Have a batcher's budget follow the measured lag.

        :param batcher: a :class:`~packets.routing.rtengine.loop.Batcher`.
        """
        if batcher not in self._batchers:
            self._batchers.append(batcher)

    def register_component(self, name, reporter, contributes_status=False):
        """Add a subsystem's own document to the health roll-up.

        For the parts of a deployment that are outside the engine but
        inside the process -- today, the REST API's server thread. The
        engine cannot ask it directly without importing Flask, and the
        alternative to this hook was an API endpoint that added its own
        keys to the health document, which would have broken the one
        property health has to have: that ``Engine.health()`` and ``GET
        /engine/health`` are the same document.

        A reporter that raises is reported as degraded rather than being
        allowed to take the health endpoint down with it, for the same
        reason a plugin's is.

        :param name: the key to publish under.
        :param reporter: a callable returning a dict of plain types.
        :param contributes_status: whether its ``status``, if it has one,
            is folded into the overall roll-up.
        """
        self._components = [entry for entry in self._components
                            if entry[0] != name]
        self._components.append((name, reporter, bool(contributes_status)))

    def unregister_component(self, name):
        """Remove a subsystem from the roll-up.

        :param name: the key it was registered under.
        :return: True if it was there.
        """
        before = len(self._components)
        self._components = [entry for entry in self._components
                            if entry[0] != name]
        return len(self._components) != before

    def note_peer_flap(self):
        """Record that a session went down after having been up.

        Counted rather than reported directly: one flap is normal
        operation, a rising count is not, and a plugin knows which of its
        own transitions count as a flap while this module does not.

        The time is kept too (E-8): a flap inside ``flap_window_s``
        degrades the status, so a session bouncing right now is visible
        to whatever polls health rather than only to whoever reads the
        counter.
        """
        self.peer_flaps += 1
        self._flaps.append(self._clock())

    def recent_flaps(self):
        """Return how many flaps happened inside the window.

        :return: the count; older flaps are forgotten as a side effect.
        """
        cutoff = self._clock() - self.flap_window_s
        flaps = self._flaps
        while flaps and flaps[0] < cutoff:
            flaps.popleft()
        return len(flaps)

    # --- the probe ---------------------------------------------------------

    def _probe(self):
        if not self._active:
            self._handle = None
            return
        now = _monotonic()
        due = self._due
        lag_ms = 0.0
        if due is not None and now > due:
            lag_ms = (now - due) * 1000.0

        self.probes += 1
        self.lag_ms = lag_ms
        if lag_ms > self.max_lag_ms:
            self.max_lag_ms = lag_ms
        if self.probes == 1:
            self.mean_lag_ms = lag_ms
        else:
            self.mean_lag_ms = self.mean_lag_ms * 0.8 + lag_ms * 0.2
        if lag_ms > self.lag_threshold_ms:
            self.over_threshold += 1
        if lag_ms > self.lag_threshold_ms * self.down_factor:
            self.severe_run += 1
        else:
            self.severe_run = 0

        for batcher in self._batchers:
            batcher.adapt(lag_ms)

        if self._loop is not None and self._active:
            # Rescheduled from now rather than from the time this was due,
            # so a long stall does not leave a backlog of probes that all
            # fire at once and each report the same lag.
            self._due = now + self.interval
            self._handle = self._loop.call_later(self.interval, self._probe)

    # --- reporting ---------------------------------------------------------

    def stalled_ms(self):
        """Return how overdue the next probe is right now, in ms.

        Only meaningful to a caller on another thread -- the REST layer --
        since on the loop thread the probe cannot be overdue by more than
        the callback asking. Zero when not probing.
        """
        due = self._due
        if not self._active or due is None:
            return 0.0
        return max(0.0, (_monotonic() - due) * 1000.0)

    def loop_status(self):
        """Return the loop's own contribution to the status.

        ``degraded`` when the latest probe was over the threshold -- which
        a sustained lag keeps it -- and ``down`` (E-8) when the lag has
        been ``down_factor`` times the threshold for ``SUSTAIN_PROBES``
        probes in a row, or the next probe is ``DEAD_PROBES`` intervals
        overdue and the loop is not running callbacks at all. A single
        spike stays a degradation, so one slow batch cannot make an engine
        that is fine look dead.

        :return: ``ok``, ``degraded`` or ``down``.
        """
        if self.severe_run >= SUSTAIN_PROBES:
            return DOWN
        dead_after_ms = max(self.lag_threshold_ms * self.down_factor,
                            self.interval * 1000.0 * DEAD_PROBES)
        if self.stalled_ms() > dead_after_ms:
            return DOWN
        if self.lag_ms > self.lag_threshold_ms:
            return DEGRADED
        return OK

    def document(self):
        """Build the health document.

        The same document the REST layer serves and ``Engine.health()``
        returns -- one producer, so the two surfaces cannot drift, which is
        what acceptance criterion 5 asks for.

        :return: a dict of plain types.
        """
        engine = self.engine
        doc = {
            'status': OK,
            'pid': os.getpid(),
            'uptime_s': round(_monotonic() - self.started_at, 3)
            if self.started_at is not None else 0.0,
            'rss_bytes': rss_bytes(),
            'loop': {
                'status': self.loop_status(),
                'running': bool(engine is not None and engine.is_running()),
                'lag_ms': round(self.lag_ms, 3),
                'mean_lag_ms': round(self.mean_lag_ms, 3),
                'max_lag_ms': round(self.max_lag_ms, 3),
                'lag_threshold_ms': self.lag_threshold_ms,
                'probes': self.probes,
                'over_threshold': self.over_threshold,
                'stalled_ms': round(self.stalled_ms(), 3),
            },
            'batches': [b.stats() for b in self._batchers],
            'peer_flaps': self.peer_flaps,
            'recent_peer_flaps': self.recent_flaps(),
        }

        statuses = [doc['loop']['status']]
        if doc['recent_peer_flaps'] >= self.flap_threshold > 0:
            statuses.append(DEGRADED)

        if engine is None:
            doc['status'] = worst(*statuses)
            return doc

        if not engine.is_running():
            # A stopped engine is down, not degraded. Anything polling this
            # to decide whether to send traffic our way needs that to be
            # unambiguous.
            statuses.append(DOWN)

        doc['commands'] = {'queued': engine.command_depth()}

        bus = getattr(engine, 'bus', None)
        if bus is not None:
            bus_stats = bus.stats()
            doc['events'] = bus_stats
            if bus_stats.get('dropped') or bus_stats.get('callback_errors'):
                # A subscriber missing events has an incomplete view of
                # routing state, which is a real degradation even though
                # nothing inside the engine is wrong.
                statuses.append(DEGRADED)

        rib = getattr(engine, 'global_rib', None)
        if rib is not None:
            doc['rib'] = rib.stats()

        resolver = getattr(engine, 'resolver', None)
        if resolver is not None:
            doc['resolver'] = resolver.stats()

        sink = getattr(engine, 'sink', None)
        if sink is not None:
            sink_stats = sink.stats()
            doc['fib'] = sink_stats
            statuses.append(sink_stats.get('status', OK))

        plugins = {}
        for plugin in engine.plugins():
            try:
                plugin_doc = plugin.health() or {}
            except Exception as exc:
                # A plugin that cannot report its own health is itself a
                # fault; saying so is more useful than letting the
                # exception take out the whole health endpoint.
                plugin_doc = {'status': DEGRADED, 'error': repr(exc)}
            plugins[plugin.name] = plugin_doc
            statuses.append(plugin_doc.get('status', OK))
        doc['plugins'] = plugins

        for name, reporter, contributes in self._components:
            try:
                component = reporter() or {}
            except Exception as exc:
                component = {'status': DEGRADED, 'error': repr(exc)}
                contributes = True
            doc[name] = component
            if contributes:
                statuses.append(component.get('status', OK))

        doc['config'] = {'revision': engine.revision}
        doc['status'] = worst(*statuses)
        return doc

    def __repr__(self):
        return '<HealthMonitor lag=%.2fms max=%.2fms probes=%d>' % (
            self.lag_ms, self.max_lag_ms, self.probes)
