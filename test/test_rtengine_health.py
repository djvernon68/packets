#!/usr/bin/env python

"""Tests for rtengine health: roll-up, loop lag, the batcher and the bus.

The engine's runtime claim is that the loop always gets control back quickly
enough to service its timers, and that a degradation anywhere is visible at
the top of one document. Both are claims about measurement, so the suite is
built around what could make the measurement lie:

  * **``worst()`` is the whole roll-up.** One wrong comparison there and a
    down plugin reads as a healthy engine, so every pair and every ordering
    is asserted rather than sampled -- including the two cases a roll-up
    normally gets wrong, an unrecognised status (counted as degraded,
    because an unknown state is not a healthy one) and a ``None`` (ignored,
    because "this component has no opinion" is not a degradation).

  * **``rss_bytes()`` exists because of a units bug.** ``ru_maxrss`` is
    kilobytes on Linux and bytes on macOS, the same field with nothing in
    the API to say which, and getting it wrong reports a thousandfold error
    in a metric that is compared against a per-route budget. So the
    assertion is on the *magnitude* -- somewhere between a mebibyte and a
    hundred gibibytes -- which is the only thing that can catch a factor of
    1024 while remaining true on any machine.

  * **Loop lag is the one place wall-clock time is unavoidable.** It is
    handled by making the stall much larger than the threshold (an 80 ms
    block against a 10 ms threshold) and then asserting a loose bound, so
    the test cannot fail because a loaded box was slow -- being slow is what
    it is looking for. The subtle part is that ``loop_status()`` reflects
    only the *most recent* probe, so the stalled document has to be read
    with the loop stopped immediately after the stalling probe; let one more
    clean probe run and the status has legitimately recovered and the
    assertion would be measuring nothing.

  * **A never-started engine is ``down``, which outranks ``degraded``.**
    That is correct and it shapes several tests: anything that wants to
    observe a degradation has to start the engine first and do its RIB work
    through ``submit()`` so it runs on the loop thread.

  * **The bus drops rather than blocking**, so the tests assert *which*
    items survived each overflow policy and not merely how many. A
    drop-oldest queue that kept the oldest would pass a counter-only test
    and be exactly backwards for the monitor it exists to serve.

Written as plain ``unittest.TestCase`` with no pytest features and no syntax
newer than Python 3.6.8. Loops are created with ``asyncio.new_event_loop()``
and driven with ``call_later``/``run_forever`` rather than with coroutines and
``asyncio.sleep``, which keeps every case free of the ``get_event_loop``
ambiguity on 3.6 and needs no process-wide loop policy change. Every loop and
every engine is registered for cleanup on creation, because a leaked loop
thread hangs the whole suite rather than failing one test.
"""

import json
import logging
import os
import queue
import threading
import time
import unittest

from packets.routing.rtengine import Engine, ProtocolPlugin
from packets.routing.rtengine import events as EV
from packets.routing.rtengine.events import EventBus
from packets.routing.rtengine.fib.sink import FibSink, NullSink
from packets.routing.rtengine.health import DEGRADED, DOWN, OK, \
    HealthMonitor, rss_bytes, worst
from packets.routing.rtengine.loop import Batcher, new_loop
from packets.routing.rtengine.rib import table as T
from packets.routing.rtengine.rib.prefix import parse_prefix

#: Deliberately far apart. The stall has to dominate both the probe interval
#: and any scheduling noise, or the assertion below becomes a measurement of
#: the machine rather than of the engine.
PROBE_INTERVAL_S = 0.01
STALL_S = 0.08
LOW_THRESHOLD_MS = 10.0

#: Every key ``HealthMonitor.document`` documents, for an engine-attached
#: monitor. Listed explicitly rather than derived from the result, so that a
#: key silently disappearing is a failure instead of a tautology.
DOCUMENT_KEYS = ('status', 'pid', 'uptime_s', 'rss_bytes', 'loop', 'batches',
                 'peer_flaps', 'recent_peer_flaps', 'commands', 'events',
                 'rib', 'resolver', 'fib', 'plugins', 'config')

LOOP_KEYS = ('status', 'running', 'lag_ms', 'mean_lag_ms', 'max_lag_ms',
             'lag_threshold_ms', 'probes', 'over_threshold', 'stalled_ms')

#: Measured at the moment the document is built, so two adjacent calls may
#: legitimately differ in these and only in these.
VOLATILE_KEYS = ('uptime_s', 'rss_bytes')


def _route(prefix_text, metric=0, source=None):
    """A Route good enough to drive selection and therefore the bus."""
    return T.Route(parse_prefix(prefix_text), T.PROTO_BGP, 20, metric,
                   b'\x0a\x00\x00\x01', source or object(), 100.0)


def _quiet(testcase, logger_name):
    """Silence one rtengine logger for the duration of a test.

    The bus logs a full traceback when a synchronous callback raises, which
    is correct behaviour and is exactly what the test is provoking. Left
    alone it prints that traceback to stderr in the middle of an otherwise
    green run, where it reads as a failure. The assertions are on the
    ``callback_errors`` counter, so the log carries nothing the test needs.
    """
    logger = logging.getLogger(logger_name)
    previous = logger.level
    logger.setLevel(logging.CRITICAL)
    testcase.addCleanup(logger.setLevel, previous)


class DegradedSink(FibSink):
    """A sink that reports itself unwell but writes nothing.

    ``writes`` stays False so it does not also trip the
    ``ip.route.install`` semantic check; the only thing under test is that
    a sink's own status reaches the top of the document.
    """

    name = 'degraded-test-sink'
    writes = False

    def stats(self):
        return {'name': self.name, 'writes': False, 'status': DEGRADED}


class ReportingPlugin(ProtocolPlugin):
    """A plugin whose ``health()`` says whatever a test needs it to say."""

    def __init__(self, name='reporter', document=None, raises=False):
        ProtocolPlugin.__init__(self)
        self.name = name
        self.document = document
        self.raises = raises

    def health(self):
        if self.raises:
            raise RuntimeError('cannot determine health')
        return self.document


class HealthFixture(unittest.TestCase):
    """Cleanup for the objects in this module that own OS resources."""

    def make_loop(self):
        loop = new_loop()
        self.addCleanup(self._close_loop, loop)
        return loop

    @staticmethod
    def _close_loop(loop):
        if not loop.is_closed():
            loop.close()

    def make_monitor(self, **kwargs):
        """A monitor whose probe is always cancelled afterwards.

        A monitor left probing keeps rescheduling itself onto a loop the
        test is about to close, which turns into a noisy warning at best.
        """
        monitor = HealthMonitor(**kwargs)
        self.addCleanup(monitor.stop)
        return monitor

    def make_engine(self, **kwargs):
        engine = Engine(**kwargs)
        self.addCleanup(engine.stop)
        return engine

    def start_engine(self, **kwargs):
        return self.make_engine(**kwargs).start()

    def run_loop_for(self, loop, seconds):
        """Run a loop for a bounded time and stop it.

        The upper bound is what makes an unexpected hang a failing test
        instead of a hung suite.
        """
        loop.call_later(seconds, loop.stop)
        loop.run_forever()


class WorstTestCase(unittest.TestCase):
    """The roll-up's ordering, in full."""

    def test_no_statuses_at_all_is_ok(self):
        # Nothing to complain about is not a reason to complain.
        self.assertEqual(worst(), OK)

    def test_each_status_alone_is_itself(self):
        self.assertEqual(worst(OK), OK)
        self.assertEqual(worst(DEGRADED), DEGRADED)
        self.assertEqual(worst(DOWN), DOWN)

    def test_every_pair_takes_the_worse(self):
        self.assertEqual(worst(OK, OK), OK)
        self.assertEqual(worst(OK, DEGRADED), DEGRADED)
        self.assertEqual(worst(OK, DOWN), DOWN)
        self.assertEqual(worst(DEGRADED, DEGRADED), DEGRADED)
        self.assertEqual(worst(DEGRADED, DOWN), DOWN)
        self.assertEqual(worst(DOWN, DOWN), DOWN)

    def test_the_result_does_not_depend_on_the_order(self):
        # The roll-up is built by appending to a list in whatever order the
        # sub-documents happen to be produced, so it has to commute.
        self.assertEqual(worst(DEGRADED, OK), DEGRADED)
        self.assertEqual(worst(DOWN, OK), DOWN)
        self.assertEqual(worst(DOWN, DEGRADED), DOWN)
        self.assertEqual(worst(DOWN, OK, DEGRADED), DOWN)
        self.assertEqual(worst(OK, DEGRADED, DOWN), DOWN)
        self.assertEqual(worst(DEGRADED, DOWN, OK), DOWN)

    def test_down_outranks_degraded_however_many_there_are(self):
        self.assertEqual(worst(*([DEGRADED] * 10 + [DOWN])), DOWN)
        self.assertEqual(worst(*([DOWN] + [DEGRADED] * 10)), DOWN)

    def test_an_unknown_status_counts_as_degraded(self):
        # An unrecognised state is not a healthy one, and it must not be
        # returned verbatim either: the caller's contract is three values.
        self.assertEqual(worst('bogus'), DEGRADED)
        self.assertEqual(worst(OK, 'bogus'), DEGRADED)
        self.assertEqual(worst('', OK), DEGRADED)
        self.assertEqual(worst(0), DEGRADED)
        self.assertEqual(worst('OK'), DEGRADED)

    def test_an_unknown_status_does_not_outrank_down(self):
        self.assertEqual(worst('bogus', DOWN), DOWN)
        self.assertEqual(worst(DOWN, 'bogus'), DOWN)

    def test_none_is_ignored_rather_than_treated_as_unknown(self):
        # "This component has no opinion" is not a degradation; a plugin
        # that does not implement health() must not drag the engine down.
        self.assertEqual(worst(None), OK)
        self.assertEqual(worst(None, None), OK)
        self.assertEqual(worst(None, OK), OK)
        self.assertEqual(worst(OK, None, OK), OK)
        self.assertEqual(worst(None, DEGRADED), DEGRADED)
        self.assertEqual(worst(None, DOWN), DOWN)


class RssBytesTestCase(unittest.TestCase):
    """The units, not the value."""

    def test_it_returns_a_non_negative_int(self):
        value = rss_bytes()
        self.assertIsInstance(value, int)
        self.assertNotIsInstance(value, bool)
        self.assertGreaterEqual(value, 0)

    def test_it_is_plausible_for_a_python_process(self):
        # This is the whole point of the function. ru_maxrss is kilobytes on
        # Linux and bytes on macOS, so a platform branch that is wrong by a
        # factor of 1024 still produces a positive int and still passes any
        # assertion that only checks the sign. A CPython process with the
        # compiled RIB extensions loaded cannot be under a mebibyte, and if
        # it is over a hundred gibibytes the units are wrong rather than the
        # machine being remarkable.
        value = rss_bytes()
        if value == 0:
            self.skipTest('resource.getrusage is unavailable here')
        self.assertGreater(value, 1024 * 1024)
        self.assertLess(value, 100 * 1024 * 1024 * 1024)

    def test_repeated_calls_do_not_go_backwards(self):
        # ru_maxrss is a peak, so it is monotonic; a call that recomputed
        # from a different field would not be.
        first = rss_bytes()
        second = rss_bytes()
        self.assertGreaterEqual(second, first)


class DocumentShapeTestCase(HealthFixture):
    """One producer, so the two surfaces cannot drift."""

    def test_engine_health_and_monitor_document_agree(self):
        # Acceptance criterion 5: ``/engine/health`` and ``Engine.health()``
        # are the same document because they are the same producer. Only the
        # two fields measured at the moment of the call are excluded, and
        # they are asserted to be present rather than simply skipped.
        engine = self.start_engine()
        first = engine.health()
        second = engine.health_monitor.document()
        self.assertEqual(sorted(first), sorted(second))
        for key in VOLATILE_KEYS:
            self.assertIn(key, first)
            self.assertIn(key, second)
            first.pop(key)
            second.pop(key)
        self.assertEqual(first, second)

    def test_a_stopped_engines_document_also_agrees(self):
        engine = self.make_engine()
        first = engine.health()
        second = engine.health_monitor.document()
        for key in VOLATILE_KEYS:
            first.pop(key)
            second.pop(key)
        self.assertEqual(first, second)

    def test_every_documented_key_is_present(self):
        engine = self.start_engine()
        document = engine.health()
        for key in DOCUMENT_KEYS:
            self.assertIn(key, document)
        self.assertEqual(sorted(document), sorted(DOCUMENT_KEYS))

    def test_every_documented_loop_key_is_present(self):
        loop_doc = self.start_engine().health()['loop']
        self.assertEqual(sorted(loop_doc), sorted(LOOP_KEYS))

    def test_the_document_is_json_serialisable(self):
        # It is served verbatim over REST, so anything in it that json
        # cannot render -- a Prefix, a bytes next-hop, a set of tasks -- is
        # a broken endpoint rather than a cosmetic problem.
        plugin = ReportingPlugin(document={'status': OK, 'peers': 3})
        engine = self.start_engine(plugins=[plugin])
        engine.configure(('ip', 'route', 'table'), 300)
        engine.submit(engine.global_rib.offer,
                      _route('192.0.2.0/24')).result(5)
        engine.submit(engine.select).result(5)
        text = json.dumps(engine.health())
        self.assertEqual(json.loads(text)['status'], OK)

    def test_the_document_is_json_serialisable_when_a_plugin_raises(self):
        # The error value is a repr(), which is a str; it would be easy for
        # it to be the exception object instead and break serialisation
        # only on the unhappy path.
        engine = self.start_engine(plugins=[ReportingPlugin(raises=True)])
        json.dumps(engine.health())

    def test_a_monitor_with_no_engine_still_produces_a_document(self):
        # The monitor is constructed before the engine has finished wiring
        # itself up, and the API blueprints may ask it for a document at
        # any point, so "no engine yet" must not be an exception.
        document = self.make_monitor().document()
        self.assertEqual(document['status'], OK)
        self.assertEqual(document['loop']['running'], False)
        self.assertEqual(document['uptime_s'], 0.0)
        self.assertEqual(document['batches'], [])
        self.assertEqual(document['peer_flaps'], 0)
        json.dumps(document)
        # The engine-specific sections are absent rather than empty: there
        # is nothing to report on, and an empty dict would read as "no
        # plugins" rather than as "no engine".
        for key in ('commands', 'events', 'rib', 'resolver', 'fib',
                    'plugins', 'config'):
            self.assertNotIn(key, document)

    def test_uptime_starts_at_zero_and_is_reported_in_seconds(self):
        monitor = self.make_monitor()
        self.assertEqual(monitor.document()['uptime_s'], 0.0)
        monitor.start(self.make_loop())
        self.assertGreaterEqual(monitor.document()['uptime_s'], 0.0)
        self.assertLess(monitor.document()['uptime_s'], 5.0)

    def test_the_document_reports_the_engines_own_counters(self):
        engine = self.start_engine()
        engine.configure(('ip', 'route', 'table'), 300)
        document = engine.health()
        self.assertEqual(document['config'], {'revision': 1})
        self.assertEqual(document['commands'], {'queued': 0})
        self.assertTrue(document['loop']['running'])
        self.assertEqual(document['pid'], os.getpid())
        self.assertEqual(document['fib']['name'], 'null')
        self.assertEqual(document['rib']['pending'], 0)
        self.assertFalse(document['resolver']['enabled'])

    def test_a_recent_peer_flap_degrades_the_status_until_it_ages_out(self):
        # E-8: flaps used to be counted and never interpreted, so health
        # said ok through a session bouncing every few seconds. A flap now
        # degrades the status for the window, and only for the window: the
        # lifetime counter keeps counting, the status recovers by itself.
        now = [5000.0]
        monitor = self.make_monitor(clock=lambda: now[0],
                                    flap_window_s=300.0)
        self.assertEqual(monitor.document()['peer_flaps'], 0)
        self.assertEqual(monitor.document()['status'], OK)
        monitor.note_peer_flap()
        monitor.note_peer_flap()
        document = monitor.document()
        self.assertEqual(document['peer_flaps'], 2)
        self.assertEqual(document['recent_peer_flaps'], 2)
        self.assertEqual(document['status'], DEGRADED)
        now[0] += 301.0
        document = monitor.document()
        self.assertEqual(document['peer_flaps'], 2)
        self.assertEqual(document['recent_peer_flaps'], 0)
        self.assertEqual(document['status'], OK)

    def test_repr_reports_the_measurements(self):
        self.assertIn('probes=0', repr(self.make_monitor()))


class StatusRollupTestCase(HealthFixture):
    """A degradation anywhere has to be visible at the top."""

    def test_a_clean_running_engine_is_ok(self):
        self.assertEqual(self.start_engine().health()['status'], OK)

    def test_an_engine_that_never_started_is_down(self):
        # Down, not degraded: anything polling this to decide whether to
        # send traffic our way needs that unambiguous.
        engine = self.make_engine()
        self.assertEqual(engine.health()['status'], DOWN)
        self.assertFalse(engine.health()['loop']['running'])

    def test_a_stopped_engine_is_down(self):
        engine = self.start_engine()
        self.assertEqual(engine.health()['status'], OK)
        engine.stop()
        self.assertEqual(engine.health()['status'], DOWN)

    def test_dropped_events_degrade_a_running_engine(self):
        # A subscriber missing events has an incomplete view of routing
        # state, which is a real degradation even though nothing inside the
        # engine is wrong.
        #
        # The engine has to be started first: a never-started engine is
        # down, which outranks degraded and would hide the thing under
        # test. And the offers have to go through submit(), because the RIB
        # is the loop thread's to touch.
        engine = self.start_engine()
        subscription = engine.subscribe(EV.ROUTE_BEST, maxsize=1)
        engine.submit(self._churn, engine, 4).result(5)

        self.assertGreater(subscription.dropped, 0)
        document = engine.health()
        self.assertEqual(document['status'], DEGRADED)
        self.assertEqual(document['events']['dropped'], subscription.dropped)
        # The loop itself is fine; only the fan-out is behind.
        self.assertEqual(document['loop']['status'], OK)

    def test_a_callback_error_degrades_a_running_engine(self):
        _quiet(self, 'packets.rtengine.events')
        engine = self.start_engine()

        def rude(_event, _payload):
            raise RuntimeError('deliberate')

        engine.bus.on(EV.ROUTE_BEST, rude)
        engine.submit(self._churn, engine, 1).result(5)
        document = engine.health()
        self.assertEqual(document['events']['callback_errors'], 1)
        self.assertEqual(document['status'], DEGRADED)

    def test_a_degraded_plugin_degrades_the_engine(self):
        engine = self.start_engine(
            plugins=[ReportingPlugin(name='unwell',
                                     document={'status': DEGRADED,
                                               'detail': 'resyncing'})])
        document = engine.health()
        self.assertEqual(document['status'], DEGRADED)
        self.assertEqual(document['plugins']['unwell']['detail'],
                         'resyncing')

    def test_a_down_plugin_takes_the_engine_down(self):
        engine = self.start_engine(
            plugins=[ReportingPlugin(name='dead', document={'status': DOWN})])
        self.assertEqual(engine.health()['status'], DOWN)

    def test_the_worst_plugin_decides(self):
        engine = self.start_engine(plugins=[
            ReportingPlugin(name='fine', document={'status': OK}),
            ReportingPlugin(name='unwell', document={'status': DEGRADED}),
            ReportingPlugin(name='dead', document={'status': DOWN})])
        document = engine.health()
        self.assertEqual(document['status'], DOWN)
        self.assertEqual(sorted(document['plugins']),
                         ['dead', 'fine', 'unwell'])

    def test_a_plugin_with_no_opinion_does_not_degrade_the_engine(self):
        # The base ProtocolPlugin.health() returns nothing useful, and a
        # protocol that has not implemented it must not report the engine
        # as unhealthy just by existing.
        engine = self.start_engine(plugins=[ReportingPlugin(document=None)])
        self.assertEqual(engine.health()['status'], OK)
        self.assertEqual(engine.health()['plugins']['reporter'], {})

    def test_a_plugin_whose_health_raises_is_degraded_not_fatal(self):
        # A plugin that cannot report its own health is itself a fault;
        # saying so is more useful than letting the exception take out the
        # whole endpoint, which is the only source of this information.
        engine = self.start_engine(
            plugins=[ReportingPlugin(name='broken', raises=True)])
        document = engine.health()
        self.assertEqual(document['status'], DEGRADED)
        entry = document['plugins']['broken']
        self.assertEqual(entry['status'], DEGRADED)
        self.assertIn('error', entry)
        self.assertIn('cannot determine health', entry['error'])

    def test_one_broken_plugin_does_not_hide_the_others(self):
        engine = self.start_engine(plugins=[
            ReportingPlugin(name='broken', raises=True),
            ReportingPlugin(name='fine', document={'status': OK,
                                                   'peers': 1})])
        plugins = engine.health()['plugins']
        self.assertEqual(plugins['fine']['peers'], 1)
        self.assertEqual(plugins['broken']['status'], DEGRADED)

    def test_the_fib_sinks_status_is_folded_in(self):
        engine = self.start_engine(sink=DegradedSink())
        document = engine.health()
        self.assertEqual(document['fib']['status'], DEGRADED)
        self.assertEqual(document['status'], DEGRADED)

    def test_a_healthy_sink_does_not_degrade_the_engine(self):
        engine = self.start_engine(sink=NullSink())
        self.assertEqual(engine.health()['fib']['status'], OK)
        self.assertEqual(engine.health()['status'], OK)

    def test_a_sink_that_reports_no_status_is_treated_as_ok(self):
        class Silent(FibSink):
            name = 'silent'

            def stats(self):
                return {'name': self.name, 'writes': False}

        engine = self.start_engine(sink=Silent())
        self.assertEqual(engine.health()['status'], OK)

    def test_a_down_sink_takes_the_engine_down(self):
        class Broken(FibSink):
            name = 'broken'

            def stats(self):
                return {'name': self.name, 'writes': False, 'status': DOWN}

        self.assertEqual(self.start_engine(sink=Broken()).health()['status'],
                         DOWN)

    @staticmethod
    def _churn(engine, count):
        """Offer and select ``count`` prefixes, on the loop thread."""
        source = object()
        for i in range(count):
            engine.global_rib.offer(_route('203.0.113.%d/32' % i,
                                           source=source))
        return engine.select()


class LoopLagTestCase(HealthFixture):
    """The measurement the runtime model rests on."""

    def test_probing_a_quiet_loop_records_small_lag(self):
        # No absolute timing assertion: the counters and the presence and
        # sign of the measurements are what matter, and the bound is
        # deliberately far looser than anything a loaded box could miss.
        monitor = self.make_monitor(interval=PROBE_INTERVAL_S,
                                    lag_threshold_ms=250.0)
        loop = self.make_loop()
        monitor.start(loop)
        self.run_loop_for(loop, 0.05)

        self.assertGreaterEqual(monitor.probes, 1)
        loop_doc = monitor.document()['loop']
        self.assertEqual(loop_doc['probes'], monitor.probes)
        for key in ('lag_ms', 'mean_lag_ms', 'max_lag_ms'):
            self.assertIn(key, loop_doc)
            self.assertGreaterEqual(loop_doc[key], 0.0)
        self.assertLess(loop_doc['max_lag_ms'], 250.0)
        self.assertEqual(loop_doc['over_threshold'], 0)
        self.assertEqual(loop_doc['status'], OK)
        self.assertEqual(monitor.document()['status'], OK)

    def test_probes_keep_rising_while_the_loop_runs(self):
        monitor = self.make_monitor(interval=PROBE_INTERVAL_S,
                                    lag_threshold_ms=250.0)
        loop = self.make_loop()
        monitor.start(loop)
        self.run_loop_for(loop, 0.03)
        first = monitor.probes
        self.run_loop_for(loop, 0.03)
        self.assertGreater(monitor.probes, first)

    def test_a_deliberate_stall_is_measured_and_degrades_the_status(self):
        # A blocking sleep inside a call_soon callback is exactly the
        # failure being detected: a long Cython call, a blocking plugin, the
        # GIL held elsewhere. The probe cannot run while it is in progress,
        # and the drift when it finally does is the time the loop could not
        # run anything.
        monitor = self.make_monitor(interval=PROBE_INTERVAL_S,
                                    lag_threshold_ms=LOW_THRESHOLD_MS)
        loop = self.make_loop()
        monitor.start(loop)

        loop.call_soon(time.sleep, STALL_S)
        # Stop as soon as the stalled probe has run. loop_status() reports
        # the *most recent* probe, so letting even one clean probe follow
        # would legitimately return the status to ok and this assertion
        # would be measuring nothing. The stop is scheduled a hair after
        # the probe so that asyncio moves both expired timers into the same
        # iteration and runs them in due order.
        loop.call_later(PROBE_INTERVAL_S * 1.05, loop.stop)
        loop.run_forever()

        self.assertEqual(monitor.probes, 1)
        # The stall was 80 ms against a 10 ms interval, so the drift is
        # about 70 ms. Asserted well below that: the test is looking for a
        # stall being noticed at all, not for the machine's precision.
        stall_ms = STALL_S * 1000.0
        self.assertGreater(monitor.max_lag_ms, stall_ms / 2.0)
        self.assertGreater(monitor.lag_ms, LOW_THRESHOLD_MS)
        self.assertEqual(monitor.over_threshold, 1)
        self.assertEqual(monitor.loop_status(), DEGRADED)

        document = monitor.document()
        self.assertEqual(document['loop']['status'], DEGRADED)
        self.assertEqual(document['loop']['over_threshold'], 1)
        self.assertEqual(document['status'], DEGRADED)
        self.assertGreater(document['loop']['max_lag_ms'], stall_ms / 2.0)

    def test_the_first_probes_lag_seeds_the_mean(self):
        # The mean is exponentially weighted, so seeding it with the first
        # sample rather than with zero is what keeps a real stall visible
        # within a few probes instead of being averaged away.
        monitor = self.make_monitor(interval=PROBE_INTERVAL_S,
                                    lag_threshold_ms=LOW_THRESHOLD_MS)
        loop = self.make_loop()
        monitor.start(loop)
        loop.call_soon(time.sleep, STALL_S)
        loop.call_later(PROBE_INTERVAL_S * 1.05, loop.stop)
        loop.run_forever()
        self.assertEqual(monitor.probes, 1)
        self.assertEqual(monitor.mean_lag_ms, monitor.lag_ms)
        self.assertEqual(monitor.mean_lag_ms, monitor.max_lag_ms)

    def test_max_lag_is_a_high_water_mark(self):
        monitor = self.make_monitor(interval=PROBE_INTERVAL_S,
                                    lag_threshold_ms=LOW_THRESHOLD_MS)
        loop = self.make_loop()
        monitor.start(loop)
        loop.call_soon(time.sleep, STALL_S)
        loop.call_later(PROBE_INTERVAL_S * 1.05, loop.stop)
        loop.run_forever()
        peak = monitor.max_lag_ms

        # Quiet probes afterwards bring the current lag back down but must
        # not erase the worst one seen, which is the only record that the
        # stall happened at all.
        self.run_loop_for(loop, 0.05)
        self.assertGreater(monitor.probes, 1)
        self.assertEqual(monitor.max_lag_ms, peak)
        self.assertLess(monitor.lag_ms, peak)
        self.assertEqual(monitor.over_threshold, 1)
        self.assertEqual(monitor.loop_status(), OK)

    def test_start_is_idempotent_and_does_not_double_probe(self):
        # Two handles on one monitor would double the probe rate and, worse,
        # leave one of them uncancellable by stop().
        monitor = self.make_monitor(interval=PROBE_INTERVAL_S,
                                    lag_threshold_ms=250.0)
        loop = self.make_loop()
        monitor.start(loop)
        handle = monitor._handle
        monitor.start(loop)
        self.assertIs(monitor._handle, handle)

    def test_stop_cancels_the_probe_and_is_idempotent(self):
        monitor = self.make_monitor(interval=PROBE_INTERVAL_S,
                                    lag_threshold_ms=250.0)
        loop = self.make_loop()
        monitor.start(loop)
        self.run_loop_for(loop, 0.03)
        self.assertGreater(monitor.probes, 0)

        self.assertIsNone(monitor.stop())
        self.assertIsNone(monitor.stop())
        probes = monitor.probes
        # The probe reschedules itself, so the only proof that it is really
        # cancelled is that running the loop again produces nothing.
        self.run_loop_for(loop, 0.05)
        self.assertEqual(monitor.probes, probes)

    def test_a_monitor_that_never_probed_reports_zeroes(self):
        monitor = self.make_monitor()
        self.assertEqual(monitor.probes, 0)
        self.assertEqual(monitor.lag_ms, 0.0)
        self.assertEqual(monitor.max_lag_ms, 0.0)
        self.assertEqual(monitor.mean_lag_ms, 0.0)
        self.assertEqual(monitor.loop_status(), OK)

    def test_an_engines_probe_is_stopped_with_the_engine(self):
        engine = self.start_engine()
        engine.stop()
        self.assertIsNone(engine.health_monitor._handle)


class BatcherAdaptTestCase(unittest.TestCase):
    """The budget follows measured lag, quickly down and slowly up."""

    def test_lag_well_above_the_budget_halves_it(self):
        # Responsiveness is bought with table throughput exactly when the
        # engine is falling behind.
        batcher = Batcher(budget_ms=10.0, min_budget_ms=0.5,
                          max_budget_ms=50.0)
        self.assertEqual(batcher.adapt(21.0), 5.0)
        self.assertEqual(batcher.adapt(21.0), 2.5)

    def test_lag_well_below_the_budget_grows_it_by_a_quarter(self):
        # A quarter rather than doubling: recovering slowly and degrading
        # quickly is the right asymmetry when being wrong costs a session.
        batcher = Batcher(budget_ms=10.0, max_budget_ms=50.0)
        self.assertEqual(batcher.adapt(0.0), 12.5)
        self.assertEqual(batcher.adapt(1.0), 15.625)

    def test_lag_in_the_middle_band_leaves_the_budget_alone(self):
        # Between half the budget and twice it there is no evidence either
        # way, and a budget that moved on every probe would never settle.
        batcher = Batcher(budget_ms=10.0)
        self.assertEqual(batcher.adapt(10.0), 10.0)
        self.assertEqual(batcher.adapt(5.0), 10.0)
        self.assertEqual(batcher.adapt(20.0), 10.0)

    def test_the_budget_never_falls_below_the_floor(self):
        batcher = Batcher(budget_ms=1.0, min_budget_ms=0.5)
        self.assertEqual(batcher.adapt(1000.0), 0.5)
        self.assertEqual(batcher.adapt(1000.0), 0.5)
        self.assertEqual(batcher.adapt(1000.0), 0.5)

    def test_the_budget_never_rises_above_the_ceiling(self):
        batcher = Batcher(budget_ms=40.0, max_budget_ms=50.0)
        self.assertEqual(batcher.adapt(0.0), 50.0)
        self.assertEqual(batcher.adapt(0.0), 50.0)

    def test_the_reported_budget_follows_adaptation(self):
        batcher = Batcher(budget_ms=10.0, name='probe')
        batcher.adapt(100.0)
        self.assertEqual(batcher.stats()['budget_ms'], 5.0)
        self.assertEqual(batcher.stats()['name'], 'probe')

    def test_a_registered_batcher_is_adapted_by_the_probe(self):
        monitor = HealthMonitor(interval=PROBE_INTERVAL_S,
                                lag_threshold_ms=LOW_THRESHOLD_MS)
        self.addCleanup(monitor.stop)
        batcher = Batcher(budget_ms=10.0, min_budget_ms=0.5)
        monitor.register_batcher(batcher)

        loop = new_loop()
        self.addCleanup(loop.close)
        monitor.start(loop)
        loop.call_soon(time.sleep, STALL_S)
        loop.call_later(PROBE_INTERVAL_S * 1.05, loop.stop)
        loop.run_forever()

        self.assertEqual(monitor.probes, 1)
        # One probe, one adaptation: a ~70 ms lag against a 10 ms budget is
        # well past twice it, so the budget halved.
        self.assertEqual(batcher.budget_ms, 5.0)

    def test_register_batcher_is_idempotent(self):
        # Registering twice would adapt the same budget twice per probe,
        # quartering it instead of halving it.
        monitor = HealthMonitor()
        batcher = Batcher()
        monitor.register_batcher(batcher)
        monitor.register_batcher(batcher)
        self.assertEqual(len(monitor.document()['batches']), 1)

    def test_registered_batchers_appear_in_the_document(self):
        monitor = HealthMonitor()
        monitor.register_batcher(Batcher(name='select'))
        monitor.register_batcher(Batcher(name='flush'))
        names = [b['name'] for b in monitor.document()['batches']]
        self.assertEqual(names, ['select', 'flush'])


class BatcherTestCase(unittest.TestCase):
    """Slices, counters and the deliberate rejections."""

    def test_a_non_positive_budget_is_refused(self):
        # A zero budget would end every slice before its first step and the
        # job would never finish; a negative one is nonsense.
        for bad in (0.0, -1.0, 0):
            with self.assertRaises(ValueError) as caught:
                Batcher(budget_ms=bad)
            self.assertIn('must be positive', str(caught.exception))

    def test_a_chunk_below_one_is_refused(self):
        for bad in (0, -5):
            with self.assertRaises(ValueError) as caught:
                Batcher(chunk=bad)
            self.assertIn('at least 1', str(caught.exception))

    def test_a_fresh_batcher_has_no_statistics(self):
        stats = Batcher(budget_ms=5.0, chunk=256, name='select').stats()
        self.assertEqual(stats, {'name': 'select', 'budget_ms': 5.0,
                                 'chunk': 256, 'slices': 0, 'items': 0,
                                 'yields': 0, 'mean_slice_ms': 0.0,
                                 'max_slice_ms': 0.0, 'overruns': 0})

    def test_one_slice_that_finishes_the_job_counts_once(self):
        batcher = Batcher(budget_ms=50.0, chunk=10)
        processed, done = batcher.run_slice(self._counter([7, 0]))
        self.assertEqual((processed, done), (7, True))
        self.assertEqual(batcher.slices, 1)
        self.assertEqual(batcher.items, 7)
        self.assertEqual(batcher.yields, 0)
        self.assertGreaterEqual(batcher.max_slice_ms, 0.0)

    def test_the_step_is_asked_for_the_chunk_size(self):
        batcher = Batcher(budget_ms=50.0, chunk=64)
        asked = []

        def step(chunk):
            asked.append(chunk)
            return 0

        batcher.run_slice(step)
        self.assertEqual(asked, [64])

    def test_a_step_that_raises_is_still_accounted(self):
        # A job that fails mid-slice must still show up in the health
        # numbers rather than silently vanishing from them.
        batcher = Batcher(budget_ms=50.0, chunk=4)
        calls = []

        def step(chunk):
            calls.append(chunk)
            if len(calls) == 2:
                raise RuntimeError('deliberate')
            return chunk

        with self.assertRaises(RuntimeError):
            batcher.run_slice(step)
        self.assertEqual(batcher.slices, 1)
        # The four items the first call did report are kept; the failed call
        # contributed nothing, which is the honest number.
        self.assertEqual(batcher.items, 4)
        self.assertGreater(batcher.stats()['max_slice_ms'], -1.0)

    def test_expired_is_false_before_the_budget_and_true_after(self):
        batcher = Batcher(budget_ms=1000.0)
        batcher.begin()
        self.assertFalse(batcher.expired())
        # Re-open with a budget already spent. Using a tiny budget rather
        # than sleeping keeps the case deterministic without a wall-clock
        # assertion: the deadline is in the past by the time it is read.
        batcher.budget_ms = 0.000001
        batcher.begin()
        time.sleep(0.001)
        self.assertTrue(batcher.expired())

    def test_end_folds_a_slice_into_the_statistics(self):
        batcher = Batcher(budget_ms=50.0)
        batcher.begin()
        elapsed = batcher.end(12)
        self.assertGreaterEqual(elapsed, 0.0)
        self.assertEqual(batcher.slices, 1)
        self.assertEqual(batcher.items, 12)
        self.assertEqual(batcher.stats()['mean_slice_ms'],
                         round(batcher.total_ms, 3))

    def test_a_slice_that_runs_well_past_its_budget_is_an_overrun(self):
        # One step call costing more than the whole slice was allowed is
        # invisible in an average, so it is counted separately: it is the
        # signal to lower the chunk size.
        batcher = Batcher(budget_ms=1.0, chunk=1)
        batcher.run_slice(self._slow_step(0.01))
        self.assertEqual(batcher.overruns, 1)
        self.assertEqual(batcher.slices, 1)
        self.assertGreater(batcher.max_slice_ms, 1.0)

    def test_a_slice_within_its_budget_is_not_an_overrun(self):
        batcher = Batcher(budget_ms=1000.0, chunk=10)
        batcher.run_slice(self._counter([5, 0]))
        self.assertEqual(batcher.overruns, 0)

    def test_drain_yields_between_slices_until_the_job_is_done(self):
        # The yield is the point of the whole class: it is where the loop
        # gets to read a socket or fire a keepalive before the next slice.
        # Each step here sleeps a millisecond against a half-millisecond
        # budget, so every slice provably ends after one step -- a sleep
        # guarantees a minimum, which is the direction this needs.
        batcher = Batcher(budget_ms=0.5, chunk=1, name='drain')
        remaining = [5]

        def step(chunk):
            time.sleep(0.001)
            take = min(chunk, remaining[0])
            remaining[0] -= take
            return take

        loop = new_loop()
        self.addCleanup(loop.close)
        total = loop.run_until_complete(batcher.drain(step))

        self.assertEqual(total, 5)
        self.assertEqual(batcher.items, 5)
        # One slice per item plus the final slice that found nothing left,
        # and a yield after every slice that was not the last.
        self.assertEqual(batcher.slices, 6)
        self.assertEqual(batcher.yields, 5)

    def test_drain_of_an_empty_job_runs_one_slice_and_never_yields(self):
        batcher = Batcher(budget_ms=50.0, chunk=8)
        loop = new_loop()
        self.addCleanup(loop.close)
        total = loop.run_until_complete(batcher.drain(lambda chunk: 0))
        self.assertEqual(total, 0)
        self.assertEqual(batcher.slices, 1)
        self.assertEqual(batcher.yields, 0)

    def test_drain_propagates_a_failing_step(self):
        batcher = Batcher(budget_ms=50.0, chunk=8)
        loop = new_loop()
        self.addCleanup(loop.close)

        def step(_chunk):
            raise RuntimeError('deliberate')

        with self.assertRaises(RuntimeError):
            loop.run_until_complete(batcher.drain(step))
        self.assertEqual(batcher.slices, 1)

    def test_reset_stats_zeroes_the_counters_but_keeps_the_budget(self):
        # Health output is cumulative by default; a caller that wants
        # per-interval numbers resets, and must not also reset the budget
        # the adaptation has settled on.
        batcher = Batcher(budget_ms=10.0, chunk=4)
        batcher.adapt(100.0)
        batcher.run_slice(self._counter([4, 0]))
        self.assertEqual(batcher.slices, 1)

        batcher.reset_stats()
        self.assertEqual(batcher.slices, 0)
        self.assertEqual(batcher.items, 0)
        self.assertEqual(batcher.yields, 0)
        self.assertEqual(batcher.overruns, 0)
        self.assertEqual(batcher.max_slice_ms, 0.0)
        self.assertEqual(batcher.total_ms, 0.0)
        self.assertEqual(batcher.budget_ms, 5.0)
        self.assertEqual(batcher.stats()['mean_slice_ms'], 0.0)

    def test_repr_reports_the_budget_and_the_work_done(self):
        batcher = Batcher(budget_ms=2.0, chunk=1, name='probe')
        batcher.run_slice(self._counter([3, 0]))
        text = repr(batcher)
        self.assertIn('probe', text)
        self.assertIn('items=3', text)

    @staticmethod
    def _counter(returns):
        """A step returning each of ``returns`` in turn, then 0."""
        pending = list(returns)

        def step(_chunk):
            return pending.pop(0) if pending else 0

        return step

    @staticmethod
    def _slow_step(seconds):
        """A step that costs a known minimum and then reports done."""
        done = []

        def step(chunk):
            if done:
                return 0
            done.append(True)
            time.sleep(seconds)
            return chunk

        return step


class EventBusTestCase(unittest.TestCase):
    """Bounded fan-out: drop, count, and say which end was dropped."""

    def setUp(self):
        self.bus = EventBus()
        self.addCleanup(self.bus.close)

    def test_an_unbounded_queue_is_refused(self):
        # The whole point of this path is that a slow subscriber cannot grow
        # without limit, so an unbounded queue is a memory leak dressed up
        # as a safety net and is refused rather than quietly accepted.
        with self.assertRaises(ValueError) as caught:
            self.bus.subscribe(EV.ROUTE_BEST, q=queue.Queue())
        self.assertIn('must be bounded', str(caught.exception))
        self.assertEqual(self.bus.stats()['subscribers'], [])

    def test_a_bounded_queue_supplied_by_the_caller_is_accepted(self):
        own = queue.Queue(4)
        subscription = self.bus.subscribe(EV.ROUTE_BEST, q=own)
        self.assertIs(subscription.queue, own)
        self.bus.publish(EV.ROUTE_BEST, {'n': 1})
        self.assertEqual(own.get_nowait(), (EV.ROUTE_BEST, {'n': 1}))

    def test_a_maxsize_below_one_is_refused(self):
        for bad in (0, -1):
            with self.assertRaises(ValueError) as caught:
                self.bus.subscribe(EV.ROUTE_BEST, maxsize=bad)
            self.assertIn('at least 1', str(caught.exception))

    def test_an_unknown_event_name_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            self.bus.subscribe('route-bestest')
        self.assertIn('unknown event', str(caught.exception))
        # The message names the real ones, because the caller passed a
        # string and has nothing else to go on.
        for event in EV.EVENTS:
            self.assertIn(event, str(caught.exception))

    def test_an_unknown_overflow_policy_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            self.bus.subscribe(EV.ROUTE_BEST, overflow='block')
        self.assertIn('overflow must be one of', str(caught.exception))

    def test_every_declared_event_can_be_subscribed_to(self):
        for event in EV.EVENTS:
            self.assertTrue(self.bus.subscribe(event, maxsize=1).active)

    def test_a_wildcard_subscriber_receives_every_event(self):
        everything = self.bus.subscribe(EV.ALL, maxsize=10)
        for event in EV.EVENTS:
            self.bus.publish(event, {'e': event})
        received = [e for e, _payload in everything.drain()]
        self.assertEqual(received, list(EV.EVENTS))

    def test_a_named_subscriber_receives_only_its_event(self):
        only = self.bus.subscribe(EV.ROUTE_WITHDRAW, maxsize=10)
        self.bus.publish(EV.ROUTE_BEST, {'n': 1})
        self.bus.publish(EV.ROUTE_WITHDRAW, {'n': 2})
        self.bus.publish(EV.PEER_STATE, {'n': 3})
        self.assertEqual(only.drain(), [(EV.ROUTE_WITHDRAW, {'n': 2})])

    def test_drop_oldest_keeps_the_newest_items(self):
        # A monitor that wants current state takes this policy, so the test
        # asserts *which* items survived. A counter-only assertion would
        # pass on a queue that kept exactly the wrong end.
        subscription = self.bus.subscribe(EV.ROUTE_BEST, maxsize=2,
                                          overflow=EV.DROP_OLDEST)
        for n in range(1, 6):
            self.bus.publish(EV.ROUTE_BEST, {'n': n})
        self.assertEqual([p['n'] for _e, p in subscription.drain()], [4, 5])

    def test_drop_newest_keeps_the_oldest_items(self):
        # An auditor that must not have gaps in the events it does see
        # takes this policy and reads the dropped counter to know a gap
        # exists at the end.
        subscription = self.bus.subscribe(EV.ROUTE_BEST, maxsize=2,
                                          overflow=EV.DROP_NEWEST)
        for n in range(1, 6):
            self.bus.publish(EV.ROUTE_BEST, {'n': n})
        self.assertEqual([p['n'] for _e, p in subscription.drain()], [1, 2])

    def test_publish_reports_how_many_deliveries_it_dropped(self):
        self.bus.subscribe(EV.ROUTE_BEST, maxsize=1,
                           overflow=EV.DROP_NEWEST)
        self.assertEqual(self.bus.publish(EV.ROUTE_BEST, {'n': 1}), 0)
        self.assertEqual(self.bus.publish(EV.ROUTE_BEST, {'n': 2}), 1)

    def test_the_counters_distinguish_delivery_from_drop(self):
        # drop-oldest delivers the new item *and* discards an old one, so
        # one overflowing publish increments both counters; drop-newest
        # increments only the drop. Pinned because the two policies would
        # otherwise be indistinguishable in health output.
        oldest = self.bus.subscribe(EV.ROUTE_BEST, maxsize=2,
                                    overflow=EV.DROP_OLDEST)
        newest = self.bus.subscribe(EV.ROUTE_BEST, maxsize=2,
                                    overflow=EV.DROP_NEWEST)
        for n in range(1, 6):
            self.bus.publish(EV.ROUTE_BEST, {'n': n})

        self.assertEqual(oldest.stats()['delivered'], 5)
        self.assertEqual(oldest.stats()['dropped'], 3)
        self.assertEqual(newest.stats()['delivered'], 2)
        self.assertEqual(newest.stats()['dropped'], 3)
        self.assertEqual(self.bus.dropped_total(), 6)
        self.assertEqual(self.bus.stats()['dropped'], 6)

    def test_a_subscription_reports_its_own_configuration(self):
        subscription = self.bus.subscribe(EV.ROUTE_BEST, maxsize=3,
                                          overflow=EV.DROP_NEWEST,
                                          name='auditor')
        self.bus.publish(EV.ROUTE_BEST, {'n': 1})
        self.assertEqual(subscription.stats(),
                         {'name': 'auditor', 'event': EV.ROUTE_BEST,
                          'overflow': EV.DROP_NEWEST, 'depth': 1,
                          'delivered': 1, 'dropped': 0, 'active': True})
        self.assertIn('auditor', repr(subscription))

    def test_a_subscription_defaults_its_name_to_its_event(self):
        self.assertEqual(self.bus.subscribe(EV.PEER_STATE).name,
                         EV.PEER_STATE)

    def test_get_blocks_up_to_the_timeout_then_raises_empty(self):
        subscription = self.bus.subscribe(EV.ROUTE_BEST, maxsize=2)
        self.bus.publish(EV.ROUTE_BEST, {'n': 1})
        self.assertEqual(subscription.get(timeout=1), (EV.ROUTE_BEST,
                                                       {'n': 1}))
        with self.assertRaises(queue.Empty):
            subscription.get(timeout=0.01)

    def test_drain_returns_oldest_first_and_empties_the_queue(self):
        subscription = self.bus.subscribe(EV.ROUTE_BEST, maxsize=10)
        for n in range(3):
            self.bus.publish(EV.ROUTE_BEST, {'n': n})
        self.assertEqual([p['n'] for _e, p in subscription.drain()],
                         [0, 1, 2])
        self.assertEqual(subscription.drain(), [])
        self.assertEqual(subscription.stats()['depth'], 0)

    def test_unsubscribe_stops_delivery_and_is_idempotent(self):
        # Shutdown paths call this without knowing what came before them,
        # so a second call has to be a no-op rather than an error.
        subscription = self.bus.subscribe(EV.ROUTE_BEST, maxsize=10)
        self.assertTrue(self.bus.unsubscribe(subscription))
        self.assertFalse(subscription.active)
        self.assertFalse(self.bus.unsubscribe(subscription))
        self.bus.publish(EV.ROUTE_BEST, {'n': 1})
        self.assertEqual(subscription.drain(), [])

    def test_unsubscribing_something_never_registered_is_not_an_error(self):
        other = EventBus()
        self.addCleanup(other.close)
        stranger = other.subscribe(EV.ROUTE_BEST, maxsize=1)
        self.assertFalse(self.bus.unsubscribe(stranger))

    def test_a_synchronous_callback_runs_in_registration_order(self):
        seen = []
        self.bus.on(EV.ROUTE_BEST, lambda e, p: seen.append(('first', p)))
        self.bus.on(EV.ROUTE_BEST, lambda e, p: seen.append(('second', p)))
        self.bus.publish(EV.ROUTE_BEST, {'n': 1})
        self.assertEqual([who for who, _p in seen], ['first', 'second'])

    def test_a_wildcard_callback_sees_every_event_exactly_once(self):
        seen = []
        self.bus.on(EV.ALL, lambda e, _p: seen.append(e))
        self.bus.on(EV.ROUTE_BEST, lambda e, _p: seen.append('specific'))
        self.bus.publish(EV.ROUTE_BEST, {})
        self.bus.publish(EV.PEER_STATE, {})
        self.assertEqual(seen, ['specific', EV.ROUTE_BEST, EV.PEER_STATE])

    def test_a_callback_that_raises_is_counted_and_does_not_stop_delivery(
            self):
        # One broken plugin must not abort the selection pass that every
        # other plugin shares -- but the count is a defect report, not a
        # supported mode, so it has to be visible in health output.
        _quiet(self, 'packets.rtengine.events')
        seen = []

        def rude(_event, _payload):
            raise RuntimeError('deliberate')

        self.bus.on(EV.ROUTE_BEST, rude)
        self.bus.on(EV.ROUTE_BEST, lambda e, p: seen.append('after'))
        queued = self.bus.subscribe(EV.ROUTE_BEST, maxsize=2)

        self.bus.publish(EV.ROUTE_BEST, {'n': 1})

        self.assertEqual(seen, ['after'])
        self.assertEqual(len(queued.drain()), 1)
        self.assertEqual(self.bus.callback_errors, 1)
        self.assertEqual(self.bus.stats()['callback_errors'], 1)

    def test_an_unknown_event_name_is_refused_for_a_callback_too(self):
        with self.assertRaises(ValueError):
            self.bus.on('not-an-event', lambda e, p: None)

    def test_off_removes_a_callback_and_reports_whether_it_was_there(self):
        def handler(_event, _payload):
            pass

        self.bus.on(EV.ROUTE_BEST, handler)
        self.assertTrue(self.bus.off(EV.ROUTE_BEST, handler))
        self.assertFalse(self.bus.off(EV.ROUTE_BEST, handler))
        self.assertFalse(self.bus.off(EV.PEER_STATE, handler))

    def test_publishing_with_nobody_listening_is_harmless(self):
        self.assertEqual(self.bus.publish(EV.ROUTE_BEST, {'n': 1}), 0)
        self.assertEqual(self.bus.stats()['published'], {EV.ROUTE_BEST: 1})

    def test_stats_count_publications_per_event(self):
        self.bus.on(EV.ROUTE_BEST, lambda e, p: None)
        self.bus.publish(EV.ROUTE_BEST, {})
        self.bus.publish(EV.ROUTE_BEST, {})
        self.bus.publish(EV.PEER_STATE, {})
        stats = self.bus.stats()
        self.assertEqual(stats['published'], {EV.ROUTE_BEST: 2,
                                              EV.PEER_STATE: 1})
        self.assertEqual(stats['callbacks'], {EV.ROUTE_BEST: 1})
        json.dumps(stats)

    def test_close_drops_every_subscription_and_callback(self):
        # Called on engine stop, so a restarted engine does not keep
        # delivering into a previous run's queues.
        subscription = self.bus.subscribe(EV.ROUTE_BEST, maxsize=10)
        self.bus.on(EV.ROUTE_BEST, lambda e, p: None)
        self.bus.close()

        self.assertFalse(subscription.active)
        self.assertEqual(self.bus.stats()['subscribers'], [])
        self.assertEqual(self.bus.stats()['callbacks'], {})
        self.bus.publish(EV.ROUTE_BEST, {'n': 1})
        self.assertEqual(subscription.drain(), [])

    def test_close_is_idempotent(self):
        self.bus.close()
        self.bus.close()
        self.assertEqual(self.bus.stats()['subscribers'], [])

    def test_repr_counts_subscribers_and_callbacks(self):
        self.bus.subscribe(EV.ROUTE_BEST, maxsize=1)
        self.bus.on(EV.PEER_STATE, lambda e, p: None)
        self.assertIn('subscribers=1', repr(self.bus))
        self.assertIn('callbacks=1', repr(self.bus))

    def test_a_subscriber_can_read_from_another_thread(self):
        # The reason the queue path exists at all: an importer reads it from
        # its own thread while the loop publishes.
        subscription = self.bus.subscribe(EV.ROUTE_BEST, maxsize=10)
        received = []

        def reader():
            received.append(subscription.get(timeout=5))

        thread = threading.Thread(target=reader, name='bus-reader')
        thread.start()
        self.addCleanup(thread.join, 5)
        self.bus.publish(EV.ROUTE_BEST, {'n': 1})
        thread.join(5)
        self.assertEqual(received, [(EV.ROUTE_BEST, {'n': 1})])


if __name__ == '__main__':
    unittest.main()
