# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The event bus: two delivery paths, deliberately different.

**Bounded queues, for importers.** Code that embeds the engine subscribes
with a ``queue.Queue`` and reads it from its own thread. The queue is
*bounded* and the bus never blocks on it. An importer that stops reading --
because it is slow, wedged, or gone -- must not be able to stall the event
loop, and an unbounded queue in front of a full-table load is a memory leak
with a routing outage at the end of it. So the bus drops, counts what it
dropped, and reports the count in ``/engine/health``: a subscriber that is
losing events is a visible degradation rather than a silent one.

Which end to drop is the subscriber's choice, because it depends on what the
subscriber is for. A monitor that wants current state takes
``drop-oldest``; an auditor that must not have gaps in the events it *does*
see takes ``drop-newest`` and reads the dropped counter to know a gap exists.

**Synchronous callbacks, for the engine's own wiring.** The ``GlobalRib``
telling the FIB sink about a new best route, or a protocol's Loc-RIB telling
its update groups, cannot go through a queue: those are steps in one
operation, not notifications about it. They run in the loop thread, in
registration order, right after the batch that produced them has committed.

Two rules make that safe, and both are contracts, not suggestions:

* a synchronous callback must not mutate RIB state. Dispatch happens after
  the commit precisely so that every callback sees one consistent picture; a
  callback that offers a route re-enters selection and can produce events
  out of order.
* a synchronous callback must not raise. One that does is caught, counted
  and logged, because the alternative is a plugin bug aborting the engine's
  selection pass -- but the count is a defect report, not a supported mode.
"""

import logging
import queue as _queue
import threading

_log = logging.getLogger('packets.rtengine.events')

# Event names. Strings rather than an enum: they appear verbatim in the REST
# API and in log lines, and a caller subscribing to 'peer-state' should not
# have to import a symbol to do it.
ROUTE_BEST = 'route-best'          # a destination's best route changed
ROUTE_WITHDRAW = 'route-withdraw'  # a destination lost its last route
PEER_STATE = 'peer-state'          # a protocol session changed state
FIB_RESULT = 'fib-result'          # the FIB sink acked or rejected a route
CONFIG_CHANGE = 'config-change'    # a configuration revision was committed
ENGINE_STATE = 'engine-state'      # the engine started or stopped

EVENTS = (ROUTE_BEST, ROUTE_WITHDRAW, PEER_STATE, FIB_RESULT, CONFIG_CHANGE,
          ENGINE_STATE)

# Subscribe with this to receive every event.
ALL = '*'

DROP_OLDEST = 'drop-oldest'
DROP_NEWEST = 'drop-newest'
OVERFLOW_POLICIES = (DROP_OLDEST, DROP_NEWEST)

DEFAULT_MAXSIZE = 10000


class Subscription(object):
    """One importer's bounded view of the event stream.

    Returned by :meth:`EventBus.subscribe`; read ``queue`` from any thread.
    Do not construct directly.

    :param event: the event name, or ``'*'`` for all of them.
    :param q: the bounded queue events are delivered into.
    :param overflow: ``'drop-oldest'`` or ``'drop-newest'``.
    :param name: label for health output.
    """

    __slots__ = ('event', 'queue', 'overflow', 'name', 'delivered', 'dropped',
                 'active')

    def __init__(self, event, q, overflow, name):
        self.event = event
        self.queue = q
        self.overflow = overflow
        self.name = name
        self.delivered = 0
        self.dropped = 0
        self.active = True

    def get(self, timeout=None):
        """Read the next event, blocking up to ``timeout`` seconds.

        A thin pass-through so a caller does not have to know that the
        underlying object is a ``queue.Queue``, which leaves room to change
        that later.

        :param timeout: seconds to wait, or None to wait forever.
        :return: ``(event_name, payload)``.
        :raises queue.Empty: nothing arrived within the timeout.
        """
        return self.queue.get(timeout=timeout)

    def drain(self):
        """Take everything currently queued, without blocking.

        :return: a list of ``(event_name, payload)``, oldest first.
        """
        out = []
        while True:
            try:
                out.append(self.queue.get_nowait())
            except _queue.Empty:
                return out

    def stats(self):
        """Return this subscription's counters.

        :return: a dict of plain types. ``dropped`` above zero means this
            subscriber is not keeping up and has an incomplete view.
        """
        return {
            'name': self.name,
            'event': self.event,
            'overflow': self.overflow,
            'depth': self.queue.qsize(),
            'delivered': self.delivered,
            'dropped': self.dropped,
            'active': self.active,
        }

    def __repr__(self):
        return '<Subscription %s %s depth=%d dropped=%d>' % (
            self.name, self.event, self.queue.qsize(), self.dropped)


class EventBus(object):
    """Fan-out for engine events: bounded queues plus in-loop callbacks."""

    def __init__(self):
        # Subscriptions are read on the loop thread (publish) and mutated
        # from whichever thread calls subscribe, so the list itself needs a
        # lock. The queues are already thread-safe; this protects the
        # membership, and is never held while a callback runs.
        self._lock = threading.Lock()
        self._subs = []
        self._callbacks = {}
        self.published = {}
        self.callback_errors = 0

    # --- bounded queue subscriptions --------------------------------------

    def subscribe(self, event=ALL, q=None, maxsize=DEFAULT_MAXSIZE,
                  overflow=DROP_OLDEST, name=None):
        """Register a bounded queue for an event.

        :param event: an event name from ``EVENTS``, or ``'*'`` for all.
        :param q: an existing queue to deliver into. It must be bounded --
            an unbounded queue is refused rather than quietly accepted,
            because the whole point of this path is that a slow subscriber
            cannot grow without limit.
        :param maxsize: bound for a queue created here.
        :param overflow: ``'drop-oldest'`` or ``'drop-newest'``.
        :param name: label for health output; defaults to the event name.
        :return: the :class:`Subscription`.
        :raises ValueError: unknown event, unknown policy, or an unbounded
            queue.
        """
        if event != ALL and event not in EVENTS:
            raise ValueError('unknown event %r; known: %s'
                             % (event, ', '.join(EVENTS)))
        if overflow not in OVERFLOW_POLICIES:
            raise ValueError('overflow must be one of %s'
                             % ', '.join(OVERFLOW_POLICIES))
        if q is None:
            if maxsize < 1:
                raise ValueError('maxsize must be at least 1')
            q = _queue.Queue(maxsize)
        elif getattr(q, 'maxsize', 0) < 1:
            raise ValueError('an event queue must be bounded: the engine '
                             'drops rather than blocking, so an unbounded '
                             'queue is a memory leak, not a safety net')

        sub = Subscription(event, q, overflow, name or event)
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub):
        """Stop delivering to a subscription.

        Idempotent: unsubscribing twice, or unsubscribing something that
        was never registered, is not an error. Shutdown paths call this
        without knowing what came before them.

        :param sub: the subscription to remove.
        :return: True if it was registered.
        """
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)
                sub.active = False
                return True
        return False

    # --- synchronous in-loop callbacks -------------------------------------

    def on(self, event, callback):
        """Register a synchronous in-loop callback.

        For engine and plugin wiring only -- see the module docstring for
        the two rules that apply to it. Importing code wants
        :meth:`subscribe`.

        :param event: an event name from ``EVENTS``, or ``'*'``.
        :param callback: called as ``callback(event, payload)`` on the loop
            thread.
        :raises ValueError: unknown event.
        """
        if event != ALL and event not in EVENTS:
            raise ValueError('unknown event %r' % (event,))
        self._callbacks.setdefault(event, []).append(callback)

    def off(self, event, callback):
        """Remove a synchronous callback.

        :param event: the event it was registered for.
        :param callback: the callable to remove.
        :return: True if it was registered.
        """
        handlers = self._callbacks.get(event)
        if handlers and callback in handlers:
            handlers.remove(callback)
            return True
        return False

    # --- publication -------------------------------------------------------

    def publish(self, event, payload):
        """Deliver one event to every interested subscriber.

        Never blocks and never raises. That is the contract the loop
        depends on: this is called from inside selection and FSM
        transitions, where an exception would abandon a half-applied batch
        and a block would stall every session.

        :param event: the event name.
        :param payload: any object; by convention a dict of plain types, so
            the REST layer can serialise it unchanged.
        :return: the number of queue deliveries that were dropped.
        """
        self.published[event] = self.published.get(event, 0) + 1
        dropped = 0

        with self._lock:
            targets = [s for s in self._subs
                       if s.event == event or s.event == ALL]
        item = (event, payload)
        for sub in targets:
            try:
                sub.queue.put_nowait(item)
                sub.delivered += 1
            except _queue.Full:
                if sub.overflow == DROP_OLDEST:
                    # Make room by discarding the stalest event. The
                    # get/put pair is not atomic, but this subscriber's
                    # queue is only ever written here, on the loop thread,
                    # so the only racing operation is the subscriber's own
                    # get -- which can only make more room.
                    try:
                        sub.queue.get_nowait()
                    except _queue.Empty:
                        pass
                    try:
                        sub.queue.put_nowait(item)
                        sub.delivered += 1
                        sub.dropped += 1
                        dropped += 1
                        continue
                    except _queue.Full:
                        pass
                sub.dropped += 1
                dropped += 1

        # Snapshots, not the live lists (E-9): a callback that calls on() or
        # off() -- a plugin unwiring itself as a session goes down -- would
        # otherwise shift the list under the iteration and make it skip
        # the next handler or run one twice. Registrations made during a
        # publish take effect from the next one.
        for callback in tuple(self._callbacks.get(event, ())):
            self._invoke(callback, event, payload)
        if event != ALL:
            for callback in tuple(self._callbacks.get(ALL, ())):
                self._invoke(callback, event, payload)
        return dropped

    def _invoke(self, callback, event, payload):
        try:
            callback(event, payload)
        except Exception:
            # A plugin's wiring callback raising is a defect in that plugin.
            # Counting and logging it keeps one broken plugin from aborting
            # the selection pass that every other plugin shares.
            self.callback_errors += 1
            _log.exception('event callback failed for %s', event)

    # --- reporting ---------------------------------------------------------

    def dropped_total(self):
        """Return the total events dropped across all subscriptions.

        :return: the count. Non-zero degrades engine health.
        """
        with self._lock:
            return sum(s.dropped for s in self._subs)

    def stats(self):
        """Return bus counters for health output.

        :return: a dict of plain types.
        """
        with self._lock:
            subs = [s.stats() for s in self._subs]
        return {
            'published': dict(self.published),
            'subscribers': subs,
            'dropped': sum(s['dropped'] for s in subs),
            'callback_errors': self.callback_errors,
            'callbacks': dict((k, len(v))
                              for k, v in self._callbacks.items() if v),
        }

    def close(self):
        """Drop every subscription and callback.

        Called on engine stop so a restarted engine does not keep
        delivering into a previous run's queues.
        """
        with self._lock:
            for sub in self._subs:
                sub.active = False
            self._subs = []
        self._callbacks = {}

    def __repr__(self):
        with self._lock:
            n = len(self._subs)
        return '<EventBus subscribers=%d callbacks=%d>' % (
            n, sum(len(v) for v in self._callbacks.values()))
