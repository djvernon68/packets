# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Where the winning routes go, if anywhere.

The ``GlobalRib`` publishes each selected best route to a ``FibSink``. The
default sink is :class:`NullSink`, which counts what it was asked to do and
touches nothing, and that is the shipped behaviour: rtengine is a
control-plane speaker unless it is configured otherwise. An imported library
that wrote the kernel routing table because someone called ``start()`` would
be indefensible, and on a host already running another routing daemon it
would be an outage.

The interface is deliberately batched and asynchronous in shape even though
the null implementation needs neither. Installing a route into the kernel is
a syscall and an acknowledgement, and a full table is a million of them: any
sink worth having queues, flushes in batches and reconciles acknowledgements
afterwards, so the interface has to allow that from the start rather than
being retrofitted around a synchronous ``install()``.

Four things a real sink must get right, all of them expressed here so the
contract is written down before there is an implementation to argue with:

* **ownership.** Routes are written with rtengine's own protocol id *and*
  its own metric. Kernel route identity is (table, destination, tos,
  priority), so a distinct metric means a replace can only ever replace our
  own route and another daemon's route for the same prefix survives at its
  own metric.
* **reconciliation at startup.** Routes carrying our protocol id that we did
  not put there are ours from a previous run. They are adopted if they match
  what we would install and removed if they do not, because leaving them is
  a black hole for as long as the process lives.
* **per-route errors.** One route rejected by the kernel -- no route to the
  next-hop, address family disabled -- must mark that route and nothing
  else. There is no cross-route rollback because routes are independent:
  a failed install leaves the other 999,999 correct.
* **shutdown.** Routes are withdrawn on stop unless retention is configured,
  so a stopped speaker does not leave the kernel forwarding through a
  next-hop nobody is maintaining.
"""

from packets.routing.rtengine.rib.table import (FIB_STATE_NAMES,
                                                FIB_STATE_NONE,
                                                FIB_STATE_NOT_INSTALLED)


class FibSink(object):
    """Interface for anything that can be handed the engine's best routes.

    Subclass it for a real forwarding plane. Every method has a working
    inert default so a partial implementation is possible, but a sink that
    installs must implement :meth:`reconcile` and :meth:`shutdown` as well:
    a forwarding plane that can be written but not cleaned up is worse than
    one that cannot be written at all.
    """

    #: Short name, used in health output and log lines.
    name = 'fib'

    #: Whether this sink actually writes a forwarding plane. Health and
    #: ``show ip route`` use it to decide whether a route's FIB state means
    #: anything.
    writes = False

    def install(self, route):
        """Queue a route for installation.

        Called once per best-route change, on the loop thread. It must not
        block: queue the work and return, and do the writing in
        :meth:`flush`.

        :param route: the :class:`~packets.routing.rtengine.rib.table.Route`
            that is now best for its prefix.
        """

    def withdraw(self, route):
        """Queue the removal of a route.

        :param route: the route that is no longer best, or whose prefix has
            no best route at all.
        """

    def flush(self):
        """Write everything queued and process acknowledgements.

        Called from a deadline-bounded batch, so it may be called many
        times per second and should do a bounded amount of work per call.

        :return: the number of routes whose state changed.
        """
        return 0

    def next_flush_in(self):
        """Say when :meth:`flush` next has something to do.

        What the engine's FIB pump (E-1) uses to keep calling ``flush``
        until the sink is idle, rather than once per selection pass --
        which left everything past the first batch of a large convergence
        sitting in the queue until some unrelated route changed.

        :return: seconds until the next flush is useful, 0 for "now", or
            None when the sink is idle.
        """
        return None

    def reconcile(self, current):
        """Adopt or remove pre-existing routes that carry our identity.

        Called once at start, before any install. ``current`` is what the
        engine believes should be installed; anything in the forwarding
        plane marked as ours and not in it is from a previous run.

        :param current: iterable of routes the engine wants installed.
        :return: a dict with counts of what was adopted and removed.
        """
        return {'adopted': 0, 'removed': 0}

    def shutdown(self, retain=False):
        """Withdraw everything, or deliberately leave it behind.

        :param retain: leave the routes in place. For a planned restart
            where a brief black hole is worse than a stale route.
        :return: the number of routes withdrawn.
        """
        return 0

    def stats(self):
        """Return counters for health output.

        :return: a dict of plain types, including a ``status`` of ``ok`` or
            ``degraded``.
        """
        return {'name': self.name, 'writes': self.writes, 'status': 'ok'}


class NullSink(FibSink):
    """The default sink: accounts for everything, forwards nothing.

    Not a stub. It is the correct implementation for the engine's default
    role, and it is also how the RIB and selection paths are tested without
    privileges or a kernel: the counters below are exactly what a test
    needs to assert that selection published what it should have.
    """

    name = 'null'
    writes = False

    def __init__(self):
        self.installed = 0
        self.withdrawn = 0
        self.flushes = 0
        # Keyed by prefix text rather than by Prefix so the contents are
        # directly comparable in a test and directly serialisable in health
        # output.
        self.routes = {}

    def install(self, route):
        """Record a route as selected, and as *not* installed.

        The route's own ``fib_state`` becomes ``not-installed`` (L-7). It
        used to say ``installed``, on the theory that the configured
        forwarding plane had accepted it -- but ``show ip route`` is read
        by people deciding whether traffic will follow a route, and on an
        engine with no forwarding plane the true answer is that it will
        not.

        :param route: the route now best for its prefix.
        """
        self.installed += 1
        self.routes[route.prefix.to_str()] = route
        route.fib_state = FIB_STATE_NOT_INSTALLED
        route.fib_errno = 0

    def withdraw(self, route):
        """Record a route as withdrawn.

        :param route: the route no longer best for its prefix.
        """
        self.withdrawn += 1
        self.routes.pop(route.prefix.to_str(), None)
        route.fib_state = FIB_STATE_NONE
        route.fib_errno = 0

    def flush(self):
        """Nothing is queued, so nothing is written.

        :return: 0, always.
        """
        self.flushes += 1
        return 0

    def reconcile(self, current):
        """Nothing pre-exists in a sink that writes nothing.

        :param current: ignored.
        :return: zero counts.
        """
        return {'adopted': 0, 'removed': 0}

    def shutdown(self, retain=False):
        """Forget every recorded route.

        :param retain: keep the record, for symmetry with a real sink.
        :return: the number of routes forgotten.
        """
        n = len(self.routes)
        if not retain:
            for route in list(self.routes.values()):
                route.fib_state = FIB_STATE_NONE
            self.routes = {}
        return n

    def stats(self):
        """Return the counters.

        :return: a dict of plain types.
        """
        return {
            'name': self.name,
            'writes': False,
            'status': 'ok',
            'installed': self.installed,
            'withdrawn': self.withdrawn,
            'flushes': self.flushes,
            'present': len(self.routes),
        }

    def state_of(self, prefix_text):
        """Return the recorded FIB state for a prefix, for tests and show.

        :param prefix_text: the prefix in ``address/length`` form.
        :return: the state name, or ``'none'`` if not present.
        """
        route = self.routes.get(prefix_text)
        if route is None:
            return FIB_STATE_NAMES[FIB_STATE_NONE]
        return FIB_STATE_NAMES.get(route.fib_state, 'unknown')

    def __repr__(self):
        return '<NullSink present=%d installed=%d withdrawn=%d>' % (
            len(self.routes), self.installed, self.withdrawn)
