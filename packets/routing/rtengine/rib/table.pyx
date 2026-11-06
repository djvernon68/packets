# cython: language_level=3

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Protocol-neutral route state: what plugins offer and who wins.

Three objects and one comparison:

``Route``       one candidate for one prefix, from one protocol. A prefix, a
                next-hop, an administrative distance and a metric -- the two
                numbers every routing protocol can express -- plus the
                offering plugin's opaque token.
``Dest``        every route offered for one prefix, and the winner.
``RouteTable``  one per (afi, safi): a trie of Dests plus the change queue
                that makes selection deadline-bounded.
``route_cmp``   administrative distance, then metric, then protocol
                preference, then age.

Nothing here knows what BGP is, and that is the design. A plugin runs its own
protocol RIB and its own best-path algorithm -- BGP's AS_PATH, MED grouping
and communities live entirely inside the BGP plugin -- and only its winners
become ``Route`` candidates here. With one protocol configured the selection
below is trivial; the point of it is that OSPF and RIP can arrive later
without the core learning anything new.

The change queue is the part worth understanding. An offer or a withdrawal
does not select anything: it updates the destination's route list, marks the
destination dirty and returns. Selection happens in ``reselect()``, which
drains as much of the queue as the caller's time budget allows. That is what
lets a full-table load of a million prefixes run without blocking the event
loop long enough to miss a KEEPALIVE, and it also collapses work: a prefix
that flaps a thousand times inside one batch is selected once.
"""

import socket
import time

from cpython.bytes cimport PyBytes_GET_SIZE

from packets.routing.rtengine.rib.prefix cimport (PFX_SAFI_UNICAST, Prefix,
                                                  pfx_addr_len)
from packets.routing.rtengine.rib.trie cimport TrieNode, trie_node_value


# Python-visible spellings of the C enums in table.pxd. The C names are
# prefixed so these can exist: a module cannot assign to a name its own .pxd
# has made a compile-time constant.
PROTO_UNSPEC = RT_PROTO_UNSPEC
PROTO_CONNECTED = RT_PROTO_CONNECTED
PROTO_STATIC = RT_PROTO_STATIC
PROTO_BGP = RT_PROTO_BGP
PROTO_OSPF = RT_PROTO_OSPF
PROTO_RIP = RT_PROTO_RIP

PROTO_NAMES = {
    RT_PROTO_UNSPEC: 'unspec',
    RT_PROTO_CONNECTED: 'connected',
    RT_PROTO_STATIC: 'static',
    RT_PROTO_BGP: 'bgp',
    RT_PROTO_OSPF: 'ospf',
    RT_PROTO_RIP: 'rip',
}

PROTO_IDS = dict((name, pid) for pid, name in PROTO_NAMES.items())

FIB_STATE_NONE = FIB_NONE
FIB_STATE_PENDING = FIB_PENDING
FIB_STATE_INSTALLED = FIB_INSTALLED
FIB_STATE_ERROR = FIB_ERROR
FIB_STATE_ORPHANED = FIB_ORPHANED
FIB_STATE_NOT_INSTALLED = FIB_NOT_INSTALLED

FIB_STATE_NAMES = {
    FIB_NONE: 'none',
    FIB_PENDING: 'pending',
    FIB_INSTALLED: 'installed',
    FIB_ERROR: 'fib-error',
    FIB_ORPHANED: 'orphaned',
    FIB_NOT_INSTALLED: 'not-installed',
}

# Cisco/FRR conventional defaults. The engine's configuration can override
# the BGP pair through `distance bgp`; connected and static are fixed
# because a configuration that trusts a learned route over a directly
# attached network is a mistake rather than a policy.
DEFAULT_ADMIN_DISTANCE = {
    'connected': 0,
    'static': 1,
    'ebgp': 20,
    'ibgp': 200,
}

# Selection reads the clock for the age tie-break, so it must be monotonic:
# a wall-clock step backwards (ntp, a suspended VM) would otherwise reorder
# existing routes. Bound once here rather than looked up per route.
_monotonic = time.monotonic


cdef class Route:
    """One protocol's candidate route for one prefix.

    :param prefix: the destination.
    :param protocol: an ``RT_PROTO_*`` id; also the protocol-preference
        tie-break, low first.
    :param admin_distance: how much the operator trusts this protocol for
        this route, 0 to 255, low wins. See ``DEFAULT_ADMIN_DISTANCE``.
    :param metric: the protocol's own idea of path cost, low wins. Compared
        only between routes at the same administrative distance, because
        metrics from different protocols are not commensurable.
    :param nexthop: the next-hop address, packed -- 4 or 16 bytes, or empty
        for a directly attached destination.
    :param source: the offering plugin's token. Opaque to the core and
        compared by identity; with ``protocol`` it is this route's identity
        within its destination.
    :param recv_time: monotonic timestamp for the age tie-break; defaults to
        now.
    :raises ValueError: no prefix, or a next-hop that is not 0, 4 or 16
        bytes.
    """

    def __init__(self, Prefix prefix, unsigned char protocol,
                 unsigned char admin_distance, uint32_t metric,
                 bytes nexthop=None, object source=None,
                 double recv_time=-1.0):
        cdef Py_ssize_t nh_len

        if prefix is None:
            raise ValueError('a route needs a prefix')
        if nexthop is None:
            nexthop = b''
        nh_len = PyBytes_GET_SIZE(nexthop)
        if nh_len != 0 and nh_len != 4 and nh_len != 16:
            # Deliberately not checked against the prefix family: RFC 5549
            # style IPv4-over-IPv6 next-hops are a real thing, out of scope
            # for v1 but not worth forbidding structurally here.
            raise ValueError('next-hop must be 4 or 16 bytes, or empty for '
                             'a connected route, not %d' % nh_len)

        self.prefix = prefix
        self.protocol = protocol
        self.admin_distance = admin_distance
        self.metric = metric
        self.nexthop = nexthop
        self.source = source
        self.recv_time = _monotonic() if recv_time < 0.0 else recv_time
        self.version = 0
        self.fib_state = FIB_NONE
        self.fib_errno = 0

    cpdef bint same_origin(self, Route other):
        """Return whether two routes are the same protocol's same offer.

        Identity is ``(protocol, source)`` with the source compared by
        object identity: a plugin re-offering a prefix it already offered is
        an update to that route, not a second path. Add-path style
        multiplicity is a protocol-internal matter and never reaches the
        protocol-neutral table.

        :param other: the route to compare with.
        :return: True if ``other`` would replace this route.
        """
        if other is None:
            return 0
        return self.protocol == other.protocol and self.source is other.source

    @property
    def protocol_name(self):
        """The protocol id as a name, for show output."""
        return PROTO_NAMES.get(self.protocol, 'unknown')

    @property
    def fib_state_name(self):
        """The FIB install state as a name, for show output."""
        return FIB_STATE_NAMES.get(self.fib_state, 'unknown')

    def as_dict(self):
        """Render this route as the JSON-ready document show output uses.

        The next-hop is rendered as text rather than bytes so the result is
        directly serialisable; an empty next-hop stays empty rather than
        becoming ``'0.0.0.0'``, which would claim a gateway that does not
        exist.

        :return: a dict of plain types.
        """
        cdef object nh = ''

        if self.nexthop:
            nh = _addr_to_str(self.nexthop)
        return {
            'prefix': self.prefix.to_str(),
            'protocol': self.protocol_name,
            'distance': self.admin_distance,
            'metric': self.metric,
            'next-hop': nh,
            'fib': self.fib_state_name,
            'fib-errno': self.fib_errno if self.fib_state == FIB_ERROR else 0,
        }

    def __repr__(self):
        return '<Route %s via %s %s d=%d m=%d>' % (
            self.prefix.to_str(),
            _addr_to_str(self.nexthop) if self.nexthop else 'connected',
            self.protocol_name, self.admin_distance, self.metric)


cdef class Dest:
    """Every route offered for one prefix, and the current winner.

    :param prefix: the destination this collects routes for.
    """

    def __cinit__(self, Prefix prefix):
        if prefix is None:
            raise ValueError('a destination needs a prefix')
        self.prefix = prefix
        self.routes = []
        self.best = None
        self.version = 0
        self.queued = 0

    cdef Route _select(self):
        """Return the winning route, or None when nothing is offered.

        A linear scan, not a sorted container: a prefix normally carries one
        or two candidates and never more than a handful, so a scan beats
        maintaining order on every offer. It is also stable -- ties keep the
        earlier route -- which matters because route_cmp can legitimately
        return 0 for two routes from the same protocol at the same distance
        and metric, and a table that reordered those between passes would
        flap the FIB for no reason.
        """
        cdef list routes = self.routes
        cdef Py_ssize_t i
        cdef Py_ssize_t n = len(routes)
        cdef Route best = None
        cdef Route r

        for i in range(n):
            r = <Route>routes[i]
            if best is None or route_cmp(r, best) < 0:
                best = r
        return best

    def __len__(self):
        return len(self.routes)

    def __iter__(self):
        return iter(self.routes)

    def as_dict(self):
        """Render the destination and all its candidates for show output.

        :return: a dict of plain types, best route first.
        """
        return {
            'prefix': self.prefix.to_str(),
            'best': self.best.as_dict() if self.best is not None else None,
            'routes': [r.as_dict() for r in self.routes],
        }

    def __repr__(self):
        return '<Dest %s routes=%d best=%s>' % (
            self.prefix.to_str(), len(self.routes),
            self.best.protocol_name if self.best is not None else 'none')


cdef inline bint _same_content(Route a, Route b):
    # Everything selection and a sink can see, minus the receive time: a
    # re-offer stamped later is the same route, and adopting its newer age
    # would lose the "oldest path" tie-break the original has earned.
    return (a.admin_distance == b.admin_distance and a.metric == b.metric
            and a.nexthop == b.nexthop)


cdef class RouteTable:
    """The route table for one (afi, safi).

    :param afi: IANA address family number, 1 or 2.
    :param safi: subsequent address family identifier; only unicast (1) has
        a meaning in v1, but it is carried so that a second SAFI does not
        change the table's identity later.
    :raises ValueError: unknown address family.
    """

    def __cinit__(self, unsigned char afi,
                  unsigned char safi=PFX_SAFI_UNICAST):
        if pfx_addr_len(afi) == 0:
            raise ValueError('unsupported address family number %d' % afi)
        self.afi = afi
        self.safi = safi
        self.trie = Trie(afi)
        self.route_count = 0
        self.version = 0
        self._queue = []
        self._qhead = 0

    # --- lookups -----------------------------------------------------------

    cpdef Dest get(self, Prefix p):
        """Return the destination for exactly this prefix, or None.

        :param p: the prefix.
        :return: the Dest, or None if no protocol offers this prefix.
        """
        return <Dest>self.trie.get(p)

    cpdef Dest dest(self, Prefix p):
        """Return the destination for a prefix, creating it if needed.

        A freshly created destination has no routes and no best route. It is
        garbage collected by the next selection pass if nothing fills it, so
        a caller that interns a destination and then changes its mind does
        not leak a trie node.

        Do not hold a Dest across selection passes: an empty one is removed
        from the trie, and a route offered into a removed Dest would be
        invisible. Call this again instead -- it is one trie descent.

        :param p: the prefix.
        :return: the Dest.
        :raises ValueError: the prefix belongs to another address family.
        """
        cdef TrieNode *n
        cdef Dest d

        if p is None:
            raise ValueError('a prefix is required')
        if p.afi != self.afi:
            raise ValueError('prefix afi %d does not belong in an afi %d '
                             'table' % (p.afi, self.afi))
        n = self.trie.node_intern(&p.addr[0], p.plen)
        d = <Dest>trie_node_value(n)
        if d is None:
            d = Dest(p)
            self.trie.set_value(n, d)
            # Queued on creation, which is what makes the promise above
            # true: reselect only ever visits queued destinations, so a
            # destination interned and then abandoned would otherwise keep
            # its trie node, its place in an ordered walk and its ability
            # to answer an lpm for the life of the table. The pass reports
            # nothing for it -- previous and winner are both None -- so
            # this costs one queue slot and no event.
            self._enqueue(d)
        return d

    cpdef Dest lpm(self, Prefix p):
        """Return the destination of the longest prefix covering ``p``.

        The result can be a destination whose ``best`` is None -- every
        route withdrawn but the selection pass not yet run -- so a caller
        validating reachability must test ``best``, not just the Dest.

        :param p: the prefix to resolve.
        :return: the covering Dest, or None.
        """
        return <Dest>self.trie.lpm(p)

    cpdef Dest lpm_addr(self, bytes addr):
        """Resolve a bare host address, as next-hop validation does.

        :param addr: packed address, 4 or 16 bytes to match the family.
        :return: the covering Dest, or None.
        :raises ValueError: wrong address width for this table.
        """
        return <Dest>self.trie.lpm_addr(addr)

    # --- offers and withdrawals -------------------------------------------

    cpdef int offer(self, Route r) except -1:
        """Offer a route, replacing any previous offer from the same origin.

        Cheap and deliberately incomplete: it updates the destination's
        candidate list and marks it dirty. No selection, no event, no FIB
        write happens here -- that is :meth:`reselect`'s job, under the
        caller's time budget.

        :param r: the candidate route.
        :return: 1 if this replaced an existing offer, 0 if it is new.
        :raises ValueError: no route, or a prefix from another family.
        """
        cdef Dest d
        cdef list routes
        cdef Py_ssize_t i
        cdef Py_ssize_t n

        if r is None:
            raise ValueError('a route is required')
        d = self.dest(r.prefix)
        routes = d.routes
        n = len(routes)
        for i in range(n):
            if (<Route>routes[i]).same_origin(r):
                if _same_content(<Route>routes[i], r):
                    # P-5: an identical re-offer -- a soft refresh, a
                    # reselection that settled on the same path -- is not
                    # a change. Replacing the object made selection see a
                    # new winner (it compares by identity), which meant a
                    # FIB rewrite and a ROUTE_BEST event per prefix for
                    # nothing; keeping the original also keeps its FIB
                    # state and its age.
                    return 1
                routes[i] = r
                self._enqueue(d)
                return 1
        routes.append(r)
        self.route_count += 1
        self._enqueue(d)
        return 0

    cpdef int retract(self, Prefix p, unsigned char protocol,
                      object source) except -1:
        """Withdraw one protocol's offer for a prefix.

        The destination itself survives until the next selection pass, which
        is what lets the pass report the best route going away before the
        entry disappears.

        :param p: the prefix.
        :param protocol: the ``RT_PROTO_*`` id that offered it.
        :param source: the same token that was offered with it.
        :return: 1 if a route was removed, 0 if there was nothing to remove.
        """
        cdef Dest d
        cdef list routes
        cdef Py_ssize_t i
        cdef Py_ssize_t n
        cdef Route r

        d = <Dest>self.trie.get(p)
        if d is None:
            return 0
        routes = d.routes
        n = len(routes)
        for i in range(n):
            r = <Route>routes[i]
            if r.protocol == protocol and r.source is source:
                del routes[i]
                self.route_count -= 1
                self._enqueue(d)
                return 1
        return 0

    cdef int _enqueue(self, Dest d) except -1:
        # The flag is what collapses repeated changes to one selection: a
        # destination already waiting is not queued twice, so a prefix that
        # flaps a thousand times in one batch costs one selection.
        if d.queued:
            return 0
        d.queued = 1
        self._queue.append(d)
        return 0

    # --- selection ---------------------------------------------------------

    cpdef Py_ssize_t pending(self):
        """Return how many destinations are waiting for selection.

        :return: the queue depth. A health metric as much as a loop control:
            a depth that does not fall is the engine failing to keep up.
        """
        return len(self._queue) - self._qhead

    cpdef list reselect(self, Py_ssize_t limit):
        """Re-run selection for up to ``limit`` queued destinations.

        This is the only place a best route changes. Call it repeatedly from
        a deadline-bounded loop -- see ``loop.Batcher`` -- rather than with
        a huge limit: the point of the queue is that the caller, not the
        table, decides how long a single pass may block the event loop.

        Destinations left with no routes at all are dropped here, along with
        their trie node. A destination whose best route went away is
        reported first and removed second, so the caller always sees the
        withdrawal.

        :param limit: maximum destinations to process; 0 or less means
            drain the whole queue.
        :return: the destinations whose best route changed, in the order
            they were queued. Each carries its new ``best``, which is None
            when the last route for the prefix went away.
        """
        cdef list changed = []
        cdef list queue = self._queue
        cdef Py_ssize_t n = len(queue)
        cdef Py_ssize_t done = 0
        cdef Dest d
        cdef Route previous
        cdef Route winner

        while self._qhead < n and (limit <= 0 or done < limit):
            d = <Dest>queue[self._qhead]
            self._qhead += 1
            done += 1
            d.queued = 0
            previous = d.best
            winner = d._select()
            if winner is not previous:
                self.version += 1
                d.best = winner
                d.version = self.version
                if winner is not None:
                    winner.version = self.version
                changed.append(d)
            if winner is None and len(d.routes) == 0:
                # Nothing offers this prefix any more. Removing the trie
                # node is what keeps a table that has seen a million
                # transient prefixes from staying a million nodes wide.
                self.trie.remove(d.prefix)

        # Compaction, not a pop per item: len() is re-read because a change
        # callback or another plugin may have queued more work while this
        # pass ran, and those entries must not be dropped.
        if self._qhead >= len(queue):
            del queue[:]
            self._qhead = 0
        elif self._qhead > 1024:
            del queue[:self._qhead]
            self._qhead = 0
        return changed

    # --- views -------------------------------------------------------------

    def __len__(self):
        return self.trie.size()

    def __iter__(self):
        """Iterate destinations in ascending prefix order."""
        return iter(self.trie.values())

    def items(self):
        """Iterate ``(Prefix, Dest)`` in ascending prefix order."""
        return self.trie.items()

    def prefixes(self):
        """Iterate prefixes in ascending prefix order."""
        return iter(self.trie)

    def stats(self):
        """Return counters for health and benchmark reporting.

        :return: a dict of plain ints.
        """
        return {
            'afi': self.afi,
            'safi': self.safi,
            'prefixes': self.trie.size(),
            'routes': self.route_count,
            'nodes': self.trie.nodes,
            'pending': self.pending(),
            'version': self.version,
        }

    def __repr__(self):
        return '<RouteTable afi=%d safi=%d prefixes=%d routes=%d>' % (
            self.afi, self.safi, self.trie.size(), self.route_count)


cdef int route_cmp(Route a, Route b) nogil:
    # Declared in table.pxd; see there for why this is the ordering.
    #
    # Metric is compared only after administrative distance, because a
    # metric means something different to every protocol: an OSPF cost and a
    # BGP MED are not on the same scale, and comparing them across
    # protocols would be arithmetic on unrelated units. Administrative
    # distance is the operator's statement of which protocol to believe, so
    # it has to come first.
    if a.admin_distance != b.admin_distance:
        return -1 if a.admin_distance < b.admin_distance else 1
    if a.metric != b.metric:
        return -1 if a.metric < b.metric else 1
    if a.protocol != b.protocol:
        return -1 if a.protocol < b.protocol else 1
    if a.recv_time != b.recv_time:
        # Oldest wins, which keeps an established route in place rather than
        # letting a newly learned equal route churn the FIB.
        return -1 if a.recv_time < b.recv_time else 1
    return 0


def _addr_to_str(bytes addr):
    """Render a packed address for show output.

    Kept private: the only thing in the RIB that renders a bare address is
    show output, and Prefix already owns the prefix form.

    :param addr: 4 or 16 packed bytes.
    :return: the text form, or a hex fallback for an unexpected width.
    """
    if addr is None:
        return ''
    if len(addr) == 4:
        return socket.inet_ntop(socket.AF_INET, addr)
    if len(addr) == 16:
        return socket.inet_ntop(socket.AF_INET6, addr)
    return addr.hex()
