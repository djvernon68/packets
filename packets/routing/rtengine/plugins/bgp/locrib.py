# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The BGP Loc-RIB: BGP decides first, the engine arbitrates afterwards.

This is the BGP plugin's own table, one instance per ``(afi, safi)``,
sitting between the peers and the engine's protocol-neutral ``GlobalRib``.
Peers put paths in through :meth:`LocRib.add_path` and take them out through
:meth:`LocRib.remove_path`; the engine sees, at most, one winning ``Route``
per prefix.

**Why the protocol runs its own selection.** The ``GlobalRib`` compares
candidate routes by administrative distance, then metric, then protocol
preference, then age. That is everything two *different* protocols have in
common and nothing more: it knows nothing about AS paths, local preference,
MEDs, communities, route reflection or ADD-PATH. If BGP offered it every
path it holds for a prefix, the core would arbitrate between paths of one
protocol on criteria that are not the ones BGP uses -- a path with a shorter
AS path and a higher MED would lose to a path the BGP decision process
prefers, and the two routers in a pair could disagree about which of their
own paths to use. So the plugin runs the full decision process here, over
``bestpath.BgpDest``, and hands the core exactly one winner per prefix. The
same split is what keeps the core free of protocol specifics: OSPF and RIP
plug in the same way, each with its own selection, and ``rib/table.pyx``
never learns what any of them are.

**Why offers are queued rather than applied.** An update that touches a
prefix only updates that prefix's path list and marks the destination dirty;
:meth:`LocRib.reselect` is what runs the decision process and talks to the
``GlobalRib``, and it stops after ``limit`` destinations. This is the same
device, for the same reason, as the change queue in
``rib/table.pyx``: a full-table load is a million destinations and a single
unbounded selection pass over them would hold the event loop long enough to
miss a KEEPALIVE and lose the sessions that are still loading. It also
collapses work -- a prefix that flaps a thousand times inside one batch is
selected once, because a destination already waiting is not queued twice.

**Why every intern is paired with a release.** Path attributes are interned
in a shared ``attrs.AttrTable`` (Key Decision 3, FRR's ``attrhash`` model):
a million-path table holds only tens of thousands of distinct attribute
sets, so the paths share them and hold a reference each. That only works if
the references are balanced. Every place a path leaves this table --
replaced by a re-advertisement, withdrawn, dropped with its peer, or cleared
at shutdown -- releases that path's set, which is precisely why
``BgpDest.add`` returns the path it replaced and ``BgpDest.remove`` returns
the path it removed. An unpaired intern is not a slow leak either: a peer
flapping one prefix leaks one set per update.

**Storage.** Destinations live in a dict keyed by ``Prefix``, not in a
``Trie``. The Loc-RIB is only ever looked up by exact prefix; longest-prefix
matching is next-hop resolution, and that question is asked of the
``GlobalRib``, which is what knows about connected and static routes as well
as BGP ones. A dict is the cheaper structure for exact match, and ``Prefix``
caches its hash for exactly this use.

**Independently testable.** ``global_rib`` may be None, in which case
selection still runs and the winners are still tracked -- the table simply
has nowhere to publish them. That is not only for tests: it is what lets a
Loc-RIB exist before the engine has finished wiring itself up.
"""

import time

from packets.routing.rtengine.events import ROUTE_BEST, ROUTE_WITHDRAW
from packets.routing.rtengine.health import DEGRADED, OK
from packets.routing.rtengine.plugins.bgp.bestpath import (BgpDest, BgpPath,
                                                           SRC_PEER)
from packets.routing.rtengine.rib.table import PROTO_BGP, Route

# Bound once rather than looked up per path. Monotonic, like everything else
# that times route state: the age tie-break must not reorder paths because
# ntp stepped the wall clock or the machine was suspended.
_monotonic = time.monotonic

#: The default source code for a path this table is given. Spelled here so
#: a caller does not have to import ``bestpath`` for the common case; it is
#: the ``PATH_SRC_PEER`` of ``bestpath.pxd`` under its Python-visible name.
PATH_SRC_PEER = SRC_PEER

#: Cisco/FRR conventional administrative distances for BGP, and the
#: defaults of :class:`LocRib`. ``distance bgp`` overrides them; they are
#: kept apart because trusting an iBGP path as much as an eBGP one makes a
#: route reflector's clients prefer each other's copies of a route over the
#: eBGP path it came in on.
DEFAULT_DISTANCE_EBGP = 20
DEFAULT_DISTANCE_IBGP = 200


class LocRib(object):
    """The BGP plugin's table for one address family, and its winners.

    Not thread-safe and not meant to be: every method runs on the engine's
    loop thread, like the rest of the plugin.

    No per-prefix or per-peer Python object is defined here on purpose. A
    destination is a ``bestpath.BgpDest`` and a path is a
    ``bestpath.BgpPath``, both C extension types with no instance
    dictionary, and the per-peer index below holds dicts of those rather
    than wrapper objects -- which is the same economy ``__slots__`` buys,
    taken one step further.

    :param afi: IANA address family number; 1 for IPv4, 2 for IPv6. Every
        prefix offered to this table must match it.
    :param safi: subsequent address family identifier, 1 for unicast. Not
        interpreted here beyond keying the ``GlobalRib`` table the winners
        go to.
    :param attr_table: the shared :class:`attrs.AttrTable`. Shared across
        every Loc-RIB and every peer in the plugin, because the point of
        interning is that two address families advertising the same
        attributes hold one copy between them.
    :param config: the :class:`bestpath.BestpathConfig` the decision
        process runs with. Held by reference, so a configuration commit
        that builds a new one must hand it over and mark the affected
        destinations dirty.
    :param global_rib: the engine's
        :class:`~packets.routing.rtengine.rib.globalrib.GlobalRib`, or None
        to run without publishing anything.
    :param events: the :class:`~packets.routing.rtengine.events.EventBus`,
        or None. See :meth:`reselect` for what is published and when.
    :param admin_distance_ebgp: distance offered for a winning eBGP path.
    :param admin_distance_ibgp: distance offered for a winning iBGP path.
    :raises ValueError: no attribute table or no best-path configuration.
        Both are programming errors: a Loc-RIB without them cannot intern
        an attribute set or select a path, and failing at construction is
        better than failing on the first update.
    """

    def __init__(self, afi, safi, attr_table, config, global_rib=None,
                 events=None, admin_distance_ebgp=DEFAULT_DISTANCE_EBGP,
                 admin_distance_ibgp=DEFAULT_DISTANCE_IBGP):
        if attr_table is None:
            raise ValueError('a Loc-RIB needs the shared AttrTable')
        if config is None:
            raise ValueError('a Loc-RIB needs a BestpathConfig')

        self.afi = afi
        self.safi = safi
        self.attr_table = attr_table
        self.config = config
        self.global_rib = global_rib
        self.events = events
        self.admin_distance_ebgp = admin_distance_ebgp
        self.admin_distance_ibgp = admin_distance_ibgp

        # Prefix -> BgpDest. See the module docstring for why this is not a
        # trie.
        self._dests = {}
        # PeerRef -> {Prefix: BgpDest}: the destinations one session
        # contributes to. See remove_peer for why it is worth maintaining.
        self._by_peer = {}
        # next-hop bytes -> {Prefix: BgpDest}, and next-hop bytes ->
        # (resolved, igp_metric): the next-hop tracking index. See
        # revalidate() for what it buys and why it is pruned lazily.
        self._nh_dests = {}
        self._nh_state = {}
        # The prefixes currently offered to the GlobalRib. Kept so a
        # retraction is only sent for something that was actually offered,
        # and so clear() can take back exactly what it put there.
        self._offered = set()
        # A list plus a head index rather than a deque, copied from
        # RouteTable: the drain is a bulk slice at the end of a pass rather
        # than a pop per destination.
        self._queue = []
        self._qhead = 0

        self.path_count = 0
        self.version = 0
        self.selections = 0
        self.offers = 0
        self.retractions = 0
        # Winners this table could not turn into a Route. Counted rather
        # than raised -- see _offer -- and reported by health() because a
        # non-zero value means some prefix is missing from the forwarding
        # plane.
        self.offer_errors = 0
        # Winners kept out of the core because they are our own (L-7).
        self.local_unoffered = 0

    def set_config(self, config):
        """Adopt new decision-process knobs, reselecting if they changed.

        The plugin rebuilds its :class:`bestpath.BestpathConfig` on every
        commit, but a Loc-RIB that already existed kept the one it was
        constructed with -- so ``always-compare-med``, ``deterministic-med``
        or the default local preference, changed on a running router, did
        nothing until a restart. Every destination is requeued when the
        knobs differ, because any of them can change any winner.

        :param config: the new :class:`bestpath.BestpathConfig`.
        :return: the number of destinations requeued; 0 when nothing that
            selection reads has changed.
        """
        if config is None or config is self.config:
            return 0
        if self.config is not None and \
                config.as_dict() == self.config.as_dict():
            self.config = config
            return 0
        self.config = config
        for d in self._dests.values():
            self._enqueue(d)
        return len(self._dests)

    # --- lookups -----------------------------------------------------------

    def get(self, prefix):
        """Return the destination for a prefix, or None.

        The read-only lookup: nothing is created and nothing is marked
        dirty, so ``show`` and next-hop tracking can ask about a prefix
        without bringing it into existence.

        :param prefix: the :class:`Prefix` to look up.
        :return: the :class:`bestpath.BgpDest`, or None if no path is held
            for it.
        """
        return self._dests.get(prefix)

    def dest(self, prefix):
        """Return the destination for a prefix, creating it if needed.

        The write path's lookup. A destination created here holds no paths
        and no winner yet; it becomes visible to selection when something
        marks it dirty.

        :param prefix: the :class:`Prefix`.
        :return: the :class:`bestpath.BgpDest`.
        :raises ValueError: no prefix, or a prefix from another address
            family. A family mismatch is a wiring error in the caller --
            the decoder picks the Loc-RIB by the NLRI's family -- and
            silently accepting it would put IPv6 routes in the IPv4 table.
        """
        if prefix is None:
            raise ValueError('a prefix is required')
        if prefix.afi != self.afi:
            raise ValueError('prefix %s is afi %d, this Loc-RIB is afi %d'
                             % (prefix.to_str(), prefix.afi, self.afi))
        d = self._dests.get(prefix)
        if d is None:
            d = BgpDest(prefix)
            self._dests[prefix] = d
        return d

    def paths_for(self, prefix):
        """Return every path held for a prefix.

        :param prefix: the :class:`Prefix`.
        :return: a new list of :class:`bestpath.BgpPath`, empty if the
            prefix is not held. A copy, because the destination's own list
            is mutated in place by ``add`` and ``remove`` and a caller
            iterating it across an update would see the table change under
            it.
        """
        d = self._dests.get(prefix)
        if d is None:
            return []
        return list(d.paths)

    # --- the peer-facing surface -------------------------------------------

    def add_path(self, peer_ref, prefix, attrs, path_id=0, weight=0,
                 source=SRC_PEER, igp_metric=0, recv_time=None,
                 resolved=True, keep_age=False):
        """Take one path for one prefix, replacing the peer's previous one.

        The whole of an UPDATE's effect on one NLRI. It interns the
        attribute set through the shared table, builds the path, hands it
        to the destination and marks the destination dirty. It deliberately
        does *not* select: a peer sending a full table would otherwise run
        the decision process a million times inside one read, which is
        exactly the unbounded pass the change queue exists to prevent.

        The interning discipline lives here. The set the caller passes is a
        candidate; what the path keeps is whatever
        :meth:`attrs.AttrTable.intern` returned, which is usually a set
        some other path is already using. If this path replaced one --
        which is what a re-advertisement of a prefix the peer already sent
        looks like, since a path's identity is ``(peer, path_id)`` and not
        its attributes -- the replaced path's set is released here.
        ``BgpDest.add`` returns that path precisely so this can happen; not
        doing it is the leak that makes the shared table grow without bound
        on a flapping peer.

        :param peer_ref: the :class:`bestpath.PeerRef` the path arrived
            through, shared by every path from that session.
        :param prefix: the :class:`Prefix` advertised.
        :param attrs: the finalised :class:`attrs.AttrSet`, interned here.
        :param path_id: RFC 7911 path identifier; 0 without ADD-PATH, which
            collapses the identity to the peer.
        :param weight: Cisco-style local weight, highest wins first.
        :param source: one of the ``bestpath`` source codes; defaults to a
            path learned from a peer.
        :param igp_metric: cost to reach the next hop, from next-hop
            tracking.
        :param recv_time: monotonic arrival time; None means now.
        :param resolved: whether the next hop currently resolves. An
            unresolved path stays in the table and takes part in no
            comparison until resolution says otherwise.
        :param keep_age: a replay of a path already held -- a soft inbound
            reset re-running policy -- rather than a new arrival. The path
            it replaces keeps its arrival time, so the oldest-eBGP
            tie-break is not handed to whichever peer was replayed last
            (B-9). A path not already held takes ``recv_time`` as usual.
        :return: True if the table changed, which it always does -- the
            return type matches :meth:`remove_path` so a caller can count
            changes across a mixed batch of announcements and withdrawals
            without special-casing either.
        :raises ValueError: no peer, no prefix, no attributes, or a prefix
            from another family. All four are programming errors; nothing
            a peer can put on the wire reaches them, because the decoder
            has already turned the wire into these objects or rejected it.
        """
        if peer_ref is None:
            raise ValueError('a path needs the PeerRef it arrived through')
        if attrs is None:
            raise ValueError('a path needs an attribute set')

        d = self.dest(prefix)
        if recv_time is None:
            recv_time = _monotonic()
        if keep_age:
            for held in d.paths:
                if held.peer is peer_ref and held.path_id == path_id:
                    recv_time = held.recv_time
                    break
        interned = self.attr_table.intern(attrs)
        path = BgpPath(interned, peer_ref, path_id, weight, source,
                       igp_metric, recv_time, resolved)
        replaced = d.add(path)
        if replaced is None:
            self.path_count += 1
        else:
            # One release for one intern. The replaced path is gone from
            # the destination and nothing else holds its claim.
            self.attr_table.release(replaced.attrs)
            if replaced.attrs.nexthop != interned.nexthop:
                self._unindex_nexthop(replaced.attrs.nexthop, d)
        self._index_add(peer_ref, d)
        self._index_nexthop(interned.nexthop, d, resolved, igp_metric)
        self._enqueue(d)
        return True

    def remove_path(self, peer_ref, prefix, path_id=0):
        """Withdraw one peer's path for one prefix.

        A WITHDRAWN_ROUTES entry, or one NLRI of an MP_UNREACH. Releases
        the removed path's attribute set and marks the destination dirty so
        the next pass can offer a new winner or retract the prefix.

        The destination is dropped from the table as soon as its last path
        goes, rather than being left empty until the next pass. A table
        that has seen a million transient prefixes should not stay a
        million entries wide, and the pending retraction does not need the
        entry: the queued destination still carries its prefix and its
        outgoing best path, which is all :meth:`reselect` needs to take the
        route back out of the ``GlobalRib``.

        :param peer_ref: the withdrawing session's
            :class:`bestpath.PeerRef`.
        :param prefix: the :class:`Prefix` withdrawn.
        :param path_id: RFC 7911 path identifier; 0 without ADD-PATH.
        :return: True if a path was removed, False if there was none. A
            withdrawal for something never advertised is normal on a
            session that is being torn down and is not an error.
        """
        if peer_ref is None or prefix is None:
            return False
        d = self._dests.get(prefix)
        if d is None:
            return False
        path = d.remove(peer_ref, path_id)
        if path is None:
            return False

        self.path_count -= 1
        self.attr_table.release(path.attrs)
        if not self._peer_has(peer_ref, d):
            self._index_remove(peer_ref, prefix)
        self._enqueue(d)
        if not d.paths:
            del self._dests[prefix]
        self._unindex_nexthop(path.attrs.nexthop, d)
        return True

    def remove_peer(self, peer_ref):
        """Withdraw every path one session contributed.

        The teardown path: a session that goes down takes its whole
        contribution with it, and on a full-table peer that is a million
        paths.

        It walks a per-peer index of the destinations that peer contributes
        to rather than the table itself. Walking the table would be
        proportional to the number of prefixes the *engine* holds rather
        than to the number this peer sent, which is the wrong cost in both
        directions: a peer with ten prefixes in a million-prefix table
        would pay for the million, and a router with several peers would
        pay for the whole table once per session on a reset. The index
        costs one dict entry per ``(peer, prefix)`` pair, which is the same
        order as the paths it tracks, and it is maintained on the add and
        remove paths where the destination is already in hand.

        Each path's attribute set is released before the paths go, because
        ``BgpDest.remove_peer`` reports only how many it dropped; the paths
        themselves have to be read out of the destination first.

        :param peer_ref: the departing session's
            :class:`bestpath.PeerRef`.
        :return: the number of paths removed.
        """
        if peer_ref is None:
            return 0
        contributed = self._by_peer.pop(peer_ref, None)
        if not contributed:
            return 0

        release = self.attr_table.release
        removed = 0
        for prefix, d in contributed.items():
            nexthops = []
            for path in d.paths:
                if path.peer is peer_ref:
                    release(path.attrs)
                    nexthops.append(path.attrs.nexthop)
            gone = d.remove_peer(peer_ref)
            if not gone:
                continue
            removed += gone
            self.path_count -= gone
            self._enqueue(d)
            if not d.paths:
                # Only this peer contributed, so no other peer's index
                # entry can be pointing at this destination.
                if self._dests.get(prefix) is d:
                    del self._dests[prefix]
            for nexthop in nexthops:
                self._unindex_nexthop(nexthop, d)
        return removed

    # --- next-hop tracking --------------------------------------------------

    def _index_nexthop(self, nexthop, d, resolved, igp_metric):
        """Record that a destination depends on a next hop.

        :param nexthop: the packed next-hop bytes.
        :param d: the destination.
        :param resolved: the resolution state the caller just established.
        :param igp_metric: the cost the caller just established.
        """
        if not nexthop:
            return
        dests = self._nh_dests.get(nexthop)
        if dests is None:
            dests = {}
            self._nh_dests[nexthop] = dests
        dests[d.prefix] = d
        # Seed the cached answer from the caller, which has just asked the
        # resolver about this next hop. Without it the first revalidation
        # would see "no previous answer", decide everything had changed
        # and requeue the whole table for nothing.
        self._nh_state[nexthop] = (bool(resolved), igp_metric)

    def _unindex_nexthop(self, nexthop, d):
        """Forget that a destination depends on a next hop, if it no longer
        does (B-3).

        The reverse index used to be pruned only when a destination left
        the table altogether. A destination that stayed but moved to a new
        next hop -- the ordinary result of a peer re-advertising with a
        different NEXT_HOP, or of next-hop churn upstream -- stayed filed
        under every next hop it had ever had, so the index grew without
        bound and revalidation re-tested next hops nothing used.

        :param nexthop: the packed next-hop bytes the destination may have
            stopped using.
        :param d: the destination.
        """
        if not nexthop:
            return
        dests = self._nh_dests.get(nexthop)
        if dests is None or dests.get(d.prefix) is not d:
            return
        if self._dests.get(d.prefix) is d:
            for path in d.paths:
                if path.attrs.nexthop == nexthop:
                    return
        del dests[d.prefix]
        if not dests:
            del self._nh_dests[nexthop]
            self._nh_state.pop(nexthop, None)

    def nexthop_index_size(self):
        """Return ``(next hops, destination entries)`` in the reverse index.

        :return: a pair of ints, for health output and the B-3 test.
        """
        return (len(self._nh_dests),
                sum(len(v) for v in self._nh_dests.values()))

    def revalidate(self, check):
        """Re-test every distinct next hop and requeue what changed.

        Next-hop tracking, and the reason it is affordable. Reachability
        is a property of a *next hop*, not of a path: a full table from
        one upstream shares one next hop, and a million paths in this
        table point at a few thousand of them at most. So a routing change
        costs one resolver lookup per distinct next hop, and only the
        destinations behind a next hop whose answer actually changed are
        touched. Walking the paths instead would make every selection pass
        O(table), which is the one thing the change queue exists to
        prevent.

        The index is pruned here rather than on the withdrawal path.
        Keeping it exact would mean, on every path removal, asking whether
        any *other* path of that destination still uses the same next hop
        -- a scan on the hot path to save memory proportional to the
        number of distinct next hops, which is the wrong trade. A stale
        entry costs one wasted lookup and is dropped the first time this
        runs.

        :param check: a callable ``(afi, nexthop) -> (resolved, metric)``.
        :return: the number of destinations requeued.
        """
        changed = 0
        for nexthop in list(self._nh_dests):
            dests = self._nh_dests[nexthop]
            answer = check(self.afi, nexthop)
            resolved = bool(answer[0])
            metric = answer[1]
            if self._nh_state.get(nexthop) == (resolved, metric):
                # Still prune, even when the answer has not moved: a
                # destination that has gone leaves an entry here that
                # would otherwise be revisited for the life of the
                # process.
                self._prune_nexthop(nexthop, dests)
                continue
            self._nh_state[nexthop] = (resolved, metric)
            for prefix in list(dests):
                d = dests[prefix]
                if self._dests.get(prefix) is not d:
                    del dests[prefix]
                    continue
                touched = False
                for path in d.paths:
                    if path.attrs.nexthop != nexthop:
                        continue
                    if path.resolved != resolved \
                            or path.igp_metric != metric:
                        path.resolved = resolved
                        path.igp_metric = metric
                        touched = True
                if touched:
                    self._enqueue(d)
                    changed += 1
            self._prune_nexthop(nexthop, dests)
        return changed

    def _prune_nexthop(self, nexthop, dests):
        """Drop index entries for destinations that have gone, or that no
        longer use this next hop."""
        for prefix in list(dests):
            d = dests[prefix]
            if self._dests.get(prefix) is not d:
                del dests[prefix]
                continue
            for path in d.paths:
                if path.attrs.nexthop == nexthop:
                    break
            else:
                del dests[prefix]
        if not dests:
            del self._nh_dests[nexthop]
            self._nh_state.pop(nexthop, None)

    # --- the change queue --------------------------------------------------

    def _enqueue(self, d):
        """Mark a destination dirty, once.

        The flag on the destination is what collapses repeated changes into
        one selection: a destination already waiting is not queued a second
        time, so a prefix that flaps a thousand times inside one batch
        costs one run of the decision process instead of a thousand.

        :param d: the :class:`bestpath.BgpDest` that changed.
        """
        if d.queued:
            return
        d.queued = 1
        self._queue.append(d)

    def pending(self):
        """Return how many destinations are waiting for selection.

        A health metric as much as a loop control: a depth that does not
        fall between passes is the plugin failing to keep up with what its
        peers are sending.

        :return: the queue depth.
        """
        return len(self._queue) - self._qhead

    def reselect(self, limit):
        """Run the decision process for up to ``limit`` dirty destinations.

        This is the only place a BGP best path changes and the only place
        this table talks to the ``GlobalRib``. Call it repeatedly from a
        deadline-bounded loop -- see :meth:`select_step` and
        ``loop.Batcher`` -- rather than with a huge limit: the point of the
        queue is that the caller, which is the only thing that knows how
        much of the loop's time it may spend, decides how long one pass
        runs. This is the function that makes the claim in the module
        docstring true, and it is bounded exactly the way
        ``RouteTable.reselect`` is bounded, down to the queue compaction.

        For each destination whose winner changed, the new winner is
        offered to the ``GlobalRib`` and a destination that has lost its
        last path, or whose best has become unresolvable, is retracted.
        Destinations that were emptied and selected are dropped here too,
        as a backstop for the removal :meth:`remove_path` has normally
        already done.

        Events are published only when there is no ``GlobalRib`` to publish
        them. With one attached, the core emits ``route-best`` and
        ``route-withdraw`` from its own selection pass -- after it has
        chosen between protocols, which is the answer a subscriber wants --
        and emitting them here as well would report every BGP prefix twice
        and report it before the core had agreed.

        :param limit: maximum destinations to process; 0 or less drains the
            whole queue, which is only safe for tests and for start-up.
        :return: the destinations whose best path changed, in the order
            they were queued. Each carries its new ``best``, which is None
            when the prefix has no usable path left.
        """
        changed = []
        queue = self._queue
        n = len(queue)
        done = 0

        while self._qhead < n and (limit <= 0 or done < limit):
            d = queue[self._qhead]
            self._qhead += 1
            done += 1
            d.queued = 0
            previous = d.best
            d.reselect(self.config)
            self.selections += 1
            winner = d.best
            if winner is not previous:
                self.version += 1
                changed.append(d)
                if winner is None or not winner.resolved:
                    self._retract(d.prefix)
                else:
                    self._offer(d, winner)
            if winner is None and not d.paths:
                if self._dests.get(d.prefix) is d:
                    del self._dests[d.prefix]

        # Compaction, not a pop per destination. len() is re-read rather
        # than reusing `n`, because offering a route can mark more work
        # dirty and those entries must not be discarded with the drained
        # ones.
        if self._qhead >= len(queue):
            del queue[:]
            self._qhead = 0
        elif self._qhead > 1024:
            del queue[:self._qhead]
            self._qhead = 0
        return changed

    def select_step(self, chunk):
        """Run one bounded chunk of selection, for a ``Batcher``.

        The step-function shape ``loop.Batcher.drain`` expects, and the
        same one ``GlobalRib.select_step`` has: it reports how many
        destinations were *examined*, not how many changed, because a pass
        over a thousand destinations that changes none of them has still
        done a thousand destinations' worth of work and a step reporting 0
        would tell the batcher it had finished when it had not.

        :param chunk: maximum destinations to examine.
        :return: destinations examined; 0 when the queue is empty.
        """
        before = self.pending()
        if not before:
            return 0
        self.reselect(chunk)
        return before - self.pending()

    # --- publication to the core --------------------------------------------

    def _offer(self, d, path):
        """Offer one winning path to the ``GlobalRib`` as a ``Route``.

        The translation from a BGP path to something the core understands,
        and the only place in the plugin that performs it. Everything
        BGP-specific is dropped on the way across: what survives is a
        next hop, an administrative distance and a metric.

        The distance is chosen by whether the winner is an eBGP or an iBGP
        path, because that is the distinction operators configure and the
        one that decides whether a learned route beats a static one. The
        metric is the MED, the only BGP number that is a cost at all -- and
        it is only ever compared by the core against another BGP route's
        metric, since ``route_cmp`` reaches the metric only after the
        distances are equal.

        A ``Route`` that cannot be built is counted, not raised. The only
        way that happens is a next hop of some width other than 4 or 16
        bytes, which would have to have come off the wire, and a decoder
        defect must not take down the selection pass for every other
        prefix. The prefix is retracted instead, so the core is never left
        believing in a route this table can no longer describe.

        Only paths learned from a neighbour are offered (L-7). A ``network``
        statement, an aggregate or a redistributed route is BGP's copy of
        something that is already in the core under its own protocol --
        IOS will not even originate a ``network`` that is not -- and it
        has no gateway: offered, it reached the kernel as a route via
        ``0.0.0.0``, which the kernel refuses with ENODEV, and left health
        degraded for as long as the statement was configured. It is still
        BGP's best path and is still advertised; it is simply not a
        forwarding entry.

        :param d: the destination.
        :param path: its winning :class:`bestpath.BgpPath`.
        :return: True if the route was offered.
        """
        if path.source != SRC_PEER:
            self.local_unoffered += 1
            self._retract(d.prefix)
            return False
        attrs = path.attrs
        if path.peer.is_ebgp:
            distance = self.admin_distance_ebgp
        else:
            distance = self.admin_distance_ibgp
        try:
            route = Route(d.prefix, PROTO_BGP, distance,
                          attrs.med if attrs.has_med() else 0,
                          attrs.nexthop, self,
                          path.recv_time if path.recv_time > 0.0 else -1.0)
        except ValueError:
            self.offer_errors += 1
            self._retract(d.prefix)
            return False

        self._offered.add(d.prefix)
        self.offers += 1
        if self.global_rib is not None:
            self.global_rib.offer(route, self.safi)
        elif self.events is not None:
            self.events.publish(ROUTE_BEST, {
                'afi': self.afi, 'safi': self.safi,
                'prefix': d.prefix.to_str(),
                'route': path.as_dict(),
                'previous': None,
                'version': self.version,
            })
        return True

    def _retract(self, prefix):
        """Take a prefix back out of the ``GlobalRib``.

        Retracting something never offered is a no-op rather than an
        error: a destination can lose its last path in the same batch that
        created it, and a prefix whose only path was unresolved never
        reached the core at all.

        :param prefix: the :class:`Prefix` to withdraw.
        :return: True if something was withdrawn.
        """
        if prefix not in self._offered:
            return False
        self._offered.discard(prefix)
        self.retractions += 1
        if self.global_rib is not None:
            self.global_rib.retract(prefix, PROTO_BGP, self, self.safi)
        elif self.events is not None:
            self.events.publish(ROUTE_WITHDRAW, {
                'afi': self.afi, 'safi': self.safi,
                'prefix': prefix.to_str(),
            })
        return True

    # --- the per-peer index -------------------------------------------------

    def _index_add(self, peer_ref, d):
        """Record that a peer contributes to a destination."""
        contributed = self._by_peer.get(peer_ref)
        if contributed is None:
            contributed = {}
            self._by_peer[peer_ref] = contributed
        contributed[d.prefix] = d

    def _index_remove(self, peer_ref, prefix):
        """Forget that a peer contributes to a destination."""
        contributed = self._by_peer.get(peer_ref)
        if contributed is None:
            return
        contributed.pop(prefix, None)
        if not contributed:
            del self._by_peer[peer_ref]

    def _peer_has(self, peer_ref, d):
        """Return whether a peer still has any path in a destination.

        Asked after an ADD-PATH withdrawal, where one of a peer's several
        paths for a prefix went but the others may remain. A scan of the
        destination's path list, because a destination holds one path per
        peer in the ordinary case and a handful with ADD-PATH; a second
        index keyed by ``(peer, prefix)`` would cost more to maintain than
        this costs to read.

        :param peer_ref: the peer.
        :param d: the destination.
        :return: True if the peer still contributes a path.
        """
        for path in d.paths:
            if path.peer is peer_ref:
                return True
        return False

    # --- shutdown ------------------------------------------------------------

    def clear(self):
        """Drop every destination, releasing every interned attribute set.

        The plugin's shutdown path, and the one that proves the interning
        discipline: after a clear, the shared ``AttrTable`` holds nothing
        this table put there, so an engine that starts a BGP plugin,
        loads a full table and stops it returns to the count it began with.
        A ``clear`` that only dropped the dicts would leave the shared
        table holding every attribute set the session ever saw.

        Routes already offered are retracted rather than abandoned. The
        core retracts nothing on a plugin's behalf -- see
        ``ProtocolPlugin.stop`` -- so a plugin that forgot them would leave
        them in the ``GlobalRib`` and, with install on, in the kernel.

        :return: the number of paths dropped.
        """
        release = self.attr_table.release
        dropped = 0
        for d in self._dests.values():
            for path in d.paths:
                release(path.attrs)
                dropped += 1
            d.queued = 0
        for prefix in list(self._offered):
            self._retract(prefix)

        self._dests = {}
        self._by_peer = {}
        self._nh_dests = {}
        self._nh_state = {}
        self._offered = set()
        self._queue = []
        self._qhead = 0
        self.path_count = 0
        return dropped

    # --- views -------------------------------------------------------------

    def __len__(self):
        return len(self._dests)

    def __iter__(self):
        """Iterate destinations in ascending prefix order.

        Sorted rather than in dict order, so ``show ip bgp`` and a paged
        API walk agree with each other and with a second request made after
        the table changed. The sort is O(n log n) over the whole table and
        is affordable only because nothing on the update or selection path
        iterates: those reach a destination by key.

        :return: an iterator over :class:`bestpath.BgpDest`.
        """
        dests = self._dests
        return iter([dests[p] for p in sorted(dests)])

    def __contains__(self, prefix):
        return prefix in self._dests

    def stats(self):
        """Return counters for health and show output.

        :return: a dict of plain, JSON-serialisable types. The keys are
            stable: the health document and the benchmark harness both read
            them, so they are part of this module's interface rather than
            an incidental rendering.
        """
        return {
            'afi': self.afi,
            'safi': self.safi,
            'destinations': len(self._dests),
            'paths': self.path_count,
            'peers': len(self._by_peer),
            'dirty': self.pending(),
            'selections': self.selections,
            'offers': self.offers,
            'retractions': self.retractions,
            'offered': len(self._offered),
            'offer-errors': self.offer_errors,
            'local-unoffered': self.local_unoffered,
            'version': self.version,
            'next-hops': len(self._nh_dests),
            'next-hops-unresolved': sum(
                1 for state in self._nh_state.values() if not state[0]),
            'attrs': self.attr_table.stats(),
        }

    def health(self):
        """Report this table's contribution to the plugin's health.

        Degraded only on an offer that could not be built, because that is
        the one condition this table can detect on its own that means the
        engine's picture is wrong: a prefix BGP has chosen a path for that
        the core was never told about. A deep queue is deliberately *not* a
        degradation -- a full-table load is supposed to produce one, and
        whether the engine is keeping up is answered by the loop-lag
        measurement in ``health.py``, which measures the symptom rather
        than guessing at a cause.

        :return: a dict of plain types, including a ``status`` of ``ok`` or
            ``degraded``, for merging into the plugin's health document.
        """
        doc = self.stats()
        doc['status'] = DEGRADED if self.offer_errors else OK
        return doc

    def __repr__(self):
        return '<LocRib afi=%d safi=%d dests=%d paths=%d dirty=%d>' % (
            self.afi, self.safi, len(self._dests), self.path_count,
            self.pending())
