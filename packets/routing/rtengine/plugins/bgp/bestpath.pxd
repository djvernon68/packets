# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint32_t, uint64_t

from packets.routing.rtengine.rib.prefix cimport Prefix
from packets.routing.rtengine.plugins.bgp.attrs cimport AttrSet


# --- Where a path came from -------------------------------------------------
# Step 3 of the decision process prefers a locally sourced path over a
# learned one, and prefers them in this order. The numeric order IS the
# preference order, the same convention rib/table.pxd uses for protocol ids.

cdef enum:
    PATH_SRC_LOCAL = 0        # `network` statement or a static local route
    PATH_SRC_AGGREGATE = 1    # produced by aggregation
    PATH_SRC_REDIST = 2       # redistributed from another protocol
    PATH_SRC_PEER = 3         # learned from a BGP neighbour


# --- Which comparison decided ------------------------------------------------
# Every comparison reports the step that settled it. That is not
# instrumentation for its own sake: "why is this path best" is the single
# most common operational question about BGP, `show ip bgp <prefix>` is
# expected to answer it, and a selector that only returns a winner cannot.
#
# The numbering is the canonical decision-process order, so a lower step
# number is an earlier and more decisive reason.

cdef enum:
    STEP_NONE = 0             # indistinguishable on every criterion
    STEP_RESOLVED = 1         # only one path has a usable next hop
    STEP_WEIGHT = 2
    STEP_LOCAL_PREF = 3
    STEP_ORIGINATED = 4
    STEP_AS_PATH = 5
    STEP_ORIGIN = 6
    STEP_MED = 7
    STEP_EXTERNAL = 8         # eBGP beats iBGP
    STEP_IGP_METRIC = 9
    STEP_AGE = 10             # older eBGP path wins
    STEP_ROUTER_ID = 11
    STEP_CLUSTER_LIST = 12
    STEP_PEER_ADDR = 13


cdef class PeerRef:
    # The handful of peer facts the decision process needs, in one object
    # shared by every path from that peer.
    #
    # A peer in a full-table deployment contributes on the order of a
    # million paths. Copying its AS, router id, address and eBGP flag onto
    # each of them would cost more than the paths themselves and would make
    # a router-id change a million-object edit instead of one. The Peer
    # itself is held opaquely: bestpath needs the peer's numbers, not its
    # behaviour, and keeping the session object out of the comparator means
    # the comparator can be tested without one.

    cdef readonly object peer
    cdef readonly uint32_t peer_as
    cdef readonly uint32_t local_as
    cdef readonly uint32_t router_id
    cdef readonly bytes addr
    cdef readonly bint is_ebgp


cdef class BgpPath:
    # One candidate path for one prefix: a shared AttrSet, a shared PeerRef,
    # and the few facts unique to this one arrival.
    #
    # Both shared halves matter. The AttrSet is interned across every path
    # carrying the same attributes, so nothing peer-specific may live in it
    # -- two paths that differ only in who sent them must not collapse. The
    # PeerRef is shared across every path from one session. What is left
    # here is genuinely per-path: the path id, the arrival time, the weight
    # policy assigned, and the resolution state.

    cdef readonly AttrSet attrs
    cdef readonly PeerRef peer
    # RFC 7911. Zero when ADD-PATH was not negotiated, which is also why it
    # cannot double as "no path": every path has one, most are 0.
    cdef readonly uint32_t path_id
    cdef readonly uint32_t weight
    cdef readonly unsigned char source
    # Public, not readonly: next-hop tracking rewrites it when the cost to
    # reach this path's next hop changes. The decision process compares it
    # ("prefer the lowest IGP metric") long after the path arrived, so a
    # metric frozen at arrival time would make two routers with the same
    # IGP disagree about the same pair of paths.
    cdef public uint32_t igp_metric
    cdef readonly double recv_time

    # Written by selection and by next-hop tracking.
    cdef public bint resolved
    cdef public bint best
    cdef public bint multipath
    cdef public uint64_t version

    cpdef dict as_dict(self)


cdef class BestpathConfig:
    # The knobs. Every one exists because operators expect it and because
    # its absence changes which path wins, not because the RFC is ambiguous.

    cdef readonly uint32_t local_as
    cdef readonly uint32_t router_id

    # Compare MED between paths from different neighbouring ASes. Off by
    # default because MED is a hint about one neighbour's internal costs and
    # two neighbours' MEDs are not denominated in the same units.
    cdef readonly bint always_compare_med
    # Group paths by neighbouring AS and pick a group winner before
    # comparing across groups. Without this, MED comparison is not
    # transitive and the winner can depend on the order paths arrived in --
    # the single most notorious source of "the same routers disagree".
    cdef readonly bint deterministic_med
    # Treat an absent MED as 2^32-1 rather than 0.
    cdef readonly bint med_missing_as_worst
    # Use the router id as a tie-break even between eBGP paths, instead of
    # preferring the oldest. Trades stability for determinism.
    cdef readonly bint compare_router_id
    # Skip the AS-path length comparison entirely.
    cdef readonly bint as_path_ignore
    # Allow paths with equal-length but *different* AS paths into a
    # multipath set.
    cdef readonly bint as_path_multipath_relax
    cdef readonly unsigned char maximum_paths
    cdef readonly unsigned char maximum_paths_ibgp
    # The LOCAL_PREF a path without one is compared as: IOS `bgp default
    # local-preference`. The same value the outbound side gives such a path
    # towards internal peers, so this router and its iBGP neighbours rank it
    # the same way (B-7).
    cdef readonly uint32_t default_local_pref


cdef class BestpathResult:
    cdef readonly BgpPath best
    cdef readonly list multipath
    cdef readonly int reason
    cdef readonly Py_ssize_t considered
    cdef readonly Py_ssize_t comparisons


cdef class BgpDest:
    # Every path the BGP plugin holds for one prefix, plus the winner.
    #
    # The identity of a path within a destination is `(peer, path_id)`, not
    # its attributes. That is what makes a re-advertisement an in-place
    # replacement rather than a second path: a peer that sends 10.0.0.0/8
    # again with a new MED has changed its one path, and a destination that
    # treated the two as distinct would accumulate a path per update until
    # the session dropped. Without ADD-PATH the path id is always 0, so the
    # key degenerates to the peer, which is exactly right.
    #
    # This is the BGP plugin's own per-prefix container and is deliberately
    # not rib.table.Dest: that one holds protocol-neutral Routes from every
    # protocol at once and knows nothing of AS paths. The plugin runs this
    # selection first and offers only the winner to the GlobalRib.

    cdef readonly Prefix prefix
    cdef readonly list paths
    cdef readonly BgpPath best
    cdef readonly list multipath
    cdef readonly int reason
    cdef readonly uint64_t version
    # Set while the destination is waiting in the plugin's change queue, so
    # a prefix touched a thousand times in one batch is selected once. Same
    # device, and same reason, as rib.table.Dest.queued.
    cdef public unsigned char queued

    cpdef BgpPath find(self, PeerRef peer, uint32_t path_id)
    cpdef BgpPath add(self, BgpPath path)
    cpdef BgpPath remove(self, PeerRef peer, uint32_t path_id)
    cpdef Py_ssize_t remove_peer(self, PeerRef peer)
    cpdef BestpathResult reselect(self, BestpathConfig cfg)


# Order two candidate paths. Negative if `a` wins, positive if `b` wins,
# zero if the two are indistinguishable all the way down. `step` reports
# which criterion decided, as one of the STEP_* codes.

cdef int path_cmp(BgpPath a, BgpPath b, BestpathConfig cfg,
                  int *step) except -2
