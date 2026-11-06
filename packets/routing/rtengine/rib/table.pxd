# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint32_t, uint64_t

from packets.routing.rtengine.rib.prefix cimport Prefix
from packets.routing.rtengine.rib.trie cimport Trie


# --- Protocol identity and preference ---------------------------------------
# A small dense id per protocol, not a string, because it is compared once per
# candidate route in the selection pass and stored on every route in the
# table.
#
# The numeric order IS the protocol preference order, which is the last
# tie-break before route age: connected beats static beats a dynamic
# protocol. It is only ever reached when two protocols offer the same prefix
# at the same administrative distance and the same metric, which a sane
# configuration never does -- but "never does" is not "cannot", and an
# arbitrary winner would make the table non-deterministic between runs.
#
# These are rtengine's own ids and have nothing to do with the kernel's
# rtm_protocol: that is a single value identifying us to the kernel, chosen
# so our routes cannot collide with another daemon's.

cdef enum:
    RT_PROTO_UNSPEC = 0
    RT_PROTO_CONNECTED = 1
    RT_PROTO_STATIC = 2
    RT_PROTO_BGP = 3
    RT_PROTO_OSPF = 4
    RT_PROTO_RIP = 5
    RT_PROTO_MAX = 6


# --- FIB install state, carried on the route itself -------------------------
# Kept on the Route rather than in a side table in the sink: `show ip route`
# reports it per route, and a parallel dict keyed by prefix would be a second
# thing to keep in step with every withdrawal.

cdef enum:
    FIB_NONE = 0          # not offered to a sink (install off, or not best)
    FIB_PENDING = 1       # queued for the sink, not yet acknowledged
    FIB_INSTALLED = 2     # the sink acknowledged it
    FIB_ERROR = 3         # the sink rejected it; fib_errno says why
    FIB_ORPHANED = 4      # found in the kernel carrying our id, not ours now
    FIB_NOT_INSTALLED = 5  # best, but the sink installs nothing (NullSink)


cdef class Route:
    # What a plugin offers the GlobalRib: a destination, a next-hop and the
    # two numbers every routing protocol can express -- an administrative
    # distance (how much the operator trusts the protocol) and a metric (how
    # good the protocol thinks this path is). Nothing protocol-specific
    # appears here. BGP's AS_PATH, communities and MED stay inside the BGP
    # plugin, which has already run its own best-path selection before it
    # offers anything.
    #
    # `source` is the offering plugin's own token, opaque to the core and
    # compared by identity. Together with `protocol` it is the route's
    # identity in a Dest: offering a second route with the same pair
    # replaces the first, which is what an attribute change on an already
    # advertised prefix looks like.

    cdef readonly Prefix prefix
    cdef readonly unsigned char protocol
    cdef readonly unsigned char admin_distance
    cdef readonly uint32_t metric
    cdef readonly bytes nexthop
    cdef readonly object source
    cdef readonly double recv_time

    # Mutable: selection and the FIB sink write these.
    cdef public uint64_t version
    cdef public unsigned char fib_state
    cdef public int fib_errno

    cpdef bint same_origin(self, Route other)


cdef class Dest:
    # Every route offered for one prefix, plus the winner. A Dest exists as
    # long as any protocol offers the prefix; the table drops it, and its
    # trie node with it, when the last route goes.

    cdef readonly Prefix prefix
    cdef readonly list routes
    cdef readonly Route best
    cdef readonly uint64_t version
    # Set while the Dest is waiting in the table's change queue, so a prefix
    # updated a thousand times inside one batch is selected once.
    cdef unsigned char queued

    cdef Route _select(self)


cdef class RouteTable:
    # One table per (afi, safi). The trie maps prefix to Dest; the change
    # queue is what makes selection deadline-bounded: offers and withdrawals
    # are O(1) and only mark the destination dirty, and reselect() drains as
    # much of the queue as the caller's time budget allows.

    cdef readonly unsigned char afi
    cdef readonly unsigned char safi
    cdef readonly Trie trie
    cdef readonly Py_ssize_t route_count
    cdef readonly uint64_t version

    # A list plus a head index rather than a deque: the drain is a bulk
    # slice, not a pop per item, and this stays typed C indexing inside the
    # selection loop.
    cdef list _queue
    cdef Py_ssize_t _qhead

    cdef int _enqueue(self, Dest d) except -1

    cpdef Dest get(self, Prefix p)
    cpdef Dest dest(self, Prefix p)
    cpdef int offer(self, Route r) except -1
    cpdef int retract(self, Prefix p, unsigned char protocol,
                      object source) except -1
    cpdef Dest lpm(self, Prefix p)
    cpdef Dest lpm_addr(self, bytes addr)
    cpdef Py_ssize_t pending(self)
    cpdef list reselect(self, Py_ssize_t limit)


# Order two candidate routes for the same prefix. Returns a negative value if
# `a` is preferred, positive if `b` is, zero if they are indistinguishable.
#
# Administrative distance, then metric, then protocol preference, then age.
# Declared here so a plugin can order protocol-neutral candidates the same
# way the core does without reimplementing it.

cdef int route_cmp(Route a, Route b) nogil
