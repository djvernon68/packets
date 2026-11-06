# cython: language_level=3

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint16_t, uint32_t


# --- ORIGIN, and AS_PATH segment types --------------------------------------
# These live here rather than in wire.pxd, even though they are wire values,
# because AttrSet interprets them: it walks the AS_PATH segments to derive
# the path length and the neighbouring AS, and it orders ORIGIN in best-path.
# wire.pxd cimports this file (it has to, it builds AttrSet objects), so
# putting them here keeps one definition and one direction of dependency.
# The reverse -- attrs cimporting wire -- would be a cycle.

cdef enum:
    ORIGIN_IGP = 0
    ORIGIN_EGP = 1
    ORIGIN_INCOMPLETE = 2

    AS_SET = 1
    AS_SEQUENCE = 2
    AS_CONFED_SEQUENCE = 3
    AS_CONFED_SET = 4

    # RFC 6793: what a 2-octet speaker sees in place of a 4-octet AS it
    # cannot represent. Never a real AS, so it is never a loop match and
    # never a MED grouping key.
    AS_TRANS = 23456


# --- Presence flags ---------------------------------------------------------
# MED and LOCAL_PREF are unsigned 32-bit values whose whole range is legal,
# so there is no in-band "absent". A missing MED is not a MED of 0: RFC 4271
# says a missing MED is treated as 0 for comparison *by default*, but
# `bgp bestpath med missing-as-worst` inverts that to 2^32-1, and a path
# with no MED must be re-advertised with no MED rather than with 0. One bit
# each is the cheapest way to keep "absent" distinguishable from "zero"
# without paying for a boxed Python int per attribute set.
#
# ATOMIC_AGGREGATE has no value at all -- its presence *is* the information.

cdef enum:
    ATTRF_MED = 0x01
    ATTRF_LOCAL_PREF = 0x02
    ATTRF_ATOMIC_AGGREGATE = 0x04
    ATTRF_ORIGINATOR_ID = 0x08
    # Set by AttrTable.intern on the canonical instance. An AttrSet carrying
    # this bit is shared by every path that matched it, so mutating one is a
    # cross-table corruption rather than a local mistake; the bit exists so
    # that assertion can be made cheaply where it matters.
    ATTRF_INTERNED = 0x10


cdef class AttrSet:
    # One BGP path attribute set, canonicalised and immutable.
    #
    # "Canonical" is doing real work here. A full table has on the order of a
    # million paths and only tens of thousands of distinct attribute sets, so
    # the design (Key Decision 3, FRR's `attrhash`) is to intern them and let
    # every path hold a reference. That only collapses properly if two
    # attribute sets that *mean* the same thing also *hash* the same, which
    # is why the decoder does not store what it received:
    #
    #   * AS_PATH is always widened to 4-byte ASNs, with AS4_PATH already
    #     merged in, so a 2-octet and a 4-octet session that describe the
    #     same path produce the same bytes;
    #   * communities, extended communities and large communities are sorted,
    #     because their order carries no meaning and an unsorted pair would
    #     otherwise intern as two objects;
    #   * CLUSTER_LIST is deliberately *not* sorted -- it is a path record
    #     and its order is its content;
    #   * unknown transitive attributes are kept, sorted by type code, so a
    #     re-advertisement is faithful (RFC 4271 requires it) without
    #     defeating interning.
    #
    # Immutability is a hard contract, not a convention: an interned instance
    # is shared by every path that matched it and is a live dictionary key in
    # AttrTable. Build a new one instead.

    cdef readonly unsigned char origin
    cdef readonly unsigned char flags

    # Canonical AS_PATH: a run of (seg_type, count, count * 4 bytes of ASN)
    # segments, ASNs in network order. Empty bytes means an empty AS_PATH,
    # which is what a locally originated path and an iBGP-learned local path
    # both carry -- distinct from "no AS_PATH attribute", which is malformed
    # and never reaches here.
    cdef readonly bytes as_path

    # Next hop as it will be used, 4 bytes for IPv4 and 16 for IPv6. The
    # MP_REACH link-local next hop is kept separately rather than
    # concatenated, because the two are used in different places: the global
    # address resolves and installs, the link-local one is only ever
    # re-advertised to a peer on the same link.
    cdef readonly bytes nexthop
    cdef readonly bytes nexthop_local

    cdef readonly uint32_t med
    cdef readonly uint32_t local_pref

    cdef readonly bytes communities
    cdef readonly bytes ext_communities
    cdef readonly bytes large_communities

    cdef readonly uint32_t originator_id
    cdef readonly bytes cluster_list

    # AGGREGATOR, always stored in its 4-octet form (4-byte AS + 4-byte
    # router id), with AS4_AGGREGATOR already folded in. Empty when absent.
    cdef readonly bytes aggregator

    # Unrecognised optional-transitive attributes, concatenated in their
    # on-wire TLV form and sorted by type code. RFC 4271 requires these to
    # survive a re-advertisement with the partial bit set; discarding them
    # would silently break communities-like extensions this engine does not
    # know about yet.
    cdef readonly bytes unknown

    # --- derived, computed once at construction -----------------------------
    # Best-path runs these comparisons per candidate pair per destination
    # over a million destinations. Walking the AS_PATH segment list to count
    # ASNs inside the comparator would put a parse loop on the hottest path
    # in the engine; doing it once per *distinct attribute set* instead is
    # the same argument that justifies interning in the first place.

    # AS count for the length tie-break: an AS_SET counts as 1 regardless of
    # its membership, and confederation segments count as 0 (RFC 5065).
    cdef readonly uint32_t as_path_len
    # Leftmost AS of the first non-confederation segment: the neighbouring
    # AS, which is the MED grouping key of Key Decision 10. 0 when the path
    # is empty (locally originated), which forms its own group.
    cdef readonly uint32_t neighbor_as
    # len(cluster_list) / 4, for the cluster-list-length tie-break.
    cdef readonly uint16_t cluster_len

    cdef long _hash
    # Interning refcount, owned by AttrTable. Not the CPython refcount: this
    # counts how many *paths* claim the set, which is what decides when the
    # table may forget it.
    cdef Py_ssize_t refs

    cpdef list as_path_list(self)
    cpdef str as_path_str(self)
    cpdef bint has_as(self, uint32_t asn)
    cpdef list community_list(self)
    cpdef list cluster_ids(self)
    cpdef bint has_med(self)
    cpdef bint has_local_pref(self)
    cpdef dict as_dict(self)


cdef class AttrTable:
    # The interning table. Self-keyed: an AttrSet is its own dictionary key,
    # so a lookup is one hash of the cached value and, on a hit, one
    # comparison -- there is no separate key object to build or keep in step.

    cdef dict _sets
    cdef readonly Py_ssize_t hits
    cdef readonly Py_ssize_t misses
    cdef readonly Py_ssize_t releases

    cpdef AttrSet intern(self, AttrSet a)
    # `except? -1`, not `except -1`. This returns -1 as a legitimate value
    # meaning "that set was not mine to free", and a bare `except -1` would
    # declare the same -1 to be the error sentinel: the generated wrapper
    # then returns NULL with no exception set and CPython raises
    # SystemError at every caller who asked about a set the table does not
    # hold. The `?` makes Cython check PyErr_Occurred() to tell the two
    # apart, which costs one branch on a path that is not hot.
    cpdef int release(self, AttrSet a) except? -1
    cpdef Py_ssize_t count(self)
    cpdef dict stats(self)


# Allocate an uninitialised AttrSet for a decoder to fill field by field.
#
# The decoder in wire.pyx cimports this module, so it writes the cdef fields
# directly -- `readonly` only restricts Python attribute access, not C. That
# avoids marshalling fourteen fields through a keyword __init__ once per
# UPDATE, which at a million prefixes is not a rounding error.
#
# The returned object is NOT usable until attrs_finalize has run: the derived
# fields and the hash are unset, so hashing or comparing it is meaningless.

cdef AttrSet attrs_blank()

# Canonicalise, derive and hash. Call exactly once, after the last field is
# written and before the set is interned, compared or used as a key.
#
# Sorts the three community collections and the unknown-attribute run, walks
# the AS_PATH to derive as_path_len and neighbor_as, and computes the cached
# hash. Returns its argument so a decoder can write
# `a = attrs_finalize(a)` as the last line of a parse.

cdef AttrSet attrs_finalize(AttrSet a)

# Total order over attribute sets, for deterministic show output and for
# tests that need a stable sort. Not used by best-path, which orders paths by
# protocol semantics rather than by attribute bytes.

cdef int attrs_cmp(AttrSet a, AttrSet b)
