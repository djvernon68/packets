# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint32_t, uint64_t

from packets.routing.rtengine.rib.prefix cimport Prefix
from packets.routing.rtengine.rib.trie cimport Trie


# --- Actions ----------------------------------------------------------------
# A filter answers one of three things, and all three are distinct: permit,
# deny, and "nothing in this list had an opinion". The third is IOS' implicit
# deny, and a caller treats it as a deny -- but `show` and `debug` have to be
# able to say *why* a prefix was dropped, and "no entry matched" is a
# configuration mistake far more often than an explicit deny is. So the
# no-match case is its own return value rather than being folded into deny.
#
# The C names carry the PL_ prefix because the .pyx re-exports the same values
# as the plain Python ints ACTION_DENY / ACTION_PERMIT, and a module cannot
# assign to a name its own .pxd has already made a compile-time constant.
# This mirrors PFX_AFI_IP in prefix.pxd and RT_PROTO_BGP in table.pxd.

cdef enum:
    PL_ACTION_DENY = 0
    PL_ACTION_PERMIT = 1


# --- One configured entry ---------------------------------------------------
# Immutable apart from the hit counter. The prefix is the trie key the entry
# is filed under, so rewriting it in place would leave the entry filed in the
# wrong node; `remove` then `add` is the supported way to change one.
#
# lo/hi are the derived, inclusive prefix-length window this entry accepts,
# computed once in `add` from (plen, le, ge). Storing the window rather than
# the le/ge pair is what makes the hot-path test two comparisons with no
# branching on which of le and ge were configured -- the four spellings
# (neither, le only, ge only, both) all collapse to one range test. le and ge
# are kept alongside it only so `show` can reproduce the configuration as it
# was written.

cdef class PrefixListEntry:
    cdef readonly uint32_t seq
    cdef readonly unsigned char action
    cdef readonly Prefix prefix
    cdef readonly unsigned char le
    cdef readonly unsigned char ge
    cdef readonly unsigned char lo
    cdef readonly unsigned char hi
    cdef readonly uint64_t hits
    # A cdef class is not weak-referenceable unless it says so, and the leak
    # tests assert on entry lifetime through weakref rather than by reading
    # refcounts of an object the test itself holds.
    cdef object __weakref__

    cpdef dict as_dict(self)


# --- The list ---------------------------------------------------------------

cdef class PrefixList:
    cdef readonly str name
    cdef readonly unsigned char afi
    # 32 or 128. Derived from afi, stored because every le/ge validation and
    # every "ge only" window needs it.
    cdef readonly unsigned char abits
    cdef readonly uint64_t version
    cdef readonly uint64_t hits
    cdef readonly uint64_t matches

    # The index: entry prefix -> list of entries filed under that prefix,
    # ordered by seq. Two entries may share a prefix and differ only in their
    # le/ge window, which is why the value is a list and not an entry.
    #
    # Public and readonly so that a test can assert on `nodes` and `count`
    # after a rebuild -- a prefix-list that leaked a trie node per reload
    # would otherwise be invisible until a long-running engine ran out of
    # memory.
    cdef readonly Trie trie

    # Every entry, ordered by seq. The evaluation path does not read it; it
    # exists for `entries`, `as_dict`, and the binary search in add/remove.
    cdef list _entries

    cdef PrefixListEntry _lookup(self, Prefix p)
    cdef Py_ssize_t _index_of(self, uint32_t seq)

    # Internal. Declared here only because Cython requires every cdef method
    # of a class whose declaration lives in a .pxd to be declared there too;
    # nothing outside prefixlist.pyx should call these.
    cdef int _file(self, PrefixListEntry entry) except -1
    cdef int _unfile(self, PrefixListEntry entry) except -1

    # `except -2`, not `except -1`: -1 is a legitimate return meaning "no
    # entry matched", and declaring it the error sentinel would make every
    # caller who got an honest no-match see a NULL return with no exception
    # set, which CPython reports as SystemError. -2 is not a value this can
    # ever return.
    cpdef int evaluate(self, object prefix) except -2
    cpdef bint permits(self, object prefix) except -1
    cpdef list entries(self)
    cpdef dict as_dict(self)
