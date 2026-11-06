# cython: language_level=3

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from cpython.ref cimport PyObject

from packets.routing.rtengine.rib.prefix cimport Prefix


# --- Node layout ------------------------------------------------------------
# A path-compressed binary radix (Patricia) trie. Each node carries the whole
# prefix it represents rather than a single bit, so a chain of single-child
# nodes -- which is most of a real routing table, where /24s hang a long way
# below the first branching bit -- collapses to one node per branch point.
#
# Invariants, relied on by every walk below:
#   * a node's prefix is a strict extension of its parent's prefix;
#   * child[0] holds the subtree whose next bit after plen is 0, child[1] the
#     subtree whose next bit is 1;
#   * a node with value == NULL is glue: it exists only because two subtrees
#     diverge at its plen, and it is removed again when it stops having two
#     children;
#   * is_real == 1 exactly when value != NULL. The flag is kept because the
#     walks test it once per visited node and a flag test reads better than
#     a pointer test at those call sites.
#
# The value is an owned reference. Cython cannot put an `object` field in a C
# struct, so the reference count is managed by hand: set_value INCREFs,
# clear_value and __dealloc__ DECREF, and nothing else writes the field. Every
# read goes through trie_node_value, which hands back a proper owned
# reference, so no caller outside this module ever sees a PyObject*.

cdef struct TrieNode:
    unsigned char addr[16]
    unsigned char plen
    unsigned char is_real
    TrieNode *parent
    TrieNode *child[2]
    PyObject *value


cdef inline object trie_node_value(TrieNode *n):
    """Return the value stored at a node, or None.

    The cast to ``object`` is what turns the borrowed PyObject* in the node
    into an owned reference, which is why this is the only sanctioned way to
    read the field. A NULL node is accepted so that a caller can hand a
    lookup result straight in without testing it first.

    :param n: node, or NULL.
    :return: the stored value, or None when the node is absent or glue.
    """
    if n == NULL or n.value == NULL:
        return None
    return <object>n.value


cdef class Trie:
    # One structure serves the protocol-neutral RouteTable, the resolver and
    # the policy prefix-lists. They need the same three operations -- exact
    # match for UPDATE processing, longest-prefix match for next-hop
    # resolution and prefix-list le/ge tests, ordered traversal for show and
    # pagination -- and a second index would only be a second thing to keep
    # consistent.
    #
    # A Trie is single-family: afi is fixed at construction and every key is
    # checked against it. Mixing families in one trie would mean either a
    # per-node address length or treating IPv4 as an IPv6 prefix, and both
    # cost more on the hot path than keeping two tries.

    cdef TrieNode *root
    cdef readonly unsigned char afi
    cdef readonly unsigned char alen        # significant address bytes
    cdef readonly unsigned char abits       # 32 or 128
    cdef readonly Py_ssize_t count          # real entries, not nodes
    cdef readonly Py_ssize_t nodes          # allocated nodes, glue included

    # --- C-level core ------------------------------------------------------
    # The two searches take no exception clause and report by return value:
    # an `except NULL` on a nogil function makes Cython re-acquire the GIL to
    # check for an exception on every call, which is the opposite of the
    # point, and a lookup that cannot fail has nothing to report anyway.
    # Callers pass a pointer to at least `alen` readable bytes of an address
    # already masked to `plen`; Prefix guarantees both.

    cdef TrieNode *node_exact(self, const unsigned char *addr,
                              unsigned char plen) nogil
    cdef TrieNode *node_lpm(self, const unsigned char *addr,
                            unsigned char plen) nogil
    cdef TrieNode *node_intern(self, const unsigned char *addr,
                               unsigned char plen) except NULL
    cdef int set_value(self, TrieNode *n, object value) except -1
    cdef int clear_value(self, TrieNode *n) except -1

    # Internal. Declared here only because Cython requires every cdef method
    # of a class whose declaration lives in a .pxd to be declared there too;
    # nothing outside trie.pyx should call these.
    cdef TrieNode *_alloc(self, const unsigned char *addr,
                          unsigned char plen) except NULL
    cdef int _release(self, TrieNode *n) except -1
    cdef void _prune(self, TrieNode *n)

    # --- Python-facing -----------------------------------------------------
    cpdef object insert(self, Prefix p, object value)
    cpdef object get(self, Prefix p)
    cpdef object lpm(self, Prefix p)
    cpdef tuple lpm_entry(self, Prefix p)
    cpdef object lpm_addr(self, bytes addr)
    cpdef object remove(self, Prefix p)
    cpdef Py_ssize_t size(self)
