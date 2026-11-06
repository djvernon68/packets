# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""A path-compressed binary radix trie keyed by :class:`Prefix`.

One structure serves the protocol-neutral route table, the next-hop resolver
and the policy prefix-lists, because all three want the same three
operations:

* **exact match**, which is what UPDATE processing does for every prefix it
  receives -- find the destination this prefix already has, or make one;
* **longest-prefix match**, which is what next-hop resolution and a
  prefix-list ``le``/``ge`` bound need;
* **ordered traversal**, which is what ``show`` output and API pagination
  need, in an order that agrees with ``sorted()`` of the same keys.

Why a trie and not a dictionary. Exact match alone would be better served by
a dict, and the hash is already cached on the Prefix. But LPM over a dict
means up to 33 (or 129) lookups per query, one per candidate length, and
ordered traversal means sorting the whole key set. The trie answers all three
from the same nodes, and it is the structure a prefix-list needs anyway. What
it costs is memory: see the node layout note in trie.pxd.

Path compression is what makes the depth bearable. A node carries the whole
prefix it represents rather than one bit, so the long single-child chains a
real routing table is full of -- a /24 hanging 24 bits below the first
branching bit -- collapse to one node per branch point. Nodes with no value
("glue") exist only to hold two diverging subtrees together, and are removed
again as soon as they stop doing that.

Stored values are owned references, managed by hand because Cython cannot put
an ``object`` in a C struct. ``None`` is not a storable value: it is how every
lookup spells "absent", and allowing it would make the two states
indistinguishable. Use a sentinel object if you need "present but empty".

Mutating a trie while iterating it is undefined, exactly as it is for a dict:
the iterator holds raw node pointers, and a removal can free one.
"""

from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_GET_SIZE
from cpython.mem cimport PyMem_Free, PyMem_Malloc
from cpython.ref cimport Py_DECREF, Py_INCREF
from libc.string cimport memcpy, memset

from packets.routing.rtengine.rib.prefix cimport (Prefix, pfx_addr_bits,
                                                  pfx_addr_len, pfx_bit,
                                                  pfx_common_bits, pfx_mask,
                                                  pfx_match, pfx_new)


cdef class Trie:
    """A single-family radix trie mapping prefixes to arbitrary objects.

    :param afi: IANA address family number -- 1 (IPv4) or 2 (IPv6). Fixed
        for the life of the trie; mixing families in one trie would mean
        either a per-node address width or treating IPv4 as IPv6, and both
        cost more on the hot path than keeping two tries.
    :raises ValueError: unknown address family.
    """

    def __cinit__(self, unsigned char afi):
        cdef unsigned char alen = pfx_addr_len(afi)

        if alen == 0:
            raise ValueError('unsupported address family number %d' % afi)
        self.root = NULL
        self.afi = afi
        self.alen = alen
        self.abits = pfx_addr_bits(afi)
        self.count = 0
        self.nodes = 0

    def __dealloc__(self):
        # Iterative, not recursive: a million-prefix IPv6 trie can be 128
        # levels deep and a recursive free would be a stack overflow on a
        # thread with a small stack. Walks down to a leaf, frees it,
        # unlinks it from its parent and repeats, so each node is visited
        # a bounded number of times and no auxiliary memory is needed.
        cdef TrieNode *n = self.root
        cdef TrieNode *parent

        while n != NULL:
            if n.child[0] != NULL:
                n = n.child[0]
                continue
            if n.child[1] != NULL:
                n = n.child[1]
                continue
            parent = n.parent
            if parent != NULL:
                if parent.child[0] == n:
                    parent.child[0] = NULL
                else:
                    parent.child[1] = NULL
            if n.value != NULL:
                self._release(n)
            PyMem_Free(n)
            n = parent
        self.root = NULL
        self.count = 0
        self.nodes = 0

    # --- node allocation ---------------------------------------------------

    cdef TrieNode *_alloc(self, const unsigned char *addr,
                          unsigned char plen) except NULL:
        """Allocate a zeroed node holding the masked prefix addr/plen."""
        cdef TrieNode *n = <TrieNode*>PyMem_Malloc(sizeof(TrieNode))

        if n == NULL:
            raise MemoryError('trie node')
        memset(n, 0, sizeof(TrieNode))
        # Copy the full family width, not (plen + 7) / 8: the tail must be
        # zero for the byte comparisons in pfx_match and for the node
        # address to be usable as a Prefix address directly.
        memcpy(&n.addr[0], addr, self.alen)
        pfx_mask(&n.addr[0], plen, self.alen)
        n.plen = plen
        self.nodes += 1
        return n

    cdef int _release(self, TrieNode *n) except -1:
        """Drop the node's reference to its value, leaving value NULL.

        The dance with ``held`` is how manual reference counting is done
        from Cython: casting the PyObject* to ``object`` takes a new
        reference, the explicit Py_DECREF gives up the node's reference, and
        Cython drops ``held`` on return. Net effect is exactly one release,
        and the object stays alive across the middle of it, so a __del__ on
        the value cannot see a half-updated trie.
        """
        cdef object held

        if n.value == NULL:
            return 0
        held = <object>n.value
        n.value = NULL
        n.is_real = 0
        Py_DECREF(held)
        return 0

    # --- searches ----------------------------------------------------------
    # No exception clause, by the same rule the Stage-1 decode primitives
    # follow: an `except` on a nogil function makes Cython re-acquire the GIL
    # to check for an exception on every call. A lookup reports "not found"
    # as NULL, which is not an error.

    cdef TrieNode *node_exact(self, const unsigned char *addr,
                              unsigned char plen) nogil:
        """Return the real node for exactly addr/plen, or NULL."""
        cdef TrieNode *n = self.root

        while n != NULL and n.plen <= plen:
            if not pfx_match(&n.addr[0], n.plen, addr):
                return NULL
            if n.plen == plen:
                return n if n.is_real else NULL
            # A node at length p branches on bit p of the key. Path
            # compression means the child's own length may be much greater,
            # which is why its prefix is re-checked at the top of the loop.
            n = n.child[pfx_bit(addr, n.plen)]
        return NULL

    cdef TrieNode *node_lpm(self, const unsigned char *addr,
                            unsigned char plen) nogil:
        """Return the longest real node covering addr/plen, or NULL."""
        cdef TrieNode *n = self.root
        cdef TrieNode *best = NULL

        while n != NULL and n.plen <= plen:
            if not pfx_match(&n.addr[0], n.plen, addr):
                break
            if n.is_real:
                best = n
            if n.plen == plen:
                break
            n = n.child[pfx_bit(addr, n.plen)]
        return best

    cdef TrieNode *node_intern(self, const unsigned char *addr,
                               unsigned char plen) except NULL:
        """Return the node for addr/plen, creating it if it does not exist.

        The returned node may be glue (no value yet); the caller decides
        whether to give it one. Splitting find-or-create from set-value is
        what lets the route table do a single descent per received prefix:
        it interns the node, and only builds a destination object if the
        node turns out to be new.
        """
        cdef TrieNode *n = self.root
        cdef TrieNode *parent = NULL
        cdef TrieNode *fresh
        cdef TrieNode *glue
        cdef unsigned int common

        # Descend while the tree still agrees with the key and has not
        # overshot the target length.
        while n != NULL and n.plen <= plen and \
                pfx_match(&n.addr[0], n.plen, addr):
            if n.plen == plen:
                return n
            parent = n
            n = n.child[pfx_bit(addr, n.plen)]

        if n == NULL:
            # Nothing in the way: hang a new node off the last match.
            fresh = self._alloc(addr, plen)
            fresh.parent = parent
            if parent == NULL:
                self.root = fresh
            else:
                parent.child[pfx_bit(addr, parent.plen)] = fresh
            return fresh

        # n is in the way: either the new prefix is an ancestor of it, or
        # the two diverge. common is the first bit position at which the
        # answer differs, capped by both lengths.
        common = pfx_common_bits(&n.addr[0], addr, self.abits)
        if common > n.plen:
            common = n.plen
        if common > plen:
            common = plen

        if common == plen:
            # The new prefix covers n, so it belongs between n and its
            # parent. plen < n.plen here: equality was returned inside the
            # loop.
            fresh = self._alloc(addr, plen)
            fresh.parent = parent
            fresh.child[pfx_bit(&n.addr[0], plen)] = n
            if parent == NULL:
                self.root = fresh
            else:
                parent.child[pfx_bit(addr, parent.plen)] = fresh
            n.parent = fresh
            return fresh

        # They diverge above both lengths, so a glue node at the divergence
        # point holds the existing subtree and the new prefix apart. Its
        # address can be taken from either key: they agree on the first
        # `common` bits by construction.
        glue = self._alloc(addr, <unsigned char>common)
        try:
            fresh = self._alloc(addr, plen)
        except MemoryError:
            # Undo the half-built split rather than leaving an orphan glue
            # node linked into nothing.
            PyMem_Free(glue)
            self.nodes -= 1
            raise
        glue.parent = parent
        glue.child[pfx_bit(&n.addr[0], common)] = n
        glue.child[pfx_bit(addr, common)] = fresh
        n.parent = glue
        fresh.parent = glue
        if parent == NULL:
            self.root = glue
        else:
            parent.child[pfx_bit(addr, parent.plen)] = glue
        return fresh

    # --- value management --------------------------------------------------

    cdef int set_value(self, TrieNode *n, object value) except -1:
        """Store ``value`` at a node, replacing and releasing any previous one.

        :param n: a node from node_intern.
        :param value: any object except None.
        :raises ValueError: value is None -- None is how a lookup spells
            "absent", so storing it would make the two indistinguishable.
        """
        if value is None:
            raise ValueError('None cannot be stored in a trie; use a '
                             'sentinel object for "present but empty"')
        if n.value == NULL:
            self.count += 1
        else:
            self._release(n)
        Py_INCREF(value)
        n.value = <PyObject*>value
        n.is_real = 1
        return 0

    cdef int clear_value(self, TrieNode *n) except -1:
        """Remove a node's value and prune the node if it is now redundant.

        ``n`` may be freed by this call and must not be used afterwards.

        :param n: a node, possibly already glue.
        """
        if n.value == NULL:
            return 0
        self._release(n)
        self.count -= 1
        self._prune(n)
        return 0

    cdef void _prune(self, TrieNode *n):
        """Free a chain of glue nodes that no longer hold two subtrees apart.

        Three cases per node, walking up: two children means it is still
        doing its job; one child means it is redundant and the child takes
        its place (its parent's child count does not change, so the walk
        stops); no children means it is dead, and its parent may now be in
        the same position.
        """
        cdef TrieNode *parent
        cdef TrieNode *child

        while n != NULL and n.is_real == 0:
            if n.child[0] != NULL and n.child[1] != NULL:
                return
            child = n.child[0] if n.child[0] != NULL else n.child[1]
            parent = n.parent
            if child != NULL:
                child.parent = parent
            if parent == NULL:
                self.root = child
            elif parent.child[0] == n:
                parent.child[0] = child
            else:
                parent.child[1] = child
            PyMem_Free(n)
            self.nodes -= 1
            if child != NULL:
                return
            n = parent

    # --- Python-facing -----------------------------------------------------

    cpdef object insert(self, Prefix p, object value):
        """Store a value under a prefix.

        :param p: the key; its family must match the trie's.
        :param value: any object except None.
        :return: the value previously stored under ``p``, or None.
        :raises ValueError: family mismatch, or a None value.
        """
        cdef TrieNode *n
        cdef object previous

        if p is None:
            raise ValueError('prefix is required')
        if p.afi != self.afi:
            raise ValueError('prefix afi %d does not belong in an afi %d '
                             'trie' % (p.afi, self.afi))
        # Checked here, before the node is created, and again in set_value
        # for the callers that reach it directly. Interning first and
        # validating second would strand a node on every rejection: it
        # would be linked in with no value, so clear_value returns early
        # for it, node_exact will not see it because it is not real, and
        # _prune is unreachable -- only clear() or __dealloc__ would ever
        # release it. Validating input by attempting the store is the
        # natural reading of an API that documents a ValueError, so this
        # would grow the trie by roughly two permanent nodes per distinct
        # rejected prefix.
        if value is None:
            raise ValueError('None cannot be stored in a trie; use a '
                             'sentinel object for "present but empty"')
        n = self.node_intern(&p.addr[0], p.plen)
        # Taken before set_value, which releases the node's reference: this
        # owned reference is what keeps the old value alive for the caller.
        previous = trie_node_value(n)
        self.set_value(n, value)
        return previous

    cpdef object get(self, Prefix p):
        """Return the value stored under exactly this prefix, or None.

        :param p: the key. A family mismatch is a miss, not an error, so a
            caller iterating both families can probe without branching.
        :return: the stored value, or None.
        """
        if p is None or p.afi != self.afi:
            return None
        return trie_node_value(self.node_exact(&p.addr[0], p.plen))

    cpdef object lpm(self, Prefix p):
        """Return the value of the longest prefix covering ``p``, or None.

        Covering includes ``p`` itself, so an exact hit wins over its
        less-specific parents -- which is what "longest match" means and
        what next-hop resolution wants.

        :param p: the prefix to resolve.
        :return: the stored value, or None if nothing covers it.
        """
        if p is None or p.afi != self.afi:
            return None
        return trie_node_value(self.node_lpm(&p.addr[0], p.plen))

    cpdef tuple lpm_entry(self, Prefix p):
        """Like :meth:`lpm`, but also return which prefix matched.

        ``show ip route`` and the resolver both need to report the covering
        prefix, not only its value.

        :param p: the prefix to resolve.
        :return: ``(Prefix, value)``, or None if nothing covers it.
        """
        cdef TrieNode *n

        if p is None or p.afi != self.afi:
            return None
        n = self.node_lpm(&p.addr[0], p.plen)
        if n == NULL:
            return None
        return (pfx_new(self.afi, n.plen, &n.addr[0]), trie_node_value(n))

    cpdef object lpm_addr(self, bytes addr):
        """Resolve a bare host address rather than a prefix.

        This is the resolver's entry point: a next-hop is an address, and
        building a /32 Prefix for every validation would allocate an object
        per lookup for nothing.

        :param addr: exactly 4 bytes (IPv4) or 16 (IPv6).
        :return: the stored value of the longest covering prefix, or None.
        :raises ValueError: wrong address width for the trie's family.
        """
        if addr is None or PyBytes_GET_SIZE(addr) != self.alen:
            raise ValueError('afi %d needs a %d byte address'
                             % (self.afi, self.alen))
        return trie_node_value(self.node_lpm(
            <const unsigned char*>PyBytes_AS_STRING(addr), self.abits))

    cpdef object remove(self, Prefix p):
        """Remove a prefix and return the value it held.

        :param p: the key.
        :return: the removed value, or None if the prefix was not present.
        """
        cdef TrieNode *n
        cdef object previous

        if p is None or p.afi != self.afi:
            return None
        n = self.node_exact(&p.addr[0], p.plen)
        if n == NULL:
            return None
        previous = trie_node_value(n)
        self.clear_value(n)
        return previous

    cpdef Py_ssize_t size(self):
        """Return the number of prefixes stored.

        Typed, so a Cython caller counting table sizes does not go through
        ``len()`` and a Python int.

        :return: the entry count, glue nodes excluded.
        """
        return self.count

    def __len__(self):
        return self.count

    def __contains__(self, p):
        if not isinstance(p, Prefix):
            return False
        return self.get(<Prefix>p) is not None

    def __iter__(self):
        """Iterate prefixes in ascending prefix order."""
        return TrieIterator(self, False)

    def items(self):
        """Iterate ``(Prefix, value)`` pairs in ascending prefix order.

        The order is :func:`pfx_cmp`'s, which is also ``sorted()``'s: a
        prefix comes before everything beneath it, and the 0 subtree before
        the 1 subtree. That agreement is what lets paginated API output
        resume from a prefix the client last saw.
        """
        return TrieIterator(self, True)

    def keys(self):
        """Iterate prefixes in ascending prefix order."""
        return TrieIterator(self, False)

    def values(self):
        """Return the stored values, in ascending prefix order."""
        return [v for _, v in TrieIterator(self, True)]

    def clear(self):
        """Remove every entry, releasing all nodes and values."""
        cdef TrieNode *n = self.root
        cdef TrieNode *parent

        while n != NULL:
            if n.child[0] != NULL:
                n = n.child[0]
                continue
            if n.child[1] != NULL:
                n = n.child[1]
                continue
            parent = n.parent
            if parent != NULL:
                if parent.child[0] == n:
                    parent.child[0] = NULL
                else:
                    parent.child[1] = NULL
            if n.value != NULL:
                self._release(n)
            PyMem_Free(n)
            n = parent
        self.root = NULL
        self.count = 0
        self.nodes = 0

    def __repr__(self):
        return '<Trie afi=%d entries=%d nodes=%d>' % (self.afi, self.count,
                                                      self.nodes)


cdef class TrieIterator:
    """Pre-order walk over a trie, yielding real entries only.

    Pre-order -- node, then 0 subtree, then 1 subtree -- is exactly
    ascending prefix order for a masked radix trie, so no sort is needed and
    the walk is O(nodes) with no allocation beyond the yielded objects.

    The stack is a fixed C array. Its depth is bounded by the address width:
    the walk holds at most one unvisited sibling per level, and a level is
    one bit, so twice the address width plus a margin can never be exceeded
    and there is no growth path to get wrong.

    A strong reference to the trie is held so that iterating a temporary does
    not free the nodes out from under the walk. It does not protect against
    mutation: removing an entry mid-iteration can free a node the stack
    still points at, exactly as mutating a dict during iteration is
    undefined.
    """

    cdef Trie trie
    cdef TrieNode **stack
    cdef Py_ssize_t top
    cdef Py_ssize_t cap
    cdef bint with_values

    def __cinit__(self, Trie trie, bint with_values=True):
        self.trie = trie
        self.with_values = with_values
        self.cap = 2 * (<Py_ssize_t>trie.abits + 2)
        self.stack = <TrieNode**>PyMem_Malloc(self.cap * sizeof(TrieNode*))
        if self.stack == NULL:
            raise MemoryError('trie iterator stack')
        self.top = 0
        if trie.root != NULL:
            self.stack[0] = trie.root
            self.top = 1

    def __dealloc__(self):
        if self.stack != NULL:
            PyMem_Free(self.stack)
            self.stack = NULL

    def __iter__(self):
        return self

    def __next__(self):
        cdef TrieNode *n

        while self.top > 0:
            self.top -= 1
            n = self.stack[self.top]
            # Push the 1 subtree first so the 0 subtree is popped first.
            if n.child[1] != NULL:
                self.stack[self.top] = n.child[1]
                self.top += 1
            if n.child[0] != NULL:
                self.stack[self.top] = n.child[0]
                self.top += 1
            if n.is_real:
                if self.with_values:
                    return (pfx_new(self.trie.afi, n.plen, &n.addr[0]),
                            trie_node_value(n))
                return pfx_new(self.trie.afi, n.plen, &n.addr[0])
        raise StopIteration
