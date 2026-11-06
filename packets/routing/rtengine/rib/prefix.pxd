# cython: language_level=3

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.string cimport memcmp, memset


# --- Address family and address width ---------------------------------------
# The values are the IANA Address Family Numbers, which are also what BGP
# puts on the wire in MP_REACH_NLRI. A protocol-neutral core has no business
# inventing its own numbering when a registry the plugins already speak
# exists, and using AF_INET/AF_INET6 instead would tie the RIB key to
# whatever the host's socket headers happen to number them (they differ
# between Linux and macOS for AF_INET6).
#
# The C names are prefixed because the .pyx re-exports the same values as
# plain Python ints named AFI_IP / AFI_IP6 / SAFI_UNICAST, and a module
# cannot assign to a name its own .pxd has already made a C constant.

cdef enum:
    PFX_AFI_IP = 1
    PFX_AFI_IP6 = 2
    PFX_SAFI_UNICAST = 1
    # Every Prefix carries a 16-byte address regardless of family. An IPv4
    # prefix wastes 12 bytes and in exchange the trie, the route table and
    # the resolver all index one flat layout with no per-family branch on
    # the hot path, and an IPv4 and an IPv6 Prefix are the same size, so a
    # freelist or an array of them stays uniform.
    PFX_MAX_ADDR = 16


cdef inline unsigned char pfx_addr_len(unsigned char afi) nogil:
    """Return the number of significant address bytes for an AFI.

    Anything that is not a known AFI reports 0, which every caller treats as
    "reject": the RIB has no way to size a key it does not recognise, and
    guessing would corrupt the trie rather than fail a lookup.

    :param afi: IANA address family number.
    :return: 4 for IPv4, 16 for IPv6, 0 otherwise.
    """
    if afi == PFX_AFI_IP:
        return 4
    if afi == PFX_AFI_IP6:
        return 16
    return 0


cdef inline unsigned char pfx_addr_bits(unsigned char afi) nogil:
    """Return the maximum prefix length for an AFI, or 0 if unknown.

    :param afi: IANA address family number.
    :return: 32 for IPv4, 128 for IPv6, 0 otherwise.
    """
    if afi == PFX_AFI_IP:
        return 32
    if afi == PFX_AFI_IP6:
        return 128
    return 0


# --- Bit-level helpers shared by the trie, the resolver and prefix-lists ----
# Bodies live here rather than in prefix.pyx so trie.pyx, table.pyx and the
# policy prefix-lists inline the same code instead of each calling across a
# module boundary on every node visited during a lookup. This is the same
# reason inetpkt.pxd carries the bodies of rd_u16 and friends.
#
# They all index raw C pointers, so Cython emits no bounds or wraparound
# checking for them in the first place and there is nothing for a compiler
# directive to switch off -- see the .pxd directive rule in AGENTS.md. The
# safety contract is instead on the caller: every pointer must address at
# least pfx_addr_len(afi) readable bytes, and every plen must already have
# been range-checked against pfx_addr_bits(afi). Prefix.__init__ and pfx_new
# are the only places that check, which is why the trie can walk millions of
# nodes without re-validating.

cdef inline unsigned int pfx_bit(const unsigned char *addr,
                                 unsigned int pos) nogil:
    """Return bit ``pos`` of an address, counting from the most significant.

    Bit 0 is the top bit of byte 0, which is the order a radix trie
    branches in and the order prefixes are written in.

    :param addr: at least ``(pos >> 3) + 1`` readable bytes.
    :param pos: bit index.
    :return: 0 or 1.
    """
    return (addr[pos >> 3] >> (7 - (pos & 7))) & 1


cdef inline unsigned int pfx_common_bits(const unsigned char *a,
                                         const unsigned char *b,
                                         unsigned int maxbits) nogil:
    """Return the number of leading bits ``a`` and ``b`` share.

    This is the operation path compression is built on: it decides where a
    new node splits an existing edge. ``maxbits`` must be a multiple of 8
    (it is always 32 or 128 here), which removes the partial trailing byte
    case entirely -- callers that care about a prefix length shorter than
    the address cap the result themselves, which is one comparison rather
    than a mask and a shift inside the loop.

    :param a: at least ``maxbits / 8`` readable bytes.
    :param b: at least ``maxbits / 8`` readable bytes.
    :param maxbits: number of bits to compare; a multiple of 8.
    :return: count of matching leading bits, at most ``maxbits``.
    """
    cdef unsigned int nbytes = maxbits >> 3
    cdef unsigned int i = 0
    cdef unsigned int bit
    cdef unsigned char x

    while i < nbytes:
        if a[i] != b[i]:
            # The bytes differ, so the first set bit of the xor is the first
            # differing bit. Scanning from the top is at most 7 iterations
            # and needs no lookup table or compiler intrinsic, which keeps
            # this portable across the gcc 8.5 and clang builds.
            x = a[i] ^ b[i]
            bit = 0
            while (x & 0x80) == 0:
                x = <unsigned char>(x << 1)
                bit += 1
            return (i << 3) + bit
        i += 1
    return maxbits


cdef inline bint pfx_match(const unsigned char *net, unsigned char plen,
                           const unsigned char *addr) nogil:
    """Return whether ``addr`` falls inside the prefix ``net``/``plen``.

    ``net`` is assumed already masked (Prefix guarantees it), so only the
    bits covered by ``plen`` are compared and a plen of 0 matches
    everything, which is what makes a default route work.

    :param net: masked network address.
    :param plen: prefix length in bits.
    :param addr: address to test, same family as ``net``.
    :return: True if ``addr`` is covered by the prefix.
    """
    cdef unsigned int nbytes = plen >> 3
    cdef unsigned int rem = plen & 7

    if nbytes and memcmp(net, addr, nbytes) != 0:
        return 0
    if rem and ((net[nbytes] ^ addr[nbytes]) &
                <unsigned char>(0xff << (8 - rem))):
        return 0
    return 1


cdef inline void pfx_mask(unsigned char *addr, unsigned char plen,
                          unsigned char alen) nogil:
    """Zero every host bit of ``addr``, in place.

    Canonicalising on the way in is what lets equality, hashing and trie
    placement all be byte comparisons: 10.0.0.1/8 and 10.0.0.0/8 become the
    same key, so a peer advertising a sloppy prefix cannot create a second
    entry for a destination that already exists.

    :param addr: ``alen`` writable bytes.
    :param plen: prefix length in bits.
    :param alen: significant address bytes for the family (4 or 16).
    """
    cdef unsigned int nbytes = plen >> 3
    cdef unsigned int rem = plen & 7

    if rem:
        addr[nbytes] = <unsigned char>(addr[nbytes] &
                                       <unsigned char>(0xff << (8 - rem)))
        nbytes += 1
    if nbytes < alen:
        memset(addr + nbytes, 0, alen - nbytes)


cdef inline long pfx_hash_raw(const unsigned char *addr, unsigned char plen,
                              unsigned char afi, unsigned char alen) nogil:
    """Hash a masked prefix key.

    FNV-1a over the significant address bytes plus the length and family. A
    Prefix is a dictionary key on hot paths (the raw Adj-RIB-In is keyed by
    one), so the hash is computed once at construction and cached; this
    function exists so anything holding only raw bytes -- a prefix-list
    lookup, a decode loop deciding whether it already has this key -- can
    compute the same value without building the object first.

    Never returns -1: CPython reserves it for "error" and would call the
    hash again on every lookup of a key that legitimately hashed to it.

    :param addr: masked network address.
    :param plen: prefix length in bits.
    :param afi: IANA address family number.
    :param alen: significant address bytes for the family.
    :return: the hash value.
    """
    cdef unsigned long h = 2166136261UL
    cdef unsigned int i = 0

    while i < alen:
        h = (h ^ addr[i]) * 16777619UL
        i += 1
    h = (h ^ plen) * 16777619UL
    h = (h ^ afi) * 16777619UL
    if <long>h == -1:
        return -2
    return <long>h


# --- The key itself ---------------------------------------------------------

# An (address family, length, masked address) routing key.
#
# Immutable once constructed: the trie stores raw copies of the address and
# the hash is cached, so a mutable Prefix would silently corrupt every
# container holding it. Nothing in this class or the modules that cimport it
# writes to addr after construction.
#
# addr is sized PFX_MAX_ADDR but written as the literal, because an array
# bound in a .pxd is emitted into the generated header ahead of the enum
# that would name it on some Cython versions.

cdef class Prefix:
    cdef readonly unsigned char afi
    cdef readonly unsigned char plen
    # Significant address bytes for the family. Derived from afi, but stored
    # so the trie does not re-derive it for every node it visits.
    cdef readonly unsigned char alen
    cdef unsigned char addr[16]
    cdef long _hash

    cpdef bytes packed(self)
    cpdef str to_str(self)
    cpdef bint contains(self, Prefix other)


# Build a Prefix straight from C memory, for a decode loop that has an NLRI
# in a parse buffer and no reason to allocate a bytes object first.
#
# src is read in the truncated form the wire uses: exactly (plen + 7) / 8
# bytes, the rest of the address zero-filled. That is precisely what BGP
# NLRI, OSPF and RIP all put on the wire, so a caller iterating prefixes can
# pass a pointer into its own buffer with no staging copy. A caller holding a
# full 4- or 16-byte address can pass it too: the extra bytes are host bits
# and would be masked off anyway.
#
# Raises ValueError for an unknown afi or an out-of-range plen. This is the
# validation boundary: past it, the trie and the table treat addr and plen as
# already checked.

cdef Prefix pfx_new(unsigned char afi, unsigned char plen,
                    const unsigned char *src)

# Total order over prefixes: family, then masked address bytes, then length.
#
# That ordering is the trie's own traversal order -- a node sorts before
# every node beneath it, and the 0 subtree before the 1 subtree -- so an
# ordered walk of the trie and a sorted() of the same keys agree. Show output
# and API pagination both depend on that agreement.

cdef int pfx_cmp(Prefix a, Prefix b)
