# cython: language_level=3

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The routing key: an address family, a length and a masked address.

Every RIB, prefix-list, resolver entry and FIB route is keyed by a ``Prefix``.
It is deliberately the smallest thing that can be one:

* the address is stored as raw bytes, not as a string or an ``int``, because
  a full table is a million of these and the trie compares them a byte at a
  time;
* host bits are zeroed at construction, so 10.0.0.1/8 and 10.0.0.0/8 are the
  same key and a peer advertising a non-canonical prefix cannot create a
  duplicate destination;
* the hash is computed once, in the constructor, because a ``Prefix`` spends
  its life as a dictionary key (BGP's raw Adj-RIB-In is keyed by
  ``(prefix, path_id)``) and rehashing 16 bytes per lookup is pure waste;
* the total order is the trie's traversal order, so an ordered walk of a
  table and ``sorted()`` of its keys agree -- which is what lets ``show``
  output and API pagination be consistent.

The family is carried as an IANA Address Family Number (1 for IPv4, 2 for
IPv6), the same value BGP puts in MP_REACH_NLRI, rather than as a socket
``AF_*`` constant whose numbering differs between Linux and macOS.
"""

import socket

from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_FromStringAndSize, \
                           PyBytes_GET_SIZE
from libc.string cimport memcmp, memcpy, memset


# Python-visible spellings of the C constants in prefix.pxd. The C names
# carry the PFX_ prefix precisely so these can exist: a module cannot assign
# to a name its own .pxd has already made a compile-time constant.
AFI_IP = PFX_AFI_IP
AFI_IP6 = PFX_AFI_IP6
SAFI_UNICAST = PFX_SAFI_UNICAST
MAX_ADDR_BYTES = PFX_MAX_ADDR

# Only used by to_str/parse_prefix, which are show, config and test paths.
# Nothing on the decode or selection path touches the socket module.
_AFI_TO_FAMILY = {PFX_AFI_IP: socket.AF_INET, PFX_AFI_IP6: socket.AF_INET6}
_FAMILY_TO_AFI = {socket.AF_INET: PFX_AFI_IP, socket.AF_INET6: PFX_AFI_IP6}


cdef class Prefix:
    """An (address family, prefix length, masked address) routing key.

    Immutable. The trie keeps its own copy of the address bytes and the hash
    is cached, so mutating one after construction would corrupt every
    container holding it; there is deliberately no setter for any field.

    :param afi: IANA address family number -- 1 (IPv4) or 2 (IPv6).
    :param plen: prefix length in bits, 0 to 32 for IPv4 or 0 to 128 for
        IPv6.
    :param addr: the address, exactly 4 or 16 bytes for the family. Host
        bits beyond ``plen`` may be set; they are masked off here.
    :raises ValueError: unknown family, out-of-range length, or an address
        of the wrong size. Construction is the validation boundary for the
        whole RIB: everything below it treats a Prefix as already checked.
    """

    def __init__(self, unsigned char afi, unsigned char plen, bytes addr):
        cdef unsigned char alen = pfx_addr_len(afi)
        cdef Py_ssize_t given

        if alen == 0:
            raise ValueError('unsupported address family number %d' % afi)
        if plen > pfx_addr_bits(afi):
            raise ValueError('prefix length %d out of range for afi %d'
                             % (plen, afi))
        given = PyBytes_GET_SIZE(addr)
        if given != alen:
            raise ValueError('afi %d needs a %d byte address, got %d'
                             % (afi, alen, given))

        self.afi = afi
        self.plen = plen
        self.alen = alen
        # The tail beyond alen is never read, but zeroing the whole buffer
        # keeps two Prefix objects of different families from comparing
        # equal on uninitialised padding if that tail is ever included in a
        # wider memcmp by mistake.
        memset(&self.addr[0], 0, PFX_MAX_ADDR)
        memcpy(&self.addr[0], PyBytes_AS_STRING(addr), alen)
        pfx_mask(&self.addr[0], plen, alen)
        self._hash = pfx_hash_raw(&self.addr[0], plen, afi, alen)

    def __hash__(self):
        # Computed in the constructor; see pfx_hash_raw for why it can never
        # be -1.
        return self._hash

    def __richcmp__(x, y, int op):
        # Cython 0.x has one __richcmp__ per type rather than the six
        # individual methods, and neither operand is guaranteed to be a
        # Prefix -- so this cannot assume `self`.
        cdef int c

        if not (isinstance(x, Prefix) and isinstance(y, Prefix)):
            # Let the other operand's reflected comparison run, and let
            # Python raise the TypeError for an ordering against an
            # unrelated type, rather than inventing an answer here.
            return NotImplemented

        c = pfx_cmp(<Prefix>x, <Prefix>y)
        if op == 0:
            return c < 0
        if op == 1:
            return c <= 0
        if op == 2:
            return c == 0
        if op == 3:
            return c != 0
        if op == 4:
            return c > 0
        return c >= 0

    # Deliberately no __len__: it would read naturally as the mask length,
    # and would also make the default route falsy, so `if prefix:` would
    # quietly skip 0.0.0.0/0. Use `plen`.

    def __repr__(self):
        return "Prefix('%s')" % self.to_str()

    def __str__(self):
        return self.to_str()

    def __reduce__(self):
        # Pickling matters because tests and benchmarks hand tables between
        # processes; reconstructing through __init__ also re-validates.
        return (Prefix, (self.afi, self.plen, self.packed()))

    @property
    def address(self):
        """The masked network address as bytes, 4 or 16 of them."""
        return self.packed()

    @property
    def family(self):
        """The socket address family (``AF_INET`` or ``AF_INET6``)."""
        return _AFI_TO_FAMILY[self.afi]

    @property
    def max_plen(self):
        """The host prefix length for this family: 32 or 128."""
        return pfx_addr_bits(self.afi)

    @property
    def is_host(self):
        """Whether this prefix addresses a single host (/32 or /128)."""
        return self.plen == pfx_addr_bits(self.afi)

    @property
    def is_default(self):
        """Whether this is the default route (0.0.0.0/0 or ::/0)."""
        return self.plen == 0

    cpdef bytes packed(self):
        """Return the masked network address as bytes.

        4 bytes for IPv4 and 16 for IPv6 -- the full address width, not the
        truncated wire form, because callers use this to build next-hops and
        netlink attributes.

        :return: the masked address.
        """
        return PyBytes_FromStringAndSize(<const char*>&self.addr[0],
                                         self.alen)

    cpdef str to_str(self):
        """Return the conventional ``address/length`` text form.

        :return: e.g. ``'10.0.0.0/8'`` or ``'2001:db8::/32'``.
        """
        return '%s/%d' % (socket.inet_ntop(_AFI_TO_FAMILY[self.afi],
                                           self.packed()), self.plen)

    cpdef bint contains(self, Prefix other):
        """Return whether ``other`` falls inside this prefix.

        A prefix contains itself. Different families never contain each
        other, and a longer prefix never contains a shorter one, so this is
        the covering test a resolver or a prefix-list ``le``/``ge`` bound
        needs rather than a bare address match.

        :param other: the prefix to test.
        :return: True if ``other`` is equal to, or more specific than and
            inside, this prefix.
        """
        if other is None or other.afi != self.afi:
            return 0
        if other.plen < self.plen:
            return 0
        return pfx_match(&self.addr[0], self.plen, &other.addr[0])

    @staticmethod
    def from_str(text):
        """Parse ``'address/length'`` into a Prefix.

        :param text: e.g. ``'10.0.0.0/8'``, ``'2001:db8::/32'``, or a bare
            address, which is taken as a host prefix.
        :return: the Prefix.
        :raises ValueError: the text is not a prefix in either family.
        """
        return parse_prefix(text)


def parse_prefix(text):
    """Parse ``'address/length'`` into a :class:`Prefix`.

    The family is inferred from the address -- a colon means IPv6 -- because
    every configuration and API surface writes prefixes the way an operator
    does, without naming the family separately.

    A bare address with no ``/`` is accepted as a host prefix (``/32`` or
    ``/128``), which is what ``ip route`` and ``show ip bgp`` both do.

    Strict about everything else: the length must be plain digits with no
    sign or whitespace, and the address must be canonical for its family, so
    a typo in a configuration file is an error at load time rather than a
    route for somewhere unintended.

    :param text: the prefix text, ``str`` or ASCII ``bytes``.
    :return: the parsed Prefix.
    :raises ValueError: unparseable address, non-numeric or out-of-range
        length.
    """
    cdef unsigned char afi
    cdef object addr_text, plen_text, packed

    if isinstance(text, bytes):
        try:
            text = text.decode('ascii')
        except UnicodeDecodeError:
            raise ValueError('prefix must be ASCII text')
    if not isinstance(text, str):
        raise ValueError('prefix must be a string, not %s'
                         % type(text).__name__)

    if '/' in text:
        addr_text, _, plen_text = text.partition('/')
    else:
        addr_text, plen_text = text, None

    afi = PFX_AFI_IP6 if ':' in addr_text else PFX_AFI_IP
    try:
        packed = socket.inet_pton(_AFI_TO_FAMILY[afi], addr_text)
    except (OSError, ValueError):
        # inet_pton reports a bad address as OSError, which would reach an
        # API handler as a 500. Everything wrong with a prefix is the
        # caller's input, so it is all one ValueError.
        raise ValueError('not a valid address: %r' % (addr_text,))

    if plen_text is None:
        return Prefix(afi, pfx_addr_bits(afi), packed)
    if not plen_text.isdigit():
        raise ValueError('prefix length must be digits: %r' % (plen_text,))
    plen = int(plen_text)
    if plen > pfx_addr_bits(afi):
        raise ValueError('prefix length %d out of range for %s'
                         % (plen, 'IPv6' if afi == PFX_AFI_IP6 else 'IPv4'))
    return Prefix(afi, plen, packed)


def addr_len(afi):
    """Return the significant address byte count for an AFI, or 0.

    The C helper of the same purpose is a ``cdef inline`` in prefix.pxd and
    is not reachable from Python, so this exists for the Python-level
    callers -- configuration validation and the global RIB -- that need to
    reject an unknown family without a try/except around a constructor.

    :param afi: IANA address family number.
    :return: 4 for IPv4, 16 for IPv6, 0 for anything else.
    """
    if not isinstance(afi, int) or isinstance(afi, bool) \
            or afi < 0 or afi > 255:
        return 0
    return pfx_addr_len(<unsigned char>afi)


def addr_bits(afi):
    """Return the host prefix length for an AFI, or 0.

    :param afi: IANA address family number.
    :return: 32 for IPv4, 128 for IPv6, 0 for anything else.
    """
    if not isinstance(afi, int) or isinstance(afi, bool) \
            or afi < 0 or afi > 255:
        return 0
    return pfx_addr_bits(<unsigned char>afi)


def afi_for_family(family):
    """Map a socket address family to its IANA AFI number.

    :param family: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :return: 1 or 2.
    :raises ValueError: any other family.
    """
    try:
        return _FAMILY_TO_AFI[family]
    except KeyError:
        raise ValueError('unsupported socket family %r' % (family,))


def family_for_afi(afi):
    """Map an IANA AFI number to its socket address family.

    :param afi: 1 (IPv4) or 2 (IPv6).
    :return: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :raises ValueError: any other AFI.
    """
    try:
        return _AFI_TO_FAMILY[afi]
    except KeyError:
        raise ValueError('unsupported address family number %r' % (afi,))


cdef Prefix pfx_new(unsigned char afi, unsigned char plen,
                    const unsigned char *src):
    # Declared in prefix.pxd; see there for the wire-truncated src contract.
    cdef Prefix p
    cdef unsigned char alen = pfx_addr_len(afi)
    cdef unsigned char nbytes

    if alen == 0:
        raise ValueError('unsupported address family number %d' % afi)
    if plen > pfx_addr_bits(afi):
        raise ValueError('prefix length %d out of range for afi %d'
                         % (plen, afi))

    # __new__ rather than the constructor: the arguments are already
    # validated above and there is no bytes object to build. This is the
    # allocation a decode loop pays per prefix, so it does exactly one
    # object allocation, one memset, one memcpy and one hash.
    p = Prefix.__new__(Prefix)
    p.afi = afi
    p.plen = plen
    p.alen = alen
    nbytes = (plen + 7) >> 3
    memset(&p.addr[0], 0, PFX_MAX_ADDR)
    if nbytes:
        memcpy(&p.addr[0], src, nbytes)
    # The wire form can carry set host bits in its last byte (a /12 sends
    # two bytes, four of whose bits are outside the prefix), so masking is
    # not optional even though the tail is already zero.
    pfx_mask(&p.addr[0], plen, alen)
    p._hash = pfx_hash_raw(&p.addr[0], plen, afi, alen)
    return p


cdef int pfx_cmp(Prefix a, Prefix b):
    # Declared in prefix.pxd; see there for why this order is the trie's.
    cdef int c

    if a.afi != b.afi:
        return -1 if a.afi < b.afi else 1
    # Both addresses are masked, so comparing the full family width puts a
    # prefix immediately before everything beneath it: 10.0.0.0/8 and
    # 10.0.0.0/16 have identical bytes and are separated by the length test,
    # while 10.0.0.0/8 sorts before 10.1.0.0/16 on the bytes alone.
    c = memcmp(&a.addr[0], &b.addr[0], a.alen)
    if c != 0:
        return -1 if c < 0 else 1
    if a.plen != b.plen:
        return -1 if a.plen < b.plen else 1
    return 0
