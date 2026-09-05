# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from struct import pack, unpack
cimport cython
from cpython.array cimport array, clone
from cpython.bytes cimport PyBytes_FromStringAndSize
from cpython.unicode cimport PyUnicode_DecodeASCII
import binascii
import socket
import re

from libc.stdint cimport uint32_t, uint16_t
from libc.stdlib cimport malloc, realloc, free
from libc.string cimport strlen

# The same conversion the socket module performs, reached directly. An IPv6
# address has no single canonical text form until RFC 5952 zero compression
# is applied, so hand rolling the formatter risks disagreeing with every
# other tool on the host; calling the platform's own converter cannot.
cdef extern from "sys/socket.h":
    int AF_INET6

cdef extern from "arpa/inet.h":
    const char *inet_ntop(int af, const void *src, char *dst,
                          unsigned int size) nogil

offset_re = re.compile(r'^(udp|tcp)\.payload\.offset\[(\d*):(\d*)\]$')

MIN_FRAME_SIZE = 60

PTR_VAL = 0
IPV4_LEN = 4
IPV4_VER = 4
IPV4_MIN_HDR_LEN = 5
IPV6_LEN = 8
IPV6_VER = 6
MAC_LEN = 6
ARP_TYPE_ETH = 1
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2
ARP_OP_RARP_REQUEST = 3
ARP_OP_RARP_REPLY = 4
ARP_OP_DYN_RARP_REQUEST = 5
ARP_OP_DYN_RARP_REPLY = 6
ARP_OP_DYN_RARP_ERR = 7
ARP_OP_INV_REQUEST = 8
ARP_OP_INV_REPLY = 9
ARP_OP_NAK = 10
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_RARP = 0x8035
ETH_TYPE_8021Q = 0x8100
ETH_TYPE_IPV6 = 0x86dd
ETH_TYPE_MPLS_UCAST = 0x8847
ETH_TYPE_MPLS_MCAST = 0x8848
# RFC 3032 puts no ceiling on the MPLS label stack, so the parser has to. A
# label stack is a chain of layer objects, and every layer in it is also a
# frame in the parse, serialize and teardown walks, so an attacker supplied
# stack would otherwise trade 4 bytes of input for unbounded native stack.
# Deployed stacks are a handful of labels deep; past this the remaining bytes
# are kept as an opaque payload so the packet still round trips byte for byte.
MPLS_MAX_STACK_DEPTH = 64
# Smallest legal TCP data offset, in 32 bit words: a header with no options.
TCP_MIN_DATA_OFFSET = 5
# An ICMP error quotes only the first 8 bytes of the TCP header that caused
# it, so that exact length is a valid partial header rather than truncation.
TCP_QUOTE_LEN = 8
ICMP_TYPE_ECHO_REPLY = 0
ICMP_TYPE_DU = 3
ICMP_TYPE_SRC_QUENCH = 4
ICMP_TYPE_REDIR = 5
ICMP_TYPE_ECHO = 8
ICMP_TYPE_TIME_EX = 11
ICMP_TYPE_PER_PROB = 12
ICMP_TYPE_TS = 13
ICMP_TYPE_TS_REPLY = 14
ICMP_TYPE_INFO = 15
ICMP_TYPE_INFO_REPLY = 16
ICMP_DU_CODE_NET_UNREACH = 0
ICMP_DU_CODE_HOST_UNREACH = 1
ICMP_DU_CODE_PROTO_UNREACH = 2
ICMP_DU_CODE_PORT_UNREACH = 3
ICMP_DU_CODE_FRAG_NEEDED = 4
ICMP_DU_CODE_SRC_RT_FAIL = 5
ICMP_DU_CODE_DEST_NET_UNKNOWN = 6
ICMP_DU_CODE_DEST_HOST_UNKNOWN = 7
ICMP_DU_CODE_SRC_HOST_ISOLATED = 8
ICMP_DU_CODE_NET_ADMIN_PROHIBIT = 9
ICMP_DU_CODE_HOST_ADMIN_PROHIBIT = 10
ICMP_DU_CODE_NET_TOS_UNREACH = 11
ICMP_DU_CODE_HOST_TOS_UNREACH = 12
ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT = 13
ICMP_DU_CODE_HOST_PRECEDENCE = 14
ICMP_DU_CODE_PRECEDENCE_CUTOFF = 15
ICMP_REDIR_CODE_NET = 0
ICMP_REDIR_CODE_HOST = 1
ICMP_REDIR_CODE_NET_TOS = 2
ICMP_REDIR_CODE_HOST_TOS = 3
ICMP_TIME_EX_CODE_TTL_EXCEEDED = 0
ICMP_TIME_EX_CODE_FRAG_EXCEEDED = 1
ICMP_PER_PROB_CODE_POINTER = 0
ICMP_PER_PROB_CODE_OPTION_MISSING = 1
ICMP_PER_PROB_CODE_LENGTH = 2
IGMP_MEMBER_QUERY = 0x11
IGMP_V1_MEMBER_REPORT = 0x12
IGMP_V2_MEMBER_REPORT = 0x16
IGMP_V3_MEMBER_REPORT = 0x22
IGMP_LEAVE_GROUP = 0x17
PROTO_ICMP = 1
PROTO_IGMP = 2
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_GRE = 47
PROTO_ICMPV6 = 58
IPV6_HDR_LEN = 40
ICMP6_DST_UNREACH = 1
ICMP6_PKT_TOO_BIG = 2
ICMP6_TIME_EXCEEDED = 3
ICMP6_PARAM_PROB = 4
ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129
ICMP6_MLD_QUERY = 130
ICMP6_MLD_REPORT = 131
ICMP6_MLD_DONE = 132
ICMP6_ND_ROUTER_SOLICIT = 133
ICMP6_ND_ROUTER_ADVERT = 134
ICMP6_ND_NEIGHBOR_SOLICIT = 135
ICMP6_ND_NEIGHBOR_ADVERT = 136
ICMP6_ND_REDIRECT = 137
ICMP6_MLDV2_REPORT = 143
# RFC 4861 section 4.6 Neighbor Discovery option types.
ICMP6_OPT_SRC_LLADDR = 1
ICMP6_OPT_TGT_LLADDR = 2
ICMP6_OPT_PREFIX_INFO = 3
ICMP6_OPT_REDIR_HDR = 4
ICMP6_OPT_MTU = 5
PQ_PKT = 0
PQ_ETH = 1
PQ_FRAME = 2
PQ_ICMP = 3
PQ_IGMP = 4
PQ_IGMPv3GroupRecord = 5
PQ_IP = 0x0800
PQ_IP6 = 0x86dd
PQ_TCP = 6
PQ_UDP = 17
PQ_ICMPV6 = 58
PQ_ARP = 0x0806
PQ_MPLS = 0x8847
PQ_GRE = 47
PQ_NETFLOW_SIMPLE = 2005
PQ_ICMP6OPT = 2006
PQ_MLDV2_ADDRESS_RECORD = 2007
PQ_NULLPKT = 0xffff
NOT_FOUND = -1

# --- Per class pcap_query metadata ------------------------------------------
# Every class used to run ``self.pq_type, self.query_fields = X.query_info()``
# in __init__: a Python classmethod dispatch plus a freshly built tuple, per
# layer, per packet, for metadata only pcap_query ever reads. The tuples are
# built once at import time at the bottom of this module, from the very same
# query_info() classmethods, so there is no second copy of the field lists to
# drift out of step. query_info() itself is unchanged, so the public contract
# is the same.
cdef tuple _QI_PKT
cdef tuple _QI_ARP
cdef tuple _QI_NULLPKT
cdef tuple _QI_NETFLOW_SIMPLE
cdef tuple _QI_UDP
cdef tuple _QI_TCP
cdef tuple _QI_ICMP
cdef tuple _QI_IGMPGroupRecord
cdef tuple _QI_IGMP
cdef tuple _QI_IP
cdef tuple _QI_IP6
cdef tuple _QI_ICMP6
cdef tuple _QI_ICMP6Opt
cdef tuple _QI_MLDv2AddressRecord
cdef tuple _QI_MPLS
cdef tuple _QI_ETH
cdef tuple _QI_GRE

# Address conversion entry points, bound once at import. These sit on the
# construction path (every src/dst set) and on the parse path (every address
# get), where the socket module attribute lookup is pure per-packet tax.
cdef object _inet_aton = socket.inet_aton
cdef object _inet_ntoa = socket.inet_ntoa
cdef object _inet_pton = socket.inet_pton
cdef object _inet_ntop = socket.inet_ntop
cdef object _AF_INET6 = socket.AF_INET6

# Shared empty buffer handed back by from_buffer() on the kwargs (build) path.
# from_buffer used to allocate a throwaway array('B') per layer, per packet,
# purely to be discarded. MUST NOT be mutated in place: it is handed to every
# kwargs construction, so an in place edit would poison every packet built
# afterwards. Callers hold it in a local and rebind rather than extend.
cdef array _EMPTY_BUF = array('B')


@cython.final
cdef class IP_CONST:
    def __cinit__(self):
        self.IPV4_LEN = IPV4_LEN
        self.IPV4_VER = IPV4_VER
        self.IPV4_MIN_HDR_LEN = IPV4_MIN_HDR_LEN
        self.IPV6_LEN = IPV6_LEN
        self.IPV6_VER = IPV6_VER
        self.MAC_LEN = MAC_LEN
        self.ARP_TYPE_ETH = ARP_TYPE_ETH
        self.ARP_OP_REQUEST = ARP_OP_REQUEST
        self.ARP_OP_REPLY = ARP_OP_REPLY
        self.ARP_OP_RARP_REQUEST = ARP_OP_RARP_REQUEST
        self.ARP_OP_RARP_REPLY = ARP_OP_RARP_REPLY
        self.ARP_OP_DYN_RARP_REQUEST = ARP_OP_DYN_RARP_REQUEST
        self.ARP_OP_DYN_RARP_REPLY = ARP_OP_DYN_RARP_REPLY
        self.ARP_OP_DYN_RARP_ERR = ARP_OP_DYN_RARP_ERR
        self.ARP_OP_INV_REQUEST = ARP_OP_INV_REQUEST
        self.ARP_OP_INV_REPLY = ARP_OP_INV_REPLY
        self.ARP_OP_NAK = ARP_OP_NAK
        self.ETH_TYPE_IPV4 = ETH_TYPE_IPV4
        self.ETH_TYPE_ARP = ETH_TYPE_ARP
        self.ETH_TYPE_RARP = ETH_TYPE_RARP
        self.ETH_TYPE_8021Q = ETH_TYPE_8021Q
        self.ETH_TYPE_IPV6 = ETH_TYPE_IPV6
        self.ETH_TYPE_MPLS_UCAST = ETH_TYPE_MPLS_UCAST
        self.ETH_TYPE_MPLS_MCAST = ETH_TYPE_MPLS_MCAST
        self.MPLS_MAX_STACK_DEPTH = MPLS_MAX_STACK_DEPTH
        self.TCP_MIN_DATA_OFFSET = TCP_MIN_DATA_OFFSET
        self.TCP_QUOTE_LEN = TCP_QUOTE_LEN
        self.ICMP_TYPE_ECHO_REPLY = ICMP_TYPE_ECHO_REPLY
        self.ICMP_TYPE_DU = ICMP_TYPE_DU
        self.ICMP_TYPE_SRC_QUENCH = ICMP_TYPE_SRC_QUENCH
        self.ICMP_TYPE_REDIR = ICMP_TYPE_REDIR
        self.ICMP_TYPE_ECHO = ICMP_TYPE_ECHO
        self.ICMP_TYPE_TIME_EX = ICMP_TYPE_TIME_EX
        self.ICMP_TYPE_PER_PROB = ICMP_TYPE_PER_PROB
        self.ICMP_TYPE_TS = ICMP_TYPE_TS
        self.ICMP_TYPE_TS_REPLY = ICMP_TYPE_TS_REPLY
        self.ICMP_TYPE_INFO = ICMP_TYPE_INFO
        self.ICMP_TYPE_INFO_REPLY = ICMP_TYPE_INFO_REPLY
        self.ICMP_DU_CODE_NET_UNREACH = ICMP_DU_CODE_NET_UNREACH
        self.ICMP_DU_CODE_HOST_UNREACH = ICMP_DU_CODE_HOST_UNREACH
        self.ICMP_DU_CODE_PROTO_UNREACH = ICMP_DU_CODE_PROTO_UNREACH
        self.ICMP_DU_CODE_PORT_UNREACH = ICMP_DU_CODE_PORT_UNREACH
        self.ICMP_DU_CODE_FRAG_NEEDED = ICMP_DU_CODE_FRAG_NEEDED
        self.ICMP_DU_CODE_SRC_RT_FAIL = ICMP_DU_CODE_SRC_RT_FAIL
        self.ICMP_DU_CODE_DEST_NET_UNKNOWN = ICMP_DU_CODE_DEST_NET_UNKNOWN
        self.ICMP_DU_CODE_DEST_HOST_UNKNOWN = \
            ICMP_DU_CODE_DEST_HOST_UNKNOWN
        self.ICMP_DU_CODE_SRC_HOST_ISOLATED = \
            ICMP_DU_CODE_SRC_HOST_ISOLATED
        self.ICMP_DU_CODE_NET_ADMIN_PROHIBIT = \
            ICMP_DU_CODE_NET_ADMIN_PROHIBIT
        self.ICMP_DU_CODE_HOST_ADMIN_PROHIBIT = \
            ICMP_DU_CODE_HOST_ADMIN_PROHIBIT
        self.ICMP_DU_CODE_NET_TOS_UNREACH = ICMP_DU_CODE_NET_TOS_UNREACH
        self.ICMP_DU_CODE_HOST_TOS_UNREACH = ICMP_DU_CODE_HOST_TOS_UNREACH
        self.ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT = \
            ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT
        self.ICMP_DU_CODE_HOST_PRECEDENCE = ICMP_DU_CODE_HOST_PRECEDENCE
        self.ICMP_DU_CODE_PRECEDENCE_CUTOFF = \
            ICMP_DU_CODE_PRECEDENCE_CUTOFF
        self.ICMP_REDIR_CODE_NET = ICMP_REDIR_CODE_NET
        self.ICMP_REDIR_CODE_HOST = ICMP_REDIR_CODE_HOST
        self.ICMP_REDIR_CODE_NET_TOS = ICMP_REDIR_CODE_NET_TOS
        self.ICMP_REDIR_CODE_HOST_TOS = ICMP_REDIR_CODE_HOST_TOS
        self.ICMP_TIME_EX_CODE_TTL_EXCEEDED = \
            ICMP_TIME_EX_CODE_TTL_EXCEEDED
        self.ICMP_TIME_EX_CODE_FRAG_EXCEEDED = \
            ICMP_TIME_EX_CODE_FRAG_EXCEEDED
        self.ICMP_PER_PROB_CODE_POINTER = ICMP_PER_PROB_CODE_POINTER
        self.ICMP_PER_PROB_CODE_OPTION_MISSING = \
            ICMP_PER_PROB_CODE_OPTION_MISSING
        self.ICMP_PER_PROB_CODE_LENGTH = ICMP_PER_PROB_CODE_LENGTH
        self.IGMP_MEMBER_QUERY = IGMP_MEMBER_QUERY
        self.IGMP_V1_MEMBER_REPORT = IGMP_V1_MEMBER_REPORT
        self.IGMP_V2_MEMBER_REPORT = IGMP_V2_MEMBER_REPORT
        self.IGMP_V3_MEMBER_REPORT = IGMP_V3_MEMBER_REPORT
        self.IGMP_LEAVE_GROUP = IGMP_LEAVE_GROUP
        self.PROTO_ICMP = PROTO_ICMP
        self.PROTO_IGMP = PROTO_IGMP
        self.PROTO_TCP = PROTO_TCP
        self.PROTO_UDP = PROTO_UDP
        self.PROTO_GRE = PROTO_GRE
        self.PROTO_ICMPV6 = PROTO_ICMPV6
        self.IPV6_HDR_LEN = IPV6_HDR_LEN
        self.ICMP6_DST_UNREACH = ICMP6_DST_UNREACH
        self.ICMP6_PKT_TOO_BIG = ICMP6_PKT_TOO_BIG
        self.ICMP6_TIME_EXCEEDED = ICMP6_TIME_EXCEEDED
        self.ICMP6_PARAM_PROB = ICMP6_PARAM_PROB
        self.ICMP6_ECHO_REQUEST = ICMP6_ECHO_REQUEST
        self.ICMP6_ECHO_REPLY = ICMP6_ECHO_REPLY
        self.ICMP6_MLD_QUERY = ICMP6_MLD_QUERY
        self.ICMP6_MLD_REPORT = ICMP6_MLD_REPORT
        self.ICMP6_MLD_DONE = ICMP6_MLD_DONE
        self.ICMP6_ND_ROUTER_SOLICIT = ICMP6_ND_ROUTER_SOLICIT
        self.ICMP6_ND_ROUTER_ADVERT = ICMP6_ND_ROUTER_ADVERT
        self.ICMP6_ND_NEIGHBOR_SOLICIT = ICMP6_ND_NEIGHBOR_SOLICIT
        self.ICMP6_ND_NEIGHBOR_ADVERT = ICMP6_ND_NEIGHBOR_ADVERT
        self.ICMP6_ND_REDIRECT = ICMP6_ND_REDIRECT
        self.ICMP6_MLDV2_REPORT = ICMP6_MLDV2_REPORT
        self.ICMP6_OPT_SRC_LLADDR = ICMP6_OPT_SRC_LLADDR
        self.ICMP6_OPT_TGT_LLADDR = ICMP6_OPT_TGT_LLADDR
        self.ICMP6_OPT_PREFIX_INFO = ICMP6_OPT_PREFIX_INFO
        self.ICMP6_OPT_REDIR_HDR = ICMP6_OPT_REDIR_HDR
        self.ICMP6_OPT_MTU = ICMP6_OPT_MTU
        self.PQ_PKT = PQ_PKT
        self.PQ_ETH = PQ_ETH
        self.PQ_FRAME = PQ_FRAME
        self.PQ_ICMP = PQ_ICMP
        self.PQ_IGMP = PQ_IGMP
        self.PQ_IGMPv3GroupRecord = PQ_IGMPv3GroupRecord
        self.PQ_IP = PQ_IP
        self.PQ_IP6 = PQ_IP6
        self.PQ_TCP = PQ_TCP
        self.PQ_UDP = PQ_UDP
        self.PQ_ICMPV6 = PQ_ICMPV6
        self.PQ_ARP = PQ_ARP
        self.PQ_MPLS = PQ_MPLS
        self.PQ_GRE = PQ_GRE
        self.PQ_NETFLOW_SIMPLE = PQ_NETFLOW_SIMPLE
        self.PQ_NULLPKT = PQ_NULLPKT


# --- Serialization writer ----------------------------------------------------
# See the PktWriter declaration and the inline w_* field writers in
# inetpkt.pxd for what this is and why. Below is only the memory management.

# Initial capacity. Sized to hold a standard 1500 byte MTU frame plus the
# Ethernet header and a little slack, so the common case never reallocates.
cdef Py_ssize_t _W_INIT_CAP = 1600


@cython.final
cdef class PktWriter:

    def __cinit__(self):
        self.b = <unsigned char *>malloc(_W_INIT_CAP)
        if self.b is NULL:
            raise MemoryError('PktWriter: could not allocate output buffer')
        self.cap = _W_INIT_CAP
        self.n = 0
        self.in_use = 0

    def __dealloc__(self):
        if self.b is not NULL:
            free(self.b)
            self.b = NULL


cdef int w_grow(PktWriter w, Py_ssize_t need) except -1:
    """Grow the output buffer to hold at least ``need`` bytes.

    Called only from the inline w_* writers, and only when a jumbo frame or a
    deeply stacked payload overruns the initial capacity.

    :param w: the writer.
    :param need: total number of bytes the buffer must hold.
    :return: 0, or -1 with MemoryError set.
    """
    cdef:
        Py_ssize_t newcap = w.cap
        unsigned char *nb
    while newcap < need:
        newcap *= 2
    nb = <unsigned char *>realloc(w.b, newcap)
    if nb is NULL:
        raise MemoryError('PktWriter: could not grow output buffer to %d '
                          'bytes' % newcap)
    w.b = nb
    w.cap = newcap
    return 0


# One writer is kept alive for the whole process and handed out again for
# every top level pkt2net call, so the steady state cost of serializing a
# packet is zero allocations for the buffer itself. A second writer is only
# ever created if a layer calls pkt2net on a sub packet while the outer call
# still holds this one -- ICMP does that for its embedded IP header.
cdef PktWriter _WRITER = PktWriter()


cdef PktWriter w_acquire():
    """Return a writer positioned at zero, ready to be written into."""
    cdef PktWriter w = _WRITER
    if w.in_use:
        w = PktWriter()
    w.in_use = 1
    w.n = 0
    return w


cdef bytes _serialize(PKT p, dict kwargs):
    """Run one layer's writer over a fresh buffer and return the bytes.

    Every converted class's pkt2net is this one call. Kept as a single
    function rather than inlined into each of them so the exception handling
    around the writer exists once in the module instead of a dozen times.

    :param p: the layer to serialize.
    :param kwargs: the arguments pkt2net was given.
    :return: the network order bytes for p and everything below it.
    """
    cdef PktWriter w = w_acquire()
    try:
        p._write(w, kwargs)
        return w_take(w, 0)
    finally:
        w_release(w)


cdef void w_release(PktWriter w):
    """Hand the writer back. Must be called even if serialization raised."""
    w.in_use = 0


@cython.boundscheck(False)
@cython.wraparound(False)
cdef uint32_t cksum_acc(const unsigned char *p, Py_ssize_t n, uint32_t s):
    """Add ``n`` bytes into a running one's complement checksum accumulator.

    Split out of ``checksum`` so a pseudo header and a region of the output
    buffer can be summed as two calls instead of being concatenated into a
    throwaway bytes object first -- that concatenation copied the entire
    payload a second time on every checksummed layer.

    An odd trailing byte is folded in as the low byte of a final word, so a
    buffer may only be summed in pieces if every piece except the last has an
    even length. All pseudo headers here are 12 or 40 bytes, so they do.

    :param p: bytes to add.
    :param n: number of bytes to add.
    :param s: accumulator so far, 0 for the first call.
    :return: the updated accumulator. Pass it to cksum_fin when done.
    """
    cdef Py_ssize_t i = 0
    while i + 1 < n:
        s += p[i] | (<uint32_t>p[i + 1] << 8)
        i += 2
    if i < n:
        s += p[i]
    return s


cdef inline uint16_t cksum_fin(uint32_t s):
    """Fold and complement a cksum_acc accumulator into the wire value."""
    cdef uint16_t _s
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    _s = ~s
    return (((_s >> 8) & 0xff) | _s << 8) & 0xffff


cdef inline void ph_addr(unsigned char *dst, bytes v, Py_ssize_t k):
    """Copy a pseudo header address into a fixed size slot.

    Short or missing input is zero padded rather than read past, so a
    hand-built pseudo header used for negative testing cannot walk off the
    end of a bytes object.
    """
    cdef Py_ssize_t n = 0
    if v is not None:
        n = PyBytes_GET_SIZE(v)
    if n > k:
        n = k
    if n:
        memcpy(dst, <const unsigned char *>PyBytes_AS_STRING(v), n)
    if n < k:
        memset(dst + n, 0, k - n)


cdef inline uint16_t w_cksum(PktWriter w, Py_ssize_t start, uint32_t seed):
    """Checksum everything written from ``start`` to the current position.

    Reads the bytes in place, so a layer can checksum itself and its whole
    payload without copying either.
    """
    return cksum_fin(cksum_acc(w.b + start, w.n - start, seed))


@cython.boundscheck(False)
@cython.wraparound(False)
cdef uint16_t checksum(const unsigned char[:] data):
    """16-bit one's complement of the one's complement sum of a byte buffer.
    The buffer is padded with a zero byte if its length is odd.

    Bit-for-bit equivalent to the previous ``array('H', pkt)`` + ``sum()``
    implementation, but computed with a tight C loop over a zero-copy typed
    memoryview instead of allocating a Python array and summing in Python.
    Words are read little-endian and the final result is byte-swapped, matching
    the native-endian semantics of the original ``array('H')`` on x86.

    Args:
        :data (const unsigned char[:]): buffer to checksum. Accepts any
            read-only buffer (e.g. ``bytes``) with no copy.

    Returns:
        uint16_t: 16 bit checksum value.
    """
    cdef:
        Py_ssize_t n = data.shape[0]
        Py_ssize_t i = 0
        uint32_t s = 0
        uint16_t _s
    while i + 1 < n:
        s += data[i] | (<uint32_t>data[i + 1] << 8)
        i += 2
    if i < n:
        # Odd trailing byte: contributes as the low byte of the final word,
        # matching the original's trailing-zero pad + little-endian read.
        s += data[i]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    _s = ~s
    return (((_s >> 8) & 0xff) | _s << 8) & 0xffff


cdef unsigned char is_ipv4(str ip):
    """
    Test if a set of bytes is a valid IPv4 address.
    :param ip: 
    :return: 1/0 depending on if the bytes are a IPv4 address.
    """
    return pack_ipv4(ip) is not None


cdef unsigned char is_ipv6(str ip):
    """Test if a string is a valid IPv6 address.

    :param ip: address string in colon notation (e.g. '2001:db8::1')
    :return: 1/0 depending on whether the string is a valid IPv6 address.
    """
    return pack_ipv6(ip) is not None


cdef bytes pack_ipv4(str ip):
    """Validate and convert a dot notation IPv4 address in one call.

    Every address setter used to call ``is_ipv4()`` -- which converts the
    string inside a try/except purely to throw the result away -- and then
    convert it a second time. Constructing one IP therefore ran four
    conversions for two addresses. Callers raise their own ValueError so the
    public contract is unchanged.

    :param ip: address string in dot notation (e.g. '1.1.1.1')
    :return: the 4 packed network order bytes, or None if ip is not valid.
    """
    try:
        return _inet_aton(ip)
    except (OSError, ValueError):
        return None


cdef array pack_mac(str mac):
    """Convert a colon notation MAC address to an array of 6 bytes.

    Replaces ``array('B', (int(x, 16) for x in val.split(':')))``, which
    allocated a list of six substrings, ran a generator and six int() parses
    per address. Every Ethernet costs two of these -- including the default
    '00:00:00:00:00:00' pair -- which measured as the single largest item on
    the construction path.

    :param mac: address string in colon notation ('01:02:03:04:05:06').
        Non standard forms fall back to the original permissive parse.
    :return: array('B') of the address bytes.
    """
    cdef str hexed = mac.replace(':', '')
    if len(hexed) == 12:            # 6 octets, two hex digits each
        try:
            return array('B', bytes.fromhex(hexed))
        except ValueError:
            pass
    # Fall back to the permissive original for odd input such as single
    # digit groups ('1:2:3:4:5:6') or a non standard address length.
    return array('B', [int(x, 16) for x in mac.split(':')])


# Lowercase hex digits indexed by nibble, and the two separators plus the
# digit base as their ASCII code points -- Cython has no character literal.
# The literal below becomes a C string constant, not a Python object.
cdef const char *_HEX_DIGITS = b'0123456789abcdef'
DEF ASCII_COLON = 0x3a
# Widest text form of a MAC address, written into a stack buffer of exactly
# that size. The dotted quad equivalent lives with _fmt_ipv4_buf in the pxd.
DEF MAC_TEXT_LEN = 17
# INET6_ADDRSTRLEN: 8 groups of 4 hex digits, 7 colons, the IPv4 mapped tail
# and the terminating NUL inet_ntop writes.
DEF IPV6_TEXT_LEN = 46


cdef inline str _fmt_mac_buf(const unsigned char *src):
    """Format 6 address bytes as lowercase colon notation, entirely in C.

    The counterpart of :func:`pack_mac`, and open to the same objection:
    ``"%02x:..." % unpack("BBBBBB", buf)`` is two Python calls and a six
    element tuple per address. Reading an address is not a one off -- a
    pcap_query asking for eth.src and eth.dst pays it twice for every packet
    in the capture -- and it measured larger than parsing the whole frame.

    :param src: at least 6 readable bytes of address.
    :return: the address as a str, e.g. '01:02:03:04:05:06'.
    """
    cdef char out[MAC_TEXT_LEN]
    cdef Py_ssize_t i, j = 0
    cdef unsigned char octet

    for i in range(6):              # MAC_LEN, as a C loop bound
        if i:
            out[j] = ASCII_COLON
            j += 1
        octet = src[i]
        out[j] = _HEX_DIGITS[octet >> 4]
        out[j + 1] = _HEX_DIGITS[octet & 0x0f]
        j += 2
    return PyUnicode_DecodeASCII(out, j, NULL)


cdef inline str _fmt_mac(array mac):
    """Colon notation for an address held as the usual array('B') of 6."""
    if mac is None or len(mac) < 6:
        # Shorter than an address: keep the original code's behaviour of
        # raising out of the unpack rather than inventing bytes.
        return "%02x:%02x:%02x:%02x:%02x:%02x" % unpack("BBBBBB", mac)
    return _fmt_mac_buf(mac.data.as_uchars)


cdef inline array _mac_from_buf(const unsigned char *src):
    """Copy 6 address bytes out of a parse buffer into a fresh array('B').

    ``array('B', rd_bytes(mv, a, b))`` is two allocations and two copies: one
    bytes object purely to hand to the array constructor, then the array
    itself. Every frame parses two MAC addresses before any IP work, so this
    is one allocation and one copy instead of four of each per frame.

    :param src: at least 6 readable bytes of address.
    :return: array('B') of the address bytes.
    """
    cdef array out = clone(_EMPTY_BUF, 6, False)
    memcpy(out.data.as_uchars, src, 6)
    return out


cdef inline str _fmt_ipv4(bytes packed):
    """Format 4 address bytes as dot notation, entirely in C.

    socket.inet_ntoa does the same job correctly, but as a Python call taking
    a bytes argument, and ip.src/ip.dst are the most frequently read fields
    in the library. Anything that is not exactly 4 bytes is handed to
    inet_ntoa so its exception stays the caller's contract.

    The digit writer itself is _fmt_ipv4_buf in inetpkt.pxd, so the proto
    modules parsing straight out of a buffer share it instead of copying it.

    :param packed: the 4 packed network order bytes.
    :return: the address as a str, e.g. '10.1.2.3'.
    """
    if packed is None or PyBytes_GET_SIZE(packed) != 4:
        return _inet_ntoa(packed)
    return _fmt_ipv4_buf(<const unsigned char *>PyBytes_AS_STRING(packed))


cdef inline str _fmt_ipv6(bytes packed):
    """Format 16 address bytes as colon notation, entirely in C.

    socket.inet_ntop is a Python call that packs its arguments, dispatches on
    the address family and builds a str; this is the C function underneath it
    writing into a stack buffer. Anything that is not exactly 16 bytes, or a
    conversion the platform refuses, is handed back to socket.inet_ntop so
    its exception stays the caller's contract.

    :param packed: the 16 packed network order bytes.
    :return: the address as a str, e.g. '2001:db8::1'.
    """
    cdef char out[IPV6_TEXT_LEN]

    if packed is None or PyBytes_GET_SIZE(packed) != 16:
        return _inet_ntop(_AF_INET6, packed)
    if inet_ntop(AF_INET6, PyBytes_AS_STRING(packed), out,
                 IPV6_TEXT_LEN) == NULL:
        return _inet_ntop(_AF_INET6, packed)
    return PyUnicode_DecodeASCII(out, strlen(out), NULL)


cdef inline bytes _payload_offset_bytes(PKT payload, object first,
                                       object last):
    """Bytes ``[first:last]`` of a payload without serializing all of it.

    ``udp.payload.offset[0:32]`` used to answer a 32 byte question by running
    pkt2net over the whole payload -- a full copy of a 1400 byte datagram,
    for every packet in the capture. When layer 7 was not decoded the bytes
    are already held, either directly or as a range in the frame that owns
    them, so only the requested window needs copying. Python slice semantics
    are preserved by handing anything unusual -- negative or out of range
    indices -- back to a real slice.

    :param payload: the payload layer being queried.
    :param first: slice start, as the caller wrote it.
    :param last: slice stop, as the caller wrote it.
    :return: the requested bytes.
    """
    cdef NullPkt raw
    cdef Py_ssize_t a, b, n

    if isinstance(payload, NullPkt):
        raw = <NullPkt>payload
        if raw._payload is not None:
            return raw._payload[first:last]
        n = raw._length
        if 0 <= first <= n and 0 <= last <= n:
            a = first
            b = last
            if a >= b:
                return b''
            return PyBytes_FromStringAndSize(
                PyBytes_AS_STRING(raw._owner) + raw._start + a, b - a)
        return raw._payload_bytes()[first:last]
    return payload.pkt2net({})[first:last]


cdef bytes pack_ipv6(str ip):
    """Validate and convert a colon notation IPv6 address in one call.

    IPv6 counterpart of :func:`pack_ipv4`.

    :param ip: address string in colon notation (e.g. '2001:db8::1')
    :return: the 16 packed network order bytes, or None if ip is not valid.
    """
    try:
        return _inet_pton(_AF_INET6, ip)
    except (OSError, ValueError):
        return None


cdef void set_short_nibble(uint16_t* short_word,
                           unsigned char nibble,
                           unsigned char offset):
    """
    Set the value of a 4 bit nibble in a 16 bit short.
    :param short_word: Pointer to the short to set.
    :param nibble: 4 bit value to set.
    :param offset: 0-15 the offset of the nibble in bits
    :return: void
    """
    short_word[PTR_VAL] = \
        (short_word[PTR_VAL] & ~(0xf << offset)) | (nibble << offset)


cdef void set_char_nibble(unsigned char* char_word,
                          unsigned char nibble,
                          unsigned char offset):
    """
    Set the value of a 4 bit nibble in a 8 bit char.
    :param short_word: Pointer to the char to set.
    :param nibble: 4 bit value to set.
    :param offset: 0-7 the offset of the nibble in bits
    :return: void
    """
    char_word[PTR_VAL] =  \
        (char_word[PTR_VAL] & ~(0xf << offset)) | (nibble << offset)


cdef uint16_t get_short_nibble(uint16_t short_word, unsigned char offset):
    """
    Get 4 bit value from a 16 bit short.
    :param short_word: unsigned short value to get a nibble from.
    :param offset: 0-15 the offset of the nibble in bits
    :return: unsigned short containing value of nibble.
    """
    return (short_word >> offset) & 0xF


cdef unsigned char get_char_nibble(unsigned char char_word,
                                   unsigned char offset):
    """
    Get 4 bit value from a 8 bit char.
    :param char_word: unsigned char value to get a nibble from.
    :param offset: 0-7 the offset of the nibble in bits
    :return: unsigned char containing value of nibble.
    """
    return (char_word >> offset) & 0xF


cdef void set_bit(uint16_t* flags, unsigned char offset):
    """
    Set a single bit in a unsigned short
    :param flags: pointer to 16bit flags value
    :param offset: bit offset from low to high (0-15)
    :return: void
    """
    cdef:
        uint16_t mask
    if offset <= 15:
        mask = 1 << offset
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] | mask
    else:
        raise ValueError("inetpkt.set_bit() offset ({0}) value to large "
                         "for short type".format(offset))


cdef void set_word_bit(uint32_t* flags, unsigned char offset):
    """
    Set a single bit in a unsigned int
    :param flags: pointer to 32bit flags value
    :param offset: bit offset from low to high (0-31)
    :return: void
    """
    cdef:
        uint16_t mask
    if offset <= 31:
        mask = 1 << offset
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] | mask
    else:
        raise ValueError("inetpkt.set_bit() offset ({0}) value to large "
                         "for int type".format(offset))


cdef void set_cbit(unsigned char* flags, unsigned char offset):
    """
    Set a single bit in a unsigned char
    :param flags: pointer to 8bit flags value
    :param offset: bit offset from low to high (0-7)
    :return: void
    """
    cdef:
        unsigned char mask
    if offset <= 7:
        mask = 1 << offset
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] | mask
    else:
        raise ValueError("inetpkt.set_cbit() offset ({0}) value to large "
                         "for unsigned char type".format(offset))


cdef void unset_bit(uint16_t* flags, unsigned char offset):
    """
    Unset a single bit in a unsigned short
    :param flags: pointer to 16bit flags value
    :param offset: bit offset from low to high (0-15)
    :return: void
    """
    cdef:
        uint16_t mask
    if offset <= 15:
        mask = ~(1 << offset)
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] & mask
    else:
        raise ValueError("inetpkt.unset_bit() offset ({0}) value to large "
                         "for short type".format(offset))


cdef void unset_word_bit(uint32_t* flags, unsigned char offset):
    """
    Unset a single bit in a unsigned int
    :param flags: pointer to 32bit flags value
    :param offset: bit offset from low to high (0-31)
    :return: void
    """
    cdef:
        uint16_t mask
    if offset <= 31:
        mask = ~(1 << offset)
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] & mask
    else:
        raise ValueError("inetpkt.unset_bit() offset ({0}) value to large "
                         "for int type".format(offset))


cdef void unset_cbit(unsigned char* flags, unsigned char offset):
    """
    Unset a single bit in a unsigned char
    :param flags: pointer to 8bit flags value
    :param offset: bit offset from low to high (0-7)
    :return: void
    """
    cdef:
        unsigned char mask
    if offset <= 15:
        mask = ~(1 << offset)
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] & mask
    else:
        raise ValueError("inetpkt.unset_cbit() offset ({0}) value to large "
                         "for unsigned char type".format(offset))


cdef class PKT:
    def __init__(self, *args, **kwargs):
        """Initialize a PKT object

        Args:
            :args (list): pass through to sub classes.
            :kwargs (dict): pass through to sub classes excepting 'l7_ports'.
            :l7_ports (dict): A dictionary of <port>: <class>. Used by
                sub classes like TCP and UDP to determine what class to use in
                decoding their payload.

        """
        self.pkt_name = 'PKT'
        self.pq_type, self.query_fields = _QI_PKT
        self._base_l7(kwargs)

    cdef void _base_l7(self, dict kwargs):
        """Lean base initialization shared by all PKT subclasses.

        Only sets up ``l7_ports``; subclasses set their own ``pkt_name`` and
        ``pq_type``/``query_fields`` immediately after calling this, so the
        old ``super().__init__`` path (which also assigned those, only to be
        overwritten) was pure per-packet waste.
        """
        if 'l7_ports' in kwargs and isinstance(kwargs['l7_ports'], dict):
            self._l7_ports = kwargs['l7_ports']
        else:
            self._l7_ports = None
        self._decode_context = kwargs.get('decode_context')
        self._decode_exporter = kwargs.get('exporter')

    property l7_ports:
        """Layer-7 registry, allocated on first public access when absent."""
        def __get__(self):
            if self._l7_ports is None:
                self._l7_ports = {}
            return self._l7_ports

        def __set__(self, value):
            if not isinstance(value, dict):
                raise TypeError('l7_ports must be a dict')
            self._l7_ports = value

    property trailer:
        """Bytes that followed this layer's own declared length.

        IP, IP6 and UDP all carry a length field, and the frame handed to
        them is often longer than that field says: every Ethernet NIC pads
        short frames out to 60 bytes, and captures can carry a trailer. Those
        extra bytes are not payload, so parsing stops at the declared length
        and leaves them here. They are written back out after the payload, so
        a padded frame still re-serializes to the bytes it was parsed from,
        and they are excluded from the length and checksum fields recomputed
        by ``pkt2net({'update': 1, 'csum': 1})``.

        Empty for a layer with no length field, for a layer whose length
        field accounted for every byte, and for any packet built from
        keyword arguments.
        """
        def __get__(self):
            return self._trailer if self._trailer is not None else b''

        def __set__(self, bytes val):
            self._trailer = val if val else None

    @classmethod
    def query_info(cls):
        """ Used by pcap_query to determine what query fields this packet type
        supports and what its PKT type ID is. The PKT type ID is usually the
        layer 4 port number for layer 7 PKT types.

        Returns:
            :tuple: Consisting of PKT type and a tuple of the supported field
                names.
        """
        return (PQ_PKT,
                ())

    @classmethod
    def default_ports(cls):
        """Used by pcap_query to automatically decode layer 7 protocols.

        Returns:
            :list: list of layer 4 ports for 'this' protocol.
        """
        return []

    cpdef object get_field_val(self, str field):
        return None

    cpdef PKT get_layer(self, str name, int instance=1, int found=0):
        """Used to get sub 'layers' of a PKT class based on the name of the
        desired layer.

        Args:
            :name (str): Class name of the desired layer ('IP', 'UDP', ...)
            :instance (int): The Nth instance of the class you want. 
                Useful for PKT types that can exist multiple times in a single 
                packet. Examples include MPLS or Ethernet.
            :found (int): Used in recursive calls to get_layer when instance 
                is > 1

        Returns:
            PKT: The PKT instance OR an empty NullPkt instance if not found.

        """
        cdef:
            int fnd

        fnd = found
        if self.pkt_name == name:
            fnd += 1
            if fnd == instance:
                return self

        if hasattr(self, 'payload') and isinstance(self.payload, PKT):
            if self.payload.pkt_name == name:
                fnd += 1
            if fnd == instance:
                return self.payload
            else:
                return self.payload.get_layer(name,
                                              instance=instance,
                                              found=fnd)
        else:
            return NullPkt()

    cpdef PKT get_layer_by_type(self,
                                uint16_t pq_type,
                                int instance=1,
                                int found=0):
        """Used to get sub 'layers' of a PKT class based on the PKT type ID 
        of the desired layer.

        Args:
            :pq_type (uint16_t): Class type ID of the desired layer. For 
                example PQTYPES.t_ip, PQTYPES.t_udp, ...
            :instance (int): The Nth instance of the class you want. Useful for
                   PKT types that can exist multiple times in a single packet.
                   Examples include MPLS or Ethernet.
            :found (int): Used in recursive calls to get_layer when instance 
                is > 1
        Returns: 
            :PKT: The PKT instance OR an empty NullPkt instance if not found.

        """
        cdef:
            int fnd

        fnd = found

        if self.pq_type == pq_type:
            fnd += 1
            if fnd == instance:
                return self

        if hasattr(self, 'payload') and isinstance(self.payload, PKT):
            if self.payload.pq_type == pq_type:
                fnd += 1
            if fnd == instance:
                return self.payload
            else:
                return self.payload.get_layer_by_type(pq_type,
                                                      instance=instance,
                                                      found=fnd)
        else:
            return NullPkt()

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a PKT based packet class in network order for writing
        to a socket or into a pcap file.

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes.
        Returns: 
            :bytes: network order byte string representation of the PKT 
                instance.
        """

        return b''

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this layer and everything below it to a shared buffer.

        This base implementation is the bridge for classes that still build
        their own bytes: it calls pkt2net and copies the result in. Classes
        that have been converted override it and write their fields directly,
        which is what removes the per layer copy of the payload.

        Args:
            :w (PktWriter): the output buffer to append to.
            :kwargs (dict): the same arguments pkt2net takes.

        Returns:
            :int: 0, or -1 with an exception set.
        """
        return w_bytes(w, self.pkt2net(kwargs))

    cpdef tuple from_buffer(self, tuple args, dict kwargs):
        """Used to determine if the instance is being initialized from data or
        from keyword arguments. If args[0] is an array, bytes, or a string OR
        if a 'data' keyword argument is then the PKT instance is initialized
        from an array of Unsigned chars.

        Args:
            :args (list): array of initialization arguments 
            :kwargs (dict): dictionary of keyword arguments

        Returns: 
            :tuple: First element contains 1 or 0 specifying if the instance
                is or is not initializing from data. The second element of the
                tuple contains the data as an array of unsigned chars if data
                is present. Otherwise an empty array.
        """
        cdef object arg0
        # An array the caller handed in is copied, not adopted. array('B')
        # is mutable and the caller keeps its reference, so returning it as
        # is left the parse exposed to whatever they did to it afterwards -
        # any slice a constructor kept was a live view of their buffer. The
        # owner/offset constructors already copy through tobytes(), so this
        # is the same isolation guarantee for the classes still parsing the
        # old way, at the cost of one copy they were about to make anyway.
        if len(args) == 1:
            arg0 = args[0]
            if isinstance(arg0, array):
                return 1, array('B', arg0)
            elif isinstance(arg0, bytes):
                return 1, array('B', arg0)
        if 'data' in kwargs:
            arg0 = kwargs['data']
            if isinstance(arg0, array):
                return 1, array('B', arg0)
            elif isinstance(arg0, bytes):
                return 1, array('B', arg0)
        return 0, _EMPTY_BUF


@cython.final
cdef class ARP(PKT):

    def __init__(self, *args, **kwargs):
        """Initialize an ARP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an ARP packet
            :data (bytes or array.arry): Optional keyword argument containing
                network order bytes of an ARP packet
            :hardware_type (uint16_t): Network Protocol Type. For example:
                Ethernet is hardware_type 1.
            :proto_type (uint16_t): Network protocol for this ARP request. For
                example this field would be set to 0x800 if this is a IPv4 ARP.
                Valid values for this field are shared with the IEEE 802.3
                EtherType specification used by Ethernet.
            :hardware_len (unsigned char): Length in bytes (octets) for the
                hardware type specified in hardware_type above.
            :proto_len (unsigned char): Length in octets for the proto_type
                specified above. IPv4 has a length of 4 for example.
            :operation (unsigned char): 1 for request and 2 for response.
            :sender_hw_addr (bytes): bytes representation of the senders
                hardware address. For example with hardware_type 1 this would
                be: 'xx:xx:xx:xx:xx:xx'
            :sender_proto_addr (bytes): bytes representation of the senders
                hardware address. For example with proto_type 0x800 this would
                be 'xxx.xxx.xxx.xxx'
            :target_hw_addr (bytes): bytes representation of the targets
                hardware address.
            :target_proto_addr (bytes): bytes representation of the targets
                hardware address.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'ARP'
        self.pq_type, self.query_fields = _QI_ARP

        cdef:
            unsigned char use_buffer
            unsigned int s_proto_start, t_hw_start, t_proto_start, t_proto_end
            bytes tmpbuf
            array buf
            const unsigned char[:] mv
        # buf is a local, not an attribute: the raw bytes are fully consumed
        # here, so retaining them would keep a second copy of every parsed
        # packet alive for the lifetime of the object (plan item B).
        use_buffer, buf = self.from_buffer(args, kwargs)
        self._raw = None
        if use_buffer:
            mv = buf
            need_bytes(mv, 8, 'ARP')
            self.hardware_type = rd_u16(mv, 0)
            self.proto_type = rd_u16(mv, 2)
            self.hardware_len = mv[4]
            self.proto_len = mv[5]
            self.operation = rd_u16(mv, 6)
            if(self.hardware_type == ARP_TYPE_ETH and
                       self.proto_type == ETH_TYPE_IPV4 and
                       self.proto_len == IPV4_LEN):
                need_bytes(mv, 28, 'ARP')
                self._sender_hw_addr = buf[8:14]
                self.sender_proto_addr = _fmt_ipv4(rd_bytes(mv, 14, 18))
                self._target_hw_addr = buf[18:24]
                self.target_proto_addr = _fmt_ipv4(rd_bytes(mv, 24, 28))
            else:
                s_proto_start = 8 + self.hardware_len
                t_hw_start = s_proto_start + self.proto_len
                t_proto_start = t_hw_start + self.hardware_len
                t_proto_end = t_proto_start + self.proto_len
                need_bytes(mv, t_proto_end, 'ARP')
                # Non standard address lengths cannot be re-packed, so this
                # branch alone keeps the raw bytes -- as bytes, not as a
                # second array -- for pkt2net to hand straight back.
                self._raw = rd_bytes(mv, 0, -1)
                self._sender_hw_addr = buf[8:s_proto_start]
                self.sender_proto_addr = \
                    ''.join('%02x' % i for i in
                            mv[s_proto_start:t_hw_start])
                self._target_hw_addr = buf[t_hw_start:t_proto_start]
                self.target_proto_addr = \
                    ''.join('%02x' % i for i in
                            mv[t_proto_start:t_proto_end])
        else:

            self.hardware_type = kwargs.get('hardware_type',
                                            ARP_TYPE_ETH)
            self.proto_type = kwargs.get('proto_type', ETH_TYPE_IPV4)

            self.hardware_len = kwargs.get('hardware_len',MAC_LEN)
            self.proto_len = kwargs.get('proto_len', IPV4_LEN)
            self.operation = kwargs.get('operation', 1)
            if (self.hardware_type == ARP_TYPE_ETH and
                    self.proto_type == ETH_TYPE_IPV4 and
                    self.proto_len == IPV4_LEN):
                self.sender_hw_addr = kwargs.get('sender_hw_addr',
                                                 '00:00:00:00:00:00')
                self.sender_proto_addr = kwargs.get('sender_proto_addr',
                                                    '0.0.0.0')
                self.target_hw_addr = kwargs.get('target_hw_addr',
                                                '00:00:00:00:00:00')
                self.target_proto_addr = kwargs.get('target_proto_addr',
                                                    '0.0.0.0')
            else:
                # No idea how to pack this so build the bytes now.
                # Temporary hack to get around not being able to pack any
                # other supported address types.
                tmpbuf = b'\x00' * (self.hardware_len * 2 + self.proto_len * 2)
                self._raw = pack(b'!HHBBH', self.hardware_type,
                                            self.proto_type,
                                            self.hardware_len,
                                            self.proto_len,
                                            self.operation) + tmpbuf

    property sender_hw_addr:
        def __get__(self):
            return _fmt_mac(self._sender_hw_addr)
        def __set__(self, str val):
            self._sender_hw_addr = pack_mac(val)

    property target_hw_addr:
        def __get__(self):
            return _fmt_mac(self._target_hw_addr)
        def __set__(self, str val):
            self._target_hw_addr = pack_mac(val)

    @classmethod
    def query_info(cls):
        """classmethod - provides pcap_query with the query fields ARP
        supports and ARP's PKT type ID.

        Returns:
            :tuple: 2 elements: PQTYPES.t_arp and a tuple of the supported
                field names.
        """
        return (ETH_TYPE_ARP,
                ('arp.hw.type', 'arp.proto.type', 'arp.hw.size',
                 'arp.proto.size', 'arp.opcode', 'arp.src.hw_mac',
                 'arp.src.proto_ipv4', 'arp.dst.hw_mac',
                 'arp.dst.proto_ipv4'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as
        an if, elif, else set because Cython documentation shows that this
        form is turned that into an efficient case switch.

        Args:
            :field (str): name of the desired field in Wireshark format. For
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """
        if field == 'arp.hw.type':
            return self.hardware_type
        elif field == 'arp.proto.type':
            return self.proto_type
        elif field == 'arp.hw.size':
            return self.hardware_len
        elif field == 'arp.proto.size':
            return self.proto_len
        elif field == 'arp.opcode':
            return self.operation
        elif field == 'arp.src.hw_mac':
            return self.sender_hw_addr
        elif field == 'arp.src.proto_ipv4':
            return self.sender_proto_addr
        elif field == 'arp.dst.hw_mac':
            return self.target_hw_addr
        elif field == 'arp.dst.proto_ipv4':
            return self.target_proto_addr
        else:
            return None

    property operation:
        """
        Get and Set the ARP operation value.
        """
        def __get__(self):
            """
            Get ARP.operation

            Returns:
                :uint16_t: current operation value.
            """
            return self._operation
        def __set__(self, uint16_t val):
            """
            Set ARP.operation

            Args:
            :val (uint16_t): 16-bit unsigned operation code.
            """
            self._operation = val

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a ARP packet class instance in network order for
        writing to a socket or into a pcap file. At present this function
        only works Ethernet/IPv4 ARP packets OR if buffer was set. If this is
        not a self.hardware_type == ARP_CONST.hwt_ether,
        self.proto_type == ETHERTYPES.ipv4 packet BUT buffer is set then the
        packet in will simply be repeated from the buffer. Any changes are
        lost.

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. ARP
                does not support any key work arguments and does not have a
                payload so any args passed will be ignored.
        Returns:
            :bytes: network order byte string representation of the ARP
                instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this ARP packet to a shared buffer. See PKT._write."""
        if(self.hardware_type == ARP_TYPE_ETH and
               self.proto_type == ETH_TYPE_IPV4 and
               self.proto_len == IPV4_LEN):
            w_u16(w, self.hardware_type)
            w_u16(w, self.proto_type)
            w_u8(w, self.hardware_len)
            w_u8(w, self.proto_len)
            w_u16(w, self._operation)
            w_raw(w, self._sender_hw_addr.data.as_uchars,
                  len(self._sender_hw_addr))
            w_bytes(w, _inet_aton(self.sender_proto_addr))
            w_raw(w, self._target_hw_addr.data.as_uchars,
                  len(self._target_hw_addr))
            w_bytes(w, _inet_aton(self.target_proto_addr))
        else:
            w_bytes(w, self._raw)
        return 0


@cython.final
cdef class NullPkt(PKT):
    """
    NullPkt is a catch all packet type that can be used to simply store
    packet bytes without any decode.
    """
    def __init__(self, *args, **kwargs):
        """ Initialize an NullPkt object.

        Args:
        :args (list): Optional one element list containing network order bytes
            of an ARP packet
        :data (bytes): Optional keyword argument containing network order bytes
            of an ARP packet
        """
        self._base_l7(kwargs)
        self.pkt_name = 'NullPkt'
        self.pq_type, self.query_fields = _QI_NULLPKT

        # NullPkt is the one class whose buffer *is* its content, so it is
        # kept -- but as bytes rather than an array('B'). from_buffer would
        # copy bytes input into an array only for every accessor to copy it
        # straight back out again, so the arg is unpacked directly here and
        # a bytes payload is now stored with no copy at all. That matters:
        # NullPkt wraps the payload of every packet whose layer 7 is not
        # decoded.
        cdef object arg0 = None
        self._owner = None
        self._start = 0
        self._length = 0
        if len(args) == 1:
            arg0 = args[0]
        elif 'data' in kwargs:
            arg0 = kwargs['data']

        if arg0 is None:
            self._payload = b''
        elif isinstance(arg0, bytes):
            self._payload = arg0
        elif isinstance(arg0, array):
            self._payload = (<array>arg0).tobytes()
        else:
            # from_buffer ignored anything that was not bytes or array('B'),
            # so an unusable arg still yields an empty packet, not a TypeError.
            self._payload = b''

    cdef bytes _payload_bytes(self):
        if self._payload is not None:
            return self._payload
        return PyBytes_FromStringAndSize(
            PyBytes_AS_STRING(self._owner) + self._start, self._length)

    @classmethod
    def query_info(cls):
        """pseudo pcap_query support for query_info.

        Returns:
            :tuple: PQTYPES.t_nullpkt and an empty field list
        """
        return (PQ_NULLPKT,
                ())

    property payload:
        """
        get and set payload bytes
        """
        def __get__(self):
            return self._payload_bytes()

        def __set__(self, bytes value):
            self._payload = value
            self._owner = None
            self._start = 0
            self._length = 0

    property fake_proto_id:
        """
        get the first two bytes of payload as an short
        """
        def __get__(self):
            cdef const unsigned char[:] mv
            if self._payload is not None:
                if len(self._payload) >= 2:
                    mv = self._payload
                    return rd_u16(mv, 0)
            elif self._length >= 2:
                mv = self._owner
                return rd_u16(mv, self._start)

    def __repr__(self):
        return '{0}: {1}'.format(
            self.pkt_name,
            self._payload_bytes().decode('utf-8', 'replace'))

    cpdef object get_field_val(self, str field):
        """
        pseudo pcap_query support for get_field_val.
        """
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a NullPkt object for writing to a socket or into 
        a pcap file. Data is exactly as it came in.

        Args:
            :kwargs (dict): Ignored

        Returns:
            :bytes: The NullPkt data exactly as it came into __init__
        """
        return self._payload_bytes()

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append the raw payload bytes. See PKT._write."""
        if self._payload is not None:
            return w_bytes(w, self._payload)
        return w_raw(w, <const unsigned char*>PyBytes_AS_STRING(self._owner) +
                     self._start, self._length)


@cython.final
cdef class Ip4Ph:
    """
    Class to encapsulate an IPv4 pseudo header. Used in pkt2net functions
    for TCP and UDP. Part of checksum calculation. Automatically passed in
    to pkt2net by IP if its payload is TCP or UDP
    """

    def __init__(self, **kwargs):
        """Initialize a new Ip4Ph object. Actual initialization is done by the
        classes Cython __cinit__ function. __init__ exists to support
        documentation generation.

        Args:
            :src (bytes): IPv4 src address for parent IP Object
            :dst (bytes ): IPv4 dst address for parent IP Object
            :reserved (unsigned char): unused 8 bits in pseudo header. Should
                be 0
            :proto (unsigned char): Proto of parent IP object.
            :payload_len (uint16_t): Total length of IP payload in octets.

        """

    def __cinit__(self, **kwargs):
        """The real C level init function for Ip4Ph. __init__ above is only
        for documentation.
        """
        self.src = kwargs.get('src', b'\x00\x00\x00\x00')
        self.dst = kwargs.get('dst', b'\x00\x00\x00\x00')
        self.reserved = kwargs.get('reserved', 0)
        self.proto = kwargs.get('proto', 0)
        self.payload_len = kwargs.get('payload_len', 0)


@cython.final
cdef class Ip6Ph:
    """Encapsulates an IPv6 pseudo header (RFC 2460 sec 8.1). Used in the
    pkt2net checksum calculations for TCP, UDP and ICMPv6. Automatically
    passed to the layer 4 pkt2net by IP6 under the ``ipv6_pheader`` kwarg.

    The pseudo header layout is::

        +------------------- 16 bytes -------------------+
        |                 Source Address                 |
        +------------------- 16 bytes -------------------+
        |              Destination Address               |
        +---------------------- 4 bytes -----------------+
        |             Upper-Layer Packet Length          |
        +------------ 3 bytes ------------+--- 1 byte ---+
        |                 zero            |  Next Header  |
        +--------------------------------+---------------+

    The upper-layer length is supplied by the layer 4 class (it already
    tracks its own length) so this object only carries src, dst and nh.
    """

    def __init__(self, **kwargs):
        """Initialize a new Ip6Ph object. Actual initialization happens in
        __cinit__; __init__ exists for documentation generation.

        Args:
            :src (bytes): 16-byte IPv6 src address of the parent IP6 object.
            :dst (bytes): 16-byte IPv6 dst address of the parent IP6 object.
            :nh (unsigned char): upper-layer protocol number (6, 17 or 58).
        """

    def __cinit__(self, **kwargs):
        """The real C level init for Ip6Ph. __init__ above is documentation."""
        self.src = kwargs.get('src', b'\x00' * 16)
        self.dst = kwargs.get('dst', b'\x00' * 16)
        self.nh = kwargs.get('nh', 0)


@cython.final
cdef class NetflowSimple(PKT):
    """
    A Netflow decoder used by Riverbed's QA group to replay
    captured netflow data. This packet type only decodes enough of a
    Netflow version 1-9 packet to allow the timestamps to be altered.
    Useful to make previously captured flows appear to a Netflow analyzer
    to have happened 'now'. Be aware that the field unix_nano_seconds in
    this packet type is not accurately defined if the version is 9.
    """

    def __init__(self, *args, **kwargs):
        """Initialize a NetflowSimple object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an ARP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an ARP packet
            :version (uint16_t): Netflow version (1-9)
            :count (uint16_t): Count of records if version is 1-8 or count of
                flow sets if version is 9
            :sys_uptime (uint32_t): Current time in milliseconds since the
                export device started at the moment the netflow packet was
                sent.
            :unix_secs (uint32_t): Seconds since the start of the epoch
            :unix_nano_seconds (uint32_t): nanoseconds remaining from
                unix_secs. This field will not be correct IF the version is 9
            :payload (bytes): The rest of the netflow packet as bytes.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'NetflowSimple'
        self.pq_type, self.query_fields = _QI_NETFLOW_SIMPLE
        cdef:
            unsigned char use_buffer
            array buf
            const unsigned char[:] mv
        use_buffer, buf = self.from_buffer(args, kwargs)

        if use_buffer:
            mv = buf
            need_bytes(mv, 16, 'NetflowSimple')
            self.version = rd_u16(mv, 0)
            self.count = rd_u16(mv, 2)
            self.sys_uptime = rd_u32(mv, 4)
            self.unix_secs = rd_u32(mv, 8)
            self.unix_nano_seconds = rd_u32(mv, 12)

            if mv.shape[0] > 16:
                self.payload = rd_bytes(mv, 16, -1)
            else:
                self.payload = b''
        else:
            self.version = kwargs.get('version', 0)
            self.count = kwargs.get('count', 0)
            self.sys_uptime = kwargs.get('sys_uptime', 0)
            self.unix_secs = kwargs.get('unix_secs', 0)
            self.unix_nano_seconds = kwargs.get('unix_nano_seconds', 0)
            self.payload = kwargs.get('payload', b'')

    @classmethod
    def query_info(cls):
        """classmethod - provides pcap_query with the query fields
        NetflowSimple supports and NetflowSimple's PKT type ID.

        Returns:
            :tuple: PQTYPES.t_netflow_simple and a tuple of the supported
            field names.
        """
        return (PQ_NETFLOW_SIMPLE,
                ('netflow.version', 'netflow.count', 'netflow.sys_uptime',
                 'netflow.unix_secs', 'netflow.unix_nano_seconds'))

    @classmethod
    def default_ports(cls):
        """
        Used by pcap_query to automatically decode layer 7 protocols.
        The default Layer 4 ports for netflow are 2005 and 2055.

        NOTE: 2055 is claimed by packets.protos.netflow.Netflow as well, so
        a caller building one l7_ports mapping out of both classes gets
        whichever it merged last on that port, silently. The two are not
        interchangeable: NetflowSimple keeps the datagram opaque behind its
        header, which is what replay and pass-through want, while Netflow
        decodes flowsets and records. Decide per port which one you mean,
        for instance {2005: NetflowSimple, 2055: Netflow}.

        Returns:
            :list: layer 4 ports for NetflowSimple.
        """
        return [2005, 2055]

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (str): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """
        if field == 'netflow.version':
            return self.version
        elif field == 'netflow.count':
            return self.count
        elif field == 'netflow.sys_uptime':
            return self.sys_uptime
        elif field == 'netflow.unix_secs':
            return self.unix_secs
        elif field == 'netflow.unix_nano_seconds':
            return self.unix_nano_seconds
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a NetflowSimple packet class instance in network 
        order for writing to a socket or into a pcap file.

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                NetflowSimple does not support any key work arguments and 
                does not have a PKT class payload so any args passed will 
                be ignored.
        Returns: 
            :bytes: network order byte string representation of the 
                NetflowSimple instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this NetflowSimple header and payload to a shared buffer.
        See PKT._write."""
        w_u16(w, self.version)
        w_u16(w, self.count)
        w_u32(w, self.sys_uptime)
        w_u32(w, self.unix_secs)
        w_u32(w, self.unix_nano_seconds)
        w_bytes(w, self.payload)
        return 0


cdef type _l7_pkt_cls(dict l7_ports, uint16_t sport, uint16_t dport):
    cdef object configured
    cdef object pkt_cls

    if dport in l7_ports:
        configured = l7_ports[dport]
    elif sport in l7_ports:
        configured = l7_ports[sport]
    elif len(l7_ports) == 1 and 0 in l7_ports:
        configured = l7_ports[0]
    else:
        return NullPkt

    if isinstance(configured, type):
        pkt_cls = configured
    elif isinstance(configured, str):
        pkt_cls = globals()[configured]
    else:
        raise TypeError('l7_ports values must be PKT subclasses or built-in '
                        'class names')
    if not issubclass(pkt_cls, PKT):
        raise TypeError('l7_ports values must be PKT subclasses')
    return pkt_cls


cdef inline int _init_udp_kwargs(UDP pkt, dict kwargs) except -1:
    """Initialize a newly allocated UDP object without generic buffer work.

    Extension attributes start at zero, so absent zero-default fields need no
    dictionary lookup followed by an assignment. Explicit values still pass
    through the same typed attributes, and payload handling remains identical
    to the public constructor's established behavior.
    """
    cdef object payload
    if 'sport' in kwargs:
        pkt.sport = kwargs['sport']
    if 'dport' in kwargs:
        pkt.dport = kwargs['dport']
    if 'ulen' in kwargs:
        pkt.ulen = kwargs['ulen']
    if 'checksum' in kwargs:
        pkt.checksum = kwargs['checksum']
    if 'payload' in kwargs:
        payload = kwargs['payload']
        if isinstance(payload, PKT):
            pkt.payload = payload
        elif isinstance(payload, bytes):
            pkt.app_layer(array('B', b'\x00' * 8 + payload))
        else:
            pkt.payload = NullPkt()
    else:
        pkt.payload = NullPkt()
    return 0


@cython.final
cdef class UDP(PKT):
    def __init__(self, *args, **kwargs):
        """Initialize a UDP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an UDP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an UDP packet
            :sport (uint16_t): Layer 4 source port of this packet
            :dport (uint16_t): Layer 4 destination port of this packet
            :ulen (uint16_t): UDP Length - Total length of the UDP header plus
                data in bytes
            :checksum (uint16_t): The checksum value for this packet. Optional
                with IPv4 and must be 0 if not used.
            :payload (PKT or bytes): The payload of this packet.
            :l7_ports: A dictionary where the keys are layer 4 port numbers
                   and the values are PKT subclass packet classes. Used by
                   UDP.app_layer() to determine what class should be used to
                   decode the payload string or byte array.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'UDP'
        self.pq_type, self.query_fields = _QI_UDP
        cdef:
            unsigned char use_buffer
            array buf
            const unsigned char[:] mv
            bytes owner
        if not args and 'data' not in kwargs:
            _init_udp_kwargs(self, kwargs)
            return
        owner = _owned_buffer(args, kwargs)
        if owner is not None:
            mv = owner
            _decode_udp(self, owner, mv, 0, len(owner), self._l7_ports)
            return
        use_buffer, buf = self.from_buffer(args, kwargs)
        if use_buffer:
            mv = buf
            need_bytes(mv, 8, 'UDP')
            self.sport = rd_u16(mv, 0)
            self.dport = rd_u16(mv, 2)
            self.ulen = rd_u16(mv, 4)
            self.checksum = rd_u16(mv, 6)
            self.app_layer(buf)
        else:
            self.sport = kwargs.get('sport', 0)
            self.dport = kwargs.get('dport', 0)
            self.ulen = kwargs.get('ulen', 0)
            self.checksum = kwargs.get('checksum', 0)
            if 'payload' in kwargs:
                if isinstance(kwargs['payload'], PKT):
                   self.payload = kwargs['payload']
                elif isinstance(kwargs['payload'], bytes):
                    self.app_layer(
                        array('B', (b'\x00' * 8 + kwargs['payload'])))
                else:
                    self.payload = NullPkt()
            else:
                self.payload = NullPkt()

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields UDP supports and UDP's
        PKT type ID.

        Returns:
            :tuple: PQTYPES.t_udp and a tuple of the supported field names.
        """
        return (PQ_UDP,
                ('udp.srcport', 'udp.dstport', 'udp.length',
                 'udp.checksum', 'udp.payload','udp.payload.offset[x:y]'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch. Also handles 
        udp.payload.offset[x:y] field.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns: 
            :object: value of the field.
        """
        cdef list offsets
        cdef f = field[:18]
        if f == 'udp.srcport':
            return self.sport
        elif f == 'udp.dstport':
            return self.dport
        elif f == 'udp.length':
            return self.ulen
        elif f == 'udp.checksum':
            return self.checksum
        elif f == 'udp.payload':
            return self.payload.pkt2net({})
        elif f == 'udp.payload.offset':
            offsets = (field[19:field.index(']')].split(':'))
            if len(offsets) == 2:
                return _payload_offset_bytes(self.payload,
                                             int(offsets[0]),
                                             int(offsets[1]))
            return None
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a UDP packet class instance in network order  for 
        writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by UDP to payload classes. UDP supports the 
                following keyword arguments:
            :csum (0 or 1): Determines if this UDP instance should re-calculate 
                its checksum.
            :update (0 or 1): Determines if this UDP instance and any sub 
                layers should update size counters. For UDP this means updating
                the ulen variable.
            :ipv4_pheader (Ip4Ph): IPv4 pseudo header used in checksum 
                calculation.

        Returns: 
            :bytes: network order byte string representation of this UDP 
                instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this UDP header and its payload to a shared buffer.

        ulen and the checksum both depend on the payload behind them, so the
        header goes out first with those two fields as placeholders and they
        are patched back into the buffer afterwards. The checksum is then
        taken directly over the pseudo header and the bytes already sitting
        in the buffer, which is what removes the second full copy of the
        payload the old bytes-concatenating version needed. See PKT._write.
        """
        cdef:
            unsigned char _update, _csum
            Ip4Ph _ipv4_pheader
            Ip6Ph _ipv6_pheader
            Py_ssize_t start
            unsigned char ph[40]

        _update = kwargs.get('update', 0)
        if kwargs.get('udp_csum'):
            _csum = kwargs.get('udp_csum')
            self.checksum = 0
        else:
            _csum = kwargs.get('csum', 0)
        _ipv4_pheader = kwargs.get('ipv4_pheader', Ip4Ph())
        _ipv6_pheader = kwargs.get('ipv6_pheader')

        start = w.n
        w_u16(w, self.sport)
        w_u16(w, self.dport)
        w_u16(w, self.ulen)
        w_u16(w, self.checksum)

        self.payload._write(w, kwargs)

        if _update:
            self.ulen = <uint16_t>(w.n - start)
            w_set_u16(w, start + 4, self.ulen)

        if _csum and _ipv6_pheader is not None:
            ph_addr(ph, _ipv6_pheader.src, 16)
            ph_addr(ph + 16, _ipv6_pheader.dst, 16)
            ph[32] = 0
            ph[33] = 0
            ph[34] = <unsigned char>(self.ulen >> 8)
            ph[35] = <unsigned char>(self.ulen & 0xff)
            ph[36] = 0
            ph[37] = 0
            ph[38] = 0
            ph[39] = _ipv6_pheader.nh
            w_set_u16(w, start + 6, 0)
            self.checksum = w_cksum(w, start, cksum_acc(ph, 40, 0))
            # RFC 768: a computed UDP checksum of zero goes on the wire as
            # 0xffff, because zero is the encoding for 'no checksum sent'.
            # Over IPv6 the checksum is not optional at all (RFC 8200 s8.1),
            # so zero there is simply an invalid datagram. Storing whatever
            # the fold produced meant a payload whose ones complement sum
            # happened to come out zero silently turned the checksum off.
            if self.checksum == 0:
                self.checksum = 0xffff
            w_set_u16(w, start + 6, self.checksum)
        elif _csum and isinstance(_ipv4_pheader, Ip4Ph):
            ph_addr(ph, _ipv4_pheader.src, 4)
            ph_addr(ph + 4, _ipv4_pheader.dst, 4)
            ph[8] = <unsigned char>(_ipv4_pheader.proto >> 8)
            ph[9] = <unsigned char>(_ipv4_pheader.proto & 0xff)
            ph[10] = <unsigned char>(self.ulen >> 8)
            ph[11] = <unsigned char>(self.ulen & 0xff)
            w_set_u16(w, start + 6, 0)
            self.checksum = w_cksum(w, start, cksum_acc(ph, 12, 0))
            # See the IPv6 branch above: RFC 768 reserves zero for 'no
            # checksum', so a computed zero is transmitted as 0xffff.
            if self.checksum == 0:
                self.checksum = 0xffff
            w_set_u16(w, start + 6, self.checksum)

        # Frame bytes that sat behind ulen when this packet was parsed. Both
        # checksum branches above run w_cksum over start..w.n, so these have
        # to go out after them as well as after the length patch.
        if self._trailer is not None:
            w_bytes(w, self._trailer)
        return 0

    cdef app_layer(self, array buf):
        """Attempts to create an instance of the correct layer 7 protocol
        if the layer 4 ports match. Otherwise sets payload to a NullPkt.
        instance.

        Args:
            :buf (array): the raw layer 4 bytes. Passed in rather than read
                from an attribute so UDP does not have to retain a copy of
                every packet it parses (plan item B).
        """
        cdef type pkt_cls
        pkt_cls = NullPkt
        if len(buf) > 8 and self._l7_ports:
            pkt_cls = _l7_pkt_cls(self._l7_ports, self.sport, self.dport)
        self.payload = pkt_cls(buf[8:])


cdef inline int _init_tcp_kwargs(TCP pkt, dict kwargs) except -1:
    """Initialize a newly allocated TCP object from construction keywords."""
    cdef object payload
    pkt._pad = b''
    if 'sport' in kwargs:
        pkt.sport = kwargs['sport']
    if 'dport' in kwargs:
        pkt.dport = kwargs['dport']
    if 'sequence' in kwargs:
        pkt.sequence = kwargs['sequence']
    if 'acknowledgment' in kwargs:
        pkt.acknowledgment = kwargs['acknowledgment']
    if 'data_offset' in kwargs:
        # Preserve validation even though the options setter below determines
        # the final header length, as the established constructor does.
        pkt.data_offset = kwargs['data_offset']
    if 'flag_ns' in kwargs:
        pkt.flag_ns = kwargs['flag_ns']
    if 'flag_cwr' in kwargs:
        pkt.flag_cwr = kwargs['flag_cwr']
    if 'flag_ece' in kwargs:
        pkt.flag_ece = kwargs['flag_ece']
    if 'flag_urg' in kwargs:
        pkt.flag_urg = kwargs['flag_urg']
    if 'flag_ack' in kwargs:
        pkt.flag_ack = kwargs['flag_ack']
    if 'flag_psh' in kwargs:
        pkt.flag_psh = kwargs['flag_psh']
    if 'flag_rst' in kwargs:
        pkt.flag_rst = kwargs['flag_rst']
    if 'flag_syn' in kwargs:
        pkt.flag_syn = kwargs['flag_syn']
    if 'flag_fin' in kwargs:
        pkt.flag_fin = kwargs['flag_fin']
    if 'window' in kwargs:
        pkt.window = kwargs['window']
    if 'checksum' in kwargs:
        pkt.checksum = kwargs['checksum']
    if 'urg_ptr' in kwargs:
        pkt.urg_ptr = kwargs['urg_ptr']
    pkt.options = kwargs.get('options', b'')
    if 'payload' in kwargs:
        payload = kwargs['payload']
        if isinstance(payload, PKT):
            pkt.payload = payload
        elif isinstance(payload, bytes):
            pkt.app_layer(array('B',
                                b'\x00' * (pkt.data_offset * 4) + payload))
        else:
            pkt.payload = NullPkt()
    else:
        pkt.payload = NullPkt()
    return 0


@cython.final
cdef class TCP(PKT):
    def __init__(self, *args, **kwargs):
        """Initialize a TCP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an TCP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an TCP packet
            :sport (uint16_t): Layer 4 source port of this packet
            :dport (uint16_t): Layer 4 destination port of this packet
            :sequence (uint32_t): TCP sequence number.
            :acknowledgment (uint32_t): Acknowledgment number.
            :data_offset (uint16_t): Size of the TCP header in 32-bit 'words'.
                Min is 5.
            :flag_ns (0 or 1): ECN-nonce concealment protection (RFC 3540).
            :flag_cwr (0 or 1): Congestion Window Reduced flag (RFC 3168).
            :flag_ece (0 or 1): ECN-Echo flag (RFC 3168).
            :flag_urg (0 or 1): flag that the Urgent pointer field is
                significant.
            :flag_ack (0 or 1): flag that Acknowledgment field is significant.
            :flag_psh (0 or 1): flag requesting buffered data be pushed to the
                receiving application.
            :flag_rst (0 or 1): Reset the connection
            :flag_syn (0 or 1): Synchronize sequence numbers. Starts TCP
                handshake.
            :flag_fin (0 or 1): Flag as the last package from src of this
                packet.
            :window (uint16_t): Size of the receive window (default in bytes).
            :checksum (uint16_t): The 16-bit checksum field.
            :urg_ptr (uint16_t): Offset from the sequence number indicating the
                last urgent data byte. Use urg flag if set.
            :options (bytes): Array of bytes to use as the TCP options. The
                user must update data_offset and make these bytes align to
                32bit words. This is not fully implemented in this PKT class.
            :payload (PKT or bytes): The payload of this packet.
            :l7_ports (dict): A dictionary where the keys are layer 4 port
                numbers and the values are PKT subclass packet classes. Used by
                TCP.app_layer() to determine what class should be used to
                decode the payload string or byte array.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'TCP'
        self.pq_type, self.query_fields = _QI_TCP
        cdef:
            unsigned char use_buffer
            array buf
            const unsigned char[:] mv
            bytes owner
        if not args and 'data' not in kwargs:
            _init_tcp_kwargs(self, kwargs)
            return
        owner = _owned_buffer(args, kwargs)
        if owner is not None:
            mv = owner
            _decode_tcp(self, owner, mv, 0, len(owner), self._l7_ports,
                        kwargs)
            return
        use_buffer, buf = self.from_buffer(args, kwargs)
        self.ws_len = len(buf)
        self._pad = b''

        if use_buffer and self.ws_len >= 20:
            mv = buf
            self.sport = rd_u16(mv, 0)
            self.dport = rd_u16(mv, 2)
            self.sequence = rd_u32(mv, 4)
            self.acknowledgment = rd_u32(mv, 8)
            self._off_flags = rd_u16(mv, 12)
            self.window = rd_u16(mv, 14)
            self.checksum = rd_u16(mv, 16)
            self.urg_ptr = rd_u16(mv, 18)
            if self.data_offset > 5:
                self._options = rd_bytes(mv, 20, (self.data_offset * 4))
            else:
                self._options = b''
            self.app_layer(buf)
        else:
            if use_buffer and self.ws_len == 8:
                # From ICMP
                mv = buf
                self.sport = rd_u16(mv, 0)
                self.dport = rd_u16(mv, 2)
                self.sequence = rd_u32(mv, 4)
            else:
                self.sport = kwargs.get('sport', 0)
                self.dport = kwargs.get('dport', 0)
                self.sequence = kwargs.get('sequence', 0)
            self.acknowledgment = kwargs.get('acknowledgment', 0)
            self.data_offset = kwargs.get('data_offset', 5)
            self.flag_ns = kwargs.get('flag_ns', 0)
            self.flag_cwr = kwargs.get('flag_cwr', 0)
            self.flag_ece = kwargs.get('flag_ece', 0)
            self.flag_urg = kwargs.get('flag_urg', 0)
            self.flag_ack = kwargs.get('flag_ack', 0)
            self.flag_psh = kwargs.get('flag_psh', 0)
            self.flag_rst = kwargs.get('flag_rst', 0)
            self.flag_syn = kwargs.get('flag_syn', 0)
            self.flag_fin = kwargs.get('flag_fin', 0)
            self.window = kwargs.get('window', 0)
            self.checksum = kwargs.get('checksum', 0)
            self.urg_ptr = kwargs.get('urg_ptr', 0)
            self.options = kwargs.get('options', b'')
            if 'payload' in kwargs:
                if isinstance(kwargs['payload'], PKT):
                   self.payload = kwargs['payload']
                elif isinstance(kwargs['payload'], bytes):
                    self.app_layer(
                        array('B', b'\x00' * (self.data_offset * 4) +
                                   kwargs['payload']))
                else:
                    self.payload = NullPkt()
            else:
                self.payload = NullPkt()

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields UDP supports and TCP's
        PKT type ID.

        Returns:
            :tuple: PQTYPES.t_tcp and a tuple of the supported field names.
        """
        return (PQ_TCP,
                ('tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.ack',
                 'tcp.hdr_len', 'tcp.len', 'tcp.flags', 'tcp.flags.urg',
                 'tcp.flags.ack', 'tcp.flags.push', 'tcp.flags.reset',
                 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size_value',
                 'tcp.checksum', 'tcp.urgent_pointer', 'tcp.payload',
                 'tcp.payload.offset[x:y]'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch. Also handles 
        tcp.payload.offset[x:y] field. 

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg
        Returns: 
            :object: value of the field.
        """
        cdef list offsets
        cdef f = field[:18]
        if f == 'tcp.srcport':
            return self.sport
        elif f == 'tcp.dstport':
            return self.dport
        elif f == 'tcp.seq':
            return self.sequence
        elif f == 'tcp.ack':
            return self.acknowledgment
        elif f == 'tcp.hdr_len':
            return self.data_offset
        elif f == 'tcp.len':
            return self.ws_len
        elif f == 'tcp.flags':
            return self.flags
        elif f == 'tcp.flags.urg':
            return self.flag_urg
        elif f == 'tcp.flags.ack':
            return self.flag_ack
        elif f == 'tcp.flags.push':
            return self.flag_psh
        elif f == 'tcp.flags.reset':
            return self.flag_rst
        elif f == 'tcp.flags.syn':
            return self.flag_syn
        elif f == 'tcp.flags.fin':
            return self.flag_fin
        elif f == 'tcp.window_size_va':
            return self.window
        elif f == 'tcp.checksum':
            return self.checksum
        elif f == 'tcp.urgent_pointer':
            return self.urg_ptr
        elif f == 'tcp.payload':
            return self.payload.pkt2net({})
        elif f == 'tcp.payload.offset':
            offsets = (field[19:field.index(']')].split(':'))
            if len(offsets) == 2:
                return _payload_offset_bytes(self.payload,
                                             int(offsets[0]),
                                             int(offsets[1]))
            return None
        else:
            return None

    property data_offset:
        # 4 bits
        def __get__(self):
            return get_short_nibble(self._off_flags, 12)
        def __set__(self, unsigned char val):
            if 5 <= val <= 15:
                set_short_nibble(&self._off_flags, val, 12)
            else:
                raise ValueError("data_offset valid values are 5-15")

    property flags:
        # support for wireshark flags field. fin - urg
        def __get__(self):
            return self._off_flags & 0b111111


    property flag_ns:
        def __get__(self):
            return (self._off_flags >> 8) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 8)
            elif val == 0:
                unset_bit(&self._off_flags, 8)
            else:
                raise ValueError("TCP NS bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_cwr:
        def __get__(self):
            return (self._off_flags >> 7) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 7)
            elif val == 0:
                unset_bit(&self._off_flags, 7)
            else:
                raise ValueError("TCP CRW bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_ece:
        def __get__(self):
            return (self._off_flags >> 6) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 6)
            elif val == 0:
                unset_bit(&self._off_flags, 6)
            else:
                raise ValueError("TCP ECE bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_urg:
        def __get__(self):
            return (self._off_flags >> 5) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 5)
            elif val == 0:
                unset_bit(&self._off_flags, 5)
            else:
                raise ValueError("TCP URG bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_ack:
        def __get__(self):
            return (self._off_flags >> 4) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 4)
            elif val == 0:
                unset_bit(&self._off_flags, 4)
            else:
                raise ValueError("TCP ACK bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_psh:
        def __get__(self):
            return (self._off_flags >> 3) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 3)
            elif val == 0:
                unset_bit(&self._off_flags, 3)
            else:
                raise ValueError("TCP PSH bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_rst:
        def __get__(self):
            return (self._off_flags >> 2) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 2)
            elif val == 0:
                unset_bit(&self._off_flags, 2)
            else:
                raise ValueError("TCP RST bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_syn:
        def __get__(self):
            return (self._off_flags >> 1) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 1)
            elif val == 0:
                unset_bit(&self._off_flags, 1)
            else:
                raise ValueError("TCP SYN bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_fin:
        def __get__(self):
            return self._off_flags  & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 0)
            elif val == 0:
                unset_bit(&self._off_flags, 0)
            else:
                raise ValueError("TCP FIN bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property options:
        def __get__(self):
            return self._options
        def __set__(self, bytes val):
            pad_mod = len(val) % 4
            self.data_offset = 5 + len(val) // 4
            if pad_mod:
                self._pad = b'\x00' * (4 - len(val) % 4)
                self.data_offset += 1
            self._options = val

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a TCP packet class instance in network order 
        for writing to a socket or into a pcap file.

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. TCP
                supports the following keyword arguments:
            :csum (0 or 1): Determines if this TCP instance should re-calculate 
                its checksum.
            :ipv4_pheader (Ip4Ps): IPv4 psuedo header used in checksum 
                calculation.

        Returns: 
            :bytes: network order byte string representation of this 
                TCP instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this TCP header and its payload to a shared buffer.

        The checksum field goes out as a placeholder and is patched back in
        once the payload behind it has been written, so the checksum can be
        taken over the pseudo header plus the segment already in the buffer
        rather than over a freshly concatenated copy of it. See PKT._write.
        """
        cdef:
            uint16_t tcp_len
            bint _csum
            Ip4Ph _ipv4_pheader
            Ip6Ph _ipv6_pheader
            Py_ssize_t start
            unsigned char ph[40]

        _csum = kwargs.get('csum', 0)
        _ipv4_pheader = kwargs.get('ipv4_pheader', Ip4Ph())
        _ipv6_pheader = kwargs.get('ipv6_pheader')

        start = w.n
        w_u16(w, self.sport)
        w_u16(w, self.dport)
        w_u32(w, self.sequence)
        w_u32(w, self.acknowledgment)
        w_u16(w, self._off_flags)
        w_u16(w, self.window)
        w_u16(w, self.checksum)
        w_u16(w, self.urg_ptr)
        w_bytes(w, self._options)
        w_bytes(w, self._pad)

        self.payload._write(w, kwargs)

        if _csum and _ipv6_pheader is not None:
            tcp_len = <uint16_t>(w.n - start)
            ph_addr(ph, _ipv6_pheader.src, 16)
            ph_addr(ph + 16, _ipv6_pheader.dst, 16)
            ph[32] = 0
            ph[33] = 0
            ph[34] = <unsigned char>(tcp_len >> 8)
            ph[35] = <unsigned char>(tcp_len & 0xff)
            ph[36] = 0
            ph[37] = 0
            ph[38] = 0
            ph[39] = _ipv6_pheader.nh
            w_set_u16(w, start + 16, 0)
            self.checksum = w_cksum(w, start, cksum_acc(ph, 40, 0))
            w_set_u16(w, start + 16, self.checksum)
        elif _csum and isinstance(_ipv4_pheader, Ip4Ph):
            tcp_len = <uint16_t>(w.n - start)
            # Note _ipv4_pheader.proto is packed as a short on purpose.
            ph_addr(ph, _ipv4_pheader.src, 4)
            ph_addr(ph + 4, _ipv4_pheader.dst, 4)
            ph[8] = <unsigned char>(_ipv4_pheader.proto >> 8)
            ph[9] = <unsigned char>(_ipv4_pheader.proto & 0xff)
            ph[10] = <unsigned char>(tcp_len >> 8)
            ph[11] = <unsigned char>(tcp_len & 0xff)
            w_set_u16(w, start + 16, 0)
            self.checksum = w_cksum(w, start, cksum_acc(ph, 12, 0))
            w_set_u16(w, start + 16, self.checksum)
        return 0

    cdef app_layer(self, array buf):
        """
        Attempts to create an instance of the correct layer 7 protocol
        if the layer 4 ports match. Otherwise sets payload to  NullPkt or PKT
        instance.

        Args:
            :buf (array): the raw layer 4 bytes. Passed in rather than read
                from an attribute so TCP does not have to retain a copy of
                every packet it parses (plan item B).
        :return: void
        """
        cdef type pkt_cls
        pkt_cls = NullPkt
        if len(buf) > (self.data_offset * 4) and self._l7_ports:
            pkt_cls = _l7_pkt_cls(self._l7_ports, self.sport, self.dport)
        self.payload = pkt_cls(buf[(self.data_offset * 4):])


@cython.final
cdef class ICMP(PKT):
    """ RFC 792 ICMP with some additions. For example next hop MTU supported
    for destination unreachable. Not all record types supported.
    """
    def __init__(self, *args, **kwargs):
        self._base_l7(kwargs)
        self.pkt_name = 'ICMP'
        self.pq_type, self.query_fields = _QI_ICMP
        cdef:
            unsigned char use_buffer
            array buf
            const unsigned char[:] mv
        use_buffer, buf = self.from_buffer(args, kwargs)
        self._raw = None
        if use_buffer:
            self.identifier = 0
            self.sequence = 0
            self.mtu = 0
            self.pointer = 0
            self.orig_ts = 0
            self.rec_ts = 0
            self.trans_ts = 0
            self.hdr_pkt = NullPkt()
            self.data = array('B')
            self.echo_data = b''
            self._address = b'\x00\x00\x00\x00'
            mv = buf
            need_bytes(mv, 4, 'ICMP')
            self.type = mv[0]
            self.code = mv[1]
            self.checksum = rd_u16(mv, 2)
            if (self.type in (ICMP_TYPE_ECHO_REPLY,
                              ICMP_TYPE_ECHO,
                              ICMP_TYPE_INFO,
                              ICMP_TYPE_INFO_REPLY)):
                # Echo packet format
                need_bytes(mv, 8, 'ICMP')
                self.identifier = rd_u16(mv, 4)
                self.sequence = rd_u16(mv, 6)
                if len(mv) > 8:
                    self.echo_data = rd_bytes(mv, 8, -1)
                else:
                    self.echo_data = b''
            elif self.type == ICMP_TYPE_DU:
                # Destination Unreachable format
                need_bytes(mv, 8, 'ICMP')
                self.mtu = rd_u16(mv, 6)
                self.hdr_pkt = IP(buf[8:])
            elif (self.type in (ICMP_TYPE_SRC_QUENCH,
                                ICMP_TYPE_TIME_EX)):
                # Source quench format
                self.hdr_pkt = IP(buf[8:])
            elif self.type == ICMP_TYPE_REDIR:
                # redirect format
                need_bytes(mv, 8, 'ICMP')
                self._address = rd_bytes(mv, 4, 8)
                self.hdr_pkt = IP(buf[8:])
            elif self.type == ICMP_TYPE_PER_PROB:
                # Parameter Problem format
                need_bytes(mv, 8, 'ICMP')
                self.pointer = mv[4]
                self.hdr_pkt = IP(buf[8:])
            elif (self.type in (ICMP_TYPE_TS,
                                ICMP_TYPE_TS_REPLY)):
                # RFC 792: identifier and sequence at 4 and 6, then the three
                # 32 bit timestamps at 8, 12 and 16 -- 20 bytes in all, which
                # is exactly what pkt2net emits. The old parse was
                # unpack(b'!HHIII', self._buffer): 16 bytes read from offset
                # 0, so identifier took type/code, sequence took the
                # checksum, and every timestamp was one field early. A
                # timestamp message could not survive its own round trip.
                need_bytes(mv, 20, 'ICMP')
                self.identifier = rd_u16(mv, 4)
                self.sequence = rd_u16(mv, 6)
                self.orig_ts = rd_u32(mv, 8)
                self.rec_ts = rd_u32(mv, 12)
                self.trans_ts = rd_u32(mv, 16)
            else:
                # unknown: keep the bytes so pkt2net can hand them back.
                self.have_data = 1
                self._raw = rd_bytes(mv, 0, -1)
        else:
            self.type = kwargs.get('type', 0)
            self.code = kwargs.get('code', 0)
            self.checksum = kwargs.get('checksum', 0)
            self.identifier = kwargs.get('identifier', 0)
            self.sequence = kwargs.get('sequence', 0)
            self.mtu = kwargs.get('mtu', 0)
            self.pointer = kwargs.get('pointer', 0)
            self.orig_ts = kwargs.get('orig_ts', 0)
            self.rec_ts = kwargs.get('rec_ts', 0)
            self.trans_ts = kwargs.get('trans_ts', 0)
            self.hdr_pkt = kwargs.get('hdr_pkt', NullPkt())
            self.data = kwargs.get('data', array('B'))
            self.echo_data = kwargs.get('echo_data', b'')
            self.address = kwargs.get('address', '0.0.0.0')

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields UDP supports and UDP's
        PKT type ID.

        Returns:
            :tuple: PQTYPES.t_udp and a tuple of the supported field names.
        """
        return (PQ_ICMP,
                ('icmp.checksum', 'icmp.code', 'icmp.seq', 'icmp.mtu',
                 'icmp.ident', 'icmp.originate_timestamp', 'icmp.pointer',
                 'icmp.receive_timestamp', 'icmp.redir_gw',
                 'icmp.transmit_timestamp', 'icmp.type'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """
        cdef:
            uint32_t ts_secs, ts_mills
        if field == 'icmp.checksum':
            return self.checksum
        elif field == 'icmp.code':
            return self.code
        elif field == 'icmp.ident':
            return self.identifier
        elif field == 'icmp.originate_timestamp':
            return self.orig_ts
        elif field == 'icmp.receive_timestamp':
            return self.rec_ts
        elif field == 'icmp.redir_gw':
            return self.address
        elif field == 'icmp.seq':
            return self.sequence
        elif field == 'icmp.transmit_timestamp':
            return self.trans_ts
        elif field == 'icmp.type':
            return self.type
        elif field == 'icmp.mtu':
            return self.mtu
        elif field == 'icmp.pointer':
            return self.pointer
        elif field == 'icmp.data_time':
            if (self.type in (ICMP_TYPE_ECHO_REPLY, ICMP_TYPE_ECHO) and
                    len(self.echo_data) >= 8):
                ts_secs, ts_mills = unpack('!II', self.echo_data[:8])
                return b'%d.%d' % (ts_secs, ts_mills)
            else:
                return b'0.0'
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a IP packet class instance in network order  for 
        writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by IP to payload classes. IP supports the 
                following keyword arguments:

        Returns: 
            :bytes: network order byte string representation of this IP 
                instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this ICMP message to a shared buffer.

        The embedded header of the offending packet is written straight into
        the buffer instead of being serialized to its own bytes object first,
        and the checksum -- which covers the whole message -- is emitted as a
        placeholder and patched back in. See PKT._write.
        """
        cdef:
            bint _csum = kwargs.get('csum', 0)
            Py_ssize_t start

        if self.type in (ICMP_TYPE_DU, ICMP_TYPE_SRC_QUENCH, ICMP_TYPE_TIME_EX,
                         ICMP_TYPE_REDIR, ICMP_TYPE_PER_PROB):
            kwargs['for_icmp'] = 1

        start = w.n
        w_u8(w, self.type)
        w_u8(w, self.code)
        w_u16(w, self.checksum)

        if (self.type in (ICMP_TYPE_ECHO_REPLY,
                          ICMP_TYPE_ECHO,
                          ICMP_TYPE_INFO,
                          ICMP_TYPE_INFO_REPLY)):
            w_u16(w, self.identifier)
            w_u16(w, self.sequence)
            w_bytes(w, self.echo_data)
        elif self.type == ICMP_TYPE_DU:
            w_zeros(w, 2)
            w_u16(w, self.mtu)
            self.hdr_pkt._write(w, kwargs)
        elif (self.type in (ICMP_TYPE_SRC_QUENCH,
                            ICMP_TYPE_TIME_EX)):
            w_zeros(w, 4)
            self.hdr_pkt._write(w, kwargs)
        elif self.type == ICMP_TYPE_REDIR:
            w_bytes(w, self._address)
            self.hdr_pkt._write(w, kwargs)
        elif self.type == ICMP_TYPE_PER_PROB:
            w_u8(w, self.pointer)
            w_zeros(w, 3)
            self.hdr_pkt._write(w, kwargs)
        elif (self.type in (ICMP_TYPE_TS,
                            ICMP_TYPE_TS_REPLY)):
            w_u16(w, self.identifier)
            w_u16(w, self.sequence)
            w_u32(w, self.orig_ts)
            w_u32(w, self.rec_ts)
            w_u32(w, self.trans_ts)
        else:
            # type is not supported yet. Just try to write the bytes we got,
            # header included, so drop the one written above.
            w.n = start
            if self.have_data:
                w_bytes(w, self._raw)
            return 0

        if _csum:
            w_set_u16(w, start + 2, 0)
            self.checksum = w_cksum(w, start, 0)
            w_set_u16(w, start + 2, self.checksum)
        return 0

    property address:
        def __get__(self):
            return _fmt_ipv4(self._address)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv4(value)
            if packed is None:
                raise ValueError("address must be a dot notation "
                                 "IPv4 string. (1.1.1.1)")
            self._address = packed


@cython.final
cdef class IGMPGroupRecord(PKT):
    """One Group Record from an IGMPv3 membership report (RFC 3376 4.2.4).

    The IPv4 counterpart of MLDv2AddressRecord. Both count their auxiliary
    data in 32 bit words, per RFC 3376 4.2.6 and RFC 3810 5.2.10.
    """

    def __init__(self, *args, **kwargs):
        """Initialize an IGMPGroupRecord object.

        Args:
            :args (list): Optional one element list of network order bytes.
            :data (bytes): Optional network order bytes of one record.
            :type (unsigned char): Record type. 1-6 per RFC 3376 4.2.12.
            :aux_data_len (unsigned char): Auxiliary data length in 32 bit
                words, as RFC 3376 4.2.6 defines it. This is a word count,
                not a byte count: 4 bytes of aux_data means 1 here.
            :num_src (uint16_t): Number of source addresses. Derived from
                source_addresses when that is given.
            :group_address (str): Dot notation IPv4 multicast address.
            :source_addresses (list): Dot notation IPv4 source addresses.
            :aux_data (bytes): Auxiliary data.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'IGMPGroupRecord'
        self.pq_type, self.query_fields = _QI_IGMPGroupRecord
        self._source_addresses = self._group_address = self.aux_data = b''

        cdef:
            unsigned char use_buffer
            Py_ssize_t start, aux_len
            array buf
            const unsigned char[:] mv
        use_buffer, buf = self.from_buffer(args, kwargs)

        if use_buffer:
            mv = buf
            need_bytes(mv, 8, 'IGMPGroupRecord')
            self.type = mv[0]
            self.aux_data_len = mv[1]
            self.num_src = rd_u16(mv, 2)
            self._group_address = rd_bytes(mv, 4, 8)
            start = 8 + (4 * <Py_ssize_t>self.num_src)
            if self.num_src:
                need_bytes(mv, start, 'IGMPGroupRecord')
                self._source_addresses = rd_bytes(mv, 8, start)
            if self.aux_data_len:
                aux_len = 4 * <Py_ssize_t>self.aux_data_len
                need_bytes(mv, start + aux_len, 'IGMPGroupRecord')
                self.aux_data = rd_bytes(mv, start, start + aux_len)
        else:
            self.type = kwargs.get('type', 0)
            self.aux_data_len = kwargs.get('aux_data_len', 0)
            self.num_src = kwargs.get('num_src', 0)
            self.group_address = kwargs.get('group_address', '0.0.0.0')
            self.source_addresses = kwargs.get('source_addresses', list())
            self.aux_data = kwargs.get('aux_data', b'')

    property byte_len:
        """Size of this record on the wire.

        aux_data_len is a 32 bit word count, so it is multiplied by 4 here.
        IGMP walks its record list by adding this to the running offset, so
        reading the field as a byte count did not merely mis-size one
        record: it desynchronized every record behind it.
        """
        def __get__(self):
            return 8 + (self.num_src * 4) + (self.aux_data_len * 4)

    property group_address:
        def __get__(self):
            return _fmt_ipv4(self._group_address)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv4(value)
            if packed is None:
                raise ValueError("group_address must be a dot notation "
                                 "IPv4 string. (1.1.1.1)")
            self._group_address = packed

    property source_addresses:
        def __get__(self):
            cdef:
                uint16_t i
                list r
            if self._source_addresses:
                r = list()
                for i in range(self.num_src):
                    r.append(
                        _fmt_ipv4(self._source_addresses[i*4:i*4+4])
                    )
                return r
            else:
                return list()
        def __set__(self, list value):
            cdef:
                str ip
                bytes packed
                list packed_addrs = []

            for ip in value:
                packed = pack_ipv4(ip)
                if packed is None:
                    raise ValueError("source_addresses must be a list of dot "
                                     "notation IPv4 string. (1.1.1.1)")
                packed_addrs.append(packed)
            # join, not += in a loop: repeated bytes concatenation is
            # quadratic in the number of sources (plan item E).
            self._source_addresses = b''.join(packed_addrs)
            self.num_src = len(packed_addrs)

    @classmethod
    def query_info(cls):
        """classmethod - provides pcap_query with the query fields
        IGMP supports and IGMP's PKT type ID.

        Returns:
            :tuple: PQTYPES.PQ_IGMP and a tuple of the supported
            field names.
        """
        return (PQ_IGMPv3GroupRecord,
                ('igmpv3grouprecord.type', 'igmpv3grouprecord.aux_data_len',
                 'igmpv3grouprecord.num_src',
                 'igmpv3grouprecord.group_address',
                 'igmpv3grouprecord.source_addresses',
                 'igmpv3grouprecord.aux_data'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (str): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """
        if field == 'igmpv3grouprecord.type':
            return self.type
        elif field == 'igmpv3grouprecord.aux_data_len':
            return self.aux_data_len
        elif field == 'igmpv3grouprecord.num_src':
            return self.num_src
        elif field == 'igmpv3grouprecord.group_address':
            return self.group_address
        elif field == 'igmpv3grouprecord.source_addresses':
            return self.source_addresses
        elif field == 'igmpv3grouprecord.aux_data':
            return self.aux_data
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):

        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this group record to a shared buffer. IGMP writes its
        records straight into the parent buffer instead of building a bytes
        object per record and joining them. See PKT._write."""
        w_u8(w, self.type)
        w_u8(w, self.aux_data_len)
        w_u16(w, self.num_src)
        w_bytes(w, self._group_address)
        w_bytes(w, self._source_addresses)
        w_bytes(w, self.aux_data)
        return 0


@cython.final
cdef class IGMP(PKT):
    """
    RFC 2236 IGMP version 1 and 2 + rfc3376 version 3
    """

    def __init__(self, *args, **kwargs):
        """Initialize a IGMP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an ARP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an IGMP packet
            :type (unsigned char): 0x11 (query), 0x12 (v1 membership report),
            0x16 (v2 membership report), 0x17 (leave group)
            :max_resp (unsigned char): Meaningful only in Membership Query
            messages, and specifies the maximum allowed time before sending a
            responding report in units of 1/10 second.
            :checksum (uint16_t): 16-bit one's complement of the one's
            complement sum of the whole IGMP message (the entire IP payload).
            :maddr (str): String containing the IPv4 dot notation multicast
            address
        """
        self._base_l7(kwargs)
        self.pkt_name = 'IGMP'
        self.pq_type, self.query_fields = _QI_IGMP
        cdef:
            unsigned char use_buffer, operation, version
            uint16_t _len, offset, i
            array buf
            const unsigned char[:] mv
        use_buffer, buf = self.from_buffer(args, kwargs)
        self._s_qrv = self.qqic = 0
        self.group_records = list()
        self._source_addresses = b''

        if use_buffer:
            # These are true for all versions and types
            mv = buf
            need_bytes(mv, 8, 'IGMP')
            self.type = mv[0]
            self.max_resp = mv[1]
            self.checksum = rd_u16(mv, 2)
            if self.type != IGMP_V3_MEMBER_REPORT:
                self._group_address = rd_bytes(mv, 4, 8)
            self._source_addresses = b''
            self.version = version = 0
            operation = self.type
            _len = kwargs.get('length', 0)

            # If we got a length from IP then this track will be fastest.
            # Otherwise we will have to pre-parse a few more bytes of the
            # packet to figure out what version it is. See 'else' case below.
            if _len:
                if _len > 8:
                        version = 3
                else:
                    if operation == IGMP_MEMBER_QUERY:
                        if mv[1] == 0:
                            version = 1
                        else:
                            version = 2
                    elif operation == IGMP_V1_MEMBER_REPORT:
                        version = 1
                    else:
                        version = 2
            else:
                # Looks like we have to parse our way through this:
                if operation == IGMP_MEMBER_QUERY:
                    # The buffer could be ethernet padding so make sure the
                    # 10th byte is not zero. With IGMPv3 that byte is the QQIC
                    # value and must be 125 or the last query interval used.
                    # RFC 3376 section 8.2
                    if mv.shape[0] >= 11 and mv[9] != 0:
                        version = 3
                    elif mv[1] == 0:
                        version = 1
                    else:
                        version = 2
                elif operation in (IGMP_V2_MEMBER_REPORT, IGMP_LEAVE_GROUP):
                    version = 2
                elif operation == IGMP_V3_MEMBER_REPORT:
                    version = 3
                else:
                    version = 1

            if version:
                self.version = version
                if version in (2, 1):
                    if version == 1:
                        self.max_resp = self.reserved1 = 0
                else:
                    if operation == IGMP_MEMBER_QUERY:
                        need_bytes(mv, 12, 'IGMP')
                        self._s_qrv = mv[8]
                        self.qqic = mv[9]
                        self.num_records = rd_u16(mv, 10)
                        if self.num_records:
                            # RFC 3376 4.1: the source list follows the
                            # resv/S/QRV, QQIC and number-of-sources fields,
                            # so it starts at offset 12, not 8.
                            need_bytes(mv, 12 + 4 * self.num_records, 'IGMP')
                            self._source_addresses = \
                                rd_bytes(mv, 12, 12+4*self.num_records)
                    else:
                        self.max_resp = self.reserved1 = self.reserved2 = 0
                        self.num_records = rd_u16(mv, 6)
                        offset = 0
                        for i in range(self.num_records):
                            self.group_records.append(
                                IGMPGroupRecord(buf[8+offset:])
                            )
                            offset += self.group_records[-1].byte_len
            else:
                raise ValueError("Data passed into IGMP __init__ does not "
                                 "look like an IGMP packet. Data was: {}"
                                 "".format(rd_bytes(mv, 0, -1)))

        else:
            self.type = kwargs.get('type', 0)
            self.version = kwargs.get('version', 2)
            self.checksum = kwargs.get('checksum', 0)
            if self.version == 1:
                self.reserved1 = kwargs.get('reserved1', 0)
                self.group_address = kwargs.get('group_address', '0.0.0.0')
            elif self.version == 2:
                self.max_resp = kwargs.get('max_resp', 0)
                self.group_address = kwargs.get('group_address', '0.0.0.0')
            elif self.version == 3:
                if self.type == IGMP_MEMBER_QUERY:
                    self.max_resp = kwargs.get('max_resp', 0)
                    self.group_address = kwargs.get('group_address', '0.0.0.0')
                    self.s = kwargs.get('s', 0)
                    self.qrv = kwargs.get('qrv', 0)
                    self.qqic = kwargs.get('qqic', 0)
                    self.num_records = kwargs.get('num_records', 0)
                    self.source_addresses = kwargs.get('source_addresses',
                                                       list())
                else:
                    self._s_qrv = 0
                    self.max_resp = self.reserved1 = self.reserved2 = 0
                    self.num_records = kwargs.get('num_records', 0)
                    self.group_records = kwargs.get('group_records',
                                                    list())

    @classmethod
    def query_info(cls):
        """classmethod - provides pcap_query with the query fields
        IGMP supports and IGMP's PKT type ID.

        Returns:
            :tuple: PQTYPES.PQ_IGMP and a tuple of the supported
            field names.
        """
        return (PQ_IGMP,
                ('igmp.version', 'igmp.type', 'igmp.saddr', 'igmp.s',
                 'igmp.qrv', 'igmp.num_src', 'igmp.num_grp_recs',
                 'igmp.max_resp', 'igmp.maddr', 'igmp.checksum',
                 'igmp.obj.saddr', 'igmp.obj.grecs'))


    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (str): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """

        cdef:
            str b_out_vals
            list out_vals
            IGMPGroupRecord rec

        if field == 'igmp.version':
            return self.version
        elif field == 'igmp.type':
            return self.type
        elif field == 'igmp.saddr' and self.version == 3:
            if self.type == IGMP_MEMBER_QUERY:
                return ','.join(self.source_addresses)
            else:
                return ''.join(
                    [','.join(rec.source_addresses)
                     for rec in self.group_records])
        elif (field == 'igmp.s' and
                self.version == 3 and
                self.type == IGMP_MEMBER_QUERY):
            return self.s
        elif (field == 'igmp.qrv' and
                self.version == 3 and
                self.type == IGMP_MEMBER_QUERY):
            return self.qrv
        elif (field == 'igmp.num_src' and
                self.type == IGMP_MEMBER_QUERY and
                self.version == 3):
            return self.num_records
        elif (field == 'igmp.num_grp_recs' and
                self.type != IGMP_MEMBER_QUERY and
                self.version == 3):
            return self.num_records
        elif (field == 'igmp.max_resp' and
                self.type != IGMP_V3_MEMBER_REPORT and
                self.version != 1):
            return self.max_resp
        elif field == 'igmp.maddr':
            if self.type != IGMP_V3_MEMBER_REPORT:
                return self.group_address
            else:
                out_vals = list()
                for rec in self.group_records:
                    out_vals.append(rec.group_address)
                return ','.join(out_vals)
        elif field == 'igmp.checksum':
            return self.checksum
        elif (field == 'igmp.obj.saddr' and
                self.version == 3 and
                self.type == IGMP_MEMBER_QUERY):
            return self.source_addresses
        elif (field == 'igmp.obj.grecs' and
                self.version == 3 and
                self.type != IGMP_MEMBER_QUERY):
            return self.group_records
        else:
            return None

    property group_address:
        def __get__(self):
            return _fmt_ipv4(self._group_address)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv4(value)
            if packed is None:
                raise ValueError("group_address must be a dot notation "
                                 "IPv4 string. (1.1.1.1)")
            self._group_address = packed

    property s:
        def __get__(self):
            return (self._s_qrv >> 3) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_cbit(&self._s_qrv, 3)
            elif val == 0:
                unset_cbit(&self._s_qrv, 3)
            else:
                raise ValueError("IGMP v3 S bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property qrv:
        def __get__(self):
            return self._s_qrv & 7
        def __set__(self, unsigned char val):
            if 0 <= val <= 7:
                if (self._s_qrv >> 3) & 1:
                    self._s_qrv = val + 8
                else:
                    self._s_qrv = val
            else:
                raise ValueError("IGMP v3 qrv bit must be 0 - 7 "
                                 "got: {0}".format(val))

    property source_addresses:
        def __get__(self):
            cdef:
                uint16_t i
                list r
            if self._source_addresses:
                r = list()
                for i in range(self.num_records):
                    r.append(_fmt_ipv4(self._source_addresses[i*4:i*4+4]))
                return r
            else:
                return list()
        def __set__(self, list value):
            cdef:
                str ip
                bytes packed
                list packed_addrs = []

            for ip in value:
                packed = pack_ipv4(ip)
                if packed is None:
                    raise ValueError("source_addresses must be a list of dot "
                                     "notation IPv4 string. (1.1.1.1)")
                packed_addrs.append(packed)
            # join, not += in a loop: repeated bytes concatenation is
            # quadratic in the number of sources (plan item E).
            self._source_addresses = b''.join(packed_addrs)
            self.num_records = len(packed_addrs)

    cpdef bytes pkt2net(self, dict kwargs):
        """
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this IGMP message to a shared buffer.

        All four message shapes are byte 0, byte 1, checksum, body -- only
        the second byte and the body differ -- so the header goes out with a
        placeholder checksum, the body is appended, and the checksum is taken
        over the message already in the buffer and patched back in. Note that
        the v1 branch checksums over ``reserved1`` but emits ``max_resp`` in
        that byte; that asymmetry is preserved exactly as it was.
        See PKT._write.
        """
        cdef:
            bint csum, update
            Py_ssize_t start
            IGMPGroupRecord record

        csum = kwargs.get('csum', 0)
        update = kwargs.get('update', 0)

        start = w.n

        if self.version == 2:
            w_u8(w, self.type)
            w_u8(w, self.max_resp)
            w_u16(w, self.checksum)
            w_bytes(w, self._group_address)
        elif self.version == 3:
            if self.type == IGMP_MEMBER_QUERY:
                if update:
                    self.num_records = <uint16_t>(
                        len(self._source_addresses) // 4)
                w_u8(w, self.type)
                w_u8(w, self.max_resp)
                w_u16(w, self.checksum)
                w_bytes(w, self._group_address)
                w_u8(w, self._s_qrv)
                w_u8(w, self.qqic)
                w_u16(w, self.num_records)
                w_bytes(w, self._source_addresses)
            else:
                if update:
                    self.num_records = <uint16_t>len(self.group_records)
                w_u8(w, self.type)
                w_u8(w, self.reserved1)
                w_u16(w, self.checksum)
                w_u16(w, self.reserved2)
                w_u16(w, self.num_records)
                for record in self.group_records:
                    record._write(w, {})
        else:
            w_u8(w, self.type)
            w_u8(w, self.max_resp)
            w_u16(w, self.checksum)
            w_bytes(w, self._group_address)

        if csum:
            w_set_u16(w, start + 2, 0)
            if self.version != 2 and self.version != 3:
                # The v1 branch checksums with reserved1 in byte 1 but emits
                # max_resp there. Preserved exactly as it was rather than
                # quietly "corrected", since it is what the golden output and
                # any capture written by an older release contain.
                w.b[start + 1] = self.reserved1
                self.checksum = w_cksum(w, start, 0)
                w.b[start + 1] = self.max_resp
            else:
                self.checksum = w_cksum(w, start, 0)
            w_set_u16(w, start + 2, self.checksum)
        return 0


cdef inline int _init_ip_kwargs(IP pkt, dict kwargs) except -1:
    """Initialize a newly allocated IPv4 object from construction keywords."""
    cdef object payload
    pkt.ipv4_pheader = Ip4Ph()
    pkt._version_iphl = (IPV4_VER << 4) | IPV4_MIN_HDR_LEN
    if 'version' in kwargs:
        pkt.version = kwargs['version']
    if 'iphl' in kwargs:
        pkt.iphl = kwargs['iphl']
    if 'tos' in kwargs:
        pkt.tos = kwargs['tos']
    if 'total_len' in kwargs:
        pkt.total_len = kwargs['total_len']
    if 'ident' in kwargs:
        pkt.ident = kwargs['ident']
    if 'flag_x' in kwargs:
        pkt.flag_x = kwargs['flag_x']
    if 'flag_d' in kwargs:
        pkt.flag_d = kwargs['flag_d']
    if 'flag_m' in kwargs:
        pkt.flag_m = kwargs['flag_m']
    if 'frag_offset' in kwargs:
        pkt.frag_offset = kwargs['frag_offset']
    if 'ttl' in kwargs:
        pkt.ttl = kwargs['ttl']
    else:
        pkt.ttl = 64
    if 'proto' in kwargs:
        pkt.proto = kwargs['proto']
    if 'checksum' in kwargs:
        pkt.checksum = kwargs['checksum']
    if 'src' in kwargs:
        pkt.src = kwargs['src']
    else:
        pkt.src_nochk = b'\x00\x00\x00\x00'
    if 'dst' in kwargs:
        pkt.dst = kwargs['dst']
    else:
        pkt.dst_nochk = b'\x00\x00\x00\x00'
    if 'options' in kwargs:
        pkt.options = kwargs['options']
    else:
        pkt.options = b''
    if 'payload' in kwargs:
        payload = kwargs['payload']
        if isinstance(payload, PKT):
            pkt.payload = payload
        elif isinstance(payload, bytes):
            if pkt.proto == PROTO_UDP:
                pkt.payload = UDP(payload, l7_ports=pkt._l7_ports)
            elif pkt.proto == PROTO_TCP:
                pkt.payload = TCP(payload, l7_ports=pkt._l7_ports)
            elif pkt.proto == PROTO_ICMP:
                pkt.payload = ICMP(payload)
            elif pkt.proto == PROTO_IGMP:
                pkt.payload = IGMP(payload, length=len(payload))
            else:
                pkt.payload = NullPkt(payload, l7_ports=pkt._l7_ports)
        else:
            pkt.payload = PKT()
    else:
        pkt.payload = PKT()
    return 0


@cython.final
cdef class IP(PKT):
    def __init__(self, *args, **kwargs):
        """
        Initialize a IP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an IP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an IP packet
            :version (unsigned char): IP version of this packet. Only 4 is
                supported. Default is 4.
            :iphl (unsigned char): Internet Protocol Header Length in 32-bit
                'words'. Minimum valid value is 5. Default is 5.
            :tos (unsigned char): IP type of service. Now primarily used to
                store DSCP values and ECN values. ECN is the low 2 bits.
            :total_len (uint16_t): The total lenght of the IP packet including
                the header and data.
            :ident (uint16_t): Primarily used for uniquely identifying the
                group of fragments of a single IP datagram. Used with
                frag_offset and flag_m.
            :flag_x (1 or 0): Flag bit zero implemented as x bit. See RFC 3514
                for appropriate use ;-)
            :flag_d (1 or 0): Don't fragment flag.
            :flag_m (1 or 0): More fragments flag.
            :frag_offset (uint16_t): This IP packet fragment offset from the
                beginning of the original un-fragmented IP datagram measured in
                units of eight-byte blocks.
            :ttl (unsigned char): The time to live for the IP datagram.
                Decremented by routers as a method to prevent endless circular
                routes. Default is 64.
            :checksum (uint16_t): The 16-bit checksum field.
            :src (bytes): IPv4 src address in dot notation. Default is
                '0.0.0.0'.
            :dst (bytes): IPv4 dst address in dot notation Default is
                '0.0.0.0'.
            :payload (bytes or PKT): The payload of this packet. Payload can
                be a PKT sub class or a byte string.
            :l7_ports (dict): A dictionary where the keys are layer 4 port
                numbers and the values are PKT subclass packet classes. Used by
                app_layer to determine what class should be used to decode
                the payload string or byte array.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'IP'
        self.pq_type, self.query_fields = _QI_IP
        cdef:
            unsigned char use_buffer, hl_bytes, iphl
            array buf
            const unsigned char[:] mv
            bytes owner
        if not args and 'data' not in kwargs:
            _init_ip_kwargs(self, kwargs)
            return
        self.ipv4_pheader = Ip4Ph()
        self.options = b''
        owner = _owned_buffer(args, kwargs)
        if owner is not None:
            mv = owner
            _decode_ip(self, owner, mv, 0, len(owner), self._l7_ports)
            return
        use_buffer, buf = self.from_buffer(args, kwargs)

        if use_buffer:
            mv = buf
            need_bytes(mv, 20, 'IP')
            self._version_iphl = mv[0]
            iphl = self.iphl
            self.tos = mv[1]
            self.total_len = rd_u16(mv, 2)
            self.ident = rd_u16(mv, 4)
            self._flags_offset = rd_u16(mv, 6)
            self.ttl = mv[8]
            self.proto = mv[9]
            self.checksum = rd_u16(mv, 10)
            self.src_nochk = rd_bytes(mv, 12, 16)
            self.dst_nochk = rd_bytes(mv, 16, 20)
            hl_bytes = iphl * 4
            if iphl > 5:
                self.options = rd_bytes(mv, 20, hl_bytes)
            if mv.shape[0] > hl_bytes:
                if self.proto == PROTO_UDP:
                    self.payload = UDP(buf[hl_bytes:],
                                       l7_ports = self._l7_ports)
                elif self.proto == PROTO_TCP:
                    self.payload = TCP(buf[hl_bytes:],
                                       l7_ports = self._l7_ports)
                elif self.proto == PROTO_ICMP:
                    self.payload = ICMP(buf[hl_bytes:])
                elif self.proto == PROTO_IGMP:
                    self.payload = IGMP(buf[hl_bytes:],
                                        length=(self.total_len - hl_bytes))
                else:
                    self.payload = NullPkt(buf[hl_bytes:],
                                           l7_ports = self._l7_ports)
            else:
                self.payload = PKT()
        else:
            self.version = kwargs.get('version', IPV4_VER)
            self.iphl = kwargs.get('iphl', IPV4_MIN_HDR_LEN)
            self.tos = kwargs.get('tos', 0)
            self.total_len = kwargs.get('total_len', 0)
            self.ident = kwargs.get('ident', 0)
            self.flag_x = kwargs.get('flag_x', 0)
            self.flag_d = kwargs.get('flag_d', 0)
            self.flag_m = kwargs.get('flag_m', 0)
            self.frag_offset = kwargs.get('frag_offset', 0)
            self.ttl = kwargs.get('ttl', 64)
            self.proto = kwargs.get('proto', 0)
            self.checksum = kwargs.get('checksum', 0)
            self.src = kwargs.get('src', '0.0.0.0')
            self.dst = kwargs.get('dst', '0.0.0.0')
            self.options = kwargs.get('options', b'')
            if ('payload' in kwargs and
                    isinstance(kwargs['payload'], PKT)):
                self.payload = kwargs['payload']
            elif ('payload' in kwargs and
                      isinstance(kwargs['payload'], bytes)):
                if self.proto == PROTO_UDP:
                    self.payload = UDP(kwargs['payload'],
                                       l7_ports = self._l7_ports)
                elif self.proto == PROTO_TCP:
                    self.payload = TCP(kwargs['payload'],
                                       l7_ports = self._l7_ports)
                elif self.proto == PROTO_ICMP:
                    self.payload = ICMP(kwargs['payload'])
                elif self.proto == PROTO_IGMP:
                    self.payload = IGMP(kwargs['payload'],
                                        length=len(kwargs['payload']))
                else:
                    self.payload = NullPkt(kwargs['payload'],
                                           l7_ports = self._l7_ports)
            else:
                self.payload = PKT()

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields IP supports and
        IP's PKT type ID.

        Returns:
            :tuple: PQTYPES.t_ip and a tuple of the supported
                field names.
        """
        return (PQ_IP,
                ('ip.version', 'ip.hdr_len', 'ip.tos', 'ip.len', 'ip.id',
                 'ip.flags', 'ip.flags.df', 'ip.flags.mf',
                 'ip.frag_offset', 'ip.ttl', 'ip.proto', 'ip.src',
                 'ip.dst', 'ip.checksum'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """
        if field == 'ip.version':
            return self.version
        elif field == 'ip.hdr_len':
            return self.iphl
        elif field == 'ip.tos':
            return self.tos
        elif field == 'ip.len':
            return self.total_len
        elif field == 'ip.id':
            return self.ident
        elif field == 'ip.flags':
            return self.flags
        elif field == 'ip.flags.df':
            return self.flag_d
        elif field == 'ip.flags.mf':
            return self.flag_m
        elif field == 'ip.frag_offset':
            return self.frag_offset
        elif field == 'ip.ttl':
            return self.ttl
        elif field == 'ip.proto':
            return self.proto
        elif field == 'ip.src':
            return self.src
        elif field == 'ip.dst':
            return self.dst
        elif field == 'ip.checksum':
            return self.checksum
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a IP packet class instance in network order  for 
        writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by IP to payload classes. IP supports the 
                following keyword arguments:
            :csum (0 or 1): Determines if this IP instance should re-calculate 
                its checksum.
            :update (0 or 1): Determines if this IP instance and any sub layers
                should update size counters. For IP this means updating the
                total_len variable.
            :for_icmp (0 or 1): Return on the 64 bits of the header needed
                for ICMP packets.
            :ipv4_pheader (Ip4Ph): IPv4 pseudo header used in checksum 
                calculation.

        Returns: 
            :bytes: network order byte string representation of this IP 
                instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this IP header and its payload to a shared buffer.

        total_len is only known once the payload has been written, so the
        header goes out first and total_len -- and then the header checksum,
        which covers it -- are patched back into the buffer. See PKT._write.
        """
        cdef:
            bint _csum, _update, _icmp
            Py_ssize_t start, hdr_end, hdr_bytes

        _icmp = kwargs.get('for_icmp', 0)
        if _icmp:
            _csum = 0
            _update = 0
        else:
            _csum = kwargs.get('csum', 0)
            _update = kwargs.get('update', 0)

        # support a user passing in a pheader of their own for negative testing
        kwargs['ipv4_pheader'] = kwargs.get('ipv4_pheader', self.ipv4_pheader)

        if _update:
            # options is what decides how long the header written below
            # actually is, so iphl is derived from it rather than trusted.
            # A caller who set options without touching iphl used to emit a
            # header whose own declared length pointed into the middle of
            # it, and a receiver would start reading layer 4 from there.
            # Serialize without 'update' to put a deliberately wrong iphl on
            # the wire, exactly as for total_len and the checksum.
            hdr_bytes = IPV4_MIN_HDR_LEN * 4 + len(self.options)
            if hdr_bytes <= 60 and hdr_bytes % 4 == 0:
                self.iphl = <unsigned char>(hdr_bytes >> 2)

        start = w.n
        w_u8(w, self._version_iphl)
        w_u8(w, self.tos)
        w_u16(w, self.total_len)
        w_u16(w, self.ident)
        w_u16(w, self._flags_offset)
        w_u8(w, self.ttl)
        w_u8(w, self._proto)
        w_u16(w, self.checksum)
        w_bytes(w, self._src)
        w_bytes(w, self._dst)
        w_bytes(w, self.options)
        hdr_end = w.n

        if isinstance(self.payload, PKT):
            if _icmp:
                # ICMP embeds only the header of the offending packet, and
                # with none of the parent's kwargs applied to it.
                (<PKT>self.payload)._write(w, {})
            else:
                (<PKT>self.payload)._write(w, kwargs)

        if _update:
            # The bytes actually written, not iphl * 4: those two disagree
            # whenever options is not exactly (iphl - 5) * 4 bytes long, and
            # the old form described a header that was never emitted, so
            # total_len covered the wrong span of the datagram.
            self.total_len = <uint16_t>(w.n - start)
            w_set_u16(w, start + 2, self.total_len)

        if _csum:
            w_set_u16(w, start + 10, 0)
            self.checksum = cksum_fin(
                cksum_acc(w.b + start, hdr_end - start, 0))
            w_set_u16(w, start + 10, self.checksum)

        # Frame bytes that sat behind total_len when this packet was parsed,
        # written last so they stay outside the length patched above.
        if self._trailer is not None:
            w_bytes(w, self._trailer)
        return 0

    property version:
        """ The IP version defined by this packet. """
        def __get__(self):
            """ Return the IP Version. """
            return get_char_nibble(self._version_iphl, 4)
        def __set__(self, unsigned char val):
            """ Set the IP Version. """
            if val in (IPV4_VER, IPV6_VER):
                set_char_nibble(&self._version_iphl, val, 4)
            else:
                raise ValueError("Only IP versions 4 and 6 supported")

    property iphl:
        """ Number of 32 bit words in the header. Max is 15 (60 bytes). """
        def __get__(self):
            """ Return the number of 32 bit words in the header. """
            return get_char_nibble(self._version_iphl, 0)

        def __set__(self, unsigned char val):
            """ Set the IP header length in 32 bit words. """
            if val <= 0xf:
                set_char_nibble(&self._version_iphl, val, 0)
            else:
                raise ValueError("IP iphl valid values are 0-15")

    property flags:
        # support for wireshark ip.flags field.
        def __get__ (self):
            # return the last 3 bits of _flags_offset
            return get_short_nibble(self._flags_offset, 12) >> 1

    property flag_x:
        """ Set or get the so called evil bit. See RFC 3514. Implemented
        here for fun. """
        def __get__(self):
            return (self._flags_offset >> 15) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._flags_offset, 15)
            elif val == 0:
                unset_bit(&self._flags_offset, 15)
            else:
                raise ValueError("IP Evil bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_d:
        def __get__(self):
            return (self._flags_offset >> 14) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._flags_offset, 14)
            elif val == 0:
                unset_bit(&self._flags_offset, 14)
            else:
                raise ValueError("IP do not fragment bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_m:
        def __get__(self):
            return (self._flags_offset >> 13) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._flags_offset, 13)
            elif val == 0:
                unset_bit(&self._flags_offset, 13)
            else:
                raise ValueError("IP more fragments must be 0 or 1 "
                                 "got: {0}".format(val))

    property frag_offset:
        """ Get and set the frag_offset of the datagram. """
        def __get__(self):
            """ Return the frag_offset. """
            return self._flags_offset & 0x1fff
        def __set__(self, uint16_t val):
            """ Set the datagram frag_offset value. """
            if val <= 0x1fff:
                self._flags_offset = (self._flags_offset & ~(0x1fff)) | val
            else:
                raise ValueError("IP frag offset valid values are 0-8191")

    property proto:
        """ Get and set the proto. """
        def __get__(self):
            """ Return the proto. """
            return self._proto
        def __set__(self, unsigned char val):
            """ Set the datagram proto value. """
            self._proto = val
            self.ipv4_pheader.proto = val

    property src_nochk:
        # Accepts bytes (what the parser now hands it, with no intermediate
        # array slice) or an array('B'), which is what callers used to pass.
        def __set__(self, value):
            if isinstance(value, bytes):
                self.ipv4_pheader.src = self._src = value
            else:
                self.ipv4_pheader.src = self._src = (<array>value).tobytes()

    property src:
        def __get__(self):
            return _fmt_ipv4(self._src)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv4(value)
            if packed is None:
                raise ValueError("src must be a dot notation "
                                 "IPv4 string. (1.1.1.1)")
            self.ipv4_pheader.src = self._src = packed
    property dst_nochk:
        def __set__(self, value):
            if isinstance(value, bytes):
                self.ipv4_pheader.dst = self._dst = value
            else:
                self.ipv4_pheader.dst = self._dst = (<array>value).tobytes()

    property dst:
        def __get__(self):
            return _fmt_ipv4(self._dst)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv4(value)
            if packed is None:
                raise ValueError("dst must be a dot notation "
                                 "IPv4 string. (1.1.1.1)")
            self.ipv4_pheader.dst = self._dst = packed


cdef inline bint _is_ip6_ext(unsigned char nh):
    """True if `nh` is an IPv6 extension header this parser walks through:
    Hop-by-Hop (0), Routing (43), Fragment (44), Authentication (51) and
    Destination Options (60). ESP (50) is intentionally excluded because its
    payload is encrypted and cannot be walked."""
    return nh == 0 or nh == 43 or nh == 44 or nh == 51 or nh == 60


cdef unsigned char _walk_ip6_ext(const unsigned char[:] mv,
                                  Py_ssize_t start,
                                  unsigned char first_nh,
                                  Py_ssize_t *ext_len,
                                  bint *incomplete):
    """Walk the IPv6 extension-header chain (RFC 8200) beginning at buffer
    offset `start`, given the header's first next-header value `first_nh`.

    Writes the total number of extension-header bytes to ``*ext_len`` and sets
    ``*incomplete`` when a Fragment header with a non-zero offset is seen (the
    bytes that follow are a fragment body, not a parseable upper layer). The
    terminal upper-layer protocol number is returned. Walking stops safely at
    the end of the buffer so a truncated capture cannot over-read.
    """
    cdef:
        Py_ssize_t off = start
        Py_ssize_t n = mv.shape[0]
        unsigned char cur = first_nh
        unsigned char nxt, hlen
        Py_ssize_t size
    incomplete[0] = 0
    while _is_ip6_ext(cur):
        if off + 2 > n:
            break
        nxt = mv[off]
        hlen = mv[off + 1]
        if cur == 44:               # Fragment: fixed 8 bytes.
            size = 8
            # frag offset lives in the top 13 bits of the 16-bit field at +2.
            if off + 4 <= n and (((<int>mv[off + 2] << 8) | mv[off + 3]) >> 3):
                incomplete[0] = 1
        elif cur == 51:             # Authentication Header: (len + 2) * 4.
            size = (<Py_ssize_t>hlen + 2) * 4
        else:                       # HopOpts / Routing / DstOpts: (len + 1)*8.
            size = (<Py_ssize_t>hlen + 1) * 8
        if size <= 0 or off + size > n:
            break                   # Malformed/truncated: stop the walk.
        off += size
        cur = nxt
    ext_len[0] = off - start
    return cur


@cython.final
cdef class IP6(PKT):
    """Implements the IPv6 header (RFC 2460/8200) with the same construction
    and export contract as the IPv4 :class:`IP` class.

    The fixed 40-byte header carries a 4-bit version, an 8-bit traffic class,
    a 20-bit flow label, the payload length, the next-header protocol number,
    the hop limit and the 128-bit source and destination addresses. Layer 4
    payloads (TCP/UDP, and ICMPv6 once implemented) are checksummed using the
    IPv6 pseudo header, which IP6 supplies to the payload's pkt2net via the
    ``ipv6_pheader`` keyword argument.
    """

    def __init__(self, *args, **kwargs):
        """Initialize an IP6 object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an IPv6 packet.
            :data (bytes): Optional keyword argument containing network order
                bytes of an IPv6 packet.
            :traffic_class (unsigned char): 8-bit traffic class (DSCP + ECN).
                Default 0.
            :flow_label (uint32_t): 20-bit flow label. Default 0.
            :payload_len (uint16_t): Length in octets of everything after the
                40-byte header. Recomputed when pkt2net is called with
                ``update=1``.
            :next_header (unsigned char): Protocol number of the first header
                that follows (6 TCP, 17 UDP, 58 ICMPv6, or an extension header
                number). Default 0.
            :hop_limit (unsigned char): Replaces IPv4 ttl. Default 64.
            :src (str): IPv6 src address in colon notation. Default '::'.
            :dst (str): IPv6 dst address in colon notation. Default '::'.
            :payload (bytes or PKT): Payload of this packet.
            :l7_ports (dict): Mapping of layer 4 port numbers to PKT
                subclasses, used to decode application layers.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'IP6'
        self.pq_type, self.query_fields = _QI_IP6
        cdef:
            unsigned char use_buffer
            array buf
            const unsigned char[:] mv
            const unsigned char[:] emv
            Py_ssize_t _ext_len
            bint _incomplete
            bytes owner
        self.ipv6_pheader = Ip6Ph()
        self._ext_hdrs = b''
        self._upper_proto = 0
        # Default version 6, traffic class 0, flow label 0.
        self._v_tc_flow = 0x60000000
        owner = _owned_buffer(args, kwargs)
        if owner is not None:
            mv = owner
            _decode_ip6(self, owner, mv, 0, len(owner), self._l7_ports)
            return
        use_buffer, buf = self.from_buffer(args, kwargs)

        if use_buffer:
            mv = buf
            need_bytes(mv, IPV6_HDR_LEN, 'IP6')
            self._v_tc_flow = rd_u32(mv, 0)
            self.payload_len = rd_u16(mv, 4)
            self._nh = mv[6]
            self.hop_limit = mv[7]
            self.src_nochk = rd_bytes(mv, 8, 24)
            self.dst_nochk = rd_bytes(mv, 24, 40)
            # Walk any extension-header chain to find the true upper-layer
            # protocol and keep the raw ext-header bytes for byte-faithful
            # export. The pseudo header used for L4 checksums must carry the
            # terminal upper-layer protocol, not the first ext-header number.
            _ext_len = 0
            _incomplete = 0
            self._upper_proto = _walk_ip6_ext(mv, IPV6_HDR_LEN, self._nh,
                                              &_ext_len, &_incomplete)
            self.ipv6_pheader.nh = self._upper_proto
            if _ext_len:
                self._ext_hdrs = \
                    rd_bytes(mv, IPV6_HDR_LEN, IPV6_HDR_LEN + _ext_len)
            _l4 = buf[IPV6_HDR_LEN + _ext_len:]
            if len(_l4):
                if _incomplete:
                    self.payload = NullPkt(_l4, l7_ports=self._l7_ports)
                elif self._upper_proto == PROTO_UDP:
                    self.payload = UDP(_l4, l7_ports=self._l7_ports)
                elif self._upper_proto == PROTO_TCP:
                    self.payload = TCP(_l4, l7_ports=self._l7_ports)
                elif self._upper_proto == PROTO_ICMPV6:
                    self.payload = ICMP6(_l4)
                else:
                    self.payload = NullPkt(_l4, l7_ports=self._l7_ports)
            else:
                self.payload = PKT()
        else:
            self.traffic_class = kwargs.get('traffic_class', 0)
            self.flow_label = kwargs.get('flow_label', 0)
            self.payload_len = kwargs.get('payload_len', 0)
            self.next_header = kwargs.get('next_header', 0)
            self.hop_limit = kwargs.get('hop_limit', 64)
            self.src = kwargs.get('src', '::')
            self.dst = kwargs.get('dst', '::')
            # Optional raw extension-header chain supplied as bytes. Derive the
            # terminal upper-layer protocol from it so checksums and payload
            # dispatch use the right protocol number.
            self._ext_hdrs = kwargs.get('ext_headers', b'')
            if self._ext_hdrs:
                emv = self._ext_hdrs
                _ext_len = 0
                _incomplete = 0
                self._upper_proto = _walk_ip6_ext(emv, 0, self._nh,
                                                  &_ext_len, &_incomplete)
                self.ipv6_pheader.nh = self._upper_proto
            else:
                self._upper_proto = self._nh
            if ('payload' in kwargs and
                    isinstance(kwargs['payload'], PKT)):
                self.payload = kwargs['payload']
            elif ('payload' in kwargs and
                      isinstance(kwargs['payload'], bytes)):
                if self._upper_proto == PROTO_UDP:
                    self.payload = UDP(kwargs['payload'],
                                       l7_ports=self._l7_ports)
                elif self._upper_proto == PROTO_TCP:
                    self.payload = TCP(kwargs['payload'],
                                       l7_ports=self._l7_ports)
                elif self._upper_proto == PROTO_ICMPV6:
                    self.payload = ICMP6(kwargs['payload'])
                else:
                    self.payload = NullPkt(kwargs['payload'],
                                           l7_ports=self._l7_ports)
            else:
                self.payload = PKT()

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields IP6 supports and IP6's
        PKT type ID.

        Returns:
            :tuple: PQ_IP6 and a tuple of the supported field names.
        """
        return (PQ_IP6,
                ('ipv6.version', 'ipv6.tclass', 'ipv6.flow', 'ipv6.plen',
                 'ipv6.nxt', 'ipv6.hlim', 'ipv6.src', 'ipv6.dst'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name.

        Args:
            :field (str): name of the desired field in Wireshark format, for
                example ipv6.src or ipv6.hlim.

        Returns:
            :object: the value of the field.
        """
        if field == 'ipv6.version':
            return self.version
        elif field == 'ipv6.tclass':
            return self.traffic_class
        elif field == 'ipv6.flow':
            return self.flow_label
        elif field == 'ipv6.plen':
            return self.payload_len
        elif field == 'ipv6.nxt':
            return self._nh
        elif field == 'ipv6.hlim':
            return self.hop_limit
        elif field == 'ipv6.src':
            return self.src
        elif field == 'ipv6.dst':
            return self.dst
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Export this IP6 instance as network order bytes.

        Args:
            :kwargs (dict): arguments passed along to payload classes. IP6
                honors:
            :csum (0 or 1): Whether layer 4 payloads should recalculate their
                checksums (IPv6 has no header checksum of its own).
            :update (0 or 1): Whether to recompute the payload_len field and
                have sub layers update their size counters.

        Returns:
            :bytes: network order byte string for this IP6 instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this IP6 header and its payload to a shared buffer.

        payload_len is patched back into the header once the payload behind
        it has been written. IPv6 has no header checksum of its own, so this
        is the only field that needs it. See PKT._write.
        """
        cdef:
            bint _update, _icmp
            Py_ssize_t start, hdr_end

        # An IP6 sitting inside an ICMPv6 error message is a quotation of a
        # packet that already went out: it keeps the length it was sent with
        # and its payload must not be re-checksummed against this frame's
        # pseudo header. Same contract as IP.
        _icmp = kwargs.get('for_icmp', 0)
        _update = 0 if _icmp else kwargs.get('update', 0)

        # Hand the payload our pseudo header for its checksum. src/dst/nh are
        # kept in sync by the property setters below.
        kwargs['ipv6_pheader'] = kwargs.get('ipv6_pheader', self.ipv6_pheader)

        start = w.n
        w_u32(w, self._v_tc_flow)
        w_u16(w, self.payload_len)
        w_u8(w, self._nh)
        w_u8(w, self.hop_limit)
        w_bytes(w, self._src)
        w_bytes(w, self._dst)
        w_bytes(w, self._ext_hdrs)
        hdr_end = w.n

        if isinstance(self.payload, PKT):
            if _icmp:
                (<PKT>self.payload)._write(w, {})
            else:
                (<PKT>self.payload)._write(w, kwargs)

        if _update:
            self.payload_len = <uint16_t>(len(self._ext_hdrs) +
                                          (w.n - hdr_end))
            w_set_u16(w, start + 4, self.payload_len)

        # Frame bytes that sat behind payload_len when this packet was
        # parsed, written last so they stay outside the length patched above.
        if self._trailer is not None:
            w_bytes(w, self._trailer)
        return 0

    property ext_headers:
        """Raw bytes of the IPv6 extension-header chain (empty when none).
        Setting it re-derives the terminal upper-layer protocol used for
        layer 4 checksums and payload dispatch."""
        def __get__(self):
            return self._ext_hdrs
        def __set__(self, bytes val):
            cdef:
                const unsigned char[:] emv
                Py_ssize_t _ext_len = 0
                bint _incomplete = 0
            self._ext_hdrs = val if val is not None else b''
            if self._ext_hdrs:
                emv = self._ext_hdrs
                self._upper_proto = _walk_ip6_ext(emv, 0, self._nh,
                                                  &_ext_len, &_incomplete)
            else:
                self._upper_proto = self._nh
            self.ipv6_pheader.nh = self._upper_proto

    property version:
        """The IP version. Always 6 for a valid IP6 packet."""
        def __get__(self):
            return (self._v_tc_flow >> 28) & 0xf
        def __set__(self, unsigned char val):
            if val in (IPV4_VER, IPV6_VER):
                self._v_tc_flow = (self._v_tc_flow & 0x0fffffff) | \
                                  (<uint32_t>val << 28)
            else:
                raise ValueError("Only IP versions 4 and 6 supported")

    property traffic_class:
        """8-bit traffic class (DSCP in the high 6 bits, ECN in the low 2)."""
        def __get__(self):
            return (self._v_tc_flow >> 20) & 0xff
        def __set__(self, unsigned char val):
            self._v_tc_flow = (self._v_tc_flow & 0xf00fffff) | \
                              (<uint32_t>val << 20)

    property flow_label:
        """20-bit flow label."""
        def __get__(self):
            return self._v_tc_flow & 0xfffff
        def __set__(self, uint32_t val):
            if val <= 0xfffff:
                self._v_tc_flow = (self._v_tc_flow & 0xfff00000) | val
            else:
                raise ValueError("IPv6 flow label valid values are 0-1048575")

    property next_header:
        """The next header / upper-layer protocol number. Kept in sync with
        the pseudo header used for layer 4 checksums."""
        def __get__(self):
            return self._nh
        def __set__(self, unsigned char val):
            self._nh = val
            # With no extension headers the next header IS the upper-layer
            # protocol; otherwise the pseudo header keeps the terminal protocol
            # derived from the extension-header chain.
            if not self._ext_hdrs:
                self._upper_proto = val
                self.ipv6_pheader.nh = val

    property src_nochk:
        def __set__(self, value):
            if isinstance(value, bytes):
                self.ipv6_pheader.src = self._src = value
            else:
                self.ipv6_pheader.src = self._src = (<array>value).tobytes()

    property src:
        def __get__(self):
            return _fmt_ipv6(self._src)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv6(value)
            if packed is None:
                raise ValueError("src must be a colon notation "
                                 "IPv6 string. (2001:db8::1)")
            self.ipv6_pheader.src = self._src = packed

    property dst_nochk:
        def __set__(self, value):
            if isinstance(value, bytes):
                self.ipv6_pheader.dst = self._dst = value
            else:
                self.ipv6_pheader.dst = self._dst = (<array>value).tobytes()

    property dst:
        def __get__(self):
            return _fmt_ipv6(self._dst)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv6(value)
            if packed is None:
                raise ValueError("dst must be a colon notation "
                                 "IPv6 string. (2001:db8::1)")
            self.ipv6_pheader.dst = self._dst = packed


# The unspecified address, used as the default for every 128 bit address
# field ICMP6 and its sub records carry. Built once rather than per packet.
cdef bytes _V6_ANY = b'\x00' * 16


cdef PKT _icmp6_embedded(array buf):
    """Parse the packet that provoked an ICMPv6 error message.

    RFC 4443 has the sender include as much of the offending packet as fits
    in a 1280 byte reply, so the copy is very often cut off part way through
    a layer 4 header. IP6 -- and every parser under it -- raises on a short
    buffer, which would turn an ordinary error message into an exception, so
    anything that will not parse is kept verbatim instead.

    :param buf: the bytes after the error message's 8 byte header.
    :return: an IP6 layer, or a NullPkt holding the bytes unchanged.
    """
    if not len(buf):
        return NullPkt()
    try:
        return IP6(buf)
    except ValueError:
        return NullPkt(buf)


@cython.final
cdef class ICMP6Opt(PKT):
    """One Neighbor Discovery option (RFC 4861 section 4.6).

    Every option is a type/length/value triple in which the length counts
    the whole option -- the two byte header included -- in units of 8
    octets. The value is kept exactly as it arrived, padding and all, so an
    option this class has no accessors for still round-trips byte for byte.

    Accessors are provided for the options that carry a single value:
    source/target link-layer address (1, 2) and MTU (5). Prefix Information
    (3) is read through its own read-only properties; build one by handing
    the 30 byte value in as ``data``.
    """

    def __init__(self, *args, **kwargs):
        """Initialize an ICMP6Opt object.

        Args:
            :args (list): Optional one element list of network order bytes.
            :data (bytes): Optional network order bytes of one ND option.
            :type (unsigned char): Option type. Default 0.
            :length (unsigned char): Option length in 8 octet units. Derived
                from the value when it is not given.
            :link_layer_address (str): Colon notation MAC, for option types
                1 and 2.
            :mtu (uint32_t): MTU value, for option type 5.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'ICMP6Opt'
        self.pq_type, self.query_fields = _QI_ICMP6Opt
        cdef:
            unsigned char use_buffer
            array buf
            const unsigned char[:] mv
            Py_ssize_t total
        self._data = b''
        use_buffer, buf = self.from_buffer(args, kwargs)

        if use_buffer:
            mv = buf
            need_bytes(mv, 2, 'ICMP6Opt')
            self.type = mv[0]
            self.length = mv[1]
            total = (<Py_ssize_t>self.length) * 8
            if total:
                need_bytes(mv, total, 'ICMP6Opt')
                self._data = rd_bytes(mv, 2, total)
        else:
            self.type = kwargs.get('type', 0)
            self.data = kwargs.get('data', b'')
            if 'link_layer_address' in kwargs:
                self.link_layer_address = kwargs['link_layer_address']
            if 'mtu' in kwargs:
                self.mtu = kwargs['mtu']
            # An explicit length wins, so a deliberately malformed option can
            # still be built for negative testing.
            if 'length' in kwargs:
                self.length = kwargs['length']

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields ICMP6Opt supports and
        its PKT type ID.

        Returns:
            :tuple: PQ_ICMP6OPT and a tuple of the supported field names.
        """
        return (PQ_ICMP6OPT,
                ('icmpv6.opt.type', 'icmpv6.opt.length',
                 'icmpv6.opt.linkaddr', 'icmpv6.opt.mtu',
                 'icmpv6.opt.prefix.length', 'icmpv6.opt.prefix.flag.l',
                 'icmpv6.opt.prefix.flag.a',
                 'icmpv6.opt.prefix.valid_lifetime',
                 'icmpv6.opt.prefix.preferred_lifetime',
                 'icmpv6.opt.prefix.prefix'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name."""
        if field == 'icmpv6.opt.type':
            return self.type
        elif field == 'icmpv6.opt.length':
            return self.length
        elif field == 'icmpv6.opt.linkaddr':
            return self.link_layer_address
        elif field == 'icmpv6.opt.mtu':
            return self.mtu
        elif field == 'icmpv6.opt.prefix.length':
            return self.prefix_len
        elif field == 'icmpv6.opt.prefix.flag.l':
            return self.prefix_on_link
        elif field == 'icmpv6.opt.prefix.flag.a':
            return self.prefix_autonomous
        elif field == 'icmpv6.opt.prefix.valid_lifetime':
            return self.valid_lifetime
        elif field == 'icmpv6.opt.prefix.preferred_lifetime':
            return self.preferred_lifetime
        elif field == 'icmpv6.opt.prefix.prefix':
            return self.prefix
        else:
            return None

    property byte_len:
        """Size of this option on the wire, header included."""
        def __get__(self):
            return 2 + len(self._data)

    property data:
        """The option value: everything after the two byte header.

        Setting it pads the value out to the 8 octet boundary RFC 4861
        requires and derives ``length`` from the result.
        """
        def __get__(self):
            return self._data
        def __set__(self, bytes val):
            cdef Py_ssize_t pad
            if not val:
                # An option with no value is not a legal option; leave it
                # empty rather than inventing 6 bytes of padding for it.
                self._data = b''
                self.length = 0
                return
            pad = (8 - ((len(val) + 2) % 8)) % 8
            self._data = val + (b'\x00' * pad)
            self.length = <unsigned char>((len(self._data) + 2) // 8)

    property link_layer_address:
        """Colon notation MAC from a source (1) or target (2) link-layer
        address option. None when the option is too short to hold one."""
        def __get__(self):
            if len(self._data) >= MAC_LEN:
                return _fmt_mac_buf(
                    <const unsigned char *>PyBytes_AS_STRING(self._data))
            return None
        def __set__(self, str val):
            self.data = pack_mac(val).tobytes()

    property mtu:
        """The MTU carried by an option type 5. Zero for every other type."""
        def __get__(self):
            if self.type == ICMP6_OPT_MTU and len(self._data) >= 6:
                return unpack('!I', self._data[2:6])[0]
            return 0
        def __set__(self, uint32_t val):
            self.type = ICMP6_OPT_MTU
            self.data = b'\x00\x00' + pack('!I', val)

    property prefix_len:
        """Prefix Information (3): significant bits in the prefix."""
        def __get__(self):
            if self.type == ICMP6_OPT_PREFIX_INFO and len(self._data) >= 30:
                return self._data[0]
            return 0

    property prefix_on_link:
        """Prefix Information (3): the L (on-link) flag."""
        def __get__(self):
            if self.type == ICMP6_OPT_PREFIX_INFO and len(self._data) >= 30:
                return (self._data[1] >> 7) & 1
            return 0

    property prefix_autonomous:
        """Prefix Information (3): the A (autonomous address) flag."""
        def __get__(self):
            if self.type == ICMP6_OPT_PREFIX_INFO and len(self._data) >= 30:
                return (self._data[1] >> 6) & 1
            return 0

    property valid_lifetime:
        """Prefix Information (3): valid lifetime in seconds."""
        def __get__(self):
            if self.type == ICMP6_OPT_PREFIX_INFO and len(self._data) >= 30:
                return unpack('!I', self._data[2:6])[0]
            return 0

    property preferred_lifetime:
        """Prefix Information (3): preferred lifetime in seconds."""
        def __get__(self):
            if self.type == ICMP6_OPT_PREFIX_INFO and len(self._data) >= 30:
                return unpack('!I', self._data[6:10])[0]
            return 0

    property prefix:
        """Prefix Information (3): the prefix in colon notation."""
        def __get__(self):
            if self.type == ICMP6_OPT_PREFIX_INFO and len(self._data) >= 30:
                return _fmt_ipv6(self._data[14:30])
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Export this option as network order bytes.

        Returns:
            :bytes: network order byte string for this ICMP6Opt instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this option to a shared buffer. See PKT._write."""
        w_u8(w, self.type)
        w_u8(w, self.length)
        w_bytes(w, self._data)
        return 0


@cython.final
cdef class MLDv2AddressRecord(PKT):
    """One Multicast Address Record from an MLDv2 report (RFC 3810 5.2.12).

    The IPv6 counterpart of IGMPGroupRecord. Both count their auxiliary data
    in 32 bit words, per RFC 3810 5.2.10 and RFC 3376 4.2.6.
    """

    def __init__(self, *args, **kwargs):
        """Initialize a MLDv2AddressRecord object.

        Args:
            :args (list): Optional one element list of network order bytes.
            :data (bytes): Optional network order bytes of one record.
            :type (unsigned char): Record type. 1-6 per RFC 3810 5.2.12.
            :aux_data_len (unsigned char): Auxiliary data length in 32 bit
                words.
            :num_src (uint16_t): Number of source addresses. Derived from
                source_addresses when that is given.
            :multicast_address (str): Colon notation IPv6 multicast address.
            :source_addresses (list): Colon notation IPv6 source addresses.
            :aux_data (bytes): Auxiliary data.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'MLDv2AddressRecord'
        self.pq_type, self.query_fields = _QI_MLDv2AddressRecord
        self._multicast_address = _V6_ANY
        self._source_addresses = self.aux_data = b''

        cdef:
            unsigned char use_buffer
            Py_ssize_t start, aux_len
            array buf
            const unsigned char[:] mv
        use_buffer, buf = self.from_buffer(args, kwargs)

        if use_buffer:
            mv = buf
            need_bytes(mv, 20, 'MLDv2AddressRecord')
            self.type = mv[0]
            self.aux_data_len = mv[1]
            self.num_src = rd_u16(mv, 2)
            self._multicast_address = rd_bytes(mv, 4, 20)
            start = 20 + (16 * <Py_ssize_t>self.num_src)
            if self.num_src:
                need_bytes(mv, start, 'MLDv2AddressRecord')
                self._source_addresses = rd_bytes(mv, 20, start)
            if self.aux_data_len:
                aux_len = 4 * <Py_ssize_t>self.aux_data_len
                need_bytes(mv, start + aux_len, 'MLDv2AddressRecord')
                self.aux_data = rd_bytes(mv, start, start + aux_len)
        else:
            self.type = kwargs.get('type', 0)
            self.aux_data_len = kwargs.get('aux_data_len', 0)
            self.num_src = kwargs.get('num_src', 0)
            self.multicast_address = kwargs.get('multicast_address', '::')
            self.source_addresses = kwargs.get('source_addresses', list())
            self.aux_data = kwargs.get('aux_data', b'')

    property byte_len:
        """Size of this record on the wire."""
        def __get__(self):
            return 20 + (self.num_src * 16) + (self.aux_data_len * 4)

    property multicast_address:
        def __get__(self):
            return _fmt_ipv6(self._multicast_address)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv6(value)
            if packed is None:
                raise ValueError("multicast_address must be a colon notation "
                                 "IPv6 string. (ff02::1)")
            self._multicast_address = packed

    property source_addresses:
        def __get__(self):
            cdef:
                uint16_t i
                list r
            if self._source_addresses:
                r = list()
                for i in range(self.num_src):
                    r.append(_fmt_ipv6(
                        self._source_addresses[i*16:i*16+16]))
                return r
            else:
                return list()
        def __set__(self, list value):
            cdef:
                str ip
                bytes packed
                list packed_addrs = []

            for ip in value:
                packed = pack_ipv6(ip)
                if packed is None:
                    raise ValueError("source_addresses must be a list of "
                                     "colon notation IPv6 strings. "
                                     "(2001:db8::1)")
                packed_addrs.append(packed)
            self._source_addresses = b''.join(packed_addrs)
            self.num_src = len(packed_addrs)

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields MLDv2AddressRecord
        supports and its PKT type ID.

        Returns:
            :tuple: PQ_MLDV2_ADDRESS_RECORD and a tuple of the supported
                field names.
        """
        return (PQ_MLDV2_ADDRESS_RECORD,
                ('icmpv6.mldr.mar.record_type',
                 'icmpv6.mldr.mar.aux_data_len',
                 'icmpv6.mldr.mar.nb_sources',
                 'icmpv6.mldr.mar.multicast_address',
                 'icmpv6.mldr.mar.source_address',
                 'icmpv6.mldr.mar.auxiliary_data'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name."""
        if field == 'icmpv6.mldr.mar.record_type':
            return self.type
        elif field == 'icmpv6.mldr.mar.aux_data_len':
            return self.aux_data_len
        elif field == 'icmpv6.mldr.mar.nb_sources':
            return self.num_src
        elif field == 'icmpv6.mldr.mar.multicast_address':
            return self.multicast_address
        elif field == 'icmpv6.mldr.mar.source_address':
            return self.source_addresses
        elif field == 'icmpv6.mldr.mar.auxiliary_data':
            return self.aux_data
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Export this record as network order bytes.

        Returns:
            :bytes: network order byte string for this record.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this record to a shared buffer. See PKT._write."""
        w_u8(w, self.type)
        w_u8(w, self.aux_data_len)
        w_u16(w, self.num_src)
        w_bytes(w, self._multicast_address)
        w_bytes(w, self._source_addresses)
        w_bytes(w, self.aux_data)
        return 0


@cython.final
cdef class ICMP6(PKT):
    """Implements ICMPv6 (RFC 4443). Unlike IPv4 ICMP, the ICMPv6 checksum
    covers the IPv6 pseudo header, so this class must be given an
    ``ipv6_pheader`` (supplied automatically by IP6) when csum is requested.

    The common 4-byte header (type, code, checksum) is always present. What
    follows it depends on the type:

    * **Errors (1-4, RFC 4443):** a 32-bit word -- unused for Destination
      Unreachable and Time Exceeded, the MTU for Packet Too Big, the pointer
      for Parameter Problem -- and then as much of the packet that provoked
      the error as the sender could fit, parsed into ``hdr_pkt``.
    * **Echo (128, 129):** identifier, sequence and an opaque data field.
    * **MLD (130-132, RFC 2710):** maximum response delay and the multicast
      address. A type 130 longer than 24 bytes is an MLDv2 query (RFC 3810),
      which adds S/QRV, QQIC and a source list.
    * **MLDv2 report (143, RFC 3810):** a list of ``MLDv2AddressRecord``.
    * **Neighbor Discovery (133-137, RFC 4861):** the per-type fixed part
      followed by a list of ``ICMP6Opt`` option TLVs.

    Any other type is still preserved verbatim in ``msg_body`` so that it
    round-trips byte-for-byte, and so is any trailing garbage found where an
    option should have started.
    """

    def __init__(self, *args, **kwargs):
        """Initialize an ICMP6 object.

        Args:
            :args (list): Optional one element list of network order bytes.
            :data (bytes): Optional network order bytes of an ICMPv6 message.
            :type (unsigned char): ICMPv6 type. Default 128 (Echo Request).
            :code (unsigned char): ICMPv6 code. Default 0.
            :checksum (uint16_t): Recomputed by pkt2net when csum=1.
            :identifier (uint16_t): Echo identifier (echo types only).
            :sequence (uint16_t): Echo sequence number (echo types only).
            :echo_data (bytes): Echo payload (echo types only).
            :mtu (uint32_t): Next hop MTU (type 2 only).
            :pointer (uint32_t): Offset of the bad octet (type 4 only).
            :hdr_pkt (PKT): The packet that provoked an error (types 1-4).
            :cur_hop_limit (unsigned char): Router Advertisement hop limit.
            :ra_flags (unsigned char): Router Advertisement flag octet.
            :router_lifetime (uint16_t): Router Advertisement lifetime.
            :reachable_time (uint32_t): Router Advertisement reachable time.
            :retrans_timer (uint32_t): Router Advertisement retrans timer.
            :na_flags (unsigned char): Neighbor Advertisement flag octet.
            :target_address (str): ND target address (types 135, 136, 137).
            :dest_address (str): Redirect destination address (type 137).
            :options (list): ICMP6Opt instances for ND types 133-137.
            :max_resp (uint16_t): MLD maximum response delay/code.
            :multicast_address (str): MLD multicast address.
            :mld_version (unsigned char): 1 or 2. Selects the short or long
                form of a type 130 query. Defaults to 2 when any MLDv2 query
                field is supplied, 1 otherwise.
            :qqic (unsigned char): MLDv2 querier's query interval code.
            :s_flag (0 or 1): MLDv2 suppress router-side processing flag.
            :qrv (unsigned char): MLDv2 querier's robustness variable.
            :source_addresses (list): MLDv2 query source addresses.
            :records (list): MLDv2AddressRecord instances (type 143).
            :msg_body (bytes): Raw message body for unsupported types.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'ICMP6'
        self.pq_type, self.query_fields = _QI_ICMP6
        cdef:
            unsigned char use_buffer
            uint16_t i
            Py_ssize_t offset, src_end
            array buf
            const unsigned char[:] mv
            MLDv2AddressRecord rec
        self.echo_data = b''
        self._body = b''
        self.hdr_pkt = NullPkt()
        self.options = list()
        self.records = list()
        self._target_address = _V6_ANY
        self._dest_address = _V6_ANY
        self._multicast_address = _V6_ANY
        self._source_addresses = b''
        use_buffer, buf = self.from_buffer(args, kwargs)

        if use_buffer:
            mv = buf
            need_bytes(mv, 4, 'ICMP6')
            self.type = mv[0]
            self.code = mv[1]
            self.checksum = rd_u16(mv, 2)
            if self.type in (ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY):
                need_bytes(mv, 8, 'ICMP6')
                self.identifier = rd_u16(mv, 4)
                self.sequence = rd_u16(mv, 6)
                self.echo_data = rd_bytes(mv, 8, -1)
            elif self.type in (ICMP6_DST_UNREACH, ICMP6_PKT_TOO_BIG,
                               ICMP6_TIME_EXCEEDED, ICMP6_PARAM_PROB):
                need_bytes(mv, 8, 'ICMP6')
                self._err_word = rd_u32(mv, 4)
                self.hdr_pkt = _icmp6_embedded(buf[8:])
            elif self.type in (ICMP6_MLD_QUERY, ICMP6_MLD_REPORT,
                               ICMP6_MLD_DONE):
                need_bytes(mv, 24, 'ICMP6')
                self.mld_version = 1
                self.max_resp = rd_u16(mv, 4)
                self._multicast_address = rd_bytes(mv, 8, 24)
                if self.type == ICMP6_MLD_QUERY and mv.shape[0] > 24:
                    # RFC 3810 5.1: a query longer than the MLDv1 24 bytes
                    # carries the v2 tail.
                    need_bytes(mv, 28, 'ICMP6')
                    self.mld_version = 2
                    self._s_qrv = mv[24]
                    self.qqic = mv[25]
                    self.num_src = rd_u16(mv, 26)
                    if self.num_src:
                        src_end = 28 + (16 * <Py_ssize_t>self.num_src)
                        need_bytes(mv, src_end, 'ICMP6')
                        self._source_addresses = rd_bytes(mv, 28, src_end)
            elif self.type == ICMP6_MLDV2_REPORT:
                need_bytes(mv, 8, 'ICMP6')
                self.mld_version = 2
                self.num_records = rd_u16(mv, 6)
                offset = 8
                for i in range(self.num_records):
                    rec = MLDv2AddressRecord(buf[offset:])
                    self.records.append(rec)
                    offset += rec.byte_len
            elif self.type == ICMP6_ND_ROUTER_SOLICIT:
                need_bytes(mv, 8, 'ICMP6')
                self._parse_options_buffer(buf, 8)
            elif self.type == ICMP6_ND_ROUTER_ADVERT:
                need_bytes(mv, 16, 'ICMP6')
                self.cur_hop_limit = mv[4]
                self._ra_flags = mv[5]
                self.router_lifetime = rd_u16(mv, 6)
                self.reachable_time = rd_u32(mv, 8)
                self.retrans_timer = rd_u32(mv, 12)
                self._parse_options_buffer(buf, 16)
            elif self.type in (ICMP6_ND_NEIGHBOR_SOLICIT,
                               ICMP6_ND_NEIGHBOR_ADVERT):
                need_bytes(mv, 24, 'ICMP6')
                if self.type == ICMP6_ND_NEIGHBOR_ADVERT:
                    self._na_flags = mv[4]
                self._target_address = rd_bytes(mv, 8, 24)
                self._parse_options_buffer(buf, 24)
            elif self.type == ICMP6_ND_REDIRECT:
                need_bytes(mv, 40, 'ICMP6')
                self._target_address = rd_bytes(mv, 8, 24)
                self._dest_address = rd_bytes(mv, 24, 40)
                self._parse_options_buffer(buf, 40)
            else:
                self._body = rd_bytes(mv, 4, -1)
        else:
            self.type = kwargs.get('type', ICMP6_ECHO_REQUEST)
            self.code = kwargs.get('code', 0)
            self.checksum = kwargs.get('checksum', 0)
            self.identifier = kwargs.get('identifier', 0)
            self.sequence = kwargs.get('sequence', 0)
            self.echo_data = kwargs.get('echo_data', b'')
            self._body = kwargs.get('msg_body', b'')
            # mtu and pointer are the same 32 bit word; only one of them can
            # be meaningful for any given type, so only one may be set.
            self._err_word = 0
            if 'mtu' in kwargs:
                self.mtu = kwargs['mtu']
            if 'pointer' in kwargs:
                self.pointer = kwargs['pointer']
            self.hdr_pkt = kwargs.get('hdr_pkt', NullPkt())
            self.cur_hop_limit = kwargs.get('cur_hop_limit', 0)
            self._ra_flags = kwargs.get('ra_flags', 0)
            self.router_lifetime = kwargs.get('router_lifetime', 0)
            self.reachable_time = kwargs.get('reachable_time', 0)
            self.retrans_timer = kwargs.get('retrans_timer', 0)
            self._na_flags = kwargs.get('na_flags', 0)
            self.target_address = kwargs.get('target_address', '::')
            self.dest_address = kwargs.get('dest_address', '::')
            self.options = kwargs.get('options', list())
            self.max_resp = kwargs.get('max_resp', 0)
            self.multicast_address = kwargs.get('multicast_address', '::')
            self.qqic = kwargs.get('qqic', 0)
            self.s_flag = kwargs.get('s_flag', 0)
            self.qrv = kwargs.get('qrv', 0)
            self.source_addresses = kwargs.get('source_addresses', list())
            self.records = kwargs.get('records', list())
            self.num_records = len(self.records)
            if 'mld_version' in kwargs:
                self.mld_version = kwargs['mld_version']
            elif self._s_qrv or self.qqic or self.num_src:
                self.mld_version = 2
            else:
                self.mld_version = 1

    cdef int _parse_options_buffer(self, array buf,
                                   Py_ssize_t off) except -1:
        cdef:
            const unsigned char[:] mv = buf
            Py_ssize_t n = mv.shape[0]
            Py_ssize_t size
        while off < n:
            if off + 2 > n:
                self._body = rd_bytes(mv, off, -1)
                break
            size = (<Py_ssize_t>mv[off + 1]) * 8
            if size <= 0 or off + size > n:
                self._body = rd_bytes(mv, off, -1)
                break
            self.options.append(ICMP6Opt(buf[off:off + size]))
            off += size
        return 0

    cdef int _parse_options(self, bytes owner, Py_ssize_t off,
                            Py_ssize_t end) except -1:
        """Walk the Neighbor Discovery option TLVs at the end of an ND
        message.

        RFC 4861 4.6 gives every option an 8 octet granular length that
        counts its own two byte header, so the walk is length driven. A zero
        length is invalid and would not terminate, and a length running off
        the end of the buffer means the frame was cut short: in both cases
        the remainder is kept verbatim in msg_body rather than guessed at,
        which is also what makes those frames round-trip.

        :param owner: immutable owner of the whole ICMPv6 message buffer.
        :param off: offset of the first option.
        :param end: one past the final byte of the ICMPv6 message.
        :return: 0.
        """
        cdef:
            const unsigned char[:] mv = owner
            Py_ssize_t size
            ICMP6Opt opt
        while off < end:
            if off + 2 > end:
                self._body = rd_bytes(mv, off, end)
                break
            size = (<Py_ssize_t>mv[off + 1]) * 8
            if size <= 0 or off + size > end:
                self._body = rd_bytes(mv, off, end)
                break
            opt = ICMP6Opt.__new__(ICMP6Opt)
            opt._l7_ports = None
            opt.pkt_name = 'ICMP6Opt'
            opt.pq_type, opt.query_fields = _QI_ICMP6Opt
            opt._data = b''
            _decode_icmp6_opt(opt, owner, off, off + size)
            self.options.append(opt)
            off += size
        return 0

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields ICMP6 supports and its
        PKT type ID.

        Returns:
            :tuple: PQ_ICMPV6 and a tuple of the supported field names.
        """
        return (PQ_ICMPV6,
                ('icmpv6.type', 'icmpv6.code', 'icmpv6.checksum',
                 'icmpv6.echo.identifier', 'icmpv6.echo.sequence_number',
                 'icmpv6.mtu', 'icmpv6.pointer',
                 'icmpv6.nd.ra.cur_hop_limit', 'icmpv6.nd.ra.flag.m',
                 'icmpv6.nd.ra.flag.o', 'icmpv6.nd.ra.router_lifetime',
                 'icmpv6.nd.ra.reachable_time', 'icmpv6.nd.ra.retrans_timer',
                 'icmpv6.nd.ns.target_address', 'icmpv6.nd.na.target_address',
                 'icmpv6.nd.na.flag.r', 'icmpv6.nd.na.flag.s',
                 'icmpv6.nd.na.flag.o', 'icmpv6.nd.rd.target_address',
                 'icmpv6.nd.rd.destination_address',
                 'icmpv6.mld.maximum_response_delay',
                 'icmpv6.mld.multicast_address', 'icmpv6.mld.flag.s',
                 'icmpv6.mld.qrv', 'icmpv6.mld.qqic',
                 'icmpv6.mld.nb_sources', 'icmpv6.mld.source_address',
                 'icmpv6.mldr.nb_mcast_records'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name.

        The Neighbor Discovery target address appears under three Wireshark
        names -- ns, na and rd -- because Wireshark names it per message
        type. All three resolve to the same field here, and return None when
        this instance is not of the matching type, so a query that mixes
        message types gets None rather than another type's address.

        Args:
            :field (str): name of the desired field in Wireshark format, for
                example icmpv6.type or icmpv6.nd.ns.target_address.

        Returns:
            :object: the value of the field.
        """
        if field == 'icmpv6.type':
            return self.type
        elif field == 'icmpv6.code':
            return self.code
        elif field == 'icmpv6.checksum':
            return self.checksum
        elif field == 'icmpv6.echo.identifier':
            return self.identifier
        elif field == 'icmpv6.echo.sequence_number':
            return self.sequence
        elif field == 'icmpv6.mtu':
            if self.type == ICMP6_PKT_TOO_BIG:
                return self.mtu
            return None
        elif field == 'icmpv6.pointer':
            if self.type == ICMP6_PARAM_PROB:
                return self.pointer
            return None
        elif field == 'icmpv6.nd.ra.cur_hop_limit':
            return self.cur_hop_limit
        elif field == 'icmpv6.nd.ra.flag.m':
            return self.ra_flag_m
        elif field == 'icmpv6.nd.ra.flag.o':
            return self.ra_flag_o
        elif field == 'icmpv6.nd.ra.router_lifetime':
            return self.router_lifetime
        elif field == 'icmpv6.nd.ra.reachable_time':
            return self.reachable_time
        elif field == 'icmpv6.nd.ra.retrans_timer':
            return self.retrans_timer
        elif field == 'icmpv6.nd.ns.target_address':
            if self.type == ICMP6_ND_NEIGHBOR_SOLICIT:
                return self.target_address
            return None
        elif field == 'icmpv6.nd.na.target_address':
            if self.type == ICMP6_ND_NEIGHBOR_ADVERT:
                return self.target_address
            return None
        elif field == 'icmpv6.nd.na.flag.r':
            return self.na_flag_r
        elif field == 'icmpv6.nd.na.flag.s':
            return self.na_flag_s
        elif field == 'icmpv6.nd.na.flag.o':
            return self.na_flag_o
        elif field == 'icmpv6.nd.rd.target_address':
            if self.type == ICMP6_ND_REDIRECT:
                return self.target_address
            return None
        elif field == 'icmpv6.nd.rd.destination_address':
            if self.type == ICMP6_ND_REDIRECT:
                return self.dest_address
            return None
        elif field == 'icmpv6.mld.maximum_response_delay':
            return self.max_resp
        elif field == 'icmpv6.mld.multicast_address':
            return self.multicast_address
        elif field == 'icmpv6.mld.flag.s':
            return self.s_flag
        elif field == 'icmpv6.mld.qrv':
            return self.qrv
        elif field == 'icmpv6.mld.qqic':
            return self.qqic
        elif field == 'icmpv6.mld.nb_sources':
            return self.num_src
        elif field == 'icmpv6.mld.source_address':
            return self.source_addresses
        elif field == 'icmpv6.mldr.nb_mcast_records':
            return self.num_records
        else:
            return None

    property msg_body:
        """The message body: everything after the 4-byte header.

        Built from the parsed fields for every type this class understands,
        so it stays the whole body no matter how much of it has names now.
        Setting it supplies the raw body used by types that have none.
        """
        def __get__(self):
            return _serialize(self, {})[4:]
        def __set__(self, bytes val):
            self._body = val

    property mtu:
        """Next hop MTU carried by a Packet Too Big (2) message."""
        def __get__(self):
            return self._err_word
        def __set__(self, uint32_t val):
            self._err_word = val

    property pointer:
        """Offset of the octet that a Parameter Problem (4) points at."""
        def __get__(self):
            return self._err_word
        def __set__(self, uint32_t val):
            self._err_word = val

    property ra_flags:
        """The Router Advertisement flag octet (RFC 4861 4.2)."""
        def __get__(self):
            return self._ra_flags
        def __set__(self, unsigned char val):
            self._ra_flags = val

    property ra_flag_m:
        """Router Advertisement managed address configuration flag."""
        def __get__(self):
            return (self._ra_flags >> 7) & 1
        def __set__(self, unsigned char val):
            if val:
                self._ra_flags |= 0x80
            else:
                self._ra_flags &= 0x7f

    property ra_flag_o:
        """Router Advertisement other configuration flag."""
        def __get__(self):
            return (self._ra_flags >> 6) & 1
        def __set__(self, unsigned char val):
            if val:
                self._ra_flags |= 0x40
            else:
                self._ra_flags &= 0xbf

    property na_flags:
        """The Neighbor Advertisement flag octet (RFC 4861 4.4)."""
        def __get__(self):
            return self._na_flags
        def __set__(self, unsigned char val):
            self._na_flags = val

    property na_flag_r:
        """Neighbor Advertisement router flag."""
        def __get__(self):
            return (self._na_flags >> 7) & 1
        def __set__(self, unsigned char val):
            if val:
                self._na_flags |= 0x80
            else:
                self._na_flags &= 0x7f

    property na_flag_s:
        """Neighbor Advertisement solicited flag."""
        def __get__(self):
            return (self._na_flags >> 6) & 1
        def __set__(self, unsigned char val):
            if val:
                self._na_flags |= 0x40
            else:
                self._na_flags &= 0xbf

    property na_flag_o:
        """Neighbor Advertisement override flag."""
        def __get__(self):
            return (self._na_flags >> 5) & 1
        def __set__(self, unsigned char val):
            if val:
                self._na_flags |= 0x20
            else:
                self._na_flags &= 0xdf

    property s_flag:
        """MLDv2 query: suppress router-side processing (RFC 3810 5.1.7)."""
        def __get__(self):
            return (self._s_qrv >> 3) & 1
        def __set__(self, unsigned char val):
            if val:
                self._s_qrv |= 0x08
            else:
                self._s_qrv &= 0xf7

    property qrv:
        """MLDv2 query: querier's robustness variable (RFC 3810 5.1.8)."""
        def __get__(self):
            return self._s_qrv & 0x07
        def __set__(self, unsigned char val):
            if val <= 0x07:
                self._s_qrv = (self._s_qrv & 0xf8) | val
            else:
                raise ValueError("qrv valid values are 0-7")

    property target_address:
        """ND target address (types 135, 136 and 137) in colon notation."""
        def __get__(self):
            return _fmt_ipv6(self._target_address)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv6(value)
            if packed is None:
                raise ValueError("target_address must be a colon notation "
                                 "IPv6 string. (2001:db8::1)")
            self._target_address = packed

    property dest_address:
        """Redirect (137) destination address in colon notation."""
        def __get__(self):
            return _fmt_ipv6(self._dest_address)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv6(value)
            if packed is None:
                raise ValueError("dest_address must be a colon notation "
                                 "IPv6 string. (2001:db8::1)")
            self._dest_address = packed

    property multicast_address:
        """MLD multicast address in colon notation."""
        def __get__(self):
            return _fmt_ipv6(self._multicast_address)
        def __set__(self, str value):
            cdef bytes packed = pack_ipv6(value)
            if packed is None:
                raise ValueError("multicast_address must be a colon notation "
                                 "IPv6 string. (ff02::1)")
            self._multicast_address = packed

    property source_addresses:
        """MLDv2 query source list, as colon notation strings."""
        def __get__(self):
            cdef:
                uint16_t i
                list r
            if self._source_addresses:
                r = list()
                for i in range(self.num_src):
                    r.append(_fmt_ipv6(
                        self._source_addresses[i*16:i*16+16]))
                return r
            else:
                return list()
        def __set__(self, list value):
            cdef:
                str ip
                bytes packed
                list packed_addrs = []

            for ip in value:
                packed = pack_ipv6(ip)
                if packed is None:
                    raise ValueError("source_addresses must be a list of "
                                     "colon notation IPv6 strings. "
                                     "(2001:db8::1)")
                packed_addrs.append(packed)
            self._source_addresses = b''.join(packed_addrs)
            self.num_src = len(packed_addrs)

    cpdef bytes pkt2net(self, dict kwargs):
        """Export this ICMP6 instance as network order bytes.

        Args:
            :kwargs (dict): honors ``csum`` (recompute checksum, which requires
                ``ipv6_pheader`` to be present) and passes through otherwise.

        Returns:
            :bytes: network order byte string for this ICMP6 instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this ICMP6 message to a shared buffer.

        The checksum covers the whole message, so it is emitted as a
        placeholder and patched back in once the body is written.
        See PKT._write.
        """
        cdef:
            bint _csum
            Ip6Ph _ipv6_pheader
            Py_ssize_t start
            uint16_t msg_len
            unsigned char ph[40]
            ICMP6Opt opt
            MLDv2AddressRecord rec

        _csum = kwargs.get('csum', 0)
        _ipv6_pheader = kwargs.get('ipv6_pheader')

        start = w.n
        w_u8(w, self.type)
        w_u8(w, self.code)
        w_u16(w, self.checksum)
        if self.type in (ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY):
            w_u16(w, self.identifier)
            w_u16(w, self.sequence)
            w_bytes(w, self.echo_data)
        elif self.type in (ICMP6_DST_UNREACH, ICMP6_PKT_TOO_BIG,
                           ICMP6_TIME_EXCEEDED, ICMP6_PARAM_PROB):
            w_u32(w, self._err_word)
            # Same contract as IPv4 ICMP: the quoted packet is written as it
            # stands, with none of this message's kwargs applied to it.
            kwargs['for_icmp'] = 1
            self.hdr_pkt._write(w, kwargs)
        elif self.type in (ICMP6_MLD_QUERY, ICMP6_MLD_REPORT,
                           ICMP6_MLD_DONE):
            w_u16(w, self.max_resp)
            w_zeros(w, 2)
            w_bytes(w, self._multicast_address)
            if self.type == ICMP6_MLD_QUERY and self.mld_version == 2:
                w_u8(w, self._s_qrv)
                w_u8(w, self.qqic)
                self.num_src = <uint16_t>(len(self._source_addresses) // 16)
                w_u16(w, self.num_src)
                w_bytes(w, self._source_addresses)
        elif self.type == ICMP6_MLDV2_REPORT:
            w_zeros(w, 2)
            self.num_records = <uint16_t>len(self.records)
            w_u16(w, self.num_records)
            for rec in self.records:
                rec._write(w, kwargs)
        elif self.type == ICMP6_ND_ROUTER_SOLICIT:
            w_zeros(w, 4)
            for opt in self.options:
                opt._write(w, kwargs)
            w_bytes(w, self._body)
        elif self.type == ICMP6_ND_ROUTER_ADVERT:
            w_u8(w, self.cur_hop_limit)
            w_u8(w, self._ra_flags)
            w_u16(w, self.router_lifetime)
            w_u32(w, self.reachable_time)
            w_u32(w, self.retrans_timer)
            for opt in self.options:
                opt._write(w, kwargs)
            w_bytes(w, self._body)
        elif self.type in (ICMP6_ND_NEIGHBOR_SOLICIT,
                           ICMP6_ND_NEIGHBOR_ADVERT):
            if self.type == ICMP6_ND_NEIGHBOR_ADVERT:
                w_u8(w, self._na_flags)
                w_zeros(w, 3)
            else:
                w_zeros(w, 4)
            w_bytes(w, self._target_address)
            for opt in self.options:
                opt._write(w, kwargs)
            w_bytes(w, self._body)
        elif self.type == ICMP6_ND_REDIRECT:
            w_zeros(w, 4)
            w_bytes(w, self._target_address)
            w_bytes(w, self._dest_address)
            for opt in self.options:
                opt._write(w, kwargs)
            w_bytes(w, self._body)
        else:
            w_bytes(w, self._body)

        if _csum and _ipv6_pheader is not None:
            msg_len = <uint16_t>(w.n - start)
            ph_addr(ph, _ipv6_pheader.src, 16)
            ph_addr(ph + 16, _ipv6_pheader.dst, 16)
            ph[32] = 0
            ph[33] = 0
            ph[34] = <unsigned char>(msg_len >> 8)
            ph[35] = <unsigned char>(msg_len & 0xff)
            ph[36] = 0
            ph[37] = 0
            ph[38] = 0
            ph[39] = _ipv6_pheader.nh
            w_set_u16(w, start + 2, 0)
            self.checksum = w_cksum(w, start, cksum_acc(ph, 40, 0))
            w_set_u16(w, start + 2, self.checksum)
        return 0


@cython.final
cdef class MPLS(PKT):
    """ Very limited implementation of MPLS (RFC 3031). Supports IPv4, IPv6
    and Ethernet payloads, and only detects the difference by looking at the
    first nibble of the payload bytes.

    RFC 3031 does not bound the label stack, so parsing does. At most
    IP_CONST.MPLS_MAX_STACK_DEPTH labels become MPLS layers; a longer stack
    keeps the labels past that point as an opaque NullPkt payload, which
    still serializes back to the bytes that were parsed.
    """

    def __init__(self, *args, **kwargs):
        """Initialize a MPLS object. Note on data types for Args. Only the
        stack bit and the TTL use the full size of the data types specified
        below. label used only 20 bits and the traffic class uses 3 bits.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an MPLS packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an MPLS packet
            :label (uint32_t): 20 bit MPLS label value.
            :tc (unsigned char): Traffic Class (QoS and ECN). 3 bits used
            :s (0 or 1): Bottom of label stack bit.
            :ttl (unsigned char): Time to live for this label.
            :payload (PKT or bytes): The payload of this packet.
            :l7_ports (dict): Keys are layer 4 port numbers and the values are
                PKT subclass packet classes. Used by the app_layer() in layer
                7 protocols to determine what class should be used to decode
                the payload string or byte array. MPLS only passes this option
                on to subsequent packet layers.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'MPLS'
        self.pq_type, self.query_fields = _QI_MPLS
        cdef:
            unsigned char use_buffer
            array buf
            const unsigned char[:] mv
            bytes owner
        owner = _owned_buffer(args, kwargs)
        if owner is not None:
            mv = owner
            _decode_mpls(self, owner, mv, 0, len(owner), self._l7_ports)
            return
        use_buffer, buf = self.from_buffer(args, kwargs)

        if use_buffer:
            mv = buf
            need_bytes(mv, 4, 'MPLS')
            self._data = rd_u32(mv, 0)
            if self.s and mv.shape[0] > 4:
                # There is no protocol id in an MPLS label, so the payload is
                # identified from its first nibble: 4 is IPv4 and 6 is IPv6
                # (RFC 4385 keeps 0 clear for the pseudowire control word, so
                # the guess is unambiguous for both IP versions). Anything
                # else is treated as an Ethernet pseudowire.
                if mv[4] >> 4 == IPV4_VER:
                    self.payload = IP(buf[4:],
                                      l7_ports = self._l7_ports)
                elif mv[4] >> 4 == IPV6_VER:
                    self.payload = IP6(buf[4:],
                                       l7_ports = self._l7_ports)
                else:
                    self.payload = Ethernet(buf[4:],
                                            l7_ports = self._l7_ports)
            elif mv.shape[0] > 4:
                self.payload = MPLS(buf[4:],
                                    l7_ports = self._l7_ports)
            else:
                self.payload = NullPkt()
        else:
            self._data = 0
            self.label = kwargs.get('label', 0)
            self.tc = kwargs.get('tc', 0)
            self.s = kwargs.get('s', 1)
            self.ttl = kwargs.get('ttl', 0)
            if ('payload' in kwargs and
                    isinstance(kwargs['payload'], PKT)):
                self.payload = kwargs['payload']
            elif ('payload' in kwargs and
                      isinstance(kwargs['payload'], (str, bytes, array))):
                if self.s:
                    if isinstance(kwargs['payload'], (str, bytes)):
                        kwargs['payload'] = array('B', kwargs['payload'])
                    if kwargs['payload'][0] >> 4 == IPV4_VER:
                        self.payload = IP(kwargs['payload'],
                                          l7_ports = self._l7_ports)
                    elif kwargs['payload'][0] >> 4 == IPV6_VER:
                        self.payload = IP6(kwargs['payload'],
                                           l7_ports = self._l7_ports)
                    else:
                        self.payload = Ethernet(kwargs['payload'],
                                                l7_ports = self._l7_ports)
                else:
                    self.payload = MPLS(kwargs['payload'],
                                        l7_ports = self._l7_ports)
            else:
                self.payload = NullPkt(b'')

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields MPLS supports and MPLS's
        PKT type ID.

        Returns:
            :tuple: PQTYPES.t_mpls and a tuple of the supported field names.
        """
        return (PQ_MPLS,
                ('mpls.bottom.label', 'mpls.bottom.tc',
                 'mpls.bottom.stack_bit', 'mpls.bottom.ttl',
                 'mpls.top.label', 'mpls.top.tc',
                 'mpls.top.stack_bit', 'mpls.top.ttl'))

    cpdef get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch. This function is
        different from other protocols in that it detects if this is or is not
        the botton of stack MPLS label.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns: 
            :object: value of the field.
        """
        if field.find('.bottom.') >= 0 and self.s:
            if field == 'mpls.bottom.label':
                return self.label
            elif field == 'mpls.bottom.tc':
                return self.tc
            elif field == 'mpls.bottom.stack_bit':
                return self.s
            elif field == 'mpls.bottom.ttl':
                return self.ttl
            else:
                return None
        elif field.find('.top.') >= 0 and not self.s:
            if field == 'mpls.top.label':
                return self.label
            elif field == 'mpls.top.tc':
                return self.tc
            elif field == 'mpls.top.stack_bit':
                return self.s
            elif field == 'mpls.top.ttl':
                return self.ttl
            else:
                return None
        else:
            return self.payload.get_field_val(field)

    property label:
        """ The label value. """
        def __get__(self):
            """ Return the label value. """
            return self._data >> 12
        def __set__(self, uint32_t val):
            """ Set the label value. """
            if val <= 0xfffff:
                self._data = (self._data & ~(0xfffff << 12)) | (val << 12)
            else:
                raise ValueError("label valid values are 0-1048575")

    property tc:
        """ The Traffic Class. """
        def __get__(self):
            """ Return the traffic class value. """
            return (self._data >> 9) & 0b111
        def __set__(self, unsigned char val):
            """ Set the traffic class value. """
            if val <= 0b111:
                self._data = (self._data & ~(0b111 << 9)) | (val << 9)
            else:
                raise ValueError("MPLS TC valid values are 0-7")

    property s:
        """ Set or get the stack bit. """
        def __get__(self):
            """ Return the stack bit. """
            return (self._data >> 8) & 1
        def __set__(self, unsigned char val):
            """ Set the stack bit. """
            if val == 1:
                set_word_bit(&self._data, 8)
            elif val == 0:
                unset_word_bit(&self._data, 8)
            else:
                raise ValueError("Bottom of stack bit must be 0 or 1")

    property ttl:
        """ Set or get ttl value. """
        def __get__(self):
            """ Return the TTL. """
            return self._data & 0xff
        def __set__(self, unsigned char val):
            """ Set the TTL. """
            self._data = (self._data & ~0xff) | val


    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a MPLS packet class instance in network order 
        for writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by MPLS to payload classes. MPLS has no options
                that it directly supports.

        Returns: 
            :bytes: network order byte string representation of this MPLS 
                instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this MPLS label and its payload to a shared buffer.

        MPLS has no length or checksum of its own, so this is a straight
        append -- but a stacked label used to copy everything under it once
        per label on the way back up. See PKT._write.
        """
        w_u32(w, self._data)
        if isinstance(self.payload, PKT):
            (<PKT>self.payload)._write(w, kwargs)
        return 0


cdef inline void _need_range(Py_ssize_t start, Py_ssize_t end,
                             Py_ssize_t least, str name) except *:
    cdef Py_ssize_t available = end - start
    if start < 0 or available < least:
        if available < 0:
            available = 0
        raise ValueError('%s: truncated packet, need at least %d bytes, '
                         'got %d' % (name, least, available))


cdef inline Py_ssize_t _declared_end(Py_ssize_t start, Py_ssize_t end,
                                     Py_ssize_t declared,
                                     Py_ssize_t header_len,
                                     str name) except -1:
    """Return where a layer ends according to its own length field.

    A layer is handed the range its parent had left over, which is not the
    same thing as the length the layer's own header declares. Every Ethernet
    NIC pads a frame out to 60 bytes and a capture can carry a trailer, so
    for short packets the leftover range routinely runs past the end of the
    real IP datagram or UDP datagram. Parsing all of it treats padding as
    payload: an inflated ``udp.payload``, a layer 7 parser handed bytes that
    were never sent, and lengths that no longer agree with the wire.

    Only shrinking is done here. A capture truncated by snaplen has a length
    field larger than the bytes present, and reading such a file has to stay
    possible, so a declared length past ``end`` is ignored rather than
    treated as an error -- the individual header reads below still bound
    themselves with _need_range.

    A declared length of zero means "not stated": that is what every packet
    built from keyword arguments and serialized without ``update`` carries,
    and for IPv6 it is also how a jumbogram is signalled.

    :param start: first byte of this layer.
    :param end: one past the last byte the parent left for this layer.
    :param declared: the value of this layer's length field, counted from
        ``start``.
    :param header_len: size of the header the length field must at minimum
        account for.
    :param name: layer name, used in the error message.
    :return: the end offset to parse to.
    """
    cdef Py_ssize_t declared_end
    if declared <= 0:
        return end
    if declared < header_len:
        raise ValueError('%s: length field says %d bytes, less than the %d '
                         'byte header it has to cover'
                         % (name, declared, header_len))
    declared_end = start + declared
    if declared_end < end:
        return declared_end
    return end


# --- Routing protocols: malformed-input contract ----------------------------
# The routing-protocol codecs added below (GRE now; OSPF, BGP, RIP and HSRP in
# later stages) follow a strict never-raise contract that is deliberately
# stronger than the raise-on-truncation behaviour of need_bytes/_need_range
# used by the older layers:
#
#   1. Truncated input (fewer bytes than a fixed header or a declared length)
#      is parsed as far as it goes. The codec sets its readonly ``malformed``
#      flag and preserves every remaining byte as a trailing NullPkt so the
#      packet still re-serializes to what came in. It does NOT raise.
#   2. Unknown or reserved codes (ethertypes, flag combinations, versions) are
#      kept as-is and remain round-trippable rather than becoming parse errors.
#   3. Invalid field values (reserved bits, checksum mismatches) are exposed
#      verbatim; validation is the caller's job.
#   4. The zero-exception rule: parsing never raises on malformed input. Only
#      MemoryError-class system failures may propagate. This matches the master
#      plan (IMPORTANT-1) and Answers 6 and 7, which require GRE-in-UDP and
#      IPsec-wrapped payloads to parse without raising.
#
# The soft-bounds helper below is what keeps these codecs off the raising path:
# it reports whether a range holds a given number of bytes instead of raising
# when it does not. Existing protocols and their raising helpers are unchanged.


cdef inline bint _have_range(Py_ssize_t start, Py_ssize_t end,
                             Py_ssize_t least):
    """Soft bounds check for the never-raise routing codecs.

    The routing analogue of _need_range: it returns whether at least ``least``
    bytes are available in ``[start, end)`` rather than raising when they are
    not, so a codec can stop cleanly on a short header, flag itself malformed,
    and preserve the remainder instead of aborting the whole parse.

    :param start: first readable offset.
    :param end: one past the last readable offset.
    :param least: minimum number of bytes the caller is about to read.
    :return: 1 when the bytes are present, 0 otherwise.
    """
    return start >= 0 and (end - start) >= least


@cython.final
cdef class GRE(PKT):
    """GRE (RFC 2784) with the key/sequence extensions (RFC 2890), PPTP
    enhanced GRE (RFC 2637), NVGRE (RFC 7637) and Transparent Ethernet
    Bridging.

    One class covers every variant because they differ only in which optional
    header words are present, and the flag bits in the first two bytes decide
    that:

      C -> a 16-bit checksum and 16 bits of reserved1 follow the base header.
      K -> a 32-bit key follows. NVGRE reuses it as a 24-bit Virtual Subnet Id
           and an 8-bit FlowID, exposed as gre.key.vsid / gre.key.flowid.
      S -> a 32-bit sequence number follows.
      A -> (enhanced GRE, Ver == 1) a 32-bit acknowledgment number follows.

    The 16-bit Protocol Type selects the inner payload the way an EtherType
    does: 0x0800 -> IP, 0x86DD -> IP6, 0x8847/0x8848 -> MPLS, 0x6558 ->
    Ethernet (TEB / NVGRE). Anything else is kept as a NullPkt so an unknown
    protocol still re-serializes to the bytes it came from.

    Parsing follows the routing never-raise contract documented above: a
    truncated header sets ``malformed`` and keeps the remainder as a trailing
    NullPkt rather than raising. The checksum is recomputed only when
    pkt2net is called with ``csum`` set, like the other checksummed layers.
    """

    def __init__(self, *args, **kwargs):
        """Initialize a GRE object.

        Args:
            :args (list): optional one-element list of network-order bytes.
            :data (bytes): optional network-order bytes of a GRE packet.
            :proto (uint16_t): inner protocol type (EtherType). Derived from
                the payload class on serialization when a known PKT payload is
                set.
            :checksum (uint16_t): header/payload checksum. Supplying it sets
                the C bit; the value is recomputed on pkt2net({'csum': 1}).
            :reserved1 (uint16_t): the 16 bits following the checksum.
            :key (uint32_t): 32-bit key. Supplying it sets the K bit.
            :vsid (uint32_t) / :flowid (unsigned char): NVGRE key parts, an
                alternative to key; supplying either sets the K bit.
            :sequence_number (uint32_t): sequence number. Supplying it sets S.
            :ack_number (uint32_t): enhanced-GRE acknowledgment number.
                Supplying it sets the A bit; use version=1 for enhanced GRE.
            :version (unsigned char): 3-bit version. 0 standard, 1 enhanced.
            :c/:k/:s/:a (0 or 1): force a flag bit on with no field value so a
                reserved-but-empty option still round-trips.
            :payload (PKT or bytes): the encapsulated packet.
            :l7_ports (dict): passed on to inner layers unchanged.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'GRE'
        self.pq_type, self.query_fields = _QI_GRE
        cdef:
            bytes owner
            const unsigned char[:] mv
            uint16_t flags = 0
        owner = _owned_buffer(args, kwargs)
        if owner is not None:
            mv = owner
            _decode_gre(self, owner, mv, 0, len(owner), self._l7_ports)
            return

        # Keyword construction.
        self._raw = None
        self.malformed = 0
        self.checksum = kwargs.get('checksum', 0)
        self._reserved1 = kwargs.get('reserved1', 0)
        self.sequence = kwargs.get('sequence_number', 0)
        self.ack = kwargs.get('ack_number', 0)
        if 'key' in kwargs:
            self.key = kwargs['key']
        elif 'vsid' in kwargs or 'flowid' in kwargs:
            self.key = (((<uint32_t>kwargs.get('vsid', 0) & 0xffffff) << 8) |
                        (<uint32_t>kwargs.get('flowid', 0) & 0xff))
        else:
            self.key = 0
        self.vsid = self.key >> 8
        self.flowid = self.key & 0xff

        # Flag/version word. Presence is inferred from the fields supplied and
        # can be forced with the c/k/s/a keywords.
        flags |= (<uint16_t>kwargs.get('version', 0) & 0x0007)
        if kwargs.get('c', 1 if 'checksum' in kwargs else 0):
            flags |= 0x8000
        if kwargs.get('k', 1 if ('key' in kwargs or 'vsid' in kwargs or
                                 'flowid' in kwargs) else 0):
            flags |= 0x2000
        if kwargs.get('s', 1 if 'sequence_number' in kwargs else 0):
            flags |= 0x1000
        if kwargs.get('a', 1 if 'ack_number' in kwargs else 0):
            flags |= 0x0080
        self._flags = flags

        if 'payload' in kwargs and isinstance(kwargs['payload'], PKT):
            self.payload = kwargs['payload']
        elif ('payload' in kwargs and
              isinstance(kwargs['payload'], (str, bytes, array))):
            self.payload = NullPkt(kwargs['payload'])
        else:
            self.payload = NullPkt(b'')

        # Settle the protocol type from a known payload so a keyword-built
        # packet reports gre.proto before it is ever serialized.
        if 'proto' in kwargs:
            self.proto = kwargs['proto']
        elif isinstance(self.payload, IP):
            self.proto = 0x0800
        elif isinstance(self.payload, IP6):
            self.proto = 0x86dd
        elif isinstance(self.payload, MPLS):
            self.proto = 0x8847
        elif isinstance(self.payload, Ethernet):
            self.proto = 0x6558
        else:
            self.proto = 0

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields GRE supports and GRE's
        PKT type ID.

        The field names are Wireshark packet-gre.c abbreviations. The NVGRE
        key parts render as gre.key.vsid (24-bit) and gre.key.flowid (8-bit).

        Returns:
            :tuple: PQ_GRE and a tuple of the supported field names.
        """
        return (PQ_GRE,
                ('gre.proto', 'gre.checksum', 'gre.key',
                 'gre.key.vsid', 'gre.key.flowid',
                 'gre.sequence_number', 'gre.ack_number',
                 'gre.flags.k', 'gre.flags.s', 'gre.flags.c'))

    cpdef object get_field_val(self, str field):
        """Return the value of a Wireshark-format field name.

        Optional fields report None when their presence bit is clear, so a
        caller can tell an absent key or sequence number from a zero one.
        Unrecognized names fall through to the payload, matching the other
        container layers.
        """
        if field == 'gre.proto':
            return self.proto
        elif field == 'gre.checksum':
            return self.checksum if (self._flags & 0x8000) else None
        elif field == 'gre.key':
            return self.key if (self._flags & 0x2000) else None
        elif field == 'gre.key.vsid':
            return self.vsid if (self._flags & 0x2000) else None
        elif field == 'gre.key.flowid':
            return self.flowid if (self._flags & 0x2000) else None
        elif field == 'gre.sequence_number':
            return self.sequence if (self._flags & 0x1000) else None
        elif field == 'gre.ack_number':
            if (self._flags & 0x0007) == 1 and (self._flags & 0x0080):
                return self.ack
            return None
        elif field == 'gre.flags.k':
            return 1 if (self._flags & 0x2000) else 0
        elif field == 'gre.flags.s':
            return 1 if (self._flags & 0x1000) else 0
        elif field == 'gre.flags.c':
            return 1 if (self._flags & 0x8000) else 0
        elif isinstance(self.payload, PKT):
            return self.payload.get_field_val(field)
        else:
            return None

    property version:
        """The 3-bit GRE version. 0 for standard GRE, 1 for enhanced GRE."""
        def __get__(self):
            return self._flags & 0x0007
        def __set__(self, unsigned char val):
            self._flags = (self._flags & ~0x0007) | (val & 0x0007)

    property flag_c:
        """Checksum-present bit."""
        def __get__(self):
            return 1 if (self._flags & 0x8000) else 0

    property flag_k:
        """Key-present bit."""
        def __get__(self):
            return 1 if (self._flags & 0x2000) else 0

    property flag_s:
        """Sequence-number-present bit."""
        def __get__(self):
            return 1 if (self._flags & 0x1000) else 0

    property flag_a:
        """Acknowledgment-present bit (enhanced GRE)."""
        def __get__(self):
            return 1 if (self._flags & 0x0080) else 0

    cpdef bytes pkt2net(self, dict kwargs):
        """Export this GRE packet in network order.

        Args:
            :kwargs (dict): passed on to the payload. GRE reads ``csum``: when
                set and the C bit is present, the checksum is recomputed over
                the GRE header and everything it carries.

        Returns:
            :bytes: network-order bytes for this GRE packet and its payload.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this GRE header and its payload to a shared buffer.

        The protocol type is settled from the payload class first, mirroring
        Ethernet, so a keyword-built packet whose payload was assigned after
        construction still serializes with a matching EtherType. Only the
        optional words whose flag bits are set are emitted, and the checksum --
        when present and requested -- is written as a placeholder, the payload
        is appended, and the real value is patched back in. See PKT._write.
        """
        cdef:
            bint _csum
            Py_ssize_t start = w.n

        # A malformed packet keeps its exact parsed bytes and emits them
        # verbatim: the truncated option words were never decoded, so the
        # header cannot be faithfully rebuilt from the flag bits.
        if self.malformed and self._raw is not None:
            w_bytes(w, self._raw)
            return 0

        _csum = kwargs.get('csum', 0)
        if isinstance(self.payload, IP):
            self.proto = 0x0800
        elif isinstance(self.payload, IP6):
            self.proto = 0x86dd
        elif isinstance(self.payload, MPLS):
            if self.proto not in (0x8847, 0x8848):
                self.proto = 0x8847
        elif isinstance(self.payload, Ethernet):
            self.proto = 0x6558

        w_u16(w, self._flags)
        w_u16(w, self.proto)
        if self._flags & 0x8000:
            w_u16(w, self.checksum)
            w_u16(w, self._reserved1)
        if self._flags & 0x2000:
            w_u32(w, self.key)
        if self._flags & 0x1000:
            w_u32(w, self.sequence)
        if (self._flags & 0x0007) == 1 and (self._flags & 0x0080):
            w_u32(w, self.ack)

        if isinstance(self.payload, PKT):
            (<PKT>self.payload)._write(w, kwargs)

        if _csum and (self._flags & 0x8000):
            w_set_u16(w, start + 4, 0)
            self.checksum = w_cksum(w, start, 0)
            w_set_u16(w, start + 4, self.checksum)
        return 0


cdef int _decode_gre(GRE pkt, bytes owner, const unsigned char[:] mv,
                     Py_ssize_t start, Py_ssize_t end,
                     dict l7_ports) except -1:
    cdef:
        Py_ssize_t off = start
        uint16_t ethertype
        IP ip
        IP6 ip6
        MPLS mpls
        Ethernet eth
    pkt.malformed = 0
    pkt._raw = None
    pkt._flags = 0
    pkt.proto = 0
    pkt.checksum = 0
    pkt._reserved1 = 0
    pkt.key = 0
    pkt.vsid = 0
    pkt.flowid = 0
    pkt.sequence = 0
    pkt.ack = 0

    # Base header: a 2-byte flag/version word and a 2-byte protocol type.
    if not _have_range(off, end, 4):
        pkt.malformed = 1
        pkt._raw = rd_bytes(mv, start, end)
        pkt.payload = _null_range(owner, off, end, l7_ports)
        return 0
    pkt._flags = rd_u16(mv, off)
    pkt.proto = rd_u16(mv, off + 2)
    off += 4

    # Checksum + reserved1, present when the C bit is set (RFC 2784).
    if pkt._flags & 0x8000:
        if not _have_range(off, end, 4):
            pkt.malformed = 1
            pkt._raw = rd_bytes(mv, start, end)
            pkt.payload = _null_range(owner, off, end, l7_ports)
            return 0
        pkt.checksum = rd_u16(mv, off)
        pkt._reserved1 = rd_u16(mv, off + 2)
        off += 4  # C word consumed

    # Key, present when the K bit is set (RFC 2890). NVGRE (RFC 7637) reads the
    # same 32 bits as a 24-bit VSID and an 8-bit FlowID.
    if pkt._flags & 0x2000:
        if not _have_range(off, end, 4):
            pkt.malformed = 1
            pkt._raw = rd_bytes(mv, start, end)
            pkt.payload = _null_range(owner, off, end, l7_ports)
            return 0
        pkt.key = rd_u32(mv, off)
        pkt.vsid = pkt.key >> 8
        pkt.flowid = pkt.key & 0xff
        off += 4

    # Sequence number, present when the S bit is set (RFC 2890).
    if pkt._flags & 0x1000:
        if not _have_range(off, end, 4):
            pkt.malformed = 1
            pkt._raw = rd_bytes(mv, start, end)
            pkt.payload = _null_range(owner, off, end, l7_ports)
            return 0
        pkt.sequence = rd_u32(mv, off)
        off += 4

    # Acknowledgment number, present in enhanced GRE (RFC 2637, Ver == 1) when
    # the A bit is set.
    if (pkt._flags & 0x0007) == 1 and (pkt._flags & 0x0080):
        if not _have_range(off, end, 4):
            pkt.malformed = 1
            pkt._raw = rd_bytes(mv, start, end)
            pkt.payload = _null_range(owner, off, end, l7_ports)
            return 0
        pkt.ack = rd_u32(mv, off)
        off += 4

    if off >= end:
        pkt.payload = NullPkt()
        return 0

    # Inner payload dispatch by protocol type (EtherType). The inner decoders
    # still use the raising bounds helpers, so the dispatch is wrapped: a
    # truncated or otherwise unparsable inner payload marks GRE malformed and
    # is kept whole as a NullPkt instead of propagating an exception, which is
    # what the routing never-raise contract requires.
    ethertype = pkt.proto
    try:
        if ethertype == 0x0800:
            ip = IP.__new__(IP)
            ip._l7_ports = l7_ports
            ip.pkt_name = 'IP'
            ip.pq_type, ip.query_fields = _QI_IP
            _decode_ip(ip, owner, mv, off, end, l7_ports)
            pkt.payload = ip
        elif ethertype == 0x86dd:
            ip6 = IP6.__new__(IP6)
            ip6._l7_ports = l7_ports
            ip6.pkt_name = 'IP6'
            ip6.pq_type, ip6.query_fields = _QI_IP6
            _decode_ip6(ip6, owner, mv, off, end, l7_ports)
            pkt.payload = ip6
        elif ethertype == 0x8847 or ethertype == 0x8848:
            mpls = MPLS.__new__(MPLS)
            mpls._l7_ports = l7_ports
            mpls.pkt_name = 'MPLS'
            mpls.pq_type, mpls.query_fields = _QI_MPLS
            _decode_mpls(mpls, owner, mv, off, end, l7_ports)
            pkt.payload = mpls
        elif ethertype == 0x6558:
            eth = Ethernet.__new__(Ethernet)
            eth._l7_ports = l7_ports
            eth.pkt_name = 'Ethernet'
            eth.pq_type, eth.query_fields = _QI_ETH
            eth.tpid = 0
            eth._tci = 0
            _decode_ethernet(eth, owner, mv, off, end, l7_ports)
            pkt.payload = eth
        else:
            pkt.payload = _null_range(owner, off, end, l7_ports)
    except (ValueError, IndexError):
        pkt.malformed = 1
        pkt._raw = rd_bytes(mv, start, end)
        pkt.payload = _null_range(owner, off, end, l7_ports)
    return 0


cdef bytes _owned_buffer(tuple args, dict kwargs):
    """Return the public parse input as one immutable owner, or None."""
    cdef object value
    if len(args) == 1:
        value = args[0]
        if isinstance(value, bytes):
            return value
        if isinstance(value, array):
            return (<array>value).tobytes()
    if 'data' in kwargs:
        value = kwargs['data']
        if isinstance(value, bytes):
            return value
        if isinstance(value, array):
            return (<array>value).tobytes()
    return None


cdef int _decode_arp(ARP pkt, bytes owner, Py_ssize_t start,
                     Py_ssize_t end) except -1:
    cdef:
        const unsigned char[:] mv = owner
        Py_ssize_t s_proto_start, t_hw_start, t_proto_start, t_proto_end
    _need_range(start, end, 8, 'ARP')
    pkt.hardware_type = rd_u16(mv, start)
    pkt.proto_type = rd_u16(mv, start + 2)
    pkt.hardware_len = mv[start + 4]
    pkt.proto_len = mv[start + 5]
    pkt.operation = rd_u16(mv, start + 6)
    if (pkt.hardware_type == ARP_TYPE_ETH and
            pkt.proto_type == ETH_TYPE_IPV4 and
            pkt.hardware_len == MAC_LEN and
            pkt.proto_len == IPV4_LEN):
        _need_range(start, end, 28, 'ARP')
        pkt._sender_hw_addr = _mac_from_buf(&mv[start + 8])
        pkt.sender_proto_addr = _fmt_ipv4(rd_bytes(mv, start + 14,
                                                   start + 18))
        pkt._target_hw_addr = _mac_from_buf(&mv[start + 18])
        pkt.target_proto_addr = _fmt_ipv4(rd_bytes(mv, start + 24,
                                                   start + 28))
    else:
        s_proto_start = start + 8 + pkt.hardware_len
        t_hw_start = s_proto_start + pkt.proto_len
        t_proto_start = t_hw_start + pkt.hardware_len
        t_proto_end = t_proto_start + pkt.proto_len
        _need_range(start, end, t_proto_end - start, 'ARP')
        pkt._raw = rd_bytes(mv, start, end)
        pkt._sender_hw_addr = array('B', rd_bytes(mv, start + 8,
                                                  s_proto_start))
        pkt.sender_proto_addr = ''.join(
            '%02x' % i for i in mv[s_proto_start:t_hw_start])
        pkt._target_hw_addr = array('B', rd_bytes(mv, t_hw_start,
                                                  t_proto_start))
        pkt.target_proto_addr = ''.join(
            '%02x' % i for i in mv[t_proto_start:t_proto_end])
    return 0


cdef int _decode_netflow_simple(NetflowSimple pkt, bytes owner,
                                Py_ssize_t start,
                                Py_ssize_t end) except -1:
    cdef const unsigned char[:] mv = owner
    _need_range(start, end, 16, 'NetflowSimple')
    pkt.version = rd_u16(mv, start)
    pkt.count = rd_u16(mv, start + 2)
    pkt.sys_uptime = rd_u32(mv, start + 4)
    pkt.unix_secs = rd_u32(mv, start + 8)
    pkt.unix_nano_seconds = rd_u32(mv, start + 12)
    if end - start > 16:
        pkt.payload = rd_bytes(mv, start + 16, end)
    else:
        pkt.payload = b''
    return 0


cdef int _decode_icmp(ICMP pkt, bytes owner, Py_ssize_t start,
                      Py_ssize_t end) except -1:
    cdef:
        const unsigned char[:] mv = owner
        IP ip
    pkt.identifier = 0
    pkt.sequence = 0
    pkt.mtu = 0
    pkt.pointer = 0
    pkt.orig_ts = 0
    pkt.rec_ts = 0
    pkt.trans_ts = 0
    pkt.hdr_pkt = NullPkt()
    pkt.data = array('B')
    pkt.echo_data = b''
    pkt._address = b'\x00\x00\x00\x00'
    pkt.have_data = 0
    pkt._raw = None
    _need_range(start, end, 4, 'ICMP')
    pkt.type = mv[start]
    pkt.code = mv[start + 1]
    pkt.checksum = rd_u16(mv, start + 2)
    if pkt.type in (ICMP_TYPE_ECHO_REPLY, ICMP_TYPE_ECHO,
                    ICMP_TYPE_INFO, ICMP_TYPE_INFO_REPLY):
        _need_range(start, end, 8, 'ICMP')
        pkt.identifier = rd_u16(mv, start + 4)
        pkt.sequence = rd_u16(mv, start + 6)
        pkt.echo_data = rd_bytes(mv, start + 8, end)
    elif pkt.type in (ICMP_TYPE_DU, ICMP_TYPE_SRC_QUENCH,
                      ICMP_TYPE_REDIR, ICMP_TYPE_TIME_EX,
                      ICMP_TYPE_PER_PROB):
        if pkt.type in (ICMP_TYPE_DU, ICMP_TYPE_REDIR,
                        ICMP_TYPE_PER_PROB):
            _need_range(start, end, 8, 'ICMP')
        if pkt.type == ICMP_TYPE_DU:
            pkt.mtu = rd_u16(mv, start + 6)
        elif pkt.type == ICMP_TYPE_REDIR:
            pkt._address = rd_bytes(mv, start + 4, start + 8)
        elif pkt.type == ICMP_TYPE_PER_PROB:
            pkt.pointer = mv[start + 4]
        ip = IP.__new__(IP)
        ip._l7_ports = None
        ip.pkt_name = 'IP'
        ip.pq_type, ip.query_fields = _QI_IP
        _decode_ip(ip, owner, mv, start + 8, end, ip._l7_ports)
        pkt.hdr_pkt = ip
    elif pkt.type in (ICMP_TYPE_TS, ICMP_TYPE_TS_REPLY):
        _need_range(start, end, 20, 'ICMP')
        pkt.identifier = rd_u16(mv, start + 4)
        pkt.sequence = rd_u16(mv, start + 6)
        pkt.orig_ts = rd_u32(mv, start + 8)
        pkt.rec_ts = rd_u32(mv, start + 12)
        pkt.trans_ts = rd_u32(mv, start + 16)
    else:
        pkt.have_data = 1
        pkt._raw = rd_bytes(mv, start, end)
    return 0


cdef int _decode_igmp_group_record(IGMPGroupRecord pkt, bytes owner,
                                   Py_ssize_t start,
                                   Py_ssize_t end) except -1:
    cdef:
        const unsigned char[:] mv = owner
        Py_ssize_t src_end, aux_len
    pkt._source_addresses = pkt._group_address = pkt.aux_data = b''
    _need_range(start, end, 8, 'IGMPGroupRecord')
    pkt.type = mv[start]
    pkt.aux_data_len = mv[start + 1]
    pkt.num_src = rd_u16(mv, start + 2)
    pkt._group_address = rd_bytes(mv, start + 4, start + 8)
    src_end = start + 8 + (4 * <Py_ssize_t>pkt.num_src)
    if pkt.num_src:
        _need_range(start, end, src_end - start, 'IGMPGroupRecord')
        pkt._source_addresses = rd_bytes(mv, start + 8, src_end)
    if pkt.aux_data_len:
        # RFC 3376 4.2.6 counts the auxiliary data in 32 bit words, the same
        # as MLDv2 below. Reading it as bytes both truncated aux_data and,
        # because IGMP advances by byte_len, moved the next record's start.
        aux_len = 4 * <Py_ssize_t>pkt.aux_data_len
        # rd_bytes clamps to the owner buffer, not to this record's end, so
        # without a range check a record claiming aux data it does not have
        # silently read the bytes of whatever followed it in the frame.
        _need_range(start, end, src_end + aux_len - start,
                    'IGMPGroupRecord')
        pkt.aux_data = rd_bytes(mv, src_end, src_end + aux_len)
    return 0


cdef int _decode_igmp(IGMP pkt, bytes owner, Py_ssize_t start,
                      Py_ssize_t end, object packet_len_arg) except -1:
    cdef:
        const unsigned char[:] mv = owner
        unsigned char operation, version = 0
        uint16_t i, packet_len
        Py_ssize_t offset
        IGMPGroupRecord rec
    _need_range(start, end, 8, 'IGMP')
    pkt.type = mv[start]
    pkt.max_resp = mv[start + 1]
    pkt.checksum = rd_u16(mv, start + 2)
    if pkt.type != IGMP_V3_MEMBER_REPORT:
        pkt._group_address = rd_bytes(mv, start + 4, start + 8)
    pkt._source_addresses = b''
    pkt.version = 0
    operation = pkt.type
    # Preserve the constructor's conversion point: malformed short data is
    # rejected above before an invalid Python length is converted to uint16.
    packet_len = packet_len_arg
    if packet_len:
        if packet_len > 8:
            version = 3
        elif operation == IGMP_MEMBER_QUERY:
            if mv[start + 1] == 0:
                version = 1
            else:
                version = 2
        elif operation == IGMP_V1_MEMBER_REPORT:
            version = 1
        else:
            version = 2
    elif operation == IGMP_MEMBER_QUERY:
        if end - start >= 11 and mv[start + 9] != 0:
            version = 3
        elif mv[start + 1] == 0:
            version = 1
        else:
            version = 2
    elif operation in (IGMP_V2_MEMBER_REPORT, IGMP_LEAVE_GROUP):
        version = 2
    elif operation == IGMP_V3_MEMBER_REPORT:
        version = 3
    else:
        version = 1
    if not version:
        raise ValueError("Data passed into IGMP __init__ does not look like "
                         "an IGMP packet. Data was: {}".format(
                             rd_bytes(mv, start, end)))
    pkt.version = version
    if version in (1, 2):
        if version == 1:
            pkt.max_resp = pkt.reserved1 = 0
        return 0
    if operation == IGMP_MEMBER_QUERY:
        _need_range(start, end, 12, 'IGMP')
        pkt._s_qrv = mv[start + 8]
        pkt.qqic = mv[start + 9]
        pkt.num_records = rd_u16(mv, start + 10)
        if pkt.num_records:
            _need_range(start, end, 12 + 4 * pkt.num_records, 'IGMP')
            pkt._source_addresses = rd_bytes(
                mv, start + 12, start + 12 + 4 * pkt.num_records)
    else:
        pkt.max_resp = pkt.reserved1 = pkt.reserved2 = 0
        pkt.num_records = rd_u16(mv, start + 6)
        offset = start + 8
        for i in range(pkt.num_records):
            rec = IGMPGroupRecord.__new__(IGMPGroupRecord)
            rec._l7_ports = None
            rec.pkt_name = 'IGMPGroupRecord'
            rec.pq_type, rec.query_fields = _QI_IGMPGroupRecord
            _decode_igmp_group_record(rec, owner, offset, end)
            pkt.group_records.append(rec)
            offset += rec.byte_len
    return 0


cdef int _decode_icmp6_opt(ICMP6Opt pkt, bytes owner, Py_ssize_t start,
                           Py_ssize_t end) except -1:
    cdef:
        const unsigned char[:] mv = owner
        Py_ssize_t total
    _need_range(start, end, 2, 'ICMP6Opt')
    pkt.type = mv[start]
    pkt.length = mv[start + 1]
    total = (<Py_ssize_t>pkt.length) * 8
    if total:
        _need_range(start, end, total, 'ICMP6Opt')
        pkt._data = rd_bytes(mv, start + 2, start + total)
    return 0


cdef int _decode_mldv2_address_record(MLDv2AddressRecord pkt, bytes owner,
                                      Py_ssize_t start,
                                      Py_ssize_t end) except -1:
    cdef:
        const unsigned char[:] mv = owner
        Py_ssize_t src_end, aux_len
    pkt._multicast_address = _V6_ANY
    pkt._source_addresses = pkt.aux_data = b''
    _need_range(start, end, 20, 'MLDv2AddressRecord')
    pkt.type = mv[start]
    pkt.aux_data_len = mv[start + 1]
    pkt.num_src = rd_u16(mv, start + 2)
    pkt._multicast_address = rd_bytes(mv, start + 4, start + 20)
    src_end = start + 20 + (16 * <Py_ssize_t>pkt.num_src)
    if pkt.num_src:
        _need_range(start, end, src_end - start, 'MLDv2AddressRecord')
        pkt._source_addresses = rd_bytes(mv, start + 20, src_end)
    if pkt.aux_data_len:
        aux_len = 4 * <Py_ssize_t>pkt.aux_data_len
        _need_range(start, end, src_end + aux_len - start,
                    'MLDv2AddressRecord')
        pkt.aux_data = rd_bytes(mv, src_end, src_end + aux_len)
    return 0


cdef int _decode_icmp6(ICMP6 pkt, bytes owner, Py_ssize_t start,
                       Py_ssize_t end) except -1:
    cdef:
        const unsigned char[:] mv = owner
        uint16_t i
        Py_ssize_t offset, src_end
        MLDv2AddressRecord rec
        IP6 ip6
    pkt.echo_data = b''
    pkt._body = b''
    pkt.hdr_pkt = NullPkt()
    pkt.options = list()
    pkt.records = list()
    pkt._target_address = _V6_ANY
    pkt._dest_address = _V6_ANY
    pkt._multicast_address = _V6_ANY
    pkt._source_addresses = b''
    _need_range(start, end, 4, 'ICMP6')
    pkt.type = mv[start]
    pkt.code = mv[start + 1]
    pkt.checksum = rd_u16(mv, start + 2)
    if pkt.type in (ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY):
        _need_range(start, end, 8, 'ICMP6')
        pkt.identifier = rd_u16(mv, start + 4)
        pkt.sequence = rd_u16(mv, start + 6)
        pkt.echo_data = rd_bytes(mv, start + 8, end)
    elif pkt.type in (ICMP6_DST_UNREACH, ICMP6_PKT_TOO_BIG,
                      ICMP6_TIME_EXCEEDED, ICMP6_PARAM_PROB):
        _need_range(start, end, 8, 'ICMP6')
        pkt._err_word = rd_u32(mv, start + 4)
        if start + 8 < end:
            try:
                ip6 = IP6.__new__(IP6)
                ip6._l7_ports = None
                ip6.pkt_name = 'IP6'
                ip6.pq_type, ip6.query_fields = _QI_IP6
                _decode_ip6(ip6, owner, mv, start + 8, end, ip6._l7_ports)
                pkt.hdr_pkt = ip6
            except ValueError:
                pkt.hdr_pkt = _null_range(owner, start + 8, end, {})
    elif pkt.type in (ICMP6_MLD_QUERY, ICMP6_MLD_REPORT, ICMP6_MLD_DONE):
        _need_range(start, end, 24, 'ICMP6')
        pkt.mld_version = 1
        pkt.max_resp = rd_u16(mv, start + 4)
        pkt._multicast_address = rd_bytes(mv, start + 8, start + 24)
        if pkt.type == ICMP6_MLD_QUERY and end - start > 24:
            _need_range(start, end, 28, 'ICMP6')
            pkt.mld_version = 2
            pkt._s_qrv = mv[start + 24]
            pkt.qqic = mv[start + 25]
            pkt.num_src = rd_u16(mv, start + 26)
            if pkt.num_src:
                src_end = start + 28 + (16 * <Py_ssize_t>pkt.num_src)
                _need_range(start, end, src_end - start, 'ICMP6')
                pkt._source_addresses = rd_bytes(mv, start + 28, src_end)
    elif pkt.type == ICMP6_MLDV2_REPORT:
        _need_range(start, end, 8, 'ICMP6')
        pkt.mld_version = 2
        pkt.num_records = rd_u16(mv, start + 6)
        offset = start + 8
        for i in range(pkt.num_records):
            rec = MLDv2AddressRecord.__new__(MLDv2AddressRecord)
            rec._l7_ports = None
            rec.pkt_name = 'MLDv2AddressRecord'
            rec.pq_type, rec.query_fields = _QI_MLDv2AddressRecord
            _decode_mldv2_address_record(rec, owner, offset, end)
            pkt.records.append(rec)
            offset += rec.byte_len
    elif pkt.type == ICMP6_ND_ROUTER_SOLICIT:
        _need_range(start, end, 8, 'ICMP6')
        pkt._parse_options(owner, start + 8, end)
    elif pkt.type == ICMP6_ND_ROUTER_ADVERT:
        _need_range(start, end, 16, 'ICMP6')
        pkt.cur_hop_limit = mv[start + 4]
        pkt._ra_flags = mv[start + 5]
        pkt.router_lifetime = rd_u16(mv, start + 6)
        pkt.reachable_time = rd_u32(mv, start + 8)
        pkt.retrans_timer = rd_u32(mv, start + 12)
        pkt._parse_options(owner, start + 16, end)
    elif pkt.type in (ICMP6_ND_NEIGHBOR_SOLICIT,
                      ICMP6_ND_NEIGHBOR_ADVERT):
        _need_range(start, end, 24, 'ICMP6')
        if pkt.type == ICMP6_ND_NEIGHBOR_ADVERT:
            pkt._na_flags = mv[start + 4]
        pkt._target_address = rd_bytes(mv, start + 8, start + 24)
        pkt._parse_options(owner, start + 24, end)
    elif pkt.type == ICMP6_ND_REDIRECT:
        _need_range(start, end, 40, 'ICMP6')
        pkt._target_address = rd_bytes(mv, start + 8, start + 24)
        pkt._dest_address = rd_bytes(mv, start + 24, start + 40)
        pkt._parse_options(owner, start + 40, end)
    else:
        pkt._body = rd_bytes(mv, start + 4, end)
    return 0


cdef inline int _decode_eth_ip_udp_fast(Ethernet pkt, bytes owner,
                                        const unsigned char[:] mv,
                                        Py_ssize_t end) except -1:
    cdef:
        Py_ssize_t ip_start = 14
        Py_ssize_t udp_start, datagram_end
        unsigned char iphl, hl_bytes
        IP ip
        UDP udp

    _need_range(0, end, 14, 'Ethernet')
    pkt._dst_mac = _mac_from_buf(&mv[0])
    pkt._src_mac = _mac_from_buf(&mv[6])
    pkt.type = rd_u16(mv, 12)
    if pkt.type == ETH_TYPE_8021Q:
        _need_range(0, end, 18, 'Ethernet')
        pkt.tpid = ETH_TYPE_8021Q
        pkt._tci = rd_u16(mv, 14)
        pkt.type = rd_u16(mv, 16)
        ip_start = 18

    _need_range(ip_start, end, 20, 'IP')
    ip = IP.__new__(IP)
    ip._l7_ports = pkt._l7_ports
    ip.pkt_name = 'IP'
    ip.pq_type, ip.query_fields = _QI_IP
    ip.ipv4_pheader = Ip4Ph()
    ip.options = b''
    ip._version_iphl = mv[ip_start]
    iphl = ip.iphl
    ip.tos = mv[ip_start + 1]
    ip.total_len = rd_u16(mv, ip_start + 2)
    ip.ident = rd_u16(mv, ip_start + 4)
    ip._flags_offset = rd_u16(mv, ip_start + 6)
    ip.ttl = mv[ip_start + 8]
    ip.proto = mv[ip_start + 9]
    ip.checksum = rd_u16(mv, ip_start + 10)
    ip.src_nochk = rd_bytes(mv, ip_start + 12, ip_start + 16)
    ip.dst_nochk = rd_bytes(mv, ip_start + 16, ip_start + 20)
    hl_bytes = iphl * 4
    _need_range(ip_start, end, hl_bytes, 'IP')
    udp_start = ip_start + hl_bytes
    if iphl > 5:
        ip.options = rd_bytes(mv, ip_start + 20, udp_start)
    # The same length clamps the general _decode_ip / _decode_udp path
    # applies. Ethernet pads every frame under 60 bytes, so without these a
    # short datagram taking this path would report padding as its payload,
    # and which path a frame took would change what it decoded to.
    datagram_end = _declared_end(ip_start, end, ip.total_len, hl_bytes, 'IP')
    if datagram_end < end:
        ip._trailer = rd_bytes(mv, datagram_end, end)
        end = datagram_end
    if udp_start >= end:
        ip.payload = PKT()
        pkt.payload = ip
        return 0

    _need_range(udp_start, end, 8, 'UDP')
    udp = UDP.__new__(UDP)
    udp._l7_ports = pkt._l7_ports
    udp.pkt_name = 'UDP'
    udp.pq_type, udp.query_fields = _QI_UDP
    udp.sport = rd_u16(mv, udp_start)
    udp.dport = rd_u16(mv, udp_start + 2)
    udp.ulen = rd_u16(mv, udp_start + 4)
    udp.checksum = rd_u16(mv, udp_start + 6)
    datagram_end = _declared_end(udp_start, end, udp.ulen, 8, 'UDP')
    if datagram_end < end:
        udp._trailer = rd_bytes(mv, datagram_end, end)
        end = datagram_end

    # The datagram body is handed on as an owner plus a range, which is what
    # _null_range does for the general path and what the whole owner/offset
    # design is for. Copying it here made this path allocate and memcpy the
    # entire payload of every packet in a capture -- the one thing the fast
    # path was supposed to avoid -- and left the two paths returning
    # NullPkts with different internal representations of the same bytes.
    udp.payload = _null_range(owner, udp_start + 8, end, None)
    ip.payload = udp
    pkt.payload = ip
    return 0


cdef inline NullPkt _null_range(bytes owner, Py_ssize_t start,
                                Py_ssize_t end, dict l7_ports):
    cdef NullPkt raw = NullPkt.__new__(NullPkt)
    raw._l7_ports = l7_ports
    raw.pkt_name = 'NullPkt'
    raw.pq_type, raw.query_fields = _QI_NULLPKT
    raw._payload = None
    raw._owner = owner
    raw._start = start
    raw._length = end - start
    return raw


cdef inline PKT _l7_range(bytes owner, const unsigned char[:] mv,
                           Py_ssize_t start, Py_ssize_t end, dict l7_ports,
                           uint16_t sport, uint16_t dport,
                           object decode_context, object exporter_source,
                           str transport):
    cdef:
        type pkt_cls = NullPkt
        NetflowSimple netflow
        object owner_factory, dispatcher, exporter
    if end > start and l7_ports:
        pkt_cls = _l7_pkt_cls(l7_ports, sport, dport)
    if pkt_cls is NullPkt:
        return _null_range(owner, start, end, l7_ports)
    if pkt_cls is NetflowSimple:
        netflow = NetflowSimple.__new__(NetflowSimple)
        netflow._l7_ports = l7_ports
        netflow.pkt_name = 'NetflowSimple'
        netflow.pq_type, netflow.query_fields = _QI_NETFLOW_SIMPLE
        _decode_netflow_simple(netflow, owner, start, end)
        return netflow
    owner_factory = getattr(pkt_cls, '_from_owner', None)
    if owner_factory is not None:
        return owner_factory(owner, start, end, l7_ports)
    dispatcher = getattr(pkt_cls, 'dispatch', None)
    if dispatcher is not None:
        if isinstance(exporter_source, tuple):
            exporter = exporter_source
        else:
            exporter = (exporter_source, sport, dport, transport)
        return dispatcher(rd_bytes(mv, start, end),
                          context=decode_context, exporter=exporter)
    # Configured layer-7 implementations have not opted into owner/range
    # parsing yet. Preserve their established independently-owned array input.
    return pkt_cls(array('B', rd_bytes(mv, start, end)))


cdef inline int _decode_udp(UDP pkt, bytes owner,
                            const unsigned char[:] mv, Py_ssize_t start,
                            Py_ssize_t end, dict l7_ports) except -1:
    cdef Py_ssize_t body_end
    _need_range(start, end, 8, 'UDP')
    pkt.sport = rd_u16(mv, start)
    pkt.dport = rd_u16(mv, start + 2)
    pkt.ulen = rd_u16(mv, start + 4)
    pkt.checksum = rd_u16(mv, start + 6)
    # ulen counts the header and the data behind it, so it is what says where
    # the datagram stops. Anything past it belongs to the frame, not to this
    # layer, and must not reach the layer 7 parser.
    body_end = _declared_end(start, end, pkt.ulen, 8, 'UDP')
    if body_end < end:
        pkt._trailer = rd_bytes(mv, body_end, end)
    pkt.payload = _l7_range(owner, mv, start + 8, body_end, l7_ports,
                            pkt.sport, pkt.dport, pkt._decode_context,
                            pkt._decode_exporter, 'udp')
    return 0


cdef inline int _decode_tcp(TCP pkt, bytes owner,
                            const unsigned char[:] mv, Py_ssize_t start,
                            Py_ssize_t end, dict l7_ports,
                            dict kwargs) except -1:
    cdef:
        Py_ssize_t header_end
        Py_ssize_t length = end - start
    pkt.ws_len = length
    pkt._pad = b''
    if length >= 20:
        pkt.sport = rd_u16(mv, start)
        pkt.dport = rd_u16(mv, start + 2)
        pkt.sequence = rd_u32(mv, start + 4)
        pkt.acknowledgment = rd_u32(mv, start + 8)
        pkt._off_flags = rd_u16(mv, start + 12)
        pkt.window = rd_u16(mv, start + 14)
        pkt.checksum = rd_u16(mv, start + 16)
        pkt.urg_ptr = rd_u16(mv, start + 18)
        if pkt.data_offset < TCP_MIN_DATA_OFFSET:
            # data_offset is where the header ends and the payload begins.
            # Below 5 it points back inside the header, so the header bytes
            # themselves used to be handed to the layer 7 parser.
            raise ValueError('TCP: data offset field is %d 32 bit words, '
                             'less than the %d word minimum header'
                             % (pkt.data_offset, TCP_MIN_DATA_OFFSET))
        header_end = start + (pkt.data_offset * 4)
        if header_end > end:
            # The options the header claims are not in the capture. Clamping
            # silently produced short options and a payload starting inside
            # the header.
            raise ValueError('TCP: truncated packet, data offset field needs '
                             '%d header bytes, got %d'
                             % (pkt.data_offset * 4, length))
        if pkt.data_offset > 5:
            pkt._options = rd_bytes(mv, start + 20, header_end)
        else:
            pkt._options = b''
        pkt.payload = _l7_range(owner, mv, header_end, end, l7_ports,
                                pkt.sport, pkt.dport, pkt._decode_context,
                                pkt._decode_exporter, 'tcp')
        return 0

    if length != TCP_QUOTE_LEN:
        # Anything shorter than a full header that is not the 8 byte quote an
        # ICMP error carries is truncated. This used to fall through to the
        # keyword defaults below, and since every caller that parses bytes
        # passes no keywords the result was a silent, fully zeroed TCP layer
        # with a NullPkt payload rather than an error.
        raise ValueError('TCP: truncated packet, need at least 20 bytes for '
                         'a header or exactly %d for an ICMP quote, got %d'
                         % (TCP_QUOTE_LEN, length))
    pkt.sport = rd_u16(mv, start)
    pkt.dport = rd_u16(mv, start + 2)
    pkt.sequence = rd_u32(mv, start + 4)
    pkt.acknowledgment = kwargs.get('acknowledgment', 0)
    pkt.data_offset = kwargs.get('data_offset', 5)
    pkt.flag_ns = kwargs.get('flag_ns', 0)
    pkt.flag_cwr = kwargs.get('flag_cwr', 0)
    pkt.flag_ece = kwargs.get('flag_ece', 0)
    pkt.flag_urg = kwargs.get('flag_urg', 0)
    pkt.flag_ack = kwargs.get('flag_ack', 0)
    pkt.flag_psh = kwargs.get('flag_psh', 0)
    pkt.flag_rst = kwargs.get('flag_rst', 0)
    pkt.flag_syn = kwargs.get('flag_syn', 0)
    pkt.flag_fin = kwargs.get('flag_fin', 0)
    pkt.window = kwargs.get('window', 0)
    pkt.checksum = kwargs.get('checksum', 0)
    pkt.urg_ptr = kwargs.get('urg_ptr', 0)
    pkt.options = kwargs.get('options', b'')
    pkt.payload = NullPkt()
    return 0


cdef inline int _decode_ip(IP pkt, bytes owner,
                           const unsigned char[:] mv, Py_ssize_t start,
                           Py_ssize_t end, dict l7_ports) except -1:
    cdef:
        unsigned char iphl, hl_bytes
        Py_ssize_t payload_start, datagram_end
        UDP udp
        TCP tcp
        ICMP icmp
        IGMP igmp
        GRE gre
    _need_range(start, end, 20, 'IP')
    pkt.ipv4_pheader = Ip4Ph()
    pkt.options = b''
    pkt._version_iphl = mv[start]
    iphl = pkt.iphl
    if iphl < IPV4_MIN_HDR_LEN:
        # ihl is where the layer 4 header starts. Below 5 it points back
        # inside the IPv4 header itself, which used to be decoded as the
        # payload -- so a single crafted nibble decided what the rest of the
        # packet was parsed as.
        raise ValueError('IP: header length field is %d 32 bit words, less '
                         'than the %d word minimum header'
                         % (iphl, IPV4_MIN_HDR_LEN))
    pkt.tos = mv[start + 1]
    pkt.total_len = rd_u16(mv, start + 2)
    pkt.ident = rd_u16(mv, start + 4)
    pkt._flags_offset = rd_u16(mv, start + 6)
    pkt.ttl = mv[start + 8]
    pkt.proto = mv[start + 9]
    pkt.checksum = rd_u16(mv, start + 10)
    pkt.src_nochk = rd_bytes(mv, start + 12, start + 16)
    pkt.dst_nochk = rd_bytes(mv, start + 16, start + 20)
    hl_bytes = iphl * 4
    _need_range(start, end, hl_bytes, 'IP')
    payload_start = start + hl_bytes
    if iphl > 5:
        pkt.options = rd_bytes(mv, start + 20, payload_start)
    # total_len covers the header and the data behind it, so it is what says
    # where the datagram stops. The frame it arrived in is usually longer:
    # Ethernet pads anything under 60 bytes, and that padding is not payload.
    datagram_end = _declared_end(start, end, pkt.total_len, hl_bytes, 'IP')
    if datagram_end < end:
        pkt._trailer = rd_bytes(mv, datagram_end, end)
        end = datagram_end
    if payload_start >= end:
        pkt.payload = PKT()
        return 0

    if pkt.proto == PROTO_UDP:
        udp = UDP.__new__(UDP)
        udp._l7_ports = l7_ports
        udp._decode_context = pkt._decode_context
        udp._decode_exporter = (pkt._decode_exporter
                                if pkt._decode_exporter is not None
                                else pkt.src)
        udp.pkt_name = 'UDP'
        udp.pq_type, udp.query_fields = _QI_UDP
        _decode_udp(udp, owner, mv, payload_start, end, l7_ports)
        pkt.payload = udp
    elif pkt.proto == PROTO_TCP:
        tcp = TCP.__new__(TCP)
        tcp._l7_ports = l7_ports
        tcp._decode_context = pkt._decode_context
        tcp._decode_exporter = (pkt._decode_exporter
                                if pkt._decode_exporter is not None
                                else pkt.src)
        tcp.pkt_name = 'TCP'
        tcp.pq_type, tcp.query_fields = _QI_TCP
        _decode_tcp(tcp, owner, mv, payload_start, end, l7_ports, {})
        pkt.payload = tcp
    elif pkt.proto == PROTO_ICMP:
        icmp = ICMP.__new__(ICMP)
        icmp._l7_ports = None
        icmp.pkt_name = 'ICMP'
        icmp.pq_type, icmp.query_fields = _QI_ICMP
        _decode_icmp(icmp, owner, payload_start, end)
        pkt.payload = icmp
    elif pkt.proto == PROTO_IGMP:
        igmp = IGMP.__new__(IGMP)
        igmp._l7_ports = None
        igmp.pkt_name = 'IGMP'
        igmp.pq_type, igmp.query_fields = _QI_IGMP
        igmp._s_qrv = igmp.qqic = 0
        igmp.group_records = list()
        igmp._source_addresses = b''
        # The bytes actually available, which the clamp above has already made
        # equal to total_len - hl_bytes whenever total_len was stated. Deriving
        # it from the range rather than subtracting keeps a total_len smaller
        # than the header from reaching a uint16 conversion, and gives the
        # version guard a real length when total_len is 0.
        _decode_igmp(igmp, owner, payload_start, end, end - payload_start)
        pkt.payload = igmp
    elif pkt.proto == PROTO_GRE:
        gre = GRE.__new__(GRE)
        gre._l7_ports = l7_ports
        gre.pkt_name = 'GRE'
        gre.pq_type, gre.query_fields = _QI_GRE
        _decode_gre(gre, owner, mv, payload_start, end, l7_ports)
        pkt.payload = gre
    else:
        pkt.payload = _null_range(owner, payload_start, end, l7_ports)
    return 0


cdef inline unsigned char _walk_ip6_ext_range(
        const unsigned char[:] mv, Py_ssize_t start, Py_ssize_t end,
        unsigned char first_nh, Py_ssize_t *ext_len, bint *incomplete,
        bint *truncated):
    """Walk the IPv6 extension header chain, reporting how it ended.

    incomplete says the bytes after the chain are not an upper layer
    header, which is true both for a non-first fragment and for a chain
    that ran off the end of the capture. truncated distinguishes the second
    case, because the caller has no other way to tell: the walk stops with
    the next-header value of an extension header still in hand, and no
    decode branch matches one of those, so a truncated chain and a protocol
    this library does not know looked exactly alike.
    """
    cdef:
        Py_ssize_t off = start
        unsigned char cur = first_nh
        unsigned char nxt, hlen
        Py_ssize_t size
    incomplete[0] = 0
    truncated[0] = 0
    while _is_ip6_ext(cur):
        if off + 2 > end:
            # Not even the two bytes naming the next header are present.
            incomplete[0] = 1
            truncated[0] = 1
            break
        nxt = mv[off]
        hlen = mv[off + 1]
        if cur == 44:
            size = 8
            if off + 4 <= end and \
                    (((<int>mv[off + 2] << 8) | mv[off + 3]) >> 3):
                incomplete[0] = 1
        elif cur == 51:
            size = (<Py_ssize_t>hlen + 2) * 4
        else:
            size = (<Py_ssize_t>hlen + 1) * 8
        if size <= 0 or off + size > end:
            # The chain runs past the bytes we have, so the extension header
            # after this one - and with it the real upper layer protocol -
            # is unknowable.
            incomplete[0] = 1
            truncated[0] = 1
            break
        off += size
        cur = nxt
    ext_len[0] = off - start
    return cur


cdef inline int _decode_ip6(IP6 pkt, bytes owner,
                            const unsigned char[:] mv, Py_ssize_t start,
                            Py_ssize_t end, dict l7_ports) except -1:
    cdef:
        Py_ssize_t ext_len = 0
        Py_ssize_t payload_start, datagram_end, declared
        bint incomplete = 0
        bint truncated = 0
        UDP udp
        TCP tcp
        ICMP6 icmp6
        GRE gre
    _need_range(start, end, IPV6_HDR_LEN, 'IP6')
    pkt.ipv6_pheader = Ip6Ph()
    pkt._ext_hdrs = b''
    pkt._upper_proto = 0
    pkt._v_tc_flow = rd_u32(mv, start)
    pkt.payload_len = rd_u16(mv, start + 4)
    pkt._nh = mv[start + 6]
    pkt.hop_limit = mv[start + 7]
    pkt.src_nochk = rd_bytes(mv, start + 8, start + 24)
    pkt.dst_nochk = rd_bytes(mv, start + 24, start + 40)
    # payload_len counts everything after the 40 byte header, so the datagram
    # ends there. Clamped before the extension header walk so padding cannot
    # be mistaken for another extension header either. A payload_len of 0 is
    # a jumbogram, whose real length lives in a hop by hop option, so it is
    # left to _declared_end to treat as unstated.
    declared = 0
    if pkt.payload_len:
        declared = IPV6_HDR_LEN + <Py_ssize_t>pkt.payload_len
    datagram_end = _declared_end(start, end, declared, IPV6_HDR_LEN, 'IP6')
    if datagram_end < end:
        pkt._trailer = rd_bytes(mv, datagram_end, end)
        end = datagram_end
    pkt._upper_proto = _walk_ip6_ext_range(
        mv, start + IPV6_HDR_LEN, end, pkt._nh, &ext_len, &incomplete,
        &truncated)
    pkt.ext_hdrs_truncated = truncated
    pkt.ipv6_pheader.nh = pkt._upper_proto
    if ext_len:
        pkt._ext_hdrs = rd_bytes(mv, start + IPV6_HDR_LEN,
                                 start + IPV6_HDR_LEN + ext_len)
    payload_start = start + IPV6_HDR_LEN + ext_len
    if payload_start >= end:
        pkt.payload = PKT()
        return 0

    if incomplete:
        pkt.payload = _null_range(owner, payload_start, end, l7_ports)
    elif pkt._upper_proto == PROTO_UDP:
        udp = UDP.__new__(UDP)
        udp._l7_ports = l7_ports
        udp._decode_context = pkt._decode_context
        udp._decode_exporter = (pkt._decode_exporter
                                if pkt._decode_exporter is not None
                                else pkt.src)
        udp.pkt_name = 'UDP'
        udp.pq_type, udp.query_fields = _QI_UDP
        _decode_udp(udp, owner, mv, payload_start, end, l7_ports)
        pkt.payload = udp
    elif pkt._upper_proto == PROTO_TCP:
        tcp = TCP.__new__(TCP)
        tcp._l7_ports = l7_ports
        tcp._decode_context = pkt._decode_context
        tcp._decode_exporter = (pkt._decode_exporter
                                if pkt._decode_exporter is not None
                                else pkt.src)
        tcp.pkt_name = 'TCP'
        tcp.pq_type, tcp.query_fields = _QI_TCP
        _decode_tcp(tcp, owner, mv, payload_start, end, l7_ports, {})
        pkt.payload = tcp
    elif pkt._upper_proto == PROTO_ICMPV6:
        icmp6 = ICMP6.__new__(ICMP6)
        icmp6._l7_ports = None
        icmp6.pkt_name = 'ICMP6'
        icmp6.pq_type, icmp6.query_fields = _QI_ICMP6
        _decode_icmp6(icmp6, owner, payload_start, end)
        pkt.payload = icmp6
    elif pkt._upper_proto == PROTO_GRE:
        gre = GRE.__new__(GRE)
        gre._l7_ports = l7_ports
        gre.pkt_name = 'GRE'
        gre.pq_type, gre.query_fields = _QI_GRE
        _decode_gre(gre, owner, mv, payload_start, end, l7_ports)
        pkt.payload = gre
    else:
        pkt.payload = _null_range(owner, payload_start, end, l7_ports)
    return 0


cdef int _decode_mpls(MPLS pkt, bytes owner, const unsigned char[:] mv,
                      Py_ssize_t start, Py_ssize_t end,
                      dict l7_ports) except -1:
    cdef:
        Py_ssize_t payload_start
        Py_ssize_t depth = 0
        MPLS label = pkt
        MPLS mpls
        IP ip
        IP6 ip6
        Ethernet eth
    # The label stack is walked iteratively, not by recursing into
    # _decode_mpls: a crafted stack must not cost one native stack frame per
    # label. Each pass either hands the stack on to the next label or breaks
    # out to decode the bottom of stack payload below.
    while True:
        _need_range(start, end, 4, 'MPLS')
        label._data = rd_u32(mv, start)
        payload_start = start + 4
        if payload_start >= end:
            label.payload = NullPkt()
            return 0
        if label.s:
            break
        if depth >= MPLS_MAX_STACK_DEPTH:
            # Past any real deployment. Keep the rest of the stack as opaque
            # bytes rather than building an unbounded chain of layers: the
            # packet still re-serializes byte for byte.
            label.payload = _null_range(owner, payload_start, end, l7_ports)
            return 0
        mpls = MPLS.__new__(MPLS)
        mpls._l7_ports = l7_ports
        mpls.pkt_name = 'MPLS'
        mpls.pq_type, mpls.query_fields = _QI_MPLS
        label.payload = mpls
        label = mpls
        start = payload_start
        depth += 1
    # label is the bottom of stack label reached by the walk above, which is
    # pkt itself for the common single label case.
    if mv[payload_start] >> 4 == IPV4_VER:
        ip = IP.__new__(IP)
        ip._l7_ports = l7_ports
        ip.pkt_name = 'IP'
        ip.pq_type, ip.query_fields = _QI_IP
        _decode_ip(ip, owner, mv, payload_start, end, l7_ports)
        label.payload = ip
    elif mv[payload_start] >> 4 == IPV6_VER:
        ip6 = IP6.__new__(IP6)
        ip6._l7_ports = l7_ports
        ip6.pkt_name = 'IP6'
        ip6.pq_type, ip6.query_fields = _QI_IP6
        _decode_ip6(ip6, owner, mv, payload_start, end, l7_ports)
        label.payload = ip6
    else:
        eth = Ethernet.__new__(Ethernet)
        eth._l7_ports = l7_ports
        eth.pkt_name = 'Ethernet'
        eth.pq_type, eth.query_fields = _QI_ETH
        eth.tpid = 0
        eth._tci = 0
        _decode_ethernet(eth, owner, mv, payload_start, end, l7_ports)
        label.payload = eth
    return 0


cdef inline int _decode_ethernet(Ethernet pkt, bytes owner,
                                 const unsigned char[:] mv,
                                 Py_ssize_t start, Py_ssize_t end,
                                 dict l7_ports) except -1:
    cdef:
        Py_ssize_t payload_start = start + 14
        IP ip
        IP6 ip6
        MPLS mpls
        ARP arp
    _need_range(start, end, 14, 'Ethernet')
    pkt._dst_mac = _mac_from_buf(&mv[start])
    pkt._src_mac = _mac_from_buf(&mv[start + 6])
    pkt.type = rd_u16(mv, start + 12)
    if pkt.type == ETH_TYPE_8021Q:
        _need_range(start, end, 18, 'Ethernet')
        pkt.tpid = ETH_TYPE_8021Q
        pkt._tci = rd_u16(mv, start + 14)
        pkt.type = rd_u16(mv, start + 16)
        payload_start = start + 18
    if pkt.type == ETH_TYPE_IPV4:
        ip = IP.__new__(IP)
        ip._l7_ports = l7_ports
        ip._decode_context = pkt._decode_context
        ip._decode_exporter = pkt._decode_exporter
        ip.pkt_name = 'IP'
        ip.pq_type, ip.query_fields = _QI_IP
        _decode_ip(ip, owner, mv, payload_start, end, l7_ports)
        pkt.payload = ip
    elif pkt.type == ETH_TYPE_IPV6:
        ip6 = IP6.__new__(IP6)
        ip6._l7_ports = l7_ports
        ip6._decode_context = pkt._decode_context
        ip6._decode_exporter = pkt._decode_exporter
        ip6.pkt_name = 'IP6'
        ip6.pq_type, ip6.query_fields = _QI_IP6
        _decode_ip6(ip6, owner, mv, payload_start, end, l7_ports)
        pkt.payload = ip6
    elif pkt.type == ETH_TYPE_ARP:
        arp = ARP.__new__(ARP)
        arp._l7_ports = None
        arp.pkt_name = 'ARP'
        arp.pq_type, arp.query_fields = _QI_ARP
        arp._raw = None
        _decode_arp(arp, owner, payload_start, end)
        pkt.payload = arp
    elif pkt.type in (ETH_TYPE_MPLS_UCAST, ETH_TYPE_MPLS_MCAST):
        mpls = MPLS.__new__(MPLS)
        # l7_ports is forwarded here as it is everywhere else. This branch
        # used to drop it to preserve an Ethernet specific quirk, which left
        # MPLS encapsulated TCP and UDP unable to reach any registered layer
        # 7 class while the very same labels parsed through MPLS(...)
        # directly could.
        mpls._l7_ports = l7_ports
        mpls.pkt_name = 'MPLS'
        mpls.pq_type, mpls.query_fields = _QI_MPLS
        _decode_mpls(mpls, owner, mv, payload_start, end, l7_ports)
        pkt.payload = mpls
    else:
        pkt.payload = _null_range(owner, payload_start, end, None)
    return 0


cdef inline int _init_ethernet_kwargs(Ethernet pkt,
                                      dict kwargs) except -1:
    """Initialize a newly allocated Ethernet object from keywords."""
    if 'src_mac' in kwargs:
        pkt.src_mac = kwargs['src_mac']
    else:
        # clone(zero=True) is calloc'd storage: no bytes literal to walk and
        # no array constructor call for the default address pair.
        pkt._src_mac = clone(_EMPTY_BUF, 6, True)
    if 'dst_mac' in kwargs:
        pkt.dst_mac = kwargs['dst_mac']
    else:
        pkt._dst_mac = clone(_EMPTY_BUF, 6, True)
    if 'type' in kwargs:
        pkt.type = kwargs['type']
    else:
        pkt.type = ETH_TYPE_IPV4
    if 'tpid' in kwargs:
        pkt.tpid = kwargs['tpid']
    if 'priority_code' in kwargs:
        pkt.priority_code = kwargs['priority_code']
    if 'drop_eligible' in kwargs:
        pkt.drop_eligible = kwargs['drop_eligible']
    if 'vlan_id' in kwargs:
        pkt.vlan_id = kwargs['vlan_id']
    if 'payload' in kwargs:
        pkt.payload = kwargs['payload']
    else:
        pkt.payload = PKT()
    return 0


@cython.final
cdef class Ethernet(PKT):
    """Implements Ethernet II frame without CRC.
    """
    def __init__(self, *args, **kwargs):\

        """Initialize a Ethernet II object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an Ethernet packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an Ethernet packet
            :src_mac (str): Layer 2 source address in colon notation. For 
                example the layer 2 broadcast MAC would be 'ff:ff:ff:ff:ff:ff'
            :dst_mac (str): Layer 2 destination address in colon notation.
            :type (uint16_t): EtherType of the payload. Common values are 
                0x0800 for IPv4 and 0x0806 for ARP.
            :payload (PKT or bytes): The payload of this packet. Payload can be 
                a PKT sub class or a byte string.
            :l7_ports (dict): A dictionary where the keys are layer 4 port 
                numbers and the values are PKT subclass packet classes. Used 
                by app_layer to determine what class should be used to decode
                the payload string or byte array.
        """
        self._base_l7(kwargs)
        self.pkt_name = 'Ethernet'
        self.tpid = 0
        self._tci = 0
        self.pq_type, self.query_fields = _QI_ETH
        cdef:
            unsigned char use_buffer
            uint16_t vlan_hdr_add
            uint16_t preflight_type
            Py_ssize_t owner_len, ip_start
            array buf
            const unsigned char[:] mv
            bytes owner

        if not args and 'data' not in kwargs:
            _init_ethernet_kwargs(self, kwargs)
            return
        owner = _owned_buffer(args, kwargs)
        if owner is not None:
            mv = owner
            owner_len = len(owner)
            ip_start = -1
            if not self._l7_ports and owner_len >= 24:
                preflight_type = ((<uint16_t>mv[12]) << 8) | mv[13]
                if preflight_type == ETH_TYPE_IPV4:
                    ip_start = 14
                elif (preflight_type == ETH_TYPE_8021Q and
                      owner_len >= 28 and
                      (((<uint16_t>mv[16]) << 8) | mv[17]) ==
                      ETH_TYPE_IPV4):
                    ip_start = 18
                if (ip_start >= 0 and
                        mv[ip_start] >> 4 == IPV4_VER and
                        (mv[ip_start] & 0x0f) >= IPV4_MIN_HDR_LEN and
                        mv[ip_start + 9] == PROTO_UDP):
                    _decode_eth_ip_udp_fast(self, owner, mv, owner_len)
                    return
            _decode_ethernet(self, owner, mv, 0, len(owner), self._l7_ports)
            return

        use_buffer, buf = self.from_buffer(args, kwargs)
        vlan_hdr_add = 0
        if use_buffer:
            mv = buf
            need_bytes(mv, 14, 'Ethernet')
            self._dst_mac = buf[:6]
            self._src_mac = buf[6:12]
            self.type = rd_u16(mv, 12)
            if self.type == ETH_TYPE_8021Q:
                need_bytes(mv, 18, 'Ethernet')
                self.tpid = ETH_TYPE_8021Q
                self._tci = rd_u16(mv, 14)
                self.type = rd_u16(mv, 16)
                vlan_hdr_add = 4
            if self.type == ETH_TYPE_IPV4:
                self.payload = IP(buf[14 + vlan_hdr_add:],
                                  l7_ports = self._l7_ports)
            elif self.type == ETH_TYPE_IPV6:
                self.payload = IP6(buf[14 + vlan_hdr_add:],
                                   l7_ports = self._l7_ports)
            elif self.type == ETH_TYPE_ARP:
                self.payload = ARP(buf[14 + vlan_hdr_add:])
            elif self.type in (ETH_TYPE_MPLS_UCAST,
                               ETH_TYPE_MPLS_MCAST):
                self.payload = MPLS(buf[14 + vlan_hdr_add:])
            else:
                self.payload = NullPkt(buf[14 + vlan_hdr_add:])
        else:
            self.src_mac = kwargs.get('src_mac', '00:00:00:00:00:00')
            self.dst_mac = kwargs.get('dst_mac', '00:00:00:00:00:00')
            self.type = kwargs.get('type', ETH_TYPE_IPV4)
            self.tpid = kwargs.get('tpid', 0)
            self.priority_code = kwargs.get('priority_code', 0)
            self.drop_eligible = kwargs.get('drop_eligible', 0)
            self.vlan_id = kwargs.get('vlan_id', 0)
            if 'payload' in kwargs:
                self.payload = kwargs['payload']
            else:
                self.payload = PKT()

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields Ethernet supports and
        Ethernet's PKT type ID.

        Returns:
            :tuple: PQTYPES.t_eth and a tuple of the supported
                field names.
        """
        return (PQ_ETH,
                ('eth.type', 'eth.src', 'eth.dst', 'eth.vlan.cfi',
                 'eth.vlan.id', 'eth.vlan.pri', 'eth.vlan.tpid'))

    cpdef object get_field_val(self, str field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """
        if field == 'eth.type':
            return self.type
        elif field == 'eth.src':
            return self.src_mac
        elif field == 'eth.dst':
            return self.dst_mac
        elif field == 'eth.vlan.cfi':
            return self.drop_eligible
        elif field == 'eth.vlan.id':
            return self.vlan_id
        elif field == 'eth.vlan.pri':
            return self.priority_code
        elif field == 'eth.vlan.tpid':
            return self.tpid
        else:
            return None

    property src_mac:
        def __get__(self):
            return _fmt_mac(self._src_mac)
        def __set__(self, str val):
            self._src_mac = pack_mac(val)

    property dst_mac:
        def __get__(self):
            return _fmt_mac(self._dst_mac)
        def __set__(self, str val):
            self._dst_mac = pack_mac(val)

    property priority_code:
        """ The priority_code. """
        def __get__(self):
            """ Return the priority_code value. """
            return (self._tci >> 13) & 0b111
        def __set__(self, unsigned char val):
            """ Set the priority_code value. """
            if val <= 0b111:
                self._tci = (self._tci & ~(0b111 << 13)) | (val << 13)
            else:
                raise ValueError("priority_code valid values are 0-7")

    property drop_eligible:
        """ Set or get the drop_eligible bit. """
        def __get__(self):
            """ Return the drop_eligible bit. """
            return (self._tci >> 12) & 1
        def __set__(self, unsigned char val):
            """ Set the drop_eligible bit. """
            if val == 1:
                set_bit(&self._tci, 12)
            elif val == 0:
                unset_bit(&self._tci, 12)
            else:
                raise ValueError("drop_eligible bit must be 0 or 1")

    property vlan_id:
        """ Set or get vlan_id. """
        def __get__(self):
            """ Return the vlan_id. """
            return self._tci & 0xfff
        def __set__(self, uint16_t val):
            """ Set the vlan_id. """
            if val <= 0xfff:
                self._tci = (self._tci & ~0xfff) | val
            else:
                raise ValueError(
                    "vlan_id has a max value of: {}".format(0xfff))

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a Ethernet packet class instance in network order 
        for writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by Ethernet to payload classes. Ethernet has no 
                options that it directly supports.

        Returns: 
            :bytes: network order byte string representation of this Ethernet 
                instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this Ethernet frame and everything it carries to a shared
        buffer.

        The EtherType only depends on the *type* of the payload, not on its
        bytes, so it can be settled before the header is written and the
        payload can then be appended straight behind it. See PKT._write.
        """
        cdef:
            bint csum
            Py_ssize_t start, length, min_frame
            uint32_t check

        csum = kwargs.get('eth_crc', 0)
        min_frame = MIN_FRAME_SIZE
        start = w.n

        if isinstance(self.payload, PKT):
            # Keep the EtherType consistent with the payload so frames whose
            # payload is assigned after construction (pkt.payload = IP6(...))
            # serialize and re-parse correctly. Raw/unknown payloads keep any
            # explicitly set type.
            if isinstance(self.payload, IP6):
                self.type = ETH_TYPE_IPV6
            elif isinstance(self.payload, IP):
                self.type = ETH_TYPE_IPV4
            elif isinstance(self.payload, ARP):
                self.type = ETH_TYPE_ARP
            elif isinstance(self.payload, MPLS):
                if self.type not in (ETH_TYPE_MPLS_UCAST, ETH_TYPE_MPLS_MCAST):
                    self.type = ETH_TYPE_MPLS_UCAST

        w_raw(w, self._dst_mac.data.as_uchars, MAC_LEN)
        w_raw(w, self._src_mac.data.as_uchars, MAC_LEN)
        if self.tpid == ETH_TYPE_8021Q:
            w_u16(w, self.tpid)
            w_u16(w, self._tci)
        w_u16(w, self.type)

        if isinstance(self.payload, PKT):
            (<PKT>self.payload)._write(w, kwargs)

        length = w.n - start
        if csum and length < (min_frame - 4):
            w_zeros(w, (min_frame - 4) - length)
        elif not csum and length < min_frame:
            w_zeros(w, min_frame - length)

        if csum:
            # crc32 needs a real buffer object; this is the one copy left,
            # and only on the rarely used eth_crc path.
            check = binascii.crc32(w_take(w, start))
            w_u32(w, check)
        return 0


# --- pcap_query metadata, built once at import ------------------------------
# See the _QI_* declarations at the top of this module. Each class __init__
# assigns from these instead of calling its query_info() classmethod per
# layer, per packet. They are built here, after the classes exist, from the
# classmethods themselves so the field lists cannot drift.
_QI_PKT = PKT.query_info()
_QI_ARP = ARP.query_info()
_QI_NULLPKT = NullPkt.query_info()
_QI_NETFLOW_SIMPLE = NetflowSimple.query_info()
_QI_UDP = UDP.query_info()
_QI_TCP = TCP.query_info()
_QI_ICMP = ICMP.query_info()
_QI_IGMPGroupRecord = IGMPGroupRecord.query_info()
_QI_IGMP = IGMP.query_info()
_QI_IP = IP.query_info()
_QI_IP6 = IP6.query_info()
_QI_ICMP6 = ICMP6.query_info()
_QI_ICMP6Opt = ICMP6Opt.query_info()
_QI_MLDv2AddressRecord = MLDv2AddressRecord.query_info()
_QI_MPLS = MPLS.query_info()
_QI_ETH = Ethernet.query_info()
_QI_GRE = GRE.query_info()
