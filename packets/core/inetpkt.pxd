# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from cpython.array cimport array
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AS_STRING, \
                           PyBytes_GET_SIZE
from cpython.unicode cimport PyUnicode_DecodeASCII
from libc.stdint cimport uint32_t, uint16_t
from libc.string cimport memcpy, memset
cimport cython


# --- Shared parse-buffer readers --------------------------------------------
# Defined here rather than in inetpkt.pyx so protos/dns.pyx gets the same
# inlined code instead of a second copy of it. Every parser in the package
# reads its header fields through these.

@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline uint16_t rd_u16(const unsigned char[:] b, Py_ssize_t off):
    """Read a big-endian (network order) 16-bit word from a typed memoryview.

    Direct-indexing replacement for ``unpack('!H', buf[off:off+2])[0]`` that
    avoids allocating a buffer slice and an unpack tuple per field.
    """
    return (<uint16_t>b[off] << 8) | b[off + 1]


@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline uint32_t rd_u32(const unsigned char[:] b, Py_ssize_t off):
    """Read a big-endian (network order) 32-bit word from a typed memoryview.

    Direct-indexing replacement for ``unpack('!I', buf[off:off+4])[0]``.
    """
    return ((<uint32_t>b[off] << 24) | (<uint32_t>b[off + 1] << 16) |
            (<uint32_t>b[off + 2] << 8) | b[off + 3])


@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline bytes rd_bytes(const unsigned char[:] b,
                           Py_ssize_t start,
                           Py_ssize_t stop):
    """Copy a slice of a parse buffer straight into a bytes object.

    ``bytes(mv[a:b])`` on a typed memoryview allocates a whole intermediate
    memoryview object per slice, which measured slower than the
    ``array_slice.tobytes()`` it was meant to replace. This is one
    allocation and one memcpy.

    :param b: the parse buffer.
    :param start: first byte to copy.
    :param stop: one past the last byte, or -1 for "to the end".
    :return: the bytes, or b'' if the range is empty.
    """
    cdef Py_ssize_t n = b.shape[0]
    if stop < 0 or stop > n:
        stop = n
    if start >= stop:
        return b''
    return PyBytes_FromStringAndSize(<const char*>&b[start], stop - start)


cdef inline void need_bytes(const unsigned char[:] b,
                            Py_ssize_t least,
                            str name) except *:
    """Raise if a parse buffer is too short for the header about to be read.

    ``rd_u16``/``rd_u32`` run with ``boundscheck(False)``, so a truncated
    frame would read past the end of the buffer instead of failing. The
    struct.unpack calls these replaced raised struct.error on short input;
    this keeps truncated input an exception rather than undefined behaviour.

    :param b: the parse buffer.
    :param least: minimum number of bytes the caller is about to read.
    :param name: layer name, used in the error message.
    """
    if b.shape[0] < least:
        raise ValueError('%s: truncated packet, need at least %d bytes, '
                         'got %d' % (name, least, b.shape[0]))


# --- Shared address formatting ----------------------------------------------
# Here for the same reason the readers above are: protos/dhcp.pyx and
# protos/netflow.pyx each grew their own IPv4 formatter because inetpkt's was
# private to inetpkt.pyx, and both of theirs were slower than this one.

# The dot separator and the digit base as their ASCII code points -- Cython
# has no character literal. 15 characters is the widest dotted quad, and the
# buffer below is exactly that size.
DEF ASCII_DOT = 0x2e
DEF ASCII_ZERO = 0x30
DEF IPV4_TEXT_LEN = 15


cdef inline str _fmt_ipv4_buf(const unsigned char *src):
    """Format 4 address bytes as dot notation, entirely in C.

    socket.inet_ntoa and the platform's inet_ntop both do this correctly, but
    the first is a Python call taking a bytes argument and the second costs
    more than writing the four octets does: measured on macOS, inet_ntop
    alone is ~110ns of the ~136ns a formatted address used to take, against
    ~26ns here. Addresses are never read once -- a NetFlow v9 capture can
    carry hundreds of thousands of them -- so the difference is the decode.

    The caller owns the bounds check: 4 readable bytes are assumed. Callers
    holding a Python object rather than a pointer should wrap this in the
    length test their own error contract needs.

    :param src: at least 4 readable bytes of address.
    :return: the address as a str, e.g. '10.1.2.3'.
    """
    cdef char out[IPV4_TEXT_LEN]
    cdef Py_ssize_t i, j = 0
    cdef unsigned char octet

    for i in range(4):              # IPV4_LEN, as a C loop bound
        if i:
            out[j] = ASCII_DOT
            j += 1
        octet = src[i]
        if octet >= 100:
            out[j] = ASCII_ZERO + octet // 100
            j += 1
        if octet >= 10:
            out[j] = ASCII_ZERO + (octet // 10) % 10
            j += 1
        out[j] = ASCII_ZERO + octet % 10
        j += 1
    return PyUnicode_DecodeASCII(out, j, NULL)


# --- Serialization writer ---------------------------------------------------
# pkt2net used to build each layer's bytes on its own and hand them up to the
# layer above, which concatenated them into a new bytes object -- so the
# payload of an N layer frame was copied N times, and the checksum paths
# copied it once more to build their checksum input. Every layer now appends
# into one growable buffer instead and patches its length and checksum fields
# back in place once the payload behind them is known (plan item C).
#
# The buffer is raw malloc'd memory rather than a bytearray so the field
# writers below inline to a couple of stores with no Python level call.

@cython.final
cdef class PktWriter:
    cdef:
        unsigned char *b
        Py_ssize_t n
        Py_ssize_t cap
        bint in_use


cdef int w_grow(PktWriter w, Py_ssize_t need) except -1

cdef PktWriter w_acquire()

cdef void w_release(PktWriter w)


cdef inline int w_u8(PktWriter w, unsigned char v) except -1:
    """Append one byte."""
    if w.n + 1 > w.cap:
        w_grow(w, w.n + 1)
    w.b[w.n] = v
    w.n += 1
    return 0


cdef inline int w_u16(PktWriter w, uint16_t v) except -1:
    """Append a 16 bit word in network order."""
    if w.n + 2 > w.cap:
        w_grow(w, w.n + 2)
    w.b[w.n] = <unsigned char>(v >> 8)
    w.b[w.n + 1] = <unsigned char>(v & 0xff)
    w.n += 2
    return 0


cdef inline int w_u32(PktWriter w, uint32_t v) except -1:
    """Append a 32 bit word in network order."""
    if w.n + 4 > w.cap:
        w_grow(w, w.n + 4)
    w.b[w.n] = <unsigned char>(v >> 24)
    w.b[w.n + 1] = <unsigned char>((v >> 16) & 0xff)
    w.b[w.n + 2] = <unsigned char>((v >> 8) & 0xff)
    w.b[w.n + 3] = <unsigned char>(v & 0xff)
    w.n += 4
    return 0


cdef inline int w_raw(PktWriter w, const unsigned char *p,
                      Py_ssize_t k) except -1:
    """Append k bytes read straight out of C memory."""
    if k <= 0:
        return 0
    if w.n + k > w.cap:
        w_grow(w, w.n + k)
    memcpy(w.b + w.n, p, k)
    w.n += k
    return 0


cdef inline int w_bytes(PktWriter w, bytes v) except -1:
    """Append a bytes object with no intermediate copy."""
    return w_raw(w, <const unsigned char*>PyBytes_AS_STRING(v),
                 PyBytes_GET_SIZE(v))


cdef inline int w_zeros(PktWriter w, Py_ssize_t k) except -1:
    """Append k zero bytes -- header placeholders and frame padding."""
    if k <= 0:
        return 0
    if w.n + k > w.cap:
        w_grow(w, w.n + k)
    memset(w.b + w.n, 0, k)
    w.n += k
    return 0


cdef inline void w_set_u16(PktWriter w, Py_ssize_t off, uint16_t v):
    """Overwrite an already written 16 bit field.

    This is what makes the single buffer work: a length or checksum field is
    emitted as a placeholder, the payload behind it is written, and the real
    value is stored back into its slot instead of the header being rebuilt.
    """
    w.b[off] = <unsigned char>(v >> 8)
    w.b[off + 1] = <unsigned char>(v & 0xff)


cdef inline bytes w_take(PktWriter w, Py_ssize_t start):
    """Copy everything written from ``start`` onwards out as bytes."""
    return PyBytes_FromStringAndSize(<const char*>(w.b + start), w.n - start)



cdef:
    unsigned char IPV4_LEN
    unsigned char IPV4_VER
    unsigned char IPV4_MIN_HDR_LEN
    unsigned char IPV6_LEN
    unsigned char IPV6_VER
    unsigned char MAC_LEN
    # ARP
    unsigned char ARP_TYPE_ETH
    unsigned char ARP_OP_REQUEST
    unsigned char ARP_OP_REPLY
    unsigned char ARP_OP_RARP_REQUEST
    unsigned char ARP_OP_RARP_REPLY
    unsigned char ARP_OP_DYN_RARP_REQUEST
    unsigned char ARP_OP_DYN_RARP_REPLY
    unsigned char ARP_OP_DYN_RARP_ERR
    unsigned char ARP_OP_INV_REQUEST
    unsigned char ARP_OP_INV_REPLY
    unsigned char ARP_OP_NAK
    # ETHERTYPES
    uint16_t ETH_TYPE_IPV4
    uint16_t ETH_TYPE_ARP
    uint16_t ETH_TYPE_RARP
    uint16_t ETH_TYPE_8021Q
    uint16_t ETH_TYPE_IPV6
    uint16_t ETH_TYPE_MPLS_UCAST
    uint16_t ETH_TYPE_MPLS_MCAST
    # MPLS
    Py_ssize_t MPLS_MAX_STACK_DEPTH
    # TCP
    unsigned char TCP_MIN_DATA_OFFSET
    Py_ssize_t TCP_QUOTE_LEN
    # ICMP
    unsigned char ICMP_TYPE_ECHO_REPLY
    unsigned char ICMP_TYPE_DU
    unsigned char ICMP_TYPE_SRC_QUENCH
    unsigned char ICMP_TYPE_REDIR
    unsigned char ICMP_TYPE_ECHO
    unsigned char ICMP_TYPE_TIME_EX
    unsigned char ICMP_TYPE_PER_PROB
    unsigned char ICMP_TYPE_TS
    unsigned char ICMP_TYPE_TS_REPLY
    unsigned char ICMP_TYPE_INFO
    unsigned char ICMP_TYPE_INFO_REPLY
    unsigned char ICMP_DU_CODE_NET_UNREACH
    unsigned char ICMP_DU_CODE_HOST_UNREACH
    unsigned char ICMP_DU_CODE_PROTO_UNREACH
    unsigned char ICMP_DU_CODE_PORT_UNREACH
    unsigned char ICMP_DU_CODE_FRAG_NEEDED
    unsigned char ICMP_DU_CODE_SRC_RT_FAIL
    unsigned char ICMP_DU_CODE_DEST_NET_UNKNOWN
    unsigned char ICMP_DU_CODE_DEST_HOST_UNKNOWN
    unsigned char ICMP_DU_CODE_SRC_HOST_ISOLATED
    unsigned char ICMP_DU_CODE_NET_ADMIN_PROHIBIT
    unsigned char ICMP_DU_CODE_HOST_ADMIN_PROHIBIT
    unsigned char ICMP_DU_CODE_NET_TOS_UNREACH
    unsigned char ICMP_DU_CODE_HOST_TOS_UNREACH
    unsigned char ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT
    unsigned char ICMP_DU_CODE_HOST_PRECEDENCE
    unsigned char ICMP_DU_CODE_PRECEDENCE_CUTOFF
    unsigned char ICMP_REDIR_CODE_NET
    unsigned char ICMP_REDIR_CODE_HOST
    unsigned char ICMP_REDIR_CODE_NET_TOS
    unsigned char ICMP_REDIR_CODE_HOST_TOS
    unsigned char ICMP_TIME_EX_CODE_TTL_EXCEEDED
    unsigned char ICMP_TIME_EX_CODE_FRAG_EXCEEDED
    unsigned char ICMP_PER_PROB_CODE_POINTER
    unsigned char ICMP_PER_PROB_CODE_OPTION_MISSING
    unsigned char ICMP_PER_PROB_CODE_LENGTH
    # IGMP
    unsigned char IGMP_MEMBER_QUERY
    unsigned char IGMP_V1_MEMBER_REPORT
    unsigned char IGMP_V2_MEMBER_REPORT
    unsigned char IGMP_V3_MEMBER_REPORT
    unsigned char IGMP_LEAVE_GROUP
    # PROTO IDs
    unsigned char PROTO_IGMP
    unsigned char PROTO_ICMP
    unsigned char PROTO_TCP
    unsigned char PROTO_UDP
    unsigned char PROTO_GRE
    unsigned char PROTO_ICMPV6
    unsigned char IPV6_HDR_LEN
    # ICMPv6 message types (RFC 4443, RFC 4861, RFC 2710, RFC 3810)
    unsigned char ICMP6_DST_UNREACH
    unsigned char ICMP6_PKT_TOO_BIG
    unsigned char ICMP6_TIME_EXCEEDED
    unsigned char ICMP6_PARAM_PROB
    unsigned char ICMP6_ECHO_REQUEST
    unsigned char ICMP6_ECHO_REPLY
    unsigned char ICMP6_MLD_QUERY
    unsigned char ICMP6_MLD_REPORT
    unsigned char ICMP6_MLD_DONE
    unsigned char ICMP6_ND_ROUTER_SOLICIT
    unsigned char ICMP6_ND_ROUTER_ADVERT
    unsigned char ICMP6_ND_NEIGHBOR_SOLICIT
    unsigned char ICMP6_ND_NEIGHBOR_ADVERT
    unsigned char ICMP6_ND_REDIRECT
    unsigned char ICMP6_MLDV2_REPORT
    # Neighbor Discovery option types
    unsigned char ICMP6_OPT_SRC_LLADDR
    unsigned char ICMP6_OPT_TGT_LLADDR
    unsigned char ICMP6_OPT_PREFIX_INFO
    unsigned char ICMP6_OPT_REDIR_HDR
    unsigned char ICMP6_OPT_MTU
    # PACKET QUERY TYPES
    unsigned char PQ_PKT
    unsigned char PQ_ETH
    unsigned char PQ_FRAME
    unsigned char PQ_ICMP
    unsigned char PQ_IGMP
    unsigned char PQ_IGMPv3GroupRecord
    uint16_t PQ_IP
    uint16_t PQ_IP6
    unsigned char PQ_TCP
    unsigned char PQ_UDP
    unsigned char PQ_ICMPV6
    uint16_t PQ_ARP
    uint16_t PQ_MPLS
    unsigned char PQ_GRE
    uint16_t PQ_NETFLOW_SIMPLE
    uint16_t PQ_ICMP6OPT
    uint16_t PQ_MLDV2_ADDRESS_RECORD
    uint16_t PQ_NULLPKT
    unsigned char PTR_VAL
    object offset_re
    char NOT_FOUND = -1
    unsigned char MIN_FRAME_SIZE

cdef uint16_t checksum(const unsigned char[:] data)

cdef unsigned char is_ipv4(str ip)

cdef unsigned char is_ipv6(str ip)

cdef void set_short_nibble(uint16_t* short_word,
                           unsigned char nibble,
                           unsigned char offset)

cdef void set_char_nibble(unsigned char* char_word,
                          unsigned char nibble,
                          unsigned char offset)

cdef uint16_t get_short_nibble(uint16_t short_word,
                               unsigned char offset)

cdef unsigned char get_char_nibble(unsigned char char_word,
                                   unsigned char offset)

cdef void set_bit(uint16_t* flags, unsigned char offset)

cdef void set_word_bit(uint32_t* flags, unsigned char offset)

cdef void set_cbit(unsigned char* flags, unsigned char offset)

cdef void unset_bit(uint16_t* flags, unsigned char offset)

cdef void unset_word_bit(uint32_t* flags, unsigned char offset)

cdef void unset_cbit(unsigned char* flags, unsigned char offset)

cdef class IP_CONST:
    cdef:
        readonly unsigned char IPV4_LEN
        readonly unsigned char IPV4_VER
        readonly unsigned char IPV4_MIN_HDR_LEN
        readonly unsigned char IPV6_LEN
        readonly unsigned char IPV6_VER
        readonly unsigned char MAC_LEN
        readonly unsigned char ARP_TYPE_ETH
        readonly unsigned char ARP_OP_REQUEST
        readonly unsigned char ARP_OP_REPLY
        readonly unsigned char ARP_OP_RARP_REQUEST
        readonly unsigned char ARP_OP_RARP_REPLY
        readonly unsigned char ARP_OP_DYN_RARP_REQUEST
        readonly unsigned char ARP_OP_DYN_RARP_REPLY
        readonly unsigned char ARP_OP_DYN_RARP_ERR
        readonly unsigned char ARP_OP_INV_REQUEST
        readonly unsigned char ARP_OP_INV_REPLY
        readonly unsigned char ARP_OP_NAK
        readonly uint16_t ETH_TYPE_IPV4
        readonly uint16_t ETH_TYPE_ARP
        readonly uint16_t ETH_TYPE_RARP
        readonly uint16_t ETH_TYPE_8021Q
        readonly uint16_t ETH_TYPE_IPV6
        readonly uint16_t ETH_TYPE_MPLS_UCAST
        readonly uint16_t ETH_TYPE_MPLS_MCAST
        readonly Py_ssize_t MPLS_MAX_STACK_DEPTH
        readonly unsigned char TCP_MIN_DATA_OFFSET
        readonly Py_ssize_t TCP_QUOTE_LEN
        readonly unsigned char ICMP_TYPE_ECHO_REPLY
        readonly unsigned char ICMP_TYPE_DU
        readonly unsigned char ICMP_TYPE_SRC_QUENCH
        readonly unsigned char ICMP_TYPE_REDIR
        readonly unsigned char ICMP_TYPE_ECHO
        readonly unsigned char ICMP_TYPE_TIME_EX
        readonly unsigned char ICMP_TYPE_PER_PROB
        readonly unsigned char ICMP_TYPE_TS
        readonly unsigned char ICMP_TYPE_TS_REPLY
        readonly unsigned char ICMP_TYPE_INFO
        readonly unsigned char ICMP_TYPE_INFO_REPLY
        readonly unsigned char ICMP_DU_CODE_NET_UNREACH
        readonly unsigned char ICMP_DU_CODE_HOST_UNREACH
        readonly unsigned char ICMP_DU_CODE_PROTO_UNREACH
        readonly unsigned char ICMP_DU_CODE_PORT_UNREACH
        readonly unsigned char ICMP_DU_CODE_FRAG_NEEDED
        readonly unsigned char ICMP_DU_CODE_SRC_RT_FAIL
        readonly unsigned char ICMP_DU_CODE_DEST_NET_UNKNOWN
        readonly unsigned char ICMP_DU_CODE_DEST_HOST_UNKNOWN
        readonly unsigned char ICMP_DU_CODE_SRC_HOST_ISOLATED
        readonly unsigned char ICMP_DU_CODE_NET_ADMIN_PROHIBIT
        readonly unsigned char ICMP_DU_CODE_HOST_ADMIN_PROHIBIT
        readonly unsigned char ICMP_DU_CODE_NET_TOS_UNREACH
        readonly unsigned char ICMP_DU_CODE_HOST_TOS_UNREACH
        readonly unsigned char ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT
        readonly unsigned char ICMP_DU_CODE_HOST_PRECEDENCE
        readonly unsigned char ICMP_DU_CODE_PRECEDENCE_CUTOFF
        readonly unsigned char ICMP_REDIR_CODE_NET
        readonly unsigned char ICMP_REDIR_CODE_HOST
        readonly unsigned char ICMP_REDIR_CODE_NET_TOS
        readonly unsigned char ICMP_REDIR_CODE_HOST_TOS
        readonly unsigned char ICMP_TIME_EX_CODE_TTL_EXCEEDED
        readonly unsigned char ICMP_TIME_EX_CODE_FRAG_EXCEEDED
        readonly unsigned char ICMP_PER_PROB_CODE_POINTER
        readonly unsigned char ICMP_PER_PROB_CODE_OPTION_MISSING
        readonly unsigned char ICMP_PER_PROB_CODE_LENGTH
        readonly unsigned char IGMP_MEMBER_QUERY
        readonly unsigned char IGMP_V1_MEMBER_REPORT
        readonly unsigned char IGMP_V2_MEMBER_REPORT
        readonly unsigned char IGMP_V3_MEMBER_REPORT
        readonly unsigned char IGMP_LEAVE_GROUP
        readonly unsigned char PROTO_ICMP
        readonly unsigned char PROTO_IGMP
        readonly unsigned char PROTO_TCP
        readonly unsigned char PROTO_UDP
        readonly unsigned char PROTO_GRE
        readonly unsigned char PROTO_ICMPV6
        readonly unsigned char IPV6_HDR_LEN
        readonly unsigned char ICMP6_DST_UNREACH
        readonly unsigned char ICMP6_PKT_TOO_BIG
        readonly unsigned char ICMP6_TIME_EXCEEDED
        readonly unsigned char ICMP6_PARAM_PROB
        readonly unsigned char ICMP6_ECHO_REQUEST
        readonly unsigned char ICMP6_ECHO_REPLY
        readonly unsigned char ICMP6_MLD_QUERY
        readonly unsigned char ICMP6_MLD_REPORT
        readonly unsigned char ICMP6_MLD_DONE
        readonly unsigned char ICMP6_ND_ROUTER_SOLICIT
        readonly unsigned char ICMP6_ND_ROUTER_ADVERT
        readonly unsigned char ICMP6_ND_NEIGHBOR_SOLICIT
        readonly unsigned char ICMP6_ND_NEIGHBOR_ADVERT
        readonly unsigned char ICMP6_ND_REDIRECT
        readonly unsigned char ICMP6_MLDV2_REPORT
        readonly unsigned char ICMP6_OPT_SRC_LLADDR
        readonly unsigned char ICMP6_OPT_TGT_LLADDR
        readonly unsigned char ICMP6_OPT_PREFIX_INFO
        readonly unsigned char ICMP6_OPT_REDIR_HDR
        readonly unsigned char ICMP6_OPT_MTU
        readonly unsigned char PQ_PKT
        readonly unsigned char PQ_ETH
        readonly unsigned char PQ_FRAME
        readonly unsigned char PQ_ICMP
        readonly unsigned char PQ_IGMP
        readonly unsigned char PQ_IGMPv3GroupRecord
        readonly uint16_t PQ_IP
        readonly uint16_t PQ_IP6
        readonly unsigned char PQ_TCP
        readonly unsigned char PQ_UDP
        readonly unsigned char PQ_ICMPV6
        readonly uint16_t PQ_ARP
        readonly uint16_t PQ_MPLS
        readonly unsigned char PQ_GRE
        readonly uint16_t PQ_NETFLOW_SIMPLE
        readonly uint16_t PQ_ICMP6OPT
        readonly uint16_t PQ_MLDV2_ADDRESS_RECORD
        readonly uint16_t PQ_NULLPKT

cdef class PKT:
    cdef:
        dict _l7_ports
        object _decode_context, _decode_exporter
        # Bytes that followed this layer's own declared length. A layer whose
        # header carries a length field parses only that many bytes and keeps
        # whatever the frame had behind them here, so Ethernet padding stays
        # out of the payload without being lost on the way back to the wire.
        bytes _trailer
        public dict query_field_map
        public str pkt_name
        public uint16_t pq_type
        public tuple query_fields

    cdef void _base_l7(self, dict kwargs)

    cpdef PKT get_layer(self, str name, int instance=*, int found=*)

    cpdef PKT get_layer_by_type(self,
                                uint16_t pq_type,
                                int instance=*,
                                int found=*)

    cpdef bytes pkt2net(self, dict kwargs)

    # Append this layer, and everything below it, to a shared output buffer.
    # The base implementation bridges to pkt2net so classes that have not
    # been converted to the writer still serialize correctly.
    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef tuple from_buffer(self, tuple args, dict kwargs)

    cpdef object get_field_val(self, str field)


# Declared here rather than only in the .pyx so protos/dns.pyx can serialize
# through the same shared buffer instead of building its own bytes and going
# back through the PKT._write bridge.
cdef bytes _serialize(PKT p, dict kwargs)


cdef class ARP(PKT):
    cdef:
        # _raw is set only on the non standard hardware/proto length branch,
        # which pkt2net cannot re-pack and so hands straight back. Every
        # other class parses its buffer inside __init__ and keeps nothing.
        bytes _raw
        array _sender_hw_addr, _target_hw_addr
        uint16_t _operation
        public uint16_t hardware_type, proto_type,
        public unsigned char hardware_len, proto_len
        public str sender_proto_addr, target_proto_addr

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class NullPkt(PKT):
    cdef:
        # Public construction stores content directly in _payload. Transport
        # parsing instead retains one immutable owner and a range into it.
        bytes _payload
        bytes _owner
        Py_ssize_t _start, _length

    cdef bytes _payload_bytes(self)

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class Ip4Ph:
    cdef:
        public bytes src, dst
        public unsigned char reserved, proto
        public uint16_t payload_len


cdef class Ip6Ph:
    cdef:
        public bytes src, dst
        public unsigned char nh


cdef class NetflowSimple(PKT):
    cdef:
        public uint16_t version, count
        public uint32_t sys_uptime, unix_secs, unix_nano_seconds
        public bytes payload

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class UDP(PKT):

    cdef:
        public uint16_t sport, dport, ulen, checksum
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cdef app_layer(self, array buf)

    cpdef object get_field_val(self, str field)


cdef class TCP(PKT):

    cdef:
        public uint16_t sport, dport, window, checksum, urg_ptr, ws_len
        uint16_t _off_flags
        public uint32_t sequence, acknowledgment
        bytes _options, _pad
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cdef app_layer(self, array buf)

    cpdef object get_field_val(self, str field)


cdef class IGMPGroupRecord(PKT):
    cdef:
        public unsigned char type, aux_data_len
        public bytes aux_data
        public uint16_t num_src
        bytes _group_address, _source_addresses

    cpdef object get_field_val(self, str field)

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class IGMP(PKT):
    cdef:
        public unsigned char version, type, max_resp, qqic, reserved1
        public uint16_t checksum, num_records
        public list group_records
        public uint16_t reserved2
        unsigned char _s_qrv
        bytes _group_address, _source_addresses

    cpdef object get_field_val(self, str field)

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class ICMP(PKT):
    cdef:
        public array data
        # Only the unsupported-type fallback keeps its bytes, so pkt2net can
        # hand back exactly what came in.
        bytes _raw
        bint have_data
        public unsigned char type, code, pointer
        public uint16_t checksum, identifier, sequence, mtu
        public uint32_t orig_ts, rec_ts, trans_ts
        public PKT hdr_pkt
        public bytes echo_data
        bytes _address

    cpdef object get_field_val(self, str field)

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

cdef class IP(PKT):

    cdef:
        bytes _src, _dst
        array _pad
        uint16_t _flags_offset
        unsigned char _version_iphl, _proto
        Ip4Ph ipv4_pheader

        public unsigned char ttl, tos
        public uint16_t checksum, total_len, ident
        public PKT payload
        public bytes options


    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class IP6(PKT):

    cdef:
        bytes _src, _dst
        uint32_t _v_tc_flow
        unsigned char _nh, _upper_proto
        bytes _ext_hdrs
        Ip6Ph ipv6_pheader

        public unsigned char hop_limit
        public uint16_t payload_len
        public PKT payload
        # True when the extension header chain ran past the bytes present,
        # so the real upper layer protocol could not be reached and the
        # remainder was kept as opaque bytes. The walk used to stop at that
        # point without telling anyone, and since the last next-header value
        # it held was always an extension header the payload landed in the
        # same fall through branch a genuinely unknown protocol would - the
        # two were indistinguishable to a caller.
        readonly bint ext_hdrs_truncated

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class ICMP6Opt(PKT):
    cdef:
        # The option value exactly as it appeared on the wire -- everything
        # after the 2 byte type/length header, including any padding the
        # sender used to reach the 8 byte boundary. Keeping it verbatim is
        # what lets an option this class does not interpret round trip.
        bytes _data
        public unsigned char type, length

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class MLDv2AddressRecord(PKT):
    cdef:
        public unsigned char type, aux_data_len
        public bytes aux_data
        public uint16_t num_src
        bytes _multicast_address, _source_addresses

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class ICMP6(PKT):
    cdef:
        bytes _body
        public unsigned char type, code
        public uint16_t checksum, identifier, sequence
        public bytes echo_data
        # Error messages (1-4): the 32 bit word between the header and the
        # packet that provoked the error. Unused for types 1 and 3, the MTU
        # for type 2 and the pointer for type 4 -- see the mtu and pointer
        # properties.
        uint32_t _err_word
        public PKT hdr_pkt
        # Neighbor Discovery (133-137)
        public unsigned char cur_hop_limit
        public uint16_t router_lifetime
        public uint32_t reachable_time, retrans_timer
        unsigned char _ra_flags, _na_flags
        bytes _target_address, _dest_address
        public list options
        # MLD (130-132) and MLDv2 (130 long form, 143)
        public uint16_t max_resp, num_src, num_records
        public unsigned char qqic, mld_version
        unsigned char _s_qrv
        bytes _multicast_address, _source_addresses
        public list records

    cdef int _parse_options_buffer(self, array buf,
                                   Py_ssize_t off) except -1
    cdef int _parse_options(self, bytes owner, Py_ssize_t off,
                            Py_ssize_t end) except -1

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class MPLS(PKT):
    cdef:
        uint32_t _data
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class Ethernet(PKT):

    cdef:
        array _src_mac, _dst_mac
        uint16_t _tci
        public uint16_t type, tpid
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class GRE(PKT):
    cdef:
        # Set only on the malformed path to the exact parsed byte range, so a
        # truncated or unparsable GRE re-serializes to what came in rather than
        # to a reconstructed header (the option words are gone, so they cannot
        # be rebuilt from the flag bits). Mirrors ARP._raw.
        bytes _raw
        # Raw first two header bytes: C|R|K|S|s|Recur|A|Flags|Ver, kept whole so
        # reserved bits round-trip untouched. Presence bits are read from here
        # and exposed through the c/k/s/ack/version properties.
        uint16_t _flags
        # 16 bits following the checksum, present only when C is set.
        uint16_t _reserved1
        public uint16_t proto
        public uint16_t checksum
        public uint32_t key
        # NVGRE (RFC 7637) reinterpretation of the key: 24-bit VSID and 8-bit
        # FlowID. Populated from key whenever K is set.
        public uint32_t vsid
        public unsigned char flowid
        public uint32_t sequence
        public uint32_t ack
        # Set when a header field was truncated. Readonly from Python; the
        # decoder writes it. This is the malformed-flag convention every later
        # routing protocol inherits.
        readonly bint malformed
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


# Private owner/range parser entry points.  Public constructors use these
# after normalizing bytes/array input to one immutable bytes owner.
cdef bytes _owned_buffer(tuple args, dict kwargs)
cdef int _decode_arp(ARP pkt, bytes owner, Py_ssize_t start,
                     Py_ssize_t end) except -1
cdef int _decode_netflow_simple(NetflowSimple pkt, bytes owner,
                                Py_ssize_t start,
                                Py_ssize_t end) except -1
cdef int _decode_icmp(ICMP pkt, bytes owner, Py_ssize_t start,
                      Py_ssize_t end) except -1
cdef int _decode_igmp_group_record(IGMPGroupRecord pkt, bytes owner,
                                   Py_ssize_t start,
                                   Py_ssize_t end) except -1
cdef int _decode_igmp(IGMP pkt, bytes owner, Py_ssize_t start,
                      Py_ssize_t end, object packet_len_arg) except -1
cdef int _decode_icmp6_opt(ICMP6Opt pkt, bytes owner, Py_ssize_t start,
                           Py_ssize_t end) except -1
cdef int _decode_mldv2_address_record(MLDv2AddressRecord pkt, bytes owner,
                                      Py_ssize_t start,
                                      Py_ssize_t end) except -1
cdef int _decode_icmp6(ICMP6 pkt, bytes owner, Py_ssize_t start,
                       Py_ssize_t end) except -1
cdef int _decode_eth_ip_udp_fast(Ethernet pkt, bytes owner,
                                 const unsigned char[:] mv,
                                 Py_ssize_t end) except -1
cdef NullPkt _null_range(bytes owner, Py_ssize_t start,
                         Py_ssize_t end, dict l7_ports)
cdef PKT _l7_range(bytes owner, const unsigned char[:] mv,
                   Py_ssize_t start, Py_ssize_t end, dict l7_ports,
                   uint16_t sport, uint16_t dport,
                   object decode_context, object exporter_source,
                   str transport)
cdef int _decode_udp(UDP pkt, bytes owner,
                     const unsigned char[:] mv, Py_ssize_t start,
                     Py_ssize_t end, dict l7_ports) except -1
cdef int _decode_tcp(TCP pkt, bytes owner,
                     const unsigned char[:] mv, Py_ssize_t start,
                     Py_ssize_t end, dict l7_ports,
                     dict kwargs) except -1
cdef int _decode_ip(IP pkt, bytes owner,
                    const unsigned char[:] mv, Py_ssize_t start,
                    Py_ssize_t end, dict l7_ports) except -1
cdef unsigned char _walk_ip6_ext_range(
        const unsigned char[:] mv, Py_ssize_t start, Py_ssize_t end,
        unsigned char first_nh, Py_ssize_t *ext_len, bint *incomplete,
        bint *truncated)
cdef int _decode_ip6(IP6 pkt, bytes owner,
                     const unsigned char[:] mv, Py_ssize_t start,
                     Py_ssize_t end, dict l7_ports) except -1
cdef int _decode_mpls(MPLS pkt, bytes owner, const unsigned char[:] mv,
                      Py_ssize_t start, Py_ssize_t end,
                      dict l7_ports) except -1
cdef int _decode_gre(GRE pkt, bytes owner, const unsigned char[:] mv,
                     Py_ssize_t start, Py_ssize_t end,
                     dict l7_ports) except -1
cdef int _decode_ethernet(Ethernet pkt, bytes owner,
                          const unsigned char[:] mv,
                          Py_ssize_t start, Py_ssize_t end,
                          dict l7_ports) except -1
