# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from cpython.array cimport array
from libc.stdint cimport int64_t, uint64_t, \
    int32_t, uint32_t, uint16_t, intptr_t

from packets.core.inetpkt cimport PKT, PktWriter

cpdef enum:
    # global
    # for pointer dereference
    PNTR=0
    # dns specific
    DNS_PACKET_TYPE = 53
    DNS_PACKET_PORT = 53
    DNSTYPE_ANY = 0
    DNSTYPE_A = 1
    DNSTYPE_NS = 2
    DNSTYPE_CNAME = 5
    DNSTYPE_SOA = 6
    DNSTYPE_WKS = 11
    DNSTYPE_PTR = 12
    DNSTYPE_HINFO = 13
    DNSTYPE_MX = 15
    DNSTYPE_TXT = 16
    DNSTYPE_SIG = 24
    DNSTYPE_KEY = 25
    DNSTYPE_GPOS = 27
    DNSTYPE_AAAA = 28
    DNSTYPE_LOC = 29
    DNSTYPE_EID = 31
    DNSTYPE_SRV = 33
    DNSTYPE_KX = 36
    DNSTYPE_CERT = 37
    DNSTYPE_OPT = 41
    DNSTYPE_RRSIG = 46
    DNSTYPE_NSEC = 47
    DNSTYPE_DNSKEY = 48
    DNSTYPE_DHCID = 49
    DNSTYPE_NSEC3 = 50
    DNSTYPE_NSEC3PARAM = 51
    DNSTYPE_IXFR = 251
    DNSTYPE_AXFR = 252
    DNSTYPE_ALL = 255
    DNSTYPE_RESERVED = 65535
    OPTCODE_QUERY = 0
    OPTCODE_STATUS = 2
    OPTCODE_NOTIFY = 4
    OPTCODE_UPDATE = 5
    RCODE_NOERROR = 0
    RCODE_FORMERR = 1
    RCODE_SERVFAIL = 2
    RCODE_NXDOMAIN = 3
    RCODE_NOTIMP = 4
    RCODE_REFUSED = 5
    RCODE_YXDOMAIN = 6
    RCODE_YXRRSET = 7
    RCODE_NXRRSET = 8
    RCODE_NOTAUTH = 9
    RCODE_NOTZONE = 10
    RCLASS_IN = 1
    RCLASS_NONE = 254
    RCLASS_ANY = 255
    LABEL = 49152
    SOA_MNAME = 2
    SOA_RNAME = 4
    SOA_SER = 6
    SOA_REF = 8
    SOA_RET = 10
    SOA_EXP = 12
    SOA_MIN = 14

cdef array hostname_to_label_array(bytes hostname)

# The per-message store maps wire offsets to already resolved suffix strings;
# the parse path never needs the writer's reverse suffix-to-offset mapping.
cdef str read_dns_name_bytes(const unsigned char[:] byte_array,
                             uint16_t* offset,
                             dict label_store)

# The write side no longer carries its own offset counter. RFC 1035
# compression pointers are relative to the start of the DNS message, and the
# writer already knows where that is, so the pointer value is w.n - dns_start
# and every one of these takes dns_start instead of a uint16_t*.
cdef int w_dns_name(PktWriter w,
                    str dns_name,
                    Py_ssize_t dns_start,
                    dict labels,
                    bint compress=*) except -1

cdef tuple parse_resource(const unsigned char[:] byte_array,
                          uint16_t* offset,
                          dict label_store)

cdef str parse_soa(const unsigned char[:] res_data, uint16_t* offset,
                   uint16_t* rlen, dict labels)

cdef int w_soa(PktWriter w, str res_data, Py_ssize_t dns_start, dict labels,
               bint compress=*) except -1


cdef class DNSQuery:
    cdef:
        str _query_name
        public uint16_t query_type, query_class

    cdef int _write(self, PktWriter w, Py_ssize_t dns_start, dict labels,
                    bint compress=*) except -1


cdef class DNSResource:
    cdef:
        str _domain_name
        public uint16_t res_type, res_class, res_len
        public uint32_t res_ttl
        public str res_data

    cdef int _write(self, PktWriter w,
                          Py_ssize_t dns_start,
                          dict labels,
                          bint compress=*,
                          bint update=*) except -1


cdef class DNS(PKT):
    cdef:
        public uint16_t ident, query_count, answer_count, auth_count, ad_count
        uint16_t _flags
        public list queries, answers, authority, ad
        dict labels

    cpdef object get_field_val(self, str field)

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _parse_message(self, const unsigned char[:] mv) except -1

    cdef int _write(self, PktWriter w, dict kwargs) except -1
