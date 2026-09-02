# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint8_t, uint16_t, uint32_t

from packets.core.inetpkt cimport PKT, PktWriter


# The constants intentionally cover the common protocol vocabulary while the
# option classes themselves remain generic. Unknown option and message values
# are therefore data, not parse errors.
cpdef enum:
    DHCP_PACKET_TYPE = 67
    DHCP_CLIENT_PORT = 68
    DHCP_SERVER_PORT = 67
    DHCP_BOOTREQUEST = 1
    DHCP_BOOTREPLY = 2
    DHCP_MAGIC = 0x63825363
    DHCP_OPT_PAD = 0
    DHCP_OPT_SUBNET_MASK = 1
    DHCP_OPT_ROUTER = 3
    DHCP_OPT_DOMAIN_NAME_SERVER = 6
    DHCP_OPT_HOST_NAME = 12
    DHCP_OPT_DOMAIN_NAME = 15
    DHCP_OPT_REQUESTED_IP = 50
    DHCP_OPT_LEASE_TIME = 51
    DHCP_OPT_OVERLOAD = 52
    DHCP_OPT_MESSAGE_TYPE = 53
    DHCP_OPT_SERVER_IDENTIFIER = 54
    DHCP_OPT_PARAMETER_REQUEST_LIST = 55
    DHCP_OPT_MESSAGE = 56
    DHCP_OPT_MAX_MESSAGE_SIZE = 57
    DHCP_OPT_RENEWAL_TIME = 58
    DHCP_OPT_REBINDING_TIME = 59
    DHCP_OPT_VENDOR_CLASS_IDENTIFIER = 60
    DHCP_OPT_CLIENT_IDENTIFIER = 61
    DHCP_OPT_END = 255
    DHCP_DISCOVER = 1
    DHCP_OFFER = 2
    DHCP_REQUEST = 3
    DHCP_DECLINE = 4
    DHCP_ACK = 5
    DHCP_NAK = 6
    DHCP_RELEASE = 7
    DHCP_INFORM = 8

    DHCP6_PACKET_TYPE = 547
    DHCP6_CLIENT_PORT = 546
    DHCP6_SERVER_PORT = 547
    DHCP6_SOLICIT = 1
    DHCP6_ADVERTISE = 2
    DHCP6_REQUEST = 3
    DHCP6_CONFIRM = 4
    DHCP6_RENEW = 5
    DHCP6_REBIND = 6
    DHCP6_REPLY = 7
    DHCP6_RELEASE = 8
    DHCP6_DECLINE = 9
    DHCP6_RECONFIGURE = 10
    DHCP6_INFORMATION_REQUEST = 11
    DHCP6_RELAY_FORWARD = 12
    DHCP6_RELAY_REPLY = 13


cdef class DHCPOption:
    cdef:
        public uint8_t code
        public bytes data

    cpdef bytes pkt2net(self, dict kwargs)
    cdef int _write(self, PktWriter w) except -1


cdef class DHCP(PKT):
    cdef:
        public uint8_t op, htype, hlen, hops
        public uint32_t xid, magic
        public uint16_t secs, flags
        bytes _ciaddr, _yiaddr, _siaddr, _giaddr
        public bytes chaddr, sname, file, data
        public list options

    cpdef object get_field_val(self, str field)
    cpdef bytes pkt2net(self, dict kwargs)
    cdef int _parse_message(self, const unsigned char[:] mv) except -1
    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class DHCP6Option:
    cdef:
        public uint16_t code
        public bytes data

    cpdef bytes pkt2net(self, dict kwargs)
    cdef int _write(self, PktWriter w) except -1


cdef class DHCP6(PKT):
    cdef:
        public uint8_t msg_type, hop_count
        public uint32_t transaction_id
        bytes _link_address, _peer_address
        public list options

    cpdef object get_field_val(self, str field)
    cpdef bytes pkt2net(self, dict kwargs)
    cdef int _parse_message(self, const unsigned char[:] mv) except -1
    cdef int _write(self, PktWriter w, dict kwargs) except -1
