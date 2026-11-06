# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint16_t, uint32_t

from packets.routing.rtengine.rib.prefix cimport Prefix
from packets.routing.rtengine.plugins.bgp.attrs cimport AttrSet


# --- Message framing --------------------------------------------------------

cdef enum:
    BGP_VERSION = 4
    BGP_HEADER_LEN = 19
    # RFC 4271 s4.1. Both limits are enforced per session, never globally:
    # which one applies depends on what was negotiated, and on the message
    # type even then (Key Decision 14 / RFC 8654).
    BGP_MAX_MSG = 4096
    BGP_MAX_MSG_EXT = 65535
    BGP_MIN_OPEN = 29          # header + 10 fixed OPEN bytes
    BGP_MIN_UPDATE = 23        # header + two 2-byte length fields

    MSG_OPEN = 1
    MSG_UPDATE = 2
    MSG_NOTIFICATION = 3
    MSG_KEEPALIVE = 4
    MSG_ROUTE_REFRESH = 5


# --- Path attribute type codes and flags ------------------------------------
# rtengine keeps its own copy of these rather than reaching into the
# dissector's private value-string dicts: those exist to render text and are
# free to change their spelling, while these are a wire contract.

cdef enum:
    ATTR_ORIGIN = 1
    ATTR_AS_PATH = 2
    ATTR_NEXT_HOP = 3
    ATTR_MED = 4
    ATTR_LOCAL_PREF = 5
    ATTR_ATOMIC_AGGREGATE = 6
    ATTR_AGGREGATOR = 7
    ATTR_COMMUNITIES = 8
    ATTR_ORIGINATOR_ID = 9
    ATTR_CLUSTER_LIST = 10
    ATTR_MP_REACH = 14
    ATTR_MP_UNREACH = 15
    ATTR_EXT_COMMUNITIES = 16
    ATTR_AS4_PATH = 17
    ATTR_AS4_AGGREGATOR = 18
    ATTR_LARGE_COMMUNITY = 32

    AFLAG_OPTIONAL = 0x80
    AFLAG_TRANSITIVE = 0x40
    AFLAG_PARTIAL = 0x20
    AFLAG_EXT_LEN = 0x10
    # The four flag bits that are defined. The low nibble is "MUST be zero"
    # in RFC 4271 and is ignored on receive rather than treated as an error,
    # because RFC 7606 s4 says so explicitly.
    AFLAG_DEFINED = 0xf0


cdef class DecodeCtx:
    # What the decoder needs to know about the session it is decoding for.
    #
    # Every one of these changes how identical bytes are read, which is why
    # they are a required argument rather than module state: two sessions on
    # one engine can disagree about all four at once, and a decoder that
    # guessed would silently mis-parse the quieter peer.

    cdef readonly bint as4              # 4-octet ASNs in AS_PATH on the wire
    cdef readonly bint is_ebgp
    cdef readonly uint32_t local_as
    cdef readonly uint32_t peer_as
    # (afi, safi) pairs for which ADD-PATH receive was negotiated, so NLRI
    # in those families carries a 4-byte path id.
    cdef readonly frozenset add_path
    cdef readonly Py_ssize_t max_msg
    # (afi, safi) pairs negotiated for the session. An MP attribute for any
    # other family is recorded as unnegotiated and ignored (RFC 4760 s7).
    # Empty means "not restricted", for decoding outside a session.
    cdef readonly frozenset families

    cdef bint _add_path_for(self, uint16_t afi, unsigned char safi)


cdef class Framer:
    # Splits a TCP byte stream into whole BGP messages.
    #
    # BGP runs over a stream, so a read can deliver half a message, three
    # messages, or a message split across five reads. The framer is the one
    # place that knows that, and it is deliberately the only place: every
    # decoder below takes a complete message and may assume it is complete.

    cdef bytearray _buf
    cdef Py_ssize_t _start
    cdef readonly Py_ssize_t max_msg
    cdef readonly Py_ssize_t messages
    cdef readonly Py_ssize_t bytes_in
    # Set when the stream is no longer trustworthy -- a bad marker, an
    # impossible length. Framing cannot resynchronise after either, so the
    # framer latches the fault and the session must be reset.
    cdef readonly int error_code
    cdef readonly int error_subcode
    cdef readonly str error_detail
    # The NOTIFICATION data field RFC 4271 s6.1 requires: the erroneous
    # Length field for 1/2, the erroneous Type for 1/3. None otherwise.
    cdef readonly bytes error_data
    cdef int _fault(self, int code, int subcode, str detail,
                    bytes data) except -1


cdef class OpenMsg:
    cdef readonly unsigned char version
    cdef readonly uint32_t my_as          # already widened from the cap
    cdef readonly uint16_t my_as_wire     # exactly what the header carried
    cdef readonly uint16_t hold_time
    cdef readonly uint32_t bgp_id
    cdef readonly list capabilities       # [(code, value_bytes)]
    cdef readonly list unsupported_params # non-capability optional params
    cdef readonly list errors


cdef class UpdateMsg:
    # An UPDATE parsed completely, and applied by nobody yet.
    #
    # Two-phase is the whole design (Key Decision 13): the decoder never
    # mutates a RIB, so an UPDATE that turns out to be malformed halfway
    # through has not already half-applied itself. `errors` carries what
    # went wrong, and the caller runs the RFC 7606 matrix over it to decide
    # between discarding an attribute, withdrawing the NLRI and resetting
    # the session.

    cdef readonly list withdrawn     # [(Prefix, path_id)]
    cdef readonly list nlri          # [(Prefix, path_id)]
    cdef readonly AttrSet attrs
    cdef readonly bint has_attrs
    # MP_REACH / MP_UNREACH, one tuple each or None:
    #   reach:   (afi, safi, nexthop, nexthop_local, [(Prefix, path_id)])
    #   unreach: (afi, safi, [(Prefix, path_id)])
    cdef readonly tuple mp_reach
    cdef readonly tuple mp_unreach
    cdef readonly list errors
    cdef readonly bint end_of_rib
    # NLRI entries, in any field, whose bits past the prefix length were not
    # zero. They are masked off -- RFC 4271 only requires the trailing bits
    # be "irrelevant" -- and counted, because a peer that sends them is
    # usually one whose prefixes are not what its operator thinks they are.
    cdef readonly Py_ssize_t host_bits


cdef class NotificationMsg:
    cdef readonly unsigned char code
    cdef readonly unsigned char subcode
    cdef readonly bytes data


cdef class RouteRefreshMsg:
    cdef readonly uint16_t afi
    cdef readonly unsigned char safi
    # RFC 7313 subtype: 0 normal, 1 BoRR, 2 EoRR. Carried in the byte
    # RFC 2918 reserved, which is why a plain route-refresh reads as 0.
    cdef readonly unsigned char subtype
