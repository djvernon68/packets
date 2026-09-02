# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from packets.core.inetpkt cimport PKT, PktWriter


cpdef enum:
    HTTP_PACKET_TYPE = 80
    HTTP_PACKET_PORT = 80


cdef class HTTPRequest(PKT):
    cdef:
        public bytes method, target, version, body, data
        public list headers, trailers
        bint _chunked
        bytes _chunk_wire, _chunk_body
        tuple _chunk_trailers

    cpdef object get_header(self, object name, object default=*)
    cpdef list get_headers(self, object name)
    cpdef object get_field_val(self, str field)
    cpdef bytes pkt2net(self, dict kwargs)
    cdef int _parse_message(self, const unsigned char[:] mv) except -1
    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class HTTPResponse(PKT):
    cdef:
        public bytes version, status, reason, body, data
        public list headers, trailers
        bint _chunked
        bytes _chunk_wire, _chunk_body
        tuple _chunk_trailers

    cpdef object get_header(self, object name, object default=*)
    cpdef list get_headers(self, object name)
    cpdef object get_field_val(self, str field)
    cpdef bytes pkt2net(self, dict kwargs)
    cdef int _parse_message(self, const unsigned char[:] mv) except -1
    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class HTTP(PKT):
    cdef:
        public object message

    cpdef object get_header(self, object name, object default=*)
    cpdef list get_headers(self, object name)
    cpdef object get_field_val(self, str field)
    cpdef bytes pkt2net(self, dict kwargs)
    cdef int _write(self, PktWriter w, dict kwargs) except -1
