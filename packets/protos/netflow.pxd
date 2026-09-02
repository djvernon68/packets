# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint32_t, uint16_t

from packets.core.inetpkt cimport PKT, PktWriter


cdef struct NetflowCodecOperation:
    Py_ssize_t field_length
    Py_ssize_t fixed_offset
    int codec_type
    int variable_length


cdef class NetflowTemplateRegistry:
    cdef:
        public dict templates


cdef class NetflowDecodeContext:
    cdef:
        public dict templates
        public object registry
        public bint force_simple


cdef class NetflowSimple(PKT):
    cdef:
        public uint16_t version, count
        public uint32_t sys_uptime, unix_secs, unix_nano_seconds
        public bytes payload

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1

    cpdef object get_field_val(self, str field)


cdef class NetflowV1Header:
    cdef:
        public object version, count, sys_uptime, unix_secs, unix_nsecs

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowV5Header:
    cdef:
        public object version, count, sys_uptime, unix_secs, unix_nsecs
        public object flow_sequence, engine_type, engine_id, sampling_interval

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowV9Header:
    cdef:
        public object version, count, sys_uptime, unix_secs, sequence, source_id

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class IPFIXHeader:
    cdef:
        public object version, length, export_time, sequence
        public object observation_domain_id

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowV7Header:
    cdef:
        public object version, count, sys_uptime, unix_secs, unix_nsecs
        public object flow_sequence, reserved

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowV1Record:
    cdef:
        public object src_addr, dst_addr, next_hop, input_snmp, output_snmp
        public object packets, octets, first, last, src_port, dst_port
        public object pad1, protocol, tos, pad2, reserved

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowV5Record:
    cdef:
        public object src_addr, dst_addr, next_hop, input_snmp, output_snmp
        public object packets, octets, first, last, src_port, dst_port
        public object pad1, tcp_flags, protocol, tos, src_as, dst_as
        public object src_mask, dst_mask, pad2

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowV7Record:
    cdef:
        public object src_addr, dst_addr, next_hop, input_snmp, output_snmp
        public object packets, octets, first, last, src_port, dst_port
        public object pad1, tcp_flags, protocol, tos, src_as, dst_as
        public object src_mask, dst_mask, pad2, router_sc

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowTemplateField:
    cdef:
        public object element_id, field_length, enterprise_number
        public object name, data_type, variable_length

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowTemplate:
    cdef:
        public object template_id, fields, options, version, withdrawn
        public object codec_plan, record_class

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowOptionsTemplate(NetflowTemplate):
    cdef:
        public object scope_fields, option_fields

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowFieldMap:
    cdef:
        dict _values, _aliases

    cdef dict _as_dict(self)


cdef class NetflowCodecPlan:
    cdef:
        readonly tuple signature, operations
        readonly tuple codec_fields, keys, identities
        dict aliases
        readonly object record_class
        readonly bint has_variable
        NetflowCodecOperation *c_operations
        Py_ssize_t operation_count

    cpdef tuple decode(self, bytes data, int offset, object template)

    cpdef bytes encode(self, object record)

    cdef NetflowDataRecord _decode_record(
        self, bytes data, const unsigned char[:] mv,
        Py_ssize_t *result_offset, object template)

    cdef int _write_record(self, PktWriter w, object record) except -1


cdef class NetflowDataRecord:
    cdef:
        public object template_id, fields, template, codec_plan
        object _raw_data, _raw_owner, _raw_fields, _raw_ranges
        object _original_fields, _original_values
        Py_ssize_t _raw_start, _raw_length

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class NetflowFlowSet:
    cdef:
        public object set_id, length, templates, records, raw_data, padding
        public object malformed, version

    cpdef bytes pkt2net(self, dict kwargs=*)

    cdef int _write(self, PktWriter w, dict kwargs) except -1


cdef class Netflow(PKT):
    cdef:
        public object version, header, flowsets, records, raw_data
        public object context, exporter
        bytes _wire_data
        bint _parsed, _requires_simple

    cdef void _parse(self, bytes data)

    cpdef object get_field_val(self, str field)

    cpdef bytes pkt2net(self, dict kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1
