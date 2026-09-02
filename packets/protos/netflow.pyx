# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

import socket
import struct
import zlib

from collections import OrderedDict

from cpython.array cimport array
from cpython.mem cimport PyMem_Free, PyMem_Malloc
from cpython.ref cimport Py_INCREF
from cpython.tuple cimport PyTuple_New, PyTuple_SET_ITEM
from libc.stdio cimport snprintf

cdef extern from "Python.h":
    object PyUnicode_DecodeUTF8(const char *string, Py_ssize_t size,
                                const char *errors)
    object PyUnicode_FromString(const char *string)

cdef extern from "sys/socket.h":
    cdef enum:
        AF_INET
        AF_INET6

cdef extern from "arpa/inet.h":
    const char *inet_ntop(int af, const void *src, char *dst,
                          unsigned int size)

from packets.core.inetpkt cimport PKT, PktWriter, _fmt_ipv4_buf, _serialize, \
    need_bytes, rd_bytes, rd_u16, rd_u32, w_acquire, w_bytes, w_release, \
    w_set_u16, w_take, w_u8, w_u16, w_u32

# NetflowSimple stays in packets.core.inetpkt and is re-exported here rather
# than reimplemented. The core layer 7 dispatch has a C level fast path keyed
# on that exact extension type (_l7_range -> _decode_netflow_simple), so a
# second class of the same name would both break isinstance for callers that
# import it from inetpkt and silently disable that fast path.
from packets.core.inetpkt import NetflowSimple


NETFLOW_PACKET_TYPE = 2055
NETFLOW_PACKET_PORT = 2055
NETFLOW_SIMPLE_PACKET_TYPE = 2005
NETFLOW_V1_HEADER_LEN = 16
NETFLOW_V1_RECORD_LEN = 48
NETFLOW_V5_HEADER_LEN = 24
NETFLOW_V5_RECORD_LEN = 48
NETFLOW_V7_HEADER_LEN = 24
NETFLOW_V7_RECORD_LEN = 52
NETFLOW_V9_HEADER_LEN = 20
IPFIX_HEADER_LEN = 16

cdef int CODEC_BYTES = 0
cdef int CODEC_UNSIGNED = 1
cdef int CODEC_IPV4 = 2
cdef int CODEC_IPV6 = 3
cdef int CODEC_MAC = 4
cdef int CODEC_STRING = 5

INFORMATION_ELEMENTS = {
    1: ('octetDeltaCount', 'unsigned'),
    2: ('packetDeltaCount', 'unsigned'),
    3: ('deltaFlowCount', 'unsigned'),
    4: ('protocolIdentifier', 'unsigned'),
    5: ('ipClassOfService', 'unsigned'),
    6: ('tcpControlBits', 'unsigned'),
    7: ('sourceTransportPort', 'unsigned'),
    8: ('sourceIPv4Address', 'ipv4'),
    9: ('sourceIPv4PrefixLength', 'unsigned'),
    10: ('ingressInterface', 'unsigned'),
    11: ('destinationTransportPort', 'unsigned'),
    12: ('destinationIPv4Address', 'ipv4'),
    13: ('destinationIPv4PrefixLength', 'unsigned'),
    14: ('egressInterface', 'unsigned'),
    15: ('ipNextHopIPv4Address', 'ipv4'),
    16: ('bgpSourceAsNumber', 'unsigned'),
    17: ('bgpDestinationAsNumber', 'unsigned'),
    18: ('bgpNextHopIPv4Address', 'ipv4'),
    21: ('flowEndSysUpTime', 'unsigned'),
    22: ('flowStartSysUpTime', 'unsigned'),
    23: ('postOctetDeltaCount', 'unsigned'),
    24: ('postPacketDeltaCount', 'unsigned'),
    27: ('sourceIPv6Address', 'ipv6'),
    28: ('destinationIPv6Address', 'ipv6'),
    29: ('sourceIPv6PrefixLength', 'unsigned'),
    30: ('destinationIPv6PrefixLength', 'unsigned'),
    31: ('flowLabelIPv6', 'unsigned'),
    32: ('icmpTypeCodeIPv4', 'unsigned'),
    34: ('samplingInterval', 'unsigned'),
    35: ('samplingAlgorithm', 'unsigned'),
    40: ('exportedOctetTotalCount', 'unsigned'),
    41: ('exportedMessageTotalCount', 'unsigned'),
    42: ('exportedFlowRecordTotalCount', 'unsigned'),
    44: ('sourceIPv4Prefix', 'ipv4'),
    45: ('destinationIPv4Prefix', 'ipv4'),
    56: ('sourceMacAddress', 'mac'),
    57: ('postDestinationMacAddress', 'mac'),
    58: ('vlanId', 'unsigned'),
    59: ('postVlanId', 'unsigned'),
    60: ('ipVersion', 'unsigned'),
    61: ('flowDirection', 'unsigned'),
    62: ('ipNextHopIPv6Address', 'ipv6'),
    63: ('bgpNextHopIPv6Address', 'ipv6'),
    80: ('destinationMacAddress', 'mac'),
    81: ('postSourceMacAddress', 'mac'),
    82: ('interfaceName', 'string'),
    83: ('interfaceDescription', 'string'),
    85: ('octetTotalCount', 'unsigned'),
    86: ('packetTotalCount', 'unsigned'),
    130: ('exporterIPv4Address', 'ipv4'),
    131: ('exporterIPv6Address', 'ipv6'),
    136: ('flowEndReason', 'unsigned'),
    138: ('observationPointId', 'unsigned'),
    139: ('icmpTypeCodeIPv6', 'unsigned'),
    144: ('exportingProcessId', 'unsigned'),
    145: ('templateId', 'unsigned'),
    147: ('wlanSSID', 'string'),
    148: ('flowId', 'unsigned'),
    149: ('observationDomainId', 'unsigned'),
    150: ('flowStartSeconds', 'unsigned'),
    151: ('flowEndSeconds', 'unsigned'),
    152: ('flowStartMilliseconds', 'unsigned'),
    153: ('flowEndMilliseconds', 'unsigned'),
    154: ('flowStartMicroseconds', 'unsigned'),
    155: ('flowEndMicroseconds', 'unsigned'),
    156: ('flowStartDeltaMicroseconds', 'unsigned'),
    157: ('flowEndDeltaMicroseconds', 'unsigned'),
    176: ('icmpTypeIPv4', 'unsigned'),
    177: ('icmpCodeIPv4', 'unsigned'),
    178: ('icmpTypeIPv6', 'unsigned'),
    179: ('icmpCodeIPv6', 'unsigned'),
    180: ('udpSourcePort', 'unsigned'),
    181: ('udpDestinationPort', 'unsigned'),
    182: ('tcpSourcePort', 'unsigned'),
    183: ('tcpDestinationPort', 'unsigned'),
    184: ('tcpSequenceNumber', 'unsigned'),
    185: ('tcpAcknowledgementNumber', 'unsigned'),
    186: ('tcpWindowSize', 'unsigned'),
    187: ('tcpUrgentPointer', 'unsigned'),
    188: ('tcpHeaderLength', 'unsigned'),
    189: ('ipHeaderLength', 'unsigned'),
    190: ('totalLengthIPv4', 'unsigned'),
    191: ('payloadLengthIPv6', 'unsigned'),
    192: ('ipTTL', 'unsigned'),
    193: ('nextHeaderIPv6', 'unsigned'),
    195: ('ipDiffServCodePoint', 'unsigned'),
    196: ('ipPrecedence', 'unsigned'),
    197: ('fragmentFlags', 'unsigned'),
    211: ('collectorIPv4Address', 'ipv4'),
    212: ('collectorIPv6Address', 'ipv6'),
    214: ('exportProtocolVersion', 'unsigned'),
    215: ('exportTransportProtocol', 'unsigned'),
    216: ('collectorTransportPort', 'unsigned'),
    217: ('exporterTransportPort', 'unsigned'),
}

# Keyed on a template's field signature, so two exporters sending the same
# template shape share one codec plan and one generated record class. Each
# entry pins a dynamically created Python class for as long as it is here,
# and a collector sees a new signature for every exporter that varies its
# template or revises it, so an unbounded dict was a slow leak on any long
# lived process: clearing the decode context did not touch it, because the
# cache is deliberately wider than one context. Bounded and used in least
# recently used order instead - an evicted signature simply costs one
# rebuild the next time it is seen.
_TEMPLATE_ARTIFACT_CACHE = OrderedDict()
_TEMPLATE_ARTIFACT_CACHE_LIMIT = 512
cdef tuple _QI_NETFLOW


def template_artifact_cache_info():
    """Current size and limit of the template codec plan cache.

    Returns:
        :tuple: (entries, limit).
    """
    return len(_TEMPLATE_ARTIFACT_CACHE), _TEMPLATE_ARTIFACT_CACHE_LIMIT


def set_template_artifact_cache_limit(limit):
    """Set how many template codec plans are kept, evicting if needed.

    Args:
        :limit (int): maximum entries to retain. Must be positive.

    Returns:
        :int: the limit now in force.
    """
    global _TEMPLATE_ARTIFACT_CACHE_LIMIT
    if int(limit) < 1:
        raise ValueError('template artifact cache limit must be positive')
    _TEMPLATE_ARTIFACT_CACHE_LIMIT = int(limit)
    _trim_template_artifact_cache()
    return _TEMPLATE_ARTIFACT_CACHE_LIMIT


def clear_template_artifact_cache():
    """Drop every cached template codec plan and record class."""
    _TEMPLATE_ARTIFACT_CACHE.clear()


cdef int _trim_template_artifact_cache() except -1:
    while len(_TEMPLATE_ARTIFACT_CACHE) > _TEMPLATE_ARTIFACT_CACHE_LIMIT:
        _TEMPLATE_ARTIFACT_CACHE.popitem(last=False)
    return 0


cdef object _inet_aton = socket.inet_aton
cdef object _inet_ntoa = socket.inet_ntoa
cdef object _inet_pton = socket.inet_pton
cdef object _inet_ntop = socket.inet_ntop
cdef object _AF_INET6 = socket.AF_INET6


cdef bytes _input_bytes(tuple args, dict kwargs):
    cdef object data

    if len(args) == 1:
        data = args[0]
    elif 'data' in kwargs:
        data = kwargs['data']
    else:
        return b''
    try:
        return bytes(data)
    except (TypeError, ValueError):
        raise TypeError('data must be bytes or a bytes-like object')


cdef int _write_component(PktWriter w, object value, dict kwargs) except -1:
    if isinstance(value, NetflowV1Header):
        return (<NetflowV1Header>value)._write(w, kwargs)
    if isinstance(value, NetflowV5Header):
        return (<NetflowV5Header>value)._write(w, kwargs)
    if isinstance(value, NetflowV7Header):
        return (<NetflowV7Header>value)._write(w, kwargs)
    if isinstance(value, NetflowV9Header):
        return (<NetflowV9Header>value)._write(w, kwargs)
    if isinstance(value, IPFIXHeader):
        return (<IPFIXHeader>value)._write(w, kwargs)
    if isinstance(value, NetflowV1Record):
        return (<NetflowV1Record>value)._write(w, kwargs)
    if isinstance(value, NetflowV5Record):
        return (<NetflowV5Record>value)._write(w, kwargs)
    if isinstance(value, NetflowV7Record):
        return (<NetflowV7Record>value)._write(w, kwargs)
    if isinstance(value, NetflowOptionsTemplate):
        return (<NetflowOptionsTemplate>value)._write(w, kwargs)
    if isinstance(value, NetflowTemplate):
        return (<NetflowTemplate>value)._write(w, kwargs)
    if isinstance(value, NetflowTemplateField):
        return (<NetflowTemplateField>value)._write(w, kwargs)
    if isinstance(value, NetflowDataRecord):
        return (<NetflowDataRecord>value)._write(w, kwargs)
    if isinstance(value, NetflowFlowSet):
        return (<NetflowFlowSet>value)._write(w, kwargs)
    if hasattr(value, 'pkt2net'):
        w_bytes(w, value.pkt2net(kwargs))
    elif hasattr(value, 'raw_data'):
        w_bytes(w, value.raw_data)
    return 0


cdef bytes _serialize_component(object value, dict kwargs):
    cdef PktWriter w = w_acquire()
    try:
        _write_component(w, value, kwargs)
        return w_take(w, 0)
    finally:
        w_release(w)


cdef object _exporter_key(object exporter):
    if exporter is None:
        return None
    try:
        hash(exporter)
        return exporter
    except TypeError:
        return repr(exporter)


cdef tuple _field_metadata(int element_id, object enterprise_number):
    if enterprise_number is not None:
        return (None, 'bytes')
    return INFORMATION_ELEMENTS.get(element_id, (None, 'bytes'))


cdef object _field_key(object field):
    if field.enterprise_number is not None:
        return (field.enterprise_number, field.element_id)
    if field.name is not None:
        return field.name
    return field.element_id


cdef tuple _field_identity(object field):
    return (field.enterprise_number or 0, field.element_id)


cdef int _codec_type(object data_type):
    if data_type == 'unsigned':
        return CODEC_UNSIGNED
    if data_type == 'ipv4':
        return CODEC_IPV4
    if data_type == 'ipv6':
        return CODEC_IPV6
    if data_type == 'mac':
        return CODEC_MAC
    if data_type == 'string':
        return CODEC_STRING
    return CODEC_BYTES


cdef inline object _decode_ip(const unsigned char[:] data,
                              Py_ssize_t offset, int family):
    """Format an address read straight out of the parse buffer.

    IPv4 goes to the shared digit writer rather than to inet_ntop: the
    platform converter costs more than writing four octets does, and a single
    30 minute v9 capture in this repository carries 795,824 of them. IPv6
    still goes to inet_ntop, deliberately -- RFC 5952 zero compression is not
    worth reimplementing to save a call made far less often.

    The caller has already checked that the field is the right length.
    """
    cdef char text[46]

    if family == AF_INET:
        return _fmt_ipv4_buf(&data[offset])
    if inet_ntop(family, <const void *>&data[offset], text,
                 sizeof(text)) == NULL:
        raise ValueError('invalid address value')
    return PyUnicode_FromString(text)


cdef inline object _decode_mac(const unsigned char[:] data,
                               Py_ssize_t offset):
    cdef char text[18]

    snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
             data[offset], data[offset + 1], data[offset + 2],
             data[offset + 3], data[offset + 4], data[offset + 5])
    return PyUnicode_FromString(text)


cdef inline object _decode_string(const unsigned char[:] data,
                                  Py_ssize_t offset,
                                  Py_ssize_t length):
    while length and data[offset + length - 1] == 0:
        length -= 1
    if not length:
        return ''
    return PyUnicode_DecodeUTF8(
        <const char *>&data[offset], length, "replace")


cdef object _decode_value(object field, bytes value):
    if field.data_type == 'unsigned':
        return int.from_bytes(value, byteorder='big', signed=False)
    if field.data_type == 'ipv4' and len(value) == 4:
        return _inet_ntoa(value)
    if field.data_type == 'ipv6' and len(value) == 16:
        return _inet_ntop(_AF_INET6, value)
    if field.data_type == 'mac' and len(value) == 6:
        return ':'.join('{:02x}'.format(byte) for byte in value)
    if field.data_type == 'string':
        return value.decode('utf-8', errors='replace').rstrip('\x00')
    return value


cdef bytes _encode_value(object field, object value):
    cdef bytes encoded

    if isinstance(value, bytes):
        encoded = value
    elif field.data_type == 'unsigned':
        encoded = int(value).to_bytes(
            field.field_length if not field.variable_length else
            max(1, (int(value).bit_length() + 7) // 8),
            byteorder='big', signed=False)
    elif field.data_type == 'ipv4':
        encoded = _inet_aton(value)
    elif field.data_type == 'ipv6':
        encoded = _inet_pton(_AF_INET6, value)
    elif field.data_type == 'mac':
        encoded = bytes(int(part, 16) for part in value.split(':'))
    elif field.data_type == 'string':
        encoded = value.encode('utf-8')
    else:
        encoded = bytes(value)

    if field.variable_length:
        if len(encoded) < 255:
            return struct.pack('!B', len(encoded)) + encoded
        if len(encoded) > 65535:
            raise ValueError('IPFIX variable-length value exceeds 65535 bytes')
        return b'\xff' + struct.pack('!H', len(encoded)) + encoded
    if len(encoded) < field.field_length:
        encoded += b'\x00' * (field.field_length - len(encoded))
    if len(encoded) > field.field_length:
        raise ValueError('field value exceeds template field length')
    return encoded


cdef tuple _parse_template_fields(bytes data, int offset, int count,
                                  int version):
    """Read ``count`` template field specifiers starting at ``offset``.

    The top bit of the field specifier means different things per version.
    RFC 7011 3.2 defines it for IPFIX as the Enterprise bit: when set, the
    low 15 bits are the element id and a 4 byte Private Enterprise Number
    follows. RFC 3954 8 gives NetFlow v9 no such bit -- the whole 16 bits are
    the field type, and 32768 and up are ordinary vendor field types. Cisco
    ASA NSEL uses exactly that range (33000-33002, 40000 and up), so applying
    the IPFIX rule to v9 both mangled the element id and consumed 4 bytes of
    the next field as a PEN, which failed the template and left every data
    set from that exporter to fall back to NetflowSimple.

    :param data: the flowset body.
    :param offset: where to start reading.
    :param count: how many field specifiers to read.
    :param version: NetFlow version, 9 or 10. Only 10 has the Enterprise bit.
    :return: (fields, new offset, valid).
    """
    cdef list fields = []
    cdef int raw_element_id, field_length, element_id
    cdef bint enterprise_capable = version == 10
    cdef object enterprise_number, name, data_type
    cdef const unsigned char[:] mv = data

    while len(fields) < count:
        if offset + 4 > len(data):
            return (fields, offset, False)
        raw_element_id = rd_u16(mv, offset)
        field_length = rd_u16(mv, offset + 2)
        offset += 4
        if field_length == 0:
            return (fields, offset, False)
        enterprise_number = None
        element_id = raw_element_id
        if enterprise_capable and raw_element_id & 0x8000:
            element_id = raw_element_id & 0x7fff
            if offset + 4 > len(data):
                return (fields, offset - 4, False)
            enterprise_number = rd_u32(mv, offset)
            offset += 4
        name, data_type = _field_metadata(element_id, enterprise_number)
        fields.append(NetflowTemplateField(
            element_id, field_length, enterprise_number, name, data_type,
            field_length == 65535))
    return (fields, offset, True)


cdef tuple _parse_data_record(bytes data, int offset, object template):
    cdef int start = offset
    cdef int value_length
    cdef object field, key
    cdef bytes value
    cdef dict fields = {}
    cdef dict raw_fields = {}

    for field in template.fields:
        if field.variable_length:
            if offset >= len(data):
                return (None, start, False)
            value_length = data[offset]
            offset += 1
            if value_length == 255:
                if offset + 2 > len(data):
                    return (None, start, False)
                value_length = struct.unpack(
                    '!H', data[offset:offset + 2])[0]
                offset += 2
        else:
            value_length = field.field_length
        if offset + value_length > len(data):
            return (None, start, False)
        value = data[offset:offset + value_length]
        offset += value_length
        key = _field_key(field)
        raw_fields[key] = value
        fields[key] = _decode_value(field, value)
    return (NetflowDataRecord(template.template_id, fields, raw_fields,
                              data[start:offset], template), offset, True)


def _decode_interpreted(object template, bytes data, int offset=0):
    """Run the retained descriptor-walking decoder for benchmarks."""
    cdef object record, field, key, identity
    cdef int next_offset
    cdef bint valid

    record, next_offset, valid = _parse_data_record(data, offset, template)
    if not valid:
        return (record, next_offset, valid)
    for field in template.fields:
        key = _field_key(field)
        identity = _field_identity(field)
        record.fields[identity] = record.fields[key]
        record.original_fields[identity] = record.fields[key]
        record.raw_fields[identity] = record.raw_fields[key]
    return (record, next_offset, valid)


cdef tuple _template_signature(object template):
    cdef object field

    return (template.version, template.template_id, bool(template.options),
            tuple((field.element_id, field.field_length,
                   field.enterprise_number, field.name, field.data_type,
                   bool(field.variable_length))
                  for field in template.fields))


cdef object _prepare_template(object template):
    cdef tuple signature
    cdef object artifact, record_class
    cdef NetflowCodecPlan plan
    cdef str class_name
    cdef unsigned long checksum

    if template.withdrawn:
        template.codec_plan = None
        template.record_class = None
        return template
    signature = _template_signature(template)
    artifact = _TEMPLATE_ARTIFACT_CACHE.get(signature)
    if artifact is not None:
        _TEMPLATE_ARTIFACT_CACHE.move_to_end(signature)
    if artifact is None:
        plan = NetflowCodecPlan(template.fields, signature)
        checksum = zlib.crc32(repr(signature).encode('utf-8')) & 0xffffffff
        class_name = 'NetflowV{}Record{}_{:08x}'.format(
            template.version, template.template_id, checksum)
        record_class = type(class_name, (NetflowDataRecord,), {})
        plan.record_class = record_class
        artifact = (plan, record_class)
        _TEMPLATE_ARTIFACT_CACHE[signature] = artifact
        _trim_template_artifact_cache()
    template.codec_plan, template.record_class = artifact
    return template


cdef class NetflowTemplateRegistry:
    """Version- and transport-scoped store of learned templates."""

    def __cinit__(self):
        self.templates = {}

    def register_template(self, version, exporter, source_id, template):
        _prepare_template(template)
        self.templates[(version, _exporter_key(exporter), source_id,
                        template.template_id)] = template
        return template

    def resolve_template(self, version, exporter, source_id, template_id):
        return self.templates.get((version, _exporter_key(exporter),
                                   source_id, template_id))

    def resolve_any_template(self, exporter, source_id, template_id):
        cdef object exporter_key = _exporter_key(exporter)
        cdef object key, template

        for key, template in self.templates.items():
            if (key[1] == exporter_key and key[2] == source_id and
                    key[3] == template_id):
                return template
        return None

    def withdraw_template(self, version, exporter, source_id, template_id):
        return self.templates.pop((version, _exporter_key(exporter),
                                   source_id, template_id), None)

    def withdraw_templates(self, version, exporter, source_id, options=None):
        cdef object exporter_key = _exporter_key(exporter)
        cdef object key, template
        cdef list withdrawn = []

        for key, template in list(self.templates.items()):
            if (key[0] != version or key[1] != exporter_key or
                    key[2] != source_id):
                continue
            if options is not None and bool(template.options) != bool(options):
                continue
            withdrawn.append(self.templates.pop(key))
        return withdrawn

    def clear(self):
        self.templates.clear()


cdef class NetflowDecodeContext:
    """Reusable template store scoped by exporter, domain, and template ID."""

    def __cinit__(self, force_simple=False):
        self.registry = NetflowTemplateRegistry()
        self.templates = self.registry.templates
        self.force_simple = force_simple

    def register_template(self, exporter, source_id, template, version=None):
        if version is None:
            version = template.version
        return self.registry.register_template(version, exporter, source_id,
                                               template)

    def resolve_template(self, exporter, source_id, template_id, version=None):
        if version is None:
            return self.registry.resolve_any_template(
                exporter, source_id, template_id)
        return self.registry.resolve_template(version, exporter, source_id,
                                              template_id)

    def withdraw_template(self, exporter, source_id, template_id,
                          version=None):
        if version is None:
            version = 9
        return self.registry.withdraw_template(version, exporter, source_id,
                                               template_id)

    def withdraw_templates(self, exporter, source_id, options=None,
                           version=None):
        if version is None:
            version = 9
        return self.registry.withdraw_templates(
            version, exporter, source_id, options)

    def clear(self):
        self.registry.clear()


cdef inline void _read_v1_header(NetflowV1Header header,
                                 const unsigned char[:] data,
                                 Py_ssize_t offset):
    header.version = rd_u16(data, offset)
    header.count = rd_u16(data, offset + 2)
    header.sys_uptime = rd_u32(data, offset + 4)
    header.unix_secs = rd_u32(data, offset + 8)
    header.unix_nsecs = rd_u32(data, offset + 12)


cdef inline void _read_v5_header(NetflowV5Header header,
                                 const unsigned char[:] data,
                                 Py_ssize_t offset):
    header.version = rd_u16(data, offset)
    header.count = rd_u16(data, offset + 2)
    header.sys_uptime = rd_u32(data, offset + 4)
    header.unix_secs = rd_u32(data, offset + 8)
    header.unix_nsecs = rd_u32(data, offset + 12)
    header.flow_sequence = rd_u32(data, offset + 16)
    header.engine_type = data[offset + 20]
    header.engine_id = data[offset + 21]
    header.sampling_interval = rd_u16(data, offset + 22)


cdef inline void _read_v7_header(NetflowV7Header header,
                                 const unsigned char[:] data,
                                 Py_ssize_t offset):
    header.version = rd_u16(data, offset)
    header.count = rd_u16(data, offset + 2)
    header.sys_uptime = rd_u32(data, offset + 4)
    header.unix_secs = rd_u32(data, offset + 8)
    header.unix_nsecs = rd_u32(data, offset + 12)
    header.flow_sequence = rd_u32(data, offset + 16)
    header.reserved = rd_u32(data, offset + 20)


cdef inline void _read_v9_header(NetflowV9Header header,
                                 const unsigned char[:] data,
                                 Py_ssize_t offset):
    header.version = rd_u16(data, offset)
    header.count = rd_u16(data, offset + 2)
    header.sys_uptime = rd_u32(data, offset + 4)
    header.unix_secs = rd_u32(data, offset + 8)
    header.sequence = rd_u32(data, offset + 12)
    header.source_id = rd_u32(data, offset + 16)


cdef inline void _read_ipfix_header(IPFIXHeader header,
                                    const unsigned char[:] data,
                                    Py_ssize_t offset):
    header.version = rd_u16(data, offset)
    header.length = rd_u16(data, offset + 2)
    header.export_time = rd_u32(data, offset + 4)
    header.sequence = rd_u32(data, offset + 8)
    header.observation_domain_id = rd_u32(data, offset + 12)


cdef class NetflowV1Header:
    """NetFlow v1 packet header."""

    def __init__(self, *args, **kwargs):
        cdef bytes data = _input_bytes(args, kwargs)
        cdef const unsigned char[:] mv

        if data:
            mv = data
            need_bytes(mv, NETFLOW_V1_HEADER_LEN, 'NetFlow v1 header')
            _read_v1_header(self, mv, 0)
        else:
            self.version = kwargs.get('version', 1)
            self.count = kwargs.get('count', 0)
            self.sys_uptime = kwargs.get('sys_uptime', 0)
            self.unix_secs = kwargs.get('unix_secs', 0)
            self.unix_nsecs = kwargs.get(
                'unix_nsecs', kwargs.get('unix_nano_seconds', 0))

    property unix_nano_seconds:
        def __get__(self):
            return self.unix_nsecs

        def __set__(self, value):
            self.unix_nsecs = value

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        w_u16(w, self.version)
        w_u16(w, self.count)
        w_u32(w, self.sys_uptime)
        w_u32(w, self.unix_secs)
        w_u32(w, self.unix_nsecs)
        return 0


cdef class NetflowV5Header:
    """NetFlow v5 packet header."""

    def __init__(self, *args, **kwargs):
        cdef bytes data = _input_bytes(args, kwargs)
        cdef const unsigned char[:] mv

        if data:
            mv = data
            need_bytes(mv, NETFLOW_V5_HEADER_LEN, 'NetFlow v5 header')
            _read_v5_header(self, mv, 0)
        else:
            self.version = kwargs.get('version', 5)
            self.count = kwargs.get('count', 0)
            self.sys_uptime = kwargs.get('sys_uptime', 0)
            self.unix_secs = kwargs.get('unix_secs', 0)
            self.unix_nsecs = kwargs.get(
                'unix_nsecs', kwargs.get('unix_nano_seconds', 0))
            self.flow_sequence = kwargs.get(
                'flow_sequence', kwargs.get('sequence', 0))
            self.engine_type = kwargs.get('engine_type', 0)
            self.engine_id = kwargs.get('engine_id', 0)
            self.sampling_interval = kwargs.get('sampling_interval', 0)

    property sequence:
        def __get__(self):
            return self.flow_sequence

        def __set__(self, value):
            self.flow_sequence = value

    property unix_nano_seconds:
        def __get__(self):
            return self.unix_nsecs

        def __set__(self, value):
            self.unix_nsecs = value

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        w_u16(w, self.version)
        w_u16(w, self.count)
        w_u32(w, self.sys_uptime)
        w_u32(w, self.unix_secs)
        w_u32(w, self.unix_nsecs)
        w_u32(w, self.flow_sequence)
        w_u8(w, self.engine_type)
        w_u8(w, self.engine_id)
        w_u16(w, self.sampling_interval)
        return 0


cdef class NetflowV7Header:
    """NetFlow v7 packet header."""

    def __init__(self, *args, **kwargs):
        cdef bytes data = _input_bytes(args, kwargs)
        cdef const unsigned char[:] mv

        if data:
            mv = data
            need_bytes(mv, NETFLOW_V7_HEADER_LEN, 'NetFlow v7 header')
            _read_v7_header(self, mv, 0)
        else:
            self.version = kwargs.get('version', 7)
            self.count = kwargs.get('count', 0)
            self.sys_uptime = kwargs.get('sys_uptime', 0)
            self.unix_secs = kwargs.get('unix_secs', 0)
            self.unix_nsecs = kwargs.get(
                'unix_nsecs', kwargs.get('unix_nano_seconds', 0))
            self.flow_sequence = kwargs.get(
                'flow_sequence', kwargs.get('sequence', 0))
            self.reserved = kwargs.get('reserved', 0)

    property sequence:
        def __get__(self):
            return self.flow_sequence

        def __set__(self, value):
            self.flow_sequence = value

    property unix_nano_seconds:
        def __get__(self):
            return self.unix_nsecs

        def __set__(self, value):
            self.unix_nsecs = value

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        w_u16(w, self.version)
        w_u16(w, self.count)
        w_u32(w, self.sys_uptime)
        w_u32(w, self.unix_secs)
        w_u32(w, self.unix_nsecs)
        w_u32(w, self.flow_sequence)
        w_u32(w, self.reserved)
        return 0


cdef class NetflowV9Header:
    """NetFlow v9 packet header."""

    def __init__(self, *args, **kwargs):
        cdef bytes data = _input_bytes(args, kwargs)
        cdef const unsigned char[:] mv

        if data:
            mv = data
            need_bytes(mv, NETFLOW_V9_HEADER_LEN, 'NetFlow v9 header')
            _read_v9_header(self, mv, 0)
        else:
            self.version = kwargs.get('version', 9)
            self.count = kwargs.get('count', 0)
            self.sys_uptime = kwargs.get('sys_uptime', 0)
            self.unix_secs = kwargs.get('unix_secs', 0)
            self.sequence = kwargs.get('sequence', 0)
            self.source_id = kwargs.get('source_id', 0)

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        w_u16(w, self.version)
        w_u16(w, self.count)
        w_u32(w, self.sys_uptime)
        w_u32(w, self.unix_secs)
        w_u32(w, self.sequence)
        w_u32(w, self.source_id)
        return 0


cdef class IPFIXHeader:
    """IPFIX message header."""

    def __init__(self, *args, **kwargs):
        cdef bytes data = _input_bytes(args, kwargs)
        cdef const unsigned char[:] mv

        if data:
            mv = data
            need_bytes(mv, IPFIX_HEADER_LEN, 'IPFIX header')
            _read_ipfix_header(self, mv, 0)
        else:
            self.version = kwargs.get('version', 10)
            self.length = kwargs.get('length', IPFIX_HEADER_LEN)
            self.export_time = kwargs.get('export_time', 0)
            self.sequence = kwargs.get('sequence', 0)
            self.observation_domain_id = kwargs.get(
                'observation_domain_id', kwargs.get('source_id', 0))

    property source_id:
        def __get__(self):
            return self.observation_domain_id

        def __set__(self, value):
            self.observation_domain_id = value

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        w_u16(w, self.version)
        w_u16(w, self.length)
        w_u32(w, self.export_time)
        w_u32(w, self.sequence)
        w_u32(w, self.observation_domain_id)
        return 0


cdef inline void _read_common_record(object record,
                                     const unsigned char[:] data,
                                     Py_ssize_t offset):
    # Three addresses per record, and a real v5 exporter packs 30 records
    # into a datagram: _inet_ntoa(rd_bytes(...)) was a bytes allocation and a
    # Python call each, and dominated the decode of a full datagram.
    record.src_addr = _fmt_ipv4_buf(&data[offset])
    record.dst_addr = _fmt_ipv4_buf(&data[offset + 4])
    record.next_hop = _fmt_ipv4_buf(&data[offset + 8])
    record.input_snmp = rd_u16(data, offset + 12)
    record.output_snmp = rd_u16(data, offset + 14)
    record.packets = rd_u32(data, offset + 16)
    record.octets = rd_u32(data, offset + 20)
    record.first = rd_u32(data, offset + 24)
    record.last = rd_u32(data, offset + 28)
    record.src_port = rd_u16(data, offset + 32)
    record.dst_port = rd_u16(data, offset + 34)


cdef inline void _read_v1_record(NetflowV1Record record,
                                 const unsigned char[:] data,
                                 Py_ssize_t offset):
    _read_common_record(record, data, offset)
    record.pad1 = rd_u16(data, offset + 36)
    record.protocol = data[offset + 38]
    record.tos = data[offset + 39]
    record.pad2 = rd_u32(data, offset + 40)
    record.reserved = rd_u32(data, offset + 44)


cdef inline void _read_v5_record(NetflowV5Record record,
                                 const unsigned char[:] data,
                                 Py_ssize_t offset):
    _read_common_record(record, data, offset)
    record.pad1 = data[offset + 36]
    record.tcp_flags = data[offset + 37]
    record.protocol = data[offset + 38]
    record.tos = data[offset + 39]
    record.src_as = rd_u16(data, offset + 40)
    record.dst_as = rd_u16(data, offset + 42)
    record.src_mask = data[offset + 44]
    record.dst_mask = data[offset + 45]
    record.pad2 = rd_u16(data, offset + 46)


cdef inline void _read_v7_record(NetflowV7Record record,
                                 const unsigned char[:] data,
                                 Py_ssize_t offset):
    _read_common_record(record, data, offset)
    record.pad1 = data[offset + 36]
    record.tcp_flags = data[offset + 37]
    record.protocol = data[offset + 38]
    record.tos = data[offset + 39]
    record.src_as = rd_u16(data, offset + 40)
    record.dst_as = rd_u16(data, offset + 42)
    record.src_mask = data[offset + 44]
    record.dst_mask = data[offset + 45]
    record.pad2 = rd_u16(data, offset + 46)
    record.router_sc = rd_u32(data, offset + 48)


cdef inline int _write_common_record(PktWriter w, object record) except -1:
    w_bytes(w, _inet_aton(record.src_addr))
    w_bytes(w, _inet_aton(record.dst_addr))
    w_bytes(w, _inet_aton(record.next_hop))
    w_u16(w, record.input_snmp)
    w_u16(w, record.output_snmp)
    w_u32(w, record.packets)
    w_u32(w, record.octets)
    w_u32(w, record.first)
    w_u32(w, record.last)
    w_u16(w, record.src_port)
    w_u16(w, record.dst_port)
    return 0


cdef class NetflowV1Record:
    """A fixed-width NetFlow v1 flow record."""

    def __init__(self, *args, **kwargs):
        cdef bytes data = _input_bytes(args, kwargs)
        cdef const unsigned char[:] mv

        if data:
            mv = data
            need_bytes(mv, NETFLOW_V1_RECORD_LEN, 'NetFlow v1 record')
            _read_v1_record(self, mv, 0)
        else:
            self.src_addr = kwargs.get('src_addr', '0.0.0.0')
            self.dst_addr = kwargs.get('dst_addr', '0.0.0.0')
            self.next_hop = kwargs.get('next_hop', '0.0.0.0')
            self.input_snmp = kwargs.get('input_snmp', 0)
            self.output_snmp = kwargs.get('output_snmp', 0)
            self.packets = kwargs.get('packets', 0)
            self.octets = kwargs.get('octets', 0)
            self.first = kwargs.get('first', 0)
            self.last = kwargs.get('last', 0)
            self.src_port = kwargs.get('src_port', 0)
            self.dst_port = kwargs.get('dst_port', 0)
            self.pad1 = kwargs.get('pad1', 0)
            self.protocol = kwargs.get('protocol', 0)
            self.tos = kwargs.get('tos', 0)
            self.pad2 = kwargs.get('pad2', 0)
            self.reserved = kwargs.get('reserved', 0)

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        _write_common_record(w, self)
        w_u16(w, self.pad1)
        w_u8(w, self.protocol)
        w_u8(w, self.tos)
        w_u32(w, self.pad2)
        w_u32(w, self.reserved)
        return 0


cdef class NetflowV5Record:
    """A fixed-width NetFlow v5 flow record."""

    def __init__(self, *args, **kwargs):
        cdef bytes data = _input_bytes(args, kwargs)
        cdef const unsigned char[:] mv

        if data:
            mv = data
            need_bytes(mv, NETFLOW_V5_RECORD_LEN, 'NetFlow v5 record')
            _read_v5_record(self, mv, 0)
        else:
            self.src_addr = kwargs.get('src_addr', '0.0.0.0')
            self.dst_addr = kwargs.get('dst_addr', '0.0.0.0')
            self.next_hop = kwargs.get('next_hop', '0.0.0.0')
            self.input_snmp = kwargs.get('input_snmp', 0)
            self.output_snmp = kwargs.get('output_snmp', 0)
            self.packets = kwargs.get('packets', 0)
            self.octets = kwargs.get('octets', 0)
            self.first = kwargs.get('first', 0)
            self.last = kwargs.get('last', 0)
            self.src_port = kwargs.get('src_port', 0)
            self.dst_port = kwargs.get('dst_port', 0)
            self.pad1 = kwargs.get('pad1', 0)
            self.tcp_flags = kwargs.get('tcp_flags', 0)
            self.protocol = kwargs.get('protocol', 0)
            self.tos = kwargs.get('tos', 0)
            self.src_as = kwargs.get('src_as', 0)
            self.dst_as = kwargs.get('dst_as', 0)
            self.src_mask = kwargs.get('src_mask', 0)
            self.dst_mask = kwargs.get('dst_mask', 0)
            self.pad2 = kwargs.get('pad2', 0)

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        _write_common_record(w, self)
        w_u8(w, self.pad1)
        w_u8(w, self.tcp_flags)
        w_u8(w, self.protocol)
        w_u8(w, self.tos)
        w_u16(w, self.src_as)
        w_u16(w, self.dst_as)
        w_u8(w, self.src_mask)
        w_u8(w, self.dst_mask)
        w_u16(w, self.pad2)
        return 0


cdef class NetflowV7Record:
    """A fixed-width NetFlow v7 flow record."""

    def __init__(self, *args, **kwargs):
        cdef bytes data = _input_bytes(args, kwargs)
        cdef const unsigned char[:] mv

        if data:
            mv = data
            need_bytes(mv, NETFLOW_V7_RECORD_LEN, 'NetFlow v7 record')
            _read_v7_record(self, mv, 0)
        else:
            self.src_addr = kwargs.get('src_addr', '0.0.0.0')
            self.dst_addr = kwargs.get('dst_addr', '0.0.0.0')
            self.next_hop = kwargs.get('next_hop', '0.0.0.0')
            self.input_snmp = kwargs.get('input_snmp', 0)
            self.output_snmp = kwargs.get('output_snmp', 0)
            self.packets = kwargs.get('packets', 0)
            self.octets = kwargs.get('octets', 0)
            self.first = kwargs.get('first', 0)
            self.last = kwargs.get('last', 0)
            self.src_port = kwargs.get('src_port', 0)
            self.dst_port = kwargs.get('dst_port', 0)
            self.pad1 = kwargs.get('pad1', 0)
            self.tcp_flags = kwargs.get('tcp_flags', 0)
            self.protocol = kwargs.get('protocol', 0)
            self.tos = kwargs.get('tos', 0)
            self.src_as = kwargs.get('src_as', 0)
            self.dst_as = kwargs.get('dst_as', 0)
            self.src_mask = kwargs.get('src_mask', 0)
            self.dst_mask = kwargs.get('dst_mask', 0)
            self.pad2 = kwargs.get('pad2', 0)
            self.router_sc = kwargs.get('router_sc', 0)

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        _write_common_record(w, self)
        w_u8(w, self.pad1)
        w_u8(w, self.tcp_flags)
        w_u8(w, self.protocol)
        w_u8(w, self.tos)
        w_u16(w, self.src_as)
        w_u16(w, self.dst_as)
        w_u8(w, self.src_mask)
        w_u8(w, self.dst_mask)
        w_u16(w, self.pad2)
        w_u32(w, self.router_sc)
        return 0


cdef class NetflowTemplateField:
    def __init__(self, element_id=0, field_length=0,
                 enterprise_number=None, name=None, data_type=None,
                 variable_length=False):
        cdef object known_name, known_type

        known_name, known_type = _field_metadata(element_id,
                                                  enterprise_number)
        self.element_id = element_id
        self.field_length = field_length
        self.enterprise_number = enterprise_number
        self.name = known_name if name is None else name
        self.data_type = known_type if data_type is None else data_type
        self.variable_length = variable_length or field_length == 65535

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef int element_id = self.element_id

        if self.enterprise_number is not None:
            element_id |= 0x8000
        w_u16(w, element_id)
        w_u16(w, self.field_length)
        if self.enterprise_number is not None:
            w_u32(w, self.enterprise_number)
        return 0


cdef class NetflowTemplate:
    def __init__(self, template_id=0, fields=None, options=False, version=9,
                 withdrawn=False):
        self.template_id = template_id
        self.fields = list(fields) if fields is not None else []
        self.options = options
        self.version = version
        self.withdrawn = withdrawn
        _prepare_template(self)

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef object field

        w_u16(w, self.template_id)
        w_u16(w, 0 if self.withdrawn else len(self.fields))
        if not self.withdrawn:
            for field in self.fields:
                (<NetflowTemplateField>field)._write(w, kwargs)
        return 0


cdef class NetflowOptionsTemplate(NetflowTemplate):
    def __init__(self, template_id=0, scope_fields=None, option_fields=None,
                 version=9, withdrawn=False):
        self.scope_fields = (list(scope_fields)
                             if scope_fields is not None else [])
        self.option_fields = (list(option_fields)
                              if option_fields is not None else [])
        NetflowTemplate.__init__(self, template_id,
                                 self.scope_fields + self.option_fields, True,
                                 version, withdrawn)

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef object field
        cdef int scope_length = 0
        cdef int option_length = 0

        if self.version == 9:
            if not self.withdrawn:
                for field in self.scope_fields:
                    scope_length += (8 if field.enterprise_number is not None
                                     else 4)
                for field in self.option_fields:
                    option_length += (8
                                      if field.enterprise_number is not None
                                      else 4)
            w_u16(w, self.template_id)
            w_u16(w, scope_length)
            w_u16(w, option_length)
        else:
            w_u16(w, self.template_id)
            w_u16(w, 0 if self.withdrawn else len(self.fields))
            w_u16(w, 0 if self.withdrawn else len(self.scope_fields))
        if not self.withdrawn:
            for field in self.fields:
                (<NetflowTemplateField>field)._write(w, kwargs)
        return 0


cdef class NetflowFieldMap:
    """One stored value per field with template-shared alternate keys."""

    def __init__(self, values=None, aliases=None, canonical=False):
        cdef object key, value

        self._aliases = aliases if aliases is not None else {}
        if canonical:
            self._values = values if values is not None else {}
        else:
            self._values = {}
            if values is not None:
                for key, value in values.items():
                    self._values[self._aliases.get(key, key)] = value

    def __getitem__(self, key):
        return self._values[self._aliases.get(key, key)]

    def __setitem__(self, key, value):
        self._values[self._aliases.get(key, key)] = value

    def __delitem__(self, key):
        del self._values[self._aliases.get(key, key)]

    def __contains__(self, key):
        return self._aliases.get(key, key) in self._values

    def __len__(self):
        cdef object key, canonical
        cdef Py_ssize_t length = len(self._values)

        for key, canonical in self._aliases.items():
            if canonical in self._values:
                length += 1
        return length

    def __iter__(self):
        return iter(self.keys())

    def __repr__(self):
        return repr(self._as_dict())

    def __eq__(self, other):
        if isinstance(other, NetflowFieldMap):
            return self._as_dict() == (<NetflowFieldMap>other)._as_dict()
        return self._as_dict() == other

    def __ne__(self, other):
        return not self == other

    cdef dict _as_dict(self):
        cdef dict values = dict(self._values)
        cdef object alias, canonical

        for alias, canonical in self._aliases.items():
            if canonical in self._values:
                values[alias] = self._values[canonical]
        return values

    def get(self, key, default=None):
        return self._values.get(self._aliases.get(key, key), default)

    def keys(self):
        return self._as_dict().keys()

    def items(self):
        return self._as_dict().items()

    def values(self):
        return self._as_dict().values()

    def copy(self):
        return self._as_dict()

    def clear(self):
        self._values.clear()

    def setdefault(self, key, default=None):
        return self._values.setdefault(self._aliases.get(key, key), default)

    def pop(self, key, *default):
        return self._values.pop(self._aliases.get(key, key), *default)

    def update(self, other=None, **kwargs):
        cdef object key

        if other is not None:
            if hasattr(other, 'keys'):
                for key in other.keys():
                    self[key] = other[key]
            else:
                for key, value in other:
                    self[key] = value
        for key, value in kwargs.items():
            self[key] = value


cdef class NetflowCodecPlan:
    """Cached Python metadata and typed C operations for one template."""

    def __cinit__(self):
        self.c_operations = NULL
        self.operation_count = 0

    def __dealloc__(self):
        if self.c_operations != NULL:
            PyMem_Free(self.c_operations)

    def __init__(self, fields, signature=None):
        cdef list operations = []
        cdef list codec_fields = []
        cdef list keys = []
        cdef list identities = []
        cdef dict aliases = {}
        cdef object field, key, identity
        cdef int codec_type, fixed_offset = 0
        cdef Py_ssize_t index

        if self.c_operations != NULL:
            PyMem_Free(self.c_operations)
            self.c_operations = NULL
            self.operation_count = 0

        for field in fields:
            if field.field_length <= 0:
                raise ValueError('template field length must be positive')
            if field.variable_length and field.field_length != 65535:
                raise ValueError(
                    'variable-length template field must use length 65535')
            key = _field_key(field)
            identity = _field_identity(field)
            codec_type = _codec_type(field.data_type)
            operations.append((field, key, identity, fixed_offset,
                               bool(field.variable_length),
                               codec_type))
            codec_fields.append(field)
            keys.append(key)
            identities.append(identity)
            if identity != key:
                aliases[identity] = key
            if field.variable_length:
                fixed_offset = -1
            elif fixed_offset >= 0:
                fixed_offset += field.field_length
        self.signature = (signature if signature is not None else
                          tuple((operation[2], operation[0].field_length,
                                 operation[0].data_type,
                                 operation[4])
                                for operation in operations))
        self.operations = tuple(operations)
        self.codec_fields = tuple(codec_fields)
        self.keys = tuple(keys)
        self.identities = tuple(identities)
        self.aliases = aliases
        self.has_variable = fixed_offset < 0
        # fixed_offset carries the running total of the fixed field lengths
        # and is set to -1 by the first variable length field, so it is
        # already the record length for a fixed template and -1 otherwise.
        self.fixed_length = fixed_offset
        self.record_class = NetflowDataRecord
        self.operation_count = len(operations)
        if self.operation_count:
            self.c_operations = <NetflowCodecOperation *>PyMem_Malloc(
                self.operation_count * sizeof(NetflowCodecOperation))
            if self.c_operations == NULL:
                raise MemoryError()
            for index in range(self.operation_count):
                field = codec_fields[index]
                self.c_operations[index].field_length = field.field_length
                self.c_operations[index].fixed_offset = operations[index][3]
                self.c_operations[index].codec_type = operations[index][5]
                self.c_operations[index].variable_length = operations[index][4]

    cpdef tuple decode(self, bytes data, int offset, object template):
        cdef Py_ssize_t result_offset = offset
        cdef NetflowDataRecord record
        cdef const unsigned char[:] mv = data

        record = self._decode_record(
            data, mv, &result_offset, template)
        if record is None:
            return (None, offset, False)
        return (record, result_offset, True)

    cdef NetflowDataRecord _decode_record(
            self, bytes data, const unsigned char[:] mv,
            Py_ssize_t *result_offset, object template):
        cdef Py_ssize_t offset = result_offset[0]
        cdef Py_ssize_t start = offset
        cdef int value_length, codec_type
        cdef Py_ssize_t index, byte_index, value_start
        cdef unsigned long long unsigned_value
        cdef object field, key, identity, value
        cdef NetflowDataRecord record
        cdef bytes raw_value
        cdef dict fields = {}
        cdef tuple original_values = PyTuple_New(self.operation_count)
        cdef object raw_ranges = [] if self.has_variable else None

        for index in range(self.operation_count):
            field = self.codec_fields[index]
            key = self.keys[index]
            identity = self.identities[index]
            if self.c_operations[index].variable_length:
                if offset >= len(data):
                    return None
                value_length = mv[offset]
                offset += 1
                if value_length == 255:
                    if offset + 2 > len(data):
                        return None
                    value_length = rd_u16(mv, offset)
                    offset += 2
            else:
                value_length = self.c_operations[index].field_length
            if offset + value_length > len(data):
                return None
            value_start = offset
            offset += value_length
            codec_type = self.c_operations[index].codec_type
            if codec_type == CODEC_UNSIGNED and value_length <= 8:
                unsigned_value = 0
                for byte_index in range(value_length):
                    unsigned_value = ((unsigned_value << 8) |
                                      mv[value_start + byte_index])
                value = unsigned_value
            elif codec_type == CODEC_IPV4 and value_length == 4:
                value = _decode_ip(mv, value_start, AF_INET)
            elif codec_type == CODEC_IPV6 and value_length == 16:
                value = _decode_ip(mv, value_start, AF_INET6)
            elif codec_type == CODEC_MAC and value_length == 6:
                value = _decode_mac(mv, value_start)
            elif codec_type == CODEC_STRING:
                value = _decode_string(mv, value_start, value_length)
            else:
                raw_value = data[value_start:offset]
                value = _decode_value(field, raw_value)
            fields[key] = value
            Py_INCREF(value)
            PyTuple_SET_ITEM(original_values, index, value)
            if raw_ranges is not None:
                raw_ranges.append((value_start - start, value_length))

        record = self.record_class.__new__(self.record_class)
        record.template_id = template.template_id
        record.fields = NetflowFieldMap(fields, self.aliases, True)
        record._raw_fields = None
        record._raw_ranges = (tuple(raw_ranges)
                              if raw_ranges is not None else None)
        record._raw_data = None
        record._raw_owner = data
        record._raw_start = start
        record._raw_length = offset - start
        record.template = template
        record.codec_plan = self
        record._original_fields = None
        record._original_values = original_values
        result_offset[0] = offset
        return record

    cpdef bytes encode(self, object record):
        cdef PktWriter w = w_acquire()
        try:
            self._write_record(w, record)
            return w_take(w, 0)
        finally:
            w_release(w)

    cdef int _write_record(self, PktWriter w, object record) except -1:
        cdef bytes raw_value
        cdef bytes raw_source
        cdef Py_ssize_t index, raw_start, raw_length
        cdef object operation, field, key, identity, value, original
        cdef NetflowDataRecord data_record = record
        cdef dict field_values = None
        cdef bint changed = False

        if isinstance(record.fields, NetflowFieldMap):
            field_values = (<NetflowFieldMap>record.fields)._values
        if ((data_record._raw_data is not None or
             data_record._raw_owner is not None) and
                data_record._raw_fields is None and
                data_record._original_fields is None and
                data_record._original_values is not None):
            for index in range(self.operation_count):
                key = self.keys[index]
                identity = self.identities[index]
                original = data_record._original_values[index]
                if field_values is not None:
                    if key not in field_values:
                        raise ValueError(
                            'missing value for template field {!r}'.format(
                                key))
                    value = field_values[key]
                else:
                    if (key not in record.fields and
                            identity not in record.fields):
                        raise ValueError(
                            'missing value for template field {!r}'.format(
                                key))
                    value = record.fields.get(
                        key, record.fields.get(identity))
                    if (identity in record.fields and
                            record.fields[identity] != original):
                        value = record.fields[identity]
                if value != original:
                    changed = True
                    break
            if not changed:
                if data_record._raw_data is not None:
                    w_bytes(w, data_record._raw_data)
                else:
                    w_bytes(w, data_record._raw_owner[
                        data_record._raw_start:
                        data_record._raw_start + data_record._raw_length])
                return 0

        for index in range(self.operation_count):
            operation = self.operations[index]
            field = self.codec_fields[index]
            key = self.keys[index]
            identity = self.identities[index]
            if field_values is not None:
                if key not in field_values:
                    raise ValueError(
                        'missing value for template field {!r}'.format(key))
                value = field_values[key]
            else:
                if key not in record.fields and identity not in record.fields:
                    raise ValueError(
                        'missing value for template field {!r}'.format(key))
                value = record.fields.get(key, record.fields.get(identity))
            if data_record._original_fields is not None:
                original = data_record._original_fields.get(
                    key, data_record._original_fields.get(identity))
            elif data_record._original_values is not None:
                original = data_record._original_values[index]
            else:
                original = None
            if (field_values is None and identity in record.fields and
                    record.fields[identity] !=
                    original):
                value = record.fields[identity]
            raw_value = None
            if data_record._raw_fields is not None:
                raw_value = data_record._raw_fields.get(identity)
            elif (data_record._raw_data is not None or
                  data_record._raw_owner is not None):
                if data_record._raw_ranges is None:
                    raw_start = self.c_operations[index].fixed_offset
                    raw_length = self.c_operations[index].field_length
                else:
                    raw_start, raw_length = data_record._raw_ranges[index]
                if data_record._raw_data is not None:
                    raw_source = data_record._raw_data
                else:
                    raw_source = data_record._raw_owner
                    raw_start += data_record._raw_start
                raw_value = raw_source[raw_start:raw_start + raw_length]
            if raw_value is not None and value == original:
                if self.c_operations[index].variable_length:
                    if len(raw_value) < 255:
                        w_u8(w, len(raw_value))
                    else:
                        w_u8(w, 255)
                        w_u16(w, len(raw_value))
                w_bytes(w, raw_value)
            else:
                w_bytes(w, _encode_value(field, value))
        return 0


cdef class NetflowDataRecord:
    """Eager query values with deferred raw and edit-tracking mappings."""

    def __init__(self, template_id=0, fields=None, raw_fields=None,
                 raw_data=None, template=None, codec_plan=None):
        cdef object operation, key, identity
        cdef list original_values

        self.template_id = template_id
        self.fields = (NetflowFieldMap(
                           fields, (<NetflowCodecPlan>codec_plan).aliases)
                       if codec_plan is not None else
                       dict(fields) if fields is not None else {})
        self._raw_fields = (dict(raw_fields)
                            if raw_fields is not None else {})
        self._raw_ranges = None
        self._raw_data = raw_data
        self._raw_owner = None
        self._raw_start = 0
        self._raw_length = len(raw_data) if raw_data is not None else 0
        self.template = template
        self.codec_plan = codec_plan
        self._original_fields = dict(self.fields)
        self._original_values = None
        if codec_plan is not None:
            original_values = []
            for operation in codec_plan.operations:
                key = operation[1]
                identity = operation[2]
                original_values.append(self.fields.get(
                    key, self.fields.get(identity)))
            self._original_values = tuple(original_values)

    property raw_data:
        def __get__(self):
            if self._raw_data is None and self._raw_owner is not None:
                self._raw_data = self._raw_owner[
                    self._raw_start:self._raw_start + self._raw_length]
            return self._raw_data

        def __set__(self, value):
            self._raw_data = value
            self._raw_owner = None
            self._raw_start = 0
            self._raw_length = len(value) if value is not None else 0

    property raw_fields:
        def __get__(self):
            cdef Py_ssize_t index, raw_start, raw_length, owner_start = 0
            cdef object operation, field, identity
            cdef dict raw_fields
            cdef bytes raw_source

            if self._raw_fields is None:
                raw_fields = {}
                if self._raw_data is not None:
                    raw_source = self._raw_data
                elif self._raw_owner is not None:
                    raw_source = self._raw_owner
                    owner_start = self._raw_start
                else:
                    raw_source = None
                if self.codec_plan is not None and raw_source is not None:
                    for index in range(len(self.codec_plan.operations)):
                        operation = self.codec_plan.operations[index]
                        field = operation[0]
                        identity = operation[2]
                        if self._raw_ranges is None:
                            raw_start = operation[3]
                            raw_length = field.field_length
                        else:
                            raw_start, raw_length = self._raw_ranges[index]
                        raw_start += owner_start
                        raw_fields[identity] = raw_source[
                            raw_start:raw_start + raw_length]
                self._raw_fields = raw_fields
            return self._raw_fields

        def __set__(self, value):
            self._raw_fields = dict(value) if value is not None else {}

    property original_fields:
        def __get__(self):
            cdef Py_ssize_t index
            cdef object key, identity, value
            cdef dict original_fields

            if self._original_fields is None:
                original_fields = {}
                for index in range(len(self.codec_plan.operations)):
                    key = self.codec_plan.keys[index]
                    identity = self.codec_plan.identities[index]
                    value = self._original_values[index]
                    original_fields[key] = value
                    if identity != key:
                        original_fields[identity] = value
                self._original_fields = original_fields
            return self._original_fields

        def __set__(self, value):
            self._original_fields = (dict(value)
                                     if value is not None else {})

    cpdef bytes pkt2net(self, dict kwargs={}):
        if self.codec_plan is not None:
            return self.codec_plan.encode(self)
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef object field, key, value

        if self.codec_plan is not None:
            return (<NetflowCodecPlan>self.codec_plan)._write_record(w, self)
        if self.raw_data is not None:
            w_bytes(w, self.raw_data)
            return 0
        if self.template is None:
            raise ValueError('a template is required to encode a data record')
        for field in self.template.fields:
            key = _field_key(field)
            if key in self.raw_fields:
                value = self.raw_fields[key]
            elif key in self.fields:
                value = self.fields[key]
            else:
                raise ValueError('missing value for template field {!r}'.format(
                    key))
            w_bytes(w, _encode_value(field, value))
        return 0


cdef class NetflowFlowSet:
    def __init__(self, set_id=0, length=0, templates=None, records=None,
                 raw_data=b'', padding=b'', malformed=False, version=9):
        self.set_id = set_id
        self.length = length
        self.templates = list(templates) if templates is not None else []
        self.records = list(records) if records is not None else []
        self.raw_data = raw_data
        self.padding = padding
        self.malformed = malformed
        self.version = version

    cpdef bytes pkt2net(self, dict kwargs={}):
        return _serialize_component(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef object item
        cdef Py_ssize_t start = w.n

        w_u16(w, self.set_id)
        w_u16(w, self.length)
        if self.templates or self.records:
            for item in self.templates:
                _write_component(w, item, kwargs)
            for item in self.records:
                _write_component(w, item, kwargs)
        else:
            w_bytes(w, self.raw_data)
        w_bytes(w, self.padding)
        if kwargs.get('update') or not self.length:
            self.length = w.n - start
            w_set_u16(w, start + 2, self.length)
        return 0


cdef class Netflow(PKT):
    """Version-dispatching NetFlow v1, v5, v7, v9, and IPFIX datagram."""

    def __init__(self, *args, **kwargs):
        cdef bytes data
        cdef int offset, record_count

        self._base_l7(kwargs)
        self.pkt_name = 'Netflow'
        self.pq_type, self.query_fields = _QI_NETFLOW
        self.context = kwargs.get('context', kwargs.get('decode_context'))
        if self.context is None:
            self.context = NetflowDecodeContext()
        self.exporter = kwargs.get('exporter')
        self.header = kwargs.get('header')
        self.flowsets = list(kwargs.get('flowsets', []))
        self.records = list(kwargs.get('records', []))
        self.raw_data = kwargs.get('raw_data', b'')
        self._wire_data = b''
        self._parsed = False
        self._requires_simple = False

        data = _input_bytes(args, kwargs)
        if data:
            self._parsed = True
            self._wire_data = data
            self._parse(data)
        else:
            self.version = kwargs.get('version',
                                      getattr(self.header, 'version', 0))
            if self.header is None and self.version == 1:
                self.header = NetflowV1Header()
            elif self.header is None and self.version == 5:
                self.header = NetflowV5Header()
            elif self.header is None and self.version == 7:
                self.header = NetflowV7Header()
            elif self.header is None and self.version == 9:
                self.header = NetflowV9Header()
            elif self.header is None and self.version == 10:
                self.header = IPFIXHeader()

    @classmethod
    def dispatch(cls, *args, **kwargs):
        cdef Netflow packet
        cdef object context

        context = kwargs.get('context', kwargs.get('decode_context'))
        if context is None:
            context = NetflowDecodeContext()
            kwargs['decode_context'] = context
        if context.force_simple:
            return NetflowSimple(*args, **kwargs)
        packet = cls(*args, **kwargs)
        if packet._requires_simple:
            return NetflowSimple(*args, **kwargs)
        return packet

    cdef int _parse(self, bytes data) except -1:
        cdef int offset, record_count
        cdef const unsigned char[:] mv = data
        cdef NetflowV1Header v1_header
        cdef NetflowV5Header v5_header
        cdef NetflowV7Header v7_header
        cdef NetflowV9Header v9_header
        cdef IPFIXHeader ipfix_header
        cdef NetflowV1Record v1_record
        cdef NetflowV5Record v5_record
        cdef NetflowV7Record v7_record

        self.header = None
        self.flowsets = []
        self.records = []
        self.raw_data = data
        if len(data) < 2:
            self.version = 0
            return 0
        self.version = rd_u16(mv, 0)
        if self.version == 1:
            if len(data) < NETFLOW_V1_HEADER_LEN:
                return 0
            v1_header = NetflowV1Header.__new__(NetflowV1Header)
            _read_v1_header(v1_header, mv, 0)
            self.header = v1_header
            offset = NETFLOW_V1_HEADER_LEN
            record_count = 0
            while (record_count < self.header.count and
                   offset + NETFLOW_V1_RECORD_LEN <= len(data)):
                v1_record = NetflowV1Record.__new__(NetflowV1Record)
                _read_v1_record(v1_record, mv, offset)
                self.records.append(v1_record)
                offset += NETFLOW_V1_RECORD_LEN
                record_count += 1
            self.raw_data = rd_bytes(mv, offset, -1)
        elif self.version == 5:
            if len(data) < NETFLOW_V5_HEADER_LEN:
                return 0
            v5_header = NetflowV5Header.__new__(NetflowV5Header)
            _read_v5_header(v5_header, mv, 0)
            self.header = v5_header
            offset = NETFLOW_V5_HEADER_LEN
            record_count = 0
            while (record_count < self.header.count and
                   offset + NETFLOW_V5_RECORD_LEN <= len(data)):
                v5_record = NetflowV5Record.__new__(NetflowV5Record)
                _read_v5_record(v5_record, mv, offset)
                self.records.append(v5_record)
                offset += NETFLOW_V5_RECORD_LEN
                record_count += 1
            self.raw_data = rd_bytes(mv, offset, -1)
        elif self.version == 7:
            if len(data) < NETFLOW_V7_HEADER_LEN:
                return 0
            v7_header = NetflowV7Header.__new__(NetflowV7Header)
            _read_v7_header(v7_header, mv, 0)
            self.header = v7_header
            offset = NETFLOW_V7_HEADER_LEN
            record_count = 0
            while (record_count < self.header.count and
                   offset + NETFLOW_V7_RECORD_LEN <= len(data)):
                v7_record = NetflowV7Record.__new__(NetflowV7Record)
                _read_v7_record(v7_record, mv, offset)
                self.records.append(v7_record)
                offset += NETFLOW_V7_RECORD_LEN
                record_count += 1
            self.raw_data = rd_bytes(mv, offset, -1)
        elif self.version == 9:
            if len(data) < NETFLOW_V9_HEADER_LEN:
                return 0
            v9_header = NetflowV9Header.__new__(NetflowV9Header)
            _read_v9_header(v9_header, mv, 0)
            self.header = v9_header
            self._parse_flowsets(data, NETFLOW_V9_HEADER_LEN, len(data))
        elif self.version == 10:
            if len(data) < IPFIX_HEADER_LEN:
                return 0
            ipfix_header = IPFIXHeader.__new__(IPFIXHeader)
            _read_ipfix_header(ipfix_header, mv, 0)
            self.header = ipfix_header
            if self.header.length < IPFIX_HEADER_LEN:
                self.raw_data = data[IPFIX_HEADER_LEN:]
            else:
                self._parse_flowsets(
                    data, IPFIX_HEADER_LEN,
                    min(len(data), self.header.length))
                if self.header.length < len(data):
                    self.raw_data += data[self.header.length:]
        return 0

    def _parse_flowsets(self, bytes data, int offset, int limit):
        cdef int set_id, set_length, end
        cdef bytes body
        cdef object flowset
        cdef const unsigned char[:] mv = data

        self.raw_data = b''
        while offset + 4 <= limit:
            set_id = rd_u16(mv, offset)
            set_length = rd_u16(mv, offset + 2)
            if set_length < 4:
                flowset = NetflowFlowSet(
                    set_id, set_length, raw_data=data[offset + 4:limit],
                    malformed=True, version=self.version)
                self.flowsets.append(flowset)
                offset = limit
                break
            end = offset + set_length
            if end > limit:
                flowset = NetflowFlowSet(
                    set_id, set_length, raw_data=data[offset + 4:limit],
                    malformed=True, version=self.version)
                self.flowsets.append(flowset)
                offset = limit
                break
            body = data[offset + 4:end]
            flowset = NetflowFlowSet(set_id, set_length, raw_data=body,
                                     version=self.version)
            self.flowsets.append(flowset)
            offset = end
        self.raw_data += data[offset:limit]

        for flowset in self.flowsets:
            if flowset.malformed:
                continue
            if ((self.version == 9 and flowset.set_id in (0, 1)) or
                    (self.version == 10 and flowset.set_id in (2, 3))):
                self._decode_flowset(flowset, flowset.raw_data)
        for flowset in self.flowsets:
            if not flowset.malformed and flowset.set_id >= 256:
                self._decode_data(flowset, flowset.raw_data)

        # Anything we could not read means this datagram is not fully
        # understood, so dispatch has to hand back a NetflowSimple rather
        # than a half decoded Netflow: a malformed template set leaves the
        # data sets that reference it undecodable, and a malformed set
        # header means the rest of the datagram was not framed at all.
        # Previously only a missing template raised this, so a template set
        # this parser could not read produced a Netflow with some flowsets
        # decoded and some not, with no signal to the caller.
        for flowset in self.flowsets:
            if flowset.malformed:
                self._requires_simple = True
                break

    def _decode_flowset(self, flowset, bytes body):
        if ((self.version == 9 and flowset.set_id == 0) or
                (self.version == 10 and flowset.set_id == 2)):
            self._decode_templates(flowset, body, False)
        elif ((self.version == 9 and flowset.set_id == 1) or
              (self.version == 10 and flowset.set_id == 3)):
            self._decode_templates(flowset, body, True)
        elif flowset.set_id >= 256:
            self._decode_data(flowset, body)

    def _decode_templates(self, flowset, bytes body, bint options):
        cdef int offset = 0
        cdef int template_start
        cdef int template_id, field_count, scope_count
        cdef int scope_length, option_length, scope_end, option_end
        cdef int new_offset
        cdef list fields, scope_fields, option_fields
        cdef bint valid
        cdef object template, parsed
        cdef const unsigned char[:] mv = body

        flowset.raw_data = b''
        while offset < len(body):
            if (len(body) - offset <= 3 and
                    body[offset:] == b'\x00' * (len(body) - offset)):
                flowset.padding = body[offset:]
                return
            template_start = offset
            if options:
                if offset + 6 > len(body):
                    flowset.padding = body[offset:]
                    flowset.malformed = True
                    return
                template_id = rd_u16(mv, offset)
                field_count = rd_u16(mv, offset + 2)
                scope_count = rd_u16(mv, offset + 4)
                offset += 6
                if self.version == 9:
                    scope_length = field_count
                    option_length = scope_count
                    if (offset + scope_length + option_length > len(body)):
                        flowset.padding = body[template_start:]
                        flowset.malformed = True
                        return
                    scope_end = offset + scope_length
                    option_end = scope_end + option_length
                    scope_fields = []
                    valid = True
                    while offset < scope_end:
                        parsed, new_offset, valid = _parse_template_fields(
                            body, offset, 1, self.version)
                        if not valid or new_offset > scope_end:
                            valid = False
                            break
                        scope_fields.extend(parsed)
                        offset = new_offset
                    option_fields = []
                    if valid:
                        while offset < option_end:
                            parsed, new_offset, valid = _parse_template_fields(
                                body, offset, 1, self.version)
                            if not valid or new_offset > option_end:
                                valid = False
                                break
                            option_fields.extend(parsed)
                            offset = new_offset
                    if not valid or offset != option_end:
                        flowset.padding = body[template_start:]
                        flowset.malformed = True
                        return
                else:
                    if scope_count > field_count:
                        flowset.padding = body[template_start:]
                        flowset.malformed = True
                        return
                    fields, new_offset, valid = _parse_template_fields(
                        body, offset, field_count, self.version)
                    if not valid:
                        flowset.padding = body[template_start:]
                        flowset.malformed = True
                        return
                    offset = new_offset
                    scope_fields = fields[:scope_count]
                    option_fields = fields[scope_count:]
                template = NetflowOptionsTemplate(
                    template_id, scope_fields, option_fields, self.version,
                    field_count == 0 and scope_count == 0)
            else:
                if offset + 4 > len(body):
                    flowset.padding = body[offset:]
                    flowset.malformed = True
                    return
                template_id = rd_u16(mv, offset)
                field_count = rd_u16(mv, offset + 2)
                offset += 4
                fields, new_offset, valid = _parse_template_fields(
                    body, offset, field_count, self.version)
                if not valid:
                    flowset.padding = body[template_start:]
                    flowset.malformed = True
                    return
                offset = new_offset
                template = NetflowTemplate(template_id, fields, False,
                                             self.version, field_count == 0)

            flowset.templates.append(template)
            if template.withdrawn:
                if ((self.version == 10 and not options and
                     template.template_id == 2) or
                        (self.version == 9 and not options and
                         template.template_id == 0)):
                    self.context.withdraw_templates(
                        self.exporter, self.header.source_id, False,
                        self.version)
                elif ((self.version == 10 and options and
                       template.template_id == 3) or
                      (self.version == 9 and options and
                       template.template_id == 1)):
                    self.context.withdraw_templates(
                        self.exporter, self.header.source_id, True,
                        self.version)
                else:
                    self.context.withdraw_template(
                        self.exporter, self.header.source_id,
                        template.template_id, self.version)
            else:
                self.context.register_template(
                    self.exporter, self.header.source_id, template,
                    self.version)

    def _decode_data(self, flowset, bytes body):
        cdef Py_ssize_t offset = 0
        cdef Py_ssize_t new_offset
        cdef Py_ssize_t remaining
        cdef Py_ssize_t record_length
        cdef NetflowCodecPlan codec_plan
        cdef NetflowDataRecord record
        cdef object template
        cdef const unsigned char[:] mv = body

        template = self.context.resolve_template(
            self.exporter, self.header.source_id, flowset.set_id,
            self.version)
        if template is None:
            self._requires_simple = True
            return
        codec_plan = template.codec_plan
        if codec_plan is None:
            # A withdrawn template carries no codec plan, and codec_plan is
            # a typed cdef reference: calling through it would be a C level
            # crash rather than an AttributeError. Treat the set as one we
            # have no template for.
            self._requires_simple = True
            return
        # Byte length of one record, or -1 when the template has a variable
        # length field and there is no such thing.
        record_length = codec_plan.fixed_length
        flowset.raw_data = b''
        while offset < len(body):
            remaining = len(body) - offset
            # RFC 3954 s5.3 and RFC 7011 s3.3.1 allow a data set to be padded
            # to a 4 byte boundary, so up to 3 trailing zero bytes are not a
            # record. Length alone used to decide that, which threw away a
            # genuine final record 1 to 3 bytes long whose fields were all
            # zero: a template of one 2 byte field carrying two zero valued
            # flows decoded as one, and header.count came back one short of
            # what was on the wire. The template says how long a record is,
            # so only rule one out when it cannot fit.
            if (remaining <= 3 and
                    (record_length < 0 or remaining < record_length) and
                    body[offset:] == b'\x00' * remaining):
                flowset.padding = body[offset:]
                break
            new_offset = offset
            record = codec_plan._decode_record(
                body, mv, &new_offset, template)
            if record is None or new_offset <= offset:
                flowset.padding = body[offset:]
                flowset.malformed = not (
                    len(flowset.padding) <= 3 and
                    flowset.padding == b'\x00' * len(flowset.padding))
                break
            flowset.records.append(record)
            self.records.append(record)
            offset = new_offset

    @classmethod
    def query_info(cls):
        return (NETFLOW_PACKET_TYPE,
                ('netflow.version', 'netflow.count', 'netflow.sequence',
                 'netflow.source_id', 'netflow.sys_uptime',
                 'netflow.unix_secs'))

    @classmethod
    def default_ports(cls):
        """Layer 4 ports pcap_query decodes as a full NetFlow datagram.

        NOTE: 2055 is also in NetflowSimple.default_ports(), so a caller
        merging both classes into one l7_ports mapping silently keeps
        whichever went in last. Pick one per port deliberately: Netflow
        decodes flowsets and records, NetflowSimple keeps the datagram
        opaque behind its header, which is what replay wants.

        Returns:
            :list: layer 4 ports for Netflow.
        """
        return [NETFLOW_PACKET_PORT]

    cpdef object get_field_val(self, str field):
        if field == 'netflow.version':
            return self.version
        if self.header is None:
            return None
        if field == 'netflow.count':
            return getattr(self.header, 'count', None)
        elif field == 'netflow.sequence':
            return getattr(self.header, 'sequence', None)
        elif field == 'netflow.source_id':
            return getattr(self.header, 'source_id', None)
        elif field == 'netflow.sys_uptime':
            return getattr(self.header, 'sys_uptime', None)
        elif field == 'netflow.unix_secs':
            return getattr(self.header, 'unix_secs', None)
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef object record, flowset
        cdef int data_record_count = 0
        cdef int total_record_count = 0
        cdef int orphans = 0
        cdef set carried
        cdef Py_ssize_t start = w.n

        if self.header is None:
            if self._parsed:
                w_bytes(w, self._wire_data)
                return 0
            if self.version:
                w_u16(w, self.version)
            w_bytes(w, self.raw_data)
            return 0

        if self.version in (1, 5, 7):
            if kwargs.get('update'):
                self.header.count = len(self.records)
                if self.version in (5, 7):
                    self.header.flow_sequence = (
                        self.header.flow_sequence +
                        len(self.records)) & 0xffffffff
            _write_component(w, self.header, kwargs)
            for record in self.records:
                _write_component(w, record, kwargs)
            w_bytes(w, self.raw_data)
            return 0

        for flowset in self.flowsets:
            data_record_count += len(flowset.records)
            total_record_count += (len(flowset.records) +
                                   len(flowset.templates))

        # v9 and IPFIX put records inside a data flowset, which is what
        # supplies the set id identifying the template they were encoded
        # against - a bare record has nowhere to go. The loop below walks
        # flowsets only, so records attached straight to .records were
        # written nowhere and Netflow(version=9, records=[rec]).pkt2net()
        # returned a header and nothing else, with no error. More records
        # on the packet than the flowsets hold means at least one of them
        # is such a record; the integer compare keeps the write path free
        # of the identity walk in the ordinary case, where .records is just
        # the flattened view of the flowsets that _parse built.
        if len(self.records) > data_record_count:
            carried = set()
            for flowset in self.flowsets:
                for record in flowset.records:
                    carried.add(id(record))
            for record in self.records:
                if id(record) not in carried:
                    orphans += 1
            if orphans:
                raise ValueError(
                    "NetFlow v{0} carries records inside a NetflowFlowSet; "
                    "{1} of {2} records on this packet belong to no flowset "
                    "and cannot be serialized".format(
                        self.version, orphans, len(self.records)))

        if kwargs.get('update'):
            if self.version == 9:
                self.header.count = total_record_count
                self.header.sequence = (self.header.sequence + 1) & 0xffffffff
            elif self.version == 10:
                self.header.sequence = (self.header.sequence +
                                        data_record_count) & 0xffffffff
        _write_component(w, self.header, kwargs)
        for flowset in self.flowsets:
            (<NetflowFlowSet>flowset)._write(w, kwargs)
        w_bytes(w, self.raw_data)
        if kwargs.get('update') and self.version == 10:
            self.header.length = w.n - start
            w_set_u16(w, start + 2, self.header.length)
        return 0


_QI_NETFLOW = Netflow.query_info()
