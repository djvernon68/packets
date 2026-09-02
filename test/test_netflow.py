#!/usr/bin/env python

import os
import struct
import sys
import tempfile
import unittest

from packets.commands import netflow_player

from packets.core.pcap import PCAPReader, PCAPWriter
from packets.query.pcap_query import PcapQuery

from packets.protos import netflow
from packets.protos.netflow import IPFIXHeader, Netflow, NetflowCodecPlan, \
    NetflowDataRecord, NetflowDecodeContext, NetflowFlowSet, NetflowSimple, \
    NetflowTemplate, NetflowTemplateField, NetflowTemplateRegistry, \
    NetflowV1Header, NetflowV1Record, NetflowV5Header, NetflowV5Record, \
    NetflowV7Header, NetflowV7Record, NetflowV9Header
from packets.core.inetpkt import Ethernet, \
    NetflowSimple as LegacyNetflowSimple


class TestNetflow(unittest.TestCase):

    @staticmethod
    def netflow_frame(payload, dport=2055):
        udp = struct.pack('!HHHH', 50000, dport, 8 + len(payload), 0) + payload
        ip = (struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(udp), 0, 0,
                          64, 17, 0) + b'\xc0\x00\x02\x0a' +
              b'\xc6\x33\x64\x14' + udp)
        return (b'\x00\x11\x22\x33\x44\x55' +
                b'\x66\x77\x88\x99\xaa\xbb\x08\x00' + ip)

    def test_netflow_v1_pkt_construction_and_update(self):
        header = struct.pack('!HHIII', 1, 1, 123456, 1500000000,
                             123000000)
        record = struct.pack(
            '!4s4s4sHHIIIIHHHBBII',
            b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02',
            b'\x0a\x00\x00\xfe', 10, 11, 12, 1300, 1000, 2000,
            12345, 443, 0x1234, 6, 16, 0x10203040, 0x50607080)
        wire = header + record

        packet = Netflow(wire)
        self.assertEqual(packet.version, 1)
        self.assertIsInstance(packet.header, NetflowV1Header)
        self.assertIsInstance(packet.records[0], NetflowV1Record)
        self.assertEqual(packet.records[0].src_addr, '10.0.0.1')
        self.assertEqual(packet.records[0].dst_port, 443)
        self.assertEqual(packet.records[0].protocol, 6)
        self.assertEqual(packet.records[0].reserved, 0x50607080)
        self.assertIsNone(packet.get_field_val('netflow.sequence'))
        self.assertEqual(packet.pkt2net({}), wire)

        model = Netflow(
            header=NetflowV1Header(count=99, sys_uptime=1, unix_secs=2,
                                   unix_nsecs=3),
            records=[NetflowV1Record(src_addr='192.0.2.1',
                                     dst_addr='198.51.100.2', packets=7,
                                     octets=700, src_port=53,
                                     dst_port=2055, protocol=17)])
        self.assertEqual(Netflow(model.pkt2net({})).header.count, 99)
        updated = Netflow(model.pkt2net({'update': 1}))
        self.assertEqual(updated.header.count, 1)
        self.assertEqual(updated.records[0].octets, 700)

    def test_netflow_v5_pkt_construction_and_update(self):
        header = struct.pack('!HHIIIIBBH', 5, 1, 123456, 1500000000,
                             123000000, 77, 2, 3, 0x4001)
        record = struct.pack(
            '!4s4s4sHHIIIIHHBBBBHHBBH',
            b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02',
            b'\x0a\x00\x00\xfe', 10, 11, 12, 1300, 1000, 2000,
            12345, 443, 0, 0x12, 6, 16, 64512, 64513, 24, 24, 0)
        wire = header + record

        packet = Netflow(wire)
        self.assertEqual(packet.version, 5)
        self.assertIsInstance(packet.header, NetflowV5Header)
        self.assertIsInstance(packet.records[0], NetflowV5Record)
        self.assertEqual(packet.header.sequence, 77)
        self.assertEqual(packet.records[0].src_addr, '10.0.0.1')
        self.assertEqual(packet.get_field_val('netflow.sequence'), 77)
        self.assertEqual(packet.pkt2net({}), wire)

        model = Netflow(
            header=NetflowV5Header(count=99, sys_uptime=100,
                                   unix_secs=200, flow_sequence=10),
            records=[NetflowV5Record(src_addr='192.0.2.1',
                                     dst_addr='198.51.100.2', packets=7,
                                     octets=700, src_port=53,
                                     dst_port=2055, protocol=17)])
        self.assertEqual(Netflow(model.pkt2net({})).header.count, 99)
        updated = Netflow(model.pkt2net({'update': 1}))
        self.assertEqual(updated.header.count, 1)
        self.assertEqual(updated.header.sequence, 11)

    def test_netflow_v7_pkt_construction_and_update(self):
        header = struct.pack('!HHIIIII', 7, 1, 123456, 1500000000,
                             123000000, 77, 0x01020304)
        record = struct.pack(
            '!4s4s4sHHIIIIHHBBBBHHBBHI',
            b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02',
            b'\x0a\x00\x00\xfe', 10, 11, 12, 1300, 1000, 2000,
            12345, 443, 0, 0x12, 6, 16, 64512, 64513, 24, 24,
            0x1234, 0x10203040)
        wire = header + record

        packet = Netflow(wire)
        self.assertEqual(packet.version, 7)
        self.assertIsInstance(packet.header, NetflowV7Header)
        self.assertIsInstance(packet.records[0], NetflowV7Record)
        self.assertEqual(packet.header.sequence, 77)
        self.assertEqual(packet.records[0].router_sc, 0x10203040)
        self.assertEqual(packet.pkt2net({}), wire)

        model = Netflow(
            header=NetflowV7Header(count=99, sys_uptime=1, unix_secs=2,
                                   unix_nsecs=3, flow_sequence=10),
            records=[NetflowV7Record(src_addr='192.0.2.1',
                                     dst_addr='198.51.100.2', packets=7,
                                     octets=700, src_port=53,
                                     dst_port=2055, protocol=17)])
        updated = Netflow(model.pkt2net({'update': 1}))
        self.assertEqual(updated.header.count, 1)
        self.assertEqual(updated.header.sequence, 11)

    def test_netflow_fixed_versions_truncated_and_unknown(self):
        wires = [
            b'\x00\x01\x00\x01broken',
            struct.pack('!HHIII', 1, 1, 1, 2, 3) + b'partial',
            b'\x00\x05\x00\x01broken',
            struct.pack('!HHIIIIBBH', 5, 1, 1, 2, 3, 4,
                        0, 0, 0) + b'partial',
            b'\x00\x07\x00\x01broken',
            struct.pack('!HHIIIII', 7, 1, 1, 2, 3, 4, 5) + b'partial',
            b'\x00\x0bunknown-version-payload',
            b'',
        ]
        for wire in wires:
            packet = Netflow(wire)
            self.assertEqual(packet.pkt2net({}), wire)

    def test_netflow_simple_compatibility_exports(self):
        wire = struct.pack('!HHIII', 9, 2, 100, 200, 300) + b'opaque'

        self.assertIs(LegacyNetflowSimple, NetflowSimple)
        legacy = LegacyNetflowSimple(wire)
        protocol = NetflowSimple(version=9, count=2, sys_uptime=100,
                                 unix_secs=200, unix_nano_seconds=300,
                                 payload=b'opaque')
        self.assertEqual(legacy.pkt2net({}), wire)
        self.assertEqual(protocol.pkt2net({}), wire)
        self.assertEqual(protocol.get_field_val('netflow.unix_secs'), 200)
        self.assertEqual(NetflowSimple.query_info()[0], 2005)
        self.assertEqual(NetflowSimple.default_ports(), [2005, 2055])

    def test_netflow_simple_has_one_implementation(self):
        """There must be exactly one NetflowSimple extension type.

        This module used to define a second NetflowSimple and assign it over
        packets.core.inetpkt.NetflowSimple at import. That made the two names
        compare equal from Python while the core parser's C level layer 7 fast
        path still tested against the original type, so the fast path went
        dead and isinstance() depended on import order. Pinning the defining
        module keeps a re-export from silently becoming a second class again.
        """
        self.assertIs(LegacyNetflowSimple, NetflowSimple)
        self.assertEqual(NetflowSimple.__module__, 'packets.core.inetpkt')

        # Registering the re-exported class must reach the core fast path and
        # produce that same type, byte for byte.
        wire = struct.pack('!HHIII', 5, 1, 100, 200, 300) + b'opaque'
        frame = Ethernet(self.netflow_frame(wire),
                         l7_ports={2055: NetflowSimple})
        layer = frame.get_layer('NetflowSimple')
        self.assertIsInstance(layer, NetflowSimple)
        self.assertIsInstance(layer, LegacyNetflowSimple)
        self.assertEqual(layer.pkt2net({}), wire)

    def test_netflow_nested_dispatch_and_mutable_source_isolation(self):
        wire = (struct.pack('!HHIII', 5, 0, 123456, 1500000000,
                            123000000) + struct.pack('!IBBH', 77, 2, 3,
                                                     0x4001))
        source = bytearray(wire)
        packet = Netflow(source)
        source[0] = 0xff
        self.assertEqual(packet.pkt2net({}), wire)

        frame = Ethernet(self.netflow_frame(wire), l7_ports={2055: Netflow})
        nested = frame.get_layer('Netflow')
        self.assertIsInstance(nested, Netflow)
        self.assertEqual(nested.header.sequence, 77)
        self.assertEqual(frame.pkt2net({}), self.netflow_frame(wire))

    def test_netflow_v9_stateful_template_data(self):
        context = NetflowDecodeContext()
        template_body = struct.pack('!HHHHHH', 256, 2, 8, 4, 2, 4)
        template_set = (struct.pack('!HH', 0, 4 + len(template_body)) +
                        template_body)
        template_wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) +
                         template_set)
        data_body = b'\xc0\x00\x02\x01' + struct.pack('!I', 7)
        data_set = struct.pack('!HH', 256, 4 + len(data_body)) + data_body
        data_wire = (struct.pack('!HHIIII', 9, 1, 101, 201, 11, 42) +
                     data_set)

        template_packet = Netflow(template_wire, context=context,
                                  exporter='198.51.100.1')
        data_packet = Netflow(data_wire, context=context,
                              exporter='198.51.100.1')
        self.assertEqual(template_packet.flowsets[0].templates[0].template_id,
                         256)
        self.assertEqual(data_packet.records[0].fields[
            'sourceIPv4Address'], '192.0.2.1')
        self.assertEqual(data_packet.records[0].fields[
            'packetDeltaCount'], 7)
        self.assertEqual(template_packet.pkt2net({}), template_wire)
        self.assertEqual(data_packet.pkt2net({}), data_wire)

        unresolved = Netflow(data_wire, context=NetflowDecodeContext(),
                             exporter='198.51.100.1')
        self.assertEqual(unresolved.records, [])
        self.assertEqual(unresolved.flowsets[0].raw_data, data_body)
        self.assertEqual(unresolved.pkt2net({}), data_wire)

        updated = Netflow(data_packet.pkt2net({'update': 1}),
                          context=context, exporter='198.51.100.1')
        self.assertEqual(updated.header.count, 1)
        self.assertEqual(updated.header.sequence, 12)

    def test_netflow_v9_tutorial_generation_and_decode(self):
        template = NetflowTemplate(
            256, [NetflowTemplateField(8, 4),
                  NetflowTemplateField(12, 4),
                  NetflowTemplateField(7, 2),
                  NetflowTemplateField(11, 2),
                  NetflowTemplateField(2, 4)], version=9)
        record = template.record_class(
            template_id=template.template_id,
            fields={'sourceIPv4Address': '192.0.2.10',
                    'destinationIPv4Address': '198.51.100.20',
                    'sourceTransportPort': 49152,
                    'destinationTransportPort': 2055,
                    'packetDeltaCount': 25},
            template=template, codec_plan=template.codec_plan)
        template_set = NetflowFlowSet(
            set_id=0, templates=[template], version=9)
        data_set = NetflowFlowSet(
            set_id=template.template_id, records=[record], version=9)
        packet = Netflow(
            header=NetflowV9Header(sys_uptime=123456, unix_secs=1700000000,
                                   sequence=10, source_id=42),
            flowsets=[template_set, data_set])

        wire = packet.pkt2net({'update': 1})
        decoded = Netflow.dispatch(
            wire, context=NetflowDecodeContext(), exporter='192.0.2.1')
        frame = Ethernet(self.netflow_frame(wire),
                         l7_ports={2055: Netflow},
                         decode_context=NetflowDecodeContext())
        nested = frame.get_layer('Netflow')

        self.assertEqual(packet.header.count, 2)
        self.assertEqual(packet.header.sequence, 11)
        self.assertEqual(decoded.records[0].fields['sourceIPv4Address'],
                         '192.0.2.10')
        self.assertEqual(decoded.records[0].fields[
            'destinationIPv4Address'], '198.51.100.20')
        self.assertEqual(decoded.records[0].fields['sourceTransportPort'],
                         49152)
        self.assertEqual(decoded.records[0].fields[
            'destinationTransportPort'], 2055)
        self.assertEqual(decoded.records[0].fields['packetDeltaCount'], 25)
        self.assertEqual(decoded.pkt2net({}), wire)
        self.assertEqual(nested.records[0].fields['packetDeltaCount'], 25)
        self.assertEqual(frame.pkt2net({}), self.netflow_frame(wire))

    def test_netflow_generated_record_cache_edit_and_replacement(self):
        context = NetflowDecodeContext()
        template_body = struct.pack('!HHHHHH', 256, 2, 8, 4, 2, 4)
        template_wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) +
                         struct.pack('!HH', 0, 4 + len(template_body)) +
                         template_body)
        data_body = b'\xc0\x00\x02\x01' + struct.pack('!I', 7)
        data_wire = (struct.pack('!HHIIII', 9, 1, 101, 201, 11, 42) +
                     struct.pack('!HH', 256, 4 + len(data_body)) + data_body)

        Netflow(template_wire, context=context, exporter='router')
        first = Netflow(data_wire, context=context, exporter='router')
        second = Netflow(data_wire, context=context, exporter='router')
        record = first.records[0]
        template = context.resolve_template('router', 42, 256, version=9)

        self.assertIsInstance(template.codec_plan, NetflowCodecPlan)
        self.assertIs(record.codec_plan, template.codec_plan)
        self.assertIs(type(record), type(second.records[0]))
        self.assertIsNot(type(record), NetflowDataRecord)
        self.assertTrue(type(record).__name__.startswith(
            'NetflowV9Record256'))
        self.assertEqual(record.fields[(0, 8)], '192.0.2.1')
        self.assertEqual(record.fields[(0, 2)], 7)
        self.assertEqual(record.raw_data, data_body)
        self.assertEqual(len(record.fields), 4)
        self.assertEqual(dict(record.fields), {
            'sourceIPv4Address': '192.0.2.1',
            (0, 8): '192.0.2.1',
            'packetDeltaCount': 7,
            (0, 2): 7,
        })
        self.assertEqual(record.raw_fields[(0, 8)], b'\xc0\x00\x02\x01')
        self.assertEqual(record.raw_fields[(0, 2)], struct.pack('!I', 7))
        self.assertEqual(record.original_fields['packetDeltaCount'], 7)
        self.assertEqual(record.original_fields[(0, 2)], 7)

        other_context = NetflowDecodeContext()
        Netflow(template_wire, context=other_context, exporter='router')
        other = Netflow(data_wire, context=other_context, exporter='router')
        self.assertIs(type(record), type(other.records[0]))
        self.assertIs(record.codec_plan, other.records[0].codec_plan)

        record.fields['packetDeltaCount'] = 8
        self.assertEqual(record.fields[(0, 2)], 8)
        record.fields[(0, 2)] = 9
        self.assertEqual(record.fields['packetDeltaCount'], 9)
        edited_body = b'\xc0\x00\x02\x01' + struct.pack('!I', 9)
        edited_wire = (struct.pack('!HHIIII', 9, 1, 101, 201, 11, 42) +
                       struct.pack('!HH', 256, 4 + len(edited_body)) +
                       edited_body)
        self.assertEqual(first.pkt2net({}), edited_wire)

        replacement_body = struct.pack('!HHHH', 256, 1, 12, 4)
        replacement_wire = (
            struct.pack('!HHIIII', 9, 1, 102, 202, 12, 42) +
            struct.pack('!HH', 0, 4 + len(replacement_body)) +
            replacement_body)
        Netflow(replacement_wire, context=context, exporter='router')
        replacement_data = (
            struct.pack('!HHIIII', 9, 1, 103, 203, 13, 42) +
            struct.pack('!HH', 256, 8) + b'\xc6\x33\x64\x01')
        replaced = Netflow(replacement_data, context=context,
                           exporter='router')
        self.assertIsNot(type(record), type(replaced.records[0]))
        self.assertEqual(replaced.records[0].fields[
            'destinationIPv4Address'], '198.51.100.1')

    def test_netflow_generated_address_mac_and_string_codecs(self):
        template = NetflowTemplate(
            400, [NetflowTemplateField(27, 16),
                  NetflowTemplateField(56, 6),
                  NetflowTemplateField(82, 6),
                  NetflowTemplateField(83, 3)], version=9)
        body = (bytes.fromhex('20010db8000000000000000000000001') +
                bytes.fromhex('001122aabbcc') + b'wan\x00\x00\x00' +
                b'a\xff\x00')

        record, offset, valid = template.codec_plan.decode(
            body, 0, template)

        self.assertTrue(valid)
        self.assertEqual(offset, len(body))
        self.assertEqual(record.fields['sourceIPv6Address'], '2001:db8::1')
        self.assertEqual(record.fields['sourceMacAddress'],
                         '00:11:22:aa:bb:cc')
        self.assertEqual(record.fields['interfaceName'], 'wan')
        self.assertEqual(record.fields['interfaceDescription'], 'a\ufffd')
        self.assertEqual(record.pkt2net({}), body)

    def test_netflow_registry_scope_replacement_and_withdrawal(self):
        context = NetflowDecodeContext()
        scope_a = ('192.0.2.1', 10001, 2055, 'udp')
        scope_b = ('192.0.2.1', 10002, 2055, 'udp')
        v9 = NetflowTemplate(300, [NetflowTemplateField(8, 4)], version=9)
        v10 = NetflowTemplate(300, [NetflowTemplateField(12, 4)],
                              version=10)

        self.assertIsInstance(context.registry, NetflowTemplateRegistry)
        context.registry.register_template(9, scope_a, 77, v9)
        context.registry.register_template(10, scope_a, 77, v10)
        context.registry.register_template(9, scope_b, 77, v10)
        self.assertIs(context.registry.resolve_template(
            9, scope_a, 77, 300), v9)
        self.assertIs(context.registry.resolve_template(
            10, scope_a, 77, 300), v10)
        self.assertIs(context.registry.resolve_template(
            9, scope_b, 77, 300), v10)
        self.assertIsNone(NetflowDecodeContext().registry.resolve_template(
            9, scope_a, 77, 300))

        template_body = struct.pack('!HHHH', 300, 1, 8, 4)
        template_wire = (struct.pack('!HHIIII', 9, 1, 0, 0, 0, 77) +
                         struct.pack('!HH', 0, 4 + len(template_body)) +
                         template_body)
        Netflow(template_wire, context=context, exporter='exporter-a')
        withdrawal = struct.pack('!HH', 300, 0)
        withdrawal_wire = (struct.pack('!HHIIII', 9, 1, 0, 0, 2, 77) +
                           struct.pack('!HH', 0, 8) + withdrawal)
        Netflow(withdrawal_wire, context=context, exporter='exporter-a')
        self.assertIsNone(context.resolve_template('exporter-a', 77, 300))

    def test_ipfix_enterprise_variable_length_and_options(self):
        context = NetflowDecodeContext()
        fields = (struct.pack('!HH', 8, 4) +
                  struct.pack('!HH', 82, 65535) +
                  struct.pack('!HHI', 0x8001, 2, 32473))
        template_body = struct.pack('!HH', 300, 3) + fields
        template_set = (struct.pack('!HH', 2, 4 + len(template_body)) +
                        template_body)
        template_wire = (struct.pack('!HHIII', 10,
                                     16 + len(template_set), 1000, 20, 55) +
                         template_set)
        Netflow(template_wire, context=context, exporter='192.0.2.10')

        data_body = b'\xc6\x33\x64\x02\x03wan\x12\x34\x00\x00'
        data_set = struct.pack('!HH', 300, 4 + len(data_body)) + data_body
        data_wire = (struct.pack('!HHIII', 10, 16 + len(data_set),
                                1001, 21, 55) + data_set)
        data_packet = Netflow(data_wire, context=context,
                              exporter='192.0.2.10')
        self.assertEqual(data_packet.records[0].fields[
            'sourceIPv4Address'], '198.51.100.2')
        self.assertEqual(data_packet.records[0].fields['interfaceName'],
                         'wan')
        self.assertEqual(data_packet.records[0].fields[(32473, 1)],
                         b'\x12\x34')
        self.assertEqual(data_packet.records[0].raw_fields[(0, 82)], b'wan')
        self.assertEqual(data_packet.records[0].raw_fields[(32473, 1)],
                         b'\x12\x34')
        self.assertEqual(data_packet.flowsets[0].padding, b'\x00\x00')
        self.assertEqual(data_packet.pkt2net({}), data_wire)

        model_template = NetflowTemplate(
            300, [NetflowTemplateField(8, 4),
                  NetflowTemplateField(82, 65535),
                  NetflowTemplateField(1, 2, 32473)], version=10)
        model_packet = Netflow(
            header=IPFIXHeader(length=len(template_wire), export_time=1000,
                               sequence=20, observation_domain_id=55),
            flowsets=[NetflowFlowSet(set_id=2,
                                     templates=[model_template], version=10)])
        self.assertEqual(model_packet.pkt2net({}), template_wire)

    def test_netflow_options_data_uses_generated_codec(self):
        context = NetflowDecodeContext()
        options_body = (struct.pack('!HHH', 400, 4, 4) +
                        struct.pack('!HHHH', 10, 4, 34, 4) + b'\x00\x00')
        template_wire = (struct.pack('!HHIIII', 9, 1, 0, 0, 0, 5) +
                         struct.pack('!HH', 1, 4 + len(options_body)) +
                         options_body)
        data_body = struct.pack('!II', 10, 100)
        data_wire = (struct.pack('!HHIIII', 9, 1, 0, 0, 1, 5) +
                     struct.pack('!HH', 400, 4 + len(data_body)) + data_body)

        Netflow(template_wire, context=context, exporter='router')
        packet = Netflow(data_wire, context=context, exporter='router')
        record = packet.records[0]
        self.assertIsNot(type(record), NetflowDataRecord)
        self.assertEqual(record.fields['ingressInterface'], 10)
        self.assertEqual(record.fields['samplingInterval'], 100)
        self.assertEqual(record.pkt2net({}), data_body)

    def test_netflow_repeated_parse_write_owns_input(self):
        fixtures = [
            struct.pack('!HHIII', 1, 0, 1, 2, 3),
            struct.pack('!HHIIIIBBH', 5, 0, 1, 2, 3, 4, 0, 0, 0),
            struct.pack('!HHIIIII', 7, 0, 1, 2, 3, 4, 0),
        ]
        for wire in fixtures:
            current = wire
            for unused_index in range(100):
                source = bytearray(current)
                packet = Netflow(source)
                source[:] = b'\xff' * len(source)
                current = packet.pkt2net({})
                self.assertEqual(current, wire)

    def test_netflow_malformed_templates_and_field_metadata(self):
        with self.assertRaises(ValueError):
            NetflowTemplate(256, [NetflowTemplateField(8, 0)], version=9)

        malformed_set = struct.pack('!HH', 256, 3) + b'x'
        wire = (struct.pack('!HHIIII', 9, 0, 0, 0, 0, 1) +
                malformed_set)
        packet = Netflow(wire)
        self.assertTrue(packet.flowsets[0].malformed)
        self.assertEqual(packet.pkt2net({}), wire)

        zero_length_option = (struct.pack('!HHH', 300, 4, 0) +
                              struct.pack('!HH', 8, 0))
        zero_length_set = (struct.pack(
            '!HH', 1, 4 + len(zero_length_option)) + zero_length_option)
        zero_length_wire = (struct.pack(
            '!HHIIII', 9, 1, 0, 0, 0, 1) + zero_length_set)
        zero_length_packet = Netflow(zero_length_wire)
        self.assertTrue(zero_length_packet.flowsets[0].malformed)
        self.assertEqual(zero_length_packet.pkt2net({}), zero_length_wire)

        timestamp = NetflowTemplateField(152, 8)
        interface = NetflowTemplateField(83, 65535)
        enterprise = NetflowTemplateField(152, 8, 32473)
        unknown = NetflowTemplateField(999, 4)
        self.assertEqual((timestamp.name, timestamp.data_type),
                         ('flowStartMilliseconds', 'unsigned'))
        self.assertEqual((interface.name, interface.data_type),
                         ('interfaceDescription', 'string'))
        self.assertEqual((enterprise.name, enterprise.data_type),
                         (None, 'bytes'))
        self.assertEqual((unknown.name, unknown.data_type), (None, 'bytes'))

    def test_netflow_v9_high_element_ids_are_not_enterprise(self):
        """NetFlow v9 has no enterprise bit, so 0x8000 is part of the id.

        RFC 7011 3.2 gives IPFIX an Enterprise bit in the top bit of the
        field specifier: when it is set the low 15 bits are the element id
        and a 4 byte Private Enterprise Number follows. RFC 3954 8 gives v9
        no such bit -- all 16 bits are the field type, and 32768 and up are
        ordinary vendor field types. Cisco ASA NSEL uses exactly that range.

        The parser applied the IPFIX rule to both versions, so a v9 template
        carrying 33000 came out as element 232 and then consumed the next 4
        bytes as a PEN. That desynchronized the rest of the template, the
        whole set was marked malformed, no template was learned, and every
        data set from that exporter fell back to NetflowSimple forever.
        """
        context = NetflowDecodeContext()
        template_body = (struct.pack('!HH', 256, 3) +
                         struct.pack('!HH', 8, 4) +
                         struct.pack('!HH', 33000, 2) +
                         struct.pack('!HH', 40000, 1))
        template_wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) +
                         struct.pack('!HH', 0, 4 + len(template_body)) +
                         template_body)
        packet = Netflow.dispatch(template_wire, context=context,
                                  exporter='192.0.2.10')
        self.assertIsInstance(packet, Netflow)
        self.assertFalse(packet.flowsets[0].malformed)
        template = packet.flowsets[0].templates[0]
        self.assertEqual([f.element_id for f in template.fields],
                         [8, 33000, 40000])
        self.assertEqual([f.enterprise_number for f in template.fields],
                         [None, None, None])
        self.assertEqual(packet.pkt2net({}), template_wire)

        data_body = b'\xc0\x00\x02\x01' + b'\x12\x34' + b'\x07'
        data_wire = (struct.pack('!HHIIII', 9, 1, 101, 201, 11, 42) +
                     struct.pack('!HH', 256, 4 + len(data_body)) + data_body)
        decoded = Netflow.dispatch(data_wire, context=context,
                                   exporter='192.0.2.10')
        self.assertIsInstance(decoded, Netflow)
        self.assertEqual(decoded.records[0].fields['sourceIPv4Address'],
                         '192.0.2.1')
        self.assertEqual(decoded.records[0].fields[33000], b'\x12\x34')
        self.assertEqual(decoded.records[0].fields[40000], b'\x07')
        self.assertEqual(decoded.pkt2net({}), data_wire)

        # IPFIX must still apply the bit. 33000 is 0x8000 | 232, so the very
        # bytes read above as element 33000 are element 232 with a private
        # enterprise number here -- the two versions really do disagree about
        # what this specifier means, which is why the parser needs to know
        # which one it is reading.
        ipfix_body = (struct.pack('!HH', 256, 1) +
                      struct.pack('!HHI', 33000, 4, 32473))
        ipfix_wire = (struct.pack('!HHIII', 10, 16 + 4 + len(ipfix_body),
                                  200, 11, 42) +
                      struct.pack('!HH', 2, 4 + len(ipfix_body)) + ipfix_body)
        ipfix = Netflow(ipfix_wire, exporter='192.0.2.10',
                        context=NetflowDecodeContext())
        field = ipfix.flowsets[0].templates[0].fields[0]
        self.assertEqual((field.element_id, field.enterprise_number),
                         (232, 32473))
        self.assertEqual(ipfix.pkt2net({}), ipfix_wire)

    def test_netflow_malformed_flowset_falls_back_to_simple(self):
        """A datagram we cannot fully read dispatches to NetflowSimple.

        Only a data set whose template was unknown used to raise the fallback
        flag. A template set the parser could not read left it clear, so
        dispatch handed back a Netflow with some flowsets decoded, some
        marked malformed and no signal to the caller that anything was
        missing. Preserving such a datagram through NetflowSimple is what the
        NetFlow support plan asks for.
        """
        context = NetflowDecodeContext()
        # 40 field specifiers claimed, 8 bytes of body to hold them.
        template_body = struct.pack('!HH', 256, 40) + struct.pack('!HH', 8, 4)
        wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) +
                struct.pack('!HH', 0, 4 + len(template_body)) + template_body)
        packet = Netflow(wire, context=context, exporter='192.0.2.10')
        self.assertTrue(packet.flowsets[0].malformed)
        self.assertEqual(packet.pkt2net({}), wire)

        simple = Netflow.dispatch(wire, context=context,
                                  exporter='192.0.2.10')
        self.assertIsInstance(simple, NetflowSimple)
        self.assertEqual(simple.pkt2net({}), wire)

        frame_wire = self.netflow_frame(wire)
        frame = Ethernet(frame_wire, l7_ports={2055: Netflow},
                         decode_context=context)
        self.assertIsInstance(frame.get_layer('NetflowSimple'), NetflowSimple)
        self.assertEqual(frame.pkt2net({}), frame_wire)

        # A set header whose length runs past the datagram is the other way
        # a flowset gets marked malformed, and it means the same thing.
        truncated = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) +
                     struct.pack('!HH', 0, 400) + template_body)
        self.assertIsInstance(
            Netflow.dispatch(truncated, context=context,
                             exporter='192.0.2.10'), NetflowSimple)

        # A datagram that reads cleanly is still a Netflow.
        good_body = struct.pack('!HHHH', 256, 1, 8, 4)
        good = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) +
                struct.pack('!HH', 0, 4 + len(good_body)) + good_body)
        self.assertIsInstance(
            Netflow.dispatch(good, context=context, exporter='192.0.2.10'),
            Netflow)

    def test_netflow_unknown_template_fallback_and_transition(self):
        context = NetflowDecodeContext()
        template_body = struct.pack('!HHHH', 256, 1, 8, 4)
        template_wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) +
                         struct.pack('!HH', 0, 4 + len(template_body)) +
                         template_body)
        data_body = b'\xc0\x00\x02\x01'
        data_wire = (struct.pack('!HHIIII', 9, 1, 101, 201, 11, 42) +
                     struct.pack('!HH', 256, 4 + len(data_body)) + data_body)

        unresolved = Netflow.dispatch(data_wire, context=context,
                                      exporter='192.0.2.10')
        self.assertIsInstance(unresolved, NetflowSimple)
        self.assertEqual(unresolved.pkt2net({}), data_wire)

        frame = Ethernet(self.netflow_frame(data_wire),
                         l7_ports={2055: Netflow}, decode_context=context)
        self.assertIsInstance(frame.get_layer('NetflowSimple'), NetflowSimple)

        Netflow.dispatch(template_wire, context=context,
                         exporter='192.0.2.10')
        resolved = Netflow.dispatch(data_wire, context=context,
                                    exporter='192.0.2.10')
        self.assertIsInstance(resolved, Netflow)
        self.assertEqual(resolved.records[0].fields[
            'sourceIPv4Address'], '192.0.2.1')

        nested_context = NetflowDecodeContext()
        Ethernet(self.netflow_frame(template_wire),
                 l7_ports={2055: Netflow}, decode_context=nested_context)
        frame = Ethernet(self.netflow_frame(data_wire),
                         l7_ports={2055: Netflow},
                         decode_context=nested_context)
        self.assertEqual(frame.get_layer('Netflow').records[0].fields[
            'sourceIPv4Address'], '192.0.2.1')

    def test_netflow_force_simple_and_same_packet_learning(self):
        context = NetflowDecodeContext()
        template_body = struct.pack('!HHHH', 256, 1, 12, 4)
        template_set = (struct.pack('!HH', 0, 4 + len(template_body)) +
                        template_body)
        data_body = b'\xc6\x33\x64\x01'
        data_set = struct.pack('!HH', 256, 4 + len(data_body)) + data_body
        combined_wire = (struct.pack('!HHIIII', 9, 2, 101, 201, 11, 42) +
                         data_set + template_set)

        combined = Netflow.dispatch(combined_wire, context=context,
                                    exporter='198.51.100.1')
        self.assertIsInstance(combined, Netflow)
        self.assertEqual(combined.flowsets[0].records[0].fields[
            'destinationIPv4Address'], '198.51.100.1')
        self.assertEqual(combined.pkt2net({}), combined_wire)

        context.force_simple = True
        forced = Netflow.dispatch(combined_wire, context=context,
                                  exporter='198.51.100.1')
        self.assertIsInstance(forced, NetflowSimple)
        self.assertEqual(forced.pkt2net({}), combined_wire)

        frame = Ethernet(self.netflow_frame(combined_wire),
                         l7_ports={2055: Netflow}, decode_context=context)
        self.assertIsInstance(frame.get_layer('NetflowSimple'), NetflowSimple)

        ipfix_template_set = (
            struct.pack('!HH', 2, 4 + len(template_body)) + template_body)
        ipfix_wire = (struct.pack(
            '!HHIII', 10, 16 + len(data_set) + len(ipfix_template_set),
            200, 11, 42) + data_set + ipfix_template_set)
        ipfix = Netflow.dispatch(ipfix_wire, context=NetflowDecodeContext(),
                                 exporter='198.51.100.1')
        self.assertIsInstance(ipfix, Netflow)
        self.assertEqual(ipfix.records[0].fields[
            'destinationIPv4Address'], '198.51.100.1')

    def test_netflow_pcap_query_reuses_decode_context(self):
        template_body = struct.pack('!HHHH', 256, 1, 8, 4)
        template_wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) +
                         struct.pack('!HH', 0, 4 + len(template_body)) +
                         template_body)
        data_body = b'\xc0\x00\x02\x01'
        data_wire = (struct.pack('!HHIIII', 9, 1, 101, 201, 11, 42) +
                     struct.pack('!HH', 256, 4 + len(data_body)) + data_body)
        context = NetflowDecodeContext()
        fd, filename = tempfile.mkstemp(suffix='.pcap')
        os.close(fd)
        os.unlink(filename)
        try:
            writer = PCAPWriter(filename=filename, snaplen=65535)
            writer.dump_pkt(self.netflow_frame(template_wire), 1000, 0)
            writer.dump_pkt(self.netflow_frame(data_wire), 1001, 0)
            writer.close()

            reader = PCAPReader(filename=filename,
                                decode_context=context)
            self.assertIs(reader.decode_context, context)
            reader.close()

            query = PcapQuery(
                filename=filename,
                wshark_fields=['netflow.version', 'netflow.sequence'],
                pkt_classes=[Netflow], l7_ports={2055: Netflow},
                decode_context=context)
            self.assertIs(query.decode_context, context)
            self.assertEqual(query.query(), [(9, 10), (9, 11)])
            self.assertIsNotNone(context.resolve_template(
                ('192.0.2.10', 50000, 2055, 'udp'), 42, 256, version=9))
        finally:
            if os.path.exists(filename):
                os.unlink(filename)

    def test_netflow_player_forces_simple_replay(self):
        calls = []

        def replay_raw(*args, **kwargs):
            calls.append(('raw', kwargs))
            return 0

        def replay_system(*args, **kwargs):
            calls.append(('system', kwargs))
            return 0

        fd, filename = tempfile.mkstemp(suffix='.pcap')
        os.close(fd)
        original_raw = netflow_player.netflow_replay_raw_sock
        original_system = netflow_player.netflow_replay_system_sock
        original_devices = netflow_player.known_devices
        original_argv = sys.argv
        netflow_player.netflow_replay_raw_sock = replay_raw
        netflow_player.netflow_replay_system_sock = replay_system
        # --device is checked against the devices libpcap reports, and the
        # name below is not on every host. What is under test here is that
        # main() passes force_simple down, not this machine's NICs.
        netflow_player.known_devices = lambda: ['eth0']
        try:
            sys.argv = ['netflow-player', '--file', filename,
                        '--dest_ip', '198.51.100.20', '--spoofing',
                        '--device', 'eth0']
            with self.assertRaises(SystemExit) as raw_exit:
                netflow_player.main()
            self.assertEqual(raw_exit.exception.code, 0)

            sys.argv = ['netflow-player', '--file', filename,
                        '--dest_ip', '198.51.100.20']
            with self.assertRaises(SystemExit) as system_exit:
                netflow_player.main()
            self.assertEqual(system_exit.exception.code, 0)
        finally:
            netflow_player.netflow_replay_raw_sock = original_raw
            netflow_player.netflow_replay_system_sock = original_system
            netflow_player.known_devices = original_devices
            sys.argv = original_argv
            os.unlink(filename)

        self.assertEqual([call[0] for call in calls], ['raw', 'system'])
        for call in calls:
            self.assertTrue(call[1]['decode_context'].force_simple)

    def test_netflow_v9_short_zero_record_is_not_padding(self):
        """A 2 byte all zero flow record is a record, not set padding.

        RFC 3954 s5.3 lets a data set be padded to a 4 byte boundary, so up
        to 3 trailing bytes are not a record. The decoder decided that on
        length alone, so the second of two zero valued records from a 2 byte
        template was thrown away and header.count came back one short of
        what was on the wire. How long a record is comes from the template.
        """
        context = NetflowDecodeContext()
        template_body = struct.pack('!HHHH', 256, 1, 7, 2)
        template_set = (struct.pack('!HH', 0, 4 + len(template_body)) +
                        template_body)
        data_body = b'\x00\x00' + b'\x00\x00'
        data_set = struct.pack('!HH', 256, 4 + len(data_body)) + data_body
        wire = (struct.pack('!HHIIII', 9, 3, 100, 200, 10, 42) +
                template_set + data_set)

        pkt = Netflow(wire, context=context, exporter='198.51.100.1')
        self.assertEqual(len(pkt.records), 2)
        self.assertEqual([record.raw_data for record in pkt.records],
                         [b'\x00\x00', b'\x00\x00'])
        self.assertEqual(pkt.flowsets[1].padding, b'')
        self.assertEqual(pkt.pkt2net({}), wire)

        # count is every record in the datagram, templates included.
        updated = Netflow(pkt.pkt2net({'update': 1}),
                          context=NetflowDecodeContext(),
                          exporter='198.51.100.1')
        self.assertEqual(updated.header.count, 3)

        # Genuine padding is still padding: 2 zero bytes cannot hold a
        # record from a 4 byte template.
        wide_template = struct.pack('!HHHH', 257, 1, 8, 4)
        wide_set = (struct.pack('!HH', 0, 4 + len(wide_template)) +
                    wide_template)
        padded_body = b'\x0a\x00\x00\x01' + b'\x00\x00'
        padded_set = (struct.pack('!HH', 257, 4 + len(padded_body)) +
                      padded_body)
        padded_wire = (struct.pack('!HHIIII', 9, 2, 100, 200, 11, 42) +
                       wide_set + padded_set)
        padded = Netflow(padded_wire, context=NetflowDecodeContext(),
                         exporter='198.51.100.2')
        self.assertEqual(len(padded.records), 1)
        self.assertEqual(padded.flowsets[1].padding, b'\x00\x00')
        self.assertEqual(padded.pkt2net({}), padded_wire)

    def test_netflow_v9_record_outside_a_flowset_is_reported(self):
        """v9 and IPFIX records live in a flowset; a stray one is an error.

        _write walks flowsets for these versions, so a record attached
        straight to .records was written nowhere at all and pkt2net()
        returned a header with no body and no complaint.
        """
        context = NetflowDecodeContext()
        template_body = struct.pack('!HHHH', 256, 1, 7, 2)
        template_set = (struct.pack('!HH', 0, 4 + len(template_body)) +
                        template_body)
        data_body = b'\x12\x34'
        data_set = struct.pack('!HH', 256, 4 + len(data_body)) + data_body
        wire = (struct.pack('!HHIIII', 9, 2, 100, 200, 10, 42) +
                template_set + data_set)

        pkt = Netflow(wire, context=context, exporter='198.51.100.1')
        self.assertEqual(pkt.pkt2net({}), wire)

        # The same record, also listed outside any flowset.
        pkt.records.append(pkt.records[0])
        self.assertEqual(pkt.pkt2net({}), wire)

        stray = NetflowDataRecord(template_id=256, raw_data=b'\x56\x78')
        pkt.records.append(stray)
        with self.assertRaises(ValueError) as caught:
            pkt.pkt2net({})
        self.assertIn('belong to no flowset', str(caught.exception))

    def test_netflow_template_artifact_cache_is_bounded(self):
        """The codec plan cache evicts instead of growing forever.

        Every distinct template signature pinned a generated record class
        in a module level dict that nothing ever trimmed, so a collector
        seeing many exporters or many template revisions leaked slowly.
        """
        entries, original_limit = netflow.template_artifact_cache_info()
        netflow.clear_template_artifact_cache()
        try:
            netflow.set_template_artifact_cache_limit(8)
            registry = NetflowTemplateRegistry()
            for length in range(1, 41):
                registry.register_template(
                    9, '198.51.100.1', 42,
                    NetflowTemplate(256,
                                    [NetflowTemplateField(7, length)],
                                    False, 9, False))
            entries, limit = netflow.template_artifact_cache_info()
            self.assertEqual(limit, 8)
            self.assertLessEqual(entries, 8)
            # An evicted signature simply costs one rebuild.
            template = registry.resolve_template(9, '198.51.100.1', 42, 256)
            self.assertIsNotNone(template.codec_plan)
            self.assertRaises(ValueError,
                              netflow.set_template_artifact_cache_limit, 0)
        finally:
            netflow.set_template_artifact_cache_limit(original_limit)
            netflow.clear_template_artifact_cache()

    def test_netflow_parse_errors_reach_the_caller(self):
        """An exception raised while parsing propagates out of __init__.

        _parse was declared 'cdef void', and a cdef function with no
        exception value cannot propagate: Cython printed the traceback and
        returned, handing back a half initialised packet that looked fine.
        """
        class Boom(object):
            force_simple = False

            def resolve_template(self, *args, **kwargs):
                raise RuntimeError('resolve_template exploded')

            def register_template(self, *args, **kwargs):
                raise RuntimeError('register_template exploded')

            def withdraw_templates(self, *args, **kwargs):
                raise RuntimeError('withdraw_templates exploded')

        data_body = b'\x12\x34'
        data_set = struct.pack('!HH', 256, 4 + len(data_body)) + data_body
        wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 10, 42) + data_set)

        with self.assertRaises(RuntimeError) as caught:
            Netflow(wire, context=Boom(), exporter='198.51.100.1')
        self.assertIn('resolve_template exploded', str(caught.exception))

    def test_netflow_default_ports_overlap_on_2055(self):
        """Both NetFlow classes claim 2055, and that is now documented.

        A caller merging both into one l7_ports mapping keeps whichever
        went in last, silently, and the two are not interchangeable.
        """
        self.assertEqual(Netflow.default_ports(), [2055])
        self.assertEqual(NetflowSimple.default_ports(), [2005, 2055])
        self.assertEqual(
            set(Netflow.default_ports()) & set(NetflowSimple.default_ports()),
            {2055})
        for cls in (Netflow, NetflowSimple):
            self.assertIn('2055', cls.default_ports.__doc__)


if __name__ == '__main__':
    unittest.main()