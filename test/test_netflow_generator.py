# Copyright (c) 2019-2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License"). This software is distributed "AS IS"
# as set forth in the License.

import os
import tempfile
import unittest

from packets.core.inetpkt import Ethernet
from packets.core.pcap import PCAPReader
from packets.query.pcap_query import PcapQuery
from packets.protos.netflow import (
    Netflow,
    NetflowDecodeContext,
    NetflowTemplate,
    NetflowTemplateField,
    NetflowV9Header,
)
from packets.commands.netflow_generator import (
    CISCO_NETFLOW_V9_FIELD_SPECS,
    NetflowV9Generator,
    create_cisco_netflow_v9_template,
    main,
    normalize_template,
)


class TestNetflowGenerator(unittest.TestCase):

    def test_cisco_netflow_v9_template_definition(self):
        template = create_cisco_netflow_v9_template(template_id=256)
        self.assertEqual(template.template_id, 256)
        self.assertEqual(template.version, 9)
        self.assertEqual(len(template.fields), 10)

        expected_elements = [
            (1, 4, 'octetDeltaCount'),       # IN_BYTES
            (2, 4, 'packetDeltaCount'),      # IN_PKTS
            (4, 1, 'protocolIdentifier'),    # PROTOCOL
            (8, 4, 'sourceIPv4Address'),     # SRC_ADDR
            (7, 2, 'sourceTransportPort'),   # SRC_PORT
            (12, 4, 'destinationIPv4Address'), # DST_ADDR
            (11, 2, 'destinationTransportPort'), # DST_PORT
            (10, 2, 'ingressInterface'),     # INPUT_SNMP
            (14, 2, 'egressInterface'),      # OUTPUT_SNMP
            (5, 1, 'ipClassOfService'),      # TCP_FLAGS / ToS
        ]

        for i, (elem_id, flen, name) in enumerate(expected_elements):
            field = template.fields[i]
            self.assertEqual(field.element_id, elem_id)
            self.assertEqual(field.field_length, flen)
            self.assertEqual(field.name, name)

    def test_normalize_template(self):
        # Default
        tmpl_default = normalize_template()
        self.assertEqual(tmpl_default.template_id, 256)
        self.assertEqual(len(tmpl_default.fields), 10)

        # Existing template
        tmpl_existing = NetflowTemplate(300, [NetflowTemplateField(8, 4)], version=9)
        self.assertIs(normalize_template(tmpl_existing), tmpl_existing)

        # List of tuples
        tmpl_tuples = normalize_template([(8, 4), (12, 4), (7, 2)], template_id=500)
        self.assertEqual(tmpl_tuples.template_id, 500)
        self.assertEqual(len(tmpl_tuples.fields), 3)
        self.assertEqual(tmpl_tuples.fields[0].element_id, 8)

        # Invalid spec
        with self.assertRaises(TypeError):
            normalize_template(["invalid"])

    def test_generate_cisco_v9_records_and_decode(self):
        gen = NetflowV9Generator(seed=12345)
        records = gen.generate_records(5)
        self.assertEqual(len(records), 5)

        for rec in records:
            self.assertEqual(rec.template_id, 256)
            # Check presence of all Cisco fields
            self.assertIn('sourceIPv4Address', rec.fields)
            self.assertIn('destinationIPv4Address', rec.fields)
            self.assertIn('sourceTransportPort', rec.fields)
            self.assertIn('destinationTransportPort', rec.fields)
            self.assertIn('protocolIdentifier', rec.fields)
            self.assertIn('octetDeltaCount', rec.fields)
            self.assertIn('packetDeltaCount', rec.fields)
            self.assertIn('ingressInterface', rec.fields)
            self.assertIn('egressInterface', rec.fields)
            self.assertIn('ipClassOfService', rec.fields)

            # Check value types
            self.assertIsInstance(rec.fields['sourceIPv4Address'], str)
            self.assertIsInstance(rec.fields['destinationIPv4Address'], str)
            self.assertIsInstance(rec.fields['sourceTransportPort'], int)
            self.assertIsInstance(rec.fields['destinationTransportPort'], int)
            self.assertIsInstance(rec.fields['protocolIdentifier'], int)
            self.assertIsInstance(rec.fields['octetDeltaCount'], int)
            self.assertIsInstance(rec.fields['packetDeltaCount'], int)
            self.assertIsInstance(rec.fields['ingressInterface'], int)
            self.assertIsInstance(rec.fields['egressInterface'], int)
            self.assertIsInstance(rec.fields['ipClassOfService'], int)

    def test_custom_user_supplied_template(self):
        # Define a custom template with IPv6, MAC, string, and unsigned fields
        custom_fields = [
            NetflowTemplateField(27, 16), # sourceIPv6Address
            NetflowTemplateField(28, 16), # destinationIPv6Address
            NetflowTemplateField(56, 6),  # sourceMacAddress
            NetflowTemplateField(80, 6),  # destinationMacAddress
            NetflowTemplateField(82, 8),  # interfaceName
            NetflowTemplateField(85, 8),  # octetTotalCount (64-bit)
            NetflowTemplateField(86, 8),  # packetTotalCount (64-bit)
            NetflowTemplateField(999, 4), # uncatalogued/raw
        ]
        custom_template = NetflowTemplate(template_id=400, fields=custom_fields, version=9)
        gen = NetflowV9Generator(template=custom_template, seed=999)

        pkt = gen.generate_packet(records=3, include_template=True)
        wire = pkt.pkt2net({'update': 1})

        # Decode using NetflowDecodeContext
        ctx = NetflowDecodeContext()
        decoded = Netflow.dispatch(wire, context=ctx, exporter='192.0.2.1')
        self.assertEqual(len(decoded.records), 3)

        rec = decoded.records[0]
        self.assertIn('sourceIPv6Address', rec.fields)
        self.assertIn('destinationIPv6Address', rec.fields)
        self.assertIn('sourceMacAddress', rec.fields)
        self.assertIn('destinationMacAddress', rec.fields)
        self.assertIn('interfaceName', rec.fields)
        self.assertIn('octetTotalCount', rec.fields)
        self.assertIn('packetTotalCount', rec.fields)
        self.assertIn((0, 999), rec.fields)

        self.assertTrue(rec.fields['sourceIPv6Address'].startswith('2001:db8:'))
        self.assertEqual(len(rec.fields['sourceMacAddress'].split(':')), 6)
        self.assertIsInstance(rec.fields['interfaceName'], str)
        self.assertIsInstance(rec.fields['octetTotalCount'], int)
        self.assertIsInstance(rec.fields[(0, 999)], bytes)
        self.assertEqual(len(rec.fields[(0, 999)]), 4)

    def test_packet_sequence_and_uptime_progression(self):
        gen = NetflowV9Generator(seed=42, base_uptime=1000, base_unix_secs=1700000000, base_sequence=1)
        packets = list(gen.generate_packets(total_records=100, records_per_packet=25, template_interval=2))
        self.assertEqual(len(packets), 4)

        # Check sequence numbers progression across packets
        self.assertEqual(packets[0].header.sequence, 1)
        self.assertEqual(packets[1].header.sequence, 2)
        self.assertEqual(packets[2].header.sequence, 3)
        self.assertEqual(packets[3].header.sequence, 4)

        # Check template flowset frequency (interval=2 means packets 0 and 2 have templates)
        self.assertEqual(len(packets[0].flowsets), 2)  # Template set + Data set
        self.assertEqual(packets[0].flowsets[0].set_id, 0)
        self.assertEqual(packets[0].flowsets[1].set_id, 256)

        self.assertEqual(len(packets[1].flowsets), 1)  # Data set only
        self.assertEqual(packets[1].flowsets[0].set_id, 256)

        self.assertEqual(len(packets[2].flowsets), 2)  # Template set + Data set
        self.assertEqual(len(packets[3].flowsets), 1)  # Data set only

        # Check uptime advancement
        self.assertGreater(packets[1].header.sys_uptime, packets[0].header.sys_uptime)
        self.assertGreater(packets[2].header.sys_uptime, packets[1].header.sys_uptime)

    def test_deterministic_seed_reproducibility(self):
        gen1 = NetflowV9Generator(seed=777)
        pkt1 = gen1.generate_packet(records=5, include_template=True)
        wire1 = pkt1.pkt2net({'update': 1})

        gen2 = NetflowV9Generator(seed=777)
        pkt2 = gen2.generate_packet(records=5, include_template=True)
        wire2 = pkt2.pkt2net({'update': 1})

        self.assertEqual(wire1, wire2)

        gen3 = NetflowV9Generator(seed=888)
        pkt3 = gen3.generate_packet(records=5, include_template=True)
        wire3 = pkt3.pkt2net({'update': 1})

        self.assertNotEqual(wire1, wire3)

    def test_generate_large_pcap_and_verify(self):
        fd, filename = tempfile.mkstemp(suffix='.pcap')
        os.close(fd)
        os.unlink(filename)

        try:
            gen = NetflowV9Generator(seed=555)
            # Generate 500 records in batches of 25 (20 packets)
            total_pkts = gen.generate_pcap(
                filename=filename,
                total_records=500,
                records_per_packet=25,
                template_interval=5,
            )
            self.assertEqual(total_pkts, 20)

            # Read with PCAPReader and decode with NetflowDecodeContext
            ctx = NetflowDecodeContext()
            reader = PCAPReader(
                filename=filename,
                decode_context=ctx,
                l7_ports={2055: Netflow},
            )

            decoded_packets = 0
            total_decoded_records = 0
            for ts, hdr, wire_data in reader:
                frame = Ethernet(wire_data, l7_ports={2055: Netflow}, decode_context=ctx)
                netflow_layer = frame.get_layer('Netflow')
                self.assertIsNotNone(netflow_layer)
                self.assertEqual(netflow_layer.version, 9)
                decoded_packets += 1
                total_decoded_records += len(netflow_layer.records)
            reader.close()

            self.assertEqual(decoded_packets, 20)
            self.assertEqual(total_decoded_records, 500)

            # Query with PcapQuery
            query = PcapQuery(
                filename=filename,
                wshark_fields=['netflow.version', 'netflow.sequence'],
                pkt_classes=[Netflow],
                l7_ports={2055: Netflow},
                decode_context=ctx,
            )
            results = query.query()
            self.assertEqual(len(results), 20)
            self.assertEqual(results[0], (9, 2))
            self.assertEqual(results[1], (9, 3))
            self.assertEqual(results[19], (9, 21))

        finally:
            if os.path.exists(filename):
                os.unlink(filename)

    def test_cli_main(self):
        fd, filename = tempfile.mkstemp(suffix='.pcap')
        os.close(fd)
        os.unlink(filename)

        try:
            # Run CLI to generate PCAP
            rc = main(['-c', '100', '-r', '20', '-o', filename, '--seed', '101'])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(filename))
            self.assertGreater(os.path.getsize(filename), 0)

            # Run in-memory CLI count
            rc2 = main(['-c', '50', '-r', '10'])
            self.assertEqual(rc2, 0)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)


if __name__ == '__main__':
    unittest.main()
