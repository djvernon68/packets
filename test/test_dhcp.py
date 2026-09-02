#!/usr/bin/env python

import gc
import struct
import unittest
from array import array

from packets.core.inetpkt import NullPkt, UDP
from packets.protos.dhcp import DHCP, DHCP6, DHCP6Option, DHCPOption, \
    DHCP_MAGIC, DHCP_OPT_END, DHCP_OPT_MESSAGE_TYPE, DHCP_OPT_PAD, \
    DHCP6_RELAY_FORWARD, DHCP6_SOLICIT


class DHCPTestCase(unittest.TestCase):

    def test_dhcp_independent_wire_fixture(self):
        wire = struct.pack(
            '!BBBBIHH4s4s4s4s16s64s128sI',
            1, 1, 6, 0, 0x89abcdef, 12, 0x8000,
            b'\x00\x00\x00\x00', b'\x0a\x00\x00\x64',
            b'\x0a\x00\x00\x01', b'\x00\x00\x00\x00',
            b'\x00\x11\x22\x33\x44\x55' + b'\x00' * 10,
            b'server' + b'\x00' * 58,
            b'boot.img' + b'\x00' * 120,
            DHCP_MAGIC)
        wire += b'\x35\x01\x05\xde\x02\xaa\xbb\xff\x00\x00'

        packet = DHCP(wire)
        self.assertEqual(packet.xid, 0x89abcdef)
        self.assertEqual(packet.yiaddr, '10.0.0.100')
        self.assertEqual(packet.message_type, 5)
        self.assertEqual(packet.options[1].code, 222)
        self.assertEqual(packet.options[1].data, b'\xaa\xbb')
        self.assertEqual(packet.data, b'\x00\x00')
        self.assertEqual(packet.pkt2net({}), wire)

    def test_dhcp_option_roundtrip_and_markers(self):
        option = DHCPOption(code=222, data=b'\x01\x02\x03')
        wire = option.pkt2net({})
        self.assertEqual(wire, b'\xde\x03\x01\x02\x03')
        parsed = DHCPOption(wire)
        self.assertEqual(parsed.code, 222)
        self.assertEqual(parsed.data, b'\x01\x02\x03')
        self.assertEqual(parsed.pkt2net({}), wire)

        self.assertEqual(DHCPOption(code=DHCP_OPT_PAD).pkt2net({}), b'\x00')
        self.assertEqual(DHCPOption(code=DHCP_OPT_END).pkt2net({}), b'\xff')
        with self.assertRaises(ValueError):
            DHCPOption(b'\x35')
        with self.assertRaises(ValueError):
            DHCPOption(b'\x35\x02\x01')

    def test_dhcp_roundtrip_preserves_unknown_options_and_tail(self):
        packet = DHCP(
            op=1, htype=1, hlen=6, hops=2, xid=0x12345678,
            secs=9, flags=0x8000,
            ciaddr='0.0.0.0', yiaddr='10.0.0.100',
            siaddr='10.0.0.1', giaddr='10.0.0.254',
            chaddr=b'\x00\x11\x22\x33\x44\x55',
            sname=b'example-server', file=b'pxelinux.0', magic=DHCP_MAGIC,
            options=[
                DHCPOption(code=DHCP_OPT_PAD),
                DHCPOption(code=DHCP_OPT_MESSAGE_TYPE, data=b'\x02'),
                DHCPOption(code=222, data=b'private'),
                DHCPOption(code=DHCP_OPT_END),
            ],
            data=b'\x00\xaa')
        wire = packet.pkt2net({})
        parsed = DHCP(wire)

        self.assertEqual(parsed.pkt2net({}), wire)
        self.assertEqual(parsed.xid, 0x12345678)
        self.assertEqual(parsed.yiaddr, '10.0.0.100')
        self.assertEqual(parsed.siaddr, '10.0.0.1')
        self.assertEqual(parsed.giaddr, '10.0.0.254')
        self.assertEqual(parsed.chaddr, b'\x00\x11\x22\x33\x44\x55')
        self.assertEqual(parsed.sname, b'example-server')
        self.assertEqual(parsed.file, b'pxelinux.0')
        self.assertEqual(parsed.message_type, 2)
        self.assertEqual([o.code for o in parsed.options],
                         [DHCP_OPT_PAD, DHCP_OPT_MESSAGE_TYPE, 222,
                          DHCP_OPT_END])
        self.assertEqual(parsed.options[2].data, b'private')
        self.assertEqual(parsed.data, b'\x00\xaa')

    def test_dhcp_rejects_truncated_header_and_option(self):
        with self.assertRaises(ValueError):
            DHCP(b'\x00' * 239)

        base = DHCP(options=[]).pkt2net({})
        with self.assertRaises(ValueError):
            DHCP(base + b'\xde\x04\x01\x02')

    def test_dhcp_mutable_input_and_udp_owner_dispatch(self):
        wire = DHCP(
            xid=0x01020304,
            options=[DHCPOption(code=DHCP_OPT_MESSAGE_TYPE, data=b'\x01'),
                     DHCPOption(code=DHCP_OPT_END)]).pkt2net({})
        mutable = array('B', wire)
        direct = DHCP(mutable)
        mutable[4] = 0xff
        self.assertEqual(direct.xid, 0x01020304)
        self.assertEqual(direct.pkt2net({}), wire)

        udp_wire = UDP(sport=68, dport=67, payload=NullPkt(wire)).pkt2net(
            {'update': 1})
        udp = UDP(udp_wire, l7_ports={67: DHCP})
        child = udp.payload
        self.assertIsInstance(child, DHCP)
        del udp
        gc.collect()
        self.assertEqual(child.xid, 0x01020304)
        self.assertEqual(child.pkt2net({}), wire)

    def test_dhcp6_option_and_normal_message_roundtrip(self):
        option = DHCP6Option(code=65000, data=b'opaque')
        option_wire = option.pkt2net({})
        self.assertEqual(DHCP6Option(option_wire).pkt2net({}), option_wire)

        packet = DHCP6(
            msg_type=DHCP6_SOLICIT, transaction_id=0x010203,
            options=[DHCP6Option(code=1, data=b'client-id'), option])
        wire = packet.pkt2net({})
        parsed = DHCP6(wire)
        self.assertEqual(parsed.msg_type, DHCP6_SOLICIT)
        self.assertEqual(parsed.transaction_id, 0x010203)
        self.assertEqual([o.code for o in parsed.options], [1, 65000])
        self.assertEqual(parsed.options[1].data, b'opaque')
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_dhcp6_independent_wire_fixture(self):
        wire = b'\x01\x01\x02\x03\x00\x7b\x00\x03abc'
        packet = DHCP6(wire)
        self.assertEqual(packet.msg_type, DHCP6_SOLICIT)
        self.assertEqual(packet.transaction_id, 0x010203)
        self.assertEqual(packet.options[0].code, 123)
        self.assertEqual(packet.options[0].data, b'abc')
        self.assertEqual(packet.pkt2net({}), wire)

    def test_dhcp6_relay_roundtrip(self):
        packet = DHCP6(
            msg_type=DHCP6_RELAY_FORWARD, hop_count=3,
            link_address='2001:db8::1', peer_address='fe80::1234',
            options=[DHCP6Option(code=9, data=b'relay-message')])
        wire = packet.pkt2net({})
        parsed = DHCP6(wire)
        self.assertEqual(parsed.msg_type, DHCP6_RELAY_FORWARD)
        self.assertEqual(parsed.hop_count, 3)
        self.assertEqual(parsed.link_address, '2001:db8::1')
        self.assertEqual(parsed.peer_address, 'fe80::1234')
        self.assertEqual(parsed.options[0].data, b'relay-message')
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_dhcp6_rejects_bad_ranges_and_udp_owner_dispatch(self):
        with self.assertRaises(ValueError):
            DHCP6(b'\x01\x00\x00')
        with self.assertRaises(ValueError):
            DHCP6(bytes([DHCP6_RELAY_FORWARD]) + b'\x00' * 32)
        with self.assertRaises(ValueError):
            DHCP6Option(b'\x00\x01\x00\x02\xff')
        with self.assertRaises(ValueError):
            DHCP6(b'\x01\x00\x00\x01\x00\x01\x00\x02\xff')

        wire = DHCP6(
            msg_type=DHCP6_SOLICIT, transaction_id=7,
            options=[DHCP6Option(code=65000, data=b'x')]).pkt2net({})
        udp_wire = UDP(sport=546, dport=547, payload=NullPkt(wire)).pkt2net(
            {'update': 1})
        udp = UDP(udp_wire, l7_ports={547: DHCP6})
        child = udp.payload
        self.assertIsInstance(child, DHCP6)
        del udp
        gc.collect()
        self.assertEqual(child.transaction_id, 7)
        self.assertEqual(child.pkt2net({}), wire)

    def test_dhcp_query_fields_resolve(self):
        packet = DHCP(
            xid=1,
            options=[DHCPOption(code=DHCP_OPT_MESSAGE_TYPE, data=b'\x03'),
                     DHCPOption(code=DHCP_OPT_END)])
        for field in DHCP.query_info()[1]:
            self.assertIsNotNone(packet.get_field_val(field), field)

        packet6 = DHCP6(msg_type=DHCP6_SOLICIT, transaction_id=2)
        for field in DHCP6.query_info()[1]:
            self.assertIsNotNone(packet6.get_field_val(field), field)


if __name__ == '__main__':
    unittest.main()
