"""Behavior pins for the fast paths added for performance.

Every test here exists because an optimization replaced a Python level
implementation with a C one, or replaced a copy with a reference. Nothing in
this file measures speed: each test asserts that the fast path returns
exactly what the implementation it replaced returned, including for the
inputs that make the fast path decline to run.
"""
import os
import random
import socket
import struct
import tempfile
import unittest

from packets.core.inetpkt import Ethernet, IP, IP6, UDP, TCP, ARP, ICMP6, \
    ICMP6Opt, IGMP, IGMPGroupRecord, MLDv2AddressRecord, NullPkt, IP_CONST
from packets.core.pcap import PCAPWriter
from packets.protos.dhcp import DHCP, DHCP_MAGIC
from packets.protos.netflow import Netflow, NetflowDecodeContext
from packets.query.pcap_query import PcapQuery

C = IP_CONST()

# Every field pcap_query extracts through a compiled descriptor rather than
# through the layer's get_field_val. The descriptor path is only correct if
# it agrees with the layer for all of them, which is what
# TestQueryDescriptors checks.
DESCRIPTOR_FIELDS = (
    'eth.src', 'eth.dst', 'eth.type',
    'ip.src', 'ip.dst', 'ip.version', 'ip.hdr_len', 'ip.len', 'ip.ttl',
    'udp.srcport', 'udp.dstport', 'udp.length', 'udp.checksum',
    'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.ack', 'tcp.hdr_len',
    'tcp.len', 'tcp.flags', 'tcp.flags.urg', 'tcp.flags.ack',
    'tcp.flags.push', 'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin',
    'tcp.window_size_value', 'tcp.checksum', 'tcp.urgent_pointer',
    'ipv6.version', 'ipv6.tclass', 'ipv6.flow', 'ipv6.plen', 'ipv6.nxt',
    'ipv6.hlim', 'ipv6.src', 'ipv6.dst',
)
FIELD_LAYER = {'eth': 'Ethernet', 'ip': 'IP', 'ipv6': 'IP6',
               'udp': 'UDP', 'tcp': 'TCP'}


def udp_frame(payload=b'\xAB' * 200):
    eth = Ethernet(src_mac='aa:bb:cc:dd:ee:ff', dst_mac='01:02:03:04:05:06')
    eth.payload = IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                     ttl=63,
                     payload=UDP(sport=34567, dport=53,
                                 payload=NullPkt(payload)))
    return eth.pkt2net({'csum': 1, 'update': 1})


def tcp_frame(payload=b'\xCD' * 100):
    eth = Ethernet(src_mac='11:22:33:44:55:66', dst_mac='ff:ff:ff:ff:ff:ff')
    eth.payload = IP(proto=C.PROTO_TCP, src='192.168.0.200', dst='8.8.8.8',
                     ttl=255,
                     payload=TCP(sport=443, dport=51000, sequence=123456789,
                                 acknowledgment=987654321, window=65535,
                                 flag_syn=1, flag_ack=1, flag_psh=1,
                                 urg_ptr=7, payload=NullPkt(payload)))
    return eth.pkt2net({'csum': 1, 'update': 1})


def ip6_tcp_frame():
    eth = Ethernet(src_mac='00:00:00:00:00:01', dst_mac='00:00:00:00:00:02')
    eth.payload = IP6(src='2001:db8::1', dst='fe80::e6c7:22ff:feaf:68e1',
                      hop_limit=64, tclass=17, flow=0x12345,
                      payload=TCP(sport=80, dport=40000, sequence=1,
                                  window=100, flag_fin=1, flag_rst=1,
                                  flag_urg=1,
                                  payload=NullPkt(b'\xEF' * 40)))
    return eth.pkt2net({'csum': 1, 'update': 1})


def ip6_udp_frame():
    eth = Ethernet(src_mac='00:00:00:00:00:03', dst_mac='00:00:00:00:00:04')
    eth.payload = IP6(src='::ffff:1.2.3.4', dst='::1', hop_limit=1,
                      payload=UDP(sport=2055, dport=2055,
                                  payload=NullPkt(b'\x09' * 30)))
    return eth.pkt2net({'csum': 1, 'update': 1})


def write_pcap(frames):
    descriptor, path = tempfile.mkstemp(suffix='.pcap')
    os.close(descriptor)
    writer = PCAPWriter(filename=path)
    for frame in frames:
        writer.dump_pkt(frame, 1700000000, 1)
    writer.close()
    return path


def netflow_v5_datagram(records):
    """A v5 datagram carrying the given (src, dst, next_hop) packed triples."""
    wire = struct.pack('!HHIIIIBBH', 5, len(records), 100, 200, 300, 0,
                       0, 0, 0)
    for src, dst, next_hop in records:
        wire += (src + dst + next_hop +
                 struct.pack('!HHIIIIHHBBBBHHBBH', 1, 2, 3, 4, 5, 6, 7, 8,
                             0, 0x18, 6, 0, 100, 200, 24, 24, 0))
    return wire


def netflow_v9_datagram(template_id, fields, values, sequence=1):
    """A v9 datagram whose single data set follows its own template.

    :param fields: (element_id, length) pairs.
    :param values: the packed field values, in the same order.
    """
    template_body = struct.pack('!HH', template_id, len(fields))
    for element_id, length in fields:
        template_body += struct.pack('!HH', element_id, length)
    template_set = (struct.pack('!HH', 0, 4 + len(template_body)) +
                    template_body)
    data_body = b''.join(values)
    data_set = struct.pack('!HH', template_id, 4 + len(data_body)) + data_body
    return (struct.pack('!HHIIII', 9, 2, 100, 200, sequence, 42) +
            template_set + data_set)


def dhcp_wire(ciaddr, yiaddr, siaddr, giaddr):
    """A minimal BOOTP fixture carrying the four packed address fields."""
    return struct.pack(
        '!BBBBIHH4s4s4s4s16s64s128sI',
        1, 1, 6, 0, 0x89abcdef, 12, 0x8000,
        ciaddr, yiaddr, siaddr, giaddr,
        b'\x00\x11\x22\x33\x44\x55' + b'\x00' * 10,
        b'server' + b'\x00' * 58,
        b'boot.img' + b'\x00' * 120,
        DHCP_MAGIC) + b'\x35\x01\x05\xff'


def ipv4_cases(seed, count=500):
    """Every octet value in each position, plus randomized addresses."""
    random.seed(seed)
    cases = [bytes([value, 0, 255, value]) for value in range(256)]
    cases += [bytes([0, value, value, 255]) for value in range(256)]
    cases += [bytes(random.randrange(256) for _ in range(4))
              for _ in range(count)]
    return cases


class TestAddressFormatting(unittest.TestCase):
    """The address getters format in C instead of through struct/socket."""

    def test_mac_matches_struct_format(self):
        random.seed(20260830)
        for _ in range(500):
            raw = bytes(random.randrange(256) for _ in range(6))
            expected = '%02x:%02x:%02x:%02x:%02x:%02x' % struct.unpack(
                'BBBBBB', raw)
            eth = Ethernet(src_mac=expected, dst_mac='00:00:00:00:00:00')
            self.assertEqual(eth.src_mac, expected)
            self.assertEqual(eth.dst_mac, '00:00:00:00:00:00')

    def test_mac_low_and_high_octets(self):
        for value in (0x00, 0x01, 0x0f, 0x10, 0x7f, 0x80, 0xf0, 0xff):
            text = ':'.join(['%02x' % value] * 6)
            self.assertEqual(Ethernet(src_mac=text).src_mac, text)

    def test_mac_on_every_layer_that_carries_one(self):
        arp = ARP(sender_hw_addr='0a:0b:0c:0d:0e:0f',
                  target_hw_addr='ff:ee:dd:cc:bb:aa',
                  sender_proto_addr='1.1.1.1', target_proto_addr='2.2.2.2')
        self.assertEqual(arp.sender_hw_addr, '0a:0b:0c:0d:0e:0f')
        self.assertEqual(arp.target_hw_addr, 'ff:ee:dd:cc:bb:aa')
        opt = ICMP6Opt(type=1, link_layer_address='01:02:03:04:05:06')
        self.assertEqual(opt.link_layer_address, '01:02:03:04:05:06')

    def test_ipv4_matches_inet_ntoa(self):
        for raw in ipv4_cases(20260831):
            expected = socket.inet_ntoa(raw)
            self.assertEqual(IP(src=expected).src, expected)
            self.assertEqual(IP(dst=expected).dst, expected)

    def test_ipv4_octet_digit_widths(self):
        # One, two and three digit octets take different branches.
        for text in ('0.0.0.0', '1.2.3.4', '9.10.99.100', '255.255.255.255',
                     '10.100.1.200', '99.100.101.9'):
            self.assertEqual(IP(src=text).src, text)

    def test_ipv4_on_igmp_layers(self):
        record = IGMPGroupRecord(group_address='239.1.2.3',
                                 source_addresses=['10.0.0.1', '10.0.0.2'])
        self.assertEqual(record.group_address, '239.1.2.3')
        self.assertEqual(record.source_addresses, ['10.0.0.1', '10.0.0.2'])
        igmp = IGMP(version=2, type=0x16, group_address='224.0.0.251')
        self.assertEqual(igmp.group_address, '224.0.0.251')

    def test_ipv6_matches_inet_ntop(self):
        # Zero compression, the IPv4 mapped and embedded forms, and the
        # single zero group that RFC 5952 does not allow to be compressed.
        cases = ('::', '::1', '1::', 'fe80::1', '2001:db8::1',
                 '::ffff:1.2.3.4', '::ffff:0:0', '1:0:0:2::3',
                 '0:1:0:1:0:1:0:1', '1:2:3:4:5:6:7:8', '1:0:0:0:2:0:0:3',
                 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', '0:0:1::',
                 '::2:3:4:5:6:7:8', '1:2:3:4:5:6:7:0', '64:ff9b::1.2.3.4',
                 'fe80::e6c7:22ff:feaf:68e1', 'ff02::1:ff95:3f23')
        for text in cases:
            packed = socket.inet_pton(socket.AF_INET6, text)
            expected = socket.inet_ntop(socket.AF_INET6, packed)
            self.assertEqual(IP6(src=text).src, expected)
            self.assertEqual(IP6(dst=text).dst, expected)

    def test_ipv6_random_matches_inet_ntop(self):
        random.seed(20260901)
        for _ in range(500):
            packed = bytes(random.randrange(256) for _ in range(16))
            expected = socket.inet_ntop(socket.AF_INET6, packed)
            self.assertEqual(IP6(src=expected).src, expected)

    def test_ipv6_on_icmp6_layers(self):
        icmp6 = ICMP6(type=136, target_address='fe80::2')
        self.assertEqual(icmp6.target_address, 'fe80::2')
        record = MLDv2AddressRecord(multicast_address='ff02::1',
                                    source_addresses=['2001:db8::a',
                                                      '2001:db8::b'])
        self.assertEqual(record.multicast_address, 'ff02::1')
        self.assertEqual(record.source_addresses,
                         ['2001:db8::a', '2001:db8::b'])


class TestPayloadOffsetQuery(unittest.TestCase):
    """udp/tcp.payload.offset[x:y] no longer serializes the whole payload."""

    SLICES = ((0, 32), (0, 0), (5, 5), (10, 4), (0, 300), (0, 400),
              (290, 400), (300, 301), (0, -1), (-10, -1), (-5, 300),
              (1, 2), (299, 300), (400, 500))

    def setUp(self):
        self.payload = bytes((i & 0xff) for i in range(300))

    def _check(self, layer, prefix, expected):
        for first, last in self.SLICES:
            field = '%s.payload.offset[%d:%d]' % (prefix, first, last)
            self.assertEqual(layer.get_field_val(field),
                             expected[first:last],
                             'slice [%d:%d] of %s' % (first, last, prefix))

    def test_parsed_udp_owner_backed_payload(self):
        frame = Ethernet(udp_frame(self.payload))
        self._check(frame.payload.payload, 'udp', self.payload)

    def test_parsed_tcp_owner_backed_payload(self):
        frame = Ethernet(tcp_frame(self.payload))
        self._check(frame.payload.payload, 'tcp', self.payload)

    def test_parsed_with_l7_ports_registered(self):
        # A registered layer 7 port takes the general parse path, which
        # produces the same NullPkt through a different route.
        frame = Ethernet(udp_frame(self.payload), l7_ports={65000: NullPkt})
        self._check(frame.payload.payload, 'udp', self.payload)

    def test_constructed_payload(self):
        udp = UDP(sport=1, dport=2, payload=NullPkt(self.payload))
        self._check(udp, 'udp', self.payload)
        tcp = TCP(sport=1, dport=2, payload=NullPkt(self.payload))
        self._check(tcp, 'tcp', self.payload)

    def test_malformed_field_returns_none(self):
        udp = UDP(sport=1, dport=2, payload=NullPkt(self.payload))
        self.assertIsNone(udp.get_field_val('udp.payload.offset[4]'))


class TestFastPathPayloadLifetime(unittest.TestCase):
    """The Ethernet/IP/UDP fast path hands on a range, not a copy."""

    def test_payload_bytes_unchanged(self):
        payload = bytes((i & 0xff) for i in range(413))
        frame = Ethernet(udp_frame(payload))
        self.assertEqual(frame.payload.payload.payload.payload, payload)

    def test_detached_payload_outlives_the_frame(self):
        payload = bytes((i & 0xff) for i in range(413))
        frame = Ethernet(udp_frame(payload))
        detached = frame.payload.payload.payload
        del frame
        self.assertEqual(detached.payload, payload)
        self.assertEqual(detached.pkt2net({}), payload)

    def test_round_trip_is_byte_identical(self):
        raw = udp_frame(bytes((i & 0xff) for i in range(413)))
        self.assertEqual(Ethernet(raw).pkt2net({}), raw)

    def test_padded_short_frame_keeps_padding_out_of_the_payload(self):
        # The declared-length clamp has to survive the change of payload
        # representation: the padding belongs to the frame, not to UDP.
        eth = Ethernet(src_mac='00:00:00:00:00:01',
                       dst_mac='00:00:00:00:00:02')
        eth.payload = IP(proto=C.PROTO_UDP, src='1.1.1.1', dst='2.2.2.2',
                         payload=UDP(sport=1, dport=2, payload=NullPkt(b'')))
        raw = eth.pkt2net({'csum': 1, 'update': 1}) + b'\xee' * 18
        frame = Ethernet(raw)
        self.assertEqual(frame.payload.payload.payload.payload, b'')
        self.assertEqual(frame.pkt2net({}), raw)


class TestQueryDescriptors(unittest.TestCase):
    """Compiled descriptors must agree with the layer's get_field_val."""

    @classmethod
    def setUpClass(cls):
        cls.frames = (udp_frame(), tcp_frame(), ip6_tcp_frame(),
                      ip6_udp_frame())
        cls.path = write_pcap(cls.frames)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.path):
            os.remove(cls.path)

    def _oracle(self, field):
        """What the layer itself reports, for the frames that carry it."""
        values = []
        for raw in self.frames:
            layer = Ethernet(raw).get_layer(FIELD_LAYER[field.split('.')[0]])
            if layer is None or layer.pkt_name == 'NullPkt':
                continue
            values.append(layer.get_field_val(field))
        return values

    def test_every_descriptor_field_matches_the_layer(self):
        for field in DESCRIPTOR_FIELDS:
            rows = PcapQuery(filename=self.path,
                             wshark_fields=[field]).query()
            self.assertEqual([row[0] for row in rows], self._oracle(field),
                             'descriptor disagrees with layer for ' + field)

    def test_mixed_row_matches_single_field_rows(self):
        fields = ['eth.src', 'ip.src', 'tcp.srcport', 'udp.srcport',
                  'ipv6.src']
        rows = PcapQuery(filename=self.path, wshark_fields=fields).query()
        self.assertEqual(len(rows), len(self.frames))
        for index, field in enumerate(fields):
            single = [row[0] for row in
                      PcapQuery(filename=self.path,
                                wshark_fields=[field]).query()]
            self.assertEqual([row[index] for row in rows
                              if row[index] is not None], single)


class TestFrameOnlyQuery(unittest.TestCase):
    """A frame-only query skips the decode, so its bounds are its own."""

    def setUp(self):
        self.frames = [udp_frame(), tcp_frame()]

    def test_values_match_the_decoding_path(self):
        path = write_pcap(self.frames)
        try:
            frame_fields = ['frame.time_epoch', 'frame.len', 'frame.caplen']
            skipped = PcapQuery(filename=path,
                                wshark_fields=frame_fields).query()
            decoded = PcapQuery(filename=path,
                                wshark_fields=frame_fields + ['eth.type']
                                ).query()
            self.assertEqual(len(skipped), len(self.frames))
            self.assertEqual([row[:3] for row in skipped],
                             [row[:3] for row in decoded])
        finally:
            os.remove(path)

    def test_frame_shorter_than_ethernet_still_raises(self):
        path = write_pcap(self.frames + [b'\x00' * 10])
        try:
            query = PcapQuery(filename=path, wshark_fields=['frame.len'])
            self.assertRaises(ValueError, query.query)
        finally:
            os.remove(path)

    def test_layer_malformed_behind_ethernet_is_not_decoded(self):
        """Deliberate consequence of skipping the decode.

        A frame with a complete Ethernet header but a malformed IP header
        used to abort the whole query, because every query decoded every
        packet whether or not it asked for a decoded field. A query for
        frame.len asks nothing of the IP header, so it no longer looks at
        it, and the row is returned. Asking for a decoded field still
        raises, which is the case that has a caller who cares.
        """
        malformed = b'\x00' * 12 + b'\x08\x00' + b'\x45'
        path = write_pcap(self.frames + [malformed])
        try:
            rows = PcapQuery(filename=path,
                             wshark_fields=['frame.len']).query()
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[-1][0], len(malformed))
            decoding = PcapQuery(filename=path, wshark_fields=['ip.src'])
            self.assertRaises(ValueError, decoding.query)
        finally:
            os.remove(path)


class TestNetflowAddresses(unittest.TestCase):
    """NetFlow decodes addresses through the shared C writer.

    v1/v5/v7 records used socket.inet_ntoa on a freshly allocated bytes
    object per address, and the v9/IPFIX data path called the platform
    inet_ntop. Both now call _fmt_ipv4_buf on the parse buffer directly, so
    what these pin is that the text is still exactly what those two produced.
    """

    def test_v5_record_addresses_match_inet_ntoa(self):
        cases = ipv4_cases(20260902)
        triples = [(cases[i], cases[(i + 1) % len(cases)],
                    cases[(i + 2) % len(cases)])
                   for i in range(len(cases))]
        # One datagram per batch, so the offset of each record differs.
        for start in range(0, len(triples), 30):
            batch = triples[start:start + 30]
            packet = Netflow(netflow_v5_datagram(batch))
            self.assertEqual(len(packet.records), len(batch))
            for record, (src, dst, next_hop) in zip(packet.records, batch):
                self.assertEqual(record.src_addr, socket.inet_ntoa(src))
                self.assertEqual(record.dst_addr, socket.inet_ntoa(dst))
                self.assertEqual(record.next_hop,
                                 socket.inet_ntoa(next_hop))

    def test_v5_record_roundtrips_after_decode(self):
        # The addresses are re-packed from the text, so a formatter that
        # produced a plausible but wrong string would corrupt the wire too.
        wire = netflow_v5_datagram([(b'\x00\x0a\x63\xff',
                                     b'\xff\x64\x09\x00',
                                     b'\x0a\x01\x02\x03')])
        self.assertEqual(Netflow(wire).pkt2net({}), wire)

    def test_v9_ipv4_field_matches_inet_ntoa(self):
        fields = ((8, 4), (12, 4), (2, 4))
        for raw in ipv4_cases(20260903, 200):
            context = NetflowDecodeContext()
            wire = netflow_v9_datagram(
                256, fields, (raw, raw[::-1], struct.pack('!I', 7)))
            packet = Netflow(wire, context=context, exporter='198.51.100.1')
            record = packet.records[0]
            self.assertEqual(record.fields['sourceIPv4Address'],
                             socket.inet_ntoa(raw))
            self.assertEqual(record.fields['destinationIPv4Address'],
                             socket.inet_ntoa(raw[::-1]))

    def test_v9_ipv6_field_still_uses_inet_ntop(self):
        # IPv6 was deliberately left on the platform converter: RFC 5952
        # zero compression is not worth reimplementing to save a call.
        random.seed(20260904)
        for _ in range(200):
            raw = bytes(random.randrange(256) for _ in range(16))
            context = NetflowDecodeContext()
            wire = netflow_v9_datagram(257, ((27, 16), (2, 4)),
                                       (raw, struct.pack('!I', 3)))
            packet = Netflow(wire, context=context, exporter='198.51.100.1')
            self.assertEqual(packet.records[0].fields['sourceIPv6Address'],
                             socket.inet_ntop(socket.AF_INET6, raw))


class TestDhcpAddresses(unittest.TestCase):
    """The four BOOTP address properties format through the shared writer.

    They are lazy, so a decode never noticed, but get_field_val routes
    dhcp.ciaddr through dhcp.giaddr straight to them and a query naming those
    columns formats four addresses per packet.
    """

    def test_addresses_match_inet_ntop(self):
        cases = ipv4_cases(20260905)
        for i, raw in enumerate(cases):
            other = cases[(i + 1) % len(cases)]
            packet = DHCP(dhcp_wire(raw, other, raw[::-1], other[::-1]))
            self.assertEqual(packet.ciaddr,
                             socket.inet_ntop(socket.AF_INET, raw))
            self.assertEqual(packet.yiaddr,
                             socket.inet_ntop(socket.AF_INET, other))
            self.assertEqual(packet.siaddr,
                             socket.inet_ntop(socket.AF_INET, raw[::-1]))
            self.assertEqual(packet.giaddr,
                             socket.inet_ntop(socket.AF_INET, other[::-1]))

    def test_addresses_survive_the_setter_and_the_wire(self):
        wire = dhcp_wire(b'\x00\x00\x00\x00', b'\x0a\x00\x00\x64',
                         b'\x0a\x00\x00\x01', b'\xff\xff\xff\xff')
        packet = DHCP(wire)
        self.assertEqual(packet.ciaddr, '0.0.0.0')
        self.assertEqual(packet.giaddr, '255.255.255.255')
        self.assertEqual(packet.pkt2net({}), wire)
        packet.ciaddr = '192.168.100.9'
        self.assertEqual(packet.ciaddr, '192.168.100.9')
        self.assertEqual(DHCP(packet.pkt2net({})).ciaddr, '192.168.100.9')

    def test_query_columns_match_the_properties(self):
        # get_field_val is the path a PcapQuery takes to these.
        packet = DHCP(dhcp_wire(b'\x01\x02\x03\x04', b'\x0a\x00\x00\x64',
                                b'\x63\x64\x09\x0a', b'\x00\x00\x00\x00'))
        for name, expected in (('dhcp.ciaddr', packet.ciaddr),
                               ('dhcp.yiaddr', packet.yiaddr),
                               ('dhcp.siaddr', packet.siaddr),
                               ('dhcp.giaddr', packet.giaddr)):
            self.assertEqual(packet.get_field_val(name), expected)


if __name__ == '__main__':
    unittest.main()
