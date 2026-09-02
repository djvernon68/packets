#!/usr/bin/env python

import json
import unittest
import logging
import os
import pandas
import socket as _socket
import struct as _struct
from array import array
from unittest import mock

import packets.core.pcap as _pcap
from packets.core.inetpkt import IP_CONST, PKT, Ethernet, ARP, IP, \
    UDP, TCP, NullPkt, IP6, ICMP6, ICMP6Opt, MLDv2AddressRecord, ICMP, \
    IGMP, IGMPGroupRecord, MPLS, NetflowSimple
from packets.core.pcap import PCAPReader, PCAPWriter, \
    get_pkts_header, ip2int, int2ip, pcap_info, \
    _build_netflow_replay_frame

from packets.protos.dns import DNS, DNSQuery, DNSResource, \
    DNSTYPE_A, DNSTYPE_AAAA, DNSTYPE_CNAME, DNSTYPE_NS, DNSTYPE_PTR, \
    DNSTYPE_SOA, DNSTYPE_TXT, RCLASS_IN

from packets.query.pcap_query import PcapQuery

logger = logging.getLogger(__name__)


class _DownstreamProtocol(PKT):
    pass


class _OwnedDownstreamProtocol(PKT):
    def __init__(self, data):
        super().__init__()
        self.data = bytes(data)


class _DynamicQueryProtocol(PKT):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pkt_name = 'DynamicQueryProtocol'
        self.pq_type = 49152

    @classmethod
    def query_info(cls):
        return 49152, ('dynamic.value',)

    @classmethod
    def default_ports(cls):
        return [5555]

    def get_field_val(self, field):
        if field == 'dynamic.value':
            return 'fallback'
        return None


def _cksum(data):
    """Independent 16-bit one's-complement checksum for test verification."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _v6_pheader(src, dst, upper_len, nh):
    """Build an RFC 2460 IPv6 pseudo header for checksum verification."""
    return (_socket.inet_pton(_socket.AF_INET6, src) +
            _socket.inet_pton(_socket.AF_INET6, dst) +
            _struct.pack('!I', upper_len) + b'\x00\x00\x00' + bytes([nh]))


V6_SRC = '2001:db8::1'
V6_DST = '2001:db8::2'
V6_ETH = bytes.fromhex('00112233445500aabbccddee86dd')


def _v6(addr):
    """Pack a colon notation IPv6 address."""
    return _socket.inet_pton(_socket.AF_INET6, addr)


def _ip6_hdr(payload_len, nh, src=V6_SRC, dst=V6_DST, hop_limit=255):
    """Build a 40 byte IPv6 header."""
    return (_struct.pack('!IHBB', 0x60000000, payload_len, nh, hop_limit) +
            _v6(src) + _v6(dst))


def _icmp6_frame(body, src=V6_SRC, dst=V6_DST):
    """Ethernet/IPv6 frame carrying a raw ICMPv6 message.

    ``body`` is the whole ICMPv6 message with its checksum field left at
    zero; the real checksum is computed here from an independent RFC 4443
    pseudo header, so every frame the ICMPv6 tests parse is ground truth
    rather than something the library produced.
    """
    ck = _cksum(_v6_pheader(src, dst, len(body), 58) + body)
    body = body[:2] + _struct.pack('!H', ck) + body[4:]
    return V6_ETH + _ip6_hdr(len(body), 58, src, dst) + body


def _nd_opt(otype, value):
    """Build one Neighbor Discovery option TLV around an 8 octet value."""
    return bytes([otype, (len(value) + 2) // 8]) + value


C = IP_CONST()
icmp_pkt_data = array('B', [0, 11, 134, 99, 252, 32, 8, 0, 39, 64, 45, 200, 8,
                            0, 69, 0, 0, 28, 0, 0, 0, 0, 64, 1, 202, 227, 10,
                            38, 25, 153, 10, 38, 130, 25, 8, 0, 61, 86, 15,
                            255, 170, 170])
icmp_destun_pkt_data = array('B', [124, 122, 145, 108, 216, 21, 196, 179, 1,
                                   211, 170, 123, 8, 0, 69, 0, 0, 56, 69, 255,
                                   0, 0, 64, 1, 237, 106, 10, 38, 25, 198, 10,
                                   38, 25, 74, 3, 3, 17, 104, 0, 0, 0, 0, 69,
                                   96, 0, 56, 41, 139, 0, 0, 128, 17, 201,
                                   110, 10, 38, 25, 74, 10, 38, 25, 198, 227,
                                   106, 8, 6, 0, 36, 0, 0])

igmp_pkt_data = array('B', [1, 0, 94, 127, 255, 250, 0, 28, 35, 170, 190, 173,
                            8, 0, 70, 0, 0, 32, 140, 98, 0, 0, 1, 2, 230, 146,
                            192, 168, 1, 64, 239, 255, 255, 250, 148, 4, 0, 0,
                            22, 0, 250, 4, 239, 255, 255, 250])

igmp_json = """
{"eth.src":{"0":"00:1b:11:10:26:11","1":"00:1c:23:aa:be:ad",
            "2":"00:02:02:19:51:28","3":"00:02:02:19:51:28",
            "4":"00:02:02:19:51:28","5":"00:1b:11:10:26:11",
            "6":"00:02:02:19:51:28","7":"00:02:02:19:51:28",
            "8":"00:02:02:19:51:28","9":"00:02:02:19:51:28",
            "10":"00:1b:11:10:26:11","11":"00:02:02:19:51:28",
            "12":"00:02:02:19:51:28","13":"00:02:02:19:51:28",
            "14":"00:1b:11:10:26:11","15":"00:02:02:19:51:28",
            "16":"00:1c:23:aa:be:ad","17":"00:02:02:19:51:28"},
"eth.dst":{"0":"01:00:5e:00:00:01","1":"01:00:5e:7f:ff:fa",
           "2":"01:00:5e:0a:0a:0a","3":"01:00:5e:01:01:03",
           "4":"01:00:5e:00:00:02","5":"01:00:5e:01:01:03",
           "6":"01:00:5e:01:01:04","7":"01:00:5e:01:01:04",
           "8":"01:00:5e:01:01:04","9":"01:00:5e:00:00:02",
           "10":"01:00:5e:01:01:04","11":"01:00:5e:01:01:05",
           "12":"01:00:5e:01:01:05","13":"01:00:5e:01:01:05",
           "14":"01:00:5e:00:00:01","15":"01:00:5e:0a:0a:0a",
           "16":"01:00:5e:7f:ff:fa","17":"01:00:5e:01:01:05"},
"ip.src":{"0":"192.168.1.2","1":"192.168.1.64","2":"192.168.11.201",
          "3":"192.168.11.201","4":"192.168.11.201","5":"192.168.1.2",
          "6":"192.168.11.201","7":"192.168.11.201","8":"192.168.11.201",
          "9":"192.168.11.201","10":"192.168.1.2","11":"192.168.11.201",
          "12":"192.168.11.201","13":"192.168.11.201","14":"192.168.1.2",
          "15":"192.168.11.201","16":"192.168.1.64","17":"192.168.11.201"},
"ip.dst":{"0":"224.0.0.1","1":"239.255.255.250","2":"225.10.10.10",
          "3":"225.1.1.3","4":"224.0.0.2","5":"225.1.1.3","6":"225.1.1.4",
          "7":"225.1.1.4","8":"225.1.1.4","9":"224.0.0.2","10":"225.1.1.4",
          "11":"225.1.1.5","12":"225.1.1.5","13":"225.1.1.5","14":"224.0.0.1",
          "15":"225.10.10.10","16":"239.255.255.250","17":"225.1.1.5"},
"igmp.type":{"0":17,"1":22,"2":22,"3":22,"4":23,"5":17,"6":22,"7":22,"8":22,
             "9":23,"10":17,"11":22,"12":22,"13":22,"14":17,"15":22,"16":22,
             "17":22},
"igmp.max_resp":{"0":100,"1":0,"2":0,"3":0,"4":0,"5":10,"6":0,"7":0,"8":0,
                 "9":0,"10":10,"11":0,"12":0,"13":0,"14":100,"15":0,"16":0,
                 "17":0},
"igmp.maddr":{"0":"0.0.0.0","1":"239.255.255.250","2":"225.10.10.10",
              "3":"225.1.1.3","4":"225.1.1.3","5":"225.1.1.3","6":"225.1.1.4",
              "7":"225.1.1.4","8":"225.1.1.4","9":"225.1.1.4",
              "10":"225.1.1.4","11":"225.1.1.5","12":"225.1.1.5",
              "13":"225.1.1.5","14":"0.0.0.0","15":"225.10.10.10",
              "16":"239.255.255.250","17":"225.1.1.5"}}
"""

igmp_file = os.path.join(os.path.dirname(__file__), 'igmp_v2.pcap')

igmpv3_member_report = (b'\x01\x00^\x00\x00\x16\x00%.Q\xc3\x81\x08\x00FX\x008'
                        b'\x02F\x00\x00\x01\x02\x80!\xc0\xa8\x01B\xe0\x00\x00'
                        b'\x16\x94\x04\x00\x00"\x00\x00\x19\x00\x00\x00\x03'
                        b'\x02\x00\x00\x00\xef\xc3\x07\x02\x02\x00\x00\x00'
                        b'\xef\xff\xff\xfa\x02\x00\x00\x00\xef\xc3\x01_')
igmpv3_member_query = (b'\x01\x00^\x00\x00\x01\x00&Dl\x1e\xda\x08\x00F\xc0'
                       b'\x00$\x18\x0f@\x00\x01\x02)]\xc0\xa8\x01\xfe\xe0'
                       b'\x00\x00\x01\x94\x04\x00\x00\x11\x18\xec\xd3\x00'
                       b'\x00\x00\x00\x02\x14\x00\x00\x00\x00\x00\x00\x00'
                       b'\x00\x00\x00\x00\x00')

class TestPackets(unittest.TestCase):

    def test_Ethernet_pkt(self):
        pkt = Ethernet(dst_mac='01:02:03:04:05:06')
        pkt.src_mac = '06:05:04:03:02:01'
        pkt.type = C.ETH_TYPE_IPV4

        self.assertEqual(pkt.dst_mac, '01:02:03:04:05:06')
        self.assertEqual(pkt.src_mac, '06:05:04:03:02:01')
        self.assertEqual(pkt.type, C.ETH_TYPE_IPV4)
        self.assertIsInstance(pkt.payload, PKT)

        payload = NullPkt(b'payload')
        self.assertIs(Ethernet(payload=payload).payload, payload)
        self.assertIsNone(Ethernet(payload=None).payload)

        pkt.dst_mac = '01:01:01:01:01:01'
        self.assertEqual(pkt.dst_mac, '01:01:01:01:01:01')
        self.assertEqual(pkt.src_mac, '06:05:04:03:02:01')

        def try_bad_mac(obj):
            obj.dst_mac = "this ain't a mac!"
            return obj.pkt2net({})

        self.assertRaises(ValueError, try_bad_mac, pkt)

    def test_ARP_pkt(self):
        pkt = Ethernet(dst_mac='ff:ff:ff:ff:ff:ff',
                       src_mac='06:05:04:03:02:02')
        pkt.type = C.ETH_TYPE_ARP
        # ARP defaults:
        # hw type Ethernet
        # proto type IP
        # operation 1 (request)
        pkt.payload = ARP(sender_hw_addr='06:05:04:03:02:02',
                          sender_proto_addr='1.2.3.4',
                          target_hw_addr='00:00:00:00:00:00',
                          target_proto_addr='4.3.2.1')

        # Write the packet above to a byte string and create a new
        # ethernet packet from it.
        pkt_copy = Ethernet(pkt.pkt2net({}))
        a = pkt.get_layer("ARP")
        b = pkt_copy.get_layer("ARP")
        self.assertEqual(a.sender_hw_addr, b.sender_hw_addr)
        self.assertEqual(a.sender_proto_addr, b.sender_proto_addr)
        self.assertEqual(a.target_hw_addr, b.target_hw_addr)
        self.assertEqual(a.target_proto_addr, b.target_proto_addr)

        def try_bad_opcode(obj):
            arp = obj.get_layer('ARP')
            arp.operation = 14

        self.assertRaises(ValueError, try_bad_opcode, pkt_copy)

    def test_DNS_roundtrip(self):
        # DNS build -> pkt2net -> parse round-trip with label compression.
        # Two queries share the 'example.com' suffix and answers reuse names,
        # so a correct compressed encoding must be shorter than uncompressed.
        d = DNS()
        d.ident = 0x1234
        d.query_resp = 1
        d.recursion_requested = 1
        d.recursion_available = 1
        d.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
        d.queries.append(DNSQuery('mail.example.com', DNSTYPE_A, RCLASS_IN))
        d.answers.append(DNSResource('www.example.com', DNSTYPE_CNAME,
                                     RCLASS_IN, 300, 0, 'host.example.com'))
        d.answers.append(DNSResource('host.example.com', DNSTYPE_A,
                                     RCLASS_IN, 300, 4, '93.184.216.34'))
        d.answers.append(DNSResource('host.example.com', DNSTYPE_AAAA,
                                     RCLASS_IN, 300, 16,
                                     '2606:2800:220:1:248:1893:25c8:1946'))

        wire = d.pkt2net({'update': 1, 'compress': 1})
        wire_nc = d.pkt2net({'update': 1, 'compress': 0})
        self.assertIsInstance(wire, bytes)
        self.assertTrue(len(wire) > 12)
        self.assertTrue(len(wire) < len(wire_nc))

        p = DNS(wire)
        self.assertEqual(p.ident, 0x1234)
        self.assertEqual(p.query_resp, 1)
        self.assertEqual(p.recursion_requested, 1)
        self.assertEqual(p.recursion_available, 1)
        self.assertEqual(p.query_count, 2)
        self.assertEqual(p.answer_count, 3)

        self.assertEqual([q.query_name for q in p.queries],
                         ['www.example.com', 'mail.example.com'])

        # res_data must be readable from Python (regression: it was not public)
        ans = [(a.domain_name, a.res_type, a.res_data) for a in p.answers]
        self.assertEqual(ans[0],
                         ('www.example.com', DNSTYPE_CNAME, 'host.example.com'))
        self.assertEqual(ans[1],
                         ('host.example.com', DNSTYPE_A, '93.184.216.34'))
        self.assertEqual(ans[2][0], 'host.example.com')
        self.assertEqual(ans[2][1], DNSTYPE_AAAA)
        self.assertEqual(ans[2][2], '2606:2800:220:1:248:1893:25c8:1946')

        # re-serializing the parsed packet reproduces the same fields
        p2 = DNS(p.pkt2net({'update': 1, 'compress': 1}))
        self.assertEqual([q.query_name for q in p2.queries],
                         [q.query_name for q in p.queries])
        self.assertEqual([(a.domain_name, a.res_type, a.res_data)
                          for a in p2.answers], ans)

    def test_DNS_soa_ns_ptr_txt_roundtrip(self):
        """The record types the A/AAAA/CNAME test does not reach.

        SOA, NS and PTR each take a different branch of parse_resource, and
        SOA has its own sub-parser; TXT falls through to the raw-data branch.
        """
        soa = ('SOA mname: ns1.example.com, rname: hostmaster@example.com, '
               'serial: 2026082801, refresh: 7200, retry: 3600, '
               'expire: 1209600, minimum: 300')
        d = DNS()
        d.ident = 0x5678
        d.query_resp = 1
        d.queries.append(DNSQuery('example.com', DNSTYPE_SOA, RCLASS_IN))
        d.answers.append(DNSResource('example.com', DNSTYPE_SOA, RCLASS_IN,
                                     300, 0, soa))
        d.authority.append(DNSResource('example.com', DNSTYPE_NS, RCLASS_IN,
                                       300, 0, 'ns1.example.com'))
        d.ad.append(DNSResource('4.3.2.1.in-addr.arpa', DNSTYPE_PTR,
                                RCLASS_IN, 300, 0, 'host.example.com'))
        d.ad.append(DNSResource('example.com', DNSTYPE_TXT, RCLASS_IN,
                                300, 6, 'v=spf1'))

        wire = d.pkt2net({'update': 1, 'compress': 1})
        p = DNS(wire)
        self.assertEqual(p.ident, 0x5678)
        self.assertEqual(p.answer_count, 1)
        self.assertEqual(p.auth_count, 1)
        self.assertEqual(p.ad_count, 2)
        self.assertEqual(p.answers[0].res_type, DNSTYPE_SOA)
        self.assertEqual(p.answers[0].res_data, soa)
        self.assertEqual(p.authority[0].res_data, 'ns1.example.com')
        self.assertEqual(p.ad[0].domain_name, '4.3.2.1.in-addr.arpa')
        self.assertEqual(p.ad[0].res_data, 'host.example.com')
        self.assertEqual(p.ad[1].res_data, 'v=spf1')
        self.assertEqual(p.pkt2net({'update': 1, 'compress': 1}), wire)

    def test_DNS_compression_offsets_are_message_relative(self):
        """A DNS message must serialize identically inside a frame.

        RFC 1035 compression pointers are offsets from the start of the DNS
        message, not from the start of the frame. The writer appends DNS into
        the same buffer that already holds Ethernet/IP/UDP, so it has to
        subtract the message origin; measuring from the buffer origin instead
        would shift every pointer by the 42 byte header and is invisible in
        any test that serializes DNS on its own.
        """
        def build():
            d = DNS()
            d.ident = 0x1234
            d.query_resp = 1
            d.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
            d.answers.append(DNSResource('www.example.com', DNSTYPE_CNAME,
                                         RCLASS_IN, 300, 0,
                                         'host.example.com'))
            d.answers.append(DNSResource('host.example.com', DNSTYPE_A,
                                         RCLASS_IN, 300, 4, '10.1.2.3'))
            return d

        alone = build().pkt2net({'update': 1, 'compress': 1})

        eth = Ethernet(dst_mac='03:02:03:04:05:06',
                       src_mac='06:05:04:03:02:03')
        eth.payload = IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                         payload=UDP(sport=34567, dport=53,
                                     payload=build()))
        frame = eth.pkt2net({'csum': 1, 'update': 1, 'compress': 1})

        # 14 Ethernet + 20 IP + 8 UDP.
        self.assertEqual(frame[42:], alone)
        # And a compression pointer really is present, or the check above
        # would pass for a writer that never compresses at all.
        self.assertTrue(len(alone) <
                        len(build().pkt2net({'update': 1, 'compress': 0})))

        parsed = Ethernet(frame, l7_ports={53: DNS})
        dns = parsed.get_layer('DNS')
        self.assertIsInstance(dns, DNS)
        self.assertEqual(dns.ident, 0x1234)
        self.assertEqual([q.query_name for q in dns.queries],
                         ['www.example.com'])
        self.assertEqual([(a.domain_name, a.res_data) for a in dns.answers],
                         [('www.example.com', 'host.example.com'),
                          ('host.example.com', '10.1.2.3')])

    def test_DNS_pointer_chain(self):
        header = _struct.pack('!HHHHHH', 0x1234, 0, 3, 0, 0, 0)
        qtype_class = _struct.pack('!HH', DNSTYPE_A, RCLASS_IN)
        first = b'\x03www\x07example\x03com\x00' + qtype_class
        second_offset = len(header) + len(first)
        second = b'\xc0\x0c' + qtype_class
        third = (_struct.pack('!H', 0xc000 | second_offset) +
                 qtype_class)

        parsed = DNS(header + first + second + third)
        self.assertEqual([query.query_name for query in parsed.queries],
                         ['www.example.com'] * 3)

    def test_DNS_root_and_multilabel_names(self):
        header = _struct.pack('!HHHHHH', 0x1234, 0, 2, 0, 0, 0)
        qtype_class = _struct.pack('!HH', DNSTYPE_A, RCLASS_IN)
        labels = ['label{0}'.format(index) for index in range(12)]
        encoded = b''.join(bytes([len(label)]) + label.encode()
                           for label in labels) + b'\x00'
        parsed = DNS(header + b'\x00' + qtype_class + encoded + qtype_class)
        self.assertEqual(parsed.queries[0].query_name, '')
        self.assertEqual(parsed.queries[1].query_name, '.'.join(labels))

        root = DNS()
        root.ident = 0x4321
        root.queries.append(DNSQuery('', DNSTYPE_A, RCLASS_IN))
        root_wire = root.pkt2net({'update': 1, 'compress': 1})
        self.assertEqual(root_wire[12:], b'\x00' + qtype_class)
        self.assertEqual(DNS(root_wire).queries[0].query_name, '')

    def test_DNS_compressed_and_uncompressed_bytes(self):
        dns = DNS()
        dns.ident = 0x4444
        dns.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
        dns.queries.append(DNSQuery('mail.example.com', DNSTYPE_A,
                                    RCLASS_IN))
        header = _struct.pack('!HHHHHH', 0x4444, 0, 2, 0, 0, 0)
        qtype_class = _struct.pack('!HH', DNSTYPE_A, RCLASS_IN)
        first = b'\x03www\x07example\x03com\x00' + qtype_class
        second_compressed = b'\x04mail\xc0\x10' + qtype_class
        second_full = b'\x04mail\x07example\x03com\x00' + qtype_class
        self.assertEqual(dns.pkt2net({'update': 1, 'compress': 1}),
                         header + first + second_compressed)
        self.assertEqual(dns.pkt2net({'update': 1, 'compress': 0}),
                         header + first + second_full)

    def test_DNS_invalid_compression_pointers(self):
        header = _struct.pack('!HHHHHH', 0x1234, 0, 1, 0, 0, 0)
        qtype_class = _struct.pack('!HH', DNSTYPE_A, RCLASS_IN)
        with self.assertRaises(ValueError):
            DNS(header)
        with self.assertRaises(ValueError):
            DNS(header + b'\xc0')
        with self.assertRaises(ValueError):
            DNS(header + b'\xc0\x20' + qtype_class)

    def test_DNS_rdlength_patched_from_written_data(self):
        """rdlength must be the length of the data actually written.

        It cannot be known until the resource data behind it is on the wire,
        so it goes out as a placeholder and is patched back. The caller here
        passes res_len=0 for names it cannot measure, and update=1 must
        replace those with the real values.
        """
        d = DNS()
        d.ident = 0x1111
        d.query_resp = 1
        d.answers.append(DNSResource('example.com', DNSTYPE_CNAME, RCLASS_IN,
                                     300, 0, 'host.example.com'))
        wire = d.pkt2net({'update': 1, 'compress': 0})

        # header 12 + name 'example.com' (13) + type/class/ttl (8)
        rdlen_at = 12 + 13 + 8
        rdlength = _struct.unpack('!H', wire[rdlen_at:rdlen_at + 2])[0]
        self.assertEqual(rdlength, len(b'\x04host\x07example\x03com\x00'))
        self.assertEqual(len(wire), rdlen_at + 2 + rdlength)
        # The object was updated too, not just the bytes.
        self.assertEqual(d.answers[0].res_len, rdlength)
        self.assertEqual(DNS(wire).answers[0].res_len, rdlength)

    def test_DNS_root_owner_name(self):
        """A record owned by the root zone is a single zero length label."""
        d = DNS()
        d.ident = 0x0001
        d.query_resp = 1
        d.answers.append(DNSResource('', DNSTYPE_NS, RCLASS_IN, 300, 0,
                                     'ns1.example.com'))
        wire = d.pkt2net({'update': 1, 'compress': 1})
        self.assertEqual(wire[12], 0)
        p = DNS(wire)
        self.assertEqual(p.answers[0].domain_name, '')
        self.assertEqual(p.answers[0].res_data, 'ns1.example.com')
        self.assertEqual(p.pkt2net({'update': 1, 'compress': 1}), wire)

    def test_DNS_serialize_repeatable(self):
        """Serializing the same message twice must give the same bytes.

        The output buffer is reused between calls and the label store is
        rebuilt per call; either leaking state would show up here.
        """
        d = DNS()
        d.ident = 0x2222
        d.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
        d.answers.append(DNSResource('www.example.com', DNSTYPE_CNAME,
                                     RCLASS_IN, 300, 0, 'host.example.com'))
        first = d.pkt2net({'update': 1, 'compress': 1})
        for _ in range(3):
            self.assertEqual(d.pkt2net({'update': 1, 'compress': 1}), first)

    def test_DNS_truncated_header(self):
        """A DNS header shorter than 12 bytes must raise, not over-read."""
        self.assertRaises(ValueError, DNS, b'\x12\x34\x81\x80')

    def test_DNS_bad_name(self):
        # domain_name setter must raise ValueError (not TypeError) on bad input
        self.assertRaises(ValueError, DNSResource,
                          'not a valid name!!', DNSTYPE_A, RCLASS_IN, 300, 4,
                          '1.2.3.4')

    def test_pcap_helpers(self):
        # ip2int previously assigned to the type name and returned 0 always.
        self.assertEqual(ip2int('1.2.3.4'), 0x01020304)
        self.assertEqual(ip2int('0.0.0.0'), 0)
        self.assertEqual(ip2int('255.255.255.255'), 0xffffffff)
        for addr in ('10.38.25.153', '192.168.1.64', '8.8.8.8'):
            self.assertEqual(int2ip(ip2int(addr)), addr)

        # get_pkts_header derived microseconds from str(ts).split('.')[1],
        # so 1234.5 became 5us instead of 500000 and could exceed 1e6.
        h = get_pkts_header(1234.5, b'x' * 40)
        self.assertEqual(h['ts']['tv_sec'], 1234)
        self.assertEqual(h['ts']['tv_usec'], 500000)
        self.assertEqual(h['caplen'], 40)
        self.assertEqual(h['len'], 40)
        h2 = get_pkts_header(1700000000.999999, b'z')
        self.assertLessEqual(h2['ts']['tv_usec'], 999999)

    def test_pcap_roundtrip(self):
        # write packets through dump_pkt (which uses get_pkts_header) and read
        # them back; bytes and timestamps must survive the round-trip.
        import os
        import tempfile
        pkts = [(1000.5, bytes(bytearray(range(60)))),
                (1000.750001, b'\xaa\xbb\xcc\xdd' * 15)]
        out = os.path.join(tempfile.gettempdir(), 'pkt_rt_test.pcap')
        if os.path.exists(out):
            os.remove(out)
        w = PCAPWriter(filename=out, snaplen=65535)
        for ts, data in pkts:
            sec = int(ts)
            usec = int(round((ts - sec) * 1000000))
            w.dump_pkt(data, sec, usec)
        w.close()

        back = [(ts, pkt) for ts, hdr, pkt in PCAPReader(filename=out)]
        os.remove(out)
        self.assertEqual(len(back), len(pkts))
        for (ots, odata), (bts, bdata) in zip(pkts, back):
            self.assertEqual(bdata, odata)
            self.assertLess(abs(bts - ots), 1e-6)

    def test_pcap_info(self):
        # pcap_info called PCAPReader(file_name=...), a keyword the reader
        # does not take, so it always tried to open '' and raised.
        import os
        import tempfile
        pkts = [(1000.5, b'a' * 60),
                (1001.25, b'b' * 100),
                (1002.0, b'c' * 40)]
        out = os.path.join(tempfile.gettempdir(), 'pkt_info_test.pcap')
        if os.path.exists(out):
            os.remove(out)
        w = PCAPWriter(filename=out, snaplen=65535)
        for ts, data in pkts:
            sec = int(ts)
            usec = int(round((ts - sec) * 1000000))
            w.dump_pkt(data, sec, usec)
        w.close()

        info = pcap_info(out)
        os.remove(out)
        self.assertEqual(info['total_packets'], 3)
        self.assertEqual(info['total_bytes'], 200)
        self.assertLess(abs(info['first_timestamp'] - 1000.5), 1e-6)
        self.assertLess(abs(info['last_timestamp'] - 1002.0), 1e-6)

    def test_pcap_info_empty_file(self):
        # An empty capture raised StopIteration out of pcap_info's next().
        import os
        import tempfile
        out = os.path.join(tempfile.gettempdir(), 'pkt_info_empty.pcap')
        if os.path.exists(out):
            os.remove(out)
        w = PCAPWriter(filename=out, snaplen=65535)
        w.close()

        info = pcap_info(out)
        os.remove(out)
        self.assertEqual(info['total_packets'], 0)
        self.assertEqual(info['total_bytes'], 0)
        self.assertEqual(info['first_timestamp'], 0)
        self.assertEqual(info['last_timestamp'], 0)

    def test_pcap_info_pcapng(self):
        import os
        import tempfile
        out = os.path.join(tempfile.gettempdir(), 'pkt_info_test.pcapng')
        if os.path.exists(out):
            os.remove(out)

        section = _struct.pack('<IIIHHqI', 0x0a0d0d0a, 28,
                               0x1a2b3c4d, 1, 0, -1, 28)
        interface = _struct.pack('<IIHHII', 1, 20, 1, 0, 65535, 20)
        packet1 = _struct.pack('<IIIIIII4sI', 6, 36, 0, 0, 1000500000,
                               4, 4, b'abcd', 36)
        packet2 = _struct.pack('<IIIIIII8sI', 6, 40, 0, 0, 1002000000,
                               8, 8, b'efghijkl', 40)
        with open(out, 'wb') as capture:
            capture.write(section + interface + packet1 + packet2)
        try:
            info = pcap_info(out)
        finally:
            os.remove(out)

        self.assertEqual(info['total_packets'], 2)
        self.assertEqual(info['total_bytes'], 12)
        self.assertLess(abs(info['first_timestamp'] - 1000.5), 1e-6)
        self.assertLess(abs(info['last_timestamp'] - 1002.0), 1e-6)

    def test_pcap_info_truncated_packet(self):
        import os
        import tempfile
        out = os.path.join(tempfile.gettempdir(), 'pkt_info_truncated.pcap')
        if os.path.exists(out):
            os.remove(out)

        header = _struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        packet = _struct.pack('<IIII', 1000, 500000, 10, 10) + b'ab'
        with open(out, 'wb') as capture:
            capture.write(header + packet)
        try:
            self.assertRaises(IOError, pcap_info, out)
        finally:
            os.remove(out)

    def test_PCAPReader_missing_file(self):
        import os
        import tempfile
        missing = os.path.join(tempfile.gettempdir(), 'no_such_capture.pcap')
        if os.path.exists(missing):
            os.remove(missing)
        self.assertRaises(ValueError, PCAPReader, filename=missing)

    def test_PCAPReader_exhausted_then_iterated(self):
        # __next__ now returns early when the handle is already closed;
        # iterating a spent reader must still be StopIteration, not a crash.
        import os
        rdr = PCAPReader(filename=os.path.join(os.path.dirname(__file__),
                                               'igmp_v2.pcap'))
        first = len(list(rdr))
        self.assertGreater(first, 0)
        self.assertEqual(list(rdr), [])

    def test_bpf_filter_errors_are_raised(self):
        # pcap_compile failure was already raised; pcap_setfilter's return
        # value was discarded, so a filter that failed to install left the
        # caller reading everything.
        import os
        cap = os.path.join(os.path.dirname(__file__), 'igmp_v2.pcap')
        rdr = PCAPReader(filename=cap)
        self.assertEqual(rdr.add_bpf_filter('ip and udp dst port 2055'), 0)
        rdr.close()

        rdr = PCAPReader(filename=cap)
        self.assertRaises(Exception, rdr.add_bpf_filter, 'this is not a bpf')
        rdr.close()

    def test_IP6_parse_roundtrip(self):
        # Ground-truth Ethernet/IPv6/ICMPv6 frame generated by impacket.
        frame = bytes.fromhex(
            "00112233445500aabbccddee86dd6000000000113a40"
            "20010db8000000000000000000000001"
            "20010db8000000000000000000000002"
            "80004c920001000270696e673664617461")
        eth = Ethernet(frame)
        self.assertEqual(eth.type, C.ETH_TYPE_IPV6)
        v6 = eth.payload
        self.assertEqual(v6.pkt_name, 'IP6')
        self.assertEqual(v6.version, 6)
        self.assertEqual(v6.traffic_class, 0)
        self.assertEqual(v6.flow_label, 0)
        self.assertEqual(v6.payload_len, 17)
        self.assertEqual(v6.next_header, C.PROTO_ICMPV6)
        self.assertEqual(v6.hop_limit, 64)
        self.assertEqual(v6.src, '2001:db8::1')
        self.assertEqual(v6.dst, '2001:db8::2')
        # Parsing must be byte-preserving through pkt2net.
        self.assertEqual(eth.pkt2net({}), frame)

    def test_IP6_UDP_checksum(self):
        # UDP over IPv6 checksum verified against an independent RFC 2460
        # pseudo-header calculation.
        payload = b'hello ipv6 udp'
        udp = UDP(sport=4444, dport=5555, payload=payload)
        v6 = IP6(src='2001:db8::1', dst='2001:db8::2',
                 next_header=C.PROTO_UDP, hop_limit=64, payload=udp)
        v6.pkt2net({'csum': 1, 'update': 1})
        ulen = 8 + len(payload)
        self.assertEqual(v6.payload_len, ulen)
        udp_hdr = _struct.pack('!HHH', 4444, 5555, ulen) + b'\x00\x00'
        ph = _v6_pheader('2001:db8::1', '2001:db8::2', ulen, 17) + \
            udp_hdr + payload
        self.assertEqual(v6.payload.checksum, _cksum(ph))

    def test_IP6_TCP_checksum(self):
        # TCP over IPv6 checksum verified against an independent RFC 2460
        # pseudo-header calculation using the serialized segment.
        tcp = TCP(sport=1234, dport=80, sequence=1000, acknowledgment=0,
                  window=8192, payload=b'abc')
        v6 = IP6(src='2001:db8::1', dst='2001:db8::2',
                 next_header=C.PROTO_TCP, hop_limit=64, payload=tcp)
        v6.pkt2net({'csum': 1, 'update': 1})
        seg = bytearray(v6.payload.pkt2net({}))
        got = v6.payload.checksum
        seg[16] = 0
        seg[17] = 0
        exp = _cksum(_v6_pheader('2001:db8::1', '2001:db8::2',
                                 len(seg), 6) + bytes(seg))
        self.assertEqual(got, exp)

    def test_IP6_addr_validation(self):
        v6 = IP6()
        self.assertEqual(v6.version, 6)
        self.assertEqual(v6.src, '::')

        def bad_src(p):
            p.src = 'not::an::ipv6'
        self.assertRaises(ValueError, bad_src, v6)

    def test_ICMP6_parse_impacket_frame(self):
        # Eth/IPv6/ICMPv6 echo request generated by impacket.
        frame = bytes.fromhex(
            '00112233445500aabbccddee86dd6000000000113a40'
            '20010db8000000000000000000000001'
            '20010db8000000000000000000000002'
            '80004c920001000270696e673664617461')
        eth = Ethernet(frame)
        ip6 = eth.payload
        self.assertIsInstance(ip6, IP6)
        icmp6 = ip6.payload
        self.assertIsInstance(icmp6, ICMP6)
        self.assertEqual(icmp6.type, C.ICMP6_ECHO_REQUEST)
        self.assertEqual(icmp6.code, 0)
        self.assertEqual(icmp6.identifier, 1)
        self.assertEqual(icmp6.sequence, 2)
        self.assertEqual(icmp6.echo_data, b'ping6data')
        # Whole frame must round-trip byte-identical.
        self.assertEqual(eth.pkt2net({}), frame)

    def test_ICMP6_echo_checksum(self):
        icmp6 = ICMP6(type=C.ICMP6_ECHO_REQUEST, code=0,
                      identifier=1, sequence=2, echo_data=b'ping6data')
        ip6 = IP6(src='2001:db8::1', dst='2001:db8::2',
                  next_header=C.PROTO_ICMPV6, hop_limit=64,
                  payload=icmp6)
        wire = ip6.pkt2net({'csum': 1, 'update': 1})
        body = wire[C.IPV6_HDR_LEN:]
        self.assertEqual(body[0], C.ICMP6_ECHO_REQUEST)
        # Checksum field (bytes 2-3) must match an independent reference.
        zeroed = body[:2] + b'\x00\x00' + body[4:]
        ph = _v6_pheader('2001:db8::1', '2001:db8::2',
                         len(body), C.PROTO_ICMPV6)
        exp = _cksum(ph + zeroed)
        got = _struct.unpack('!H', body[2:4])[0]
        self.assertEqual(got, exp)
        self.assertEqual(got, 0x4c92)

    def test_IP6_ext_header_chain(self):
        # IPv6 -> Destination Options ext header -> UDP. The ext header is an
        # 8-byte block: nxt=17 (UDP), hdr_ext_len=0, then a PadN option.
        ext = bytes([17, 0, 1, 4, 0, 0, 0, 0])
        udp = UDP(sport=1111, dport=2222, payload=b'hi')
        ip6 = IP6(src='2001:db8::1', dst='2001:db8::2',
                  next_header=60, ext_headers=ext, hop_limit=64, payload=udp)
        wire = ip6.pkt2net({'csum': 1, 'update': 1})

        # First next-header is the ext header; upper layer is still UDP.
        self.assertEqual(ip6.next_header, 60)
        self.assertEqual(ip6.ext_headers, ext)
        # payload_len covers the ext header plus the 10-byte UDP datagram.
        self.assertEqual(ip6.payload_len, len(ext) + 10)

        # UDP checksum must use the terminal protocol (17) and the UDP length
        # only (extension headers are excluded from the pseudo header).
        ulen = 10
        udp_hdr = _struct.pack('!HHH', 1111, 2222, ulen) + b'\x00\x00'
        ph = _v6_pheader('2001:db8::1', '2001:db8::2', ulen, 17) + \
            udp_hdr + b'hi'
        self.assertEqual(ip6.payload.checksum, _cksum(ph))

        # Re-parse the serialized bytes: ext header preserved, UDP recovered.
        p = IP6(wire)
        self.assertEqual(p.next_header, 60)
        self.assertEqual(p.ext_headers, ext)
        self.assertIsInstance(p.payload, UDP)
        self.assertEqual(p.payload.sport, 1111)
        self.assertEqual(p.payload.dport, 2222)
        # Whole packet round-trips byte-identical.
        self.assertEqual(p.pkt2net({}), wire)

    def test_Ethernet_IP6_ethertype(self):
        # Assigning an IP6 payload after construction must serialize with the
        # IPv6 EtherType (0x86dd) so the frame re-parses as IP6, not IP.
        eth = Ethernet(src_mac='00:11:22:33:44:55',
                       dst_mac='66:77:88:99:aa:bb')
        eth.payload = IP6(src='2001:db8::1', dst='2001:db8::2',
                          next_header=C.PROTO_UDP,
                          payload=UDP(sport=1234, dport=53, payload=b'q'))
        wire = eth.pkt2net({'csum': 1, 'update': 1})
        self.assertEqual(wire[12:14], b'\x86\xdd')
        p = Ethernet(wire)
        self.assertIsInstance(p.payload, IP6)
        self.assertEqual(p.payload.src, '2001:db8::1')
        self.assertIsInstance(p.payload.payload, UDP)

    def test_IP_UDP_pkt(self):
        import tempfile

        pkt = Ethernet(dst_mac='03:02:03:04:05:06',
                       src_mac='06:05:04:03:02:03')

        pkt.payload = IP(proto=C.PROTO_UDP,
                         src='10.1.2.3',
                         dst='10.3.2.1',
                         payload=UDP(sport=34567,
                                     dport=53,
                                     payload=NullPkt()))

        """
        Write this packet out to a pcap file
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = os.path.join(temp_dir, 'ip_udp.pcap')
            wrt = PCAPWriter(filename=capture)
            wrt.dump_pkt(pkt.pkt2net({'csum': 1, 'update': 1}))
            wrt.close()

            """
            Read the copy packet in from the pcap file just created.
            """
            rdr = PCAPReader(filename=capture)
            pkt_copy = Ethernet(next(rdr)[2])
            rdr.close()

        a_IP = pkt.get_layer("IP")
        b_IP = pkt_copy.get_layer("IP")
        self.assertEqual(a_IP.proto, b_IP.proto)
        self.assertEqual(a_IP.src, b_IP.src)
        self.assertEqual(a_IP.dst, b_IP.dst)
        self.assertEqual(a_IP.total_len, b_IP.total_len)
        self.assertEqual(a_IP.checksum, b_IP.checksum)

        a_UDP = pkt.get_layer("UDP")
        b_UDP = pkt_copy.get_layer("UDP")
        self.assertEqual(a_UDP.sport, b_UDP.sport)
        self.assertEqual(a_UDP.dport, b_UDP.dport)
        self.assertEqual(a_UDP.checksum, b_UDP.checksum)

    def test_Ethernet_IP_UDP_parse_ownership(self):
        original = Ethernet(dst_mac='03:02:03:04:05:06',
                            src_mac='06:05:04:03:02:03',
                            tpid=C.ETH_TYPE_8021Q, vlan_id=37,
                            payload=IP(proto=C.PROTO_UDP,
                                       src='10.1.2.3', dst='10.3.2.1',
                                       iphl=6,
                                       options=b'\x01\x01\x00\x00',
                                       payload=UDP(sport=34567, dport=53,
                                                   payload=NullPkt(b'phase-c'))))
        wire = original.pkt2net({'csum': 1, 'update': 1})
        source = array('B', wire)
        parsed = Ethernet(source)
        ip = parsed.payload
        udp = ip.payload

        self.assertEqual(parsed.vlan_id, 37)
        self.assertEqual(ip.options, b'\x01\x01\x00\x00')
        self.assertEqual(udp.sport, 34567)
        self.assertTrue(udp.payload.pkt2net({}).startswith(b'phase-c'))
        self.assertEqual(parsed.pkt2net({}), wire)

        source[:] = array('B', b'\xff' * len(source))
        self.assertEqual(parsed.src_mac, '06:05:04:03:02:03')
        self.assertEqual(ip.src, '10.1.2.3')
        self.assertEqual(udp.sport, 34567)

        del parsed
        del ip
        self.assertTrue(udp.payload.pkt2net({}).startswith(b'phase-c'))
        self.assertEqual(UDP(udp.pkt2net({})).sport, 34567)

    def test_Ethernet_IP_UDP_parse_truncation(self):
        original = Ethernet(dst_mac='03:02:03:04:05:06',
                            src_mac='06:05:04:03:02:03',
                            payload=IP(proto=C.PROTO_UDP,
                                       src='10.1.2.3', dst='10.3.2.1',
                                       payload=UDP(sport=34567, dport=53)))
        wire = original.pkt2net({'csum': 1, 'update': 1})

        self.assertRaises(ValueError, Ethernet, wire[:13])
        self.assertRaises(ValueError, Ethernet, wire[:14 + 19])
        self.assertRaises(ValueError, Ethernet, wire[:14 + 20 + 7])

    def test_phase_c2_transport_owner_paths(self):
        tcp = TCP(sport=34567, dport=80, sequence=200, flag_syn=1,
                  options=b'\x02\x04\x05\xb4',
                  payload=NullPkt(b'tcp-owner'))
        vlan_tcp = Ethernet(
            dst_mac='03:02:03:04:05:10', src_mac='06:05:04:03:02:10',
            tpid=C.ETH_TYPE_8021Q, vlan_id=37,
            payload=IP(proto=C.PROTO_TCP, src='10.1.2.3', dst='10.3.2.1',
                       payload=tcp))
        hop_opts = bytes([C.PROTO_UDP, 0]) + b'\x00' * 6
        ip6_ext = Ethernet(
            dst_mac='03:02:03:04:05:11', src_mac='06:05:04:03:02:11',
            payload=IP6(next_header=0, ext_headers=hop_opts,
                        src='2001:db8::1', dst='2001:db8::2',
                        payload=UDP(sport=34567, dport=53,
                                    payload=NullPkt(b'ip6-owner'))))
        mpls_ip6 = Ethernet(
            dst_mac='03:02:03:04:05:12', src_mac='06:05:04:03:02:12',
            payload=MPLS(
                label=100, s=0, ttl=64,
                payload=MPLS(
                    label=200, s=1, ttl=63,
                    payload=IP6(
                        next_header=C.PROTO_TCP,
                        src='2001:db8::3', dst='2001:db8::4',
                        payload=TCP(sport=443, dport=40000, flag_ack=1,
                                    payload=NullPkt(b'mpls-owner'))))))

        cases = ((vlan_tcp, 'TCP', 34567, b'tcp-owner'),
                 (ip6_ext, 'UDP', 34567, b'ip6-owner'),
                 (mpls_ip6, 'TCP', 443, b'mpls-owner'))
        for original, layer_name, sport, payload in cases:
            wire = original.pkt2net({'csum': 1, 'update': 1})
            source = array('B', wire)
            parsed = Ethernet(source)
            transport = parsed.get_layer(layer_name)

            self.assertEqual(transport.sport, sport)
            self.assertTrue(transport.payload.pkt2net({}).startswith(payload))
            self.assertEqual(parsed.pkt2net({}), wire)

            source[:] = array('B', b'\xff' * len(source))
            self.assertEqual(transport.sport, sport)
            self.assertTrue(transport.payload.pkt2net({}).startswith(payload))

            del parsed
            self.assertEqual(transport.pkt2net({})[:2],
                             sport.to_bytes(2, 'big'))

    def test_phase_c2_transport_truncation(self):
        tcp_frame = Ethernet(
            dst_mac='03:02:03:04:05:13', src_mac='06:05:04:03:02:13',
            payload=IP(proto=C.PROTO_TCP, src='10.1.2.3', dst='10.3.2.1',
                       payload=TCP(sport=34567, dport=80,
                                   payload=NullPkt(b'payload'))))
        tcp_wire = tcp_frame.pkt2net({'csum': 1, 'update': 1})
        short_tcp = Ethernet(tcp_wire[:14 + 20 + 19]).payload.payload
        self.assertIsInstance(short_tcp, TCP)
        self.assertEqual(short_tcp.sport, 0)

        bad_options = bytearray(tcp_wire[:14 + 20 + 20])
        bad_options[14 + 20 + 12] = 0xf0
        clipped_tcp = Ethernet(bytes(bad_options)).payload.payload
        self.assertEqual(clipped_tcp.data_offset, 15)
        self.assertEqual(clipped_tcp.options, b'')
        self.assertEqual(clipped_tcp.payload.pkt2net({}), b'')

        ip6_frame = Ethernet(
            dst_mac='03:02:03:04:05:14', src_mac='06:05:04:03:02:14',
            payload=IP6(next_header=C.PROTO_UDP,
                        src='2001:db8::1', dst='2001:db8::2',
                        payload=UDP(sport=34567, dport=53)))
        ip6_wire = ip6_frame.pkt2net({'csum': 1, 'update': 1})
        self.assertRaises(ValueError, Ethernet, ip6_wire[:14 + 39])
        self.assertRaises(ValueError, Ethernet, ip6_wire[:14 + 40 + 7])

        mpls_frame = Ethernet(
            dst_mac='03:02:03:04:05:15', src_mac='06:05:04:03:02:15',
            payload=MPLS(label=100, s=1, ttl=64,
                         payload=IP(src='10.1.2.3', dst='10.3.2.1')))
        mpls_wire = mpls_frame.pkt2net({'csum': 1, 'update': 1})
        self.assertRaises(ValueError, Ethernet, mpls_wire[:14 + 3])

    def test_phase_c2_ipv6_noninitial_fragment_stays_raw(self):
        udp = UDP(sport=34567, dport=53,
                  payload=NullPkt(b'fragment-owner')).pkt2net({'update': 1})
        # Fragment offset one (8 bytes) means the transport header is not at
        # the start of this fragment and must not be decoded as UDP.
        fragment = bytes([C.PROTO_UDP, 0, 0, 8]) + b'\x12\x34\x56\x78'
        frame = Ethernet(
            dst_mac='03:02:03:04:05:16', src_mac='06:05:04:03:02:16',
            payload=IP6(next_header=44, ext_headers=fragment,
                        src='2001:db8::1', dst='2001:db8::2',
                        payload=NullPkt(udp)))
        wire = frame.pkt2net({'csum': 1, 'update': 1})
        parsed = Ethernet(wire)

        self.assertIsInstance(parsed.payload.payload, NullPkt)
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_phase_c2_control_owner_paths(self):
        embedded = IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                      payload=UDP(sport=34567, dport=53)).pkt2net(
                          {'csum': 1, 'update': 1})
        arp = ARP(operation=1, sender_hw_addr='06:05:04:03:02:03',
                  sender_proto_addr='10.1.2.3',
                  target_hw_addr='00:00:00:00:00:00',
                  target_proto_addr='10.3.2.1')
        netflow = NetflowSimple(version=5, count=30, sys_uptime=1000,
                                unix_secs=1500000000,
                                unix_nano_seconds=1, payload=b'flow-owner')
        icmp = ICMP(type=C.ICMP_TYPE_DU, code=4, mtu=1500,
                    hdr_pkt=IP(embedded))
        igmp = IGMP(version=3, type=C.IGMP_V3_MEMBER_REPORT, num_records=2,
                    group_records=[
                        IGMPGroupRecord(
                            type=1, group_address='224.1.1.1',
                            source_addresses=['10.1.1.1', '10.1.1.2']),
                        IGMPGroupRecord(type=2,
                                        group_address='224.1.1.2')])
        nd_opt = ICMP6Opt(type=C.ICMP6_OPT_SRC_LLADDR,
                          link_layer_address='00:11:22:33:44:55')
        icmp6_nd = ICMP6(type=C.ICMP6_ND_NEIGHBOR_SOLICIT,
                         target_address='fe80::1', options=[nd_opt])
        mld_record = MLDv2AddressRecord(
            type=4, multicast_address='ff05::1',
            source_addresses=['2001:db8::10'])
        icmp6_mld = ICMP6(type=C.ICMP6_MLDV2_REPORT,
                          records=[mld_record])

        direct_cases = (
            (ARP, arp.pkt2net({}), {}),
            (NetflowSimple, netflow.pkt2net({}), {}),
            (ICMP, icmp.pkt2net({'csum': 1}), {}),
            (IGMP, igmp.pkt2net({'csum': 1}), {}),
            (ICMP6, icmp6_nd.pkt2net({}), {}),
            (ICMP6, icmp6_mld.pkt2net({}), {}),
        )
        for cls, wire, kwargs in direct_cases:
            source = array('B', wire)
            parsed = cls(source)
            source[:] = array('B', b'\xff' * len(source))
            self.assertEqual(parsed.pkt2net(kwargs), wire)

        parsed_icmp = ICMP(icmp.pkt2net({'csum': 1}))
        embedded_ip = parsed_icmp.hdr_pkt
        del parsed_icmp
        self.assertEqual(embedded_ip.src, '10.1.2.3')

        parsed_igmp = IGMP(igmp.pkt2net({'csum': 1}))
        record = parsed_igmp.group_records[0]
        del parsed_igmp
        self.assertEqual(record.source_addresses,
                         ['10.1.1.1', '10.1.1.2'])

        parsed_nd = ICMP6(icmp6_nd.pkt2net({}))
        option = parsed_nd.options[0]
        del parsed_nd
        self.assertEqual(option.link_layer_address, '00:11:22:33:44:55')

        parsed_mld = ICMP6(icmp6_mld.pkt2net({}))
        record6 = parsed_mld.records[0]
        del parsed_mld
        self.assertEqual(record6.source_addresses, ['2001:db8::10'])

    def test_phase_c2_control_nested_and_truncated(self):
        stacks = (
            Ethernet(dst_mac='03:02:03:04:05:17',
                     src_mac='06:05:04:03:02:17',
                     payload=ARP(
                         operation=1,
                         sender_hw_addr='06:05:04:03:02:17',
                         sender_proto_addr='10.1.2.3',
                         target_hw_addr='00:00:00:00:00:00',
                         target_proto_addr='10.3.2.1')),
            Ethernet(dst_mac='03:02:03:04:05:18',
                     src_mac='06:05:04:03:02:18',
                     payload=IP(
                         proto=C.PROTO_ICMP, src='10.1.2.3', dst='10.3.2.1',
                         payload=ICMP(type=C.ICMP_TYPE_ECHO, identifier=1,
                                      sequence=2, echo_data=b'icmp-owner'))),
            Ethernet(dst_mac='03:02:03:04:05:19',
                     src_mac='06:05:04:03:02:19',
                     payload=IP(
                         proto=C.PROTO_IGMP, src='10.1.2.3', dst='224.1.1.1',
                         payload=IGMP(
                             version=2, type=C.IGMP_V2_MEMBER_REPORT,
                             group_address='224.1.1.1'))),
            Ethernet(dst_mac='03:02:03:04:05:20',
                     src_mac='06:05:04:03:02:20',
                     payload=IP6(
                         next_header=C.PROTO_ICMPV6,
                         src='2001:db8::1', dst='ff02::1',
                         payload=ICMP6(type=C.ICMP6_ECHO_REQUEST,
                                       identifier=1, sequence=2,
                                       echo_data=b'icmp6-owner'))),
        )
        for original in stacks:
            wire = original.pkt2net({'csum': 1, 'update': 1})
            parsed = Ethernet(array('B', wire))
            self.assertEqual(parsed.pkt2net({}), wire)

        arp_wire = stacks[0].payload.pkt2net({})
        self.assertRaises(ValueError, ARP, arp_wire[:27])

        netflow_wire = NetflowSimple(
            version=5, count=1, payload=b'x').pkt2net({})
        self.assertRaises(ValueError, NetflowSimple, netflow_wire[:15])

        igmp_record = IGMPGroupRecord(
            type=1, group_address='224.1.1.1',
            source_addresses=['10.1.1.1', '10.1.1.2']).pkt2net({})
        self.assertRaises(ValueError, IGMPGroupRecord, igmp_record[:-1])

        mld_record = MLDv2AddressRecord(
            type=4, multicast_address='ff05::1',
            source_addresses=['2001:db8::10']).pkt2net({})
        self.assertRaises(ValueError, MLDv2AddressRecord, mld_record[:-1])

    def test_phase_c2_dns_and_downstream_owner_contract(self):
        dns = DNS()
        dns.ident = 0x4321
        dns.query_resp = 1
        dns.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
        dns.answers.append(DNSResource('www.example.com', DNSTYPE_CNAME,
                                       RCLASS_IN, 300, 0,
                                       'host.example.com'))
        dns.answers.append(DNSResource('host.example.com', DNSTYPE_A,
                                       RCLASS_IN, 300, 4, '10.1.2.3'))
        dns_wire = dns.pkt2net({'update': 1, 'compress': 1})

        carriers = (
            UDP(sport=40000, dport=53, payload=NullPkt(dns_wire)),
            TCP(sport=40000, dport=53, sequence=1,
                payload=NullPkt(dns_wire)),
        )
        for carrier in carriers:
            proto = C.PROTO_UDP if isinstance(carrier, UDP) else C.PROTO_TCP
            frame = Ethernet(
                dst_mac='03:02:03:04:05:21',
                src_mac='06:05:04:03:02:21',
                payload=IP(proto=proto, src='10.1.2.3', dst='10.3.2.1',
                           payload=carrier))
            wire = frame.pkt2net({'csum': 1, 'update': 1})
            source = array('B', wire)
            parsed = Ethernet(source, l7_ports={53: DNS})
            parsed_dns = parsed.get_layer('DNS')

            self.assertIsInstance(parsed_dns, DNS)
            self.assertEqual(parsed_dns.ident, 0x4321)
            self.assertEqual(parsed_dns.queries[0].query_name,
                             'www.example.com')
            self.assertEqual(parsed_dns.answers[0].res_data,
                             'host.example.com')

            source[:] = array('B', b'\xff' * len(source))
            del parsed
            self.assertEqual(parsed_dns.ident, 0x4321)
            self.assertEqual(parsed_dns.queries[0].query_name,
                             'www.example.com')
            self.assertEqual(parsed_dns.answers[0].res_data,
                             'host.example.com')

        downstream_payload = b'downstream-owner-copy'
        downstream_frame = Ethernet(
            dst_mac='03:02:03:04:05:22',
            src_mac='06:05:04:03:02:22',
            payload=IP(
                proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                payload=UDP(sport=40000, dport=40500,
                            payload=NullPkt(downstream_payload))))
        downstream_wire = downstream_frame.pkt2net(
            {'csum': 1, 'update': 1})
        downstream_source = array('B', downstream_wire)
        parsed = Ethernet(
            downstream_source,
            l7_ports={40500: _OwnedDownstreamProtocol})
        downstream = parsed.payload.payload.payload
        downstream_source[:] = array('B', b'\xff' * len(downstream_source))

        self.assertIsInstance(downstream, _OwnedDownstreamProtocol)
        self.assertTrue(downstream.data.startswith(downstream_payload))

    def test_IP_TCP_pkt(self):
        import tempfile

        pkt = Ethernet(dst_mac='05:02:03:04:05:06',
                       src_mac='06:05:04:03:02:05')

        pkt.payload = IP(proto=C.PROTO_TCP,
                         src='10.1.2.5',
                         dst='10.5.2.1',
                         payload=TCP(sport=34567,
                                     dport=80,
                                     sequence=200,
                                     flag_syn=1,
                                     options=b'this is not a real option.'))

        """
        Write this packet out to a pcap file
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = os.path.join(temp_dir, 'ip_tcp.pcap')
            wrt = PCAPWriter(filename=capture)
            wrt.dump_pkt(pkt.pkt2net({'csum': 1, 'update': 1}))
            wrt.close()

            """
            Read the copy packet in from the pcap file just created.
            """
            rdr = PCAPReader(filename=capture)
            pkt_copy = Ethernet(next(rdr)[2])
            rdr.close()

        a_IP = pkt.get_layer("IP")
        b_IP = pkt_copy.get_layer("IP")
        self.assertEqual(a_IP.proto, b_IP.proto)
        self.assertEqual(a_IP.src, b_IP.src)
        self.assertEqual(a_IP.dst, b_IP.dst)
        self.assertEqual(a_IP.total_len, b_IP.total_len)
        self.assertEqual(a_IP.checksum, b_IP.checksum)

        a_TCP = pkt.get_layer("TCP")
        b_TCP = pkt_copy.get_layer("TCP")
        self.assertEqual(a_TCP.sport, b_TCP.sport)
        self.assertEqual(a_TCP.dport, b_TCP.dport)
        self.assertEqual(a_TCP.flag_syn, b_TCP.flag_syn)
        self.assertEqual(a_TCP.checksum, b_TCP.checksum)

    def test_IP_ICMP_pkt(self):
        pkt = Ethernet(icmp_pkt_data)
        icmp = pkt.get_layer_by_type(C.PQ_ICMP)
        self.assertEqual(icmp.type, C.ICMP_TYPE_ECHO)
        self.assertEqual(icmp.identifier, 0xfff)
        self.assertEqual(icmp.sequence, 0xaaaa)

        pkt_du = Ethernet(icmp_destun_pkt_data)
        icmp = pkt_du.get_layer_by_type(C.PQ_ICMP)
        self.assertEqual(icmp.type, C.ICMP_TYPE_DU)
        self.assertEqual(icmp.code, C.ICMP_DU_CODE_PORT_UNREACH)
        self.assertEqual(icmp.identifier, 0)
        self.assertEqual(icmp.sequence, 0)
        self.assertEqual(icmp.checksum, 4456)
        self.assertEqual(icmp.hdr_pkt.payload.dport, 2054)

    def test_IP_IGMP_pkt(self):
        pkt = Ethernet(igmp_pkt_data)
        igmp = pkt.get_layer_by_type(C.PQ_IGMP)
        igmpv3_report = Ethernet(igmpv3_member_report)
        igmpv3r = igmpv3_report.get_layer_by_type(C.PQ_IGMP)
        igmpv3_query = Ethernet(igmpv3_member_query)
        igmpv3q = igmpv3_query.get_layer_by_type(C.PQ_IGMP)

        self.assertEqual(igmp.version, 2)
        self.assertEqual(igmp.type, C.IGMP_V2_MEMBER_REPORT)
        self.assertEqual(igmp.max_resp, 0)
        self.assertEqual(igmp.checksum, 0xfa04)
        self.assertEqual(igmp.group_address, '239.255.255.250')
        self.assertEqual(igmp.group_address, '239.255.255.250')
        # IGMP v3
        self.assertEqual(igmpv3r.version, 3)
        self.assertEqual(igmpv3r.type, C.IGMP_V3_MEMBER_REPORT)
        self.assertEqual(igmpv3r.num_records, 3)
        self.assertEqual(igmpv3r.group_records[0].type, 2)
        self.assertEqual(igmpv3r.group_records[0].group_address,
                         '239.195.7.2')
        self.assertEqual(igmpv3r.group_records[1].group_address,
                         '239.255.255.250')
        self.assertEqual(igmpv3r.group_records[2].group_address,
                         '239.195.1.95')
        self.assertEqual(igmpv3q.version, 3)
        self.assertEqual(igmpv3q.type, C.IGMP_MEMBER_QUERY)
        self.assertEqual(igmpv3q.max_resp, 0x18)
        self.assertEqual(igmpv3q.qrv, 2)
        self.assertEqual(igmpv3q.qqic, 20)

    def test_IGMP_direct_parse(self):
        """IGMP(raw) with no length= from IP must parse, not raise.

        The version guard used to test a local that four branches never
        assigned, so every one of those types fell through to the error
        path. Masked in the pcap tests because IP always passes length=.
        """
        pkt = Ethernet(igmp_pkt_data)
        v2_bytes = pkt.get_layer_by_type(C.PQ_IGMP).pkt2net({})
        v3r_bytes = Ethernet(
            igmpv3_member_report).get_layer_by_type(C.PQ_IGMP).pkt2net({})
        v3q_bytes = Ethernet(
            igmpv3_member_query).get_layer_by_type(C.PQ_IGMP).pkt2net({})

        v2 = IGMP(v2_bytes)
        self.assertEqual(v2.version, 2)
        self.assertEqual(v2.type, C.IGMP_V2_MEMBER_REPORT)
        self.assertEqual(v2.group_address, '239.255.255.250')

        v3r = IGMP(v3r_bytes)
        self.assertEqual(v3r.version, 3)
        self.assertEqual(v3r.type, C.IGMP_V3_MEMBER_REPORT)
        self.assertEqual(v3r.num_records, 3)
        self.assertEqual(v3r.group_records[0].group_address, '239.195.7.2')

        v3q = IGMP(v3q_bytes)
        self.assertEqual(v3q.version, 3)
        self.assertEqual(v3q.type, C.IGMP_MEMBER_QUERY)
        self.assertEqual(v3q.qqic, 20)

        leave = IGMP(_struct.pack('!BBH', C.IGMP_LEAVE_GROUP, 0, 0) +
                     _socket.inet_aton('239.1.2.3'))
        self.assertEqual(leave.version, 2)
        self.assertEqual(leave.group_address, '239.1.2.3')

    def test_IGMPGroupRecord_kwargs(self):
        """source_addresses kwarg and the group record's own pq_type."""
        rec = IGMPGroupRecord(type=1,
                              group_address='239.1.1.1',
                              source_addresses=['10.1.1.1', '10.1.1.2'])
        self.assertEqual(rec.source_addresses, ['10.1.1.1', '10.1.1.2'])
        self.assertEqual(rec.num_src, 2)
        self.assertEqual(rec.pq_type, C.PQ_IGMPv3GroupRecord)
        self.assertEqual(rec.query_fields,
                         IGMPGroupRecord.query_info()[1])

    def test_IP_CONST_icmp_types(self):
        """IP_CONST members must match their module level counterparts."""
        self.assertEqual(C.ICMP_TYPE_REDIR, 5)
        self.assertEqual(C.ICMP_TYPE_SRC_QUENCH, 4)
        self.assertNotEqual(C.ICMP_TYPE_REDIR, C.ICMP_TYPE_SRC_QUENCH)

    def test_Ethernet_vlan_id_range(self):
        eth = Ethernet(vlan_id=100)
        self.assertEqual(eth.vlan_id, 100)
        with self.assertRaises(ValueError) as ctx:
            eth.vlan_id = 0x1000
        self.assertIn('4095', str(ctx.exception))

    def test_TCP_options_data_offset(self):
        self.assertEqual(TCP(options=b'\x01' * 4).data_offset, 6)
        self.assertEqual(TCP(options=b'\x01' * 8).data_offset, 7)
        self.assertEqual(TCP(options=b'\x01' * 5).data_offset, 7)

    def test_NullPkt_repr_binary(self):
        """repr() must not raise on payloads that are not valid UTF-8."""
        self.assertIn('NullPkt', repr(NullPkt(b'\xff\xfe\x80abc')))

    def test_MPLS_tc_roundtrip(self):
        """tc must survive build -> pkt2net -> parse.

        The getter read bits 12-14 (the low bits of the label) while the
        setter wrote the field at bit 9, so tc never round-tripped and
        mpls.*.tc query results were wrong.
        """
        mpls = MPLS(label=0xabcde, tc=5, s=1, ttl=64)
        self.assertEqual(mpls.label, 0xabcde)
        self.assertEqual(mpls.tc, 5)
        self.assertEqual(mpls.s, 1)
        self.assertEqual(mpls.ttl, 64)

        parsed = MPLS(mpls.pkt2net({}))
        self.assertEqual(parsed.label, 0xabcde)
        self.assertEqual(parsed.tc, 5)
        self.assertEqual(parsed.s, 1)
        self.assertEqual(parsed.ttl, 64)

        # tc must not disturb the label and vice versa.
        for tc in range(8):
            mpls.tc = tc
            self.assertEqual(mpls.tc, tc)
            self.assertEqual(mpls.label, 0xabcde)
            self.assertEqual(mpls.s, 1)

    def test_l7_ports_wildcard(self):
        """l7_ports={0: cls} must decode regardless of the port numbers.

        The wildcard branch indexed l7_ports by the source port instead of
        by 0, so it raised KeyError for exactly the case it exists to serve.
        """
        dns = DNS()
        dns.ident = 0x4321
        dns.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
        dns_bytes = dns.pkt2net({'update': 1, 'compress': 1})

        udp = UDP(sport=40000, dport=40001, payload=dns_bytes)
        udp_parsed = UDP(array('B', udp.pkt2net({'update': 1})),
                         l7_ports={0: DNS})
        self.assertIsInstance(udp_parsed.payload, DNS)
        self.assertEqual(udp_parsed.payload.ident, 0x4321)

        udp_precedence = UDP(array('B', udp.pkt2net({'update': 1})),
                             l7_ports={40000: NullPkt, 40001: DNS})
        self.assertIsInstance(udp_precedence.payload, DNS)

        udp_downstream = UDP(array('B', udp.pkt2net({'update': 1})),
                             l7_ports={40001: _DownstreamProtocol})
        self.assertIsInstance(udp_downstream.payload, _DownstreamProtocol)

        tcp = TCP(sport=40000, dport=40001, payload=dns_bytes)
        tcp_parsed = TCP(array('B', tcp.pkt2net({'update': 1})),
                         l7_ports={0: DNS})
        self.assertIsInstance(tcp_parsed.payload, DNS)
        self.assertEqual(tcp_parsed.payload.ident, 0x4321)

        tcp_string = TCP(array('B', tcp.pkt2net({'update': 1})),
                         l7_ports={40001: 'NullPkt'})
        self.assertIsInstance(tcp_string.payload, NullPkt)

    def test_l7_ports_lazy_defaults_are_independent(self):
        """Implicit registries must not become one shared writable mapping."""
        wire = Ethernet(
            payload=IP(proto=C.PROTO_UDP,
                       payload=UDP(sport=4444, dport=5555,
                                   payload=NullPkt(b'payload')))
        ).pkt2net({'update': 1})
        parsed = Ethernet(wire)
        ip = parsed.payload
        udp = ip.payload
        raw = udp.payload

        registries = [parsed.l7_ports, ip.l7_ports, udp.l7_ports,
                      raw.l7_ports]
        self.assertEqual(registries, [{}, {}, {}, {}])
        self.assertEqual(len({id(registry) for registry in registries}), 4)
        parsed.l7_ports[5555] = _DownstreamProtocol
        self.assertNotIn(5555, ip.l7_ports)
        with self.assertRaises(TypeError):
            parsed.l7_ports = None

        supplied = {5555: NullPkt}
        configured = Ethernet(wire, l7_ports=supplied)
        self.assertIs(configured.l7_ports, supplied)
        self.assertIs(configured.payload.l7_ports, supplied)
        self.assertIs(configured.payload.payload.l7_ports, supplied)
        self.assertIs(configured.payload.payload.payload.l7_ports, supplied)

    def test_ICMP_byte_fields_over_127(self):
        """type/code/pointer >= 128 must emit one byte, not UTF-8.

        chr(val).encode() produced two bytes for anything over 127 and
        silently corrupted the frame.
        """
        du = ICMP(type=C.ICMP_TYPE_DU, code=200, mtu=1500)
        du_bytes = du.pkt2net({'csum': 1})
        self.assertEqual(len(du_bytes), 8)
        self.assertEqual(du_bytes[0], C.ICMP_TYPE_DU)
        self.assertEqual(du_bytes[1], 200)

        pp = ICMP(type=C.ICMP_TYPE_PER_PROB, code=0, pointer=200)
        pp_bytes = pp.pkt2net({'csum': 1})
        self.assertEqual(len(pp_bytes), 8)
        self.assertEqual(pp_bytes[0], C.ICMP_TYPE_PER_PROB)
        self.assertEqual(pp_bytes[4], 200)

    def test_ICMP_query_fields(self):
        """icmp.pointer and icmp.receive_timestamp must be registered.

        A missing comma implicitly concatenated the two names into one
        bogus field, so neither was queryable even though get_field_val
        handles both.
        """
        fields = ICMP.query_info()[1]
        self.assertIn('icmp.pointer', fields)
        self.assertIn('icmp.receive_timestamp', fields)
        self.assertNotIn('icmp.pointericmp.receive_timestamp', fields)
        icmp = ICMP(type=C.ICMP_TYPE_PER_PROB, pointer=9, rec_ts=1234)
        self.assertEqual(icmp.get_field_val('icmp.pointer'), 9)
        self.assertEqual(icmp.get_field_val('icmp.receive_timestamp'), 1234)

    def test_IGMPv3_query_source_addresses(self):
        """A v3 membership query carrying sources must parse.

        RFC 3376 puts the source list at offset 12, after resv/S/QRV,
        QQIC and the number-of-sources field; the parser read it at 8 and
        assigned an array slice to a bytes field.
        """
        sources = ['10.1.1.1', '10.1.1.2', '10.1.1.3']
        query = _struct.pack('!BBH', C.IGMP_MEMBER_QUERY, 0x18, 0) + \
            _socket.inet_aton('224.1.1.1') + \
            _struct.pack('!BBH', 0x02, 20, len(sources)) + \
            b''.join([_socket.inet_aton(s) for s in sources])

        parsed = IGMP(query)
        self.assertEqual(parsed.version, 3)
        self.assertEqual(parsed.type, C.IGMP_MEMBER_QUERY)
        self.assertEqual(parsed.group_address, '224.1.1.1')
        self.assertEqual(parsed.qrv, 2)
        self.assertEqual(parsed.qqic, 20)
        self.assertEqual(parsed.num_records, len(sources))
        self.assertEqual(parsed.source_addresses, sources)
        self.assertEqual(parsed.pkt2net({}), query)

        built = IGMP(version=3, type=C.IGMP_MEMBER_QUERY, max_resp=0x18,
                     group_address='224.1.1.1', s=0, qrv=2, qqic=20,
                     source_addresses=sources)
        self.assertEqual(built.pkt2net({}), query)

    def test_kwargs_empty_buffer_not_shared(self):
        """The shared empty buffer must never be mutated in place.

        from_buffer() hands every kwargs construction the same empty
        array instead of allocating a throwaway one per layer per packet,
        so any path that grows _buffer in place would poison every packet
        built afterwards. ARP's non-standard hardware/proto length branch
        is the one that used to do exactly that.
        """
        self.assertEqual(NullPkt().pkt2net({}), b'')
        arp = ARP(hardware_type=99, proto_type=0x1234, hardware_len=3,
                  proto_len=5, operation=1)
        arp_bytes = arp.pkt2net({})
        self.assertEqual(len(arp_bytes), 8 + (3 * 2) + (5 * 2))
        self.assertEqual(arp_bytes[:8],
                         _struct.pack('!HHBBH', 99, 0x1234, 3, 5, 1))
        # A second one must be identical, and unrelated classes must still
        # start from an empty buffer.
        self.assertEqual(ARP(hardware_type=99, proto_type=0x1234,
                             hardware_len=3, proto_len=5,
                             operation=1).pkt2net({}), arp_bytes)
        self.assertEqual(NullPkt().pkt2net({}), b'')
        self.assertEqual(len(UDP(sport=1, dport=2).pkt2net({'update': 1})), 8)

    def test_mac_address_parsing(self):
        """The fast MAC path must accept everything the old one did."""
        eth = Ethernet(src_mac='0A:0b:0C:0d:0E:0f',
                       dst_mac='1:2:3:4:5:6')
        self.assertEqual(eth.src_mac, '0a:0b:0c:0d:0e:0f')
        self.assertEqual(eth.dst_mac, '01:02:03:04:05:06')
        arp = ARP(sender_hw_addr='ff:ff:ff:ff:ff:ff',
                  target_hw_addr='0:0:0:0:0:1')
        self.assertEqual(arp.sender_hw_addr, 'ff:ff:ff:ff:ff:ff')
        self.assertEqual(arp.target_hw_addr, '00:00:00:00:00:01')

    def test_ARP_roundtrip(self):
        """Standard Ethernet/IPv4 ARP round-trip."""
        # Request
        raw_req = _struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + \
                  b'\x01\x02\x03\x04\x05\x06' + _socket.inet_aton('10.0.0.1') + \
                  b'\x00\x00\x00\x00\x00\x00' + _socket.inet_aton('10.0.0.2')
        arp_req = ARP(raw_req)
        self.assertEqual(arp_req.operation, 1)
        self.assertEqual(arp_req.sender_hw_addr, '01:02:03:04:05:06')
        self.assertEqual(arp_req.sender_proto_addr, '10.0.0.1')
        self.assertEqual(arp_req.target_hw_addr, '00:00:00:00:00:00')
        self.assertEqual(arp_req.target_proto_addr, '10.0.0.2')
        self.assertEqual(arp_req.pkt2net({}), raw_req)

        # Reply
        raw_rep = _struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) + \
                  b'\x0a\x0b\x0c\x0d\x0e\x0f' + _socket.inet_aton('10.0.0.2') + \
                  b'\x01\x02\x03\x04\x05\x06' + _socket.inet_aton('10.0.0.1')
        arp_rep = ARP(raw_rep)
        self.assertEqual(arp_rep.operation, 2)
        self.assertEqual(arp_rep.sender_hw_addr, '0a:0b:0c:0d:0e:0f')
        self.assertEqual(arp_rep.sender_proto_addr, '10.0.0.2')
        self.assertEqual(arp_rep.target_hw_addr, '01:02:03:04:05:06')
        self.assertEqual(arp_rep.target_proto_addr, '10.0.0.1')
        self.assertEqual(arp_rep.pkt2net({}), raw_rep)

        # kwargs round-trip
        arp_kw = ARP(operation=2, sender_hw_addr='01:02:03:04:05:06',
                     sender_proto_addr='10.0.0.1')
        raw_kw = arp_kw.pkt2net({})
        parsed_kw = ARP(raw_kw)
        self.assertEqual(parsed_kw.operation, 2)
        self.assertEqual(parsed_kw.sender_hw_addr, '01:02:03:04:05:06')

    def test_ARP_non_standard_roundtrip(self):
        """Non-standard hardware/proto-length ARP."""
        raw = _struct.pack('!HHBBH', 1, 0x0800, 3, 5, 1) + \
              b'\x01\x02\x03' + b'\x0a\x0b\x0c\x0d\x0e' + \
              b'\x04\x05\x06' + b'\x0f\x10\x11\x12\x13'
        arp = ARP(raw)
        self.assertEqual(arp.hardware_len, 3)
        self.assertEqual(arp.proto_len, 5)
        self.assertEqual(arp.sender_proto_addr, '0a0b0c0d0e')
        self.assertEqual(arp.target_proto_addr, '0f10111213')
        self.assertEqual(arp.pkt2net({}), raw)

    def test_ICMP_extended_types_roundtrip(self):
        """ICMP echo, unreachable, time-exceeded, redirect, and param-problem."""
        # Echo request
        raw_echo = _struct.pack('!BBHHH', 8, 0, 0, 0x1111, 0x2222) + b'data'
        raw_echo = raw_echo[:2] + _struct.pack('!H', _cksum(raw_echo)) + raw_echo[4:]
        icmp = ICMP(raw_echo)
        self.assertEqual(icmp.identifier, 0x1111)
        self.assertEqual(icmp.echo_data, b'data')
        self.assertEqual(icmp.pkt2net({}), raw_echo)

        # Dest unreachable with embedded IP
        inner = IP(src='10.0.0.1', dst='10.0.0.2', proto=17).pkt2net({})
        raw_du = _struct.pack('!BBHHH', 3, 3, 0, 0, 1492) + inner
        raw_du = raw_du[:2] + _struct.pack('!H', _cksum(raw_du)) + raw_du[4:]
        icmp_du = ICMP(raw_du)
        self.assertEqual(icmp_du.type, 3)
        self.assertEqual(icmp_du.mtu, 1492)
        self.assertIsInstance(icmp_du.hdr_pkt, IP)
        self.assertEqual(icmp_du.hdr_pkt.src, '10.0.0.1')
        self.assertEqual(icmp_du.pkt2net({}), raw_du)

        # Time exceeded
        raw_te = _struct.pack('!BBHHH', 11, 0, 0, 0, 0) + inner
        raw_te = raw_te[:2] + _struct.pack('!H', _cksum(raw_te)) + raw_te[4:]
        self.assertEqual(ICMP(raw_te).type, 11)
        self.assertEqual(ICMP(raw_te).pkt2net({}), raw_te)

        # Redirect
        raw_redir = _struct.pack('!BBH', 5, 0, 0) + _socket.inet_aton('1.2.3.4') + inner
        raw_redir = raw_redir[:2] + _struct.pack('!H', _cksum(raw_redir)) + raw_redir[4:]
        icmp_redir = ICMP(raw_redir)
        self.assertEqual(icmp_redir.address, '1.2.3.4')
        self.assertEqual(icmp_redir.pkt2net({}), raw_redir)

        # Parameter problem: pointer, then three unused bytes
        raw_pp = _struct.pack('!BBHB', 12, 0, 0, 42) + b'\x00' * 3 + inner
        raw_pp = raw_pp[:2] + _struct.pack('!H', _cksum(raw_pp)) + raw_pp[4:]
        icmp_pp = ICMP(raw_pp)
        self.assertEqual(icmp_pp.pointer, 42)
        self.assertEqual(icmp_pp.pkt2net({}), raw_pp)

    def test_ICMP_timestamp_roundtrip(self):
        """A timestamp message must decode the fields it serializes.

        The parse was unpack('!HHIII', buffer): 16 bytes read from offset 0,
        so identifier took type/code, sequence took the checksum and each
        timestamp was one field early -- and the fixed size meant a 20 byte
        message (which is what pkt2net emits) raised struct.error outright.
        """
        for icmp_type in (C.ICMP_TYPE_TS, C.ICMP_TYPE_TS_REPLY):
            raw = _struct.pack('!BBHHHIII', icmp_type, 0, 0, 0x1234, 0x5678,
                               0x11111111, 0x22222222, 0x33333333)
            raw = raw[:2] + _struct.pack('!H', _cksum(raw)) + raw[4:]
            self.assertEqual(len(raw), 20)

            ts = ICMP(raw)
            self.assertEqual(ts.type, icmp_type)
            self.assertEqual(ts.code, 0)
            self.assertEqual(ts.identifier, 0x1234)
            self.assertEqual(ts.sequence, 0x5678)
            self.assertEqual(ts.orig_ts, 0x11111111)
            self.assertEqual(ts.rec_ts, 0x22222222)
            self.assertEqual(ts.trans_ts, 0x33333333)
            self.assertEqual(ts.pkt2net({}), raw)
            self.assertEqual(ts.get_field_val('icmp.receive_timestamp'),
                             0x22222222)

    def test_truncated_packets_raise(self):
        """A short frame must raise, not read past the end of the buffer.

        The header reads are direct memoryview indexing with boundscheck
        off, so every parser checks its minimum length up front.
        """
        for cls, short in ((ARP, b'\x00\x01\x08'),
                           (ICMP, b'\x08\x00'),
                           (IGMP, b'\x11\x64\x00\x00'),
                           (IGMPGroupRecord, b'\x01\x00\x00'),
                           (MPLS, b'\x00\x01'),
                           (NetflowSimple, b'\x00\x05\x00\x14'),
                           (IP, b'\x45\x00\x00\x1c'),
                           (Ethernet, b'\x01\x02\x03')):
            with self.assertRaises(ValueError, msg=cls.__name__):
                cls(short)

    def test_ICMP_checksum_identity(self):
        """ICMP pkt2net(csum=1) reproduces byte identity."""
        icmp = ICMP(type=8, code=0, identifier=0xabcd, sequence=1,
                    echo_data=b'tail')
        raw = icmp.pkt2net({'csum': 1})
        self.assertEqual(icmp.checksum, _cksum(_struct.pack('!BBHHH', 8, 0, 0,
                                                           0xabcd, 1) + b'tail'))
        self.assertEqual(ICMP(raw).pkt2net({}), raw)

    def test_IGMP_all_versions_roundtrip(self):
        """IGMP v1, v2, v3 membership messages round-trip."""
        # v1 Report
        raw_v1 = _struct.pack('!BBH', 0x12, 0, 0) + _socket.inet_aton('224.0.0.1')
        raw_v1 = raw_v1[:2] + _struct.pack('!H', _cksum(raw_v1)) + raw_v1[4:]
        self.assertEqual(IGMP(raw_v1).version, 1)
        self.assertEqual(IGMP(raw_v1).pkt2net({}), raw_v1)

        # v2 Query, Report, Leave
        for t, mr in [(0x11, 100), (0x16, 0), (0x17, 0)]:
            raw = _struct.pack('!BBH', t, mr, 0) + _socket.inet_aton('224.0.0.1')
            raw = raw[:2] + _struct.pack('!H', _cksum(raw)) + raw[4:]
            parsed = IGMP(raw)
            self.assertEqual(parsed.version, 2)
            self.assertEqual(parsed.type, t)
            self.assertEqual(parsed.pkt2net({}), raw)

        # v3 Query with sources. QQIC must be non-zero: RFC 3376 8.2 makes it
        # the last query interval used, and the parser relies on that to tell
        # a v3 query from ethernet padding when IP did not pass a length.
        raw_v3q = _struct.pack('!BBH', 0x11, 10, 0) + \
                  _socket.inet_aton('224.0.0.1') + \
                  _struct.pack('!BBH', 0, 125, 1) + _socket.inet_aton('1.1.1.1')
        raw_v3q = raw_v3q[:2] + _struct.pack('!H', _cksum(raw_v3q)) + raw_v3q[4:]
        self.assertEqual(IGMP(raw_v3q).version, 3)
        self.assertEqual(IGMP(raw_v3q).source_addresses, ['1.1.1.1'])
        self.assertEqual(IGMP(raw_v3q).pkt2net({}), raw_v3q)

        # v3 Report with records
        r1 = IGMPGroupRecord(type=1, group_address='239.1.1.1')
        r2 = IGMPGroupRecord(type=2, group_address='239.2.2.2',
                             source_addresses=['2.2.2.2'])
        igmp_v3r = IGMP(version=3, type=0x22, group_records=[r1, r2])
        raw_v3r = igmp_v3r.pkt2net({'csum': 1, 'update': 1})
        parsed_v3r = IGMP(raw_v3r)
        self.assertEqual(parsed_v3r.version, 3)
        self.assertEqual(parsed_v3r.num_records, 2)
        self.assertEqual(parsed_v3r.group_records[1].source_addresses,
                         ['2.2.2.2'])
        self.assertEqual(parsed_v3r.pkt2net({}), raw_v3r)

    def test_IGMP_parse_entry_points(self):
        """IGMP(raw) vs IGMP(raw, length=N) version detection."""
        raw_v2 = _struct.pack('!BBH', 0x11, 10, 0) + \
                 _socket.inet_aton('224.0.0.1')
        self.assertEqual(IGMP(raw_v2).version, 2)
        self.assertEqual(IGMP(raw_v2, length=8).version, 2)

        raw_v3 = raw_v2 + _struct.pack('!BBH', 0, 0, 0)
        # Quirk: version detection falls back to v1/v2 without length if QQIC is 0
        self.assertNotEqual(IGMP(raw_v3).version, 3)
        self.assertEqual(IGMP(raw_v3, length=12).version, 3)

    def test_IGMPGroupRecord_extended_roundtrip(self):
        """IGMPGroupRecord with source addresses and aux data."""
        raw = _struct.pack('!BBH', 4, 8, 1) + _socket.inet_aton('239.1.1.1') + \
              _socket.inet_aton('10.0.0.1') + b'aux_data'
        rec = IGMPGroupRecord(raw)
        self.assertEqual(rec.num_src, 1)
        self.assertEqual(rec.aux_data, b'aux_data')
        self.assertEqual(rec.pkt2net({}), raw)

        # kwargs path
        rec_kw = IGMPGroupRecord(type=4, group_address='239.1.1.1',
                                 source_addresses=['10.0.0.1'],
                                 aux_data=b'aux_data', aux_data_len=8)
        self.assertEqual(rec_kw.pkt2net({}), raw)

    def test_MPLS_stack_roundtrip(self):
        """MPLS single and stacked label round-trip."""
        # Single label S=1
        label1 = (100 << 12) | (1 << 8) | 64
        inner = IP(src='10.0.0.1', dst='10.0.0.2', proto=17).pkt2net({})
        raw1 = _struct.pack('!I', label1) + inner
        mpls1 = MPLS(raw1)
        self.assertEqual(mpls1.label, 100)
        self.assertEqual(mpls1.s, 1)
        self.assertIsInstance(mpls1.payload, IP)
        self.assertEqual(mpls1.pkt2net({}), raw1)

        # Stacked label S=0 -> S=1
        label0 = (200 << 12) | (0 << 8) | 255
        raw_stack = _struct.pack('!I', label0) + raw1
        mpls0 = MPLS(raw_stack)
        self.assertEqual(mpls0.label, 200)
        self.assertEqual(mpls0.s, 0)
        self.assertIsInstance(mpls0.payload, MPLS)
        self.assertEqual(mpls0.payload.label, 100)
        self.assertEqual(mpls0.pkt2net({}), raw_stack)

    def test_Ethernet_MPLS_roundtrip(self):
        """Ethernet frame carrying an MPLS stack.

        Ethernet only accepts a PKT as its payload kwarg, unlike UDP, TCP
        and MPLS which also take raw bytes.
        """
        label = (300 << 12) | (1 << 8) | 64
        inner = IP(src='10.0.0.1', dst='10.0.0.2', proto=17).pkt2net({})
        mpls_raw = _struct.pack('!I', label) + inner
        eth = Ethernet(type=0x8847, dst_mac='01:02:03:04:05:06',
                       src_mac='0a:0b:0c:0d:0e:0f',
                       payload=MPLS(mpls_raw))
        raw_eth = eth.pkt2net({})
        parsed = Ethernet(raw_eth)
        self.assertEqual(parsed.type, 0x8847)
        self.assertIsInstance(parsed.payload, MPLS)
        self.assertEqual(parsed.payload.label, 300)
        self.assertEqual(parsed.payload.s, 1)
        self.assertIsInstance(parsed.payload.payload, IP)
        self.assertEqual(parsed.payload.payload.src, '10.0.0.1')
        self.assertEqual(parsed.pkt2net({}), raw_eth)

    def test_NetflowSimple_header_payload(self):
        """NetflowSimple v5 header and payload round-trip."""
        raw_hdr = _struct.pack('!HHIII', 5, 20, 1000, 1600000000, 999)
        nf = NetflowSimple(raw_hdr)
        self.assertEqual(nf.version, 5)
        self.assertEqual(nf.count, 20)
        self.assertEqual(nf.sys_uptime, 1000)
        self.assertEqual(nf.unix_secs, 1600000000)
        self.assertEqual(nf.unix_nano_seconds, 999)
        self.assertEqual(nf.pkt2net({}), raw_hdr)

        raw_full = raw_hdr + b'remainder'
        nf_pl = NetflowSimple(raw_full)
        self.assertEqual(nf_pl.payload, b'remainder')
        self.assertEqual(nf_pl.pkt2net({}), raw_full)

    def test_netflow_replay_raw_carrier_family_conversion(self):
        nf = NetflowSimple(version=5, count=1, sys_uptime=1000,
                           unix_secs=1, unix_nano_seconds=2,
                           payload=b'flow-record')
        udp = UDP(sport=9999, dport=2055, payload=nf)
        inputs = [
            (IP(src='10.1.2.3', dst='10.3.2.1', proto=C.PROTO_UDP,
                payload=udp),
             '2001:db8::10', '2001:db8::20', IP6, 0x86dd),
            (IP6(src='2001:db8::1', dst='2001:db8::2',
                 next_header=C.PROTO_UDP, payload=udp),
             '192.0.2.10', '192.0.2.20', IP, 0x0800),
        ]
        for captured_ip, src_ip, dest_ip, ip_type, eth_type in inputs:
            captured = Ethernet(src_mac='00:11:22:33:44:55',
                                dst_mac='66:77:88:99:aa:bb',
                                payload=captured_ip)
            wire = _build_netflow_replay_frame(
                captured.pkt2net({'csum': 1, 'update': 1}), dest_ip,
                'de:ad:be:ef:00:01', 9995, src_ip,
                '02:00:00:00:00:01', 2055, 1700000000.25)
            replay = Ethernet(wire, l7_ports={9995: NetflowSimple})
            out_ip = replay.payload
            out_udp = out_ip.payload
            out_nf = out_udp.payload

            self.assertEqual(replay.type, eth_type)
            self.assertEqual(replay.src_mac, '02:00:00:00:00:01')
            self.assertEqual(replay.dst_mac, 'de:ad:be:ef:00:01')
            self.assertIsInstance(out_ip, ip_type)
            self.assertEqual(out_ip.src, src_ip)
            self.assertEqual(out_ip.dst, dest_ip)
            self.assertEqual(out_udp.sport, 9999)
            self.assertEqual(out_udp.dport, 9995)
            self.assertEqual(out_nf.version, 5)
            self.assertEqual(out_nf.unix_secs, 1700000000)
            self.assertEqual(out_nf.payload, b'flow-record')

            if ip_type is IP6:
                datagram = wire[14 + C.IPV6_HDR_LEN:
                                14 + C.IPV6_HDR_LEN + out_udp.ulen]
                pseudo = _v6_pheader(src_ip, dest_ip, len(datagram),
                                     C.PROTO_UDP)
                self.assertEqual(_cksum(pseudo + datagram), 0)
            else:
                ip_header = wire[14:34]
                datagram = wire[34:34 + out_udp.ulen]
                pseudo = (_socket.inet_pton(_socket.AF_INET, src_ip) +
                          _socket.inet_pton(_socket.AF_INET, dest_ip) +
                          _struct.pack('!BBH', 0, C.PROTO_UDP,
                                       len(datagram)))
                self.assertEqual(_cksum(ip_header), 0)
                self.assertEqual(_cksum(pseudo + datagram), 0)

    def test_netflow_replay_raw_carrier_retains_same_family_source(self):
        captured = Ethernet(
            src_mac='00:11:22:33:44:55',
            dst_mac='66:77:88:99:aa:bb',
            payload=IP(src='10.1.2.3', dst='10.3.2.1', proto=C.PROTO_UDP,
                       payload=UDP(
                           sport=9999, dport=2055,
                           payload=NetflowSimple(version=9))))
        wire = _build_netflow_replay_frame(
            captured.pkt2net({'csum': 1, 'update': 1}), '192.0.2.20',
            'de:ad:be:ef:00:01', 9995, '', '', 2055, 1700000000.0)
        replay = Ethernet(wire, l7_ports={9995: NetflowSimple})
        self.assertEqual(replay.src_mac, '00:11:22:33:44:55')
        self.assertEqual(replay.payload.src, '10.1.2.3')

    def test_netflow_replay_raw_carrier_requires_compatible_source(self):
        captured = Ethernet(
            src_mac='00:11:22:33:44:55',
            dst_mac='66:77:88:99:aa:bb',
            payload=IP(src='10.1.2.3', dst='10.3.2.1', proto=C.PROTO_UDP,
                       payload=UDP(
                           sport=9999, dport=2055,
                           payload=NetflowSimple(version=9))))
        wire = captured.pkt2net({'csum': 1, 'update': 1})
        with self.assertRaisesRegex(ValueError, 'src_ip'):
            _build_netflow_replay_frame(
                wire, '2001:db8::20', 'de:ad:be:ef:00:01', 9995,
                '', '', 2055, 1700000000.0)
        with self.assertRaisesRegex(ValueError, 'same address family'):
            _build_netflow_replay_frame(
                wire, '2001:db8::20', 'de:ad:be:ef:00:01', 9995,
                '192.0.2.10', '', 2055, 1700000000.0)

    def test_netflow_replay_system_socket_destination_family(self):
        import os
        import tempfile
        nf = NetflowSimple(version=9, count=1, sys_uptime=1000,
                           unix_secs=1, payload=b'flow-set')
        cases = [
            (IP(src='10.1.2.3', dst='10.3.2.1', proto=C.PROTO_UDP,
                payload=UDP(sport=9999, dport=2055, payload=nf)),
             '2001:db8::20', _socket.AF_INET6),
            (IP6(src='2001:db8::1', dst='2001:db8::2',
                 next_header=C.PROTO_UDP,
                 payload=UDP(sport=9999, dport=2055, payload=nf)),
             '192.0.2.20', _socket.AF_INET),
        ]
        for captured_ip, dest_ip, family in cases:
            captured = Ethernet(src_mac='00:11:22:33:44:55',
                                dst_mac='66:77:88:99:aa:bb',
                                payload=captured_ip)
            fd, pcap_path = tempfile.mkstemp(suffix='.pcap')
            os.close(fd)
            writer = PCAPWriter(filename=pcap_path, snaplen=65535)
            writer.dump_pkt(
                captured.pkt2net({'csum': 1, 'update': 1}), 1000, 0)
            writer.close()
            sender = mock.Mock()
            try:
                with mock.patch.object(_pcap.socket, 'socket',
                                       return_value=sender) as socket_ctor:
                    with mock.patch.object(_pcap.time, 'time',
                                           return_value=1700000000.0):
                        result = _pcap.netflow_replay_system_sock(
                            pcap_path, 2055, dest_ip, 9995, blast_mode=1)
                self.assertEqual(result, 0)
                socket_ctor.assert_called_once_with(family,
                                                    _socket.SOCK_DGRAM)
                datagram, destination = sender.sendto.call_args[0]
                self.assertEqual(destination, (dest_ip, 9995))
                replay_nf = NetflowSimple(datagram)
                self.assertEqual(replay_nf.version, 9)
                self.assertEqual(replay_nf.unix_secs, 1700000000)
                self.assertEqual(replay_nf.payload, b'flow-set')
            finally:
                os.remove(pcap_path)

    def test_NullPkt_buffer_types(self):
        """NullPkt from bytes vs array, and fake_proto_id."""
        data = b'\xaa\xbb\xcc\xdd'
        self.assertEqual(NullPkt(data).pkt2net({}), data)
        self.assertEqual(NullPkt(array('B', data)).pkt2net({}), data)

        self.assertEqual(NullPkt(data).fake_proto_id, 0xaabb)
        self.assertIsNone(NullPkt(b'\xff').fake_proto_id)

    def test_Ethernet_VLAN_tagging(self):
        """Ethernet 802.1q VLAN tagging round-trip."""
        # TCI: prio=1, cfi=0, vlan=4094 -> 0x2ffe
        tci = (1 << 13) | (0 << 12) | 4094
        inner = IP(src='10.0.0.1', dst='10.0.0.2', proto=17).pkt2net({})
        raw = b'\x01\x02\x03\x04\x05\x06' + b'\x0a\x0b\x0c\x0d\x0e\x0f' + \
              _struct.pack('!HHH', 0x8100, tci, 0x0800) + inner
        eth = Ethernet(raw)
        self.assertEqual(eth.tpid, 0x8100)
        self.assertEqual(eth.vlan_id, 4094)
        self.assertEqual(eth.priority_code, 1)
        self.assertEqual(eth.type, 0x0800)
        self.assertIsInstance(eth.payload, IP)
        self.assertEqual(eth.payload.src, '10.0.0.1')
        # Verify pkt2net reproduces with padding
        self.assertEqual(eth.pkt2net({}), raw + b'\x00' * (60 - len(raw)))

    def test_serialize_jumbo_frame_grows_buffer(self):
        """A frame larger than the writer's initial capacity must serialize.

        pkt2net appends into one reusable buffer that starts out big enough
        for a 1500 byte MTU. Anything larger takes the grow path, which
        reallocates while offsets into the buffer are still being held for
        the length and checksum patches.
        """
        payload = bytes((i & 0xff) for i in range(9000))
        pkt = Ethernet(dst_mac='03:02:03:04:05:06',
                       src_mac='06:05:04:03:02:03',
                       payload=IP(proto=IP_CONST().PROTO_UDP,
                                  src='10.1.2.3', dst='10.3.2.1',
                                  payload=UDP(sport=34567, dport=53,
                                              payload=NullPkt(payload))))
        raw = pkt.pkt2net({'csum': 1, 'update': 1})
        self.assertEqual(len(raw), 14 + 20 + 8 + 9000)

        back = Ethernet(raw)
        self.assertEqual(back.payload.total_len, 20 + 8 + 9000)
        self.assertEqual(back.payload.payload.ulen, 8 + 9000)
        self.assertEqual(back.payload.payload.payload.payload, payload)
        # The IP header checksum must still be right after the realloc.
        self.assertEqual(_cksum(raw[14:24] + b'\x00\x00' + raw[26:34]),
                         back.payload.checksum)
        # And the grown buffer must be reusable for a small frame afterwards.
        small = Ethernet(dst_mac='03:02:03:04:05:06',
                         src_mac='06:05:04:03:02:03',
                         payload=IP(proto=IP_CONST().PROTO_UDP,
                                    src='10.1.2.3', dst='10.3.2.1',
                                    payload=UDP(sport=1, dport=2)))
        self.assertEqual(len(small.pkt2net({'csum': 1, 'update': 1})), 60)

    def test_serialize_repeatable(self):
        """Serializing the same packet twice must give the same bytes.

        The output buffer is reused between calls, so a missed reset would
        show up here as the second call returning the first frame twice over.
        """
        pkt = Ethernet(dst_mac='03:02:03:04:05:06',
                       src_mac='06:05:04:03:02:03',
                       payload=IP(proto=IP_CONST().PROTO_UDP,
                                  src='10.1.2.3', dst='10.3.2.1',
                                  payload=UDP(sport=34567, dport=53,
                                              payload=NullPkt(b'abcdefgh'))))
        first = pkt.pkt2net({'csum': 1, 'update': 1})
        second = pkt.pkt2net({'csum': 1, 'update': 1})
        third = pkt.pkt2net({'csum': 1, 'update': 1})
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_serialize_reentrant(self):
        """A layer may serialize another packet while it is itself being
        serialized.

        The shared output buffer is handed out once; a nested pkt2net call
        has to get a buffer of its own instead of writing into the one the
        outer call is still using. A Python subclass is the way to provoke
        it: it reaches the writer through the pkt2net bridge.
        """
        inner = IP(proto=IP_CONST().PROTO_UDP, src='10.9.9.9', dst='10.8.8.8',
                   payload=UDP(sport=7, dport=9))
        inner_bytes = inner.pkt2net({'csum': 1, 'update': 1})

        class NestedPkt(PKT):
            """Emits another packet's bytes from inside pkt2net."""
            def pkt2net(self, kwargs):
                return inner.pkt2net({'csum': 1, 'update': 1})

        pkt = Ethernet(dst_mac='03:02:03:04:05:06',
                       src_mac='06:05:04:03:02:03',
                       payload=IP(proto=IP_CONST().PROTO_UDP,
                                  src='10.1.2.3', dst='10.3.2.1',
                                  payload=UDP(sport=34567, dport=53,
                                              payload=NestedPkt())))
        raw = pkt.pkt2net({'csum': 1, 'update': 1})
        self.assertEqual(raw[14 + 20 + 8:], inner_bytes)
        self.assertEqual(len(raw), 14 + 20 + 8 + len(inner_bytes))

    def test_query_info_matches_instances(self):
        """Hoisted pcap_query metadata must equal what query_info returns."""
        for cls, obj in ((ARP, ARP()), (UDP, UDP()), (TCP, TCP()),
                         (ICMP, ICMP()), (IGMP, IGMP()),
                         (IGMPGroupRecord, IGMPGroupRecord()),
                         (IP, IP()), (IP6, IP6()), (ICMP6, ICMP6()),
                         (ICMP6Opt, ICMP6Opt()),
                         (MLDv2AddressRecord, MLDv2AddressRecord()),
                         (MPLS, MPLS()), (Ethernet, Ethernet()),
                         (NullPkt, NullPkt())):
            pq_type, fields = cls.query_info()
            self.assertEqual(obj.pq_type, pq_type, cls.__name__)
            self.assertEqual(obj.query_fields, fields, cls.__name__)

    def test_pcap_query(self):
        w_fields = ['eth.src', 'eth.dst', 'ip.src', 'ip.dst',
                    'igmp.type', 'igmp.max_resp', 'igmp.maddr']
        pcap_query = PcapQuery(filename=igmp_file,
                               wshark_fields=w_fields)
        # Use PcapQuery object to do a manual query
        # Specifying that we want a dataframe back
        df1 = pcap_query.query(dataframe=True)
        json_out = df1.to_json()

        # Create it again against the same file with the same fields
        pcap_query = PcapQuery(filename=igmp_file,
                               wshark_fields=w_fields)

        # use a PcapQuery object in iterator context
        data = list(pcap_query)
        df2 = pandas.DataFrame(data, columns=w_fields)

        # both methods return the same data and it is as expected
        self.assertTrue(df1.equals(df2))
        self.assertEqual(json.loads(igmp_json), json.loads(json_out))

    # --- Phase 15: ICMPv6 beyond echo ------------------------------------
    # Every vector below is built with struct.pack from the RFC field layout
    # and checksummed independently by _icmp6_frame, so the frames are ground
    # truth rather than something this library produced. Each test asserts
    # the recovered fields and then that the whole frame survives pkt2net
    # byte for byte, with and without a checksum recompute.

    def _assert_v6_roundtrip(self, eth, frame):
        """The frame must survive re-serialization, checksum or not."""
        self.assertEqual(eth.pkt2net({}), frame)
        self.assertEqual(eth.pkt2net({'csum': 1, 'update': 1}), frame)

    def test_ICMP6_neighbor_solicitation(self):
        """RFC 4861 4.3: reserved, target address and option TLVs."""
        opt = _nd_opt(C.ICMP6_OPT_SRC_LLADDR, bytes.fromhex('001122334455'))
        body = (_struct.pack('!BBHI', C.ICMP6_ND_NEIGHBOR_SOLICIT, 0, 0, 0) +
                _v6('fe80::211:22ff:fe33:4455') + opt)
        frame = _icmp6_frame(body)

        nd = Ethernet(frame).payload.payload
        self.assertIsInstance(nd, ICMP6)
        self.assertEqual(nd.type, C.ICMP6_ND_NEIGHBOR_SOLICIT)
        self.assertEqual(nd.target_address, 'fe80::211:22ff:fe33:4455')
        self.assertEqual(len(nd.options), 1)
        self.assertIsInstance(nd.options[0], ICMP6Opt)
        self.assertEqual(nd.options[0].type, C.ICMP6_OPT_SRC_LLADDR)
        self.assertEqual(nd.options[0].length, 1)
        self.assertEqual(nd.options[0].byte_len, 8)
        self.assertEqual(nd.options[0].link_layer_address,
                         '00:11:22:33:44:55')
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_ICMP6_neighbor_advertisement_flags(self):
        """RFC 4861 4.4: the R, S and O flags live in the first reserved
        octet, which the old parser kept as opaque body bytes."""
        opt = _nd_opt(C.ICMP6_OPT_TGT_LLADDR, bytes.fromhex('aabbccddeeff'))
        body = (_struct.pack('!BBHBBBB', C.ICMP6_ND_NEIGHBOR_ADVERT, 0, 0,
                             0xe0, 0, 0, 0) +
                _v6('2001:db8::99') + opt)
        frame = _icmp6_frame(body)

        na = Ethernet(frame).payload.payload
        self.assertEqual(na.type, C.ICMP6_ND_NEIGHBOR_ADVERT)
        self.assertEqual(na.na_flags, 0xe0)
        self.assertEqual(na.na_flag_r, 1)
        self.assertEqual(na.na_flag_s, 1)
        self.assertEqual(na.na_flag_o, 1)
        self.assertEqual(na.target_address, '2001:db8::99')
        self.assertEqual(na.options[0].type, C.ICMP6_OPT_TGT_LLADDR)
        self.assertEqual(na.options[0].link_layer_address,
                         'aa:bb:cc:dd:ee:ff')
        self._assert_v6_roundtrip(Ethernet(frame), frame)

        # Individual flag bits must be settable without disturbing the rest.
        na.na_flag_s = 0
        self.assertEqual(na.na_flags, 0xa0)
        self.assertEqual(na.na_flag_r, 1)
        self.assertEqual(na.na_flag_o, 1)

    def test_ICMP6_router_advertisement_with_options(self):
        """RFC 4861 4.2 plus the MTU (5) and Prefix Information (3) options,
        which carry the fields a caller actually wants off an RA."""
        mtu_opt = _nd_opt(C.ICMP6_OPT_MTU,
                          b'\x00\x00' + _struct.pack('!I', 1500))
        prefix_opt = _nd_opt(C.ICMP6_OPT_PREFIX_INFO,
                             bytes([64, 0xc0]) +
                             _struct.pack('!III', 2592000, 604800, 0) +
                             _v6('2001:db8:1234::'))
        body = (_struct.pack('!BBHBBHII', C.ICMP6_ND_ROUTER_ADVERT, 0, 0,
                             64, 0xc0, 1800, 30000, 1000) +
                mtu_opt + prefix_opt)
        frame = _icmp6_frame(body)

        ra = Ethernet(frame).payload.payload
        self.assertEqual(ra.type, C.ICMP6_ND_ROUTER_ADVERT)
        self.assertEqual(ra.cur_hop_limit, 64)
        self.assertEqual(ra.ra_flag_m, 1)
        self.assertEqual(ra.ra_flag_o, 1)
        self.assertEqual(ra.router_lifetime, 1800)
        self.assertEqual(ra.reachable_time, 30000)
        self.assertEqual(ra.retrans_timer, 1000)
        self.assertEqual(len(ra.options), 2)
        self.assertEqual(ra.options[0].mtu, 1500)
        pfx = ra.options[1]
        self.assertEqual(pfx.type, C.ICMP6_OPT_PREFIX_INFO)
        self.assertEqual(pfx.length, 4)
        self.assertEqual(pfx.prefix_len, 64)
        self.assertEqual(pfx.prefix_on_link, 1)
        self.assertEqual(pfx.prefix_autonomous, 1)
        self.assertEqual(pfx.valid_lifetime, 2592000)
        self.assertEqual(pfx.preferred_lifetime, 604800)
        self.assertEqual(pfx.prefix, '2001:db8:1234::')
        # The MTU accessor must only answer for the option that has one.
        self.assertEqual(pfx.mtu, 0)
        self.assertEqual(ra.options[0].prefix, None)
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_ICMP6_router_solicitation(self):
        opt = _nd_opt(C.ICMP6_OPT_SRC_LLADDR, bytes.fromhex('001122334455'))
        body = _struct.pack('!BBHI', C.ICMP6_ND_ROUTER_SOLICIT, 0, 0, 0) + opt
        frame = _icmp6_frame(body)

        rs = Ethernet(frame).payload.payload
        self.assertEqual(rs.type, C.ICMP6_ND_ROUTER_SOLICIT)
        self.assertEqual(len(rs.options), 1)
        self.assertEqual(rs.options[0].link_layer_address,
                         '00:11:22:33:44:55')
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_ICMP6_redirect(self):
        """RFC 4861 4.5: a redirect carries both a target and a destination
        address; they are different fields and must not be confused."""
        opt = _nd_opt(C.ICMP6_OPT_TGT_LLADDR, bytes.fromhex('020202020202'))
        body = (_struct.pack('!BBHI', C.ICMP6_ND_REDIRECT, 0, 0, 0) +
                _v6('fe80::1') + _v6('2001:db8:aaaa::5') + opt)
        frame = _icmp6_frame(body)

        rd = Ethernet(frame).payload.payload
        self.assertEqual(rd.type, C.ICMP6_ND_REDIRECT)
        self.assertEqual(rd.target_address, 'fe80::1')
        self.assertEqual(rd.dest_address, '2001:db8:aaaa::5')
        self.assertEqual(rd.options[0].link_layer_address,
                         '02:02:02:02:02:02')
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_ICMP6_nd_option_walk_stops_on_malformed(self):
        """A zero length option is illegal (RFC 4861 4.6) and would make the
        walk loop forever. The remainder is kept verbatim instead, which is
        also what lets the frame round-trip."""
        good = _nd_opt(C.ICMP6_OPT_SRC_LLADDR, bytes.fromhex('001122334455'))
        junk = bytes([9, 0, 1, 2, 3, 4, 5, 6])
        body = (_struct.pack('!BBHI', C.ICMP6_ND_ROUTER_SOLICIT, 0, 0, 0) +
                good + junk)
        frame = _icmp6_frame(body)

        rs = Ethernet(frame).payload.payload
        self.assertEqual(len(rs.options), 1)
        self.assertEqual(rs.msg_body[-8:], junk)
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def _du_frame(self, msg_type, word, inner_payload_len=1200):
        """An ICMPv6 error quoting an IPv6/UDP packet.

        The quoted header deliberately claims a payload_len far larger than
        the bytes actually present, which is what a real quotation looks
        like once it has been cut to fit: it is a copy of what went out, not
        a packet being built, so update=1 must leave it exactly as it is.
        """
        inner = (_ip6_hdr(inner_payload_len, C.PROTO_UDP,
                          src='2001:db8::2', dst='2001:db8::1',
                          hop_limit=64) +
                 _struct.pack('!HHHH', 40000, 53, 12, 0x1234) + b'abcd')
        return _icmp6_frame(_struct.pack('!BBHI', msg_type, 4, 0, word) +
                            inner), inner

    def test_ICMP6_destination_unreachable_embeds_ip6(self):
        frame, inner = self._du_frame(C.ICMP6_DST_UNREACH, 0)
        err = Ethernet(frame).payload.payload
        self.assertEqual(err.type, C.ICMP6_DST_UNREACH)
        self.assertEqual(err.code, 4)
        self.assertIsInstance(err.hdr_pkt, IP6)
        self.assertEqual(err.hdr_pkt.src, '2001:db8::2')
        self.assertEqual(err.hdr_pkt.dst, '2001:db8::1')
        self.assertEqual(err.hdr_pkt.payload_len, 1200)
        self.assertIsInstance(err.hdr_pkt.payload, UDP)
        self.assertEqual(err.hdr_pkt.payload.sport, 40000)
        self.assertEqual(err.hdr_pkt.payload.dport, 53)
        self.assertEqual(err.hdr_pkt.payload.checksum, 0x1234)
        # update=1 must not re-length the quotation, and csum=1 must not
        # re-checksum its UDP header against this frame's pseudo header.
        self._assert_v6_roundtrip(Ethernet(frame), frame)
        self.assertEqual(Ethernet(frame).pkt2net(
            {'csum': 1, 'update': 1})[-len(inner):], inner)

    def test_ICMP6_packet_too_big_mtu(self):
        frame, _ = self._du_frame(C.ICMP6_PKT_TOO_BIG, 1280)
        err = Ethernet(frame).payload.payload
        self.assertEqual(err.type, C.ICMP6_PKT_TOO_BIG)
        self.assertEqual(err.mtu, 1280)
        self.assertEqual(err.get_field_val('icmpv6.mtu'), 1280)
        self.assertIsNone(err.get_field_val('icmpv6.pointer'))
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_ICMP6_parameter_problem_pointer(self):
        frame, _ = self._du_frame(C.ICMP6_PARAM_PROB, 40)
        err = Ethernet(frame).payload.payload
        self.assertEqual(err.type, C.ICMP6_PARAM_PROB)
        self.assertEqual(err.pointer, 40)
        self.assertEqual(err.get_field_val('icmpv6.pointer'), 40)
        self.assertIsNone(err.get_field_val('icmpv6.mtu'))
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_ICMP6_time_exceeded_truncated_quotation(self):
        """A quotation cut off inside the IPv6 header must not raise; it is
        kept verbatim so the error message still parses and round-trips."""
        stub = _ip6_hdr(1200, C.PROTO_UDP)[:20]
        body = _struct.pack('!BBHI', C.ICMP6_TIME_EXCEEDED, 0, 0, 0) + stub
        frame = _icmp6_frame(body)

        err = Ethernet(frame).payload.payload
        self.assertEqual(err.type, C.ICMP6_TIME_EXCEEDED)
        self.assertIsInstance(err.hdr_pkt, NullPkt)
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_MLDv1_query_and_report(self):
        """RFC 2710: maximum response delay, reserved, multicast address."""
        for mld_type, maddr in ((C.ICMP6_MLD_QUERY, '::'),
                                (C.ICMP6_MLD_REPORT, 'ff02::1:ff00:1'),
                                (C.ICMP6_MLD_DONE, 'ff02::1:ff00:1')):
            body = (_struct.pack('!BBHHH', mld_type, 0, 0, 10000, 0) +
                    _v6(maddr))
            frame = _icmp6_frame(body)

            mld = Ethernet(frame).payload.payload
            self.assertEqual(mld.type, mld_type)
            self.assertEqual(mld.mld_version, 1)
            self.assertEqual(mld.max_resp, 10000)
            self.assertEqual(mld.multicast_address, maddr)
            self.assertEqual(mld.num_src, 0)
            self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_MLDv2_query_source_list(self):
        """RFC 3810 5.1: a query longer than the MLDv1 24 bytes carries the
        v2 tail -- S/QRV, QQIC and a source list."""
        sources = ['2001:db8::10', '2001:db8::11']
        body = (_struct.pack('!BBHHH', C.ICMP6_MLD_QUERY, 0, 0, 10000, 0) +
                _v6('ff05::abcd') + bytes([0x0a, 125]) +
                _struct.pack('!H', len(sources)) +
                b''.join(_v6(s) for s in sources))
        frame = _icmp6_frame(body)

        q = Ethernet(frame).payload.payload
        self.assertEqual(q.type, C.ICMP6_MLD_QUERY)
        self.assertEqual(q.mld_version, 2)
        self.assertEqual(q.max_resp, 10000)
        self.assertEqual(q.multicast_address, 'ff05::abcd')
        self.assertEqual(q.s_flag, 1)
        self.assertEqual(q.qrv, 2)
        self.assertEqual(q.qqic, 125)
        self.assertEqual(q.num_src, 2)
        self.assertEqual(q.source_addresses, sources)
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_MLDv2_report_records(self):
        """RFC 3810 5.2: a list of Multicast Address Records, the IPv6
        counterpart of the IGMPv3 group records."""
        sources = ['2001:db8::10', '2001:db8::11']
        rec1 = (bytes([4, 0]) + _struct.pack('!H', 0) + _v6('ff05::1'))
        rec2 = (bytes([3, 0]) + _struct.pack('!H', len(sources)) +
                _v6('ff05::2') + b''.join(_v6(s) for s in sources))
        body = (_struct.pack('!BBHHH', C.ICMP6_MLDV2_REPORT, 0, 0, 0, 2) +
                rec1 + rec2)
        frame = _icmp6_frame(body)

        rep = Ethernet(frame).payload.payload
        self.assertEqual(rep.type, C.ICMP6_MLDV2_REPORT)
        self.assertEqual(rep.num_records, 2)
        self.assertEqual(len(rep.records), 2)
        self.assertIsInstance(rep.records[0], MLDv2AddressRecord)
        self.assertEqual(rep.records[0].type, 4)
        self.assertEqual(rep.records[0].num_src, 0)
        self.assertEqual(rep.records[0].multicast_address, 'ff05::1')
        self.assertEqual(rep.records[0].byte_len, 20)
        self.assertEqual(rep.records[1].type, 3)
        self.assertEqual(rep.records[1].num_src, 2)
        self.assertEqual(rep.records[1].multicast_address, 'ff05::2')
        self.assertEqual(rep.records[1].source_addresses, sources)
        self.assertEqual(rep.records[1].byte_len, 20 + 32)
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_ICMP6_unsupported_type_preserved(self):
        """A type with no field layout here is still kept verbatim."""
        body = _struct.pack('!BBH', 200, 3, 0) + b'\xde\xad\xbe\xef\x01\x02'
        frame = _icmp6_frame(body)

        pkt = Ethernet(frame).payload.payload
        self.assertEqual(pkt.type, 200)
        self.assertEqual(pkt.msg_body, b'\xde\xad\xbe\xef\x01\x02')
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_ICMP6_kwargs_build_matches_wire(self):
        """Building a neighbor solicitation from kwargs must produce exactly
        the bytes the parser accepts for one."""
        opt = _nd_opt(C.ICMP6_OPT_SRC_LLADDR, bytes.fromhex('001122334455'))
        body = (_struct.pack('!BBHI', C.ICMP6_ND_NEIGHBOR_SOLICIT, 0, 0, 0) +
                _v6('fe80::1') + opt)
        frame = _icmp6_frame(body)

        built = Ethernet(
            dst_mac='00:11:22:33:44:55', src_mac='00:aa:bb:cc:dd:ee',
            payload=IP6(src=V6_SRC, dst=V6_DST, hop_limit=255,
                        next_header=C.PROTO_ICMPV6,
                        payload=ICMP6(
                            type=C.ICMP6_ND_NEIGHBOR_SOLICIT,
                            target_address='fe80::1',
                            options=[ICMP6Opt(
                                type=C.ICMP6_OPT_SRC_LLADDR,
                                link_layer_address='00:11:22:33:44:55')])))
        self.assertEqual(built.pkt2net({'csum': 1, 'update': 1}), frame)

    # --- Phase 15: IPv6 dispatch behind VLAN and MPLS ---------------------

    def test_IP6_behind_vlan_tag(self):
        """0x86dd behind an 802.1Q tag must reach IP6, not NullPkt."""
        icmp6 = _struct.pack('!BBHHH', C.ICMP6_ECHO_REQUEST, 0, 0, 1, 2) + \
            b'ping6data'
        ck = _cksum(_v6_pheader(V6_SRC, V6_DST, len(icmp6), 58) + icmp6)
        icmp6 = icmp6[:2] + _struct.pack('!H', ck) + icmp6[4:]
        frame = (bytes.fromhex('00112233445500aabbccddee') +
                 _struct.pack('!HHH', C.ETH_TYPE_8021Q, 0x2064,
                              C.ETH_TYPE_IPV6) +
                 _ip6_hdr(len(icmp6), 58, hop_limit=64) + icmp6)

        eth = Ethernet(frame)
        self.assertEqual(eth.tpid, C.ETH_TYPE_8021Q)
        self.assertEqual(eth.vlan_id, 100)
        self.assertEqual(eth.priority_code, 1)
        self.assertEqual(eth.type, C.ETH_TYPE_IPV6)
        self.assertIsInstance(eth.payload, IP6)
        self.assertEqual(eth.payload.src, V6_SRC)
        self.assertIsInstance(eth.payload.payload, ICMP6)
        self.assertEqual(eth.payload.payload.echo_data, b'ping6data')
        self._assert_v6_roundtrip(Ethernet(frame), frame)

    def test_IP6_behind_mpls_label(self):
        """MPLS has no protocol id, so the payload is guessed from its first
        nibble. 6 used to fall through to Ethernet and mis-parse."""
        udp = _struct.pack('!HHHH', 4444, 5555, 8 + 6, 0) + b'mplsv6'
        ck = _cksum(_v6_pheader(V6_SRC, V6_DST, len(udp), C.PROTO_UDP) + udp)
        udp = udp[:6] + _struct.pack('!H', ck) + udp[8:]
        v6 = _ip6_hdr(len(udp), C.PROTO_UDP, hop_limit=64) + udp
        # label 1000, tc 0, bottom of stack, ttl 64
        label = _struct.pack('!I', (1000 << 12) | (0 << 9) | (1 << 8) | 64)
        frame = (bytes.fromhex('00112233445500aabbccddee') +
                 _struct.pack('!H', C.ETH_TYPE_MPLS_UCAST) + label + v6)

        eth = Ethernet(frame)
        self.assertIsInstance(eth.payload, MPLS)
        self.assertEqual(eth.payload.label, 1000)
        self.assertEqual(eth.payload.s, 1)
        self.assertIsInstance(eth.payload.payload, IP6)
        self.assertEqual(eth.payload.payload.src, V6_SRC)
        self.assertIsInstance(eth.payload.payload.payload, UDP)
        self.assertEqual(eth.payload.payload.payload.sport, 4444)
        self._assert_v6_roundtrip(Ethernet(frame), frame)

        # And the same guess on the kwargs construction path.
        built = MPLS(label=1000, s=1, ttl=64, payload=v6)
        self.assertIsInstance(built.payload, IP6)

    # --- Phase 15: query field coverage -----------------------------------

    def test_ipv6_query_field_names_resolve_whole(self):
        """Field names are registered and looked up whole.

        pcap_query used to key its name -> layer map on the first 18
        characters of every field name, which only worked as long as no two
        layers shared a prefix that long. The ipv6/icmpv6 names are the first
        ones long enough for that to matter.
        """
        q = PcapQuery(filename=igmp_file, wshark_fields=['eth.src'])
        fields = q.show_fields()
        for cls in (Ethernet, IP, IP6, ICMP, ICMP6, IGMP, TCP, UDP, ARP,
                    MPLS):
            ptype, names = cls.query_info()
            for name in names:
                self.assertIn(name, fields, name)
                self.assertEqual(fields[name], ptype, name)
        # Names longer than the old 18 character key really do exist now,
        # and the ND option names prove the collision is not hypothetical:
        # two of them share their first 18 characters exactly.
        opt_names = ICMP6Opt.query_info()[1]
        self.assertTrue([n for n in opt_names if len(n) > 18])
        self.assertGreater(len(opt_names), len({n[:18] for n in opt_names}))
        # The payload offset prefix match is the one case that still applies.
        self.assertTrue(q.fields_supported(['tcp.payload.offset[0:4]',
                                            'icmpv6.nd.rd.target_address',
                                            'icmpv6.nd.rd.destination_address',
                                            'icmpv6.mld.maximum_response_delay',
                                            'ipv6.src', 'ipv6.dst']))
        self.assertFalse(q.fields_supported(['icmpv6.nd.rd.not_a_field']))

    def test_payload_offset_field_query(self):
        """A payload offset field must survive PcapQuery construction.

        TCP and UDP register this field once, under the placeholder name
        'udp.payload.offset[x:y]'. A caller asks for a real slice,
        'udp.payload.offset[0:4]', so the two names have to be mapped onto
        each other. fields_supported() said yes and then __init__ raised
        KeyError: supported-but-unusable, and no test built a query with
        one of these fields, only checked that it was accepted.
        """
        import os
        import tempfile
        out = os.path.join(tempfile.gettempdir(), 'pkt_offset_query.pcap')
        if os.path.exists(out):
            os.remove(out)
        eth = Ethernet(src_mac='00:11:22:33:44:55',
                       dst_mac='66:77:88:99:aa:bb')
        eth.payload = IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                         payload=UDP(sport=4444, dport=5555,
                                     payload=NullPkt(b'\xde\xad\xbe\xef'
                                                     b'trailing')))
        w = PCAPWriter(filename=out, snaplen=65535)
        w.dump_pkt(eth.pkt2net({'csum': 1, 'update': 1}), 1000, 0)
        w.close()

        try:
            q = PcapQuery(filename=out,
                          wshark_fields=['ip.src', 'udp.dstport',
                                         'udp.payload.offset[0:4]'])
            # The placeholder is what the layer advertises and what
            # show_fields() must keep listing.
            self.assertIn('udp.payload.offset[x:y]', q.show_fields())
            rows = q.query()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], '10.1.2.3')
            self.assertEqual(rows[0][1], 5555)
            self.assertEqual(rows[0][2], b'\xde\xad\xbe\xef')

            # Two different slices of the same packet in one query: they
            # must not collide on the single registered key.
            q = PcapQuery(filename=out,
                          wshark_fields=['udp.payload.offset[0:2]',
                                         'udp.payload.offset[4:8]'])
            rows = q.query()
            self.assertEqual(rows[0], (b'\xde\xad', b'trai'))
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_pcap_query_dynamic_field_fallback(self):
        """Custom fields must remain queryable beside compiled common fields."""
        import os
        import tempfile
        out = os.path.join(tempfile.gettempdir(), 'pkt_dynamic_query.pcap')
        if os.path.exists(out):
            os.remove(out)
        eth = Ethernet(
            payload=IP(proto=C.PROTO_UDP, ident=0x1234,
                       payload=UDP(sport=4444, dport=5555,
                                   payload=NullPkt(b'payload'))))
        writer = PCAPWriter(filename=out, snaplen=65535)
        writer.dump_pkt(eth.pkt2net({'csum': 1, 'update': 1}), 1000, 0)
        writer.close()

        try:
            query = PcapQuery(filename=out,
                              wshark_fields=['eth.src', 'ip.id',
                                             'dynamic.value'],
                              pkt_classes=[_DynamicQueryProtocol])
            self.assertEqual(query.query(),
                             [('00:00:00:00:00:00', 0x1234, 'fallback')])
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_ipv6_query_fields_all_resolve(self):
        """Every field name IP6 and ICMP6 advertise must be answered by some
        instance of them -- an advertised name that always returns None is
        an unqueryable field, which is the bug B10 closed for IPv4 ICMP."""
        v6 = IP6(src=V6_SRC, dst=V6_DST, next_header=C.PROTO_ICMPV6,
                 traffic_class=8, flow_label=1234, hop_limit=64)
        for name in IP6.query_info()[1]:
            self.assertIsNotNone(v6.get_field_val(name), name)

        samples = [
            ICMP6(type=C.ICMP6_ECHO_REQUEST, identifier=1, sequence=2),
            ICMP6(type=C.ICMP6_PKT_TOO_BIG, mtu=1280),
            ICMP6(type=C.ICMP6_PARAM_PROB, pointer=40),
            ICMP6(type=C.ICMP6_ND_ROUTER_ADVERT, cur_hop_limit=64,
                  ra_flags=0xc0, router_lifetime=1800, reachable_time=1,
                  retrans_timer=1),
            ICMP6(type=C.ICMP6_ND_NEIGHBOR_SOLICIT,
                  target_address='fe80::1'),
            ICMP6(type=C.ICMP6_ND_NEIGHBOR_ADVERT, na_flags=0xe0,
                  target_address='fe80::1'),
            ICMP6(type=C.ICMP6_ND_REDIRECT, target_address='fe80::1',
                  dest_address='2001:db8::5'),
            ICMP6(type=C.ICMP6_MLD_QUERY, max_resp=10000, qqic=125, qrv=2,
                  s_flag=1, multicast_address='ff05::1',
                  source_addresses=['2001:db8::10']),
            ICMP6(type=C.ICMP6_MLDV2_REPORT,
                  records=[MLDv2AddressRecord(type=4,
                                              multicast_address='ff05::1')]),
        ]
        for name in ICMP6.query_info()[1]:
            self.assertTrue(
                any(s.get_field_val(name) is not None for s in samples),
                name)

        opt = ICMP6Opt(C.ICMP6_OPT_PREFIX_INFO.to_bytes(1, 'big') +
                       bytes([4, 64, 0xc0]) +
                       _struct.pack('!III', 2592000, 604800, 0) +
                       _v6('2001:db8::'))
        mtu_opt = ICMP6Opt(type=C.ICMP6_OPT_MTU, mtu=1500)
        for name in ICMP6Opt.query_info()[1]:
            self.assertTrue(
                any(o.get_field_val(name) is not None
                    for o in (opt, mtu_opt)), name)

        rec = MLDv2AddressRecord(type=4, multicast_address='ff05::1',
                                 source_addresses=['2001:db8::10'],
                                 aux_data=b'\x01\x02\x03\x04',
                                 aux_data_len=1)
        for name in MLDv2AddressRecord.query_info()[1]:
            self.assertIsNotNone(rec.get_field_val(name), name)


if __name__ == '__main__':
    unittest.main()
