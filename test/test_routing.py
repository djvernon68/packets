#!/usr/bin/env python

"""Tests for the routing-protocol codecs added to packets.core.inetpkt.

Stage 1 covers GRE (RFC 2784/2890/2637/7637) including NVGRE and Transparent
Ethernet Bridging inner dispatch, plus the library-wide never-raise contract
that every later routing protocol inherits. Later stages extend this file.
"""

import gc
import struct
import unittest
from array import array

from packets.core.inetpkt import IP_CONST, GRE, IP, IP6, ICMP, ICMP6, \
    MPLS, Ethernet, NullPkt

C = IP_CONST()

# EtherTypes GRE dispatches its inner payload by.
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86dd
ETH_MPLS_UCAST = 0x8847
ETH_TEB = 0x6558


def _icmp_echo(data=b'gre-payload-owner'):
    return ICMP(type=C.ICMP_TYPE_ECHO, identifier=1, sequence=2,
                echo_data=data)


def _inner_ip():
    return IP(proto=C.PROTO_ICMP, src='10.1.2.3', dst='10.3.2.1',
              payload=_icmp_echo())


def _inner_ip6():
    return IP6(next_header=C.PROTO_ICMPV6, src='2001:db8::1', dst='2001:db8::2',
               payload=ICMP6(type=C.ICMP6_ECHO_REQUEST, identifier=1,
                             sequence=2, echo_data=b'gre6-owner'))


class GREConstructionTestCase(unittest.TestCase):

    def test_plain_gre_keyword_construction_and_roundtrip(self):
        gre = GRE(payload=_inner_ip())
        wire = gre.pkt2net({'csum': 1, 'update': 1})
        parsed = GRE(wire)
        self.assertEqual(parsed.version, 0)
        self.assertEqual(parsed.proto, ETH_IPV4)
        self.assertEqual(parsed.flag_c, 0)
        self.assertEqual(parsed.flag_k, 0)
        self.assertEqual(parsed.flag_s, 0)
        self.assertIsInstance(parsed.payload, IP)
        self.assertIsInstance(parsed.payload.payload, ICMP)
        self.assertFalse(parsed.malformed)
        # Round-trip invariant: parse(serialize(parse(raw))) == parse(raw).
        self.assertEqual(parsed.pkt2net({}), wire)
        self.assertEqual(GRE(parsed.pkt2net({})).pkt2net({}), wire)

    def test_gre_with_checksum_key_sequence(self):
        gre = GRE(checksum=0, key=0x0a0b0c0d, sequence_number=0x11223344,
                  payload=_inner_ip())
        self.assertEqual(gre.flag_c, 1)
        self.assertEqual(gre.flag_k, 1)
        self.assertEqual(gre.flag_s, 1)
        wire = gre.pkt2net({'csum': 1, 'update': 1})
        parsed = GRE(wire)
        self.assertEqual(parsed.key, 0x0a0b0c0d)
        self.assertEqual(parsed.sequence, 0x11223344)
        # The checksum field was recomputed on the csum serialize and must be
        # preserved byte-for-byte when re-serialized without recompute.
        self.assertEqual(parsed.pkt2net({}), wire)
        self.assertEqual(parsed.get_field_val('gre.key'), 0x0a0b0c0d)
        self.assertEqual(parsed.get_field_val('gre.sequence_number'),
                         0x11223344)
        self.assertIsNotNone(parsed.get_field_val('gre.checksum'))

    def test_enhanced_gre_ack(self):
        gre = GRE(version=1, key=0x00010002, sequence_number=7,
                  ack_number=0xdeadbeef, payload=NullPkt(b''))
        self.assertEqual(gre.version, 1)
        self.assertEqual(gre.flag_a, 1)
        wire = gre.pkt2net({})
        parsed = GRE(wire)
        self.assertEqual(parsed.version, 1)
        self.assertEqual(parsed.ack, 0xdeadbeef)
        self.assertEqual(parsed.sequence, 7)
        self.assertEqual(parsed.get_field_val('gre.ack_number'), 0xdeadbeef)
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_checksum_recompute_is_gated(self):
        gre = GRE(checksum=0, payload=_inner_ip())
        no_update = gre.pkt2net({})
        # Without csum the placeholder checksum (0) is emitted verbatim.
        self.assertEqual(no_update[4:6], b'\x00\x00')
        updated = gre.pkt2net({'csum': 1})
        self.assertNotEqual(updated[4:6], b'\x00\x00')
        # A parsed packet with a real checksum round-trips unchanged.
        parsed = GRE(updated)
        self.assertEqual(parsed.pkt2net({}), updated)


class GREDispatchTestCase(unittest.TestCase):

    def _roundtrip(self, outer):
        wire = outer.pkt2net({'csum': 1, 'update': 1})
        parsed = type(outer)(array('B', wire))
        self.assertEqual(parsed.pkt2net({}), wire)
        return parsed

    def test_gre_over_ipv4(self):
        outer = IP(proto=C.PROTO_GRE, src='192.0.2.1', dst='192.0.2.2',
                   payload=GRE(payload=_inner_ip()))
        parsed = self._roundtrip(outer)
        gre = parsed.payload
        self.assertIsInstance(gre, GRE)
        self.assertIsInstance(gre.payload, IP)
        self.assertIsInstance(gre.payload.payload, ICMP)

    def test_gre_over_ipv6(self):
        outer = IP6(next_header=C.PROTO_GRE, src='2001:db8::1',
                    dst='2001:db8::2', payload=GRE(payload=_inner_ip()))
        parsed = self._roundtrip(outer)
        gre = parsed.payload
        self.assertIsInstance(gre, GRE)
        self.assertIsInstance(gre.payload, IP)

    def test_gre_inner_ip6(self):
        gre = GRE(payload=_inner_ip6())
        self.assertEqual(gre.proto, ETH_IPV6)
        wire = gre.pkt2net({'csum': 1, 'update': 1})
        parsed = GRE(wire)
        self.assertIsInstance(parsed.payload, IP6)
        self.assertIsInstance(parsed.payload.payload, ICMP6)
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_gre_inner_mpls(self):
        gre = GRE(payload=MPLS(label=100, s=1, payload=_inner_ip()))
        self.assertEqual(gre.proto, ETH_MPLS_UCAST)
        wire = gre.pkt2net({'csum': 1, 'update': 1})
        parsed = GRE(wire)
        self.assertIsInstance(parsed.payload, MPLS)
        self.assertIsInstance(parsed.payload.payload, IP)
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_gre_teb_inner_ethernet(self):
        inner = Ethernet(dst_mac='02:00:00:00:00:01',
                         src_mac='02:00:00:00:00:02',
                         payload=IP(proto=C.PROTO_ICMP, src='10.9.9.9',
                                    dst='10.8.8.8',
                                    payload=_icmp_echo(b'A' * 40)))
        gre = GRE(payload=inner)
        self.assertEqual(gre.proto, ETH_TEB)
        wire = gre.pkt2net({'csum': 1, 'update': 1})
        parsed = GRE(wire, l7_ports={})
        self.assertIsInstance(parsed.payload, Ethernet)
        self.assertIsInstance(parsed.payload.payload, IP)
        self.assertIsInstance(parsed.payload.payload.payload, ICMP)
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_nvgre_vsid_flowid(self):
        inner = Ethernet(dst_mac='02:00:00:00:00:01',
                         src_mac='02:00:00:00:00:02',
                         payload=IP(proto=C.PROTO_ICMP, src='10.9.9.9',
                                    dst='10.8.8.8',
                                    payload=_icmp_echo(b'B' * 40)))
        gre = GRE(vsid=0x123456, flowid=0x78, payload=inner)
        self.assertEqual(gre.flag_k, 1)
        self.assertEqual(gre.key, 0x12345678)
        self.assertEqual(gre.proto, ETH_TEB)
        wire = gre.pkt2net({'csum': 1, 'update': 1})
        parsed = GRE(wire)
        self.assertEqual(parsed.key, 0x12345678)
        self.assertEqual(parsed.vsid, 0x123456)
        self.assertEqual(parsed.flowid, 0x78)
        self.assertEqual(parsed.get_field_val('gre.key.vsid'), 0x123456)
        self.assertEqual(parsed.get_field_val('gre.key.flowid'), 0x78)
        self.assertIsInstance(parsed.payload, Ethernet)
        self.assertEqual(parsed.pkt2net({}), wire)


class GREQueryTestCase(unittest.TestCase):

    def test_every_advertised_query_field_resolves(self):
        # A GRE carrying every optional field so each advertised query field
        # has a value to return.
        gre = GRE(version=1, checksum=0, key=0x12345678,
                  sequence_number=9, ack_number=10, payload=_inner_ip())
        for field in GRE.query_info()[1]:
            self.assertIsNotNone(gre.get_field_val(field), field)

    def test_optional_fields_report_none_when_absent(self):
        gre = GRE(payload=_inner_ip())
        self.assertIsNone(gre.get_field_val('gre.checksum'))
        self.assertIsNone(gre.get_field_val('gre.key'))
        self.assertIsNone(gre.get_field_val('gre.key.vsid'))
        self.assertIsNone(gre.get_field_val('gre.sequence_number'))
        self.assertIsNone(gre.get_field_val('gre.ack_number'))
        self.assertEqual(gre.get_field_val('gre.flags.c'), 0)


class GREMalformedTestCase(unittest.TestCase):

    def _full_wire(self):
        gre = GRE(checksum=0, key=0x0a0b0c0d, sequence_number=0x11223344,
                  payload=_inner_ip())
        # base(4) + checksum/reserved1(4) + key(4) + sequence(4) = 16 header.
        return gre.pkt2net({'csum': 1, 'update': 1})

    def test_truncation_at_each_boundary_never_raises(self):
        wire = self._full_wire()
        # 1..3 mid base header; 4/6 mid checksum; 10 mid key; 14 mid sequence;
        # 18 mid inner IP header (inner decoder would raise -- must be caught).
        for n in (1, 2, 3, 4, 6, 10, 14, 18):
            truncated = wire[:n]
            parsed = GRE(truncated)
            self.assertTrue(parsed.malformed,
                            'expected malformed at %d bytes' % n)
            # The remainder is preserved: a malformed GRE re-serializes to
            # exactly the bytes it was handed.
            self.assertEqual(parsed.pkt2net({}), truncated,
                             'round-trip failed at %d bytes' % n)

    def test_unknown_inner_ethertype_preserved_as_nullpkt(self):
        gre = GRE(proto=0x9999, payload=b'\x01\x02\x03\x04')
        wire = gre.pkt2net({})
        parsed = GRE(wire)
        self.assertFalse(parsed.malformed)
        self.assertEqual(parsed.proto, 0x9999)
        self.assertIsInstance(parsed.payload, NullPkt)
        self.assertEqual(parsed.payload.payload, b'\x01\x02\x03\x04')
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_reserved_flag_bits_preserved(self):
        # A reserved bit (0x4000, the old routing bit) set with no matching
        # option, and an unknown protocol type, must round-trip untouched
        # rather than being treated as an error.
        raw = struct.pack('!HH', 0x4000, 0x9999) + b'\xaa\xbb\xcc\xdd'
        parsed = GRE(raw)
        self.assertFalse(parsed.malformed)
        self.assertIsInstance(parsed.payload, NullPkt)
        # The flag word is preserved: the re-serialized first two bytes still
        # carry the reserved bit.
        self.assertEqual(parsed.pkt2net({})[0:2], b'\x40\x00')
        self.assertEqual(parsed.pkt2net({}), raw)

    def test_gre_in_udp_style_payload_does_not_raise(self):
        # Out of scope per Answers 6/7, but must parse without raising.
        parsed = GRE(b'\x00\x00\x88\x99' + b'\xde\xad\xbe\xef')
        self.assertIsInstance(parsed, GRE)
        self.assertEqual(parsed.pkt2net({}), b'\x00\x00\x88\x99'
                         b'\xde\xad\xbe\xef')

    def test_mutable_source_isolation(self):
        wire = GRE(key=0x01020304, payload=_inner_ip()).pkt2net(
            {'csum': 1, 'update': 1})
        mutable = array('B', wire)
        parsed = GRE(mutable)
        mutable[0] = 0xff
        mutable[7] = 0xff
        self.assertEqual(parsed.key, 0x01020304)
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_detached_child_outlives_parent(self):
        outer = IP(proto=C.PROTO_GRE, src='192.0.2.1', dst='192.0.2.2',
                   payload=GRE(key=0x55667788, payload=_inner_ip()))
        wire = outer.pkt2net({'csum': 1, 'update': 1})
        parsed = IP(array('B', wire))
        gre = parsed.payload
        self.assertIsInstance(gre, GRE)
        del parsed
        gc.collect()
        self.assertEqual(gre.key, 0x55667788)
        self.assertIsInstance(gre.payload, IP)


if __name__ == '__main__':
    unittest.main()
