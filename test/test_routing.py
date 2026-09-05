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
    MPLS, Ethernet, NullPkt, OSPFv2, OSPFv3, OSPFLSA, TCP, UDP, BGP, \
    BGPParam, RIP, RIPng, HSRP, RtParam

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


# ---------------------------------------------------------------------------
# OSPF (Stage 2): OSPFv2 (RFC 2328) over IPv4 proto 89, OSPFv3 (RFC 5340) over
# IPv6 next-header 89. Fixtures are built by hand from the RFC wire layout so
# the tests do not depend on the encoder to prove the decoder.
# ---------------------------------------------------------------------------

OSPF_PROTO = 89


def _ip4(addr):
    return struct.pack('!BBBB', *(int(x) for x in addr.split('.')))


def _ospf2_common(msg_type, body, srcrouter='1.1.1.1', area='0.0.0.0',
                  auth_type=0, auth=b'\x00' * 8, checksum=0):
    length = 24 + len(body)
    return (bytes([2, msg_type]) + struct.pack('!H', length) +
            _ip4(srcrouter) + _ip4(area) + struct.pack('!H', checksum) +
            struct.pack('!H', auth_type) + auth + body)


def _ospf2_hello(neighbor='2.2.2.2', **kw):
    body = (_ip4('255.255.255.0') + struct.pack('!H', 10) + bytes([0x02, 1]) +
            struct.pack('!I', 40) + _ip4('1.1.1.1') + _ip4('0.0.0.0') +
            _ip4(neighbor))
    return _ospf2_common(1, body, **kw)


def _lsa2(age, opt, ls_type, ls_id, adv, seq, body):
    length = 20 + len(body)
    return (struct.pack('!HBB', age, opt, ls_type) + _ip4(ls_id) + _ip4(adv) +
            struct.pack('!I', seq) + struct.pack('!H', 0) +
            struct.pack('!H', length) + body)


def _router_lsa():
    lbody = (bytes([0x00, 0x00]) + struct.pack('!H', 1) + _ip4('10.0.0.1') +
             _ip4('255.255.255.255') + bytes([1, 0]) + struct.pack('!H', 5))
    return _lsa2(1, 0x02, 1, '1.1.1.1', '1.1.1.1', 0x80000001, lbody)


def _asext_lsa():
    ebody = (_ip4('255.255.255.0') + bytes([0x80, 0x00, 0x00, 0x14]) +
             _ip4('9.9.9.9') + struct.pack('!I', 100))
    return _lsa2(2, 0x02, 5, '20.0.0.0', '2.2.2.2', 0x80000002, ebody)


def _ospf2_lsupdate(*lsas):
    body = struct.pack('!I', len(lsas)) + b''.join(lsas)
    return _ospf2_common(4, body)


class OSPFv2ConstructionTestCase(unittest.TestCase):

    def test_hello_parse_query_and_roundtrip(self):
        raw = _ospf2_hello()
        o = OSPFv2(raw)
        self.assertFalse(o.malformed)
        self.assertEqual(o.version, 2)
        self.assertEqual(o.get_field_val('ospf.msg'), 'Hello Packet')
        self.assertEqual(o.get_field_val('ospf.srcrouter'), '1.1.1.1')
        self.assertEqual(o.get_field_val('ospf.area_id'), '0.0.0.0')
        self.assertEqual(o.get_field_val('ospf.auth.type'), 'Null')
        self.assertEqual(o.get_field_val('ospf.hello.network_mask'),
                         '255.255.255.0')
        self.assertEqual(o.get_field_val('ospf.hello.hello_interval'), 10)
        self.assertEqual(o.get_field_val('ospf.hello.router_dead_interval'),
                         40)
        self.assertEqual(o.get_field_val('ospf.hello.designated_router'),
                         '1.1.1.1')
        self.assertEqual(o.get_field_val('ospf.hello.active_neighbor'),
                         '2.2.2.2')
        self.assertEqual(o.pkt2net({}), raw)
        self.assertEqual(OSPFv2(o.pkt2net({})).pkt2net({}), raw)

    def test_hello_keyword_construction(self):
        body = (_ip4('255.255.255.0') + struct.pack('!H', 10) +
                bytes([0x02, 1]) + struct.pack('!I', 40) + _ip4('1.1.1.1') +
                _ip4('0.0.0.0'))
        o = OSPFv2(version=2, type=1, srcrouter='5.6.7.8', area_id='0.0.0.1',
                   body=body)
        wire = o.pkt2net({'update': 1})
        parsed = OSPFv2(wire)
        self.assertEqual(parsed.get_field_val('ospf.srcrouter'), '5.6.7.8')
        self.assertEqual(parsed.get_field_val('ospf.area_id'), '0.0.0.1')
        self.assertEqual(parsed.type, 1)
        self.assertEqual(parsed.length, 24 + len(body))

    def test_all_five_packet_types_parse(self):
        for msg in (1, 2, 3, 4, 5):
            if msg == 1:
                raw = _ospf2_hello()
            elif msg == 4:
                raw = _ospf2_lsupdate(_router_lsa())
            else:
                # DBD / LSR / LSAck: a header plus a single 20-byte-ish body.
                raw = _ospf2_common(msg, b'\x00' * 20)
            o = OSPFv2(raw)
            self.assertFalse(o.malformed)
            self.assertEqual(o.version, 2)
            self.assertEqual(o.pkt2net({}), raw)


class OSPFv2LSATestCase(unittest.TestCase):

    def test_lsupdate_decodes_lsas(self):
        raw = _ospf2_lsupdate(_router_lsa(), _asext_lsa())
        o = OSPFv2(raw)
        self.assertEqual(o.type, 4)
        self.assertEqual(o.body.get('ospf.lsa.number_of_lsas'), 2)
        self.assertEqual(len(o.lsas), 2)
        self.assertEqual(o.lsas[0].get_field_val('ospf.lsa.type'),
                         'Router-LSA')
        self.assertEqual(o.lsas[0].get_field_val('ospf.lsa.id'), '1.1.1.1')
        self.assertEqual(o.get_field_val('ospf.lsa.router.linktype'), 1)
        self.assertEqual(o.get_field_val('ospf.lsa.router.metric0'), 5)
        self.assertEqual(o.lsas[1].get_field_val('ospf.lsa.type'),
                         'AS-External-LSA (ASBR)')
        self.assertEqual(o.get_field_val('ospf.lsa.asext.fwdaddr'), '9.9.9.9')
        self.assertEqual(o.get_field_val('ospf.lsa.asext.extrttag'), 100)
        self.assertEqual(o.get_field_val('ospf.lsa.asext.type'), 2)
        self.assertEqual(o.pkt2net({}), raw)

    def test_unknown_lsa_type_preserved(self):
        # LSA type 200 is not decoded, but its bytes must round-trip.
        body = b'\xde\xad\xbe\xef' * 3
        lsa = _lsa2(5, 0x02, 200, '7.7.7.7', '8.8.8.8', 0x80000009, body)
        raw = _ospf2_lsupdate(lsa)
        o = OSPFv2(raw)
        self.assertEqual(len(o.lsas), 1)
        self.assertEqual(o.lsas[0].get_field_val('ospf.lsa.type'),
                         'Unknown (200)')
        self.assertEqual(o.pkt2net({}), raw)

    def test_lsack_headers(self):
        raw = _ospf2_common(5, _router_lsa()[:20] + _asext_lsa()[:20])
        o = OSPFv2(raw)
        self.assertEqual(len(o.lsas), 2)
        self.assertEqual(o.pkt2net({}), raw)


class OSPFv2AuthTestCase(unittest.TestCase):

    def test_simple_password_auth(self):
        raw = _ospf2_hello(auth_type=1, auth=b'secret00')
        o = OSPFv2(raw)
        self.assertEqual(o.get_field_val('ospf.auth.type'), 'Simple password')
        self.assertEqual(o.auth_data, b'secret00')
        self.assertEqual(o.pkt2net({}), raw)

    def test_crypto_auth_and_trailing_digest(self):
        auth = struct.pack('!H', 0) + bytes([5, 16]) + struct.pack('!I',
                                                                    0x11223344)
        digest = bytes(range(16))
        raw = _ospf2_hello(auth_type=2, auth=auth) + digest
        o = OSPFv2(raw)
        self.assertEqual(o.get_field_val('ospf.auth.type'), 'Cryptographic')
        self.assertEqual(o.get_field_val('ospf.auth.crypt.key_id'), 5)
        self.assertEqual(o.get_field_val('ospf.auth.crypt.data_length'), 16)
        self.assertEqual(o.get_field_val('ospf.auth.crypt.seq_nbr'),
                         0x11223344)
        # The appended digest is preserved as trailing payload.
        self.assertEqual(o.payload.pkt2net({}), digest)
        # Digest emitted verbatim by default (round-trip).
        self.assertEqual(o.pkt2net({}), raw)

    def test_crypto_fields_none_for_plaintext(self):
        o = OSPFv2(_ospf2_hello())
        self.assertIsNone(o.get_field_val('ospf.auth.crypt.key_id'))
        self.assertIsNone(o.get_field_val('ospf.auth.crypt.seq_nbr'))


class OSPFv2SerializeTestCase(unittest.TestCase):

    def test_update_recomputes_length_and_checksum(self):
        # A hello with a deliberately wrong checksum; update must recompute it.
        raw = _ospf2_hello(checksum=0xdead)
        o = OSPFv2(raw)
        updated = o.pkt2net({'update': 1})
        reparsed = OSPFv2(updated)
        self.assertNotEqual(reparsed.checksum, 0xdead)
        self.assertEqual(reparsed.length, o.length)
        # Idempotent: updating an already-updated packet is stable.
        again = OSPFv2(reparsed.pkt2net({'update': 1}))
        self.assertEqual(again.checksum, reparsed.checksum)

    def test_parsed_packet_roundtrips_verbatim(self):
        raw = _ospf2_lsupdate(_router_lsa(), _asext_lsa())
        self.assertEqual(OSPFv2(raw).pkt2net({}), raw)


class OSPFv2DispatchTestCase(unittest.TestCase):

    def test_ospf_over_ipv4(self):
        outer = IP(proto=OSPF_PROTO, src='10.0.0.1', dst='224.0.0.5',
                   payload=OSPFv2(_ospf2_hello()))
        wire = outer.pkt2net({'csum': 1, 'update': 1})
        parsed = IP(array('B', wire))
        self.assertIsInstance(parsed.payload, OSPFv2)
        self.assertEqual(parsed.payload.get_field_val('ospf.msg'),
                         'Hello Packet')

    def test_ethernet_ip_ospf_nested(self):
        raw = _ospf2_hello()
        frame = Ethernet(dst_mac='01:00:5e:00:00:05',
                         src_mac='02:00:00:00:00:01',
                         payload=IP(proto=OSPF_PROTO, src='10.0.0.1',
                                    dst='224.0.0.5', payload=OSPFv2(raw)))
        wire = frame.pkt2net({'update': 1})
        parsed = Ethernet(array('B', wire))
        self.assertIsInstance(parsed.payload, IP)
        self.assertIsInstance(parsed.payload.payload, OSPFv2)
        inner = parsed.payload.payload
        self.assertEqual(inner.get_field_val('ospf.msg'), 'Hello Packet')
        self.assertEqual(inner.get_field_val('ospf.srcrouter'), '1.1.1.1')
        # The frame was serialized with update, which propagates and recomputes
        # the OSPF checksum, so compare to the recovered bytes (not the stale
        # zero-checksum raw): the reparsed OSPF must round-trip verbatim.
        recovered = inner.pkt2net({})
        self.assertEqual(OSPFv2(recovered).pkt2net({}), recovered)


class OSPFv2MalformedTestCase(unittest.TestCase):

    def test_truncation_never_raises(self):
        wire = _ospf2_lsupdate(_router_lsa())
        # mid common header (< 24), mid lsa count, mid lsa header, mid body.
        for n in (1, 8, 23, 25, 30, 40, len(wire) - 1):
            parsed = OSPFv2(wire[:n])
            self.assertIsInstance(parsed, OSPFv2)
            self.assertEqual(parsed.pkt2net({}), wire[:n],
                             'round-trip failed at %d bytes' % n)

    def test_short_common_header_is_malformed(self):
        parsed = OSPFv2(b'\x02\x01\x00\x10')
        self.assertTrue(parsed.malformed)
        self.assertEqual(parsed.pkt2net({}), b'\x02\x01\x00\x10')

    def test_mutable_source_isolation(self):
        wire = _ospf2_hello()
        mutable = array('B', wire)
        parsed = OSPFv2(mutable)
        mutable[4] = 0xff
        mutable[5] = 0xff
        self.assertEqual(parsed.get_field_val('ospf.srcrouter'), '1.1.1.1')
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_detached_child_outlives_parent(self):
        outer = IP(proto=OSPF_PROTO, src='10.0.0.1', dst='224.0.0.5',
                   payload=OSPFv2(_ospf2_hello()))
        wire = outer.pkt2net({'update': 1})
        parsed = IP(array('B', wire))
        ospf = parsed.payload
        self.assertIsInstance(ospf, OSPFv2)
        del parsed
        gc.collect()
        self.assertEqual(ospf.get_field_val('ospf.srcrouter'), '1.1.1.1')


class OSPFv2QueryTestCase(unittest.TestCase):

    def test_hello_fields_resolve_lsa_fields_none(self):
        o = OSPFv2(_ospf2_hello())
        # Common + hello fields resolve.
        for f in ('ospf.version', 'ospf.msg', 'ospf.packet_length',
                  'ospf.srcrouter', 'ospf.area_id', 'ospf.checksum',
                  'ospf.auth.type', 'ospf.hello.network_mask',
                  'ospf.hello.hello_interval', 'ospf.hello.designated_router',
                  'ospf.hello.active_neighbor'):
            self.assertIsNotNone(o.get_field_val(f), f)
        # LSA-scoped fields do not apply to a hello.
        self.assertIsNone(o.get_field_val('ospf.lsa.router.metric0'))
        self.assertIsNone(o.get_field_val('ospf.lsa.asext.fwdaddr'))

    def test_lsupdate_lsa_fields_resolve(self):
        o = OSPFv2(_ospf2_lsupdate(_router_lsa(), _asext_lsa()))
        for f in ('ospf.lsa.age', 'ospf.lsa.type', 'ospf.lsa.id',
                  'ospf.advrouter', 'ospf.lsa.seqnum', 'ospf.lsa.chksum',
                  'ospf.lsa.length'):
            self.assertIsNotNone(o.get_field_val(f), f)


# --- OSPFv3 (RFC 5340) ------------------------------------------------------

def _ospf3_common(msg_type, body, srcrouter='1.1.1.1', area='0.0.0.0',
                  instance=0, checksum=0):
    length = 16 + len(body)
    return (bytes([3, msg_type]) + struct.pack('!H', length) +
            _ip4(srcrouter) + _ip4(area) + struct.pack('!H', checksum) +
            bytes([instance, 0]) + body)


def _ospf3_hello(neighbor='2.2.2.2', **kw):
    body = (struct.pack('!I', 5) + bytes([1]) + bytes([0x00, 0x00, 0x13]) +
            struct.pack('!H', 10) + struct.pack('!H', 40) + _ip4('1.1.1.1') +
            _ip4('0.0.0.0') + _ip4(neighbor))
    return _ospf3_common(1, body, **kw)


def _lsa3(age, ls_type, ls_id, adv, seq, body):
    length = 20 + len(body)
    return (struct.pack('!HH', age, ls_type) + _ip4(ls_id) + _ip4(adv) +
            struct.pack('!I', seq) + struct.pack('!H', 0) +
            struct.pack('!H', length) + body)


def _v3_router_lsa():
    body = (bytes([0x01]) + bytes([0x00, 0x00, 0x13]) + bytes([2, 0]) +
            struct.pack('!H', 10) + struct.pack('!I', 7) +
            struct.pack('!I', 8) + _ip4('3.3.3.3'))
    return _lsa3(1, 0x2001, '0.0.0.0', '1.1.1.1', 0x80000001, body)


def _ospf3_lsupdate(*lsas):
    body = struct.pack('!I', len(lsas)) + b''.join(lsas)
    return _ospf3_common(4, body)


def _at_trailer():
    return (struct.pack('!HH', 1, 20) + struct.pack('!HH', 0, 7) +
            struct.pack('!I', 0) + struct.pack('!I', 0x99) + bytes(range(20)))


class OSPFv3TestCase(unittest.TestCase):

    def test_hello_parse_query_and_roundtrip(self):
        raw = _ospf3_hello()
        o = OSPFv3(raw)
        self.assertFalse(o.malformed)
        self.assertEqual(o.version, 3)
        self.assertEqual(o.get_field_val('ospf.msg'), 'Hello Packet')
        self.assertEqual(o.get_field_val('ospf.instance_id'), 0)
        self.assertEqual(o.get_field_val('ospf.hello.interface_id'), 5)
        self.assertEqual(o.get_field_val('ospf.hello.router_priority'), 1)
        self.assertEqual(o.get_field_val('ospf.v3.options'), 0x13)
        self.assertEqual(o.get_field_val('ospf.hello.active_neighbor'),
                         '2.2.2.2')
        self.assertEqual(o.pkt2net({}), raw)

    def test_lsupdate_decodes_v3_lsas(self):
        raw = _ospf3_lsupdate(_v3_router_lsa())
        o = OSPFv3(raw)
        self.assertEqual(o.body.get('ospf.lsa.number_of_lsas'), 1)
        self.assertEqual(o.lsas[0].get_field_val('ospf.v3.lsa.type'),
                         'Router-LSA')
        self.assertEqual(o.get_field_val('ospf.v3.options'), 0x13)
        self.assertEqual(o.pkt2net({}), raw)

    def test_auth_trailer(self):
        raw = _ospf3_hello() + _at_trailer()
        o = OSPFv3(raw)
        self.assertEqual(o.get_field_val('ospf.at.auth_type'), 1)
        self.assertEqual(o.get_field_val('ospf.at.auth_data_len'), 20)
        self.assertEqual(o.get_field_val('ospf.at.sa_id'), 7)
        self.assertEqual(o.get_field_val('ospf.at.crypto_seq_nbr'), 0x99)
        self.assertEqual(o.pkt2net({}), raw)

    def test_ospfv3_over_ipv6(self):
        outer = IP6(next_header=OSPF_PROTO, src='fe80::1', dst='ff02::5',
                    payload=OSPFv3(_ospf3_hello()))
        wire = outer.pkt2net({'update': 1})
        parsed = IP6(array('B', wire))
        self.assertIsInstance(parsed.payload, OSPFv3)
        self.assertEqual(parsed.payload.get_field_val('ospf.msg'),
                         'Hello Packet')

    def test_update_recomputes_checksum(self):
        raw = _ospf3_hello(checksum=0xbeef)
        o = OSPFv3(raw)
        updated = OSPFv3(o.pkt2net({'update': 1}))
        self.assertEqual(updated.length, o.length)
        again = OSPFv3(updated.pkt2net({'update': 1}))
        self.assertEqual(again.checksum, updated.checksum)

    def test_truncation_never_raises(self):
        wire = _ospf3_lsupdate(_v3_router_lsa())
        for n in (1, 8, 15, 17, 25, 40, len(wire) - 1):
            parsed = OSPFv3(wire[:n])
            self.assertIsInstance(parsed, OSPFv3)
            self.assertEqual(parsed.pkt2net({}), wire[:n],
                             'round-trip failed at %d bytes' % n)

    def test_ipsec_style_trailer_does_not_raise(self):
        # A short (non-AT) trailer past the packet length must be preserved,
        # not raise (IPsec AH/ESP is out of scope per plan).
        raw = _ospf3_hello() + b'\x01\x02\x03'
        o = OSPFv3(raw)
        self.assertIsInstance(o, OSPFv3)
        self.assertEqual(o.pkt2net({}), raw)


# ---------------------------------------------------------------------------
# BGP (Stage 3): RFC 4271 + extensions, carried over TCP port 179. Fixtures are
# built by hand from the RFC wire layout so the tests do not depend on the
# encoder to prove the decoder. BGP is a single-message codec (CRITICAL-1,
# Option A): the caller owns TCP reassembly.
# ---------------------------------------------------------------------------

BGP_PORT = 179
BGP_MARKER = b'\xff' * 16


def _bgp_msg(mtype, body):
    return BGP_MARKER + struct.pack('!H', 19 + len(body)) + bytes([mtype]) + body


def _bgp_keepalive():
    return _bgp_msg(4, b'')


def _bgp_cap(code, value):
    return bytes([code, len(value)]) + value


def _bgp_open(myas=65001, holdtime=180, ident='1.1.1.1', caps=b''):
    optparams = _bgp_cap(2, caps) if caps else b''
    body = (bytes([4]) + struct.pack('!H', myas) + struct.pack('!H', holdtime) +
            _ip4(ident) + bytes([len(optparams)]) + optparams)
    return _bgp_msg(1, body)


def _bgp_pa(flags, atype, value):
    return bytes([flags, atype, len(value)]) + value


def _bgp_update(withdrawn=b'', attrs=b'', nlri=b''):
    body = (struct.pack('!H', len(withdrawn)) + withdrawn +
            struct.pack('!H', len(attrs)) + attrs + nlri)
    return _bgp_msg(2, body)


def _bgp_notification(major, minor, data=b''):
    return _bgp_msg(3, bytes([major, minor]) + data)


def _bgp_route_refresh(afi=1, safi=1):
    return _bgp_msg(5, struct.pack('!H', afi) + bytes([0, safi]))


def _bgp_std_update():
    attrs = (_bgp_pa(0x40, 1, bytes([0])) +                       # ORIGIN=IGP
             _bgp_pa(0x40, 2, bytes([2, 1]) + struct.pack('!H', 65010)) +  # AS_PATH
             _bgp_pa(0x40, 3, _ip4('9.9.9.9')) +                  # NEXT_HOP
             _bgp_pa(0x80, 4, struct.pack('!I', 100)) +           # MED
             _bgp_pa(0x40, 5, struct.pack('!I', 200)) +           # LOCAL_PREF
             _bgp_pa(0xC0, 8, struct.pack('!I', 0xFFFFFF01)))     # COMMUNITIES NO_EXPORT
    nlri = bytes([8, 10])                                         # 10.0.0.0/8
    return _bgp_update(attrs=attrs, nlri=nlri)


class BGPHeaderTestCase(unittest.TestCase):

    def test_keepalive_parse_and_roundtrip(self):
        raw = _bgp_keepalive()
        b = BGP(raw)
        self.assertFalse(b.malformed)
        self.assertEqual(b.get_field_val('bgp.type'), 'KEEPALIVE Message')
        self.assertEqual(b.get_field_val('bgp.length'), 19)
        self.assertEqual(b.length, 19)
        self.assertEqual(b.pkt2net({}), raw)
        self.assertEqual(BGP(b.pkt2net({})).pkt2net({}), raw)

    def test_unknown_type_preserved(self):
        raw = _bgp_msg(99, b'\x01\x02\x03')
        b = BGP(raw)
        self.assertEqual(b.get_field_val('bgp.type'), 'Unknown (99)')
        self.assertEqual(b.pkt2net({}), raw)

    def test_keyword_construction_roundtrips(self):
        body = struct.pack('!H', 0) + struct.pack('!H', 0)
        b = BGP(type=2, body=body)
        wire = b.pkt2net({})
        parsed = BGP(wire)
        self.assertEqual(parsed.get_field_val('bgp.type'), 'UPDATE Message')
        self.assertEqual(parsed.length, 19 + len(body))
        self.assertEqual(parsed.pkt2net({}), wire)

    def test_update_flag_recomputes_length(self):
        b = BGP(type=4, body=b'')
        self.assertEqual(BGP(b.pkt2net({'update': 1})).length, 19)


class BGPOpenTestCase(unittest.TestCase):

    def test_open_fields_and_roundtrip(self):
        caps = (_bgp_cap(1, struct.pack('!H', 1) + bytes([0, 1])) +   # MP IPv4 unicast
                _bgp_cap(65, struct.pack('!I', 65001)) +              # 4-octet AS
                _bgp_cap(69, struct.pack('!H', 1) + bytes([1, 3])))   # add-path Both
        raw = _bgp_open(myas=65001, ident='1.1.1.1', caps=caps)
        b = BGP(raw)
        self.assertFalse(b.malformed)
        self.assertEqual(b.get_field_val('bgp.open.version'), 4)
        self.assertEqual(b.get_field_val('bgp.open.myas'), 65001)
        self.assertEqual(b.get_field_val('bgp.open.holdtime'), 180)
        self.assertEqual(b.get_field_val('bgp.open.identifier'), '1.1.1.1')
        self.assertEqual(b.get_field_val('bgp.cap.mp.afi'), 'IP (IP version 4)')
        self.assertEqual(b.get_field_val('bgp.cap.mp.safi'), 'Unicast')
        self.assertEqual(b.get_field_val('bgp.cap.ap.afi'), 'IP (IP version 4)')
        self.assertEqual(b.get_field_val('bgp.cap.ap.safi'), 'Unicast')
        # Wireshark orf_send_recv_vals renders 3 as "Both", not
        # "Send and Receive" -- Q10 makes Wireshark the source of truth.
        self.assertEqual(b.get_field_val('bgp.cap.ap.sendreceive'), 'Both')
        self.assertEqual(len(b.params), 3)
        self.assertEqual(b.pkt2net({}), raw)

    def test_capability_type_renders_wireshark_string(self):
        caps = _bgp_cap(65, struct.pack('!I', 65001))
        b = BGP(_bgp_open(caps=caps))
        self.assertEqual(b.get_field_val('bgp.cap.type'),
                         'Support for 4-octet AS number capability')


class BGPUpdateTestCase(unittest.TestCase):

    def test_path_attributes_decode(self):
        b = BGP(_bgp_std_update())
        self.assertEqual(b.get_field_val('bgp.type'), 'UPDATE Message')
        self.assertEqual(b.get_field_val('bgp.update.path_attribute.origin'),
                         'IGP')
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.as_path_segment.type'), 'AS_SEQUENCE')
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.as_path_segment.as2'), 65010)
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.next_hop'), '9.9.9.9')
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.multi_exit_disc'), 100)
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.local_pref'), 200)
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.community'), 'NO_EXPORT')
        self.assertEqual(b.get_field_val('bgp.nlri_prefix'), '10.0.0.0')
        self.assertEqual(b.get_field_val('bgp.prefix_length'), 8)
        self.assertEqual(b.pkt2net({}), _bgp_std_update())

    def test_path_attribute_flags(self):
        b = BGP(_bgp_std_update())
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.type_code'), 'ORIGIN')
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.flags.optional'), 0)
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.flags.transitive'), 1)

    def test_as4_path_and_aggregator(self):
        attrs = (_bgp_pa(0xC0, 17, bytes([2, 1]) + struct.pack('!I', 200000)) +
                 _bgp_pa(0xC0, 18, struct.pack('!I', 200000) + _ip4('2.2.2.2')))
        b = BGP(_bgp_update(attrs=attrs))
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.as_path_segment.as4'), 200000)
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.aggregator_as'), 200000)
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.aggregator_origin'), '2.2.2.2')
        self.assertEqual(b.pkt2net({}), _bgp_update(attrs=attrs))

    def test_extended_length_attribute(self):
        # MP_REACH_NLRI with the extended-length flag (2-byte length):
        # AFI=1 (IPv4), SAFI=2 (Multicast), next-hop length 4, next hop.
        val = struct.pack('!H', 1) + bytes([2]) + bytes([4]) + _ip4('1.2.3.4')
        attr = bytes([0x90, 14]) + struct.pack('!H', len(val)) + val
        b = BGP(_bgp_update(attrs=attr))
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.flags.extended_length'), 1)
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.mp_reach_nlri.afi'),
            'IP (IP version 4)')
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.mp_reach_nlri.safi'), 'Multicast')
        self.assertEqual(b.pkt2net({}), _bgp_update(attrs=attr))

    def test_mp_unreach_and_large_community(self):
        mpu = _bgp_pa(0x80, 15, struct.pack('!H', 2) + bytes([1]))   # IPv6 unicast
        lc = _bgp_pa(0xC0, 32, struct.pack('!III', 65001, 1, 2))
        b = BGP(_bgp_update(attrs=mpu + lc))
        self.assertEqual(b.get_field_val(
            'bgp.update.path_attribute.mp_unreach_nlri.afi'),
            'IP6 (IP version 6)')
        self.assertEqual(b.get_field_val('bgp.large_communities'),
                         '65001:1:2')
        self.assertEqual(b.pkt2net({}), _bgp_update(attrs=mpu + lc))

    def test_withdrawn_routes(self):
        b = BGP(_bgp_update(withdrawn=bytes([16, 192, 168])))
        self.assertEqual(b.get_field_val(
            'bgp.update.withdrawn_routes.length'), 3)
        self.assertEqual(b.get_field_val('bgp.withdrawn_prefix'), '192.168.0.0')
        self.assertEqual(b.pkt2net({}),
                         _bgp_update(withdrawn=bytes([16, 192, 168])))

    def test_add_path_nlri_hint(self):
        # With add_path, each NLRI carries a leading 4-byte path identifier.
        nlri = struct.pack('!I', 7) + bytes([8, 10])
        raw = _bgp_update(nlri=nlri)
        without = BGP(raw)
        self.assertNotEqual(without.get_field_val('bgp.nlri_prefix'),
                            '10.0.0.0')
        with_hint = BGP(raw, add_path=1)
        self.assertEqual(with_hint.get_field_val('bgp.nlri_prefix'),
                         '10.0.0.0')
        self.assertEqual(with_hint.pkt2net({}), raw)


class BGPNotificationTestCase(unittest.TestCase):

    def test_notification_enums(self):
        b = BGP(_bgp_notification(6, 2, b'\x00'))
        self.assertEqual(b.get_field_val('bgp.notify.major_error'), 'Cease')
        self.assertEqual(b.get_field_val('bgp.notify.minor_error'),
                         'Administratively Shutdown')
        self.assertEqual(b.pkt2net({}), _bgp_notification(6, 2, b'\x00'))

    def test_notification_open_error(self):
        b = BGP(_bgp_notification(2, 4))
        self.assertEqual(b.get_field_val('bgp.notify.major_error'),
                         'OPEN Message Error')
        self.assertEqual(b.get_field_val('bgp.notify.minor_error'),
                         'Unsupported Optional Parameter')


class BGPRouteRefreshTestCase(unittest.TestCase):

    def test_route_refresh(self):
        raw = _bgp_route_refresh(afi=1, safi=1)
        b = BGP(raw)
        self.assertEqual(b.get_field_val('bgp.type'), 'ROUTE-REFRESH Message')
        self.assertEqual(b.get_field_val('bgp.route_refresh.afi'),
                         'IP (IP version 4)')
        self.assertEqual(b.get_field_val('bgp.route_refresh.safi'), 'Unicast')
        self.assertEqual(b.pkt2net({}), raw)


class BGPContractTestCase(unittest.TestCase):

    def test_inapplicable_fields_return_none(self):
        b = BGP(_bgp_keepalive())
        self.assertIsNone(b.get_field_val('bgp.open.version'))
        self.assertIsNone(b.get_field_val('bgp.update.path_attribute.origin'))
        self.assertIsNone(b.get_field_val('bgp.notify.major_error'))

    def test_every_advertised_field_resolves_or_none(self):
        _, fields = BGP.query_info()
        b = BGP(_bgp_std_update())
        for f in fields:
            # Must not raise; either a value or None.
            b.get_field_val(f)

    def test_truncation_never_raises(self):
        wire = _bgp_std_update()
        for n in (0, 1, 15, 18, 19, 21, 25, len(wire) - 1):
            parsed = BGP(wire[:n])
            self.assertIsInstance(parsed, BGP)
            self.assertEqual(parsed.pkt2net({}), wire[:n],
                             'round-trip failed at %d bytes' % n)

    def test_short_message_marked_malformed(self):
        # length field claims more than is present.
        raw = BGP_MARKER + struct.pack('!H', 60) + bytes([4])
        b = BGP(raw)
        self.assertTrue(b.malformed)
        self.assertEqual(b.pkt2net({}), raw)

    def test_back_to_back_messages_chain(self):
        two = _bgp_keepalive() + _bgp_std_update()
        b = BGP(two)
        self.assertEqual(b.get_field_val('bgp.type'), 'KEEPALIVE Message')
        self.assertIsInstance(b.payload, BGP)
        self.assertEqual(b.payload.get_field_val('bgp.type'), 'UPDATE Message')
        self.assertEqual(b.pkt2net({}), two)


class BGPDispatchTestCase(unittest.TestCase):

    def test_tcp_l7_dispatch(self):
        raw = _bgp_std_update()
        tcp = TCP(TCP(sport=50000, dport=BGP_PORT, payload=raw).pkt2net({}),
                  l7_ports={BGP_PORT: BGP})
        self.assertIsInstance(tcp.payload, BGP)
        self.assertEqual(tcp.payload.get_field_val('bgp.type'),
                         'UPDATE Message')

    def test_nested_ip_tcp_bgp(self):
        raw = _bgp_std_update()
        outer = IP(src='10.0.0.1', dst='10.0.0.2', proto=C.PROTO_TCP,
                   payload=TCP(sport=50000, dport=BGP_PORT, payload=raw))
        wire = outer.pkt2net({'update': 1, 'csum': 1})
        parsed = IP(wire, l7_ports={BGP_PORT: BGP})
        bgp = parsed.get_layer_by_type(C.PQ_BGP)
        self.assertIsInstance(bgp, BGP)
        self.assertEqual(bgp.get_field_val(
            'bgp.update.path_attribute.origin'), 'IGP')


# ---------------------------------------------------------------------------
# Stage 4a/4b: RIP / RIPng / HSRP
# ---------------------------------------------------------------------------

RIP_PORT = 520
RIPNG_PORT = 521
HSRP_PORT = 1985


def _ip4(dotted):
    return bytes(int(x) for x in dotted.split('.'))


def _rip_route(af=2, tag=0, ip='192.168.1.0', mask='255.255.255.0',
               nh='0.0.0.0', metric=1):
    return (struct.pack('!HH', af, tag) + _ip4(ip) + _ip4(mask) + _ip4(nh) +
            struct.pack('!I', metric))


def _rip(command=2, version=2, routing_domain=0, entries=b''):
    return bytes([command, version]) + struct.pack('!H', routing_domain) + \
        entries


def _rip_simple_auth(passwd=b'secret'):
    return struct.pack('!HH', 0xFFFF, 2) + (passwd + b'\x00' * 16)[:16]


def _ripng_rte(prefix='2001:db8::', tag=0, plen=64, metric=1):
    import socket
    return (socket.inet_pton(socket.AF_INET6, prefix) +
            struct.pack('!HBB', tag, plen, metric))


def _ripng(command=2, version=1, rtes=b''):
    return bytes([command, version, 0, 0]) + rtes


def _hsrpv1(version=0, opcode=0, state=8, hellotime=3, holdtime=10,
            priority=120, group=1, auth=b'cisco', vip='10.0.0.1'):
    return (bytes([version, opcode, state, hellotime, holdtime, priority,
                   group, 0]) + (auth + b'\x00' * 8)[:8] + _ip4(vip))


def _hsrp2_group_state(opcode=0, state=6, ipver=4, group=1,
                       identifier='00:00:0c:07:0a:c0', priority=120,
                       hello=3000, hold=10000, vip='192.168.0.1'):
    mac = bytes(int(x, 16) for x in identifier.split(':'))
    value = (bytes([2, opcode, state, ipver]) + struct.pack('!H', group) +
             mac + struct.pack('!III', priority, hello, hold) +
             _ip4(vip) + b'\x00' * 12)
    return bytes([1, len(value)]) + value


class RIPConstructionTestCase(unittest.TestCase):

    def test_ripv2_response_roundtrip_and_fields(self):
        raw = _rip(entries=_rip_route())
        r = RIP(raw)
        self.assertEqual(r.get_field_val('rip.command'), 'Response')
        self.assertEqual(r.get_field_val('rip.version'), 'RIPv2')
        self.assertEqual(r.get_field_val('rip.routing_domain'), 0)
        self.assertEqual(r.get_field_val('rip.family'), 'IP')
        self.assertEqual(r.get_field_val('rip.ip'), '192.168.1.0')
        self.assertEqual(r.get_field_val('rip.netmask'), '255.255.255.0')
        self.assertEqual(r.get_field_val('rip.next_hop'), '0.0.0.0')
        self.assertEqual(r.get_field_val('rip.metric'), 1)
        self.assertEqual(len(r.entries), 1)
        self.assertFalse(r.malformed)
        self.assertEqual(r.pkt2net({}), raw)
        self.assertEqual(RIP(r.pkt2net({})).pkt2net({}), raw)

    def test_ripv1_request_omits_v2_only_fields(self):
        raw = _rip(command=1, version=1, entries=_rip_route(mask='0.0.0.0'))
        r = RIP(raw)
        self.assertEqual(r.get_field_val('rip.command'), 'Request')
        self.assertEqual(r.get_field_val('rip.version'), 'RIPv1')
        self.assertEqual(r.get_field_val('rip.ip'), '192.168.1.0')
        # RIPv1 carries no route tag / netmask / next hop.
        self.assertIsNone(r.get_field_val('rip.route_tag'))
        self.assertIsNone(r.get_field_val('rip.netmask'))
        self.assertIsNone(r.get_field_val('rip.next_hop'))
        self.assertEqual(r.pkt2net({}), raw)

    def test_multiple_routes(self):
        raw = _rip(entries=_rip_route(ip='10.0.0.0', mask='255.0.0.0') +
                   _rip_route(ip='172.16.0.0', mask='255.255.0.0', metric=2))
        r = RIP(raw)
        self.assertEqual(len(r.entries), 2)
        self.assertEqual(r.get_field_val('rip.ip'), '10.0.0.0')
        self.assertEqual(r.pkt2net({}), raw)

    def test_keyword_build_roundtrip(self):
        r = RIP(command=2, version=2, body=_rip_route())
        self.assertEqual(r.pkt2net({}), _rip(entries=_rip_route()))


class RIPAuthTestCase(unittest.TestCase):

    def test_simple_password(self):
        raw = _rip(entries=_rip_simple_auth(b'secret') + _rip_route())
        r = RIP(raw)
        self.assertEqual(r.get_field_val('rip.auth.type'), 'Simple Password')
        self.assertEqual(r.get_field_val('rip.auth.passwd'), 'secret')
        # The route after the auth entry still resolves.
        self.assertEqual(r.get_field_val('rip.ip'), '192.168.1.0')
        self.assertEqual(r.pkt2net({}), raw)

    def test_keyed_md5_fields_and_verbatim_roundtrip(self):
        dpos = 4 + 20 + 20               # header + auth entry + one route
        auth = (struct.pack('!HH', 0xFFFF, 3) + struct.pack('!H', dpos) +
                bytes([1, 20]) + struct.pack('!I', 42) + b'\x00' * 8)
        trailer = struct.pack('!HH', 0xFFFF, 1) + b'\x11' * 16
        raw = _rip(entries=auth + _rip_route(ip='172.16.0.0',
                                             mask='255.255.0.0') + trailer)
        r = RIP(raw)
        self.assertEqual(r.get_field_val('rip.auth.type'),
                         'Keyed Message Digest')
        self.assertEqual(r.get_field_val('rip.digest_offset'), dpos)
        self.assertEqual(r.get_field_val('rip.key_id'), 1)
        self.assertEqual(r.get_field_val('rip.auth_data_len'), 20)
        self.assertEqual(r.get_field_val('rip.seq_num'), 42)
        self.assertEqual(r.get_field_val('rip.authentication_data'),
                         '11' * 16)
        # No key -> stored digest emitted verbatim.
        self.assertEqual(r.pkt2net({}), raw)
        self.assertEqual(r.pkt2net({'update': 1}), raw)

    def test_keyed_md5_recompute_with_key(self):
        import hashlib
        dpos = 4 + 20 + 20
        auth = (struct.pack('!HH', 0xFFFF, 3) + struct.pack('!H', dpos) +
                bytes([1, 20]) + struct.pack('!I', 42) + b'\x00' * 8)
        trailer = struct.pack('!HH', 0xFFFF, 1) + b'\x00' * 16
        raw = _rip(entries=auth + _rip_route() + trailer)
        r = RIP(raw)
        out = r.pkt2net({'update': 1, 'key': 'mykey'})
        self.assertEqual(len(out), len(raw))
        k16 = (b'mykey' + b'\x00' * 16)[:16]
        expect = hashlib.md5(raw[:dpos + 4] + k16 + raw[dpos + 20:]).digest()
        self.assertEqual(out[dpos + 4:dpos + 20], expect)
        # Re-parsing the recomputed message exposes the new digest.
        self.assertEqual(RIP(out).get_field_val('rip.authentication_data'),
                         expect.hex())


class RIPContractTestCase(unittest.TestCase):

    def test_default_ports(self):
        self.assertEqual(RIP.default_ports(), [520])

    def test_every_advertised_field_resolves_or_none(self):
        _, fields = RIP.query_info()
        r = RIP(_rip(entries=_rip_simple_auth() + _rip_route()))
        for f in fields:
            r.get_field_val(f)

    def test_truncation_never_raises(self):
        raw = _rip(entries=_rip_route())
        for n in range(0, len(raw)):
            parsed = RIP(raw[:n])
            self.assertIsInstance(parsed, RIP)
            self.assertEqual(parsed.pkt2net({}), raw[:n],
                             'round-trip failed at %d bytes' % n)

    def test_short_header_marked_malformed(self):
        r = RIP(b'\x02')
        self.assertTrue(r.malformed)
        self.assertEqual(r.pkt2net({}), b'\x02')

    def test_ip_udp_dispatch(self):
        raw = _rip(entries=_rip_route())
        outer = IP(src='10.0.0.1', dst='224.0.0.9', proto=C.PQ_UDP,
                   payload=UDP(sport=RIP_PORT, dport=RIP_PORT, payload=raw))
        wire = outer.pkt2net({'update': 1, 'csum': 1})
        r = IP(wire, l7_ports={RIP_PORT: RIP}).get_layer_by_type(C.PQ_RIP)
        self.assertIsInstance(r, RIP)
        self.assertEqual(r.get_field_val('rip.ip'), '192.168.1.0')
        self.assertEqual(r.pkt2net({}), raw)


class RIPngTestCase(unittest.TestCase):

    def test_response_roundtrip_and_fields(self):
        raw = _ripng(rtes=_ripng_rte() + _ripng_rte(prefix='::', plen=0,
                                                    metric=255))
        r = RIPng(raw)
        self.assertEqual(r.get_field_val('ripng.cmd'), 'Response')
        self.assertEqual(r.get_field_val('ripng.version'), 1)
        self.assertEqual(r.get_field_val('ripng.rte.ipv6_prefix'),
                         '2001:db8::')
        self.assertEqual(r.get_field_val('ripng.rte.prefix_length'), 64)
        self.assertEqual(r.get_field_val('ripng.rte.metric'), 1)
        self.assertEqual(len(r.rtes), 2)
        # The next-hop RTE (metric 255) is the second entry.
        self.assertEqual(r.rtes[1].get_field_val('ripng.rte.metric'), 255)
        self.assertFalse(r.malformed)
        self.assertEqual(r.pkt2net({}), raw)
        self.assertEqual(RIPng(r.pkt2net({})).pkt2net({}), raw)

    def test_default_ports(self):
        self.assertEqual(RIPng.default_ports(), [521])

    def test_keyword_build_roundtrip(self):
        r = RIPng(command=1, version=1, body=_ripng_rte())
        self.assertEqual(r.pkt2net({}), _ripng(command=1, rtes=_ripng_rte()))

    def test_every_advertised_field_resolves_or_none(self):
        _, fields = RIPng.query_info()
        r = RIPng(_ripng(rtes=_ripng_rte()))
        for f in fields:
            r.get_field_val(f)

    def test_truncation_never_raises(self):
        raw = _ripng(rtes=_ripng_rte())
        for n in range(0, len(raw)):
            parsed = RIPng(raw[:n])
            self.assertIsInstance(parsed, RIPng)
            self.assertEqual(parsed.pkt2net({}), raw[:n],
                             'round-trip failed at %d bytes' % n)

    def test_ip6_udp_dispatch(self):
        raw = _ripng(rtes=_ripng_rte())
        outer = IP6(src='2001:db8::1', dst='ff02::9',
                    next_header=C.PQ_UDP,
                    payload=UDP(sport=RIPNG_PORT, dport=RIPNG_PORT,
                                payload=raw))
        wire = outer.pkt2net({'update': 1, 'csum': 1})
        r = IP6(wire, l7_ports={RIPNG_PORT: RIPng}).get_layer_by_type(
            C.PQ_RIPNG)
        self.assertIsInstance(r, RIPng)
        self.assertEqual(r.get_field_val('ripng.rte.ipv6_prefix'),
                         '2001:db8::')


class HSRPv1TestCase(unittest.TestCase):

    def test_hello_roundtrip_and_fields(self):
        raw = _hsrpv1(opcode=0, state=8, priority=120, group=1,
                      auth=b'cisco', vip='10.0.0.1')
        h = HSRP(raw)
        self.assertFalse(h.is_v2)
        self.assertEqual(h.get_field_val('hsrp.version'), 0)
        self.assertEqual(h.get_field_val('hsrp.opcode'), 'Hello')
        self.assertEqual(h.get_field_val('hsrp.state'), 'Standby')
        self.assertEqual(h.get_field_val('hsrp.hellotime'), 3)
        self.assertEqual(h.get_field_val('hsrp.holdtime'), 10)
        self.assertEqual(h.get_field_val('hsrp.priority'), 120)
        self.assertEqual(h.get_field_val('hsrp.group'), 1)
        self.assertEqual(h.get_field_val('hsrp.auth_data'), 'cisco')
        self.assertEqual(h.get_field_val('hsrp.virt_ip'), '10.0.0.1')
        self.assertFalse(h.malformed)
        self.assertEqual(h.pkt2net({}), raw)
        self.assertEqual(HSRP(h.pkt2net({})).pkt2net({}), raw)

    def test_state_enum_values(self):
        for code, txt in ((0, 'Initial'), (1, 'Learn'), (2, 'Listen'),
                          (4, 'Speak'), (8, 'Standby'), (16, 'Active')):
            h = HSRP(_hsrpv1(state=code))
            self.assertEqual(h.get_field_val('hsrp.state'), txt)

    def test_coup_and_resign_opcodes(self):
        self.assertEqual(HSRP(_hsrpv1(opcode=1)).get_field_val('hsrp.opcode'),
                         'Coup')
        self.assertEqual(HSRP(_hsrpv1(opcode=2)).get_field_val('hsrp.opcode'),
                         'Resign')

    def test_advertise_tlv(self):
        raw = (bytes([0, 3]) + struct.pack('!HH', 1, 10) + bytes([3, 0]) +
               struct.pack('!HH', 2, 1) + struct.pack('!I', 0))
        h = HSRP(raw)
        self.assertEqual(h.get_field_val('hsrp.opcode'), 'Advertise')
        self.assertEqual(h.get_field_val('hsrp.adv.tlvtype'),
                         'HSRP interface state')
        self.assertEqual(h.get_field_val('hsrp.adv.state'), 'Active')
        self.assertEqual(h.get_field_val('hsrp.adv.activegrp'), 2)
        self.assertEqual(h.get_field_val('hsrp.adv.passivegrp'), 1)
        self.assertEqual(h.pkt2net({}), raw)

    def test_keyword_build_roundtrip(self):
        h = HSRP(opcode=0, state=16, priority=100, group=2, auth=b'pass',
                 virt_ip='192.168.1.1')
        parsed = HSRP(h.pkt2net({}))
        self.assertEqual(parsed.get_field_val('hsrp.state'), 'Active')
        self.assertEqual(parsed.get_field_val('hsrp.group'), 2)
        self.assertEqual(parsed.get_field_val('hsrp.virt_ip'), '192.168.1.1')

    def test_v1_with_trailing_md5_tlv(self):
        md5 = (bytes([4, 28, 1, 0]) + struct.pack('!H', 0) + _ip4('10.0.0.1') +
               struct.pack('!I', 7) + b'\x22' * 16)
        raw = _hsrpv1() + md5
        h = HSRP(raw)
        self.assertFalse(h.is_v2)
        self.assertEqual(h.get_field_val('hsrp.opcode'), 'Hello')
        self.assertEqual(h.get_field_val('hsrp2.md5_algorithm'), 'MD5')
        self.assertEqual(h.get_field_val('hsrp.md5_ip_address'), '10.0.0.1')
        self.assertEqual(h.get_field_val('hsrp2.md5_key_id'), 7)
        self.assertEqual(h.get_field_val('hsrp2.md5_auth_data'), '22' * 16)
        self.assertEqual(h.pkt2net({}), raw)


class HSRPv2TestCase(unittest.TestCase):

    def test_group_state_ipv4(self):
        raw = _hsrp2_group_state(opcode=0, state=6, ipver=4, group=1,
                                 priority=120, vip='192.168.0.1')
        h = HSRP(raw)
        self.assertTrue(h.is_v2)
        self.assertEqual(h.version, 2)
        self.assertEqual(h.get_field_val('hsrp2.opcode'), 'Hello')
        self.assertEqual(h.get_field_val('hsrp2.state'), 'Active')
        self.assertEqual(h.get_field_val('hsrp2.ipversion'), 'IPv4')
        self.assertEqual(h.get_field_val('hsrp2.group'), 1)
        self.assertEqual(h.get_field_val('hsrp2.identifier'),
                         '00:00:0c:07:0a:c0')
        self.assertEqual(h.get_field_val('hsrp2.priority'), 120)
        self.assertEqual(h.get_field_val('hsrp2.hellotime'), 3000)
        self.assertEqual(h.get_field_val('hsrp2.holdtime'), 10000)
        self.assertEqual(h.get_field_val('hsrp2.virt_ip'), '192.168.0.1')
        self.assertFalse(h.malformed)
        self.assertEqual(h.pkt2net({}), raw)
        self.assertEqual(HSRP(h.pkt2net({})).pkt2net({}), raw)

    def test_group_state_ipv6(self):
        import socket
        v6 = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
        value = (bytes([2, 0, 6, 6]) + struct.pack('!H', 5) +
                 bytes.fromhex('00000c070ac0') +
                 struct.pack('!III', 120, 3000, 10000) + v6)
        raw = bytes([1, len(value)]) + value
        h = HSRP(raw)
        self.assertEqual(h.get_field_val('hsrp2.ipversion'), 'IPv6')
        self.assertEqual(h.get_field_val('hsrp2.virt_ip_v6'), '2001:db8::1')
        self.assertIsNone(h.get_field_val('hsrp2.virt_ip'))
        self.assertEqual(h.pkt2net({}), raw)

    def test_state_enum_contiguous(self):
        for code, txt in ((1, 'Init'), (2, 'Learn'), (3, 'Listen'),
                          (4, 'Speak'), (5, 'Standby'), (6, 'Active')):
            h = HSRP(_hsrp2_group_state(state=code))
            self.assertEqual(h.get_field_val('hsrp2.state'), txt)

    def test_interface_and_text_auth_tlvs(self):
        gs = _hsrp2_group_state()
        iface = bytes([2, 4]) + struct.pack('!HH', 3, 1)
        text = bytes([3, 8]) + (b'cisco' + b'\x00' * 8)[:8]
        raw = gs + iface + text
        h = HSRP(raw)
        self.assertEqual(len(h.tlvs), 3)
        self.assertEqual(h.get_field_val('hsrp2.active_groups'), 3)
        self.assertEqual(h.get_field_val('hsrp2.passive_groups'), 1)
        self.assertEqual(h.get_field_val('hsrp2.auth_data'), 'cisco')
        self.assertEqual(h.pkt2net({}), raw)

    def test_md5_auth_tlv(self):
        gs = _hsrp2_group_state()
        md5 = (bytes([4, 28, 1, 0]) + struct.pack('!H', 0) + _ip4('10.0.0.9') +
               struct.pack('!I', 99) + b'\x33' * 16)
        raw = gs + md5
        h = HSRP(raw)
        self.assertEqual(h.get_field_val('hsrp2.md5_algorithm'), 'MD5')
        self.assertEqual(h.get_field_val('hsrp.md5_ip_address'), '10.0.0.9')
        self.assertEqual(h.get_field_val('hsrp2.md5_key_id'), 99)
        self.assertEqual(h.get_field_val('hsrp2.md5_auth_data'), '33' * 16)
        self.assertEqual(h.pkt2net({}), raw)

    def test_unknown_tlv_preserved(self):
        gs = _hsrp2_group_state()
        unknown = bytes([200, 4]) + b'\xde\xad\xbe\xef'
        raw = gs + unknown
        h = HSRP(raw)
        self.assertEqual(len(h.tlvs), 2)
        self.assertEqual(h.pkt2net({}), raw)


class HSRPContractTestCase(unittest.TestCase):

    def test_default_ports(self):
        self.assertEqual(HSRP.default_ports(), [1985])

    def test_one_pq_type_both_versions_disjoint(self):
        # v1 fields resolve on a v1 packet; v2 fields are None, and vice versa.
        v1 = HSRP(_hsrpv1(opcode=0))
        self.assertIsNotNone(v1.get_field_val('hsrp.opcode'))
        self.assertIsNone(v1.get_field_val('hsrp2.opcode'))
        v2 = HSRP(_hsrp2_group_state())
        self.assertIsNotNone(v2.get_field_val('hsrp2.opcode'))
        self.assertIsNone(v2.get_field_val('hsrp.opcode'))

    def test_every_advertised_field_resolves_or_none(self):
        _, fields = HSRP.query_info()
        for raw in (_hsrpv1(), _hsrp2_group_state()):
            h = HSRP(raw)
            for f in fields:
                h.get_field_val(f)

    def test_truncation_never_raises(self):
        for raw in (_hsrpv1(), _hsrp2_group_state()):
            for n in range(0, len(raw)):
                parsed = HSRP(raw[:n])
                self.assertIsInstance(parsed, HSRP)
                self.assertEqual(parsed.pkt2net({}), raw[:n],
                                 'round-trip failed at %d bytes' % n)

    def test_ip_udp_dispatch(self):
        raw = _hsrpv1(opcode=0)
        outer = IP(src='10.0.0.1', dst='224.0.0.2', proto=C.PQ_UDP,
                   payload=UDP(sport=HSRP_PORT, dport=HSRP_PORT, payload=raw))
        wire = outer.pkt2net({'update': 1, 'csum': 1})
        h = IP(wire, l7_ports={HSRP_PORT: HSRP}).get_layer_by_type(C.PQ_HSRP)
        self.assertIsInstance(h, HSRP)
        self.assertEqual(h.get_field_val('hsrp.opcode'), 'Hello')


if __name__ == '__main__':
    unittest.main()
