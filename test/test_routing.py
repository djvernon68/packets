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
    MPLS, Ethernet, NullPkt, OSPFv2, OSPFv3, OSPFLSA

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


if __name__ == '__main__':
    unittest.main()
