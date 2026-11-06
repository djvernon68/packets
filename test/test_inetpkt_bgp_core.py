#!/usr/bin/env python

"""Tests for the nogil BGP decode primitives in packets.core.inetpkt, driven
through the packets.core.bgpcore wrappers.

These are the wire-level half of the BGP codec: the functions the text
dissector and the routing engine both parse through. test_routing.py already
covers what the dissector renders; this module covers what the primitives
compute, including the cases the dissector structurally cannot reach -- IPv6
prefix lengths, RFC 7911 path identifiers, RFC 9072 extended optional
parameters, and MP_REACH/MP_UNREACH spans.

Two properties matter more than any individual assertion:

  * Nothing raises. The routing codecs are under a never-raise contract, and
    the primitives keep it by returning -1 instead of throwing. The
    truncation and fuzz cases below assert that as a property, over every
    prefix of every sample buffer, rather than trusting it.
  * Offsets are absolute into the buffer passed in, so every expected value
    here is checkable against a hexdump of the sample.

Written as plain unittest.TestCase with no pytest features: the 3.6.8
verification host has no pytest and runs this through
``python3 -m unittest discover -s test``.
"""

import os
import struct
import sys
import unittest

# test_routing.py owns the BGP byte builders and is the dissector's regression
# gate, so reusing them here means the primitives are checked against the exact
# bytes the dissector suite asserts on rather than a second, drifting set.
# unittest discover and pytest both put this directory on sys.path; the
# fallback covers being run some other way.
try:
    from test_routing import _bgp_msg, _bgp_cap, _bgp_open, _bgp_pa, \
        _bgp_update, _bgp_std_update, _bgp_keepalive, _ip4
except ImportError:                                      # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_routing import _bgp_msg, _bgp_cap, _bgp_open, _bgp_pa, \
        _bgp_update, _bgp_std_update, _bgp_keepalive, _ip4

from packets.core import bgpcore as bc
from packets.core.inetpkt import BGP

BGP_MARKER = b'\xff' * 16
HDR_LEN = 19


def _open_ext(optparams, myas=65001, holdtime=180, ident='1.1.1.1'):
    """Build an OPEN whose optional parameters use the RFC 9072 encoding.

    A Non-Ext OP Len. of 255, then a Non-Ext OP Type of 255, then the real
    two-octet length. Read without ``allow_ext`` the same bytes look like a
    255-byte optional-parameter block starting 3 bytes earlier, which is what
    makes this the one sample where the two settings must disagree.
    """
    body = (bytes([4]) + struct.pack('!H', myas) +
            struct.pack('!H', holdtime) + _ip4(ident) +
            bytes([255, 255]) + struct.pack('!H', len(optparams)) +
            optparams)
    return _bgp_msg(1, body)


def _update_offsets(msg):
    """Locate the three blocks of an UPDATE body: withdrawn, attrs, NLRI.

    Computed here from the wire rather than taken from the primitives, so the
    primitive results are compared against an independent reading.
    """
    o = HDR_LEN
    wlen = struct.unpack('!H', msg[o:o + 2])[0]
    wstart = o + 2
    wend = wstart + wlen
    tpalen = struct.unpack('!H', msg[wend:wend + 2])[0]
    astart = wend + 2
    aend = astart + tpalen
    return (wstart, wend, astart, aend, len(msg))


def _std_caps():
    """The capability blob test_routing.py's OPEN test uses: MP IPv4 unicast,
    4-octet AS, add-path Both."""
    return (_bgp_cap(1, struct.pack('!H', 1) + bytes([0, 1])) +
            _bgp_cap(65, struct.pack('!I', 65001)) +
            _bgp_cap(69, struct.pack('!H', 1) + bytes([1, 3])))


def _mp_reach_v6(nh=b'\x20\x01\x0d\xb8' + b'\x00' * 12, nlri=b'\x40\x20\x01\x0d\xb8\x00\x00\x00\x00'):
    """An MP_REACH_NLRI value: AFI 2 (IPv6), SAFI 1 (unicast), one next hop,
    the reserved octet, then NLRI."""
    return (struct.pack('!H', 2) + bytes([1, len(nh)]) + nh + bytes([0]) +
            nlri)


class BGPCoreMsgHeaderTestCase(unittest.TestCase):

    def test_keepalive_header(self):
        rc, length, mtype = bc.msg_header(_bgp_keepalive())
        self.assertEqual(rc, 0)
        self.assertEqual(length, 19)
        self.assertEqual(mtype, 4)

    def test_length_field_is_reported_not_validated(self):
        # A length claiming more than the buffer holds is precisely what the
        # caller needs to see in order to flag the message, so the primitive
        # reports it rather than rejecting it.
        msg = BGP_MARKER + struct.pack('!H', 4096) + bytes([2])
        rc, length, mtype = bc.msg_header(msg)
        self.assertEqual((rc, length, mtype), (0, 4096, 2))

    def test_header_one_byte_short(self):
        rc, length, mtype = bc.msg_header(_bgp_keepalive()[:18])
        self.assertEqual(rc, -1)
        self.assertEqual((length, mtype), (0, 0))

    def test_every_truncation_below_19_fails(self):
        msg = _bgp_keepalive()
        for n in range(0, 19):
            self.assertEqual(bc.msg_header(msg[:n])[0], -1,
                             'accepted a %d-byte header' % n)
        self.assertEqual(bc.msg_header(msg[:19])[0], 0)

    def test_offset_and_end_arguments(self):
        # Two back-to-back messages: the second is read by offset alone.
        stream = _bgp_keepalive() + _bgp_std_update()
        self.assertEqual(bc.msg_header(stream, 0)[2], 4)
        self.assertEqual(bc.msg_header(stream, 19)[2], 2)
        # An end that cuts the second header short is refused.
        self.assertEqual(bc.msg_header(stream, 19, 30)[0], -1)

    def test_negative_and_out_of_range_offsets(self):
        msg = _bgp_keepalive()
        self.assertEqual(bc.msg_header(msg, -5)[0], -1)
        self.assertEqual(bc.msg_header(msg, 1000)[0], -1)

    def test_empty_buffer(self):
        self.assertEqual(bc.msg_header(b'')[0], -1)


class BGPCoreOpenFixedTestCase(unittest.TestCase):

    def test_fixed_fields(self):
        msg = _bgp_open(myas=65001, holdtime=180, ident='1.1.1.1',
                        caps=_std_caps())
        rc, ver, my_as, hold, bgp_id, opt_start, opt_end = \
            bc.open_fixed(msg, 0, HDR_LEN)
        self.assertEqual(rc, 0)
        self.assertEqual(ver, 4)
        self.assertEqual(my_as, 65001)
        self.assertEqual(hold, 180)
        self.assertEqual(bgp_id, 0x01010101)
        self.assertEqual(opt_start, HDR_LEN + 10)
        # The optional parameters run to the end of this message.
        self.assertEqual(opt_end, len(msg))

    def test_no_optional_parameters(self):
        msg = _bgp_open(caps=b'')
        rc, _, _, _, _, opt_start, opt_end = bc.open_fixed(msg, 0, HDR_LEN)
        self.assertEqual(rc, 0)
        self.assertEqual(opt_start, HDR_LEN + 10)
        self.assertEqual(opt_end, opt_start)

    def test_rfc9072_allow_ext_set(self):
        optparams = _bgp_cap(2, _std_caps())
        msg = _open_ext(optparams)
        rc, ver, my_as, hold, bgp_id, opt_start, opt_end = \
            bc.open_fixed(msg, 1, HDR_LEN)
        self.assertEqual(rc, 0)
        self.assertEqual(ver, 4)
        self.assertEqual(my_as, 65001)
        # 10 fixed bytes, then the 255/255 markers and the 2-byte length.
        self.assertEqual(opt_start, HDR_LEN + 13)
        self.assertEqual(opt_end, HDR_LEN + 13 + len(optparams))
        self.assertEqual(opt_end, len(msg))

    def test_rfc9072_allow_ext_clear_reproduces_one_byte_reading(self):
        # The dissector passes allow_ext=0, and must keep reading these bytes
        # the way it always has: a one-octet length of 255, parameters
        # starting immediately after it.
        optparams = _bgp_cap(2, _std_caps())
        msg = _open_ext(optparams)
        rc, _, _, _, _, opt_start, opt_end = bc.open_fixed(msg, 0, HDR_LEN)
        self.assertEqual(rc, 0)
        self.assertEqual(opt_start, HDR_LEN + 10)
        self.assertEqual(opt_end, HDR_LEN + 10 + 255)
        # The declared block overruns the message, which is how a caller
        # detects it: 255 bytes claimed, far fewer present.
        self.assertGreater(opt_end, len(msg))
        # And the two settings really do differ on the same bytes.
        ext = bc.open_fixed(msg, 1, HDR_LEN)
        self.assertNotEqual(ext[5], opt_start)
        self.assertNotEqual(ext[6], opt_end)

    def test_allow_ext_ignores_a_zero_non_ext_length(self):
        # RFC 9072: the Non-Ext OP Len. "MUST NOT be set to 0", so a zero is
        # taken at face value and no type octet is inspected -- even if the
        # byte that follows happens to be 255.
        body = (bytes([4]) + struct.pack('!H', 65001) +
                struct.pack('!H', 180) + _ip4('1.1.1.1') + bytes([0, 255]))
        msg = _bgp_msg(1, body)
        for allow_ext in (0, 1):
            rc, _, _, _, _, opt_start, opt_end = \
                bc.open_fixed(msg, allow_ext, HDR_LEN)
            self.assertEqual(rc, 0)
            self.assertEqual(opt_start, HDR_LEN + 10)
            self.assertEqual(opt_end, opt_start)

    def test_allow_ext_with_only_one_length_byte_present(self):
        # Extended markers present but the two-octet length is cut off: the
        # extended reading is not available, so the non-extended one stands.
        body = (bytes([4]) + struct.pack('!H', 65001) +
                struct.pack('!H', 180) + _ip4('1.1.1.1') +
                bytes([255, 255, 0]))
        msg = _bgp_msg(1, body)
        rc, _, _, _, _, opt_start, opt_end = bc.open_fixed(msg, 1, HDR_LEN)
        self.assertEqual(rc, 0)
        self.assertEqual(opt_start, HDR_LEN + 10)
        self.assertEqual(opt_end, HDR_LEN + 10 + 255)

    def test_every_truncation_of_the_fixed_part_fails(self):
        msg = _bgp_open(caps=_std_caps())
        for n in range(HDR_LEN, HDR_LEN + 10):
            for allow_ext in (0, 1):
                self.assertEqual(
                    bc.open_fixed(msg[:n], allow_ext, HDR_LEN)[0], -1,
                    'accepted a %d-byte OPEN body' % (n - HDR_LEN))
        self.assertEqual(bc.open_fixed(msg[:HDR_LEN + 10], 0, HDR_LEN)[0], 0)

    def test_matches_the_dissector_on_the_same_bytes(self):
        msg = _bgp_open(myas=65001, holdtime=180, ident='1.1.1.1',
                        caps=_std_caps())
        pkt = BGP(msg)
        _, ver, my_as, hold, _, opt_start, opt_end = \
            bc.open_fixed(msg, 0, HDR_LEN)
        self.assertEqual(pkt.get_field_val('bgp.open.version'), ver)
        self.assertEqual(pkt.get_field_val('bgp.open.myas'), my_as)
        self.assertEqual(pkt.get_field_val('bgp.open.holdtime'), hold)
        # bgp.open.opt.len is the declared length, which is exactly what
        # opt_end - opt_start carries.
        self.assertEqual(pkt.get_field_val('bgp.open.opt.len'),
                         opt_end - opt_start)


class BGPCoreCapTestCase(unittest.TestCase):

    def setUp(self):
        self.caps = _std_caps()
        self.msg = _bgp_open(caps=self.caps)
        _, _, _, _, _, opt_start, opt_end = bc.open_fixed(self.msg, 0,
                                                          HDR_LEN)
        # The single optional parameter is type 2 (Capability): skip its
        # 2-byte TLV header to reach the capabilities themselves.
        self.cap_start = opt_start + 2
        self.cap_end = opt_end

    def test_three_capabilities_with_correct_spans(self):
        got = bc.iter_caps(self.msg, self.cap_start, self.cap_end)
        self.assertEqual([c[0] for c in got], [1, 65, 69])
        for code, vs, ve in got:
            self.assertEqual(ve - vs, self.msg[vs - 1])   # declared length
            self.assertEqual(self.msg[vs - 2], code)
        # MP: AFI 1, reserved, SAFI 1.
        _, vs, ve = got[0]
        self.assertEqual(ve - vs, 4)
        self.assertEqual(struct.unpack('!H', self.msg[vs:vs + 2])[0], 1)
        self.assertEqual(self.msg[vs + 3], 1)
        # 4-octet AS.
        _, vs, ve = got[1]
        self.assertEqual(struct.unpack('!I', self.msg[vs:ve])[0], 65001)
        # Add-path: AFI 1, SAFI 1, Send/Receive 3 (Both).
        _, vs, ve = got[2]
        self.assertEqual(self.msg[vs + 3], 3)

    def test_zero_length_capability(self):
        # Route refresh (2) carries no value at all.
        caps = _bgp_cap(2, b'') + _bgp_cap(65, struct.pack('!I', 65001))
        msg = _bgp_open(caps=caps)
        _, _, _, _, _, opt_start, opt_end = bc.open_fixed(msg, 0, HDR_LEN)
        got = bc.iter_caps(msg, opt_start + 2, opt_end)
        self.assertEqual([c[0] for c in got], [2, 65])
        self.assertEqual(got[0][1], got[0][2])

    def test_declared_length_overruns_the_block(self):
        # A capability claiming 200 bytes inside a 4-byte block: the declared
        # end is reported, iteration stops, and nothing reads out of range.
        blob = bytes([69, 200]) + b'\x00\x02'
        got = bc.iter_caps(blob, 0, len(blob))
        self.assertEqual(len(got), 1)
        code, vs, ve = got[0]
        self.assertEqual(code, 69)
        self.assertEqual(vs, 2)
        self.assertEqual(ve, 202)                 # the claim, not the buffer
        self.assertGreater(ve, len(blob))

    def test_truncation_at_every_boundary(self):
        for n in range(self.cap_start, self.cap_end + 1):
            got = bc.iter_caps(self.msg[:n], self.cap_start, n)
            self.assertLessEqual(len(got), 3)
        self.assertEqual(bc.iter_caps(self.msg, self.cap_start,
                                      self.cap_start), [])
        self.assertEqual(bc.iter_caps(self.msg, self.cap_start,
                                      self.cap_start + 1), [])

    def test_empty_and_degenerate_ranges(self):
        self.assertEqual(bc.iter_caps(b''), [])
        self.assertEqual(bc.iter_caps(self.msg, 5, 5), [])
        self.assertEqual(bc.iter_caps(self.msg, -1, 10), [])
        self.assertEqual(bc.iter_caps(self.msg, 10, 5), [])


class BGPCoreAttrTestCase(unittest.TestCase):

    def setUp(self):
        self.msg = _bgp_std_update()
        (_, _, self.astart, self.aend, _) = _update_offsets(self.msg)

    def test_six_attributes_of_the_standard_update(self):
        got = bc.iter_attrs(self.msg, self.astart, self.aend)
        self.assertEqual([(f, t) for f, t, _, _ in got],
                         [(0x40, 1), (0x40, 2), (0x40, 3), (0x80, 4),
                          (0x40, 5), (0xC0, 8)])
        # Every value span is the declared length, and none uses the extended
        # form, so each value starts 3 bytes past its attribute.
        for flags, atype, vs, ve in got:
            self.assertEqual(self.msg[vs - 1], ve - vs)
            self.assertEqual(flags & 0x10, 0)
        # ORIGIN = IGP, NEXT_HOP = 9.9.9.9, MED = 100, LOCAL_PREF = 200.
        self.assertEqual(self.msg[got[0][2]], 0)
        self.assertEqual(self.msg[got[2][2]:got[2][3]], _ip4('9.9.9.9'))
        self.assertEqual(struct.unpack('!I',
                                       self.msg[got[3][2]:got[3][3]])[0], 100)
        self.assertEqual(struct.unpack('!I',
                                       self.msg[got[4][2]:got[4][3]])[0], 200)

    def test_extended_length_attribute(self):
        # Flags 0x50 sets the extended-length bit, so the length is 2 bytes
        # and the value starts 4 bytes in rather than 3.
        value = b'\x00' * 300
        attr = bytes([0x50, 14]) + struct.pack('!H', len(value)) + value
        got = bc.iter_attrs(attr, 0, len(attr))
        self.assertEqual(len(got), 1)
        flags, atype, vs, ve = got[0]
        self.assertEqual((flags, atype), (0x50, 14))
        self.assertEqual(vs, 4)
        self.assertEqual(ve - vs, 300)
        self.assertEqual(ve, len(attr))

    def test_extended_and_plain_attributes_interleaved(self):
        attrs = (_bgp_pa(0x40, 1, bytes([0])) +
                 bytes([0x50, 8]) + struct.pack('!H', 8) + b'\x00' * 8 +
                 _bgp_pa(0x40, 5, struct.pack('!I', 200)))
        got = bc.iter_attrs(attrs, 0, len(attrs))
        self.assertEqual([t for _, t, _, _ in got], [1, 8, 5])
        self.assertEqual(got[1][2] - 4, 4)          # extended value offset
        self.assertEqual(got[2][3], len(attrs))

    def test_zero_length_attribute(self):
        # ATOMIC_AGGREGATE (6) is defined as a zero-length attribute.
        attrs = _bgp_pa(0x40, 6, b'') + _bgp_pa(0x40, 1, bytes([0]))
        got = bc.iter_attrs(attrs, 0, len(attrs))
        self.assertEqual([t for _, t, _, _ in got], [6, 1])
        self.assertEqual(got[0][2], got[0][3])

    def test_extended_bit_set_but_length_truncated(self):
        # Extended length needs 4 header bytes; only 3 are present.
        self.assertEqual(bc.iter_attrs(bytes([0x50, 14, 0]), 0, 3), [])

    def test_declared_length_runs_past_the_block(self):
        attr = bytes([0x40, 3, 40]) + _ip4('9.9.9.9')
        got = bc.iter_attrs(attr, 0, len(attr))
        self.assertEqual(len(got), 1)
        _, _, vs, ve = got[0]
        self.assertEqual(vs, 3)
        self.assertEqual(ve, 43)                  # the claim
        self.assertGreater(ve, len(attr))

    def test_truncation_at_every_boundary(self):
        full = bc.iter_attrs(self.msg, self.astart, self.aend)
        for n in range(self.astart, self.aend + 1):
            got = bc.iter_attrs(self.msg[:n], self.astart, n)
            self.assertLessEqual(len(got), len(full))
            # Whatever survives truncation must agree with the full parse.
            for i, tup in enumerate(got):
                self.assertEqual(tup[0], full[i][0])
                self.assertEqual(tup[1], full[i][1])
                self.assertEqual(tup[2], full[i][2])

    def test_empty_and_degenerate_ranges(self):
        self.assertEqual(bc.iter_attrs(b''), [])
        self.assertEqual(bc.iter_attrs(self.msg, self.astart, self.astart),
                         [])
        self.assertEqual(bc.iter_attrs(self.msg, -3, self.aend), [])

    def test_matches_the_dissector_attribute_count(self):
        pkt = BGP(self.msg)
        got = bc.iter_attrs(self.msg, self.astart, self.aend)
        self.assertEqual(len(pkt.params), len(got))
        for param, (_, _, vs, ve) in zip(pkt.params, got):
            self.assertEqual(
                param.get_field_val(
                    'bgp.update.path_attribute.length'), ve - vs)


class BGPCoreNlriTestCase(unittest.TestCase):

    def test_ipv4_run(self):
        # 10.0.0.0/8, 172.16.0.0/12, 192.0.2.0/24, 0.0.0.0/0.
        nlri = (bytes([8, 10]) + bytes([12, 172, 16]) +
                bytes([24, 192, 0, 2]) + bytes([0]))
        got = bc.iter_nlri(nlri, 0, len(nlri))
        self.assertEqual([(p, pl) for p, pl, _ in got],
                         [(0, 8), (0, 12), (0, 24), (0, 0)])
        self.assertEqual([a for _, _, a in got], [1, 3, 6, 10])
        # The /0 default route consumes no address bytes at all.
        self.assertEqual(got[3][2], len(nlri))

    def test_default_route_only(self):
        got = bc.iter_nlri(bytes([0]), 0, 1)
        self.assertEqual(got, [(0, 0, 1)])

    def test_ipv6_needs_max_addr_bytes_16(self):
        # A /64 and a /128 -- 8 and 16 address bytes.
        nlri = (bytes([64]) + b'\x20\x01\x0d\xb8\x00\x00\x00\x00' +
                bytes([128]) + b'\x20\x01\x0d\xb8' + b'\x00' * 11 + b'\x01')
        self.assertEqual(bc.iter_nlri(nlri, 0, len(nlri), 0, 4), [])
        got = bc.iter_nlri(nlri, 0, len(nlri), 0, 16)
        self.assertEqual([pl for _, pl, _ in got], [64, 128])
        self.assertEqual([a for _, _, a in got], [1, 10])

    def test_ipv4_width_rejects_a_prefix_that_is_too_wide(self):
        # /40 needs 5 address bytes, which the dissector's IPv4-only reader
        # has always refused; the run stops there rather than resyncing.
        nlri = bytes([8, 10]) + bytes([40]) + b'\x01\x02\x03\x04\x05'
        got = bc.iter_nlri(nlri, 0, len(nlri), 0, 4)
        self.assertEqual([pl for _, pl, _ in got], [8])

    def test_add_path_identifiers(self):
        nlri = (struct.pack('!I', 7) + bytes([8, 10]) +
                struct.pack('!I', 9) + bytes([24, 192, 0, 2]))
        got = bc.iter_nlri(nlri, 0, len(nlri), 1, 4)
        self.assertEqual([(p, pl) for p, pl, _ in got], [(7, 8), (9, 24)])
        self.assertEqual([a for _, _, a in got], [5, 11])
        # Without the flag the same bytes read as garbage prefixes, which is
        # why add-path has to be negotiated and cannot be guessed.
        self.assertNotEqual(bc.iter_nlri(nlri, 0, len(nlri), 0, 4), got)

    def test_add_path_with_fewer_than_four_bytes_left(self):
        nlri = struct.pack('!I', 7) + bytes([8, 10]) + b'\x00\x00'
        got = bc.iter_nlri(nlri, 0, len(nlri), 1, 4)
        self.assertEqual([(p, pl) for p, pl, _ in got], [(7, 8)])

    def test_path_id_is_zero_without_add_path(self):
        for path_id, _, _ in bc.iter_nlri(bytes([8, 10]), 0, 2, 0, 4):
            self.assertEqual(path_id, 0)

    def test_truncated_address_bytes(self):
        # /24 claims 3 address bytes but only 2 remain.
        self.assertEqual(bc.iter_nlri(bytes([24, 192, 0]), 0, 3), [])

    def test_truncation_at_every_boundary(self):
        nlri = bytes([8, 10]) + bytes([24, 192, 0, 2]) + bytes([0])
        full = bc.iter_nlri(nlri, 0, len(nlri))
        for n in range(0, len(nlri) + 1):
            got = bc.iter_nlri(nlri[:n], 0, n)
            self.assertEqual(got, full[:len(got)])

    def test_empty_and_degenerate_ranges(self):
        self.assertEqual(bc.iter_nlri(b''), [])
        self.assertEqual(bc.iter_nlri(bytes([8, 10]), 2, 2), [])
        self.assertEqual(bc.iter_nlri(bytes([8, 10]), -1, 2), [])
        self.assertEqual(bc.iter_nlri(bytes([8, 10]), 5, 2), [])

    def test_matches_the_dissector_on_the_standard_update(self):
        msg = _bgp_std_update()
        (_, _, _, aend, end) = _update_offsets(msg)
        got = bc.iter_nlri(msg, aend, end, 0, 4)
        pkt = BGP(msg)
        self.assertEqual(len(got), 1)
        self.assertEqual(pkt.get_field_val('bgp.prefix_length'), got[0][1])
        self.assertEqual(pkt.get_field_val('bgp.nlri_prefix'), '10.0.0.0')


class BGPCoreAsPathTestCase(unittest.TestCase):

    def test_two_byte_asns(self):
        # AS_SEQUENCE of 3, then AS_SET of 2.
        value = (bytes([2, 3]) + struct.pack('!HHH', 65010, 65020, 65030) +
                 bytes([1, 2]) + struct.pack('!HH', 65040, 65050))
        got = bc.iter_aspath(value, 0, len(value), 0)
        self.assertEqual([(t, c) for t, c, _ in got], [(2, 3), (1, 2)])
        self.assertEqual([a for _, _, a in got], [2, 10])
        t, c, a = got[0]
        self.assertEqual(struct.unpack('!H', value[a:a + 2])[0], 65010)

    def test_four_byte_asns(self):
        value = bytes([2, 2]) + struct.pack('!II', 4200000000, 65010)
        got = bc.iter_aspath(value, 0, len(value), 1)
        self.assertEqual([(t, c) for t, c, _ in got], [(2, 2)])
        a = got[0][2]
        self.assertEqual(struct.unpack('!I', value[a:a + 4])[0], 4200000000)

    def test_stride_changes_the_segmentation(self):
        # The same bytes read with the wrong stride give a different walk,
        # which is why as4 comes from the session and not from the segment.
        value = bytes([2, 2]) + struct.pack('!HH', 65010, 65020) + \
            bytes([2, 1]) + struct.pack('!H', 65030)
        self.assertEqual(len(bc.iter_aspath(value, 0, len(value), 0)), 2)
        self.assertEqual(len(bc.iter_aspath(value, 0, len(value), 1)), 1)

    def test_zero_count_segment(self):
        value = bytes([2, 0]) + bytes([2, 1]) + struct.pack('!H', 65010)
        got = bc.iter_aspath(value, 0, len(value), 0)
        self.assertEqual([(t, c) for t, c, _ in got], [(2, 0), (2, 1)])

    def test_count_claims_more_asns_than_present(self):
        value = bytes([2, 9]) + struct.pack('!H', 65010)
        got = bc.iter_aspath(value, 0, len(value), 0)
        self.assertEqual(len(got), 1)
        seg_type, count, asn_start = got[0]
        self.assertEqual((seg_type, count), (2, 9))
        self.assertEqual(asn_start, 2)

    def test_truncation_at_every_boundary(self):
        value = bytes([2, 2]) + struct.pack('!HH', 65010, 65020)
        for n in range(0, len(value) + 1):
            got = bc.iter_aspath(value[:n], 0, n, 0)
            self.assertLessEqual(len(got), 1)
        self.assertEqual(bc.iter_aspath(value[:1], 0, 1, 0), [])

    def test_empty_and_degenerate_ranges(self):
        self.assertEqual(bc.iter_aspath(b''), [])
        self.assertEqual(bc.iter_aspath(bytes([2, 1, 0, 1]), 4, 4), [])
        self.assertEqual(bc.iter_aspath(bytes([2, 1, 0, 1]), -2, 4), [])

    def test_matches_the_dissector_first_segment(self):
        msg = _bgp_std_update()
        (_, _, astart, aend, _) = _update_offsets(msg)
        attrs = bc.iter_attrs(msg, astart, aend)
        as_path = [a for a in attrs if a[1] == 2][0]
        got = bc.iter_aspath(msg, as_path[2], as_path[3], 0)
        pkt = BGP(msg)
        self.assertEqual(
            pkt.get_field_val(
                'bgp.update.path_attribute.as_path_segment.length'),
            got[0][1])
        self.assertEqual(
            pkt.get_field_val(
                'bgp.update.path_attribute.as_path_segment.as2'),
            struct.unpack('!H', msg[got[0][2]:got[0][2] + 2])[0])


class BGPCoreMpNlriTestCase(unittest.TestCase):

    def test_mp_reach_ipv6_unicast(self):
        value = _mp_reach_v6()
        rc, afi, safi, nh_start, nh_end, nlri_start = \
            bc.mp_reach_hdr(value, 0, len(value))
        self.assertEqual(rc, 0)
        self.assertEqual((afi, safi), (2, 1))
        self.assertEqual(nh_end - nh_start, 16)
        self.assertEqual(value[nh_start:nh_end],
                         b'\x20\x01\x0d\xb8' + b'\x00' * 12)
        # One reserved octet sits between the next hop and the NLRI.
        self.assertEqual(nlri_start, nh_end + 1)
        nlri = bc.iter_nlri(value, nlri_start, len(value), 0, 16)
        self.assertEqual([pl for _, pl, _ in nlri], [64])

    def test_mp_reach_link_local_next_hop(self):
        # A 32-byte next hop: global plus link-local, as RFC 2545 allows.
        nh = b'\x20\x01\x0d\xb8' + b'\x00' * 12 + b'\xfe\x80' + b'\x00' * 14
        value = _mp_reach_v6(nh=nh)
        _, _, _, nh_start, nh_end, _ = bc.mp_reach_hdr(value, 0, len(value))
        self.assertEqual(nh_end - nh_start, 32)

    def test_mp_reach_zero_length_next_hop(self):
        value = struct.pack('!H', 2) + bytes([1, 0]) + bytes([0])
        rc, afi, safi, nh_start, nh_end, nlri_start = \
            bc.mp_reach_hdr(value, 0, len(value))
        self.assertEqual(rc, 0)
        self.assertEqual(nh_start, nh_end)
        self.assertEqual(nlri_start, len(value))

    def test_mp_reach_afi_safi_survive_a_missing_next_hop(self):
        # Truncated right after AFI/SAFI: the pair is still reported, which
        # is what the dissector has always shown, and the spans say -1.
        value = struct.pack('!H', 2) + bytes([1])
        rc, afi, safi, nh_start, nh_end, nlri_start = \
            bc.mp_reach_hdr(value, 0, len(value))
        self.assertEqual(rc, 0)
        self.assertEqual((afi, safi), (2, 1))
        self.assertEqual((nh_start, nh_end, nlri_start), (-1, -1, -1))

    def test_mp_reach_next_hop_length_overruns(self):
        value = struct.pack('!H', 2) + bytes([1, 16]) + b'\x20\x01'
        rc, _, _, nh_start, nh_end, nlri_start = \
            bc.mp_reach_hdr(value, 0, len(value))
        self.assertEqual(rc, 0)
        self.assertEqual((nh_start, nh_end, nlri_start), (-1, -1, -1))

    def test_mp_reach_truncation_at_every_boundary(self):
        value = _mp_reach_v6()
        for n in range(0, len(value) + 1):
            rc, _, _, nh_start, _, _ = bc.mp_reach_hdr(value[:n], 0, n)
            if n < 3:
                self.assertEqual(rc, -1)
            else:
                self.assertEqual(rc, 0)
            if nh_start >= 0:
                self.assertGreaterEqual(n, 20)

    def test_mp_unreach(self):
        value = struct.pack('!H', 2) + bytes([1]) + bytes([64]) + \
            b'\x20\x01\x0d\xb8\x00\x00\x00\x00'
        rc, afi, safi, nlri_start = bc.mp_unreach_hdr(value, 0, len(value))
        self.assertEqual(rc, 0)
        self.assertEqual((afi, safi), (2, 1))
        self.assertEqual(nlri_start, 3)
        got = bc.iter_nlri(value, nlri_start, len(value), 0, 16)
        self.assertEqual([pl for _, pl, _ in got], [64])

    def test_mp_unreach_truncation(self):
        value = struct.pack('!H', 2) + bytes([1])
        for n in range(0, 3):
            rc, _, _, nlri_start = bc.mp_unreach_hdr(value[:n], 0, n)
            self.assertEqual(rc, -1)
            self.assertEqual(nlri_start, -1)
        self.assertEqual(bc.mp_unreach_hdr(value, 0, 3)[0], 0)

    def test_mp_headers_inside_a_real_attribute(self):
        attrs = _bgp_pa(0x80, 14, _mp_reach_v6())
        got = bc.iter_attrs(attrs, 0, len(attrs))
        self.assertEqual(len(got), 1)
        _, atype, vs, ve = got[0]
        self.assertEqual(atype, 14)
        rc, afi, safi, _, _, _ = bc.mp_reach_hdr(attrs, vs, ve)
        self.assertEqual((rc, afi, safi), (0, 2, 1))

    def test_empty_and_degenerate_ranges(self):
        self.assertEqual(bc.mp_reach_hdr(b'')[0], -1)
        self.assertEqual(bc.mp_unreach_hdr(b'')[0], -1)
        self.assertEqual(bc.mp_reach_hdr(b'\x00' * 8, -1, 8)[0], -1)
        self.assertEqual(bc.mp_unreach_hdr(b'\x00' * 8, 9, 8)[0], -1)


class BGPCoreScanTestCase(unittest.TestCase):

    def test_counts_one_update(self):
        msg = _bgp_std_update()
        self.assertEqual(bc.scan_updates(msg), (1, 6, 1, 0))

    def test_counts_a_stream(self):
        stream = (_bgp_keepalive() + _bgp_std_update() + _bgp_keepalive() +
                  _bgp_std_update())
        messages, attributes, prefixes, withdrawn = bc.scan_updates(stream)
        self.assertEqual(messages, 4)
        self.assertEqual(attributes, 12)
        self.assertEqual(prefixes, 2)
        self.assertEqual(withdrawn, 0)

    def test_counts_withdrawn_routes(self):
        msg = _bgp_update(withdrawn=bytes([8, 10]) + bytes([16, 172, 16]))
        messages, attributes, prefixes, withdrawn = bc.scan_updates(msg)
        self.assertEqual((messages, attributes, prefixes, withdrawn),
                         (1, 0, 0, 2))

    def test_stops_on_a_length_that_overruns(self):
        msg = BGP_MARKER + struct.pack('!H', 4096) + bytes([2])
        self.assertEqual(bc.scan_updates(msg), (0, 0, 0, 0))

    def test_stops_on_a_length_below_the_minimum(self):
        msg = BGP_MARKER + struct.pack('!H', 4) + bytes([4]) + b'\x00' * 40
        self.assertEqual(bc.scan_updates(msg), (0, 0, 0, 0))

    def test_empty_buffer(self):
        self.assertEqual(bc.scan_updates(b''), (0, 0, 0, 0))

    def test_add_path_counts_prefixes_behind_their_path_ids(self):
        # C-4: add_path=1 used to be run only for not crashing. One
        # withdrawn and two announced prefixes, each behind a 4-byte RFC
        # 7911 path identifier.
        pid = struct.pack('!I', 7)
        msg = _bgp_update(withdrawn=pid + bytes([8, 10]),
                          attrs=_bgp_pa(0x40, 1, bytes([0])),
                          nlri=(pid + bytes([16, 172, 16]) +
                                struct.pack('!I', 8) + bytes([24, 192, 0, 2])))
        self.assertEqual(bc.scan_updates(msg, 1), (1, 1, 2, 1))
        # Read without add-path the identifiers' bytes become prefix
        # lengths, and the counts are wrong in exactly that way.
        self.assertEqual(bc.scan_updates(msg, 0), (1, 1, 4, 4))

    def test_agrees_with_the_dissector_on_the_chain(self):
        stream = _bgp_std_update() + _bgp_keepalive()
        messages, _, _, _ = bc.scan_updates(stream)
        pkt = BGP(stream)
        chained = 1
        p = pkt.payload
        while isinstance(p, BGP):
            chained += 1
            p = p.payload
        self.assertEqual(messages, chained)


class BGPCoreNeverRaiseTestCase(unittest.TestCase):
    """The never-raise contract, asserted as a property rather than assumed.

    Every primitive is called over every prefix of a set of sample buffers,
    and at offsets inside, at, and beyond the end -- including negative ones.
    Any exception fails the test; the primitives have no exception path at
    all, so one appearing would mean the nogil contract had been broken.
    """

    def _samples(self):
        yield b''
        yield b'\x00'
        yield b'\xff' * 19
        yield _bgp_keepalive()
        yield _bgp_open(caps=_std_caps())
        yield _open_ext(_bgp_cap(2, _std_caps()))
        yield _bgp_std_update()
        yield _bgp_update(withdrawn=bytes([8, 10]),
                          attrs=_bgp_pa(0x80, 14, _mp_reach_v6()),
                          nlri=bytes([24, 192, 0, 2]))
        yield _bgp_msg(2, b'\xff' * 40)
        yield bytes(range(256))

    def _offsets(self, n):
        return (-9, -1, 0, 1, 2, 3, n // 2, max(n - 1, 0), n, n + 1, n + 97)

    def test_no_primitive_raises_on_any_slice_or_offset(self):
        for sample in self._samples():
            for cut in range(0, len(sample) + 1):
                buf = sample[:cut]
                n = len(buf)
                for s in self._offsets(n):
                    for e in (-1, 0, n, n + 5):
                        bc.msg_header(buf, s, e)
                        bc.open_fixed(buf, 0, s, e)
                        bc.open_fixed(buf, 1, s, e)
                        bc.iter_caps(buf, s, e)
                        bc.iter_attrs(buf, s, e)
                        bc.iter_nlri(buf, s, e, 0, 4)
                        bc.iter_nlri(buf, s, e, 1, 16)
                        bc.iter_aspath(buf, s, e, 0)
                        bc.iter_aspath(buf, s, e, 1)
                        bc.mp_reach_hdr(buf, s, e)
                        bc.mp_unreach_hdr(buf, s, e)
                bc.scan_updates(buf)
                bc.scan_updates(buf, 1, 16)

    def test_iterators_always_terminate_and_stay_in_range(self):
        # An iterator that returned a non-advancing offset would hang, and one
        # that returned an offset past the end would let a caller read out of
        # bounds. Both are checked on adversarial input.
        for sample in self._samples():
            n = len(sample)
            for caps in bc.iter_caps(sample, 0, n):
                self.assertTrue(0 <= caps[1] <= n)
            for attr in bc.iter_attrs(sample, 0, n):
                self.assertTrue(0 <= attr[2] <= n)
            for _, plen, addr in bc.iter_nlri(sample, 0, n, 0, 4):
                self.assertTrue(0 <= addr <= n)
                self.assertTrue(addr + (plen + 7) // 8 <= n)
            for _, plen, addr in bc.iter_nlri(sample, 0, n, 1, 16):
                self.assertTrue(addr + (plen + 7) // 8 <= n)
            for seg in bc.iter_aspath(sample, 0, n, 0):
                self.assertTrue(0 <= seg[2] <= n)

    def test_the_dissector_still_never_raises_on_the_same_samples(self):
        for sample in self._samples():
            for cut in range(0, len(sample) + 1):
                pkt = BGP(sample[:cut])
                # A parsed message always round-trips to its own bytes.
                self.assertEqual(pkt.pkt2net({}), sample[:cut])


if __name__ == '__main__':
    unittest.main()
