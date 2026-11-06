# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Inbound validation: what a malformed or out-of-contract message costs.

Regression tests for the inbound findings of the 2.3 review (report
``packets_rtengine_review_aff61bc.md``), each named in its docstring:

* **L-2** -- an UPDATE that announces only through MP_REACH_NLRI must
  carry ORIGIN and AS_PATH like any other, or its prefixes are withdrawn;
  the decoder used to skip the check and invent the missing attributes;
* **L-3** -- a well-formed MP attribute for a family that was not
  negotiated is ignored, not a session reset any peer can trigger;
* **L-8** -- every message type has its own length rule, and a violation
  draws NOTIFICATION 1/2 carrying the bad length (1/3 and the type for an
  unknown type);
* **W-1** -- AS4_AGGREGATOR only replaces an AGGREGATOR that says AS_TRANS;
* **W-2** -- capability and optional-parameter lengths are range-checked,
  and RFC 9072's extended parameters are read and written correctly;
* **W-4** -- MP_REACH/MP_UNREACH must be optional non-transitive;
* **W-5** -- OPEN grading: 2/1, 2/2, 2/3, 2/4, 2/6 and 2/0;
* **W-6** -- LOCAL_PREF is discretionary, on iBGP too;
* **W-8** -- NLRI host bits are counted rather than silently masked;
* **W-10** -- the Partial bit on a well-known attribute is a flags error,
  and unrecognised attributes are re-advertised in type order;
* **W-11** -- one name for the ``'unparseable'`` reason.

The codec cases build bytes by hand rather than through the encoder, so a
fault in the encoder cannot hide the same fault in the decoder. The
``Live*`` cases drive a real engine with the byte-level speaker in
:mod:`rtengine_rawspeaker`, re-running the cases that reproduced the
findings on cnp02.
"""

import socket
import struct
import unittest

import rtengine_rawspeaker as raw
import test_rtengine_session_notify as notify

from packets.core.inetpkt import BGP
from packets.routing.rtengine.plugins.bgp import errors
from packets.routing.rtengine.plugins.bgp import fsm as fsm_mod
from packets.routing.rtengine.plugins.bgp import peer as peer_mod
from packets.routing.rtengine.plugins.bgp import wire
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, \
    parse_prefix


MARKER = b'\xff' * 16
NEXTHOP = b'\x0a\x00\x00\x01'
BIG_AS = 4200000001
AS_TRANS = 23456
ADD_PATH = 69


def _msg(mtype, body):
    return MARKER + struct.pack('>HB', 19 + len(body), mtype) + body


def _header(length, mtype):
    """A header that lies about its length, and nothing after it."""
    return MARKER + struct.pack('>HB', length, mtype)


def _attr(flags, atype, value):
    if flags & wire.FLAG_EXT_LEN:
        return struct.pack('>BBH', flags, atype, len(value)) + value
    return struct.pack('>BBB', flags, atype, len(value)) + value


def _update(withdrawn=b'', attrs=b'', nlri=b''):
    return _msg(wire.UPDATE,
                struct.pack('>H', len(withdrawn)) + withdrawn +
                struct.pack('>H', len(attrs)) + attrs + nlri)


def _seg(asns, width=4):
    fmt = '>I' if width == 4 else '>H'
    return struct.pack('>BB', 2, len(asns)) + b''.join(
        struct.pack(fmt, a) for a in asns)


def _v6(text):
    return socket.inet_pton(socket.AF_INET6, text)


A_ORIGIN = _attr(0x40, wire.TYPE_ORIGIN, b'\x00')
A_AS_PATH = _attr(0x40, wire.TYPE_AS_PATH, _seg([65001]))
A_NEXT_HOP = _attr(0x40, wire.TYPE_NEXT_HOP, NEXTHOP)
N_10_1 = b'\x10\x0a\x01'
P6 = parse_prefix('2001:db8:500::/48')
N6 = b'\x30' + _v6('2001:db8:500::')[:6]


def _mp_reach(nlri=N6, flags=0x80, afi=AFI_IP6, safi=1,
              nexthop=None):
    if nexthop is None:
        nexthop = _v6('2001:db8::5') if afi == AFI_IP6 else NEXTHOP
    value = (struct.pack('>HBB', afi, safi, len(nexthop)) + nexthop +
             b'\x00' + nlri)
    return _attr(flags, wire.TYPE_MP_REACH, value)


def _mp_unreach(nlri=N6, flags=0x80, afi=AFI_IP6, safi=1):
    return _attr(flags, wire.TYPE_MP_UNREACH,
                 struct.pack('>HB', afi, safi) + nlri)


def _faults(msg):
    return [(e[0], e[1]) for e in msg.errors]


def _judge(msg, from_ebgp=True):
    return errors.worst_outcome(
        errors.attribute_outcome(t, r, from_ebgp=from_ebgp)
        for t, r, _ in msg.errors)


class MpMandatoryTestCase(unittest.TestCase):
    """L-2: MP_REACH-only UPDATEs need ORIGIN and AS_PATH too."""

    def setUp(self):
        self.ctx = wire.DecodeCtx()

    def test_mp_reach_alone_is_missing_origin_and_as_path(self):
        """L-2: the case that installed `origin igp, as-path []` live."""
        msg = wire.decode_update(_update(attrs=_mp_reach()), self.ctx)
        self.assertEqual(sorted(_faults(msg)),
                         [(wire.TYPE_ORIGIN, wire.REASON_MISSING),
                          (wire.TYPE_AS_PATH, wire.REASON_MISSING)])
        self.assertEqual(_judge(msg), errors.OUTCOME_WITHDRAW)
        # Still extracted: treat-as-withdraw needs to know what to withdraw.
        self.assertEqual([p for p, _ in msg.mp_reach[4]], [P6])

    def test_mp_reach_without_as_path_alone(self):
        """L-2: each missing attribute is reported on its own."""
        msg = wire.decode_update(_update(attrs=A_ORIGIN + _mp_reach()),
                                 self.ctx)
        self.assertEqual(_faults(msg),
                         [(wire.TYPE_AS_PATH, wire.REASON_MISSING)])

    def test_mp_reach_never_needs_the_next_hop_attribute(self):
        """L-2: RFC 4760 carries the next hop inside MP_REACH."""
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + _mp_reach()), self.ctx)
        self.assertEqual(msg.errors, [])

    def test_a_withdraw_only_update_needs_nothing(self):
        """L-2: MP_UNREACH alone is legal without any attribute."""
        msg = wire.decode_update(_update(attrs=_mp_unreach()), self.ctx)
        self.assertEqual(msg.errors, [])

    def test_an_mp_reach_that_announces_nothing_needs_nothing(self):
        """L-2: nothing announced, so nothing can be withdrawn."""
        msg = wire.decode_update(_update(attrs=_mp_reach(nlri=b'')),
                                 self.ctx)
        self.assertEqual(msg.errors, [])

    def test_classic_nlri_still_needs_all_three(self):
        msg = wire.decode_update(_update(nlri=N_10_1), self.ctx)
        self.assertEqual(sorted(_faults(msg)),
                         [(wire.TYPE_ORIGIN, wire.REASON_MISSING),
                          (wire.TYPE_AS_PATH, wire.REASON_MISSING),
                          (wire.TYPE_NEXT_HOP, wire.REASON_MISSING)])


class UnnegotiatedFamilyTestCase(unittest.TestCase):
    """L-3: a family nobody negotiated is ignored, never a reset."""

    def test_an_unsupported_family_is_discarded(self):
        """L-3: AFI 1 / SAFI 128 (VPNv4), the live case."""
        nlri = b'\x58' + b'\x00\x00\x01' + b'\x00\x01' + \
            struct.pack('>I', 1) + b'\x0a\x09\x09'
        attrs = A_ORIGIN + A_AS_PATH + _mp_reach(
            nlri=nlri, afi=AFI_IP, safi=128, nexthop=b'\x00' * 8 + NEXTHOP)
        msg = wire.decode_update(_update(attrs=attrs), wire.DecodeCtx())
        self.assertEqual(_faults(msg),
                         [(wire.TYPE_MP_REACH, wire.REASON_UNNEGOTIATED)])
        self.assertIsNone(msg.mp_reach)
        self.assertEqual(_judge(msg), errors.OUTCOME_DISCARD)

    def test_an_unsupported_family_in_mp_unreach_is_discarded(self):
        msg = wire.decode_update(
            _update(attrs=_mp_unreach(nlri=b'', afi=AFI_IP, safi=128)),
            wire.DecodeCtx())
        self.assertEqual(_faults(msg),
                         [(wire.TYPE_MP_UNREACH, wire.REASON_UNNEGOTIATED)])
        self.assertEqual(_judge(msg), errors.OUTCOME_DISCARD)

    def test_a_supported_family_the_session_did_not_negotiate(self):
        """L-3: IPv6 unicast on an IPv4-only session is ignored."""
        ctx = wire.DecodeCtx(families=[(AFI_IP, 1)])
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + _mp_reach()), ctx)
        self.assertEqual(_faults(msg),
                         [(wire.TYPE_MP_REACH, wire.REASON_UNNEGOTIATED)])
        self.assertIsNone(msg.mp_reach)
        self.assertEqual(ctx.families, frozenset([(AFI_IP, 1)]))

    def test_a_negotiated_family_is_decoded(self):
        ctx = wire.DecodeCtx(families=[(AFI_IP, 1), (AFI_IP6, 1)])
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + _mp_reach()), ctx)
        self.assertEqual(msg.errors, [])
        self.assertEqual([p for p, _ in msg.mp_reach[4]], [P6])

    def test_an_unparseable_mp_reach_still_resets(self):
        """L-3: RESET stays for MP attributes whose NLRI is unreadable."""
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + _mp_reach(nlri=b'\x30\x20')),
            wire.DecodeCtx())
        self.assertEqual(_faults(msg),
                         [(wire.TYPE_MP_REACH, wire.REASON_UNPARSEABLE)])
        self.assertEqual(_judge(msg), errors.OUTCOME_RESET)

    def test_the_matrix_discards_both_mp_attributes(self):
        for atype in (wire.TYPE_MP_REACH, wire.TYPE_MP_UNREACH):
            self.assertEqual(
                errors.attribute_outcome(atype, errors.REASON_UNNEGOTIATED),
                errors.OUTCOME_DISCARD)


class MessageLengthTestCase(unittest.TestCase):
    """L-8: per-type length rules (RFC 4271 s6.1, RFC 8654)."""

    def _fault(self, data, max_msg=wire.MAX_MSG):
        framer = wire.Framer(max_msg)
        framer.feed(data)
        self.assertIsNone(framer.next_message())
        return framer.error_code, framer.error_subcode, framer.error_data

    def test_a_twenty_byte_keepalive_is_bad_length(self):
        """L-8: the live case, which used to be accepted."""
        self.assertEqual(self._fault(_header(20, wire.KEEPALIVE)),
                         (1, 2, b'\x00\x14'))

    def test_an_open_below_29_bytes_is_bad_length(self):
        self.assertEqual(self._fault(_header(28, wire.OPEN)),
                         (1, 2, b'\x00\x1c'))

    def test_an_open_above_4096_is_bad_length_even_with_extended(self):
        """L-8: RFC 8654 never lets an OPEN past 4096."""
        self.assertEqual(self._fault(_header(4097, wire.OPEN), 65535),
                         (1, 2, b'\x10\x01'))

    def test_short_update_notification_and_route_refresh(self):
        self.assertEqual(self._fault(_header(22, wire.UPDATE)),
                         (1, 2, b'\x00\x16'))
        self.assertEqual(self._fault(_header(20, wire.NOTIFICATION)),
                         (1, 2, b'\x00\x14'))
        self.assertEqual(self._fault(_header(22, wire.ROUTE_REFRESH)),
                         (1, 2, b'\x00\x16'))

    def test_a_length_outside_the_session_range_carries_the_length(self):
        self.assertEqual(self._fault(_header(5000, wire.UPDATE)),
                         (1, 2, b'\x13\x88'))

    def test_an_unknown_type_carries_the_type(self):
        self.assertEqual(self._fault(_header(19, 9)), (1, 3, b'\x09'))

    def test_the_shortest_legal_messages_pass(self):
        framer = wire.Framer()
        data = (_msg(wire.KEEPALIVE, b'') +
                _msg(wire.NOTIFICATION, b'\x06\x02') +
                _msg(wire.UPDATE, b'\x00\x00\x00\x00') +
                _msg(wire.ROUTE_REFRESH, b'\x00\x01\x00\x01'))
        framer.feed(data)
        self.assertEqual([t for t, _ in framer.messages_available()],
                         [wire.KEEPALIVE, wire.NOTIFICATION, wire.UPDATE,
                          wire.ROUTE_REFRESH])
        self.assertFalse(framer.failed)
        self.assertIsNone(framer.error_data)

    def test_the_length_is_judged_before_the_body_arrives(self):
        """L-8: a bad header is answered without waiting for its body."""
        framer = wire.Framer()
        framer.feed(_header(200, wire.KEEPALIVE))
        framer.next_message()
        self.assertTrue(framer.failed)


class As4AggregatorTestCase(unittest.TestCase):
    """W-1: RFC 6793 s4.2.3 on a two-octet session."""

    ADDR = b'\x0a\x00\x00\x09'

    def setUp(self):
        self.ctx = wire.DecodeCtx(as4=False)
        self.path = _attr(0x40, wire.TYPE_AS_PATH,
                          _seg([65001, AS_TRANS], width=2))
        self.as4_path = _attr(0xc0, wire.TYPE_AS4_PATH,
                              _seg([65001, BIG_AS]))
        self.as4_agg = _attr(0xc0, wire.TYPE_AS4_AGGREGATOR,
                             struct.pack('>I', BIG_AS) + self.ADDR)

    def _decode(self, *attrs):
        return wire.decode_update(
            _update(attrs=A_ORIGIN + A_NEXT_HOP + b''.join(attrs),
                    nlri=N_10_1), self.ctx)

    def _aggregator(self, asn):
        return _attr(0xc0, wire.TYPE_AGGREGATOR,
                     struct.pack('>H', asn) + self.ADDR)

    def test_a_real_aggregator_wins_and_as4_path_is_ignored(self):
        """W-1: AGGREGATOR is not AS_TRANS, so both AS4_* attributes go."""
        plain = self._decode(self.path, self._aggregator(65010))
        msg = self._decode(self.path, self._aggregator(65010),
                           self.as4_path, self.as4_agg)
        self.assertEqual(msg.errors, [])
        self.assertEqual(msg.attrs.aggregator,
                         b'\x00\x00' + struct.pack('>H', 65010) + self.ADDR)
        self.assertEqual(msg.attrs.as_path, plain.attrs.as_path)

    def test_an_as_trans_aggregator_is_replaced(self):
        plain = self._decode(self.path, self._aggregator(AS_TRANS))
        msg = self._decode(self.path, self._aggregator(AS_TRANS),
                           self.as4_path, self.as4_agg)
        self.assertEqual(msg.attrs.aggregator,
                         struct.pack('>I', BIG_AS) + self.ADDR)
        self.assertNotEqual(msg.attrs.as_path, plain.attrs.as_path)

    def test_without_aggregator_the_as4_path_still_merges(self):
        plain = self._decode(self.path)
        msg = self._decode(self.path, self.as4_path)
        self.assertNotEqual(msg.attrs.as_path, plain.attrs.as_path)


class OpenEncodingTestCase(unittest.TestCase):
    """W-2: capability and optional-parameter lengths never wrap."""

    @staticmethod
    def _add_path(count):
        return b''.join(struct.pack('>HBB', 1, 1 + (i % 254), 1)
                        for i in range(count))

    def test_a_capability_that_would_wrap_its_length_raises(self):
        """W-2: a 300-byte capability cannot be encoded classically."""
        with self.assertRaises(ValueError):
            wire.encode_open(65001, 90, '10.0.0.1',
                             [(64, b'\x00' * 300)])

    def test_parameters_over_255_bytes_raise_without_extended(self):
        """W-2: the peer's RFC 9072 support is unknown when OPEN is sent."""
        with self.assertRaises(ValueError):
            wire.encode_open(65001, 90, '10.0.0.1',
                             [(ADD_PATH, self._add_path(70))])

    def test_extended_parameters_round_trip(self):
        """W-2: RFC 9072 framing with 2-byte parameter lengths."""
        caps = [(1, struct.pack('>HBB', 1, 0, safi))
                for safi in range(1, 41)]    # 40 x 8 = 320 bytes
        raw_open = wire.encode_open(65001, 90, '10.0.0.1', caps,
                                    extended=True)
        self.assertEqual(raw_open[28:30], b'\xff\xff')
        msg = wire.decode_open(raw_open)
        self.assertEqual(msg.errors, [])
        self.assertEqual(msg.capabilities, caps)

    def test_extended_is_only_used_when_needed(self):
        """W-2: RFC 9072 s2 -- the classic form whenever it fits."""
        caps = [(1, struct.pack('>HBB', 1, 0, 1))]
        self.assertEqual(
            wire.encode_open(65001, 90, '10.0.0.1', caps, extended=True),
            wire.encode_open(65001, 90, '10.0.0.1', caps))

    def test_add_path_is_never_split_across_instances(self):
        """W-2: RFC 7911 s4 keeps every family in one ADD-PATH instance."""
        with self.assertRaises(ValueError) as caught:
            wire.encode_open(65001, 90, '10.0.0.1',
                             [(ADD_PATH, self._add_path(75))],
                             extended=True)
        self.assertIn('ADD-PATH', str(caught.exception))

    def test_an_oversized_capability_raises_even_extended(self):
        with self.assertRaises(ValueError):
            wire.encode_open(65001, 90, '10.0.0.1', [(64, b'\x00' * 300)],
                             extended=True)

    def test_a_classic_open_near_the_limit_still_dissects(self):
        raw_open = wire.encode_open(65001, 90, '10.0.0.1',
                                    [(ADD_PATH, self._add_path(60))])
        self.assertFalse(BGP(raw_open).malformed)
        self.assertEqual(wire.decode_open(raw_open).errors, [])

    def test_a_peers_extended_open_is_read_with_two_byte_lengths(self):
        """W-2: decode_open used to walk RFC 9072 params as 1-byte TLVs."""
        caps = (struct.pack('>BB', 1, 4) + struct.pack('>HBB', 1, 0, 1) +
                struct.pack('>BB', 65, 4) + struct.pack('>I', BIG_AS))
        params = struct.pack('>BH', 2, len(caps)) + caps
        body = (struct.pack('>BHH', 4, AS_TRANS, 90) + b'\x0a\x00\x00\x01' +
                struct.pack('>BBH', 255, 255, len(params)) + params)
        msg = wire.decode_open(_msg(wire.OPEN, body))
        self.assertEqual(msg.errors, [])
        self.assertEqual([c for c, _ in msg.capabilities], [1, 65])
        self.assertEqual(msg.my_as, BIG_AS)

    def test_a_parameter_that_overruns_is_never_read_past(self):
        """A capability parameter claiming more than the OPEN holds.

        Found while grading OPENs: the capability walk followed the
        parameter's claimed length past the end of the message, and an
        AS4 capability straddling the end read the peer's AS out of
        whatever memory followed. It must be a fault, and nothing past the
        message may be read.
        """
        params = struct.pack('>BB', 2, 40) + b'\x41\x04'
        body = (struct.pack('>BHH', 4, 65005, 90) + b'\x0a\x00\x00\x01' +
                struct.pack('>B', len(params)) + params)
        msg = wire.decode_open(_msg(wire.OPEN, body))
        self.assertNotEqual(msg.errors, [])
        self.assertEqual(msg.capabilities, [])
        self.assertEqual(msg.my_as, 65005)

    def test_a_capability_that_overruns_its_parameter(self):
        caps = struct.pack('>BB', 65, 20) + struct.pack('>I', 65005)
        params = struct.pack('>BB', 2, len(caps)) + caps
        body = (struct.pack('>BHH', 4, 65005, 90) + b'\x0a\x00\x00\x01' +
                struct.pack('>B', len(params)) + params)
        msg = wire.decode_open(_msg(wire.OPEN, body))
        self.assertNotEqual(msg.errors, [])
        self.assertEqual(msg.capabilities, [])


class MpFlagsTestCase(unittest.TestCase):
    """W-4: MP_REACH/MP_UNREACH are optional non-transitive."""

    def test_wrong_mp_reach_flags_are_a_flags_error(self):
        for flags in (0xc0, 0x40):
            msg = wire.decode_update(
                _update(attrs=A_ORIGIN + A_AS_PATH + _mp_reach(flags=flags)),
                wire.DecodeCtx())
            self.assertEqual(_faults(msg),
                             [(wire.TYPE_MP_REACH, wire.REASON_FLAGS)])
            self.assertIsNone(msg.mp_reach)
            self.assertEqual(_judge(msg), errors.OUTCOME_RESET)

    def test_wrong_mp_unreach_flags_are_a_flags_error(self):
        msg = wire.decode_update(_update(attrs=_mp_unreach(flags=0x40)),
                                 wire.DecodeCtx())
        self.assertEqual(_faults(msg),
                         [(wire.TYPE_MP_UNREACH, wire.REASON_FLAGS)])

    def test_the_extended_length_bit_is_fine(self):
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + _mp_reach(flags=0x90)),
            wire.DecodeCtx())
        self.assertEqual(msg.errors, [])


class LocalPrefTestCase(unittest.TestCase):
    """W-6: LOCAL_PREF is well-known discretionary (RFC 4271 s5.1.5)."""

    def test_an_ibgp_update_without_local_pref_is_clean(self):
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + A_NEXT_HOP, nlri=N_10_1),
            wire.DecodeCtx(is_ebgp=False))
        self.assertEqual(msg.errors, [])

    def test_the_mandatory_set_is_the_same_on_both_sides(self):
        mandatory = set([wire.TYPE_ORIGIN, wire.TYPE_AS_PATH,
                         wire.TYPE_NEXT_HOP])
        self.assertEqual(set(errors.mandatory_attributes(False)), mandatory)
        self.assertEqual(set(errors.mandatory_attributes(True)), mandatory)

    def test_a_missing_local_pref_is_not_a_fault(self):
        self.assertEqual(
            errors.attribute_outcome(wire.TYPE_LOCAL_PREF,
                                     errors.REASON_MISSING),
            errors.OUTCOME_OK)


class HostBitsTestCase(unittest.TestCase):
    """W-8: masked NLRI host bits are counted."""

    def test_host_bits_are_masked_and_counted(self):
        # 10.31.0.0/12 on the wire: the low four bits of 0x1f are host bits.
        msg = wire.decode_update(
            _update(withdrawn=b'\x0c\x0a\x1f',
                    attrs=A_ORIGIN + A_AS_PATH + A_NEXT_HOP,
                    nlri=b'\x0c\x0a\x1f' + N_10_1),
            wire.DecodeCtx())
        self.assertEqual(msg.errors, [])
        self.assertEqual([p for p, _ in msg.nlri],
                         [parse_prefix('10.16.0.0/12'),
                          parse_prefix('10.1.0.0/16')])
        self.assertEqual(msg.host_bits, 2)

    def test_mp_nlri_host_bits_are_counted(self):
        nlri = b'\x2c' + _v6('2001:db8:5ff::')[:6]      # /44, 0xff
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + _mp_reach(nlri=nlri)),
            wire.DecodeCtx())
        self.assertEqual(msg.host_bits, 1)

    def test_clean_nlri_counts_nothing(self):
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + A_NEXT_HOP, nlri=N_10_1),
            wire.DecodeCtx())
        self.assertEqual(msg.host_bits, 0)


class PartialAndOrderTestCase(unittest.TestCase):
    """W-10: flags on well-known attributes; attribute order on output."""

    def test_partial_on_a_well_known_attribute_is_a_flags_error(self):
        for atype, value in ((wire.TYPE_ORIGIN, b'\x00'),
                             (wire.TYPE_ATOMIC_AGGREGATE, b'')):
            attrs = _attr(0x60, atype, value)
            if atype != wire.TYPE_ORIGIN:
                attrs = A_ORIGIN + attrs
            msg = wire.decode_update(
                _update(attrs=attrs + A_AS_PATH + A_NEXT_HOP, nlri=N_10_1),
                wire.DecodeCtx())
            self.assertEqual(_faults(msg), [(atype, wire.REASON_FLAGS)])

    def test_partial_on_an_optional_transitive_attribute_is_fine(self):
        comm = _attr(0xe0, wire.TYPE_COMMUNITIES, b'\x00\x01\x00\x02')
        msg = wire.decode_update(
            _update(attrs=A_ORIGIN + A_AS_PATH + A_NEXT_HOP + comm,
                    nlri=N_10_1), wire.DecodeCtx())
        self.assertEqual(msg.errors, [])

    def test_unknown_attributes_are_re_advertised_in_type_order(self):
        attrs = (A_ORIGIN + A_AS_PATH + A_NEXT_HOP +
                 _attr(0xc0, 40, b'xy') +
                 _attr(0xc0, wire.TYPE_COMMUNITIES, b'\x00\x01\x00\x02') +
                 _attr(0xc0, 12, b'ab') +
                 _attr(0xc0, wire.TYPE_LARGE_COMMUNITY, b'\x00' * 12))
        msg = wire.decode_update(_update(attrs=attrs, nlri=N_10_1),
                                 wire.DecodeCtx())
        self.assertEqual(msg.errors, [])
        out = wire.encode_announce([parse_prefix('10.1.0.0/16')],
                                   msg.attrs)[0]
        types = []
        wlen = struct.unpack('>H', out[19:21])[0]
        off = 23 + wlen
        end = off + struct.unpack('>H', out[21 + wlen:23 + wlen])[0]
        while off < end:
            types.append(out[off + 1])
            if out[off] & wire.FLAG_EXT_LEN:
                off += 4 + struct.unpack('>H', out[off + 2:off + 4])[0]
            else:
                off += 3 + out[off + 2]
        self.assertEqual(types, sorted(types))
        self.assertIn(12, types)
        self.assertIn(40, types)


class ReasonNameTestCase(unittest.TestCase):
    """W-11: one name for each reason, in both modules."""

    def test_unparseable_has_one_name(self):
        self.assertEqual(errors.REASON_UNPARSEABLE, wire.REASON_UNPARSEABLE)
        # The old spelling survives one release as an alias.
        self.assertIs(errors.REASON_UNRESOLVABLE, errors.REASON_UNPARSEABLE)

    def test_unnegotiated_is_known_to_both(self):
        self.assertEqual(errors.REASON_UNNEGOTIATED,
                         wire.REASON_UNNEGOTIATED)
        self.assertIn(errors.REASON_UNNEGOTIATED, errors.REASONS)


# --- OPEN grading on a session ----------------------------------------------


def _open(asn, router_id, hold=30, version=4, params=None):
    if params is None:
        caps = (struct.pack('>BB', 1, 4) + struct.pack('>HBB', 1, 0, 1) +
                struct.pack('>BB', 65, 4) + struct.pack('>I', asn))
        params = struct.pack('>BB', 2, len(caps)) + caps
    body = (struct.pack('>BHH', version, asn if asn <= 0xffff else AS_TRANS,
                        hold) +
            socket.inet_aton(router_id) + struct.pack('>B', len(params)) +
            params)
    return _msg(wire.OPEN, body)


class OpenGradingTestCase(notify.BarePeerFixture):
    """W-5: each OPEN fault gets its own NOTIFICATION (RFC 4271 s6.2)."""

    def _notifications(self, raw_open, remote_as=notify.SPEAKER_AS):
        peer = peer_mod.Peer(
            peer_mod.PeerConfig(notify.LOOPBACK, remote_as, notify.ENGINE_AS,
                                '10.0.0.9', passive=True, hold_time=30),
            loop=self.loop)
        conn = notify.FakeConn(self.loop)
        peer.start()
        peer.adopt(conn)
        self.assertEqual(peer.state, fsm_mod.OPEN_SENT)
        peer._handle_open(raw_open)
        # The read loop performs the FSM's actions after each slice of
        # messages; this is that step.
        peer._drain_actions()
        out = []
        for data in conn.written:
            if data[18:19] == b'\x03':
                out.append((bytearray(data)[19], bytearray(data)[20],
                            bytes(data[21:])))
        return out

    def test_an_unsupported_version_names_the_one_we_speak(self):
        self.assertEqual(
            self._notifications(_open(notify.SPEAKER_AS, '10.0.0.5',
                                      version=3)),
            [(2, 1, b'\x00\x04')])

    def test_the_wrong_peer_as(self):
        self.assertEqual(
            self._notifications(_open(65099, '10.0.0.5')),
            [(2, 2, b'')])

    def test_a_zero_bgp_identifier(self):
        self.assertEqual(
            self._notifications(_open(notify.SPEAKER_AS, '0.0.0.0')),
            [(2, 3, b'')])

    def test_our_own_identifier_from_an_internal_peer(self):
        """W-5: RFC 6286 s2.2, iBGP only."""
        self.assertEqual(
            self._notifications(_open(notify.ENGINE_AS, '10.0.0.9'),
                                remote_as=notify.ENGINE_AS),
            [(2, 3, b'')])

    def test_our_own_identifier_from_an_external_peer_is_accepted(self):
        self.assertEqual(
            self._notifications(_open(notify.SPEAKER_AS, '10.0.0.9')), [])

    def test_hold_times_of_one_and_two(self):
        for hold in (1, 2):
            self.assertEqual(
                self._notifications(_open(notify.SPEAKER_AS, '10.0.0.5',
                                          hold=hold)),
                [(2, 6, b'')])

    def test_an_unsupported_optional_parameter(self):
        """W-5: a non-capability parameter used to be accepted silently."""
        caps = struct.pack('>BB', 65, 4) + struct.pack('>I',
                                                      notify.SPEAKER_AS)
        params = (struct.pack('>BB', 1, 2) + b'\x00\x00' +
                  struct.pack('>BB', 2, len(caps)) + caps)
        self.assertEqual(
            self._notifications(_open(notify.SPEAKER_AS, '10.0.0.5',
                                      params=params)),
            [(2, 4, b'')])

    def test_a_malformed_open_is_unspecific(self):
        """W-5: a truncated parameter is not an *unsupported* one."""
        params = struct.pack('>BB', 2, 40) + b'\x41\x04'
        self.assertEqual(
            self._notifications(_open(notify.SPEAKER_AS, '10.0.0.5',
                                      params=params)),
            [(2, 0, b'')])


# --- live, against an engine ------------------------------------------------


def _mp_update(prefix_bytes, plen, mandatory=True):
    value = (struct.pack('!HBB', 2, 1, 16) + _v6('2001:db8::5') + b'\x00' +
             bytes(bytearray([plen])) + prefix_bytes)
    attrs = raw.attr(0x90, 14, value)
    if mandatory:
        attrs = raw.origin_igp() + raw.as_path(notify.SPEAKER_AS) + attrs
    return raw.update(attrs=attrs)


class LiveInboundTestCase(notify.LiveFixture):
    """The raw-speaker cases that reproduced the findings on cnp02."""

    def setUp(self):
        families = {'address-family': {
            'ipv4': {'unicast': {'activate': True}},
            'ipv6': {'unicast': {'activate': True}}}}
        # The instance must carry IPv6 too: activating a family on a
        # neighbour that the instance does not have is a config error
        # (Stage 3), and this fixture was the first thing it caught.
        self.start_engine(hold=30, neighbor_extra=families,
                          instance_extra={'address-family': {
                              'ipv4': {'unicast': {}},
                              'ipv6': {'unicast': {}}}})
        self.s = self.speaker().connect(notify.LOOPBACK, self.listen_port)
        self.s.handshake(hold=30)
        self.wait_state(fsm_mod.ESTABLISHED)

    def _v6_routes(self):
        table = self.session.adj_in.get((AFI_IP6, 1)) or {}
        return set(str(k[0]) for k in list(table))

    def _still_up(self):
        self.s.send(raw.keepalive())
        got = self.s.read(2.5, until=raw.KEEPALIVE)
        kinds = [t for t, _ in got]
        self.assertNotIn(raw.NOTIFICATION, kinds, raw.describe(got))
        self.assertNotIn(raw.EOF, kinds)
        self.assertEqual(self.session.state, fsm_mod.ESTABLISHED)

    def test_mp_no_mandatory_withdraws_instead_of_installing(self):
        """L-2: live case `mp-no-mandatory`."""
        self.s.send(_mp_update(b'\x20\x01\x0d\xb8\x05\x01', 48))
        self.wait_until(lambda: '2001:db8:501::/48' in self._v6_routes(),
                        'the well-formed IPv6 route being learned')
        # The same prefix again without ORIGIN/AS_PATH: treat-as-withdraw.
        self.s.send(_mp_update(b'\x20\x01\x0d\xb8\x05\x01', 48,
                               mandatory=False))
        self.wait_until(
            lambda: '2001:db8:501::/48' not in self._v6_routes(),
            'the route being withdrawn')
        # And a prefix that only ever arrived without them never appears.
        self.s.send(_mp_update(b'\x20\x01\x0d\xb8\x05\x00', 48,
                               mandatory=False))
        self._still_up()
        self.assertNotIn('2001:db8:500::/48', self._v6_routes())

    def test_an_unsupported_family_is_ignored_and_the_session_stays(self):
        """L-3: live case `unsupported-afi`."""
        nh = b'\x00' * 8 + bytes(bytearray([127, 0, 0, 5]))
        nlri = b'\x58\x00\x00\x01\x00\x01' + struct.pack('!I', 1) + \
            b'\x0a\x09\x09'
        value = struct.pack('!HBB', 1, 128, len(nh)) + nh + b'\x00' + nlri
        self.s.send(raw.update(attrs=raw.origin_igp() +
                               raw.as_path(notify.SPEAKER_AS) +
                               raw.attr(0x90, 14, value)))
        self._still_up()
        # Still processing UPDATEs, not merely still connected.
        self.s.send(_mp_update(b'\x20\x01\x0d\xb8\x05\x02', 48))
        self.wait_until(lambda: '2001:db8:502::/48' in self._v6_routes(),
                        'a route learned after the ignored attribute')

    def test_a_twenty_byte_keepalive_draws_bad_message_length(self):
        """L-8: live case `keepalive-len20`."""
        self.s.send(raw.msg(raw.KEEPALIVE, b'\x00'))
        _code, _sub, data = self.s.expect_notification(
            errors.NOTIFY_HEADER, errors.HDR_BAD_LENGTH)
        self.assertEqual(data, b'\x00\x14')

    def test_an_unknown_message_type_draws_bad_message_type(self):
        """L-8: the type byte goes back in the data field."""
        self.s.send(raw.msg(9, b''))
        _code, _sub, data = self.s.expect_notification(
            errors.NOTIFY_HEADER, errors.HDR_BAD_TYPE)
        self.assertEqual(data, b'\x09')


if __name__ == '__main__':
    unittest.main()
