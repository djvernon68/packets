#!/usr/bin/env python

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Tests for the typed BGP codec in rtengine.plugins.bgp.wire.

The codec is the engine's only contact with a hostile network, and it is
the second BGP parser in this library. Both of those shape the suite more
than the source layout does:

  * **Acceptance criterion 2 is the reason this file is worth writing.**
    The library already has a text dissector for BGP; the codec exists for
    speed, not because it disagrees. So the central test here encodes a
    message with the codec, parses the same bytes with
    ``packets.core.inetpkt.BGP``, and asserts the two agree on every field
    both expose. Where the dissector is deliberately shallower -- it
    renders only the first AS_PATH segment and the first prefix, and it
    has no session context so it always reads AS_PATH as 2-octet ASNs --
    the comparison is driven from a 2-octet session, where the two really
    do mean the same thing, and the limit is named in a comment rather
    than quietly skipped.

  * **Framing is the one place that may not be permissive.** A TCP read
    can deliver a byte, a message, or three and a half messages, and a
    framer that resynchronises after a bad marker is a framer that will
    happily parse an attacker's payload as a header. The three latching
    faults each get a test that checks the exact NOTIFICATION code and
    subcode the caller must send, because "it failed" and "it failed with
    1/2" are different obligations.

  * **Malformed input must never raise.** RFC 7606's whole point is that
    a bad attribute costs a route rather than a session, and an exception
    escaping the decoder costs the session by definition. Every malformed
    case below therefore asserts two things -- that an entry lands in
    ``UpdateMsg.errors``, and that nothing propagated -- because a decoder
    that raises after recording the fault is still wrong.

  * **Size limits are per-session policy, not a constant.** Key Decision
    14: OPEN is capped at 4096 whatever was negotiated, KEEPALIVE is 19,
    and everything else follows the session ceiling. The splitting tests
    assert the properties a caller depends on (every message within the
    limit, none empty, nothing lost) rather than a message count, which
    would change with any attribute added to the encoder.

``bestpath`` is deliberately not exercised here.

Written as plain ``unittest.TestCase`` with no pytest features, matching
``test_rtengine_rib.py``: the 3.6.8 verification host has no pytest and
runs these through ``python3 -m unittest discover -s test``.
"""

import socket
import struct
import unittest

from packets.core.inetpkt import BGP
from packets.routing.rtengine.plugins.bgp import errors as bgp_errors
from packets.routing.rtengine.plugins.bgp import wire
from packets.routing.rtengine.plugins.bgp.attrs import AttrSet, \
    make_as_path, make_communities
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, Prefix, \
    parse_prefix

MARKER = b'\xff' * 16
NEXTHOP = b'\x0a\x00\x00\x01'
# An AS that does not fit in 16 bits, for every RFC 6793 case.
BIG_AS = 4200000001


def _v6(text):
    return socket.inet_pton(socket.AF_INET6, text)


def _msg(mtype, body):
    """Wrap a body in a well-formed 19-byte header."""
    return MARKER + struct.pack('>HB', 19 + len(body), mtype) + body


def _attr(flags, atype, value):
    """One path-attribute TLV in its one-byte-length form."""
    return struct.pack('>BBB', flags, atype, len(value)) + value


def _update(withdrawn=b'', attrs=b'', nlri=b''):
    """A well-formed UPDATE whose two length fields match its content."""
    return _msg(wire.UPDATE,
                struct.pack('>H', len(withdrawn)) + withdrawn +
                struct.pack('>H', len(attrs)) + attrs + nlri)


def _seg(seg_type, asns, width=4):
    """One AS_PATH segment at the given ASN width."""
    out = struct.pack('>BB', seg_type, len(asns))
    for asn in asns:
        if width == 4:
            out += struct.pack('>I', asn)
        else:
            out += struct.pack('>H', asn)
    return out


# The three well-known mandatory attributes, correct, for tests that need
# an UPDATE to be valid apart from the one thing under test.
A_ORIGIN = _attr(0x40, wire.TYPE_ORIGIN, b'\x00')
A_AS_PATH = _attr(0x40, wire.TYPE_AS_PATH, _seg(2, [65001]))
A_NEXT_HOP = _attr(0x40, wire.TYPE_NEXT_HOP, NEXTHOP)
A_MANDATORY = A_ORIGIN + A_AS_PATH + A_NEXT_HOP
# 10.1.0.0/16 as one NLRI entry, in the truncated on-wire form.
N_10_1 = b'\x10\x0a\x01'


def _attrset(**kwargs):
    """An announceable attribute set with the mandatory fields filled."""
    fields = {'as_path': make_as_path([65001, 65002]), 'nexthop': NEXTHOP}
    fields.update(kwargs)
    return AttrSet(**fields)


def _find_attr(raw, atype):
    """Return ``(flags, value)`` for one attribute of an encoded UPDATE.

    The tests need to look at bytes the decoder deliberately normalises
    away -- AS_TRANS substitution, the partial bit -- so they read the
    wire form directly rather than through ``decode_update``.
    """
    wlen = struct.unpack('>H', raw[19:21])[0]
    off = 21 + wlen
    end = off + 2 + struct.unpack('>H', raw[off:off + 2])[0]
    off += 2
    while off + 3 <= end:
        flags = raw[off]
        found = raw[off + 1]
        if flags & wire.FLAG_EXT_LEN:
            vlen = struct.unpack('>H', raw[off + 2:off + 4])[0]
            vstart = off + 4
        else:
            vlen = raw[off + 2]
            vstart = off + 3
        if found == atype:
            return (flags, raw[vstart:vstart + vlen])
        off = vstart + vlen
    return (None, None)


def _attr_types(raw):
    """Every attribute type code in an encoded UPDATE, in wire order."""
    out = []
    wlen = struct.unpack('>H', raw[19:21])[0]
    off = 21 + wlen
    end = off + 2 + struct.unpack('>H', raw[off:off + 2])[0]
    off += 2
    while off + 3 <= end:
        flags = raw[off]
        out.append(raw[off + 1])
        if flags & wire.FLAG_EXT_LEN:
            off += 4 + struct.unpack('>H', raw[off + 2:off + 4])[0]
        else:
            off += 3 + raw[off + 2]
    return out


class FramerTestCase(unittest.TestCase):
    """A TCP stream is not a sequence of messages until the framer says
    so."""

    def setUp(self):
        self.framer = wire.Framer()
        self.keepalive = wire.encode_keepalive()

    def test_a_message_delivered_one_byte_at_a_time(self):
        # The degenerate read pattern a real socket produces under load,
        # and the one a length-first framer gets wrong: nothing may be
        # emitted until the last byte arrives.
        for i in range(len(self.keepalive) - 1):
            self.framer.feed(self.keepalive[i:i + 1])
            self.assertIsNone(self.framer.next_message())
            self.assertEqual(self.framer.pending, i + 1)
        self.framer.feed(self.keepalive[-1:])
        self.assertEqual(self.framer.next_message(),
                         (wire.KEEPALIVE, self.keepalive))
        self.assertEqual(self.framer.pending, 0)
        self.assertEqual(self.framer.messages, 1)

    def test_several_messages_in_one_feed_come_out_in_order(self):
        refresh = wire.encode_route_refresh(1, 1)
        notify = wire.encode_notification(6, 2)
        self.framer.feed(self.keepalive + refresh + notify)
        self.assertEqual(self.framer.messages_available(),
                         [(wire.KEEPALIVE, self.keepalive),
                          (wire.ROUTE_REFRESH, refresh),
                          (wire.NOTIFICATION, notify)])
        self.assertEqual(self.framer.pending, 0)
        self.assertEqual(self.framer.messages, 3)

    def test_a_message_split_across_two_feeds(self):
        self.framer.feed(self.keepalive[:10])
        self.assertIsNone(self.framer.next_message())
        self.assertEqual(self.framer.pending, 10)
        self.framer.feed(self.keepalive[10:])
        self.assertEqual(self.framer.next_message()[0], wire.KEEPALIVE)

    def test_a_trailing_partial_message_stays_pending(self):
        # The common case at the end of every read: one whole message and
        # the head of the next. Losing the tail here loses a message.
        self.framer.feed(self.keepalive + self.keepalive[:5])
        self.assertEqual(len(self.framer.messages_available()), 1)
        self.assertEqual(self.framer.pending, 5)
        self.framer.feed(self.keepalive[5:])
        self.assertEqual(len(self.framer.messages_available()), 1)
        self.assertEqual(self.framer.pending, 0)

    def test_a_bad_marker_latches_one_one(self):
        # 1/1 is Connection Not Synchronized. The framer must not try to
        # resynchronise: once alignment is lost nothing downstream can
        # tell a header from a payload, and a framer that hunts for the
        # next marker will happily frame whatever an attacker sent.
        self.framer.feed(b'\x00' + self.keepalive[1:])
        self.assertIsNone(self.framer.next_message())
        self.assertTrue(self.framer.failed)
        self.assertEqual((self.framer.error_code, self.framer.error_subcode),
                         (1, 1))
        self.assertIsNotNone(self.framer.error_detail)

    def test_a_latched_framer_emits_nothing_further(self):
        self.framer.feed(b'\x00' + self.keepalive[1:])
        self.framer.next_message()
        self.framer.feed(self.keepalive)
        self.assertIsNone(self.framer.next_message())
        self.assertEqual(self.framer.messages_available(), [])

    def test_a_length_below_the_header_latches_one_two(self):
        self.framer.feed(MARKER + struct.pack('>HB', 18, wire.KEEPALIVE))
        self.assertIsNone(self.framer.next_message())
        self.assertEqual((self.framer.error_code, self.framer.error_subcode),
                         (1, 2))

    def test_a_length_above_the_session_ceiling_latches_one_two(self):
        self.framer.feed(MARKER + struct.pack('>HB', 5000, wire.UPDATE))
        self.assertIsNone(self.framer.next_message())
        self.assertEqual((self.framer.error_code, self.framer.error_subcode),
                         (1, 2))

    def test_a_bad_message_type_latches_one_three(self):
        self.framer.feed(MARKER + struct.pack('>HB', 19, 9))
        self.assertIsNone(self.framer.next_message())
        self.assertEqual((self.framer.error_code, self.framer.error_subcode),
                         (1, 3))

    def test_the_first_fault_wins(self):
        # Everything after the first fault is a consequence of a stream
        # that is already unusable, so reporting the last would hide the
        # cause.
        self.framer.feed(b'\x00' + self.keepalive[1:])
        self.framer.next_message()
        self.framer.feed(MARKER + struct.pack('>HB', 19, 9))
        self.framer.next_message()
        self.assertEqual((self.framer.error_code, self.framer.error_subcode),
                         (1, 1))

    def test_reset_clears_the_fault_and_the_buffer(self):
        self.framer.feed(b'\x00' + self.keepalive[1:])
        self.framer.next_message()
        self.framer.reset()
        self.assertFalse(self.framer.failed)
        self.assertEqual(self.framer.error_code, 0)
        self.assertEqual(self.framer.error_subcode, 0)
        self.assertIsNone(self.framer.error_detail)
        self.assertEqual(self.framer.pending, 0)
        self.framer.feed(self.keepalive)
        self.assertEqual(self.framer.next_message()[0], wire.KEEPALIVE)

    def test_raising_the_ceiling_admits_a_previously_rejected_message(self):
        # RFC 8654 Extended Message, negotiated in OPEN and applied to
        # everything after it. The same bytes must go from fatal to legal
        # purely because the session agreed they were.
        big = MARKER + struct.pack('>HB', 5000, wire.UPDATE) + b'\x00' * 4981
        rejecting = wire.Framer()
        rejecting.feed(big)
        self.assertIsNone(rejecting.next_message())
        self.assertEqual(rejecting.error_subcode, 2)

        admitting = wire.Framer()
        admitting.set_max_msg(wire.MAX_MSG_EXT)
        admitting.feed(big)
        mtype, raw = admitting.next_message()
        self.assertEqual(mtype, wire.UPDATE)
        self.assertEqual(len(raw), 5000)
        self.assertFalse(admitting.failed)

    def test_stats_reports_what_the_framer_has_seen(self):
        self.framer.feed(self.keepalive + self.keepalive[:5])
        self.framer.next_message()
        self.assertEqual(self.framer.stats(),
                         {'messages': 1, 'bytes': 24, 'buffered': 5,
                          'max-message': wire.MAX_MSG, 'error': None})

    def test_feeding_nothing_changes_nothing(self):
        self.assertEqual(self.framer.feed(b''), 0)
        self.assertEqual(self.framer.pending, 0)


class RoundTripTestCase(unittest.TestCase):
    """Encode, decode, and get back what went in."""

    def setUp(self):
        self.ctx = wire.DecodeCtx(as4=True, is_ebgp=True, local_as=65000,
                                  peer_as=65001)

    def test_open_round_trips_including_capabilities(self):
        caps = [(65, struct.pack('>I', 65536)),
                (1, struct.pack('>HBB', 1, 0, 1)),
                (2, b'')]
        raw = wire.encode_open(65001, 180, '10.0.0.9', caps)
        msg = wire.decode_open(raw)
        self.assertEqual(msg.errors, [])
        self.assertEqual(msg.version, 4)
        self.assertEqual(msg.my_as_wire, 65001)
        self.assertEqual(msg.hold_time, 180)
        self.assertEqual(msg.bgp_id, 0x0a000009)
        self.assertEqual(msg.capabilities, caps)
        self.assertEqual(msg.unsupported_params, [])
        self.assertEqual(msg.as_dict()['router-id'], '10.0.0.9')

    def test_open_with_no_capabilities_round_trips(self):
        raw = wire.encode_open(65001, 0, 0x01020304)
        msg = wire.decode_open(raw)
        self.assertEqual(msg.capabilities, [])
        self.assertEqual(msg.hold_time, 0)
        self.assertEqual(msg.bgp_id, 0x01020304)

    def test_an_as_above_65535_is_as_trans_in_the_open_header(self):
        # RFC 6793: the 2-byte header field cannot carry it, so AS_TRANS
        # goes there and the real value rides in the 4-octet capability.
        raw = wire.encode_open(BIG_AS, 90, '10.0.0.1',
                               [(65, struct.pack('>I', BIG_AS))])
        msg = wire.decode_open(raw)
        self.assertEqual(msg.my_as_wire, 23456)
        self.assertEqual(msg.capabilities,
                         [(65, struct.pack('>I', BIG_AS))])

    def test_my_as_is_widened_from_the_four_octet_capability(self):
        # The peer AS is what the FSM matches against `remote-as`, so if
        # `my_as` stayed at the AS_TRANS placeholder the header carries,
        # every 4-octet neighbour would be refused -- or, worse, would
        # match a neighbour someone had configured as 23456. `my_as_wire`
        # keeps the header value so a peer that filled it in wrongly can
        # still be diagnosed (RFC 6793 s4.1).
        raw = wire.encode_open(BIG_AS, 90, '10.0.0.1',
                               [(65, struct.pack('>I', BIG_AS))])
        msg = wire.decode_open(raw)
        self.assertEqual(msg.my_as, BIG_AS)
        self.assertEqual(msg.my_as_wire, 23456)
        self.assertEqual(msg.as_dict()['my-as'], BIG_AS)

    def test_a_sixteen_bit_as_is_left_alone(self):
        # The widening must not disturb the common case: with no 4-octet
        # capability the header value stands, and both fields agree.
        raw = wire.encode_open(65010, 90, '10.0.0.1', [])
        msg = wire.decode_open(raw)
        self.assertEqual(msg.my_as, 65010)
        self.assertEqual(msg.my_as, msg.my_as_wire)

    def test_the_four_octet_capability_code_matches_capabilities(self):
        # wire mirrors capability code 65 privately so the codec keeps no
        # Python dependency; this is the assertion that keeps the two
        # spellings from drifting.
        from packets.routing.rtengine.plugins.bgp import capabilities
        self.assertEqual(wire._CAP_AS4, capabilities.CAP_AS4)

    def test_a_non_capability_optional_parameter_is_kept(self):
        # The FSM has to answer with "Unsupported Optional Parameter" and
        # cannot name what the decoder did not record.
        params = b'\x01\x02\xaa\xbb'
        raw = (MARKER + struct.pack('>HB', 19 + 10 + len(params), wire.OPEN) +
               struct.pack('>BHHIB', 4, 65001, 90, 0x0a000001, len(params)) +
               params)
        msg = wire.decode_open(raw)
        self.assertEqual(msg.unsupported_params, [(1, b'\xaa\xbb')])
        self.assertEqual(msg.capabilities, [])
        self.assertEqual(msg.errors, [])

    def test_keepalive_is_the_bare_header(self):
        # Key Decision 14 spells it out: a KEEPALIVE is exactly 19 bytes
        # and Extended Message never applies to it.
        raw = wire.encode_keepalive()
        self.assertEqual(len(raw), 19)
        self.assertEqual(raw[:16], MARKER)
        self.assertEqual(raw[18], wire.KEEPALIVE)
        self.assertIs(wire.encode_keepalive(), raw)

    def test_notification_round_trips(self):
        msg = wire.decode_notification(wire.encode_notification(6, 2))
        self.assertEqual((msg.code, msg.subcode), (6, 2))
        self.assertEqual(msg.data, b'')

    def test_notification_round_trips_with_a_data_payload(self):
        raw = wire.encode_notification(3, 5, b'\x40\x01\x02')
        msg = wire.decode_notification(raw)
        self.assertEqual((msg.code, msg.subcode), (3, 5))
        self.assertEqual(msg.data, b'\x40\x01\x02')

    def test_a_truncated_notification_decodes_to_zeros(self):
        # The session is ending either way, so logging "the peer sent a
        # malformed NOTIFICATION" beats raising on the way out.
        msg = wire.decode_notification(_msg(wire.NOTIFICATION, b''))
        self.assertEqual((msg.code, msg.subcode, msg.data), (0, 0, b''))

    def test_route_refresh_round_trips(self):
        msg = wire.decode_route_refresh(wire.encode_route_refresh(1, 1))
        self.assertEqual((msg.afi, msg.safi, msg.subtype), (1, 1, 0))

    def test_route_refresh_carries_the_rfc_7313_subtypes(self):
        # BoRR and EoRR live in the byte RFC 2918 reserved and required to
        # be zero, which is exactly why reading it as a subtype is
        # backward compatible: an old sender reads as "normal request".
        for subtype in (0, 1, 2):
            raw = wire.encode_route_refresh(2, 1, subtype)
            msg = wire.decode_route_refresh(raw)
            self.assertEqual(len(raw), 23)
            self.assertEqual((msg.afi, msg.safi, msg.subtype),
                             (2, 1, subtype))

    def test_a_short_route_refresh_decodes_to_none(self):
        self.assertIsNone(
            wire.decode_route_refresh(_msg(wire.ROUTE_REFRESH, b'\x00\x01')))

    def test_an_announce_round_trips_attributes_and_nlri(self):
        attrs = _attrset(med=5, has_med=True,
                         communities=make_communities([0xffffff01, 0x10001]),
                         atomic_aggregate=True)
        prefixes = [parse_prefix('10.1.0.0/16'),
                    parse_prefix('192.0.2.0/24')]
        raw = wire.encode_announce(prefixes, attrs)
        self.assertEqual(len(raw), 1)
        msg = wire.decode_update(raw[0], self.ctx)
        self.assertEqual(msg.errors, [])
        self.assertTrue(msg.has_attrs)
        self.assertFalse(msg.end_of_rib)
        self.assertEqual([p for p, _ in msg.nlri], prefixes)
        self.assertEqual(msg.withdrawn, [])
        self.assertEqual(msg.counts(), (2, 0))
        # The point of the canonical form: what came back interns against
        # what went in, so a re-advertisement shares one attribute set.
        self.assertEqual(msg.attrs, attrs)

    def test_local_pref_survives_an_ibgp_round_trip(self):
        # And must not even be emitted towards eBGP, which is why the
        # eBGP leg is asserted too.
        attrs = _attrset(local_pref=250, has_local_pref=True)
        internal = wire.encode_announce([parse_prefix('10.1.0.0/16')],
                                        attrs, is_ebgp=False)[0]
        msg = wire.decode_update(internal,
                                 wire.DecodeCtx(as4=True, is_ebgp=False))
        self.assertEqual(msg.errors, [])
        self.assertTrue(msg.attrs.has_local_pref())
        self.assertEqual(msg.attrs.local_pref, 250)

        external = wire.encode_announce([parse_prefix('10.1.0.0/16')],
                                        attrs, is_ebgp=True)[0]
        self.assertNotIn(wire.TYPE_LOCAL_PREF, _attr_types(external))

    def test_a_withdraw_round_trips(self):
        prefixes = [parse_prefix('10.1.0.0/16'), parse_prefix('10.2.0.0/16')]
        raw = wire.encode_withdraw(prefixes)
        self.assertEqual(len(raw), 1)
        msg = wire.decode_update(raw[0], self.ctx)
        self.assertEqual(msg.errors, [])
        self.assertEqual([p for p, _ in msg.withdrawn], prefixes)
        self.assertEqual(msg.nlri, [])
        self.assertFalse(msg.end_of_rib)
        # A withdraw-only UPDATE carries no attributes by design, so the
        # mandatory-attribute check must not fire on it.
        self.assertFalse(msg.has_attrs)

    def test_encoding_nothing_produces_no_messages(self):
        self.assertEqual(wire.encode_announce([], _attrset()), [])
        self.assertEqual(wire.encode_withdraw([]), [])

    def test_end_of_rib_for_ipv4_is_an_empty_update(self):
        raw = wire.encode_end_of_rib(AFI_IP, 1)
        self.assertEqual(len(raw), 23)
        msg = wire.decode_update(raw, self.ctx)
        self.assertTrue(msg.end_of_rib)
        self.assertEqual(msg.errors, [])
        self.assertEqual(msg.counts(), (0, 0))

    def test_end_of_rib_for_ipv6_is_an_empty_mp_unreach(self):
        raw = wire.encode_end_of_rib(AFI_IP6, 1)
        msg = wire.decode_update(raw, self.ctx)
        self.assertTrue(msg.end_of_rib)
        self.assertEqual(msg.errors, [])
        self.assertEqual(msg.mp_unreach, (AFI_IP6, 1, []))

    def test_an_update_with_nlri_is_not_end_of_rib(self):
        raw = wire.encode_announce([parse_prefix('10.1.0.0/16')],
                                   _attrset())[0]
        self.assertFalse(wire.decode_update(raw, self.ctx).end_of_rib)


class DissectorCrossCheckTestCase(unittest.TestCase):
    """Acceptance criterion 2: the codec and the library's text dissector,
    given the same bytes, agree on every field both expose.

    The dissector is the independent oracle here -- it was written first,
    against Wireshark's field names, and neither parser was built from the
    other. Where it renders an enum as text rather than a number the
    expected spelling is written out, because the point is that the two
    reached the same conclusion, not that they share a formatter.
    """

    def setUp(self):
        # A 2-octet session throughout: the dissector has no session
        # context and always reads AS_PATH as 2-byte ASNs, so this is the
        # configuration in which both parsers genuinely mean the same
        # thing by the same bytes. The 4-octet case is covered in
        # As4TestCase, where the dissector cannot follow.
        self.ctx = wire.DecodeCtx(as4=False, is_ebgp=True)

    def _both(self, raw, mtype):
        """Parse with the dissector and check the header both agree on."""
        diss = BGP(raw)
        self.assertFalse(diss.malformed)
        self.assertEqual(diss.get_field_val('bgp.type_int'), mtype)
        self.assertEqual(diss.get_field_val('bgp.length'), len(raw))
        self.assertEqual(diss.get_field_val('bgp.marker'), MARKER)
        return diss

    @staticmethod
    def _params(diss):
        """The dissector's path attributes, keyed by type code."""
        return dict(
            (p.fields['bgp.update.path_attribute.type_code_int'], p.fields)
            for p in diss.params)

    def test_keepalive_agrees(self):
        self._both(wire.encode_keepalive(), wire.KEEPALIVE)

    def test_open_agrees_on_every_header_field_and_capability(self):
        caps = [(65, struct.pack('>I', 65001)),
                (1, struct.pack('>HBB', 1, 0, 1))]
        raw = wire.encode_open(65001, 180, '10.0.0.9', caps)
        mine = wire.decode_open(raw)
        diss = self._both(raw, wire.OPEN)
        self.assertEqual(diss.get_field_val('bgp.open.version'),
                         mine.version)
        self.assertEqual(diss.get_field_val('bgp.open.myas'),
                         mine.my_as_wire)
        self.assertEqual(diss.get_field_val('bgp.open.holdtime'),
                         mine.hold_time)
        self.assertEqual(diss.get_field_val('bgp.open.identifier'),
                         mine.as_dict()['router-id'])
        self.assertEqual([p.fields['bgp.cap.type_int'] for p in diss.params],
                         [c[0] for c in mine.capabilities])
        self.assertEqual([p.fields['bgp.cap.length'] for p in diss.params],
                         [len(c[1]) for c in mine.capabilities])

    def test_notification_agrees_on_code_and_subcode(self):
        # The dissector renders the Wireshark value_string text and the
        # codec keeps the numbers, so the bridge between them is spelled
        # out rather than assumed.
        names = {(6, 2): ('Cease', 'Administratively Shutdown'),
                 (3, 11): ('UPDATE Message Error', 'Malformed AS_PATH'),
                 (1, 1): ('Message Header Error',
                          'Connection Not Synchronized')}
        for (code, subcode), (major, minor) in sorted(names.items()):
            raw = wire.encode_notification(code, subcode, b'\x01\x02')
            mine = wire.decode_notification(raw)
            diss = self._both(raw, wire.NOTIFICATION)
            self.assertEqual((mine.code, mine.subcode), (code, subcode))
            self.assertEqual(diss.get_field_val('bgp.notify.major_error'),
                             major)
            self.assertEqual(diss.get_field_val('bgp.notify.minor_error'),
                             minor)

    def test_route_refresh_agrees_on_family_and_subtype(self):
        raw = wire.encode_route_refresh(AFI_IP6, 1, 1)
        mine = wire.decode_route_refresh(raw)
        diss = self._both(raw, wire.ROUTE_REFRESH)
        self.assertEqual(mine.afi, AFI_IP6)
        self.assertEqual(diss.get_field_val('bgp.route_refresh.afi'),
                         'IP6 (IP version 6)')
        self.assertEqual(diss.get_field_val('bgp.route_refresh.safi'),
                         'Unicast')
        self.assertEqual(diss.get_field_val('bgp.route_refresh.subtype'),
                         mine.subtype)

    def test_an_announce_agrees_on_every_attribute_both_decode(self):
        attrs = AttrSet(as_path=make_as_path([65001, 65002]),
                        nexthop=NEXTHOP, med=42, has_med=True,
                        origin=1,
                        communities=make_communities([0xffffff01]),
                        large_communities=struct.pack('>III', 65001, 1, 2),
                        aggregator=struct.pack('>II', 65001, 0x0a00000a))
        prefix = parse_prefix('10.1.0.0/16')
        raw = wire.encode_announce([prefix], attrs, as4=False)[0]
        mine = wire.decode_update(raw, self.ctx)
        diss = self._both(raw, wire.UPDATE)
        self.assertEqual(mine.errors, [])

        params = self._params(diss)
        self.assertEqual(sorted(params.keys()), sorted(_attr_types(raw)))
        self.assertEqual(params[wire.TYPE_ORIGIN][
            'bgp.update.path_attribute.origin'], 'EGP')
        self.assertEqual(mine.attrs.origin, 1)
        self.assertEqual(params[wire.TYPE_NEXT_HOP][
            'bgp.update.path_attribute.next_hop'], '10.0.0.1')
        self.assertEqual(mine.attrs.nexthop, NEXTHOP)
        self.assertEqual(params[wire.TYPE_MED][
            'bgp.update.path_attribute.multi_exit_disc'], mine.attrs.med)
        self.assertEqual(params[wire.TYPE_COMMUNITIES][
            'bgp.update.path_attribute.community_wellknown'], ['NO_EXPORT'])
        self.assertEqual(mine.attrs.community_list(), [0xffffff01])
        self.assertEqual(params[wire.TYPE_LARGE_COMMUNITY][
            'bgp.large_communities'], '65001:1:2')
        self.assertEqual(params[wire.TYPE_AGGREGATOR][
            'bgp.update.path_attribute.aggregator_as'], 65001)
        self.assertEqual(params[wire.TYPE_AGGREGATOR][
            'bgp.update.path_attribute.aggregator_origin'], '10.0.0.10')

        # AS_PATH: the dissector renders only the first segment and only
        # its first AS, which on this 2-octet session is the same number
        # the codec put at the head of its canonical path.
        segment = params[wire.TYPE_AS_PATH]
        self.assertEqual(
            segment['bgp.update.path_attribute.as_path_segment.type'],
            'AS_SEQUENCE')
        self.assertEqual(
            segment['bgp.update.path_attribute.as_path_segment.length'], 2)
        self.assertEqual(
            segment['bgp.update.path_attribute.as_path_segment.as2'],
            mine.attrs.as_path_list()[0][1][0])

        # Flags and declared lengths, attribute by attribute.
        for atype, fields in sorted(params.items()):
            flags, value = _find_attr(raw, atype)
            self.assertEqual(
                fields['bgp.update.path_attribute.length'], len(value))
            self.assertEqual(
                fields['bgp.update.path_attribute.flags.optional'],
                1 if flags & wire.FLAG_OPTIONAL else 0)
            self.assertEqual(
                fields['bgp.update.path_attribute.flags.transitive'],
                1 if flags & wire.FLAG_TRANSITIVE else 0)
            self.assertEqual(
                fields['bgp.update.path_attribute.flags.extended_length'],
                1 if flags & wire.FLAG_EXT_LEN else 0)

        # NLRI. The dissector exposes only the first prefix and its
        # length, which is the whole of what the two can be compared on.
        self.assertEqual(diss.get_field_val('bgp.nlri_prefix'), '10.1.0.0')
        self.assertEqual(diss.get_field_val('bgp.prefix_length'), 16)
        self.assertEqual(str(mine.nlri[0][0]), '10.1.0.0/16')
        self.assertEqual(
            diss.get_field_val('bgp.update.path_attributes.length'),
            struct.unpack('>H', raw[21:23])[0])

    def test_a_withdraw_agrees_on_the_withdrawn_routes_field(self):
        prefixes = [parse_prefix('10.1.0.0/16'), parse_prefix('10.2.0.0/16')]
        raw = wire.encode_withdraw(prefixes)[0]
        mine = wire.decode_update(raw, self.ctx)
        diss = self._both(raw, wire.UPDATE)
        self.assertEqual(
            diss.get_field_val('bgp.update.withdrawn_routes.length'),
            struct.unpack('>H', raw[19:21])[0])
        self.assertEqual(diss.get_field_val('bgp.withdrawn_prefix'),
                         '10.1.0.0')
        self.assertEqual(str(mine.withdrawn[0][0]), '10.1.0.0/16')
        self.assertEqual(
            diss.get_field_val('bgp.update.path_attributes.length'), 0)

    def test_end_of_rib_agrees(self):
        raw = wire.encode_end_of_rib(AFI_IP, 1)
        diss = self._both(raw, wire.UPDATE)
        self.assertEqual(
            diss.get_field_val('bgp.update.withdrawn_routes.length'), 0)
        self.assertEqual(
            diss.get_field_val('bgp.update.path_attributes.length'), 0)
        self.assertTrue(wire.decode_update(raw, self.ctx).end_of_rib)

    def test_the_two_agree_on_a_whole_stream(self):
        # The dissector chains back-to-back messages through its payload;
        # the framer splits them. Both must find the same boundaries, or
        # one of them is reading a length the other is not.
        attrs = _attrset()
        stream = (wire.encode_open(65001, 90, '10.0.0.1') +
                  wire.encode_keepalive() +
                  wire.encode_announce([parse_prefix('10.1.0.0/16')],
                                       attrs, as4=False)[0] +
                  wire.encode_notification(6, 2))
        framer = wire.Framer()
        framer.feed(stream)
        framed = framer.messages_available()
        self.assertFalse(framer.failed)

        chained = []
        node = BGP(stream)
        while isinstance(node, BGP):
            chained.append((node.type, node.length))
            node = node.payload
        self.assertEqual([(t, len(raw)) for t, raw in framed], chained)


class SizeLimitTestCase(unittest.TestCase):
    """Key Decision 14: the ceiling is a property of the session, and
    OPEN and KEEPALIVE are outside it."""

    def setUp(self):
        self.ctx = wire.DecodeCtx()
        self.attrs = _attrset()
        self.prefixes = [
            Prefix(AFI_IP, 24, struct.pack('>I', (10 << 24) | (i << 8)))
            for i in range(2000)]

    def test_an_announce_over_many_prefixes_splits(self):
        # The properties a caller depends on, rather than a message count
        # that any new attribute in the encoder would change: nothing over
        # the limit, nothing empty, nothing lost.
        messages = wire.encode_announce(self.prefixes, self.attrs)
        self.assertGreater(len(messages), 1)
        seen = []
        for raw in messages:
            self.assertLessEqual(len(raw), wire.MAX_MSG)
            decoded = wire.decode_update(raw, self.ctx)
            self.assertEqual(decoded.errors, [])
            self.assertNotEqual(decoded.nlri, [])
            seen.extend([p for p, _ in decoded.nlri])
        self.assertEqual(seen, self.prefixes)

    def test_a_withdraw_over_many_prefixes_splits(self):
        messages = wire.encode_withdraw(self.prefixes)
        self.assertGreater(len(messages), 1)
        seen = []
        for raw in messages:
            self.assertLessEqual(len(raw), wire.MAX_MSG)
            decoded = wire.decode_update(raw, self.ctx)
            self.assertEqual(decoded.errors, [])
            self.assertNotEqual(decoded.withdrawn, [])
            seen.extend([p for p, _ in decoded.withdrawn])
        self.assertEqual(seen, self.prefixes)

    def test_a_raised_ceiling_produces_fewer_larger_messages(self):
        # The Extended Message payoff, and the reason the limit is an
        # argument rather than a constant.
        at_4096 = wire.encode_announce(self.prefixes, self.attrs)
        at_65535 = wire.encode_announce(self.prefixes, self.attrs,
                                        max_size=wire.MAX_MSG_EXT)
        self.assertLess(len(at_65535), len(at_4096))
        for raw in at_65535:
            self.assertLessEqual(len(raw), wire.MAX_MSG_EXT)

    def test_attributes_too_large_for_the_limit_raise(self):
        # A caller error rather than something to truncate: every UPDATE
        # in a split repeats the whole attribute set, so if it does not
        # fit once it never will.
        fat = _attrset(communities=make_communities(range(1000)))
        self.assertRaises(ValueError, wire.encode_announce,
                          [parse_prefix('10.0.0.0/8')], fat, AFI_IP, 1, 200)

    def test_a_withdrawal_too_large_for_the_limit_raises(self):
        # Rather than looping forever emitting empty messages, which is
        # what a split loop does when nothing fits.
        self.assertRaises(ValueError, wire.encode_withdraw,
                          [parse_prefix('10.0.0.0/8')], AFI_IP, 1, 20)

    def test_an_open_over_4096_raises_whatever_was_negotiated(self):
        # RFC 8654 s3 excludes OPEN from Extended Message: the message
        # that negotiates the larger size cannot itself use it. Extended
        # parameters are requested so that it is the 4096 cap that is
        # under test, not the 255-byte classic parameter limit (W-2).
        caps = [(1, b'\x00' * 250)] * 20
        self.assertRaises(ValueError, wire.encode_open, 65001, 180,
                          '10.0.0.1', caps, extended=True)

    def test_an_open_just_under_the_cap_is_produced(self):
        caps = [(1, b'\x00' * 250)] * 15
        raw = wire.encode_open(65001, 180, '10.0.0.1', caps, extended=True)
        self.assertLessEqual(len(raw), wire.MAX_MSG)
        self.assertEqual(len(wire.decode_open(raw).capabilities), 15)

    def test_a_notification_data_payload_is_truncated_not_rejected(self):
        # A NOTIFICATION that cannot be sent is worse than one missing its
        # diagnostic tail.
        raw = wire.encode_notification(6, 2, b'\x41' * 8000)
        self.assertEqual(len(raw), wire.MAX_MSG)
        self.assertEqual(wire.decode_notification(raw).code, 6)


class As4TestCase(unittest.TestCase):
    """RFC 6793: a 4-octet AS crossing a 2-octet speaker and back."""

    def setUp(self):
        self.two_octet = wire.DecodeCtx(as4=False, is_ebgp=True)
        self.four_octet = wire.DecodeCtx(as4=True, is_ebgp=True)
        self.path = make_as_path([65001, BIG_AS, 65002])
        self.attrs = AttrSet(as_path=self.path, nexthop=NEXTHOP)

    def test_encoding_to_a_two_octet_peer_emits_as_trans_and_as4_path(self):
        raw = wire.encode_announce([parse_prefix('10.1.0.0/16')],
                                   self.attrs, as4=False)[0]
        types = _attr_types(raw)
        self.assertIn(wire.TYPE_AS4_PATH, types)

        _, as_path = _find_attr(raw, wire.TYPE_AS_PATH)
        self.assertEqual(as_path, _seg(2, [65001, 23456, 65002], width=2))
        _, as4_path = _find_attr(raw, wire.TYPE_AS4_PATH)
        self.assertEqual(as4_path, self.path)

    def test_a_path_that_fits_in_two_octets_emits_no_as4_path(self):
        # AS4_PATH is a repair for a limitation, not a second copy of the
        # path: sending it unconditionally would double the attribute
        # bytes of every UPDATE towards an old speaker.
        small = AttrSet(as_path=make_as_path([65001, 65002]),
                        nexthop=NEXTHOP)
        raw = wire.encode_announce([parse_prefix('10.1.0.0/16')], small,
                                   as4=False)[0]
        self.assertNotIn(wire.TYPE_AS4_PATH, _attr_types(raw))

    def test_the_pair_reconstructs_the_original_path_exactly(self):
        # The whole point: a 2-octet session in the middle must not be
        # able to lose an AS. Byte equality with the path that went in is
        # also what makes the two sides intern to one attribute set.
        raw = wire.encode_announce([parse_prefix('10.1.0.0/16')],
                                   self.attrs, as4=False)[0]
        decoded = wire.decode_update(raw, self.two_octet)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.as_path, self.path)
        self.assertEqual(decoded.attrs.as_path_str(),
                         '65001 4200000001 65002')
        self.assertEqual(decoded.attrs.neighbor_as, 65001)

    def test_a_four_octet_session_ignores_as4_path(self):
        # RFC 6793 s4.2.3. Honouring it would let a sender override the
        # authoritative AS_PATH it sent in the same message.
        attrs = (A_ORIGIN +
                 _attr(0x40, wire.TYPE_AS_PATH, _seg(2, [65001, 65002])) +
                 A_NEXT_HOP +
                 _attr(0xc0, wire.TYPE_AS4_PATH, _seg(2, [BIG_AS])))
        decoded = wire.decode_update(_update(attrs=attrs, nlri=N_10_1),
                                     self.four_octet)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.as_path_str(), '65001 65002')

    def test_an_as4_path_longer_than_as_path_is_discarded(self):
        # AS_PATH is authoritative for length because every speaker on the
        # way maintained it, so an AS4_PATH claiming more hops than exist
        # is a broken or hostile sender trying to lengthen someone else's
        # path.
        attrs = (A_ORIGIN +
                 _attr(0x40, wire.TYPE_AS_PATH, _seg(2, [65001], width=2)) +
                 A_NEXT_HOP +
                 _attr(0xc0, wire.TYPE_AS4_PATH,
                       _seg(2, [BIG_AS, BIG_AS, BIG_AS])))
        decoded = wire.decode_update(_update(attrs=attrs, nlri=N_10_1),
                                     self.two_octet)
        self.assertEqual(decoded.attrs.as_path_str(), '65001')

    def test_an_aggregator_is_widened_on_a_two_octet_session(self):
        # Stored in the 4-octet form whatever arrived, so nothing
        # downstream has to know which session it came from.
        attrs = (A_ORIGIN +
                 _attr(0x40, wire.TYPE_AS_PATH, _seg(2, [65001], width=2)) +
                 A_NEXT_HOP +
                 _attr(0xc0, wire.TYPE_AGGREGATOR,
                       struct.pack('>HI', 65001, 0x0a00000a)))
        decoded = wire.decode_update(_update(attrs=attrs, nlri=N_10_1),
                                     self.two_octet)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.aggregator,
                         struct.pack('>II', 65001, 0x0a00000a))


class AddPathTestCase(unittest.TestCase):
    """RFC 7911 path identifiers exist only where they were negotiated."""

    def setUp(self):
        self.attrs = _attrset()
        self.prefix = parse_prefix('10.3.0.0/16')

    def test_path_ids_round_trip_when_the_family_negotiated_them(self):
        raw = wire.encode_announce([(self.prefix, 7)], self.attrs,
                                   add_path=True)[0]
        ctx = wire.DecodeCtx(add_path=[(AFI_IP, 1)])
        self.assertTrue(ctx.add_path_for(AFI_IP, 1))
        decoded = wire.decode_update(raw, ctx)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.nlri, [(self.prefix, 7)])

    def test_withdrawals_carry_path_ids_too(self):
        raw = wire.encode_withdraw([(self.prefix, 9)], add_path=True)[0]
        ctx = wire.DecodeCtx(add_path=[(AFI_IP, 1)])
        decoded = wire.decode_update(raw, ctx)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.withdrawn, [(self.prefix, 9)])

    def test_without_the_capability_no_path_id_appears(self):
        raw = wire.encode_announce([self.prefix], self.attrs)[0]
        decoded = wire.decode_update(raw, wire.DecodeCtx())
        self.assertEqual(decoded.nlri, [(self.prefix, 0)])

    def test_the_setting_is_per_family(self):
        # Two sessions on one engine can disagree, and so can two families
        # on one session, which is why this is a set of pairs rather than
        # a flag.
        ctx = wire.DecodeCtx(add_path=[(AFI_IP6, 1)])
        self.assertFalse(ctx.add_path_for(AFI_IP, 1))
        self.assertTrue(ctx.add_path_for(AFI_IP6, 1))

    def test_add_path_bytes_read_without_the_capability_are_reported(self):
        # There is no way to tell the two framings apart from the bytes,
        # so a mismatched session produces nonsense -- but it must produce
        # recorded nonsense rather than an exception or a plausible route.
        raw = wire.encode_announce([(self.prefix, 7)], self.attrs,
                                   add_path=True)[0]
        decoded = wire.decode_update(raw, wire.DecodeCtx())
        self.assertNotEqual(decoded.errors, [])
        self.assertNotIn(self.prefix, [p for p, _ in decoded.nlri])


class MultiprotocolTestCase(unittest.TestCase):
    """RFC 4760: the next hop and the NLRI move inside an attribute."""

    def setUp(self):
        self.ctx = wire.DecodeCtx()
        self.global_nh = _v6('2001:db8::1')
        self.link_local = _v6('fe80::1')
        self.prefix = parse_prefix('2001:db8:1::/48')
        self.nlri = b'\x30' + self.prefix.packed()[:6]

    def _mp_reach(self, nexthop):
        value = (struct.pack('>HBB', AFI_IP6, 1, len(nexthop)) + nexthop +
                 b'\x00' + self.nlri)
        return (struct.pack('>BBH', 0x80 | wire.FLAG_EXT_LEN,
                            wire.TYPE_MP_REACH, len(value)) + value)

    def test_a_32_byte_next_hop_splits_into_global_and_link_local(self):
        # The two are kept apart rather than concatenated because only the
        # global one can be resolved or installed; the link-local one is
        # only ever re-advertised to a peer on the same link.
        attrs = A_ORIGIN + A_AS_PATH + self._mp_reach(self.global_nh +
                                                      self.link_local)
        decoded = wire.decode_update(_update(attrs=attrs), self.ctx)
        self.assertEqual(decoded.errors, [])
        afi, safi, nexthop, local, prefixes = decoded.mp_reach
        self.assertEqual((afi, safi), (AFI_IP6, 1))
        self.assertEqual(nexthop, self.global_nh)
        self.assertEqual(local, self.link_local)
        self.assertEqual([p for p, _ in prefixes], [self.prefix])
        self.assertEqual(decoded.attrs.nexthop, self.global_nh)
        self.assertEqual(decoded.attrs.nexthop_local, self.link_local)

    def test_a_16_byte_next_hop_leaves_the_link_local_field_empty(self):
        attrs = A_ORIGIN + A_AS_PATH + self._mp_reach(self.global_nh)
        decoded = wire.decode_update(_update(attrs=attrs), self.ctx)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.mp_reach[2], self.global_nh)
        self.assertEqual(decoded.mp_reach[3], b'')
        self.assertEqual(decoded.attrs.nexthop_local, b'')

    def test_an_mp_reach_only_update_does_not_demand_next_hop(self):
        # RFC 4760 says the NEXT_HOP attribute is absent for these, and
        # requiring it is a classic way to break IPv6 peering.
        attrs = A_ORIGIN + A_AS_PATH + self._mp_reach(self.global_nh)
        decoded = wire.decode_update(_update(attrs=attrs), self.ctx)
        self.assertEqual(decoded.errors, [])

    def test_an_ipv6_withdraw_round_trips_through_mp_unreach(self):
        raw = wire.encode_withdraw([self.prefix], AFI_IP6, 1)
        self.assertEqual(len(raw), 1)
        decoded = wire.decode_update(raw[0], self.ctx)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.mp_unreach[0], AFI_IP6)
        self.assertEqual([p for p, _ in decoded.mp_unreach[2]],
                         [self.prefix])
        self.assertEqual(decoded.counts(), (0, 1))
        self.assertFalse(decoded.end_of_rib)

    def test_an_ipv6_withdraw_splits_and_stays_within_the_limit(self):
        prefixes = [Prefix(AFI_IP6, 48,
                           _v6('2001:db8:%x::' % i)) for i in range(1, 900)]
        messages = wire.encode_withdraw(prefixes, AFI_IP6, 1)
        self.assertGreater(len(messages), 1)
        seen = []
        for raw in messages:
            self.assertLessEqual(len(raw), wire.MAX_MSG)
            decoded = wire.decode_update(raw, self.ctx)
            self.assertEqual(decoded.errors, [])
            self.assertNotEqual(decoded.mp_unreach[2], [])
            seen.extend([p for p, _ in decoded.mp_unreach[2]])
        self.assertEqual(seen, prefixes)

    def test_an_unsupported_family_is_recorded_and_not_fatal(self):
        # A peer offering us VPNv4 should not cost a session: the NLRI is
        # uninterpretable but the message is otherwise well formed. L-3:
        # it has its own reason, which the matrix discards -- recorded as
        # a bad value it fell to the MP_REACH row, which resets.
        value = struct.pack('>HBB', AFI_IP, 128, 4) + NEXTHOP + b'\x00'
        attrs = A_ORIGIN + A_AS_PATH + struct.pack(
            '>BBB', 0x80, wire.TYPE_MP_REACH, len(value)) + value
        decoded = wire.decode_update(_update(attrs=attrs), self.ctx)
        self.assertEqual([(e[0], e[1]) for e in decoded.errors],
                         [(wire.TYPE_MP_REACH, wire.REASON_UNNEGOTIATED)])
        self.assertIsNone(decoded.mp_reach)
        self.assertEqual(
            bgp_errors.attribute_outcome(wire.TYPE_MP_REACH,
                                         wire.REASON_UNNEGOTIATED),
            bgp_errors.OUTCOME_DISCARD)

    def test_a_bad_mp_reach_next_hop_length_is_recorded(self):
        attrs = A_ORIGIN + A_AS_PATH + self._mp_reach(b'\x00' * 7)
        decoded = wire.decode_update(_update(attrs=attrs), self.ctx)
        self.assertEqual([(e[0], e[1]) for e in decoded.errors],
                         [(wire.TYPE_MP_REACH, wire.REASON_LENGTH)])
        self.assertIsNone(decoded.mp_reach)

    def test_an_ipv6_announce_round_trips_through_mp_reach(self):
        # The encoder's MP_REACH must be a *self-contained* attribute: its
        # NLRI has to follow its own reserved byte, not the rest of the
        # attribute list. Writing the ordinary attributes between the two
        # and stretching MP_REACH's length over them produces a message
        # this decoder rejects, so this is a round trip rather than a
        # length check.
        attrs = AttrSet(as_path=make_as_path([65001]),
                        nexthop=self.global_nh)
        raw = wire.encode_announce([self.prefix], attrs, AFI_IP6, 1,
                                   nexthop=self.global_nh)[0]
        decoded = wire.decode_update(raw, self.ctx)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.mp_reach[0], AFI_IP6)
        self.assertEqual(decoded.mp_reach[2], self.global_nh)
        self.assertEqual(decoded.mp_reach[3], b'')
        self.assertEqual([p for p, _ in decoded.mp_reach[4]],
                         [self.prefix])
        self.assertEqual(decoded.counts(), (1, 0))
        self.assertEqual(decoded.attrs.as_path_str(), '65001')
        # No IPv4 NEXT_HOP attribute: RFC 4760 carries it inside MP_REACH
        # for every family but IPv4 unicast, and emitting both is how an
        # IPv6 session ends up advertising an IPv4 next hop.
        self.assertNotIn(wire.TYPE_NEXT_HOP, _attr_types(raw))

    def test_an_ipv6_announce_carries_a_link_local_next_hop(self):
        attrs = AttrSet(as_path=make_as_path([65001]),
                        nexthop=self.global_nh)
        raw = wire.encode_announce([self.prefix], attrs, AFI_IP6, 1,
                                   nexthop=self.global_nh +
                                   self.link_local)[0]
        decoded = wire.decode_update(raw, self.ctx)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.mp_reach[2], self.global_nh)
        self.assertEqual(decoded.mp_reach[3], self.link_local)
        self.assertEqual(decoded.attrs.nexthop, self.global_nh)
        self.assertEqual(decoded.attrs.nexthop_local, self.link_local)

    def test_an_ipv6_announce_splits_and_stays_within_the_limit(self):
        attrs = AttrSet(as_path=make_as_path([65001]),
                        nexthop=self.global_nh)
        prefixes = [Prefix(AFI_IP6, 48,
                           _v6('2001:db8:%x::' % i)) for i in range(1, 900)]
        messages = wire.encode_announce(prefixes, attrs, AFI_IP6, 1,
                                        nexthop=self.global_nh)
        self.assertGreater(len(messages), 1)
        seen = []
        for raw in messages:
            self.assertLessEqual(len(raw), wire.MAX_MSG)
            decoded = wire.decode_update(raw, self.ctx)
            self.assertEqual(decoded.errors, [])
            self.assertNotEqual(decoded.mp_reach[4], [])
            seen.extend([p for p, _ in decoded.mp_reach[4]])
        self.assertEqual(seen, prefixes)

    def test_an_mp_announce_without_a_next_hop_raises(self):
        attrs = AttrSet(as_path=make_as_path([65001]))
        self.assertRaises(ValueError, wire.encode_announce,
                          [self.prefix], attrs, AFI_IP6, 1)


class MalformedUpdateTestCase(unittest.TestCase):
    """Every fault is recorded and none of them raises.

    RFC 7606 exists because an exception here costs the whole session,
    which is the outcome the graded response was invented to avoid. So
    each case asserts the entry that lands in ``UpdateMsg.errors`` -- the
    input the matrix in ``errors.py`` runs on -- and, by completing at
    all, that nothing propagated.
    """

    def setUp(self):
        self.ctx = wire.DecodeCtx(as4=True, is_ebgp=True)

    def _decode(self, raw):
        return wire.decode_update(raw, self.ctx)

    @staticmethod
    def _pairs(decoded):
        return [(e[0], e[1]) for e in decoded.errors]

    def test_a_withdrawn_routes_length_that_overruns_the_message(self):
        # Nothing after the field can be located, so this is one of the
        # few faults the matrix still escalates to a session reset.
        raw = _msg(wire.UPDATE, struct.pack('>H', 100) + N_10_1 + b'\x00\x00')
        decoded = self._decode(raw)
        self.assertEqual(self._pairs(decoded),
                         [(wire.ATTR_LIST, wire.REASON_LENGTH)])
        self.assertEqual(decoded.withdrawn, [])

    def test_a_path_attribute_length_that_overruns_the_message(self):
        raw = _msg(wire.UPDATE,
                   b'\x00\x00' + struct.pack('>H', 100) + A_ORIGIN)
        self.assertEqual(self._pairs(self._decode(raw)),
                         [(wire.ATTR_LIST, wire.REASON_LENGTH)])

    def test_an_update_below_the_minimum_length(self):
        self.assertEqual(self._pairs(self._decode(_msg(wire.UPDATE, b'\x00'))),
                         [(wire.ATTR_LIST, wire.REASON_LENGTH)])

    def test_a_truncated_attribute_header(self):
        decoded = self._decode(_update(attrs=b'\x40\x01', nlri=N_10_1))
        self.assertIn((wire.ATTR_LIST, wire.REASON_UNPARSEABLE),
                      self._pairs(decoded))

    def test_an_attribute_whose_length_overruns_the_attribute_list(self):
        # Distinguished from "the attribute is simply long": the detail
        # names both the claim and what was readable.
        raw = _msg(wire.UPDATE,
                   b'\x00\x00' + struct.pack('>H', 4) + b'\x40\x01\x0a\x00')
        self.assertEqual(self._pairs(self._decode(raw)),
                         [(wire.TYPE_ORIGIN, wire.REASON_LENGTH)])

    def test_a_duplicate_attribute(self):
        # RFC 7606 s3(g). The decoder keeps the first occurrence and
        # records that it happened; which error it costs is the matrix's
        # decision, not the decoder's.
        decoded = self._decode(_update(attrs=A_MANDATORY + A_ORIGIN,
                                       nlri=N_10_1))
        self.assertEqual(self._pairs(decoded),
                         [(wire.TYPE_ORIGIN, wire.REASON_DUPLICATE)])
        self.assertEqual(decoded.attrs.origin, 0)

    def test_origin_with_a_bad_length(self):
        attrs = _attr(0x40, wire.TYPE_ORIGIN, b'\x00\x00') + A_AS_PATH + \
            A_NEXT_HOP
        self.assertEqual(self._pairs(self._decode(_update(attrs=attrs,
                                                          nlri=N_10_1))),
                         [(wire.TYPE_ORIGIN, wire.REASON_LENGTH)])

    def test_origin_with_the_undefined_value_three(self):
        attrs = _attr(0x40, wire.TYPE_ORIGIN, b'\x03') + A_AS_PATH + \
            A_NEXT_HOP
        self.assertEqual(self._pairs(self._decode(_update(attrs=attrs,
                                                          nlri=N_10_1))),
                         [(wire.TYPE_ORIGIN, wire.REASON_VALUE)])

    def test_a_next_hop_of_the_wrong_length(self):
        attrs = A_ORIGIN + A_AS_PATH + _attr(0x40, wire.TYPE_NEXT_HOP,
                                             b'\x0a\x00\x00')
        self.assertEqual(self._pairs(self._decode(_update(attrs=attrs,
                                                          nlri=N_10_1))),
                         [(wire.TYPE_NEXT_HOP, wire.REASON_LENGTH)])

    def test_communities_whose_length_is_not_a_multiple_of_four(self):
        attrs = A_MANDATORY + _attr(0xc0, wire.TYPE_COMMUNITIES,
                                    b'\x00\x01\x02')
        decoded = self._decode(_update(attrs=attrs, nlri=N_10_1))
        self.assertEqual(self._pairs(decoded),
                         [(wire.TYPE_COMMUNITIES, wire.REASON_LENGTH)])
        # Rejected rather than half-kept: a partial community is not a
        # community, and storing three bytes would put a value into the
        # canonical form that can never be re-encoded.
        self.assertEqual(decoded.attrs.communities, b'')

    def test_an_attribute_with_the_wrong_flag_bits(self):
        # RFC 7606 s4 makes this its own error, independent of whether the
        # value would have parsed: a well-known attribute arriving marked
        # optional means the sender's notion of it differs from ours.
        attrs = _attr(0xc0, wire.TYPE_ORIGIN, b'\x00') + A_AS_PATH + \
            A_NEXT_HOP
        self.assertEqual(self._pairs(self._decode(_update(attrs=attrs,
                                                          nlri=N_10_1))),
                         [(wire.TYPE_ORIGIN, wire.REASON_FLAGS)])

    def test_a_non_transitive_med_marked_transitive(self):
        attrs = A_MANDATORY + _attr(0xc0, wire.TYPE_MED, b'\x00' * 4)
        decoded = self._decode(_update(attrs=attrs, nlri=N_10_1))
        self.assertEqual(self._pairs(decoded),
                         [(wire.TYPE_MED, wire.REASON_FLAGS)])
        self.assertFalse(decoded.attrs.has_med())

    def test_an_unknown_well_known_attribute(self):
        # Subcode 2 territory: we and the peer disagree about the base
        # protocol, so there is nothing safe to do with the rest.
        attrs = A_MANDATORY + _attr(0x40, 99, b'\x01')
        self.assertEqual(self._pairs(self._decode(_update(attrs=attrs,
                                                          nlri=N_10_1))),
                         [(99, wire.REASON_VALUE)])

    def test_an_unknown_optional_transitive_attribute_is_preserved(self):
        # Not an error at all. RFC 4271 s5 requires it to survive a
        # re-advertisement with the partial bit set, and discarding it
        # would silently break extensions this engine does not know yet.
        attrs = A_MANDATORY + _attr(0xc0, 99, b'\x01\x02')
        decoded = self._decode(_update(attrs=attrs, nlri=N_10_1))
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.unknown,
                         _attr(0xc0 | wire.FLAG_PARTIAL, 99, b'\x01\x02'))

    def test_an_unknown_optional_non_transitive_attribute_is_dropped(self):
        # Also required by RFC 4271 s5, and the opposite answer to the
        # case above, which is why both are pinned.
        attrs = A_MANDATORY + _attr(0x80, 99, b'\x01\x02')
        decoded = self._decode(_update(attrs=attrs, nlri=N_10_1))
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.unknown, b'')

    def test_nlri_with_a_prefix_length_above_the_family_maximum(self):
        # Unrecoverable rather than skippable: NLRI is self-delimiting, so
        # one bad length makes every subsequent offset wrong.
        raw = _update(attrs=A_MANDATORY, nlri=b'\x21\x0a\x00\x00\x01')
        decoded = self._decode(raw)
        self.assertEqual(self._pairs(decoded),
                         [(wire.ATTR_LIST, wire.REASON_UNPARSEABLE)])
        self.assertEqual(decoded.nlri, [])

    def test_a_missing_mandatory_attribute_is_reported_per_attribute(self):
        decoded = self._decode(_update(attrs=A_ORIGIN, nlri=N_10_1))
        self.assertEqual(self._pairs(decoded),
                         [(wire.TYPE_AS_PATH, wire.REASON_MISSING),
                          (wire.TYPE_NEXT_HOP, wire.REASON_MISSING)])

    def test_a_malformed_as_path_segment(self):
        attrs = A_ORIGIN + _attr(0x40, wire.TYPE_AS_PATH,
                                 b'\x02\x05\x00\x01') + A_NEXT_HOP
        self.assertEqual(self._pairs(self._decode(_update(attrs=attrs,
                                                          nlri=N_10_1))),
                         [(wire.TYPE_AS_PATH, wire.REASON_VALUE)])

    def test_an_as_path_segment_with_a_zero_count(self):
        # Not merely useless: a zero count is how a malformed path pads
        # itself out to the declared length while carrying nothing.
        attrs = A_ORIGIN + _attr(0x40, wire.TYPE_AS_PATH, b'\x02\x00') + \
            A_NEXT_HOP
        self.assertEqual(self._pairs(self._decode(_update(attrs=attrs,
                                                          nlri=N_10_1))),
                         [(wire.TYPE_AS_PATH, wire.REASON_VALUE)])

    def test_local_pref_from_an_ebgp_peer_is_recorded(self):
        # RFC 4271 s5.1.5 forbids it across an eBGP boundary. Recorded
        # rather than silently dropped, so the matrix decides: a peer
        # sending it is either misconfigured or trying to steer our
        # internal preference from outside.
        attrs = A_MANDATORY + _attr(0x40, wire.TYPE_LOCAL_PREF, b'\x00' * 4)
        decoded = self._decode(_update(attrs=attrs, nlri=N_10_1))
        self.assertEqual(self._pairs(decoded),
                         [(wire.TYPE_LOCAL_PREF, wire.REASON_VALUE)])
        self.assertFalse(decoded.attrs.has_local_pref())

    def test_cluster_list_from_an_ebgp_peer_is_recorded(self):
        attrs = A_MANDATORY + _attr(0x80, wire.TYPE_CLUSTER_LIST,
                                    b'\x0a\x00\x00\x01')
        self.assertEqual(self._pairs(self._decode(_update(attrs=attrs,
                                                          nlri=N_10_1))),
                         [(wire.TYPE_CLUSTER_LIST, wire.REASON_VALUE)])

    def test_several_faults_in_one_update_are_all_reported(self):
        # Two-phase decode: every fault is known before anything is
        # applied, which is what lets the matrix fold them to one outcome.
        attrs = (_attr(0x40, wire.TYPE_ORIGIN, b'\x03') + A_AS_PATH +
                 A_NEXT_HOP +
                 _attr(0xc0, wire.TYPE_COMMUNITIES, b'\x00\x01\x02'))
        decoded = self._decode(_update(attrs=attrs, nlri=N_10_1))
        self.assertEqual(self._pairs(decoded),
                         [(wire.TYPE_ORIGIN, wire.REASON_VALUE),
                          (wire.TYPE_COMMUNITIES, wire.REASON_LENGTH)])
        # The readable half of the message survives, which is the
        # precondition for treat-as-withdraw to mean anything.
        self.assertEqual(len(decoded.nlri), 1)

    def test_every_error_entry_is_a_type_reason_detail_triple(self):
        # The shape errors.attribute_outcome is called with, so it is
        # worth pinning once rather than assuming it at every call site.
        attrs = _attr(0x40, wire.TYPE_ORIGIN, b'\x03') + A_AS_PATH + \
            A_NEXT_HOP
        for entry in self._decode(_update(attrs=attrs,
                                          nlri=N_10_1)).errors:
            self.assertEqual(len(entry), 3)
            self.assertIn(entry[1], bgp_errors.REASONS)
            self.assertIsInstance(entry[2], str)


class ConstantAgreementTestCase(unittest.TestCase):
    """``wire`` and ``errors`` deliberately duplicate these, so the
    duplication is asserted rather than trusted.

    ``wire`` is a compiled extension and spells the reasons itself so it
    imports with no Python dependency of its own; ``errors`` spells them
    because it is the module that grades them. Two sources of truth only
    stay in step if something checks.
    """

    @staticmethod
    def _reason_values(module):
        return set(v for k, v in vars(module).items()
                   if k.startswith('REASON_') and isinstance(v, str))

    def test_the_reason_strings_are_the_same_set(self):
        # Compared by value rather than by name on purpose: it is the
        # string that travels in an errors entry. (errors also keeps the
        # old REASON_UNRESOLVABLE spelling as an alias for one release;
        # W-11.)
        self.assertEqual(self._reason_values(wire),
                         self._reason_values(bgp_errors))

    def test_the_errors_module_lists_every_reason_it_defines(self):
        self.assertEqual(set(bgp_errors.REASONS),
                         self._reason_values(bgp_errors))

    def test_the_attribute_list_sentinel_agrees(self):
        self.assertEqual(wire.ATTR_LIST, bgp_errors.ATTR_LIST)
        self.assertLess(wire.ATTR_LIST, 0)

    def test_the_size_constants_are_the_rfc_ones(self):
        self.assertEqual(wire.HEADER_LEN, 19)
        self.assertEqual(wire.MAX_MSG, 4096)
        self.assertEqual(wire.MAX_MSG_EXT, 65535)
        self.assertEqual(wire.VERSION, 4)
        self.assertEqual(wire.MARKER, MARKER)

    def test_every_message_type_is_named(self):
        for mtype in (wire.OPEN, wire.UPDATE, wire.NOTIFICATION,
                      wire.KEEPALIVE, wire.ROUTE_REFRESH):
            self.assertIn(mtype, wire.MSG_NAMES)

    def test_every_attribute_the_decoder_handles_is_named(self):
        for atype in (wire.TYPE_ORIGIN, wire.TYPE_AS_PATH,
                      wire.TYPE_NEXT_HOP, wire.TYPE_MED,
                      wire.TYPE_LOCAL_PREF, wire.TYPE_ATOMIC_AGGREGATE,
                      wire.TYPE_AGGREGATOR, wire.TYPE_COMMUNITIES,
                      wire.TYPE_ORIGINATOR_ID, wire.TYPE_CLUSTER_LIST,
                      wire.TYPE_MP_REACH, wire.TYPE_MP_UNREACH,
                      wire.TYPE_EXT_COMMUNITIES, wire.TYPE_AS4_PATH,
                      wire.TYPE_AS4_AGGREGATOR,
                      wire.TYPE_LARGE_COMMUNITY):
            self.assertIn(atype, wire.ATTR_NAMES)

    def test_every_attribute_the_matrix_grades_is_one_wire_knows(self):
        # The matrix is keyed by raw code because wire owns the names; if
        # it ever grows a row for something the codec cannot produce, that
        # row is dead and worth noticing.
        known = set(wire.ATTR_NAMES.keys())
        known.add(bgp_errors.ATTR_LIST)
        self.assertEqual(set(bgp_errors.ATTRIBUTE_MATRIX.keys()) - known,
                         set())


class CanonicalAsPathTestCase(unittest.TestCase):
    """A 4-octet AS_PATH is stored as its wire bytes once the segment walk
    has checked them, rather than rebuilt; a 2-octet one is still widened.
    Both must land on the same canonical form, and the walk must still
    reject what it rejected when it was also doing the copy."""

    SEGMENTS = ((2, [65001, BIG_AS, 65002]), (1, [7, 3, BIG_AS]),
                (3, [64512]), (4, [64513, 64514]))

    def _as_path(self, ctx, value):
        attrs = A_ORIGIN + _attr(0x40, wire.TYPE_AS_PATH, value) + A_NEXT_HOP
        return wire.decode_update(_update(attrs=attrs, nlri=N_10_1), ctx)

    def test_every_segment_type_at_both_widths(self):
        four = wire.DecodeCtx(as4=True, is_ebgp=True)
        two = wire.DecodeCtx(as4=False, is_ebgp=True)
        canonical = b''.join(_seg(t, asns) for t, asns in self.SEGMENTS)
        decoded = self._as_path(four, canonical)
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.as_path, canonical)
        narrow = [(t, [a if a <= 0xffff else 23456 for a in asns])
                  for t, asns in self.SEGMENTS]
        decoded = self._as_path(two, b''.join(_seg(t, asns, width=2)
                                              for t, asns in narrow))
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.as_path,
                         b''.join(_seg(t, asns) for t, asns in narrow))

    def test_malformed_four_octet_paths_are_still_rejected(self):
        four = wire.DecodeCtx(as4=True, is_ebgp=True)
        good = _seg(2, [65001, 65002])
        for value in (b'\x05\x01' + struct.pack('>I', 1),  # segment type
                      b'\x02\x00',                        # zero count
                      b'\x02\x03' + struct.pack('>II', 1, 2),  # overrun
                      good + b'\x02',                       # trailing byte
                      good[:-1]):                           # short ASN
            with self.subTest(value=value):
                decoded = self._as_path(four, value)
                self.assertEqual([(e[0], e[1]) for e in decoded.errors],
                                 [(wire.TYPE_AS_PATH, wire.REASON_VALUE)])


class DuplicateAttributeTypeTestCase(unittest.TestCase):
    """The decoder's seen-set is a 256 bit map; every type code, including
    both ends of the range, must be tracked on its own."""

    def test_duplicates_at_each_end_of_the_type_range(self):
        ctx = wire.DecodeCtx(as4=True, is_ebgp=True)
        for atype in (0, 63, 64, 127, 128, 191, 192, 255):
            with self.subTest(atype=atype):
                # A neighbouring bit in the map, but never ORIGIN, AS_PATH
                # or NEXT_HOP, which A_MANDATORY already carries.
                neighbour = atype - 1 if atype > 4 else 250
                unknown = _attr(0xc0, atype, b'\x01')
                other = _attr(0xc0, neighbour, b'\x02')
                decoded = wire.decode_update(
                    _update(attrs=A_MANDATORY + unknown + other + unknown,
                            nlri=N_10_1), ctx)
                self.assertIn((atype, wire.REASON_DUPLICATE),
                              [(e[0], e[1]) for e in decoded.errors])
                self.assertNotIn((neighbour, wire.REASON_DUPLICATE),
                                 [(e[0], e[1]) for e in decoded.errors])


class _SubPrefix(Prefix):
    pass


class EncodeItemTestCase(unittest.TestCase):
    """The encoders take bare prefixes and (prefix, path_id) pairs mixed,
    without wrapping every bare prefix in a tuple first."""

    def setUp(self):
        self.attrs = _attrset()
        self.prefixes = [parse_prefix('10.%d.0.0/16' % i) for i in range(40)]

    def test_mixed_items_encode_as_pairs_would(self):
        mixed = [p if i % 2 else (p, 0) for i, p in enumerate(self.prefixes)]
        pairs = [(p, 0) for p in self.prefixes]
        for max_size in (4096, 80):
            self.assertEqual(
                wire.encode_announce(mixed, self.attrs, max_size=max_size),
                wire.encode_announce(pairs, self.attrs, max_size=max_size))
            self.assertEqual(
                wire.encode_withdraw(mixed, max_size=max_size),
                wire.encode_withdraw(pairs, max_size=max_size))
        with_ids = [p if i % 3 else (p, i) for i, p in
                    enumerate(self.prefixes)]
        ctx = wire.DecodeCtx(add_path=[(AFI_IP, 1)])
        nlri = []
        for raw in wire.encode_announce(with_ids, self.attrs,
                                        add_path=True):
            nlri += wire.decode_update(raw, ctx).nlri
        self.assertEqual(nlri, [(p, 0 if i % 3 else i)
                                for i, p in enumerate(self.prefixes)])

    def test_v6_mixed_items(self):
        v6 = [parse_prefix('2001:db8:%x::/48' % i) for i in range(20)]
        attrs = _attrset(nexthop=_v6('2001:db8::1'))
        mixed = [p if i % 2 else (p, 0) for i, p in enumerate(v6)]
        self.assertEqual(
            wire.encode_announce(mixed, attrs, afi=AFI_IP6),
            wire.encode_announce([(p, 0) for p in v6], attrs, afi=AFI_IP6))

    def test_bad_items_are_rejected_before_encoding(self):
        good = self.prefixes[0]
        for bad in ([(good, -1)], [('10.0.0.0/8', 0)], [(good,)], [7]):
            with self.subTest(bad=bad):
                with self.assertRaises((TypeError, OverflowError,
                                        IndexError)):
                    wire.encode_announce([good] + bad, self.attrs)

if __name__ == '__main__':
    unittest.main()
