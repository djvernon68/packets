#!/usr/bin/env python

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Tests for canonical BGP path attributes in rtengine.plugins.bgp.attrs.

``AttrSet`` exists so that a million paths can share tens of thousands of
attribute objects, and ``AttrTable`` is what makes them share. Both claims
are only as good as one property -- two attribute sets that *mean* the same
thing must be byte-equal, hash-equal and intern to one object -- so the
suite is shaped around the ways that property can fail rather than around
the source layout:

  * **Canonicalisation is the whole design.** Communities, extended
    communities and large communities carry no order, so two peers that
    list them differently must still collapse to one set; CLUSTER_LIST
    does carry order, so the same sorting applied to it would corrupt a
    route-reflector path record. Those are opposite requirements on
    adjacent fields in the same object, which is exactly the pair an
    optimisation gets wrong, so both directions are asserted rather than
    just the one that is easy to check.

  * **Absent is not zero.** MED and LOCAL_PREF have no out-of-band value,
    so presence is carried in a flag bit. If that bit escapes the hash or
    the comparison, a path with no MED and a path with MED 0 intern
    together and one of them is re-advertised wrongly for the rest of its
    life. There is therefore a test per flag that pins inequality *and*
    non-interning, not merely a different accessor result.

  * **The derived fields are read by best-path and never recomputed.**
    ``as_path_len`` and ``neighbor_as`` are calculated once at
    construction, so an error in the segment walk is permanent and silent.
    The two rules that are easy to get wrong -- an AS_SET counts as one
    hop, a confederation segment counts as none -- get a test each, in
    both the length and the neighbouring-AS role.

  * **The table's refcount is not CPython's.** ``release`` has three
    distinct answers (still held, dropped, not ours) and the last two are
    the ones that corrupt a table when confused, so a never-interned set
    and an equal-but-distinct set are checked to leave the table exactly
    as they found it.

``bestpath`` is deliberately not exercised here; it is the consumer of
these fields, not part of their contract.

Written as plain ``unittest.TestCase`` with no pytest features, matching
``test_rtengine_rib.py``: the 3.6.8 verification host has no pytest and
runs these through ``python3 -m unittest discover -s test``.
"""

import struct
import unittest

from packets.routing.rtengine.plugins.bgp.attrs import AS_TRANS_V, \
    ORIGIN_CODES, ORIGIN_EGP_V, ORIGIN_IGP_V, ORIGIN_INCOMPLETE_V, \
    ORIGIN_NAMES, SEG_AS_CONFED_SEQUENCE, SEG_AS_CONFED_SET, \
    SEG_AS_SEQUENCE, SEG_AS_SET, AttrSet, AttrTable, make_as_path, \
    make_communities

NEXTHOP = b'\x0a\x00\x00\x01'


def _u32(value):
    """One 32-bit value in network order."""
    return struct.pack('>I', value)


def _u32s(*values):
    """Several 32-bit values in network order, concatenated."""
    return b''.join([struct.pack('>I', v) for v in values])


def _ext(*values):
    """Packed 8-byte extended communities, from 64-bit integers."""
    return b''.join([struct.pack('>Q', v) for v in values])


def _large(*triples):
    """Packed 12-byte large communities, from (global, ld1, ld2)."""
    return b''.join([struct.pack('>III', a, b, c) for a, b, c in triples])


def _tlv(atype, value, flags=0xc0):
    """One on-wire attribute TLV, for the unknown-attribute run.

    Default flags are optional-transitive, which is the only combination
    an AttrSet is ever asked to preserve.
    """
    return struct.pack('>BBB', flags, atype, len(value)) + value


class AttrSetConstructionTestCase(unittest.TestCase):
    """Keyword construction, and the accessors that read it back."""

    def test_keyword_construction_keeps_every_field(self):
        a = AttrSet(origin=ORIGIN_EGP_V,
                    as_path=make_as_path([65001, 65002]),
                    nexthop=NEXTHOP, med=7, has_med=True,
                    local_pref=300, has_local_pref=True,
                    atomic_aggregate=True,
                    communities=make_communities([0x10001]),
                    ext_communities=_ext(0x0002fde800000001),
                    large_communities=_large((65001, 1, 2)),
                    originator_id=0x0a000002, has_originator=True,
                    cluster_list=_u32(0x0a000003),
                    aggregator=_u32s(65001, 0x0a000004))
        self.assertEqual(a.origin, ORIGIN_EGP_V)
        self.assertEqual(a.nexthop, NEXTHOP)
        self.assertEqual(a.med, 7)
        self.assertEqual(a.local_pref, 300)
        self.assertTrue(a.has_med())
        self.assertTrue(a.has_local_pref())
        self.assertTrue(a.atomic_aggregate)
        self.assertTrue(a.has_originator_id)
        self.assertEqual(a.originator_id, 0x0a000002)
        self.assertEqual(a.cluster_ids(), [0x0a000003])
        self.assertEqual(a.aggregator, _u32s(65001, 0x0a000004))

    def test_defaults_are_an_empty_locally_originated_set(self):
        # An empty AS_PATH is legal and distinct from a missing one, which
        # never reaches here; everything else defaults to absent so a
        # locally originated route needs no arguments at all.
        a = AttrSet()
        self.assertEqual(a.origin, ORIGIN_IGP_V)
        self.assertEqual(a.as_path, b'')
        self.assertEqual(a.as_path_list(), [])
        self.assertEqual(a.as_path_str(), '')
        self.assertEqual(a.as_path_len, 0)
        self.assertEqual(a.neighbor_as, 0)
        self.assertFalse(a.has_med())
        self.assertFalse(a.has_local_pref())
        self.assertFalse(a.atomic_aggregate)
        self.assertFalse(a.interned)

    def test_as_path_str_renders_a_sequence_bare(self):
        a = AttrSet(as_path=make_as_path([65001, 65002, 65003]))
        self.assertEqual(a.as_path_str(), '65001 65002 65003')

    def test_as_path_str_braces_an_as_set_with_commas(self):
        # The brace-and-comma spelling is what IOS and FRR print and what
        # the Stage-4 as-path regex policy will match against, so it is a
        # contract rather than presentation.
        a = AttrSet(as_path=make_as_path([(SEG_AS_SEQUENCE, [65001]),
                                          (SEG_AS_SET, [65003, 65004])]))
        self.assertEqual(a.as_path_str(), '65001 {65003,65004}')

    def test_as_path_str_parenthesises_confederation_segments(self):
        # A confederation sequence is parenthesised and space-separated; a
        # confederation set is bracketed and comma-separated. Rendering
        # either one bare would make a confederation-internal path
        # indistinguishable from a real external one in show output.
        a = AttrSet(as_path=make_as_path(
            [(SEG_AS_CONFED_SEQUENCE, [65100, 65101]),
             (SEG_AS_CONFED_SET, [65102, 65103]),
             (SEG_AS_SEQUENCE, [65001])]))
        self.assertEqual(a.as_path_str(),
                         '(65100 65101) [65102,65103] 65001')

    def test_make_as_path_round_trips_through_as_path_list(self):
        segments = [(SEG_AS_SEQUENCE, [65001, 4200000001]),
                    (SEG_AS_SET, [65003, 65004]),
                    (SEG_AS_CONFED_SEQUENCE, [65100])]
        a = AttrSet(as_path=make_as_path(segments))
        self.assertEqual(a.as_path_list(), segments)

    def test_make_as_path_accepts_a_bare_list_as_one_sequence(self):
        self.assertEqual(make_as_path([65001, 65002]),
                         make_as_path([(SEG_AS_SEQUENCE, [65001, 65002])]))

    def test_make_as_path_rejects_a_segment_the_count_cannot_express(self):
        # The on-wire count is one byte, so a 256-AS segment would silently
        # wrap to 0 and produce a path that decodes as empty.
        #
        # W-3: an AS_SEQUENCE is split instead -- consecutive sequences are
        # the same path -- and only an AS_SET, which cannot be split
        # without lengthening the path, still raises.
        raw = make_as_path([(SEG_AS_SEQUENCE, list(range(1, 301)))])
        self.assertEqual(raw[:2], bytes(bytearray([SEG_AS_SEQUENCE, 255])))
        self.assertEqual(raw[2 + 255 * 4:4 + 255 * 4],
                         bytes(bytearray([SEG_AS_SEQUENCE, 45])))
        self.assertEqual(len(raw), 4 + 300 * 4)
        self.assertEqual(AttrSet(as_path=raw).as_path_len, 300)
        self.assertRaises(ValueError, make_as_path,
                          [(SEG_AS_SET, list(range(256)))])

    def test_make_communities_round_trips_through_community_list(self):
        values = [0xffffff01, 0x10001, 0x10002]
        a = AttrSet(communities=make_communities(values))
        self.assertEqual(a.community_list(), sorted(values))

    def test_community_list_is_empty_when_the_attribute_is_absent(self):
        self.assertEqual(AttrSet().community_list(), [])
        self.assertEqual(AttrSet().cluster_ids(), [])

    def test_origin_tables_name_every_defined_value(self):
        for value in (ORIGIN_IGP_V, ORIGIN_EGP_V, ORIGIN_INCOMPLETE_V):
            self.assertIn(value, ORIGIN_NAMES)
            self.assertIn(value, ORIGIN_CODES)


class AttrSetCanonicalTestCase(unittest.TestCase):
    """Two sets that mean the same thing must be one set.

    Every case here is a pair built from the same information in two
    spellings. If a pair compares unequal the interning table stores both,
    and the memory budget the whole design rests on is gone.
    """

    def test_communities_in_any_order_are_the_same_set(self):
        first = AttrSet(communities=_u32s(0x10002, 0x10001, 0xffffff01))
        second = AttrSet(communities=_u32s(0xffffff01, 0x10001, 0x10002))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(first.communities, second.communities)

    def test_extended_communities_in_any_order_are_the_same_set(self):
        first = AttrSet(ext_communities=_ext(0x0002fde800000002,
                                             0x0002fde800000001))
        second = AttrSet(ext_communities=_ext(0x0002fde800000001,
                                              0x0002fde800000002))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))

    def test_large_communities_in_any_order_are_the_same_set(self):
        first = AttrSet(large_communities=_large((65001, 2, 2),
                                                 (65001, 1, 1)))
        second = AttrSet(large_communities=_large((65001, 1, 1),
                                                  (65001, 2, 2)))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))

    def test_cluster_list_order_is_content_and_is_not_reordered(self):
        # The opposite requirement to the three above, on an adjacent
        # field: CLUSTER_LIST records the reflectors a path traversed, in
        # order, and is also the reflection loop check. Sorting it would
        # merge two genuinely different paths.
        ids = [0x0a000003, 0x0a000001, 0x0a000002]
        forward = AttrSet(cluster_list=_u32s(*ids))
        reverse = AttrSet(cluster_list=_u32s(*reversed(ids)))
        self.assertEqual(forward.cluster_ids(), ids)
        self.assertNotEqual(forward, reverse)
        self.assertEqual(forward.cluster_len, 3)

    def test_unknown_attributes_are_ordered_by_type_code(self):
        # Preserved verbatim for re-advertisement, but ordered, so the
        # sender's arbitrary emission order does not produce two attribute
        # sets for one path.
        high_first = AttrSet(unknown=_tlv(40, b'\x01') + _tlv(35, b'\x02'))
        low_first = AttrSet(unknown=_tlv(35, b'\x02') + _tlv(40, b'\x01'))
        self.assertEqual(high_first.unknown, low_first.unknown)
        self.assertEqual(high_first, low_first)
        self.assertEqual(high_first.unknown,
                         _tlv(35, b'\x02') + _tlv(40, b'\x01'))
        self.assertEqual(high_first.as_dict()['unknown-attributes'],
                         [35, 40])

    def test_a_single_unknown_attribute_is_preserved_unchanged(self):
        run = _tlv(40, b'\x01\x02\x03')
        self.assertEqual(AttrSet(unknown=run).unknown, run)

    def test_communities_not_a_multiple_of_four_are_truncated(self):
        # Downstream of the codec, which has already recorded the fault.
        # Truncating to whole records keeps the "whole records only"
        # invariant that community_list and the re-encoder both assume;
        # raising here would turn an already-accepted message into a
        # crash on the packet path.
        a = AttrSet(communities=_u32s(0x10001) + b'\x00\x01')
        self.assertEqual(a.communities, _u32(0x10001))
        self.assertEqual(a.community_list(), [0x10001])

    def test_extended_communities_are_truncated_to_whole_records(self):
        a = AttrSet(ext_communities=_ext(0x0002fde800000001) + b'\xff' * 3)
        self.assertEqual(a.ext_communities, _ext(0x0002fde800000001))

    def test_large_communities_are_truncated_to_whole_records(self):
        a = AttrSet(large_communities=_large((65001, 1, 2)) + b'\xff' * 5)
        self.assertEqual(a.large_communities, _large((65001, 1, 2)))

    def test_cluster_list_is_truncated_to_whole_records(self):
        a = AttrSet(cluster_list=_u32(0x0a000001) + b'\x0a')
        self.assertEqual(a.cluster_list, _u32(0x0a000001))
        self.assertEqual(a.cluster_len, 1)

    def test_a_short_community_value_becomes_empty_rather_than_partial(self):
        self.assertEqual(AttrSet(communities=b'\x00\x01').communities, b'')

    def test_equality_against_a_non_attrset_is_false_not_an_error(self):
        # AttrSet is a live dictionary key; a comparison against whatever
        # else shares a hash bucket must not raise.
        a = AttrSet()
        self.assertFalse(a == object())
        self.assertTrue(a != object())


class AttrSetDerivedTestCase(unittest.TestCase):
    """The fields best-path reads, computed once and never recomputed."""

    def test_as_path_len_counts_a_sequence_hop_per_as(self):
        a = AttrSet(as_path=make_as_path([65001, 65002, 65003]))
        self.assertEqual(a.as_path_len, 3)

    def test_an_as_set_counts_as_one_hop_however_many_members(self):
        # RFC 4271 s9.1.2.2: an AS_SET stands for an aggregate whose real
        # length is unknown. Counting its members would make aggregation
        # look worse than the routes it replaced and quietly discourage it.
        a = AttrSet(as_path=make_as_path(
            [(SEG_AS_SEQUENCE, [65001]),
             (SEG_AS_SET, [65010, 65011, 65012, 65013])]))
        self.assertEqual(a.as_path_len, 2)

    def test_confederation_segments_count_as_zero_hops(self):
        # RFC 5065: confederation hops are invisible outside the
        # confederation, so a member that counted its own would lose to an
        # external path that is genuinely longer.
        a = AttrSet(as_path=make_as_path(
            [(SEG_AS_CONFED_SEQUENCE, [65100, 65101]),
             (SEG_AS_CONFED_SET, [65102]),
             (SEG_AS_SEQUENCE, [65001, 65002])]))
        self.assertEqual(a.as_path_len, 2)

    def test_neighbor_as_is_the_leftmost_as_of_the_path(self):
        a = AttrSet(as_path=make_as_path([65001, 65002]))
        self.assertEqual(a.neighbor_as, 65001)

    def test_neighbor_as_skips_confederation_segments(self):
        # The MED grouping key of Key Decision 10. A confederation segment
        # naming the group would make MED comparable between paths that
        # arrived through genuinely different neighbours.
        a = AttrSet(as_path=make_as_path(
            [(SEG_AS_CONFED_SEQUENCE, [65100, 65101]),
             (SEG_AS_SEQUENCE, [65001, 65002])]))
        self.assertEqual(a.neighbor_as, 65001)

    def test_neighbor_as_of_a_leading_as_set_is_its_first_member(self):
        a = AttrSet(as_path=make_as_path([(SEG_AS_SET, [65005, 65006])]))
        self.assertEqual(a.neighbor_as, 65005)

    def test_neighbor_as_is_zero_for_an_empty_path(self):
        # A locally originated path forms its own MED group, which is what
        # a neighbouring AS of 0 means here.
        self.assertEqual(AttrSet(as_path=b'').neighbor_as, 0)
        self.assertEqual(AttrSet(as_path=b'').as_path_len, 0)

    def test_a_four_byte_as_survives_the_derivation(self):
        a = AttrSet(as_path=make_as_path([4200000001, 65002]))
        self.assertEqual(a.neighbor_as, 4200000001)
        self.assertEqual(a.as_path_len, 2)

    def test_cluster_len_is_the_record_count_not_the_byte_count(self):
        a = AttrSet(cluster_list=_u32s(1, 2, 3, 4))
        self.assertEqual(a.cluster_len, 4)
        self.assertEqual(len(a.cluster_list), 16)


class AttrSetPresenceTestCase(unittest.TestCase):
    """An absent attribute and a zero-valued one are different paths."""

    def test_an_absent_med_is_not_a_med_of_zero(self):
        # The single most consequential distinction in this module. RFC
        # 4271 compares a missing MED as 0 *by default*, but
        # `bestpath med missing-as-worst` inverts that, and a path with no
        # MED must be re-advertised with no MED. If the presence bit left
        # the hash these two would intern together and one of them would
        # be re-advertised wrongly for as long as it lived.
        absent = AttrSet()
        zero = AttrSet(med=0, has_med=True)
        self.assertNotEqual(absent, zero)
        self.assertFalse(absent.has_med())
        self.assertTrue(zero.has_med())

        table = AttrTable()
        self.assertIsNot(table.intern(absent), table.intern(zero))
        self.assertEqual(table.count(), 2)

    def test_an_absent_local_pref_is_not_a_local_pref_of_zero(self):
        absent = AttrSet()
        zero = AttrSet(local_pref=0, has_local_pref=True)
        self.assertNotEqual(absent, zero)

        table = AttrTable()
        self.assertIsNot(table.intern(absent), table.intern(zero))
        self.assertEqual(table.count(), 2)

    def test_an_absent_originator_id_is_not_an_originator_id_of_zero(self):
        absent = AttrSet()
        zero = AttrSet(originator_id=0, has_originator=True)
        self.assertNotEqual(absent, zero)
        self.assertFalse(absent.has_originator_id)
        self.assertTrue(zero.has_originator_id)

    def test_atomic_aggregate_presence_alone_distinguishes_two_sets(self):
        # The attribute has no value at all: its presence is the whole
        # information, so it can only be carried by the flag.
        self.assertNotEqual(AttrSet(), AttrSet(atomic_aggregate=True))

    def test_the_med_value_is_ignored_while_the_flag_is_clear(self):
        # The decoder leaves the value field alone when the attribute was
        # absent, so two sets that differ only in ignored bytes must still
        # be one set.
        self.assertEqual(AttrSet(med=0), AttrSet(med=99))

    def test_as_dict_omits_an_absent_med_rather_than_rendering_zero(self):
        # The same distinction at the show boundary: a reader of the
        # rendered document must be able to tell "no MED" from "MED 0".
        self.assertNotIn('med', AttrSet().as_dict())
        self.assertEqual(AttrSet(med=0, has_med=True).as_dict()['med'], 0)

    def test_as_dict_renders_the_fields_an_operator_asks_for(self):
        a = AttrSet(origin=ORIGIN_INCOMPLETE_V,
                    as_path=make_as_path([65001]), nexthop=NEXTHOP,
                    communities=make_communities([0xffffff01]),
                    local_pref=100, has_local_pref=True)
        rendered = a.as_dict()
        self.assertEqual(rendered['origin'], 'incomplete')
        self.assertEqual(rendered['as-path'], '65001')
        self.assertEqual(rendered['as-path-length'], 1)
        self.assertEqual(rendered['neighbor-as'], 65001)
        self.assertEqual(rendered['next-hop'], '10.0.0.1')
        self.assertEqual(rendered['communities'], ['no-export'])
        self.assertEqual(rendered['local-preference'], 100)


class AttrSetHasAsTestCase(unittest.TestCase):
    """Loop detection: our own AS anywhere in the path means the path
    came back to us."""

    def test_has_as_finds_an_as_in_a_sequence(self):
        a = AttrSet(as_path=make_as_path([65001, 65002]))
        self.assertTrue(a.has_as(65002))
        self.assertFalse(a.has_as(65003))

    def test_has_as_finds_an_as_in_an_as_set(self):
        a = AttrSet(as_path=make_as_path([(SEG_AS_SET, [65010, 65011])]))
        self.assertTrue(a.has_as(65011))

    def test_has_as_searches_confederation_segments_too(self):
        # A member's own AS inside a confederation segment is just as much
        # a loop as one in a sequence, and skipping those segments is the
        # classic way a confederation forms a routing loop it cannot see.
        a = AttrSet(as_path=make_as_path(
            [(SEG_AS_CONFED_SEQUENCE, [65100]),
             (SEG_AS_CONFED_SET, [65101]),
             (SEG_AS_SEQUENCE, [65001])]))
        self.assertTrue(a.has_as(65100))
        self.assertTrue(a.has_as(65101))
        self.assertTrue(a.has_as(65001))

    def test_has_as_never_matches_as_trans(self):
        # AS_TRANS is the placeholder a 2-octet speaker writes for an AS it
        # cannot represent. Matching it would make every such path look
        # like a loop to anyone who happened to be configured as 23456.
        a = AttrSet(as_path=make_as_path([AS_TRANS_V, 65001]))
        self.assertFalse(a.has_as(AS_TRANS_V))
        self.assertTrue(a.has_as(65001))

    def test_has_as_on_an_empty_path_is_false(self):
        self.assertFalse(AttrSet().has_as(65001))

    def test_has_as_finds_a_four_byte_as(self):
        a = AttrSet(as_path=make_as_path([4200000001]))
        self.assertTrue(a.has_as(4200000001))
        self.assertFalse(a.has_as(1))


class AttrTableTestCase(unittest.TestCase):
    """The interning table, and the refcount that is not CPython's."""

    def setUp(self):
        self.table = AttrTable()

    @staticmethod
    def _set(med=None):
        """An attribute set built fresh each call, optionally with a MED."""
        if med is None:
            return AttrSet(as_path=make_as_path([65001]), nexthop=NEXTHOP)
        return AttrSet(as_path=make_as_path([65001]), nexthop=NEXTHOP,
                       med=med, has_med=True)

    def test_intern_returns_one_object_for_two_equal_sets(self):
        first = self.table.intern(self._set())
        second = self.table.intern(self._set())
        self.assertIs(first, second)
        self.assertEqual(self.table.count(), 1)
        self.assertEqual(len(self.table), 1)

    def test_intern_marks_and_counts_the_canonical_instance(self):
        canonical = self.table.intern(self._set())
        self.assertTrue(canonical.interned)
        self.assertEqual(canonical.refcount, 1)
        self.table.intern(self._set())
        self.assertEqual(canonical.refcount, 2)

    def test_distinct_sets_are_kept_apart(self):
        self.table.intern(self._set(med=1))
        self.table.intern(self._set(med=2))
        self.assertEqual(self.table.count(), 2)

    def test_release_drops_the_set_only_at_zero(self):
        canonical = self.table.intern(self._set())
        self.table.intern(self._set())
        self.assertEqual(self.table.release(canonical), 1)
        self.assertEqual(self.table.count(), 1)
        self.assertEqual(self.table.release(canonical), 0)
        self.assertEqual(self.table.count(), 0)
        self.assertFalse(canonical.interned)
        self.assertEqual(canonical.refcount, 0)

    # --- releasing a set the table does not own ----------------------------
    # `release` answers -1 for "that was not mine to free" and leaves the
    # table untouched. The declaration is `except? -1` rather than
    # `except -1` precisely so that -1 can be an answer instead of an
    # error sentinel; with the bare form the wrapper returned NULL with no
    # exception set and every such call raised SystemError. These three
    # tests pin the answer *and* the invariant that actually matters --
    # nothing is freed -- so a regression in either is caught.

    def test_release_of_a_never_interned_set_does_not_touch_the_table(self):
        # Too many releases is the failure mode that hands out a set the
        # table has already forgotten, so an unknown set must not free
        # anything, and must say so rather than raising.
        self.table.intern(self._set(med=1))
        self.assertEqual(self.table.release(self._set(med=2)), -1)
        self.assertEqual(self.table.count(), 1)
        self.assertEqual(self.table.stats()['releases'], 0)

    def test_release_of_an_equal_but_distinct_set_frees_nothing(self):
        # The subtle one: the argument compares equal to the canonical
        # instance, so a dict lookup finds it. Freeing on that basis would
        # let a caller who built its own copy release someone else's
        # reference, and the canonical set would vanish from under the
        # paths still using it.
        canonical = self.table.intern(self._set())
        twin = self._set()
        self.assertEqual(twin, canonical)
        self.assertIsNot(twin, canonical)
        self.assertEqual(self.table.release(twin), -1)
        self.assertEqual(self.table.count(), 1)
        self.assertEqual(canonical.refcount, 1)
        self.assertTrue(canonical.interned)

    def test_release_of_none_frees_nothing(self):
        self.table.intern(self._set())
        self.assertEqual(self.table.release(None), -1)
        self.assertEqual(self.table.count(), 1)

    def test_stats_reports_the_documented_keys(self):
        self.assertEqual(sorted(self.table.stats().keys()),
                         ['distinct', 'hit-rate', 'hits', 'misses',
                          'references', 'releases'])

    def test_hit_rate_is_hits_over_lookups(self):
        # The number worth watching on a real feed: a low hit rate means
        # the canonical form is failing to collapse something it should,
        # which is a memory regression rather than a correctness one and
        # would otherwise be invisible.
        self.assertEqual(self.table.stats()['hit-rate'], 0.0)
        self.table.intern(self._set())
        self.table.intern(self._set())
        self.table.intern(self._set())
        stats = self.table.stats()
        self.assertEqual(stats['misses'], 1)
        self.assertEqual(stats['hits'], 2)
        self.assertEqual(stats['hit-rate'], round(2.0 / 3.0, 4))
        self.assertEqual(stats['distinct'], 1)
        self.assertEqual(stats['references'], 3)

    def test_releases_are_counted_only_when_they_are_ours(self):
        canonical = self.table.intern(self._set())
        self.table.release(canonical)
        self.assertEqual(self.table.stats()['releases'], 1)

    def test_clear_forgets_every_set_and_every_counter(self):
        self.table.intern(self._set())
        self.table.clear()
        self.assertEqual(self.table.count(), 0)
        self.assertEqual(self.table.stats()['hits'], 0)
        self.assertEqual(self.table.stats()['misses'], 0)

    def test_an_interned_set_still_equals_a_freshly_built_one(self):
        # ATTRF_INTERNED is bookkeeping, so it must stay out of both the
        # hash and the comparison; if it leaked in, the second lookup of
        # every set would miss and the table would never collapse anything.
        canonical = self.table.intern(self._set())
        fresh = self._set()
        self.assertEqual(canonical, fresh)
        self.assertEqual(hash(canonical), hash(fresh))


if __name__ == '__main__':
    unittest.main()
