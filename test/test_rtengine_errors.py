#!/usr/bin/env python

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Tests for the RFC 7606 error matrix in rtengine.plugins.bgp.errors.

This module is a decision table and two counters, and neither has any
state or any wire format, so the risk is not that it crashes -- it is that
it quietly answers a shade too harshly or too leniently:

  * **Every wrong answer here is expensive in one direction or the
    other.** Grading a malformed attribute as ``session-reset`` when it
    should have been ``attribute-discard`` throws away a full table over
    one tunnelled bad byte; grading it the other way keeps a route whose
    next hop nobody can trust. So there is at least one row asserted per
    outcome class rather than a spot check, and the rows chosen are the
    ones that a plausible refactor would move between classes.

  * **The precedence between the rules is the specification, not an
    implementation detail.** Two rules in ``attribute_outcome`` deliberately
    override the table they sit in front of -- the eBGP rule for
    ORIGINATOR_ID and CLUSTER_LIST, and the NLRI-attribute exception to
    the duplicate rule -- and an ``if`` chain reordered by accident still
    passes every test that only ever exercises one rule at a time. Both
    overrides therefore get a test that would fail if the rule moved.

  * **``stats()`` is read by ``/engine/health`` over JSON.** Its tuple
    keys are expanded into records precisely so a consumer never has to
    parse ``'(9, 1)'`` apart again, and the outcome keys are pre-seeded so
    a chart does not wait for a peer to misbehave before the series
    exists. Both are properties of the output document, so the test
    serialises it rather than inspecting it field by field.

Written as plain ``unittest.TestCase`` with no pytest features, matching
``test_rtengine_rib.py``: the 3.6.8 verification host has no pytest and
runs these through ``python3 -m unittest discover -s test``.
"""

import json
import unittest

from packets.routing.rtengine.plugins.bgp.errors import ATTR_LIST, \
    ATTRIBUTE_MATRIX, CEASE_ADMIN_SHUTDOWN, NOTIFY_CEASE, \
    NOTIFY_HOLD_TIMER, NOTIFY_UPDATE, OUTCOME_DISCARD, OUTCOME_OK, \
    OUTCOME_RESET, OUTCOME_WITHDRAW, OUTCOMES, REASON_DUPLICATE, \
    REASON_FLAGS, REASON_LENGTH, REASON_MISSING, REASON_UNRESOLVABLE, \
    REASON_VALUE, REASONS, UPD_MALFORMED_AS_PATH, PeerErrorCounters, \
    UpdateError, attribute_outcome, mandatory_attributes, notify_name, \
    worst_outcome

# Attribute type codes, spelled here as literals for the same reason the
# matrix keys them that way: wire.py owns the ATTR_* names, and a second
# set of constants in the test would be a third source of truth.
ORIGIN = 1
AS_PATH = 2
NEXT_HOP = 3
LOCAL_PREF = 5
ATOMIC_AGGREGATE = 6
AGGREGATOR = 7
COMMUNITIES = 8
ORIGINATOR_ID = 9
CLUSTER_LIST = 10
MP_REACH = 14
MP_UNREACH = 15
AS4_PATH = 17
LARGE_COMMUNITY = 32


class AttributeOutcomeTestCase(unittest.TestCase):
    """One representative row per outcome class, plus the precedence."""

    def test_a_fault_in_the_attribute_list_resets_whatever_the_reason(self):
        # Nothing else can be graded: if the attribute list cannot be
        # framed we do not know where the NLRI begins, so there is no set
        # of prefixes to withdraw and nothing narrower than a reset is
        # honest.
        for reason in REASONS:
            self.assertEqual(attribute_outcome(ATTR_LIST, reason),
                             OUTCOME_RESET)

    def test_a_malformed_well_known_attribute_withdraws(self):
        # RFC 7606 s3(e) explicitly overrides RFC 4271 here: the NLRI is
        # still readable, so the prefixes go and the session lives.
        for attr in (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF):
            self.assertEqual(attribute_outcome(attr, REASON_LENGTH),
                             OUTCOME_WITHDRAW)

    def test_a_malformed_community_attribute_withdraws(self):
        for attr in (COMMUNITIES, LARGE_COMMUNITY):
            self.assertEqual(attribute_outcome(attr, REASON_LENGTH),
                             OUTCOME_WITHDRAW)

    def test_an_annotation_only_attribute_is_discarded(self):
        # These say something *about* a route without changing it or where
        # it points, so dropping the attribute loses information while
        # dropping the route would lose reachability.
        for attr in (ATOMIC_AGGREGATE, AGGREGATOR, AS4_PATH):
            self.assertEqual(attribute_outcome(attr, REASON_LENGTH),
                             OUTCOME_DISCARD)

    def test_a_malformed_nlri_attribute_resets(self):
        # The NLRI lives inside MP_REACH/MP_UNREACH, so past the point
        # where prefixes can be extracted there is nothing to withdraw.
        for attr in (MP_REACH, MP_UNREACH):
            self.assertEqual(attribute_outcome(attr, REASON_UNRESOLVABLE),
                             OUTCOME_RESET)

    def test_the_ebgp_rule_beats_the_table_for_ibgp_only_attributes(self):
        # Precedence, not a row: ORIGINATOR_ID and CLUSTER_LIST sit in the
        # table as treat-as-withdraw, and the eBGP rule in front of it
        # must win. Withdrawing here would punish our session for someone
        # else's leaked route-reflector state, over an attribute that
        # means nothing to us across that boundary.
        for attr in (ORIGINATOR_ID, CLUSTER_LIST):
            self.assertEqual(ATTRIBUTE_MATRIX[attr], OUTCOME_WITHDRAW)
            self.assertEqual(
                attribute_outcome(attr, REASON_LENGTH, from_ebgp=True),
                OUTCOME_DISCARD)
            self.assertEqual(
                attribute_outcome(attr, REASON_LENGTH, from_ebgp=False),
                OUTCOME_WITHDRAW)

    def test_the_ebgp_rule_beats_the_duplicate_rule_as_well(self):
        # The eBGP override is tested ahead of the duplicate rule, so a
        # duplicate ORIGINATOR_ID from an eBGP peer is still a discard.
        # Reordering the two rules would change this answer alone.
        self.assertEqual(
            attribute_outcome(ORIGINATOR_ID, REASON_DUPLICATE,
                              from_ebgp=True),
            OUTCOME_DISCARD)

    def test_a_duplicate_attribute_withdraws(self):
        # RFC 7606 s3(g). The first occurrence is kept by the decoder, but
        # a sender that repeats an attribute has told us two things and we
        # cannot know which it meant.
        for attr in (ORIGIN, AS_PATH, COMMUNITIES, ATOMIC_AGGREGATE):
            self.assertEqual(attribute_outcome(attr, REASON_DUPLICATE),
                             OUTCOME_WITHDRAW)

    def test_a_duplicate_nlri_attribute_resets_instead(self):
        # The exception inside the duplicate rule: s3(g) still requires
        # Malformed Attribute List for a repeated MP_REACH/MP_UNREACH,
        # because the two copies describe two different sets of prefixes.
        for attr in (MP_REACH, MP_UNREACH):
            self.assertEqual(attribute_outcome(attr, REASON_DUPLICATE),
                             OUTCOME_RESET)

    def test_a_duplicate_of_an_otherwise_discarded_attribute_withdraws(self):
        # AGGREGATOR is a discard row, so this pins that the duplicate
        # rule runs before the table rather than after it.
        self.assertEqual(ATTRIBUTE_MATRIX[AGGREGATOR], OUTCOME_DISCARD)
        self.assertEqual(attribute_outcome(AGGREGATOR, REASON_DUPLICATE),
                         OUTCOME_WITHDRAW)

    def test_a_missing_mandatory_attribute_withdraws(self):
        for attr in (ORIGIN, AS_PATH, NEXT_HOP):
            self.assertEqual(attribute_outcome(attr, REASON_MISSING),
                             OUTCOME_WITHDRAW)

    def test_a_missing_local_pref_is_not_a_fault(self):
        # W-6: LOCAL_PREF is well-known *discretionary* (RFC 4271
        # s5.1.5); a receiver applies its default rather than withdrawing.
        self.assertEqual(attribute_outcome(LOCAL_PREF, REASON_MISSING),
                         OUTCOME_OK)

    def test_a_missing_optional_attribute_is_not_a_fault_at_all(self):
        # Returning an outcome rather than raising is what lets a caller
        # ask about an attribute it merely hoped for.
        self.assertEqual(attribute_outcome(COMMUNITIES, REASON_MISSING),
                         OUTCOME_OK)

    def test_an_unknown_optional_attribute_is_discarded(self):
        # The sender's own Optional bit decides, not our table: for an
        # attribute we do not implement, what the sender claimed is the
        # only information there is.
        self.assertNotIn(200, ATTRIBUTE_MATRIX)
        self.assertEqual(
            attribute_outcome(200, REASON_FLAGS, optional=True),
            OUTCOME_DISCARD)

    def test_an_unknown_well_known_attribute_resets(self):
        # Subcode 2 territory: the peer and we disagree about the base
        # protocol, and there is no safe way to carry on.
        self.assertEqual(
            attribute_outcome(200, REASON_FLAGS, optional=False),
            OUTCOME_RESET)

    def test_the_transitive_bit_does_not_change_the_outcome(self):
        # Accepted so the caller can record it with the fault; an
        # attribute we could not parse is not one we can re-advertise.
        for transitive in (False, True):
            self.assertEqual(
                attribute_outcome(200, REASON_VALUE, optional=True,
                                  transitive=transitive),
                OUTCOME_DISCARD)

    def test_every_matrix_row_names_a_defined_outcome(self):
        for outcome in ATTRIBUTE_MATRIX.values():
            self.assertIn(outcome, OUTCOMES)


class MandatoryAttributesTestCase(unittest.TestCase):
    """The same three, inside the AS and out; LOCAL_PREF is neither."""

    def test_ebgp_requires_origin_as_path_and_next_hop(self):
        self.assertEqual(set(mandatory_attributes(True)),
                         set([ORIGIN, AS_PATH, NEXT_HOP]))

    def test_local_pref_is_required_on_neither_kind_of_session(self):
        # RFC 4271 s5.1.5 forbids sending LOCAL_PREF over eBGP, so
        # demanding it there would reject every conformant eBGP UPDATE --
        # the single most damaging way to get this function wrong. And it
        # is discretionary over iBGP too (W-6): demanding it there
        # withdrew every route from an internal peer that omitted it.
        self.assertEqual(set(mandatory_attributes(False)),
                         set([ORIGIN, AS_PATH, NEXT_HOP]))
        self.assertNotIn(LOCAL_PREF, mandatory_attributes(True))


class WorstOutcomeTestCase(unittest.TestCase):
    """An UPDATE is handled by the most severe answer any of its faults
    selects."""

    def test_an_empty_list_is_ok(self):
        self.assertEqual(worst_outcome([]), OUTCOME_OK)

    def test_a_mixed_list_folds_to_the_most_severe(self):
        # Discarding a stray attribute is no help if another attribute in
        # the same message means the prefixes cannot be trusted.
        self.assertEqual(
            worst_outcome([OUTCOME_OK, OUTCOME_DISCARD, OUTCOME_WITHDRAW]),
            OUTCOME_WITHDRAW)
        self.assertEqual(
            worst_outcome([OUTCOME_WITHDRAW, OUTCOME_RESET,
                           OUTCOME_DISCARD]),
            OUTCOME_RESET)

    def test_the_order_of_the_list_does_not_matter(self):
        mixed = [OUTCOME_DISCARD, OUTCOME_RESET, OUTCOME_OK,
                 OUTCOME_WITHDRAW]
        self.assertEqual(worst_outcome(mixed),
                         worst_outcome(list(reversed(mixed))))

    def test_a_single_outcome_is_returned_unchanged(self):
        for outcome in OUTCOMES:
            self.assertEqual(worst_outcome([outcome]), outcome)

    def test_an_unknown_string_ranks_below_everything_known(self):
        # Defensive: a caller that invents an outcome must not be able to
        # out-rank a genuine reset and suppress it.
        self.assertEqual(worst_outcome(['made-up', OUTCOME_RESET]),
                         OUTCOME_RESET)


class NotifyNameTestCase(unittest.TestCase):
    """A NOTIFICATION renders as something an operator can compare with a
    vendor's log line."""

    def test_a_known_code_and_subcode_pair(self):
        self.assertEqual(notify_name(NOTIFY_UPDATE, UPD_MALFORMED_AS_PATH),
                         'UPDATE Message Error/Malformed AS_PATH')
        self.assertEqual(notify_name(NOTIFY_CEASE, CEASE_ADMIN_SHUTDOWN),
                         'Cease/Administrative Shutdown')

    def test_subcode_zero_names_the_code_alone(self):
        # Zero is "unspecified" for every code and is the correct thing to
        # send with Hold Timer Expired, so it must not render as an
        # unknown subcode.
        self.assertEqual(notify_name(NOTIFY_HOLD_TIMER, 0),
                         'Hold Timer Expired')

    def test_omitting_the_subcode_names_the_code_alone(self):
        self.assertEqual(notify_name(NOTIFY_UPDATE), 'UPDATE Message Error')

    def test_an_unknown_pair_is_rendered_numerically(self):
        # When a peer sends something we have never heard of, the number
        # is the only useful thing in the message; replacing it with
        # 'unknown' would make the log line worthless.
        self.assertEqual(notify_name(200, 7), 'Error Code 200/Subcode 7')

    def test_an_unknown_subcode_of_a_known_code_keeps_the_code_name(self):
        self.assertEqual(notify_name(NOTIFY_UPDATE, 200),
                         'UPDATE Message Error/Subcode 200')


class UpdateErrorTestCase(unittest.TestCase):
    """The unit the counters and show output are built from."""

    def test_as_dict_carries_the_four_fields(self):
        err = UpdateError(COMMUNITIES, REASON_LENGTH, OUTCOME_WITHDRAW,
                          'length 6 is not a multiple of 4')
        self.assertEqual(err.as_dict(), {
            'attr_type': COMMUNITIES,
            'reason': REASON_LENGTH,
            'outcome': OUTCOME_WITHDRAW,
            'detail': 'length 6 is not a multiple of 4',
        })

    def test_detail_is_optional(self):
        # The decoder builds these on the packet path, where formatting a
        # string for an UPDATE that will be discarded anyway is pure cost.
        self.assertIsNone(
            UpdateError(ORIGIN, REASON_VALUE, OUTCOME_WITHDRAW).detail)


class PeerErrorCountersTestCase(unittest.TestCase):
    """Three breakdowns rather than one total, because they answer
    different questions."""

    def setUp(self):
        self.counters = PeerErrorCounters()

    @staticmethod
    def _error(attr=COMMUNITIES, reason=REASON_LENGTH,
               outcome=OUTCOME_WITHDRAW):
        return UpdateError(attr, reason, outcome)

    def test_record_returns_the_outcome_it_counted(self):
        # So a decode loop can accumulate the worst outcome without
        # reaching back into the object it just handed over.
        self.assertEqual(self.counters.record(self._error()),
                         OUTCOME_WITHDRAW)

    def test_record_counts_by_outcome_and_by_attribute_and_reason(self):
        # "Forty-one discards on one optional attribute" and "forty-one
        # withdrawn UPDATEs" are the same number and very different
        # problems, which is why the two breakdowns are kept apart.
        self.counters.record(self._error())
        self.counters.record(self._error())
        self.counters.record(self._error(attr=ORIGIN,
                                         reason=REASON_VALUE))
        stats = self.counters.stats()
        self.assertEqual(stats['outcomes'][OUTCOME_WITHDRAW], 3)
        self.assertEqual(stats['attributes'],
                         [{'attr_type': ORIGIN, 'reason': REASON_VALUE,
                           'count': 1},
                          {'attr_type': COMMUNITIES,
                           'reason': REASON_LENGTH, 'count': 2}])

    def test_total_counts_every_fault_including_the_harmless_ones(self):
        # A decoder that keeps asking about attributes that turn out to be
        # fine is itself worth noticing.
        self.counters.record(self._error(outcome=OUTCOME_OK))
        self.counters.record(self._error(outcome=OUTCOME_RESET))
        self.assertEqual(self.counters.total(), 2)

    def test_notifications_are_counted_separately_in_each_direction(self):
        # "Who ended the last session" is the most common question asked
        # of show ip bgp neighbors, and a combined counter cannot answer
        # it.
        self.assertEqual(
            self.counters.record_notification_sent(NOTIFY_CEASE,
                                                   CEASE_ADMIN_SHUTDOWN), 1)
        self.assertEqual(
            self.counters.record_notification_sent(NOTIFY_CEASE,
                                                   CEASE_ADMIN_SHUTDOWN), 2)
        self.assertEqual(
            self.counters.record_notification_received(
                NOTIFY_UPDATE, UPD_MALFORMED_AS_PATH), 1)
        stats = self.counters.stats()
        self.assertEqual(stats['notifications_sent'],
                         [{'code': NOTIFY_CEASE,
                           'subcode': CEASE_ADMIN_SHUTDOWN,
                           'name': 'Cease/Administrative Shutdown',
                           'count': 2}])
        self.assertEqual(stats['notifications_received'],
                         [{'code': NOTIFY_UPDATE,
                           'subcode': UPD_MALFORMED_AS_PATH,
                           'name': 'UPDATE Message Error/Malformed AS_PATH',
                           'count': 1}])

    def test_notifications_are_not_counted_as_attribute_faults(self):
        self.counters.record_notification_sent(NOTIFY_CEASE, 1)
        self.assertEqual(self.counters.total(), 0)

    def test_every_outcome_key_exists_before_anything_goes_wrong(self):
        # A health consumer plotting 'treat-as-withdraw' should not have
        # to cope with the series appearing only once a peer misbehaves.
        stats = PeerErrorCounters().stats()
        self.assertEqual(sorted(stats['outcomes'].keys()),
                         sorted(OUTCOMES))
        for value in stats['outcomes'].values():
            self.assertEqual(value, 0)
        self.assertEqual(stats['faults'], 0)

    def test_stats_is_json_serialisable_as_it_stands(self):
        # The tuple keys are expanded into records precisely so a consumer
        # of /engine/health never has to parse '(9, 1)' back apart; a dict
        # keyed by tuples would raise here instead.
        self.counters.record(self._error(attr=ORIGINATOR_ID,
                                         reason=REASON_FLAGS))
        self.counters.record_notification_sent(NOTIFY_CEASE, 1)
        self.counters.record_notification_received(NOTIFY_UPDATE, 1)
        document = json.loads(json.dumps(self.counters.stats()))
        self.assertEqual(sorted(document.keys()),
                         ['attributes', 'faults', 'notifications_received',
                          'notifications_sent', 'outcomes'])

    def test_stats_copies_rather_than_exposing_the_live_counters(self):
        stats = self.counters.stats()
        stats['outcomes'][OUTCOME_RESET] = 99
        self.assertEqual(self.counters.stats()['outcomes'][OUTCOME_RESET],
                         0)

    def test_reset_zeroes_every_counter_and_keeps_the_outcome_keys(self):
        # After a clear ip bgp the numbers must describe the session in
        # front of the operator, not its predecessor.
        self.counters.record(self._error())
        self.counters.record_notification_sent(NOTIFY_CEASE, 1)
        self.counters.record_notification_received(NOTIFY_CEASE, 1)
        self.counters.reset()
        stats = self.counters.stats()
        self.assertEqual(stats['faults'], 0)
        self.assertEqual(stats['attributes'], [])
        self.assertEqual(stats['notifications_sent'], [])
        self.assertEqual(stats['notifications_received'], [])
        self.assertEqual(sorted(stats['outcomes'].keys()),
                         sorted(OUTCOMES))


if __name__ == '__main__':
    unittest.main()
