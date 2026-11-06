#!/usr/bin/env python

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Tests for the BGP decision process in rtengine.plugins.bgp.bestpath.

The decision process is thirteen comparisons in a fixed order, and the
order is the specification. A step applied too early silently changes
which route a network uses; a step applied too late is invisible until
the day two paths happen to tie above it. So the bulk of this file is one
test per step, each built from two paths differing *only* in the
criterion under test, asserting both the winner and the reported reason.
Asserting the reason and not just the winner is the point: a comparator
that reaches the right answer at the wrong step is right by accident and
will be wrong for the next pair.

Beyond the per-step sweep the file is shaped around the three ways this
code can be wrong in a way that a casual test would not notice:

  * **Absent is not zero.** An absent LOCAL_PREF compares as 100, not 0.
    Get that wrong and every eBGP path loses to every iBGP path at step
    3, so the external-over-internal comparison at step 8 -- the one
    that is supposed to decide it -- is never reached. The symptom is
    not a crash, it is a network that prefers the long way round.

  * **MED is not a total order.** It is only comparable between paths
    from the same neighbouring AS, which makes the relation
    non-transitive, which makes a linear scan depend on arrival order.
    ``deterministic_med`` groups by neighbouring AS to remove that
    dependence, and the test for it constructs the classic cycle and
    runs every permutation of the input, because a single ordering
    proves nothing about an order-dependence bug.

  * **Multipath is a different question from best path.** A path joins
    the set when nothing that expresses a real *preference* separates it
    from the winner; the tie-breaks below MULTIPATH_BOUNDARY exist only
    to manufacture a single winner and must not exclude anybody. The
    boundary, the identical-AS-path rule and the never-mix-eBGP-and-iBGP
    rule each get their own test, because each of the three is a rule
    somebody will eventually "simplify".

The ``STEP_*`` codes are declared in ``bestpath.pxd`` as a C enum and are
therefore not importable from Python; only the ``STEP_REASONS`` mapping
is exported. They are mirrored below and checked against that mapping in
:class:`StepCodeTestCase`, so a renumbering fails loudly here rather than
making every reason assertion in the file quietly compare the wrong pair
of integers.

Written as plain ``unittest.TestCase`` with no pytest features, matching
``test_rtengine_rib.py``: the 3.6.8 verification host has no pytest and
runs these through ``python3 -m unittest discover -s test``.
"""

import itertools
import unittest

from packets.routing.rtengine.plugins.bgp.attrs import AttrSet, \
    ORIGIN_EGP_V, ORIGIN_IGP_V, ORIGIN_INCOMPLETE_V, make_as_path, \
    make_communities
from packets.routing.rtengine.plugins.bgp.bestpath import LOCAL_PEER, \
    MED_WORST, MULTIPATH_BOUNDARY, SRC_AGGREGATE, SRC_LOCAL, SRC_PEER, \
    SRC_REDIST, STEP_REASONS, BestpathConfig, BgpDest, BgpPath, PeerRef, \
    compare, explain, select
from packets.routing.rtengine.rib.prefix import parse_prefix

# The decision-process step codes, mirrored from bestpath.pxd. See the
# module docstring: the enum is C-level and the .pyx exports only the
# reason text, so a test that wants to say "this was decided at the MED
# step" has nowhere else to get the number from.
STEP_NONE = 0
STEP_RESOLVED = 1
STEP_WEIGHT = 2
STEP_LOCAL_PREF = 3
STEP_ORIGINATED = 4
STEP_AS_PATH = 5
STEP_ORIGIN = 6
STEP_MED = 7
STEP_EXTERNAL = 8
STEP_IGP_METRIC = 9
STEP_AGE = 10
STEP_ROUTER_ID = 11
STEP_CLUSTER_LIST = 12
STEP_PEER_ADDR = 13

# The default LOCAL_PREF a path without the attribute is compared at.
# Named because two separate tests turn on it being 100 rather than 0.
DEFAULT_LOCAL_PREF = 100

PREFIX = parse_prefix('10.0.0.0/8')


def attrs(as_path=(65001,), origin=ORIGIN_IGP_V, med=None, local_pref=None,
          originator_id=None, cluster_list=(), communities=(),
          nexthop=b'\x0a\x00\x00\xfe'):
    """An AttrSet with only the fields a decision-process test cares about.

    ``med`` and ``local_pref`` take None for "attribute absent", which is
    the distinction the whole comparison turns on and which a plain
    integer argument would quietly erase. ``as_path`` defaults to a
    single-AS sequence so that two paths built with the defaults are in
    the same neighbouring-AS group and their MEDs are comparable --
    otherwise half the tests in this file would be silently skipping the
    step they claim to exercise.
    """
    return AttrSet(
        origin=origin,
        as_path=make_as_path(list(as_path)),
        nexthop=nexthop,
        med=0 if med is None else med,
        has_med=med is not None,
        local_pref=0 if local_pref is None else local_pref,
        has_local_pref=local_pref is not None,
        originator_id=0 if originator_id is None else originator_id,
        has_originator=originator_id is not None,
        cluster_list=b''.join([make_communities([c]) for c in cluster_list]),
        communities=make_communities(communities))


def peer(last_octet, router_id=None, is_ebgp=True, peer_as=65001):
    """A PeerRef with its identity spread across three distinct fields.

    The router id defaults to something derived from, but not equal to,
    the address, so that a comparator confusing the two tie-breaks -- one
    at step 11 and one at step 13 -- produces a different answer rather
    than the same one by coincidence.
    """
    if router_id is None:
        router_id = 0x01010100 + last_octet
    return PeerRef(peer_as=peer_as, local_as=65000, router_id=router_id,
                   addr=bytes(bytearray([10, 0, 0, last_octet])),
                   is_ebgp=is_ebgp)


def path(attributes=None, contributor=None, **kwargs):
    """A BgpPath with every selection input pinned by default.

    ``recv_time`` defaults to a fixed value rather than being left to
    vary, so the age tie-break at step 10 cannot decide a test that is
    about something else -- the same trap ``_route`` avoids in
    ``test_rtengine_rib.py``.
    """
    kwargs.setdefault('recv_time', 100.0)
    return BgpPath(attributes if attributes is not None else attrs(),
                   contributor if contributor is not None else peer(1),
                   **kwargs)


DEFAULT_CONFIG = BestpathConfig(local_as=65000, router_id=0x0a0a0a0a)


class StepCodeTestCase(unittest.TestCase):
    """The mirrored step codes must still name the steps they name."""

    def test_every_mirrored_code_matches_the_exported_reason(self):
        # This file asserts step numbers all the way through and gets
        # them from a hand-written mirror of a C enum. If the enum is
        # renumbered, this is the one test that has to fail, loudly,
        # instead of sixty tests quietly comparing the wrong integers.
        expected = {
            STEP_NONE: 'no distinguishing criterion',
            STEP_RESOLVED: 'only resolvable next hop',
            STEP_WEIGHT: 'higher weight',
            STEP_LOCAL_PREF: 'higher local preference',
            STEP_ORIGINATED: 'locally originated',
            STEP_AS_PATH: 'shorter AS path',
            STEP_ORIGIN: 'lower origin',
            STEP_MED: 'lower MED',
            STEP_EXTERNAL: 'external peer',
            STEP_IGP_METRIC: 'lower IGP metric to next hop',
            STEP_AGE: 'older path',
            STEP_ROUTER_ID: 'lower router ID',
            STEP_CLUSTER_LIST: 'shorter cluster list',
            STEP_PEER_ADDR: 'lower neighbour address',
        }
        self.assertEqual(STEP_REASONS, expected)

    def test_the_steps_are_in_ascending_decision_order(self):
        # The comparator walks them in numeric order, so the numbers are
        # the order. A step inserted with a number out of sequence would
        # be applied in the wrong place.
        self.assertEqual(sorted(STEP_REASONS), list(range(14)))

    def test_the_multipath_boundary_is_the_igp_metric_step(self):
        # Everything after the IGP metric is an arbitrary tie-break, and
        # the boundary is what stops those tie-breaks from shrinking a
        # multipath set the operator asked for.
        self.assertEqual(MULTIPATH_BOUNDARY, STEP_IGP_METRIC)


class DecisionStepTestCase(unittest.TestCase):
    """One test per step, in the order the comparator applies them.

    Each builds two paths differing only in the criterion under test and
    asserts the winner *and* the step that decided, because a comparator
    that gets the right answer from the wrong step is right by accident.
    """

    def assert_beats(self, winner, loser, step, cfg=None):
        """Assert ``winner`` beats ``loser``, and at which step.

        Run in both argument orders. The comparator returns a sign, and a
        sign convention inverted in one branch is a bug that a one-sided
        assertion cannot see.
        """
        cfg = DEFAULT_CONFIG if cfg is None else cfg
        result, decided, reason = compare(winner, loser, cfg)
        self.assertLess(result, 0)
        self.assertEqual(decided, step)
        self.assertEqual(reason, STEP_REASONS[step])
        result, decided, reason = compare(loser, winner, cfg)
        self.assertGreater(result, 0)
        self.assertEqual(decided, step)
        self.assertEqual(select([loser, winner], cfg).best, winner)
        self.assertEqual(select([winner, loser], cfg).best, winner)

    def test_step_1_an_unresolved_path_is_not_a_candidate(self):
        # Next-hop resolution is a precondition, not a preference: a path
        # whose next hop does not resolve cannot carry traffic however
        # good it looks. It stays in the table because next-hop tracking
        # may resolve it a second later.
        good = path(contributor=peer(2))
        bad = path(contributor=peer(1), resolved=False)
        self.assert_beats(good, bad, STEP_RESOLVED)

    def test_step_2_higher_weight_wins(self):
        # Weight is local and outranks everything: it is the operator
        # overriding the protocol, and an operator override that can be
        # beaten by an attribute is not an override.
        self.assert_beats(path(weight=100), path(weight=50), STEP_WEIGHT)

    def test_step_3_higher_local_preference_wins(self):
        self.assert_beats(path(attrs(local_pref=200)),
                          path(attrs(local_pref=100)), STEP_LOCAL_PREF)

    def test_step_4_a_locally_originated_path_wins(self):
        # ``source`` is ordered so that local beats aggregate beats
        # redistributed beats learned-from-a-peer. Our own route must win
        # against the same route learned back from a neighbour, or the
        # router follows somebody else's copy of its own advertisement.
        self.assert_beats(path(attrs(()), LOCAL_PEER, source=SRC_LOCAL),
                          path(source=SRC_PEER), STEP_ORIGINATED)

    def test_step_4_orders_every_source_class(self):
        # The full order, because only the two extremes are obvious.
        for better, worse in ((SRC_LOCAL, SRC_AGGREGATE),
                              (SRC_AGGREGATE, SRC_REDIST),
                              (SRC_REDIST, SRC_PEER)):
            self.assert_beats(path(source=better), path(source=worse),
                              STEP_ORIGINATED)

    def test_step_5_a_shorter_as_path_wins(self):
        # Both paths are from the same neighbouring AS so that the MED
        # step below cannot be what actually decides this.
        self.assert_beats(path(attrs((65001,))),
                          path(attrs((65001, 65009, 65010))), STEP_AS_PATH)

    def test_step_6_a_lower_origin_wins(self):
        # IGP beats EGP beats INCOMPLETE: a route the originator knows
        # from its own IGP is better evidence than one it inferred.
        self.assert_beats(path(attrs(origin=ORIGIN_IGP_V)),
                          path(attrs(origin=ORIGIN_EGP_V)), STEP_ORIGIN)
        self.assert_beats(path(attrs(origin=ORIGIN_EGP_V)),
                          path(attrs(origin=ORIGIN_INCOMPLETE_V)),
                          STEP_ORIGIN)

    def test_step_7_a_lower_med_wins(self):
        # Lower, not higher: MED is the neighbour telling us which of its
        # entry points it would rather we used, expressed as a cost.
        self.assert_beats(path(attrs(med=10)), path(attrs(med=20)),
                          STEP_MED)

    def test_step_8_an_external_path_beats_an_internal_one(self):
        # Prefer the path that does not need another internal hop. This
        # is also the step the absent-LOCAL_PREF default exists to let us
        # reach.
        self.assert_beats(path(contributor=peer(1, is_ebgp=True)),
                          path(contributor=peer(2, is_ebgp=False)),
                          STEP_EXTERNAL)

    def test_step_9_a_lower_igp_metric_wins(self):
        # The last step that expresses a real preference, and therefore
        # the last one a path can lose at and still be a multipath.
        self.assert_beats(path(igp_metric=5), path(igp_metric=9),
                          STEP_IGP_METRIC)

    def test_step_10_the_older_path_wins(self):
        # Stability, not quality. Preferring the established path means a
        # session that flaps cannot repeatedly take the best path back
        # and re-announce the change to the entire network.
        self.assert_beats(path(recv_time=100.0), path(recv_time=200.0),
                          STEP_AGE)

    def test_step_10_is_skipped_between_internal_paths(self):
        # Age applies only between two external paths. Two iBGP paths
        # must fall through to the router id, which every reflector in
        # the cluster agrees on, rather than to an arrival time that
        # differs on every router.
        older = path(contributor=peer(1, router_id=1, is_ebgp=False),
                     recv_time=100.0)
        newer = path(contributor=peer(2, router_id=2, is_ebgp=False),
                     recv_time=200.0)
        self.assert_beats(older, newer, STEP_ROUTER_ID)

    def test_step_10_is_skipped_when_router_id_determinism_is_asked_for(self):
        # ``compare_router_id`` trades stability for reproducibility: an
        # operator who wants every router in the network to make the same
        # choice cannot have it depend on local arrival times.
        cfg = BestpathConfig(local_as=65000, compare_router_id=True)
        self.assert_beats(path(contributor=peer(1, router_id=1),
                               recv_time=200.0),
                          path(contributor=peer(2, router_id=2),
                               recv_time=100.0),
                          STEP_ROUTER_ID, cfg=cfg)

    def test_step_11_a_lower_router_id_wins(self):
        low = path(contributor=peer(1, router_id=0x0a000001,
                                    is_ebgp=False))
        high = path(contributor=peer(2, router_id=0x0a000002,
                                     is_ebgp=False))
        self.assert_beats(low, high, STEP_ROUTER_ID)

    def test_step_12_a_shorter_cluster_list_wins(self):
        # Fewer reflections means fewer hops through the cluster. Both
        # peers share a router id so the previous step cannot decide.
        short = path(attrs(cluster_list=(1,)),
                     peer(1, router_id=7, is_ebgp=False))
        long = path(attrs(cluster_list=(1, 2)),
                    peer(2, router_id=7, is_ebgp=False))
        self.assert_beats(short, long, STEP_CLUSTER_LIST)

    def test_step_13_a_lower_neighbour_address_wins(self):
        # The last resort, and it must be decisive: two paths that reach
        # here and still tie would leave the caller with no winner at all.
        low = path(contributor=peer(1, router_id=7, is_ebgp=False))
        high = path(contributor=peer(2, router_id=7, is_ebgp=False))
        self.assert_beats(low, high, STEP_PEER_ADDR)

    def test_two_identical_paths_from_one_peer_compare_equal(self):
        # Zero is the caller's signal that it has a duplicate rather than
        # a tie, so it must be reachable and must report no step.
        p = peer(1)
        self.assertEqual(compare(path(contributor=p), path(contributor=p),
                                 DEFAULT_CONFIG),
                         (0, STEP_NONE, STEP_REASONS[STEP_NONE]))


class StepPrecedenceTestCase(unittest.TestCase):
    """An earlier step must win even when a later one disagrees."""

    def test_weight_beats_a_better_everything_else(self):
        # The ordering property stated the hard way: a path that is worse
        # on every subsequent criterion still wins on weight alone.
        winner = path(attrs((65001, 65002, 65003), origin=ORIGIN_INCOMPLETE_V,
                            med=500), peer(9, is_ebgp=False), weight=100,
                      igp_metric=99, recv_time=900.0)
        loser = path(attrs((65001,), origin=ORIGIN_IGP_V, med=0),
                     peer(1, is_ebgp=True), weight=50, igp_metric=1,
                     recv_time=1.0)
        result, step, _ = compare(winner, loser, DEFAULT_CONFIG)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_WEIGHT)

    def test_local_preference_beats_a_shorter_as_path(self):
        # The pair an operator actually configures: local policy raising
        # a preference is meant to override the protocol's own metric.
        self.assert_local_pref_wins(200, (65001, 65002, 65003), 100,
                                    (65001,))

    def assert_local_pref_wins(self, hi, hi_as_path, lo, lo_as_path):
        winner = path(attrs(hi_as_path, local_pref=hi))
        loser = path(attrs(lo_as_path, local_pref=lo))
        result, step, _ = compare(winner, loser, DEFAULT_CONFIG)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_LOCAL_PREF)


class AbsentLocalPrefTestCase(unittest.TestCase):
    """An absent LOCAL_PREF compares as 100, and it matters."""

    def test_an_absent_local_pref_compares_equal_to_an_explicit_hundred(self):
        # If absent meant 0 this would be decided at step 3 instead of
        # falling through, and the assertion below would be the symptom.
        absent = path(attrs(local_pref=None), peer(1, is_ebgp=False))
        explicit = path(attrs(local_pref=DEFAULT_LOCAL_PREF),
                        peer(2, is_ebgp=False))
        result, step, _ = compare(absent, explicit, DEFAULT_CONFIG)
        self.assertNotEqual(step, STEP_LOCAL_PREF)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_ROUTER_ID)

    def test_an_ebgp_path_is_not_beaten_before_the_external_step(self):
        # The failure this default exists to prevent. LOCAL_PREF must not
        # cross an eBGP boundary, so an eBGP path never carries one; if
        # absent compared as 0, every eBGP path would lose at step 3 to
        # every iBGP path and step 8 would never decide anything. The
        # visible symptom is a network that prefers the long way round.
        external = path(attrs(local_pref=None), peer(1, is_ebgp=True))
        internal = path(attrs(local_pref=DEFAULT_LOCAL_PREF),
                        peer(2, is_ebgp=False))
        result, step, reason = compare(external, internal, DEFAULT_CONFIG)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_EXTERNAL)
        self.assertEqual(reason, STEP_REASONS[STEP_EXTERNAL])

    def test_an_explicit_lower_local_pref_still_loses_at_step_three(self):
        # The other side of the same coin: the default must not swallow a
        # LOCAL_PREF an operator really did set below it.
        external = path(attrs(local_pref=None), peer(1, is_ebgp=True))
        internal = path(attrs(local_pref=50), peer(2, is_ebgp=False))
        result, step, _ = compare(external, internal, DEFAULT_CONFIG)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_LOCAL_PREF)

    def test_an_explicit_higher_local_pref_beats_an_absent_one(self):
        internal = path(attrs(local_pref=150), peer(2, is_ebgp=False))
        external = path(attrs(local_pref=None), peer(1, is_ebgp=True))
        result, step, _ = compare(internal, external, DEFAULT_CONFIG)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_LOCAL_PREF)


class UnresolvedPathTestCase(unittest.TestCase):
    """A path whose next hop does not resolve can never win."""

    def test_an_unresolved_path_loses_despite_being_better_everywhere(self):
        # Resolution is a precondition, so it has to survive a path that
        # would otherwise win at the very first comparison after it.
        unresolved = path(attrs((65001,), local_pref=500, med=0),
                          peer(1), weight=1000, igp_metric=0,
                          recv_time=1.0, resolved=False)
        plain = path(attrs((65001, 65002, 65003),
                           origin=ORIGIN_INCOMPLETE_V, med=500),
                     peer(2), weight=0, igp_metric=99, recv_time=900.0)
        result, step, reason = compare(unresolved, plain, DEFAULT_CONFIG)
        self.assertGreater(result, 0)
        self.assertEqual(step, STEP_RESOLVED)
        self.assertEqual(reason, STEP_REASONS[STEP_RESOLVED])
        self.assertEqual(select([unresolved, plain], DEFAULT_CONFIG).best,
                         plain)

    def test_an_all_unresolved_destination_has_no_best_path(self):
        # Not "the least bad one". Installing an unresolvable next hop is
        # a blackhole, and the prefix must stay unresolved until next-hop
        # tracking says otherwise.
        paths = [path(contributor=peer(1), resolved=False),
                 path(contributor=peer(2), resolved=False)]
        result = select(paths, DEFAULT_CONFIG)
        self.assertIsNone(result.best)
        self.assertEqual(result.reason, STEP_NONE)
        self.assertEqual(result.multipath, [])

    def test_an_empty_destination_has_no_best_path(self):
        result = select([], DEFAULT_CONFIG)
        self.assertIsNone(result.best)
        self.assertEqual(result.considered, 0)

    def test_a_sole_survivor_reports_that_it_was_the_only_one(self):
        # ``only resolvable next hop`` is a different answer from ``no
        # distinguishing criterion`` and an operator needs to see which.
        winner = path(contributor=peer(1))
        result = select([winner, path(contributor=peer(2), resolved=False)],
                        DEFAULT_CONFIG)
        self.assertEqual(result.best, winner)
        self.assertEqual(result.reason, STEP_RESOLVED)


class AsPathIgnoreTestCase(unittest.TestCase):
    """as-path-ignore removes step 5 and nothing else."""

    def test_as_path_ignore_skips_the_length_comparison(self):
        # Used where AS-path length is meaningless -- a confederation, or
        # a network buying transit from a peer that prepends heavily.
        cfg = BestpathConfig(local_as=65000, as_path_ignore=True)
        short = path(attrs((65001,)), peer(1))
        long = path(attrs((65001, 65009, 65010)), peer(1))
        self.assertEqual(compare(short, long, DEFAULT_CONFIG)[1],
                         STEP_AS_PATH)
        self.assertEqual(compare(short, long, cfg),
                         (0, STEP_NONE, STEP_REASONS[STEP_NONE]))

    def test_as_path_ignore_leaves_the_later_steps_working(self):
        # Skipping a step must not skip the ones after it. With the
        # length ignored the pair has to be decided by origin.
        cfg = BestpathConfig(local_as=65000, as_path_ignore=True)
        short = path(attrs((65001,), origin=ORIGIN_EGP_V), peer(1))
        long = path(attrs((65001, 65009), origin=ORIGIN_IGP_V), peer(1))
        result, step, _ = compare(short, long, cfg)
        self.assertGreater(result, 0)
        self.assertEqual(step, STEP_ORIGIN)


class MedComparisonTestCase(unittest.TestCase):
    """MED: absent, inverted, and only within one neighbouring AS."""

    def test_an_absent_med_compares_as_zero_by_default(self):
        # RFC 4271's default. A path with no MED is therefore the most
        # attractive one, which surprises people but is what the standard
        # says and what a neighbour sending no MED should expect.
        with_med = path(attrs(med=10), peer(1))
        without = path(attrs(med=None), peer(2))
        result, step, _ = compare(with_med, without, DEFAULT_CONFIG)
        self.assertGreater(result, 0)
        self.assertEqual(step, STEP_MED)

    def test_med_missing_as_worst_inverts_an_absent_med(self):
        # The knob exists because "no MED means best" lets a neighbour
        # that simply forgot to set one outrank every path from a
        # neighbour that configured theirs carefully.
        cfg = BestpathConfig(local_as=65000, med_missing_as_worst=True)
        with_med = path(attrs(med=10), peer(1))
        without = path(attrs(med=None), peer(2))
        result, step, _ = compare(with_med, without, cfg)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_MED)

    def test_med_missing_as_worst_uses_the_largest_representable_value(self):
        # An absent MED must lose to any real one, including the largest
        # a neighbour can actually send.
        cfg = BestpathConfig(local_as=65000, med_missing_as_worst=True)
        huge = path(attrs(med=MED_WORST - 1), peer(1))
        without = path(attrs(med=None), peer(2))
        result, step, _ = compare(huge, without, cfg)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_MED)

    def test_med_is_not_compared_across_neighbouring_ases(self):
        # MED expresses one neighbour's internal costs in units only it
        # defines. Comparing across ASes is comparing a Cisco's IGP metric
        # with a Juniper's hop count and calling one of them better.
        low = path(attrs((65001,), med=10), peer(1, router_id=2))
        high = path(attrs((65002,), med=20), peer(2, router_id=1))
        result, step, _ = compare(low, high, DEFAULT_CONFIG)
        self.assertNotEqual(step, STEP_MED)
        self.assertGreater(result, 0)
        self.assertEqual(step, STEP_ROUTER_ID)

    def test_always_compare_med_compares_across_neighbouring_ases(self):
        # Safe only in a network where every neighbour is known to use
        # the same scale, which is why it is off by default.
        cfg = BestpathConfig(local_as=65000, always_compare_med=True)
        low = path(attrs((65001,), med=10), peer(1, router_id=2))
        high = path(attrs((65002,), med=20), peer(2, router_id=1))
        result, step, _ = compare(low, high, cfg)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_MED)

    def test_a_locally_originated_path_forms_its_own_med_group(self):
        # An empty AS_PATH gives a neighbouring AS of 0, which is not any
        # real neighbour's group -- correctly, since a local path carries
        # nobody's MED.
        local = attrs(())
        self.assertEqual(local.neighbor_as, 0)
        self.assertNotEqual(local.neighbor_as, attrs((65001,)).neighbor_as)


class DeterministicMedTestCase(unittest.TestCase):
    """The most important property in the file: selection is reproducible.

    MED is only comparable inside one neighbouring AS, so the "better
    than" relation is *not transitive* and a linear scan gets a different
    answer depending on the order it met the candidates in. That is not a
    tie-break detail: it means two routers with identical tables disagree,
    and a full-table load is not reproducible from one run to the next.
    ``deterministic_med`` groups by neighbouring AS, picks a winner per
    group and only then compares across groups, which removes the
    dependence on arrival order entirely.
    """

    def _cycle(self):
        """Three paths whose "better than" relation is a cycle.

        ``b`` beats ``a`` on MED, because they share a neighbouring AS.
        ``a`` beats ``c`` and ``c`` beats ``b`` on router id, because
        those pairs do not and so never reach the MED comparison. Every
        other criterion is identical, so nothing else can intervene.
        """
        a = path(attrs((65001,), med=200), peer(1, router_id=1))
        b = path(attrs((65001,), med=100), peer(3, router_id=3))
        c = path(attrs((65002,), med=150), peer(2, router_id=2))
        return a, b, c

    def test_the_constructed_relation_really_is_a_cycle(self):
        # Asserted explicitly, because if the fixture ever stops being
        # non-transitive the permutation test below still passes and
        # stops proving anything at all.
        a, b, c = self._cycle()
        self.assertLess(compare(b, a, DEFAULT_CONFIG)[0], 0)
        self.assertEqual(compare(b, a, DEFAULT_CONFIG)[1], STEP_MED)
        self.assertLess(compare(a, c, DEFAULT_CONFIG)[0], 0)
        self.assertEqual(compare(a, c, DEFAULT_CONFIG)[1], STEP_ROUTER_ID)
        self.assertLess(compare(c, b, DEFAULT_CONFIG)[0], 0)
        self.assertEqual(compare(c, b, DEFAULT_CONFIG)[1], STEP_ROUTER_ID)

    def test_deterministic_med_picks_the_same_winner_in_every_order(self):
        # Six permutations of three paths. With grouping on, all six must
        # agree; this is the property that makes a full-table load
        # reproducible and two routers with the same inputs agree.
        cfg = BestpathConfig(local_as=65000, deterministic_med=True)
        winners = set()
        for ordering in itertools.permutations(self._cycle()):
            result = select(list(ordering), cfg)
            winners.add(id(result.best))
            self.assertIsNotNone(result.best)
        self.assertEqual(len(winners), 1)

    def test_without_deterministic_med_the_order_changes_the_winner(self):
        # The behaviour being removed, demonstrated rather than asserted
        # from the documentation. Three different winners across six
        # orderings of the same three paths: that is what "arrival-order
        # dependent" costs, and why this engine defaults the grouping on
        # in a deliberate departure from IOS.
        cfg = BestpathConfig(local_as=65000, deterministic_med=False)
        winners = set()
        for ordering in itertools.permutations(self._cycle()):
            winners.add(id(select(list(ordering), cfg).best))
        self.assertEqual(len(winners), 3)

    def test_the_grouping_is_what_achieves_the_determinism(self):
        # Shows the mechanism, not just the outcome. Within the shared
        # neighbouring AS the MED comparison picks b over a in either
        # order; the surviving group winners are then compared across
        # groups, where router id decides for c -- and c is exactly the
        # winner every permutation produced above.
        cfg = BestpathConfig(local_as=65000, deterministic_med=True)
        a, b, c = self._cycle()
        self.assertEqual(a.attrs.neighbor_as, b.attrs.neighbor_as)
        self.assertNotEqual(a.attrs.neighbor_as, c.attrs.neighbor_as)
        self.assertEqual(select([a, b], cfg).best, b)
        self.assertEqual(select([b, a], cfg).best, b)
        self.assertEqual(select([b, c], cfg).best, c)
        for ordering in itertools.permutations((a, b, c)):
            self.assertEqual(select(list(ordering), cfg).best, c)

    def test_the_eliminated_path_cannot_come_back_through_ordering(self):
        # ``a`` loses its group to ``b`` and must never win overall, even
        # in the ordering where a linear scan would have let it.
        cfg = BestpathConfig(local_as=65000, deterministic_med=True)
        a, b, c = self._cycle()
        for ordering in itertools.permutations((a, b, c)):
            self.assertIsNot(select(list(ordering), cfg).best, a)

    def test_grouping_does_not_change_a_transitive_case(self):
        # The grouping must be invisible when MED is not involved,
        # otherwise it would be buying reproducibility by changing
        # answers that were never in doubt.
        cfg = BestpathConfig(local_as=65000, deterministic_med=True)
        plain = BestpathConfig(local_as=65000, deterministic_med=False)
        best = path(attrs((65001,)), peer(1), weight=100)
        rest = [path(attrs((65002,)), peer(2), weight=50),
                path(attrs((65003,)), peer(3), weight=10)]
        for ordering in itertools.permutations([best] + rest):
            self.assertEqual(select(list(ordering), cfg).best, best)
            self.assertEqual(select(list(ordering), plain).best, best)


class OriginatorIdTestCase(unittest.TestCase):
    """A reflected path is tie-broken on who originated it."""

    def test_originator_id_replaces_the_peers_router_id(self):
        # Otherwise every path reflected by one reflector carries that
        # reflector's id and the tie-break collapses -- it is supposed to
        # distinguish origins, and after reflection the peer's id names
        # the reflector rather than the origin.
        low = path(attrs(originator_id=1), peer(1, router_id=0xffffff00,
                                                is_ebgp=False))
        high = path(attrs(originator_id=2), peer(2, router_id=0x00000001,
                                                 is_ebgp=False))
        result, step, _ = compare(low, high, DEFAULT_CONFIG)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_ROUTER_ID)

    def test_the_peers_router_id_is_used_when_there_is_no_originator(self):
        # The unreflected case has to keep working, and the two must not
        # be confusable: here the peer ids order the opposite way round
        # from the originator ids in the test above.
        low = path(attrs(originator_id=None),
                   peer(1, router_id=0x00000001, is_ebgp=False))
        high = path(attrs(originator_id=None),
                    peer(2, router_id=0xffffff00, is_ebgp=False))
        result, step, _ = compare(low, high, DEFAULT_CONFIG)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_ROUTER_ID)

    def test_an_originator_id_of_zero_is_still_an_originator_id(self):
        # Presence is a flag, not a sentinel value. A reflector that set
        # ORIGINATOR_ID to 0 must not fall back to the peer's id.
        zero = path(attrs(originator_id=0), peer(1, router_id=0xffffff00,
                                                 is_ebgp=False))
        one = path(attrs(originator_id=1), peer(2, router_id=0x00000001,
                                                is_ebgp=False))
        result, step, _ = compare(zero, one, DEFAULT_CONFIG)
        self.assertLess(result, 0)
        self.assertEqual(step, STEP_ROUTER_ID)


class BgpDestTestCase(unittest.TestCase):
    """Path identity is (peer, path_id), never the attributes."""

    def test_add_replaces_a_path_with_the_same_peer_and_id(self):
        # A peer resending a prefix with a new MED has changed its single
        # path. A container keyed on attributes would grow one path per
        # update until the session dropped.
        dest = BgpDest(PREFIX)
        p = peer(1)
        first = path(attrs(med=10), p)
        self.assertIsNone(dest.add(first))
        second = path(attrs(med=20), p)
        self.assertIs(dest.add(second), first)
        self.assertEqual(len(dest), 1)
        self.assertIs(dest.find(p, 0), second)

    def test_add_returns_the_replaced_path_so_its_attrs_can_be_released(self):
        # The return value is not a convenience. Dropping it on the floor
        # leaks the replaced path's interned attribute set, which is the
        # leak that makes an AttrTable grow without bound on a flapping
        # peer.
        dest = BgpDest(PREFIX)
        p = peer(1)
        first = path(attrs(med=10), p)
        dest.add(first)
        replaced = dest.add(path(attrs(med=20), p))
        self.assertIs(replaced, first)
        self.assertIsNot(replaced.attrs, dest.paths[0].attrs)

    def test_a_different_path_id_from_one_peer_is_a_second_path(self):
        # RFC 7911 ADD-PATH: the same peer may legitimately offer several
        # paths for one prefix, distinguished only by the identifier.
        dest = BgpDest(PREFIX)
        p = peer(1)
        first = path(attrs(med=10), p, path_id=1)
        second = path(attrs(med=20), p, path_id=2)
        self.assertIsNone(dest.add(first))
        self.assertIsNone(dest.add(second))
        self.assertEqual(len(dest), 2)
        self.assertIs(dest.find(p, 1), first)
        self.assertIs(dest.find(p, 2), second)

    def test_path_id_zero_collapses_to_one_path_per_peer(self):
        # Without ADD-PATH every identifier is 0, which must reproduce
        # the pre-ADD-PATH rule exactly.
        dest = BgpDest(PREFIX)
        p = peer(1)
        dest.add(path(attrs(med=10), p))
        dest.add(path(attrs(med=20), p))
        dest.add(path(attrs(med=30), p))
        self.assertEqual(len(dest), 1)

    def test_remove_returns_the_path_it_took_out(self):
        # Same ownership argument as ``add``: the caller releases the
        # attribute set and cannot do so without the path.
        dest = BgpDest(PREFIX)
        p = peer(1)
        target = path(attrs(med=10), p, path_id=7)
        dest.add(target)
        dest.add(path(attrs(med=20), peer(2)))
        self.assertIs(dest.remove(p, 7), target)
        self.assertEqual(len(dest), 1)
        self.assertIsNone(dest.remove(p, 7))
        self.assertIsNone(dest.find(p, 7))

    def test_remove_peer_takes_every_path_that_peer_contributed(self):
        # One session teardown, one call, and the count is what the
        # caller uses to know how many attribute sets to release.
        dest = BgpDest(PREFIX)
        leaving = peer(1)
        staying = peer(2)
        for path_id in (1, 2, 3):
            dest.add(path(attrs(med=path_id), leaving, path_id=path_id))
        dest.add(path(attrs(med=9), staying))
        self.assertEqual(dest.remove_peer(leaving), 3)
        self.assertEqual(len(dest), 1)
        self.assertEqual(dest.remove_peer(leaving), 0)
        self.assertEqual(len(dest), 1)

    def test_reselect_caches_the_best_path_and_the_reason(self):
        # ``show`` reads these rather than re-running the decision
        # process, so a stale cache is a report that contradicts the
        # forwarding table.
        dest = BgpDest(PREFIX)
        winner = path(attrs((65001,)), peer(1), weight=100)
        loser = path(attrs((65002,)), peer(2), weight=50)
        dest.add(winner)
        dest.add(loser)
        result = dest.reselect(DEFAULT_CONFIG)
        self.assertIs(dest.best, winner)
        self.assertIs(dest.best, result.best)
        self.assertEqual(dest.reason, STEP_WEIGHT)
        self.assertEqual(dest.reason_text, STEP_REASONS[STEP_WEIGHT])

    def test_reselect_follows_a_change_in_the_paths(self):
        # The cache must be a cache, not a memory. Withdrawing the winner
        # has to move the best path, not leave the old one on display.
        dest = BgpDest(PREFIX)
        winner = path(attrs((65001,)), peer(1), weight=100)
        runner_up = path(attrs((65002,)), peer(2), weight=50)
        dest.add(winner)
        dest.add(runner_up)
        dest.reselect(DEFAULT_CONFIG)
        self.assertIs(dest.best, winner)
        dest.remove(winner.peer, 0)
        dest.reselect(DEFAULT_CONFIG)
        self.assertIs(dest.best, runner_up)

    def test_as_dict_reports_the_prefix_the_reason_and_every_path(self):
        dest = BgpDest(PREFIX)
        dest.add(path(attrs((65001,)), peer(1), weight=100))
        dest.add(path(attrs((65002,)), peer(2), weight=50))
        dest.reselect(DEFAULT_CONFIG)
        rendered = dest.as_dict()
        self.assertEqual(rendered['prefix'], '10.0.0.0/8')
        self.assertEqual(rendered['reason'], STEP_REASONS[STEP_WEIGHT])
        self.assertEqual(len(rendered['paths']), 2)


class MultipathTestCase(unittest.TestCase):
    """Equal-cost means equal down to the last real preference."""

    def _equal_pair(self, **cfg_kwargs):
        """Two eBGP paths separated only by a tie-break below the boundary."""
        cfg = BestpathConfig(local_as=65000, maximum_paths=4,
                             **cfg_kwargs)
        first = path(attrs((65001,)), peer(1, router_id=1))
        second = path(attrs((65001,)), peer(2, router_id=2))
        return cfg, first, second

    def test_paths_equal_down_to_the_igp_metric_join_the_set(self):
        # These two are separated only by their router ids, at step 11 --
        # below the boundary, so the separation is an arbitrary choice of
        # winner and not a reason to install one route where the operator
        # configured two.
        cfg, first, second = self._equal_pair()
        result = select([first, second], cfg)
        self.assertEqual(compare(first, second, cfg)[1], STEP_ROUTER_ID)
        self.assertEqual(len(result.multipath), 2)
        self.assertIn(first, result.multipath)
        self.assertIn(second, result.multipath)
        self.assertTrue(first.multipath)
        self.assertTrue(second.multipath)

    def test_a_worse_igp_metric_keeps_a_path_out(self):
        # The boundary from the other side: the IGP metric is the last
        # criterion that expresses a real preference, so losing on it is
        # losing, not tying.
        cfg, first, second = self._equal_pair()
        second = path(attrs((65001,)), peer(2, router_id=2), igp_metric=5)
        result = select([first, second], cfg)
        self.assertEqual(result.best, first)
        self.assertEqual(result.multipath, [])
        self.assertFalse(second.multipath)

    def test_maximum_paths_of_one_disables_multipath(self):
        # The default. One route installed, and no path marked -- a stale
        # multipath flag would show up in ``show`` as a set of one.
        cfg = BestpathConfig(local_as=65000, maximum_paths=1)
        first = path(attrs((65001,)), peer(1, router_id=1))
        second = path(attrs((65001,)), peer(2, router_id=2))
        result = select([first, second], cfg)
        self.assertEqual(result.best, first)
        self.assertEqual(result.multipath, [])
        self.assertFalse(first.multipath)
        self.assertFalse(second.multipath)

    def test_maximum_paths_caps_the_set(self):
        # An operator's limit is a hardware limit as often as a policy
        # one, and exceeding it means routes the forwarding plane cannot
        # hold.
        cfg = BestpathConfig(local_as=65000, maximum_paths=2)
        paths = [path(attrs((65001,)), peer(n, router_id=n))
                 for n in range(1, 5)]
        result = select(paths, cfg)
        self.assertEqual(len(result.multipath), 2)

    def test_equal_length_but_different_as_paths_are_excluded(self):
        # Same length, different ASes: different paths in every way that
        # matters for traffic engineering. Load-sharing across them is a
        # decision an operator must opt into, not a default.
        cfg = BestpathConfig(local_as=65000, maximum_paths=4)
        first = path(attrs((65001,)), peer(1, router_id=1))
        second = path(attrs((65002,)), peer(2, router_id=2))
        self.assertEqual(first.attrs.as_path_len, second.attrs.as_path_len)
        self.assertNotEqual(first.attrs.as_path, second.attrs.as_path)
        result = select([first, second], cfg)
        self.assertEqual(result.multipath, [])

    def test_as_path_multipath_relax_admits_them(self):
        # The opt-in. With it set the same two paths must form a set,
        # which is what makes the previous test a policy and not a bug.
        cfg = BestpathConfig(local_as=65000, maximum_paths=4,
                             as_path_multipath_relax=True)
        first = path(attrs((65001,)), peer(1, router_id=1))
        second = path(attrs((65002,)), peer(2, router_id=2))
        result = select([first, second], cfg)
        self.assertEqual(len(result.multipath), 2)

    def test_the_set_never_mixes_external_and_internal_paths(self):
        # Mixing them means some traffic takes an extra internal hop for
        # no reason, and the two have separate configured limits
        # precisely because they are separate decisions.
        cfg = BestpathConfig(local_as=65000, maximum_paths=4,
                             maximum_paths_ibgp=4)
        external = path(attrs((65001,)), peer(1, router_id=1,
                                              is_ebgp=True))
        also_external = path(attrs((65001,)), peer(2, router_id=2,
                                                   is_ebgp=True))
        internal = path(attrs((65001,)), peer(3, router_id=3,
                                              is_ebgp=False))
        result = select([external, also_external, internal], cfg)
        self.assertEqual(len(result.multipath), 2)
        self.assertNotIn(internal, result.multipath)
        self.assertFalse(internal.multipath)

    def test_an_internal_best_path_uses_the_internal_limit(self):
        # The two limits must not be interchangeable: an iBGP winner is
        # capped by maximum_paths_ibgp however generous the eBGP limit is.
        cfg = BestpathConfig(local_as=65000, maximum_paths=4,
                             maximum_paths_ibgp=1)
        first = path(attrs((65001,)), peer(1, router_id=1, is_ebgp=False))
        second = path(attrs((65001,)), peer(2, router_id=2, is_ebgp=False))
        self.assertEqual(select([first, second], cfg).multipath, [])

    def test_an_unresolved_path_never_joins_the_set(self):
        # It could not carry the traffic the set exists to share.
        cfg = BestpathConfig(local_as=65000, maximum_paths=4)
        first = path(attrs((65001,)), peer(1, router_id=1))
        second = path(attrs((65001,)), peer(2, router_id=2),
                      resolved=False)
        result = select([first, second], cfg)
        self.assertEqual(result.best, first)
        self.assertEqual(result.multipath, [])


class ExplainTestCase(unittest.TestCase):
    """``explain`` answers "why is my route not being used"."""

    def test_every_losing_path_is_given_a_losing_reason(self):
        # Selection only reports the one comparison that decided the
        # winner. An operator debugging a missing route needs the verdict
        # against a specific rival, which is what this produces.
        winner = path(attrs((65001,)), peer(1), weight=100)
        on_as_path = path(attrs((65002, 65003, 65004)), peer(2))
        on_origin = path(attrs((65005,), origin=ORIGIN_INCOMPLETE_V),
                         peer(3))
        rendered = explain([winner, on_as_path, on_origin], DEFAULT_CONFIG)
        self.assertEqual(rendered['reason'], STEP_REASONS[STEP_WEIGHT])
        verdicts = [row['verdict'] for row in rendered['paths']]
        self.assertEqual(verdicts.count('best'), 1)
        for row in rendered['paths']:
            if row['verdict'] == 'best':
                self.assertNotIn('lost-on', row)
            else:
                self.assertEqual(row['lost-on'],
                                 STEP_REASONS[row['step']])
                self.assertNotEqual(row['step'], STEP_NONE)

    def test_the_losing_reason_names_the_step_that_actually_decided(self):
        # Not merely "a reason". Each rival here loses at a different
        # step, and reporting one reason for all of them would be the
        # obvious wrong implementation.
        winner = path(attrs((65001,)), peer(1), weight=100)
        on_weight = path(attrs((65001,)), peer(2), weight=50)
        rendered = explain([winner, on_weight], DEFAULT_CONFIG)
        rows = dict([(row['verdict'], row) for row in rendered['paths']])
        self.assertEqual(rows['not best']['step'], STEP_WEIGHT)

    def test_an_unresolved_path_is_reported_as_unresolved(self):
        # It did not lose a comparison, it never entered one, and saying
        # it lost on weight would send an operator looking in the wrong
        # place entirely.
        winner = path(attrs((65001,)), peer(1))
        unresolved = path(attrs((65001,)), peer(2), resolved=False)
        rendered = explain([winner, unresolved], DEFAULT_CONFIG)
        verdicts = [row['verdict'] for row in rendered['paths']]
        self.assertEqual(sorted(verdicts), ['best', 'unresolved'])

    def test_a_destination_with_no_resolvable_path_says_so(self):
        paths = [path(attrs((65001,)), peer(1), resolved=False),
                 path(attrs((65001,)), peer(2), resolved=False)]
        rendered = explain(paths, DEFAULT_CONFIG)
        self.assertIsNone(rendered['best'])
        self.assertEqual(rendered['reason'], 'no resolvable path')
        self.assertEqual([row['verdict'] for row in rendered['paths']],
                         ['unresolved', 'unresolved'])

    def test_a_multipath_member_is_labelled_as_one(self):
        # A path in the set is not "not best" -- it is carrying traffic,
        # and telling an operator it lost would send them debugging a
        # route that is already installed.
        cfg = BestpathConfig(local_as=65000, maximum_paths=4)
        first = path(attrs((65001,)), peer(1, router_id=1))
        second = path(attrs((65001,)), peer(2, router_id=2))
        rendered = explain([first, second], cfg)
        self.assertEqual(rendered['multipath'], 2)
        verdicts = sorted([row['verdict'] for row in rendered['paths']])
        self.assertEqual(verdicts, ['best', 'multipath'])


if __name__ == '__main__':
    unittest.main()
