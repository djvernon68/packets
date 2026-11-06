#!/usr/bin/env python

"""Tests for the protocol-neutral policy engine in rtengine.policy.

Four modules, four kinds of risk, and the suite is shaped around the risks
rather than around the source layout:

  * ``prefixlist`` is a *semantic* risk wearing a performance disguise. The
    le/ge rules have four spellings and every one of them is a different
    length window, the first matching entry in sequence order decides rather
    than the most specific one, and the index that makes it fast is a radix
    trie whose descent has to visit every covering entry. So the match
    semantics are table-driven across all four spellings and both families,
    with overlapping entries built so that only the sequence number can
    decide the outcome -- a suite that tested one entry at a time would pass
    against an implementation that returned the longest match. The trie is
    the only thing here holding memory, so it is also checked structurally,
    through the node counter, ``weakref`` and repeated rebuilds.

  * ``aspath`` is a spelling contract. A regex written against a different
    rendering of the AS path does not fail, it silently never matches, so the
    tests pin the exact canonical string -- including the brace-and-comma
    spelling of an AS_SET -- against the BGP plugin's own renderer, and pin
    the IOS meaning of the underscore, which used to be a literal (P-1).

  * ``routemap`` is a vocabulary. Every supported match clause is tested both
    matching and not matching, because a clause that always matches and a
    clause that never matches are both filters that do nothing and neither is
    visible from a single positive test. The community tests include the
    4-byte and 12-byte alignment traps with attributes constructed so that an
    unaligned search would answer yes -- the assertion is on both halves, so
    the test documents the trap as well as catching it. Every set clause is
    checked for the exact normalized form a protocol translator consumes.

  * ``store`` is about version numbers, and the expensive failure is the
    quiet one: an object whose version moved when its configuration did not
    causes a full table re-advertisement to every peer. So idempotence is
    asserted on object identity, on every version and on the revision, and
    separately from the assertion that a real change does move them.

Written as plain ``unittest.TestCase`` with no pytest features: the 3.6.8
verification host has no pytest and runs this through
``python3 -m unittest discover -s test``.
"""

import gc
import os
import struct
import subprocess
import sys
import unittest
import weakref

from packets.routing.rtengine.errors import ConfigError
from packets.routing.rtengine.policy import aspath as _aspath
from packets.routing.rtengine.policy.aspath import (AsPathList, AsPathMatcher,
                                                    compile_pattern)
from packets.routing.rtengine.policy.prefixlist import (ACTION_DENY,
                                                        ACTION_NAMES,
                                                        ACTION_PERMIT,
                                                        NO_MATCH, PrefixList,
                                                        PrefixListEntry)
from packets.routing.rtengine.policy.routemap import (ORIGIN_EGP, ORIGIN_IGP,
                                                      ORIGIN_INCOMPLETE,
                                                      RouteMap,
                                                      RouteMapClause,
                                                      RouteMapResult)
from packets.routing.rtengine.policy.store import KINDS, PolicyStore
from packets.routing.rtengine.rib.prefix import (AFI_IP, AFI_IP6, Prefix,
                                                 parse_prefix)

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Communities used all over the route-map tests. 65000:1 and 65000:2 are
# ordinary; NO_ADVERTISE is the well-known one the alignment trap hides.
C_65000_1 = (65000 << 16) | 1
C_65000_2 = (65000 << 16) | 2
C_NO_ADVERTISE = 0xffffff02

# The pair whose concatenation contains NO_ADVERTISE's four bytes starting at
# offset 2. Both are perfectly ordinary communities -- 0:65535 and 65282:0 --
# and they are already in canonical (sorted) order, which is what an attribute
# set really holds. An unaligned membership test answers "yes, this route
# carries NO_ADVERTISE" for them.
C_STRADDLE_LOW = 0x0000ffff
C_STRADDLE_HIGH = 0xff020000


def packed_communities(*values):
    """Pack communities the way a canonical attribute set holds them.

    Sorted and four bytes each, which is what the BGP decoder produces and
    therefore what every test here must compare against.

    :param values: community values as ints.
    :return: the packed bytes.
    """
    return b''.join(struct.pack('>I', v) for v in sorted(values))


def packed_large(*triples):
    """Pack large communities, sorted, twelve bytes each.

    :param triples: ``(a, b, c)`` tuples.
    :return: the packed bytes.
    """
    return b''.join(struct.pack('>III', *t) for t in sorted(triples))


class Attrs(object):
    """A stand-in for a protocol's path attributes.

    The route-map's attribute contract is duck-typed on purpose -- policy is
    core code and must not import the BGP plugin -- so the suite carries its
    own minimal implementation of that contract. Two things are checked
    against the real ``AttrSet`` separately: that its rendering of the AS
    path is the one the regexes are written for, and that it satisfies this
    same contract with no adapter.

    ``med`` and ``local_pref`` are None for "the attribute is absent", which
    is a distinct state from zero and one the match clauses have to
    distinguish.
    """

    __slots__ = ('origin', 'communities', 'large_communities',
                 'ext_communities', 'nexthop', 'med', 'local_pref',
                 '_as_path', '_has_med', '_has_local_pref')

    def __init__(self, origin=ORIGIN_IGP, as_path='', communities=b'',
                 large_communities=b'', ext_communities=b'', nexthop=b'',
                 med=None, local_pref=None):
        self.origin = origin
        self._as_path = as_path
        self.communities = communities
        self.large_communities = large_communities
        self.ext_communities = ext_communities
        self.nexthop = nexthop
        self._has_med = med is not None
        self._has_local_pref = local_pref is not None
        self.med = 0 if med is None else med
        self.local_pref = 0 if local_pref is None else local_pref

    def as_path_str(self):
        return self._as_path

    def has_med(self):
        return self._has_med

    def has_local_pref(self):
        return self._has_local_pref


def v4_list(*entries):
    """Build an IPv4 prefix-list from ``(seq, action, prefix, le, ge)`` rows.

    :param entries: rows, each 3 to 5 long.
    :return: the :class:`PrefixList`.
    """
    plist = PrefixList('PL-TEST', AFI_IP)
    for row in entries:
        plist.add(*row)
    return plist


def v6_list(*entries):
    """Build an IPv6 prefix-list from the same rows.

    :param entries: rows, each 3 to 5 long.
    :return: the :class:`PrefixList`.
    """
    plist = PrefixList('PL6-TEST', AFI_IP6)
    for row in entries:
        plist.add(*row)
    return plist


def one_clause_map(match=None, edits=None, action='permit', resolver=None):
    """Build a route-map of one clause, for the vocabulary tests.

    :param match: the match dict, or None.
    :param edits: the set dict, or None.
    :param action: the clause action.
    :param resolver: the list resolver.
    :return: the :class:`RouteMap`.
    """
    rmap = RouteMap('RM-TEST', resolver)
    rmap.add_clause(10, action, match, edits)
    return rmap


def store_with(document):
    """Build a loaded :class:`PolicyStore`.

    :param document: the configuration document.
    :return: the store.
    """
    store = PolicyStore()
    store.load(document)
    return store


def prefix_doc(name, entries, section='ip'):
    """Build a document holding one prefix-list.

    :param name: the list name.
    :param entries: the entry objects.
    :param section: ``'ip'`` or ``'ipv6'``.
    :return: the document.
    """
    return {section: {'prefix-list': {name: entries}}}


class PolicyBoundaryTestCase(unittest.TestCase):
    """The core/plugin boundary, and the constants duplicated across it."""

    def test_no_policy_module_names_a_plugin(self):
        # A source scan rather than an import check, because the rule is
        # about the dependency and not only about what gets imported at run
        # time: a lazy import inside a function would satisfy a sys.modules
        # test until the moment it ran.
        directory = os.path.join(_REPO_ROOT, 'packets', 'routing', 'rtengine',
                                 'policy')
        checked = 0
        for name in sorted(os.listdir(directory)):
            if not name.endswith(('.py', '.pyx', '.pxd')):
                continue
            with open(os.path.join(directory, name), 'r') as handle:
                text = handle.read()
            checked += 1
            self.assertNotIn('rtengine.plugins', text,
                             '%s reaches into a protocol plugin' % name)
            self.assertNotIn('import bgp', text,
                             '%s reaches into a protocol plugin' % name)
        self.assertGreaterEqual(checked, 5, 'the policy sources moved')

    def test_using_the_package_imports_no_plugin(self):
        # The run-time half of the same rule, in a fresh interpreter so that
        # another test's imports cannot make it pass. The probe does real
        # work -- loads a document and applies a route-map -- so a lazy
        # import on the hot path would be caught too.
        probe = (
            'import sys\n'
            'from packets.routing.rtengine.policy import PolicyStore\n'
            'from packets.routing.rtengine.rib.prefix import parse_prefix\n'
            'store = PolicyStore()\n'
            'store.load({"ip": {"prefix-list": {"P": ['
            '{"action": "permit", "prefix": "10.0.0.0/8", "le": 24}]}},'
            '"route-map": {"R": [{"seq": 10, "action": "permit",'
            ' "match": {"ip": {"address": {"prefix-list": "P"}}},'
            ' "set": {"local-preference": 200}}]}})\n'
            'store.route_map("R").apply(parse_prefix("10.1.0.0/16"), None)\n'
            'print(",".join(sorted(m for m in sys.modules'
            ' if "rtengine.plugins" in m)))\n'
        )
        env = dict(os.environ)
        env['PYTHONPATH'] = _REPO_ROOT
        output = subprocess.check_output([sys.executable, '-c', probe],
                                         cwd=_REPO_ROOT, env=env)
        self.assertEqual(output.decode('ascii').strip(), '')

    def test_origin_constants_agree_with_the_bgp_plugin(self):
        # The three origin values are duplicated in policy because a core
        # module may not import a plugin. They are a registry assignment, so
        # the duplication is safe -- but only as long as it is pinned.
        from packets.routing.rtengine.plugins.bgp import attrs

        self.assertEqual(ORIGIN_IGP, attrs.ORIGIN_IGP_V)
        self.assertEqual(ORIGIN_EGP, attrs.ORIGIN_EGP_V)
        self.assertEqual(ORIGIN_INCOMPLETE, attrs.ORIGIN_INCOMPLETE_V)

    def test_action_constants_and_names(self):
        self.assertEqual(ACTION_DENY, 0)
        self.assertEqual(ACTION_PERMIT, 1)
        self.assertEqual(NO_MATCH, -1)
        self.assertEqual(ACTION_NAMES, {0: 'deny', 1: 'permit'})

    def test_a_real_attrset_satisfies_the_apply_contract(self):
        # The claim in routemap's docstring is that AttrSet needs no adapter.
        # This is that claim as a test: a route-map using every
        # attribute-dependent match clause is applied to a real AttrSet.
        from packets.routing.rtengine.plugins.bgp import attrs

        real = attrs.AttrSet(
            origin=attrs.ORIGIN_EGP_V,
            as_path=attrs.make_as_path([(2, [65001, 65002])]),
            communities=attrs.make_communities([C_65000_1]),
            nexthop=b'\xc0\x00\x02\x01', med=7, has_med=True,
            local_pref=150, has_local_pref=True)
        rmap = one_clause_map({'origin': 'egp', 'metric': 7,
                               'local-preference': 150,
                               'next-hop': '192.0.2.1',
                               'community': ['65000:1'],
                               'as-path': '^65001'},
                              {'local-preference': 200})
        result = rmap.apply(parse_prefix('10.0.0.0/8'), real)
        self.assertTrue(result)
        self.assertEqual(result.sets, {'local-preference': 200})

    def test_as_path_string_spelling_is_the_plugins(self):
        # The canonical string the regexes are written against. If AttrSet
        # ever renders a set differently, every configured pattern that
        # mentions one silently stops matching, so the spelling is pinned
        # here rather than only described in a docstring.
        from packets.routing.rtengine.plugins.bgp import attrs

        rendered = attrs.AttrSet(as_path=attrs.make_as_path([
            (2, [65001, 65002]), (1, [65003, 65004])])).as_path_str()
        self.assertEqual(rendered, '65001 65002 {65003,65004}')
        self.assertTrue(AsPathMatcher(r'\{65003,65004\}$').matches(rendered))


class PrefixListEntryTestCase(unittest.TestCase):
    """The le/ge window, derived once at construction."""

    def test_window_for_every_spelling_ipv4(self):
        # (le, ge) -> the inclusive length window the entry accepts. The four
        # rows are the whole of the le/ge rule; everything else in this file
        # tests that the rule is applied, not what it is.
        for le, ge, expected in ((0, 0, (8, 8)),
                                 (24, 0, (8, 24)),
                                 (0, 24, (24, 32)),
                                 (24, 16, (16, 24))):
            entry = PrefixListEntry(5, 'permit', '10.0.0.0/8', le, ge)
            self.assertEqual((entry.lo, entry.hi), expected,
                             'le=%d ge=%d' % (le, ge))

    def test_window_for_every_spelling_ipv6(self):
        for le, ge, expected in ((0, 0, (32, 32)),
                                 (64, 0, (32, 64)),
                                 (0, 48, (48, 128)),
                                 (64, 48, (48, 64))):
            entry = PrefixListEntry(5, 'permit', '2001:db8::/32', le, ge)
            self.assertEqual((entry.lo, entry.hi), expected,
                             'le=%d ge=%d' % (le, ge))

    def test_ge_zero_is_the_unset_sentinel_and_le_max_says_it_instead(self):
        # A `ge 0` filter cannot be spelled, because 0 is the sentinel. It is
        # also not needed: on a /0 entry, `le 32` accepts exactly the same
        # lengths, and the two entries are identical after construction.
        sentinel = PrefixListEntry(5, 'permit', '0.0.0.0/0', 0, 0)
        spelled = PrefixListEntry(5, 'permit', '0.0.0.0/0', 32, 0)
        self.assertEqual((sentinel.lo, sentinel.hi), (0, 0))
        self.assertEqual((spelled.lo, spelled.hi), (0, 32))

    def test_action_accepts_both_spellings(self):
        self.assertEqual(
            PrefixListEntry(5, 'permit', '10.0.0.0/8').action, ACTION_PERMIT)
        self.assertEqual(
            PrefixListEntry(5, 'deny', '10.0.0.0/8').action, ACTION_DENY)
        self.assertEqual(
            PrefixListEntry(5, ACTION_DENY, '10.0.0.0/8').action, ACTION_DENY)

    def test_prefix_accepts_text_or_object(self):
        wanted = parse_prefix('10.0.0.0/8')
        self.assertEqual(PrefixListEntry(5, 'permit', wanted).prefix, wanted)
        self.assertEqual(
            PrefixListEntry(5, 'permit', '10.0.0.0/8').prefix, wanted)
        self.assertEqual(
            PrefixListEntry(5, 'permit', b'10.0.0.0/8').prefix, wanted)

    def test_malformed_entries_are_rejected(self):
        # One case per rule, because a single "it raises" test would pass
        # with any one of them implemented.
        for args, why in (
                ((5, 'allow', '10.0.0.0/8'), 'an action that is not a word'),
                ((5, 2, '10.0.0.0/8'), 'an action outside 0..1'),
                ((5, True, '10.0.0.0/8'), 'a bool action'),
                ((5, 'permit', '10.0.0.0/33'), 'a length out of range'),
                ((5, 'permit', '10.0.0.0/+8'), 'a signed length'),
                ((5, 'permit', 'not an address'), 'unparseable text'),
                ((5, 'permit', 17), 'a prefix that is not text'),
                (('x', 'permit', '10.0.0.0/8'), 'a non-numeric seq'),
                ((True, 'permit', '10.0.0.0/8'), 'a bool seq'),
                ((-1, 'permit', '10.0.0.0/8'), 'a negative seq'),
                ((1 << 32, 'permit', '10.0.0.0/8'), 'a seq past the field'),
                ((5, 'permit', '10.0.0.0/8', 4), 'le shorter than the prefix'),
                ((5, 'permit', '10.0.0.0/8', 0, 4),
                 'ge shorter than the prefix'),
                ((5, 'permit', '10.0.0.0/8', 16, 24), 'ge greater than le'),
                ((5, 'permit', '10.0.0.0/8', 33), 'le wider than the family'),
                ((5, 'permit', '10.0.0.0/8', 128),
                 'an IPv6 bound on an IPv4 entry'),
                ((5, 'permit', '10.0.0.0/8', -1), 'a negative bound'),
                ((5, 'permit', '10.0.0.0/8', True), 'a bool bound'),
                ((5, 'permit', '10.0.0.0/8', '24'), 'a bound as text')):
            with self.assertRaises(ValueError, msg=why):
                PrefixListEntry(*args)

    def test_entry_as_dict(self):
        entry = PrefixListEntry(5, 'permit', '10.0.0.0/8', 24, 16)
        self.assertEqual(entry.as_dict(), {
            'seq': 5, 'action': 'permit', 'prefix': '10.0.0.0/8',
            'le': 24, 'ge': 16, 'match': [16, 24], 'hits': 0})


class PrefixListMatchTestCase(unittest.TestCase):
    """The match rule itself, one table per spelling and per family."""

    def check(self, plist, cases):
        """Assert an evaluation table against a list.

        :param plist: the prefix-list.
        :param cases: ``(prefix text, expected)`` rows.
        """
        for text, expected in cases:
            self.assertEqual(plist.evaluate(parse_prefix(text)), expected,
                             '%s against %r' % (text, plist.entries()))

    def test_bare_prefix_matches_that_length_only(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8'))
        self.check(plist, (
            ('10.0.0.0/8', ACTION_PERMIT),
            # Inside the prefix but longer: no window, so no match. This is
            # the case an implementation that used a covering test alone
            # would get wrong.
            ('10.1.0.0/16', NO_MATCH),
            ('10.0.0.0/32', NO_MATCH),
            # Shorter, and outside.
            ('10.0.0.0/7', NO_MATCH),
            ('11.0.0.0/8', NO_MATCH),
            ('0.0.0.0/0', NO_MATCH)))

    def test_ge_only_matches_from_ge_to_the_host_length(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8', 0, 24))
        self.check(plist, (
            ('10.0.0.0/24', ACTION_PERMIT),
            ('10.1.2.0/24', ACTION_PERMIT),
            ('10.1.2.3/32', ACTION_PERMIT),
            ('10.1.0.0/23', NO_MATCH),
            ('10.0.0.0/8', NO_MATCH),
            ('11.1.2.0/24', NO_MATCH)))

    def test_le_only_matches_from_the_prefix_length_to_le(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8', 16))
        self.check(plist, (
            ('10.0.0.0/8', ACTION_PERMIT),
            ('10.1.0.0/16', ACTION_PERMIT),
            ('10.1.0.0/12', ACTION_PERMIT),
            ('10.1.1.0/17', NO_MATCH),
            ('10.0.0.0/7', NO_MATCH),
            ('11.0.0.0/16', NO_MATCH)))

    def test_ge_and_le_match_the_closed_window(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8', 24, 16))
        self.check(plist, (
            ('10.1.0.0/16', ACTION_PERMIT),
            ('10.1.0.0/20', ACTION_PERMIT),
            ('10.1.2.0/24', ACTION_PERMIT),
            ('10.0.0.0/8', NO_MATCH),
            ('10.1.0.0/15', NO_MATCH),
            ('10.1.2.128/25', NO_MATCH)))

    def test_default_route_entry_with_le_matches_everything(self):
        # `0.0.0.0/0 le 32` is how "any prefix" is written, and it exercises
        # the plen-0 node: pfx_match must accept everything at length 0.
        plist = v4_list((10, 'permit', '0.0.0.0/0', 32))
        self.check(plist, (
            ('0.0.0.0/0', ACTION_PERMIT),
            ('10.0.0.0/8', ACTION_PERMIT),
            ('255.255.255.255/32', ACTION_PERMIT)))

    def test_default_route_entry_without_le_matches_only_the_default(self):
        plist = v4_list((10, 'permit', '0.0.0.0/0'))
        self.check(plist, (
            ('0.0.0.0/0', ACTION_PERMIT),
            ('10.0.0.0/8', NO_MATCH)))

    def test_host_route_entry(self):
        plist = v4_list((10, 'deny', '10.1.2.3/32'))
        self.check(plist, (
            ('10.1.2.3/32', ACTION_DENY),
            ('10.1.2.0/24', NO_MATCH),
            ('10.1.2.4/32', NO_MATCH)))

    def test_partial_byte_lengths(self):
        # A /12 keeps four bits of the second byte. The descent compares
        # masked addresses, so a byte-granular implementation would accept
        # 10.16.0.0/16 here.
        plist = v4_list((10, 'permit', '10.0.0.0/12', 24, 16))
        self.check(plist, (
            ('10.15.0.0/16', ACTION_PERMIT),
            ('10.0.0.0/16', ACTION_PERMIT),
            ('10.16.0.0/16', NO_MATCH)))

    def test_ipv6_every_spelling(self):
        exact = v6_list((10, 'permit', '2001:db8::/32'))
        self.check(exact, (
            ('2001:db8::/32', ACTION_PERMIT),
            ('2001:db8:1::/48', NO_MATCH)))
        ge_only = v6_list((10, 'permit', '2001:db8::/32', 0, 48))
        self.check(ge_only, (
            ('2001:db8:1::/48', ACTION_PERMIT),
            ('2001:db8:1:2:3:4:5:6/128', ACTION_PERMIT),
            ('2001:db8::/47', NO_MATCH),
            ('2001:db9:1::/48', NO_MATCH)))
        le_only = v6_list((10, 'permit', '2001:db8::/32', 48))
        self.check(le_only, (
            ('2001:db8::/32', ACTION_PERMIT),
            ('2001:db8:1::/48', ACTION_PERMIT),
            ('2001:db8:1:1::/49', NO_MATCH)))
        both = v6_list((10, 'permit', '2001:db8::/32', 64, 48))
        self.check(both, (
            ('2001:db8:1::/48', ACTION_PERMIT),
            ('2001:db8:1:2::/64', ACTION_PERMIT),
            ('2001:db8::/32', NO_MATCH),
            ('2001:db8:1:2:3::/80', NO_MATCH)))

    def test_a_prefix_of_the_other_family_is_a_miss_not_an_error(self):
        # What lets a route-map's `ip address` clause be applied to a
        # dual-stack table without the caller branching on the family.
        plist = v4_list((10, 'permit', '0.0.0.0/0', 32))
        self.assertEqual(plist.evaluate(parse_prefix('2001:db8::/32')),
                         NO_MATCH)
        self.assertFalse(plist.permits(parse_prefix('2001:db8::/32')))

    def test_evaluate_requires_a_prefix(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8'))
        for bad in ('10.0.0.0/8', None, 17, b'\x0a\x00\x00\x00'):
            self.assertRaises(ValueError, plist.evaluate, bad)
            self.assertRaises(ValueError, plist.permits, bad)

    def test_permits_is_true_only_for_an_explicit_permit(self):
        plist = v4_list((10, 'deny', '10.0.0.0/8'),
                        (20, 'permit', '11.0.0.0/8'))
        self.assertTrue(plist.permits(parse_prefix('11.0.0.0/8')))
        self.assertFalse(plist.permits(parse_prefix('10.0.0.0/8')))
        self.assertFalse(plist.permits(parse_prefix('12.0.0.0/8')))

    def test_an_empty_list_matches_nothing(self):
        plist = PrefixList('PL-EMPTY', AFI_IP)
        self.assertEqual(plist.evaluate(parse_prefix('10.0.0.0/8')), NO_MATCH)
        self.assertEqual(len(plist), 0)


class PrefixListOrderTestCase(unittest.TestCase):
    """Overlapping entries: the lowest sequence number decides, always."""

    def test_lowest_seq_wins_over_a_more_specific_entry(self):
        # The specific deny is first, so it wins. An implementation that
        # returned the longest covering entry would agree here...
        plist = v4_list((5, 'deny', '10.1.0.0/16'),
                        (10, 'permit', '10.0.0.0/8', 24))
        self.assertEqual(plist.evaluate(parse_prefix('10.1.0.0/16')),
                         ACTION_DENY)

    def test_lowest_seq_wins_when_it_is_the_less_specific_entry(self):
        # ...and would disagree here, which is the point of the pair: the
        # same two entries, renumbered, must produce the other answer.
        plist = v4_list((5, 'permit', '10.0.0.0/8', 24),
                        (10, 'deny', '10.1.0.0/16'))
        self.assertEqual(plist.evaluate(parse_prefix('10.1.0.0/16')),
                         ACTION_PERMIT)

    def test_a_longer_covering_entry_whose_window_excludes_the_candidate(self):
        # The /16 covers the candidate and is visited later in the descent,
        # but its window is exact, so it does not match and the /8 at the
        # higher seq must decide. A descent that stopped at the longest
        # covering node would return no-match.
        plist = v4_list((10, 'permit', '10.1.0.0/16'),
                        (20, 'deny', '10.0.0.0/8', 32))
        self.assertEqual(plist.evaluate(parse_prefix('10.1.2.0/24')),
                         ACTION_DENY)
        self.assertEqual(plist.evaluate(parse_prefix('10.1.0.0/16')),
                         ACTION_PERMIT)

    def test_two_entries_on_the_same_prefix_with_different_windows(self):
        # Same trie node, two entries. The lowest seq whose window admits the
        # candidate decides, which is not the first entry in the node.
        plist = v4_list((10, 'deny', '10.0.0.0/8', 16, 16),
                        (20, 'permit', '10.0.0.0/8', 32, 24))
        self.assertEqual(plist.evaluate(parse_prefix('10.1.0.0/16')),
                         ACTION_DENY)
        self.assertEqual(plist.evaluate(parse_prefix('10.1.2.0/24')),
                         ACTION_PERMIT)
        self.assertEqual(plist.evaluate(parse_prefix('10.1.0.0/20')),
                         NO_MATCH)

    def test_three_deep_overlap_picks_the_lowest_matching_seq(self):
        # Three nested entries, all of which match 10.1.2.0/24, with the
        # sequence numbers deliberately running the opposite way to the
        # prefix lengths: the shortest entry holds the lowest seq, so an
        # implementation that let the last (longest) covering entry win
        # returns the wrong action rather than merely the wrong entry.
        plist = v4_list((10, 'permit', '10.0.0.0/8', 32, 8),
                        (20, 'deny', '10.1.0.0/16', 32, 16),
                        (30, 'deny', '10.1.2.0/24'))
        self.assertEqual(plist.evaluate(parse_prefix('10.1.2.0/24')),
                         ACTION_PERMIT)
        self.assertEqual([e.hits for e in plist.entries()], [1, 0, 0])
        # Remove the winner and the next-lowest matching entry takes over.
        plist.remove(10)
        self.assertEqual(plist.evaluate(parse_prefix('10.1.2.0/24')),
                         ACTION_DENY)
        self.assertEqual(plist.evaluate(parse_prefix('10.2.0.0/16')),
                         NO_MATCH)

    def test_entries_are_ordered_by_seq_whatever_the_insertion_order(self):
        plist = v4_list((30, 'permit', '10.3.0.0/16'),
                        (10, 'permit', '10.1.0.0/16'),
                        (20, 'permit', '10.2.0.0/16'))
        self.assertEqual([e.seq for e in plist.entries()], [10, 20, 30])

    def test_a_duplicate_seq_replaces_and_unfiles_the_old_prefix(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8'))
        plist.add(10, 'deny', '11.0.0.0/8')
        self.assertEqual(len(plist), 1)
        self.assertEqual(plist.evaluate(parse_prefix('11.0.0.0/8')),
                         ACTION_DENY)
        # The replaced entry must be gone from the index, not merely hidden.
        self.assertEqual(plist.evaluate(parse_prefix('10.0.0.0/8')),
                         NO_MATCH)
        self.assertEqual(plist.trie.count, 1)

    def test_remove(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8'),
                        (20, 'permit', '11.0.0.0/8'))
        self.assertTrue(plist.remove(10))
        self.assertFalse(plist.remove(10))
        self.assertEqual([e.seq for e in plist.entries()], [20])
        self.assertEqual(plist.evaluate(parse_prefix('10.0.0.0/8')), NO_MATCH)
        self.assertRaises(ValueError, plist.remove, 'ten')

    def test_removing_one_of_two_entries_on_a_prefix_keeps_the_other(self):
        plist = v4_list((10, 'deny', '10.0.0.0/8', 16, 16),
                        (20, 'permit', '10.0.0.0/8', 24, 24))
        self.assertTrue(plist.remove(10))
        self.assertEqual(plist.trie.count, 1)
        self.assertEqual(plist.evaluate(parse_prefix('10.1.0.0/16')),
                         NO_MATCH)
        self.assertEqual(plist.evaluate(parse_prefix('10.1.2.0/24')),
                         ACTION_PERMIT)

    def test_version_moves_on_every_mutation(self):
        plist = PrefixList('PL-V', AFI_IP)
        self.assertEqual(plist.version, 0)
        plist.add(10, 'permit', '10.0.0.0/8')
        self.assertEqual(plist.version, 1)
        plist.add(10, 'deny', '10.0.0.0/8')
        self.assertEqual(plist.version, 2)
        plist.add(20, 'permit', '11.0.0.0/8')
        self.assertEqual(plist.version, 3)
        plist.remove(20)
        self.assertEqual(plist.version, 4)
        # A removal of something absent changed nothing, so it must not bump:
        # a version that moves without a change re-advertises the table.
        plist.remove(999)
        self.assertEqual(plist.version, 4)
        plist.clear()
        self.assertEqual(plist.version, 5)
        plist.clear()
        self.assertEqual(plist.version, 5)

    def test_construction_is_validated(self):
        self.assertRaises(ValueError, PrefixList, '', AFI_IP)
        self.assertRaises(ValueError, PrefixList, 'PL', 3)
        self.assertRaises(ValueError, PrefixList, 'PL', -1)
        self.assertRaises(TypeError, PrefixList, b'PL', AFI_IP)

    def test_a_prefix_from_the_wrong_family_cannot_be_added(self):
        plist = PrefixList('PL', AFI_IP)
        self.assertRaises(ValueError, plist.add, 10, 'permit',
                          '2001:db8::/32')
        self.assertEqual(len(plist), 0)
        self.assertEqual(plist.version, 0)


class PrefixListCountersTestCase(unittest.TestCase):
    """Hit counters, which is how an operator debugs a filter."""

    def test_per_entry_and_total_counters(self):
        plist = v4_list((10, 'deny', '10.1.0.0/16'),
                        (20, 'permit', '10.0.0.0/8', 24))
        plist.evaluate(parse_prefix('10.1.0.0/16'))
        plist.evaluate(parse_prefix('10.2.0.0/16'))
        plist.evaluate(parse_prefix('10.3.0.0/16'))
        plist.evaluate(parse_prefix('192.0.2.0/24'))
        first, second = plist.entries()
        self.assertEqual(first.hits, 1)
        self.assertEqual(second.hits, 2)
        # Four evaluations, three of which matched an entry; the fourth fell
        # through to the implicit deny.
        self.assertEqual(plist.hits, 4)
        self.assertEqual(plist.matches, 3)
        self.assertEqual(plist.matches, sum(e.hits for e in plist.entries()))

    def test_permits_counts_like_evaluate(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8'))
        plist.permits(parse_prefix('10.0.0.0/8'))
        plist.permits(parse_prefix('11.0.0.0/8'))
        self.assertEqual((plist.hits, plist.matches), (2, 1))

    def test_a_family_mismatch_counts_as_a_lookup_and_not_a_match(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8'))
        plist.evaluate(parse_prefix('2001:db8::/32'))
        self.assertEqual((plist.hits, plist.matches), (1, 0))

    def test_list_as_dict(self):
        plist = v4_list((10, 'permit', '10.0.0.0/8', 24, 16))
        plist.evaluate(parse_prefix('10.1.0.0/16'))
        rendered = plist.as_dict()
        self.assertEqual(rendered['name'], 'PL-TEST')
        self.assertEqual(rendered['afi'], AFI_IP)
        self.assertEqual(rendered['version'], 1)
        self.assertEqual(rendered['hits'], 1)
        self.assertEqual(rendered['matches'], 1)
        self.assertEqual(rendered['entries'], [
            {'seq': 10, 'action': 'permit', 'prefix': '10.0.0.0/8',
             'le': 24, 'ge': 16, 'match': [16, 24], 'hits': 1}])


class PrefixListLifetimeTestCase(unittest.TestCase):
    """The index owns memory, so its lifetime is asserted structurally."""

    def _rebuild(self, plist, size):
        """Fill a list with ``size`` entries and then empty it again."""
        for index in range(size):
            plist.add((index + 1) * 5, 'permit',
                      Prefix(AFI_IP, 24, bytes((10, index // 256,
                                                index % 256, 0))), 32, 24)
        for index in range(size):
            self.assertTrue(plist.remove((index + 1) * 5))

    def test_repeated_rebuild_returns_the_trie_to_empty(self):
        # The Stage-2 review found two trie leaks, and a prefix-list rebuilt
        # on every configuration change is exactly the workload that turns a
        # leaked node per entry into an out-of-memory a week later. Both
        # counters must come back to zero: `count` alone would not notice a
        # glue node that was never pruned.
        plist = PrefixList('PL-CYCLE', AFI_IP)
        for _round in range(50):
            self._rebuild(plist, 32)
            self.assertEqual(plist.trie.count, 0)
            self.assertEqual(plist.trie.nodes, 0)
        self.assertEqual(len(plist), 0)
        self.assertEqual(plist.entries(), [])

    def test_clear_releases_every_node(self):
        plist = PrefixList('PL-CLEAR', AFI_IP)
        for index in range(64):
            plist.add((index + 1) * 5, 'permit',
                      Prefix(AFI_IP, 24, bytes((10, 0, index, 0))))
        self.assertEqual(plist.trie.count, 64)
        self.assertEqual(plist.clear(), 64)
        self.assertEqual(plist.trie.count, 0)
        self.assertEqual(plist.trie.nodes, 0)
        self.assertEqual(plist.evaluate(parse_prefix('10.0.5.0/24')),
                         NO_MATCH)

    def test_a_removed_entry_is_released(self):
        plist = PrefixList('PL-REF', AFI_IP)
        entry = plist.add(10, 'permit', '10.0.0.0/8')
        ref = weakref.ref(entry)
        del entry
        self.assertIsNotNone(ref())
        plist.remove(10)
        gc.collect()
        self.assertIsNone(ref(), 'the index still holds the removed entry')

    def test_a_replaced_entry_is_released(self):
        plist = PrefixList('PL-REF2', AFI_IP)
        first = plist.add(10, 'permit', '10.0.0.0/8')
        ref = weakref.ref(first)
        del first
        plist.add(10, 'deny', '10.0.0.0/8')
        gc.collect()
        self.assertIsNone(ref(), 'the replaced entry is still filed')

    def test_clearing_releases_entries(self):
        plist = PrefixList('PL-REF3', AFI_IP)
        refs = [weakref.ref(plist.add((i + 1) * 5, 'permit',
                                      Prefix(AFI_IP, 24,
                                             bytes((10, 0, i, 0)))))
                for i in range(8)]
        plist.clear()
        gc.collect()
        self.assertEqual([r() for r in refs], [None] * 8)

    def test_the_trie_holds_one_node_per_distinct_prefix(self):
        # Two entries on one prefix must not be two nodes, and the entry list
        # must not be duplicated: this is the structural half of the
        # same-prefix-different-window case.
        plist = v4_list((10, 'deny', '10.0.0.0/8', 16, 16),
                        (20, 'permit', '10.0.0.0/8', 24, 24),
                        (30, 'permit', '11.0.0.0/8'))
        self.assertEqual(plist.trie.count, 2)


class AsPathMatcherTestCase(unittest.TestCase):
    """AS-path regexes, and the spelling they are written against."""

    def test_a_bare_pattern_is_a_substring_match(self):
        matcher = AsPathMatcher('65002')
        self.assertTrue(matcher.matches('65001 65002 65003'))
        self.assertTrue(matcher.matches('65002'))
        self.assertFalse(matcher.matches('65001 65003'))

    def test_caret_anchors_at_the_start(self):
        matcher = AsPathMatcher('^65001')
        self.assertTrue(matcher.matches('65001 65002'))
        self.assertFalse(matcher.matches('65002 65001'))

    def test_dollar_anchors_at_the_end(self):
        matcher = AsPathMatcher('65002$')
        self.assertTrue(matcher.matches('65001 65002'))
        self.assertFalse(matcher.matches('65002 65001'))

    def test_both_anchors_are_a_whole_string_match(self):
        matcher = AsPathMatcher('^65001 65002$')
        self.assertTrue(matcher.matches('65001 65002'))
        self.assertFalse(matcher.matches('65001 65002 65003'))
        self.assertFalse(matcher.matches('65000 65001 65002'))

    def test_the_empty_path_of_a_locally_originated_route(self):
        self.assertTrue(AsPathMatcher('^$').matches(''))
        self.assertFalse(AsPathMatcher('^65001').matches(''))
        # None is an empty path rather than an error, so a route with no
        # attributes at all can be filtered.
        self.assertTrue(AsPathMatcher('^$').matches(None))

    def test_the_set_and_sequence_spellings(self):
        # The canonical string from AttrSet.as_path_str(): a sequence is
        # space-separated and bare, a set is brace-and-comma.
        path = '65001 65002 {65003,65004}'
        self.assertTrue(AsPathMatcher(r'\{65003,65004\}$').matches(path))
        self.assertTrue(AsPathMatcher(r'\{').matches(path))
        self.assertTrue(AsPathMatcher('65003,65004').matches(path))
        # A pattern written for a space-separated set never matches, which is
        # exactly the silent failure the spelling contract exists to prevent.
        self.assertFalse(AsPathMatcher(r'\{65003 65004\}').matches(path))

    def test_the_confederation_spellings(self):
        self.assertTrue(
            AsPathMatcher(r'^\(65001 65002\)').matches('(65001 65002) 65003'))
        self.assertTrue(
            AsPathMatcher(r'\[65003,65004\]').matches('[65003,65004]'))

    def test_the_underscore_is_the_ios_path_delimiter(self):
        # P-1: `_` used to be a literal underscore, which never appears in
        # the canonical string, so `deny _65002_` matched nothing and the
        # filter failed open.
        self.assertTrue(AsPathMatcher('_65002_').matches('65001 65002 3'))
        self.assertFalse(AsPathMatcher('_65002_').matches('65001 165002'))
        # The explicit spelling still works.
        self.assertTrue(AsPathMatcher('( |^)65002( |$)')
                        .matches('65001 65002 65003'))

    def test_compiled_patterns_are_cached_and_reused(self):
        first = compile_pattern(r'^65001_unique_marker')
        second = compile_pattern(r'^65001_unique_marker')
        self.assertIs(first, second)
        self.assertIs(AsPathMatcher('^65001 65099$')._regex,
                      compile_pattern('^65001 65099$'))

    def test_the_cache_is_bounded(self):
        limit = _aspath.cache_stats()['limit']
        for index in range(limit + 5):
            compile_pattern('^6500%d bounded' % index)
        self.assertLessEqual(_aspath.cache_stats()['patterns'], limit)
        # Still functional after the overflow clear.
        self.assertTrue(AsPathMatcher('^65001').matches('65001 2'))

    def test_bad_patterns_are_configuration_errors(self):
        for bad in ('(unbalanced', '*', '[', None, 17, ''):
            self.assertRaises(ValueError, compile_pattern, bad)
            self.assertRaises(ValueError, AsPathMatcher, bad)

    def test_repr_keeps_the_pattern(self):
        self.assertEqual(AsPathMatcher('^65001').pattern, '^65001')
        self.assertIn('^65001', repr(AsPathMatcher('^65001')))


class AsPathListTestCase(unittest.TestCase):
    """AS-path access-lists: the prefix-list rule, over regexes."""

    def make(self):
        alist = AsPathList('AS-IN')
        alist.add(10, 'deny', '^65001 65666')
        alist.add(20, 'permit', '^65001')
        return alist

    def test_first_matching_entry_decides(self):
        alist = self.make()
        self.assertEqual(alist.evaluate('65001 65666 3'), ACTION_DENY)
        self.assertEqual(alist.evaluate('65001 65002'), ACTION_PERMIT)
        self.assertEqual(alist.evaluate('65009 65001'), NO_MATCH)

    def test_permits(self):
        alist = self.make()
        self.assertTrue(alist.permits('65001 65002'))
        self.assertFalse(alist.permits('65001 65666'))
        self.assertFalse(alist.permits('65009'))

    def test_entries_are_ordered_by_seq(self):
        alist = AsPathList('AS-ORDER')
        alist.add(30, 'permit', 'c')
        alist.add(10, 'permit', 'a')
        alist.add(20, 'permit', 'b')
        self.assertEqual([e.seq for e in alist.entries()], [10, 20, 30])
        self.assertEqual([e.pattern for e in alist.entries()],
                         ['a', 'b', 'c'])

    def test_a_duplicate_seq_replaces(self):
        alist = AsPathList('AS-DUP')
        alist.add(10, 'permit', '^65001')
        alist.add(10, 'deny', '^65001')
        self.assertEqual(len(alist), 1)
        self.assertEqual(alist.evaluate('65001'), ACTION_DENY)

    def test_none_is_the_empty_path(self):
        alist = AsPathList('AS-NONE')
        alist.add(10, 'permit', '^$')
        self.assertEqual(alist.evaluate(None), ACTION_PERMIT)
        self.assertRaises(ValueError, alist.evaluate, 17)

    def test_counters_and_version(self):
        alist = self.make()
        self.assertEqual(alist.version, 2)
        alist.evaluate('65001 65002')
        alist.evaluate('65009')
        self.assertEqual((alist.hits, alist.matches), (2, 1))
        self.assertEqual([e.hits for e in alist.entries()], [0, 1])
        self.assertTrue(alist.remove(10))
        self.assertEqual(alist.version, 3)
        self.assertFalse(alist.remove(10))
        self.assertEqual(alist.version, 3)
        self.assertEqual(alist.clear(), 1)
        self.assertEqual(alist.version, 4)

    def test_as_dict(self):
        alist = AsPathList('AS-SHOW')
        alist.add(10, 'permit', '^65001')
        alist.evaluate('65001')
        self.assertEqual(alist.as_dict(), {
            'name': 'AS-SHOW', 'version': 1, 'hits': 1, 'matches': 1,
            'entries': [{'seq': 10, 'action': 'permit', 'regex': '^65001',
                         'hits': 1}]})

    def test_construction_and_entry_validation(self):
        self.assertRaises(ValueError, AsPathList, '')
        alist = AsPathList('AS-BAD')
        self.assertRaises(ValueError, alist.add, 10, 'allow', '^65001')
        self.assertRaises(ValueError, alist.add, 10, 'permit', '(bad')
        self.assertRaises(ValueError, alist.add, 'ten', 'permit', '^1')
        # A rejected entry must leave the list alone, including its version.
        self.assertEqual(len(alist), 0)
        self.assertEqual(alist.version, 0)


class RouteMapMatchTestCase(unittest.TestCase):
    """Every supported match clause, matching and not matching."""

    def setUp(self):
        self.store = store_with({
            'ip': {
                'prefix-list': {
                    'PL-IN': [{'action': 'permit', 'prefix': '10.0.0.0/8',
                               'le': 24}],
                    'PL-DENY': [{'action': 'deny', 'prefix': '10.0.0.0/8',
                                 'le': 24}],
                },
                'as-path-access-list': {
                    'AS-OK': [{'action': 'permit', 'regex': '^65001'}],
                    'AS-NO': [{'action': 'deny', 'regex': '^65001'}],
                },
            },
            'ipv6': {
                'prefix-list': {
                    'PL6-IN': [{'action': 'permit',
                                'prefix': '2001:db8::/32', 'le': 48}],
                },
            },
        })
        self.v4 = parse_prefix('10.1.0.0/16')
        self.v6 = parse_prefix('2001:db8:1::/48')

    def clause(self, match):
        """A one-clause permit map wired to this test's store."""
        return one_clause_map(match, None, 'permit', self.store)

    def test_ip_address_prefix_list(self):
        rmap = self.clause({'ip': {'address': {'prefix-list': 'PL-IN'}}})
        self.assertTrue(rmap.apply(self.v4, None))
        self.assertFalse(rmap.apply(parse_prefix('192.0.2.0/24'), None))
        # A prefix the list explicitly denies does not match either: the
        # clause matches on permit alone.
        denied = self.clause({'ip': {'address': {'prefix-list': 'PL-DENY'}}})
        self.assertFalse(denied.apply(self.v4, None))
        # An IPv6 prefix through an `ip` clause is a miss, not an error.
        self.assertFalse(rmap.apply(self.v6, None))

    def test_ipv6_address_prefix_list(self):
        rmap = self.clause({'ipv6': {'address': {'prefix-list': 'PL6-IN'}}})
        self.assertTrue(rmap.apply(self.v6, None))
        self.assertFalse(rmap.apply(parse_prefix('2001:db9::/48'), None))
        self.assertFalse(rmap.apply(self.v4, None))

    def test_a_reference_to_a_missing_list_never_matches(self):
        rmap = self.clause({'ip': {'address': {'prefix-list': 'ABSENT'}}})
        self.assertFalse(rmap.apply(self.v4, None))
        # And a clause with no resolver at all behaves the same way.
        orphan = one_clause_map(
            {'ip': {'address': {'prefix-list': 'PL-IN'}}})
        self.assertFalse(orphan.apply(self.v4, None))

    def test_as_path_regex(self):
        rmap = self.clause({'as-path': '^65001'})
        self.assertTrue(rmap.apply(self.v4, Attrs(as_path='65001 65002')))
        self.assertFalse(rmap.apply(self.v4, Attrs(as_path='65009 65001')))
        self.assertFalse(rmap.apply(self.v4, None))

    def test_as_path_regex_list_is_any_of(self):
        rmap = self.clause({'as-path': ['^65001', '^65002']})
        self.assertTrue(rmap.apply(self.v4, Attrs(as_path='65001 9')))
        self.assertTrue(rmap.apply(self.v4, Attrs(as_path='65002 9')))
        self.assertFalse(rmap.apply(self.v4, Attrs(as_path='65003 9')))

    def test_as_path_access_list(self):
        rmap = self.clause({'as-path': {'access-list': 'AS-OK'}})
        self.assertTrue(rmap.apply(self.v4, Attrs(as_path='65001 2')))
        self.assertFalse(rmap.apply(self.v4, Attrs(as_path='65009 2')))
        # A list whose matching entry is a deny does not match the clause.
        denied = self.clause({'as-path': {'access-list': 'AS-NO'}})
        self.assertFalse(denied.apply(self.v4, Attrs(as_path='65001 2')))
        missing = self.clause({'as-path': {'access-list': 'ABSENT'}})
        self.assertFalse(missing.apply(self.v4, Attrs(as_path='65001')))

    def test_community_requires_every_listed_value(self):
        rmap = self.clause({'community': ['65000:1', '65000:2']})
        both = Attrs(communities=packed_communities(C_65000_1, C_65000_2))
        one = Attrs(communities=packed_communities(C_65000_1))
        extra = Attrs(communities=packed_communities(C_65000_1, C_65000_2,
                                                     C_NO_ADVERTISE))
        self.assertTrue(rmap.apply(self.v4, both))
        self.assertFalse(rmap.apply(self.v4, one))
        # Extra communities are fine without exact-match.
        self.assertTrue(rmap.apply(self.v4, extra))
        self.assertFalse(rmap.apply(self.v4, Attrs()))
        self.assertFalse(rmap.apply(self.v4, None))

    def test_community_exact_match(self):
        rmap = self.clause({'community': {'list': ['65000:1', '65000:2'],
                                          'exact-match': True}})
        exact = Attrs(communities=packed_communities(C_65000_1, C_65000_2))
        extra = Attrs(communities=packed_communities(C_65000_1, C_65000_2,
                                                     C_NO_ADVERTISE))
        short = Attrs(communities=packed_communities(C_65000_1))
        self.assertTrue(rmap.apply(self.v4, exact))
        self.assertFalse(rmap.apply(self.v4, extra))
        self.assertFalse(rmap.apply(self.v4, short))

    def test_community_spellings(self):
        # Well-known name, ASN:VALUE and a bare integer all name the same
        # community, so all three must match the same attribute.
        attrs = Attrs(communities=packed_communities(C_NO_ADVERTISE))
        for spelling in ('no-advertise', '65535:65282', C_NO_ADVERTISE,
                         str(C_NO_ADVERTISE)):
            rmap = self.clause({'community': [spelling]})
            self.assertTrue(rmap.apply(self.v4, attrs),
                            'spelling %r' % (spelling,))
        # local-as is IOS' name for NO_EXPORT_SUBCONFED.
        subconfed = Attrs(communities=packed_communities(0xffffff03))
        self.assertTrue(self.clause({'community': ['local-as']})
                        .apply(self.v4, subconfed))
        self.assertTrue(self.clause({'community': ['no-export-subconfed']})
                        .apply(self.v4, subconfed))

    def test_the_community_alignment_trap(self):
        # 0:65535 followed by 65282:0 are two ordinary communities whose
        # bytes contain NO_ADVERTISE's four bytes starting two bytes in. The
        # first assertion is the trap itself: an unaligned membership test --
        # which is what `target in packed` is -- says yes.
        packed = packed_communities(C_STRADDLE_LOW, C_STRADDLE_HIGH)
        self.assertIn(struct.pack('>I', C_NO_ADVERTISE), packed)
        rmap = self.clause({'community': ['no-advertise']})
        self.assertFalse(rmap.apply(self.v4, Attrs(communities=packed)),
                         'an unaligned community was accepted')
        # The aligned value in the same attribute still matches.
        self.assertTrue(self.clause({'community': ['0:65535']})
                        .apply(self.v4, Attrs(communities=packed)))

    def test_large_community(self):
        rmap = self.clause({'large-community': ['1:2:3']})
        self.assertTrue(rmap.apply(
            self.v4, Attrs(large_communities=packed_large((1, 2, 3)))))
        self.assertTrue(rmap.apply(
            self.v4, Attrs(large_communities=packed_large((1, 2, 3),
                                                          (9, 9, 9)))))
        self.assertFalse(rmap.apply(
            self.v4, Attrs(large_communities=packed_large((1, 2, 4)))))
        self.assertFalse(rmap.apply(self.v4, Attrs()))

    def test_large_community_exact_match_and_all_of(self):
        rmap = self.clause({'large-community': {'list': ['1:2:3', '4:5:6'],
                                                'exact-match': True}})
        self.assertTrue(rmap.apply(
            self.v4, Attrs(large_communities=packed_large((1, 2, 3),
                                                          (4, 5, 6)))))
        self.assertFalse(rmap.apply(
            self.v4, Attrs(large_communities=packed_large((1, 2, 3),
                                                          (4, 5, 6),
                                                          (7, 8, 9)))))
        all_of = self.clause({'large-community': ['1:2:3', '4:5:6']})
        self.assertTrue(all_of.apply(
            self.v4, Attrs(large_communities=packed_large((1, 2, 3),
                                                          (4, 5, 6),
                                                          (7, 8, 9)))))
        self.assertFalse(all_of.apply(
            self.v4, Attrs(large_communities=packed_large((1, 2, 3)))))

    def test_the_large_community_alignment_trap(self):
        # (0,1,2) followed by (3,0,0) contain (1,2,3)'s twelve bytes starting
        # four bytes in.
        packed = packed_large((0, 1, 2), (3, 0, 0))
        self.assertIn(struct.pack('>III', 1, 2, 3), packed)
        rmap = self.clause({'large-community': ['1:2:3']})
        self.assertFalse(rmap.apply(self.v4,
                                    Attrs(large_communities=packed)),
                         'an unaligned large community was accepted')
        self.assertTrue(self.clause({'large-community': ['0:1:2']})
                        .apply(self.v4, Attrs(large_communities=packed)))

    def test_metric_matches_the_med_and_absence_is_not_zero(self):
        rmap = self.clause({'metric': 100})
        self.assertTrue(rmap.apply(self.v4, Attrs(med=100)))
        self.assertFalse(rmap.apply(self.v4, Attrs(med=101)))
        self.assertFalse(rmap.apply(self.v4, Attrs()))
        zero = self.clause({'metric': 0})
        self.assertTrue(zero.apply(self.v4, Attrs(med=0)))
        # A path with no MED must not match `metric 0`, or the clause would
        # select every path on the session.
        self.assertFalse(zero.apply(self.v4, Attrs()))

    def test_local_preference(self):
        rmap = self.clause({'local-preference': 200})
        self.assertTrue(rmap.apply(self.v4, Attrs(local_pref=200)))
        self.assertFalse(rmap.apply(self.v4, Attrs(local_pref=100)))
        self.assertFalse(rmap.apply(self.v4, Attrs()))

    def test_origin(self):
        for name, value in (('igp', ORIGIN_IGP), ('egp', ORIGIN_EGP),
                            ('incomplete', ORIGIN_INCOMPLETE)):
            rmap = self.clause({'origin': name})
            self.assertTrue(rmap.apply(self.v4, Attrs(origin=value)))
            self.assertFalse(rmap.apply(self.v4,
                                        Attrs(origin=(value + 1) % 3)))
            self.assertFalse(rmap.apply(self.v4, None))

    def test_next_hop(self):
        rmap = self.clause({'next-hop': '192.0.2.1'})
        self.assertTrue(rmap.apply(self.v4,
                                   Attrs(nexthop=b'\xc0\x00\x02\x01')))
        self.assertFalse(rmap.apply(self.v4,
                                    Attrs(nexthop=b'\xc0\x00\x02\x02')))
        self.assertFalse(rmap.apply(self.v4, Attrs()))
        v6 = self.clause({'next-hop': '2001:db8::1'})
        packed = parse_prefix('2001:db8::1').packed()
        self.assertTrue(v6.apply(self.v6, Attrs(nexthop=packed)))
        self.assertFalse(v6.apply(self.v6,
                                  Attrs(nexthop=b'\xc0\x00\x02\x01')))

    def test_several_conditions_are_a_conjunction(self):
        rmap = self.clause({'ip': {'address': {'prefix-list': 'PL-IN'}},
                            'origin': 'igp',
                            'community': ['65000:1'],
                            'as-path': '^65001'})
        good = Attrs(origin=ORIGIN_IGP, as_path='65001 2',
                     communities=packed_communities(C_65000_1))
        self.assertTrue(rmap.apply(self.v4, good))
        # Each condition on its own is enough to reject.
        self.assertFalse(rmap.apply(parse_prefix('192.0.2.0/24'), good))
        self.assertFalse(rmap.apply(self.v4, Attrs(
            origin=ORIGIN_EGP, as_path='65001 2',
            communities=packed_communities(C_65000_1))))
        self.assertFalse(rmap.apply(self.v4, Attrs(
            origin=ORIGIN_IGP, as_path='65009 2',
            communities=packed_communities(C_65000_1))))
        self.assertFalse(rmap.apply(self.v4, Attrs(
            origin=ORIGIN_IGP, as_path='65001 2',
            communities=packed_communities(C_65000_2))))

    def test_a_clause_with_no_conditions_matches_everything(self):
        rmap = one_clause_map(None, {'local-preference': 50})
        self.assertTrue(rmap.apply(self.v4, None))
        self.assertTrue(rmap.apply(self.v6, Attrs()))
        self.assertEqual(one_clause_map({}, None).apply(self.v4, None).action,
                         ACTION_PERMIT)


class RouteMapSetTestCase(unittest.TestCase):
    """Every set clause, and the exact normalized form it produces."""

    def sets(self, edits):
        """Apply a one-clause map carrying ``edits`` and return the result."""
        rmap = one_clause_map(None, edits)
        return rmap.apply(parse_prefix('10.0.0.0/8'), Attrs())

    def test_scalar_edits(self):
        self.assertEqual(self.sets({'local-preference': 200}).sets,
                         {'local-preference': 200})
        self.assertEqual(self.sets({'metric': 42}).sets, {'metric': 42})
        self.assertEqual(self.sets({'origin': 'incomplete'}).sets,
                         {'origin': ORIGIN_INCOMPLETE})
        self.assertEqual(self.sets({'origin': ORIGIN_EGP}).sets,
                         {'origin': ORIGIN_EGP})

    def test_next_hop_is_packed_at_configuration_time(self):
        self.assertEqual(self.sets({'next-hop': '192.0.2.1'}).sets,
                         {'next-hop': b'\xc0\x00\x02\x01'})
        packed = self.sets({'next-hop': '2001:db8::1'}).sets['next-hop']
        self.assertEqual(len(packed), 16)
        self.assertEqual(packed, parse_prefix('2001:db8::1').packed())

    def test_weight_is_surfaced_separately_and_not_as_an_edit(self):
        # It is local to the speaker and never encoded, so a translator
        # iterating `sets` must not find it there.
        result = self.sets({'weight': 300})
        self.assertEqual(result.weight, 300)
        self.assertEqual(result.sets, {})
        both = self.sets({'weight': 300, 'metric': 1})
        self.assertEqual(both.weight, 300)
        self.assertEqual(both.sets, {'metric': 1})
        self.assertIsNone(self.sets({'metric': 1}).weight)

    def test_community_replace_add_and_clear(self):
        self.assertEqual(self.sets({'community': ['65000:1']}).sets,
                         {'community': ('set', (C_65000_1,))})
        self.assertEqual(
            self.sets({'community': {'list': ['65000:1', '65000:2']}}).sets,
            {'community': ('set', (C_65000_1, C_65000_2))})
        self.assertEqual(
            self.sets({'community': {'list': ['65000:1'],
                                     'additive': True}}).sets,
            {'community': ('add', (C_65000_1,))})
        self.assertEqual(
            self.sets({'community': {'list': ['65000:1'],
                                     'additive': False}}).sets,
            {'community': ('set', (C_65000_1,))})
        self.assertEqual(self.sets({'community': 'none'}).sets,
                         {'community': ('none', ())})

    def test_community_values_are_sorted_and_deduplicated(self):
        # The attribute they will be compared and interned against is
        # canonicalised the same way.
        edits = self.sets({'community': ['65000:2', '65000:1',
                                         '65000:2']}).sets
        self.assertEqual(edits['community'],
                         ('set', (C_65000_1, C_65000_2)))

    def test_large_community_replace_add_and_clear(self):
        self.assertEqual(self.sets({'large-community': ['1:2:3']}).sets,
                         {'large-community': ('set', ((1, 2, 3),))})
        self.assertEqual(
            self.sets({'large-community': {'list': ['4:5:6', '1:2:3'],
                                           'additive': True}}).sets,
            {'large-community': ('add', ((1, 2, 3), (4, 5, 6)))})
        self.assertEqual(self.sets({'large-community': 'none'}).sets,
                         {'large-community': ('none', ())})

    def test_as_path_prepend_both_spellings(self):
        self.assertEqual(
            self.sets({'as-path': {'prepend': [65001, 65001]}}).sets,
            {'as-path-prepend': (65001, 65001)})
        self.assertEqual(
            self.sets({'as-path': {'prepend': '65001 65002'}}).sets,
            {'as-path-prepend': (65001, 65002)})

    def test_every_key_at_once(self):
        result = self.sets({
            'local-preference': 200, 'metric': 5, 'origin': 'egp',
            'next-hop': '192.0.2.1', 'weight': 7,
            'community': ['65000:1'], 'large-community': ['1:2:3'],
            'as-path': {'prepend': [65001]}})
        self.assertEqual(result.weight, 7)
        self.assertEqual(result.sets, {
            'local-preference': 200,
            'metric': 5,
            'origin': ORIGIN_EGP,
            'next-hop': b'\xc0\x00\x02\x01',
            'community': ('set', (C_65000_1,)),
            'large-community': ('set', ((1, 2, 3),)),
            'as-path-prepend': (65001,),
        })

    def test_malformed_set_clauses_are_rejected(self):
        for edits, why in (
                ({'lcoal-preference': 1}, 'a misspelled keyword'),
                ({'set': {}}, 'a keyword that is not in the vocabulary'),
                ({'local-preference': 'high'}, 'a non-numeric value'),
                ({'local-preference': True}, 'a bool value'),
                ({'local-preference': -1}, 'a negative value'),
                ({'metric': 1 << 32}, 'a value past the field width'),
                ({'metric': '+10'}, 'a relative metric'),
                ({'origin': 'unknown'}, 'an unknown origin'),
                ({'origin': 3}, 'an origin out of range'),
                ({'next-hop': 'nowhere'}, 'an unparseable address'),
                ({'next-hop': b'\x01\x02'}, 'packed bytes of the wrong size'),
                ({'weight': 1 << 16}, 'a weight past 65535'),
                ({'community': []}, 'an empty community list'),
                ({'community': 'add'}, 'a string other than none'),
                ({'community': ['65536:1']}, 'an ASN half past 16 bits'),
                ({'community': ['65000:x']}, 'a non-numeric half'),
                ({'community': ['bogus']}, 'an unknown community name'),
                ({'community': {'exact-match': True}},
                 'an exact-match on a set clause'),
                ({'community': {'list': ['65000:1'], 'additive': 'yes'}},
                 'a non-boolean additive'),
                ({'large-community': ['1:2']}, 'a two-part large community'),
                ({'large-community': ['1:2:x']}, 'a non-numeric part'),
                ({'as-path': {'prepend': []}}, 'an empty prepend'),
                ({'as-path': {'prepend': 'x'}}, 'a non-numeric AS'),
                ({'as-path': {'exclude': [1]}}, 'an unsupported as-path op'),
                ({'as-path': [65001]}, 'a prepend without its keyword'),
                ({'continue': 10}, 'route-map continue')):
            with self.assertRaises(ValueError, msg=why):
                RouteMapClause(10, 'permit', None, edits)

    def test_malformed_match_clauses_are_rejected(self):
        for match, why in (
                ({'ip-address': 'x'}, 'a misspelled keyword'),
                ({'ip': 'PL'}, 'a prefix-list without its nesting'),
                ({'ip': {'next-hop': {'prefix-list': 'PL'}}},
                 'an unimplemented match ip keyword'),
                ({'ip': {'address': {'access-list': 'PL'}}},
                 'an unimplemented address source'),
                ({'ip': {'address': {'prefix-list': ''}}}, 'an empty name'),
                ({'ipv6': {}}, 'an empty ipv6 clause'),
                ({'as-path': {'list': 'AS'}}, 'a misspelled as-path option'),
                ({'as-path': []}, 'an empty regex list'),
                ({'as-path': 17}, 'a regex that is not text'),
                ({'as-path': '(bad'}, 'an uncompilable regex'),
                ({'community': []}, 'an empty community list'),
                ({'community': {'list': ['1:1'], 'additive': True}},
                 'an additive on a match clause'),
                ({'community': ['65000:1:2']}, 'three community halves'),
                ({'large-community': ['1:2:3:4']}, 'four parts'),
                ({'metric': 'low'}, 'a non-numeric metric'),
                ({'local-preference': None}, 'a null local-preference'),
                ({'origin': 'ospf'}, 'an unknown origin'),
                ({'next-hop': '10.0.0.256'}, 'a malformed address'),
                ({'continue': 10}, 'route-map continue'),
                ('not a dict', 'a match clause that is not an object')):
            with self.assertRaises(ValueError, msg=why):
                RouteMapClause(10, 'permit', match, None)

    def test_continue_is_rejected_with_its_own_message(self):
        for spec in ({'continue': 20}, None):
            if spec is None:
                continue
            try:
                RouteMapClause(10, 'permit', spec, None)
            except ValueError as exc:
                self.assertIn('continue', str(exc))
                self.assertIn('not supported', str(exc))
            else:
                self.fail('continue was accepted')


class RouteMapSemanticsTestCase(unittest.TestCase):
    """Clause order, the implicit deny, and what the result promises."""

    def setUp(self):
        self.prefix = parse_prefix('10.1.0.0/16')
        self.attrs = Attrs(origin=ORIGIN_IGP, as_path='65001 65002',
                           communities=packed_communities(C_65000_1),
                           med=10, local_pref=100)

    def test_the_first_matching_clause_decides(self):
        rmap = RouteMap('RM')
        rmap.add_clause(10, 'deny', {'origin': 'igp'})
        rmap.add_clause(20, 'permit', None, {'metric': 1})
        result = rmap.apply(self.prefix, self.attrs)
        self.assertFalse(result)
        self.assertEqual(result.action, ACTION_DENY)
        self.assertEqual(result.clause, 10)
        self.assertTrue(result.matched)
        self.assertEqual(result.sets, {})

    def test_clauses_are_evaluated_in_seq_order_not_insertion_order(self):
        rmap = RouteMap('RM')
        rmap.add_clause(20, 'permit', None, {'metric': 20})
        rmap.add_clause(10, 'deny', None)
        self.assertEqual([c.seq for c in rmap.clauses], [10, 20])
        self.assertEqual(rmap.apply(self.prefix, self.attrs).clause, 10)

    def test_a_non_matching_clause_falls_through_to_the_next(self):
        rmap = RouteMap('RM')
        rmap.add_clause(10, 'deny', {'origin': 'egp'})
        rmap.add_clause(20, 'permit', {'origin': 'igp'}, {'metric': 7})
        result = rmap.apply(self.prefix, self.attrs)
        self.assertTrue(result)
        self.assertEqual(result.clause, 20)
        self.assertEqual(result.sets, {'metric': 7})

    def test_no_matching_clause_is_an_implicit_deny(self):
        rmap = RouteMap('RM')
        rmap.add_clause(10, 'permit', {'origin': 'egp'})
        result = rmap.apply(self.prefix, self.attrs)
        self.assertFalse(result)
        self.assertEqual(result.action, ACTION_DENY)
        self.assertIsNone(result.clause)
        self.assertFalse(result.matched)
        self.assertEqual(result.sets, {})
        self.assertIsNone(result.weight)

    def test_an_empty_route_map_denies_everything(self):
        rmap = RouteMap('RM-EMPTY')
        result = rmap.apply(self.prefix, self.attrs)
        self.assertFalse(result)
        self.assertFalse(result.matched)
        self.assertEqual(rmap.unmatched, 1)

    def test_a_deny_clause_ignores_its_sets(self):
        rmap = RouteMap('RM')
        clause = rmap.add_clause(10, 'deny', None,
                                 {'metric': 5, 'weight': 9,
                                  'community': ['65000:1']})
        result = rmap.apply(self.prefix, self.attrs)
        self.assertFalse(result)
        self.assertEqual(result.sets, {})
        self.assertIsNone(result.weight)
        # The clause still remembers them, so show output reproduces the
        # configuration as written.
        self.assertEqual(clause.set['metric'], 5)
        self.assertEqual(clause.as_dict()['set']['weight'], 9)

    def test_the_result_shares_the_clauses_edit_dict(self):
        # Documented and load-bearing: the dict is not copied per route, so a
        # consumer must not mutate it.
        rmap = RouteMap('RM')
        clause = rmap.add_clause(10, 'permit', None, {'metric': 5})
        first = rmap.apply(self.prefix, self.attrs)
        second = rmap.apply(self.prefix, self.attrs)
        self.assertIs(first.sets, clause.set)
        self.assertIs(first.sets, second.sets)

    def test_counters(self):
        rmap = RouteMap('RM')
        permit = rmap.add_clause(10, 'permit', {'origin': 'igp'})
        deny = rmap.add_clause(20, 'deny', {'origin': 'egp'})
        rmap.apply(self.prefix, self.attrs)
        rmap.apply(self.prefix, Attrs(origin=ORIGIN_EGP))
        rmap.apply(self.prefix, Attrs(origin=ORIGIN_INCOMPLETE))
        self.assertEqual(rmap.applied, 3)
        self.assertEqual(rmap.permitted, 1)
        self.assertEqual(rmap.denied, 1)
        self.assertEqual(rmap.unmatched, 1)
        self.assertEqual(permit.hits, 1)
        self.assertEqual(deny.hits, 1)

    def test_truthiness_is_permission(self):
        self.assertTrue(RouteMapResult(ACTION_PERMIT, 10, None, None, True))
        self.assertFalse(RouteMapResult(ACTION_DENY, 10, None, None, True))
        self.assertFalse(RouteMapResult(ACTION_DENY, None, None, None, False))

    def test_result_as_dict(self):
        rmap = one_clause_map(None, {'next-hop': '192.0.2.1', 'weight': 5,
                                     'community': ['no-export'],
                                     'origin': 'igp',
                                     'large-community': ['1:2:3'],
                                     'as-path': {'prepend': [65001]}})
        rendered = rmap.apply(self.prefix, self.attrs).as_dict()
        self.assertEqual(rendered['action'], 'permit')
        self.assertEqual(rendered['clause'], 10)
        self.assertTrue(rendered['matched'])
        self.assertEqual(rendered['set'], {
            'next-hop': '192.0.2.1',
            'weight': 5,
            'origin': 'igp',
            'community': {'action': 'set', 'values': ['no-export']},
            'large-community': {'action': 'set', 'values': ['1:2:3']},
            'as-path-prepend': [65001]})

    def test_clause_as_dict_reproduces_the_configuration(self):
        match = {'ip': {'address': {'prefix-list': 'PL'}},
                 'as-path': ['^65001', '^65002'],
                 'community': {'list': ['65000:1'], 'exact-match': True},
                 'metric': 5, 'local-preference': 100, 'origin': 'igp',
                 'next-hop': '192.0.2.1',
                 'large-community': ['1:2:3']}
        clause = RouteMapClause(10, 'permit', match, {'metric': 1})
        rendered = clause.as_dict()
        self.assertEqual(rendered['match'], match)
        self.assertEqual(rendered['seq'], 10)
        self.assertEqual(rendered['action'], 'permit')
        # The single-regex spelling round-trips as a string, not a list.
        self.assertEqual(
            RouteMapClause(10, 'permit', {'as-path': '^65001'})
            .as_dict()['match'], {'as-path': '^65001'})
        self.assertEqual(
            RouteMapClause(10, 'permit',
                           {'as-path': {'access-list': 'AS'}})
            .as_dict()['match'], {'as-path': {'access-list': 'AS'}})

    def test_references(self):
        rmap = RouteMap('RM')
        rmap.add_clause(10, 'permit',
                        {'ip': {'address': {'prefix-list': 'PL4'}}})
        rmap.add_clause(20, 'permit',
                        {'ipv6': {'address': {'prefix-list': 'PL6'}},
                         'as-path': {'access-list': 'AS'}})
        rmap.add_clause(30, 'permit', {'as-path': '^65001'})
        self.assertEqual(rmap.references(), {
            ('prefix-list', 'PL4'),
            ('ipv6-prefix-list', 'PL6'),
            ('as-path', 'AS')})
        # A regex clause depends on nothing, so it must not appear.
        self.assertEqual(rmap.clauses[2].references(), set())

    def test_clause_mutation_and_version(self):
        rmap = RouteMap('RM')
        self.assertEqual(rmap.version, 0)
        rmap.add_clause(10, 'permit', None)
        self.assertEqual(rmap.version, 1)
        rmap.add_clause(10, 'deny', None)
        self.assertEqual((rmap.version, len(rmap)), (2, 1))
        self.assertEqual(rmap.clauses[0].action, ACTION_DENY)
        rmap.add_clause(20, 'permit', None)
        self.assertTrue(rmap.remove_clause(20))
        self.assertFalse(rmap.remove_clause(20))
        self.assertEqual(rmap.version, 4)
        self.assertEqual(rmap.clear(), 1)
        self.assertEqual(rmap.version, 5)
        self.assertEqual(rmap.clear(), 0)
        self.assertEqual(rmap.version, 5)

    def test_a_rejected_clause_leaves_the_map_untouched(self):
        rmap = RouteMap('RM')
        rmap.add_clause(10, 'permit', None)
        self.assertRaises(ValueError, rmap.add_clause, 20, 'permit',
                          {'nonsense': 1})
        self.assertRaises(ValueError, rmap.add_clause, 20, 'allow', None)
        self.assertEqual(len(rmap), 1)
        self.assertEqual(rmap.version, 1)

    def test_construction_is_validated(self):
        self.assertRaises(ValueError, RouteMap, '')
        self.assertRaises(ValueError, RouteMapClause, 10, 'allow', None, None)
        self.assertRaises(ValueError, RouteMapClause, 'ten', 'permit',
                          None, None)

    def test_map_as_dict(self):
        rmap = RouteMap('RM-SHOW')
        rmap.add_clause(10, 'permit', {'origin': 'igp'}, {'metric': 1})
        rmap.apply(self.prefix, self.attrs)
        rendered = rmap.as_dict()
        self.assertEqual(rendered['name'], 'RM-SHOW')
        self.assertEqual(rendered['version'], 1)
        self.assertEqual(rendered['applied'], 1)
        self.assertEqual(rendered['permitted'], 1)
        self.assertEqual(rendered['denied'], 0)
        self.assertEqual(rendered['unmatched'], 0)
        self.assertEqual(len(rendered['clauses']), 1)
        self.assertEqual(rendered['clauses'][0]['hits'], 1)


# The document every store test starts from, as a function rather than a
# constant: the tests mutate their copies, and a shared literal would make
# one test's edit another test's fixture.
def base_document():
    """A small but complete policy document."""
    return {
        'ip': {
            'prefix-list': {
                'PL-IN': [{'seq': 5, 'action': 'permit',
                           'prefix': '10.0.0.0/8', 'le': 24},
                          {'seq': 10, 'action': 'deny',
                           'prefix': '0.0.0.0/0', 'le': 32}],
            },
            'as-path-access-list': {
                'AS-IN': [{'seq': 5, 'action': 'permit', 'regex': '^65001'}],
            },
        },
        'ipv6': {
            'prefix-list': {
                'PL6-IN': [{'seq': 5, 'action': 'permit',
                            'prefix': '2001:db8::/32', 'le': 48}],
            },
        },
        'route-map': {
            'RM-IN': [
                {'seq': 10, 'action': 'permit',
                 'match': {'ip': {'address': {'prefix-list': 'PL-IN'}},
                           'as-path': {'access-list': 'AS-IN'}},
                 'set': {'local-preference': 200}},
                {'seq': 20, 'action': 'deny'},
            ],
            'RM6-IN': [
                {'seq': 10, 'action': 'permit',
                 'match': {'ipv6': {'address': {'prefix-list': 'PL6-IN'}}}},
            ],
        },
    }


class PolicyStoreValidateTestCase(unittest.TestCase):
    """Validation: pure, and specific about where the mistake is."""

    def test_a_good_document_validates(self):
        PolicyStore().validate(base_document())

    def test_none_and_empty_documents_validate(self):
        store = PolicyStore()
        store.validate(None)
        store.validate({})
        self.assertRaises(ConfigError, store.validate, 'not a document')

    def check_rejects(self, document, path, needle=None):
        """Assert a document is rejected at a path.

        :param document: the document.
        :param path: the expected ``ConfigError.path``.
        :param needle: a substring the detail must contain.
        """
        store = PolicyStore()
        try:
            store.validate(document)
        except ConfigError as exc:
            self.assertEqual(exc.path, path, exc.detail)
            if needle is not None:
                self.assertIn(needle, exc.detail)
            self.assertEqual(exc.as_dict()['error'], 'Invalid')
        else:
            self.fail('accepted %r' % (document,))

    def test_an_unknown_match_keyword_is_rejected_with_its_path(self):
        document = base_document()
        document['route-map']['RM-IN'][0]['match'] = {'nonsense': 1}
        self.check_rejects(document, 'route-map.RM-IN.0.match',
                           'unknown match keyword')

    def test_an_unknown_set_keyword_is_rejected_with_its_path(self):
        document = base_document()
        document['route-map']['RM-IN'][1]['set'] = {'nonsense': 1}
        self.check_rejects(document, 'route-map.RM-IN.1.set',
                           'unknown set keyword')

    def test_a_bad_community_is_rejected(self):
        document = base_document()
        document['route-map']['RM-IN'][0]['match'] = {
            'community': ['65536:1']}
        self.check_rejects(document, 'route-map.RM-IN.0.match')
        document = base_document()
        document['route-map']['RM-IN'][0]['set'] = {'community': ['bogus']}
        self.check_rejects(document, 'route-map.RM-IN.0.set')

    def test_a_bad_regex_is_rejected(self):
        document = base_document()
        document['route-map']['RM-IN'][0]['match'] = {'as-path': '(bad'}
        self.check_rejects(document, 'route-map.RM-IN.0.match')
        document = base_document()
        document['ip']['as-path-access-list']['AS-IN'][0]['regex'] = '(bad'
        self.check_rejects(document, 'ip.as-path-access-list.AS-IN.0')

    def test_a_bad_prefix_is_rejected(self):
        document = base_document()
        document['ip']['prefix-list']['PL-IN'][0]['prefix'] = '10.0.0.0/33'
        self.check_rejects(document, 'ip.prefix-list.PL-IN.0')
        document = base_document()
        document['ipv6']['prefix-list']['PL6-IN'][0]['prefix'] = 'nope'
        self.check_rejects(document, 'ipv6.prefix-list.PL6-IN.0')

    def test_a_bound_from_the_wrong_family_is_rejected(self):
        # The schema cannot catch this: it accepts 0..128 for both families
        # because it does not know which family the entry is in.
        document = base_document()
        document['ip']['prefix-list']['PL-IN'][0]['le'] = 64
        self.check_rejects(document, 'ip.prefix-list.PL-IN.0')

    def test_a_missing_prefix_list_reference_is_rejected(self):
        document = base_document()
        document['route-map']['RM-IN'][0]['match'] = {
            'ip': {'address': {'prefix-list': 'ABSENT'}}}
        self.check_rejects(document, 'route-map.RM-IN.0.match',
                           'does not define')

    def test_a_missing_ipv6_prefix_list_reference_is_rejected(self):
        document = base_document()
        document['route-map']['RM6-IN'][0]['match'] = {
            'ipv6': {'address': {'prefix-list': 'PL-IN'}}}
        # PL-IN exists, but in the IPv4 namespace, which is a different list.
        self.check_rejects(document, 'route-map.RM6-IN.0.match',
                           'ipv6-prefix-list')

    def test_a_missing_as_path_reference_is_rejected(self):
        document = base_document()
        document['route-map']['RM-IN'][0]['match'] = {
            'as-path': {'access-list': 'ABSENT'}}
        self.check_rejects(document, 'route-map.RM-IN.0.match',
                           'as-path')

    def test_continue_is_rejected_at_the_clause(self):
        document = base_document()
        document['route-map']['RM-IN'][0]['continue'] = 20
        self.check_rejects(document, 'route-map.RM-IN.0', 'continue')

    def test_malformed_sections_are_rejected(self):
        cases = (
            ({'ip': {'prefix-list': []}}, 'ip.prefix-list'),
            ({'ip': {'prefix-list': {'P': {}}}}, 'ip.prefix-list.P'),
            ({'ip': {'prefix-list': {'P': ['x']}}}, 'ip.prefix-list.P.0'),
            ({'ip': {'prefix-list': {'P': [{'prefix': '10.0.0.0/8'}]}}},
             'ip.prefix-list.P.0'),
            ({'ip': {'prefix-list': {'P': [{'action': 'permit'}]}}},
             'ip.prefix-list.P.0'),
            ({'ip': {'prefix-list': {'P': [{'action': 'permit',
                                            'prefix': '10.0.0.0/8',
                                            'nonsense': 1}]}}},
             'ip.prefix-list.P.0'),
            ({'ipv6': {'prefix-list': {'P': 'x'}}}, 'ipv6.prefix-list.P'),
            ({'ip': {'as-path-access-list': {'A': [{'action': 'permit'}]}}},
             'ip.as-path-access-list.A.0'),
            ({'ip': {'as-path-access-list': {'A': [{'action': 'permit',
                                                    'regex': '^1',
                                                    'pattern': '^1'}]}}},
             'ip.as-path-access-list.A.0'),
            ({'route-map': []}, 'route-map'),
            ({'route-map': {'R': {}}}, 'route-map.R'),
            ({'route-map': {'R': ['x']}}, 'route-map.R.0'),
            ({'route-map': {'R': [{}]}}, 'route-map.R.0'),
            ({'route-map': {'R': [{'action': 'permit', 'nonsense': 1}]}},
             'route-map.R.0'),
            ({'route-map': {'R': [{'action': 'permit', 'seq': 'x'}]}},
             'route-map.R.0'),
            ({'route-map': {'R': [{'action': 'allow'}]}}, 'route-map.R.0'),
        )
        for document, path in cases:
            self.check_rejects(document, path)

    def test_the_pattern_synonym_is_accepted(self):
        PolicyStore().validate({'ip': {'as-path-access-list': {
            'A': [{'action': 'permit', 'pattern': '^65001'}]}}})

    def test_validate_does_not_mutate_the_store(self):
        store = store_with(base_document())
        before = (store.revision, store.names(),
                  store.version_of('prefix-list', 'PL-IN'),
                  store.version_of('route-map', 'RM-IN'),
                  store.version_of('as-path', 'AS-IN'))
        identities = (store.prefix_list('PL-IN', AFI_IP),
                      store.route_map('RM-IN'))

        # A document that would add and change things, but is never loaded.
        other = base_document()
        other['ip']['prefix-list']['PL-EXTRA'] = [
            {'action': 'permit', 'prefix': '192.0.2.0/24'}]
        other['route-map']['RM-IN'][0]['set'] = {'metric': 99}
        store.validate(other)

        # And one that is rejected part-way through.
        broken = base_document()
        broken['route-map']['RM-IN'][0]['match'] = {'nonsense': 1}
        self.assertRaises(ConfigError, store.validate, broken)

        after = (store.revision, store.names(),
                 store.version_of('prefix-list', 'PL-IN'),
                 store.version_of('route-map', 'RM-IN'),
                 store.version_of('as-path', 'AS-IN'))
        self.assertEqual(before, after)
        self.assertIs(identities[0], store.prefix_list('PL-IN', AFI_IP))
        self.assertIs(identities[1], store.route_map('RM-IN'))
        self.assertEqual(store.route_map('RM-IN').clauses[0].set,
                         {'local-preference': 200})


class PolicyStoreLoadTestCase(unittest.TestCase):
    """Loading: idempotent, identity-preserving, and version-honest."""

    def test_load_builds_everything(self):
        store = store_with(base_document())
        self.assertEqual(store.names(), {
            'prefix-list': ['PL-IN'],
            'ipv6-prefix-list': ['PL6-IN'],
            'route-map': ['RM-IN', 'RM6-IN'],
            'as-path': ['AS-IN']})
        self.assertEqual(store.revision, 1)
        self.assertEqual(len(store.prefix_list('PL-IN')), 2)
        self.assertEqual(len(store.route_map('RM-IN')), 2)
        self.assertEqual(len(store.as_path_list('AS-IN')), 1)

    def test_the_two_prefix_list_namespaces_are_separate(self):
        store = store_with({
            'ip': {'prefix-list': {'P': [{'action': 'permit',
                                          'prefix': '10.0.0.0/8'}]}},
            'ipv6': {'prefix-list': {'P': [{'action': 'deny',
                                            'prefix': '2001:db8::/32'}]}}})
        self.assertEqual(store.prefix_list('P', AFI_IP).afi, AFI_IP)
        self.assertEqual(store.prefix_list('P', AFI_IP6).afi, AFI_IP6)
        # No AFI searches IPv4 first, which is what a caller that does not
        # care gets.
        self.assertEqual(store.prefix_list('P').afi, AFI_IP)
        self.assertIsNone(store.prefix_list('P', 99))
        self.assertIsNone(store.prefix_list('ABSENT'))
        self.assertIsNone(store.route_map('ABSENT'))
        self.assertIsNone(store.as_path_list('ABSENT'))

    def test_load_is_idempotent_and_preserves_identity_and_versions(self):
        # The expensive failure this guards: a version that moves when the
        # configuration did not re-advertises the whole table to every peer
        # in the update group that cites it.
        store = store_with(base_document())
        objects = {
            'prefix-list': store.prefix_list('PL-IN', AFI_IP),
            'ipv6-prefix-list': store.prefix_list('PL6-IN', AFI_IP6),
            'route-map': store.route_map('RM-IN'),
            'as-path': store.as_path_list('AS-IN'),
        }
        versions = dict((kind, obj.version)
                        for kind, obj in objects.items())
        revision = store.revision

        self.assertEqual(store.load(base_document()), 0)
        self.assertEqual(store.revision, revision)
        self.assertIs(store.prefix_list('PL-IN', AFI_IP),
                      objects['prefix-list'])
        self.assertIs(store.prefix_list('PL6-IN', AFI_IP6),
                      objects['ipv6-prefix-list'])
        self.assertIs(store.route_map('RM-IN'), objects['route-map'])
        self.assertIs(store.as_path_list('AS-IN'), objects['as-path'])
        for kind, obj in objects.items():
            self.assertEqual(obj.version, versions[kind], kind)
            self.assertEqual(store.version_of(kind,
                                              obj.name), versions[kind])

    def test_a_document_whose_keys_are_reordered_is_still_unchanged(self):
        store = store_with(base_document())
        revision = store.revision
        reordered = base_document()
        # Same entry, different key order in the object.
        entry = reordered['ip']['prefix-list']['PL-IN'][0]
        reordered['ip']['prefix-list']['PL-IN'][0] = {
            'le': entry['le'], 'prefix': entry['prefix'],
            'action': entry['action'], 'seq': entry['seq']}
        self.assertEqual(store.load(reordered), 0)
        self.assertEqual(store.revision, revision)

    def test_a_real_change_bumps_the_version_and_keeps_the_object(self):
        store = store_with(base_document())
        plist = store.prefix_list('PL-IN', AFI_IP)
        before = plist.version
        rmap = store.route_map('RM-IN')
        map_before = rmap.version
        as_before = store.version_of('as-path', 'AS-IN')

        changed = base_document()
        changed['ip']['prefix-list']['PL-IN'][0]['le'] = 28
        self.assertEqual(store.load(changed), 1)
        self.assertEqual(store.revision, 2)
        # Same object, higher version -- so an update-group key citing it
        # changes, and every holder of a reference sees the new entries.
        self.assertIs(store.prefix_list('PL-IN', AFI_IP), plist)
        self.assertGreater(plist.version, before)
        self.assertEqual(plist.entries()[0].le, 28)
        # Nothing else moved.
        self.assertEqual(rmap.version, map_before)
        self.assertEqual(store.version_of('as-path', 'AS-IN'), as_before)

    def test_a_single_entry_swap_still_bumps_the_version(self):
        # The case a rebuild-from-scratch implementation gets wrong: one
        # entry replaced by a different one, so a fresh object's version
        # would land on exactly the number it had before.
        store = store_with(prefix_doc('P', [{'action': 'permit',
                                             'prefix': '10.0.0.0/8'}]))
        first = store.version_of('prefix-list', 'P')
        store.load(prefix_doc('P', [{'action': 'permit',
                                     'prefix': '11.0.0.0/8'}]))
        self.assertNotEqual(store.version_of('prefix-list', 'P'), first)
        self.assertEqual(store.prefix_list('P').entries()[0].prefix.to_str(),
                         '11.0.0.0/8')

    def test_changing_a_route_map_clause_bumps_only_that_map(self):
        store = store_with(base_document())
        other = store.route_map('RM6-IN')
        other_version = other.version
        changed = base_document()
        changed['route-map']['RM-IN'][0]['set'] = {'local-preference': 300}
        self.assertEqual(store.load(changed), 1)
        self.assertEqual(store.route_map('RM-IN').clauses[0].set,
                         {'local-preference': 300})
        self.assertIs(store.route_map('RM6-IN'), other)
        self.assertEqual(other.version, other_version)

    def test_removal(self):
        store = store_with(base_document())
        reduced = base_document()
        del reduced['route-map']['RM6-IN']
        del reduced['ipv6']['prefix-list']['PL6-IN']
        self.assertEqual(store.load(reduced), 2)
        self.assertIsNone(store.route_map('RM6-IN'))
        self.assertIsNone(store.prefix_list('PL6-IN', AFI_IP6))
        self.assertIsNone(store.version_of('route-map', 'RM6-IN'))
        self.assertEqual(store.names()['ipv6-prefix-list'], [])
        # Loading the reduced document again changes nothing further.
        self.assertEqual(store.load(reduced), 0)

    def test_load_none_clears_everything(self):
        store = store_with(base_document())
        self.assertEqual(store.load(None), 5)
        self.assertEqual(store.names(), {'prefix-list': [],
                                         'ipv6-prefix-list': [],
                                         'route-map': [], 'as-path': []})
        self.assertEqual(store.load(None), 0)

    def test_a_removed_and_readded_name_is_a_new_object(self):
        store = store_with(base_document())
        first = store.route_map('RM-IN')
        reduced = base_document()
        del reduced['route-map']['RM-IN']
        store.load(reduced)
        store.load(base_document())
        self.assertIsNot(store.route_map('RM-IN'), first)
        self.assertEqual(store.route_map('RM-IN').version, 2)

    def test_the_snapshot_does_not_alias_the_callers_document(self):
        # The caller owns its document and may edit it afterwards; the store
        # must compare against what it was given, not against a live view of
        # it, or an in-place edit would go unnoticed on the next load.
        document = base_document()
        store = store_with(document)
        document['ip']['prefix-list']['PL-IN'][0]['le'] = 30
        self.assertEqual(store.load(document), 1)
        self.assertEqual(store.prefix_list('PL-IN').entries()[0].le, 30)
        self.assertEqual(store.load(base_document()), 1)
        self.assertEqual(store.prefix_list('PL-IN').entries()[0].le, 24)

    def test_a_rejected_load_leaves_the_store_untouched(self):
        store = store_with(base_document())
        revision = store.revision
        plist = store.prefix_list('PL-IN', AFI_IP)
        version = plist.version

        broken = base_document()
        broken['ip']['prefix-list']['PL-IN'][0]['le'] = 28
        broken['route-map']['RM-IN'][0]['set'] = {'nonsense': 1}
        self.assertRaises(ConfigError, store.load, broken)

        # The prefix-list change in the same document must not have been
        # applied: load validates the whole document before it touches
        # anything.
        self.assertEqual(store.revision, revision)
        self.assertIs(store.prefix_list('PL-IN', AFI_IP), plist)
        self.assertEqual(plist.version, version)
        self.assertEqual(plist.entries()[0].le, 24)

    def test_sequence_numbers_are_auto_assigned_when_omitted(self):
        store = store_with({
            'ip': {
                'prefix-list': {'P': [{'action': 'permit',
                                       'prefix': '10.0.0.0/8'},
                                      {'action': 'deny',
                                       'prefix': '11.0.0.0/8'}]},
                'as-path-access-list': {'A': [{'action': 'permit',
                                               'regex': '^1'},
                                              {'action': 'deny',
                                               'regex': '^2'}]},
            },
            'route-map': {'R': [{'action': 'permit'}, {'action': 'deny'}]},
        })
        self.assertEqual([e.seq for e in store.prefix_list('P').entries()],
                         [5, 10])
        self.assertEqual([e.seq for e in store.as_path_list('A').entries()],
                         [5, 10])
        self.assertEqual([c.seq for c in store.route_map('R').clauses],
                         [10, 20])

    def test_a_loaded_route_map_resolves_its_lists_through_the_store(self):
        store = store_with(base_document())
        rmap = store.route_map('RM-IN')
        attrs = Attrs(as_path='65001 65002')
        self.assertTrue(rmap.apply(parse_prefix('10.1.0.0/16'), attrs))
        self.assertFalse(rmap.apply(parse_prefix('192.0.2.0/24'), attrs))

        # Narrow the prefix-list and the same map must change behaviour,
        # without being rebuilt: the clause resolves by name per application.
        narrowed = base_document()
        narrowed['ip']['prefix-list']['PL-IN'][0]['prefix'] = '172.16.0.0/12'
        store.load(narrowed)
        self.assertIs(store.route_map('RM-IN'), rmap)
        self.assertFalse(rmap.apply(parse_prefix('10.1.0.0/16'), attrs))
        self.assertTrue(rmap.apply(parse_prefix('172.16.1.0/24'), attrs))

    def test_version_of(self):
        store = store_with(base_document())
        for kind in KINDS:
            # None, not 0: 0 is a defined object never edited (P-6).
            self.assertIsNone(store.version_of(kind, 'ABSENT'))
        self.assertGreater(store.version_of('prefix-list', 'PL-IN'), 0)
        self.assertRaises(ValueError, store.version_of, 'prefixlist', 'PL-IN')

    def test_show_helpers(self):
        store = store_with(base_document())
        both = store.prefix_list_dict()
        self.assertEqual([item['name'] for item in both['items']],
                         ['PL-IN', 'PL6-IN'])
        self.assertEqual([item['afi'] for item in both['items']],
                         [AFI_IP, AFI_IP6])
        one = store.prefix_list_dict('PL6-IN')
        self.assertEqual(len(one['items']), 1)
        self.assertEqual(one['items'][0]['entries'][0]['prefix'],
                         '2001:db8::/32')
        self.assertEqual(store.prefix_list_dict('ABSENT'), {'items': []})

        maps = store.route_map_dict()
        self.assertEqual([item['name'] for item in maps['items']],
                         ['RM-IN', 'RM6-IN'])
        self.assertEqual(store.route_map_dict('RM-IN')['items'][0]['clauses']
                         [0]['match'],
                         {'ip': {'address': {'prefix-list': 'PL-IN'}},
                          'as-path': {'access-list': 'AS-IN'}})
        self.assertEqual(store.route_map_dict('ABSENT'), {'items': []})

        as_paths = store.as_path_list_dict()
        self.assertEqual([item['name'] for item in as_paths['items']],
                         ['AS-IN'])

    def test_stats(self):
        store = store_with(base_document())
        stats = store.stats()
        self.assertEqual(stats['revision'], 1)
        self.assertEqual(stats['loads'], 1)
        self.assertEqual(stats['prefix-lists'], 1)
        self.assertEqual(stats['ipv6-prefix-lists'], 1)
        self.assertEqual(stats['route-maps'], 2)
        self.assertEqual(stats['as-path-lists'], 1)
        self.assertEqual(stats['prefix-list-entries'], 3)
        self.assertEqual(stats['route-map-clauses'], 3)
        store.load(base_document())
        self.assertEqual(store.stats()['loads'], 2)
        self.assertEqual(store.stats()['revision'], 1)

    def test_reloading_repeatedly_does_not_grow_the_index(self):
        # The store-level half of the prefix-list lifetime test: a reload
        # that cleared and refilled without releasing trie nodes would leak
        # once per configuration change, which is the shape of the two leaks
        # the Stage-2 review found.
        store = PolicyStore()
        entries = [{'seq': (index + 1) * 5, 'action': 'permit',
                    'prefix': '10.%d.0.0/16' % index, 'le': 24}
                   for index in range(16)]
        for round_number in range(40):
            document = prefix_doc('P', [dict(entry) for entry in entries])
            # Alternate the bound so every round is a real change.
            document['ip']['prefix-list']['P'][0]['le'] = \
                24 + (round_number % 2)
            store.load(document)
            plist = store.prefix_list('P', AFI_IP)
            self.assertEqual(plist.trie.count, 16)
            self.assertLessEqual(plist.trie.nodes, 32)
        self.assertEqual(len(plist), 16)
        store.load(None)
        gc.collect()


if __name__ == '__main__':
    unittest.main()
