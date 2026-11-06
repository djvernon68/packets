# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Policy and RIB semantics: the Stage 6 fixes of packets 2.2.2.

  * P-1 -- IOS ``_`` in an AS-path regex is the path delimiter, so ``deny
    _65001_`` no longer fails open.
  * P-2 -- an AS-path regex that could stall the engine on a long path is
    refused when it is configured; expensive ones remember their answers;
    and ``maxas-limit`` (default 255) bounds the path they run over.
  * P-3 -- next-hop resolution recurses through learned routes, will not let
    a protocol vouch for its own next hop, and ignores a default route unless
    ``resolve-via-default`` says otherwise.
  * P-4 -- the ``show ip route`` cursor names the last prefix returned.
  * P-6 -- ``version_of`` tells "absent" from "defined, never edited".
  * P-7 -- a kernel route is shadowed by a static that *covers* it.
"""

import struct
import time
import unittest

import rtengine_rawspeaker as raw
import test_rtengine_session_notify as notify

from packets.routing.rtengine import ConfigError
from packets.routing.rtengine.engine import Engine
from packets.routing.rtengine.plugins.bgp import fsm as fsm_mod
from packets.routing.rtengine.plugins.bgp import peer as peer_mod
from packets.routing.rtengine.plugins.bgp import plugin as bgp_plugin
from packets.routing.rtengine.policy import aspath as aspath_mod
from packets.routing.rtengine.policy.aspath import (AsPathList,
                                                    AsPathMatcher,
                                                    compile_pattern,
                                                    strip_wildcards,
                                                    translate)
from packets.routing.rtengine.policy.store import KINDS, PolicyStore
from packets.routing.rtengine.rib import resolver as resolver_mod
from packets.routing.rtengine.rib import table as T
from packets.routing.rtengine.rib.prefix import AFI_IP, parse_prefix


def _addr(text):
    return parse_prefix(text).packed()


def _route(prefix, protocol=T.PROTO_STATIC, nexthop=b'', distance=1):
    if isinstance(nexthop, str):
        nexthop = _addr(nexthop)
    return T.Route(parse_prefix(prefix), protocol, distance, 0, nexthop,
                   object(), 100.0)


# --- P-1: the underscore ----------------------------------------------------

class UnderscoreTestCase(unittest.TestCase):
    """P-1: ``_`` is a delimiter of the canonical path string."""

    def test_it_matches_at_every_kind_of_delimiter(self):
        matcher = AsPathMatcher('_65001_')
        for path in ('65001', '1 65001 2', '65001 2', '1 65001', '{65001}',
                     '{2,65001}', '{65001,2}', '(65001 3)', '(3 65001)',
                     '[3,65001]'):
            self.assertTrue(matcher.matches(path), path)

    def test_it_does_not_match_inside_an_asn(self):
        matcher = AsPathMatcher('_65001_')
        for path in ('165001', '650011', '1 165001 2', '', '6500 1'):
            self.assertFalse(matcher.matches(path), path)

    def test_a_deny_entry_now_denies(self):
        # The defect: this list permitted every path, because `_65001_`
        # was a literal underscore and matched nothing.
        alist = AsPathList('NO-65001')
        alist.add(10, 'deny', '_65001_')
        alist.add(20, 'permit', '.*')
        self.assertFalse(alist.permits('1 65001 2'))
        self.assertFalse(alist.permits('{65001}'))
        self.assertTrue(alist.permits('1 165001 2'))
        self.assertTrue(alist.permits(''))

    def test_anchored_forms(self):
        self.assertTrue(AsPathMatcher('^65001_').matches('65001 2'))
        self.assertFalse(AsPathMatcher('^65001_').matches('650012'))
        self.assertTrue(AsPathMatcher('_65001$').matches('2 65001'))
        self.assertTrue(AsPathMatcher('^65001_65002$').matches(
            '65001 65002'))

    def test_escaped_and_bracketed_underscores_stay_literal(self):
        self.assertEqual(translate(r'\_'), r'\_')
        self.assertEqual(translate('[_]'), '[_]')
        self.assertEqual(translate('[^_]x_'),
                         '[^_]x' + aspath_mod.UNDERSCORE)
        self.assertEqual(translate('[]_]_'), '[]_]' + aspath_mod.UNDERSCORE)
        self.assertFalse(AsPathMatcher(r'65001\_').matches('65001 2'))


# --- P-2: the guard, the cache, and maxas-limit -----------------------------

class RegexGuardTestCase(unittest.TestCase):
    """P-2: what could run away is refused, and IOS idioms are not."""

    ACCEPTED = (
        '_65001_', '^65001_', '_65001$', '.*65001.*', '^[0-9]+$',
        '^[0-9]+(_[0-9]+)*$', '(_[0-9]+)*_65001$', '^(_[0-9]+){0,3}$',
        '^65001(_65001)*$', '_65001_.*_65002_', '(_65001|_65002)+',
        '^65000_([0-9]+_)*65001$', r'\{65003,65004\}$', '^$', '.*',
    )

    REFUSED = (
        ('([0-9]+)+', 'repeats a group that itself repeats'),
        ('(.*)*', 'repeats a group that itself repeats'),
        ('(_.*)*', 'repeats a group that itself repeats'),
        ('([0-9 ]+_)+', 'repeats a group that itself repeats'),
        ('(_[0-9]+|[0-9]+_)+', 'repeats a group that itself repeats'),
        ('(1 |1 )+X', 'alternation whose branches'),
        ('(a|ab)+', 'alternation whose branches'),
        (r'(1)\1', 'backreference'),
        ('(?P<x>1)(?P=x)', 'backreference'),
        ('_1_.*_1_.*_1_.*_1_', 'path-spanning repeats'),
        # Cubic (S6-d): accepted by the Stage 6 rule of two spanning
        # repeats, and ~1 s on cnp02 at 255 ASNs for the worst of them.
        ('.*_1_.*_1_.*X', 'cube of the path length'),
        ('(_[0-9]+)*(_[0-9]+)*X', 'cube of the path length'),
        ('x' * 257, 'the limit is 256'),
    )

    def test_ios_idioms_are_accepted(self):
        for pattern in self.ACCEPTED:
            AsPathMatcher(pattern)

    def test_what_could_run_away_is_refused_with_the_reason(self):
        for pattern, reason in self.REFUSED:
            with self.assertRaises(ValueError) as caught:
                compile_pattern(pattern)
            self.assertIn(reason, str(caught.exception), pattern)

    def test_the_length_limit_is_inclusive(self):
        compile_pattern('1' * aspath_mod.MAX_PATTERN_LENGTH)
        self.assertRaises(ValueError, compile_pattern,
                          '1' * (aspath_mod.MAX_PATTERN_LENGTH + 1))

    def test_redundant_wildcards_are_dropped_and_change_nothing(self):
        self.assertEqual(strip_wildcards('.*65001.*'), '65001')
        self.assertEqual(strip_wildcards('^.*65001.*$'), '65001')
        self.assertEqual(strip_wildcards('.*.*65001'), '65001')
        self.assertEqual(strip_wildcards('.*?65001'), '65001')
        self.assertEqual(strip_wildcards('.*'), '')
        self.assertEqual(strip_wildcards(r'65001\.*'), r'65001\.*')
        self.assertEqual(strip_wildcards('(.*)65001'), '(.*)65001')
        for path in ('65001', '1 65001 2', '2'):
            self.assertEqual(AsPathMatcher('.*65001.*').matches(path),
                             AsPathMatcher('65001').matches(path), path)

    def test_a_refused_regex_is_a_configuration_error(self):
        store = PolicyStore()
        with self.assertRaises(ConfigError) as caught:
            store.load({'ip': {'as-path-access-list': {'BAD': [
                {'seq': 10, 'action': 'deny', 'regex': '([0-9]+)+'}]}}})
        self.assertEqual(caught.exception.path, 'ip.as-path-access-list.BAD.0')
        self.assertIn('repeats a group', str(caught.exception))

    def test_the_slowest_accepted_pattern_is_bounded_on_the_longest_path(self):
        # 255 ten-digit ASNs: the longest path maxas-limit lets through,
        # and the shape that made two-wildcard patterns slowest. Before
        # the guard, `.*_1_.*_1_.*X` alone ran for 105 s on a path of 1,000
        # one-digit ASNs; S6-d now refuses it. These are the worst shapes
        # still accepted at 255 ASNs, all quadratic.
        paths = (' '.join(['4200000001'] * 255), ' '.join(['1'] * 255))
        for pattern in ('_4200000001_.*_4200000001_X', '(_[0-9]+)*_1_X',
                        '^[0-9]+(_[0-9]+)*(_[0-9]+)*X'):
            regex = compile_pattern(pattern)
            for path in paths:
                started = time.monotonic()
                regex.search(path)
                self.assertLess(time.monotonic() - started, 1.0, pattern)


class ResultCacheTestCase(unittest.TestCase):
    """P-2: an expensive pattern answers a repeated path from memory."""

    def test_a_spanning_pattern_caches_and_shares_its_answers(self):
        first = AsPathMatcher('_64999_.*_64998_')
        second = AsPathMatcher('_64999_.*_64998_')
        self.assertIs(first._results, second._results)
        self.assertTrue(first.matches('64999 1 64998'))
        self.assertIn('64999 1 64998', second._results)
        self.assertTrue(second.matches('64999 1 64998'))
        self.assertFalse(first.matches('64998 64999'))
        self.assertIs(first._results['64998 64999'], False)

    def test_a_cheap_pattern_is_not_cached(self):
        self.assertIsNone(AsPathMatcher('_64997_')._results)

    def test_the_cache_is_bounded(self):
        matcher = AsPathMatcher('^64996_.*_1$')
        old = aspath_mod.RESULT_CACHE_MAX
        aspath_mod.RESULT_CACHE_MAX = 8
        try:
            for i in range(20):
                matcher.matches('64996 %d 1' % i)
            self.assertLessEqual(len(matcher._results), 8)
            # Most recent kept, oldest evicted.
            self.assertIn('64996 19 1', matcher._results)
            self.assertNotIn('64996 0 1', matcher._results)
        finally:
            aspath_mod.RESULT_CACHE_MAX = old


class _Attrs(object):
    def __init__(self, as_path):
        self.as_path = as_path


class _Config(object):
    address = '192.0.2.9'

    def __init__(self, limit):
        self.maxas_limit = limit


class _Session(object):
    """Just what Peer._too_long reads."""

    def __init__(self, limit):
        self.config = _Config(limit)
        self._maxas_warned = False

    too_long = peer_mod.Peer._too_long


def _segments(*segments):
    out = b''
    for seg_type, count in segments:
        out += bytes(bytearray([seg_type, count])) + struct.pack('!I', 1) * count
    return out


class MaxasLimitTestCase(unittest.TestCase):
    """P-2: maxas-limit counts every ASN and is on by default."""

    def test_the_default_is_255(self):
        self.assertEqual(peer_mod.DEFAULT_MAXAS_LIMIT, 255)
        self.assertEqual(
            peer_mod.PeerConfig('192.0.2.1', 1, 2, '1.1.1.1').maxas_limit,
            255)

    def test_the_boundary(self):
        session = _Session(255)
        self.assertFalse(session.too_long(_Attrs(_segments((2, 255)))))
        self.assertTrue(session.too_long(_Attrs(_segments((2, 255),
                                                          (2, 1)))))

    def test_set_and_confederation_members_all_count(self):
        # A best-path length would count the set as one; this limit bounds
        # the rendered string, and every member is in it.
        session = _Session(10)
        self.assertTrue(session.too_long(_Attrs(_segments((2, 5), (1, 6)))))
        self.assertTrue(session.too_long(_Attrs(_segments((3, 11)))))
        self.assertFalse(session.too_long(_Attrs(_segments((2, 5), (1, 5)))))

    def test_zero_is_off(self):
        self.assertFalse(_Session(0).too_long(
            _Attrs(_segments((2, 255), (2, 255), (2, 255)))))

    def test_it_warns_once_per_session(self):
        session = _Session(1)
        with self.assertLogs(peer_mod.LOG.name, 'WARNING') as logs:
            session.too_long(_Attrs(_segments((2, 3))))
            session.too_long(_Attrs(_segments((2, 3))))
        self.assertEqual(len(logs.records), 1)
        self.assertIn('maxas-limit 1', logs.output[0])


class MaxasLimitConfigTestCase(unittest.TestCase):
    """The instance key: range, default, and a change that costs no reset."""

    def _engine(self, extra=None):
        body = {'router-id': '10.0.0.1', 'neighbor': {
            '192.0.2.1': {'remote-as': 65002, 'passive': True}}}
        body.update(extra or {})
        engine = Engine(name='maxas', plugins=[bgp_plugin.BGPPlugin()])
        self.addCleanup(engine.stop)
        engine.replace_config({'router': {'bgp': {'65001': body}}})
        return engine

    def test_the_default_reaches_every_neighbour(self):
        engine = self._engine()
        peer = engine.plugin('bgp').peers['192.0.2.1']
        self.assertEqual(peer.config.maxas_limit, 255)

    def test_the_range_is_0_to_2000(self):
        self.assertEqual(self._engine({'maxas-limit': 0}).plugin('bgp')
                         .peers['192.0.2.1'].config.maxas_limit, 0)
        self.assertRaises(ConfigError, self._engine, {'maxas-limit': 2001})
        self.assertRaises(ConfigError, self._engine, {'maxas-limit': -1})

    def test_a_change_applies_in_place(self):
        engine = self._engine()
        before = engine.plugin('bgp').peers['192.0.2.1']
        engine.configure(('router', 'bgp', '65001', 'maxas-limit'), 20)
        after = engine.plugin('bgp').peers['192.0.2.1']
        self.assertIs(after, before)
        self.assertEqual(after.config.maxas_limit, 20)


def _long_path(count):
    """An AS_PATH of ``count`` copies of the speaker's AS, 255 a segment."""
    value = b''
    left = count
    while left:
        n = min(255, left)
        value += bytes(bytearray([2, n])) + \
            struct.pack('!I', notify.SPEAKER_AS) * n
        left -= n
    return raw.attr(0x50, 2, value)


class LiveMaxasLimitTestCase(notify.LiveFixture):
    """The limit on a real session: dropped, withdrawn, and the session up."""

    def setUp(self):
        self.start_engine(hold=30)
        self.s = self.speaker().connect(notify.LOOPBACK, self.listen_port)
        self.s.handshake(hold=30)
        self.wait_state(fsm_mod.ESTABLISHED)

    def _announce(self, nlri, length):
        self.s.send(raw.update(attrs=raw.origin_igp() + _long_path(length) +
                               raw.next_hop('192.0.2.5'), nlri=nlri))

    def _routes(self):
        table = self.session.adj_in.get((AFI_IP, 1)) or {}
        return set(str(k[0]) for k in list(table))

    def test_an_over_long_path_is_treated_as_withdrawn(self):
        self._announce(bytes(bytearray([16, 10, 6])), 255)
        self.wait_until(lambda: '10.6.0.0/16' in self._routes(),
                        'a 255-ASN path being accepted')
        # The same prefix with one ASN more: the earlier path must go.
        self._announce(bytes(bytearray([16, 10, 6])), 256)
        self.wait_until(lambda: '10.6.0.0/16' not in self._routes(),
                        'the 256-ASN path withdrawing the prefix')
        self.assertEqual(
            self.session.stats_counters['maxas-limit-dropped'], 1)
        # A session that keeps going, not one torn down for it.
        self._announce(bytes(bytearray([24, 10, 7, 1])), 10)
        self.wait_until(lambda: '10.7.1.0/24' in self._routes(),
                        'a later, ordinary route being learned')
        self.assertEqual(self.session.state, fsm_mod.ESTABLISHED)


# --- P-3: next-hop resolution -----------------------------------------------

class ResolverTestCase(unittest.TestCase):
    """P-3: what may vouch for a next hop."""

    def _engine(self, **route):
        cfg = {'validate-next-hop': True}
        cfg.update(route)
        engine = Engine(name='p3', config={'ip': {'route': cfg}})
        self.addCleanup(engine.stop)
        return engine

    def test_a_bgp_route_does_not_vouch_for_a_bgp_next_hop(self):
        engine = self._engine()
        engine.global_rib.offer(_route('10.0.0.0/24', protocol=T.PROTO_BGP,
                                       distance=20))
        engine.select()
        nh = _addr('10.0.0.9')
        self.assertIsNone(engine.resolver.resolve(AFI_IP, nh,
                                                  protocol=T.PROTO_BGP))
        # Another protocol may still use it.
        self.assertEqual(engine.resolver.resolve(AFI_IP, nh).source, 'rib')

    def test_a_shorter_cover_from_another_protocol_is_used_instead(self):
        engine = self._engine()
        engine.global_rib.offer(_route('10.0.0.0/24', protocol=T.PROTO_BGP,
                                       distance=20))
        engine.global_rib.offer(_route('10.0.0.0/16'))
        engine.select()
        found = engine.resolver.resolve(AFI_IP, _addr('10.0.0.9'),
                                        protocol=T.PROTO_BGP)
        self.assertEqual(found.prefix.to_str(), '10.0.0.0/16')

    def test_a_default_route_counts_only_with_resolve_via_default(self):
        engine = self._engine(static={'0.0.0.0/0': {'next-hop':
                                                    '192.0.2.1'}})
        self.assertIsNone(engine.resolver.resolve(AFI_IP, _addr('10.9.9.9')))
        self.assertFalse(engine.resolver.reachable(AFI_IP, _addr('10.9.9.9')))
        engine.configure(('ip', 'route', 'resolve-via-default'), True)
        found = engine.resolver.resolve(AFI_IP, _addr('10.9.9.9'))
        self.assertEqual(found.prefix.to_str(), '0.0.0.0/0')
        self.assertTrue(engine.resolver.stats()['resolve-via-default'])

    def test_a_default_in_the_rib_is_ignored_the_same_way(self):
        engine = self._engine()
        engine.global_rib.offer(_route('0.0.0.0/0'))
        engine.select()
        self.assertIsNone(engine.resolver.resolve(AFI_IP, _addr('10.9.9.9')))

    def test_a_learned_route_needs_its_own_next_hop_to_resolve(self):
        engine = self._engine()
        engine.global_rib.offer(_route('10.0.0.0/24', nexthop='192.0.2.1'))
        engine.select()
        nh = _addr('10.0.0.9')
        self.assertIsNone(engine.resolver.resolve(AFI_IP, nh))
        engine.configure(('ip', 'route', 'static', '192.0.2.0/24'),
                         {'next-hop': '192.0.2.254'})
        found = engine.resolver.resolve(AFI_IP, nh)
        # The first step of the chain is what is reported.
        self.assertEqual((found.source, found.prefix.to_str()),
                         ('rib', '10.0.0.0/24'))

    def test_a_route_that_resolves_through_itself_is_a_loop(self):
        engine = self._engine()
        engine.global_rib.offer(_route('10.0.0.0/24', nexthop='10.0.0.1'))
        engine.select()
        self.assertIsNone(engine.resolver.resolve(AFI_IP, _addr('10.0.0.9')))
        self.assertGreater(engine.resolver.stats()['recursion-failures'], 0)

    def _chain(self, engine, hops):
        # 10.1.0.0/24 via 10.2.0.1, 10.2.0.0/24 via 10.3.0.1, ..., and the
        # last one attached.
        for i in range(1, hops + 1):
            engine.global_rib.offer(_route('10.%d.0.0/24' % i,
                                           nexthop='10.%d.0.1' % (i + 1)))
        engine.global_rib.offer(_route('10.%d.0.0/24' % (hops + 1)))
        engine.select()

    def test_recursion_is_followed_to_max_depth(self):
        engine = self._engine()
        self._chain(engine, resolver_mod.MAX_DEPTH)
        self.assertIsNotNone(engine.resolver.resolve(AFI_IP,
                                                     _addr('10.1.0.9')))

    def test_recursion_stops_past_max_depth(self):
        engine = self._engine()
        self._chain(engine, resolver_mod.MAX_DEPTH + 1)
        self.assertIsNone(engine.resolver.resolve(AFI_IP, _addr('10.1.0.9')))

    def test_a_static_entry_still_ends_the_chain(self):
        # rtengine knows no connected routes, so a static's own next hop
        # is not resolved: it is the operator's word.
        engine = self._engine(static={'10.0.0.0/8': {'next-hop':
                                                     '198.51.100.9'}})
        self.assertEqual(engine.resolver.resolve(AFI_IP,
                                                 _addr('10.1.2.3')).source,
                         'static')

    def test_bgp_asks_as_bgp(self):
        asked = []

        class Resolver(object):
            def resolve(self, afi, addr, protocol=None):
                asked.append(protocol)
                return None

        class FakeEngine(object):
            resolver = Resolver()

        plugin = bgp_plugin.BGPPlugin()
        plugin.engine = FakeEngine()
        self.assertEqual(plugin._check_nexthop(AFI_IP, _addr('10.0.0.1')),
                         (False, 0))
        self.assertEqual(asked, [T.PROTO_BGP])


# --- P-4, P-6, P-7 ----------------------------------------------------------

class PaginationTestCase(unittest.TestCase):
    """P-4: following ``next`` returns every prefix exactly once."""

    def test_every_page_size_walks_the_whole_table(self):
        engine = Engine(name='p4')
        self.addCleanup(engine.stop)
        expected = ['192.0.2.%d/32' % i for i in range(1, 8)]
        for prefix in expected:
            engine.global_rib.offer(_route(prefix))
        engine.select()
        for limit in (1, 2, 3, 7, 8):
            seen = []
            after = None
            for _ in range(20):
                page = engine.show('ip', 'route', limit=limit,
                                   after=(parse_prefix(after)
                                          if after else None))
                seen.extend(item['prefix'] for item in page['items'])
                after = page['next']
                if after is None:
                    break
                self.assertEqual(after, seen[-1])
            self.assertEqual(seen, expected, 'limit %d' % limit)


class VersionOfTestCase(unittest.TestCase):
    """P-6: absent and defined-but-never-edited are different answers."""

    def test_absent_is_none_and_never_edited_is_a_number(self):
        store = PolicyStore()
        store.load({'ip': {'as-path-access-list': {'EMPTY': []}}})
        for kind in KINDS:
            self.assertIsNone(store.version_of(kind, 'ABSENT'))
        version = store.version_of('as-path', 'EMPTY')
        self.assertIsInstance(version, int)
        self.assertNotEqual(version, store.version_of('as-path', 'ABSENT'))


class ShadowedKernelRouteTestCase(unittest.TestCase):
    """P-7: a static shadows every kernel route it covers."""

    def test_covering_not_equal(self):
        resolver = resolver_mod.Resolver(enabled=True)
        resolver.add_static('10.0.0.0/8', '198.51.100.9')
        self.assertTrue(resolver._covered_by_static(
            parse_prefix('10.0.0.0/8')))
        self.assertTrue(resolver._covered_by_static(
            parse_prefix('10.1.0.0/16')))
        self.assertFalse(resolver._covered_by_static(
            parse_prefix('172.16.0.0/12')))
        self.assertFalse(resolver._covered_by_static(
            parse_prefix('0.0.0.0/0')))

    def test_a_static_default_shadows_only_when_it_would_be_used(self):
        resolver = resolver_mod.Resolver(enabled=True)
        resolver.add_static('0.0.0.0/0', '198.51.100.9')
        self.assertFalse(resolver._covered_by_static(
            parse_prefix('172.16.0.0/12')))
        resolver.resolve_via_default = True
        self.assertTrue(resolver._covered_by_static(
            parse_prefix('172.16.0.0/12')))


if __name__ == '__main__':
    unittest.main()
