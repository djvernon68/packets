"""S6-a..S6-c: defects the 2026-11-05 live re-test against FRR found.

All three date from ``aff61bc`` and survived the suite for one reason: each
earlier test reached one layer below the one that broke -- AS-path lists
loaded straight into a ``PolicyStore``, ``GlobalRib.as_dict`` paged with a
``Prefix``, the resolver asked directly. So every test here goes in the way
an operator does: ``Engine.configure``/``show``, the REST API, or a live
session from the raw speaker.

* **S6-a** -- ``ip.as-path-access-list`` was missing from the core schema,
  so no AS-path list could be configured and a ``filter-list`` could only
  name an absent list (which denies everything).
* **S6-b** -- ``show ip route?after=`` was a 500: the cursor reached the
  RIB as a string and was compared with a ``Prefix``.
* **S6-c** -- next hops were re-validated only after a core selection, so a
  change to a static route or to ``resolve-via-default`` left every held
  path's verdict stale until a soft clear.
* **S6-d** -- found while re-testing: the P-2 regex guard counted repeats
  but not how the cost grows, and did not know how long a path could be.
  Accepted patterns took ~1 s at the default maxas-limit and minutes with
  it raised.
"""
import json
import struct
import time
import unittest

import rtengine_rawspeaker as raw
import test_rtengine_session_notify as notify
from test_rtengine_api import ApiFixture, _flask

from packets.routing.rtengine import ConfigError
from packets.routing.rtengine.engine import Engine
from packets.routing.rtengine.plugins.bgp import fsm as fsm_mod
from packets.routing.rtengine.plugins.bgp.plugin import BGPPlugin
from packets.routing.rtengine.policy import aspath as aspath_mod
from packets.routing.rtengine.rib import resolver as resolver_mod
from packets.routing.rtengine.rib import table as T
from packets.routing.rtengine.rib.prefix import parse_prefix


def _deny_then_permit(regex):
    return [{'seq': 10, 'action': 'deny', 'regex': regex},
            {'seq': 20, 'action': 'permit', 'regex': '.*'}]


def _route(prefix, nexthop=b''):
    return T.Route(parse_prefix(prefix), T.PROTO_STATIC, 1, 0, nexthop,
                   'test')


# --- S6-a: AS-path lists through the configuration -------------------------

class AsPathListConfigTestCase(unittest.TestCase):
    """S6-a: the engine accepts what the docs and PolicyStore accept."""

    def test_engine_configure_accepts_an_as_path_list(self):
        engine = Engine(name='s6a')
        self.addCleanup(engine.stop)
        engine.configure(('ip', 'as-path-access-list', 'A'),
                         _deny_then_permit('_65010_'))
        entries = engine.show('ip', 'as-path-access-list',
                              'A')['items'][0]['entries']
        self.assertEqual([(10, 'deny'), (20, 'permit')],
                         [(e['seq'], e['action']) for e in entries])
        self.assertEqual('_65010_', entries[0]['regex'])

    def test_a_refused_regex_names_the_guard_rule(self):
        """The P-2 guard's reason reaches the operator, not 'unknown key'."""
        engine = Engine(name='s6a')
        self.addCleanup(engine.stop)
        with self.assertRaises(ConfigError) as caught:
            engine.configure(('ip', 'as-path-access-list', 'BAD'),
                             [{'action': 'deny', 'regex': '([0-9]+)+'}])
        self.assertEqual(caught.exception.path,
                         'ip.as-path-access-list.BAD.0')
        self.assertIn('repeats a group', str(caught.exception))

    def test_an_ios_idiom_is_accepted(self):
        engine = Engine(name='s6a')
        self.addCleanup(engine.stop)
        engine.configure(('ip', 'as-path-access-list', 'OK'),
                         [{'action': 'permit',
                           'regex': '^[0-9]+(_[0-9]+)*$'}])


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class AsPathListApiTestCase(ApiFixture):
    """S6-a over REST: a running-config replace carrying a list."""

    def _post(self, client, document):
        return client.post('/api/v1/running-config',
                           data=json.dumps(document),
                           content_type='application/json')

    def test_a_document_with_a_list_is_accepted_and_shown(self):
        engine, client = self.make_client(plugins=[])
        response = self._post(client, {'ip': {'as-path-access-list': {
            'A': _deny_then_permit('_65010_')}}})
        self.assertEqual(200, response.status_code, response.data)
        shown = self.body(client.get('/api/v1/show/ip/as-path-access-list'))
        self.assertEqual(['A'], [item['name'] for item in shown['items']])

    def test_a_refused_regex_is_a_400_at_its_entry(self):
        engine, client = self.make_client(plugins=[])
        doc = self.assertError(
            self._post(client, {'ip': {'as-path-access-list': {
                'BAD': [{'action': 'deny',
                         'regex': '(_[0-9]+)*(_[0-9]+)*(_[0-9]+)*X'}]}}}),
            400, 'Invalid')
        self.assertEqual('ip.as-path-access-list.BAD.0', doc['path'])
        self.assertNotIn('unknown key', doc['detail'])


class LiveFilterListTestCase(notify.LiveFixture):
    """S6-a end to end: a filter-list on a real session (and P-1 live)."""

    PREFIX = '10.8.0.0/16'

    def _run(self, regex):
        self.start_engine(hold=30, neighbor_extra={'address-family': {
            'ipv4': {'unicast': {'filter-list': {'in': 'P1'}}}}})
        self.engine.configure(('ip', 'as-path-access-list', 'P1'),
                              _deny_then_permit(regex))
        s = self.speaker().connect(notify.LOOPBACK, self.listen_port)
        s.handshake(hold=30)
        self.wait_state(fsm_mod.ESTABLISHED)
        # One route that the list judges, then a marker route sent after
        # it: once the marker has been decided, so has the first.
        s.send(raw.update(attrs=raw.origin_igp() +
                          raw.as_path(notify.SPEAKER_AS, 64800) +
                          raw.next_hop('192.0.2.5'),
                          nlri=bytes(bytearray([16, 10, 8]))))
        s.send(raw.update(attrs=raw.origin_igp() + raw.as_path(64999) +
                          raw.next_hop('192.0.2.5'),
                          nlri=bytes(bytearray([16, 10, 9]))))
        self.wait_until(lambda: self._paths('10.9.0.0/16'),
                        'the marker route being learned')
        return self._paths(self.PREFIX)

    def _paths(self, prefix):
        return len(self.engine.show('ip', 'bgp', prefix).get('paths', []))

    def test_deny_underscore_asn_drops_the_route(self):
        """P-1: ``_65005_`` matches the peer's AS and drops the route."""
        self.assertEqual(0, self._run('_%d_' % notify.SPEAKER_AS))

    def test_an_asn_that_is_a_prefix_of_another_does_not_match(self):
        """``_6500_`` is not ``65005``: the underscore is a delimiter."""
        self.assertEqual(1, self._run('_6500_'))

    def test_a_later_asn_in_the_path_matches(self):
        self.assertEqual(0, self._run('_64800_'))

    def test_an_escaped_underscore_is_literal(self):
        """``\\_65005\\_`` needs a literal ``_``, which no path has."""
        self.assertEqual(1, self._run('\\_%d\\_' % notify.SPEAKER_AS))


# --- S6-b: show ip route paging by cursor ----------------------------------

ROUTES = ['10.0.%d.0/24' % i for i in range(7)]


class RoutePagingTestCase(unittest.TestCase):
    """S6-b: ``after`` as an operator sends it -- text."""

    def setUp(self):
        self.engine = Engine(name='s6b')
        self.addCleanup(self.engine.stop)
        for prefix in ROUTES:
            self.engine.global_rib.offer(_route(prefix))
        self.engine.select()

    def _walk(self, limit):
        seen, kwargs = [], {'limit': limit}
        while True:
            page = self.engine.show('ip', 'route', **kwargs)
            seen += [item['prefix'] for item in page['items']]
            if not page['next']:
                return seen
            kwargs = {'limit': limit, 'after': page['next']}

    def test_walking_by_next_visits_every_prefix_once(self):
        for limit in (1, 2, 3, 6, 7, 8):
            self.assertEqual(ROUTES, self._walk(limit), limit)

    def test_a_bad_cursor_is_a_configuration_error(self):
        with self.assertRaises(ConfigError) as caught:
            self.engine.show('ip', 'route', after='not-a-prefix')
        self.assertEqual('after', caught.exception.path)

    def test_a_cursor_of_the_other_family_is_refused(self):
        with self.assertRaises(ConfigError):
            self.engine.show('ip', 'route', after='2001:db8::/32')


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class RoutePagingApiTestCase(ApiFixture):
    """S6-b over REST, where the 500 was."""

    def setUp(self):
        engine = self.make_engine(plugins=[], start=False)
        for prefix in ROUTES:
            engine.global_rib.offer(_route(prefix))
        engine.select()
        engine.start()
        self.engine, self.client = self.make_client(engine=engine)

    def test_walking_by_next_visits_every_prefix_once(self):
        seen, url = [], '/api/v1/show/ip/route?limit=3'
        while True:
            response = self.client.get(url)
            self.assertEqual(200, response.status_code, response.data)
            page = self.body(response)
            seen += [item['prefix'] for item in page['items']]
            if not page['next']:
                break
            url = '/api/v1/show/ip/route?limit=3&after=' + page['next']
        self.assertEqual(ROUTES, seen)

    def test_a_bad_cursor_is_a_400(self):
        doc = self.assertError(
            self.client.get('/api/v1/show/ip/route?after=nonsense'), 400,
            'Invalid')
        self.assertEqual('after', doc['path'])


# --- S6-c: re-validation when the resolver's inputs change -----------------

class ResolverGenerationTestCase(unittest.TestCase):
    """S6-c: the resolver says when its answers may have changed."""

    def test_a_real_change_moves_the_generation_and_a_no_op_does_not(self):
        resolver = resolver_mod.Resolver(enabled=True)
        start = resolver.generation
        resolver.load_static({'10.0.0.0/8': {'next-hop': '192.0.2.1'}})
        loaded = resolver.generation
        self.assertNotEqual(start, loaded)
        resolver.load_static({'10.0.0.0/8': {'next-hop': '192.0.2.1'}})
        self.assertEqual(loaded, resolver.generation)
        resolver.load_static({'10.0.0.0/8': {'next-hop': '192.0.2.2'}})
        self.assertNotEqual(loaded, resolver.generation)

    def test_each_knob_moves_the_generation_only_when_it_changes(self):
        resolver = resolver_mod.Resolver()
        for knob in ('enabled', 'resolve_via_default', 'kernel_import'):
            before = resolver.generation
            setattr(resolver, knob, False)
            self.assertEqual(before, resolver.generation, knob)
            setattr(resolver, knob, True)
            self.assertNotEqual(before, resolver.generation, knob)

    def test_add_and_remove_static_move_it(self):
        resolver = resolver_mod.Resolver()
        before = resolver.generation
        resolver.add_static('10.0.0.0/8', '192.0.2.1')
        added = resolver.generation
        self.assertNotEqual(before, added)
        resolver.remove_static('10.0.0.0/8')
        self.assertNotEqual(added, resolver.generation)


class LiveRevalidationTestCase(notify.LiveFixture):
    """S6-c on a real session: no soft clear anywhere in these tests."""

    PREFIX = '10.10.0.0/16'

    def setUp(self):
        self.start_engine(hold=30,
                          instance_extra={'next-hop-validation': True})
        s = self.speaker().connect(notify.LOOPBACK, self.listen_port)
        s.handshake(hold=30)
        self.wait_state(fsm_mod.ESTABLISHED)
        s.send(raw.update(attrs=raw.origin_igp() +
                          raw.as_path(notify.SPEAKER_AS) +
                          raw.next_hop('192.0.2.5'),
                          nlri=bytes(bytearray([16, 10, 10]))))
        self.wait_until(lambda: self._verdict() == 'unresolved',
                        'the path arriving with an unresolved next hop')
        # The first pass after start always revalidates (the marker starts
        # unset: None now, -1 before S6-c). Without this wait a change made
        # before that pass rides on it and the test passes on the defect it
        # is for -- which is what the first version of this test did.
        plugin = self.engine.plugin('bgp')
        self.wait_until(lambda: plugin._nh_marker not in (None, -1),
                        'the first pass running')

    def _verdict(self):
        paths = self.engine.show('ip', 'bgp', self.PREFIX).get('paths', [])
        return paths[0]['verdict'] if paths else None

    def test_adding_and_removing_a_static_revalidates(self):
        self.engine.configure(('ip', 'route', 'static', '192.0.2.0/24'),
                              {'next-hop': '127.0.0.1'})
        self.wait_until(lambda: self._verdict() == 'best',
                        'a covering static resolving the next hop')
        self.engine.unconfigure(('ip', 'route', 'static', '192.0.2.0/24'))
        self.wait_until(lambda: self._verdict() == 'unresolved',
                        'removing the static unresolving it again')

    def test_resolve_via_default_revalidates_both_ways(self):
        self.engine.configure(('ip', 'route', 'static', '0.0.0.0/0'),
                              {'next-hop': '127.0.0.1'})
        self.engine.configure(('ip', 'route', 'resolve-via-default'), True)
        self.wait_until(lambda: self._verdict() == 'best',
                        'the default resolving the next hop')
        # The unsafe direction: a path must not stay best on a next hop
        # that no longer resolves.
        self.engine.configure(('ip', 'route', 'resolve-via-default'), False)
        self.wait_until(lambda: self._verdict() == 'unresolved',
                        'turning resolve-via-default off unresolving it')


# --- S6-d: the regex guard bounds growth, not just repeats ------------------

#: Cubic or worse: refused whatever maxas-limit is. The first two took
#: ~0.9 s and ~0.13 s on cnp02 at 255 ASNs and over 30 s at 1000.
CUBIC = ('(_[0-9]+)*(_[0-9]+)*X', '_1_.*_1_.*_1_X', '.*_1_.*_1_.*X',
         '_65001_.*_65002_.*_65003_', '^.*_1_.*_1_.*_1_X')

#: Quadratic: accepted only while paths are at most 255 ASNs.
QUADRATIC = ('(_[0-9]+)*_65001$', '_65001_.*_65002_', '(_[0-9]+)*_1_X',
             '^[0-9]+(_[0-9]+)*(_[0-9]+)*X', '^65001_.*_65002_.*_65003_')

#: Linear: accepted at any path length.
LINEAR = ('_65001_', '^65001_', '_65001$', '^[0-9]+(_[0-9]+)*$',
          '^65001(_65001)*$', '^65000_([0-9]+_)*65001$', '^[0-9]+_.*X')


class GuardExponentTestCase(unittest.TestCase):
    """S6-d: each pattern's growth class, and where each is accepted."""

    def test_cubic_patterns_are_refused_outright(self):
        for pattern in CUBIC:
            with self.assertRaises(ValueError) as caught:
                aspath_mod.compile_pattern(pattern)
            self.assertIn('cube of the path length', str(caught.exception),
                          pattern)

    def test_quadratic_patterns_need_a_short_enough_path(self):
        for pattern in QUADRATIC:
            aspath_mod.check_length(pattern, 255)
            for longest in (256, 2000, 0):
                with self.assertRaises(ValueError) as caught:
                    aspath_mod.check_length(pattern, longest)
                self.assertIn('square of the path length',
                              str(caught.exception), (pattern, longest))

    def test_linear_patterns_pass_at_any_length(self):
        for pattern in LINEAR:
            for longest in (255, 2000, 0):
                aspath_mod.check_length(pattern, longest)


class GuardMaxasTestCase(unittest.TestCase):
    """S6-d through the engine: maxas-limit and the lists judge each other."""

    def _engine(self, maxas=None, ip=None, route_map=None):
        body = {'router-id': '10.0.0.1'}
        if maxas is not None:
            body['maxas-limit'] = maxas
        document = {'router': {'bgp': {'65001': body}}}
        if ip:
            document['ip'] = ip
        if route_map:
            document['route-map'] = route_map
        engine = Engine(name='s6d', plugins=[BGPPlugin()])
        self.addCleanup(engine.stop)
        engine.replace_config(document)
        return engine

    def _list(self, regex):
        return {'as-path-access-list': {'Q': [{'action': 'permit',
                                               'regex': regex}]}}

    def test_a_quadratic_list_is_accepted_at_the_default(self):
        self._engine(ip=self._list(QUADRATIC[0]))

    def test_a_quadratic_list_is_refused_with_a_longer_limit(self):
        for maxas in (1000, 0):
            with self.assertRaises(ConfigError) as caught:
                self._engine(maxas=maxas, ip=self._list(QUADRATIC[0]))
            self.assertEqual('ip.as-path-access-list.Q.0',
                             caught.exception.path)
            self.assertIn('maxas-limit is %s' % (maxas or '0 (no limit)'),
                          str(caught.exception))

    def test_raising_the_limit_under_a_quadratic_list_is_refused(self):
        engine = self._engine(ip=self._list(QUADRATIC[0]))
        with self.assertRaises(ConfigError):
            engine.configure(('router', 'bgp', '65001', 'maxas-limit'), 1000)
        self.assertEqual(255, engine.plugin('bgp').maxas_limit)

    def test_a_linear_list_survives_any_limit(self):
        engine = self._engine(ip=self._list(LINEAR[3]))
        engine.configure(('router', 'bgp', '65001', 'maxas-limit'), 2000)
        engine.configure(('router', 'bgp', '65001', 'maxas-limit'), 0)

    def test_an_inline_route_map_regex_is_judged_too(self):
        with self.assertRaises(ConfigError) as caught:
            self._engine(maxas=1000, route_map={'RM': [
                {'seq': 10, 'action': 'permit',
                 'match': {'as-path': QUADRATIC[1]}}]})
        self.assertEqual('route-map.RM.0.match', caught.exception.path)

    def test_without_bgp_nothing_bounds_the_path_and_nothing_is_checked(self):
        """No plugin hands AS paths to policy, so no length applies."""
        engine = Engine(name='s6d')
        self.addCleanup(engine.stop)
        engine.configure(('ip', 'as-path-access-list', 'Q'),
                         [{'action': 'permit', 'regex': QUADRATIC[0]}])


class GuardCostTestCase(unittest.TestCase):
    """S6-d: the worst accepted patterns, timed on the worst paths.

    The bounds here are loose so the test is not flaky on a slow builder;
    ``bench/aspath_guard_bench.py`` holds the cnp02 numbers.
    """

    def _worst(self, patterns, asns):
        worst = 0.0
        for count in asns:
            for asn in ('1', '4294967295'):
                path = ' '.join([asn] * count)
                for pattern in patterns:
                    regex = aspath_mod.compile_pattern(pattern)
                    started = time.monotonic()
                    regex.search(path)
                    worst = max(worst, time.monotonic() - started)
        return worst

    def test_quadratic_at_255_asns(self):
        self.assertLess(self._worst(QUADRATIC, (255,)), 0.25)

    def test_linear_at_2000_asns(self):
        self.assertLess(self._worst(LINEAR, (2000,)), 0.05)


# --- S6-e: enhanced route refresh, advertised but not implemented -----------

def _capability_codes(open_body):
    """The capability codes in an OPEN body (no header)."""
    params = open_body[10:10 + open_body[9]]
    codes = []
    i = 0
    while i + 2 <= len(params):
        ptype, plen = params[i], params[i + 1]
        if ptype == 2:
            value = params[i + 2:i + 2 + plen]
            j = 0
            while j + 2 <= len(value):
                codes.append(value[j])
                j += 2 + value[j + 1]
        i += 2 + plen
    return codes


def _route_refresh(subtype, afi=1, safi=1):
    return raw.msg(raw.ROUTE_REFRESH, struct.pack('!HBB', afi, subtype, safi))


class LiveRouteRefreshTestCase(notify.LiveFixture):
    """S6-e: what rtengine promises in its OPEN, and what a marker does.

    rtengine advertised Enhanced Route Refresh (RFC 7313) without
    implementing it: a peer's BoRR and EoRR markers were each taken as a
    fresh request, so every soft-in clear re-sent the Adj-RIB-Out twice,
    and nothing honoured EoRR's purge. Until it is implemented the
    capability is not advertised, and a marker is never a request.
    """

    def setUp(self):
        self.start_engine(hold=30, instance_extra={'address-family': {
            'ipv4': {'unicast': {'network': {'192.0.2.0/24': {}}}}}})
        self.s = self.speaker().connect(notify.LOOPBACK, self.listen_port)
        self.got = self.s.handshake(hold=30)
        self.wait_state(fsm_mod.ESTABLISHED)
        # Drain the initial advertisement and its End-of-RIB.
        self.s.read(2.0)

    def _updates_after(self, message, timeout=2.0):
        self.s.send(message)
        return [m for m in self.s.read(timeout) if m[0] == raw.UPDATE]

    def test_the_open_does_not_promise_enhanced_route_refresh(self):
        engine_open = [body for mtype, body in self.got
                       if mtype == raw.OPEN][0]
        codes = _capability_codes(engine_open)
        self.assertIn(2, codes, 'plain route refresh is still offered')
        self.assertNotIn(70, codes)

    def test_borr_and_eorr_are_markers_not_requests(self):
        self.assertEqual([], self._updates_after(_route_refresh(1)))
        self.assertEqual([], self._updates_after(_route_refresh(2)))
        self.assertEqual(0, self.session.stats_counters['refresh-in'])
        self.assertEqual(2, self.session.stats_counters['refresh-markers-in'])

    def test_a_plain_request_is_still_answered(self):
        self.assertTrue(self._updates_after(_route_refresh(0)))
        self.assertEqual(1, self.session.stats_counters['refresh-in'])


if __name__ == '__main__':
    unittest.main()
