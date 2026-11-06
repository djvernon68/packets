# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Outbound advertisement: what rtengine tells its neighbours.

Regression tests for the outbound findings of the 2.3 review (report
``packets_rtengine_review_aff61bc.md``), each named in its docstring:

* **L-4** -- an IPv6 route never carries ``::`` as its next hop: a
  configured per-family next hop, else the session's own address, else
  the IPv4-mapped form over an IPv4 session;
* **L-5** -- instance timers are the default for every neighbour that
  sets none of its own, in the OPEN and in validation;
* **B-2** -- NO_EXPORT_SUBCONFED is honoured towards external peers;
* **B-3** -- the next-hop reverse index forgets a next hop a destination
  stopped using;
* **B-4** -- ``remove-private-as`` strips only an all-private path, and
  ``all`` strips any;
* **B-5** -- ``allowas-in`` is inbound only; ``sender-loop-check`` is the
  outbound knob;
* **B-6** -- a route that could not be encoded is never recorded as
  advertised;
* **B-7** -- the decision process ranks a path without LOCAL_PREF at the
  configured default, the same value internal peers are sent;
* **B-8** -- ``advertised-to`` leaves out members still owed a replay;
* **B-9** -- ``explain()`` leaves the live flags alone, and a soft inbound
  reset keeps each path's age;
* **B-11** -- ``set as-path prepend 0`` is a configuration error;
* **W-3** -- a path longer than 255 ASNs is split into segments, not
  wrapped;
* **W-7** -- community lists are deduplicated when interned.

B-10 (MRAI and withdrawals) is in ``test_rtengine_updategroup.py`` next to
the rest of the interval's tests. Also here, the two defects found while
fixing these: a running Loc-RIB ignoring changed bestpath knobs, and a
neighbour activating a family the instance does not carry.
"""

import socket
import struct
import types
import unittest

import rtengine_rawspeaker as raw
import test_rtengine_session_notify as notify
from test_rtengine_updategroup import AF_V4, AF_V6, LOCAL_ADDR_V6, \
    LOCAL_AS, NET_A, NET_B, PEER_AS, FakePeer, attrs, dest, source_ref, \
    spec

from packets.core.inetpkt import BGP
from packets.routing.rtengine import errors as engine_errors
from packets.routing.rtengine.plugins.bgp import adjout as adjout_mod
from packets.routing.rtengine.plugins.bgp import bestpath
from packets.routing.rtengine.plugins.bgp import fsm as fsm_mod
from packets.routing.rtengine.plugins.bgp import peer as peer_mod
from packets.routing.rtengine.plugins.bgp import plugin as bgp_plugin
from packets.routing.rtengine.plugins.bgp import show as show_mod
from packets.routing.rtengine.plugins.bgp import wire
from packets.routing.rtengine.plugins.bgp.attrs import AttrSet, \
    AttrTable, SEG_AS_SEQUENCE, make_as_path, make_communities
from packets.routing.rtengine.plugins.bgp.locrib import LocRib
from packets.routing.rtengine.policy import routemap
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, \
    parse_prefix


NO_EXPORT_SUBCONFED = 0xffffff03
PRIVATE_A = 64600
PRIVATE_B = 65100
PUBLIC = 3356


def _v6(text):
    return socket.inet_pton(socket.AF_INET6, text)


def _table(**kwargs):
    """A built Adj-RIB-Out for one peer, from a test spec.

    The peer ref agrees with the spec about the session, as the plugin
    guarantees: the transform reads ``is_ebgp`` and the AS from the ref.
    """
    peer = FakePeer('192.0.2.1', peer_as=kwargs.get('peer_as', PEER_AS),
                    is_ebgp=kwargs.get('is_ebgp', True))
    return spec(**kwargs).build(peer.peer_ref)


# --- L-4: the IPv6 next hop -------------------------------------------------


def _session(address='127.0.0.1', update_source=None, local_addr=None,
             next_hop_af=None):
    cfg = peer_mod.PeerConfig(address, PEER_AS, LOCAL_AS, '10.0.0.9',
                              update_source=update_source,
                              next_hop_af=next_hop_af)
    conn = types.SimpleNamespace(local_addr=local_addr) \
        if local_addr else None
    return types.SimpleNamespace(config=cfg, conn=conn, next_hops={})


class Ipv6NextHopTestCase(unittest.TestCase):
    """L-4: precedence, and the unspecified address is never the answer."""

    def setUp(self):
        self.plugin = bgp_plugin.BGPPlugin()

    def test_ipv4_transport_falls_back_to_ipv4_mapped(self):
        """L-4: the live case; it used to be sixteen zero bytes."""
        session = _session(local_addr='127.0.0.2')
        packed = self.plugin._local_next_hop(session, AF_V6)
        self.assertEqual(packed, _v6('::ffff:127.0.0.2'))
        self.assertEqual(session.next_hops[AF_V6]['source'], 'ipv4-mapped')

    def test_a_configured_next_hop_wins(self):
        session = _session(local_addr='127.0.0.2', update_source='127.0.0.2',
                           next_hop_af={AF_V6: '2001:db8::9'})
        self.assertEqual(self.plugin._local_next_hop(session, AF_V6),
                         _v6('2001:db8::9'))
        self.assertEqual(session.next_hops[AF_V6]['source'], 'configured')

    def test_an_ipv6_transport_address_is_used_as_is(self):
        session = _session(address='2001:db8::1', local_addr='2001:db8::2')
        self.assertEqual(self.plugin._local_next_hop(session, AF_V6),
                         _v6('2001:db8::2'))
        self.assertEqual(session.next_hops[AF_V6]['source'], 'transport')

    def test_update_source_comes_before_the_transport(self):
        session = _session(update_source='10.0.0.5', local_addr='10.0.0.6')
        self.assertEqual(self.plugin._local_next_hop(session, AF_V4),
                         socket.inet_aton('10.0.0.5'))

    def test_the_mapped_fallback_warns_once_per_neighbour(self):
        session = _session(local_addr='127.0.0.2')
        with self.assertLogs(bgp_plugin.LOG, 'WARNING') as logged:
            self.plugin._local_next_hop(session, AF_V6)
            self.plugin._local_next_hop(session, AF_V6)
        self.assertEqual(len(logged.records), 1)

    def test_the_adj_rib_out_refuses_an_unspecified_next_hop(self):
        """L-4: a family with no usable next hop advertises nothing."""
        with self.assertRaises(ValueError):
            _table(afi=AFI_IP6, local_addr=b'\x00' * 16)
        with self.assertRaises(ValueError):
            _table(local_addr=b'\x00' * 4)

    def test_the_encoder_refuses_to_emit_the_unspecified_address(self):
        """L-4: the encoder's last-line assert."""
        a = AttrSet(origin=0, as_path=make_as_path([PEER_AS]),
                    nexthop=b'\x00' * 16)
        with self.assertRaises(ValueError):
            wire.encode_announce([parse_prefix('2001:db8:1::/48')], a,
                                 AFI_IP6, 1)

    def test_an_internal_peer_never_gets_a_local_network_as_zero(self):
        """L-4: a `network` route's 0.0.0.0/:: is rewritten for iBGP too."""
        table = _table(is_ebgp=False, peer_as=LOCAL_AS, afi=AFI_IP6,
                       local_addr=LOCAL_ADDR_V6)
        local = attrs(as_path=(), nexthop=b'\x00' * 16)
        d = bestpath.BgpDest(parse_prefix('2001:db8:100::/48'))
        d.add(bestpath.BgpPath(local, source_ref(is_ebgp=False),
                               source=bestpath.SRC_LOCAL, recv_time=1.0))
        d.reselect(bestpath.BestpathConfig(local_as=LOCAL_AS))
        table.announce(d)
        self.assertEqual(table.encode_pending() and
                         table.advertised(d.prefix).nexthop, LOCAL_ADDR_V6)

    def test_a_link_local_or_wrong_family_next_hop_is_rejected(self):
        for value in ('fe80::1', '10.0.0.1', '::'):
            with self.assertRaises(engine_errors.ConfigError):
                bgp_plugin._check_next_hop(value, AF_V6, 'x')
        bgp_plugin._check_next_hop('2001:db8::1', AF_V6, 'x')


# --- L-5: timer inheritance -------------------------------------------------


class TimerInheritanceTestCase(unittest.TestCase):
    """L-5: neighbour > instance > built-in."""

    INSTANCE = {'timers': {'hold-time': 30, 'keepalive': 10}}

    def test_a_silent_neighbour_takes_the_instance_timers(self):
        self.assertEqual(bgp_plugin.resolve_timers(self.INSTANCE, {})[:2],
                         (30, 10))

    def test_a_neighbour_hold_time_wins_and_derives_its_keepalive(self):
        # The instance keepalive was chosen for a 30 s hold; it must not be
        # paired with the neighbour's 20.
        nbr = {'timers': {'hold-time': 20}}
        self.assertEqual(bgp_plugin.resolve_timers(self.INSTANCE, nbr)[:2],
                         (20, None))

    def test_a_neighbour_keepalive_alone_keeps_the_instance_hold(self):
        nbr = {'timers': {'keepalive': 5}}
        self.assertEqual(bgp_plugin.resolve_timers(self.INSTANCE, nbr)[:2],
                         (30, 5))

    def test_nothing_configured_is_the_built_in_default(self):
        self.assertEqual(bgp_plugin.resolve_timers({}, {})[:2], (90, None))

    def test_the_peer_config_carries_the_inherited_values(self):
        plugin = bgp_plugin.BGPPlugin()
        plugin.config = self.INSTANCE
        cfg = plugin._peer_config('192.0.2.1', {'remote-as': PEER_AS})
        self.assertEqual((cfg.hold_time, cfg.keepalive), (30, 10))

    def test_validation_sees_the_inherited_pair(self):
        """L-5: an instance keepalive above a neighbour-free hold fails."""
        plugin = bgp_plugin.BGPPlugin()
        section = {'65000': {'router-id': '10.0.0.1',
                             'timers': {'hold-time': 9, 'keepalive': 10},
                             'neighbor': {'192.0.2.1':
                                          {'remote-as': PEER_AS}}}}
        with self.assertRaises(engine_errors.ConfigError):
            plugin.prepare_config(section, None)


# --- B-2, B-4, B-5, B-6: the transform --------------------------------------


class SuppressionTestCase(unittest.TestCase):

    def test_no_export_subconfed_is_not_sent_to_an_external_peer(self):
        """B-2."""
        table = _table()
        d = dest(NET_A, attrs(communities=(NO_EXPORT_SUBCONFED,)))
        self.assertFalse(table.announce(d))
        self.assertEqual(
            table.stats()['suppressed'][adjout_mod.SUPPRESS_NO_EXPORT_SUBCONFED],
            1)

    def test_no_export_subconfed_still_goes_to_an_internal_peer(self):
        """B-2: inside the AS it is an ordinary route."""
        table = _table(is_ebgp=False, peer_as=LOCAL_AS)
        d = dest(NET_A, attrs(communities=(NO_EXPORT_SUBCONFED,)),
                 contributor=source_ref(is_ebgp=True))
        self.assertTrue(table.announce(d))


class RemovePrivateAsTestCase(unittest.TestCase):
    """B-4: IOS's plain form and `all`."""

    def _sent_path(self, mode, path):
        table = _table(remove_private_as=mode)
        table.announce(dest(NET_A, attrs(as_path=path)))
        table.encode_pending()
        return table.advertised(parse_prefix(NET_A)).as_path_list()

    def test_a_mixed_path_is_left_alone_by_the_plain_form(self):
        self.assertEqual(
            self._sent_path(True, (PUBLIC, PRIVATE_A)),
            [(SEG_AS_SEQUENCE, [LOCAL_AS, PUBLIC, PRIVATE_A])])

    def test_an_all_private_path_is_stripped_by_the_plain_form(self):
        self.assertEqual(self._sent_path(True, (PRIVATE_A, PRIVATE_B)),
                         [(SEG_AS_SEQUENCE, [LOCAL_AS])])

    def test_all_strips_a_mixed_path(self):
        self.assertEqual(
            self._sent_path('all', (PUBLIC, PRIVATE_A)),
            [(SEG_AS_SEQUENCE, [LOCAL_AS, PUBLIC])])

    def test_the_configuration_accepts_only_true_false_or_all(self):
        plugin = bgp_plugin.BGPPlugin()
        for value, ok in ((True, True), (False, True), ('all', True),
                          ('some', False), (2, True), (7, False)):
            section = {'65000': {'router-id': '10.0.0.1', 'neighbor': {
                '192.0.2.1': {'remote-as': PEER_AS,
                              'remove-private-as': value}}}}
            if ok:
                plugin.prepare_config(section, None)
            else:
                with self.assertRaises(engine_errors.ConfigError):
                    plugin.prepare_config(section, None)


class SenderLoopCheckTestCase(unittest.TestCase):
    """B-5: the outbound loop check has its own knob."""

    def test_a_path_with_the_peers_as_is_suppressed_by_default(self):
        table = _table()
        self.assertFalse(table.announce(dest(NET_A,
                                             attrs(as_path=(PEER_AS,)))))

    def test_turning_it_off_sends_the_path(self):
        table = _table(sender_loop_check=False)
        self.assertTrue(table.announce(dest(NET_A,
                                            attrs(as_path=(PEER_AS,)))))

    def test_allowas_in_no_longer_touches_the_outbound_spec(self):
        plugin = bgp_plugin.BGPPlugin()
        cfg = plugin._peer_config('192.0.2.1', {'remote-as': PEER_AS,
                                                'allowas-in': 3})
        self.assertTrue(cfg.sender_loop_check)
        self.assertIsNone(spec(sender_loop_check=cfg.sender_loop_check)
                          .unique)


class EncodeCommitTestCase(unittest.TestCase):
    """B-6: the record holds only what was actually encoded."""

    def _huge(self):
        # Large communities past what a 4096-byte UPDATE can carry.
        return AttrSet(origin=0, as_path=make_as_path([65002]),
                       nexthop=b'\x0a\x00\x00\xfe',
                       large_communities=b''.join(
                           struct.pack('>III', 65002, i, i)
                           for i in range(400)))

    def test_an_unencodable_route_is_not_recorded_and_is_counted(self):
        table = _table()
        table.announce(dest(NET_A, self._huge()))
        table.announce(dest(NET_B))
        messages = table.encode_pending()
        self.assertEqual(len(messages), 1)
        self.assertIsNone(table.advertised(parse_prefix(NET_A)))
        self.assertIsNotNone(table.advertised(parse_prefix(NET_B)))
        self.assertEqual(
            table.stats()['suppressed'][adjout_mod.SUPPRESS_ENCODE], 1)

    def test_an_older_version_the_peer_holds_is_withdrawn(self):
        table = _table()
        table.announce(dest(NET_A))
        table.encode_pending()
        table.announce(dest(NET_A, self._huge()))
        messages = table.encode_pending()
        decoded = wire.decode_update(messages[0], wire.DecodeCtx())
        self.assertEqual([p for p, _ in decoded.withdrawn],
                         [parse_prefix(NET_A)])
        self.assertIsNone(table.advertised(parse_prefix(NET_A)))


# --- B-3, B-7, B-9 and the bestpath-knob defect: the Loc-RIB ---------------


def _locrib(default_local_pref=100):
    cfg = bestpath.BestpathConfig(local_as=LOCAL_AS,
                                  default_local_pref=default_local_pref)
    return LocRib(AFI_IP, 1, AttrTable(), cfg)


class NextHopIndexTestCase(unittest.TestCase):
    """B-3: the reverse index does not grow under next-hop churn."""

    def test_a_destination_that_changes_next_hop_leaves_the_old_one(self):
        rib = _locrib()
        ref = source_ref()
        prefix = parse_prefix(NET_A)
        for i in range(1, 51):
            rib.add_path(ref, prefix,
                         attrs(nexthop=bytes(bytearray([10, 0, 0, i]))))
        self.assertEqual(rib.nexthop_index_size(), (1, 1))

    def test_a_withdrawn_path_leaves_the_index(self):
        rib = _locrib()
        ref = source_ref()
        rib.add_path(ref, parse_prefix(NET_A), attrs())
        rib.remove_path(ref, parse_prefix(NET_A))
        self.assertEqual(rib.nexthop_index_size(), (0, 0))

    def test_a_next_hop_another_path_still_uses_stays(self):
        rib = _locrib()
        prefix = parse_prefix(NET_A)
        first, second = source_ref('10.0.0.7'), source_ref('10.0.0.8')
        rib.add_path(first, prefix, attrs())
        rib.add_path(second, prefix, attrs())
        rib.add_path(first, prefix, attrs(nexthop=b'\x0a\x00\x00\x01'))
        self.assertEqual(rib.nexthop_index_size(), (2, 2))


class DefaultLocalPrefTestCase(unittest.TestCase):
    """B-7: one default, for ranking and for advertising."""

    def _winner(self, default):
        cfg = bestpath.BestpathConfig(local_as=LOCAL_AS,
                                      default_local_pref=default)
        d = bestpath.BgpDest(parse_prefix(NET_A))
        external = bestpath.BgpPath(attrs(), source_ref('10.0.0.7'),
                                    recv_time=1.0)
        internal = bestpath.BgpPath(
            attrs(local_pref=150),
            source_ref('10.0.0.8', peer_as=LOCAL_AS, is_ebgp=False),
            recv_time=1.0)
        d.add(external)
        d.add(internal)
        d.reselect(cfg)
        return 'external' if d.best is external else 'internal'

    def test_the_configured_default_ranks_a_path_without_local_pref(self):
        self.assertEqual(self._winner(100), 'internal')
        self.assertEqual(self._winner(200), 'external')

    def test_the_plugin_hands_the_same_value_to_both_sides(self):
        plugin = bgp_plugin.BGPPlugin()
        plugin.commit_config({'65000': {'router-id': '10.0.0.1',
                                        'default-local-preference': 250}},
                             None)
        self.assertEqual(plugin.bestpath_config[AF_V4].default_local_pref,
                         250)
        self.assertEqual(plugin.default_local_pref, 250)

    def test_a_changed_knob_reaches_a_running_loc_rib(self):
        """Found with B-7: a running Loc-RIB kept its first config."""
        plugin = bgp_plugin.BGPPlugin()
        plugin.commit_config({'65000': {'router-id': '10.0.0.1'}}, None)
        rib = plugin.locribs[AF_V4]
        rib.add_path(source_ref(), parse_prefix(NET_A), attrs())
        rib.reselect(100)
        plugin.commit_config({'65000': {'router-id': '10.0.0.1',
                                        'default-local-preference': 300}},
                             None)
        self.assertIs(rib.config, plugin.bestpath_config[AF_V4])
        self.assertEqual(rib.pending(), 1)


class ExplainAndAgeTestCase(unittest.TestCase):
    """B-9."""

    def test_explain_leaves_the_live_flags_alone(self):
        cfg = bestpath.BestpathConfig(local_as=LOCAL_AS)
        d = bestpath.BgpDest(parse_prefix(NET_A))
        old = bestpath.BgpPath(attrs(), source_ref('10.0.0.7'),
                               recv_time=1.0)
        new = bestpath.BgpPath(attrs(), source_ref('10.0.0.8'),
                               recv_time=2.0)
        d.add(old)
        d.add(new)
        d.reselect(cfg)
        self.assertTrue(old.best)
        # Pretend the table is mid-update: flags not what select would say.
        old.best, new.best = False, True
        bestpath.explain(d.paths, cfg)
        self.assertEqual((old.best, new.best), (False, True))

    def test_a_soft_inbound_reset_keeps_each_paths_age(self):
        now = [100.0]
        rib = _locrib()
        cfg = peer_mod.PeerConfig('10.0.0.7', PEER_AS, LOCAL_AS, '10.0.0.9')
        peer = peer_mod.Peer(cfg, locribs={AF_V4: rib},
                             attr_table=rib.attr_table,
                             clock=lambda: now[0])
        peer.peer_ref = source_ref('10.0.0.7')
        prefix = parse_prefix(NET_A)
        peer.adj_in[AF_V4] = {(prefix, 0): attrs()}
        peer._to_locrib(AF_V4, rib, prefix, 0, attrs(), now[0])
        now[0] = 500.0
        self.assertEqual(peer.soft_reset_in(AF_V4), 1)
        self.assertEqual(rib.get(prefix).paths[0].recv_time, 100.0)


class AdvertisedToTestCase(unittest.TestCase):
    """B-8: a member owed its replay has not been told yet."""

    def test_catch_up_members_are_left_out(self):
        plugin = bgp_plugin.BGPPlugin()
        first, second = FakePeer('192.0.2.1'), FakePeer('192.0.2.2')
        plugin.groups.join(first, spec())
        group = plugin.groups.group_of('192.0.2.1', AF_V4)
        group.announce(dest(NET_A))
        group.flush()
        plugin.groups.join(second, spec())
        self.assertEqual(group.catchup(), ['192.0.2.2'])
        prefix = parse_prefix(NET_A)
        self.assertEqual(show_mod._advertised_to(plugin, AF_V4, prefix),
                         ['192.0.2.1'])
        group.replay(second)
        self.assertEqual(show_mod._advertised_to(plugin, AF_V4, prefix),
                         ['192.0.2.1', '192.0.2.2'])


# --- B-11, W-3, W-7 ---------------------------------------------------------


class PrependZeroTestCase(unittest.TestCase):

    def test_prepend_zero_is_rejected(self):
        """B-11: it used to mean the local AS."""
        for value in ([0], '0', [65001, 0]):
            with self.assertRaises(ValueError):
                routemap._parse_prepend({'prepend': value})
        self.assertEqual(routemap._parse_prepend({'prepend': [65001]}),
                         (65001,))


class LongAsPathTestCase(unittest.TestCase):
    """W-3: 300 ASNs are two segments on the wire, not a wrapped count."""

    def test_a_300_asn_path_round_trips_and_dissects(self):
        path = list(range(64512, 64512 + 300))
        a = AttrSet(origin=0, as_path=make_as_path(path),
                    nexthop=b'\x0a\x00\x00\x01')
        raw_msg = wire.encode_announce([parse_prefix(NET_A)], a, AFI_IP, 1)[0]
        self.assertFalse(BGP(raw_msg).malformed)
        decoded = wire.decode_update(raw_msg, wire.DecodeCtx())
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.as_path_len, 300)

    def test_a_two_octet_session_splits_the_downgraded_path_too(self):
        path = list(range(1, 301))
        a = AttrSet(origin=0, as_path=make_as_path(path),
                    nexthop=b'\x0a\x00\x00\x01')
        raw_msg = wire.encode_announce([parse_prefix(NET_A)], a, AFI_IP, 1,
                                       as4=False)[0]
        decoded = wire.decode_update(raw_msg, wire.DecodeCtx(as4=False))
        self.assertEqual(decoded.errors, [])
        self.assertEqual(decoded.attrs.as_path_len, 300)


class CommunityDedupeTestCase(unittest.TestCase):
    """W-7."""

    def test_a_repeated_community_interns_with_the_plain_list(self):
        twice = b'\x00\x01\x00\x02' * 2 + b'\x00\x01\x00\x01'
        once = make_communities([0x10001, 0x10002])
        table = AttrTable()
        a = table.intern(AttrSet(communities=twice))
        b = table.intern(AttrSet(communities=once))
        self.assertIs(a, b)
        self.assertEqual(a.communities, once)


# --- found while fixing: neighbour families ---------------------------------


class NeighbourFamilyTestCase(unittest.TestCase):

    def _section(self, instance_af):
        body = {'router-id': '10.0.0.1', 'neighbor': {
            '192.0.2.1': {'remote-as': PEER_AS, 'address-family': {
                'ipv6': {'unicast': {'activate': True}}}}}}
        if instance_af:
            body['address-family'] = {'ipv6': {'unicast': {}}}
        return {'65000': body}

    def test_activating_a_family_the_instance_lacks_is_an_error(self):
        with self.assertRaises(engine_errors.ConfigError):
            bgp_plugin.BGPPlugin().prepare_config(self._section(False), None)

    def test_it_is_accepted_once_the_instance_carries_it(self):
        bgp_plugin.BGPPlugin().prepare_config(self._section(True), None)


# --- live, against an engine ------------------------------------------------


def _mp_reach_next_hops(messages):
    """Pull the MP_REACH next hop out of every UPDATE that has one."""
    out = []
    for mtype, body in messages:
        if mtype != raw.UPDATE:
            continue
        wlen = struct.unpack('>H', body[0:2])[0]
        off = 2 + wlen
        alen = struct.unpack('>H', body[off:off + 2])[0]
        off += 2
        end = off + alen
        while off < end:
            flags, atype = bytearray(body[off:off + 2])
            if flags & 0x10:
                vlen = struct.unpack('>H', body[off + 2:off + 4])[0]
                value = body[off + 4:off + 4 + vlen]
                off += 4 + vlen
            else:
                vlen = bytearray(body[off + 2:off + 3])[0]
                value = body[off + 3:off + 3 + vlen]
                off += 3 + vlen
            if atype == 14:
                nhlen = bytearray(value[3:4])[0]
                out.append(bytes(value[4:4 + nhlen]))
    return out


class LiveOutboundTestCase(notify.LiveFixture):
    """The cnp02 observations, against an in-process engine."""

    def _start(self, next_hop=None, timers=None):
        families = {'ipv4': {'unicast': {'activate': True}},
                    'ipv6': {'unicast': {'activate': True}}}
        if next_hop:
            families['ipv6']['unicast']['next-hop'] = next_hop
        instance = {
            'timers': {'hold-time': 30, 'keepalive': 10},
            'address-family': {
                'ipv4': {'unicast': {'network': {'203.0.113.0/24': {}}}},
                'ipv6': {'unicast': {'network': {
                    '2001:db8:100::/48': {}}}}}}
        self.start_engine(
            neighbor_extra={'address-family': families,
                            'timers': timers or {'connect-retry': 1}},
            instance_extra=instance)
        s = self.speaker().connect(notify.LOOPBACK, self.listen_port)
        got = s.handshake(hold=90)
        self.wait_state(fsm_mod.ESTABLISHED)
        return s, got

    def test_the_open_carries_the_instance_hold_time(self):
        """L-5: the live case; the OPEN used to say 90."""
        _s, got = self._start()
        body = [b for t, b in got if t == raw.OPEN][0]
        self.assertEqual(struct.unpack('>H', body[3:5])[0], 30)

    def test_a_neighbour_hold_time_still_overrides(self):
        _s, got = self._start(timers={'hold-time': 45, 'connect-retry': 1})
        body = [b for t, b in got if t == raw.OPEN][0]
        self.assertEqual(struct.unpack('>H', body[3:5])[0], 45)

    def test_ipv6_over_ipv4_is_never_the_unspecified_address(self):
        """L-4: the live case; ExaBGP used to show `next-hop ::`."""
        s, _got = self._start()
        hops = _mp_reach_next_hops(s.read(3.0))
        self.assertTrue(hops, 'no IPv6 UPDATE arrived')
        for nh in hops:
            self.assertNotEqual(nh, b'\x00' * 16)
            self.assertEqual(nh, _v6('::ffff:127.0.0.1'))

    def test_a_configured_ipv6_next_hop_is_what_is_sent(self):
        """L-4: the per-family `next-hop` key."""
        s, _got = self._start(next_hop='2001:db8::9')
        hops = _mp_reach_next_hops(s.read(3.0))
        self.assertTrue(hops, 'no IPv6 UPDATE arrived')
        self.assertEqual(set(hops), set([_v6('2001:db8::9')]))
        shown = self.session.as_dict()['next-hops']['IPv6 Unicast']
        self.assertEqual(shown, {'address': '2001:db8::9',
                                 'source': 'configured'})


if __name__ == '__main__':
    unittest.main()
