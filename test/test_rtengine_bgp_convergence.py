#!/usr/bin/env python

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Stage 3 acceptance: two routing engines peering over loopback.

Everything below this line runs real sockets. ``test_rtengine_wire.py``,
``test_rtengine_fsm.py`` and friends test the pieces in isolation with
injected clocks and synthetic byte strings; this module is the only place
where two complete engines are stood up, told about each other, and left
to converge over TCP. It discharges acceptance criterion 1 -- "two engines
peer over loopback (IPv4 and IPv6 transport), negotiate capabilities,
originate ``network``s, advertise them per peer, and received
IPv4/IPv6-unicast routes land in the BGP Loc-RIB and the ``GlobalRib``" --
and is organised as one class per claim:

  * :class:`Ipv4SessionTestCase` -- the session comes up and says so in
    both ``health()`` and ``show ip bgp summary``, and the two ends agree
    on the families, four-octet AS and route refresh.
  * :class:`Ipv4ConvergenceTestCase` -- each side's ``network`` reaches
    the other side's Loc-RIB with a one-hop AS_PATH and a usable next
    hop, and reaches its ``GlobalRib`` at the eBGP distance. Withdrawal
    and session teardown take it back out of both, and the interned
    attribute table returns to where it started.
  * :class:`Ipv6ConvergenceTestCase` -- the same over an IPv6 transport,
    with MP_REACH carrying the prefixes. Skipped, not failed, where the
    IPv6 loopback is not up.
  * :class:`FourOctetAsTestCase` -- a session with an AS above 65535 puts
    the real ASN in the AS_PATH the peer receives, not AS_TRANS.
  * :class:`ShowAndClearTestCase` -- the operational surface answers with
    JSON-serialisable dicts while the session is up, and a soft clear
    refreshes without bouncing it.
  * :class:`AuthenticationTestCase` -- the fail-closed policy. MD5 needs a
    kernel that has it and skips elsewhere; TCP-AO's rejection is asserted
    on every platform, because a peer that comes up unauthenticated when
    the operator asked for AO is the worst outcome in the stage.
  * :class:`RegressionTestCase` -- the four integration defects this
    file found when it was written, each reduced to its smallest
    reproducer. All four are fixed in the modules under test now, and
    these tests pin the fixes: none of them could pass before, and each
    one guards a seam that only appears when two whole engines run.

Three decisions worth knowing before reading the fixtures:

**Both speakers live on 127.0.0.1 and are told apart by port.** On macOS
``127.0.0.2`` is not configured on lo0 by default, so a test that needed
it would skip on every developer machine and only run in CI. Two speakers
on one address is not a configuration anybody would deploy, but nothing
under test distinguishes peers by address except the neighbour table, and
each engine here has exactly one neighbour. Ports come from the ephemeral
range at run time rather than being fixed constants, so a rerun never
collides with the previous run's lingering sockets, and port 179 -- which
needs root -- is never involved.

**Timers are short and waits are long.** ``hold-time 3``, ``keepalive 1``
and ``connect-retry 1`` are the fastest RFC 4271 allows (hold time is 0 or
at least 3), which keeps a session's establishment inside a second; every
wait is then a poll with a generous ceiling and a message naming what
never happened, because a test that fails on a loaded machine is testing
the machine.

**Advertisement is driven, not awaited.** ``BGPPlugin.run_pass()`` exists
so a test can make selection and advertisement happen at a known moment
instead of waiting out the 0.5 second interval, and
:meth:`PeeringFixture.converge` drives it on both engines in a loop until
the caller's predicate holds. Core selection is *not* driven at all:
``run_pass`` asks the core for a selection pass itself, through
``Engine.schedule_select()``, so a route offered to the ``GlobalRib``
reaches ``show ip route`` on its own and nothing in this file calls
``Engine.select()``. ``test_convergence_needs_no_help_from_the_test``
drops even ``run_pass`` and asserts the wholly unaided path, which is
what the last of the four regressions below is about.
"""

import json
import socket
import time
import unittest

# Deliberately no pytest import. The 3.6.8 verification host runs this
# suite with `python3 -m unittest discover -s test` and has no pytest
# installed, so importing it here fails collection of the whole module on
# the one platform where the MD5 and GTSM paths below can actually
# execute -- which is the opposite of what these tests are for.
# unittest.skipUnless does the same job in both runners.

from packets.routing.rtengine import ConfigError, Engine
from packets.routing.rtengine.plugins.bgp import capabilities
from packets.routing.rtengine.plugins.bgp import plugin as bgp_plugin
from packets.routing.rtengine.transport import auth as auth_mod

#: The loopback address both speakers bind and dial. See the module
#: docstring: one address, two ports, because 127.0.0.2 is not up on macOS.
V4_LOOPBACK = '127.0.0.1'
V6_LOOPBACK = '::1'

#: RFC 5737 and RFC 3849 documentation prefixes, so nothing here could ever
#: be confused with a real advertisement if it escaped a test machine.
#: ``NET_C_V4`` is the third documentation range, used where a test needs
#: one prefix policy denies and another it permits -- "nothing arrived"
#: and "the right thing was withheld" are different outcomes and a single
#: prefix cannot tell them apart.
NET_A_V4 = '192.0.2.0/24'
NET_C_V4 = '203.0.113.0/24'
NET_B_V4 = '198.51.100.0/24'
NET_A_V6 = '2001:db8:1::/48'
NET_B_V6 = '2001:db8:2::/48'

AS_A = 65010
AS_B = 65020
#: Above 65535, so the session has to carry it in AS4_PATH-capable OPENs
#: rather than substituting AS_TRANS (23456).
AS_FOUR_OCTET = 4200000001
AS_TRANS = 23456

IPV4_UNICAST = (1, 1)
IPV6_UNICAST = (2, 1)

#: The eBGP administrative distance the Loc-RIB offers routes at.
DISTANCE_EBGP = 20


def _free_port(host, family):
    """Return a port nothing is listening on, by asking the kernel.

    Fixed port numbers make a test fail for the previous run's reasons.
    There is a race between closing this socket and the engine binding
    the port, but it is a race against other processes on a test machine
    rather than against anything in this file.

    :param host: the address the port has to be free on.
    :param family: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :return: a free port number.
    """
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind((host, 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _ipv6_loopback_up():
    """Report whether ``::1`` can be bound on this host.

    IPv6 can be compiled in, configured out, and disabled by policy, and
    the only answer that means anything is whether a bind succeeds.

    :return: True if an IPv6 loopback listener is possible.
    """
    if not socket.has_ipv6:
        return False
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        sock.bind((V6_LOOPBACK, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


HAVE_IPV6 = _ipv6_loopback_up()
HAVE_MD5 = auth_mod.md5_supported()
HAVE_AO = auth_mod.ao_supported()


def _instance(asn, router_id, address, port, family, networks,
              neighbors=None):
    """Build a complete one-instance ``router bgp`` document.

    The AS is a string key, and the address families nest as
    ``address-family.<afi>.<safi>``.

    :param asn: the local AS, used as the instance key.
    :param router_id: dotted quad; distinct per speaker so OPEN collision
        resolution has something to compare.
    :param address: the address to listen on.
    :param port: the port to listen on.
    :param family: ``'ipv4'`` or ``'ipv6'``.
    :param networks: prefixes to originate.
    :param neighbors: address to neighbour subtree, or None for a
        document that configures no peerings.
    :return: a configuration document.
    """
    instance = {
        'router-id': router_id,
        'listen': {'address': address, 'port': port},
        'address-family': {
            family: {'unicast': {
                'network': dict((net, {}) for net in networks)}},
        },
    }
    if neighbors:
        instance['neighbor'] = dict(neighbors)
    return {'router': {'bgp': {str(asn): instance}}}


def _neighbor(remote_as, port, update_source, **extra):
    """Build one ``neighbor`` subtree with the fast timers.

    :param remote_as: the peer's AS.
    :param port: the peer's listening port, never 179.
    :param update_source: the local address, which also becomes the next
        hop advertised to this peer.
    :param extra: merged in, for ``password``, ``ao``, ``shutdown``.
    :return: a neighbour dict.
    """
    nbr = {
        'remote-as': remote_as,
        'port': port,
        'update-source': update_source,
        'timers': {'hold-time': 3, 'keepalive': 1, 'connect-retry': 1},
    }
    nbr.update(extra)
    return nbr


class Speaker(object):
    """One engine, plus the handful of facts a test needs to address it.

    Exists so a test reads ``left.prefix_in_locrib(NET_B_V4)`` rather than
    unpacking a tuple of engine, address and port at every call site.
    """

    def __init__(self, engine, asn, address, port, family):
        self.engine = engine
        self.asn = asn
        self.address = address
        self.port = port
        self.family = family

    @property
    def plugin(self):
        """The BGP plugin instance this engine is running."""
        return self.engine.plugin('bgp')

    @property
    def show_root(self):
        """``'ip'`` or ``'ipv6'``, whichever this speaker's shows use."""
        return 'ip' if self.family == 'ipv4' else 'ipv6'

    @property
    def af(self):
        """The ``(afi, safi)`` tuple this speaker carries."""
        return IPV4_UNICAST if self.family == 'ipv4' else IPV6_UNICAST

    def session(self, address=V4_LOOPBACK):
        """Return the one peer session, by neighbour address."""
        return self.plugin.peers.get(address)

    def established(self):
        """Whether every configured neighbour is up."""
        health = self.plugin.health()
        return (health['neighbors'] > 0 and
                health['established'] == health['neighbors'])

    def locrib_row(self, prefix):
        """Return the ``show ... bgp`` row for a prefix, or None.

        Reads through the show handler rather than the Loc-RIB object, so
        the assertion covers the operational surface an operator would
        use to answer the same question.
        """
        table = self.engine.show(self.show_root, 'bgp')
        for row in table['routes']:
            if row['prefix'] == prefix:
                return row
        return None

    def core_route(self, prefix):
        """Return the ``GlobalRib`` entry for a prefix, or None."""
        found = self.engine.show(self.show_root, 'route', prefix)
        if not found.get('found'):
            return None
        return found['best']

    def attr_count(self):
        """How many distinct attribute sets the intern table holds."""
        return self.plugin.attr_table.stats()['distinct']

    def run_pass(self):
        """Drive one selection-and-advertisement pass on the loop thread.

        Nothing else happens in the call: the pass asks the core for a
        selection of its own, so a route offered here reaches the
        ``GlobalRib`` without this file helping.
        """
        return self.engine.submit(self.plugin.run_pass).result(10)


class PeeringFixture(unittest.TestCase):
    """Stands speakers up, and guarantees they come down.

    Modelled on ``EngineFixture`` in ``test_rtengine_engine.py`` and for
    the same reason: a leaked engine thread outlives the test that made
    it, keeps its listening socket, and fails later tests for reasons
    that have nothing to do with them. Everything here registers its
    cleanup before returning the object, so a test that fails halfway
    through construction still tears down what it built.
    """

    def make_engine(self, name):
        """Construct an engine with a BGP plugin and register teardown.

        ``stop()`` on an engine that never started is a no-op, so the
        cleanup is registered unconditionally.
        """
        engine = Engine(name=name, plugins=[bgp_plugin.BGPPlugin()])
        self.addCleanup(engine.stop)
        return engine

    def speaker(self, name, asn, router_id, port, family='ipv4',
                networks=(), neighbors=None):
        """Commit one speaker's whole configuration, then start it.

        Configure and then start, which is how an engine loads a file at
        boot and the only order an operator would call natural. It was
        not usable when this file was written -- a neighbour built before
        the engine ran never got an event loop and never dialled -- so
        the fixture used to split the document either side of
        ``start()``. :class:`RegressionTestCase` pins both halves of the
        fix, and the split is gone.

        :param neighbors: address to neighbour subtree, committed with
            the rest. Peerings can also be added after start, which
            :meth:`add_neighbor` does.
        :return: a started :class:`Speaker`.
        """
        address = V4_LOOPBACK if family == 'ipv4' else V6_LOOPBACK
        engine = self.make_engine(name)
        engine.replace_config(_instance(asn, router_id, address, port,
                                        family, networks, neighbors))
        engine.start()
        return Speaker(engine, asn, address, port, family)

    def pair(self, name_a, name_b, asn_a=AS_A, asn_b=AS_B,
             networks_a=(NET_A_V4,), networks_b=(NET_B_V4,),
             family='ipv4', **extra):
        """Two speakers that know about each other before either runs.

        The ports are taken from the kernel first so each document can
        name the other's, and then each engine is handed one complete
        configuration and started. Whichever comes up first spends a
        connect-retry or two dialling a port nothing is listening on yet,
        which is exactly what happens when two routers boot together.

        :param extra: merged into both neighbour blocks.
        :return: ``(left, right)``, both Established.
        """
        address = V4_LOOPBACK if family == 'ipv4' else V6_LOOPBACK
        sock_family = (socket.AF_INET if family == 'ipv4'
                       else socket.AF_INET6)
        port_a = _free_port(address, sock_family)
        port_b = _free_port(address, sock_family)
        left = self.speaker(
            name_a, asn_a, '10.0.0.1', port_a, family, networks_a,
            {address: _neighbor(asn_b, port_b, address, **extra)})
        right = self.speaker(
            name_b, asn_b, '10.0.0.2', port_b, family, networks_b,
            {address: _neighbor(asn_a, port_a, address, **extra)})
        self.wait_established(left, right)
        return left, right

    def peer(self, one, other, **extra):
        """Configure two running speakers as each other's neighbour.

        The other way round from :meth:`pair`, which commits the
        neighbours with the rest of the document before ``start()``.
        Both orders work; a test picks this one when it needs to do
        something -- read a counter, assert a rejection -- in the window
        between the engine running and the session existing.

        :param one: a :class:`Speaker`.
        :param other: the :class:`Speaker` it should peer with.
        :param extra: merged into both neighbour blocks.
        """
        self.add_neighbor(one, other, **extra)
        self.add_neighbor(other, one, **extra)

    @staticmethod
    def add_neighbor(speaker, other, **extra):
        """Configure one direction of a peering on a running engine."""
        speaker.engine.configure(
            ('router', 'bgp', str(speaker.asn), 'neighbor', other.address),
            _neighbor(other.asn, other.port, speaker.address, **extra))

    def wait_until(self, predicate, what, timeout=20.0):
        """Poll until a predicate holds, failing with a useful message.

        Generous on purpose. These waits synchronise with two other
        threads and a TCP handshake; they are not measuring anything.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail('%s did not happen within %.0f seconds'
                  % (what, timeout))

    def wait_established(self, *speakers):
        """Wait until every speaker reports all its sessions up."""
        for speaker in speakers:
            self.wait_until(
                speaker.established,
                'the session on %s reached Established (state was %r)'
                % (speaker.engine.name, self._states(speaker)))

    @staticmethod
    def _states(speaker):
        """The FSM state of every session, for a failure message."""
        return dict((addr, session.state)
                    for addr, session in speaker.plugin.peers.items())

    def converge(self, speakers, predicate, what, timeout=20.0):
        """Drive passes on every speaker until a predicate holds.

        One "round" is an advertisement pass on each speaker, and that is
        all: the pass offers what changed to the core and asks the core
        to select, so nothing here drives ``Engine.select()``. Rounds
        repeat because a full exchange takes several -- one to send, one
        for the peer to read and offer, one for the answer to come back
        -- and because the core's selection is a coalescing task on the
        loop rather than something that has finished when ``run_pass``
        returns.

        :param speakers: the speakers to drive.
        :param predicate: called between rounds; the goal.
        :param what: named in the failure message.
        :param timeout: seconds before giving up.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            for speaker in speakers:
                speaker.run_pass()
            if predicate():
                return
            time.sleep(0.05)
        self.fail('%s did not happen within %.0f seconds' % (what, timeout))

    def ipv4_pair(self, networks_a=(NET_A_V4,), networks_b=(NET_B_V4,),
                  **extra):
        """The standard two-speaker IPv4 peering, established.

        :param networks_a: what the left speaker originates.
        :param networks_b: what the right speaker originates.
        :param extra: merged into both neighbour blocks.
        :return: ``(left, right)``, both Established.
        """
        return self.pair('left', 'right', networks_a=networks_a,
                         networks_b=networks_b, **extra)


class Ipv4SessionTestCase(PeeringFixture):
    """Item 1 and item 2: the session comes up, and on agreed terms."""

    def test_both_sides_reach_established(self):
        left, right = self.ipv4_pair()

        for speaker in (left, right):
            health = speaker.plugin.health()
            self.assertEqual(health['status'], 'ok',
                             '%s is not healthy: %r'
                             % (speaker.engine.name, health))
            self.assertEqual(health['neighbors'], 1)
            self.assertEqual(health['established'], 1)

            summary = speaker.engine.show('ip', 'bgp', 'summary')
            self.assertEqual(summary['established'], 1)
            self.assertEqual(len(summary['peers']), 1)
            row = summary['peers'][0]
            self.assertEqual(row['neighbor'], V4_LOOPBACK)
            self.assertEqual(row['state'], 'Established')
            self.assertIsNone(row['last-error'])
            # An unauthenticated session is what this pair asked for, and
            # `auth` says so rather than being absent: "blocked" here
            # would mean the peer never came up.
            self.assertEqual(row['auth'], 'none')

        self.assertEqual(left.engine.show('ip', 'bgp', 'summary')['local-as'],
                         AS_A)
        self.assertEqual(right.engine.show('ip', 'bgp',
                                           'summary')['local-as'], AS_B)

    def test_capabilities_are_negotiated_the_same_on_both_sides(self):
        left, right = self.ipv4_pair()

        negotiated = dict(
            (speaker.engine.name,
             speaker.session().negotiated.as_dict())
            for speaker in (left, right))

        for name, caps in negotiated.items():
            self.assertEqual(caps['families'], ['IPv4 Unicast'],
                             '%s negotiated %r' % (name, caps['families']))
            self.assertEqual(caps['afi_safi'], [[1, 1]])
            self.assertTrue(caps['as4'], '%s did not negotiate 4-octet AS'
                                         % (name,))
            self.assertTrue(caps['route_refresh'],
                            '%s did not negotiate route refresh' % (name,))
            self.assertTrue(caps['peer_as4'])
            # Nothing asked for these, so agreeing to them would mean the
            # negotiation is answering questions it was not asked.
            self.assertEqual(caps['add_path_recv'], [])
            self.assertEqual(caps['add_path_send'], [])

        self.assertEqual(negotiated['left']['peer_asn'], AS_B)
        self.assertEqual(negotiated['right']['peer_asn'], AS_A)
        self.assertEqual(negotiated['left']['max_message_size'],
                         negotiated['right']['max_message_size'])


class Ipv4ConvergenceTestCase(PeeringFixture):
    """Items 3, 5 and 7: routes arrive, leave, and are released."""

    def assert_learned(self, speaker, prefix, origin_as):
        """Assert a prefix is in the Loc-RIB and the core, from a peer.

        The pair of assertions is the point: a prefix that reached the
        BGP table but not the ``GlobalRib`` means the offer never crossed
        into the core, which is exactly the seam this stage is about.
        """
        row = speaker.locrib_row(prefix)
        self.assertIsNotNone(
            row, '%s never learned %s (table: %r)'
                 % (speaker.engine.name, prefix,
                    speaker.engine.show(speaker.show_root, 'bgp')))
        self.assertEqual(row['as-path'], str(origin_as),
                         '%s has the wrong AS_PATH for %s'
                         % (speaker.engine.name, prefix))
        self.assertEqual(row['peer'], speaker.address)
        self.assertEqual(row['next-hop'], speaker.address)
        self.assertEqual(row['paths'], 1)

        route = speaker.core_route(prefix)
        self.assertIsNotNone(route, '%s never installed %s in the GlobalRib'
                                    % (speaker.engine.name, prefix))
        self.assertEqual(route['protocol'], 'bgp')
        self.assertEqual(route['distance'], DISTANCE_EBGP)
        self.assertEqual(route['next-hop'], speaker.address)

    def assert_gone(self, speaker, prefix):
        """Assert a prefix is in neither the Loc-RIB nor the core."""
        self.assertIsNone(speaker.locrib_row(prefix),
                          '%s still has %s in its BGP table'
                          % (speaker.engine.name, prefix))
        self.assertIsNone(speaker.core_route(prefix),
                          '%s still has %s in its GlobalRib'
                          % (speaker.engine.name, prefix))

    def learned_both_ways(self, left, right):
        """Predicate: each side has the other's network in the core."""
        return (right.core_route(NET_A_V4) is not None and
                left.core_route(NET_B_V4) is not None)

    def test_each_network_reaches_the_other_engine(self):
        left, right = self.ipv4_pair()

        self.converge([left, right],
                      lambda: self.learned_both_ways(left, right),
                      'both engines learned the other\'s network')

        self.assert_learned(right, NET_A_V4, AS_A)
        self.assert_learned(left, NET_B_V4, AS_B)

        # The originator keeps its own network as a locally sourced path,
        # with an empty AS_PATH: an engine that learned its own network
        # back from the peer would be an AS loop the peer failed to stop.
        own = left.locrib_row(NET_A_V4)
        self.assertEqual(own['as-path'], '')
        self.assertEqual(own['peer'], '-')

    def test_withdrawing_a_network_withdraws_it_from_the_peer(self):
        left, right = self.ipv4_pair()
        self.converge([left, right],
                      lambda: right.core_route(NET_A_V4) is not None,
                      'the right engine learned %s' % (NET_A_V4,))

        left.engine.unconfigure(('router', 'bgp', str(AS_A),
                                 'address-family', 'ipv4', 'unicast',
                                 'network', NET_A_V4))

        self.converge([left, right],
                      lambda: right.core_route(NET_A_V4) is None,
                      'the right engine withdrew %s' % (NET_A_V4,))

        self.assert_gone(right, NET_A_V4)
        self.assert_gone(left, NET_A_V4)
        # The other direction is untouched: a withdrawal that took the
        # whole session's routes with it would pass a test that only
        # looked at the withdrawn prefix.
        self.assert_learned(left, NET_B_V4, AS_B)

    def test_shutting_a_neighbour_down_releases_its_routes(self):
        # The two speakers are peered after they are running rather than
        # from their boot configuration, because the baseline has to be
        # read while the left engine has no session at all. Read it a
        # moment later and the advertisement loop may already have
        # interned the peer's attribute set, so the baseline would
        # include the very thing this test watches being released and
        # the release would be invisible.
        left = self.speaker('shut-left', AS_A, '10.0.0.1',
                            _free_port(V4_LOOPBACK, socket.AF_INET),
                            networks=[NET_A_V4])
        right = self.speaker('shut-right', AS_B, '10.0.0.2',
                             _free_port(V4_LOOPBACK, socket.AF_INET),
                             networks=[NET_B_V4])
        baseline = left.attr_count()
        self.peer(left, right)
        self.wait_established(left, right)

        self.converge([left, right],
                      lambda: left.core_route(NET_B_V4) is not None,
                      'the left engine learned %s' % (NET_B_V4,))
        self.assertGreater(
            left.attr_count(), baseline,
            'the peer\'s attribute set was never interned, so the '
            'release assertion below would prove nothing')

        left.engine.configure(('router', 'bgp', str(AS_A), 'neighbor',
                               right.address, 'shutdown'), True)

        self.wait_until(lambda: not left.session().established,
                        'the left session left Established after shutdown')
        self.converge([left, right],
                      lambda: left.core_route(NET_B_V4) is None,
                      'the left engine dropped %s after shutdown'
                      % (NET_B_V4,))

        self.assert_gone(left, NET_B_V4)
        # Its own origination survives: shutting a neighbour down must
        # not empty the table.
        self.assertIsNotNone(left.locrib_row(NET_A_V4))

        # The intern table is the reason this test exists. A connect and
        # disconnect cycle that leaks one attribute set per session leaks
        # unboundedly on a flapping peer, and nothing else in the suite
        # would notice.
        self.assertLessEqual(
            left.attr_count(), baseline,
            'the attribute table grew across a connect/disconnect cycle: '
            '%d distinct sets now against %d before the session'
            % (left.attr_count(), baseline))

    def test_the_peer_notices_the_shutdown_and_releases_too(self):
        left, right = self.ipv4_pair()
        self.converge([left, right],
                      lambda: right.core_route(NET_A_V4) is not None,
                      'the right engine learned %s' % (NET_A_V4,))

        left.engine.configure(('router', 'bgp', str(AS_A), 'neighbor',
                               right.address, 'shutdown'), True)

        self.wait_until(lambda: not right.session().established,
                        'the right session noticed the peer going away')
        self.converge([right],
                      lambda: right.core_route(NET_A_V4) is None,
                      'the right engine released %s' % (NET_A_V4,))
        self.assert_gone(right, NET_A_V4)


@unittest.skipUnless(HAVE_IPV6, 'the IPv6 loopback ::1 is not available '
                                'on this host')
class Ipv6ConvergenceTestCase(PeeringFixture):
    """Item 4: the same exchange over an IPv6 transport, via MP_REACH.

    A separate pair of engines rather than a second family on the IPv4
    pair, because ``update-source`` is one address per neighbour and the
    Adj-RIB-Out packs it to the family's next-hop width: a v4
    ``update-source`` with an IPv6 family is rejected at construction.
    Two transports therefore mean two peerings, which is also the honest
    reading of "IPv4 and IPv6 transport".
    """

    def ipv6_pair(self):
        return self.pair('left6', 'right6', family='ipv6',
                         networks_a=[NET_A_V6], networks_b=[NET_B_V6])

    def test_ipv6_unicast_converges_over_an_ipv6_session(self):
        left, right = self.ipv6_pair()

        caps = left.session(V6_LOOPBACK).negotiated.as_dict()
        self.assertEqual(caps['families'], ['IPv6 Unicast'])
        self.assertTrue(caps['as4'])

        self.converge(
            [left, right],
            lambda: (right.core_route(NET_A_V6) is not None and
                     left.core_route(NET_B_V6) is not None),
            'both engines learned the other\'s IPv6 network')

        row = right.locrib_row(NET_A_V6)
        self.assertEqual(row['as-path'], str(AS_A))
        self.assertEqual(row['next-hop'], V6_LOOPBACK)
        route = right.core_route(NET_A_V6)
        self.assertEqual(route['protocol'], 'bgp')
        self.assertEqual(route['distance'], DISTANCE_EBGP)
        self.assertEqual(route['next-hop'], V6_LOOPBACK)

        row = left.locrib_row(NET_B_V6)
        self.assertEqual(row['as-path'], str(AS_B))
        self.assertEqual(left.core_route(NET_B_V6)['next-hop'], V6_LOOPBACK)

        # The IPv4 table was never created: `afi_safi()` is derived from
        # configuration, and an engine carrying only IPv6 should not have
        # an empty IPv4 Loc-RIB sitting in its show output.
        self.assertNotIn(IPV4_UNICAST, left.plugin.locribs)


class FourOctetAsTestCase(PeeringFixture):
    """Item 6: an AS above 65535 survives the round trip intact."""

    def test_the_real_asn_appears_in_the_as_path_not_as_trans(self):
        left, right = self.pair('left32', 'right32', asn_a=AS_FOUR_OCTET)

        caps = right.session().negotiated.as_dict()
        self.assertTrue(caps['as4'],
                        'the session fell back to 2-octet AS numbers')
        self.assertEqual(caps['peer_asn'], AS_FOUR_OCTET)

        self.converge([left, right],
                      lambda: right.core_route(NET_A_V4) is not None,
                      'the 2-octet speaker learned the 4-octet peer\'s '
                      'network')

        row = right.locrib_row(NET_A_V4)
        self.assertEqual(row['as-path'], str(AS_FOUR_OCTET))
        self.assertNotIn(str(AS_TRANS), row['as-path'],
                         'AS_TRANS leaked into the AS_PATH')
        self.assertEqual(right.engine.show('ip', 'bgp',
                                           'summary')['peers'][0]['as'],
                         AS_FOUR_OCTET)


class ShowAndClearTestCase(PeeringFixture):
    """Item 8: the operational surface, with a session up."""

    def setUp(self):
        self.left, self.right = self.ipv4_pair()
        self.converge([self.left, self.right],
                      lambda: self.right.core_route(NET_A_V4) is not None,
                      'the right engine learned %s' % (NET_A_V4,))

    def assert_json(self, doc, what):
        """Assert a show answer is a dict of plain, serialisable types."""
        self.assertIsInstance(doc, dict, '%s is not a dict' % (what,))
        try:
            json.dumps(doc)
        except (TypeError, ValueError) as exc:
            self.fail('%s is not JSON-serialisable: %s' % (what, exc))
        return doc

    def test_every_show_path_answers_with_serialisable_plain_types(self):
        show = self.right.engine.show

        summary = self.assert_json(show('ip', 'bgp', 'summary'),
                                   'show ip bgp summary')
        self.assertEqual(summary['established'], 1)

        table = self.assert_json(show('ip', 'bgp'), 'show ip bgp')
        self.assertEqual(table['family'], 'IPv4 Unicast')
        self.assertFalse(table['truncated'])
        self.assertEqual(table['destinations'], 2)

        one = self.assert_json(show('ip', 'bgp', 'neighbors', V4_LOOPBACK),
                               'show ip bgp neighbors <addr>')
        self.assertNotIn('error', one)
        self.assertEqual(one['neighbor']['state'], 'Established')

        dest = self.assert_json(show('ip', 'bgp', NET_A_V4),
                                'show ip bgp <prefix>')
        self.assertEqual(dest['prefix'], NET_A_V4)
        self.assertEqual(len(dest['paths']), 1)
        self.assertIsNotNone(dest['best-reason'])

        # The originator's view of the same prefix names who was told
        # about it, which is the only place the Adj-RIB-Out is visible.
        advertised = self.assert_json(self.left.engine.show('ip', 'bgp',
                                                            NET_A_V4),
                                      'show ip bgp <prefix> on the origin')
        self.assertEqual(advertised['advertised-to'], [V4_LOOPBACK])

    def test_an_unknown_neighbour_is_an_answer_not_an_exception(self):
        doc = self.assert_json(
            self.right.engine.show('ip', 'bgp', 'neighbors', '10.255.0.1'),
            'show ip bgp neighbors <unknown>')
        self.assertIn('error', doc)
        self.assertEqual(doc['known'], [V4_LOOPBACK])

    def test_a_soft_clear_refreshes_without_bouncing_the_session(self):
        session = self.right.session()
        before = session.stats_counters['refresh-out']
        uptime = session.fsm.stats().get('uptime')

        answer = self.assert_json(
            self.right.engine.clear('ip', 'bgp', 'neighbor', V4_LOOPBACK,
                                    soft=True),
            'clear ip bgp neighbor <addr> soft')
        # A bare `soft` means inbound, and since Stage 4 it does two
        # things rather than one: it re-runs inbound policy over the
        # paths already held -- which is what makes a policy edit take
        # effect -- *and* asks the peer to re-send, which is the only way
        # to recover anything the previous policy discarded.
        self.assertEqual(answer['soft'], 'in')
        self.assertEqual(answer['refresh-sent'], ['1/1'])
        self.assertEqual(answer['replayed'], 1)
        self.assertEqual(session.stats_counters['refresh-out'], before + 1)

        # The session must not have flapped: a soft clear that resets is
        # a hard clear with a friendlier name.
        self.assertEqual(session.state, 'Established')
        self.assertTrue(self.right.established())
        self.assertGreaterEqual(session.fsm.stats().get('uptime'), uptime)

        # And the peer answers the refresh rather than ignoring it.
        self.converge([self.left, self.right],
                      lambda: self.right.core_route(NET_A_V4) is not None,
                      'the refreshed route came back')
        self.assertEqual(self.right.locrib_row(NET_A_V4)['as-path'],
                         str(AS_A))


class AuthenticationTestCase(PeeringFixture):
    """Items 9 and 10: authentication, and refusing to do without it.

    Item 10 is the one that matters on every platform. Key Decision 8
    says a peer configured for TCP-AO on a kernel without it must not
    come up, and the enforcement is at configuration time: ``show ip bgp
    neighbors`` cannot report a fail-closed reason for a session that was
    never accepted into the running configuration, so the test asserts
    the rejection rather than the shown state.
    """

    def test_md5_is_not_silently_ignored_when_the_kernel_lacks_it(self):
        """A password with no kernel MD5 is refused, not downgraded."""
        if HAVE_MD5:
            self.skipTest('this kernel has TCP-MD5, so the refusal path '
                          'is not the one under test here')
        left = self.speaker('left-md5', AS_A, '10.0.0.1',
                            _free_port(V4_LOOPBACK, socket.AF_INET),
                            networks=[NET_A_V4])
        right = self.speaker('right-md5', AS_B, '10.0.0.2',
                             _free_port(V4_LOOPBACK, socket.AF_INET),
                             networks=[NET_B_V4])
        with self.assertRaises(ConfigError) as caught:
            self.add_neighbor(left, right, password='correct horse')
        self.assertIn('md5-unsupported', str(caught.exception))
        self.assertEqual(left.plugin.peers, {})

    @unittest.skipUnless(HAVE_MD5, 'this kernel has no TCP-MD5 support')
    def test_a_matching_md5_password_brings_the_session_up(self):
        left, right = self.ipv4_pair(**{'password': 'correct horse'})
        for speaker in (left, right):
            row = speaker.engine.show('ip', 'bgp', 'summary')['peers'][0]
            self.assertEqual(row['state'], 'Established')
            self.assertEqual(row['auth'], auth_mod.AUTH_MD5)

    @unittest.skipUnless(HAVE_MD5, 'this kernel has no TCP-MD5 support')
    def test_a_mismatched_md5_password_keeps_the_session_down(self):
        left = self.speaker('left-md5x', AS_A, '10.0.0.1',
                            _free_port(V4_LOOPBACK, socket.AF_INET),
                            networks=[NET_A_V4])
        right = self.speaker('right-md5x', AS_B, '10.0.0.2',
                             _free_port(V4_LOOPBACK, socket.AF_INET),
                             networks=[NET_B_V4])
        self.add_neighbor(left, right, password='correct horse')
        self.add_neighbor(right, left, password='battery staple')

        # Long enough for several connect-retry cycles, so "not yet" and
        # "never" are told apart.
        deadline = time.time() + 8.0
        while time.time() < deadline:
            self.assertFalse(
                left.established() or right.established(),
                'a session came up with mismatched MD5 passwords')
            time.sleep(0.1)

    def test_tcp_ao_without_a_sanctioned_fallback_is_rejected(self):
        """Item 10, the security assertion of the stage.

        Not skipped anywhere. On a kernel *with* AO the configuration is
        accepted, which is also correct; what must never happen is the
        third outcome, where a kernel without AO takes the configuration
        and peers in the clear.
        """
        left = self.speaker('left-ao', AS_A, '10.0.0.1',
                            _free_port(V4_LOOPBACK, socket.AF_INET),
                            networks=[NET_A_V4])
        right = self.speaker('right-ao', AS_B, '10.0.0.2',
                             _free_port(V4_LOOPBACK, socket.AF_INET),
                             networks=[NET_B_V4])
        ao = {'key-chain': 'peering-keys', 'algorithm': 'hmac-sha1'}

        if HAVE_AO:
            self.add_neighbor(left, right, ao=ao)
            session = left.session()
            self.assertEqual(session.auth_mode, auth_mod.AUTH_AO)
            return

        with self.assertRaises(ConfigError) as caught:
            self.add_neighbor(left, right, ao=ao)
        message = str(caught.exception)
        self.assertIn(auth_mod.REASON_AO_UNSUPPORTED, message)
        self.assertIn('ao-unsupported', message)
        # Rejected means rejected: no peer object, nothing listening for
        # it, and the running configuration unchanged.
        self.assertEqual(left.plugin.peers, {})
        self.assertNotIn(
            'neighbor',
            left.engine.running_config()['router']['bgp'][str(AS_A)])

    def test_tcp_ao_falls_back_to_md5_only_when_authorised_in_writing(self):
        """The sanctioned downgrade, and only the sanctioned one."""
        ao = {'key-chain': 'peering-keys', 'fallback-md5': True}

        mode, key, reason = auth_mod.resolve_auth(
            {'ao': ao, 'password': 'correct horse'}, ao_available=False)
        self.assertEqual(mode, auth_mod.AUTH_MD5_AO_FALLBACK)
        self.assertEqual(key, 'correct horse')
        self.assertEqual(reason, auth_mod.REASON_AO_FALLBACK)

        # fallback-md5 without a password authorises nothing: there is no
        # key to fall back to, so the peer must stay down.
        mode, _key, reason = auth_mod.resolve_auth({'ao': ao},
                                                   ao_available=False)
        self.assertIsNone(mode)
        self.assertEqual(reason, auth_mod.REASON_AO_UNSUPPORTED)

        # A truthy value is not authorisation. This is the hand-edited
        # configuration case the `is True` comparison exists for.
        mode, _key, reason = auth_mod.resolve_auth(
            {'ao': {'key-chain': 'k', 'fallback-md5': 'yes'},
             'password': 'correct horse'}, ao_available=False)
        self.assertIsNone(mode)
        self.assertEqual(reason, auth_mod.REASON_AO_UNSUPPORTED)

    @unittest.skipUnless(HAVE_MD5,
                         'this kernel has no TCP-MD5 support, so an '
                         'authorised AO fallback cannot be applied to a '
                         'socket')
    def test_an_authorised_ao_fallback_session_comes_up_as_md5(self):
        left, right = self.ipv4_pair(
            ao={'key-chain': 'peering-keys', 'fallback-md5': True},
            password='correct horse')
        row = left.engine.show('ip', 'bgp', 'summary')['peers'][0]
        self.assertEqual(row['state'], 'Established')
        self.assertEqual(row['auth'], auth_mod.AUTH_MD5_AO_FALLBACK)


class RegressionTestCase(PeeringFixture):
    """The four integration defects this file found, now pinned.

    Every one of these was a real defect in the modules under test when
    this stage was written, and every one of them was invisible to the
    unit suites: each lives in a seam that only exists once two whole
    engines run against each other over a socket. All four are fixed,
    and these tests exist so that a future change which reintroduces one
    is caught here rather than by an operator whose router will not
    peer.

    They are deliberately smaller and more direct than the acceptance
    classes above. A convergence test that stopped converging would say
    only that; these say which seam parted.
    """

    def test_a_complete_configuration_before_start_establishes(self):
        """The ordinary boot order: whole document, then ``start()``.

        **The defect:** ``BGPPlugin._add_peer`` handed the ``Peer`` the
        engine's loop as it found it at commit time, which before the
        engine starts is None, and ``start()`` started each session
        without giving it the loop it had by then. A loopless peer can
        neither dial nor arm a timer, so the FSM sat in Connect for ever
        and nothing on either side ever said why. This is the order
        every engine that loads its configuration from a file uses, so
        the only working order was the unnatural one -- listen block
        before ``start()``, neighbours after -- which is what this
        fixture used to do.

        **Why it matters:** a router that comes up with a complete
        configuration and silently refuses to peer is the worst kind of
        failure, because there is no error to find. ``start()`` now
        passes ``engine.loop`` to every session it starts, and
        ``_add_peer`` does the same for a neighbour added later, so both
        orders work; the fixture uses this one everywhere.
        """
        port_a = _free_port(V4_LOOPBACK, socket.AF_INET)
        port_b = _free_port(V4_LOOPBACK, socket.AF_INET)
        left = self.make_engine('boot-left')
        right = self.make_engine('boot-right')
        left.replace_config(_instance(
            AS_A, '10.0.0.1', V4_LOOPBACK, port_a, 'ipv4', [NET_A_V4],
            {V4_LOOPBACK: _neighbor(AS_B, port_b, V4_LOOPBACK)}))
        right.replace_config(_instance(
            AS_B, '10.0.0.2', V4_LOOPBACK, port_b, 'ipv4', [NET_B_V4],
            {V4_LOOPBACK: _neighbor(AS_A, port_a, V4_LOOPBACK)}))

        # Both peers exist and are loopless at this point, which is
        # correct -- there is no loop to hand them yet.
        self.assertIsNone(left.plugin('bgp').peers[V4_LOOPBACK].loop)

        left.start()
        right.start()

        for engine in (left, right):
            session = engine.plugin('bgp').peers[V4_LOOPBACK]
            self.assertIsNotNone(
                session.loop,
                '%s left its peer without an event loop after start(), '
                'so it can never open a connection' % (engine.name,))

        speakers = (Speaker(left, AS_A, V4_LOOPBACK, port_a, 'ipv4'),
                    Speaker(right, AS_B, V4_LOOPBACK, port_b, 'ipv4'))
        self.wait_established(*speakers)

    def test_a_listen_block_committed_after_start_accepts_a_peer(self):
        """A configuration pushed to a running engine opens its socket.

        **The defect:** ``_start_listener`` was called from
        ``BGPPlugin.start()`` and nowhere else, so an engine started
        before its configuration arrived -- which is what happens when
        configuration is pushed to a running daemon rather than read at
        boot -- never bound anything. The symptom was maddening: the
        engine dialled out perfectly well and simply never accepted,
        which looks like the other end's fault.

        **Why it matters:** half a peering is not a peering. The
        neighbour here is ``passive``, so it will never dial and the
        session can only come up through the listener that
        ``commit_config`` had to open; an engine that only got as far as
        the old behaviour would sit in Active until the timeout.
        """
        port_late = _free_port(V4_LOOPBACK, socket.AF_INET)
        port_dial = _free_port(V4_LOOPBACK, socket.AF_INET)

        late = self.make_engine('late-listen')
        late.start()
        self.assertEqual(late.plugin('bgp').listeners, [])
        late.replace_config(_instance(
            AS_A, '10.0.0.1', V4_LOOPBACK, port_late, 'ipv4', [NET_A_V4],
            {V4_LOOPBACK: _neighbor(AS_B, port_dial, V4_LOOPBACK,
                                    passive=True)}))

        self.assertTrue(
            late.plugin('bgp').listeners,
            'no listening socket was opened for a listen block that was '
            'committed after the engine started')

        dialer = self.speaker(
            'dialer', AS_B, '10.0.0.2', port_dial, networks=[NET_B_V4],
            neighbors={V4_LOOPBACK: _neighbor(AS_A, port_late,
                                              V4_LOOPBACK)})
        listener = Speaker(late, AS_A, V4_LOOPBACK, port_late, 'ipv4')
        self.wait_established(listener, dialer)

    def test_the_adj_rib_out_is_linked_to_the_sessions_peer_ref(self):
        """An established session can actually advertise.

        **The defect:** ``_add_peer`` builds each ``AdjRibOut`` when the
        neighbour is configured, which is long before the peer's router
        id is known, so it passed None where the ``PeerRef`` belongs --
        and nothing ever filled it in once ``Peer._handle_open`` built
        the real one. The first advertisement pass over an established
        session then dereferenced None inside
        ``AdjRibOut._outbound_attrs`` and raised ``AttributeError``,
        which ``_advertise_loop`` catches and logs, so a running engine
        just never advertised anything to anybody.

        **Why it matters:** this is the whole product. Two peers that
        establish and exchange nothing look healthy in every summary
        while carrying no traffic. ``_handle_open`` now links every
        Adj-RIB-Out to the ref at the first moment it exists, and this
        file no longer has a helper that did it from the outside.
        """
        left, right = self.ipv4_pair()

        session = left.session()
        self.assertIsNotNone(session.peer_ref,
                             'the session has no PeerRef although it is '
                             'Established')
        self.assertEqual(sorted(session.adjout), [IPV4_UNICAST])
        for af, out in session.adjout.items():
            self.assertIs(
                out.peer, session.peer_ref,
                'the Adj-RIB-Out for %r is not linked to the session\'s '
                'PeerRef, so advertisement will raise AttributeError'
                % (af,))

        # The consequence, asserted directly: the first pass over a
        # freshly established session must queue the local network
        # rather than raise.
        queued = left.engine.submit(left.plugin.run_pass).result(10)
        self.assertGreater(queued, 0,
                           'the first pass over an established session '
                           'queued no UPDATE at all')
        self.converge([left, right],
                      lambda: right.locrib_row(NET_A_V4) is not None,
                      'the advertisement reached the peer')

    def test_convergence_needs_no_help_from_the_test(self):
        """Two engines converge with nothing driving them.

        **The defect:** ``LocRib.reselect`` offers its winners to the
        ``GlobalRib``, which only marks those destinations dirty;
        publishing them is a selection pass, and nothing in the plugin,
        the Loc-RIB or the tables ever called ``Engine.schedule_select``.
        A BGP route therefore reached the core and stopped there --
        present in ``show ip bgp``, absent from ``show ip route``, for
        ever -- and every convergence assertion in this file used to
        call ``Engine.select()`` by hand to get past it.

        **Why it matters:** a route that is not in the core is not in
        the forwarding table, so the session was decorative.
        ``run_pass`` now asks for a selection whenever it offered
        anything, which is the documented way for a plugin to do it.

        This test drives nothing at all: no ``run_pass``, no
        ``select()``. The plugin's own advertisement loop and the core's
        own selection pass have to carry two networks in opposite
        directions between two processes' worth of engine, from
        ``network`` statement to ``show ip route``, or it fails.
        """
        left, right = self.ipv4_pair()

        self.wait_until(
            lambda: (right.core_route(NET_A_V4) is not None and
                     left.core_route(NET_B_V4) is not None),
            'both engines installed the other\'s network in the core '
            'without the test driving a pass or a selection (%s and %s)'
            % (NET_A_V4, NET_B_V4))

        self.assertEqual(right.core_route(NET_A_V4)['distance'],
                         DISTANCE_EBGP)
        self.assertEqual(left.core_route(NET_B_V4)['distance'],
                         DISTANCE_EBGP)


# --- Stage 4 -----------------------------------------------------------------

#: A prefix-list and a route-map, as an operator would configure them.
#: Written as functions for the reason the schema fragments in plugin.py
#: are: a shared mutable document edited by one test would change what a
#: later test committed.

def _prefix_list(action, prefix, seq=5):
    """One prefix-list entry, plus the implicit deny that follows it."""
    return [{'seq': seq, 'action': action, 'prefix': prefix}]


def _route_map(seq=10, action='permit', match=None, sets=None):
    """One route-map clause."""
    clause = {'seq': seq, 'action': action}
    if match:
        clause['match'] = match
    if sets:
        clause['set'] = sets
    return [clause]


def _policy_names(direction, **names):
    """Turn ``route_map='RM'`` into the per-family policy keys.

    :param direction: ``'in'`` or ``'out'``.
    :param names: any of ``route_map``, ``prefix_list``, ``filter_list``.
    :return: the address-family body a neighbour carries.
    """
    body = {}
    for key, value in names.items():
        body[key.replace('_', '-')] = {direction: value}
    return body


class PolicyTestCase(PeeringFixture):
    """Acceptance criterion 3: policy filters, rewrites, and re-applies.

    The criterion is one sentence -- "a ``route-map``/``prefix-list``
    applied ``in`` or ``out`` filters and rewrites paths as configured;
    ``clear ip bgp X soft in|out`` re-applies policy from the retained raw
    Adj-RIB-In / regenerates Adj-RIB-Out without a session reset" -- and
    it contains six separable claims. Each test below is one of them, and
    each runs over two real engines and a real socket, because the claim
    that matters operationally is not "the matcher matched" (the unit
    tests cover that) but "the neighbour's table is different as a
    result".

    The last two are the ones worth reading. A policy edit that only
    affects paths arriving *after* it is the classic way a filter appears
    not to work, and a soft clear that quietly resets the session is a
    hard clear with a friendlier name.
    """

    def peer_with_policy(self, side_policy=None, other_policy=None,
                         networks_a=(NET_A_V4,), networks_b=(NET_B_V4,)):
        """Stand up the standard pair, with policy on one or both ends.

        :param side_policy: the left speaker's neighbour address-family
            body.
        :param other_policy: the right speaker's.
        :return: ``(left, right)``, established.
        """
        port_a = _free_port(V4_LOOPBACK, socket.AF_INET)
        port_b = _free_port(V4_LOOPBACK, socket.AF_INET)
        left_nbr = _neighbor(AS_B, port_b, V4_LOOPBACK)
        right_nbr = _neighbor(AS_A, port_a, V4_LOOPBACK)
        if side_policy:
            left_nbr['address-family'] = {'ipv4': {'unicast': side_policy}}
        if other_policy:
            right_nbr['address-family'] = {'ipv4': {'unicast':
                                                    other_policy}}
        left = self.speaker('left', AS_A, '10.0.0.1', port_a, 'ipv4',
                            networks_a, {V4_LOOPBACK: left_nbr})
        right = self.speaker('right', AS_B, '10.0.0.2', port_b, 'ipv4',
                             networks_b, {V4_LOOPBACK: right_nbr})
        self.wait_established(left, right)
        return left, right

    def configure_policy(self, speaker, path, value):
        """Commit one policy object on a running engine."""
        return speaker.engine.configure(path, value)

    @staticmethod
    def field(speaker, prefix, key):
        """Return one field of a speaker's row for a prefix, or None.

        Every wait in this class goes through here rather than through
        ``locrib_row is not None``, and the difference is not cosmetic: a
        destination exists from the moment a path is added to it, which is
        one pass *before* selection has chosen a winner, and until then
        the row is the "no usable path" shape with no attributes in it at
        all. Waiting on the field under test waits for the thing the test
        is about.

        :param speaker: the :class:`Speaker` to ask.
        :param prefix: the prefix in CIDR notation.
        :param key: the row key, e.g. ``'local-preference'``.
        :return: the value, or None if the prefix or the field is absent.
        """
        return (speaker.locrib_row(prefix) or {}).get(key)

    def test_an_inbound_prefix_list_filters_what_reaches_the_locrib(self):
        # The neighbour still says it, and the raw Adj-RIB-In still holds
        # it: the difference between "my neighbour did not send it" and
        # "my policy dropped it" is the whole reason the pre-policy table
        # is kept, and `received-routes` is where an operator reads it.
        left, right = self.peer_with_policy(
            other_policy=_policy_names('in', prefix_list='DENY-A'))
        self.configure_policy(right, ('ip', 'prefix-list', 'DENY-A'),
                              _prefix_list('deny', NET_A_V4))
        self.converge([left, right],
                      lambda: right.session().stats_counters[
                          'prefixes-filtered'] > 0,
                      'the right engine filtered a prefix inbound')

        self.assertIsNone(right.locrib_row(NET_A_V4))
        self.assertIsNone(right.core_route(NET_A_V4))
        received = right.engine.show('ip', 'bgp', 'neighbors', V4_LOOPBACK,
                                     'received-routes')
        self.assertEqual([row['prefix'] for row in received['routes']],
                         [NET_A_V4])
        self.assertGreaterEqual(received['filtered'], 1)

    def test_an_inbound_route_map_rewrites_the_attributes_it_sets(self):
        left, right = self.peer_with_policy(
            other_policy=_policy_names('in', route_map='RM-IN'))
        self.configure_policy(
            right, ('route-map', 'RM-IN'),
            _route_map(sets={'local-preference': 250, 'metric': 42,
                             'community': ['65000:7']}))
        self.converge([left, right],
                      lambda: self.field(right, NET_A_V4,
                                         'local-preference') == 250,
                      'the inbound route-map set the local preference')

        row = right.locrib_row(NET_A_V4)
        self.assertEqual(row['med'], 42)
        # `explain` wraps each path with the verdict that decided it, so
        # the attributes are one level in.
        detail = right.engine.show('ip', 'bgp', NET_A_V4)
        self.assertIn('65000:7',
                      detail['paths'][0]['path']['communities'])

    def test_an_outbound_prefix_list_filters_what_the_peer_is_told(self):
        # Outbound denial is not the same as inbound denial and is worth
        # its own test: the path is in our own table and our own decision
        # process chose it, and what policy changes is only whether the
        # neighbour hears about it.
        left, right = self.peer_with_policy(
            side_policy=_policy_names('out', prefix_list='DENY-A'),
            networks_a=(NET_A_V4, NET_C_V4))
        self.configure_policy(left, ('ip', 'prefix-list', 'DENY-A'),
                              _prefix_list('deny', NET_A_V4, seq=5)
                              + [{'seq': 10, 'action': 'permit',
                                  'prefix': '0.0.0.0/0', 'le': 32}])
        self.converge([left, right],
                      lambda: right.locrib_row(NET_C_V4) is not None,
                      'the right engine learned the permitted prefix')

        self.assertIsNone(right.locrib_row(NET_A_V4))
        group = left.plugin.groups.group_of(V4_LOOPBACK, IPV4_UNICAST)
        self.assertGreaterEqual(
            group.out.stats()['suppressed']['policy'], 1,
            'the denied prefix should be counted against the policy '
            'suppression reason rather than vanishing silently')
        advertised = left.engine.show('ip', 'bgp', 'neighbors',
                                      V4_LOOPBACK, 'advertised-routes')
        self.assertEqual([row['prefix'] for row in advertised['routes']],
                         [NET_C_V4])

    def test_an_outbound_route_map_rewrites_what_the_peer_receives(self):
        # The attributes as sent, not as held: the peer's view is the only
        # honest test of an outbound rewrite, and the AS_PATH it sees must
        # carry the prepend *and* the AS we prepend on every external
        # advertisement.
        left, right = self.peer_with_policy(
            side_policy=_policy_names('out', route_map='RM-OUT'))
        self.configure_policy(
            left, ('route-map', 'RM-OUT'),
            _route_map(sets={'as-path': {'prepend': [AS_A]},
                             'community': ['65000:99'],
                             'metric': 7}))
        self.converge([left, right],
                      lambda: self.field(right, NET_A_V4, 'as-path')
                      == '%d %d' % (AS_A, AS_A),
                      'the outbound prepend reached the peer')

        row = right.locrib_row(NET_A_V4)
        self.assertEqual(row['med'], 7)
        detail = right.engine.show('ip', 'bgp', NET_A_V4)
        self.assertIn('65000:99',
                      detail['paths'][0]['path']['communities'])

    def test_a_policy_edit_reaches_paths_already_received(self):
        # The claim that makes policy usable at all. `route-map` and `ip
        # prefix-list` are core keys, so an edit to them reaches no
        # plugin's commit_config; without the policy_changed hook this
        # prefix would stay in the table until the session bounced.
        left, right = self.peer_with_policy(
            other_policy=_policy_names('in', prefix_list='FILTER-A'))
        self.configure_policy(right, ('ip', 'prefix-list', 'FILTER-A'),
                              _prefix_list('permit', NET_A_V4))
        self.converge([left, right],
                      lambda: self.field(right, NET_A_V4, 'next-hop')
                      is not None,
                      'the right engine learned %s' % (NET_A_V4,))
        session = right.session()
        uptime = session.fsm.stats().get('uptime')

        self.configure_policy(right, ('ip', 'prefix-list', 'FILTER-A'),
                              _prefix_list('deny', NET_A_V4))
        # Wait on the *core* view, not the Loc-RIB's. The retraction
        # reaches the GlobalRib through a coalescing task on the loop, so
        # the Loc-RIB row goes first and the core follows a moment later;
        # a test that waited on the first and asserted the second would
        # pass or fail on timing.
        self.converge([left, right],
                      lambda: right.core_route(NET_A_V4) is None,
                      'the edited prefix-list took the path back out of '
                      'the core table')

        self.assertIsNone(right.locrib_row(NET_A_V4))
        self.assertEqual(session.state, 'Established')
        self.assertGreaterEqual(session.fsm.stats().get('uptime'), uptime)

    def test_a_soft_clear_in_re_applies_policy_without_a_reset(self):
        # Same outcome as the test above, reached the other way: the
        # operator edits policy and asks for it to be re-applied rather
        # than waiting for the engine to notice. Both paths exist because
        # the second is the one an operator uses when they have changed
        # something the engine cannot see, and it must not cost the
        # session either.
        left, right = self.peer_with_policy(
            other_policy=_policy_names('in', route_map='RM-IN'))
        self.configure_policy(
            right, ('route-map', 'RM-IN'),
            _route_map(sets={'local-preference': 111}))
        self.converge([left, right],
                      lambda: self.field(right, NET_A_V4,
                                         'local-preference') == 111,
                      'the first route-map took effect')
        session = right.session()
        uptime = session.fsm.stats().get('uptime')

        self.configure_policy(
            right, ('route-map', 'RM-IN'),
            _route_map(sets={'local-preference': 222}))
        answer = right.engine.clear('ip', 'bgp', 'neighbor', V4_LOOPBACK,
                                    soft='in')
        self.assertEqual(answer['soft'], 'in')
        self.assertGreaterEqual(answer['replayed'], 1)
        self.converge([right],
                      lambda: self.field(right, NET_A_V4,
                                         'local-preference') == 222,
                      'the soft clear re-applied the edited route-map')

        self.assertEqual(session.state, 'Established')
        self.assertGreaterEqual(session.fsm.stats().get('uptime'), uptime)

    def test_a_soft_clear_out_re_advertises_without_a_reset(self):
        left, right = self.peer_with_policy()
        self.converge([left, right],
                      lambda: self.field(right, NET_A_V4, 'next-hop')
                      is not None,
                      'the right engine learned %s' % (NET_A_V4,))
        session = left.session()
        uptime = session.fsm.stats().get('uptime')
        before = session.stats_counters['updates-out']

        answer = left.engine.clear('ip', 'bgp', 'neighbor', V4_LOOPBACK,
                                   soft='out')
        self.assertEqual(answer['soft'], 'out')
        self.assertGreaterEqual(answer['re-advertised'], 1)
        self.assertEqual(answer['families'], ['1/1'])

        # Re-advertised means messages actually went, and the session
        # never left Established while they did.
        self.assertGreater(session.stats_counters['updates-out'], before)
        self.assertEqual(session.state, 'Established')
        self.assertGreaterEqual(session.fsm.stats().get('uptime'), uptime)


class UpdateGroupAcceptanceTestCase(PeeringFixture):
    """Update groups, over real sessions: shared when equivalent, split
    when not.

    The unit tests in ``test_rtengine_updategroup.py`` prove the key, the
    shared record and the encoder in isolation, with a fake peer. What
    they cannot prove is that the *plugin* computes a stable key from a
    real negotiated session -- the message ceiling, the four-octet AS and
    the local address all come from the far end's OPEN and the accepted
    socket -- or that a peer moves when it should. That is what these do.

    A second neighbour is deliberately not stood up here. Every speaker
    in this file lives on 127.0.0.1 and is told apart by port (see the
    module docstring), while the neighbour table is keyed by address, so
    one engine cannot hold two neighbours that differ only in port. The
    multi-member arithmetic -- one encode, N writes -- is therefore
    pinned in the unit tests, and what is pinned here is the identity:
    the same peer must not remain in a group whose encoded stream was
    built under rules that have since changed.
    """

    def test_an_established_neighbour_is_in_a_readable_update_group(self):
        left, right = self.ipv4_pair()
        self.converge([left, right],
                      lambda: right.locrib_row(NET_A_V4) is not None,
                      'the right engine learned %s' % (NET_A_V4,))

        doc = left.engine.show('ip', 'bgp', 'update-groups')
        json.dumps(doc)
        self.assertEqual(doc['groups'], 1)
        group = doc['items'][0]
        self.assertEqual(group['members'], [V4_LOOPBACK])
        # The key is rendered component by component, because "why is
        # this peer not in that group" is only answerable if the
        # components can be read.
        self.assertEqual(group['key']['afi'], 1)
        self.assertTrue(group['key']['is-ebgp'])
        self.assertEqual(group['key']['peer-as'], AS_B)
        self.assertIsNone(group['key']['unique'])

        # And the neighbour detail names the group, so the two views
        # agree about membership.
        neighbour = left.engine.show('ip', 'bgp', 'neighbors', V4_LOOPBACK)
        self.assertEqual(
            neighbour['neighbor']['update-groups'],
            {capabilities.afi_safi_name(*IPV4_UNICAST): group['id']})

    def test_an_outbound_policy_splits_a_peer_into_its_own_group(self):
        # One neighbour, one group; give that neighbour an outbound
        # route-map and the group's key changes, which is what re-stages
        # the table through the new policy. The identity is what is under
        # test here: the same peer must not stay in a group whose
        # encoded stream was built under the previous rules.
        left, right = self.ipv4_pair()
        self.converge([left, right],
                      lambda: right.locrib_row(NET_A_V4) is not None,
                      'the right engine learned %s' % (NET_A_V4,))
        before = left.plugin.groups.group_of(V4_LOOPBACK, IPV4_UNICAST)

        left.engine.configure(('route-map', 'RM-OUT'),
                              _route_map(sets={'metric': 5}))
        left.engine.configure(
            ('router', 'bgp', str(AS_A), 'neighbor', V4_LOOPBACK,
             'address-family', 'ipv4', 'unicast'),
            _policy_names('out', route_map='RM-OUT'))
        after = left.plugin.groups.group_of(V4_LOOPBACK, IPV4_UNICAST)

        self.assertIsNotNone(after)
        self.assertNotEqual(after.gid, before.gid)
        self.assertEqual(after.key.differences(before.key), ['policy'])

        self.converge([left, right],
                      lambda: (right.locrib_row(NET_A_V4) or {}).get('med')
                      == 5,
                      'the new outbound policy reached the peer')

    def test_editing_a_route_map_moves_the_peer_to_a_new_group(self):
        # The version of every object the policy names is part of the
        # key, so an *edit* -- not a reconfiguration of the neighbour --
        # must move the peer too. Without the version in the key the peer
        # would stay in a group whose record was built under the old
        # rules and the edit would never be advertised.
        left, right = self.ipv4_pair()
        left.engine.configure(('route-map', 'RM-OUT'),
                              _route_map(sets={'metric': 5}))
        left.engine.configure(
            ('router', 'bgp', str(AS_A), 'neighbor', V4_LOOPBACK,
             'address-family', 'ipv4', 'unicast'),
            _policy_names('out', route_map='RM-OUT'))
        self.converge([left, right],
                      lambda: (right.locrib_row(NET_A_V4) or {}).get('med')
                      == 5,
                      'the peer saw the first metric')
        first = left.plugin.groups.group_of(V4_LOOPBACK, IPV4_UNICAST)

        left.engine.configure(('route-map', 'RM-OUT'),
                              _route_map(sets={'metric': 9}))
        second = left.plugin.groups.group_of(V4_LOOPBACK, IPV4_UNICAST)
        self.assertNotEqual(second.gid, first.gid)

        self.converge([left, right],
                      lambda: (right.locrib_row(NET_A_V4) or {}).get('med')
                      == 9,
                      'the edited route-map reached the peer')


class NetworkOriginationTestCase(PeeringFixture):
    """``network`` with ``import-check``: originate only what is backed.

    RFC 4271 requires a `network` statement to be backed by something
    else in the router's table, and the reason is worth stating: a
    prefix originated with nothing behind it advertises a black hole with
    this AS's name on it. The check is off by default because a
    control-plane speaker has no other source of routes to check
    against, which makes "on, and nothing backs it" the interesting case
    -- and the one an operator will hit first.
    """

    def test_import_check_withholds_a_network_nothing_backs(self):
        port_a = _free_port(V4_LOOPBACK, socket.AF_INET)
        port_b = _free_port(V4_LOOPBACK, socket.AF_INET)
        document = _instance(AS_A, '10.0.0.1', V4_LOOPBACK, port_a, 'ipv4',
                             (), {V4_LOOPBACK: _neighbor(AS_B, port_b,
                                                         V4_LOOPBACK)})
        af = document['router']['bgp'][str(AS_A)]['address-family']
        af['ipv4']['unicast']['network'] = {NET_A_V4: {'import-check': True}}
        engine = self.make_engine('left')
        engine.replace_config(document)
        engine.start()
        left = Speaker(engine, AS_A, V4_LOOPBACK, port_a, 'ipv4')
        right = self.speaker('right', AS_B, '10.0.0.2', port_b, 'ipv4',
                             (NET_B_V4,),
                             {V4_LOOPBACK: _neighbor(AS_A, port_a,
                                                     V4_LOOPBACK)})
        self.wait_established(left, right)

        # Nothing else in this engine reaches 192.0.2.0/24, so it is not
        # originated and the peer never hears it.
        left.run_pass()
        self.assertIsNone(left.locrib_row(NET_A_V4))
        self.assertEqual(left.plugin.health()['networks'],
                         {'configured': 1, 'originated': 0})

        # Turning the check off is the operator saying "I know": the
        # prefix is originated at once and reaches the peer.
        left.engine.configure(
            ('router', 'bgp', str(AS_A), 'address-family', 'ipv4',
             'unicast', 'network', NET_A_V4, 'import-check'), False)
        self.converge([left, right],
                      lambda: right.locrib_row(NET_A_V4) is not None,
                      'the network was originated once the check was off')
        self.assertEqual(left.plugin.health()['networks'],
                         {'configured': 1, 'originated': 1})


if __name__ == '__main__':
    unittest.main()
