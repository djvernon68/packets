#!/usr/bin/env python

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Stage 4 unit tests: the update group's key, its arithmetic and its clock.

``test_rtengine_bgp_convergence.py`` stands two engines up on loopback and
watches routes arrive. That is the right way to find integration defects
and the wrong way to pin an invariant, because a socket test can only
observe that the right bytes arrived -- it cannot observe that they were
encoded *once*. This module is the unit-level companion: no sockets, no
engine, no asyncio, an injected clock, and a fake peer that implements the
five attributes a group actually touches. Everything here is an assertion
about ``updategroup.py`` and the ``adjout.AdjRibOut`` it shares.

The module docstring of ``updategroup.py`` makes two claims that the rest
of Stage 4 rests on, and this file exists to hold them down:

**The suppression invariant.** Sharing one staging area between N peers is
only sound if every path is advertised to all of them or to none of them.
Three of ``adjout``'s suppression rules look per-peer -- split horizon,
the eBGP AS-path loop check, the iBGP split-horizon rule -- and the key is
what makes them uniform: ``peer_as`` and ``is_ebgp`` are components of it,
so all three rules reach the same verdict for every member. The invariant
therefore lives or dies by the key covering every input to the transform,
which is why :class:`UpdateGroupKeyTestCase` is driven from
``UpdateGroupKey.FIELDS`` rather than from a hand-written list: a
component added to the key later without a test fails *this* file, which
is a loud and cheap failure, instead of sliding through to a group whose
members disagree about what they were sent.

**The MRAI exemptions.** A per-group advertisement interval is a
simplification (RFC 4271 s9.2.1.1 is per destination) and it is only safe
because of two carve-outs: the first flush of a quiet group goes
immediately, so a session that has just come up is not held back for the
interval, and a flush carrying withdrawals goes immediately, because a
delayed withdrawal is a black hole while a delayed announcement is merely
slower convergence. Both are asserted here against a clock the test
advances by hand. Nothing in this file sleeps; a timing test that sleeps
is a timing test that is flaky on a loaded machine, and the group takes a
``clock`` argument precisely so it need not.

One class per claim:

  * :class:`UpdateGroupKeyTestCase` -- every component of the key
    separates two otherwise identical peers, and ``differences()`` names
    the ones that differed. Table-driven from ``FIELDS``.
  * :class:`SingletonEscapeHatchTestCase` -- ``as-override`` and
    ``allowas-in`` relax loop detection, which is the definition of a peer
    that is not equivalent to another, so a spec carrying either is
    supposed to become a group of one. This class contains the one known
    failing test in the file; see its comments.
  * :class:`EncodeOnceSendManyTestCase` -- the claim the module exists
    for. Three members, one destination, one encode, three writes, and
    every member handed the same message objects.
  * :class:`MembershipTestCase` -- ``join`` is idempotent, a changed key
    moves a peer, the last member's departure destroys the group, and one
    member's departure leaves the shared record alone.
  * :class:`CatchUpTestCase` -- a member that joins a group which already
    knows things is replayed the record without the other members or the
    staging area noticing, and the ``seeded`` flag is not the same
    question as the catch-up set.
  * :class:`MinimumAdvertisementIntervalTestCase` -- deferral, release,
    the withdrawal exemption and the forced flush.
  * :class:`OutboundPolicyThroughAGroupTestCase` -- a real
    :class:`PolicyStore` behind a real chain behind a group: what is
    denied, what is rewritten, what is never mutated, and why editing a
    route-map moves peers between groups.
  * :class:`ReportingTestCase` -- ``stats()`` and ``as_dict()`` survive
    ``json.dumps`` and carry the fields the show commands promise.

Written as plain ``unittest.TestCase`` with no pytest features, matching
``test_rtengine_bestpath.py`` and ``test_rtengine_rib.py``: the 3.6.8
verification host has no pytest and runs these through ``python3 -m
unittest discover -s test``.
"""

import json
import unittest

from packets.routing.rtengine.plugins.bgp import adjout as adjout_mod
from packets.routing.rtengine.plugins.bgp import policy as policy_mod
from packets.routing.rtengine.plugins.bgp.attrs import AttrSet, \
    make_as_path, make_communities
from packets.routing.rtengine.plugins.bgp.bestpath import BestpathConfig, \
    BgpDest, BgpPath, PeerRef
from packets.routing.rtengine.plugins.bgp.updategroup import OutboundSpec, \
    UpdateGroup, UpdateGroupKey, UpdateGroupManager
from packets.routing.rtengine.policy.store import PolicyStore
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, parse_prefix

#: The families the groups here are built for. Spelled out because a
#: group's identity includes its family and half the membership tests turn
#: on a peer being in two groups at once for two of them.
AF_V4 = (AFI_IP, 1)
AF_V6 = (AFI_IP6, 1)

#: Our AS, the group's peer AS, and a third AS that owns the paths the
#: tests advertise. Three distinct numbers rather than two: a path whose
#: AS_PATH contains the group's peer AS is suppressed by the loop check,
#: which is correct behaviour and a trap for any test that meant to
#: exercise something else and finds nothing was sent.
LOCAL_AS = 65000
PEER_AS = 65001
ORIGIN_AS = 65002

#: Our router id, as the 32-bit integer the transform wants.
ROUTER_ID = 0x0A0A0A0A

#: The next hop we rewrite to, and the next hop paths arrive with.
LOCAL_ADDR = b'\x0a\x00\x00\x01'
LOCAL_ADDR_V6 = b'\x20\x01\x0d\xb8' + b'\x00' * 11 + b'\x01'
PATH_NEXTHOP = b'\x0a\x00\x00\xfe'

#: The three RFC 5737 documentation prefixes, so nothing here could be
#: confused with a real advertisement if it escaped a test machine.
NET_A = '192.0.2.0/24'
NET_B = '198.51.100.0/24'
NET_C = '203.0.113.0/24'

#: The same two under the names the policy tests use. One prefix the
#: prefix-list denies and one it permits, because "nothing was
#: advertised" and "the right thing was withheld" are different outcomes
#: and a single prefix cannot tell them apart.
NET_PERMITTED = NET_A
NET_DENIED = NET_B

#: The selection config the destinations below are resolved against. Its
#: values do not matter to anything in this file -- every destination here
#: has exactly one path, so the decision process has nothing to decide --
#: but a destination with no ``best`` is silently ignored by the staging
#: code, so calling ``reselect`` is not optional.
SELECT_CONFIG = BestpathConfig(local_as=LOCAL_AS, router_id=ROUTER_ID)


def packed(text):
    """Return a dotted-quad as the four bytes a PeerRef holds.

    :param text: an IPv4 address in dotted-quad form.
    :return: four bytes.
    """
    return bytes(bytearray(int(part) for part in text.split('.')))


class FakeClock(object):
    """A monotonic clock the test moves by hand.

    Every MRAI assertion in this file is a statement about arithmetic on
    two timestamps, and the only way to make such a statement
    deterministic is to own both of them. Passed to ``UpdateGroup`` and
    ``UpdateGroupManager`` as their ``clock``, which is the argument's
    whole purpose.
    """

    def __init__(self, now=1000.0):
        self.now = now

    def advance(self, seconds):
        """Move the clock forward.

        :param seconds: how far.
        :return: the new value.
        """
        self.now += seconds
        return self.now

    def __call__(self):
        return self.now


class FakePeer(object):
    """As much of ``peer.Peer`` as an update group ever touches.

    Which is the point of writing it out. A group calls exactly five
    things on a member: ``config.address`` to key the membership,
    ``peer_ref`` when it has to build the shared transform, ``adjout`` to
    point the session's show output at the shared table, ``established``
    to skip a member whose session went down between staging and flushing,
    and ``send_updates(messages)`` to hand it the already-encoded stream.
    Nothing else. A fake that implements those five and records what it
    was handed is therefore not a simplification of the real session --
    for this interface it is the whole of it, and the assertion that a
    real ``Peer`` is unnecessary here is itself worth pinning.

    ``send_updates`` mirrors the real one's contract: it returns the
    number of messages queued and returns 0 without queueing anything when
    the session is not established, because a group flush can legitimately
    reach a member that went down earlier in the same loop turn.

    :param address: the neighbour address, which is the membership key.
    :param peer_as: the AS on ``peer_ref``. Defaults to the same
        ``PEER_AS`` the specs here use, because a group's transform reads
        the peer AS from the ref while the key reads it from the spec, and
        a fake that let the two disagree would be testing a state the
        plugin cannot produce.
    :param is_ebgp: whether the ref says the session is external.
    """

    def __init__(self, address, peer_as=PEER_AS, is_ebgp=True):
        self.config = _PeerConfig(address)
        self.established = True
        self.adjout = {}
        self.peer_ref = PeerRef(peer=self, peer_as=peer_as,
                                local_as=LOCAL_AS, router_id=ROUTER_ID,
                                addr=packed(address), is_ebgp=is_ebgp)
        #: One entry per ``send_updates`` call, each the list it was
        #: handed. A list of lists rather than a flat list, so a test can
        #: tell "one call carrying three messages" from "three calls" --
        #: which is exactly the distinction this module is about.
        self.sent = []

    def send_updates(self, messages):
        """Record an encoded stream as the real session would write it.

        :param messages: the encoded UPDATEs the group built once.
        :return: the number queued; 0 when not established.
        """
        if not self.established:
            return 0
        self.sent.append(messages)
        return len(messages)

    def messages(self):
        """Return every message this peer was handed, flattened.

        :return: a list of encoded messages, in the order they arrived.
        """
        out = []
        for batch in self.sent:
            out.extend(batch)
        return out


class _PeerConfig(object):
    """The one configuration field a group reads off a session."""

    def __init__(self, address):
        self.address = address


def attrs(as_path=(ORIGIN_AS,), nexthop=PATH_NEXTHOP, communities=(),
          local_pref=None, med=None):
    """An AttrSet standing in for one the Loc-RIB interned.

    ``local_pref`` and ``med`` take None for "attribute absent", the same
    convention ``test_rtengine_bestpath.py`` uses, because "absent" and
    "zero" are different on the wire and the policy tests below turn on
    an attribute the path did *not* arrive with being present afterwards.
    """
    return AttrSet(
        origin=0,
        as_path=make_as_path(list(as_path)),
        nexthop=nexthop,
        med=0 if med is None else med,
        has_med=med is not None,
        local_pref=0 if local_pref is None else local_pref,
        has_local_pref=local_pref is not None,
        communities=make_communities(communities))


def source_ref(address='10.0.0.7', peer_as=ORIGIN_AS, is_ebgp=True):
    """A PeerRef for whoever the path came from.

    Distinct from any :class:`FakePeer`'s ref by default, so that the
    from-peer split-horizon rule does not quietly suppress a path a test
    meant to see advertised.
    """
    return PeerRef(peer_as=peer_as, local_as=LOCAL_AS, router_id=7,
                   addr=packed(address), is_ebgp=is_ebgp)


def dest(prefix_text, attributes=None, contributor=None):
    """A BgpDest with one resolved path, already selected.

    :param prefix_text: the prefix in text form.
    :param attributes: the AttrSet, or None for the default.
    :param contributor: the PeerRef the path arrived through.
    :return: a :class:`BgpDest` whose ``best`` is set.
    """
    destination = BgpDest(parse_prefix(prefix_text))
    destination.add(BgpPath(
        attributes if attributes is not None else attrs(),
        contributor if contributor is not None else source_ref(),
        recv_time=100.0))
    destination.reselect(SELECT_CONFIG)
    return destination


def spec(**kwargs):
    """An OutboundSpec with the family and identity fields filled in.

    Only the fields a test is making a point about are ever passed; the
    rest come from here so that two specs built by two different tests are
    comparable, and so that a test which means "these differ in exactly
    one thing" cannot accidentally be true for a second reason.
    """
    kwargs.setdefault('afi', AFI_IP)
    kwargs.setdefault('safi', 1)
    kwargs.setdefault('is_ebgp', True)
    kwargs.setdefault('peer_as', PEER_AS)
    kwargs.setdefault('local_as', LOCAL_AS)
    kwargs.setdefault('router_id', ROUTER_ID)
    kwargs.setdefault('local_addr', LOCAL_ADDR)
    return OutboundSpec(**kwargs)


#: One entry per component of ``UpdateGroupKey.FIELDS``: the spec keyword
#: that changes it, a value that differs from :func:`spec`'s default, and
#: the component names ``differences()`` is expected to report.
#:
#: The last is not always the single field being varied, and the exception
#: is load-bearing rather than an annoyance: setting ``as_override`` or
#: turning ``sender_loop_check`` off also sets ``unique``, because those
#: two options are meant to make a peer a group of one. The table states
#: that coupling instead of hiding it behind an explicitly-passed
#: ``unique``. (``allowas_in`` used to be the second; it is inbound-only
#: since B-5 and is not in the key at all.)
#:
#: ``afi`` is varied without varying ``local_addr`` to match, which no
#: real configuration would do; it is safe here because a key is a value
#: and never builds anything, and the alternative -- changing two
#: components at once -- would not test what this table is for.
KEY_VARIANTS = {
    'afi': ({'afi': AFI_IP6}, ('afi',)),
    'safi': ({'safi': 2}, ('safi',)),
    'is-ebgp': ({'is_ebgp': False}, ('is-ebgp',)),
    'peer-as': ({'peer_as': PEER_AS + 1}, ('peer-as',)),
    'local-as': ({'local_as': LOCAL_AS + 1}, ('local-as',)),
    'local-addr': ({'local_addr': packed('10.0.0.254')}, ('local-addr',)),
    'next-hop-self': ({'next_hop_self': True}, ('next-hop-self',)),
    'default-local-pref': ({'default_local_pref': 200},
                           ('default-local-pref',)),
    'send-community': ({'send_community': False}, ('send-community',)),
    'send-ext-community': ({'send_ext_community': False},
                           ('send-ext-community',)),
    'send-large-community': ({'send_large_community': False},
                             ('send-large-community',)),
    'max-size': ({'max_size': 2048}, ('max-size',)),
    'as4': ({'as4': False}, ('as4',)),
    'add-path-send': ({'add_path_send': True}, ('add-path-send',)),
    'remove-private-as': ({'remove_private_as': True},
                          ('remove-private-as',)),
    'as-override': ({'as_override': True}, ('as-override', 'unique')),
    'sender-loop-check': ({'sender_loop_check': False},
                          ('sender-loop-check', 'unique')),
    'mrai': ({'mrai': 30.0}, ('mrai',)),
    'policy': ({'policy_id': (('route-map', 'RM-OUT', 7),)}, ('policy',)),
    'unique': ({'unique': '192.0.2.1'}, ('unique',)),
}


class UpdateGroupKeyTestCase(unittest.TestCase):
    """Every input to the outbound transform is part of the identity.

    "Encode once, send N" is only a true statement if two peers in one
    group would have encoded the same bytes separately. That is not a
    property of the encoder, it is a property of the key, so each of these
    tests is really the same test: a peer that differs in *this* cannot be
    in the same group as one that does not.
    """

    def test_two_specs_that_differ_in_nothing_agree_on_one_key(self):
        first = spec().key()
        second = spec().key()
        self.assertEqual(first, second)
        # Hashing separately matters as much as comparing equal: the
        # manager finds a peer's group by dict lookup, so a key that
        # compared equal but hashed differently would create a second
        # group for every peer and the whole mechanism would be a
        # per-peer Adj-RIB-Out with extra steps.
        self.assertEqual(hash(first), hash(second))
        self.assertEqual([], first.differences(second))

    def test_the_variant_table_names_every_component_of_the_key(self):
        # The guard that makes the rest of this class future-proof. A
        # component added to FIELDS without a row here fails this one
        # test with the missing name in the message, rather than being
        # untested and letting two non-equivalent peers share a stream.
        self.assertEqual(sorted(UpdateGroupKey.FIELDS),
                         sorted(KEY_VARIANTS))

    def test_each_component_separates_two_otherwise_identical_specs(self):
        base = spec().key()
        for field in sorted(KEY_VARIANTS):
            delta, _ = KEY_VARIANTS[field]
            with self.subTest(field=field):
                other = spec(**delta).key()
                self.assertNotEqual(base, other)
                self.assertTrue(base != other)

    def test_differences_names_exactly_the_components_that_changed(self):
        # The diagnostic behind `show ip bgp update-groups`: an operator
        # asking why two neighbours did not merge needs the name of the
        # component, not two opaque tuples.
        base = spec().key()
        for field in sorted(KEY_VARIANTS):
            delta, expected = KEY_VARIANTS[field]
            with self.subTest(field=field):
                other = spec(**delta).key()
                self.assertEqual(list(expected), base.differences(other))
                # Symmetric, because the caller has no reason to care
                # which key it asked.
                self.assertEqual(list(expected), other.differences(base))

    def test_every_variant_occupies_a_dictionary_slot_of_its_own(self):
        # The manager stores groups in a dict keyed by these, so equality
        # and hashing have to agree for all of them at once; testing them
        # pairwise would not catch two variants colliding with each other
        # rather than with the base.
        table = {spec().key(): 'base'}
        for field in sorted(KEY_VARIANTS):
            delta, _ = KEY_VARIANTS[field]
            table[spec(**delta).key()] = field
        self.assertEqual(len(KEY_VARIANTS) + 1, len(table))

    def test_our_own_router_id_is_not_part_of_the_identity(self):
        # Deliberate, and the reason it is worth a test: the router id in
        # the spec is *ours*, so it is the same for every peer of one
        # speaker and could never separate two of them. Putting it in the
        # key would cost nothing today and would be wrong the day a
        # confederation or a view gives one speaker two ids, so the
        # absence is an assertion rather than an oversight.
        self.assertEqual(spec(router_id=1).key(),
                         spec(router_id=2).key())

    def test_a_policy_edit_alone_changes_the_key(self):
        # Same names, different version. Without the version in the key,
        # editing a route-map would leave every peer in a group whose
        # encoded stream was built under the old rules and nothing would
        # ever move them.
        before = spec(policy_id=(('route-map', 'RM-OUT', 4),)).key()
        after = spec(policy_id=(('route-map', 'RM-OUT', 5),)).key()
        self.assertNotEqual(before, after)
        self.assertEqual(['policy'], before.differences(after))

    def test_the_order_the_policy_triples_arrive_in_is_significant(self):
        # The key compares the tuple as it was given, so two peers with
        # the same policy listed in a different order do *not* merge.
        # That is why `plugin._policy_id` sorts before returning, and it
        # is worth pinning here: the cost of getting it wrong is silent
        # -- two identical peers in two groups, encoding everything
        # twice, with no error anywhere -- and this is the only place
        # that would say so.
        pair = (('prefix-list', 'PL-OUT', 1), ('route-map', 'RM-OUT', 1))
        self.assertNotEqual(spec(policy_id=pair).key(),
                            spec(policy_id=tuple(reversed(pair))).key())
        self.assertEqual(spec(policy_id=pair).key(),
                         spec(policy_id=tuple(sorted(reversed(pair)))).key())

    def test_a_key_is_not_equal_to_something_that_is_not_a_key(self):
        # __eq__ returns NotImplemented rather than False, so Python falls
        # back to identity and the comparison stays honest in both
        # directions.
        key = spec().key()
        self.assertFalse(key == object())
        self.assertTrue(key != object())
        self.assertIs(NotImplemented, key.__eq__(object()))

    def test_differences_refuses_to_diff_against_a_foreign_object(self):
        # Unlike the comparison, this one raises: asking for the
        # differences between a key and a non-key is a programming error,
        # and an empty list would read as "they are the same".
        with self.assertRaises(ValueError):
            spec().key().differences(object())

    def test_a_key_repr_says_which_group_it_is(self):
        text = repr(spec(unique='192.0.2.1').key())
        self.assertIn('unique=192.0.2.1', text)
        self.assertIn('as=%d' % PEER_AS, text)


class SingletonEscapeHatchTestCase(unittest.TestCase):
    """The two options that relax loop detection must isolate a peer.

    ``as-override`` rewrites the peer's AS out of the AS_PATH and turning
    ``sender-loop-check`` off sends paths that still contain it (B-5; it
    used to be inferred from ``allowas-in``), and both exist to send a peer
    paths that the loop check would otherwise suppress. That is precisely
    the definition of a peer that is not equivalent to its neighbours, and
    the module docstring says the ``unique`` component of the key forces
    such a peer into a group of its own -- which is what makes the
    suppression invariant hold "by construction".

    One test in this class fails against the current module. See its
    comments: it is left failing on purpose.
    """

    def test_as_override_marks_the_spec_unique_without_being_asked(self):
        self.assertIsNotNone(spec(as_override=True).unique)

    def test_no_sender_loop_check_marks_the_spec_unique(self):
        self.assertIsNotNone(spec(sender_loop_check=False).unique)

    def test_a_spec_that_relaxes_nothing_stays_shareable(self):
        # The common case, and the one that has to stay None: a spec that
        # marked itself unique by accident would give every peer its own
        # group and silently undo the whole stage.
        self.assertIsNone(spec().unique)
        self.assertIsNone(spec(sender_loop_check=True).unique)

    def test_remove_private_as_modes_are_different_keys(self):
        """B-4: `true` and `all` produce different streams."""
        plain = spec(remove_private_as=True).key()
        every = spec(remove_private_as='all').key()
        self.assertNotEqual(plain, every)
        self.assertEqual(every.as_dict()['remove-private-as'], 'all')
        self.assertIs(plain.as_dict()['remove-private-as'], True)

    def test_an_explicit_unique_survives_the_automatic_one(self):
        # The documented usage: the caller passes the peer's address, and
        # the automatic marker must not overwrite it, because the address
        # is what actually distinguishes two such peers from each other.
        marked = spec(as_override=True, unique='192.0.2.1')
        self.assertEqual('192.0.2.1', marked.unique)

    def test_two_as_override_peers_do_not_share_an_update_group(self):
        # KNOWN DEFECT -- this test fails today and is left in place.
        #
        # `OutboundSpec.__init__` sets `unique` to the *constant* string
        # 'relaxed-loop-detection' when as-override or allowas-in is on.
        # A constant is the same value for every peer, so it does not
        # distinguish anything: two as-override peers with otherwise
        # identical configuration produce equal keys and share one group,
        # which is the exact case the module docstring says "cannot
        # arise". `plugin._outbound_spec` never passes `unique`, so the
        # constant is what runs in production.
        #
        # The harm is not theoretical, and the second half of this test
        # shows it: the group's shared transform holds one member's
        # PeerRef, so a path learned from that member is suppressed by
        # the from-peer rule for the whole group and the *other* member
        # never receives it -- as-override exists to deliver exactly that
        # path. `allowas_in` has the same shape.
        #
        # The fix belongs in the module, not here: either
        # `OutboundSpec.__init__` should default `unique` to something
        # per-peer, or `plugin._outbound_spec` should pass the
        # neighbour's address as the docstring says it does.
        clock = FakeClock()
        manager = UpdateGroupManager(clock=clock)
        first = FakePeer('192.0.2.1', peer_as=PEER_AS)
        second = FakePeer('192.0.2.2', peer_as=PEER_AS)
        one = manager.join(first, spec(as_override=True))
        two = manager.join(second, spec(as_override=True))

        self.assertIsNot(one, two, 'as-override must be a group of one')
        self.assertEqual(2, len(manager))

        # The consequence, stated as an assertion so that a fix can be
        # checked against the behaviour rather than against the key.
        learned = dest(NET_A, attrs(as_path=(PEER_AS,)),
                       contributor=first.peer_ref)
        manager.announce(AF_V4, learned)
        manager.flush()
        self.assertTrue(second.messages(),
                        'the second peer never received the path that '
                        'as-override exists to send it')


class EncodeOnceSendManyTestCase(unittest.TestCase):
    """One encode, N writes: the claim the whole module exists for.

    Everything else in ``updategroup.py`` -- the key, the catch-up set,
    the interval -- is in service of this arithmetic, so it is asserted
    on the counters *and* on object identity. Counting messages alone
    would pass if the group encoded three times and sent one each.
    """

    def setUp(self):
        self.clock = FakeClock()
        self.manager = UpdateGroupManager(clock=self.clock)
        self.peers = [FakePeer('192.0.2.%d' % octet)
                      for octet in (1, 2, 3)]
        for member in self.peers:
            self.group = self.manager.join(member, spec())

    def test_three_members_share_one_group(self):
        self.assertEqual(1, len(self.manager))
        self.assertEqual(['192.0.2.1', '192.0.2.2', '192.0.2.3'],
                         self.group.member_addresses())
        self.assertEqual(3, self.manager.stats()['memberships'])

    def test_three_members_cost_one_encode_and_three_writes(self):
        self.group.announce(dest(NET_A))
        written = self.group.flush()
        stats = self.group.stats()
        encoded = stats['group-messages']
        # The two numbers together are the measure of what grouping
        # saved: `group-messages` counts what was built, `writes` counts
        # what went out. If the encoder ran per member these would be
        # equal, and this assertion is the difference between "the peers
        # got the right bytes" and "the bytes were built once".
        self.assertEqual(1, encoded)
        self.assertEqual(encoded * len(self.peers), written)
        self.assertEqual(written, stats['writes'])
        self.assertEqual(1, stats['flushes'])

    def test_every_member_is_handed_the_very_same_messages(self):
        self.group.announce(dest(NET_A))
        self.group.flush()
        batches = [member.sent[0] for member in self.peers]
        for batch in batches[1:]:
            # Identity, not equality: equal byte strings would also be
            # produced by encoding once per member, which is what this
            # module is here to avoid.
            self.assertIs(batches[0], batch)
        for member in self.peers:
            self.assertEqual(1, len(member.sent))

    def test_a_member_whose_session_went_down_is_skipped_not_raised(self):
        # A flush can reach a member that went down earlier in the same
        # loop turn. Skipping it keeps the flush from depending on the
        # order two events happened in; raising would take the other two
        # members' updates down with it.
        self.peers[1].established = False
        self.group.announce(dest(NET_A))
        written = self.group.flush()
        self.assertEqual(2, written)
        self.assertEqual([], self.peers[1].sent)
        # The encode still happened once, and the group still counts it:
        # the message existed, it simply had two takers instead of three.
        self.assertEqual(1, self.group.stats()['group-messages'])

    def test_a_flush_with_nothing_staged_writes_nothing(self):
        self.assertEqual(0, self.group.flush())
        self.assertEqual(0, self.group.stats()['flushes'])
        self.assertEqual(0, self.group.stats()['deferrals'])
        for member in self.peers:
            self.assertEqual([], member.sent)

    def test_a_withdrawal_reaches_every_member_once(self):
        announced = dest(NET_A)
        self.group.announce(announced)
        self.group.flush()
        for member in self.peers:
            del member.sent[:]
        self.assertTrue(self.group.withdraw(announced.prefix))
        written = self.group.flush()
        self.assertEqual(3, written)
        for member in self.peers:
            self.assertEqual(1, len(member.sent))
        self.assertIsNone(self.group.out.advertised(announced.prefix))

    def test_the_manager_stages_to_every_group_of_the_family(self):
        # Two groups, one destination: the manager's job is the fan-out
        # across groups, the group's job is the fan-out across members,
        # and confusing the two would show up here as a count of 1.
        other = FakePeer('203.0.113.1')
        self.manager.join(other, spec(send_community=False))
        self.assertEqual(2, self.manager.announce(AF_V4, dest(NET_A)))
        self.assertEqual(0, self.manager.announce(AF_V6, dest(NET_A)))
        self.assertEqual(2, self.manager.pending())
        self.assertEqual(4, self.manager.flush())


class MembershipTestCase(unittest.TestCase):
    """Joining, moving and leaving must not re-advertise anything.

    A configuration commit recomputes every peer's spec, so ``join`` is
    called constantly with keys that have not changed; and a session that
    drops is one member leaving a group the others are still using. Both
    paths are one mistake away from re-advertising a table to peers that
    already have it, which is the churn update groups exist to remove.
    """

    def setUp(self):
        self.clock = FakeClock()
        self.manager = UpdateGroupManager(clock=self.clock)
        self.peer = FakePeer('192.0.2.1')

    def test_join_points_the_member_at_the_shared_table(self):
        group = self.manager.join(self.peer, spec())
        # Everything that already reads `session.adjout[af]` -- show
        # output, the acceptance tests -- now reads the shared record
        # rather than a private one, which is what makes the change
        # invisible above this layer.
        self.assertIs(group.out, self.peer.adjout[AF_V4])
        self.assertEqual(1, self.manager.stats()['created'])

    def test_joining_twice_with_an_equal_key_is_a_no_op(self):
        first = self.manager.join(self.peer, spec())
        first.announce(dest(NET_A))
        first.flush()
        del self.peer.sent[:]
        before = self.manager.stats()

        again = self.manager.join(self.peer, spec())

        self.assertIs(first, again)
        self.assertEqual(1, len(self.manager))
        # Not one counter moves: the early return happens before the
        # join is even recorded, which is the difference between a commit
        # that changed nothing and a commit that re-advertised the table.
        self.assertEqual(before, self.manager.stats())
        self.assertEqual([], self.peer.sent)
        self.assertEqual([], again.catchup())

    def test_a_changed_key_moves_the_peer_to_another_group(self):
        first = self.manager.join(self.peer, spec())
        second = self.manager.join(self.peer, spec(mrai=30.0))

        self.assertIsNot(first, second)
        self.assertEqual(1, self.manager.stats()['moves'])
        self.assertEqual([], first.member_addresses())
        self.assertEqual(['192.0.2.1'], second.member_addresses())
        self.assertIs(second.out, self.peer.adjout[AF_V4])
        # The old group had one member, so moving out of it destroyed it.
        self.assertEqual(1, len(self.manager))
        self.assertEqual(1, self.manager.stats()['destroyed'])

    def test_a_peer_is_in_one_group_per_family(self):
        # The family is in the key, so a dual-stack neighbour is two
        # memberships; `leave` without a family has to find both.
        v4 = self.manager.join(self.peer, spec())
        v6 = self.manager.join(self.peer, spec(afi=AFI_IP6,
                                               local_addr=LOCAL_ADDR_V6))
        self.assertIsNot(v4, v6)
        self.assertEqual(2, len(self.manager))
        self.assertIs(v4, self.manager.group_of('192.0.2.1', AF_V4))
        self.assertIs(v6, self.manager.group_of('192.0.2.1', AF_V6))
        self.assertEqual([v4], self.manager.groups_for(AF_V4))
        self.assertEqual(2, self.manager.leave(self.peer))
        self.assertEqual(0, len(self.manager))
        self.assertEqual({}, self.peer.adjout)

    def test_the_last_member_leaving_destroys_the_group(self):
        group = self.manager.join(self.peer, spec())
        group.announce(dest(NET_A))
        group.flush()

        self.assertEqual(1, self.manager.leave(self.peer, AF_V4))

        self.assertEqual(0, len(self.manager))
        self.assertEqual(1, self.manager.stats()['destroyed'])
        self.assertEqual(1, self.manager.stats()['leaves'])
        self.assertIsNone(self.manager.group_of('192.0.2.1', AF_V4))
        # The record goes away with the group, which is the only place it
        # is correct for it to go away.
        self.assertEqual({}, self.peer.adjout)

    def test_one_member_leaving_leaves_the_shared_record_alone(self):
        # The assertion this class is really for. The record says "the
        # group has been told", and the members still in the group have
        # been told; resetting it when one session flaps would suppress
        # nothing and re-advertise everything to everybody else.
        staying = FakePeer('192.0.2.2')
        group = self.manager.join(self.peer, spec())
        self.manager.join(staying, spec())
        group.announce(dest(NET_A))
        group.flush()
        del staying.sent[:]
        advertised = group.out.advertised_count()

        self.manager.leave(self.peer, AF_V4)

        self.assertEqual(1, len(self.manager))
        self.assertEqual(0, self.manager.stats()['destroyed'])
        self.assertEqual(advertised, group.out.advertised_count())
        self.assertEqual(['192.0.2.2'], group.member_addresses())
        self.assertEqual([], staying.sent)
        self.assertEqual([], group.catchup())
        # And nothing is owed on the next pass either: the departure
        # changed no member's view of what it has been told.
        self.assertEqual(0, group.flush())

    def test_leaving_a_family_the_peer_never_joined_is_not_an_error(self):
        self.manager.join(self.peer, spec())
        self.assertEqual(0, self.manager.leave(self.peer, AF_V6))
        self.assertEqual(1, len(self.manager))

    def test_remove_takes_the_shared_table_off_the_member(self):
        group = self.manager.join(self.peer, spec())
        self.assertIn(AF_V4, self.peer.adjout)
        self.assertTrue(group.remove('192.0.2.1'))
        self.assertNotIn(AF_V4, self.peer.adjout)

    def test_groups_are_listed_in_creation_order(self):
        # A stable order is a reproducible send order, which is what
        # makes a failing convergence test readable.
        second = FakePeer('192.0.2.2')
        third = FakePeer('192.0.2.3')
        one = self.manager.join(self.peer, spec())
        two = self.manager.join(second, spec(mrai=30.0))
        three = self.manager.join(third, spec(max_size=2048))
        self.assertEqual([one, two, three], self.manager.groups())
        self.assertEqual([1, 2, 3], [g.gid for g in self.manager.groups()])


class CatchUpTestCase(unittest.TestCase):
    """A late joiner is owed the record, and only the late joiner.

    The shared record is what makes the group cheap and what makes a new
    member's arrival awkward: the record says the group has been told
    things this member has not, and it would suppress exactly the
    announcements the new member needs. The answer is a one-off replay
    encoded from the record, and the hard part is that it must be
    invisible to everybody else.
    """

    def setUp(self):
        self.clock = FakeClock()
        self.manager = UpdateGroupManager(clock=self.clock)
        self.first = FakePeer('192.0.2.1')
        self.group = self.manager.join(self.first, spec())

    def test_a_member_joining_an_empty_group_owes_no_catch_up(self):
        late = FakePeer('192.0.2.2')
        self.assertFalse(self.group.add(late))
        self.assertEqual([], self.group.catchup())
        self.assertEqual(0, self.group.replay(late))

    def test_a_brand_new_group_is_not_seeded_even_owing_no_catch_up(self):
        # Two different questions that a single boolean would conflate.
        # "Nobody owes a replay" is true of a brand new group, and the
        # plugin still has to walk the Loc-RIB once to offer it the
        # table; `seeded` is that second question.
        self.assertEqual([], self.group.catchup())
        self.assertFalse(self.group.seeded)
        self.group.mark_seeded()
        self.assertTrue(self.group.seeded)
        self.assertEqual([], self.group.catchup())

    def test_a_member_joining_a_group_that_knows_things_is_reported(self):
        self.group.announce(dest(NET_A))
        self.group.flush()
        late = FakePeer('192.0.2.2')
        self.assertTrue(self.manager.join(late, spec()) is self.group)
        self.assertEqual(['192.0.2.2'], self.group.catchup())

    def test_a_replay_sends_the_record_and_disturbs_nothing_else(self):
        self.group.announce(dest(NET_A))
        self.group.announce(dest(NET_B))
        self.group.flush()
        del self.first.sent[:]
        late = FakePeer('192.0.2.2')
        self.manager.join(late, spec())
        advertised = self.group.out.advertised_count()

        sent = self.group.replay(late)

        self.assertTrue(sent > 0)
        self.assertEqual(sent, len(late.messages()))
        # Encoded from the record, not from the staging area: the staging
        # area was empty before the replay and must still be, or the next
        # flush would re-announce the whole table to every member.
        self.assertEqual(0, self.group.pending())
        self.assertEqual(advertised, self.group.out.advertised_count())
        self.assertEqual([], self.first.sent)
        # And the debt is discharged, so a second pass does not send it
        # all again.
        self.assertEqual([], self.group.catchup())
        self.assertEqual(0, self.group.replay(late))
        self.assertEqual(1, self.group.stats()['replays'])

    def test_a_replay_counts_as_group_messages_and_as_writes(self):
        self.group.announce(dest(NET_A))
        self.group.flush()
        before = self.group.stats()
        late = FakePeer('192.0.2.2')
        self.manager.join(late, spec())

        sent = self.group.replay(late)

        after = self.group.stats()
        self.assertEqual(before['group-messages'] + sent,
                         after['group-messages'])
        self.assertEqual(before['writes'] + sent, after['writes'])
        # A replay is not a flush: the group's staging area never ran, so
        # counting it as one would make the MRAI arithmetic wrong as well
        # as the report.
        self.assertEqual(before['flushes'], after['flushes'])

    def test_a_forced_replay_serves_the_route_refresh_path(self):
        # A peer that asks for a route refresh owes no catch-up and must
        # still be re-sent the record -- for one member of a group, which
        # is why this is the same mechanism rather than a group reset.
        self.group.announce(dest(NET_A))
        self.group.flush()
        del self.first.sent[:]

        sent = self.group.replay(self.first, force=True)

        self.assertTrue(sent > 0)
        self.assertEqual(sent, len(self.first.messages()))
        self.assertEqual(0, self.group.pending())

    def test_a_replay_to_a_member_that_is_down_sends_nothing(self):
        self.group.announce(dest(NET_A))
        self.group.flush()
        late = FakePeer('192.0.2.2')
        self.manager.join(late, spec())
        late.established = False
        self.assertEqual(0, self.group.replay(late))
        self.assertEqual([], late.sent)

    def test_resetting_a_group_puts_every_member_back_in_the_queue(self):
        # The group-wide counterpart: correct when the group's policy
        # changed under it and *every* member must be re-advertised to.
        second = FakePeer('192.0.2.2')
        self.manager.join(second, spec())
        self.group.announce(dest(NET_A))
        self.group.flush()
        self.group.mark_seeded()

        self.group.reset()

        self.assertEqual(0, self.group.out.advertised_count())
        self.assertFalse(self.group.seeded)
        self.assertEqual(['192.0.2.1', '192.0.2.2'], self.group.catchup())


class MinimumAdvertisementIntervalTestCase(unittest.TestCase):
    """MRAI holds announcements back, and never a withdrawal.

    The interval is per group rather than per destination -- the same
    simplification FRR makes -- so the exemptions are what keep it
    honest. Every assertion here moves a clock the test owns; nothing
    sleeps.
    """

    def setUp(self):
        self.clock = FakeClock()
        self.manager = UpdateGroupManager(clock=self.clock)
        self.peer = FakePeer('192.0.2.1')

    def group_with(self, mrai):
        """Return a one-member group with the given interval."""
        return self.manager.join(self.peer, spec(mrai=mrai))

    def test_a_group_without_an_interval_sends_every_time(self):
        group = self.group_with(0.0)
        for prefix in (NET_A, NET_B, NET_C):
            group.announce(dest(prefix))
            self.assertEqual(1, group.flush())
        self.assertEqual(3, group.stats()['flushes'])
        self.assertEqual(0, group.stats()['deferrals'])

    def test_the_first_flush_of_a_quiet_group_is_exempt(self):
        # A session that has just come up must not wait out an interval
        # it has never used; the peer would look broken for 30 seconds.
        group = self.group_with(30.0)
        group.announce(dest(NET_A))
        self.assertTrue(group.due())
        self.assertEqual(0.0, group.due_in())
        self.assertEqual(1, group.flush())
        self.assertEqual(self.clock.now, group.last_send)

    def test_a_second_flush_inside_the_interval_is_deferred(self):
        group = self.group_with(30.0)
        group.announce(dest(NET_A))
        group.flush()
        del self.peer.sent[:]

        self.clock.advance(5.0)
        self.assertTrue(group.announce(dest(NET_B)))
        self.assertFalse(group.due())
        self.assertEqual(0, group.flush())

        self.assertEqual(1, group.stats()['deferrals'])
        self.assertEqual([], self.peer.sent)
        # Deferred, not dropped: the change is still staged and the
        # report says how long it has to wait, which is the difference
        # between an operator seeing rate limiting and seeing a bug.
        self.assertEqual(1, group.pending())
        self.assertEqual(25.0, group.due_in())
        self.assertEqual(25.0, group.stats()['due-in'])

    def test_advancing_past_the_interval_releases_the_deferred_change(self):
        group = self.group_with(30.0)
        group.announce(dest(NET_A))
        group.flush()
        group.announce(dest(NET_B))
        group.flush()
        del self.peer.sent[:]

        self.clock.advance(30.0)

        self.assertTrue(group.due())
        self.assertEqual(0.0, group.due_in())
        self.assertEqual(1, group.flush())
        self.assertEqual(0, group.pending())
        # One message for the change that flapped inside the interval,
        # which is the saving the interval exists to make.
        self.assertEqual(1, len(self.peer.messages()))

    def test_a_staged_withdrawal_ignores_the_interval(self):
        # The exemption that matters most: a delayed withdrawal is a
        # black hole, while a delayed announcement is only slower
        # convergence.
        group = self.group_with(30.0)
        announced = dest(NET_A)
        group.announce(announced)
        group.flush()
        del self.peer.sent[:]

        self.clock.advance(1.0)
        self.assertTrue(group.withdraw(announced.prefix))

        self.assertTrue(group.due())
        self.assertEqual(0.0, group.due_in())
        self.assertEqual(1, group.flush())
        self.assertEqual(0, group.stats()['deferrals'])

    def test_a_withdrawal_does_not_carry_a_deferred_announcement(self):
        """B-10: only the withdrawal is exempt from the interval.

        This used to send both: the exemption was a property of the
        staging area, so any withdrawal released every held announcement
        with it, and a peer flapping one prefix defeated MRAI for all the
        others. The announcement now waits out the interval, which keeps
        running from the last announcement.
        """
        group = self.group_with(30.0)
        first = dest(NET_A)
        group.announce(first)
        group.flush()
        del self.peer.sent[:]

        self.clock.advance(1.0)
        group.announce(dest(NET_B))
        self.assertEqual(0, group.flush())
        group.withdraw(first.prefix)

        self.assertEqual(1, group.flush())
        self.assertEqual(1, group.pending())
        self.assertEqual(1, group.out.pending_announcements())
        self.assertGreater(group.due_in(), 28.0)

        self.clock.advance(29.0)
        self.assertEqual(1, group.flush())
        self.assertEqual(0, group.pending())
        self.assertEqual(3, group.stats()['flushes'])

    def test_force_ignores_the_interval_for_a_soft_clear(self):
        # An operator who typed `clear ip bgp ... soft out` and watched
        # nothing happen for 30 seconds would reasonably conclude the
        # command is broken.
        group = self.group_with(30.0)
        group.announce(dest(NET_A))
        group.flush()
        del self.peer.sent[:]

        self.clock.advance(1.0)
        group.announce(dest(NET_B))

        self.assertFalse(group.due())
        self.assertEqual(1, group.flush(force=True))
        self.assertEqual(0, group.pending())

    def test_due_in_is_zero_when_there_is_nothing_to_send(self):
        # Not "the time until the interval expires": a group with an
        # empty staging area is not waiting for anything, and reporting a
        # countdown would read as a message being held.
        group = self.group_with(30.0)
        group.announce(dest(NET_A))
        group.flush()
        self.clock.advance(1.0)
        self.assertFalse(group.due())
        self.assertEqual(0.0, group.due_in())

    def test_the_manager_passes_one_moment_to_every_group(self):
        # Every group in a pass is judged against the same timestamp, so
        # two groups configured alike cannot disagree about whether their
        # interval has elapsed because the clock moved between them.
        second = FakePeer('192.0.2.2')
        one = self.manager.join(self.peer, spec(mrai=30.0))
        two = self.manager.join(second, spec(mrai=30.0, max_size=2048))
        self.manager.announce(AF_V4, dest(NET_A))
        self.assertEqual(2, self.manager.flush())
        self.assertEqual(one.last_send, two.last_send)

        self.clock.advance(5.0)
        self.manager.announce(AF_V4, dest(NET_B))
        self.assertEqual(0, self.manager.flush())
        self.assertEqual(1, one.stats()['deferrals'])
        self.assertEqual(1, two.stats()['deferrals'])
        self.assertEqual(2, self.manager.pending())

        self.assertEqual(2, self.manager.flush(force=True))


class OutboundPolicyThroughAGroupTestCase(unittest.TestCase):
    """A real policy store, a real chain, and one shared transform.

    ``test_rtengine_policy.py`` tests the chain on its own. What is left
    to pin here is the seam: that a denied prefix is suppressed for the
    *group* and counted as a policy suppression rather than vanishing,
    that a permitted one carries the rewritten attributes, that the
    rewrite never touches the interned set the Loc-RIB is holding, and
    that editing a route-map is what moves peers between groups.
    """

    #: A prefix-list that denies one documentation prefix and permits the
    #: rest, and a route-map that rewrites three attributes. Small on
    #: purpose: the point is the wiring, not the policy language.
    DOCUMENT = {
        'ip': {
            'prefix-list': {
                'PL-OUT': [
                    {'seq': 5, 'action': 'deny', 'prefix': NET_DENIED},
                    {'seq': 10, 'action': 'permit', 'prefix': '0.0.0.0/0',
                     'le': 32},
                ],
            },
        },
        'route-map': {
            'RM-OUT': [
                {'seq': 10, 'action': 'permit',
                 'set': {'local-preference': 250, 'metric': 77,
                         'community': ['65000:7']}},
            ],
        },
    }

    NAMES = {'prefix-list': 'PL-OUT', 'route-map': 'RM-OUT'}

    def setUp(self):
        self.store = PolicyStore()
        self.store.load(self.DOCUMENT)
        self.clock = FakeClock()
        self.manager = UpdateGroupManager(clock=self.clock)
        # An internal group, so that `set local-preference` is an
        # attribute the session may actually carry; an external peer
        # would have LOCAL_PREF stripped by the transform and the test
        # would be asserting something the wire does not do.
        self.peer = FakePeer('192.0.2.1', peer_as=LOCAL_AS, is_ebgp=False)
        self.group = self.manager.join(self.peer, self.build_spec())

    def policy_id(self):
        """Return the ``(kind, name, version)`` triples for the key.

        Mirrors ``plugin._policy_id``: the version of each named object is
        part of the identity, not just its name.
        """
        return tuple(sorted(
            (kind, name, self.store.version_of(kind, name))
            for kind, name in (('prefix-list', 'PL-OUT'),
                               ('route-map', 'RM-OUT'))))

    def build_spec(self):
        """Return the internal group's spec for the store as it stands."""
        chain = policy_mod.build_chain(
            policy_mod.DIR_OUT, self.store, self.NAMES, local_as=LOCAL_AS,
            afi=AFI_IP)
        return spec(is_ebgp=False, peer_as=LOCAL_AS, policy=chain,
                    policy_id=self.policy_id())

    def test_a_denied_prefix_is_withheld_and_counted_as_policy(self):
        denied = dest(NET_DENIED)
        # Nothing is staged at all: the suppression happens as the
        # destination is offered, so the group never encodes a message it
        # then has to decide not to send.
        self.assertFalse(self.group.announce(denied))
        self.assertEqual(0, self.group.pending())
        self.assertEqual(0, self.group.flush())
        self.assertIsNone(self.group.out.advertised(denied.prefix))
        # Counted under its own reason, so `show` can distinguish "policy
        # withheld this" from "the path never arrived" -- the two look
        # identical from the peer's side and need different fixes.
        suppressed = self.group.out.stats()['suppressed']
        self.assertEqual(1, suppressed[adjout_mod.SUPPRESS_POLICY])
        self.assertEqual(1, self.group.out.stats()['suppressed-total'])

    def test_a_permitted_prefix_carries_the_rewritten_attributes(self):
        permitted = dest(NET_PERMITTED)
        self.assertTrue(self.group.announce(permitted))
        self.assertEqual(1, self.group.flush())

        advertised = self.group.out.advertised(permitted.prefix)
        self.assertIsNotNone(advertised)
        self.assertTrue(advertised.has_local_pref())
        self.assertEqual(250, advertised.local_pref)
        self.assertEqual(77, advertised.med)
        # 65000:7 on the wire, which is what `set community` was asked
        # for; asserted as bytes because that is what the encoder reads.
        self.assertEqual(b'\xfd\xe8\x00\x07', advertised.communities)

    def test_the_group_never_hands_out_the_interned_attribute_set(self):
        # The Loc-RIB interns attribute sets and shares one object
        # between every path that carries the same attributes. A
        # transform that rewrote in place would change what every other
        # peer -- and the RIB itself -- believes the path says, so the
        # separate object is not an implementation detail but the
        # invariant that makes outbound policy safe at all.
        permitted = dest(NET_PERMITTED)
        original = permitted.best.attrs
        self.group.announce(permitted)
        self.group.flush()

        advertised = self.group.out.advertised(permitted.prefix)
        self.assertIsNot(original, advertised)
        self.assertFalse(original.has_local_pref())
        self.assertEqual(b'', original.communities)

    def test_a_permit_all_chain_leaves_the_stream_alone(self):
        # The control case for the two above: with no policy configured
        # the group advertises what the RIB holds and says so in `show`.
        plain = FakePeer('203.0.113.1')
        group = self.manager.join(plain, spec(
            policy=policy_mod.PERMIT_ALL_OUT))
        self.assertTrue(group.announce(dest(NET_DENIED)))
        self.assertEqual(1, group.flush())
        self.assertEqual(0, group.out.stats()['suppressed-total'])
        self.assertIsNone(group.as_dict()['policy'])

    def test_editing_the_route_map_moves_the_peer_to_a_new_group(self):
        # The reason versions are in the key. An edited route-map means
        # the encoded stream the old group is producing no longer matches
        # the peer's policy, and the peer has to leave that group for one
        # built under the new rules.
        before = self.group.key
        edited = json.loads(json.dumps(self.DOCUMENT))
        edited['route-map']['RM-OUT'][0]['set']['metric'] = 78
        self.store.load(edited)

        after_spec = self.build_spec()
        self.assertEqual(['policy'], before.differences(after_spec.key()))

        moved = self.manager.join(self.peer, after_spec)
        self.assertIsNot(self.group, moved)
        self.assertEqual(1, self.manager.stats()['moves'])
        self.assertIs(moved.out, self.peer.adjout[AF_V4])
        # The new group starts empty, so the peer is re-advertised to by
        # the next staging pass rather than being left with whatever the
        # old group's record happened to say.
        self.assertEqual(0, moved.out.advertised_count())
        self.assertFalse(moved.seeded)

    def test_reloading_an_unchanged_document_moves_nobody(self):
        # The other half of the same claim, and the more important one in
        # practice: a commit that edited something unrelated must not
        # bump a version, because every peer naming that route-map would
        # be rebuilt and re-advertised to for nothing.
        self.store.load(self.DOCUMENT)
        again = self.manager.join(self.peer, self.build_spec())
        self.assertIs(self.group, again)
        self.assertEqual(0, self.manager.stats()['moves'])

    def test_two_peers_under_one_policy_share_one_group(self):
        # The saving, stated directly: identical policy means identical
        # keys means one encode for both.
        second = FakePeer('192.0.2.2', peer_as=LOCAL_AS, is_ebgp=False)
        group = self.manager.join(second, self.build_spec())
        self.assertIs(self.group, group)
        self.assertEqual(1, len(self.manager))
        self.group.announce(dest(NET_PERMITTED))
        self.assertEqual(2, self.group.flush())
        self.assertEqual(1, self.group.stats()['group-messages'])


class ReportingTestCase(unittest.TestCase):
    """``show`` output is a dict of plain types, all the way down.

    The operational surface is rendered as JSON by the engine's show
    commands, so a value that is a raw byte string or a tuple is not a
    cosmetic problem -- it is a traceback in front of an operator who was
    trying to diagnose something else.
    """

    def setUp(self):
        self.clock = FakeClock()
        self.manager = UpdateGroupManager(clock=self.clock)
        self.peer = FakePeer('192.0.2.1')
        self.other = FakePeer('192.0.2.2')
        self.group = self.manager.join(self.peer, spec(mrai=30.0))
        self.manager.join(self.other, spec(mrai=30.0))
        self.group.announce(dest(NET_A))
        self.group.flush()

    def test_a_group_reports_every_counter_the_show_command_promises(self):
        stats = self.group.stats()
        for field in ('member-count', 'mrai', 'flushes', 'group-messages',
                      'writes', 'deferrals', 'replays', 'catchup',
                      'seeded', 'due-in'):
            self.assertIn(field, stats)
        self.assertEqual(2, stats['member-count'])
        self.assertEqual(30.0, stats['mrai'])
        self.assertEqual(1, stats['flushes'])
        self.assertEqual(1, stats['group-messages'])
        self.assertEqual(2, stats['writes'])
        self.assertEqual(0, stats['deferrals'])
        self.assertEqual(0, stats['replays'])
        self.assertEqual([], stats['catchup'])
        self.assertFalse(stats['seeded'])
        self.assertEqual(0.0, stats['due-in'])
        # Inherited from the shared table, because the group's report is
        # the table's report plus the group's own counters -- an operator
        # asking about a group should not have to ask twice.
        self.assertEqual(1, stats['advertised'])
        self.assertEqual(['192.0.2.1', '192.0.2.2'], stats['members'])

    def test_a_group_renders_as_json(self):
        document = json.loads(json.dumps(self.group.as_dict()))
        self.assertEqual(self.group.gid, document['id'])
        self.assertIn('key', document)

    def test_the_key_renders_with_its_component_names(self):
        # Not a tuple of twenty anonymous values: `show ip bgp
        # update-groups` prints this, and the whole reason `differences()`
        # exists is that a human has to be able to read why two peers did
        # not merge.
        document = self.group.as_dict()['key']
        self.assertEqual(sorted(UpdateGroupKey.FIELDS), sorted(document))
        self.assertEqual(AFI_IP, document['afi'])
        self.assertEqual(PEER_AS, document['peer-as'])
        self.assertEqual(30.0, document['mrai'])
        # Hex rather than raw bytes, which is the one field that would
        # otherwise make the document unserialisable.
        self.assertEqual(LOCAL_ADDR.hex(), document['local-addr'])
        self.assertIsNone(document['unique'])

    def test_a_manager_renders_every_group_as_json(self):
        document = json.loads(json.dumps(self.manager.as_dict()))
        self.assertEqual(1, document['groups'])
        self.assertEqual(2, document['memberships'])
        self.assertEqual(1, len(document['items']))
        for field in ('created', 'destroyed', 'joins', 'moves', 'leaves',
                      'pending'):
            self.assertIn(field, document)

    def test_a_group_with_a_policy_renders_its_policy_too(self):
        store = PolicyStore()
        store.load({'route-map': {'RM-OUT': [
            {'seq': 10, 'action': 'permit', 'set': {'metric': 5}}]}})
        chain = policy_mod.build_chain(
            policy_mod.DIR_OUT, store, {'route-map': 'RM-OUT'},
            local_as=LOCAL_AS, afi=AFI_IP)
        third = FakePeer('203.0.113.1')
        group = self.manager.join(third, spec(
            policy=chain,
            policy_id=(('route-map', 'RM-OUT',
                        store.version_of('route-map', 'RM-OUT')),)))
        document = json.loads(json.dumps(group.as_dict()))
        self.assertIsNotNone(document['policy'])
        self.assertEqual([['route-map', 'RM-OUT',
                           store.version_of('route-map', 'RM-OUT')]],
                         document['key']['policy'])

    def test_a_group_repr_says_what_it_holds(self):
        text = repr(self.group)
        self.assertIn('members=2', text)
        self.assertIn('advertised=1', text)
        self.assertIn('groups=1', repr(self.manager))

    def test_a_group_built_directly_takes_the_clock_it_is_given(self):
        # The constructor is exercised on its own because the plugin is
        # not the only caller: a group built without the manager must
        # still honour the injected clock, or a future caller would get
        # the wall clock and an untestable interval.
        clock = FakeClock(now=5.0)
        peer = FakePeer('203.0.113.9')
        group = UpdateGroup(99, spec(mrai=10.0), peer.peer_ref, clock=clock)
        group.add(peer)
        group.announce(dest(NET_A))
        group.flush()
        self.assertEqual(5.0, group.last_send)
        clock.advance(1.0)
        group.announce(dest(NET_B))
        self.assertEqual(0, group.flush())
        self.assertEqual(9.0, group.due_in())


if __name__ == '__main__':
    unittest.main()
