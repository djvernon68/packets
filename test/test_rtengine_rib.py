#!/usr/bin/env python

"""Tests for the protocol-neutral routing RIB in packets.routing.rtengine.rib.

Three modules, three kinds of risk, and the suite is shaped around the risks
rather than around the source layout:

  * ``prefix`` is the key every other structure is indexed by, so the things
    that must hold are the algebraic ones -- host-bit masking makes
    10.0.0.1/8 and 10.0.0.0/8 the same key, equality and ``hash`` agree so a
    Prefix is usable as a dict key, and the total order is the trie's
    traversal order so ``sorted()`` of a table's keys and an ordered walk of
    it cannot disagree. Parsing is the configuration boundary, so every
    malformed spelling is pinned to ``ValueError`` individually; a parser
    that accepts ``'10.0.0.0/+8'`` installs a route somewhere unintended.

  * ``trie`` is the only hand-written data structure here, and the only code
    in the RIB doing its own memory and reference-count management. Spot
    assertions are close to worthless against a path-compressed radix trie:
    the interesting states are the edge splits, the glue nodes and their
    removal, and those are reached by workloads rather than by examples. So
    the trie is checked against a dict-plus-linear-scan oracle over
    thousands of randomised operations, with the seeds fixed so a failure is
    reproducible. The structural cases the oracle cannot see -- how many
    nodes exist, whether a glue node was collapsed, whether a stored value
    was leaked -- are asserted directly through the ``nodes`` counter,
    ``sys.getrefcount`` and ``weakref``.

  * ``table`` is policy: which of several offers wins, and when the winner
    is allowed to change. ``route_cmp`` has four tie-breaks in a documented
    order, so there is one test per tie-break, each built so that only the
    tie-break under test can decide the outcome, plus a permutation test
    because a comparison that is right but an insertion order that leaks
    through is still a table that flaps. The change queue is tested for what
    it promises: collapsing repeated changes to one selection, honouring a
    caller's limit, and reporting a withdrawal before dropping the entry.

Written as plain ``unittest.TestCase`` with no pytest features: the 3.6.8
verification host has no pytest and runs this through
``python3 -m unittest discover -s test``.
"""

import gc
import itertools
import pickle
import random
import socket
import sys
import unittest
import weakref

from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, \
    MAX_ADDR_BYTES, SAFI_UNICAST, Prefix, afi_for_family, family_for_afi, \
    parse_prefix
from packets.routing.rtengine.rib.table import DEFAULT_ADMIN_DISTANCE, \
    FIB_STATE_ERROR, FIB_STATE_INSTALLED, FIB_STATE_NONE, \
    FIB_STATE_ORPHANED, FIB_STATE_PENDING, PROTO_BGP, PROTO_CONNECTED, \
    PROTO_IDS, PROTO_NAMES, PROTO_OSPF, PROTO_RIP, PROTO_STATIC, \
    PROTO_UNSPEC, Dest, Route, RouteTable
from packets.routing.rtengine.rib.trie import Trie

V4_ZERO = b'\x00' * 4
V6_ZERO = b'\x00' * 16

# Per-family constants, keyed by AFI so a test body can be family-agnostic
# and still be run twice. Deriving them from the AFI in each test would just
# be the same branch written many times.
ALEN = {AFI_IP: 4, AFI_IP6: 16}
ABITS = {AFI_IP: 32, AFI_IP6: 128}
# Root prefixes are generated no longer than this, so that the extensions
# built beneath them have room to nest.
ROOT_MAX_PLEN = {AFI_IP: 24, AFI_IP6: 48}


def _pack(value, alen):
    """Pack an address held as an int into ``alen`` big-endian bytes."""
    return value.to_bytes(alen, 'big')


def _unpack(addr):
    """Unpack a packed address into an int."""
    return int.from_bytes(addr, 'big')


def _rand_bits(rng, count):
    """``rng.getrandbits(count)``, tolerating a zero-width request.

    ``getrandbits(0)`` returns 0 from Python 3.9 onward but raises
    ``ValueError`` on 3.6, and the deployment target is 3.6.8. A zero width
    is reached whenever the host bits of a prefix are filled in at random
    and the prefix is already a host route (/32 or /128), which the random
    pools here do generate -- it cost an error on cnp02 that the Mac could
    not reproduce.
    """
    if count <= 0:
        return 0
    return rng.getrandbits(count)


def _rand_root(rng, afi):
    """A random prefix of moderate length, to be extended beneath."""
    alen = ALEN[afi]
    return Prefix(afi, rng.randint(0, ROOT_MAX_PLEN[afi]),
                  _pack(rng.getrandbits(ABITS[afi]), alen))


def _rand_below(rng, afi, parent):
    """A random prefix strictly more specific than ``parent``.

    Deriving keys from keys already in the pool is the only way to get a
    generated set that actually nests. Independently random prefixes almost
    never cover one another, which would leave longest-prefix match, the
    ancestor-splice path in ``node_intern`` and glue-node collapse all
    effectively untested however many operations the workload runs.
    """
    abits = ABITS[afi]
    alen = ALEN[afi]
    if parent.plen >= abits:
        return parent
    # Cap the step so the pool spreads over many lengths rather than jumping
    # straight to host routes.
    plen = rng.randint(parent.plen + 1, min(abits, parent.plen + 24))
    # The parent is masked, so every bit below its length is zero and the OR
    # cannot disturb the bits the two keys must share.
    noise = rng.getrandbits(abits - parent.plen)
    return Prefix(afi, plen, _pack(_unpack(parent.packed()) | noise, alen))


def _make_pool(rng, afi, size):
    """Build a list of prefixes for a randomised workload.

    Duplicates are deliberately not removed: re-offering a key the trie
    already holds is what exercises the replace-and-release path and the
    previous-value return, and a de-duplicated pool would never do it.
    """
    pool = [Prefix(afi, 0, b'\x00' * ALEN[afi])]
    while len(pool) < size:
        if rng.random() < 0.55:
            pool.append(_rand_below(rng, afi, rng.choice(pool)))
        else:
            pool.append(_rand_root(rng, afi))
    return pool


def _oracle_lpm(oracle, query):
    """Longest covering key in ``oracle``, by brute force over every key.

    ``Prefix.contains`` is the definition being checked against, and it is
    independent of the trie: it compares two masked addresses directly with
    no descent, no path compression and no glue nodes.
    """
    best = None
    for key in oracle:
        if key.contains(query):
            if best is None or key.plen > best.plen:
                best = key
    return best


class Holder(object):
    """A weak-referenceable, identity-compared value for the trie tests.

    ``object()`` cannot carry a weakref and a str may be interned, either of
    which would make a reference-count assertion measure the wrong thing.
    """

    __slots__ = ('tag', '__weakref__')

    def __init__(self, tag=''):
        self.tag = tag


def _route(prefix, protocol=PROTO_BGP, distance=20, metric=0,
           nexthop=b'\x0a\x00\x00\x01', source=None, recv_time=100.0):
    """A Route with every selection input pinned.

    ``recv_time`` defaults to a fixed value rather than "now" so that the
    age tie-break cannot decide a test that is about something else, and
    ``source`` defaults to a fresh object so two calls are two distinct
    origins unless a test says otherwise.
    """
    if source is None:
        source = object()
    return Route(prefix, protocol, distance, metric, nexthop, source,
                 recv_time)


class PrefixMaskingTestCase(unittest.TestCase):
    """Host bits must be gone by the time a Prefix exists."""

    def test_ipv4_host_bits_are_masked(self):
        p = Prefix(AFI_IP, 8, b'\x0a\x00\x00\x01')
        self.assertEqual(p.packed(), b'\x0a\x00\x00\x00')
        self.assertEqual(p.to_str(), '10.0.0.0/8')

    def test_ipv6_host_bits_are_masked(self):
        p = Prefix(AFI_IP6, 32, socket.inet_pton(socket.AF_INET6,
                                                 '2001:db8:dead:beef::1'))
        self.assertEqual(p.packed(),
                         socket.inet_pton(socket.AF_INET6, '2001:db8::'))

    def test_a_partial_byte_length_masks_only_the_bits_above_it(self):
        # A /12 keeps four bits of the second byte and drops the other four,
        # which is the case a byte-granular mask would get wrong.
        p = Prefix(AFI_IP, 12, b'\x0a\xff\xff\xff')
        self.assertEqual(p.packed(), b'\x0a\xf0\x00\x00')

    def test_default_route_masks_to_all_zeros(self):
        self.assertEqual(Prefix(AFI_IP, 0, b'\xff\xff\xff\xff').packed(),
                         V4_ZERO)
        self.assertEqual(Prefix(AFI_IP6, 0, b'\xff' * 16).packed(), V6_ZERO)

    def test_host_length_keeps_every_bit(self):
        self.assertEqual(Prefix(AFI_IP, 32, b'\x0a\x01\x02\x03').packed(),
                         b'\x0a\x01\x02\x03')
        self.assertEqual(Prefix(AFI_IP6, 128, b'\xab' * 16).packed(),
                         b'\xab' * 16)

    def test_a_non_canonical_prefix_cannot_create_a_second_key(self):
        # This is the property the masking exists for: a peer advertising a
        # sloppy prefix must land on the destination that already exists.
        sloppy = parse_prefix('10.0.0.1/8')
        canonical = parse_prefix('10.0.0.0/8')
        self.assertEqual(sloppy, canonical)
        trie = Trie(AFI_IP)
        trie.insert(canonical, 'first')
        self.assertEqual(trie.insert(sloppy, 'second'), 'first')
        self.assertEqual(len(trie), 1)


class PrefixEqualityTestCase(unittest.TestCase):
    """Equality, hash and dict-key interchangeability must agree."""

    def test_equal_prefixes_are_equal_and_hash_equal(self):
        a = parse_prefix('10.0.0.0/8')
        b = Prefix(AFI_IP, 8, b'\x0a\x00\x00\x00')
        self.assertIsNot(a, b)
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))

    def test_equal_prefixes_are_interchangeable_as_dict_keys(self):
        a = parse_prefix('2001:db8::/32')
        b = parse_prefix('2001:db8:0:0:0:0:0:0/32')
        table = {a: 'value'}
        self.assertIn(b, table)
        table[b] = 'replaced'
        self.assertEqual(len(table), 1)
        self.assertEqual(table[a], 'replaced')

    def test_a_different_length_is_a_different_key(self):
        a = parse_prefix('10.0.0.0/8')
        b = parse_prefix('10.0.0.0/16')
        self.assertNotEqual(a, b)
        self.assertEqual(len({a: 1, b: 2}), 2)

    def test_a_different_family_is_a_different_key(self):
        # Both mask to all zeros, so only the family can tell them apart --
        # which is exactly why the family is part of the hash.
        a = parse_prefix('0.0.0.0/0')
        b = parse_prefix('::/0')
        self.assertNotEqual(a, b)
        self.assertEqual(len({a: 1, b: 2}), 2)

    def test_hash_is_never_the_error_value(self):
        # CPython reserves -1 for "hash failed" and would recompute the hash
        # on every lookup of a key that legitimately produced it.
        rng = random.Random(20190301)
        for _ in range(4000):
            p = Prefix(AFI_IP, rng.randint(0, 32),
                       _pack(rng.getrandbits(32), 4))
            self.assertNotEqual(hash(p), -1)
        for _ in range(4000):
            p = Prefix(AFI_IP6, rng.randint(0, 128),
                       _pack(rng.getrandbits(128), 16))
            self.assertNotEqual(hash(p), -1)


class PrefixOrderTestCase(unittest.TestCase):
    """The total order is the trie's traversal order."""

    def test_sorted_orders_by_family_then_address_then_length(self):
        mixed = [parse_prefix('10.1.0.0/16'),
                 parse_prefix('2001:db8::/32'),
                 parse_prefix('::/0'),
                 parse_prefix('10.0.0.0/16'),
                 parse_prefix('10.0.0.0/8'),
                 parse_prefix('0.0.0.0/0'),
                 parse_prefix('11.0.0.0/8')]
        self.assertEqual([p.to_str() for p in sorted(mixed)],
                         ['0.0.0.0/0', '10.0.0.0/8', '10.0.0.0/16',
                          '10.1.0.0/16', '11.0.0.0/8', '::/0',
                          '2001:db8::/32'])

    def test_a_prefix_sorts_immediately_before_everything_beneath_it(self):
        # The property show output and API pagination depend on: a covering
        # prefix precedes its children, and a sibling subtree follows all of
        # them.
        covering = parse_prefix('10.0.0.0/8')
        beneath = parse_prefix('10.0.0.0/16')
        sibling = parse_prefix('10.1.0.0/16')
        self.assertLess(covering, beneath)
        self.assertLess(beneath, sibling)
        self.assertGreater(sibling, covering)

    def test_every_ordering_operator_agrees_with_the_comparison(self):
        a = parse_prefix('10.0.0.0/8')
        b = parse_prefix('10.0.0.0/16')
        same = parse_prefix('10.0.0.0/8')
        self.assertTrue(a < b)
        self.assertTrue(a <= b)
        self.assertTrue(a <= same)
        self.assertTrue(b > a)
        self.assertTrue(b >= a)
        self.assertTrue(a >= same)
        self.assertFalse(a > b)
        self.assertFalse(b <= a)

    def test_order_is_a_strict_total_order_over_a_random_set(self):
        rng = random.Random(20190302)
        prefixes = _make_pool(rng, AFI_IP, 60) + _make_pool(rng, AFI_IP6, 60)
        for a, b in itertools.combinations(prefixes, 2):
            if a == b:
                self.assertFalse(a < b)
                self.assertFalse(b < a)
            else:
                self.assertEqual(a < b, not b < a)
                self.assertEqual(a < b, b > a)

    def test_equality_against_a_non_prefix_answers_rather_than_raising(self):
        p = parse_prefix('10.0.0.0/8')
        for other in (5, '10.0.0.0/8', None, object(), (1, 8)):
            self.assertFalse(p == other)
            self.assertTrue(p != other)

    def test_ordering_against_a_non_prefix_raises_type_error(self):
        # __richcmp__ returns NotImplemented rather than inventing an
        # answer, which is what lets Python raise this.
        p = parse_prefix('10.0.0.0/8')
        for other in (5, '10.0.0.0/8', None):
            with self.assertRaises(TypeError):
                p < other
            with self.assertRaises(TypeError):
                p >= other


class PrefixContainsTestCase(unittest.TestCase):
    """The covering test a resolver and a prefix-list bound both need."""

    def test_a_prefix_contains_itself(self):
        p = parse_prefix('10.0.0.0/8')
        self.assertTrue(p.contains(parse_prefix('10.0.0.0/8')))

    def test_a_more_specific_prefix_inside_is_contained(self):
        p = parse_prefix('10.0.0.0/8')
        self.assertTrue(p.contains(parse_prefix('10.1.2.0/24')))
        self.assertTrue(p.contains(parse_prefix('10.255.255.255/32')))

    def test_a_more_specific_prefix_outside_is_not_contained(self):
        p = parse_prefix('10.0.0.0/8')
        self.assertFalse(p.contains(parse_prefix('11.1.2.0/24')))

    def test_a_less_specific_prefix_is_never_contained(self):
        # Even though the addresses match: containment is not a bare address
        # match, or a /24 would "contain" the /8 it sits under.
        p = parse_prefix('10.0.0.0/16')
        self.assertFalse(p.contains(parse_prefix('10.0.0.0/8')))
        self.assertFalse(p.contains(parse_prefix('0.0.0.0/0')))

    def test_families_never_contain_each_other(self):
        self.assertFalse(parse_prefix('0.0.0.0/0').contains(
            parse_prefix('2001:db8::/32')))
        self.assertFalse(parse_prefix('::/0').contains(
            parse_prefix('10.0.0.0/8')))

    def test_the_default_route_contains_everything_in_its_family(self):
        rng = random.Random(20190303)
        v4_default = parse_prefix('0.0.0.0/0')
        for _ in range(500):
            self.assertTrue(v4_default.contains(_rand_root(rng, AFI_IP)))
            self.assertTrue(v4_default.contains(
                Prefix(AFI_IP, 32, _pack(rng.getrandbits(32), 4))))
        v6_default = parse_prefix('::/0')
        for _ in range(500):
            self.assertTrue(v6_default.contains(_rand_root(rng, AFI_IP6)))
            self.assertTrue(v6_default.contains(
                Prefix(AFI_IP6, 128, _pack(rng.getrandbits(128), 16))))

    def test_contains_none_is_false(self):
        self.assertFalse(parse_prefix('0.0.0.0/0').contains(None))

    def test_a_partial_byte_boundary_is_respected(self):
        # 10.16.0.0 shares the first twelve bits with 10.0.0.0 but not the
        # thirteenth, so a /12 covers it and a /13 does not.
        p12 = parse_prefix('10.0.0.0/12')
        p13 = parse_prefix('10.0.0.0/13')
        candidate = parse_prefix('10.8.0.0/24')
        self.assertTrue(p12.contains(candidate))
        self.assertFalse(p13.contains(candidate))


class PrefixAccessorTestCase(unittest.TestCase):
    """The read-only surface, and the representations built on it."""

    def test_packed_is_the_full_family_width(self):
        # Not the wire-truncated form: callers build next-hops and netlink
        # attributes from this.
        self.assertEqual(len(parse_prefix('10.0.0.0/8').packed()), 4)
        self.assertEqual(len(parse_prefix('10.0.0.0/32').packed()), 4)
        self.assertEqual(len(parse_prefix('2001:db8::/32').packed()), 16)
        self.assertEqual(len(parse_prefix('::/0').packed()), 16)

    def test_address_property_matches_packed(self):
        p = parse_prefix('2001:db8::/32')
        self.assertEqual(p.address, p.packed())

    def test_family_maps_to_the_socket_constant(self):
        self.assertEqual(parse_prefix('10.0.0.0/8').family, socket.AF_INET)
        self.assertEqual(parse_prefix('::/0').family, socket.AF_INET6)

    def test_max_plen_is_the_family_host_length(self):
        self.assertEqual(parse_prefix('10.0.0.0/8').max_plen, 32)
        self.assertEqual(parse_prefix('2001:db8::/32').max_plen, 128)

    def test_is_host_and_is_default(self):
        self.assertTrue(parse_prefix('10.0.0.1/32').is_host)
        self.assertFalse(parse_prefix('10.0.0.0/8').is_host)
        self.assertTrue(parse_prefix('2001:db8::1/128').is_host)
        self.assertFalse(parse_prefix('2001:db8::/32').is_host)
        self.assertTrue(parse_prefix('0.0.0.0/0').is_default)
        self.assertTrue(parse_prefix('::/0').is_default)
        self.assertFalse(parse_prefix('10.0.0.0/8').is_default)

    def test_alen_and_afi_are_exposed(self):
        v4 = parse_prefix('10.0.0.0/8')
        self.assertEqual((v4.afi, v4.plen, v4.alen), (AFI_IP, 8, 4))
        v6 = parse_prefix('2001:db8::/32')
        self.assertEqual((v6.afi, v6.plen, v6.alen), (AFI_IP6, 32, 16))

    def test_repr_and_str(self):
        p = parse_prefix('10.0.0.1/8')
        self.assertEqual(str(p), '10.0.0.0/8')
        self.assertEqual(repr(p), "Prefix('10.0.0.0/8')")
        self.assertEqual(str(parse_prefix('2001:db8::1/128')),
                         '2001:db8::1/128')

    def test_pickle_round_trip(self):
        # Tests and benchmarks hand tables between processes, and the
        # reconstruction goes back through __init__ so it re-validates.
        for text in ('10.0.0.0/8', '0.0.0.0/0', '10.1.2.3/32',
                     '2001:db8::/32', '::/0', '2001:db8::1/128'):
            p = parse_prefix(text)
            revived = pickle.loads(pickle.dumps(p))
            self.assertEqual(revived, p)
            self.assertEqual(hash(revived), hash(p))
            self.assertEqual(revived.to_str(), p.to_str())

    def test_module_constants(self):
        self.assertEqual((AFI_IP, AFI_IP6, SAFI_UNICAST), (1, 2, 1))
        self.assertEqual(MAX_ADDR_BYTES, 16)


class PrefixParseTestCase(unittest.TestCase):
    """parse_prefix is the configuration and API boundary."""

    def test_ipv4_prefix(self):
        p = parse_prefix('192.168.1.0/24')
        self.assertEqual((p.afi, p.plen), (AFI_IP, 24))
        self.assertEqual(p.packed(), b'\xc0\xa8\x01\x00')

    def test_ipv6_prefix(self):
        p = parse_prefix('2001:0db8:0000:0000:0000:0000:0000:0000/32')
        self.assertEqual((p.afi, p.plen), (AFI_IP6, 32))
        self.assertEqual(p.to_str(), '2001:db8::/32')

    def test_compressed_ipv6_prefix(self):
        self.assertEqual(parse_prefix('2001:db8::/32'),
                         parse_prefix('2001:db8:0:0:0:0:0:0/32'))
        self.assertEqual(parse_prefix('::/0').packed(), V6_ZERO)
        self.assertEqual(parse_prefix('::1/128').to_str(), '::1/128')

    def test_a_bare_address_becomes_a_host_prefix(self):
        # What `ip route` and `show ip bgp` both accept.
        self.assertEqual(parse_prefix('10.1.2.3'),
                         parse_prefix('10.1.2.3/32'))
        self.assertEqual(parse_prefix('2001:db8::1'),
                         parse_prefix('2001:db8::1/128'))

    def test_ascii_bytes_input(self):
        self.assertEqual(parse_prefix(b'10.0.0.0/8'),
                         parse_prefix('10.0.0.0/8'))
        self.assertEqual(parse_prefix(b'2001:db8::/32'),
                         parse_prefix('2001:db8::/32'))

    def test_from_str_is_parse_prefix(self):
        self.assertEqual(Prefix.from_str('10.0.0.0/8'),
                         parse_prefix('10.0.0.0/8'))
        with self.assertRaises(ValueError):
            Prefix.from_str('10.0.0.0/33')

    def test_rejections(self):
        # Every one of these is the caller's input being wrong, so all of
        # them are ValueError -- inet_pton's OSError would reach an API
        # handler as a 500 rather than a bad request.
        bad = [
            '10.0.0.0/33',            # past the IPv4 host length
            '2001:db8::/129',         # past the IPv6 host length
            '10.0.0.0/eight',         # non-numeric length
            '10.0.0.0/-1',            # negative length
            '10.0.0.0/+8',            # signed length
            '10.0.0.0/ 8',            # leading whitespace in the length
            '10.0.0.0/8 ',            # trailing whitespace in the length
            '10.0.0.0/',              # empty length
            '',                       # empty string
            '10.0.0.256/8',           # octet out of range
            '10.0.0/8',               # too few octets
            '2001:db8:::1/64',        # two runs of elision
            '2001:db8::1::2/64',      # ditto, the other spelling
            'not-an-address/8',
        ]
        for text in bad:
            with self.assertRaises(ValueError):
                parse_prefix(text)

    def test_a_non_string_object_is_rejected(self):
        for obj in (None, 5, 10.5, object(), ['10.0.0.0/8'],
                    b'\xff\xfe/8'):
            with self.assertRaises(ValueError):
                parse_prefix(obj)

    def test_an_absurdly_long_length_is_rejected_not_truncated(self):
        # A length that overflows an unsigned char must not wrap into a
        # length that happens to be legal.
        with self.assertRaises(ValueError):
            parse_prefix('10.0.0.0/256')
        with self.assertRaises(ValueError):
            parse_prefix('10.0.0.0/99999999999999999999')

    def test_parse_masks_host_bits_like_the_constructor(self):
        self.assertEqual(parse_prefix('10.1.2.3/8').to_str(), '10.0.0.0/8')
        self.assertEqual(parse_prefix('2001:db8::1/32').to_str(),
                         '2001:db8::/32')

    def test_round_trip_through_text_for_a_random_set(self):
        rng = random.Random(20190304)
        for afi in (AFI_IP, AFI_IP6):
            for p in _make_pool(rng, afi, 200):
                self.assertEqual(parse_prefix(p.to_str()), p)


class PrefixConstructionTestCase(unittest.TestCase):
    """Direct construction is the validation boundary for the whole RIB."""

    def test_an_unknown_family_is_rejected(self):
        for afi in (0, 3, 7, 255):
            with self.assertRaises(ValueError):
                Prefix(afi, 0, V4_ZERO)

    def test_an_out_of_range_length_is_rejected(self):
        with self.assertRaises(ValueError):
            Prefix(AFI_IP, 33, V4_ZERO)
        with self.assertRaises(ValueError):
            Prefix(AFI_IP, 255, V4_ZERO)
        with self.assertRaises(ValueError):
            Prefix(AFI_IP6, 129, V6_ZERO)

    def test_a_wrong_width_address_is_rejected(self):
        with self.assertRaises(ValueError):
            Prefix(AFI_IP, 8, V6_ZERO)
        with self.assertRaises(ValueError):
            Prefix(AFI_IP6, 8, V4_ZERO)
        with self.assertRaises(ValueError):
            Prefix(AFI_IP, 8, b'')
        with self.assertRaises(ValueError):
            Prefix(AFI_IP, 8, b'\x0a\x00\x00\x00\x00')

    def test_the_boundary_lengths_are_accepted(self):
        self.assertEqual(Prefix(AFI_IP, 32, b'\xff' * 4).plen, 32)
        self.assertEqual(Prefix(AFI_IP6, 128, b'\xff' * 16).plen, 128)
        self.assertEqual(Prefix(AFI_IP, 0, b'\xff' * 4).plen, 0)


class AfiFamilyMappingTestCase(unittest.TestCase):
    """The AFI/socket-family mapping, which exists because AF_INET6 differs
    between Linux and macOS while the IANA numbers do not."""

    def test_round_trip(self):
        self.assertEqual(afi_for_family(socket.AF_INET), AFI_IP)
        self.assertEqual(afi_for_family(socket.AF_INET6), AFI_IP6)
        self.assertEqual(family_for_afi(AFI_IP), socket.AF_INET)
        self.assertEqual(family_for_afi(AFI_IP6), socket.AF_INET6)
        for afi in (AFI_IP, AFI_IP6):
            self.assertEqual(afi_for_family(family_for_afi(afi)), afi)
        for family in (socket.AF_INET, socket.AF_INET6):
            self.assertEqual(family_for_afi(afi_for_family(family)), family)

    def test_family_rejections(self):
        for family in (socket.AF_UNIX, 0, 999, None, 'AF_INET'):
            with self.assertRaises(ValueError):
                afi_for_family(family)

    def test_afi_rejections(self):
        for afi in (0, 3, 255, None, 'ip'):
            with self.assertRaises(ValueError):
                family_for_afi(afi)


class TrieOracleTestCase(unittest.TestCase):
    """The trie against a dict-plus-linear-scan oracle.

    Spot assertions cannot reach the states that matter in a
    path-compressed trie: an edge split, a glue node created and collapsed
    again, an ancestor spliced in above an existing node. A randomised
    workload does, and a fixed seed makes any failure reproducible.
    """

    OPERATIONS = 4000
    POOL = 400
    SEEDS = (20190401, 20190402, 20190403)

    def _workload(self, afi, seed):
        rng = random.Random(seed)
        trie = Trie(afi)
        oracle = {}
        pool = _make_pool(rng, afi, self.POOL)
        serial = 0

        for _ in range(self.OPERATIONS):
            key = rng.choice(pool)
            roll = rng.random()
            if roll < 0.55:
                serial += 1
                value = Holder('%d-%d' % (seed, serial))
                previous = trie.insert(key, value)
                # Identity, not equality: the trie must hand back the exact
                # object it was holding, because that owned reference is
                # what keeps a replaced value alive for the caller.
                self.assertIs(previous, oracle.get(key))
                oracle[key] = value
            elif roll < 0.85:
                removed = trie.remove(key)
                self.assertIs(removed, oracle.get(key))
                oracle.pop(key, None)
            else:
                self.assertIs(trie.get(key), oracle.get(key))
            self.assertEqual(len(trie), len(oracle))
            self.assertEqual(trie.size(), len(oracle))
        return trie, oracle

    def _check_final_state(self, trie, oracle):
        for key, value in oracle.items():
            self.assertIs(trie.get(key), value)
            self.assertIn(key, trie)
        expected = sorted(oracle)
        self.assertEqual(list(trie), expected)
        self.assertEqual(list(trie.keys()), expected)
        pairs = list(trie.items())
        self.assertEqual([k for k, _ in pairs], expected)
        for key, value in pairs:
            self.assertIs(value, oracle[key])
        self.assertEqual(trie.values(), [oracle[k] for k in expected])
        # A workload that never made the trie branch would exercise none of
        # the splitting this test exists for, and the seeds could drift into
        # that without anything else here noticing.
        self.assertGreater(trie.nodes, len(oracle))

    def test_ipv4_mixed_workload(self):
        for seed in self.SEEDS:
            trie, oracle = self._workload(AFI_IP, seed)
            self.assertTrue(oracle, 'seed %d produced an empty trie' % seed)
            self._check_final_state(trie, oracle)

    def test_ipv6_mixed_workload(self):
        for seed in self.SEEDS:
            trie, oracle = self._workload(AFI_IP6, seed)
            self.assertTrue(oracle, 'seed %d produced an empty trie' % seed)
            self._check_final_state(trie, oracle)

    def test_removing_every_key_returns_the_trie_to_empty(self):
        # The counters, not just the contents: a glue node left behind by a
        # removal is invisible to len() and would only show up here.
        for afi in (AFI_IP, AFI_IP6):
            trie, oracle = self._workload(afi, 20190404)
            for key in list(oracle):
                self.assertIs(trie.remove(key), oracle[key])
            self.assertEqual(len(trie), 0)
            self.assertEqual(trie.nodes, 0)
            self.assertEqual(list(trie), [])


class TrieLpmTestCase(unittest.TestCase):
    """Longest-prefix match, against a brute-force oracle and by example."""

    QUERIES = 400
    SEEDS = (20190501, 20190502, 20190503)
    # Keys shorter than this are not inserted. Left in, the pool's default
    # route and its handful of very short prefixes cover the whole address
    # space between them, and then every query is covered and the
    # comparison never once checks that a query nothing covers reports a
    # miss -- the one answer a resolver acts on differently. Confirmed
    # empirically: without this floor all 400 queries hit for every seed.
    MIN_PLEN = {AFI_IP: 8, AFI_IP6: 16}

    def _populated(self, afi, seed):
        rng = random.Random(seed)
        trie = Trie(afi)
        oracle = {}
        for key in _make_pool(rng, afi, 300):
            if key.plen < self.MIN_PLEN[afi]:
                continue
            value = Holder(key.to_str())
            trie.insert(key, value)
            oracle[key] = value
        return rng, trie, oracle

    def _queries(self, rng, afi, oracle):
        """Queries mixing keys that are present with keys that are not.

        A query set drawn only from absent prefixes would never exercise the
        "an exact hit wins over its own parents" branch, and one drawn only
        from present keys would never exercise the descent that runs off the
        end of a compressed edge.
        """
        keys = sorted(oracle)
        out = []
        for _ in range(self.QUERIES):
            roll = rng.random()
            if roll < 0.35:
                out.append(rng.choice(keys))
            elif roll < 0.7:
                out.append(_rand_below(rng, afi, rng.choice(keys)))
            else:
                out.append(Prefix(afi, ABITS[afi],
                                  _pack(rng.getrandbits(ABITS[afi]),
                                        ALEN[afi])))
        return out

    def _check_family(self, afi, seed):
        rng, trie, oracle = self._populated(afi, seed)
        hits = 0
        misses = 0
        for query in self._queries(rng, afi, oracle):
            expected_key = _oracle_lpm(oracle, query)
            if expected_key is None:
                misses += 1
                self.assertIsNone(trie.lpm(query))
                self.assertIsNone(trie.lpm_entry(query))
                continue
            hits += 1
            self.assertIs(trie.lpm(query), oracle[expected_key])
            entry = trie.lpm_entry(query)
            self.assertEqual(entry[0], expected_key)
            self.assertIs(entry[1], oracle[expected_key])
        # A randomised comparison that drifts into all hits or all misses
        # stops testing half of what it is here for, and would do so
        # silently. Both counts are around 300/100 for every seed used
        # here, so an eighth of the queries is a wide margin.
        self.assertGreater(hits, self.QUERIES // 8)
        self.assertGreater(misses, self.QUERIES // 8)

    def test_ipv4_lpm_matches_the_oracle(self):
        for seed in self.SEEDS:
            self._check_family(AFI_IP, seed)

    def test_ipv6_lpm_matches_the_oracle(self):
        for seed in self.SEEDS:
            self._check_family(AFI_IP6, seed)

    def test_lpm_addr_matches_the_oracle(self):
        # The resolver's entry point: an address, not a prefix, so that
        # next-hop validation does not allocate a host Prefix per lookup.
        for afi in (AFI_IP, AFI_IP6):
            rng, trie, oracle = self._populated(afi, 20190504)
            keys = sorted(oracle)
            hits = 0
            misses = 0
            for step in range(self.QUERIES):
                if step % 2:
                    # A key that is present, with its host bits filled in at
                    # random, so half the queries are guaranteed hits.
                    # Purely random addresses almost all miss -- measured at
                    # 377 of 400 for IPv4 and 400 of 400 for IPv6 -- which
                    # would leave the matching half of the comparison
                    # untested.
                    key = rng.choice(keys)
                    addr = _pack(_unpack(key.packed())
                                 | _rand_bits(rng, ABITS[afi] - key.plen),
                                 ALEN[afi])
                else:
                    addr = _pack(rng.getrandbits(ABITS[afi]), ALEN[afi])
                expected_key = _oracle_lpm(oracle,
                                           Prefix(afi, ABITS[afi], addr))
                if expected_key is None:
                    misses += 1
                    self.assertIsNone(trie.lpm_addr(addr))
                else:
                    hits += 1
                    self.assertIs(trie.lpm_addr(addr), oracle[expected_key])
            self.assertGreater(hits, self.QUERIES // 8)
            self.assertGreater(misses, self.QUERIES // 8)

    def test_an_exact_hit_beats_its_less_specific_parents(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('0.0.0.0/0'), 'default')
        trie.insert(parse_prefix('10.0.0.0/8'), 'eight')
        trie.insert(parse_prefix('10.1.0.0/16'), 'sixteen')
        trie.insert(parse_prefix('10.1.2.0/24'), 'twentyfour')
        self.assertEqual(trie.lpm(parse_prefix('10.1.2.0/24')),
                         'twentyfour')
        self.assertEqual(trie.lpm(parse_prefix('10.1.0.0/16')), 'sixteen')
        self.assertEqual(trie.lpm(parse_prefix('10.0.0.0/8')), 'eight')
        self.assertEqual(trie.lpm(parse_prefix('0.0.0.0/0')), 'default')
        # A query below the deepest entry still stops at that entry.
        self.assertEqual(trie.lpm(parse_prefix('10.1.2.200/32')),
                         'twentyfour')
        # ... and one that leaves the /24 falls back to the /16.
        self.assertEqual(trie.lpm(parse_prefix('10.1.3.1/32')), 'sixteen')

    def test_the_default_route_is_the_fallback_for_everything(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('0.0.0.0/0'), 'default')
        rng = random.Random(20190505)
        for _ in range(300):
            addr = _pack(rng.getrandbits(32), 4)
            self.assertEqual(trie.lpm_addr(addr), 'default')
            self.assertEqual(trie.lpm(Prefix(AFI_IP, 32, addr)), 'default')
        self.assertEqual(trie.lpm(parse_prefix('0.0.0.0/0')), 'default')

    def test_no_match_returns_none(self):
        trie = Trie(AFI_IP)
        self.assertIsNone(trie.lpm(parse_prefix('10.0.0.0/8')))
        self.assertIsNone(trie.lpm_entry(parse_prefix('10.0.0.0/8')))
        self.assertIsNone(trie.lpm_addr(b'\x0a\x00\x00\x01'))
        trie.insert(parse_prefix('10.0.0.0/8'), 'eight')
        self.assertIsNone(trie.lpm(parse_prefix('11.0.0.0/8')))
        self.assertIsNone(trie.lpm_addr(b'\x0b\x00\x00\x01'))
        # A glue node is not a match: inserting a second /8 creates one at
        # /7, and nothing may resolve to it.
        trie.insert(parse_prefix('11.0.0.0/8'), 'eleven')
        self.assertIsNone(trie.lpm(parse_prefix('10.0.0.0/7')))
        self.assertIsNone(trie.lpm_entry(parse_prefix('10.0.0.0/7')))

    def test_lpm_entry_reports_the_matched_prefix(self):
        trie = Trie(AFI_IP6)
        trie.insert(parse_prefix('2001:db8::/32'), 'value')
        entry = trie.lpm_entry(parse_prefix('2001:db8:1:2::1/128'))
        self.assertEqual(entry[0], parse_prefix('2001:db8::/32'))
        self.assertEqual(entry[0].to_str(), '2001:db8::/32')
        self.assertEqual(entry[1], 'value')


class TrieStructureTestCase(unittest.TestCase):
    """Glue-node bookkeeping, read through the ``nodes`` counter.

    The counter is the only external view of the structure, and it is what
    distinguishes a trie that prunes correctly from one that quietly grows a
    node per transient prefix it has ever seen.
    """

    def test_two_siblings_create_exactly_one_glue_node(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.0.0.0/8'), 'ten')
        self.assertEqual((len(trie), trie.nodes), (1, 1))
        # 10/8 and 11/8 diverge at bit 7, so one glue node at /7 holds them
        # apart. Nothing may resolve to it.
        trie.insert(parse_prefix('11.0.0.0/8'), 'eleven')
        self.assertEqual((len(trie), trie.nodes), (2, 3))
        self.assertIsNone(trie.get(parse_prefix('10.0.0.0/7')))

    def test_removing_one_sibling_collapses_the_glue_node(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.0.0.0/8'), 'ten')
        trie.insert(parse_prefix('11.0.0.0/8'), 'eleven')
        self.assertEqual(trie.remove(parse_prefix('11.0.0.0/8')), 'eleven')
        self.assertEqual((len(trie), trie.nodes), (1, 1))
        self.assertEqual(trie.get(parse_prefix('10.0.0.0/8')), 'ten')

    def test_removing_both_siblings_leaves_no_nodes(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.0.0.0/8'), 'ten')
        trie.insert(parse_prefix('11.0.0.0/8'), 'eleven')
        trie.remove(parse_prefix('10.0.0.0/8'))
        trie.remove(parse_prefix('11.0.0.0/8'))
        self.assertEqual((len(trie), trie.nodes), (0, 0))
        self.assertEqual(list(trie), [])

    def test_a_glue_node_survives_while_it_holds_two_subtrees(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.0.0.0/8'), 'ten')
        trie.insert(parse_prefix('11.0.0.0/8'), 'eleven')
        trie.insert(parse_prefix('10.1.0.0/16'), 'ten-one')
        self.assertEqual((len(trie), trie.nodes), (3, 4))
        # The /7 glue still holds two subtrees apart, so it survives. The /8
        # does not: once its value goes it has a single child, and a glue
        # node with one child is redundant, so the /16 is relinked straight
        # onto the /7.
        self.assertEqual(trie.remove(parse_prefix('10.0.0.0/8')), 'ten')
        self.assertEqual((len(trie), trie.nodes), (2, 3))
        self.assertEqual(list(trie), [parse_prefix('10.1.0.0/16'),
                                      parse_prefix('11.0.0.0/8')])
        self.assertEqual(trie.lpm(parse_prefix('10.1.2.3/32')), 'ten-one')
        self.assertIsNone(trie.lpm(parse_prefix('10.2.0.0/16')))

    def test_a_less_specific_prefix_is_spliced_in_above_an_existing_node(self):
        # The other half of node_intern: the new prefix covers the node
        # already there, so it has to take that node's place under its
        # parent rather than hang below it. No glue node is involved.
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.1.2.0/24'), 'deep')
        self.assertEqual(trie.nodes, 1)
        trie.insert(parse_prefix('10.0.0.0/8'), 'shallow')
        self.assertEqual((len(trie), trie.nodes), (2, 2))
        self.assertEqual(trie.get(parse_prefix('10.1.2.0/24')), 'deep')
        self.assertEqual(trie.get(parse_prefix('10.0.0.0/8')), 'shallow')
        self.assertEqual(list(trie), [parse_prefix('10.0.0.0/8'),
                                      parse_prefix('10.1.2.0/24')])

    def test_a_less_specific_prefix_spliced_in_at_the_root(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.1.2.0/24'), 'deep')
        trie.insert(parse_prefix('0.0.0.0/0'), 'default')
        self.assertEqual((len(trie), trie.nodes), (2, 2))
        self.assertEqual(trie.lpm(parse_prefix('11.0.0.0/8')), 'default')
        self.assertEqual(trie.lpm(parse_prefix('10.1.2.3/32')), 'deep')

    def test_three_level_nesting_uses_one_node_per_entry(self):
        trie = Trie(AFI_IP)
        for text, value in (('10.0.0.0/8', 'a'), ('10.1.0.0/16', 'b'),
                            ('10.1.2.0/24', 'c')):
            trie.insert(parse_prefix(text), value)
        self.assertEqual((len(trie), trie.nodes), (3, 3))
        self.assertEqual(trie.values(), ['a', 'b', 'c'])
        # Removing the middle level leaves the other two and no glue: the
        # node has one child, so the child takes its place.
        self.assertEqual(trie.remove(parse_prefix('10.1.0.0/16')), 'b')
        self.assertEqual((len(trie), trie.nodes), (2, 2))
        self.assertEqual(trie.values(), ['a', 'c'])

    def test_three_level_nesting_inserted_deepest_first(self):
        trie = Trie(AFI_IP)
        for text, value in (('10.1.2.0/24', 'c'), ('10.1.0.0/16', 'b'),
                            ('10.0.0.0/8', 'a')):
            trie.insert(parse_prefix(text), value)
        self.assertEqual((len(trie), trie.nodes), (3, 3))
        self.assertEqual(trie.values(), ['a', 'b', 'c'])

    def test_node_count_never_exceeds_twice_the_entry_count(self):
        # The structural invariant a glue-node leak would break: every glue
        # node has two children, so a trie of n entries has at most n - 1 of
        # them.
        rng = random.Random(20190601)
        for afi in (AFI_IP, AFI_IP6):
            trie = Trie(afi)
            for key in _make_pool(rng, afi, 500):
                trie.insert(key, Holder(key.to_str()))
                self.assertLessEqual(trie.nodes, 2 * len(trie))

    def test_clear_empties_the_counters_and_leaves_the_trie_reusable(self):
        trie = Trie(AFI_IP)
        rng = random.Random(20190602)
        for key in _make_pool(rng, AFI_IP, 200):
            trie.insert(key, Holder(key.to_str()))
        self.assertTrue(len(trie) > 0)
        trie.clear()
        self.assertEqual(len(trie), 0)
        self.assertEqual(trie.size(), 0)
        self.assertEqual(trie.nodes, 0)
        self.assertEqual(list(trie), [])
        self.assertEqual(list(trie.items()), [])
        self.assertEqual(trie.values(), [])
        trie.insert(parse_prefix('10.0.0.0/8'), 'after')
        self.assertEqual(len(trie), 1)
        self.assertEqual(trie.nodes, 1)
        self.assertEqual(trie.get(parse_prefix('10.0.0.0/8')), 'after')
        self.assertEqual(trie.lpm_addr(b'\x0a\x01\x02\x03'), 'after')

    def test_clear_on_an_empty_trie_is_harmless(self):
        trie = Trie(AFI_IP6)
        trie.clear()
        self.assertEqual((len(trie), trie.nodes), (0, 0))

    def test_repr(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.0.0.0/8'), 'a')
        trie.insert(parse_prefix('11.0.0.0/8'), 'b')
        self.assertEqual(repr(trie), '<Trie afi=1 entries=2 nodes=3>')


class TrieValueLifetimeTestCase(unittest.TestCase):
    """The trie's hand-rolled reference counting.

    Cython cannot put an ``object`` in a C struct, so every store and
    release in trie.pyx is a manual Py_INCREF/Py_DECREF pair. An error
    either way is invisible to a functional test: one direction leaks every
    value the table has ever held, the other frees a value the caller still
    has. Only refcount and weakref assertions can see it.
    """

    def test_storing_takes_exactly_one_reference(self):
        trie = Trie(AFI_IP)
        value = Holder('stored')
        base = sys.getrefcount(value)
        trie.insert(parse_prefix('10.0.0.0/8'), value)
        self.assertEqual(sys.getrefcount(value), base + 1)

    def test_restoring_the_same_object_does_not_accumulate(self):
        trie = Trie(AFI_IP)
        prefix = parse_prefix('10.0.0.0/8')
        value = Holder('stored')
        base = sys.getrefcount(value)
        trie.insert(prefix, value)
        for _ in range(20):
            # The return value is the previous one, which is this same
            # object, so it has to be dropped or it would look like a leak.
            previous = trie.insert(prefix, value)
            self.assertIs(previous, value)
            del previous
            self.assertEqual(sys.getrefcount(value), base + 1)
        self.assertEqual(len(trie), 1)

    def test_replacing_releases_the_old_value(self):
        trie = Trie(AFI_IP)
        prefix = parse_prefix('10.0.0.0/8')
        old = Holder('old')
        new = Holder('new')
        old_base = sys.getrefcount(old)
        trie.insert(prefix, old)
        self.assertEqual(sys.getrefcount(old), old_base + 1)
        previous = trie.insert(prefix, new)
        self.assertIs(previous, old)
        del previous
        self.assertEqual(sys.getrefcount(old), old_base)
        self.assertIs(trie.get(prefix), new)

    def test_remove_hands_the_value_back_and_releases_it(self):
        trie = Trie(AFI_IP)
        prefix = parse_prefix('10.0.0.0/8')
        value = Holder('removed')
        base = sys.getrefcount(value)
        trie.insert(prefix, value)
        returned = trie.remove(prefix)
        self.assertIs(returned, value)
        del returned
        self.assertEqual(sys.getrefcount(value), base)
        ref = weakref.ref(value)
        del value
        gc.collect()
        self.assertIsNone(ref())

    def test_dropping_the_trie_releases_every_value(self):
        trie = Trie(AFI_IP)
        rng = random.Random(20190701)
        refs = []
        for key in _make_pool(rng, AFI_IP, 300):
            value = Holder(key.to_str())
            refs.append(weakref.ref(value))
            trie.insert(key, value)
        # The loop variable still holds the last value, and this test is
        # about what the trie holds.
        value = None
        gc.collect()
        self.assertTrue(any(r() is not None for r in refs))
        del trie
        gc.collect()
        self.assertEqual([r for r in refs if r() is not None], [])

    def test_clear_releases_every_value(self):
        trie = Trie(AFI_IP6)
        rng = random.Random(20190702)
        refs = []
        for key in _make_pool(rng, AFI_IP6, 200):
            value = Holder(key.to_str())
            refs.append(weakref.ref(value))
            trie.insert(key, value)
        value = None
        trie.clear()
        gc.collect()
        self.assertEqual([r for r in refs if r() is not None], [])

    def test_no_leak_after_a_large_insert_then_delete_churn(self):
        # The churn is what moves values through the replace, prune and
        # glue-collapse paths; the weakref is what proves none of them kept
        # a reference behind.
        rng = random.Random(20190703)
        trie = Trie(AFI_IP)
        pool = _make_pool(rng, AFI_IP, 500)
        sentinel = Holder('sentinel')
        sentinel_ref = weakref.ref(sentinel)
        refs = [sentinel_ref]
        trie.insert(pool[0], sentinel)
        del sentinel
        for _ in range(6000):
            key = rng.choice(pool)
            if rng.random() < 0.5:
                value = Holder(key.to_str())
                refs.append(weakref.ref(value))
                trie.insert(key, value)
            else:
                trie.remove(key)
        value = None
        for key in pool:
            trie.remove(key)
        self.assertEqual((len(trie), trie.nodes), (0, 0))
        gc.collect()
        self.assertIsNone(sentinel_ref())
        self.assertEqual([r for r in refs if r() is not None], [])

    def test_a_value_stays_alive_while_only_the_trie_holds_it(self):
        trie = Trie(AFI_IP)
        prefix = parse_prefix('10.0.0.0/8')
        value = Holder('only-reference')
        ref = weakref.ref(value)
        trie.insert(prefix, value)
        del value
        gc.collect()
        self.assertIsNotNone(ref())
        self.assertIs(trie.get(prefix), ref())
        del trie
        gc.collect()
        self.assertIsNone(ref())

    def test_an_iterated_temporary_trie_is_not_freed_mid_walk(self):
        # The iterator holds raw node pointers, so it keeps a strong
        # reference to the trie; without it this walk would read freed
        # memory.
        rng = random.Random(20190704)
        pool = _make_pool(rng, AFI_IP, 100)

        def build():
            trie = Trie(AFI_IP)
            for key in pool:
                trie.insert(key, key.to_str())
            return trie.items()

        pairs = list(build())
        self.assertEqual([k for k, _ in pairs], sorted(set(pool)))
        for key, value in pairs:
            self.assertEqual(value, key.to_str())


class TrieRejectionTestCase(unittest.TestCase):
    """What the trie refuses, and what it answers instead of refusing."""

    def test_storing_none_is_rejected(self):
        # None is how every lookup spells "absent", so storing it would make
        # the two states indistinguishable.
        trie = Trie(AFI_IP)
        with self.assertRaises(ValueError):
            trie.insert(parse_prefix('10.0.0.0/8'), None)
        self.assertEqual(len(trie), 0)
        self.assertIsNone(trie.get(parse_prefix('10.0.0.0/8')))
        self.assertNotIn(parse_prefix('10.0.0.0/8'), trie)
        self.assertEqual(list(trie), [])

    def test_a_rejected_store_leaves_no_node_behind(self):
        # trie.pxd states the glue invariant as "a node with value == NULL
        # is glue: it exists only because two subtrees diverge at its plen,
        # and it is removed again when it stops having two children".
        # insert interns the node before set_value validates the value, so a
        # rejected store leaves a childless valueless node behind. Nothing
        # can reclaim it: _prune runs only from clear_value, which returns
        # early for a node that has no value, and remove() cannot see the
        # node at all because it is not real. So a caller validating input
        # accumulates one permanent node per distinct rejected prefix, and
        # every one of them is a node an ordered walk and an lpm descent
        # both have to step over for the life of the trie.
        trie = Trie(AFI_IP)
        for i in range(10):
            with self.assertRaises(ValueError):
                trie.insert(parse_prefix('10.%d.0.0/16' % i), None)
        self.assertEqual(len(trie), 0)
        self.assertEqual(list(trie), [])
        self.assertEqual(trie.nodes, 0)

    def test_storing_none_over_an_existing_value_keeps_the_value(self):
        trie = Trie(AFI_IP)
        prefix = parse_prefix('10.0.0.0/8')
        trie.insert(prefix, 'kept')
        with self.assertRaises(ValueError):
            trie.insert(prefix, None)
        self.assertEqual(trie.get(prefix), 'kept')
        self.assertEqual(len(trie), 1)

    def test_a_missing_prefix_is_rejected_by_insert(self):
        trie = Trie(AFI_IP)
        with self.assertRaises(ValueError):
            trie.insert(None, 'value')

    def test_inserting_a_foreign_family_is_rejected(self):
        trie = Trie(AFI_IP)
        with self.assertRaises(ValueError):
            trie.insert(parse_prefix('2001:db8::/32'), 'value')
        trie6 = Trie(AFI_IP6)
        with self.assertRaises(ValueError):
            trie6.insert(parse_prefix('10.0.0.0/8'), 'value')

    def test_looking_up_a_foreign_family_is_a_miss_not_an_error(self):
        # So that a caller iterating both families can probe without
        # branching on the family first.
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.0.0.0/8'), 'value')
        foreign = parse_prefix('2001:db8::/32')
        self.assertIsNone(trie.get(foreign))
        self.assertIsNone(trie.lpm(foreign))
        self.assertIsNone(trie.lpm_entry(foreign))
        self.assertIsNone(trie.remove(foreign))
        self.assertEqual(len(trie), 1)

    def test_a_none_prefix_is_a_miss_for_the_lookups(self):
        trie = Trie(AFI_IP)
        self.assertIsNone(trie.get(None))
        self.assertIsNone(trie.lpm(None))
        self.assertIsNone(trie.lpm_entry(None))
        self.assertIsNone(trie.remove(None))

    def test_lpm_addr_rejects_a_wrong_width_address(self):
        trie = Trie(AFI_IP)
        for addr in (b'', b'\x0a', b'\x0a\x00\x00', b'\x0a\x00\x00\x00\x00',
                     b'\x00' * 16, None):
            with self.assertRaises(ValueError):
                trie.lpm_addr(addr)
        trie6 = Trie(AFI_IP6)
        with self.assertRaises(ValueError):
            trie6.lpm_addr(b'\x0a\x00\x00\x00')

    def test_an_unknown_family_trie_is_rejected(self):
        for afi in (0, 3, 7, 255):
            with self.assertRaises(ValueError):
                Trie(afi)

    def test_contains(self):
        trie = Trie(AFI_IP)
        present = parse_prefix('10.0.0.0/8')
        trie.insert(present, 'value')
        self.assertIn(present, trie)
        self.assertNotIn(parse_prefix('11.0.0.0/8'), trie)
        # A non-Prefix answers False rather than raising, so `x in trie`
        # behaves like `x in dict`.
        for other in ('10.0.0.0/8', None, 5, object()):
            self.assertNotIn(other, trie)

    def test_remove_of_an_absent_prefix_returns_none(self):
        trie = Trie(AFI_IP)
        trie.insert(parse_prefix('10.0.0.0/8'), 'value')
        self.assertIsNone(trie.remove(parse_prefix('10.0.0.0/16')))
        self.assertIsNone(trie.remove(parse_prefix('10.0.0.0/7')))
        self.assertEqual(len(trie), 1)


class TrieDepthTestCase(unittest.TestCase):
    """A trie as deep as the address space allows.

    An IPv6 chain with an entry at every length is 128 levels, which is
    where a fixed-size iterator stack or a recursive free would break. The
    second case adds a sibling at every level so the pre-order walk actually
    has to hold one unvisited node per level.
    """

    @staticmethod
    def _chain():
        ones = b'\xff' * 16
        return [Prefix(AFI_IP6, plen, ones) for plen in range(1, 129)]

    def test_a_nested_chain_at_every_ipv6_length(self):
        chain = self._chain()
        trie = Trie(AFI_IP6)
        for depth, key in enumerate(chain):
            trie.insert(key, 'level-%d' % (depth + 1))
        self.assertEqual((len(trie), trie.nodes), (128, 128))
        for depth, key in enumerate(chain):
            self.assertEqual(trie.get(key), 'level-%d' % (depth + 1))
        self.assertEqual(list(trie), chain)
        self.assertEqual(list(trie), sorted(chain))
        self.assertEqual(trie.values(),
                         ['level-%d' % n for n in range(1, 129)])
        self.assertEqual(trie.lpm(chain[-1]), 'level-128')
        self.assertEqual(trie.lpm_addr(b'\xff' * 16), 'level-128')
        # Every ancestor is still reachable as the match for a query that
        # stops short of the deepest entry.
        self.assertEqual(trie.lpm(chain[63]), 'level-64')

    def test_a_deep_chain_unwinds_without_leaking_nodes(self):
        chain = self._chain()
        trie = Trie(AFI_IP6)
        for key in chain:
            trie.insert(key, key.to_str())
        # Removing from the top down leaves each removed node with a single
        # child, which is the collapse path rather than the free path.
        for key in chain:
            self.assertEqual(trie.remove(key), key.to_str())
        self.assertEqual((len(trie), trie.nodes), (0, 0))

    def test_a_branch_at_every_level_iterates_in_order(self):
        ones = (1 << 128) - 1
        trie = Trie(AFI_IP6)
        keys = []
        for bit in range(128):
            plen = bit + 1
            on_chain = Prefix(AFI_IP6, plen, _pack(ones, 16))
            off_chain = Prefix(AFI_IP6, plen,
                               _pack(ones & ~(1 << (127 - bit)), 16))
            for key in (on_chain, off_chain):
                trie.insert(key, key.to_str())
                keys.append(key)
        self.assertEqual(len(trie), 256)
        walked = list(trie)
        self.assertEqual(len(walked), 256)
        self.assertEqual(walked, sorted(keys))
        for key, value in trie.items():
            self.assertEqual(value, key.to_str())
        self.assertEqual(trie.lpm(Prefix(AFI_IP6, 128, _pack(ones, 16))),
                         'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128')

    def test_a_deep_ipv4_chain(self):
        chain = [Prefix(AFI_IP, plen, b'\xff' * 4) for plen in range(1, 33)]
        trie = Trie(AFI_IP)
        for key in chain:
            trie.insert(key, key.plen)
        self.assertEqual((len(trie), trie.nodes), (32, 32))
        self.assertEqual(list(trie), chain)
        self.assertEqual(trie.lpm_addr(b'\xff' * 4), 32)


class RouteConstructionTestCase(unittest.TestCase):
    """What a plugin may offer, and how it renders."""

    PREFIX_TEXT = '10.0.0.0/8'

    def test_defaults(self):
        route = Route(parse_prefix(self.PREFIX_TEXT), PROTO_BGP, 20, 100)
        self.assertEqual(route.prefix, parse_prefix(self.PREFIX_TEXT))
        self.assertEqual(route.protocol, PROTO_BGP)
        self.assertEqual(route.admin_distance, 20)
        self.assertEqual(route.metric, 100)
        self.assertEqual(route.nexthop, b'')
        self.assertIsNone(route.source)
        self.assertEqual(route.version, 0)
        self.assertEqual(route.fib_state, FIB_STATE_NONE)
        self.assertEqual(route.fib_errno, 0)
        # An omitted recv_time is "now" on the monotonic clock, which must
        # not be a wall-clock value and must not be the sentinel.
        self.assertGreater(route.recv_time, 0.0)

    def test_an_empty_next_hop_is_a_connected_route(self):
        route = Route(parse_prefix(self.PREFIX_TEXT), PROTO_CONNECTED, 0, 0,
                      b'')
        self.assertEqual(route.nexthop, b'')
        self.assertIn('connected', repr(route))

    def test_an_omitted_next_hop_becomes_empty_not_none(self):
        route = Route(parse_prefix(self.PREFIX_TEXT), PROTO_CONNECTED, 0, 0,
                      None)
        self.assertEqual(route.nexthop, b'')

    def test_four_and_sixteen_byte_next_hops(self):
        v4 = Route(parse_prefix(self.PREFIX_TEXT), PROTO_BGP, 20, 0,
                   b'\x0a\x00\x00\x01')
        self.assertEqual(v4.as_dict()['next-hop'], '10.0.0.1')
        # RFC 5549 style: an IPv4 prefix with an IPv6 next-hop is
        # deliberately not forbidden here.
        v6 = Route(parse_prefix(self.PREFIX_TEXT), PROTO_BGP, 20, 0,
                   socket.inet_pton(socket.AF_INET6, '2001:db8::1'))
        self.assertEqual(v6.as_dict()['next-hop'], '2001:db8::1')

    def test_any_other_next_hop_width_is_rejected(self):
        prefix = parse_prefix(self.PREFIX_TEXT)
        for width in (1, 2, 3, 5, 6, 8, 15, 17, 32):
            with self.assertRaises(ValueError):
                Route(prefix, PROTO_BGP, 20, 0, b'\x00' * width)

    def test_a_missing_prefix_is_rejected(self):
        with self.assertRaises(ValueError):
            Route(None, PROTO_BGP, 20, 0)

    def test_protocol_and_fib_state_names(self):
        prefix = parse_prefix(self.PREFIX_TEXT)
        for proto, name in ((PROTO_UNSPEC, 'unspec'),
                            (PROTO_CONNECTED, 'connected'),
                            (PROTO_STATIC, 'static'), (PROTO_BGP, 'bgp'),
                            (PROTO_OSPF, 'ospf'), (PROTO_RIP, 'rip')):
            self.assertEqual(Route(prefix, proto, 0, 0).protocol_name, name)
        self.assertEqual(Route(prefix, 200, 0, 0).protocol_name, 'unknown')

        route = Route(prefix, PROTO_BGP, 20, 0)
        for state, name in ((FIB_STATE_NONE, 'none'),
                            (FIB_STATE_PENDING, 'pending'),
                            (FIB_STATE_INSTALLED, 'installed'),
                            (FIB_STATE_ERROR, 'fib-error'),
                            (FIB_STATE_ORPHANED, 'orphaned')):
            route.fib_state = state
            self.assertEqual(route.fib_state_name, name)
        route.fib_state = 99
        self.assertEqual(route.fib_state_name, 'unknown')

    def test_as_dict_keys_and_values(self):
        route = Route(parse_prefix('10.1.2.0/24'), PROTO_STATIC, 1, 7,
                      b'\x0a\x00\x00\x01')
        self.assertEqual(sorted(route.as_dict()),
                         ['distance', 'fib', 'fib-errno', 'metric',
                          'next-hop', 'prefix', 'protocol'])
        self.assertEqual(route.as_dict(),
                         {'prefix': '10.1.2.0/24', 'protocol': 'static',
                          'distance': 1, 'metric': 7,
                          'next-hop': '10.0.0.1', 'fib': 'none',
                          'fib-errno': 0})

    def test_as_dict_leaves_an_empty_next_hop_empty(self):
        # Rendering it as '0.0.0.0' would claim a gateway that does not
        # exist.
        route = Route(parse_prefix(self.PREFIX_TEXT), PROTO_CONNECTED, 0, 0)
        self.assertEqual(route.as_dict()['next-hop'], '')

    def test_as_dict_reports_an_errno_only_for_a_fib_error(self):
        route = Route(parse_prefix(self.PREFIX_TEXT), PROTO_BGP, 20, 0)
        route.fib_errno = 22
        route.fib_state = FIB_STATE_PENDING
        self.assertEqual(route.as_dict()['fib-errno'], 0)
        route.fib_state = FIB_STATE_ERROR
        self.assertEqual(route.as_dict()['fib-errno'], 22)

    def test_repr(self):
        route = Route(parse_prefix('10.1.2.0/24'), PROTO_BGP, 20, 5,
                      b'\x0a\x00\x00\x01')
        self.assertEqual(repr(route),
                         '<Route 10.1.2.0/24 via 10.0.0.1 bgp d=20 m=5>')

    def test_protocol_tables_agree(self):
        self.assertEqual(PROTO_IDS,
                         dict((n, p) for p, n in PROTO_NAMES.items()))
        self.assertEqual(sorted(PROTO_NAMES),
                         [PROTO_UNSPEC, PROTO_CONNECTED, PROTO_STATIC,
                          PROTO_BGP, PROTO_OSPF, PROTO_RIP])

    def test_default_admin_distances(self):
        self.assertEqual(DEFAULT_ADMIN_DISTANCE,
                         {'connected': 0, 'static': 1, 'ebgp': 20,
                          'ibgp': 200})


class RouteSameOriginTestCase(unittest.TestCase):
    """Route identity within a destination is (protocol, source by
    identity)."""

    def setUp(self):
        self.prefix = parse_prefix('10.0.0.0/8')

    def test_same_protocol_and_identical_source_matches(self):
        source = object()
        a = _route(self.prefix, source=source)
        b = _route(self.prefix, metric=99, source=source)
        self.assertTrue(a.same_origin(b))
        self.assertTrue(b.same_origin(a))

    def test_an_equal_but_distinct_source_does_not_match(self):
        # Identity, not equality: two peers that happen to compare equal are
        # still two peers, and merging them would lose a path.
        # Lists rather than tuples: CPython folds two equal tuples of
        # constants in the same code object into one object, which would
        # make this test compare a source with itself.
        a = _route(self.prefix, source=['peer', 1])
        b = _route(self.prefix, source=['peer', 1])
        self.assertEqual(a.source, b.source)
        self.assertIsNot(a.source, b.source)
        self.assertFalse(a.same_origin(b))

    def test_a_different_protocol_does_not_match(self):
        source = object()
        a = _route(self.prefix, protocol=PROTO_BGP, source=source)
        b = _route(self.prefix, protocol=PROTO_OSPF, source=source)
        self.assertFalse(a.same_origin(b))

    def test_none_does_not_match(self):
        self.assertFalse(_route(self.prefix).same_origin(None))

    def test_a_none_source_matches_only_another_none_source(self):
        a = Route(self.prefix, PROTO_BGP, 20, 0, b'', None)
        b = Route(self.prefix, PROTO_BGP, 20, 1, b'', None)
        self.assertTrue(a.same_origin(b))
        self.assertFalse(a.same_origin(_route(self.prefix)))


class RouteSelectionTestCase(unittest.TestCase):
    """route_cmp's tie-breaks, one test each, in its documented order.

    Each case pins every input the earlier tie-breaks look at, so only the
    one under test can decide the winner, and every case is offered in both
    orders because a comparison that is right but an insertion order that
    leaks through is still a table that flaps the FIB.
    """

    PREFIX_TEXT = '10.0.0.0/8'

    def _winner(self, routes):
        table = RouteTable(AFI_IP)
        for route in routes:
            table.offer(route)
        changed = table.reselect(0)
        self.assertEqual(len(changed), 1)
        return changed[0].best

    def _assert_wins(self, expected, other):
        # Both orders: the scan in Dest._select keeps the earlier route on a
        # tie, so a one-sided test would pass on insertion order alone.
        self.assertIs(self._winner([expected, other]), expected)
        self.assertIs(self._winner([other, expected]), expected)

    def test_administrative_distance_decides_first(self):
        prefix = parse_prefix(self.PREFIX_TEXT)
        # Same protocol, same metric, same age: only the distance differs,
        # and the higher-distance route even has the better metric so a
        # wrong order would be visible.
        preferred = _route(prefix, distance=20, metric=10)
        rejected = _route(prefix, distance=200, metric=0)
        self._assert_wins(preferred, rejected)

    def test_metric_decides_at_equal_distance(self):
        prefix = parse_prefix(self.PREFIX_TEXT)
        preferred = _route(prefix, distance=20, metric=5)
        rejected = _route(prefix, distance=20, metric=10)
        self._assert_wins(preferred, rejected)

    def test_a_metric_is_never_compared_across_distances(self):
        # An OSPF cost and a BGP MED are not on the same scale, so the
        # operator's distance statement has to win outright.
        prefix = parse_prefix(self.PREFIX_TEXT)
        preferred = _route(prefix, protocol=PROTO_BGP, distance=20,
                           metric=4294967295)
        rejected = _route(prefix, protocol=PROTO_OSPF, distance=110,
                          metric=0)
        self._assert_wins(preferred, rejected)

    def test_protocol_preference_decides_at_equal_distance_and_metric(self):
        # Reached only by a configuration that gives two protocols the same
        # distance, which is unusual but must still be deterministic.
        prefix = parse_prefix(self.PREFIX_TEXT)
        preferred = _route(prefix, protocol=PROTO_CONNECTED, distance=10,
                           metric=5)
        rejected = _route(prefix, protocol=PROTO_STATIC, distance=10,
                          metric=5)
        self._assert_wins(preferred, rejected)
        preferred = _route(prefix, protocol=PROTO_OSPF, distance=10,
                           metric=5)
        rejected = _route(prefix, protocol=PROTO_RIP, distance=10, metric=5)
        self._assert_wins(preferred, rejected)

    def test_age_decides_last_and_the_oldest_wins(self):
        # Keeping the established route in place rather than churning the
        # FIB for an equally good new one.
        prefix = parse_prefix(self.PREFIX_TEXT)
        preferred = _route(prefix, distance=20, metric=5, recv_time=100.0)
        rejected = _route(prefix, distance=20, metric=5, recv_time=200.0)
        self._assert_wins(preferred, rejected)

    def test_indistinguishable_routes_keep_the_earlier_one(self):
        # route_cmp legitimately returns 0 here, and a table that reordered
        # these between passes would flap the FIB for no reason.
        prefix = parse_prefix(self.PREFIX_TEXT)
        first = _route(prefix, distance=20, metric=5, recv_time=100.0)
        second = _route(prefix, distance=20, metric=5, recv_time=100.0)
        self.assertIs(self._winner([first, second]), first)
        self.assertIs(self._winner([second, first]), second)

    def test_selection_is_order_independent(self):
        prefix = parse_prefix(self.PREFIX_TEXT)
        expected = _route(prefix, protocol=PROTO_BGP, distance=20, metric=5,
                          recv_time=100.0)
        others = [
            _route(prefix, protocol=PROTO_BGP, distance=20, metric=5,
                   recv_time=300.0),
            _route(prefix, protocol=PROTO_OSPF, distance=110, metric=1,
                   recv_time=50.0),
            _route(prefix, protocol=PROTO_STATIC, distance=20, metric=6,
                   recv_time=10.0),
            _route(prefix, protocol=PROTO_RIP, distance=120, metric=0,
                   recv_time=1.0),
        ]
        for order in itertools.permutations([expected] + others):
            self.assertIs(self._winner(list(order)), expected)

    def test_selection_is_order_independent_over_random_candidate_sets(self):
        rng = random.Random(20190801)
        prefix = parse_prefix(self.PREFIX_TEXT)
        for _ in range(60):
            routes = [_route(prefix,
                             protocol=rng.choice([PROTO_CONNECTED,
                                                  PROTO_STATIC, PROTO_BGP,
                                                  PROTO_OSPF, PROTO_RIP]),
                             distance=rng.choice([0, 1, 20, 110, 200]),
                             metric=rng.choice([0, 1, 5, 100]),
                             recv_time=float(rng.choice([10, 20, 30])))
                      for _ in range(5)]
            winners = set()
            for order in itertools.permutations(routes):
                winner = self._winner(list(order))
                # A tie keeps whichever candidate was offered first, so
                # compare the values that decided rather than identity.
                winners.add((winner.admin_distance, winner.metric,
                             winner.protocol, winner.recv_time))
            self.assertEqual(len(winners), 1)


class RouteTableOfferTestCase(unittest.TestCase):
    """Offers and withdrawals: the cheap half, before selection runs."""

    def setUp(self):
        self.table = RouteTable(AFI_IP)
        self.prefix = parse_prefix('10.0.0.0/8')
        self.source = object()

    def test_offer_returns_zero_for_a_new_route(self):
        route = _route(self.prefix, source=self.source)
        self.assertEqual(self.table.offer(route), 0)
        self.assertEqual(self.table.route_count, 1)

    def test_offer_returns_one_when_it_replaces_a_same_origin_route(self):
        first = _route(self.prefix, source=self.source)
        second = _route(self.prefix, metric=9, source=self.source)
        self.table.offer(first)
        self.assertEqual(self.table.offer(second), 1)
        self.assertEqual(self.table.route_count, 1)
        dest = self.table.get(self.prefix)
        self.assertEqual(list(dest), [second])

    def test_route_count_only_grows_for_genuinely_new_routes(self):
        for i in range(5):
            self.assertEqual(
                self.table.offer(_route(self.prefix, metric=i,
                                        source=self.source)),
                1 if i else 0)
        self.assertEqual(self.table.route_count, 1)
        other_source = object()
        self.assertEqual(
            self.table.offer(_route(self.prefix, protocol=PROTO_OSPF,
                                    distance=110, source=other_source)), 0)
        self.assertEqual(self.table.route_count, 2)
        # A different protocol from the same source is a different origin.
        self.assertEqual(
            self.table.offer(_route(self.prefix, protocol=PROTO_STATIC,
                                    distance=1, source=self.source)), 0)
        self.assertEqual(self.table.route_count, 3)
        self.assertEqual(len(self.table.get(self.prefix)), 3)

    def test_offer_requires_a_route(self):
        with self.assertRaises(ValueError):
            self.table.offer(None)

    def test_offer_rejects_a_foreign_family(self):
        with self.assertRaises(ValueError):
            self.table.offer(_route(parse_prefix('2001:db8::/32')))
        self.assertEqual(len(self.table), 0)

    def test_retract_returns_one_when_it_removed_something(self):
        self.table.offer(_route(self.prefix, source=self.source))
        self.assertEqual(
            self.table.retract(self.prefix, PROTO_BGP, self.source), 1)
        self.assertEqual(self.table.route_count, 0)

    def test_retract_of_an_unknown_prefix_returns_zero(self):
        self.table.offer(_route(self.prefix, source=self.source))
        self.assertEqual(
            self.table.retract(parse_prefix('11.0.0.0/8'), PROTO_BGP,
                               self.source), 0)
        self.assertEqual(self.table.route_count, 1)

    def test_retract_of_an_unknown_protocol_returns_zero(self):
        self.table.offer(_route(self.prefix, source=self.source))
        self.assertEqual(
            self.table.retract(self.prefix, PROTO_OSPF, self.source), 0)
        self.assertEqual(self.table.route_count, 1)

    def test_retract_of_an_unknown_source_returns_zero(self):
        self.table.offer(_route(self.prefix, source=self.source))
        self.assertEqual(
            self.table.retract(self.prefix, PROTO_BGP, object()), 0)
        self.assertEqual(self.table.route_count, 1)

    def test_retract_removes_only_the_named_origin(self):
        other = object()
        self.table.offer(_route(self.prefix, source=self.source))
        self.table.offer(_route(self.prefix, protocol=PROTO_OSPF,
                                distance=110, source=other))
        self.assertEqual(
            self.table.retract(self.prefix, PROTO_BGP, self.source), 1)
        self.assertEqual(self.table.route_count, 1)
        remaining = list(self.table.get(self.prefix))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].protocol, PROTO_OSPF)

    def test_an_offer_does_not_select(self):
        # The whole point of the queue: an offer is O(1) and leaves the
        # destination dirty for a later, deadline-bounded pass.
        route = _route(self.prefix, source=self.source)
        self.table.offer(route)
        dest = self.table.get(self.prefix)
        self.assertIsNone(dest.best)
        self.assertEqual(self.table.version, 0)
        self.assertEqual(self.table.pending(), 1)


class RouteTableChangeQueueTestCase(unittest.TestCase):
    """The change queue, which is what makes selection deadline-bounded."""

    def setUp(self):
        self.table = RouteTable(AFI_IP)
        self.source = object()

    def _offer(self, text, **kwargs):
        kwargs.setdefault('source', self.source)
        route = _route(parse_prefix(text), **kwargs)
        self.table.offer(route)
        return route

    def test_pending_reflects_queued_destinations(self):
        self.assertEqual(self.table.pending(), 0)
        for i in range(5):
            self._offer('10.%d.0.0/16' % i)
            self.assertEqual(self.table.pending(), i + 1)

    def test_a_destination_offered_many_times_is_selected_once(self):
        # The flag on the Dest is what collapses this: a prefix that flaps a
        # thousand times inside one batch costs one selection.
        for i in range(50):
            self._offer('10.0.0.0/8', metric=i, source=object())
        self.assertEqual(self.table.pending(), 1)
        changed = self.table.reselect(0)
        self.assertEqual(len(changed), 1)
        self.assertEqual(self.table.version, 1)
        self.assertEqual(self.table.route_count, 50)

    def test_reselect_honours_the_limit_and_leaves_the_rest_pending(self):
        for i in range(5):
            self._offer('10.%d.0.0/16' % i)
        self.assertEqual(len(self.table.reselect(2)), 2)
        self.assertEqual(self.table.pending(), 3)
        self.assertEqual(len(self.table.reselect(1)), 1)
        self.assertEqual(self.table.pending(), 2)
        self.assertEqual(len(self.table.reselect(10)), 2)
        self.assertEqual(self.table.pending(), 0)

    def test_reselect_zero_drains_everything(self):
        for i in range(20):
            self._offer('10.%d.0.0/16' % i)
        self.assertEqual(len(self.table.reselect(0)), 20)
        self.assertEqual(self.table.pending(), 0)
        for i in range(20):
            self._offer('11.%d.0.0/16' % i)
        self.assertEqual(len(self.table.reselect(-1)), 20)
        self.assertEqual(self.table.pending(), 0)

    def test_reselect_reports_in_the_order_the_destinations_were_queued(self):
        texts = ['10.5.0.0/16', '10.1.0.0/16', '10.9.0.0/16']
        for text in texts:
            self._offer(text)
        changed = self.table.reselect(0)
        self.assertEqual([d.prefix.to_str() for d in changed], texts)

    def test_an_untouched_destination_is_not_reported_again(self):
        self._offer('10.0.0.0/8')
        self.assertEqual(len(self.table.reselect(0)), 1)
        self.assertEqual(self.table.reselect(0), [])
        self._offer('11.0.0.0/8')
        changed = self.table.reselect(0)
        self.assertEqual([d.prefix.to_str() for d in changed],
                         ['11.0.0.0/8'])

    def test_a_losing_offer_does_not_change_the_best_route(self):
        winner = self._offer('10.0.0.0/8', distance=20)
        self.assertEqual(len(self.table.reselect(0)), 1)
        version = self.table.version
        self._offer('10.0.0.0/8', protocol=PROTO_OSPF, distance=110,
                    source=object())
        self.assertEqual(self.table.pending(), 1)
        self.assertEqual(self.table.reselect(0), [])
        self.assertEqual(self.table.version, version)
        self.assertIs(self.table.get(parse_prefix('10.0.0.0/8')).best,
                      winner)

    def test_a_reoffer_that_changes_nothing_observable_is_not_a_change(self):
        # P-5: this used to be reported, because the winner was a new Route
        # object and selection compares by identity -- so every soft
        # refresh rewrote the FIB and published a ROUTE_BEST per prefix for
        # nothing. The table now keeps the original, with its FIB state
        # and its age, and queues nothing.
        first = self._offer('10.0.0.0/8', metric=5)
        self.assertEqual(len(self.table.reselect(0)), 1)
        first.fib_state = FIB_STATE_INSTALLED
        second = self._offer('10.0.0.0/8', metric=5)
        self.assertIsNot(first, second)
        self.assertEqual(self.table.pending(), 0)
        self.assertEqual(self.table.reselect(0), [])
        best = self.table.get(parse_prefix('10.0.0.0/8')).best
        self.assertIs(best, first)
        self.assertEqual(best.fib_state, FIB_STATE_INSTALLED)
        self.assertEqual(self.table.route_count, 1)

    def test_a_reoffer_with_a_new_metric_or_next_hop_is_still_a_change(self):
        # The other half of P-5: only an *identical* re-offer is absorbed.
        self._offer('10.0.0.0/8', metric=5)
        self.table.reselect(0)
        remetric = self._offer('10.0.0.0/8', metric=6)
        changed = self.table.reselect(0)
        self.assertEqual(len(changed), 1)
        self.assertIs(changed[0].best, remetric)
        renexthop = self._offer('10.0.0.0/8', metric=6,
                                nexthop=b'\xc0\x00\x02\x63')
        changed = self.table.reselect(0)
        self.assertEqual(len(changed), 1)
        self.assertIs(changed[0].best, renexthop)

    def test_a_better_offer_replaces_the_best_route(self):
        self._offer('10.0.0.0/8', distance=200)
        self.table.reselect(0)
        better = self._offer('10.0.0.0/8', distance=20, source=object())
        changed = self.table.reselect(0)
        self.assertEqual(len(changed), 1)
        self.assertIs(changed[0].best, better)

    def test_the_last_withdrawal_is_reported_once_and_then_gone(self):
        prefix = parse_prefix('10.0.0.0/8')
        self._offer('10.0.0.0/8')
        self.table.reselect(0)
        self.assertEqual(
            self.table.retract(prefix, PROTO_BGP, self.source), 1)
        changed = self.table.reselect(0)
        self.assertEqual(len(changed), 1)
        self.assertIsNone(changed[0].best)
        self.assertEqual(changed[0].prefix, prefix)
        # Reported first, removed second, so the caller always sees the
        # withdrawal before the entry disappears.
        self.assertEqual(len(self.table), 0)
        self.assertEqual(self.table.route_count, 0)
        self.assertEqual(self.table.trie.nodes, 0)
        self.assertIsNone(self.table.get(prefix))
        self.assertEqual(self.table.reselect(0), [])

    def test_a_withdrawal_inside_one_batch_never_reports_a_best_route(self):
        # Offered and retracted before any selection ran, so the
        # destination's best was never set and there is nothing to report --
        # but the trie node still has to go.
        prefix = parse_prefix('10.0.0.0/8')
        self._offer('10.0.0.0/8')
        self.assertEqual(
            self.table.retract(prefix, PROTO_BGP, self.source), 1)
        self.assertEqual(self.table.pending(), 1)
        self.assertEqual(self.table.reselect(0), [])
        self.assertEqual(len(self.table), 0)
        self.assertEqual(self.table.trie.nodes, 0)

    def test_version_increases_on_every_best_change(self):
        self.assertEqual(self.table.version, 0)
        self._offer('10.0.0.0/8')
        self._offer('11.0.0.0/8')
        changed = self.table.reselect(0)
        self.assertEqual([d.version for d in changed], [1, 2])
        self.assertEqual(self.table.version, 2)
        # A pass that changes nothing does not advance it.
        self.assertEqual(self.table.reselect(0), [])
        self.assertEqual(self.table.version, 2)
        self._offer('10.0.0.0/8', distance=1, source=object())
        changed = self.table.reselect(0)
        self.assertEqual(self.table.version, 3)
        self.assertEqual(changed[0].version, 3)

    def test_the_winning_route_version_matches_the_destination_version(self):
        self._offer('10.0.0.0/8')
        self._offer('11.0.0.0/8')
        self._offer('12.0.0.0/8')
        for dest in self.table.reselect(0):
            self.assertIsNotNone(dest.best)
            self.assertEqual(dest.best.version, dest.version)
        # A losing route keeps its initial version: only the winner is
        # stamped.
        loser = self._offer('10.0.0.0/8', protocol=PROTO_OSPF, distance=110,
                            source=object())
        self.table.reselect(0)
        self.assertEqual(loser.version, 0)

    def test_work_queued_during_a_pass_is_not_dropped(self):
        # reselect re-reads len(queue) before compacting, because a change
        # callback or another plugin may have queued more work.
        for i in range(3):
            self._offer('10.%d.0.0/16' % i)
        self.assertEqual(len(self.table.reselect(2)), 2)
        self._offer('12.0.0.0/8')
        self.assertEqual(self.table.pending(), 2)
        changed = self.table.reselect(0)
        self.assertEqual([d.prefix.to_str() for d in changed],
                         ['10.2.0.0/16', '12.0.0.0/8'])
        self.assertEqual(self.table.pending(), 0)


class RouteTableLookupTestCase(unittest.TestCase):
    """The lookup and view surface."""

    def setUp(self):
        self.table = RouteTable(AFI_IP)
        self.source = object()

    def test_dest_interns_and_is_idempotent(self):
        prefix = parse_prefix('10.0.0.0/8')
        first = self.table.dest(prefix)
        self.assertIsInstance(first, Dest)
        self.assertIs(self.table.dest(prefix), first)
        self.assertIs(self.table.get(prefix), first)
        self.assertEqual(len(first), 0)
        self.assertIsNone(first.best)
        self.assertEqual(len(self.table), 1)
        # A non-canonical spelling of the same prefix reaches the same
        # destination, which is what the masking in Prefix is for.
        self.assertIs(self.table.dest(parse_prefix('10.1.2.3/8')), first)

    def test_get_of_an_absent_prefix_is_none(self):
        self.assertIsNone(self.table.get(parse_prefix('10.0.0.0/8')))
        self.table.dest(parse_prefix('10.0.0.0/8'))
        self.assertIsNone(self.table.get(parse_prefix('10.0.0.0/16')))
        # A foreign family is a miss rather than an error on the read path.
        self.assertIsNone(self.table.get(parse_prefix('2001:db8::/32')))

    def test_dest_rejects_a_missing_prefix_and_a_foreign_family(self):
        with self.assertRaises(ValueError):
            self.table.dest(None)
        with self.assertRaises(ValueError):
            self.table.dest(parse_prefix('2001:db8::/32'))

    def test_lpm_and_lpm_addr_return_destinations(self):
        prefix = parse_prefix('10.0.0.0/8')
        self.table.offer(_route(prefix, source=self.source))
        self.table.reselect(0)
        dest = self.table.get(prefix)
        self.assertIs(self.table.lpm(parse_prefix('10.1.2.0/24')), dest)
        self.assertIs(self.table.lpm(prefix), dest)
        self.assertIs(self.table.lpm_addr(b'\x0a\x01\x02\x03'), dest)
        self.assertIsNone(self.table.lpm(parse_prefix('11.0.0.0/8')))
        self.assertIsNone(self.table.lpm_addr(b'\x0b\x00\x00\x01'))

    def test_lpm_addr_rejects_a_wrong_width_address(self):
        with self.assertRaises(ValueError):
            self.table.lpm_addr(b'\x00' * 16)
        with self.assertRaises(ValueError):
            self.table.lpm_addr(b'')

    def test_lpm_can_return_a_destination_with_no_best_route(self):
        # Documented: a destination exists as soon as a route is offered,
        # but nothing is selected until the pass runs, so a caller
        # validating reachability must test best, not just the Dest.
        prefix = parse_prefix('10.0.0.0/8')
        self.table.offer(_route(prefix, source=self.source))
        dest = self.table.lpm(parse_prefix('10.1.2.0/24'))
        self.assertIsNotNone(dest)
        self.assertIsNone(dest.best)
        self.assertEqual(len(dest), 1)
        # A withdrawal leaves the previous winner in place for the same
        # reason: the entry is stale until the next pass reports it.
        self.table.reselect(0)
        self.table.retract(prefix, PROTO_BGP, self.source)
        stale = self.table.lpm_addr(b'\x0a\x01\x02\x03')
        self.assertEqual(len(stale), 0)
        self.assertIsNotNone(stale.best)
        self.assertIsNone(self.table.reselect(0)[0].best)

    def test_an_unknown_family_table_is_rejected(self):
        for afi in (0, 3, 7, 255):
            with self.assertRaises(ValueError):
                RouteTable(afi)

    def test_safi_defaults_to_unicast_and_is_carried(self):
        self.assertEqual(RouteTable(AFI_IP).safi, SAFI_UNICAST)
        self.assertEqual(RouteTable(AFI_IP6, 4).safi, 4)
        self.assertEqual(RouteTable(AFI_IP6).afi, AFI_IP6)

    def test_views_are_in_ascending_prefix_order(self):
        texts = ['10.1.0.0/16', '0.0.0.0/0', '10.0.0.0/8', '11.0.0.0/8',
                 '10.1.2.0/24']
        for text in texts:
            self.table.offer(_route(parse_prefix(text),
                                    source=self.source))
        self.table.reselect(0)
        ordered = sorted(parse_prefix(t) for t in texts)
        self.assertEqual(list(self.table.prefixes()), ordered)
        self.assertEqual([p for p, _ in self.table.items()], ordered)
        self.assertEqual([d.prefix for d in self.table], ordered)
        for prefix, dest in self.table.items():
            self.assertIs(dest, self.table.get(prefix))

    def test_stats(self):
        self.assertEqual(self.table.stats(),
                         {'afi': AFI_IP, 'safi': SAFI_UNICAST,
                          'prefixes': 0, 'routes': 0, 'nodes': 0,
                          'pending': 0, 'version': 0})
        self.table.offer(_route(parse_prefix('10.0.0.0/8'),
                                source=self.source))
        self.table.offer(_route(parse_prefix('11.0.0.0/8'),
                                source=self.source))
        stats = self.table.stats()
        self.assertEqual(sorted(stats),
                         ['afi', 'nodes', 'pending', 'prefixes', 'routes',
                          'safi', 'version'])
        self.assertEqual(stats['prefixes'], 2)
        self.assertEqual(stats['routes'], 2)
        # Two /8s diverge at bit 7, so there is one glue node holding them
        # apart.
        self.assertEqual(stats['nodes'], 3)
        self.assertEqual(stats['pending'], 2)
        self.assertEqual(stats['version'], 0)
        self.table.reselect(0)
        self.assertEqual(self.table.stats()['pending'], 0)
        self.assertEqual(self.table.stats()['version'], 2)

    def test_dest_len_and_iteration(self):
        prefix = parse_prefix('10.0.0.0/8')
        bgp = _route(prefix, source=self.source)
        ospf = _route(prefix, protocol=PROTO_OSPF, distance=110,
                      source=object())
        self.table.offer(bgp)
        self.table.offer(ospf)
        self.table.reselect(0)
        dest = self.table.get(prefix)
        self.assertEqual(len(dest), 2)
        self.assertEqual(list(dest), [bgp, ospf])
        self.assertEqual(list(iter(dest)), dest.routes)

    def test_dest_as_dict(self):
        prefix = parse_prefix('10.0.0.0/8')
        self.table.offer(_route(prefix, source=self.source,
                                nexthop=b'\x0a\x00\x00\x01'))
        self.table.reselect(0)
        dest = self.table.get(prefix)
        document = dest.as_dict()
        self.assertEqual(sorted(document), ['best', 'prefix', 'routes'])
        self.assertEqual(document['prefix'], '10.0.0.0/8')
        self.assertEqual(document['best'], dest.best.as_dict())
        self.assertEqual(document['routes'],
                         [r.as_dict() for r in dest.routes])

    def test_dest_as_dict_with_no_best_route(self):
        dest = self.table.dest(parse_prefix('10.0.0.0/8'))
        self.assertEqual(dest.as_dict(),
                         {'prefix': '10.0.0.0/8', 'best': None,
                          'routes': []})

    def test_dest_repr(self):
        prefix = parse_prefix('10.0.0.0/8')
        self.table.offer(_route(prefix, source=self.source))
        self.table.reselect(0)
        self.assertEqual(repr(self.table.get(prefix)),
                         '<Dest 10.0.0.0/8 routes=1 best=bgp>')
        self.assertEqual(repr(self.table.dest(parse_prefix('11.0.0.0/8'))),
                         '<Dest 11.0.0.0/8 routes=0 best=none>')

    def test_a_destination_needs_a_prefix(self):
        with self.assertRaises(ValueError):
            Dest(None)

    def test_table_repr(self):
        self.table.offer(_route(parse_prefix('10.0.0.0/8'),
                                source=self.source))
        self.table.reselect(0)
        self.assertEqual(repr(self.table),
                         '<RouteTable afi=1 safi=1 prefixes=1 routes=1>')

    def test_an_interned_destination_is_collected_by_the_next_pass(self):
        # RouteTable.dest documents that a destination interned and then
        # abandoned is collected by the next selection pass, so that a
        # caller which changes its mind does not leak a trie node. Compare
        # the identical promise in reselect: "Destinations left with no
        # routes at all are dropped here, along with their trie node."
        prefix = parse_prefix('10.0.0.0/8')
        self.table.dest(prefix)
        self.assertEqual(len(self.table), 1)
        self.table.reselect(0)
        self.assertIsNone(self.table.get(prefix))
        self.assertEqual(len(self.table), 0)
        self.assertEqual(self.table.trie.nodes, 0)


class RouteTableScaleTestCase(unittest.TestCase):
    """A table the size of a small real one, built and torn down.

    A correctness check rather than a benchmark: the counters and the
    ordering are what matter, and the point of the size is that the trie's
    splits, glue nodes and pruning all happen many thousands of times rather
    than once.
    """

    COUNT = 20000

    @staticmethod
    def _prefixes(count):
        # Sequential /24s out of 10/8: consecutive keys share most of their
        # bits, which is what a real table looks like and what makes path
        # compression and glue-node reuse do any work at all.
        return [Prefix(AFI_IP, 24, _pack((10 << 24) | (i << 8), 4))
                for i in range(count)]

    def test_twenty_thousand_prefixes_in_and_out(self):
        table = RouteTable(AFI_IP)
        source = object()
        prefixes = self._prefixes(self.COUNT)

        for prefix in prefixes:
            self.assertEqual(
                table.offer(Route(prefix, PROTO_BGP, 20, 0,
                                  b'\x0a\x00\x00\x01', source, 100.0)), 0)
        self.assertEqual(table.pending(), self.COUNT)
        self.assertEqual(len(table.reselect(0)), self.COUNT)
        self.assertEqual(table.pending(), 0)
        self.assertEqual(len(table), self.COUNT)
        self.assertEqual(table.route_count, self.COUNT)
        self.assertEqual(table.version, self.COUNT)

        walked = list(table.prefixes())
        self.assertEqual(len(walked), self.COUNT)
        self.assertEqual(walked, sorted(prefixes))
        for dest in table:
            self.assertIsNotNone(dest.best)
            self.assertEqual(dest.best.prefix, dest.prefix)

        # Sampled rather than exhaustive: the resolver path is already
        # covered against an oracle, and 20,000 brute-force LPMs would make
        # this a benchmark.
        rng = random.Random(20190901)
        for _ in range(200):
            index = rng.randrange(self.COUNT)
            addr = _pack((10 << 24) | (index << 8) | rng.randint(0, 255), 4)
            dest = table.lpm_addr(addr)
            self.assertIsNotNone(dest)
            self.assertEqual(dest.prefix, prefixes[index])

        for prefix in prefixes:
            self.assertEqual(table.retract(prefix, PROTO_BGP, source), 1)
        self.assertEqual(len(table.reselect(0)), self.COUNT)
        self.assertEqual(len(table), 0)
        self.assertEqual(table.route_count, 0)
        self.assertEqual(table.trie.nodes, 0)
        self.assertEqual(table.pending(), 0)
        self.assertEqual(list(table.prefixes()), [])
        self.assertEqual(table.stats()['prefixes'], 0)


if __name__ == '__main__':
    unittest.main()
