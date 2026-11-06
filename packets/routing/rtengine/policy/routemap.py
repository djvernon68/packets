# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Route-maps: ordered clauses of match tests and normalized edits.

A route-map is the engine's general policy hook. Its shape is IOS': an
ordered list of clauses, each a ``permit`` or ``deny`` with a set of match
conditions and a set of edits, and the first clause whose conditions *all*
hold decides the fate of the route. A ``permit`` clause applies its edits and
accepts; a ``deny`` clause rejects and its edits are ignored; a clause with
no conditions matches everything, which is how the trailing catch-all is
written. A route that matches no clause at all is *denied* -- IOS' implicit
deny -- and the result says so through ``matched=False``, because "your
route-map has no clause for this prefix" and "your route-map explicitly
rejected this prefix" are the same outcome with very different fixes.

**Everything is parsed once.** This is the design constraint the whole module
is arranged around. :meth:`RouteMap.apply` runs once per prefix per peer:
accepting a full table through an inbound route-map is a million calls, and
an outbound policy re-runs on every re-selection. So the configuration is
converted at construction time into exactly the form the comparison needs --
regexes compiled, addresses packed into wire bytes, community strings
converted to integers and then to their 4-byte wire form, the length window
of a prefix-list entry reduced to two numbers -- and ``apply`` does nothing
but compare. A match clause that parsed its own configuration text per path,
or called ``inet_pton`` per path, would be the most expensive thing in the
engine and would look perfectly reasonable in review.

**What apply() is given, and why it is not a BGP object.** ``apply`` takes a
:class:`~...rib.prefix.Prefix` and an attribute object, and the attribute
object is specified by the attributes it exposes rather than by its class:
``origin``, ``as_path_str()``, ``communities``, ``large_communities``,
``ext_communities``, ``nexthop``, ``med``, ``local_pref``, ``has_med()`` and
``has_local_pref()``. The BGP plugin's ``AttrSet`` satisfies that contract as
it stands, with no adapter, and this module deliberately does not import it:
policy is core code, it is loaded and validated before any plugin is
configured, and a core module that imported a plugin would invert the
dependency the whole engine is built on. Python 3.6 has no
``typing.Protocol`` to write the contract down in, so it is written here and
enforced by the tests, which use a stand-in object of their own.

``None`` attributes are allowed and mean "no path attributes at all", which
is what a locally originated or non-BGP route looks like. Every match clause
that needs attributes then fails to match rather than raising, so a
prefix-only route-map works on a route that has no BGP attributes.

**The community alignment trap.** Communities arrive as packed bytes, four
per community, sorted. Testing membership with a substring search is wrong
and the failure is silent: the four bytes ``ff ff ff 02`` (NO_ADVERTISE)
appear in the middle of the pair ``0:65535`` followed by ``65282:0``, which
are two ordinary communities. So every membership test here is aligned to the
attribute's stride -- 4 bytes for a community, 12 for a large community --
with the unaligned search kept only as a prefilter, because it is a C-level
scan and the answer is almost always no. This is the same trick, for the same
reason, as ``_has_community`` in the BGP plugin's Adj-RIB-Out.

**What the result promises.** The edits come back in
:class:`RouteMapResult` as a dict with a fixed, normalized key set -- the
keys are the ones a protocol translator consumes, not the ones the operator
wrote -- and ``weight`` comes back separately because it is not an attribute
at all: it is local to the speaker, never encoded, and a translator that
treated it as an attribute edit would try to put it on the wire. The dict is
the *clause's own* dict, shared by every route that clause permits, so a
consumer must read it and not mutate it. Copying it per route would be a
dictionary allocation per prefix per peer for the benefit of a caller that
has no reason to write to it.

**Deliberately absent.** ``route-map continue`` is not supported and is
rejected at parse time rather than ignored: a configuration that relies on
falling through to a later clause behaves *completely* differently when the
fall-through is dropped, and silently applying only the first matching
clause would be the kind of difference that is discovered by a leaked route.
Matching on a peer's AS or address, on interfaces, on tags and on RPKI state
are all absent as well; ``ctx`` is the argument they will arrive through, and
it is accepted and ignored today so that the signature does not have to
change when they do.
"""

import socket
import struct

from packets.routing.rtengine.policy.aspath import AsPathMatcher
from packets.routing.rtengine.policy.prefixlist import (ACTION_DENY,
                                                        ACTION_NAMES,
                                                        ACTION_PERMIT,
                                                        NO_MATCH, action_id,
                                                        seq_number)
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6

__all__ = ['ACTION_DENY', 'ACTION_PERMIT', 'ACTION_NAMES', 'NO_MATCH',
           'ORIGIN_IGP', 'ORIGIN_EGP', 'ORIGIN_INCOMPLETE', 'ORIGIN_NAMES',
           'WELL_KNOWN_COMMUNITIES', 'MATCH_KEYWORDS', 'SET_KEYWORDS',
           'RouteMap', 'RouteMapClause', 'RouteMapResult', 'community_text',
           'large_community_text']

# ORIGIN, RFC 4271 s4.3. The values are the wire values, and they are
# duplicated from the BGP plugin's attrs.pxd on purpose: a core module may
# not import a plugin, and these three numbers are a registry assignment
# rather than the plugin's invention. The tests pin them against the
# plugin's own constants so the duplication cannot drift.
ORIGIN_IGP = 0
ORIGIN_EGP = 1
ORIGIN_INCOMPLETE = 2

#: Origin id to the word configuration and show output use.
ORIGIN_NAMES = {ORIGIN_IGP: 'igp', ORIGIN_EGP: 'egp',
                ORIGIN_INCOMPLETE: 'incomplete'}

_ORIGIN_IDS = dict((name, oid) for oid, name in ORIGIN_NAMES.items())

#: The community names an operator may write instead of a number. RFC 1997
#: for the first three, RFC 1997 s5 for ``internet`` (which is the value 0
#: and means "no restriction"), and ``local-as`` is IOS' spelling of
#: NO_EXPORT_SUBCONFED -- the same value, accepted under both names because
#: configurations in the wild use both.
WELL_KNOWN_COMMUNITIES = {
    'internet': 0x00000000,
    'no-export': 0xffffff01,
    'no-advertise': 0xffffff02,
    'no-export-subconfed': 0xffffff03,
    'local-as': 0xffffff03,
}

# Reverse mapping for show output. Built from the canonical spellings only,
# so a value that has two names renders as the RFC one rather than as
# whichever happened to be iterated last.
_COMMUNITY_TEXT = {
    0x00000000: 'internet',
    0xffffff01: 'no-export',
    0xffffff02: 'no-advertise',
    0xffffff03: 'no-export-subconfed',
}

#: Every match keyword this version understands. Anything else in a match
#: clause is a configuration error rather than something ignored: a
#: misspelled match keyword that was ignored would turn a filter into a
#: permit-everything clause.
MATCH_KEYWORDS = ('ip', 'ipv6', 'as-path', 'community', 'large-community',
                  'metric', 'local-preference', 'origin', 'next-hop')

#: Every set keyword this version understands.
SET_KEYWORDS = ('local-preference', 'metric', 'origin', 'next-hop', 'weight',
                'community', 'large-community', 'as-path')

# The one rejection with its own message. `continue` changes the control flow
# of the whole route-map rather than adding a condition, so treating it as an
# unknown keyword would tell an operator to check their spelling when the
# problem is that the feature is absent.
_CONTINUE_MESSAGE = (
    "'route-map continue' is not supported: this engine evaluates clauses "
    'until the first match and then stops. Rewrite the policy as '
    'independent clauses, or as several route-maps applied in turn.')

# Shared by every result that carries no edits, which is every deny and every
# implicit deny. Consumers treat `sets` as read-only -- see the module
# docstring -- so one instance is safe and saves an allocation per filtered
# prefix on a path that filters millions of them.
_NO_SETS = {}


def _coerce_int(what, value, low, high):
    """Range-check an integer configuration value.

    :param what: the keyword, for the message.
    :param value: the value.
    :param low: inclusive minimum.
    :param high: inclusive maximum.
    :return: the value as an int.
    :raises ValueError: not an int, a bool, or out of range. Bools are
        rejected explicitly because ``True`` is an ``int`` in Python and
        would otherwise become a metric of 1.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError('%s must be an integer, not %r' % (what, value))
    if value < low or value > high:
        raise ValueError('%s %r is outside %d..%d' % (what, value, low, high))
    return value


def _origin_id(value):
    """Convert a configured origin to its wire value.

    :param value: ``'igp'``, ``'egp'``, ``'incomplete'``, or 0, 1 or 2.
    :return: the origin id.
    :raises ValueError: anything else.
    """
    if isinstance(value, str):
        try:
            return _ORIGIN_IDS[value]
        except KeyError:
            raise ValueError("origin must be one of 'igp', 'egp', "
                             "'incomplete', not %r" % (value,))
    if isinstance(value, int) and not isinstance(value, bool) \
            and value in ORIGIN_NAMES:
        return value
    raise ValueError("origin must be one of 'igp', 'egp', 'incomplete', "
                     'not %r' % (value,))


def _pack_addr(value):
    """Convert an address to its packed wire form, once.

    The family is inferred from the text, as everywhere else in the engine:
    a colon means IPv6. Already-packed bytes of the right width are accepted
    so that a caller holding a next-hop it read off a route does not have to
    format it into text for this.

    :param value: address text, or 4 or 16 packed bytes.
    :return: 4 or 16 bytes.
    :raises ValueError: unparseable text, or bytes of the wrong width.
    """
    if isinstance(value, (bytes, bytearray)):
        if len(value) in (4, 16):
            return bytes(value)
        raise ValueError('a packed address must be 4 or 16 bytes, not %d'
                         % len(value))
    if not isinstance(value, str):
        raise ValueError('an address must be text or packed bytes, not %s'
                         % type(value).__name__)
    family = socket.AF_INET6 if ':' in value else socket.AF_INET
    try:
        return socket.inet_pton(family, value)
    except (OSError, ValueError):
        # inet_pton reports a bad address as OSError, which would reach an
        # API handler as a 500; everything wrong with an address here is the
        # caller's input.
        raise ValueError('not a valid address: %r' % (value,))


def _addr_text(packed):
    """Render a packed address for show output.

    :param packed: 4 or 16 bytes.
    :return: the conventional text form.
    """
    family = socket.AF_INET if len(packed) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, packed)


def community_value(item):
    """Convert one configured community to its 32-bit value.

    :param item: ``'ASN:VALUE'`` with both halves in 0..65535, a bare
        integer in 0..4294967295, a decimal string of one, or one of the
        names in :data:`WELL_KNOWN_COMMUNITIES`.
    :return: the community as an int.
    :raises ValueError: any other spelling. Strict on purpose: a community
        that was silently dropped or misparsed produces a filter that
        matches the wrong routes, and the two halves of ``ASN:VALUE`` are
        16 bits each, so ``65536:1`` is a typo rather than a wide community.
    """
    if isinstance(item, int) and not isinstance(item, bool):
        return _coerce_int('community', item, 0, 0xffffffff)
    if not isinstance(item, str):
        raise ValueError('a community must be text or an integer, not %s'
                         % type(item).__name__)
    known = WELL_KNOWN_COMMUNITIES.get(item)
    if known is not None:
        return known
    if ':' in item:
        high, _, low = item.partition(':')
        if high.isdigit() and low.isdigit():
            high_v = int(high)
            low_v = int(low)
            if high_v <= 0xffff and low_v <= 0xffff:
                return (high_v << 16) | low_v
        raise ValueError("not a community: %r; use 'ASN:VALUE' with both "
                         'halves in 0..65535' % (item,))
    if item.isdigit():
        return _coerce_int('community', int(item), 0, 0xffffffff)
    raise ValueError("not a community: %r; use 'ASN:VALUE', an integer, or "
                     'one of %s' % (item, ', '.join(
                         sorted(WELL_KNOWN_COMMUNITIES))))


def community_text(value):
    """Render a community value the way an operator writes it.

    :param value: the 32-bit community value.
    :return: its well-known name if it has one, else ``'ASN:VALUE'``.
    """
    known = _COMMUNITY_TEXT.get(value)
    if known is not None:
        return known
    return '%d:%d' % ((value >> 16) & 0xffff, value & 0xffff)


def large_community_value(item):
    """Convert one configured large community to its three 32-bit parts.

    :param item: ``'A:B:C'`` with each part in 0..4294967295, or a sequence
        of three integers.
    :return: a ``(global_admin, local1, local2)`` tuple of ints.
    :raises ValueError: any other spelling.
    """
    if isinstance(item, (tuple, list)):
        if len(item) != 3:
            raise ValueError('a large community needs exactly three parts, '
                             'not %d' % len(item))
        return tuple(_coerce_int('large community part', part, 0, 0xffffffff)
                     for part in item)
    if not isinstance(item, str):
        raise ValueError('a large community must be text or three integers, '
                         'not %s' % type(item).__name__)
    parts = item.split(':')
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError("not a large community: %r; use 'A:B:C' with each "
                         'part in 0..4294967295' % (item,))
    return tuple(_coerce_int('large community part', int(p), 0, 0xffffffff)
                 for p in parts)


def large_community_text(value):
    """Render a large community tuple as ``'A:B:C'``.

    :param value: a three-int tuple.
    :return: the text form.
    """
    return '%d:%d:%d' % value


def _community_values(items, what):
    """Parse a configured community collection into sorted unique values.

    Sorted and de-duplicated because the attribute this is compared against
    is canonicalised the same way: the BGP decoder sorts communities, since
    their order carries no meaning and an unsorted pair would otherwise
    intern as two distinct attribute sets. Keeping both sides in the same
    order is what lets the exact-match test be one bytes comparison.

    :param items: a list or tuple of community spellings.
    :param what: the keyword, for messages.
    :return: a tuple of ints, ascending, without duplicates.
    :raises ValueError: not a list, an empty list, or a bad spelling.
    """
    if not isinstance(items, (list, tuple)):
        raise ValueError('%s needs a list of communities, not %s'
                         % (what, type(items).__name__))
    if not items:
        raise ValueError("%s needs at least one community; to clear them "
                         "use 'none'" % what)
    return tuple(sorted({community_value(item) for item in items}))


def _large_community_values(items, what):
    """Parse a configured large-community collection into sorted tuples.

    :param items: a list or tuple of large-community spellings.
    :param what: the keyword, for messages.
    :return: a tuple of three-int tuples, ascending, without duplicates.
    :raises ValueError: not a list, an empty list, or a bad spelling.
    """
    if not isinstance(items, (list, tuple)):
        raise ValueError('%s needs a list of large communities, not %s'
                         % (what, type(items).__name__))
    if not items:
        raise ValueError("%s needs at least one large community; to clear "
                         "them use 'none'" % what)
    return tuple(sorted({large_community_value(item) for item in items}))


def _has_aligned(packed, target, stride):
    """Return whether a packed attribute holds one value, on its boundary.

    The alignment is the whole point. A community is four bytes and the
    attribute is a run of them, so an unaligned substring search finds a
    value that straddles two entries: ``ff ff ff 02`` sits in the middle of
    ``0:65535`` followed by ``65282:0``, neither of which is NO_ADVERTISE.
    The unaligned search is kept as a prefilter because it runs in C and
    almost always answers no, which is what keeps the aligned loop off the
    hot path for the overwhelming majority of routes.

    :param packed: the attribute bytes, ``stride`` per value.
    :param target: the packed value to look for, exactly ``stride`` bytes.
    :param stride: 4 for a community, 12 for a large community.
    :return: True if present on a ``stride`` boundary.
    """
    if not packed or target not in packed:
        return False
    for offset in range(0, len(packed) - stride + 1, stride):
        if packed[offset:offset + stride] == target:
            return True
    return False


# --- compiled match clauses -------------------------------------------------
# One class per keyword, each holding the configuration in the form the
# comparison wants and nothing else. They are ordered by `cost` inside a
# clause so the cheapest test runs first: match conditions are a conjunction,
# so the order cannot change the answer, and the first failure ends the
# clause. Selectivity would be the better ordering criterion -- a prefix-list
# usually rejects more routes than an origin test does -- but it is not
# knowable at parse time, and cost is.

class _Match(object):
    """Base for a compiled match condition.

    Subclasses hold their configuration already converted (packed, compiled,
    or reduced to integers) and implement three things: the test itself, the
    configuration fragment they came from so show output can reproduce it,
    and the policy objects they depend on so the store can refuse a
    document that references something undefined and a caller can invalidate
    an update group when a referenced list changes.
    """

    __slots__ = ()

    #: Relative expense of the test, low first. See the note above.
    cost = 50

    def matches(self, prefix, attrs, ctx):
        """Return whether this condition holds for one route."""
        raise NotImplementedError

    def as_config(self):
        """Return the ``(keyword, value)`` this was parsed from."""
        raise NotImplementedError

    def references(self):
        """Return the ``(kind, name)`` policy objects this depends on."""
        return ()


class OriginMatch(_Match):
    """``match origin igp|egp|incomplete``."""

    __slots__ = ('origin',)

    cost = 10

    def __init__(self, value):
        self.origin = _origin_id(value)

    def matches(self, prefix, attrs, ctx):
        if attrs is None:
            return False
        return attrs.origin == self.origin

    def as_config(self):
        return 'origin', ORIGIN_NAMES[self.origin]


class MetricMatch(_Match):
    """``match metric N``, which is BGP's MED.

    A path with no MED does not match any metric value, including 0. RFC
    4271 lets a *comparison* treat a missing MED as 0, but a match clause is
    a question about the attribute, and answering "yes, 0" for a path that
    carries no MED would make ``match metric 0`` select every path that has
    no MED -- which is most of them on an eBGP session.
    """

    __slots__ = ('metric',)

    cost = 10

    def __init__(self, value):
        self.metric = _coerce_int('metric', value, 0, 0xffffffff)

    def matches(self, prefix, attrs, ctx):
        if attrs is None or not attrs.has_med():
            return False
        return attrs.med == self.metric

    def as_config(self):
        return 'metric', self.metric


class LocalPrefMatch(_Match):
    """``match local-preference N``.

    As with the metric, a path carrying no LOCAL_PREF matches nothing: the
    default local preference is a property of the speaker's configuration,
    not of the path, so a match against it would be asking this module about
    a number it has not been told.
    """

    __slots__ = ('local_pref',)

    cost = 10

    def __init__(self, value):
        self.local_pref = _coerce_int('local-preference', value, 0,
                                      0xffffffff)

    def matches(self, prefix, attrs, ctx):
        if attrs is None or not attrs.has_local_pref():
            return False
        return attrs.local_pref == self.local_pref

    def as_config(self):
        return 'local-preference', self.local_pref


class NextHopMatch(_Match):
    """``match next-hop ADDRESS``.

    Compared against the packed next hop, so the address text is converted
    once here rather than per route. An address of the other family simply
    never matches, because the widths differ.
    """

    __slots__ = ('nexthop',)

    cost = 15

    def __init__(self, value):
        self.nexthop = _pack_addr(value)

    def matches(self, prefix, attrs, ctx):
        if attrs is None:
            return False
        return attrs.nexthop == self.nexthop

    def as_config(self):
        return 'next-hop', _addr_text(self.nexthop)


class PrefixListMatch(_Match):
    """``match ip address prefix-list NAME``, or the ``ipv6`` form.

    The list is resolved by name on every application rather than held as a
    reference. That is one dict lookup, and it is what makes a list that was
    deleted and re-created under the same name -- which is what a
    configuration replace looks like -- take effect without every clause
    that mentions it having to be rebuilt.

    A prefix of the other family never matches, which is what lets a
    dual-stack table be pushed through one route-map: the ``ip`` clause
    ignores IPv6 prefixes instead of erroring on them.

    :param afi: ``AFI_IP`` or ``AFI_IP6``.
    :param name: the prefix-list name.
    :param resolver: the object holding the lists, normally the
        :class:`~..store.PolicyStore`. It must expose
        ``prefix_list(name, afi)``. None means nothing can be resolved and
        the clause never matches; the store refuses to load a document that
        references an undefined list, so that state is only reachable for a
        route-map built by hand.
    """

    __slots__ = ('afi', 'name', 'resolver')

    cost = 20

    def __init__(self, afi, name, resolver=None):
        if afi not in (AFI_IP, AFI_IP6):
            raise ValueError('unsupported address family number %r' % (afi,))
        if not name or not isinstance(name, str):
            raise ValueError('a prefix-list name is required, not %r'
                             % (name,))
        self.afi = afi
        self.name = name
        self.resolver = resolver

    def matches(self, prefix, attrs, ctx):
        if prefix is None or prefix.afi != self.afi:
            return False
        if self.resolver is None:
            return False
        plist = self.resolver.prefix_list(self.name, self.afi)
        if plist is None:
            return False
        return plist.permits(prefix)

    def as_config(self):
        key = 'ip' if self.afi == AFI_IP else 'ipv6'
        return key, {'address': {'prefix-list': self.name}}

    def references(self):
        kind = 'prefix-list' if self.afi == AFI_IP else 'ipv6-prefix-list'
        return ((kind, self.name),)


class AsPathRegexMatch(_Match):
    """``match as-path REGEX``, or a list of them, matched any-of.

    A list is any-of rather than all-of because that is what a list of
    regexes means everywhere it appears in routing configuration: the
    alternative is a single pattern with an alternation, which the operator
    could have written.

    :param patterns: one pattern string, or a list of them.
    :raises ValueError: an empty list, or a pattern that does not compile.
    """

    __slots__ = ('matchers', '_single')

    cost = 60

    def __init__(self, patterns):
        if isinstance(patterns, str):
            self._single = True
            items = [patterns]
        elif isinstance(patterns, (list, tuple)):
            if not patterns:
                raise ValueError('as-path needs at least one regex')
            self._single = False
            items = list(patterns)
        else:
            raise ValueError('as-path needs a regex or a list of them, not '
                             '%s' % type(patterns).__name__)
        self.matchers = tuple(AsPathMatcher(item) for item in items)

    def matches(self, prefix, attrs, ctx):
        if attrs is None:
            return False
        # Rendered once for the whole clause, not once per pattern: the
        # string is built by walking the AS_PATH segments, which is the
        # expensive half of this test.
        text = attrs.as_path_str()
        for matcher in self.matchers:
            if matcher.matches(text):
                return True
        return False

    def as_config(self):
        if self._single:
            return 'as-path', self.matchers[0].pattern
        return 'as-path', [m.pattern for m in self.matchers]


class AsPathListMatch(_Match):
    """``match as-path access-list NAME``.

    The named list evaluates to permit, deny or no-match; the clause matches
    only on an explicit permit. A deny entry therefore means "this clause
    does not match", not "reject the route" -- the route-map's own clause
    action decides that, and folding the list's deny into a route rejection
    would make a ``deny`` clause with an as-path list mean the opposite of
    what it says.
    """

    __slots__ = ('name', 'resolver')

    cost = 60

    def __init__(self, name, resolver=None):
        if not name or not isinstance(name, str):
            raise ValueError('an as-path access-list name is required, not '
                             '%r' % (name,))
        self.name = name
        self.resolver = resolver

    def matches(self, prefix, attrs, ctx):
        if attrs is None or self.resolver is None:
            return False
        alist = self.resolver.as_path_list(self.name)
        if alist is None:
            return False
        return alist.permits(attrs.as_path_str())

    def as_config(self):
        return 'as-path', {'access-list': self.name}

    def references(self):
        return (('as-path', self.name),)


class CommunityMatch(_Match):
    """``match community``, with or without ``exact-match``.

    Without ``exact-match``, every listed community must be present on the
    route; extra communities are allowed. With it, the route's community set
    must be exactly the listed one. That is IOS' pair of behaviours for a
    standard community list, and the reason the non-exact form is all-of
    rather than any-of is that ``exact-match`` is defined as its
    strengthening: an any-of default would leave "route carries all of
    these" unexpressible.

    The exact test is one bytes comparison, because both sides are sorted
    and de-duplicated -- the decoder canonicalises the attribute and
    :func:`_community_values` canonicalises the configuration.
    """

    __slots__ = ('values', 'targets', 'exact', '_expected')

    cost = 30

    def __init__(self, values, exact=False):
        self.values = values
        self.targets = tuple(struct.pack('>I', v) for v in values)
        self.exact = bool(exact)
        self._expected = b''.join(self.targets)

    def matches(self, prefix, attrs, ctx):
        if attrs is None:
            return False
        packed = attrs.communities
        if self.exact:
            return packed == self._expected
        if not packed:
            return False
        for target in self.targets:
            if not _has_aligned(packed, target, 4):
                return False
        return True

    def as_config(self):
        items = [community_text(v) for v in self.values]
        if self.exact:
            return 'community', {'list': items, 'exact-match': True}
        return 'community', items


class LargeCommunityMatch(_Match):
    """``match large-community``, RFC 8092, with the same rules.

    All-of by default, exact-match on request, and aligned to the 12-byte
    stride of the attribute -- an unaligned search over large communities is
    even easier to fool than over ordinary ones, because three 32-bit parts
    give a longer run of bytes for a target to hide in.
    """

    __slots__ = ('values', 'targets', 'exact', '_expected')

    cost = 35

    def __init__(self, values, exact=False):
        self.values = values
        self.targets = tuple(struct.pack('>III', *v) for v in values)
        self.exact = bool(exact)
        self._expected = b''.join(self.targets)

    def matches(self, prefix, attrs, ctx):
        if attrs is None:
            return False
        packed = attrs.large_communities
        if self.exact:
            return packed == self._expected
        if not packed:
            return False
        for target in self.targets:
            if not _has_aligned(packed, target, 12):
                return False
        return True

    def as_config(self):
        items = [large_community_text(v) for v in self.values]
        if self.exact:
            return 'large-community', {'list': items, 'exact-match': True}
        return 'large-community', items


# --- parsing ----------------------------------------------------------------

def _parse_community_match(value, what, parse_values, factory):
    """Parse a community or large-community match clause.

    Both keywords take the same two shapes -- a bare list, or a dict with a
    ``list`` and an ``exact-match`` flag -- so they share a parser rather
    than having two that can drift.

    :param value: the configured value.
    :param what: the keyword, for messages.
    :param parse_values: the value parser for this keyword.
    :param factory: the matcher class to build.
    :return: the matcher.
    :raises ValueError: any other shape, or an unknown key in the dict form.
    """
    if isinstance(value, dict):
        unknown = [k for k in sorted(value)
                   if k not in ('list', 'exact-match')]
        if unknown:
            raise ValueError("unknown %s option %r; expected 'list' or "
                             "'exact-match'" % (what, unknown[0]))
        if 'list' not in value:
            raise ValueError("%s needs a 'list'" % what)
        exact = value.get('exact-match', False)
        if not isinstance(exact, bool):
            raise ValueError('%s exact-match must be true or false, not %r'
                             % (what, exact))
        return factory(parse_values(value['list'], what), exact)
    return factory(parse_values(value, what), False)


def _parse_prefix_list_match(family, value, resolver):
    """Parse ``{'ip': {'address': {'prefix-list': NAME}}}``.

    The nesting is IOS' command shape, and it is validated all the way down
    rather than reached into: ``match ip next-hop`` and ``match ip
    route-source`` are real IOS clauses this version does not implement, and
    a parser that only looked for ``address`` would accept them silently and
    filter nothing.

    :param family: ``'ip'`` or ``'ipv6'``.
    :param value: the configured value.
    :param resolver: the prefix-list resolver to give the matcher.
    :return: the matcher.
    :raises ValueError: any other shape.
    """
    afi = AFI_IP if family == 'ip' else AFI_IP6
    if not isinstance(value, dict):
        raise ValueError("match %s needs {'address': {'prefix-list': NAME}}"
                         % family)
    unknown = [k for k in sorted(value) if k != 'address']
    if unknown:
        raise ValueError("unknown match %s keyword %r; only 'address' is "
                         'supported' % (family, unknown[0]))
    if 'address' not in value:
        raise ValueError("match %s needs an 'address'" % family)
    inner = value['address']
    if not isinstance(inner, dict):
        raise ValueError("match %s address needs {'prefix-list': NAME}"
                         % family)
    unknown = [k for k in sorted(inner) if k != 'prefix-list']
    if unknown:
        raise ValueError("unknown match %s address keyword %r; only "
                         "'prefix-list' is supported" % (family, unknown[0]))
    if 'prefix-list' not in inner:
        raise ValueError("match %s address needs a 'prefix-list'" % family)
    return PrefixListMatch(afi, inner['prefix-list'], resolver)


def _parse_as_path_match(value, resolver):
    """Parse ``{'as-path': REGEX | [REGEX, ...] | {'access-list': NAME}}``.

    :param value: the configured value.
    :param resolver: the as-path list resolver.
    :return: the matcher.
    :raises ValueError: any other shape.
    """
    if isinstance(value, dict):
        unknown = [k for k in sorted(value) if k != 'access-list']
        if unknown:
            raise ValueError("unknown match as-path keyword %r; only "
                             "'access-list' is supported" % (unknown[0],))
        if 'access-list' not in value:
            raise ValueError("match as-path needs an 'access-list', a regex, "
                             'or a list of regexes')
        return AsPathListMatch(value['access-list'], resolver)
    return AsPathRegexMatch(value)


def _parse_match(spec, resolver=None):
    """Compile a clause's match conditions.

    Keys are read in sorted order so that a document with two mistakes in
    one clause always reports the same one, which is what makes an error
    message testable and a configuration failure reproducible.

    :param spec: the ``match`` dict, or None for "matches everything".
    :param resolver: the object list matchers resolve names against.
    :return: a tuple of compiled matchers, ordered cheapest test first.
        Empty for no conditions, which matches every route.
    :raises ValueError: an unknown keyword, a malformed value, or
        ``continue``.
    """
    if spec is None:
        return ()
    if not isinstance(spec, dict):
        raise ValueError('a match clause must be an object, not %s'
                         % type(spec).__name__)
    tests = []
    for key in sorted(spec):
        value = spec[key]
        if key == 'continue':
            raise ValueError(_CONTINUE_MESSAGE)
        if key in ('ip', 'ipv6'):
            tests.append(_parse_prefix_list_match(key, value, resolver))
        elif key == 'as-path':
            tests.append(_parse_as_path_match(value, resolver))
        elif key == 'community':
            tests.append(_parse_community_match(value, 'community',
                                                _community_values,
                                                CommunityMatch))
        elif key == 'large-community':
            tests.append(_parse_community_match(value, 'large-community',
                                                _large_community_values,
                                                LargeCommunityMatch))
        elif key == 'metric':
            tests.append(MetricMatch(value))
        elif key == 'local-preference':
            tests.append(LocalPrefMatch(value))
        elif key == 'origin':
            tests.append(OriginMatch(value))
        elif key == 'next-hop':
            tests.append(NextHopMatch(value))
        else:
            raise ValueError('unknown match keyword %r; supported: %s'
                             % (key, ', '.join(MATCH_KEYWORDS)))
    tests.sort(key=lambda test: test.cost)
    return tuple(tests)


def _parse_community_edit(value, what, parse_values):
    """Parse a community or large-community set clause.

    Three spellings, three meanings, and the difference matters: a bare list
    *replaces* the attribute, ``additive`` *adds* to it, and ``'none'``
    clears it. IOS' ``set community`` replaces unless ``additive`` is given,
    which is the trap this shape exists to make visible -- an operator who
    means "tag this route as well" and writes a bare list has silently
    discarded every community the route arrived with.

    :param value: the configured value.
    :param what: the keyword, for messages.
    :param parse_values: the value parser for this keyword.
    :return: ``('set'|'add'|'none', values)``.
    :raises ValueError: any other shape.
    """
    if isinstance(value, str):
        if value == 'none':
            return ('none', ())
        raise ValueError("the only %s string is 'none'; a list replaces the "
                         'attribute and {"list": [...], "additive": true} '
                         'adds to it' % what)
    if isinstance(value, dict):
        unknown = [k for k in sorted(value) if k not in ('list', 'additive')]
        if unknown:
            raise ValueError("unknown set %s option %r; expected 'list' or "
                             "'additive'" % (what, unknown[0]))
        if 'list' not in value:
            raise ValueError("set %s needs a 'list'" % what)
        additive = value.get('additive', False)
        if not isinstance(additive, bool):
            raise ValueError('set %s additive must be true or false, not %r'
                             % (what, additive))
        values = parse_values(value['list'], 'set ' + what)
        return ('add' if additive else 'set', values)
    return ('set', parse_values(value, 'set ' + what))


def _parse_prepend(value):
    """Parse ``{'as-path': {'prepend': [65001, 65001]}}``.

    The space-separated string spelling is accepted as well, because that is
    how the command is typed and how a configuration converted from a router
    arrives.

    :param value: the configured value.
    :return: a tuple of ASNs, in the order they are to be prepended.
    :raises ValueError: an unknown option, an empty prepend, or an ASN that
        is not a 32-bit number. AS 0 is rejected too (B-11): RFC 7607
        forbids it in an AS_PATH, and it used to be silently turned into
        the local AS, which is a different instruction from the one typed.
    """
    if not isinstance(value, dict):
        raise ValueError("set as-path needs {'prepend': [ASN, ...]}")
    unknown = [k for k in sorted(value) if k != 'prepend']
    if unknown:
        raise ValueError("unknown set as-path keyword %r; only 'prepend' is "
                         'supported' % (unknown[0],))
    if 'prepend' not in value:
        raise ValueError("set as-path needs a 'prepend'")
    items = value['prepend']
    if isinstance(items, str):
        items = items.split()
        if not items:
            raise ValueError('set as-path prepend needs at least one AS')
        asns = []
        for item in items:
            if not item.isdigit():
                raise ValueError('not an AS number: %r' % (item,))
            asns.append(_coerce_int('AS number', int(item), 1, 0xffffffff))
        return tuple(asns)
    if isinstance(items, (list, tuple)):
        if not items:
            raise ValueError('set as-path prepend needs at least one AS')
        return tuple(_coerce_int('AS number', item, 1, 0xffffffff)
                     for item in items)
    raise ValueError('set as-path prepend needs a list of AS numbers or a '
                     'space-separated string, not %s'
                     % type(items).__name__)


def _parse_set(spec):
    """Compile a clause's edits into the normalized form callers consume.

    The key set of the returned dict is a contract with the protocol
    translator on the other side: ``'local-preference'``, ``'metric'``,
    ``'origin'``, ``'next-hop'``, ``'community'``, ``'large-community'`` and
    ``'as-path-prepend'``. The keys are not the configuration's -- the
    configuration spells a prepend as ``{'as-path': {'prepend': [...]}}``,
    which is a shape rather than a value -- and the values are not the
    configuration's either: an address is packed bytes and a community is an
    int, converted here, once, rather than per route.

    ``weight`` is returned separately and deliberately not in the dict. It
    is not a path attribute: it is local to this speaker, is never encoded,
    and a translator iterating the edits and encoding each one would put it
    on the wire.

    :param spec: the ``set`` dict, or None.
    :return: ``(edits, weight)``, where weight is None when unset.
    :raises ValueError: an unknown keyword, a malformed value, or
        ``continue``.
    """
    if spec is None:
        return {}, None
    if not isinstance(spec, dict):
        raise ValueError('a set clause must be an object, not %s'
                         % type(spec).__name__)
    edits = {}
    weight = None
    for key in sorted(spec):
        value = spec[key]
        if key == 'continue':
            raise ValueError(_CONTINUE_MESSAGE)
        if key == 'local-preference':
            edits[key] = _coerce_int('local-preference', value, 0,
                                     0xffffffff)
        elif key == 'metric':
            # Plain values only. IOS' `set metric +10` is relative to
            # whatever the route arrived with, which makes the edit depend on
            # the route rather than on the configuration, and a translator
            # consuming this dict would have to know that a metric is
            # sometimes a delta. If it is wanted, it needs its own key.
            edits[key] = _coerce_int('metric', value, 0, 0xffffffff)
        elif key == 'origin':
            edits[key] = _origin_id(value)
        elif key == 'next-hop':
            edits[key] = _pack_addr(value)
        elif key == 'weight':
            weight = _coerce_int('weight', value, 0, 0xffff)
        elif key == 'community':
            edits[key] = _parse_community_edit(value, 'community',
                                               _community_values)
        elif key == 'large-community':
            edits[key] = _parse_community_edit(value, 'large-community',
                                               _large_community_values)
        elif key == 'as-path':
            edits['as-path-prepend'] = _parse_prepend(value)
        else:
            raise ValueError('unknown set keyword %r; supported: %s'
                             % (key, ', '.join(SET_KEYWORDS)))
    return edits, weight


def _edits_as_dict(edits, weight):
    """Render normalized edits back into readable show output.

    The normalized form holds packed addresses and integer communities,
    neither of which belongs in an API response, so this is the inverse
    rendering rather than the dict itself.

    :param edits: the normalized edit dict.
    :param weight: the clause's weight, or None.
    :return: a dict of plain, printable types.
    """
    out = {}
    for key, value in edits.items():
        if key == 'next-hop':
            out[key] = _addr_text(value)
        elif key == 'origin':
            out[key] = ORIGIN_NAMES[value]
        elif key == 'community':
            out[key] = {'action': value[0],
                        'values': [community_text(v) for v in value[1]]}
        elif key == 'large-community':
            out[key] = {'action': value[0],
                        'values': [large_community_text(v)
                                   for v in value[1]]}
        elif key == 'as-path-prepend':
            out[key] = list(value)
        else:
            out[key] = value
    if weight is not None:
        out['weight'] = weight
    return out


# --- the objects a caller sees ----------------------------------------------

class RouteMapResult(object):
    """What a route-map decided about one route.

    Truthy exactly when the route is permitted, so the common caller reads
    ``if route_map.apply(prefix, attrs):``. ``matched`` separates the two
    ways of being denied: a clause said no, or no clause said anything and
    the implicit deny applied. Callers that report why a route was filtered
    need that distinction, and callers that do not can ignore it.

    ``sets`` is the permitting clause's own normalized edit dict, shared by
    every route that clause permits, and **must not be mutated**. Copying it
    per route would allocate a dictionary per prefix per peer for a consumer
    that only reads it. It is empty for a deny, including a deny clause that
    carries edits: IOS parses those and ignores them, and so does this.

    :param action: :data:`ACTION_PERMIT` or :data:`ACTION_DENY`.
    :param clause: the ``seq`` of the clause that decided, or None when
        nothing matched.
    :param sets: the normalized edits, or None for an empty set.
    :param weight: the clause's weight, or None when it set none.
    :param matched: whether any clause matched at all.
    """

    __slots__ = ('action', 'clause', 'sets', 'weight', 'matched')

    def __init__(self, action, clause=None, sets=None, weight=None,
                 matched=False):
        self.action = action
        self.clause = clause
        self.sets = _NO_SETS if sets is None else sets
        self.weight = weight
        self.matched = matched

    def __bool__(self):
        return self.action == ACTION_PERMIT

    def __repr__(self):
        return '<RouteMapResult %s clause=%r matched=%r sets=%d>' % (
            ACTION_NAMES[self.action], self.clause, self.matched,
            len(self.sets))

    def as_dict(self):
        """Render the result for debug output.

        :return: a dict of plain, printable types.
        """
        return {
            'action': ACTION_NAMES[self.action],
            'clause': self.clause,
            'matched': self.matched,
            'set': _edits_as_dict(self.sets, self.weight),
        }


class RouteMapClause(object):
    """One ``route-map NAME permit|deny SEQ`` clause, fully compiled.

    :param seq: sequence number; ascending order is evaluation order.
    :param action: ``'permit'``, ``'deny'``, or the matching int.
    :param match: the match conditions, or None for "matches everything".
    :param set: the edits. Parsed and kept even on a ``deny`` clause, so
        that show output reproduces the configuration, but never applied
        from one.
    :param resolver: the object prefix-list and as-path matchers resolve
        names against.
    :raises ValueError: anything the match or set vocabulary rejects. The
        clause is either fully valid or not constructed: nothing here
        mutates the route-map it is destined for.
    """

    __slots__ = ('seq', 'action', 'match', 'set', 'weight', 'hits')

    def __init__(self, seq, action, match=None, set=None, resolver=None):
        self.seq = seq_number(seq)
        self.action = action_id(action)
        self.match = _parse_match(match, resolver)
        edits, weight = _parse_set(set)
        self.set = edits
        self.weight = weight
        # Per-clause, because "which clause of my route-map fired" is the
        # question an operator asks first and a map-level counter cannot
        # answer it. IOS prints these too.
        self.hits = 0

    def __repr__(self):
        return '<RouteMapClause %d %s match=%d set=%d>' % (
            self.seq, ACTION_NAMES[self.action], len(self.match),
            len(self.set))

    def matches(self, prefix, attrs, ctx=None):
        """Return whether every condition in this clause holds.

        :param prefix: the route's :class:`Prefix`.
        :param attrs: the path attributes, or None.
        :param ctx: reserved; see :meth:`RouteMap.apply`.
        :return: True when all conditions hold, which includes the case of
            no conditions at all.
        """
        for test in self.match:
            if not test.matches(prefix, attrs, ctx):
                return False
        return True

    def references(self):
        """Return the policy objects this clause depends on.

        :return: a set of ``(kind, name)`` pairs, where kind is
            ``'prefix-list'``, ``'ipv6-prefix-list'`` or ``'as-path'``.
        """
        found = set()
        for test in self.match:
            found.update(test.references())
        return found

    def as_dict(self):
        """Render the clause for ``show route-map``.

        The ``match`` and ``set`` values are the configuration as written,
        rebuilt from the compiled form, not the compiled form itself: a
        packed next hop and an integer community are not useful to a human
        or to an API client.

        :return: a dict of plain types.
        """
        match = {}
        for test in self.match:
            key, value = test.as_config()
            match[key] = value
        return {
            'seq': self.seq,
            'action': ACTION_NAMES[self.action],
            'match': match,
            'set': _edits_as_dict(self.set, self.weight),
            'hits': self.hits,
        }


class RouteMap(object):
    """A named, ordered list of clauses, applied to one route at a time.

    :param name: the name configuration and every reference use.
    :param resolver: the object whose ``prefix_list(name, afi)`` and
        ``as_path_list(name)`` the clauses resolve names against; normally
        the :class:`~..store.PolicyStore` that owns this map. Held rather
        than consulted at parse time, because a route-map may legitimately
        be built before the lists it names and because a list can be
        replaced under the same name later.
    :raises ValueError: an empty name.
    """

    __slots__ = ('name', 'clauses', 'version', 'resolver', 'applied',
                 'permitted', 'denied', 'unmatched')

    def __init__(self, name, resolver=None):
        if not name:
            raise ValueError('a route-map name is required')
        self.name = name
        self.clauses = []
        # Bumped on every mutation; cited by update-group keys. See the note
        # on version numbers in store.py for why a spurious bump is
        # expensive and a missed one is a correctness bug.
        self.version = 0
        self.resolver = resolver
        self.applied = 0
        self.permitted = 0
        self.denied = 0
        self.unmatched = 0

    def __len__(self):
        return len(self.clauses)

    def __repr__(self):
        return '<RouteMap %s clauses=%d version=%d>' % (
            self.name, len(self.clauses), self.version)

    # --- mutation ----------------------------------------------------------

    def add_clause(self, seq, action, match=None, set=None):
        """Add or replace one clause.

        A duplicate ``seq`` replaces the clause holding it, which is what
        re-issuing a clause with the same sequence number does on a router.
        The clause is built -- and therefore its whole vocabulary validated
        -- before this map is touched, so a rejected clause leaves the map
        exactly as it was.

        :param seq: sequence number.
        :param action: ``'permit'``, ``'deny'``, or the matching int.
        :param match: the match conditions, or None to match everything.
        :param set: the edits, or None.
        :return: the :class:`RouteMapClause` stored.
        :raises ValueError: anything the match or set vocabulary rejects.
        """
        clause = RouteMapClause(seq, action, match, set, self.resolver)
        for index in range(len(self.clauses)):
            existing = self.clauses[index]
            if existing.seq == clause.seq:
                self.clauses[index] = clause
                self.version += 1
                return clause
            if existing.seq > clause.seq:
                self.clauses.insert(index, clause)
                self.version += 1
                return clause
        self.clauses.append(clause)
        self.version += 1
        return clause

    def remove_clause(self, seq):
        """Remove the clause with a sequence number.

        :param seq: the sequence number.
        :return: True if a clause was removed. Removing something absent is
            not an error: it is what applying a diff twice looks like.
        :raises ValueError: a seq that is not an integer in range.
        """
        wanted = seq_number(seq)
        for index in range(len(self.clauses)):
            if self.clauses[index].seq == wanted:
                del self.clauses[index]
                self.version += 1
                return True
        return False

    def clear(self):
        """Drop every clause, keeping this object's identity and version.

        How :class:`~..store.PolicyStore` reloads a map whose configuration
        changed; see :meth:`PrefixList.clear` for why the object is not
        replaced instead.

        :return: the number of clauses removed.
        """
        removed = len(self.clauses)
        self.clauses = []
        if removed:
            self.version += 1
        return removed

    # --- application -------------------------------------------------------

    def apply(self, prefix, attrs, ctx=None):
        """Run the route-map against one route.

        :param prefix: the route's :class:`~...rib.prefix.Prefix`.
        :param attrs: the path attributes, as any object exposing
            ``origin``, ``as_path_str()``, ``communities``,
            ``large_communities``, ``ext_communities``, ``nexthop``,
            ``med``, ``local_pref``, ``has_med()`` and ``has_local_pref()``
            -- the BGP plugin's ``AttrSet`` as it stands. None means the
            route has no path attributes, and every condition that needs
            them then fails to match rather than raising.
        :param ctx: reserved for the peer-dependent conditions this version
            does not implement (peer AS, peer address). Accepted and ignored
            so that adding them later does not change this signature.
        :return: a :class:`RouteMapResult`. An empty route-map, or one whose
            clauses all fail to match, denies with ``matched=False``:
            callers rely on that, so a route-map that exists but says
            nothing about a prefix drops it rather than passing it through.
        """
        self.applied += 1
        for clause in self.clauses:
            matched = True
            for test in clause.match:
                if not test.matches(prefix, attrs, ctx):
                    matched = False
                    break
            if not matched:
                continue
            clause.hits += 1
            if clause.action == ACTION_PERMIT:
                self.permitted += 1
                return RouteMapResult(ACTION_PERMIT, clause.seq, clause.set,
                                      clause.weight, True)
            self.denied += 1
            # The clause's edits are deliberately dropped: a deny clause
            # rejects the route, and there is nothing left to edit.
            return RouteMapResult(ACTION_DENY, clause.seq, None, None, True)
        self.unmatched += 1
        return RouteMapResult(ACTION_DENY, None, None, None, False)

    # --- views -------------------------------------------------------------

    def references(self):
        """Return every policy object this map depends on.

        This is what an update group is invalidated by: a group's key cites
        the version of the map *and* of everything the map names, because a
        prefix-list changing under a map changes the map's behaviour without
        changing the map.

        :return: a set of ``(kind, name)`` pairs, where kind is
            ``'prefix-list'``, ``'ipv6-prefix-list'`` or ``'as-path'``. The
            IPv6 prefix-lists are reported under their own kind rather than
            as plain prefix-lists, because they are a separate namespace and
            ``PolicyStore.version_of`` needs to be told which one to look
            in.
        """
        found = set()
        for clause in self.clauses:
            found.update(clause.references())
        return found

    def as_dict(self):
        """Render the map for ``show route-map``.

        ``applied`` counts routes offered, ``permitted`` and ``denied``
        those a clause decided, and ``unmatched`` those that fell off the
        end into the implicit deny -- which is the counter that tells an
        operator their route-map is missing a clause rather than rejecting
        deliberately.

        :return: a dict of plain types.
        """
        return {
            'name': self.name,
            'version': self.version,
            'clauses': [c.as_dict() for c in self.clauses],
            'applied': self.applied,
            'permitted': self.permitted,
            'denied': self.denied,
            'unmatched': self.unmatched,
        }
