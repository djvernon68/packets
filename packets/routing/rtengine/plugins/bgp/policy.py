# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Policy, bound to BGP attribute sets.

The engine's policy vocabulary lives in ``rtengine/policy/``: prefix-lists,
as-path lists and route-maps, which match against a duck-typed view of a
path and return a *description* of what to change. That package knows
nothing about BGP on purpose -- the core must not grow a dependency on one
plugin, or the next protocol cannot reuse any of it. This module is the
other half: it turns those descriptions into :class:`attrs.AttrSet`
instances and applies the whole chain in the order IOS applies it.

**Why a separate translation step rather than letting the route-map edit
attributes directly.** An ``AttrSet`` is interned and shared by every path
that carries the same attributes, and it is a live key in the interning
table; mutating one to rewrite a next hop corrupts every other path using
it and breaks the table's hash invariant in a way that surfaces as a wrong
route somewhere else entirely. Every ``set`` clause therefore rebuilds a
new set from a keyword dict, exactly as the outbound transform in
``adjout.py`` does, and :func:`attr_kwargs` is the one place that dict is
built so the two cannot drift.

**Chain order.** ``prefix-list``, then ``filter-list`` (as-path), then
``route-map``. That is the IOS order and it is not arbitrary: the first two
are cheap boolean filters over one field, and running them first means a
path that will be dropped anyway never pays for a route-map's match
clauses. Reversing them would also change behaviour -- a route-map with a
``set`` clause would have applied its edits to a path the prefix-list was
going to discard, which is invisible inbound but observable outbound in
the counters.

**Implicit deny is a property of the route-map, not of the chain.** A
route-map with no matching clause denies (IOS semantics, implemented in
``policy/routemap.py``); a chain with *no* route-map configured permits.
Those are different questions and conflating them is the classic way a
configuration that was meant to filter nothing filters everything.
"""

from packets.routing.rtengine.plugins.bgp import attrs as _attrs
from packets.routing.rtengine.policy import routemap as _routemap

#: Where a chain sits. Only used for counters and show output, but it is
#: worth naming: the same class serves both directions and a counter that
#: does not say which direction it counted is useless in a dispute.
DIR_IN = 'in'
DIR_OUT = 'out'


def attr_kwargs(a):
    """Explode an attribute set into the keyword form that rebuilds it.

    The canonical "copy with edits" step for every transform in the
    plugin. It is a function rather than a method on ``AttrSet`` because
    the set is a C extension type whose fields are written directly by the
    decoder; a dict is what makes "what did we change" reviewable in one
    place, and keeping one copy of the dict means a new attribute cannot
    be added to the class and forgotten by a rewrite.

    :param a: the source :class:`attrs.AttrSet`.
    :return: a dict accepted verbatim by ``AttrSet(**kwargs)``.
    """
    return {
        'origin': a.origin,
        'as_path': a.as_path,
        'nexthop': a.nexthop,
        'nexthop_local': a.nexthop_local,
        'med': a.med,
        'local_pref': a.local_pref,
        'has_med': a.has_med(),
        'has_local_pref': a.has_local_pref(),
        'atomic_aggregate': a.atomic_aggregate,
        'communities': a.communities,
        'ext_communities': a.ext_communities,
        'large_communities': a.large_communities,
        'originator_id': a.originator_id,
        'has_originator': a.has_originator_id,
        'cluster_list': a.cluster_list,
        'aggregator': a.aggregator,
        'unknown': a.unknown,
    }


def _community_ints(packed):
    """Decode packed 4-byte communities into a list of ints.

    :param packed: canonical community bytes.
    :return: a list of 32-bit ints, in the order stored.
    """
    out = []
    for i in range(0, len(packed) - 3, 4):
        chunk = bytearray(packed[i:i + 4])
        out.append((chunk[0] << 24) | (chunk[1] << 16) |
                   (chunk[2] << 8) | chunk[3])
    return out


def _large_triples(packed):
    """Decode packed 12-byte large communities into triples.

    :param packed: canonical large-community bytes.
    :return: a list of ``(global, local1, local2)`` int triples.
    """
    out = []
    for i in range(0, len(packed) - 11, 12):
        chunk = bytearray(packed[i:i + 12])
        triple = []
        for j in range(0, 12, 4):
            triple.append((chunk[j] << 24) | (chunk[j + 1] << 16) |
                          (chunk[j + 2] << 8) | chunk[j + 3])
        out.append((triple[0], triple[1], triple[2]))
    return out


def _pack_large(triples):
    """Pack large-community triples into canonical bytes.

    Sorted here as well as by ``attrs_finalize``, so an equality test
    between two sets built by policy does not depend on the order the
    configuration happened to list them in.

    :param triples: an iterable of three-int tuples.
    :return: packed bytes.
    """
    out = []
    for triple in sorted(set(triples)):
        for value in triple:
            out.append(bytes(bytearray([(value >> 24) & 0xff,
                                        (value >> 16) & 0xff,
                                        (value >> 8) & 0xff,
                                        value & 0xff])))
    return b''.join(out)


def apply_sets(attrs, sets, local_as=0):
    """Build a new attribute set with a route-map's ``set`` clauses applied.

    Every edit is expressed as a change to the keyword dict, so the source
    set is never touched -- see the module docstring for why that is a
    hard rule rather than a preference.

    Two edits deserve a note. ``as-path prepend`` goes through
    :func:`attrs.make_as_path` on the *decoded* segment list rather than
    splicing bytes, because a prepend into a segment that already holds
    255 ASNs has to start a new segment and byte-splicing would silently
    produce a segment whose one-byte count had wrapped. ``community``
    with the additive form merges rather than replaces, and the merge is
    through a set: a community configured twice is one community, and
    the canonical form has to agree with that or two paths that mean the
    same thing intern separately.

    :param attrs: the source :class:`attrs.AttrSet`.
    :param sets: the normalized edit dict from
        :class:`policy.routemap.RouteMapResult`.
    :param local_as: our AS, for a relative prepend of our own AS.
    :return: a new :class:`attrs.AttrSet`, or the original object when
        the edit dict was empty -- callers compare identity to decide
        whether anything changed.
    :raises ValueError: a ``set next-hop`` of a width that does not match
        the path's family. That is a configuration error rather than a
        wire error, and it is reported rather than silently dropped
        because a next hop of the wrong family cannot be encoded at all.
    """
    if not sets:
        return attrs

    kwargs = attr_kwargs(attrs)

    if 'local-preference' in sets:
        kwargs['has_local_pref'] = True
        kwargs['local_pref'] = int(sets['local-preference'])
    if 'metric' in sets:
        kwargs['has_med'] = True
        kwargs['med'] = int(sets['metric'])
    if 'origin' in sets:
        kwargs['origin'] = int(sets['origin'])
    if 'next-hop' in sets:
        nexthop = sets['next-hop']
        if attrs.nexthop and len(nexthop) != len(attrs.nexthop):
            raise ValueError(
                'set next-hop is %d bytes but the path carries a %d byte '
                'next hop' % (len(nexthop), len(attrs.nexthop)))
        kwargs['nexthop'] = nexthop
        # A rewritten global next hop makes the link-local one a lie: it
        # was the second address of the *old* next hop's interface.
        kwargs['nexthop_local'] = b''
    if 'community' in sets:
        mode, values = sets['community']
        if mode == 'none':
            kwargs['communities'] = b''
        elif mode == 'add':
            merged = set(_community_ints(attrs.communities))
            merged.update(values)
            kwargs['communities'] = _attrs.make_communities(merged)
        else:
            kwargs['communities'] = _attrs.make_communities(values)
    if 'large-community' in sets:
        mode, values = sets['large-community']
        if mode == 'none':
            kwargs['large_communities'] = b''
        elif mode == 'add':
            merged = set(_large_triples(attrs.large_communities))
            merged.update(values)
            kwargs['large_communities'] = _pack_large(merged)
        else:
            kwargs['large_communities'] = _pack_large(values)
    if 'as-path-prepend' in sets:
        segments = attrs.as_path_list()
        for asn in reversed(list(sets['as-path-prepend'])):
            # The parser rejects AS 0 (B-11); `or local_as` used to turn it
            # into the local AS instead.
            segments = _prepend_one(segments, int(asn))
        kwargs['as_path'] = _attrs.make_as_path(segments)

    return _attrs.AttrSet(**kwargs)


def _prepend_one(segments, asn):
    """Put one AS at the front of a decoded AS_PATH.

    Shares its rules with ``adjout._prepend_as_path`` and for the same
    reasons: an AS_SET must not absorb the AS (it is unordered, so the
    claim would become "somewhere in this aggregate" and the length would
    not grow), and a full 255-ASN segment has to be followed by a new one
    because the count is a single byte.

    :param segments: ``[(seg_type, [asn, ...]), ...]``.
    :param asn: the AS to prepend.
    :return: a new segment list; the input is not modified.
    """
    if segments and segments[0][0] == _attrs.SEG_AS_SEQUENCE \
            and len(segments[0][1]) < 255:
        head = (segments[0][0], [asn] + list(segments[0][1]))
        return [head] + list(segments[1:])
    return [(_attrs.SEG_AS_SEQUENCE, [asn])] + list(segments)


class PolicyOutcome(object):
    """What a chain decided about one path.

    :param attrs: the attribute set to use, which is the input object
        itself when nothing was rewritten.
    :param weight: the weight a ``set weight`` asked for, or None to keep
        the neighbour's configured weight. Weight is per path rather than
        per attribute set -- it is local and never advertised -- so it
        travels beside the attributes rather than inside them.
    :param stage: which link of the chain decided, for counters and for
        ``show``: ``'prefix-list'``, ``'as-path'``, ``'route-map'`` or
        ``'none'``.
    :param clause: the route-map clause sequence number that decided, or
        None.
    """

    __slots__ = ('attrs', 'weight', 'stage', 'clause')

    def __init__(self, attrs, weight=None, stage='none', clause=None):
        self.attrs = attrs
        self.weight = weight
        self.stage = stage
        self.clause = clause

    def __repr__(self):
        return '<PolicyOutcome %s clause=%s weight=%s>' % (
            self.stage, self.clause, self.weight)


class PolicyChain(object):
    """One direction's filters and route-map for one peer and family.

    Built by the plugin from configuration and rebuilt when either the
    configuration or a referenced list changes. Held by the thing it
    applies to -- a peer for the inbound direction, an update group for
    the outbound one -- and shared by every path that goes through it.

    The counters are the operational payoff. "Why is this prefix not in
    my table" is answered by the difference between ``considered`` and
    ``permitted`` together with which stage did the denying, and that
    difference is invisible in a design that returns a bare boolean.

    :param direction: :data:`DIR_IN` or :data:`DIR_OUT`.
    :param prefix_list: a :class:`policy.prefixlist.PrefixList`, or None.
    :param as_path_list: a :class:`policy.aspath.AsPathList`, or None.
    :param route_map: a :class:`policy.routemap.RouteMap`, or None.
    :param local_as: our AS, for a prepend of our own AS.
    """

    __slots__ = ('direction', 'prefix_list', 'as_path_list', 'route_map',
                 'local_as', 'considered', 'permitted', 'denied',
                 'modified', 'errors')

    def __init__(self, direction, prefix_list=None, as_path_list=None,
                 route_map=None, local_as=0):
        self.direction = direction
        self.prefix_list = prefix_list
        self.as_path_list = as_path_list
        self.route_map = route_map
        self.local_as = local_as
        self.considered = 0
        self.permitted = 0
        self.denied = {'prefix-list': 0, 'as-path': 0, 'route-map': 0}
        self.modified = 0
        self.errors = 0

    @property
    def empty(self):
        """Whether this chain would permit everything unchanged.

        The hot-path shortcut: an unconfigured direction is the common
        case and must cost nothing per path.
        """
        return (self.prefix_list is None and self.as_path_list is None
                and self.route_map is None)

    def names(self):
        """Return the configured object names, for show output.

        :return: a dict with the configured names, omitting what is not
            configured.
        """
        out = {}
        if self.prefix_list is not None:
            out['prefix-list'] = self.prefix_list.name
        if self.as_path_list is not None:
            out['filter-list'] = self.as_path_list.name
        if self.route_map is not None:
            out['route-map'] = self.route_map.name
        return out

    def apply(self, prefix, attrs):
        """Run the chain over one path.

        :param prefix: the :class:`rib.prefix.Prefix` advertised.
        :param attrs: the path's :class:`attrs.AttrSet`.
        :return: a :class:`PolicyOutcome`, or None when the path is
            filtered. None rather than a flag inside the outcome because
            a filtered path has no attributes to speak of, and a caller
            that forgot to check a flag would install a path policy had
            rejected.
        """
        self.considered += 1

        if self.prefix_list is not None:
            if not self.prefix_list.permits(prefix):
                self.denied['prefix-list'] += 1
                return None

        if self.as_path_list is not None:
            if not self.as_path_list.permits(attrs.as_path_str()):
                self.denied['as-path'] += 1
                return None

        if self.route_map is None:
            self.permitted += 1
            return PolicyOutcome(attrs)

        result = self.route_map.apply(prefix, attrs)
        if result.action != _routemap.ACTION_PERMIT:
            self.denied['route-map'] += 1
            return None

        try:
            new_attrs = apply_sets(attrs, result.sets, self.local_as)
        except ValueError:
            # A set clause that cannot be applied to this path -- a
            # next hop of the wrong family is the only way in. Counted
            # and the path passes unchanged rather than being dropped:
            # the operator asked to rewrite an attribute, not to filter
            # the route, and dropping it would be a larger action than
            # anything they configured.
            self.errors += 1
            new_attrs = attrs

        if new_attrs is not attrs:
            self.modified += 1
        self.permitted += 1
        return PolicyOutcome(new_attrs, weight=result.weight,
                             stage='route-map', clause=result.clause)

    def stats(self):
        """Return the counters, for ``show`` and health.

        :return: a dict of plain types.
        """
        out = {
            'direction': self.direction,
            'considered': self.considered,
            'permitted': self.permitted,
            'denied': dict(self.denied),
            'denied-total': sum(self.denied.values()),
            'modified': self.modified,
        }
        if self.errors:
            out['set-errors'] = self.errors
        out.update(self.names())
        return out

    def __repr__(self):
        return '<PolicyChain %s %s>' % (
            self.direction,
            ' '.join('%s=%s' % item for item in sorted(self.names().items()))
            or 'permit-all')


#: A chain that permits everything, shared by every peer and family with
#: no policy configured. Stateless in effect -- its counters are never
#: read for a specific peer, because a peer with no policy reports none --
#: and shared so the common case allocates nothing.
PERMIT_ALL_IN = PolicyChain(DIR_IN)
PERMIT_ALL_OUT = PolicyChain(DIR_OUT)


def build_chain(direction, store, names, local_as=0, afi=None):
    """Build a chain from configured names against the policy store.

    A name that is configured but not defined produces a chain that
    *denies* everything for that link, which is IOS behaviour and the
    safe direction: an inbound route-map that has not been written yet
    must not be equivalent to no policy at all, or a half-finished
    configuration silently accepts the full table it was meant to filter.

    :param direction: :data:`DIR_IN` or :data:`DIR_OUT`.
    :param store: the engine's :class:`policy.store.PolicyStore`.
    :param names: a dict with any of ``prefix-list``, ``filter-list`` and
        ``route-map`` keys.
    :param local_as: our AS.
    :param afi: address family of the peer, so the right family's
        prefix-list namespace is consulted.
    :return: a :class:`PolicyChain`; the shared permit-all instance when
        nothing is configured.
    """
    if not names:
        return PERMIT_ALL_IN if direction == DIR_IN else PERMIT_ALL_OUT

    prefix_list = None
    as_path_list = None
    route_map = None
    if names.get('prefix-list'):
        prefix_list = store.prefix_list(names['prefix-list'], afi=afi)
        if prefix_list is None:
            prefix_list = _MissingList(names['prefix-list'])
    if names.get('filter-list'):
        as_path_list = store.as_path_list(names['filter-list'])
        if as_path_list is None:
            as_path_list = _MissingList(names['filter-list'])
    if names.get('route-map'):
        route_map = store.route_map(names['route-map'])
        if route_map is None:
            route_map = _MissingMap(names['route-map'])
    return PolicyChain(direction, prefix_list=prefix_list,
                       as_path_list=as_path_list, route_map=route_map,
                       local_as=local_as)


class _MissingList(object):
    """Stands in for a referenced prefix-list or as-path list that is not
    defined, and denies everything.

    See :func:`build_chain` for why the answer is "deny" rather than
    "permit". The class exists so the chain does not have to test for
    None on the hot path, and so ``show`` can report the name the
    operator typed rather than an empty field.
    """

    __slots__ = ('name',)

    def __init__(self, name):
        self.name = name

    def permits(self, _value):
        """Deny, whatever was asked.

        :param _value: ignored.
        :return: False.
        """
        return False

    def as_dict(self):
        """Render for show output.

        :return: a dict naming the missing object.
        """
        return {'name': self.name, 'defined': False, 'entries': []}


class _MissingMap(_MissingList):
    """Stands in for a route-map that is not defined, and denies."""

    __slots__ = ()

    def apply(self, _prefix, _attrs):
        """Deny, whatever was asked.

        :return: a denying :class:`policy.routemap.RouteMapResult`.
        """
        return _routemap.RouteMapResult(_routemap.ACTION_DENY, None, {},
                                        None, False)
