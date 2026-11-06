# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""``show ip bgp ...``: the operational view of the BGP plugin.

Every handler returns a dict of plain types and renders nothing. The same
function answers ``engine.show('ip', 'bgp', 'summary')`` and
``GET /api/v1/show/ip/bgp/summary``, so a terminal and an API client
cannot be told different things -- formatting into IOS-shaped columns is
the caller's business, and there is deliberately no second code path that
could disagree.

Two conventions run through the file.

**Keys are IOS words, not internal names.** ``local-preference``, not
``local_pref``; ``neighbor``, not ``peer_ref``. An operator who knows BGP
should be able to read the output without knowing this codebase, and the
API schema is generated from the same vocabulary.

**Nothing here is allowed to be slow enough to matter, and where it could
be, it is bounded.** A full table is a million prefixes; a ``show`` that
serialised all of them would block the loop for seconds and hand the
caller a response nobody can read. The table view therefore pages, and
says so in its output rather than silently truncating -- a truncated
routing table that does not admit it is worse than no output at all.
"""

from packets.routing.rtengine.plugins.bgp import capabilities


# Default and maximum page sizes for the table view. The default is a
# screenful's worth of scrollback; the maximum is what a JSON response can
# carry without becoming a denial of service against the API thread.
DEFAULT_LIMIT = 500
MAX_LIMIT = 10000


def handlers(plugin):
    """Return the plugin's ``show`` handlers keyed by IOS path.

    :param plugin: the :class:`BGPPlugin` to report on.
    :return: ``{path_tuple: callable(*args, **kwargs) -> dict}``.
    """
    return {
        ('ip', 'bgp', 'summary'): lambda *a, **k: summary(plugin, **k),
        ('ip', 'bgp', 'neighbors'): lambda *a, **k: neighbors(plugin, *a,
                                                              **k),
        ('ip', 'bgp'): lambda *a, **k: table(plugin, *a, **k),
        ('ip', 'bgp', 'attributes'): lambda *a, **k: attributes(plugin),
        ('ip', 'bgp', 'update-groups'): lambda *a, **k: update_groups(
            plugin, *a, **k),
        ('ipv6', 'bgp', 'summary'): lambda *a, **k: summary(
            plugin, afi=2, **k),
        ('ipv6', 'bgp'): lambda *a, **k: table(plugin, *a, afi=2, **k),
        ('ipv6', 'bgp', 'neighbors'): lambda *a, **k: neighbors(
            plugin, *a, afi=2, **k),
    }


#: ``show ip bgp neighbors <addr> <sub>`` sub-commands, dispatched inside
#: :func:`neighbors` rather than registered as their own paths. They
#: cannot be paths: the engine matches the longest *registered* prefix and
#: hands the remainder over as arguments, and in the command an operator
#: actually types the neighbour address sits between the registered path
#: and the keyword.
NEIGHBOR_VIEWS = ('received-routes', 'advertised-routes')


def summary(plugin, **_kwargs):
    """``show ip bgp summary``: one line per neighbour, plus the totals.

    This is the command an operator runs first, so it answers the three
    questions that come first: is the session up, for how long, and how
    many prefixes did it bring. The authentication mode is included
    because an unauthenticated session that was meant to be authenticated
    looks identical to a working one in every other column.

    :param plugin: the BGP plugin.
    :return: a dict of plain types.
    """
    rows = []
    for addr in sorted(plugin.peers):
        session = plugin.peers[addr]
        fsm_stats = session.fsm.stats()
        rows.append({
            'neighbor': addr,
            'version': 4,
            'as': session.config.remote_as,
            'state': session.fsm.state,
            'up-time': fsm_stats.get('uptime'),
            'prefixes-received': session.prefix_count(),
            'messages-received': session.stats_counters['messages-in'],
            'messages-sent': session.stats_counters['messages-out'],
            'auth': session.auth_mode or 'blocked',
            'description': session.config.description,
            # Present only when something is wrong, so an operator
            # scanning the output sees exceptions rather than a column of
            # nulls to read past.
            'last-error': fsm_stats.get('last-error'),
        })
    established = sum(1 for p in plugin.peers.values() if p.established)
    out = {
        'local-as': plugin.local_as,
        'router-id': plugin.router_id,
        'neighbors': len(plugin.peers),
        'established': established,
        'table-version': max(
            [rib.stats().get('version', 0) for rib in
             plugin.locribs.values()] or [0]),
        'peers': rows,
        'families': {},
    }
    for af, rib in sorted(plugin.locribs.items()):
        out['families'][capabilities.afi_safi_name(af[0], af[1])] = {
            'destinations': len(rib),
            'paths': rib.stats().get('paths', 0),
        }
    return out


def neighbors(plugin, address=None, *rest, **kwargs):
    """``show ip bgp neighbors [<address> [<view>]]``: a session in detail.

    Includes the negotiated capabilities and the RFC 7606 counters. Those
    counters are the point of the command: "the session is up but some of
    its routes are missing" is otherwise unanswerable, and the matrix's
    whole purpose is to keep such a session up rather than resetting it,
    which means the damage has to show up somewhere an operator looks.

    A trailing ``received-routes`` or ``advertised-routes`` selects one of
    the two table views instead; see :data:`NEIGHBOR_VIEWS`.

    :param plugin: the BGP plugin.
    :param address: one neighbour, or None for all of them.
    :param rest: an optional view name.
    :param kwargs: ``afi``, ``safi`` and ``limit`` for the table views.
    :return: a dict of plain types.
    """
    if address is not None and rest:
        view = rest[0]
        if view == 'received-routes':
            return received_routes(plugin, address, **kwargs)
        if view == 'advertised-routes':
            return advertised_routes(plugin, address, **kwargs)
        return {'error': 'no such neighbour view: %s' % (view,),
                'known': list(NEIGHBOR_VIEWS)}
    if address is not None:
        session = plugin.peers.get(address)
        if session is None:
            return {'error': 'no such neighbour: %s' % address,
                    'known': sorted(plugin.peers)}
        doc = {'neighbor': session.as_dict()}
        doc['neighbor']['update-groups'] = _group_ids(plugin, address)
        return doc
    out = []
    for addr in sorted(plugin.peers):
        one = plugin.peers[addr].as_dict()
        one['update-groups'] = _group_ids(plugin, addr)
        out.append(one)
    return {'neighbors': out}


def _group_ids(plugin, address):
    """Return the update groups one neighbour belongs to, by family.

    :param plugin: the BGP plugin.
    :param address: the neighbour.
    :return: ``{family_name: group_id}``, empty while the session is down.
    """
    out = {}
    for group in plugin.groups.groups():
        if address in group.members:
            out[capabilities.afi_safi_name(group.spec.afi,
                                           group.spec.safi)] = group.gid
    return out


def table(plugin, prefix=None, afi=1, safi=1, limit=DEFAULT_LIMIT,
          offset=0, **_kwargs):
    """``show ip bgp [<prefix>]``: the BGP table, or one destination.

    With a prefix, every path for that destination is returned along with
    the reason the winner won -- which is the question an operator is
    actually asking when they type a prefix after the command.

    Without one, the table is paged. ``truncated`` is set rather than the
    output being quietly cut, because an operator who counts the lines and
    concludes their table is 500 prefixes has been actively misled.

    :param plugin: the BGP plugin.
    :param prefix: a prefix in CIDR notation, or None for the whole table.
    :param afi: address family, 1 for IPv4 and 2 for IPv6.
    :param safi: subsequent address family.
    :param limit: how many destinations to return.
    :param offset: how many to skip, for paging.
    :return: a dict of plain types.
    """
    af = (afi, safi)
    rib = plugin.locribs.get(af)
    if rib is None:
        return {'error': 'no table for %s'
                         % capabilities.afi_safi_name(afi, safi),
                'families': [capabilities.afi_safi_name(a, s)
                             for a, s in sorted(plugin.locribs)]}
    if prefix is not None:
        return _one_destination(plugin, rib, af, prefix)

    limit = max(1, min(int(limit), MAX_LIMIT))
    offset = max(0, int(offset))
    rows = []
    total = len(rib)
    for index, dest in enumerate(rib):
        if index < offset:
            continue
        if len(rows) >= limit:
            break
        rows.append(_dest_row(dest))
    return {
        'family': capabilities.afi_safi_name(afi, safi),
        'local-as': plugin.local_as,
        'router-id': plugin.router_id,
        'destinations': total,
        'returned': len(rows),
        'offset': offset,
        'truncated': offset + len(rows) < total,
        'routes': rows,
    }


def _one_destination(plugin, rib, af, text):
    """Render every path for one prefix, and why the winner won."""
    from packets.routing.rtengine.rib.prefix import parse_prefix
    from packets.routing.rtengine.plugins.bgp import bestpath

    try:
        parsed = parse_prefix(text)
    except ValueError as exc:
        return {'error': str(exc)}
    dest = rib.get(parsed)
    if dest is None:
        return {'prefix': text, 'paths': [],
                'error': 'not in the BGP table'}
    config = plugin.bestpath_config.get(af)
    detail = (bestpath.explain(dest.paths, config) if config is not None
              else {'paths': [p.as_dict() for p in dest.paths]})
    return {
        'prefix': dest.prefix.to_str(),
        'family': capabilities.afi_safi_name(af[0], af[1]),
        'paths': detail.get('paths', []),
        'best-reason': detail.get('reason'),
        'multipath': detail.get('multipath', 0),
        'advertised-to': _advertised_to(plugin, af, dest.prefix),
    }


def _advertised_to(plugin, af, prefix):
    """Return the neighbours that have been sent a prefix.

    Asked of the update groups rather than of each peer in turn. The
    record belongs to the group, so this is one lookup per group instead
    of one per neighbour -- which on a router with a thousand peers in
    three groups is the difference between a thousand dict lookups per
    prefix and three.

    :param plugin: the BGP plugin.
    :param af: the ``(afi, safi)`` pair.
    :param prefix: the :class:`rib.prefix.Prefix`.
    :return: a sorted list of neighbour addresses. A member still owed its
        catch-up replay is left out (B-8): the group's record says what
        the group was told, and a member that joined after the telling
        has not heard any of it yet.
    """
    out = []
    for group in plugin.groups.groups_for(af):
        if group.out.advertised(prefix) is not None:
            owed = set(group.catchup())
            out.extend(a for a in group.member_addresses() if a not in owed)
    return sorted(out)


def _dest_row(dest):
    """One line of the table view: the winner, summarised."""
    best = dest.best
    row = {
        'prefix': dest.prefix.to_str(),
        'paths': len(dest.paths),
    }
    if best is None:
        # A destination with paths but no winner means every path is
        # unresolved. Saying so beats an empty row, which reads like a
        # bug in the show command rather than a next-hop problem.
        row['status'] = 'no usable path'
        return row
    attrs = best.attrs
    row.update({
        'next-hop': best.as_dict().get('next-hop'),
        'as-path': attrs.as_path_str(),
        'origin': best.as_dict().get('origin'),
        'local-preference': (attrs.local_pref if attrs.has_local_pref()
                             else None),
        'med': attrs.med if attrs.has_med() else None,
        'weight': best.weight,
        'peer': best.as_dict().get('peer'),
        'best-reason': dest.reason_text,
    })
    if dest.multipath:
        row['multipath'] = len(dest.multipath)
    return row


def update_groups(plugin, group_id=None, **_kwargs):
    """``show ip bgp update-groups [<id>]``: who shares an outbound view.

    Not an IOS command by this exact name, and here because the grouping
    is otherwise invisible: "why did this peer get that" and "why is this
    peer in a group of its own" are both answered by the key, and a key
    that could not be read would make the optimisation unauditable. The
    key's components are rendered individually for that reason -- see
    :meth:`updategroup.UpdateGroupKey.differences`, which is the same
    information from the other direction.

    :param plugin: the BGP plugin.
    :param group_id: one group's id, or None for all of them.
    :return: a dict of plain types.
    """
    if group_id is None:
        return plugin.groups.as_dict()
    try:
        wanted = int(group_id)
    except (TypeError, ValueError):
        return {'error': 'not an update group id: %s' % (group_id,)}
    for group in plugin.groups.groups():
        if group.gid == wanted:
            return group.as_dict()
    return {'error': 'no such update group: %d' % wanted,
            'known': [g.gid for g in plugin.groups.groups()]}


def received_routes(plugin, address=None, afi=1, safi=1,
                    limit=DEFAULT_LIMIT, **_kwargs):
    """``show ip bgp neighbors <addr> received-routes``: the raw Adj-RIB-In.

    What the peer said, before inbound policy. The command exists for
    exactly one question -- "did my neighbour send it, or did my policy
    drop it" -- and answering it requires the pre-policy attributes,
    which is why the session keeps them.

    :param plugin: the BGP plugin.
    :param address: the neighbour.
    :param afi: address family, 1 for IPv4 and 2 for IPv6.
    :param safi: subsequent address family.
    :param limit: how many prefixes to return.
    :return: a dict of plain types.
    """
    session = plugin.peers.get(address)
    if session is None:
        return {'error': 'no such neighbour: %s' % address,
                'known': sorted(plugin.peers)}
    af = (afi, safi)
    table_in = session.adj_in.get(af)
    if table_in is None:
        return {'neighbor': address,
                'error': 'that neighbour has no %s table'
                         % capabilities.afi_safi_name(afi, safi)}
    limit = max(1, min(int(limit), MAX_LIMIT))
    rows = []
    for (prefix, path_id) in sorted(table_in, key=lambda k: k[0]):
        if len(rows) >= limit:
            break
        # AttrSet.as_dict() is the one renderer for attributes, and it is
        # used here rather than a second hand-written one so this command
        # cannot disagree with `show ip bgp <prefix>` about what a path
        # carries.
        row = table_in[(prefix, path_id)].as_dict()
        row['prefix'] = prefix.to_str()
        if path_id:
            row['path-id'] = path_id
        rows.append(row)
    return {
        'neighbor': address,
        'family': capabilities.afi_safi_name(afi, safi),
        'received': len(table_in),
        'returned': len(rows),
        'truncated': len(rows) < len(table_in),
        'filtered': session.stats_counters.get('prefixes-filtered', 0),
        'accepted': session.stats_counters.get('prefixes-accepted', 0),
        'routes': rows,
    }


def advertised_routes(plugin, address=None, afi=1, safi=1,
                      limit=DEFAULT_LIMIT, **_kwargs):
    """``show ip bgp neighbors <addr> advertised-routes``: what we sent.

    Read out of the neighbour's update group, which is where the record
    of what was sent lives, and with the attributes *as sent* -- after
    the outbound transform and outbound policy. Rendering the Loc-RIB's
    copy instead would be the common lie in this command: it would show
    a next hop and an AS path that this particular neighbour never
    received.

    :param plugin: the BGP plugin.
    :param address: the neighbour.
    :param afi: address family, 1 for IPv4 and 2 for IPv6.
    :param safi: subsequent address family.
    :param limit: how many prefixes to return.
    :return: a dict of plain types.
    """
    session = plugin.peers.get(address)
    if session is None:
        return {'error': 'no such neighbour: %s' % address,
                'known': sorted(plugin.peers)}
    af = (afi, safi)
    group = plugin.groups.group_of(address, af)
    if group is None:
        return {'neighbor': address,
                'family': capabilities.afi_safi_name(afi, safi),
                'advertised': 0, 'returned': 0, 'truncated': False,
                'routes': [],
                'note': 'that neighbour is not advertising this family'}
    limit = max(1, min(int(limit), MAX_LIMIT))
    total = group.out.advertised_count()
    rows = []
    for prefix, attrs in group.out.entries():
        if len(rows) >= limit:
            break
        row = attrs.as_dict()
        row['prefix'] = prefix.to_str()
        rows.append(row)
    return {
        'neighbor': address,
        'family': capabilities.afi_safi_name(afi, safi),
        'update-group': group.gid,
        # The peers that are being sent exactly this, byte for byte.
        # Reading it is the quickest way to see whether the grouping is
        # doing anything at all on a given router.
        'shared-with': [a for a in group.member_addresses()
                        if a != address],
        'advertised': total,
        'returned': len(rows),
        'truncated': len(rows) < total,
        'routes': rows,
    }


def attributes(plugin):
    """``show ip bgp attributes``: how well the interning table is doing.

    Not an IOS command, and here on purpose. Interning is the reason the
    memory figures in the design hold, and its hit rate is the one number
    that says whether it is working: a rate below about 0.9 on a real
    feed means the canonical form is failing to collapse something it
    should, and that shows up as memory long before it shows up as
    anything else.

    :param plugin: the BGP plugin.
    :return: a dict of plain types.
    """
    stats = plugin.attr_table.stats()
    paths = sum(rib.stats().get('paths', 0)
                for rib in plugin.locribs.values())
    out = dict(stats)
    out['paths'] = paths
    out['paths-per-set'] = (round(float(paths) / stats['distinct'], 2)
                            if stats['distinct'] else 0.0)
    return out
