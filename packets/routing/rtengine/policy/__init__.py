# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Protocol-neutral routing policy: prefix-lists, AS-path lists, route-maps.

This package is the engine's answer to "which routes do I accept, which do I
advertise, and what do I change about them on the way through". It is core
code, and it imports nothing from ``plugins/``. That is not tidiness: policy
is the one part of the engine every protocol needs and none of them may own.
A prefix-list is the same object whether BGP, OSPF or a static-route filter
consults it, and a route-map has to be loadable, validated and shown by the
core before any plugin is configured -- ``prepare_config`` runs before a
peer exists.

What keeps the boundary honest is duck typing rather than an interface
class. :meth:`~.routemap.RouteMap.apply` wants a :class:`Prefix` and
"something with BGP-shaped path attributes": ``origin``, ``as_path_str()``,
``communities``, ``med``, ``local_pref`` and friends. The BGP plugin's
``AttrSet`` satisfies that contract exactly as it stands, with no adapter and
no registration, and a future protocol can satisfy it with a small object of
its own. Importing ``AttrSet`` here to type-check against it would buy
nothing and would make the core depend on the plugin -- and on 3.6 there is
no ``typing.Protocol`` to write the contract down with either, so it is
written down in the docstrings instead.

Layout::

    prefixlist.pyx  PrefixList / PrefixListEntry: le/ge matching over a
                    Patricia trie, so one evaluation is a descent and not a
                    scan of the whole list
    aspath.py       AsPathMatcher / AsPathList: IOS-style regexes over the
                    canonical AS path string
    routemap.py     RouteMap / RouteMapClause / RouteMapResult: match and
                    set, parsed and validated once at configuration time
    store.py        PolicyStore: everything the running configuration
                    defines, loaded idempotently, with per-object version
                    numbers an update-group key can cite

The version numbers are load-bearing and worth reading about before
changing anything here: see the note in :mod:`~.store`. An update-group key
cites the version of every policy object it depends on, so a version that
moves when the configuration did not causes the whole table to be
re-advertised to every peer in the group.

``prefixlist`` is compiled; the rest is plain Python. The split is where the
work is. A prefix-list is consulted once per prefix per policy application,
which is millions of calls on a full table load, and the loop inside it is
bit manipulation. A route-map's match and set vocabulary is parsed once per
configuration change, and what remains on the hot path is a handful of
attribute comparisons that Python does about as well as C would.
"""

from packets.routing.rtengine.policy.aspath import (AsPathList, AsPathMatcher,
                                                    compile_pattern)
from packets.routing.rtengine.policy.prefixlist import (ACTION_DENY,
                                                        ACTION_NAMES,
                                                        ACTION_PERMIT,
                                                        NO_MATCH, PrefixList,
                                                        PrefixListEntry)
from packets.routing.rtengine.policy.routemap import (RouteMap, RouteMapClause,
                                                      RouteMapResult)
from packets.routing.rtengine.policy.store import PolicyStore

__all__ = ['ACTION_DENY', 'ACTION_PERMIT', 'ACTION_NAMES', 'NO_MATCH',
           'PrefixList', 'PrefixListEntry', 'AsPathList', 'AsPathMatcher',
           'compile_pattern', 'RouteMap', 'RouteMapClause', 'RouteMapResult',
           'PolicyStore']
