# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Protocol-neutral routing information base.

Three compiled modules and two Python ones:

``prefix``      ``Prefix``: an (afi, plen, address) key with a cached hash, a
                total order that matches trie traversal order, and the C-level
                bit helpers the trie and the policy prefix-lists share.
``trie``        a path-compressed binary radix (Patricia) trie over ``Prefix``
                keys with exact match, longest-prefix match and removal. One
                structure serves the RIB, prefix-lists and the resolver.
``table``       ``Route`` (what a plugin offers), ``Dest`` (all routes for one
                prefix plus the winner) and ``RouteTable`` (one per afi/safi,
                with the change queue the selection pass drains).
``globalrib``   selection across protocols by administrative distance, then
                metric, then protocol preference; publishes to events and the
                FIB sink.
``resolver``    next-hop reachability lookups for the plugins that want them.

Nothing here knows what BGP is. A plugin offers ``Route`` candidates and gets
winners back; its own attribute model and best-path algorithm stay inside the
plugin. That boundary is the whole point of the split: it is what lets an
OSPF or RIP plugin arrive later without the core changing.

The compiled modules are imported here so that ``from ... import rib`` fails
loudly and immediately when the extensions are not built, rather than at the
first insert.
"""

from packets.routing.rtengine.rib.prefix import (AFI_IP, AFI_IP6,
                                                 SAFI_UNICAST, Prefix,
                                                 parse_prefix)
from packets.routing.rtengine.rib.table import Dest, Route, RouteTable
from packets.routing.rtengine.rib.trie import Trie

__all__ = ['AFI_IP', 'AFI_IP6', 'SAFI_UNICAST', 'Prefix', 'parse_prefix',
           'Trie', 'Route', 'Dest', 'RouteTable']
