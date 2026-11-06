# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Next-hop resolution: is the address a protocol wants to forward to usable?

A BGP path whose next-hop is unreachable must not be selected, and its
distance to that next-hop is one of the tie-breaks in best-path selection. Both
questions are asked of this table rather than of the protocol's own state,
because reachability is a property of everything the engine knows and not of
one protocol.

**Validation is off by default.** rtengine's normal role is a control-plane
speaker with no forwarding plane and no IGP, and in that role every next-hop is
reachable by definition -- the packets are somebody else's problem. Turning
validation on without anything to validate against would make every learned
path ineligible and the speaker would silently carry nothing, which is a far
worse failure than accepting a next-hop that is not locally reachable. So
``reachable()`` answers True for everything until validation is enabled and
something has been loaded to validate against.

**What it resolves against.** Three tables, consulted in a fixed order:
static entries from ``ip route <prefix> <next-hop>`` in the configuration,
then the kernel's own routes when ``ip.route.kernel-import`` has loaded
them, then optionally the engine's winning routes. There is no IGP plugin,
so ``igp_metric`` is the metric of whichever entry matched, or 0.

**Why a configured static always wins.** The kernel import is a snapshot of
somebody else's forwarding table, taken once; a static entry is what an
operator wrote down. If the two disagree about a prefix, the operator's
intent is the one that has to survive, and a snapshot that could silently
replace a configured route would make the configuration document stop
describing the running system. They are therefore kept in *separate* tables
and ordered, rather than merged into one and left to administrative
distance -- merging would make the outcome depend on the order the two were
loaded in, which is a start-up race rather than a policy.

**The kernel import is read-only, Linux-only and off by default.** It sends
one ``RTM_GETROUTE`` dump and never a write verb, it reuses the parser in
``fib/netlink.py`` rather than carrying a second one, and that module is
imported lazily so this file stays importable on a development Mac. Off by
default because importing another system's forwarding decisions into a
reachability test is a policy choice, and because a stale snapshot is worse
than no snapshot: nothing refreshes it, so an operator who turns it on is
saying the kernel's table is stable for the life of the process.

**What may vouch for a next hop (P-3).** Each table is searched from the
longest covering prefix to the shortest, and three things are passed over on
the way:

  * **a default route**, unless ``ip.route.resolve-via-default`` is set (FRR's
    ``ip nht resolve-via-default``). A default covers every address, so it
    proves nothing about any of them; letting it count is how a router with
    a default ends up believing every next hop is reachable;
  * **the asking protocol's own routes**, in the engine's table. A BGP next
    hop resolved through a BGP route is reachability asserted by the very
    protocol whose assertion is being checked -- the route can be the one
    that only exists because of the next hop it is vouching for;
  * **an engine route whose own next hop does not resolve**. A route learned
    by a protocol is only as good as the way to reach *its* next hop, so
    that is resolved in turn, at most :data:`MAX_DEPTH` levels deep and
    never through the same prefix twice: a chain that loops, or that is
    still going after four levels, is unresolved rather than half-trusted.

A static entry and an imported kernel route end the chain. The static is an
operator's statement that the prefix is reachable, and rtengine knows no
connected routes to check its next hop against -- requiring one would make
every static unresolvable on a box without ``kernel-import``. The kernel
already refused any route whose gateway it could not reach.
"""

#: Recursive lookups allowed beyond the first (P-3).
MAX_DEPTH = 4

from packets.routing.rtengine.rib.prefix import (AFI_IP, AFI_IP6,
                                                 SAFI_UNICAST, Prefix,
                                                 addr_len, parse_prefix)
from packets.routing.rtengine.rib.table import (PROTO_STATIC, PROTO_UNSPEC,
                                                Route, RouteTable)

#: What an imported kernel route is offered with. Protocol-neutral on
#: purpose: rtengine's ``PROTO_*`` ids name which of *our* protocols offered
#: a route, and a route read out of the kernel came from none of them. The
#: id is never compared here anyway -- imported routes live in their own
#: table where nothing competes with them.
KERNEL_PROTOCOL = PROTO_UNSPEC

#: The administrative distance imported routes are recorded with. Carried
#: for symmetry with a static entry and never consulted: resolution is
#: ordered by table, not by distance. 255 is the conventional spelling of
#: "trust this least".
KERNEL_DISTANCE = 255


def _knob(name):
    """A boolean attribute whose change moves ``Resolver.generation``.

    :param name: the attribute's public name.
    :return: a property storing ``_<name>``.
    """
    attr = '_' + name

    def get(self):
        return getattr(self, attr)

    def set(self, value):
        value = bool(value)
        if getattr(self, attr, None) is not value:
            setattr(self, attr, value)
            self.generation += 1

    return property(get, set)


class Resolution(object):
    """The answer to one next-hop lookup.

    :param prefix: the covering prefix that matched.
    :param nexthop: its next-hop, packed, or empty when directly attached.
    :param metric: the metric to carry into best-path selection as the
        distance to this next-hop.
    :param source: ``'static'``, ``'kernel'`` or ``'rib'`` -- which table
        answered. Reported verbatim by show output, so a reader can tell a
        configured route from an imported one without a second lookup.
    """

    __slots__ = ('prefix', 'nexthop', 'metric', 'source')

    def __init__(self, prefix, nexthop, metric, source):
        self.prefix = prefix
        self.nexthop = nexthop
        self.metric = metric
        self.source = source

    def as_dict(self):
        """Render for show output.

        :return: a dict of plain types.
        """
        return {
            'prefix': self.prefix.to_str(),
            'metric': self.metric,
            'source': self.source,
        }

    def __repr__(self):
        return '<Resolution %s metric=%d via %s>' % (
            self.prefix.to_str(), self.metric, self.source)


class Resolver(object):
    """Static next-hop reachability, optionally backed by the engine's RIB.

    :param global_rib: consulted when ``use_rib`` is on and no static entry
        covers the address, so a next-hop learned through a routing protocol
        can validate another protocol's next-hop.
    :param enabled: whether validation actually gates anything. Off by
        default; see the module docstring for why that is the safe default
        rather than the lax one.
    :param use_rib: whether to fall back to the engine's winning routes.
    :param kernel_import: whether :meth:`load_kernel` may run. Off by
        default, and it is only a permission: nothing is imported until
        :meth:`load_kernel` is called, so a configuration flag alone never
        opens a netlink socket.
    :param resolve_via_default: whether a default route may resolve a next
        hop; see the module docstring.
    """

    enabled = _knob('enabled')
    kernel_import = _knob('kernel_import')
    resolve_via_default = _knob('resolve_via_default')

    def __init__(self, global_rib=None, enabled=False, use_rib=True,
                 kernel_import=False, resolve_via_default=False):
        # Moves whenever an answer this object gives may have changed
        # without the GlobalRib selecting anything: a static added or
        # removed, a kernel import, a knob flipped. A protocol that caches
        # next-hop verdicts compares it to know when to re-ask (S6-c);
        # before it, such a change waited for an unrelated selection or a
        # soft clear. A no-op change leaves it alone, because every commit
        # reloads the statics and a full-table revalidation per commit
        # would be the price of not checking.
        self.generation = 0
        self._static_signature = None
        self.global_rib = global_rib
        self.enabled = bool(enabled)
        self.use_rib = bool(use_rib)
        self.kernel_import = bool(kernel_import)
        self.resolve_via_default = bool(resolve_via_default)
        self._static = {
            AFI_IP: RouteTable(AFI_IP, SAFI_UNICAST),
            AFI_IP6: RouteTable(AFI_IP6, SAFI_UNICAST),
        }
        # A second set of tables rather than more entries in the first: the
        # two sources are ranked, not merged, so a configured static cannot
        # be displaced by a snapshot of the kernel's table.
        self._kernel = {
            AFI_IP: RouteTable(AFI_IP, SAFI_UNICAST),
            AFI_IP6: RouteTable(AFI_IP6, SAFI_UNICAST),
        }
        # Every static entry is offered by this object, so retracting one is
        # a matter of naming its prefix rather than tracking who added it.
        self._source = self
        # Distinct from _source so that an imported route and a configured
        # one for the same prefix are two offers, not one replacing the
        # other, even if they ever share a table.
        self._kernel_source = object()
        self.lookups = 0
        self.hits = 0
        self.kernel_loads = 0
        self.kernel_imported = 0
        self.kernel_skipped = 0
        self.kernel_errors = 0
        self.kernel_last_error = None
        self.source_hits = {'static': 0, 'kernel': 0, 'rib': 0}
        # Lookups refused for a loop or for running past MAX_DEPTH.
        self.recursion_failures = 0

    # --- static entries ----------------------------------------------------

    def add_static(self, prefix, nexthop, distance=1, metric=0):
        """Add or replace a static resolver entry.

        :param prefix: a :class:`Prefix` or an ``address/length`` string.
        :param nexthop: the next-hop as a packed address, an address
            string, or empty/None for a directly attached destination.
        :param distance: administrative distance; carried for symmetry with
            a route, not used in resolution.
        :param metric: reported as the distance to any next-hop this entry
            resolves, and fed to a protocol's own tie-breaks.
        :return: the :class:`Route` that was stored.
        :raises ValueError: unparseable prefix or next-hop.
        """
        if not hasattr(prefix, 'afi'):
            prefix = parse_prefix(prefix)
        packed = _pack_nexthop(nexthop)
        table = self._static.get(prefix.afi)
        if table is None:
            raise ValueError('unsupported address family number %d'
                             % prefix.afi)
        route = Route(prefix, PROTO_STATIC, distance, metric, packed,
                      self._source)
        table.offer(route)
        # Resolved immediately rather than on the next engine selection
        # pass: a static entry is configuration, and configuration that has
        # been accepted should be in effect when the call returns.
        table.reselect(0)
        self._static_signature = None
        self.generation += 1
        return route

    def remove_static(self, prefix):
        """Remove a static resolver entry.

        :param prefix: a :class:`Prefix` or an ``address/length`` string.
        :return: True if an entry was removed.
        """
        if not hasattr(prefix, 'afi'):
            prefix = parse_prefix(prefix)
        table = self._static.get(prefix.afi)
        if table is None:
            return False
        removed = table.retract(prefix, PROTO_STATIC, self._source)
        table.reselect(0)
        if removed:
            self._static_signature = None
            self.generation += 1
        return bool(removed)

    def load_static(self, entries):
        """Replace every static entry from a configuration section.

        Replace, not merge: the configuration document is the whole truth
        about static routes, so an entry that is gone from it must be gone
        from here. Merging would leave a deleted route resolving for as
        long as the process lived.

        :param entries: ``{prefix_text: {'next-hop': addr, 'metric': int,
            'distance': int}}``, as the ``ip.route.static`` section holds
            it.
        :return: the number of entries loaded.
        :raises ValueError: an entry is unparseable; nothing is changed.
        """
        parsed = []
        for prefix_text, body in (entries or {}).items():
            prefix = parse_prefix(prefix_text)
            body = body or {}
            parsed.append((prefix, _pack_nexthop(body.get('next-hop')),
                           int(body.get('distance', 1)),
                           int(body.get('metric', 0))))
        # Built completely before anything is installed, so a bad entry
        # halfway down a configuration file does not leave the resolver
        # holding half of it.
        for afi in list(self._static):
            self._static[afi] = RouteTable(afi, SAFI_UNICAST)
        for prefix, packed, distance, metric in parsed:
            table = self._static.get(prefix.afi)
            if table is None:
                raise ValueError('unsupported address family number %d'
                                 % prefix.afi)
            table.offer(Route(prefix, PROTO_STATIC, distance, metric,
                              packed, self._source))
        for table in self._static.values():
            table.reselect(0)
        signature = sorted((p.afi, p.to_str(), packed, distance, metric)
                           for p, packed, distance, metric in parsed)
        if signature != self._static_signature:
            self._static_signature = signature
            self.generation += 1
        return len(parsed)

    def statics(self, afi):
        """Return the static entries for one family, in prefix order.

        :param afi: IANA address family number.
        :return: a list of :class:`Route`.
        """
        table = self._static.get(afi)
        if table is None:
            return []
        return [d.best for d in table if d.best is not None]

    # --- the kernel's own routes, read once --------------------------------

    def load_kernel(self, table=None, family=None, transport=None,
                    timeout=None):
        """Import the kernel's unicast routes, replacing any earlier import.

        One ``RTM_GETROUTE|NLM_F_DUMP`` and nothing else: this path has no
        write verb in it at all, which is the property that makes it safe
        to run on a host carrying somebody else's forwarding table.

        Replace, not merge, for the same reason :meth:`load_static` does:
        a route the kernel no longer has must not keep resolving here, and
        a second import that merged would accumulate the union of every
        snapshot ever taken.

        A prefix that a configured static already covers is counted and
        imported anyway. It cannot win -- :meth:`resolve` reads the static
        table first -- and keeping it means an operator who removes the
        static does not silently lose the kernel's answer for that prefix
        as well.

        The netlink module is imported here rather than at the top of the
        file so that this module stays importable on macOS, where the
        engine is developed and where ``ip.route.kernel-import`` can be
        configured but never used.

        :param table: limit the import to one routing table id, or None for
            every table the kernel reports.
        :param family: ``AF_INET``/``AF_INET6`` as netlink numbers, or None
            for both. Pass through from ``fib.netlink``; there is
            deliberately no translation here, because a socket constant
            from the local platform would be the wrong number.
        :param transport: a substitute netlink transport, for tests.
        :param timeout: seconds to allow the dump.
        :return: the number of entries imported.
        :raises RuntimeError: ``kernel_import`` was not enabled. A caller
            that reaches this has a configuration bug, and importing
            anyway would make the flag decorative.
        :raises OSError: the dump failed, or this host has no netlink.
        """
        if not self.kernel_import:
            raise RuntimeError('ip.route.kernel-import is not enabled on '
                               'this resolver')
        from packets.routing.rtengine.fib import netlink

        if family is None:
            family = netlink.AF_UNSPEC
        try:
            found = netlink.kernel_routes(table=table, family=family,
                                          transport=transport,
                                          timeout=timeout)
        except Exception as exc:
            # Counted and re-raised rather than swallowed: the caller asked
            # for this explicitly and a silent empty import would look
            # exactly like a kernel with no routes.
            self.kernel_errors += 1
            self.kernel_last_error = repr(exc)
            raise

        parsed = []
        skipped = 0
        for kroute in found:
            prefix = kroute.prefix
            if prefix is None or prefix.afi not in self._kernel:
                continue
            if self._covered_by_static(prefix):
                skipped += 1
            parsed.append((prefix, kroute.gateway or b'', kroute.priority))

        for afi in list(self._kernel):
            self._kernel[afi] = RouteTable(afi, SAFI_UNICAST)
        for prefix, gateway, metric in parsed:
            table_obj = self._kernel[prefix.afi]
            table_obj.offer(Route(prefix, KERNEL_PROTOCOL, KERNEL_DISTANCE,
                                  metric, gateway, self._kernel_source))
        for table_obj in self._kernel.values():
            table_obj.reselect(0)

        self.kernel_loads += 1
        self.generation += 1
        self.kernel_imported = len(parsed)
        self.kernel_skipped = skipped
        self.kernel_last_error = None
        return len(parsed)

    def clear_kernel(self):
        """Drop every imported kernel route.

        :return: the number of entries dropped.
        """
        dropped = sum(t.route_count for t in self._kernel.values())
        for afi in list(self._kernel):
            self._kernel[afi] = RouteTable(afi, SAFI_UNICAST)
        self.kernel_imported = 0
        if dropped:
            self.generation += 1
        return dropped

    def kernels(self, afi):
        """Return the imported kernel entries for one family.

        :param afi: IANA address family number.
        :return: a list of :class:`Route`, in prefix order.
        """
        table = self._kernel.get(afi)
        if table is None:
            return []
        return [d.best for d in table if d.best is not None]

    def _covered_by_static(self, prefix):
        """Return whether a configured static already covers a prefix.

        Covers, not equals (P-7): statics are consulted first whatever
        their length, so a kernel ``10.1.0.0/16`` under a static
        ``10.0.0.0/8`` can never answer a lookup either. Only a static the
        lookup would use counts, so a default does only with
        ``resolve-via-default``.
        """
        table = self._static.get(prefix.afi)
        if table is None:
            return False
        return self._covering(table, prefix.afi, prefix.packed(),
                              prefix.plen) is not None

    def _covering(self, table, afi, addr, plen=None):
        """The longest Dest in a table that may answer for an address.

        :param table: a :class:`RouteTable`.
        :param afi: its family.
        :param addr: the packed address.
        :param plen: the length of the prefix being asked about, or None
            for a bare address.
        :return: the Dest, or None. A Dest whose routes are all withdrawn,
            and a default without ``resolve-via-default``, are passed over
            for the next shorter cover.
        """
        if plen is None:
            dest = table.lpm_addr(addr)
        else:
            dest = table.lpm(Prefix(afi, plen, addr))
        while dest is not None:
            length = dest.prefix.plen
            if dest.best is not None and (length or
                                          self.resolve_via_default):
                return dest
            if length == 0:
                return None
            dest = table.lpm(Prefix(afi, length - 1, addr))
        return None

    # --- resolution --------------------------------------------------------

    def resolve(self, afi, addr, protocol=None):
        """Resolve an address to the entry that covers it.

        :param afi: IANA address family number of the address.
        :param addr: the packed address, 4 or 16 bytes.
        :param protocol: the ``PROTO_*`` id of the protocol asking, whose
            own routes in the engine's table may not vouch for its next
            hop (P-3); None to accept any.
        :return: a :class:`Resolution` for the first step of the chain, or
            None if nothing usable covers the address.
        :raises ValueError: the address is the wrong width for the family.
        """
        if addr_len(afi) == 0:
            raise ValueError('unsupported address family number %r' % (afi,))
        if not isinstance(addr, bytes) or len(addr) != addr_len(afi):
            raise ValueError('afi %r needs a %d byte address'
                             % (afi, addr_len(afi)))
        self.lookups += 1
        found = self._resolve(afi, addr, protocol, 0, set())
        if found is not None:
            self.hits += 1
            self.source_hits[found.source] += 1
        return found

    def _step(self, afi, addr, protocol):
        """One lookup, in source order: static, kernel, then the engine.

        :return: ``(source, prefix, route)``, or None.
        """
        # Static first, always: a configured route is an operator's
        # statement of intent and outranks both a snapshot of the kernel's
        # table and anything a protocol has learned.
        for source, tables in (('static', self._static),
                               ('kernel', self._kernel)):
            table = tables.get(afi)
            if table is None:
                continue
            dest = self._covering(table, afi, addr)
            if dest is not None:
                return source, dest.prefix, dest.best

        if self.use_rib and self.global_rib is not None:
            def usable(route):
                if protocol is not None and route.protocol == protocol:
                    return False
                return route.prefix.plen > 0 or self.resolve_via_default
            route = self.global_rib.lpm(afi, addr, accept=usable)
            if route is not None:
                return 'rib', route.prefix, route
        return None

    def _resolve(self, afi, addr, protocol, depth, seen):
        """Resolve one address, recursing through engine routes.

        :param seen: the ``(afi, prefix)`` pairs already on this chain.
        :return: a :class:`Resolution`, or None.
        """
        step = self._step(afi, addr, protocol)
        if step is None:
            return None
        source, prefix, route = step
        if source == 'rib' and route.nexthop:
            # A learned route: only as good as the way to its own next
            # hop. Tried before answering, so a route that cannot be
            # reached does not count -- it is not passed over for a
            # shorter one either, because forwarding would follow it.
            key = (afi, prefix)
            if key in seen or depth >= MAX_DEPTH:
                self.recursion_failures += 1
                return None
            seen.add(key)
            nh_afi = AFI_IP if len(route.nexthop) == 4 else AFI_IP6
            if self._resolve(nh_afi, route.nexthop, protocol, depth + 1,
                             seen) is None:
                return None
        return Resolution(prefix, route.nexthop, route.metric, source)

    def reachable(self, afi, addr, protocol=None):
        """Return whether a next-hop may be used.

        True for everything while validation is disabled, which is the
        default: a control-plane speaker with no forwarding plane and no
        IGP has nothing to validate against, and answering False there
        would make every learned path ineligible.

        :param afi: IANA address family number.
        :param addr: the packed next-hop address.
        :param protocol: the asking protocol; see :meth:`resolve`.
        :return: True if the next-hop may be used.
        """
        if not self.enabled:
            return True
        return self.resolve(afi, addr, protocol) is not None

    def igp_metric(self, afi, addr, protocol=None):
        """Return the cost to a next-hop, for a protocol's tie-breaks.

        0 when validation is off or nothing covers the address -- there is
        no IGP in v1, so this is the configured metric of a static entry or
        nothing at all, and every path then ties at this stage and is
        decided by the tie-break after it.

        :param afi: IANA address family number.
        :param addr: the packed next-hop address.
        :param protocol: the asking protocol; see :meth:`resolve`.
        :return: the metric.
        """
        if not self.enabled:
            return 0
        found = self.resolve(afi, addr, protocol)
        return found.metric if found is not None else 0

    def stats(self):
        """Return counters and configuration for health output.

        :return: a dict of plain types.
        """
        return {
            'enabled': self.enabled,
            'use_rib': self.use_rib,
            'static': dict((str(afi), t.route_count)
                           for afi, t in self._static.items()),
            'lookups': self.lookups,
            'hits': self.hits,
            # New keys only; the five above are what health and the tests
            # already read and they keep their names and meanings.
            'kernel-import': self.kernel_import,
            'kernel': dict((str(afi), t.route_count)
                           for afi, t in self._kernel.items()),
            'kernel-loads': self.kernel_loads,
            'kernel-imported': self.kernel_imported,
            'kernel-shadowed': self.kernel_skipped,
            'kernel-errors': self.kernel_errors,
            'kernel-last-error': self.kernel_last_error,
            'sources': dict(self.source_hits),
            'resolve-via-default': self.resolve_via_default,
            'recursion-failures': self.recursion_failures,
            'generation': self.generation,
        }

    def __repr__(self):
        return '<Resolver enabled=%s static=%d kernel=%d>' % (
            self.enabled, sum(t.route_count for t in self._static.values()),
            sum(t.route_count for t in self._kernel.values()))


def _pack_nexthop(nexthop):
    """Normalise a next-hop to packed bytes.

    Accepts what configuration and code each naturally hold: a text address
    from a JSON document, packed bytes from a decoder, or nothing at all for
    a directly attached destination.

    :param nexthop: str, bytes, or None.
    :return: packed bytes, possibly empty.
    :raises ValueError: not an address.
    """
    if nexthop is None or nexthop == '' or nexthop == b'':
        return b''
    if isinstance(nexthop, bytes):
        if len(nexthop) not in (4, 16):
            raise ValueError('a packed next-hop must be 4 or 16 bytes')
        return nexthop
    parsed = parse_prefix(nexthop)
    if not parsed.is_host:
        raise ValueError('a next-hop must be a bare address, not a prefix')
    return parsed.packed()
