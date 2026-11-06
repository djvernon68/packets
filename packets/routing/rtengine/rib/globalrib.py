# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The cross-protocol RIB: one winner per prefix, published once.

Every plugin offers its own selection winners here as protocol-neutral
``Route`` candidates. This module picks between *protocols* -- administrative
distance, then metric, then protocol preference, then age -- and publishes the
result to the event bus and to the FIB sink. It is the only place that decides
what the engine as a whole believes about a destination.

With BGP alone the choice is usually trivial: one protocol offering one route.
The layer exists anyway, and not speculatively. It is what makes a static
route beat a learned one, what lets a next-hop be validated against everything
the engine knows rather than against one protocol's table, and what an OSPF or
RIP plugin will plug into without the BGP plugin or this file changing.

Publication is deliberately narrow. A plugin's offer does nothing observable
by itself; the selection pass is what installs, withdraws and emits events, it
runs in slices under a time budget, and it publishes each destination exactly
once per pass no matter how many times that destination was offered inside it.
Collapsing repeated churn into one published change is what keeps a flapping
peer from becoming a flapping forwarding plane.

The sink is not gated by a flag here. An engine that should not write the
kernel is given a ``NullSink``, and this code publishes to it as it would to
any other -- so there is no configuration path on which a route is selected
but silently not offered to the forwarding plane it was supposed to reach.
"""

# Imported as submodules rather than as attributes of the package, because
# the package __init__ imports the engine, which imports this file: on 3.6 a
# `from packets.routing.rtengine import events` in that cycle can fail
# against the partially initialised package, while naming the submodule
# directly always resolves.
from packets.routing.rtengine.events import ROUTE_BEST, ROUTE_WITHDRAW
from packets.routing.rtengine.rib.prefix import (AFI_IP, AFI_IP6,
                                                 SAFI_UNICAST, Prefix,
                                                 addr_len)
from packets.routing.rtengine.rib.table import RouteTable

#: The address families a table is created for when nothing says otherwise.
DEFAULT_AFI_SAFI = ((AFI_IP, SAFI_UNICAST), (AFI_IP6, SAFI_UNICAST))


class GlobalRib(object):
    """Protocol-neutral route tables, selection across them, and publication.

    :param sink: the :class:`~packets.routing.rtengine.fib.sink.FibSink` to
        publish winners to. None means nothing is published to a forwarding
        plane, which is not the same as a ``NullSink``: a NullSink accounts
        for what it was given, and is what the engine actually installs by
        default.
    :param bus: the :class:`~packets.routing.rtengine.events.EventBus` to
        emit route events on, or None for no events.
    :param afi_safi: pairs to create tables for up front. More can appear
        later through :meth:`ensure_table`.
    """

    def __init__(self, sink=None, bus=None, afi_safi=DEFAULT_AFI_SAFI):
        self.sink = sink
        self.bus = bus
        self._tables = {}
        # What was last handed to the sink, per (afi, safi, prefix). A
        # withdrawal has no new route to describe, and a forwarding plane
        # needs to be told which route to remove -- the kernel identifies a
        # route by destination, table and metric, not by "the one you sent
        # before" -- so the published route is kept until it is replaced or
        # withdrawn.
        self._published = {}
        self.selected = 0
        self.installed = 0
        self.withdrawn = 0
        for afi, safi in afi_safi:
            self.ensure_table(afi, safi)

    # --- tables ------------------------------------------------------------

    def ensure_table(self, afi, safi=SAFI_UNICAST):
        """Return the table for an address family, creating it if needed.

        :param afi: IANA address family number.
        :param safi: subsequent address family identifier.
        :return: the :class:`~packets.routing.rtengine.rib.table.RouteTable`.
        :raises ValueError: unknown address family.
        """
        if addr_len(afi) == 0:
            raise ValueError('unsupported address family number %r' % (afi,))
        key = (afi, safi)
        table = self._tables.get(key)
        if table is None:
            table = RouteTable(afi, safi)
            self._tables[key] = table
        return table

    def table(self, afi, safi=SAFI_UNICAST):
        """Return an existing table, or None.

        :param afi: IANA address family number.
        :param safi: subsequent address family identifier.
        :return: the table, or None if no plugin asked for that family.
        """
        return self._tables.get((afi, safi))

    def tables(self):
        """Return every table, keyed by ``(afi, safi)``.

        :return: a dict; the live tables, not copies.
        """
        return dict(self._tables)

    # --- the plugin-facing surface -----------------------------------------

    def offer(self, route, safi=SAFI_UNICAST):
        """Take a protocol's candidate route for a prefix.

        This and :meth:`retract` are the only ways a plugin puts route
        state into the core. Nothing is selected, published or installed
        here: the destination is marked dirty and the next selection pass
        does the work, which is what keeps a burst of a million offers from
        turning into a million event dispatches.

        :param route: the candidate route.
        :param safi: which SAFI's table it belongs in.
        :return: 1 if it replaced this protocol's previous offer, else 0.
        :raises ValueError: no route, or no table for its family.
        """
        if route is None:
            raise ValueError('a route is required')
        table = self.ensure_table(route.prefix.afi, safi)
        return table.offer(route)

    def retract(self, prefix, protocol, source, safi=SAFI_UNICAST):
        """Withdraw a protocol's offer for a prefix.

        :param prefix: the destination.
        :param protocol: the ``RT_PROTO_*`` id that offered it.
        :param source: the token it was offered with.
        :param safi: which SAFI's table it is in.
        :return: 1 if something was withdrawn, else 0.
        """
        table = self._tables.get((prefix.afi, safi))
        if table is None:
            return 0
        return table.retract(prefix, protocol, source)

    def retract_all(self, protocol, source):
        """Withdraw every offer from one source, across every table.

        The path a plugin takes when it stops or when a session goes down:
        without it, a plugin would have to remember every prefix it ever
        offered in order to take them back.

        Walks every table, so it is proportional to the table size rather
        than to the source's own route count. That is the right trade for a
        session teardown -- it happens rarely and must not miss anything --
        but it is not something to call per prefix.

        :param protocol: the ``RT_PROTO_*`` id.
        :param source: the token to withdraw.
        :return: the number of routes withdrawn.
        """
        removed = 0
        for table in self._tables.values():
            for prefix in list(table.prefixes()):
                removed += table.retract(prefix, protocol, source)
        return removed

    # --- resolution --------------------------------------------------------

    def lpm(self, afi, addr, safi=SAFI_UNICAST, accept=None):
        """Resolve an address against the winning routes.

        Used for next-hop validation: a next-hop is reachable if something
        the engine believes in covers it. A destination whose routes have
        all been withdrawn but which has not been through selection yet
        reports unreachable, because its ``best`` is what is being asked
        about and that is already None.

        :param afi: IANA address family number of the address.
        :param addr: the packed address, 4 or 16 bytes.
        :param safi: which SAFI's table to consult.
        :param accept: optional ``route -> bool``. A covering winner it
            refuses is passed over for the next shorter one, which is how
            the resolver keeps a BGP route from vouching for a BGP next hop
            (P-3) without a protocol-specific lookup here.
        :return: the winning :class:`Route` covering the address, or None.
        """
        table = self._tables.get((afi, safi))
        if table is None:
            return None
        dest = table.lpm_addr(addr)
        if accept is None:
            return dest.best if dest is not None else None
        while dest is not None:
            if dest.best is not None and accept(dest.best):
                return dest.best
            plen = dest.prefix.plen
            if plen == 0:
                return None
            dest = table.lpm(Prefix(afi, plen - 1, addr))
        return None

    # --- selection ---------------------------------------------------------

    def pending(self):
        """Return how many destinations are waiting for selection.

        :return: the total queue depth across every table.
        """
        return sum(t.pending() for t in self._tables.values())

    def select_step(self, chunk):
        """Run one bounded chunk of selection across every table.

        The step function a ``Batcher`` drives. It reports how many
        destinations it *examined*, not how many changed: a pass over a
        thousand destinations that changes none of them has still done a
        thousand destinations' worth of work, and a step that reported 0
        there would tell the batcher it was finished when it was not.

        :param chunk: maximum destinations to examine per table.
        :return: destinations examined; 0 when every queue is empty.
        """
        examined = 0
        for key in list(self._tables):
            table = self._tables[key]
            before = table.pending()
            if not before:
                continue
            changed = table.reselect(chunk)
            examined += before - table.pending()
            if changed:
                self._publish(key, changed)
        return examined

    def select(self, limit=0):
        """Run selection to completion, without yielding to the loop.

        For tests, start-up and small changes. A bulk path must use
        :meth:`drain` instead, or it will hold the loop for as long as the
        work takes.

        :param limit: maximum destinations to examine per table per pass;
            0 means unbounded.
        :return: the number of destinations examined.
        """
        total = 0
        while True:
            examined = self.select_step(limit if limit > 0 else 1 << 30)
            if not examined:
                return total
            total += examined

    async def drain(self, batcher):
        """Run selection to completion in slices, yielding between them.

        :param batcher: the :class:`~packets.routing.rtengine.loop.Batcher`
            that owns the time budget.
        :return: the number of destinations examined.
        """
        return await batcher.drain(self.select_step)

    def _publish(self, key, changed):
        """Install, withdraw and announce a batch of best-route changes."""
        afi, safi = key
        sink = self.sink
        bus = self.bus

        for dest in changed:
            self.selected += 1
            pkey = (afi, safi, dest.prefix)
            best = dest.best
            previous = self._published.get(pkey)
            if best is None:
                # The prefix has no winner at all any more. Withdraw the
                # route that was actually installed, not the destination:
                # by now the destination may already have been dropped from
                # the table, and the forwarding plane needs the route it was
                # given.
                if previous is not None:
                    del self._published[pkey]
                    if sink is not None:
                        sink.withdraw(previous)
                    self.withdrawn += 1
                if bus is not None:
                    bus.publish(ROUTE_WITHDRAW, {
                        'afi': afi, 'safi': safi,
                        'prefix': dest.prefix.to_str(),
                    })
                continue

            self._published[pkey] = best
            if sink is not None:
                # install, not withdraw-then-install: a forwarding plane
                # replaces in one operation, and withdrawing first would
                # black-hole the prefix for the width of the gap.
                sink.install(best)
            self.installed += 1
            if bus is not None:
                bus.publish(ROUTE_BEST, {
                    'afi': afi, 'safi': safi,
                    'prefix': dest.prefix.to_str(),
                    'route': best.as_dict(),
                    'previous': previous.as_dict()
                    if previous is not None else None,
                    'version': dest.version,
                })

    # --- views -------------------------------------------------------------

    def routes(self, afi, safi=SAFI_UNICAST):
        """Iterate the winning routes of one table, in prefix order.

        :param afi: IANA address family number.
        :param safi: subsequent address family identifier.
        :return: a list of :class:`Route`, best only, prefix order.
        """
        table = self._tables.get((afi, safi))
        if table is None:
            return []
        return [d.best for d in table if d.best is not None]

    def as_dict(self, afi, safi=SAFI_UNICAST, limit=0, after=None):
        """Render a table for ``show ip route``.

        Pagination is offset-free: the caller passes the last prefix it
        saw and gets the next page. Because the trie walks in the same
        order ``sorted()`` would, that resumes correctly even if the table
        changed between requests -- which an index-based offset would not.

        :param afi: IANA address family number.
        :param safi: subsequent address family identifier.
        :param limit: maximum entries to return; 0 for all of them.
        :param after: return entries strictly greater than this
            :class:`Prefix`.
        :return: ``{'items': [...], 'next': <prefix text or None>}``.
            ``next`` is the *last* prefix of this page, to be passed back
            as ``after`` (P-4: it used to be the first prefix left out,
            which ``after`` then skipped -- one route lost per page). None
            when nothing with a route follows.
        """
        table = self._tables.get((afi, safi))
        items = []
        nxt = None
        if table is None:
            return {'items': items, 'next': nxt}
        last = None
        for prefix, dest in table.items():
            if after is not None and not prefix > after:
                continue
            if dest.best is None:
                continue
            if limit and len(items) >= limit:
                nxt = last.to_str()
                break
            items.append(dest.as_dict())
            last = prefix
        return {'items': items, 'next': nxt}

    def stats(self):
        """Return counters for health output.

        :return: a dict of plain types.
        """
        return {
            'tables': dict(('%d/%d' % k, t.stats())
                           for k, t in self._tables.items()),
            'pending': self.pending(),
            'selected': self.selected,
            'installed': self.installed,
            'withdrawn': self.withdrawn,
            'published': len(self._published),
        }

    def __repr__(self):
        return '<GlobalRib tables=%d published=%d pending=%d>' % (
            len(self._tables), len(self._published), self.pending())
