# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""One BGP session: transport, framing, state machine and the RIB hand-off.

Everything a session needs already exists somewhere else. :mod:`transport`
owns sockets and authentication, :mod:`wire` owns bytes, :mod:`fsm` owns
state and timers, :mod:`errors` owns the RFC 7606 matrix, :mod:`locrib`
owns the table and :mod:`adjout` owns what the peer gets told. This module
is the wiring, and its job is to make sure each of those keeps its own
concern:

* the FSM is never handed a socket, only events, and its actions are
  performed here;
* the codec is never handed a RIB, only bytes, and its output is applied
  here;
* the RIB is never handed a malformed UPDATE, because the matrix runs
  here first.

Two properties are worth calling out because they are easy to lose.

**An UPDATE applies atomically.** The decoder parses the whole message
without touching anything, the matrix judges every fault it found, and
only then is the Adj-RIB-In modified. A decoder that applied as it parsed
would leave half an UPDATE in the table when the second half turned out to
be malformed, and the half that landed would never be withdrawn because
nobody would remember it was there.

**The Adj-RIB-In is keyed by ``(prefix, path_id)``, and it is the
authority on what this peer has told us.** Without it, a withdrawal for a
prefix we never received, or a session teardown, would have to be resolved
by scanning the Loc-RIB; with it, both are a dictionary operation. It is
also the only way to answer "what did this peer actually send me", which
is the first question in any peering dispute.

Everything here runs on the engine's single event loop. Nothing blocks: a
full-table load arrives as tens of thousands of messages and is processed
in bounded slices so the loop keeps servicing other peers, health probes
and the FIB.
"""

import asyncio
import collections
import logging
import time

from packets.routing.rtengine.rib.prefix import AFI_IP, SAFI_UNICAST
from packets.routing.rtengine.plugins.bgp import (
    bestpath, capabilities, errors, fsm as fsm_mod, wire)
from packets.routing.rtengine.transport import auth as auth_mod
from packets.routing.rtengine.transport import tcp as tcp_mod


LOG = logging.getLogger(__name__)

# Cancellation is how this module is shut down, so it is expected control
# flow rather than a fault, and every coroutine here catches it by name.
# It has to be by name: on Python 3.8 and later ``CancelledError`` derives
# from ``BaseException``, so a bare ``except Exception`` no longer sees
# it, while on the 3.6 floor it still derives from ``Exception`` and the
# ordering of the two handlers is what decides which wins. Letting it
# escape leaves asyncio printing "Task exception was never retrieved" with
# a traceback for every peer on every clean shutdown, which teaches
# whoever reads the logs that tracebacks there are normal.
CANCELLED = asyncio.CancelledError

# How many decoded messages to apply before yielding to the loop. A full
# table is tens of thousands of UPDATEs; applying them in one go would
# stall every other peer, the health probe and the FIB for seconds. The
# figure is a compromise measured the same way as the RIB's batch size --
# large enough that the per-slice overhead is noise, small enough that one
# slice is well inside a millisecond.
APPLY_SLICE = 256

# The family every BGP speaker has, named once so the several places that
# default to it cannot drift apart.
IPV4_UNICAST = (AFI_IP, SAFI_UNICAST)

# BGP's own idea of "a while": used to bound how long we will sit with a
# connection that has produced nothing at all.
IDLE_READ_TIMEOUT = 1.0

# Wall-clock budget for one slice of received messages. The message count
# above bounds a slice of small UPDATEs; this bounds a slice of large ones,
# which is what starved hold timers before (S-8). The same 50 ms ceiling
# the engine's Batcher adapts towards.
APPLY_BUDGET = 0.05

# How long a closing session may spend getting its NOTIFICATION out and
# hearing the peer close in return. Bounded because a peer that stopped
# reading can otherwise hold a deconfigured session open indefinitely,
# and short because every stop path waits on it.
NOTIFY_LINGER = 1.0

# The bulk lane's high-water mark, in bytes queued but not yet written.
# Above it the session reports itself unwritable and the advertiser waits
# (``wait_writable``); below half of it, waiters are released. This is the
# back-pressure ``Connection.send`` was designed to provide and the old
# fire-and-forget flush threw away (S-3). See O-1 for the tuning.
BULK_HIGH_WATER = 256 * 1024
BULK_LOW_WATER = BULK_HIGH_WATER // 2

# Upper bound on one write from the bulk lane, so a KEEPALIVE queued
# behind a full table waits for at most this much, not for the table.
WRITE_CHUNK = 64 * 1024

# Consecutive failures of the timer loop's own sleep after which it gives
# up. It cannot back off -- the sleep is what failed -- and retrying for
# ever without yielding would hang the loop instead of one session.
TIMER_FAILURE_LIMIT = 10

#: IOS ``bgp maxas-limit``, on by default (P-2): a received AS_PATH with
#: more ASNs than this is treated as withdrawn. Real paths are a few tens of
#: ASNs long; what is longer is a prepend accident or an attack, and an
#: extended message (RFC 8654) can carry about 16,000 of them -- a string
#: every AS-path regex then has to be run over.
DEFAULT_MAXAS_LIMIT = 255


class PeerConfig(object):
    """Everything configured about one neighbour.

    Built by the plugin from the IOS-shaped configuration tree; kept as a
    plain object rather than a dict so a typo in a key is an
    ``AttributeError`` at construction rather than a silently defaulted
    setting at three in the morning.

    :param address: the neighbour's address as a string.
    :param remote_as: the neighbour's AS.
    :param local_as: our AS on this session; differs from the router's AS
        only when ``local-as`` is configured.
    :param router_id: our BGP identifier, as a 32-bit int or dotted quad.
    :param description: free text for ``show``.
    :param update_source: local address to bind before connecting.
    :param password: TCP-MD5 secret, or None.
    :param ao: TCP-AO settings dict, or None.
    :param ttl_security: GTSM hop count, or None.
    :param ebgp_multihop: TTL for a multihop eBGP session, or None.
    :param passive: never initiate, only accept.
    :param shutdown: administratively down.
    :param hold_time: proposed hold time.
    :param keepalive: keepalive interval.
    :param connect_retry: connect retry interval.
    :param delay_open: delay-open interval, 0 to disable.
    :param afi_safi: iterable of ``(afi, safi)`` to advertise.
    :param next_hop_self: rewrite the next hop to ours on iBGP output.
    :param add_path_receive: advertise ADD-PATH receive.
    :param extended_message: advertise RFC 8654 extended message.
    :param route_refresh: advertise route refresh.
    :param graceful_restart: advertise a restart time, or False.
    :param maximum_prefix: tear the session down past this many prefixes,
        or 0 for no limit.
    :param maximum_prefix_warning: warn at this fraction of the limit.
    :param send_community: send standard communities.
    :param send_ext_community: send extended communities.
    :param send_large_community: send large communities.
    :param weight: local weight applied to every path from this peer.
    :param allowas_in: tolerate our own AS this many times in a received
        AS_PATH, for hub-and-spoke designs that legitimately loop. Inbound
        only (B-5).
    :param remove_private_as: strip private ASNs on output: False, True
        (only from an all-private path, as IOS does) or ``'all'``.
    :param as_override: replace the peer's AS with ours on output.
    :param sender_loop_check: do not send this external peer paths that
        already contain its AS. Off only when the peer is configured to
        accept them.
    :param next_hop_af: a mapping of ``(afi, safi)`` to the next-hop
        address, as text, to advertise in that family when we set the
        next hop ourselves. The only way to give an IPv6 family a real
        next hop over an IPv4 session (L-4).
    :param maxas_limit: treat a received path as withdrawn when its
        AS_PATH holds more ASNs than this, every member of every segment
        counted; 0 for no limit. The instance's ``maxas-limit``, copied
        here so that the check costs no lookup. Not session-affecting.
    :param advertisement_interval: minimum seconds between two
        advertisement flushes to this peer -- RFC 4271's MRAI, applied per
        update group. 0 disables it. Not session-affecting: changing it
        moves the peer between groups and costs no reset.
    :param policy: a mapping of ``(afi, safi)`` to
        ``{'in': {...names...}, 'out': {...names...}}``, where each inner
        dict may carry ``prefix-list``, ``filter-list`` and ``route-map``.
        Names rather than compiled objects, because the objects are owned
        by the engine's policy store and are rebuilt when the
        configuration changes while this config object is not.
    :param next_hop_self_af: a mapping of ``(afi, safi)`` to a per-family
        override of ``next_hop_self``. IPv6 is the reason it exists: a
        neighbour that should keep the next hop it was given for IPv4 and
        rewrite it for IPv6 is an ordinary configuration, and one flag
        cannot say it.
    """

    __slots__ = (
        'address', 'remote_as', 'local_as', 'router_id', 'description',
        'update_source', 'password', 'ao', 'ttl_security', 'ebgp_multihop',
        'passive', 'shutdown', 'hold_time', 'keepalive', 'connect_retry',
        'delay_open', 'afi_safi', 'next_hop_self', 'add_path_receive',
        'extended_message', 'route_refresh', 'graceful_restart',
        'maximum_prefix', 'maximum_prefix_warning', 'send_community',
        'send_ext_community', 'send_large_community', 'weight',
        'allowas_in', 'remove_private_as', 'as_override', 'port',
        'advertisement_interval', 'policy', 'next_hop_self_af',
        'sender_loop_check', 'next_hop_af', 'maxas_limit')

    def __init__(self, address, remote_as, local_as, router_id,
                 description=None, update_source=None, password=None,
                 ao=None, ttl_security=None, ebgp_multihop=None,
                 passive=False, shutdown=False,
                 hold_time=fsm_mod.DEFAULT_HOLD_TIME, keepalive=None,
                 connect_retry=fsm_mod.DEFAULT_CONNECT_RETRY, delay_open=0,
                 afi_safi=None, next_hop_self=False,
                 add_path_receive=False, extended_message=False,
                 route_refresh=True, graceful_restart=False,
                 maximum_prefix=0, maximum_prefix_warning=0.75,
                 send_community=True, send_ext_community=True,
                 send_large_community=True, weight=0, allowas_in=0,
                 remove_private_as=False, as_override=False,
                 port=tcp_mod.BGP_PORT, advertisement_interval=0.0,
                 policy=None, next_hop_self_af=None,
                 sender_loop_check=True, next_hop_af=None,
                 maxas_limit=DEFAULT_MAXAS_LIMIT):
        self.address = address
        self.remote_as = remote_as
        self.local_as = local_as
        self.router_id = router_id
        self.description = description
        self.update_source = update_source
        self.password = password
        self.ao = ao
        self.ttl_security = ttl_security
        self.ebgp_multihop = ebgp_multihop
        self.passive = passive
        self.shutdown = shutdown
        self.hold_time = hold_time
        self.keepalive = keepalive
        self.connect_retry = connect_retry
        self.delay_open = delay_open
        self.afi_safi = (frozenset(afi_safi) if afi_safi
                         else frozenset([IPV4_UNICAST]))
        self.next_hop_self = next_hop_self
        self.add_path_receive = add_path_receive
        self.extended_message = extended_message
        self.route_refresh = route_refresh
        self.graceful_restart = graceful_restart
        self.maximum_prefix = maximum_prefix
        self.maximum_prefix_warning = maximum_prefix_warning
        self.send_community = send_community
        self.send_ext_community = send_ext_community
        self.send_large_community = send_large_community
        self.weight = weight
        self.allowas_in = allowas_in
        self.remove_private_as = remove_private_as
        self.as_override = as_override
        self.port = port
        self.advertisement_interval = float(advertisement_interval or 0.0)
        self.policy = policy if policy is not None else {}
        self.next_hop_self_af = (next_hop_self_af
                                 if next_hop_self_af is not None else {})
        self.sender_loop_check = bool(sender_loop_check)
        self.next_hop_af = next_hop_af if next_hop_af is not None else {}
        self.maxas_limit = int(maxas_limit or 0)

    def next_hop_self_for(self, af):
        """Return whether to rewrite the next hop for one family.

        :param af: an ``(afi, safi)`` pair.
        :return: the per-family override when one is configured, and the
            neighbour-wide setting otherwise.
        """
        override = self.next_hop_self_af.get(af)
        if override is None:
            return self.next_hop_self
        return bool(override)

    def policy_names(self, af, direction):
        """Return the policy object names configured for one direction.

        :param af: an ``(afi, safi)`` pair.
        :param direction: ``'in'`` or ``'out'``.
        :return: a dict of names, empty when nothing is configured.
        """
        return (self.policy.get(af) or {}).get(direction) or {}

    @property
    def is_ebgp(self):
        """Whether this is an external session."""
        return self.remote_as != self.local_as

    def fsm_config(self):
        """Build the :class:`fsm.FsmConfig` this neighbour implies."""
        return fsm_mod.FsmConfig(
            hold_time=self.hold_time, keepalive=self.keepalive,
            connect_retry=self.connect_retry, delay_open=self.delay_open,
            passive=self.passive,
            allow_automatic_start=not self.shutdown)

    def local_capabilities(self):
        """Build the capability set to advertise.

        ADD-PATH is advertised as receive-only. This version can accept
        several paths for a prefix but never sends more than one, and
        advertising send would promise something the encoder does not do.

        Enhanced Route Refresh (RFC 7313) is not advertised, for the same
        reason (S6-e): it obliges a speaker to bracket a refresh with BoRR
        and EoRR and to purge, at EoRR, whatever the peer did not refresh,
        and this version does neither. Advertising it made a peer's markers
        arrive and be taken as requests. Plain route refresh (RFC 2918) is
        offered as before.
        """
        add_path = {}
        if self.add_path_receive:
            for af in self.afi_safi:
                add_path[af] = capabilities.ADD_PATH_RECEIVE
        return capabilities.Capabilities(
            asn=self.local_as, afi_safi=set(self.afi_safi), as4=True,
            route_refresh=self.route_refresh,
            enhanced_route_refresh=False,
            extended_message=self.extended_message,
            add_path=add_path, graceful_restart=self.graceful_restart)

    def __repr__(self):
        return '<PeerConfig %s as=%d%s>' % (
            self.address, self.remote_as,
            ' shutdown' if self.shutdown else '')


class Peer(object):
    """A single BGP session and everything it owns.

    :param config: a :class:`PeerConfig`.
    :param loop: the engine's asyncio loop.
    :param locribs: a mapping of ``(afi, safi)`` to the Loc-RIB that
        family's routes belong in. Families absent from the mapping are
        negotiated but their routes are counted and dropped, which is
        better than refusing the session over a family we agreed to.
    :param attr_table: the shared :class:`attrs.AttrTable`.
    :param clock: monotonic clock, injected for tests.
    :param events: the engine :class:`events.EventBus`, or None.
    :param on_established: optional callback taking this peer, invoked
        when the session comes up, used by the plugin to seed the initial
        advertisement.
    :param on_session_down: optional callback taking this peer, invoked
        when the session's routes are released. The plugin uses it to take
        the peer out of its update groups, which is work the session
        cannot do itself: since Stage 4 the outbound table belongs to a
        group of peers rather than to this one, and this peer leaving must
        not disturb what the others were told.
    :param on_route_refresh: optional callback taking ``(peer, af)``,
        invoked when the peer asks for a route refresh. For the same
        reason: honouring the request means replaying one member's share
        of a shared record, and only the plugin knows the group.
    :param in_policy: a mapping of ``(afi, safi)`` to the inbound
        :class:`policy.PolicyChain`, or None for no policy. Consulted
        between the raw Adj-RIB-In and the Loc-RIB; see
        :meth:`_announce_many`.
    :param nexthop_check: optional callable ``(afi, nexthop) ->
        (resolved, igp_metric)`` used to validate a path's next hop as it
        arrives. None means every next hop is assumed reachable, which is
        the right default for a control-plane speaker with no forwarding
        plane to check against.
    """

    def __init__(self, config, loop=None, locribs=None, attr_table=None,
                 clock=None, events=None, on_established=None,
                 on_session_down=None, on_route_refresh=None,
                 in_policy=None, nexthop_check=None):
        self.config = config
        self.loop = loop
        self.locribs = locribs if locribs is not None else {}
        self.attr_table = attr_table
        self.clock = clock if clock is not None else time.monotonic
        self.events = events
        self.on_established = on_established
        self.on_session_down = on_session_down
        self.on_route_refresh = on_route_refresh
        self.in_policy = in_policy if in_policy is not None else {}
        self.nexthop_check = nexthop_check

        self.fsm = fsm_mod.Fsm(config.fsm_config(), self.clock,
                               name=config.address,
                               on_state=self._on_state_change)
        self.conn = None
        self.framer = wire.Framer()
        self.ctx = wire.DecodeCtx(as4=True, is_ebgp=config.is_ebgp,
                                  local_as=config.local_as,
                                  peer_as=config.remote_as)
        self.local_caps = config.local_capabilities()
        self.negotiated = None
        self.peer_ref = None
        # (afi, safi) -> the Adj-RIB-Out this session sends from. Since
        # Stage 4 the table belongs to an update group and is shared with
        # every other member; the manager puts it here when the peer joins
        # and takes it away when it leaves, so everything that reads
        # `session.adjout[af]` sees the group's record.
        self.adjout = {}

        # Adj-RIB-In, per family: {(afi, safi): {(prefix, path_id): attrs}}.
        # The attributes stored are the ones that came off the wire,
        # *before* inbound policy: this is the unadulterated record RFC
        # 4271 calls the Adj-RIB-In, it is what `show ip bgp neighbors X
        # received-routes` must show, and it is what a soft reset replays
        # through a changed policy. Storing the post-policy set here would
        # make a soft reset apply the new policy to the output of the old
        # one, which is not a refresh of anything.
        self.adj_in = {}
        for af in config.afi_safi:
            self.adj_in[af] = {}

        self.counters = errors.PeerErrorCounters()
        self.stats_counters = {
            'messages-in': 0, 'messages-out': 0, 'updates-in': 0,
            'updates-out': 0, 'prefixes-in': 0, 'withdraws-in': 0,
            'notifications-in': 0, 'notifications-out': 0,
            'keepalives-in': 0, 'keepalives-out': 0,
            'refresh-in': 0, 'refresh-out': 0, 'refresh-markers-in': 0,
            'bytes-in': 0,
            'bytes-out': 0,
            # Denied by inbound policy, and accepted into the Loc-RIB.
            # Both are counted because their *difference* is the answer to
            # "the session is up and the prefix is not in my table", and
            # neither number alone says anything.
            'prefixes-filtered': 0, 'prefixes-accepted': 0,
            # Paths whose next hop did not resolve when they arrived.
            'nexthop-unresolved': 0, 'soft-resets-in': 0,
            # NLRI entries with bits set past their prefix length (W-8).
            # Masked and accepted, but worth seeing: a peer sending them
            # rarely announces what its operator thinks it announces.
            'nlri-host-bits': 0,
            # Announcements treated as withdrawn for an AS_PATH longer
            # than maxas-limit (P-2).
            'maxas-limit-dropped': 0,
        }
        # Set once the first over-long path has been logged this session.
        self._maxas_warned = False
        self.auth_mode = auth_mod.AUTH_NONE
        self.auth_reason = None
        self._auth_key = None
        self.last_error = None
        self.peer_router_id = 0
        self.peer_hold_time = 0
        self.eor_sent = set()
        self.eor_received = set()
        # Families whose unnegotiated MP attributes have been logged this
        # session; see _judge. Counted every time, logged once.
        self._unnegotiated_logged = set()
        # (afi, safi) -> {'address': text, 'source': why}: the next hop
        # this session advertises when it sets the next hop itself, and
        # where it came from. Filled in by the plugin when the session
        # joins its update groups; shown so an IPv4-mapped IPv6 next hop
        # is visible rather than discovered at the far end (L-4).
        self.next_hops = {}

        self._task = None
        self._reader = None
        self._running = False
        self._connecting = False
        self._we_initiated = False
        self._peer_as = config.remote_as
        # The outbound connect in flight, kept so it can be cancelled when
        # the session moves on (S-2), and the generation it belongs to: a
        # connect that completes after a close or a stop sees a newer
        # generation and closes what it got instead of adopting it.
        self._connect_task = None
        self._gen = 0
        # A second connection held until the peer's BGP identifier is
        # known, so a collision is settled by RFC 4271 s6.8 rather than by
        # whichever SYN arrived first (S-1): ``(conn, initiated)``.
        self._pending = None
        # The single writer (S-3). Two lanes: control messages (OPEN,
        # KEEPALIVE, ROUTE-REFRESH) always go before bulk ones (UPDATE,
        # End-of-RIB), and only one write is ever in flight.
        self._ctl = []
        self._bulk = collections.deque()
        self._bulk_bytes = 0
        self._writer = None
        self._writing_conn = None
        self._wake = None
        self._writable_waiters = []
        self._idle_waiters = []
        # The NOTIFICATION the FSM asked for, held until the drop that
        # always follows it so the two are performed as one operation.
        self._notify = None
        # Set while attaching a held connection, whose OPEN already went
        # out: the FSM's next ACT_SEND_OPEN is then already done.
        self._skip_open = False
        # Closes still finishing (NOTIFICATION, half-close, drain), which
        # the engine waits on at shutdown; and every task this session
        # started, kept so none is collected mid-run or dies unreported.
        self._lingering = set()
        self._tasks = set()
        self._resolve_auth()

    # --- configuration -----------------------------------------------------

    def _resolve_auth(self):
        """Decide the authentication mode, fail-closed.

        A neighbour configured for TCP-AO on a kernel without it stays
        down with a reason an operator can read, rather than quietly
        peering unauthenticated. That is the whole point of doing this at
        configuration time instead of discovering it at connect time.
        """
        neighbor = {}
        if self.config.password:
            neighbor['password'] = self.config.password
        if self.config.ao:
            neighbor['ao'] = self.config.ao
        mode, key, reason = auth_mod.resolve_auth(neighbor)
        self.auth_mode = mode
        self._auth_key = key
        self.auth_reason = reason
        if mode is None:
            LOG.error('bgp %s: %s; the session will stay Idle',
                      self.config.address, reason)

    @property
    def auth_blocked(self):
        """Whether authentication cannot be satisfied on this platform."""
        return self.auth_mode is None

    @property
    def established(self):
        """Whether the session is up."""
        return self.fsm.established

    @property
    def state(self):
        """The FSM state name."""
        return self.fsm.state

    @property
    def running(self):
        """Whether the peer is meant to be up: started and not stopped.

        False from the first line of :meth:`stop`, so a session that goes
        down while this is still True went down by itself -- a flap -- and
        one that goes down after it was asked to.
        """
        return self._running

    # --- lifecycle ---------------------------------------------------------

    def start(self, loop=None):
        """Bring the peer up, unless configuration forbids it.

        :param loop: the engine loop, when it was not available at
            construction. A neighbour configured before the engine starts
            is built with no loop -- there is not one yet -- and would
            otherwise sit in Connect for ever, never dialling and never
            arming a timer, because both need a loop to schedule on.
            Loading a configuration from a file and then starting is the
            ordinary boot order, so this is the common case rather than
            an edge one.
        :return: True if the FSM was started.
        """
        if loop is not None:
            self.loop = loop
        if self.config.shutdown:
            LOG.info('bgp %s: configured shutdown, staying Idle',
                     self.config.address)
            return False
        if self.auth_blocked:
            # Fail closed. Not starting is the point: an operator who asked
            # for authentication must never get an unauthenticated session
            # because the platform could not provide it.
            return False
        self._running = True
        self.fsm.event(fsm_mod.EV_MANUAL_START)
        self._drain_actions()
        if self.loop is not None and self._task is None:
            self._task = self._spawn(self._timer_loop())
        return True

    def stop(self, reason='administratively shut down', subcode=None):
        """Take the peer down and stop its tasks.

        Synchronous, like every caller of it, which is why the
        NOTIFICATION it causes is written before this returns whenever
        the socket can take it (see :meth:`_finish_connection`).

        :param reason: recorded and logged.
        :param subcode: the Cease subcode to send (RFC 4486); None for
            Administrative Shutdown. The plugin passes Peer De-configured
            for a deleted neighbour and Administrative Reset for a hard
            clear, so the far end can tell the three apart.
        :return: None.
        """
        self._running = False
        if self._pending is not None:
            # First, so it hears the same Cease as the session does.
            self._drop_held(self._pending,
                            subcode if subcode is not None
                            else errors.CEASE_ADMIN_SHUTDOWN, reason)
        kw = {'reason': reason}
        if subcode is not None:
            kw['subcode'] = subcode
        self.fsm.event(fsm_mod.EV_MANUAL_STOP, **kw)
        self._drain_actions()
        self._gen += 1
        for task in (self._task, self._reader, self._connect_task):
            _cancel(task)
        self._task = None
        self._reader = None
        self._connect_task = None
        self._connecting = False
        self.last_error = reason

    def lingering(self):
        """Return the closes still finishing, for the engine to wait on.

        :return: a list of tasks; empty when every connection is gone.
        """
        return [t for t in self._lingering if not t.done()]

    def _spawn(self, coro):
        """Start a task on the session's loop and keep hold of it (S-10).

        A task nobody references can be collected while it runs, and one
        that fails with nobody awaiting it is reported only at collection
        time, as "Task exception was never retrieved" -- long after the
        session it broke. Every task this module starts goes through here.
        """
        task = self.loop.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task):
        self._tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None and not isinstance(exc, CANCELLED):
            LOG.error('bgp %s: a session task failed: %r',
                      self.config.address, exc)

    async def _timer_loop(self):
        """Wake at the FSM's next deadline and tick it.

        One task per peer holding one sleep, rather than five asyncio
        timer handles rearmed on every keepalive. At a thousand peers the
        difference is thousands of scheduler operations a second.
        """
        failures = 0
        while self._running:
            deadline = self.fsm.next_deadline()
            if deadline is None:
                delay = IDLE_READ_TIMEOUT
            else:
                delay = max(0.0, deadline - self.clock())
            try:
                await _sleep(self.loop, min(delay, IDLE_READ_TIMEOUT))
            except CANCELLED:
                return
            except Exception:
                # S-4: this used to return, silently ending keepalives and
                # hold-timer checks for the rest of the session -- which
                # then looked healthy until the peer's hold timer killed
                # it. Log, and keep going. Only a closed loop, or a sleep
                # that keeps failing (it cannot be backed off, it *is* the
                # back-off), ends the loop, and then loudly.
                failures += 1
                LOG.exception('bgp %s: timer loop sleep failed',
                              self.config.address)
                if self.loop.is_closed() or failures >= TIMER_FAILURE_LIMIT:
                    LOG.error('bgp %s: timer loop giving up after %d '
                              'failures; the session has no timers',
                              self.config.address, failures)
                    return
                continue
            failures = 0
            if not self._running:
                return
            try:
                self.fsm.tick()
                self._drain_actions()
            except CANCELLED:
                return
            except Exception:
                LOG.exception('bgp %s: timer tick failed',
                              self.config.address)

    # --- FSM actions -------------------------------------------------------

    def _drain_actions(self):
        """Perform whatever the FSM asked for, in order."""
        for action, payload in self.fsm.take_actions():
            try:
                self._perform(action, payload)
            except Exception:
                LOG.exception('bgp %s: action %s failed',
                              self.config.address, action)
        if self._notify is not None:
            # A NOTIFICATION the FSM did not follow with a drop. It never
            # does today; if it ever does, send it rather than lose it.
            notify, self._notify = self._notify, None
            self._send(notify)
        if self._pending is not None:
            self._settle_pending()

    def _perform(self, action, payload):
        if action == fsm_mod.ACT_CONNECT:
            self._begin_connect()
        elif action == fsm_mod.ACT_SEND_OPEN:
            if self._skip_open:
                self._skip_open = False
                return
            self._send(self._build_open())
        elif action == fsm_mod.ACT_SEND_KEEPALIVE:
            self._send(wire.encode_keepalive())
            self.stats_counters['keepalives-out'] += 1
        elif action == fsm_mod.ACT_SEND_NOTIFY:
            # L-1: held, not queued. The FSM always follows a NOTIFICATION
            # with a drop, and the drop used to close the socket and clear
            # the queue before the write that was supposed to carry it had
            # run -- so no NOTIFICATION ever reached a peer. _close() now
            # writes it itself, first.
            code, subcode, data = payload
            self._notify = wire.encode_notification(code, subcode, data)
            self.stats_counters['notifications-out'] += 1
            self.counters.record_notification_sent(code, subcode)
            self.last_error = 'sent %s' % errors.notify_name(code, subcode)
        elif action == fsm_mod.ACT_DROP:
            self._close(payload)
        elif action == fsm_mod.ACT_REFUSE:
            # The newcomer was refused where it arrived (adopt); the
            # session's own connection is deliberately left alone.
            LOG.debug('bgp %s: %s', self.config.address, payload)
        elif action == fsm_mod.ACT_RELEASE:
            self._release_routes()
        elif action == fsm_mod.ACT_ESTABLISHED:
            self._on_established()
        elif action == fsm_mod.ACT_LISTEN_ONLY:
            self._connecting = False

    def _begin_connect(self):
        if self.loop is None or self._connecting:
            return
        self._connecting = True
        self._connect_task = self._spawn(self._connect(self._gen))

    async def _connect(self, gen):
        """Open the TCP connection and hand it to the FSM.

        :param gen: the connection generation this attempt belongs to.
            ``_close`` and ``stop`` advance it; an attempt that completes
            after either is stale (S-2) and must not be adopted -- it
            would arrive in whatever state the session has moved on to,
            and before this check it did, as a second ``adopt``.
        """
        try:
            conn = await tcp_mod.connect(
                self.loop, self.config.address, port=self.config.port,
                local_addr=self.config.update_source,
                auth_mode=self.auth_mode, auth_key=self._auth_key,
                ttl=self.config.ebgp_multihop,
                gtsm_hops=self.config.ttl_security,
                timeout=self.config.connect_retry)
        except CANCELLED:
            # Cancelled by _close or stop, which already moved the
            # session on; the transport closed the half-open socket.
            return
        except Exception as exc:
            if gen != self._gen:
                return
            self._connect_task = None
            self._connecting = False
            LOG.info('bgp %s: connect failed: %s', self.config.address, exc)
            if self.conn is None:
                # Only a failure of *the* connection is the FSM's
                # business. With an inbound connection already in play,
                # our own outbound attempt failing says nothing about it,
                # and reporting it used to drop the working one.
                self.fsm.event(fsm_mod.EV_TCP_FAILS)
                self._drain_actions()
            return
        if gen != self._gen or not self._running:
            LOG.debug('bgp %s: discarding a connection that completed '
                      'after the session moved on', self.config.address)
            conn.close()
            return
        self._connect_task = None
        self._connecting = False
        self.adopt(conn, initiated=True)

    def adopt(self, conn, initiated=False):
        """Take ownership of an established TCP connection.

        Called both by our own connect and by the listener when the peer
        connected to us. The FSM decides what to do with it -- including
        refusing it outright when the session is Idle, which is how an
        administrative shutdown survives a peer that keeps dialling.

        :param conn: a :class:`transport.tcp.Connection`.
        :param initiated: whether we opened it, for collision resolution.
        """
        if self.conn is not None and self.conn.is_open():
            self._second_connection(conn, initiated)
            return
        self._attach(conn, initiated)

    def _attach(self, conn, initiated, held=None):
        """Make ``conn`` the session's connection and tell the FSM.

        :param held: the :class:`_Held` record when ``conn`` was held for
            collision resolution. Our OPEN already went out on it, so the
            FSM's is skipped; what its reader collected is replayed; and
            that reader carries on as the session's.
        """
        old = self.conn
        if old is not None:
            # A connection that died without telling us. S-6: its reader
            # and writer used to be left running against a closed socket.
            self.conn = None
            for task in (self._reader, self._writer):
                _cancel(task)
            self._reader = None
            self._writer = None
            self._reset_lanes()
            old.close()
        self.conn = conn
        self._we_initiated = initiated
        self.framer.reset()
        self._skip_open = held is not None
        self.fsm.event(fsm_mod.EV_TCP_CR_ACKED if initiated
                       else fsm_mod.EV_TCP_CONNECTION_VALID)
        self._drain_actions()
        if self.conn is not conn or self.loop is None:
            return
        if held is not None and held.reader is not None and \
                not held.reader.done():
            self._reader = held.reader
        else:
            self._reader = self._spawn(self._read_loop(conn))
        if held is not None and held.raw:
            raw, held.raw = bytes(held.raw), bytearray()
            self.stats_counters['bytes-in'] += len(raw)
            self.framer.feed(raw)
            self.loop.call_soon(self._dispatch_framed)

    # --- connection collisions (RFC 4271 s6.8) -----------------------------

    def _second_connection(self, conn, initiated):
        """A connection arrived while another is already in play (S-1).

        Which one survives depends on the BGP identifiers, so it cannot be
        decided by arrival order -- which is what refusing the newcomer
        outright did, and both ends then disagreed about which connection
        was the session.

        * Established: the working session always wins; the newcomer is
          told Cease/Connection Collision Resolution and closed.
        * OpenConfirm: the peer's identifier is known, decide now.
        * Earlier: hold the newcomer (see :meth:`_hold`) until either
          connection's OPEN tells us the identifier.
        """
        state = self.fsm.state
        if state == fsm_mod.ESTABLISHED:
            self._refuse(conn, errors.CEASE_COLLISION_RESOLUTION,
                         'second connection to an established session')
            return
        if state == fsm_mod.OPEN_CONFIRM:
            if self._keep_new(self.peer_router_id, initiated):
                self._switch_to(conn, initiated, None)
            else:
                self._refuse(conn, errors.CEASE_COLLISION_RESOLUTION,
                             'lost connection collision resolution')
            return
        if self._pending is not None:
            self._drop_held(self._pending, errors.CEASE_COLLISION_RESOLUTION,
                            'superseded by a newer connection')
        self._hold(conn, initiated)

    def _hold(self, conn, initiated):
        """Run the second connection's half of the handshake, on the side.

        RFC 4271 has one FSM per connection, and both connections of a
        collision exchange OPENs; the OPEN is how each end learns the
        other's identifier. A held connection that stayed silent deadlocks
        two speakers that dial each other at once: each holds the
        connection the other is using as its own, and both wait in
        OpenSent for an OPEN that never comes. So ours goes out on it now,
        and a reader collects the peer's (:meth:`_held_read`), which
        settles the collision as soon as either connection produces one.
        """
        held = _Held(conn, initiated)
        open_msg = self._build_open()
        try:
            sent = conn.send_nowait(open_msg)
        except OSError:
            sent = -1
        if sent != len(open_msg):
            # An idle socket takes an OPEN whole; one that does not is not
            # a connection worth colliding over.
            conn.close()
            return
        self.stats_counters['messages-out'] += 1
        self.stats_counters['bytes-out'] += sent
        LOG.info('bgp %s: holding a second (%s) connection until the '
                 'peer\'s identifier is known', self.config.address,
                 'outbound' if initiated else 'inbound')
        self._pending = held
        if self.loop is not None:
            held.reader = self._spawn(self._held_read(held))

    async def _held_read(self, held):
        """Read a held connection until its OPEN; then decide, or carry on.

        If the held connection wins it is attached *with this task as its
        reader*: every byte already read was kept and is replayed into the
        session's framer, and every byte after that is read here. Starting
        a fresh reader instead would mean cancelling this one, and a task
        cancelled just after its read completed loses what it read --
        possibly half a message, which no framer recovers from.
        """
        conn = held.conn
        framer = wire.Framer()
        try:
            while True:
                if self.conn is conn:
                    await self._read_loop(conn)
                    return
                if self._pending is not held or not conn.is_open():
                    return
                try:
                    data = await _recv(self.loop, conn, 65536)
                except CANCELLED:
                    raise
                except Exception:
                    data = b''
                if self.conn is conn:
                    # Attached while we were reading: these bytes are the
                    # session's now.
                    if not data:
                        self.fsm.event(fsm_mod.EV_TCP_FAILS)
                        self._drain_actions()
                        return
                    self.stats_counters['bytes-in'] += len(data)
                    self.framer.feed(data)
                    self._dispatch_framed()
                    continue
                if self._pending is not held:
                    return
                if not data:
                    self._pending = None
                    conn.close()
                    return
                held.raw += data
                framer.feed(data)
                item = framer.next_message()
                if framer.failed:
                    self._drop_held(held, errors.CEASE_CONNECTION_REJECTED,
                                    'malformed message on a held connection')
                    return
                if item is None:
                    continue
                mtype, body = item
                if mtype != wire.OPEN:
                    # The peer settled the collision first and closed this
                    # one with a NOTIFICATION, or spoke out of turn.
                    LOG.info('bgp %s: the held connection ended with %s',
                             self.config.address,
                             wire.MSG_NAMES.get(mtype, mtype))
                    self._pending = None
                    conn.close()
                    return
                msg = wire.decode_open(body)
                if msg.errors or not msg.bgp_id:
                    self._drop_held(held, errors.CEASE_CONNECTION_REJECTED,
                                    'unusable OPEN on a held connection')
                    return
                if self._keep_new(msg.bgp_id, held.initiated):
                    self._switch_to(conn, held.initiated, held)
                else:
                    self._drop_held(held, errors.CEASE_COLLISION_RESOLUTION,
                                    'lost connection collision resolution')
        except CANCELLED:
            return

    def _settle_pending(self):
        """Decide a held connection's fate once the session can."""
        held = self._pending
        if not held.conn.is_open():
            self._pending = None
            return
        state = self.fsm.state
        if self.conn is not None and self.conn.is_open():
            if state == fsm_mod.OPEN_CONFIRM:
                if self._keep_new(self.peer_router_id, held.initiated):
                    self._switch_to(held.conn, held.initiated, held)
                else:
                    self._drop_held(held, errors.CEASE_COLLISION_RESOLUTION,
                                    'lost connection collision resolution')
            elif state == fsm_mod.ESTABLISHED:
                self._drop_held(held, errors.CEASE_COLLISION_RESOLUTION,
                                'second connection to an established session')
            return
        # The connection in play went away first; the held one is next.
        self._pending = None
        if self._running and state in (fsm_mod.CONNECT, fsm_mod.ACTIVE):
            self._attach(held.conn, held.initiated, held)
        else:
            self._drop_held(held, errors.CEASE_CONNECTION_REJECTED,
                            'the session is %s' % state)

    def _keep_new(self, peer_router_id, initiated):
        """RFC 4271 s6.8: should the connection in direction ``initiated``
        replace the session's current one?

        The speaker with the higher BGP identifier keeps the connection it
        initiated; both ends compute the same answer from the same two
        identifiers, so exactly one connection survives. Two connections
        in the same direction are not a collision but a duplicate, and the
        one already in play is kept.
        """
        if initiated == self._we_initiated:
            return False
        args = (_router_id_int(self.config.router_id), peer_router_id,
                self.config.local_as, self._peer_as)
        keep_old = fsm_mod.resolve_collision(*(args + (self._we_initiated,)))
        keep_new = fsm_mod.resolve_collision(*(args + (initiated,)))
        return keep_new and not keep_old

    def _switch_to(self, conn, initiated, held, notify=True):
        """Move the session onto ``conn``; the current connection lost.

        :param held: the :class:`_Held` record when ``conn`` was held (our
            OPEN already went out on it), None for a fresh connection.
        :param notify: send Cease/Connection Collision Resolution on the
            losing connection. False when the peer already sent it to us.
        """
        LOG.info('bgp %s: connection collision: continuing on the %s '
                 'connection', self.config.address,
                 'outbound' if initiated else 'inbound')
        if self._pending is held:
            self._pending = None
        if notify:
            self._notify = wire.encode_notification(
                errors.NOTIFY_CEASE, errors.CEASE_COLLISION_RESOLUTION, b'')
            self.stats_counters['notifications-out'] += 1
            self.counters.record_notification_sent(
                errors.NOTIFY_CEASE, errors.CEASE_COLLISION_RESOLUTION)
        self._close('lost connection collision resolution')
        self.fsm.abandon_connection('connection collision: continuing on '
                                    'the %s connection'
                                    % ('outbound' if initiated
                                       else 'inbound'))
        self._attach(conn, initiated, held)

    def _drop_held(self, held, subcode, reason):
        """Close a held connection with a Cease."""
        if self._pending is held:
            self._pending = None
        _cancel(held.reader)
        held.reader = None
        self._refuse(held.conn, subcode, reason)

    def _refuse(self, conn, subcode, reason):
        """Close a connection that is not the session's, with a Cease."""
        LOG.info('bgp %s: closing a second connection: %s',
                 self.config.address, reason)
        self.stats_counters['notifications-out'] += 1
        self.counters.record_notification_sent(errors.NOTIFY_CEASE, subcode)
        self._finish_connection(
            conn, wire.encode_notification(errors.NOTIFY_CEASE, subcode, b''),
            None)

    # --- closing -----------------------------------------------------------

    def _close(self, reason):
        """Drop the transport, keeping the FSM's view and ours in step.

        L-1: the NOTIFICATION the FSM asked for goes out first, then a
        half-close, then the socket is drained and only then closed (see
        :meth:`_finish_connection`). Everything owned by the connection --
        the reader, the writer, an outbound connect still in flight (S-2),
        both send lanes -- is let go here, in one place.
        """
        conn = self.conn
        notify, self._notify = self._notify, None
        self.conn = None
        self._gen += 1
        connect, self._connect_task = self._connect_task, None
        _cancel(connect)
        reader, self._reader = self._reader, None
        _cancel(reader)
        writer, self._writer = self._writer, None
        busy = (writer is not None and conn is not None and
                self._writing_conn is conn)
        self._reset_lanes()
        self.framer.reset()
        self.negotiated = None
        self._connecting = False
        self._skip_open = False
        if conn is not None:
            LOG.info('bgp %s: closing connection: %s',
                     self.config.address, reason)
            self._finish_connection(conn, notify, writer if busy else None)
        if writer is not None and not busy:
            _cancel(writer)

    def _finish_connection(self, conn, notify, busy_writer):
        """Send a NOTIFICATION, half-close, drain, close -- in that order.

        Synchronous where it can be, because every caller is: ``stop()``
        and the engine's shutdown cannot wait for a task, so a NOTIFICATION
        that only a task would write may never be written. With no write
        in flight the NOTIFICATION and the FIN are handed to the kernel
        before this returns. With a write in flight, interrupting it would
        put the NOTIFICATION in the middle of a half-sent UPDATE, so a
        bounded linger task waits for that write and then sends it.

        Either way the close itself is left to the linger task, after a
        drain: closing with unread data in the receive queue turns the FIN
        into a reset, and a reset can take the NOTIFICATION with it.

        :param conn: the connection to finish.
        :param notify: an encoded NOTIFICATION, or None to just close.
        :param busy_writer: the writer task with a write in flight on
            ``conn``, or None when it is idle.
        """
        if notify is None or not conn.is_open():
            conn.close()
            return
        rest = notify
        if busy_writer is None:
            try:
                rest = notify[conn.send_nowait(notify):]
            except OSError as exc:
                LOG.info('bgp %s: could not send the NOTIFICATION: %s',
                         self.config.address, exc)
                conn.close()
                return
            if not rest:
                conn.shutdown_write()
        if self.loop is None or self.loop.is_closed():
            conn.close()
            return
        task = self._spawn(self._linger_close(conn, rest, busy_writer))
        self._lingering.add(task)
        task.add_done_callback(self._lingering.discard)

    async def _linger_close(self, conn, rest, writer):
        """Finish what :meth:`_finish_connection` started, within a bound."""
        loop = self.loop
        deadline = loop.time() + NOTIFY_LINGER
        try:
            if writer is not None and not writer.done():
                # The writer stops after this write: the connection is no
                # longer the session's, which is what its loop checks.
                await _wait_done(loop, writer, NOTIFY_LINGER)
                if not writer.done():
                    return
            if rest:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return
                await tcp_mod._wait_for(conn.send(rest), remaining, loop)
                conn.shutdown_write()
            remaining = deadline - loop.time()
            if remaining > 0:
                await conn.drain(remaining)
        except CANCELLED:
            pass
        except (OSError, asyncio.TimeoutError) as exc:
            LOG.debug('bgp %s: closing after the NOTIFICATION: %s',
                      self.config.address, exc)
        finally:
            conn.close()
            if writer is not None:
                _cancel(writer)

    # --- transmit ----------------------------------------------------------

    def _send(self, data, bulk=False):
        """Queue bytes for the peer, on the control or the bulk lane.

        Queued rather than written inline because an FSM action may be
        performed from inside a timer tick, and a synchronous write there
        would put socket I/O on the timer path. The queue belongs to one
        writer task per connection (:meth:`_write_loop`) -- S-3: it used
        to be one flush task *per message*, racing each other over the
        queue and, through ``sock_sendall``, over the socket, which can
        interleave two PDUs on one stream.

        :param data: one or more encoded messages.
        :param bulk: True for UPDATEs and End-of-RIB, which keep their
            order among themselves but wait behind control messages; a
            KEEPALIVE must never queue behind a full table (S-8).
        """
        if not data or self.conn is None:
            return
        if bulk:
            self._bulk.append(data)
            self._bulk_bytes += len(data)
        else:
            self._ctl.append(data)
        self._kick()

    def _kick(self):
        """Make sure the writer is running and awake."""
        if self.loop is None or self.conn is None:
            return
        writer = self._writer
        if writer is None or writer.done():
            self._writer = self._spawn(self._write_loop(self.conn))
            return
        wake = self._wake
        if wake is not None and not wake.done():
            wake.set_result(None)

    async def _write_loop(self, conn):
        """The session's only writer: control lane first, one write at a time.

        Exits when ``conn`` stops being the session's connection, which is
        how :meth:`_close` stops it without interrupting a write: a
        NOTIFICATION is only ever sent between two whole PDUs.
        """
        try:
            while conn is self.conn and conn.is_open():
                if self._ctl:
                    batch, self._ctl = self._ctl, []
                elif self._bulk:
                    batch = []
                    size = 0
                    bulk = self._bulk
                    while bulk and size < WRITE_CHUNK:
                        item = bulk.popleft()
                        batch.append(item)
                        size += len(item)
                    self._bulk_bytes -= size
                    if self._bulk_bytes <= BULK_LOW_WATER:
                        _release(self._writable_waiters)
                else:
                    _release(self._idle_waiters)
                    self._wake = self.loop.create_future()
                    await self._wake
                    self._wake = None
                    continue
                chunk = batch[0] if len(batch) == 1 else b''.join(batch)
                self._writing_conn = conn
                try:
                    await conn.send(chunk)
                finally:
                    if self._writing_conn is conn:
                        self._writing_conn = None
                # Counted when written, not when queued (S-10): `show`
                # used to report messages the peer never received.
                self.stats_counters['messages-out'] += len(batch)
                self.stats_counters['bytes-out'] += len(chunk)
        except CANCELLED:
            return
        except Exception as exc:
            if conn is self.conn:
                LOG.info('bgp %s: send failed: %s', self.config.address, exc)
                self.fsm.event(fsm_mod.EV_TCP_FAILS)
                self._drain_actions()
        finally:
            _release(self._idle_waiters)

    def _reset_lanes(self):
        """Forget everything queued; release anyone waiting on the writer."""
        self._ctl = []
        self._bulk.clear()
        self._bulk_bytes = 0
        wake, self._wake = self._wake, None
        if wake is not None and not wake.done():
            wake.set_result(None)
        _release(self._writable_waiters)
        _release(self._idle_waiters)

    @property
    def writable(self):
        """Whether the bulk lane is below its high-water mark.

        True with no connection as well: there is nothing to wait for, and
        an advertiser blocked on a session that is gone would never wake.
        """
        return self.conn is None or self._bulk_bytes < BULK_HIGH_WATER

    def wait_writable(self):
        """Return a future that resolves when more UPDATEs may be queued.

        The back-pressure half of S-3: an advertiser that awaits this
        before each batch is paced by the peer's TCP window instead of
        filling memory with a table the peer has not read yet.

        :return: a future, already done when the session is writable.
        """
        fut = self.loop.create_future()
        if self.writable:
            fut.set_result(None)
        else:
            self._writable_waiters.append(fut)
        return fut

    async def flush(self):
        """Wait until everything queued so far has been written.

        Returns early if the connection goes away; what was queued for it
        is then gone with it.
        """
        while self.conn is not None and (
                self._ctl or self._bulk or
                self._writing_conn is self.conn):
            self._kick()
            fut = self.loop.create_future()
            self._idle_waiters.append(fut)
            await fut

    def _build_open(self):
        """Encode our OPEN from the configured capabilities."""
        return wire.encode_open(self.config.local_as, self.config.hold_time,
                                self.config.router_id,
                                self.local_caps.as_tlvs())

    # --- receive -----------------------------------------------------------

    async def _read_loop(self, conn):
        """Read, frame and dispatch until the connection ends.

        The whole body is wrapped against cancellation, which is how this
        task is stopped on a session teardown or an engine shutdown. It is
        not a fault and must not be reported as one: an uncaught
        ``CancelledError`` leaves the task holding an exception nobody
        retrieves, and asyncio then prints a traceback for every peer
        every time the engine stops cleanly.

        :param conn: the connection this reader serves. Passed in rather
            than read from ``self.conn`` when the task first runs, which
            may be after the session has already moved to another one.
        """
        try:
            while self._running and conn is self.conn and conn.is_open():
                try:
                    data = await _recv(self.loop, conn, 65536)
                except CANCELLED:
                    raise
                except Exception as exc:
                    LOG.info('bgp %s: read failed: %s',
                             self.config.address, exc)
                    data = b''
                if conn is not self.conn:
                    # Replaced while we waited (a collision, or a close):
                    # these bytes belong to a connection that is gone.
                    return
                if not data:
                    self.fsm.event(fsm_mod.EV_TCP_FAILS)
                    self._drain_actions()
                    return
                self.stats_counters['bytes-in'] += len(data)
                self.framer.feed(data)
                self._dispatch_framed()
        except CANCELLED:
            LOG.debug('bgp %s: read loop cancelled', self.config.address)
            return

    def _dispatch_framed(self):
        """Drain whole messages from the framer, in bounded slices."""
        count = 0
        started = time.perf_counter()
        while True:
            item = self.framer.next_message()
            if item is None:
                break
            mtype, raw = item
            self.stats_counters['messages-in'] += 1
            try:
                self._on_message(mtype, raw)
            except Exception:
                LOG.exception('bgp %s: failed handling %s',
                              self.config.address,
                              wire.MSG_NAMES.get(mtype, mtype))
            count += 1
            if (count >= APPLY_SLICE or
                    time.perf_counter() - started >= APPLY_BUDGET):
                # Yield: the rest stays buffered and the next loop turn
                # picks it up. A full table must not monopolise the loop.
                if self.loop is not None:
                    self.loop.call_soon(self._dispatch_framed)
                break
        if self.framer.failed:
            # The data field carries the offending Length or Type (RFC 4271
            # s6.1, L-8), which is what lets the far end's operator find
            # the bug in their own encoder.
            self.fsm.event(fsm_mod.EV_HEADER_ERR,
                           subcode=self.framer.error_subcode,
                           reason=self.framer.error_detail,
                           data=self.framer.error_data or b'')
        self._drain_actions()

    def _on_message(self, mtype, raw):
        if mtype == wire.UPDATE:
            self._handle_update(raw)
        elif mtype == wire.KEEPALIVE:
            self.stats_counters['keepalives-in'] += 1
            self.fsm.event(fsm_mod.EV_KEEPALIVE_MSG)
        elif mtype == wire.OPEN:
            self._handle_open(raw)
        elif mtype == wire.NOTIFICATION:
            self._handle_notification(raw)
        elif mtype == wire.ROUTE_REFRESH:
            self._handle_route_refresh(raw)

    def _handle_notification(self, raw):
        msg = wire.decode_notification(raw)
        self.stats_counters['notifications-in'] += 1
        self.counters.record_notification_received(msg.code, msg.subcode)
        self.last_error = 'received %s' % errors.notify_name(msg.code,
                                                             msg.subcode)
        LOG.warning('bgp %s: %s', self.config.address, self.last_error)
        if (self._pending is not None and
                msg.code == errors.NOTIFY_CEASE and
                msg.subcode == errors.CEASE_COLLISION_RESOLUTION and
                self.fsm.state != fsm_mod.ESTABLISHED):
            # The peer resolved the collision before we did, and this
            # connection lost. RFC 4271 runs one FSM per connection, so
            # only this one's ends; the held connection carries on.
            self._switch_to(self._pending.conn, self._pending.initiated,
                            self._pending, notify=False)
            return
        if (msg.code == errors.NOTIFY_OPEN and
                msg.subcode == errors.OPEN_UNSUPPORTED_VERSION):
            self.fsm.event(fsm_mod.EV_NOTIFY_VERSION_ERR)
        else:
            self.fsm.event(fsm_mod.EV_NOTIFY_MSG, code=msg.code,
                           subcode=msg.subcode)

    def _handle_route_refresh(self, raw):
        msg = wire.decode_route_refresh(raw)
        if msg is None:
            return
        if msg.subtype != 0:
            # A BoRR (1) or EoRR (2) demarcation, or a reserved subtype --
            # never a request. Taking them as requests replayed the
            # Adj-RIB-Out twice per refresh (S6-e). They are not acted on
            # either: honouring EoRR's purge is RFC 7313, which this
            # version does not advertise and does not implement.
            self.stats_counters['refresh-markers-in'] += 1
            LOG.debug('bgp %s: ROUTE-REFRESH subtype %d for %d/%d ignored',
                      self.config.address, msg.subtype, msg.afi, msg.safi)
            return
        self.stats_counters['refresh-in'] += 1
        if self.negotiated is None or not self.negotiated.route_refresh:
            # We never advertised the capability, so we are not obliged to
            # honour it -- and a peer asking for something we did not offer
            # is worth noticing rather than silently obeying.
            LOG.info('bgp %s: ROUTE-REFRESH for %d/%d without the '
                     'capability negotiated', self.config.address,
                     msg.afi, msg.safi)
            return
        af = (msg.afi, msg.safi)
        if af not in self.adjout:
            return
        # Forgetting what the peer was told -- which is what this did
        # before Stage 4 -- is no longer available: the record belongs to
        # an update group and resetting it would re-advertise the table to
        # every other member of that group as well, turning one peer's
        # request into a router-wide event. The plugin replays this
        # member's share of the shared record instead.
        LOG.info('bgp %s: ROUTE-REFRESH for %s, replaying',
                 self.config.address,
                 capabilities.afi_safi_name(msg.afi, msg.safi))
        if self.on_route_refresh is not None:
            try:
                self.on_route_refresh(self, af)
            except Exception:
                LOG.exception('bgp %s: replaying for a route refresh '
                              'failed', self.config.address)

    # --- OPEN --------------------------------------------------------------

    def _handle_open(self, raw):
        """Validate the peer's OPEN and negotiate capabilities.

        Every check here ends the session rather than adapting to it. An
        OPEN that disagrees with our configuration means one of the two
        routers is wrong about the relationship, and guessing which is how
        a session comes up in a state neither operator intended.
        """
        msg = wire.decode_open(raw)
        if msg.errors:
            # W-5: Unspecific, not Unsupported Optional Parameter. An OPEN
            # that cannot be parsed has told us nothing about what it
            # supports, and the wrong subcode sends the far end's operator
            # looking for a capability mismatch that is not there.
            self.fsm.event(fsm_mod.EV_OPEN_MSG_ERR,
                           subcode=errors.OPEN_UNSPECIFIC,
                           reason='malformed OPEN: %s' % msg.errors[0][2])
            return
        if msg.version != wire.VERSION:
            # The data field must carry the version we do support, so the
            # peer can decide whether to retry (RFC 4271 s6.2).
            self.fsm.event(
                fsm_mod.EV_OPEN_MSG_ERR,
                subcode=errors.OPEN_UNSUPPORTED_VERSION,
                reason='peer offered BGP version %d' % msg.version,
                data=bytes(bytearray([0, wire.VERSION])))
            return
        if msg.unsupported_params:
            # W-5: an optional parameter other than Capabilities (RFC 4271
            # s6.2). The decoder kept them precisely so this could be said;
            # nothing used to look, and the session came up regardless.
            self.fsm.event(
                fsm_mod.EV_OPEN_MSG_ERR,
                subcode=errors.OPEN_UNSUPPORTED_OPT_PARAM,
                reason='unsupported optional parameter type %d'
                       % msg.unsupported_params[0][0])
            return

        remote_caps = capabilities.Capabilities.from_tlvs(msg.capabilities,
                                                          asn=msg.my_as)
        peer_as = remote_caps.asn if remote_caps.asn else msg.my_as
        if peer_as != self.config.remote_as:
            self.fsm.event(
                fsm_mod.EV_OPEN_MSG_ERR, subcode=errors.OPEN_BAD_PEER_AS,
                reason='peer claims AS %d, configured AS %d'
                       % (peer_as, self.config.remote_as))
            return
        if msg.bgp_id == 0 or msg.bgp_id == 0xffffffff:
            self.fsm.event(fsm_mod.EV_OPEN_MSG_ERR,
                           subcode=errors.OPEN_BAD_BGP_ID,
                           reason='peer sent BGP identifier 0x%08x'
                                  % msg.bgp_id)
            return
        if (not self.config.is_ebgp and
                msg.bgp_id == _router_id_int(self.config.router_id)):
            # W-5, RFC 6286 s2.2: identifiers are unique within an AS, so
            # an internal peer using ours is a misconfiguration -- and one
            # that breaks collision resolution, which compares them. An
            # external peer may legitimately share it.
            self.fsm.event(fsm_mod.EV_OPEN_MSG_ERR,
                           subcode=errors.OPEN_BAD_BGP_ID,
                           reason='internal peer uses our BGP identifier '
                                  '%s' % _ipv4_str(msg.bgp_id))
            return
        if msg.hold_time and msg.hold_time < fsm_mod.MIN_HOLD_TIME:
            self.fsm.event(fsm_mod.EV_OPEN_MSG_ERR,
                           subcode=errors.OPEN_UNACCEPTABLE_HOLD_TIME,
                           reason='peer proposed a hold time of %d'
                                  % msg.hold_time)
            return

        if self.fsm.state in (fsm_mod.OPEN_CONFIRM, fsm_mod.ESTABLISHED):
            # A second OPEN on the *same* connection. Collisions are
            # between connections and are settled where the second one
            # arrives (adopt / _collide); on one connection this is a
            # protocol error, and the FSM answers it -- Finite State
            # Machine Error when Established. It used to run collision
            # resolution against the connection's own direction here,
            # and renegotiate a live session's capabilities on the way.
            self.fsm.event(fsm_mod.EV_BGP_OPEN, hold_time=msg.hold_time,
                           router_id=msg.bgp_id, peer_as=peer_as)
            return

        negotiated = capabilities.negotiate(self.local_caps, remote_caps)
        missing = capabilities.missing_required(self.local_caps, negotiated)
        if not negotiated.afi_safi:
            self.fsm.event(
                fsm_mod.EV_OPEN_MSG_ERR,
                subcode=errors.OPEN_UNSUPPORTED_CAPABILITY,
                reason='no address family in common: %s'
                       % '; '.join(missing) if missing else 'none offered')
            return
        if missing:
            # A partial overlap is not fatal: the families both sides do
            # support still work, and tearing the session down would lose
            # those too. Log it so the asymmetry is visible.
            LOG.warning('bgp %s: %s', self.config.address,
                        '; '.join(missing))

        self.negotiated = negotiated
        self.peer_router_id = msg.bgp_id
        self.peer_hold_time = msg.hold_time
        self.ctx = wire.DecodeCtx(
            as4=negotiated.as4, is_ebgp=self.config.is_ebgp,
            local_as=self.config.local_as, peer_as=peer_as,
            add_path=negotiated.add_path_recv,
            max_msg=negotiated.max_message_size,
            families=negotiated.afi_safi)
        self._unnegotiated_logged = set()
        self._maxas_warned = False
        # The framer's ceiling only rises once both sides agreed to it.
        self.framer.set_max_msg(negotiated.max_message_size)
        self.peer_ref = bestpath.PeerRef(
            peer=self, peer_as=peer_as, local_as=self.config.local_as,
            router_id=msg.bgp_id, addr=_addr_bytes(self.config.address),
            is_ebgp=self.config.is_ebgp)
        # The Adj-RIB-Out tables were built when the neighbour was
        # configured, which is long before the peer's router id is known
        # -- it only arrives in this OPEN. They are linked here, at the
        # first moment the ref exists, because the outbound transform
        # reads the peer's address and AS on every path it considers and
        # would otherwise fail on the first advertisement of the session.
        for out in self.adjout.values():
            out.peer = self.peer_ref
        self._peer_as = peer_as
        self.fsm.event(fsm_mod.EV_BGP_OPEN, hold_time=msg.hold_time,
                       router_id=msg.bgp_id, peer_as=peer_as)
        if self._pending is not None:
            # The identifier a held connection was waiting for has just
            # arrived: settle the collision now, before a KEEPALIVE in the
            # same read can take the session to Established and make the
            # decision for us.
            self._drain_actions()

    def _on_established(self):
        LOG.info('bgp %s: session established, AS %d, router id %s, '
                 'families %s, auth %s', self.config.address,
                 self.config.remote_as, _ipv4_str(self.peer_router_id),
                 ','.join(sorted(capabilities.afi_safi_name(a, s)
                                 for a, s in self.negotiated.afi_safi)),
                 self.auth_mode)
        self.eor_sent = set()
        self.eor_received = set()
        if self.on_established is not None:
            try:
                self.on_established(self)
            except Exception:
                LOG.exception('bgp %s: on_established failed',
                              self.config.address)

    def _on_state_change(self, old, new, reason):
        if self.events is not None:
            try:
                from packets.routing.rtengine import events as ev_mod
                self.events.publish(ev_mod.PEER_STATE, {
                    'peer': self.config.address,
                    'peer-as': self.config.remote_as,
                    'old': old, 'new': new, 'reason': reason,
                })
            except Exception:
                LOG.exception('bgp %s: publishing peer state failed',
                              self.config.address)

    # --- UPDATE ------------------------------------------------------------

    def _handle_update(self, raw):
        """Decode and apply one UPDATE, atomically.

        The three phases are deliberately separate and in this order:
        decode the whole message; judge every fault the decoder recorded;
        apply, but only if the judgement allows it. Skipping straight from
        decode to apply is what makes a malformed UPDATE leave a partial
        one behind.
        """
        self.stats_counters['updates-in'] += 1
        msg = wire.decode_update(raw, self.ctx)
        if msg.host_bits:
            self.stats_counters['nlri-host-bits'] += msg.host_bits
        self.fsm.event(fsm_mod.EV_UPDATE_MSG)

        outcome = self._judge(msg)
        if outcome == errors.OUTCOME_RESET:
            self.fsm.event(fsm_mod.EV_UPDATE_MSG_ERR,
                           subcode=errors.UPD_MALFORMED_ATTR_LIST,
                           reason=self._first_detail(msg))
            return
        if msg.end_of_rib:
            self._note_eor(msg)
            return
        self._apply(msg, withdraw_only=(outcome == errors.OUTCOME_WITHDRAW))

    def _judge(self, msg):
        """Run the RFC 7606 matrix over everything the decoder recorded.

        :param msg: the decoded :class:`wire.UpdateMsg`.
        :return: the most severe outcome across all faults.
        """
        if not msg.errors:
            return errors.OUTCOME_OK
        verdicts = []
        for attr_type, reason, detail in msg.errors:
            outcome = errors.attribute_outcome(
                attr_type, reason, from_ebgp=self.config.is_ebgp)
            verdicts.append(outcome)
            self.counters.record(errors.UpdateError(attr_type, reason,
                                                    outcome, detail))
            if (reason == errors.REASON_UNNEGOTIATED and
                    detail not in self._unnegotiated_logged):
                # L-3: ignored, counted every time, said once per family
                # per session -- a peer that offers VPNv4 offers it in
                # every UPDATE, and a line per UPDATE buries everything.
                self._unnegotiated_logged.add(detail)
                LOG.info('bgp %s: ignoring %s (counted under errors)',
                         self.config.address, detail)
            LOG.debug('bgp %s: %s -> %s', self.config.address, detail,
                      outcome)
        return errors.worst_outcome(verdicts)

    def _first_detail(self, msg):
        if msg.errors:
            return msg.errors[0][2]
        return 'malformed UPDATE'

    def _note_eor(self, msg):
        """Record an End-of-RIB for a family."""
        if msg.mp_unreach is not None:
            af = (msg.mp_unreach[0], msg.mp_unreach[1])
        else:
            af = IPV4_UNICAST
        self.eor_received.add(af)
        LOG.info('bgp %s: End-of-RIB for %s', self.config.address,
                 capabilities.afi_safi_name(af[0], af[1]))

    def _apply(self, msg, withdraw_only=False):
        """Modify the Adj-RIB-In and the Loc-RIB from a judged UPDATE.

        :param msg: the decoded message.
        :param withdraw_only: RFC 7606 treat-as-withdraw -- the NLRI was
            extractable but its attributes were not usable, so the
            prefixes are withdrawn rather than installed. Note this
            withdraws the *announced* prefixes, which is the point: a
            peer that previously gave us a good path for them must not
            keep it on the strength of a broken update.
        """
        # Withdrawals first. An UPDATE may legitimately withdraw and
        # announce the same prefix, and the announcement is what stands.
        if msg.withdrawn:
            self._withdraw_many(IPV4_UNICAST, msg.withdrawn)
        if msg.mp_unreach is not None:
            af = (msg.mp_unreach[0], msg.mp_unreach[1])
            self._withdraw_many(af, msg.mp_unreach[2])

        if withdraw_only:
            if msg.nlri:
                self._withdraw_many(IPV4_UNICAST, msg.nlri)
            if msg.mp_reach is not None:
                af = (msg.mp_reach[0], msg.mp_reach[1])
                self._withdraw_many(af, msg.mp_reach[4])
            return

        if msg.nlri:
            self._announce_many(IPV4_UNICAST, msg.nlri, msg.attrs)
        if msg.mp_reach is not None:
            af = (msg.mp_reach[0], msg.mp_reach[1])
            self._announce_many(af, msg.mp_reach[4], msg.attrs)

    def _announce_many(self, af, entries, attrs):
        """Install a set of prefixes sharing one attribute set."""
        table = self.adj_in.get(af)
        if table is None:
            # A family we did not configure. Counted, not fatal: the peer
            # may have negotiated it with a different local policy in
            # mind, and dropping the routes is a narrower response than
            # dropping the session.
            self.stats_counters['prefixes-in'] += len(entries)
            return
        if self._loops(attrs):
            # Our own AS in the AS_PATH: this is a route we originated
            # coming back. Accepting it would be a routing loop that the
            # protocol exists to prevent.
            self._withdraw_many(af, entries)
            return
        if self._too_long(attrs):
            # maxas-limit (P-2). Withdrawn rather than ignored, for the
            # reason a looped path is: an earlier, shorter path for the
            # same prefixes must not survive this announcement.
            self.stats_counters['maxas-limit-dropped'] += len(entries)
            self._withdraw_many(af, entries)
            return
        if self._over_limit(len(entries)):
            return
        locrib = self.locribs.get(af)
        now = self.clock()
        for prefix, path_id in entries:
            key = (prefix, path_id)
            table[key] = attrs
            self.stats_counters['prefixes-in'] += 1
            self._to_locrib(af, locrib, prefix, path_id, attrs, now)

    def _to_locrib(self, af, locrib, prefix, path_id, attrs, now,
                   replay=False):
        """Take one raw path through inbound policy into the Loc-RIB.

        The seam between what the peer said and what this router believes,
        and the only place either inbound policy or next-hop validation is
        applied. Both are here rather than in the Loc-RIB because both are
        per-neighbour: the same prefix from two peers may be denied by one
        neighbour's route-map and accepted by the other's, and the table
        holds the result rather than the question.

        A path the policy denies is *removed* from the Loc-RIB rather than
        merely not added. The peer may have advertised it before the
        policy changed, or before this re-advertisement changed an
        attribute the policy matches on, and in both cases the table is
        holding a path that policy now rejects. Leaving it there is how a
        route-map edit appears to do nothing until the session bounces.

        :param af: the ``(afi, safi)`` pair.
        :param locrib: the family's Loc-RIB, or None.
        :param prefix: the advertised :class:`rib.prefix.Prefix`.
        :param path_id: RFC 7911 path identifier.
        :param attrs: the raw :class:`attrs.AttrSet` from the wire.
        :param now: monotonic arrival time.
        :param replay: the path is being re-run from the Adj-RIB-In, not
            received; a path already in the Loc-RIB keeps its age (B-9).
        :return: True if the path reached the Loc-RIB.
        """
        if locrib is None:
            return False
        chain = self.in_policy.get(af)
        weight = self.config.weight
        if chain is not None and not chain.empty:
            outcome = chain.apply(prefix, attrs)
            if outcome is None:
                self.stats_counters['prefixes-filtered'] += 1
                locrib.remove_path(self.peer_ref, prefix, path_id=path_id)
                return False
            attrs = outcome.attrs
            if outcome.weight is not None:
                weight = outcome.weight
        resolved = True
        igp_metric = 0
        if self.nexthop_check is not None:
            resolved, igp_metric = self.nexthop_check(af[0], attrs.nexthop)
            if not resolved:
                # Kept, not dropped. An unresolved path takes part in no
                # comparison and is advertised to nobody, but it must stay
                # in the table: the next hop usually becomes reachable a
                # moment later, and a path that had been discarded would
                # need the peer to re-send it, which it has no reason to
                # do.
                self.stats_counters['nexthop-unresolved'] += 1
        locrib.add_path(self.peer_ref, prefix, attrs, path_id=path_id,
                        weight=weight, source=bestpath.SRC_PEER,
                        igp_metric=igp_metric, recv_time=now,
                        resolved=resolved, keep_age=replay)
        self.stats_counters['prefixes-accepted'] += 1
        return True

    def soft_reset_in(self, af=None):
        """Re-run inbound policy over everything the peer has told us.

        ``clear ip bgp <peer> soft in`` without asking the peer for
        anything. The raw Adj-RIB-In is still here, so a policy change can
        be applied to the paths already received rather than costing the
        session and a full relearn -- which is the entire reason for
        keeping the raw table in the first place.

        :param af: one ``(afi, safi)`` pair, or None for every family.
        :return: the number of paths replayed.
        """
        families = [af] if af is not None else list(self.adj_in)
        now = self.clock()
        replayed = 0
        for family in families:
            table = self.adj_in.get(family)
            if not table:
                continue
            locrib = self.locribs.get(family)
            # A copy of the items: the replay reaches into the Loc-RIB,
            # and nothing about that may be allowed to iterate the table
            # we are walking.
            for (prefix, path_id), attrs in list(table.items()):
                self._to_locrib(family, locrib, prefix, path_id, attrs,
                                now, replay=True)
                replayed += 1
        if replayed:
            self.stats_counters['soft-resets-in'] += 1
        return replayed

    def _withdraw_many(self, af, entries):
        """Remove a set of prefixes this peer previously gave us."""
        table = self.adj_in.get(af)
        if table is None:
            return
        locrib = self.locribs.get(af)
        for prefix, path_id in entries:
            key = (prefix, path_id)
            if table.pop(key, None) is None:
                # Never advertised to us. Legal -- a peer may withdraw
                # something it never announced, and RFC 4271 says to
                # ignore it -- but worth counting, because a peer doing it
                # constantly is confused about its own state.
                continue
            self.stats_counters['withdraws-in'] += 1
            if locrib is not None:
                locrib.remove_path(self.peer_ref, prefix, path_id=path_id)

    def _loops(self, attrs):
        """Whether this path came back to its own AS.

        ``allowas_in`` exists for hub-and-spoke designs where every spoke
        legitimately sees the hub's AS, so the check counts occurrences
        rather than merely detecting one.
        """
        if not attrs.has_as(self.config.local_as):
            return False
        if self.config.allowas_in <= 0:
            return True
        seen = 0
        for _seg_type, asns in attrs.as_path_list():
            for asn in asns:
                if asn == self.config.local_as:
                    seen += 1
        return seen > self.config.allowas_in

    def _too_long(self, attrs):
        """Whether a path's AS_PATH is over ``maxas-limit``.

        Every ASN counts, set members and confederation segments
        included -- the IOS rule, and unlike the best-path length, where a
        set counts as one. The limit exists to bound the string that
        AS-path regexes are run over, and every ASN is in that string.
        The stored AS_PATH is always 4-byte ASNs behind a two-byte segment
        header, so a path of no more than ``4 * limit`` bytes cannot be
        over it, and nearly every path is decided without the walk.
        """
        limit = self.config.maxas_limit
        if limit <= 0:
            return False
        raw = attrs.as_path
        size = len(raw)
        if size <= 4 * limit:
            return False
        total = 0
        o = 0
        while o + 2 <= size:
            count = raw[o + 1]
            total += count
            o += 2 + 4 * count
        if total <= limit:
            return False
        if not self._maxas_warned:
            self._maxas_warned = True
            LOG.warning('bgp %s: AS_PATH of %d ASNs is over maxas-limit '
                        '%d; treated as withdrawn (logged once per '
                        'session)', self.config.address, total, limit)
        return True

    def _over_limit(self, incoming):
        """Enforce ``maximum-prefix``, tearing the session down if needed.

        A peer that suddenly announces the whole Internet at a router
        sized for a handful of prefixes will exhaust its memory; the limit
        is the only defence, and it has to act before the prefixes are
        stored rather than after.
        """
        limit = self.config.maximum_prefix
        if not limit:
            return False
        total = sum(len(t) for t in self.adj_in.values())
        if total + incoming <= limit:
            warn_at = int(limit * self.config.maximum_prefix_warning)
            if total < warn_at <= total + incoming:
                LOG.warning('bgp %s: %d of %d prefixes, over the %d%% '
                            'warning threshold', self.config.address,
                            total + incoming, limit,
                            int(self.config.maximum_prefix_warning * 100))
            return False
        LOG.error('bgp %s: maximum-prefix %d exceeded, resetting the '
                  'session', self.config.address, limit)
        self.fsm.event(fsm_mod.EV_AUTOMATIC_STOP,
                       reason='maximum-prefix %d exceeded' % limit)
        self._drain_actions()
        return True

    def _release_routes(self):
        """Forget everything this peer told us.

        Called when the session goes down. Without graceful restart --
        which this version does not implement -- a session loss means the
        peer's routes are gone, and holding them would be advertising
        reachability through a neighbour we cannot reach.
        """
        released = 0
        for af, table in self.adj_in.items():
            locrib = self.locribs.get(af)
            if locrib is not None and self.peer_ref is not None:
                released += locrib.remove_peer(self.peer_ref)
            table.clear()
        # The outbound tables are *not* reset here. They belong to update
        # groups now, and the members still up have been told what the
        # record says; discarding it would re-advertise the whole table to
        # all of them because one session flapped. Leaving the group is
        # the plugin's job -- it owns the manager -- and the manager
        # discards the record only when the last member has gone.
        if self.on_session_down is not None:
            try:
                self.on_session_down(self)
            except Exception:
                LOG.exception('bgp %s: leaving update groups failed',
                              self.config.address)
        else:
            self.adjout = {}
        self.eor_sent = set()
        self.eor_received = set()
        if released:
            LOG.info('bgp %s: released %d paths', self.config.address,
                     released)

    # --- outbound ----------------------------------------------------------

    def send_updates(self, messages):
        """Queue already-encoded UPDATE messages on this session.

        The session no longer encodes anything itself. Its update group
        encodes once for every member (see ``updategroup.py``) and hands
        the same list to each of them, so the only per-peer cost left is
        this write -- which is the whole point of the grouping and the
        reason this method takes messages rather than building them.

        :param messages: an iterable of encoded UPDATE messages.
        :return: the number of messages queued; 0 if the session is not
            established, which is not an error -- a group flush may reach
            a member whose session went down in the same loop turn.
        """
        if not self.established:
            return 0
        sent = 0
        for msg in messages:
            self._send(msg, bulk=True)
            self.stats_counters['updates-out'] += 1
            sent += 1
        return sent

    def send_end_of_rib(self, af):
        """Send the End-of-RIB marker for one family.

        :param af: an ``(afi, safi)`` tuple.
        :return: True if one was sent.
        """
        if not self.established or af in self.eor_sent:
            return False
        # Bulk, not control: End-of-RIB must follow the UPDATEs it ends.
        self._send(wire.encode_end_of_rib(af[0], af[1]), bulk=True)
        self.eor_sent.add(af)
        return True

    def send_route_refresh(self, af, subtype=0):
        """Ask the peer to re-advertise a family.

        :param af: an ``(afi, safi)`` tuple.
        :param subtype: RFC 7313 subtype, 0 for a plain request.
        :return: True if one was sent.
        """
        if not self.established or self.negotiated is None:
            return False
        if not self.negotiated.route_refresh:
            return False
        self._send(wire.encode_route_refresh(af[0], af[1], subtype))
        self.stats_counters['refresh-out'] += 1
        return True

    # --- reporting ---------------------------------------------------------

    def prefix_count(self, af=None):
        """Return how many prefixes this peer has given us.

        :param af: restrict to one ``(afi, safi)``, or None for all.
        :return: a count.
        """
        if af is not None:
            return len(self.adj_in.get(af, {}))
        return sum(len(t) for t in self.adj_in.values())

    def as_dict(self):
        """Render for ``show ip bgp neighbors``.

        :return: a dict of plain types.
        """
        out = {
            'peer': self.config.address,
            'peer-as': self.config.remote_as,
            'local-as': self.config.local_as,
            'description': self.config.description,
            'type': 'external' if self.config.is_ebgp else 'internal',
            'state': self.fsm.state,
            'router-id': _ipv4_str(self.peer_router_id),
            'auth': self.auth_mode or 'blocked',
            'auth-reason': self.auth_reason,
            'prefixes': self.prefix_count(),
            'last-error': self.last_error,
            'timers': self.config.fsm_config().as_dict(),
            'fsm': self.fsm.stats(),
            'framing': self.framer.stats(),
            'errors': self.counters.stats(),
            'end-of-rib-received': sorted(
                '%d/%d' % af for af in self.eor_received),
        }
        if self.next_hops:
            out['next-hops'] = dict(
                (capabilities.afi_safi_name(af[0], af[1]), dict(entry))
                for af, entry in sorted(self.next_hops.items()))
        if self.negotiated is not None:
            out['capabilities'] = self.negotiated.as_dict()
        policy = {}
        for af, chain in sorted(self.in_policy.items()):
            if chain is not None and not chain.empty:
                policy[capabilities.afi_safi_name(af[0], af[1])] = \
                    chain.stats()
        if policy:
            # Only when something is configured. A block of permit-all
            # counters under every family would be noise in the one
            # command an operator reads most often.
            out['policy-in'] = policy
        for key in sorted(self.stats_counters):
            out[key] = self.stats_counters[key]
        return out

    def stats(self):
        """Compact counters for engine health."""
        return {
            'peer': self.config.address,
            'state': self.fsm.state,
            'established': bool(self.established),
            'prefixes': self.prefix_count(),
            'auth': self.auth_mode or 'blocked',
            'faults': self.counters.total(),
        }

    def __repr__(self):
        return '<Peer %s as=%d %s prefixes=%d>' % (
            self.config.address, self.config.remote_as, self.fsm.state,
            self.prefix_count())


# --- small helpers ----------------------------------------------------------

def _cancel(task):
    """Cancel a task and make sure nobody is left holding its exception.

    Cancelling is not quite enough on its own, and the reason is a real
    difference between the Python versions this runs on. On the 3.6
    floor, a task cancelled while it is *not* suspended on a future ends
    up finishing with a ``CancelledError`` as its **result** rather than
    being marked cancelled (``Task.__step`` calls ``set_exception`` when
    ``_must_cancel`` is still set as the coroutine returns). Nothing ever
    retrieves that exception, so the task's destructor logs "Task
    exception was never retrieved" with a traceback -- once per peer,
    every time an engine shuts down cleanly. Catching the cancellation
    inside the coroutine does not prevent it, because the task sets the
    exception *after* the coroutine has already returned.

    Retrieving it here is what silences it, and it has to be done from a
    done-callback because at the moment of cancelling the task has not
    finished yet.

    :param task: the task to cancel; None and already-finished tasks are
        accepted and ignored.
    :return: None.
    """
    if task is None or task.done():
        return
    task.cancel()
    task.add_done_callback(_retrieve_cancellation)


def _retrieve_cancellation(task):
    """Read a cancelled task's exception so it is not logged as unhandled.

    ``task.exception()`` raises on a genuinely cancelled task from 3.8
    onwards, which is the normal outcome there, so that case returns
    first. What is left is the 3.6 shape described in :func:`_cancel`.
    """
    if task.cancelled():
        return
    try:
        task.exception()
    except Exception:
        pass


class _Held(object):
    """A second connection waiting for collision resolution."""

    __slots__ = ('conn', 'initiated', 'raw', 'reader')

    def __init__(self, conn, initiated):
        self.conn = conn
        self.initiated = initiated
        # Everything read from it so far, replayed if it wins.
        self.raw = bytearray()
        self.reader = None


def _release(waiters):
    """Resolve and forget every future in a waiter list."""
    while waiters:
        fut = waiters.pop()
        if not fut.done():
            fut.set_result(None)


def _wait_done(loop, task, timeout):
    """Return a future that resolves when ``task`` finishes or on timeout.

    Neither ``asyncio.wait`` nor ``wait_for`` will do: the first looks up
    the thread's default loop on 3.6, which is deliberately not the
    engine's, and the second cancels what it waits for -- here, a write
    that must be allowed to finish.
    """
    waiter = loop.create_future()

    def _wake(_ignored=None):
        if not waiter.done():
            waiter.set_result(None)

    if task.done():
        _wake()
        return waiter
    task.add_done_callback(_wake)
    handle = loop.call_later(timeout, _wake)
    waiter.add_done_callback(lambda _f: handle.cancel())
    return waiter


def _ipv4_str(value):
    """Render a 32-bit router id as a dotted quad."""
    return '%d.%d.%d.%d' % ((value >> 24) & 0xff, (value >> 16) & 0xff,
                            (value >> 8) & 0xff, value & 0xff)


def _router_id_int(value):
    """Accept a router id as an int or a dotted quad and return an int."""
    if isinstance(value, str):
        parts = value.split('.')
        if len(parts) == 4:
            return ((int(parts[0]) << 24) | (int(parts[1]) << 16) |
                    (int(parts[2]) << 8) | int(parts[3]))
        return 0
    return int(value)


def _addr_bytes(address):
    """Pack a peer address string into its raw 4 or 16 bytes."""
    import socket
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    try:
        return socket.inet_pton(family, address)
    except (OSError, ValueError):
        return b''


def _sleep(loop, delay):
    """Sleep on a specific loop, without ``asyncio.sleep``'s loop lookup.

    ``asyncio.sleep`` resolves the running loop itself, and the ``loop=``
    keyword that used to override that was removed in 3.10. The engine's
    loop is deliberately not the thread's default, so a future plus
    ``call_later`` is the one spelling that behaves the same from 3.6 to
    3.12.

    :param loop: the loop to sleep on.
    :param delay: seconds.
    :return: an awaitable.
    """
    future = loop.create_future()

    def _wake():
        if not future.done():
            future.set_result(None)

    handle = loop.call_later(delay, _wake)
    future.add_done_callback(lambda _f: handle.cancel())
    return future


async def _recv(loop, conn, size):
    """Read from a connection's socket on the engine's loop.

    :param loop: the engine loop.
    :param conn: a :class:`transport.tcp.Connection`.
    :param size: maximum bytes to read.
    :return: the bytes read; empty when the peer closed.
    """
    return await loop.sock_recv(conn.sock, size)
