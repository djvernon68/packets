# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The RFC 4271 s8 BGP finite state machine.

This module contains no sockets, no asyncio and no calls to the clock. It
takes events in, returns actions, and keeps timers as absolute deadlines
that somebody else is responsible for noticing. That is a deliberate and
slightly unusual shape, and it buys three things:

**Testable timers.** Half of what a BGP FSM does is wait. With the clock
injected, a test can drive a hold-timer expiry, an idle-hold backoff
sequence or a connect-retry storm in microseconds and assert the exact
state and the exact NOTIFICATION, instead of sleeping for ninety seconds
and hoping. The plan's "fake transport" FSM test is only possible this
way.

**One place to reason about state.** Every transition lives in the
per-state handler it belongs to, not in a condition scattered through the
I/O path. When a session misbehaves in the field the question is always
"which event did it see and what did it do", and that question has one
file to look in.

**No accidental I/O from a timer.** The FSM asks its caller to connect, to
send, to drop the connection; it never does so itself. A state machine
that both decides and acts tends to grow re-entrancy bugs where an action
raises an event that re-enters the machine mid-transition.

The caller is expected to:

1. feed events with :meth:`Fsm.event`;
2. after every call, drain :meth:`Fsm.take_actions` and perform them;
3. arrange to call :meth:`Fsm.tick` at or after :meth:`Fsm.next_deadline`.

**Idle-hold backoff** is the one piece of policy here rather than in the
peer. RFC 4271 has the IdleHold timer but leaves its value open; without
exponential backoff a peer whose far end is misconfigured -- a bad AS, a
bad password -- retries every few seconds forever, and a hundred such
peers is a self-inflicted denial of service against both ends. The delay
doubles on each failure to a ceiling and is reset only once a session has
stayed up long enough to count as healthy, because resetting it on
*reaching* Established lets a session that flaps every second keep
retrying every second.

The backoff deliberately covers failures *after* a connection was made --
a rejected OPEN, a hold timer expiry, a NOTIFICATION -- and not a TCP
connect that simply never answers. Those are already rate-limited by the
ConnectRetry timer at its configured interval, and escalating them would
mean a peer that is merely powered off takes an hour to come back after
it is switched on.

**Collision detection** (RFC 4271 s6.8) is here too, because it is a
state decision and not a transport one: when both ends open a connection
simultaneously, both must independently arrive at the same answer about
which one dies, and the only tie-break both can see is the pair of BGP
identifiers.
"""

import logging

from packets.routing.rtengine.plugins.bgp import errors


LOG = logging.getLogger(__name__)


# --- States (RFC 4271 s8.2.2) -----------------------------------------------

IDLE = 'Idle'
CONNECT = 'Connect'
ACTIVE = 'Active'
OPEN_SENT = 'OpenSent'
OPEN_CONFIRM = 'OpenConfirm'
ESTABLISHED = 'Established'

STATES = (IDLE, CONNECT, ACTIVE, OPEN_SENT, OPEN_CONFIRM, ESTABLISHED)


# --- Events (RFC 4271 s8.1), numbered as the RFC numbers them ---------------
# The numbers are kept because every BGP implementation, every book and
# every packet capture annotation uses them; renumbering them for tidiness
# would make this file harder to check against the specification.

EV_MANUAL_START = 1
EV_MANUAL_STOP = 2
EV_AUTOMATIC_START = 3
EV_AUTOMATIC_STOP = 8
EV_CONNECT_RETRY_EXPIRED = 9
EV_HOLD_EXPIRED = 10
EV_KEEPALIVE_EXPIRED = 11
EV_DELAY_OPEN_EXPIRED = 12
EV_IDLE_HOLD_EXPIRED = 13
EV_TCP_CONNECTION_VALID = 14
EV_TCP_CR_INVALID = 15
EV_TCP_CR_ACKED = 16
EV_TCP_CONFIRMED = 17
EV_TCP_FAILS = 18
EV_BGP_OPEN = 19
EV_BGP_OPEN_DELAY_OPEN = 20
EV_HEADER_ERR = 21
EV_OPEN_MSG_ERR = 22
EV_OPEN_COLLISION_DUMP = 23
EV_NOTIFY_VERSION_ERR = 24
EV_NOTIFY_MSG = 25
EV_KEEPALIVE_MSG = 26
EV_UPDATE_MSG = 27
EV_UPDATE_MSG_ERR = 28

EVENT_NAMES = {
    EV_MANUAL_START: 'ManualStart',
    EV_MANUAL_STOP: 'ManualStop',
    EV_AUTOMATIC_START: 'AutomaticStart',
    EV_AUTOMATIC_STOP: 'AutomaticStop',
    EV_CONNECT_RETRY_EXPIRED: 'ConnectRetryTimer_Expires',
    EV_HOLD_EXPIRED: 'HoldTimer_Expires',
    EV_KEEPALIVE_EXPIRED: 'KeepaliveTimer_Expires',
    EV_DELAY_OPEN_EXPIRED: 'DelayOpenTimer_Expires',
    EV_IDLE_HOLD_EXPIRED: 'IdleHoldTimer_Expires',
    EV_TCP_CONNECTION_VALID: 'TcpConnection_Valid',
    EV_TCP_CR_INVALID: 'Tcp_CR_Invalid',
    EV_TCP_CR_ACKED: 'Tcp_CR_Acked',
    EV_TCP_CONFIRMED: 'TcpConnectionConfirmed',
    EV_TCP_FAILS: 'TcpConnectionFails',
    EV_BGP_OPEN: 'BGPOpen',
    EV_BGP_OPEN_DELAY_OPEN: 'BGPOpen with DelayOpenTimer running',
    EV_HEADER_ERR: 'BGPHeaderErr',
    EV_OPEN_MSG_ERR: 'BGPOpenMsgErr',
    EV_OPEN_COLLISION_DUMP: 'OpenCollisionDump',
    EV_NOTIFY_VERSION_ERR: 'NotifMsgVerErr',
    EV_NOTIFY_MSG: 'NotifMsg',
    EV_KEEPALIVE_MSG: 'KeepaliveMsg',
    EV_UPDATE_MSG: 'UpdateMsg',
    EV_UPDATE_MSG_ERR: 'UpdateMsgErr',
}


# --- Actions the FSM asks its caller to perform -----------------------------
# Returned as (action, payload) pairs rather than performed here. The
# payload shape is documented per action because it is the contract the
# peer implements against.

ACT_CONNECT = 'connect'             # payload: None -- start a TCP connect
ACT_DROP = 'drop'                   # payload: reason string
ACT_SEND_OPEN = 'send-open'         # payload: None
ACT_SEND_KEEPALIVE = 'send-keepalive'
ACT_SEND_NOTIFY = 'send-notify'     # payload: (code, subcode, data)
ACT_ESTABLISHED = 'established'     # payload: None -- session is up
ACT_RELEASE = 'release'             # payload: None -- drop all routes
ACT_LISTEN_ONLY = 'listen-only'     # payload: None -- stop connecting
# Close the connection that produced this event and keep the session's own.
# Distinct from ACT_DROP on purpose: "drop" means the session's connection,
# and an Established session that answered a duplicate connection with a
# drop used to tear itself down -- handing any peer that could open a
# second TCP connection a reset button.
ACT_REFUSE = 'refuse'               # payload: reason string

ACTION_NAMES = (ACT_CONNECT, ACT_DROP, ACT_SEND_OPEN, ACT_SEND_KEEPALIVE,
                ACT_SEND_NOTIFY, ACT_ESTABLISHED, ACT_RELEASE,
                ACT_LISTEN_ONLY, ACT_REFUSE)


# --- Timers -----------------------------------------------------------------

T_CONNECT_RETRY = 'connect-retry'
T_HOLD = 'hold'
T_KEEPALIVE = 'keepalive'
T_DELAY_OPEN = 'delay-open'
T_IDLE_HOLD = 'idle-hold'

TIMERS = (T_CONNECT_RETRY, T_HOLD, T_KEEPALIVE, T_DELAY_OPEN, T_IDLE_HOLD)

TIMER_EVENTS = {
    T_CONNECT_RETRY: EV_CONNECT_RETRY_EXPIRED,
    T_HOLD: EV_HOLD_EXPIRED,
    T_KEEPALIVE: EV_KEEPALIVE_EXPIRED,
    T_DELAY_OPEN: EV_DELAY_OPEN_EXPIRED,
    T_IDLE_HOLD: EV_IDLE_HOLD_EXPIRED,
}

# RFC 4271 s10 defaults, and the s4.2 rule that a hold time is either 0
# (timers off) or at least 3 seconds. A hold time of 1 or 2 is rejected at
# configuration time rather than clamped, because a peer that asked for it
# has misunderstood something and silently giving it 3 hides that.
DEFAULT_HOLD_TIME = 90
DEFAULT_KEEPALIVE = 30
DEFAULT_CONNECT_RETRY = 120
MIN_HOLD_TIME = 3

# Idle-hold backoff. The first failure costs a second; each subsequent one
# doubles to the ceiling. An hour is long for an operator staring at a
# terminal and short for a peer that has been misconfigured since Tuesday,
# which is the case that matters.
IDLE_HOLD_START = 1.0
IDLE_HOLD_MAX = 3600.0
# How long a session must stay Established before its backoff is forgiven.
# Set to the default hold time: a session that survives one full hold
# period has exchanged keepalives in both directions and is genuinely up.
IDLE_HOLD_RESET_AFTER = 90.0


class FsmConfig(object):
    """Timer and behaviour settings for one session.

    :param hold_time: proposed hold time in seconds; 0 disables the hold
        and keepalive timers entirely, which is legal and occasionally
        used on a link where liveness is detected some other way.
    :param keepalive: keepalive interval; defaults to a third of the hold
        time, the RFC 4271 s10 recommendation, which leaves room for two
        lost keepalives before the far end gives up.
    :param connect_retry: seconds between outbound connection attempts.
    :param delay_open: seconds to wait before sending OPEN on a new
        connection; 0 disables. Non-zero gives a simultaneous-open
        collision a chance to resolve before either side has committed to
        an OPEN, which is cheaper than resolving it afterwards.
    :param passive: never initiate a connection, only accept one.
    :param idle_hold_start: first backoff delay.
    :param idle_hold_max: backoff ceiling.
    :param allow_automatic_start: permit the FSM to restart itself after a
        failure. False pins a peer down until an operator intervenes.
    :raises ValueError: the hold time is 1 or 2 seconds, or the keepalive
        is not less than the hold time.
    """

    __slots__ = ('hold_time', 'keepalive', 'connect_retry', 'delay_open',
                 'passive', 'idle_hold_start', 'idle_hold_max',
                 'allow_automatic_start')

    def __init__(self, hold_time=DEFAULT_HOLD_TIME, keepalive=None,
                 connect_retry=DEFAULT_CONNECT_RETRY, delay_open=0,
                 passive=False, idle_hold_start=IDLE_HOLD_START,
                 idle_hold_max=IDLE_HOLD_MAX,
                 allow_automatic_start=True):
        if hold_time and hold_time < MIN_HOLD_TIME:
            raise ValueError(
                'hold time %d is not legal: RFC 4271 s4.2 allows 0 to '
                'disable the timers, or 3 seconds and above' % hold_time)
        self.hold_time = hold_time
        if keepalive is None:
            keepalive = hold_time // 3 if hold_time else 0
        if hold_time and keepalive >= hold_time:
            raise ValueError(
                'keepalive %d must be less than the hold time %d, or the '
                'far end will time out before we send' % (keepalive,
                                                          hold_time))
        self.keepalive = keepalive
        self.connect_retry = connect_retry
        self.delay_open = delay_open
        self.passive = passive
        self.idle_hold_start = idle_hold_start
        self.idle_hold_max = idle_hold_max
        self.allow_automatic_start = allow_automatic_start

    def as_dict(self):
        """Render for ``show ip bgp neighbors``."""
        return {
            'hold-time': self.hold_time,
            'keepalive': self.keepalive,
            'connect-retry': self.connect_retry,
            'delay-open': self.delay_open,
            'passive': self.passive,
        }

    def __repr__(self):
        return '<FsmConfig hold=%d ka=%d retry=%d%s>' % (
            self.hold_time, self.keepalive, self.connect_retry,
            ' passive' if self.passive else '')


class Fsm(object):
    """One session's state machine.

    :param config: an :class:`FsmConfig`.
    :param clock: a zero-argument callable returning monotonically
        increasing seconds. Injected so tests can drive time; must be
        monotonic, because a wall clock stepping backwards would make
        every deadline fire at once.
    :param name: a label for log lines, normally the peer address.
    :param on_state: optional callback ``(old, new, reason)`` invoked on
        every transition, for events and for ``show``.
    """

    __slots__ = ('config', 'clock', 'name', 'on_state', 'state',
                 '_deadlines', '_actions', '_hold_time', '_keepalive',
                 '_idle_hold', '_established_at', '_connect_retries',
                 '_transitions', '_last_error', '_last_reason',
                 '_state_since', '_established_count', '_delay_open_armed',
                 '_counters')

    def __init__(self, config, clock, name='peer', on_state=None):
        self.config = config
        self.clock = clock
        self.name = name
        self.on_state = on_state
        self.state = IDLE
        self._deadlines = {}
        self._actions = []
        # The operating hold time is the *negotiated* one, which is the
        # smaller of the two proposals and is not known until OPEN has
        # been exchanged. Until then the configured value stands in.
        self._hold_time = config.hold_time
        self._keepalive = config.keepalive
        self._idle_hold = 0.0
        self._established_at = None
        self._connect_retries = 0
        self._transitions = 0
        self._established_count = 0
        self._last_error = None
        self._last_reason = None
        self._state_since = clock()
        self._delay_open_armed = False
        self._counters = {}

    # --- inspection --------------------------------------------------------

    @property
    def established(self):
        """Whether the session is up."""
        return self.state == ESTABLISHED

    @property
    def hold_time(self):
        """The hold time in force -- negotiated once OPEN was exchanged."""
        return self._hold_time

    @property
    def keepalive_interval(self):
        """The keepalive interval in force."""
        return self._keepalive

    @property
    def idle_hold(self):
        """The current idle-hold backoff delay, in seconds."""
        return self._idle_hold

    @property
    def uptime(self):
        """Seconds since the session reached Established, or None."""
        if self._established_at is None:
            return None
        return self.clock() - self._established_at

    def timers(self):
        """Return the running timers and their remaining seconds.

        :return: a dict of timer name to seconds remaining, rounded, for
            ``show ip bgp neighbors``. Timers that are not running are
            absent rather than zero -- "not running" and "fires now" are
            very different and an operator needs to tell them apart.
        """
        now = self.clock()
        out = {}
        for name in TIMERS:
            due = self._deadlines.get(name)
            if due is not None:
                out[name] = round(max(0.0, due - now), 3)
        return out

    def next_deadline(self):
        """Return the earliest absolute deadline, or None.

        The caller schedules a single wakeup for this instant rather than
        one timer per timer. Five asyncio callbacks per peer, rearmed on
        every keepalive, is a lot of scheduler churn at a thousand peers;
        one is not.

        :return: an absolute time on the injected clock, or None when no
            timer is running.
        """
        if not self._deadlines:
            return None
        return min(self._deadlines.values())

    def stats(self):
        """Return counters for ``show`` and for health.

        :return: a dict of plain types.
        """
        out = {
            'state': self.state,
            'state-duration': round(self.clock() - self._state_since, 3),
            'transitions': self._transitions,
            'established-count': self._established_count,
            'connect-retries': self._connect_retries,
            'idle-hold': round(self._idle_hold, 3),
            'hold-time': self._hold_time,
            'keepalive': self._keepalive,
            'uptime': None if self.uptime is None else round(self.uptime, 3),
            'last-error': self._last_error,
            'last-reason': self._last_reason,
            'timers': self.timers(),
        }
        for key in sorted(self._counters):
            out['event-' + key] = self._counters[key]
        return out

    # --- action queue ------------------------------------------------------

    def take_actions(self):
        """Remove and return the actions queued since the last call.

        :return: a list of ``(action, payload)``, in the order they must
            be performed. Order matters: a NOTIFICATION queued before a
            drop must actually reach the wire before the socket closes.
        """
        out = self._actions
        self._actions = []
        return out

    def _act(self, action, payload=None):
        self._actions.append((action, payload))

    # --- timers ------------------------------------------------------------

    def _arm(self, timer, seconds):
        """Start or restart a timer. A non-positive interval stops it."""
        if seconds and seconds > 0:
            self._deadlines[timer] = self.clock() + seconds
        else:
            self._deadlines.pop(timer, None)

    def _stop(self, *timers):
        for timer in timers:
            self._deadlines.pop(timer, None)

    def _stop_all(self):
        self._deadlines = {}

    def tick(self, now=None):
        """Fire every timer that is due, earliest deadline first.

        Deadline order, not dictionary order. If the loop was busy and
        several timers came due together, firing them in the order they
        would have fired had the loop been idle is the only ordering that
        cannot invent a transition that could never happen in real time.
        Iteration order over a dict would be arbitrary, and "arbitrary"
        here means a session that behaves differently under load.

        Each firing re-enters :meth:`event`, which may arm or cancel other
        timers, so the due set is recomputed on every pass rather than
        snapshotted -- a hold expiry that tears the session down must not
        be followed by a keepalive from the same batch.

        :param now: the current time; read from the clock when omitted.
        :return: the number of timers that fired.
        """
        if now is None:
            now = self.clock()
        fired = 0
        while True:
            due = None
            due_at = None
            for timer, deadline in self._deadlines.items():
                if deadline <= now and (due_at is None or deadline < due_at):
                    due = timer
                    due_at = deadline
            if due is None:
                return fired
            del self._deadlines[due]
            fired += 1
            self.event(TIMER_EVENTS[due])

    # --- state -------------------------------------------------------------

    def _goto(self, state, reason=None):
        if state == self.state:
            return
        old = self.state
        self.state = state
        self._transitions += 1
        self._state_since = self.clock()
        self._last_reason = reason
        if state == ESTABLISHED:
            self._established_at = self._state_since
            self._established_count += 1
        elif old == ESTABLISHED:
            self._established_at = None
        LOG.info('bgp %s: %s -> %s%s', self.name, old, state,
                 '' if reason is None else ' (%s)' % reason)
        if self.on_state is not None:
            try:
                self.on_state(old, state, reason)
            except Exception:
                # A subscriber must never be able to wedge a session.
                LOG.exception('bgp %s: state callback failed', self.name)

    def _bump_idle_hold(self):
        """Grow the backoff after a failure.

        Only grows. It is reset in one place -- a session that stayed up
        past :data:`IDLE_HOLD_RESET_AFTER` -- so a peer that flaps every
        few seconds keeps backing off instead of resetting its penalty
        each time it briefly succeeds.
        """
        if self._idle_hold <= 0:
            self._idle_hold = self.config.idle_hold_start
        else:
            self._idle_hold = min(self._idle_hold * 2,
                                  self.config.idle_hold_max)

    def _maybe_forgive_idle_hold(self):
        if (self._established_at is not None and
                self.clock() - self._established_at >=
                IDLE_HOLD_RESET_AFTER):
            self._idle_hold = 0.0

    def _to_idle(self, reason, release=True, grow_backoff=True):
        """Shut the session down and go to Idle.

        :param reason: what happened, for logs, ``show`` and events.
        :param release: drop the routes learned from this peer. False only
            for a graceful-restart-style hold, which this version does not
            implement but whose absence should be explicit.
        :param grow_backoff: charge this failure against the idle-hold
            backoff. False for an administrative stop, which is not the
            peer's fault and should not delay a deliberate restart.
        """
        self._maybe_forgive_idle_hold()
        self._stop_all()
        self._delay_open_armed = False
        self._hold_time = self.config.hold_time
        self._keepalive = self.config.keepalive
        self._act(ACT_DROP, reason)
        if release:
            self._act(ACT_RELEASE)
        if grow_backoff:
            self._bump_idle_hold()
            if self.config.allow_automatic_start and self._idle_hold > 0:
                self._arm(T_IDLE_HOLD, self._idle_hold)
        self._goto(IDLE, reason)

    def _notify_and_idle(self, code, subcode, reason, data=b'',
                         grow_backoff=True):
        """Send a NOTIFICATION, then shut down.

        The NOTIFICATION is queued before the drop so the caller performs
        it first. RFC 4271 requires a best effort to deliver it: the far
        end otherwise sees an unexplained reset and has to guess, which
        turns a five-minute misconfiguration into an afternoon.

        :param grow_backoff: charge this against the idle-hold backoff.
            False when we are the ones ending the session deliberately.
        """
        self._last_error = errors.notify_name(code, subcode)
        self._act(ACT_SEND_NOTIFY, (code, subcode, data))
        self._to_idle(reason, grow_backoff=grow_backoff)

    # --- the machine -------------------------------------------------------

    def event(self, ev, **kw):
        """Feed one event to the machine.

        Unknown or out-of-place events are counted and ignored rather than
        raising. RFC 4271 s8.2.2 specifies "ignore" for many
        state/event pairs, and a peer can always deliver a message the
        current state did not expect -- that is a protocol condition, not
        a bug in this process.

        :param ev: one of the ``EV_*`` codes.
        :param kw: event-specific data. ``EV_BGP_OPEN`` takes
            ``hold_time``, ``router_id`` and ``peer_as``;
            ``EV_NOTIFY_MSG`` takes ``code`` and ``subcode``;
            ``EV_OPEN_MSG_ERR`` and ``EV_UPDATE_MSG_ERR`` take ``code``,
            ``subcode`` and optional ``data``.
        :return: the state after the event.
        """
        name = EVENT_NAMES.get(ev, str(ev))
        self._counters[name] = self._counters.get(name, 0) + 1

        # Stops apply in every state and always win: an operator shutting a
        # peer down must not have to wait for a handshake to finish.
        if ev == EV_MANUAL_STOP:
            if self.state != IDLE:
                # No backoff: the operator did this on purpose, and making
                # the next `no shutdown` wait out a penalty we imposed for
                # obeying them would be indefensible. The Cease subcode
                # says *why* (RFC 4486): Administrative Shutdown by
                # default, Peer De-configured when the neighbour was
                # deleted, Administrative Reset for a hard clear.
                self._notify_and_idle(errors.NOTIFY_CEASE,
                                      kw.get('subcode',
                                             errors.CEASE_ADMIN_SHUTDOWN),
                                      kw.get('reason',
                                             'administratively shut down'),
                                      grow_backoff=False)
            self._idle_hold = 0.0
            self._stop_all()
            self._act(ACT_LISTEN_ONLY)
            self._goto(IDLE, 'administratively shut down')
            return self.state
        if ev == EV_AUTOMATIC_STOP:
            if self.state != IDLE:
                self._notify_and_idle(errors.NOTIFY_CEASE,
                                      errors.CEASE_OTHER_CONFIG_CHANGE,
                                      kw.get('reason', 'automatic stop'),
                                      grow_backoff=False)
            return self.state

        handler = _HANDLERS.get(self.state)
        if handler is None:
            return self.state
        handler(self, ev, kw)
        return self.state

    # --- per-state handlers ------------------------------------------------

    def _in_idle(self, ev, kw):
        if ev in (EV_MANUAL_START, EV_AUTOMATIC_START):
            # A manual start clears the penalty: the operator has just
            # told us to try now, and making them wait out a backoff they
            # cannot see would look like the command was ignored.
            if ev == EV_MANUAL_START:
                self._idle_hold = 0.0
                self._stop(T_IDLE_HOLD)
            self._connect_retries = 0
            self._start_connecting()
        elif ev == EV_IDLE_HOLD_EXPIRED:
            if self.config.allow_automatic_start:
                self._start_connecting()
        elif ev in (EV_TCP_CONNECTION_VALID, EV_TCP_CONFIRMED,
                    EV_TCP_CR_ACKED):
            # An inbound connection while Idle. RFC 4271 s8.2.2 says to
            # refuse it -- Idle means we are deliberately not peering,
            # and accepting would let a peer override an administrative
            # shutdown or short-circuit a backoff we imposed on purpose.
            self._act(ACT_DROP, 'connection refused: session is Idle')

    def _start_connecting(self):
        self._stop(T_IDLE_HOLD)
        self._arm(T_CONNECT_RETRY, self.config.connect_retry)
        if self.config.passive:
            # Passive: wait in Active for the far end to connect. Active
            # is a badly chosen name in the RFC -- it means "actively
            # listening", not "actively connecting".
            self._act(ACT_LISTEN_ONLY)
            self._goto(ACTIVE, 'passive, waiting for the peer to connect')
        else:
            self._act(ACT_CONNECT)
            self._goto(CONNECT, 'connecting')

    def _in_connect(self, ev, kw):
        if ev == EV_CONNECT_RETRY_EXPIRED:
            # The connect is taking too long. Drop it and try again, still
            # in Connect: this is not a failure of the peer, and charging
            # it against the idle-hold backoff would punish a slow network
            # the same as a misconfigured neighbour.
            self._connect_retries += 1
            self._act(ACT_DROP, 'connect retry timer expired')
            self._arm(T_CONNECT_RETRY, self.config.connect_retry)
            self._act(ACT_CONNECT)
        elif ev in (EV_TCP_CR_ACKED, EV_TCP_CONFIRMED,
                    EV_TCP_CONNECTION_VALID):
            self._connection_up()
        elif ev == EV_TCP_FAILS:
            # A refused or reset connection. Fall back to Active rather
            # than Idle: the far end may simply not be listening yet, and
            # we should keep both retrying and accepting.
            self._stop(T_CONNECT_RETRY)
            self._arm(T_CONNECT_RETRY, self.config.connect_retry)
            self._goto(ACTIVE, 'connection failed')
        elif ev == EV_DELAY_OPEN_EXPIRED:
            self._send_open_and_wait()
        elif ev in (EV_BGP_OPEN, EV_BGP_OPEN_DELAY_OPEN):
            self._open_during_delay(kw)
        elif ev in (EV_HEADER_ERR, EV_OPEN_MSG_ERR):
            self._notify_and_idle(kw.get('code', errors.NOTIFY_OPEN),
                                  kw.get('subcode', 0),
                                  'error before OPEN was exchanged',
                                  kw.get('data', b''))
        elif ev == EV_NOTIFY_VERSION_ERR:
            # A version mismatch is not transient and not our fault to
            # retry quickly; back off like any other failure.
            self._to_idle('peer rejected our BGP version')

    def _in_active(self, ev, kw):
        if ev == EV_CONNECT_RETRY_EXPIRED:
            self._arm(T_CONNECT_RETRY, self.config.connect_retry)
            if not self.config.passive:
                self._connect_retries += 1
                self._act(ACT_CONNECT)
                self._goto(CONNECT, 'retrying the connection')
        elif ev in (EV_TCP_CR_ACKED, EV_TCP_CONFIRMED,
                    EV_TCP_CONNECTION_VALID):
            self._connection_up()
        elif ev == EV_TCP_FAILS:
            self._arm(T_CONNECT_RETRY, self.config.connect_retry)
        elif ev == EV_DELAY_OPEN_EXPIRED:
            self._send_open_and_wait()
        elif ev in (EV_BGP_OPEN, EV_BGP_OPEN_DELAY_OPEN):
            self._open_during_delay(kw)
        elif ev in (EV_HEADER_ERR, EV_OPEN_MSG_ERR):
            self._notify_and_idle(kw.get('code', errors.NOTIFY_OPEN),
                                  kw.get('subcode', 0),
                                  'error before OPEN was exchanged',
                                  kw.get('data', b''))
        elif ev == EV_NOTIFY_VERSION_ERR:
            self._to_idle('peer rejected our BGP version')

    def _open_during_delay(self, kw):
        """Handle an OPEN that arrived while the DelayOpen timer ran.

        RFC 4271 s8.2.2: the peer got there first, so send our OPEN now
        rather than waiting out the remaining delay, then proceed as
        normal. Sitting on the timer would make the far end's OpenSent
        hold timer tick for no reason.

        An OPEN arriving in Connect or Active with no delay-open
        configured means the peer sent an OPEN before we did on a
        connection we have not acknowledged; the safe response is the
        same one -- answer it.
        """
        self._stop(T_DELAY_OPEN)
        self._delay_open_armed = False
        self._act(ACT_SEND_OPEN)
        self._negotiate(kw)

    def _connection_up(self):
        """A TCP connection exists. Send OPEN, or wait if delay-open is on."""
        self._stop(T_CONNECT_RETRY)
        if self.config.delay_open > 0:
            self._delay_open_armed = True
            self._arm(T_DELAY_OPEN, self.config.delay_open)
            # Stay where we are: until OPEN is sent there is nothing to
            # confirm, and moving to OpenSent would misreport the state.
            return
        self._send_open_and_wait()

    def _send_open_and_wait(self):
        self._delay_open_armed = False
        self._stop(T_DELAY_OPEN)
        self._act(ACT_SEND_OPEN)
        # RFC 4271 s8.2.2: a large hold time while waiting for the peer's
        # OPEN, so a peer that connects and then says nothing is not held
        # forever. Four minutes is the value the RFC suggests.
        self._arm(T_HOLD, 240)
        self._goto(OPEN_SENT, 'OPEN sent')

    def _in_open_sent(self, ev, kw):
        if ev == EV_BGP_OPEN:
            self._negotiate(kw)
        elif ev == EV_HOLD_EXPIRED:
            self._notify_and_idle(errors.NOTIFY_HOLD_TIMER, 0,
                                  'peer sent no OPEN')
        elif ev == EV_TCP_FAILS:
            # The RFC keeps the session in Active here rather than Idle,
            # because the connection failing before OPEN says nothing
            # about whether the peer wants to talk to us.
            self._stop_all()
            self._arm(T_CONNECT_RETRY, self.config.connect_retry)
            self._act(ACT_DROP, 'connection closed before OPEN')
            self._goto(ACTIVE, 'connection closed before OPEN')
        elif ev == EV_HEADER_ERR:
            self._notify_and_idle(errors.NOTIFY_HEADER,
                                  kw.get('subcode',
                                         errors.HDR_CONN_NOT_SYNC),
                                  'header error in OPEN',
                                  kw.get('data', b''))
        elif ev == EV_OPEN_MSG_ERR:
            self._notify_and_idle(errors.NOTIFY_OPEN,
                                  kw.get('subcode', 0),
                                  kw.get('reason', 'bad OPEN'),
                                  kw.get('data', b''))
        elif ev == EV_OPEN_COLLISION_DUMP:
            self._notify_and_idle(errors.NOTIFY_CEASE,
                                  errors.CEASE_COLLISION_RESOLUTION,
                                  'lost connection collision resolution')
        elif ev == EV_NOTIFY_VERSION_ERR:
            self._to_idle('peer rejected our BGP version')
        elif ev == EV_NOTIFY_MSG:
            self._note_notification(kw)
            self._to_idle('peer sent NOTIFICATION')
        else:
            self._unexpected(ev)

    def _negotiate(self, kw):
        """Apply the peer's OPEN and move to OpenConfirm.

        The hold time in force is the smaller of the two proposals (RFC
        4271 s4.2), and if either side proposed 0 the result is 0 and both
        timers are off. Taking our own value instead is the classic bug
        that produces a session which one end declares dead while the
        other thinks it is fine.
        """
        peer_hold = kw.get('hold_time', self.config.hold_time)
        self._hold_time = min(self.config.hold_time, peer_hold)
        if self._hold_time:
            # Keep the configured ratio rather than forcing a third, so an
            # operator who asked for a faster keepalive still gets one.
            #
            # Scaled with integer arithmetic, not a float ratio. Going via
            # a float loses the identity case: with hold 49 and keepalive
            # 16, a peer proposing the *same* 49 came back with 15,
            # because 49 * (16/49) is 15.999... and int() truncates. A
            # session that renegotiated nothing must come back exactly
            # where it started, and multiplying before dividing makes
            # that exact.
            if self.config.hold_time:
                self._keepalive = max(
                    1, self._hold_time * self.config.keepalive
                    // self.config.hold_time)
            else:
                self._keepalive = max(1, self._hold_time // 3)
            self._arm(T_HOLD, self._hold_time)
            self._arm(T_KEEPALIVE, self._keepalive)
        else:
            self._keepalive = 0
            self._stop(T_HOLD, T_KEEPALIVE)
        self._act(ACT_SEND_KEEPALIVE)
        self._goto(OPEN_CONFIRM, 'OPEN received, hold time %d'
                   % self._hold_time)

    def _in_open_confirm(self, ev, kw):
        if ev == EV_KEEPALIVE_MSG:
            self._restart_hold()
            self._act(ACT_ESTABLISHED)
            self._goto(ESTABLISHED, 'session established')
        elif ev == EV_KEEPALIVE_EXPIRED:
            self._act(ACT_SEND_KEEPALIVE)
            self._arm(T_KEEPALIVE, self._keepalive)
        elif ev == EV_HOLD_EXPIRED:
            self._notify_and_idle(errors.NOTIFY_HOLD_TIMER, 0,
                                  'hold timer expired in OpenConfirm')
        elif ev == EV_TCP_FAILS:
            self._to_idle('connection closed in OpenConfirm')
        elif ev == EV_NOTIFY_MSG:
            self._note_notification(kw)
            self._to_idle('peer sent NOTIFICATION')
        elif ev == EV_NOTIFY_VERSION_ERR:
            self._to_idle('peer rejected our BGP version')
        elif ev == EV_OPEN_COLLISION_DUMP:
            self._notify_and_idle(errors.NOTIFY_CEASE,
                                  errors.CEASE_COLLISION_RESOLUTION,
                                  'lost connection collision resolution')
        elif ev in (EV_HEADER_ERR, EV_OPEN_MSG_ERR):
            self._notify_and_idle(kw.get('code', errors.NOTIFY_OPEN),
                                  kw.get('subcode', 0),
                                  'error in OpenConfirm',
                                  kw.get('data', b''))
        else:
            self._unexpected(ev)

    def _in_established(self, ev, kw):
        if ev in (EV_KEEPALIVE_MSG, EV_UPDATE_MSG):
            # Any well-formed message proves the peer is alive, which is
            # what the hold timer is actually measuring -- not keepalives
            # specifically. A busy peer sending a continuous stream of
            # UPDATEs may legitimately never send a keepalive.
            self._restart_hold()
        elif ev == EV_KEEPALIVE_EXPIRED:
            self._act(ACT_SEND_KEEPALIVE)
            self._arm(T_KEEPALIVE, self._keepalive)
        elif ev == EV_HOLD_EXPIRED:
            self._notify_and_idle(errors.NOTIFY_HOLD_TIMER, 0,
                                  'hold timer expired')
        elif ev == EV_TCP_FAILS:
            self._to_idle('connection closed')
        elif ev == EV_NOTIFY_MSG:
            self._note_notification(kw)
            self._to_idle('peer sent NOTIFICATION')
        elif ev == EV_UPDATE_MSG_ERR:
            self._notify_and_idle(errors.NOTIFY_UPDATE,
                                  kw.get('subcode', 0),
                                  kw.get('reason', 'malformed UPDATE'),
                                  kw.get('data', b''))
        elif ev == EV_HEADER_ERR:
            self._notify_and_idle(errors.NOTIFY_HEADER,
                                  kw.get('subcode',
                                         errors.HDR_CONN_NOT_SYNC),
                                  kw.get('reason', 'message header error'),
                                  kw.get('data', b''))
        elif ev in (EV_BGP_OPEN, EV_OPEN_MSG_ERR):
            # An OPEN on an established session is a protocol violation:
            # the handshake happens once. RFC 4271 s8.2.2 calls for
            # Finite State Machine Error.
            self._notify_and_idle(errors.NOTIFY_FSM, 0,
                                  'OPEN received on an established session')
        elif ev == EV_OPEN_COLLISION_DUMP:
            self._notify_and_idle(errors.NOTIFY_CEASE,
                                  errors.CEASE_COLLISION_RESOLUTION,
                                  'lost connection collision resolution')
        elif ev in (EV_TCP_CR_ACKED, EV_TCP_CONFIRMED,
                    EV_TCP_CONNECTION_VALID):
            # A second connection to an already established peer. Refuse
            # *it* and keep the working one (RFC 4271 s6.8: the Established
            # connection is always preserved). ACT_REFUSE, never ACT_DROP:
            # a drop closes the session's own connection.
            self._act(ACT_REFUSE, 'second connection to an established peer')
        else:
            self._unexpected(ev)

    def abandon_connection(self, reason):
        """Give up the current connection without ending the session.

        Collision resolution's other outcome. When the connection the
        session is using loses to a second one (RFC 4271 s6.8), the RFC's
        model has two FSMs and simply discards the loser's; this machine
        is one per peer, so it steps back to Active -- as if the losing
        connection had never existed -- and the caller hands it the winner
        as a fresh connection event. No routes are released and no backoff
        is charged, because nothing failed: no session was ever up.

        :param reason: recorded with the transition.
        :return: True if the machine stepped back, False when the state
            has no connection to abandon (Idle) or must not lose it
            (Established).
        """
        if self.state in (IDLE, ESTABLISHED):
            return False
        self._stop(T_HOLD, T_KEEPALIVE, T_DELAY_OPEN)
        self._delay_open_armed = False
        self._hold_time = self.config.hold_time
        self._keepalive = self.config.keepalive
        self._arm(T_CONNECT_RETRY, self.config.connect_retry)
        self._goto(ACTIVE, reason)
        return True

    def _restart_hold(self):
        if self._hold_time:
            self._arm(T_HOLD, self._hold_time)

    def _note_notification(self, kw):
        code = kw.get('code', 0)
        subcode = kw.get('subcode', 0)
        self._last_error = 'received %s' % errors.notify_name(code, subcode)

    def _unexpected(self, ev):
        LOG.debug('bgp %s: ignoring %s in %s', self.name,
                  EVENT_NAMES.get(ev, ev), self.state)


_HANDLERS = {
    IDLE: Fsm._in_idle,
    CONNECT: Fsm._in_connect,
    ACTIVE: Fsm._in_active,
    OPEN_SENT: Fsm._in_open_sent,
    OPEN_CONFIRM: Fsm._in_open_confirm,
    ESTABLISHED: Fsm._in_established,
}


def resolve_collision(local_router_id, peer_router_id, local_as, peer_as,
                      we_initiated):
    """Decide which of two simultaneous connections survives.

    RFC 4271 s6.8. Both ends run this independently on the same two
    identifiers and must reach opposite conclusions about their own
    connection, or they will both drop it and immediately collide again --
    a livelock that looks exactly like a flapping peer.

    The rule is that the speaker with the **higher** BGP identifier keeps
    the connection *it* initiated. So we keep our outbound connection when
    our identifier is higher, and keep the inbound one when it is lower.

    RFC 6286 extended the tie-break to the AS number for the case where
    both identifiers are equal, which is otherwise unresolvable and
    happens in practice when a device is cloned without its router id
    being changed.

    :param local_router_id: our BGP identifier as a 32-bit integer.
    :param peer_router_id: the peer's, from its OPEN.
    :param local_as: our AS.
    :param peer_as: the peer's AS.
    :param we_initiated: whether the connection being judged is the one we
        opened.
    :return: True to keep this connection, False to close it with
        NOTIFICATION Cease/Connection Collision Resolution.
    """
    if local_router_id == peer_router_id:
        # RFC 6286 s2.3: fall back to the AS numbers. If those match too
        # the peer is almost certainly ourselves, reached by a loop in the
        # configuration, and refusing both is the right answer.
        if local_as == peer_as:
            return False
        higher_is_ours = local_as > peer_as
    else:
        higher_is_ours = local_router_id > peer_router_id
    return we_initiated if higher_is_ours else not we_initiated
