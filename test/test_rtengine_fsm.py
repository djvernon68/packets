#!/usr/bin/env python

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Tests for the BGP finite state machine in rtengine.plugins.bgp.fsm.

The module under test has an unusual shape -- an injected clock, absolute
deadlines, and actions returned to the caller instead of performed -- and
this file is the justification for it. Everything here is asserted
exactly, in microseconds, because the shape makes that possible; a state
machine that owned its own sockets and its own ``time.sleep`` could only
be tested by waiting ninety seconds and hoping.

The suite is shaped around the ways a BGP session actually fails in the
field rather than around the source layout:

  * **Timers are half of what the FSM does**, so they get most of the
    file. Hold-time negotiation is the classic interoperability bug: take
    your own proposal instead of the smaller one and you build a session
    that one end declares dead while the other thinks it is fine. The
    negotiated value, the peer-proposed 0, and the keepalive ratio are
    therefore pinned separately, as is the rule that *any* message
    restarts the hold timer -- a peer streaming UPDATEs may legitimately
    never send a KEEPALIVE, and a hold timer that only listens for
    KEEPALIVEs would tear that session down.

  * **Ordering within a batch is a correctness property, not a detail.**
    ``tick`` recomputes the due set on every pass precisely so that a
    hold expiry which tears the session down is not followed by a
    keepalive from the same batch -- a keepalive written to a socket the
    previous action just closed. Both directions are asserted: several
    due timers fire in deadline order, and a teardown cancels what was
    queued behind it.

  * **The idle-hold backoff is policy, and policy is where opinions
    drift.** It must grow on post-connection failures, double, saturate,
    be cleared by an operator's start, and -- the one that is easy to get
    backwards -- not be charged by an administrative stop, because making
    the next ``no shutdown`` wait out a penalty imposed for obeying the
    previous command is indefensible.

  * **Refusals matter as much as transitions.** An inbound connection
    while Idle is refused, so a peer that keeps dialling cannot override
    an administrative shutdown; passive mode never emits ``connect``.

  * **``resolve_collision`` exists to prevent a livelock**, so it is
    tested exhaustively and then tested again from both ends of the same
    pair. If both speakers conclude "drop mine" they collide again
    immediately, which in the field looks exactly like a flapping peer
    and not at all like a tie-break bug.

Written as plain ``unittest.TestCase`` with no pytest features, matching
``test_rtengine_rib.py``: the 3.6.8 verification host has no pytest and
runs these through ``python3 -m unittest discover -s test``.
"""

import json
import unittest

from packets.routing.rtengine.plugins.bgp import errors
from packets.routing.rtengine.plugins.bgp.fsm import ACTIVE, CONNECT, \
    ESTABLISHED, EV_BGP_OPEN, EV_HOLD_EXPIRED, EV_KEEPALIVE_MSG, \
    EV_MANUAL_START, EV_MANUAL_STOP, EV_TCP_CONFIRMED, EV_TCP_CR_ACKED, \
    EV_TCP_CONNECTION_VALID, EV_TCP_FAILS, EV_UPDATE_MSG, IDLE, \
    OPEN_CONFIRM, OPEN_SENT, T_CONNECT_RETRY, T_HOLD, T_IDLE_HOLD, \
    T_KEEPALIVE, Fsm, FsmConfig, resolve_collision

# An arbitrary non-zero epoch. Starting the fake clock away from 0 keeps a
# missing "+ now" in a deadline calculation from passing by accident, which
# it would if every deadline and every current time were small and similar.
EPOCH = 1000.0

# The NOTIFICATION codes the FSM emits, named here so a test reads as the
# protocol rather than as an integer. Taken through the errors module so
# that a renumbering there fails these tests rather than silently making
# them assert the wrong code.
HOLD_EXPIRED_CODE = errors.NOTIFY_HOLD_TIMER
FSM_ERROR_CODE = errors.NOTIFY_FSM
CEASE_CODE = errors.NOTIFY_CEASE


class FakeClock(object):
    """A monotonic clock a test drives by hand.

    The FSM stores absolute deadlines and never reads the clock except
    through this callable, so advancing it is the whole of "time passed".
    Deliberately not a subclass of float or a generator: a test that
    forgets to advance it must see a stuck machine, not a plausible one.
    """

    __slots__ = ('now',)

    def __init__(self, now=EPOCH):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        """Move forward, returning the new time for use in an assertion."""
        self.now += seconds
        return self.now


class Session(object):
    """An :class:`Fsm` plus the plumbing every test in this file needs.

    Three things are bundled, because repeating them per test is how a
    timer assertion ends up measuring the harness instead of the machine:
    the fake clock, the drain-after-every-event discipline the module's
    docstring requires of callers, and the transition log that
    ``on_state`` offers.

    Actions are returned from :meth:`event` rather than accumulated
    across a test, so an assertion about "what this event produced" is
    exactly that and cannot be satisfied by an action left over from an
    earlier one.
    """

    __slots__ = ('clock', 'config', 'fsm', 'transitions')

    def __init__(self, clock=None, **kwargs):
        self.clock = clock if clock is not None else FakeClock()
        self.config = FsmConfig(**kwargs)
        self.transitions = []
        self.fsm = Fsm(self.config, self.clock, name='10.0.0.1',
                       on_state=self._record)

    def _record(self, old, new, reason):
        self.transitions.append((old, new))

    @property
    def state(self):
        return self.fsm.state

    def event(self, ev, **kwargs):
        """Feed one event and return the actions it produced."""
        self.fsm.event(ev, **kwargs)
        return self.fsm.take_actions()

    def names(self, ev, **kwargs):
        """Feed one event and return only the action names."""
        return [name for name, _ in self.event(ev, **kwargs)]

    def tick_at(self, when):
        """Advance to an absolute time and fire what is due.

        :return: ``(fired, actions)``, so a test can pin both how many
            timers went off and what they asked for -- the two are
            independent and a bug in either is invisible from the other.
        """
        self.clock.now = when
        fired = self.fsm.tick()
        return fired, self.fsm.take_actions()

    def deadline(self, timer):
        """The absolute deadline of one timer, or None if it is stopped."""
        return self.fsm._deadlines.get(timer)

    def establish(self, peer_hold=None):
        """Run the full handshake and return the actions it produced.

        Most tests are about what happens *after* the session is up, and
        a four-event preamble repeated thirty times is four chances to
        get the preamble wrong in a way that looks like a failure of the
        thing under test.
        """
        if peer_hold is None:
            peer_hold = self.config.hold_time
        out = []
        out.extend(self.event(EV_MANUAL_START))
        out.extend(self.event(EV_TCP_CR_ACKED))
        out.extend(self.event(EV_BGP_OPEN, hold_time=peer_hold,
                              router_id=0x02020202, peer_as=65001))
        out.extend(self.event(EV_KEEPALIVE_MSG))
        return out


def _fail_after_establishing(session, up_for=1.0):
    """Establish a session and then lose the connection under it.

    The idle-hold backoff is only charged for failures *after* a
    connection was made, so every backoff test needs this exact shape and
    none of them should be spelling it out.
    """
    session.event(EV_TCP_CR_ACKED)
    session.event(EV_BGP_OPEN, hold_time=session.config.hold_time)
    session.event(EV_KEEPALIVE_MSG)
    session.clock.advance(up_for)
    return session.event(EV_TCP_FAILS)


class HandshakeTestCase(unittest.TestCase):
    """The happy path, one action at a time."""

    def test_idle_to_established_emits_one_action_per_step(self):
        # The exact sequence is the contract the peer implements against:
        # it decides when a socket is opened, when bytes go out and when
        # the route tables are allowed to fill. Asserting the whole list
        # rather than "contains send-open" is deliberate -- an extra
        # action here is a duplicate OPEN on the wire.
        s = Session()
        self.assertEqual(s.event(EV_MANUAL_START), [('connect', None)])
        self.assertEqual(s.state, CONNECT)
        self.assertEqual(s.event(EV_TCP_CR_ACKED), [('send-open', None)])
        self.assertEqual(s.state, OPEN_SENT)
        self.assertEqual(s.event(EV_BGP_OPEN, hold_time=90),
                         [('send-keepalive', None)])
        self.assertEqual(s.state, OPEN_CONFIRM)
        self.assertEqual(s.event(EV_KEEPALIVE_MSG), [('established', None)])
        self.assertEqual(s.state, ESTABLISHED)

    def test_the_handshake_visits_every_state_in_order(self):
        # Pins that no state is skipped. A machine that jumped straight
        # from Connect to Established would pass every action assertion
        # above and still be unable to report what a session is doing.
        s = Session()
        s.establish()
        self.assertEqual(s.transitions,
                         [(IDLE, CONNECT), (CONNECT, OPEN_SENT),
                          (OPEN_SENT, OPEN_CONFIRM),
                          (OPEN_CONFIRM, ESTABLISHED)])

    def test_open_sent_holds_for_four_minutes_not_the_hold_time(self):
        # RFC 4271 s8.2.2: a large hold time while waiting for the peer's
        # OPEN. Using the configured hold time here would drop a peer that
        # is merely slow to finish its own handshake.
        s = Session(hold_time=30)
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_CR_ACKED)
        self.assertEqual(s.deadline(T_HOLD), EPOCH + 240)


class HoldNegotiationTestCase(unittest.TestCase):
    """The session runs at the smaller of the two proposals."""

    def test_the_smaller_proposal_wins_from_either_side(self):
        # Taking our own value when the peer asked for less is the bug
        # that builds a session one end declares dead while the other
        # thinks it is fine, and it is invisible until the link goes quiet.
        s = Session(hold_time=90)
        s.establish(peer_hold=30)
        self.assertEqual(s.fsm.hold_time, 30)
        s = Session(hold_time=30)
        s.establish(peer_hold=90)
        self.assertEqual(s.fsm.hold_time, 30)

    def test_the_negotiated_hold_time_is_what_the_timers_use(self):
        # The negotiated value has to reach the deadlines, not just the
        # accessor: a correct negotiation that arms the configured timer
        # anyway is the same outage with a better-looking ``show``.
        s = Session(hold_time=90, keepalive=30)
        s.establish(peer_hold=30)
        self.assertEqual(s.deadline(T_HOLD), EPOCH + 30)
        self.assertEqual(s.deadline(T_KEEPALIVE),
                         EPOCH + s.fsm.keepalive_interval)

    def test_a_peer_proposing_zero_disables_both_timers(self):
        # A hold time of 0 is legal and means "no liveness timers". Both
        # timers must actually stop: an armed keepalive with no hold timer
        # is a session that chatters forever and can never notice a death.
        s = Session(hold_time=90)
        s.establish(peer_hold=0)
        self.assertEqual(s.fsm.hold_time, 0)
        self.assertEqual(s.fsm.keepalive_interval, 0)
        self.assertEqual(s.state, ESTABLISHED)
        self.assertIsNone(s.deadline(T_HOLD))
        self.assertIsNone(s.deadline(T_KEEPALIVE))
        self.assertEqual(s.fsm.timers(), {})

    def test_a_zero_hold_session_never_expires(self):
        # The point of proposing 0. An hour of silence must not tear it
        # down, because liveness is somebody else's job on such a link.
        s = Session(hold_time=90)
        s.establish(peer_hold=0)
        self.assertEqual(s.state, ESTABLISHED)
        fired, actions = s.tick_at(EPOCH + 3600)
        self.assertEqual((fired, actions), (0, []))
        self.assertEqual(s.state, ESTABLISHED)

    def test_the_keepalive_keeps_the_configured_ratio(self):
        # An operator who configured a keepalive twelve times faster than
        # the hold time asked for fast failure detection. Forcing the RFC
        # default third on renegotiation would quietly take that away, and
        # a third of a reduced hold time is not what they asked for either.
        s = Session(hold_time=60, keepalive=5)
        s.establish(peer_hold=30)
        self.assertEqual(s.fsm.hold_time, 30)
        self.assertEqual(s.fsm.keepalive_interval, 2)
        self.assertNotEqual(s.fsm.keepalive_interval, 10)

    def test_the_keepalive_stays_below_the_negotiated_hold_time(self):
        # The invariant the ratio exists to preserve. A keepalive at or
        # above the hold time means the far end times us out before we
        # speak, whatever the two configured values were.
        for hold, keepalive, peer in ((90, 30, 30), (90, 30, 9),
                                      (240, 80, 3), (60, 59, 30)):
            s = Session(hold_time=hold, keepalive=keepalive)
            s.establish(peer_hold=peer)
            self.assertLess(s.fsm.keepalive_interval, s.fsm.hold_time)
            self.assertGreaterEqual(s.fsm.keepalive_interval, 1)


class KeepaliveTimerTestCase(unittest.TestCase):
    """The keepalive timer must rearm, every time, forever."""

    def test_the_keepalive_timer_rearms_on_every_expiry(self):
        # A one-shot keepalive works for one interval and then the far end
        # drops us at its hold time -- the kind of bug that only appears
        # on a link quiet enough that nothing else restarted the timer.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        self.assertEqual(s.fsm.keepalive_interval, 10)
        for i in range(1, 6):
            when = EPOCH + 10 * i
            fired, actions = s.tick_at(when)
            self.assertEqual(fired, 1)
            self.assertEqual(actions, [('send-keepalive', None)])
            self.assertEqual(s.deadline(T_KEEPALIVE), when + 10)
            self.assertEqual(s.state, ESTABLISHED)

    def test_sending_a_keepalive_does_not_restart_our_hold_timer(self):
        # The hold timer measures the *peer's* liveness. Restarting it
        # because we spoke would make a dead peer look alive for as long
        # as we kept talking, which is the whole failure mode it guards.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        self.assertEqual(s.deadline(T_HOLD), EPOCH + 90)
        s.tick_at(EPOCH + 10)
        self.assertEqual(s.deadline(T_HOLD), EPOCH + 90)


class HoldTimerLivenessTestCase(unittest.TestCase):
    """Any message is evidence of life, not just a KEEPALIVE."""

    def test_a_keepalive_message_restarts_the_hold_timer(self):
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        s.clock.advance(50)
        s.event(EV_KEEPALIVE_MSG)
        self.assertEqual(s.deadline(T_HOLD), EPOCH + 50 + 90)

    def test_an_update_message_restarts_the_hold_timer(self):
        # The case a naive implementation gets wrong. A peer feeding a
        # full table sends a continuous stream of UPDATEs and may not emit
        # a KEEPALIVE for minutes; dropping it mid-convergence turns a
        # busy peer into a flapping one.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        s.clock.advance(50)
        s.event(EV_UPDATE_MSG)
        self.assertEqual(s.deadline(T_HOLD), EPOCH + 50 + 90)

    def test_a_stream_of_updates_keeps_the_session_up_indefinitely(self):
        # The property the test above only implies. Nothing but UPDATEs,
        # each arriving inside the hold time, must never expire the hold.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        for _ in range(20):
            s.clock.advance(80)
            s.fsm.tick()
            s.fsm.take_actions()
            s.event(EV_UPDATE_MSG)
            self.assertEqual(s.state, ESTABLISHED)


class HoldExpiryTestCase(unittest.TestCase):
    """What a dead peer costs, and in what order."""

    def test_hold_expiry_notifies_then_drops_then_releases(self):
        # Order is the assertion. The NOTIFICATION has to reach the wire
        # before the socket closes, or the far end sees an unexplained
        # reset and has to guess; the routes must not be released before
        # the drop, or a re-advertisement can race the teardown.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        actions = s.event(EV_HOLD_EXPIRED)
        self.assertEqual(actions, [
            ('send-notify', (HOLD_EXPIRED_CODE, 0, b'')),
            ('drop', 'hold timer expired'),
            ('release', None),
        ])
        self.assertEqual(s.state, IDLE)

    def test_the_hold_expiry_notification_is_code_four(self):
        # Pinned as a number as well as through the errors module, because
        # this is the code an operator reads off a packet capture and the
        # one a far-end implementation matches on.
        self.assertEqual(HOLD_EXPIRED_CODE, 4)

    def test_hold_expiry_stops_every_timer(self):
        # A timer surviving the teardown would fire against a session that
        # no longer exists and, worse, ask for a write to a closed socket.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        s.event(EV_HOLD_EXPIRED)
        self.assertIsNone(s.deadline(T_KEEPALIVE))
        self.assertIsNone(s.deadline(T_HOLD))

    def test_hold_expiry_in_open_confirm_also_notifies(self):
        # A peer that answers our OPEN and then goes silent must not be
        # held in OpenConfirm forever waiting for its KEEPALIVE.
        s = Session(hold_time=90, keepalive=10)
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_CR_ACKED)
        s.event(EV_BGP_OPEN, hold_time=90)
        self.assertEqual(s.state, OPEN_CONFIRM)
        actions = s.event(EV_HOLD_EXPIRED)
        self.assertEqual(actions[0],
                         ('send-notify', (HOLD_EXPIRED_CODE, 0, b'')))
        self.assertEqual(s.state, IDLE)


class TickOrderingTestCase(unittest.TestCase):
    """Several timers due at once must behave as if the loop were idle."""

    def test_tick_fires_due_timers_in_deadline_order(self):
        # Dictionary order would make a loaded process behave differently
        # from an idle one. Here the keepalive was due at +10 and the hold
        # at +90, so the keepalive has to be reported first even though
        # both became due during the same stall.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        fired, actions = s.tick_at(EPOCH + 95)
        self.assertEqual(fired, 2)
        self.assertEqual([name for name, _ in actions],
                         ['send-keepalive', 'send-notify', 'drop',
                          'release'])
        self.assertEqual(s.state, IDLE)

    def test_a_hold_expiry_cancels_a_keepalive_queued_behind_it(self):
        # The reason ``tick`` recomputes the due set instead of
        # snapshotting it. Here the keepalive fires first and rearms to
        # +18, past the hold at +10; the next batch must fire the hold,
        # tear the session down, and *not* then ask for a keepalive on a
        # connection the previous action just dropped.
        s = Session(hold_time=10, keepalive=9)
        s.establish(peer_hold=10)
        self.assertEqual(s.fsm.keepalive_interval, 9)
        fired, actions = s.tick_at(EPOCH + 9)
        self.assertEqual((fired, actions), (1, [('send-keepalive', None)]))
        self.assertEqual(s.deadline(T_KEEPALIVE), EPOCH + 18)
        self.assertEqual(s.deadline(T_HOLD), EPOCH + 10)
        fired, actions = s.tick_at(EPOCH + 20)
        self.assertEqual(fired, 1)
        self.assertEqual([name for name, _ in actions],
                         ['send-notify', 'drop', 'release'])
        self.assertEqual(s.state, IDLE)

    def test_tick_before_any_deadline_does_nothing(self):
        # A caller that wakes early -- a coarse event loop, a rounded
        # timeout -- must not be able to fire a timer ahead of time.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        self.assertEqual(s.tick_at(EPOCH + 9.999), (0, []))
        self.assertEqual(s.state, ESTABLISHED)


class IdleHoldBackoffTestCase(unittest.TestCase):
    """The one piece of policy in the file, and the easiest to get wrong."""

    def test_the_backoff_grows_and_doubles_and_saturates(self):
        # Without a ceiling the delay grows without bound and a peer that
        # comes back is never retried; without doubling, a hundred
        # misconfigured peers retry every second forever and the backoff
        # is not doing its job at all.
        s = Session(idle_hold_start=1.0, idle_hold_max=4.0)
        s.event(EV_MANUAL_START)
        for expected in (1.0, 2.0, 4.0, 4.0, 4.0):
            _fail_after_establishing(s)
            self.assertEqual(s.fsm.idle_hold, expected)
            self.assertEqual(s.state, IDLE)
            self.assertEqual(s.deadline(T_IDLE_HOLD),
                             s.clock.now + expected)
            s.clock.advance(expected)
            s.fsm.tick()
            s.fsm.take_actions()
            self.assertEqual(s.state, CONNECT)

    def test_the_idle_hold_timer_restarts_the_connection(self):
        # The backoff must expire into another attempt, not into silence.
        s = Session(idle_hold_start=5.0)
        s.event(EV_MANUAL_START)
        _fail_after_establishing(s)
        self.assertEqual(s.state, IDLE)
        fired, actions = s.tick_at(s.clock.now + 5.0)
        self.assertEqual((fired, actions), (1, [('connect', None)]))
        self.assertEqual(s.state, CONNECT)

    def test_a_manual_start_clears_the_backoff(self):
        # An operator who types the command has said "try now". Making
        # them wait out a penalty they cannot see looks exactly like the
        # command being ignored.
        s = Session(idle_hold_start=8.0)
        s.event(EV_MANUAL_START)
        _fail_after_establishing(s)
        self.assertEqual(s.fsm.idle_hold, 8.0)
        self.assertEqual(s.names(EV_MANUAL_START), ['connect'])
        self.assertEqual(s.fsm.idle_hold, 0.0)
        self.assertIsNone(s.deadline(T_IDLE_HOLD))

    def test_an_administrative_stop_is_not_charged_to_the_backoff(self):
        # The session going down was our decision, not the peer's fault.
        # A backoff here would delay the next deliberate start for a
        # failure that never happened.
        s = Session(idle_hold_start=8.0)
        s.establish()
        actions = s.event(EV_MANUAL_STOP)
        self.assertEqual([name for name, _ in actions],
                         ['send-notify', 'drop', 'release', 'listen-only'])
        self.assertEqual(actions[0][1][0], CEASE_CODE)
        self.assertEqual(s.state, IDLE)
        self.assertEqual(s.fsm.idle_hold, 0.0)
        self.assertIsNone(s.deadline(T_IDLE_HOLD))
        self.assertEqual(s.fsm.timers(), {})

    def test_a_stop_clears_a_backoff_a_previous_failure_imposed(self):
        # Not merely "does not add to it". An operator shutting a peer
        # down and starting it again must not inherit the penalty from
        # the failure before the shutdown.
        s = Session(idle_hold_start=8.0)
        s.event(EV_MANUAL_START)
        _fail_after_establishing(s)
        self.assertEqual(s.fsm.idle_hold, 8.0)
        s.event(EV_MANUAL_STOP)
        self.assertEqual(s.fsm.idle_hold, 0.0)
        self.assertIsNone(s.deadline(T_IDLE_HOLD))

    def test_a_connect_that_never_answers_is_not_charged_either(self):
        # Deliberately out of scope for the backoff: an unanswered TCP
        # connect is already rate-limited by the ConnectRetry timer, and
        # escalating it would mean a peer that is merely powered off takes
        # an hour to come back after somebody switches it on.
        s = Session(idle_hold_start=8.0)
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_FAILS)
        self.assertEqual(s.state, ACTIVE)
        self.assertEqual(s.fsm.idle_hold, 0.0)
        self.assertIsNone(s.deadline(T_IDLE_HOLD))


class ConnectionPolicyTestCase(unittest.TestCase):
    """Who is allowed to open a connection, and when."""

    def test_passive_mode_listens_and_never_connects(self):
        # A passive peer that dials out is a configuration promise broken
        # in the one direction the operator was trying to prevent -- often
        # because the far end is behind a firewall that only permits
        # inbound.
        s = Session(passive=True)
        self.assertEqual(s.names(EV_MANUAL_START), ['listen-only'])
        self.assertEqual(s.state, ACTIVE)

    def test_passive_mode_still_never_connects_on_a_retry(self):
        # The retry path is a second place the decision is made, and the
        # obvious implementation of "retry" is to emit ``connect``.
        s = Session(passive=True, connect_retry=10)
        s.event(EV_MANUAL_START)
        for i in range(1, 4):
            fired, actions = s.tick_at(EPOCH + 10 * i)
            self.assertEqual(fired, 1)
            self.assertEqual(actions, [])
            self.assertEqual(s.state, ACTIVE)

    def test_an_inbound_connection_while_idle_is_refused(self):
        # Idle means we are deliberately not peering. Accepting here lets
        # a peer that keeps dialling override an administrative shutdown
        # or short-circuit a backoff imposed on purpose.
        s = Session()
        self.assertEqual(s.event(EV_TCP_CONFIRMED),
                         [('drop', 'connection refused: session is Idle')])
        self.assertEqual(s.state, IDLE)

    def test_a_shut_down_peer_cannot_be_revived_by_dialling(self):
        # The property the refusal exists for, stated end to end.
        s = Session()
        s.establish()
        s.event(EV_MANUAL_STOP)
        for _ in range(5):
            self.assertEqual(
                s.event(EV_TCP_CONFIRMED),
                [('drop', 'connection refused: session is Idle')])
            self.assertEqual(s.state, IDLE)

    def test_a_second_connection_to_an_established_peer_is_refused(self):
        # Collision resolution applies before a session is up, not after.
        # Tearing down a working session for a duplicate connection would
        # hand any peer a reset button.
        #
        # S-6: the answer is 'refuse' -- close the newcomer -- and never
        # 'drop', which the peer performs on the session's *own*
        # connection and which used to tear the working session down.
        s = Session()
        s.establish()
        self.assertEqual(
            s.event(EV_TCP_CR_ACKED),
            [('refuse', 'second connection to an established peer')])
        self.assertEqual(s.state, ESTABLISHED)

    def test_tcp_failure_in_open_sent_falls_back_to_active(self):
        # Not Idle. A connection failing before OPEN says nothing about
        # whether the peer wants to talk to us, and going to Idle would
        # stop us accepting the connection it is about to make.
        s = Session()
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_CR_ACKED)
        self.assertEqual(s.state, OPEN_SENT)
        actions = s.event(EV_TCP_FAILS)
        self.assertEqual(actions,
                         [('drop', 'connection closed before OPEN')])
        self.assertEqual(s.state, ACTIVE)
        self.assertEqual(s.fsm.idle_hold, 0.0)

    def test_tcp_failure_in_connect_falls_back_to_active(self):
        s = Session()
        s.event(EV_MANUAL_START)
        self.assertEqual(s.event(EV_TCP_FAILS), [])
        self.assertEqual(s.state, ACTIVE)


class DelayOpenTestCase(unittest.TestCase):
    """delay-open buys time for a collision to resolve before OPEN."""

    def test_a_connection_does_not_immediately_send_open(self):
        # The whole point: with delay-open set, a simultaneous open can be
        # resolved before either side has committed to an OPEN, which is
        # much cheaper than resolving it afterwards. Moving to OpenSent
        # here would also misreport the state -- nothing has been sent.
        s = Session(delay_open=5)
        s.event(EV_MANUAL_START)
        self.assertEqual(s.event(EV_TCP_CR_ACKED), [])
        self.assertEqual(s.state, CONNECT)
        self.assertEqual(s.fsm.timers(), {'delay-open': 5.0})

    def test_the_delay_open_timer_expiry_sends_open(self):
        s = Session(delay_open=5)
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_CR_ACKED)
        fired, actions = s.tick_at(EPOCH + 5)
        self.assertEqual((fired, actions), (1, [('send-open', None)]))
        self.assertEqual(s.state, OPEN_SENT)

    def test_an_open_during_the_delay_is_answered_immediately(self):
        # The peer got there first, so sitting on the remaining delay
        # would leave the far end's OpenSent hold timer ticking for no
        # reason. We answer and proceed in the same event.
        s = Session(delay_open=5)
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_CR_ACKED)
        s.clock.advance(1)
        actions = s.event(EV_BGP_OPEN, hold_time=90)
        self.assertEqual(actions, [('send-open', None),
                                   ('send-keepalive', None)])
        self.assertEqual(s.state, OPEN_CONFIRM)

    def test_an_answered_open_stops_the_delay_timer(self):
        # A surviving delay-open timer would fire in OpenConfirm and, in
        # a machine that handled it there, send a second OPEN.
        s = Session(delay_open=5)
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_CR_ACKED)
        s.event(EV_BGP_OPEN, hold_time=90)
        self.assertNotIn('delay-open', s.fsm.timers())
        self.assertEqual(s.tick_at(EPOCH + 5)[1], [])

    def test_delay_open_off_sends_open_at_once(self):
        # The default, asserted alongside so the two configurations are
        # visibly different rather than accidentally identical.
        s = Session(delay_open=0)
        s.event(EV_MANUAL_START)
        self.assertEqual(s.event(EV_TCP_CR_ACKED), [('send-open', None)])
        self.assertEqual(s.state, OPEN_SENT)


class ProtocolErrorTestCase(unittest.TestCase):
    """Violations the FSM itself is responsible for detecting."""

    def test_an_open_in_established_is_a_finite_state_machine_error(self):
        # The handshake happens once. A second OPEN means the peer has
        # lost track of the session, and RFC 4271 s8.2.2 calls for
        # NOTIFICATION code 5 rather than a quiet re-handshake, which
        # would leave the two ends disagreeing about what was negotiated.
        s = Session()
        s.establish()
        actions = s.event(EV_BGP_OPEN, hold_time=90)
        self.assertEqual(actions, [
            ('send-notify', (FSM_ERROR_CODE, 0, b'')),
            ('drop', 'OPEN received on an established session'),
            ('release', None),
        ])
        self.assertEqual(s.state, IDLE)

    def test_the_finite_state_machine_error_code_is_five(self):
        self.assertEqual(FSM_ERROR_CODE, 5)

    def test_an_administrative_stop_ceases_with_subcode_two(self):
        # Cease/Administrative Shutdown is what the far end needs to see
        # to stop retrying and to log something an operator can act on.
        s = Session()
        s.establish()
        actions = s.event(EV_MANUAL_STOP)
        self.assertEqual(actions[0],
                         ('send-notify',
                          (CEASE_CODE, errors.CEASE_ADMIN_SHUTDOWN, b'')))

    def test_a_stop_can_say_the_neighbour_was_deconfigured(self):
        # L-1: deleting a neighbour is Cease/Peer De-configured (RFC 4486
        # subcode 3), not Administrative Shutdown; the far end logs the
        # difference and an operator reading it learns what happened.
        s = Session()
        s.establish()
        actions = s.event(EV_MANUAL_STOP,
                          subcode=errors.CEASE_PEER_DECONFIGURED,
                          reason='neighbour removed')
        self.assertEqual(actions[0],
                         ('send-notify',
                          (CEASE_CODE, errors.CEASE_PEER_DECONFIGURED,
                           b'')))
        self.assertEqual(actions[1], ('drop', 'neighbour removed'))
        self.assertEqual(s.state, IDLE)

    def test_a_stop_while_idle_notifies_nobody(self):
        # There is no connection to send a NOTIFICATION on. Queuing one
        # would ask the caller to write to a socket that does not exist.
        s = Session()
        actions = s.event(EV_MANUAL_STOP)
        self.assertEqual([name for name, _ in actions], ['listen-only'])


class InspectionTestCase(unittest.TestCase):
    """What the scheduler and ``show`` read out of the machine."""

    def test_next_deadline_is_none_when_no_timer_runs(self):
        # The caller schedules its single wakeup from this. None has to
        # mean "nothing to wake for", not "wake immediately".
        s = Session()
        self.assertIsNone(s.fsm.next_deadline())
        s.establish()
        s.event(EV_HOLD_EXPIRED)
        s.event(EV_MANUAL_STOP)
        self.assertIsNone(s.fsm.next_deadline())

    def test_next_deadline_is_the_earliest_of_several(self):
        # One wakeup per peer instead of one per timer is the reason this
        # exists; returning anything but the minimum oversleeps a timer.
        s = Session(hold_time=90, keepalive=10)
        s.establish()
        self.assertEqual(s.fsm.next_deadline(), EPOCH + 10)
        s.tick_at(EPOCH + 10)
        self.assertEqual(s.fsm.next_deadline(), EPOCH + 20)
        s.clock.now = EPOCH + 15
        s.event(EV_KEEPALIVE_MSG)
        self.assertEqual(s.fsm.next_deadline(), EPOCH + 20)

    def test_timers_omit_what_is_not_running(self):
        # "Not running" and "fires now" are very different and an operator
        # reading ``show ip bgp neighbors`` has to be able to tell them
        # apart; a zero for a stopped timer conflates them.
        s = Session()
        self.assertEqual(s.fsm.timers(), {})
        s.event(EV_MANUAL_START)
        self.assertEqual(sorted(s.fsm.timers()), ['connect-retry'])
        s.establish()
        self.assertEqual(sorted(s.fsm.timers()), ['hold', 'keepalive'])

    def test_stats_is_json_serialisable(self):
        # These go out as events and over an HTTP health endpoint. A
        # bytes value or a tuple key here is an exception in a monitoring
        # path, discovered at three in the morning.
        s = Session()
        s.establish()
        encoded = json.dumps(s.fsm.stats(), sort_keys=True)
        self.assertEqual(json.loads(encoded)['state'], ESTABLISHED)

    def test_stats_counts_states_transitions_and_establishments(self):
        # Four transitions for one handshake, one establishment. The
        # established count is how an operator distinguishes a session
        # that has been up for an hour from one that has flapped fifty
        # times in that hour, so it must not be a boolean in disguise.
        s = Session()
        s.establish()
        stats = s.fsm.stats()
        self.assertEqual(stats['state'], ESTABLISHED)
        self.assertEqual(stats['transitions'], 4)
        self.assertEqual(stats['established-count'], 1)
        s.event(EV_HOLD_EXPIRED)
        stats = s.fsm.stats()
        self.assertEqual(stats['state'], IDLE)
        self.assertEqual(stats['transitions'], 5)
        self.assertEqual(stats['established-count'], 1)
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_CR_ACKED)
        s.event(EV_BGP_OPEN, hold_time=90)
        s.event(EV_KEEPALIVE_MSG)
        self.assertEqual(s.fsm.stats()['established-count'], 2)

    def test_stats_counts_the_events_it_saw(self):
        # The first question about a misbehaving session is always "which
        # event did it see"; a per-event counter is the cheapest answer.
        s = Session()
        s.establish()
        s.event(EV_KEEPALIVE_MSG)
        self.assertEqual(s.fsm.stats()['event-KeepaliveMsg'], 2)
        self.assertEqual(s.fsm.stats()['event-ManualStart'], 1)

    def test_the_fsm_never_reads_a_clock_the_test_did_not_set(self):
        # The design claim of the module, asserted directly: with the
        # clock frozen, a full handshake leaves every deadline expressed
        # against that instant and state-duration at exactly zero.
        s = Session()
        s.establish()
        self.assertEqual(s.fsm.stats()['state-duration'], 0.0)
        self.assertEqual(s.fsm.stats()['uptime'], 0.0)
        self.assertEqual(min(s.fsm._deadlines.values()), EPOCH + 30)


class FsmConfigTestCase(unittest.TestCase):
    """Configuration is the boundary where a bad timer is still cheap."""

    def test_a_hold_time_of_one_or_two_is_rejected(self):
        # RFC 4271 s4.2 allows 0 or 3 and above. Clamping 1 to 3 would
        # hide a misunderstanding from the operator who typed it; there is
        # no reading of "1" that this software can honour.
        for hold in (1, 2):
            with self.assertRaises(ValueError):
                FsmConfig(hold_time=hold)

    def test_zero_and_three_are_both_accepted(self):
        # The two legal boundaries either side of the rejected range.
        self.assertEqual(FsmConfig(hold_time=0).keepalive, 0)
        self.assertEqual(FsmConfig(hold_time=3).keepalive, 1)

    def test_a_keepalive_at_or_above_the_hold_time_is_rejected(self):
        # The far end would time us out before we ever spoke. Equal is
        # just as broken as greater and is the value somebody reaches for
        # when they want "keepalive as often as possible".
        for keepalive in (30, 31, 90):
            with self.assertRaises(ValueError):
                FsmConfig(hold_time=30, keepalive=keepalive)

    def test_the_keepalive_defaults_to_a_third_of_the_hold_time(self):
        # RFC 4271 s10, which leaves room for two lost keepalives before
        # the far end gives up.
        self.assertEqual(FsmConfig(hold_time=90).keepalive, 30)
        self.assertEqual(FsmConfig(hold_time=30).keepalive, 10)

    def test_a_zero_hold_time_forces_a_zero_keepalive(self):
        # Timers off means both timers off; a keepalive with no hold timer
        # is chatter that can never detect anything.
        self.assertEqual(FsmConfig(hold_time=0).keepalive, 0)
        self.assertEqual(FsmConfig(hold_time=0, keepalive=10).keepalive, 10)


class AbandonConnectionTestCase(unittest.TestCase):
    """S-1: losing a collision steps back without ending the session."""

    def _open_confirm(self):
        s = Session()
        s.event(EV_MANUAL_START)
        s.event(EV_TCP_CR_ACKED)
        s.event(EV_BGP_OPEN, hold_time=90, router_id=0x02020202,
                peer_as=65001)
        self.assertEqual(s.state, OPEN_CONFIRM)
        return s

    def test_abandoning_returns_to_active_without_drop_or_release(self):
        # The caller closes the losing connection itself (with Cease/7);
        # the machine must not ask it to drop the session's connection or
        # to release routes that were never learned.
        s = self._open_confirm()
        self.assertTrue(s.fsm.abandon_connection('lost the collision'))
        self.assertEqual(s.fsm.take_actions(), [])
        self.assertEqual(s.state, ACTIVE)
        self.assertIsNone(s.deadline(T_HOLD))
        self.assertIsNone(s.deadline(T_KEEPALIVE))
        self.assertIsNotNone(s.deadline(T_CONNECT_RETRY))

    def test_the_winning_connection_then_runs_a_fresh_handshake(self):
        s = self._open_confirm()
        s.fsm.abandon_connection('lost the collision')
        self.assertEqual(s.names(EV_TCP_CONNECTION_VALID), ['send-open'])
        self.assertEqual(s.state, OPEN_SENT)
        self.assertIsNone(s.deadline(T_CONNECT_RETRY))

    def test_an_established_session_is_never_abandoned(self):
        s = Session()
        s.establish()
        self.assertFalse(s.fsm.abandon_connection('nope'))
        self.assertEqual(s.state, ESTABLISHED)

    def test_abandoning_does_not_charge_the_backoff(self):
        s = self._open_confirm()
        s.fsm.abandon_connection('lost the collision')
        self.assertEqual(s.fsm.idle_hold, 0.0)


class CollisionResolutionTestCase(unittest.TestCase):
    """RFC 4271 s6.8, the function that exists to prevent a livelock."""

    LOCAL_AS = 65000
    PEER_AS = 65001

    def _verdict(self, local_id, peer_id, we_initiated,
                 local_as=None, peer_as=None):
        return resolve_collision(
            local_id, peer_id,
            self.LOCAL_AS if local_as is None else local_as,
            self.PEER_AS if peer_as is None else peer_as,
            we_initiated)

    def test_a_higher_local_id_keeps_the_connection_it_initiated(self):
        # The rule itself: the higher BGP identifier keeps its own
        # outbound connection and refuses the inbound one.
        self.assertTrue(self._verdict(0x20202020, 0x10101010, True))
        self.assertFalse(self._verdict(0x20202020, 0x10101010, False))

    def test_a_lower_local_id_keeps_the_inbound_connection(self):
        # Exactly the mirror image, which is what makes the two ends agree
        # without exchanging anything beyond their identifiers.
        self.assertFalse(self._verdict(0x10101010, 0x20202020, True))
        self.assertTrue(self._verdict(0x10101010, 0x20202020, False))

    def test_identifiers_are_compared_as_unsigned_integers(self):
        # A router id with the top bit set is common (any address from
        # 128.0.0.0 up) and would lose every collision to a small id if
        # the comparison were ever signed.
        self.assertTrue(self._verdict(0xc0a80001, 0x0a000001, True))
        self.assertFalse(self._verdict(0x0a000001, 0xc0a80001, True))

    def test_equal_identifiers_fall_back_to_the_as_numbers(self):
        # RFC 6286 s2.3. Equal identifiers happen in practice when a
        # device is cloned without its router id being changed, and
        # without this the collision is simply unresolvable.
        same = 0x0a000001
        self.assertTrue(self._verdict(same, same, True,
                                      local_as=65100, peer_as=65000))
        self.assertFalse(self._verdict(same, same, False,
                                       local_as=65100, peer_as=65000))
        self.assertFalse(self._verdict(same, same, True,
                                       local_as=65000, peer_as=65100))
        self.assertTrue(self._verdict(same, same, False,
                                      local_as=65000, peer_as=65100))

    def test_an_identical_identifier_and_as_refuses_both(self):
        # The peer is almost certainly ourselves, reached through a loop
        # in the configuration. Keeping either connection would peer the
        # router with itself and feed its own routes back to it.
        same = 0x0a000001
        self.assertFalse(self._verdict(same, same, True,
                                       local_as=65000, peer_as=65000))
        self.assertFalse(self._verdict(same, same, False,
                                       local_as=65000, peer_as=65000))

    def test_the_two_ends_reach_opposite_conclusions_about_their_own(self):
        # The livelock guard, stated as the property it protects. Run the
        # same collision from both sides: if both speakers conclude "drop
        # the one I opened" they collide again immediately, which in the
        # field looks like a flapping peer rather than a tie-break bug --
        # and if both conclude "keep mine" the session runs over two
        # connections and one of them is never read.
        pairs = ((0x0a000001, 0x0a000002), (0x0a000002, 0x0a000001),
                 (0x00000000, 0xffffffff), (0xffffffff, 0x00000000),
                 (0x7fffffff, 0x80000000), (0xc0a80101, 0x0a0a0a0a))
        for a_id, b_id in pairs:
            a_keeps_own = resolve_collision(a_id, b_id, 65000, 65001, True)
            b_keeps_own = resolve_collision(b_id, a_id, 65001, 65000, True)
            self.assertNotEqual(
                a_keeps_own, b_keeps_own,
                'both ends agreed about their own connection for '
                '%08x/%08x' % (a_id, b_id))

    def test_the_two_ends_agree_about_each_individual_connection(self):
        # The other half of the same property, and the one that actually
        # makes the survivor unambiguous: for either of the two
        # connections, the speaker that opened it and the speaker that
        # received it must reach the *same* verdict on it.
        pairs = ((0x0a000001, 0x0a000002), (0x00000000, 0xffffffff),
                 (0x7fffffff, 0x80000000), (0xc0a80101, 0x0a0a0a0a))
        for a_id, b_id in pairs:
            # The connection A opened, judged by A then by B.
            a_view = resolve_collision(a_id, b_id, 65000, 65001, True)
            b_view = resolve_collision(b_id, a_id, 65001, 65000, False)
            self.assertEqual(a_view, b_view)
            # The connection B opened, judged by B then by A.
            b_own = resolve_collision(b_id, a_id, 65001, 65000, True)
            a_on_b = resolve_collision(a_id, b_id, 65000, 65001, False)
            self.assertEqual(b_own, a_on_b)
            # And exactly one of the two connections lives.
            self.assertEqual([a_view, b_own].count(True), 1)

    def test_every_combination_of_inputs_is_decided(self):
        # Exhaustive over the shape of the inputs rather than their
        # values: an identifier lower, higher or equal, crossed with an
        # AS lower, higher or equal, crossed with both roles. The answer
        # must be a bool in every cell -- a None or a raised exception in
        # any of them is a connection nobody closes.
        ids = (0x0a000001, 0x0a000002, 0x0a000003)
        ases = (65000, 65001, 65002)
        for local_id in ids:
            for peer_id in ids:
                for local_as in ases:
                    for peer_as in ases:
                        for initiated in (True, False):
                            verdict = resolve_collision(
                                local_id, peer_id, local_as, peer_as,
                                initiated)
                            self.assertIsInstance(verdict, bool)
                            if local_id == peer_id and local_as == peer_as:
                                self.assertFalse(verdict)
                            else:
                                other = resolve_collision(
                                    local_id, peer_id, local_as, peer_as,
                                    not initiated)
                                self.assertNotEqual(verdict, other)


if __name__ == '__main__':
    unittest.main()
