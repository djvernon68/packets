#!/usr/bin/env python

"""Tests for the rtengine control plane: Engine, config model, plugins, show.

``test_rtengine_rib.py`` covers the data structures -- ``Prefix``, ``Trie``,
``Route``/``Dest``/``RouteTable`` in isolation. This module covers everything
built on top of them, and it is shaped around the five promises the engine
actually makes rather than around the source layout:

  * **One thread owns everything mutable.** The engine's whole concurrency
    story is "there are exactly two doors": direct calls from the loop
    thread, and :meth:`Engine.submit` from anywhere else. So the lifecycle
    tests assert on ``threading.enumerate()`` rather than on ``is_running()``
    alone -- an engine that reports itself stopped while its loop thread is
    still alive would pass a naive test and hang the suite on the 3.6 host --
    and the submission tests assert which thread a callable actually ran on.

  * **A submitted command cancelled before it starts never runs.** That is
    what makes a timed-out REST request safe, and it is the one behaviour
    here that a timing-based test would verify by accident and then fail
    intermittently. It is tested by blocking the loop on a
    ``threading.Event``, cancelling the queued victim, and then draining the
    queue with a barrier command: because ``call_soon_threadsafe`` is FIFO,
    the barrier completing proves the victim's callback has already been
    dealt with. No sleeps, no wall-clock assumptions, and the assertion is
    on a side-effect list.

  * **A configuration change is atomic, or it never happened.** Every
    rejection path -- schema, semantic, plugin ``prepare_config``, plugin
    ``commit_config`` -- is asserted to leave the running document *and* the
    revision exactly where they were, because a half-applied routing
    configuration is the failure this design exists to prevent. The commit
    path additionally checks the contents of the inverse diff handed back to
    a plugin that had already committed: "rolled back" is a claim, and the
    only way to know it is true is to look at what the plugin was told.

  * **Secrets do not come back out.** Redaction and the ``"<redacted>"``
    keep-sentinel are tested as a round trip, because the property that
    matters is not "the API hides the key" but "a client can read the whole
    document, edit one unrelated field, PUT it back, and neither learn the
    key nor destroy it".

  * **Selection publishes once, to the sink and to the bus.** The routing
    tests drive the engine the way a plugin does -- offer, select, read the
    sink and the show output -- so they pin the seam between the RIB and the
    operational surface rather than re-testing the RIB.

Written as plain ``unittest.TestCase`` with no pytest features and no syntax
newer than Python 3.6.8: the verification host has no pytest and runs this
through ``python3 -m unittest discover -s test``. Every engine is created
through :meth:`EngineFixture.make_engine`, which registers its own cleanup, so
that a failing assertion cannot leave a loop thread behind -- a leaked engine
thread does not fail one test, it hangs the whole run.

One known failure is left in deliberately. See
``PluginLifecycleTestCase.test_plugin_stop_runs_on_the_loop_thread``.
"""

import logging
import threading
import time
import unittest
from unittest import mock

from packets.routing.rtengine import ApplyError, ConfigError, ConflictError, \
    Engine, PreconditionFailed, ProtocolPlugin, RtEngineError, \
    UnavailableError
from packets.routing.rtengine import events as EV
from packets.routing.rtengine.config import MISSING, REDACTED, ConfigStore
from packets.routing.rtengine.fib import netlink
from packets.routing.rtengine.fib.sink import FibSink, NullSink
from packets.routing.rtengine.loop import new_loop
from packets.routing.rtengine.plugins import registry
from packets.routing.rtengine.rib import table as T
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, parse_prefix

# A next-hop the engine never has to resolve, used wherever the test is about
# something other than the next-hop itself.
NH_V4 = b'\x0a\x00\x00\x01'
NH_V4_ALT = b'\x0a\x00\x00\x02'
NH_V6 = parse_prefix('2001:db8::1').packed()


def _netlink_capabilities(supported, privileged=True):
    """Pin what the FIB factory believes this host can do.

    The factory asks ``netlink.capabilities()`` whenever ``install`` is
    turned on, and the real answer differs between the Mac and a root
    shell on cnp02; a test about the engine's reaction must not depend on
    which of them runs it -- nor, on the second, open a socket into the
    main table.
    """
    return mock.patch.object(netlink, 'capabilities', return_value={
        'supported': supported, 'privileged': supported and privileged,
        'reason': 'pinned by the test', 'platform': 'test', 'euid': -1})


def _route(prefix_text, protocol=T.PROTO_BGP, distance=20, metric=0,
           nexthop=NH_V4, source=None):
    """A Route with every selection input pinned.

    ``recv_time`` is fixed rather than "now" so the age tie-break can never
    decide a test that is about administrative distance or about the sink,
    and ``source`` defaults to a fresh object so two calls are two distinct
    origins unless a test deliberately shares one.
    """
    if source is None:
        source = object()
    return T.Route(parse_prefix(prefix_text), protocol, distance, metric,
                   nexthop, source, 100.0)


class WritingSink(FibSink):
    """A sink that claims to write, so ``ip.route.install`` is permitted.

    It writes nothing. The only thing under test where a writing sink is
    needed is the semantic check in ``_prepare_core``, which asks the sink
    whether it writes and never asks it to.
    """

    name = 'writing-test-sink'
    writes = True


class RecordingPlugin(ProtocolPlugin):
    """A plugin that records what the engine did to it, and can refuse.

    Built as one configurable class rather than a family of subclasses
    because every plugin test wants the same record -- which calls arrived,
    in which order, with which diff -- and differs only in which call is
    rigged to fail.
    """

    def __init__(self, name='recording', section=('router', 'recording'),
                 schema=None, afi_safi=(), protocol_id=T.PROTO_BGP):
        ProtocolPlugin.__init__(self)
        self.name = name
        self.config_section = section
        self.protocol_id = protocol_id
        self._schema = schema
        self._afi_safi = tuple(afi_safi)
        self.prepared = []
        self.committed = []
        self.starts = []
        self.stops = []
        self.health_doc = {'status': 'ok'}
        # Each of these turns one engine-driven call into a failure. Kept as
        # attributes rather than constructor arguments so a test can arm the
        # failure after an earlier successful change has established a
        # baseline document to roll back to.
        self.fail_prepare = False
        self.fail_commit = False
        self.fail_rollback = False
        self.fail_stop = False
        self.raise_health = False

    def afi_safi(self):
        return self._afi_safi

    def config_schema(self):
        return self._schema

    def prepare_config(self, section, diff):
        if self.fail_prepare:
            raise ConfigError('%s refuses this change' % (self.name,),
                              path='.'.join(self.config_section))
        self.prepared.append((section, diff.as_list()))

    def commit_config(self, section, diff):
        if self.fail_commit:
            raise RuntimeError('%s commit exploded' % (self.name,))
        if self.fail_rollback and self.committed:
            # Only the second call -- the rollback -- fails, which is the
            # case that makes ApplyError.rolled_back false.
            raise RuntimeError('%s rollback exploded' % (self.name,))
        self.committed.append((section, diff.as_list()))

    def start(self, engine):
        ProtocolPlugin.start(self, engine)
        self.starts.append(threading.get_ident())

    def stop(self):
        self.stops.append(threading.get_ident())
        ProtocolPlugin.stop(self)
        if self.fail_stop:
            raise RuntimeError('%s stop exploded' % (self.name,))

    def show_handlers(self):
        return {
            ('ip', self.name, 'summary'): self._show_summary,
            ('ip', self.name, 'neighbors'): self._show_neighbors,
        }

    def clear_handlers(self):
        return {('ip', self.name): self._clear}

    def health(self):
        if self.raise_health:
            raise RuntimeError('%s cannot report health' % (self.name,))
        return self.health_doc

    def _show_summary(self, *args, **kwargs):
        return {'what': 'summary', 'args': list(args), 'kwargs': kwargs}

    def _show_neighbors(self, *args, **kwargs):
        return {'what': 'neighbors', 'args': list(args), 'kwargs': kwargs}

    def _clear(self, *args, **kwargs):
        return {'what': 'clear', 'args': list(args), 'kwargs': kwargs}


#: A plugin section schema with one of every node kind the tests need: a
#: bounded int, a secret, an address, and a keyed collection with a limit.
PLUGIN_SCHEMA = {
    'type': 'dict',
    'key_type': 'asn',
    'max_keys': 1,
    'value': {
        'type': 'dict',
        'keys': {
            'router-id': {'type': 'addr'},
            'hold-time': {'type': 'int', 'min': 3, 'max': 65535},
            'password': {'type': 'secret', 'minlen': 4},
        },
    },
}

#: A flat plugin section, for the atomicity tests where two plugins must be
#: changed by one document and the diff has to be readable in an assertion.
FLAT_SCHEMA = {'type': 'dict', 'keys': {'v': {'type': 'int', 'min': 0,
                                              'max': 100}}}


class EngineFixture(unittest.TestCase):
    """Base fixture: every engine and every loop a test makes is torn down.

    A leaked engine thread is worse than a failing test. The suite runs in
    one process, the loop thread is a daemon, and an engine nobody stopped
    keeps servicing a dead test's callbacks -- and holds its sink and its
    subscriptions -- for the rest of the run. So engines and loops are only
    created through these helpers, which register cleanup *before* handing
    the object back, and therefore clean up even when the test fails between
    construction and the end of the method.

    Cleanups run last-registered-first, which is why a loop meant for
    ``Engine(loop=...)`` must be created before the engine: the engine's
    ``stop()`` then runs before the loop is closed, not after.
    """

    def make_engine(self, **kwargs):
        """Construct an engine that is guaranteed to be stopped afterwards.

        ``stop()`` on an engine that was never started, or that a test
        already stopped, returns False and does nothing, so registering it
        unconditionally is safe.
        """
        engine = Engine(**kwargs)
        self.addCleanup(engine.stop)
        return engine

    def start_engine(self, **kwargs):
        """Construct and start an engine, with cleanup registered."""
        return self.make_engine(**kwargs).start()

    def make_loop(self):
        """Create a loop this test owns and must close."""
        loop = new_loop()
        self.addCleanup(self._close_loop, loop)
        return loop

    @staticmethod
    def _close_loop(loop):
        if not loop.is_closed():
            loop.close()

    def wait_until(self, predicate, what, timeout=5.0):
        """Poll until a predicate holds, failing with a useful message.

        The timeout is deliberately generous. These waits exist to
        synchronise with another thread, not to measure it: a test that
        fails because a loaded machine needed 200 ms instead of 20 ms is
        testing the machine.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(0.002)
        self.fail('%s did not happen within %.1f seconds' % (what, timeout))

    def loop_ident(self, engine):
        """Return the thread id of a running engine's loop thread."""
        return engine.submit(threading.get_ident).result(5)

    def quiet_engine_log(self):
        """Suppress the engine's own log for a deliberately failing path.

        The engine logs a full traceback when a plugin's commit, rollback or
        stop raises, which is correct behaviour and is what the test is
        provoking. Left alone it prints that traceback to stderr in the
        middle of an otherwise green run, where it reads as a failure. The
        assertions here are on the engine's *return* -- the ApplyError, the
        counters -- so the log carries no information the test needs.
        """
        logger = logging.getLogger('packets.rtengine.engine')
        previous = logger.level
        logger.setLevel(logging.CRITICAL)
        self.addCleanup(logger.setLevel, previous)

    def assertUnchanged(self, engine, revision, document):
        """Assert a rejected change moved neither the revision nor the doc.

        Every rejection path in the engine promises this, and asserting it
        once per path is the only way to know that a rejection discovered
        late -- in a plugin, or in the semantic pass -- is as clean as one
        discovered by the schema.
        """
        self.assertEqual(engine.revision, revision)
        self.assertEqual(engine.running_config(redact=False), document)


class EngineLifecycleTestCase(EngineFixture):
    """Construct, start, stop, restart -- and leave no thread behind."""

    def test_a_new_engine_is_not_running(self):
        engine = self.make_engine()
        self.assertFalse(engine.is_running())
        self.assertIsNone(engine.loop)

    def test_a_new_engine_is_at_revision_zero(self):
        self.assertEqual(self.make_engine().revision, 0)
        self.assertEqual(self.make_engine().running_config(), {})

    def test_start_returns_self_so_it_chains(self):
        engine = self.make_engine()
        self.assertIs(engine.start(), engine)
        self.assertTrue(engine.is_running())
        self.assertIsNotNone(engine.loop)

    def test_stop_returns_true_once_and_false_afterwards(self):
        engine = self.start_engine()
        self.assertTrue(engine.stop())
        # Idempotent: a signal handler and an atexit hook may both call it,
        # and the second caller must not get an error or a second teardown.
        self.assertFalse(engine.stop())
        self.assertFalse(engine.stop())

    def test_stop_on_an_engine_that_never_started_returns_false(self):
        self.assertFalse(self.make_engine().stop())

    def test_is_running_is_false_after_stop(self):
        engine = self.start_engine()
        engine.stop()
        self.assertFalse(engine.is_running())
        self.assertIsNone(engine.loop)

    def test_double_start_raises(self):
        engine = self.start_engine()
        with self.assertRaises(RtEngineError) as caught:
            engine.start()
        self.assertIn('already running', str(caught.exception))
        # The failed second start must not have disturbed the first.
        self.assertTrue(engine.is_running())

    def test_the_loop_thread_is_gone_after_stop(self):
        # is_running() going false is the engine's own bookkeeping; this is
        # the thing that actually matters, because a daemon thread left
        # behind hangs a full suite run rather than failing one test.
        engine = self.start_engine(name='lifecycle-probe')
        self.assertIn('lifecycle-probe', self._thread_names())
        engine.stop()
        self.assertNotIn('lifecycle-probe', self._thread_names())

    def test_stop_joins_the_loop_thread_before_returning(self):
        engine = self.start_engine(name='join-probe')
        engine.stop()
        # No wait_until here on purpose: stop() promises the thread is gone
        # when it returns, not shortly afterwards.
        self.assertNotIn('join-probe', self._thread_names())

    def test_start_stop_start_runs_on_a_fresh_loop(self):
        engine = self.start_engine()
        first = engine.loop
        engine.stop()
        engine.start()
        self.assertTrue(engine.is_running())
        self.assertIsNot(engine.loop, first)
        self.assertTrue(first.is_closed())
        self.assertEqual(engine.submit(lambda: 'alive').result(5), 'alive')

    def test_restart_keeps_the_configuration_and_the_revision(self):
        engine = self.make_engine()
        engine.configure(('ip', 'route', 'table'), 300)
        engine.start()
        engine.stop()
        engine.start()
        self.assertEqual(engine.revision, 1)
        self.assertEqual(engine.running_config()['ip']['route']['table'], 300)

    def test_in_loop_is_false_from_another_thread(self):
        engine = self.start_engine()
        self.assertFalse(engine.in_loop())

    def test_in_loop_is_true_on_the_loop_thread(self):
        engine = self.start_engine()
        self.assertTrue(engine.submit(engine.in_loop).result(5))

    def test_in_loop_is_false_when_the_engine_is_down(self):
        engine = self.make_engine()
        self.assertFalse(engine.in_loop())

    def test_status_describes_a_stopped_engine(self):
        engine = self.make_engine(name='status-probe')
        status = engine.status()
        self.assertEqual(status['name'], 'status-probe')
        self.assertFalse(status['running'])
        self.assertEqual(status['revision'], 0)
        self.assertEqual(status['plugins'], [])
        # The shipped default: a control-plane speaker with a sink that
        # accounts for routes and writes nothing.
        self.assertEqual(status['fib'], {'sink': 'null', 'writes': False})
        self.assertEqual(status['tables'], ['1/1', '2/1'])
        self.assertEqual(status['api']['bind'], '127.0.0.1:8179')
        self.assertTrue(status['version'])

    def test_status_reports_running_once_started(self):
        engine = self.start_engine()
        self.assertTrue(engine.status()['running'])

    def test_repr_names_the_engine_and_its_state(self):
        engine = self.make_engine(name='repr-probe')
        text = repr(engine)
        self.assertIn('repr-probe', text)
        self.assertIn('running=False', text)
        self.assertIn('plugins=none', text)

    def test_run_forever_runs_on_the_calling_thread_until_stopped(self):
        engine = Engine(name='forever-probe')
        thread = threading.Thread(target=engine.run_forever,
                                  name='forever-driver')
        self.addCleanup(self._teardown_run_forever, engine, thread)
        thread.start()
        # is_running() is set before the loop actually starts spinning, and
        # stop() can only reach a loop that is running -- so wait for the
        # loop itself, not for the flag, or the stop below can be lost and
        # the driver thread never returns.
        self.wait_until(
            lambda: engine.loop is not None and engine.loop.is_running(),
            'the run_forever loop starting')
        self.assertTrue(engine.is_running())
        self.assertEqual(engine.submit(lambda: 7).result(5), 7)

        self.assertTrue(engine.stop())
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(engine.is_running())
        # E-6: a loop run_forever created is its own to clean up, exactly
        # as start()'s is -- shut down, closed and dropped. It used to be
        # left open, leaking its selector and destroying its unfinished
        # tasks pending at interpreter exit.
        self.assertIsNone(engine.loop)

    def test_run_forever_leaves_a_loop_it_was_given_open(self):
        loop = self.make_loop()
        engine = Engine(name='forever-given', loop=loop)
        thread = threading.Thread(target=engine.run_forever,
                                  name='forever-given-driver')
        self.addCleanup(self._teardown_run_forever, engine, thread)
        thread.start()
        self.wait_until(lambda: loop.is_running(),
                        'the run_forever loop starting')
        self.assertTrue(engine.stop())
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertIs(engine.loop, loop)
        self.assertFalse(loop.is_closed())

    def test_run_forever_on_a_running_engine_raises(self):
        engine = self.start_engine()
        with self.assertRaises(RtEngineError):
            engine.run_forever()

    def test_attach_brings_up_an_engine_on_a_loop_it_does_not_own(self):
        loop = self.make_loop()
        engine = self.make_engine(loop=loop)
        self.assertIs(engine.attach(), engine)
        self.assertTrue(engine.is_running())
        self.assertIs(engine.loop, loop)
        # attach() was called from this thread, so this thread is the loop
        # thread as far as the engine is concerned and direct calls are
        # legal -- which is the whole point of the embedded path.
        self.assertTrue(engine.in_loop())
        self.assertEqual(engine.configure(('ip', 'route', 'table'), 42), 1)

    def test_attach_does_not_close_the_loop_it_was_given(self):
        loop = self.make_loop()
        engine = self.make_engine(loop=loop)
        engine.attach()
        self.assertTrue(engine.stop())
        # The loop belongs to the embedding application; the engine closing
        # it on stop would take out that application's other work.
        self.assertFalse(loop.is_closed())

    def test_start_on_an_engine_with_an_external_loop_raises(self):
        loop = self.make_loop()
        engine = self.make_engine(loop=loop)
        with self.assertRaises(RtEngineError) as caught:
            engine.start()
        self.assertIn('attach', str(caught.exception))
        self.assertFalse(engine.is_running())

    def test_start_is_still_refused_after_attach_and_stop(self):
        loop = self.make_loop()
        engine = self.make_engine(loop=loop)
        engine.attach()
        engine.stop()
        with self.assertRaises(RtEngineError):
            engine.start()

    def test_attach_without_a_loop_raises(self):
        engine = self.make_engine()
        with self.assertRaises(RtEngineError) as caught:
            engine.attach()
        self.assertIn('no loop', str(caught.exception))

    def test_attach_twice_raises(self):
        loop = self.make_loop()
        engine = self.make_engine(loop=loop)
        engine.attach()
        with self.assertRaises(RtEngineError):
            engine.attach()

    @staticmethod
    def _thread_names():
        return [t.name for t in threading.enumerate()]

    def _teardown_run_forever(self, engine, thread):
        engine.stop()
        thread.join(5)
        loop = engine.loop
        if loop is not None and not loop.is_closed():
            loop.close()


class CommandSubmissionTestCase(EngineFixture):
    """``submit`` is the only door in from another thread."""

    def test_submit_returns_the_result(self):
        engine = self.start_engine()
        self.assertEqual(engine.submit(lambda: 41 + 1).result(5), 42)

    def test_submit_passes_positional_and_keyword_arguments(self):
        engine = self.start_engine()
        future = engine.submit(lambda a, b, c=0: (a, b, c), 1, 2, c=3)
        self.assertEqual(future.result(5), (1, 2, 3))

    def test_an_exception_inside_the_callable_surfaces_through_the_future(
            self):
        engine = self.start_engine()

        def boom():
            raise ValueError('deliberate')

        future = engine.submit(boom)
        with self.assertRaises(ValueError) as caught:
            future.result(5)
        self.assertEqual(str(caught.exception), 'deliberate')
        # The engine must survive a command that raised: the exception
        # belongs to the caller, not to the loop.
        self.assertTrue(engine.is_running())
        self.assertEqual(engine.submit(lambda: 'still here').result(5),
                         'still here')

    def test_a_base_exception_inside_the_callable_also_surfaces(self):
        engine = self.start_engine()

        def boom():
            raise KeyboardInterrupt('deliberate')

        with self.assertRaises(KeyboardInterrupt):
            engine.submit(boom).result(5)
        self.assertTrue(engine.is_running())

    def test_submit_before_start_raises_unavailable(self):
        engine = self.make_engine()
        with self.assertRaises(UnavailableError):
            engine.submit(lambda: 1)

    def test_submit_on_a_stopped_engine_raises_unavailable(self):
        engine = self.start_engine()
        engine.stop()
        with self.assertRaises(UnavailableError) as caught:
            engine.submit(lambda: 1)
        self.assertEqual(caught.exception.as_dict()['error'], 'Unavailable')

    def test_submitted_callables_run_on_the_loop_thread(self):
        engine = self.start_engine()
        self.assertNotEqual(self.loop_ident(engine), threading.get_ident())

    def test_command_depth_counts_queued_work(self):
        engine = self.start_engine()
        self.assertEqual(engine.command_depth(), 0)
        with self._blocked_loop(engine) as release:
            engine.submit(lambda: None)
            engine.submit(lambda: None)
            # The blocker is already running, so it is off the queue; the
            # two behind it are not.
            self.assertEqual(engine.command_depth(), 2)
            release()
        self.wait_until(lambda: engine.command_depth() == 0,
                        'the command queue draining')

    def test_commands_run_in_submission_order(self):
        engine = self.start_engine()
        order = []
        futures = [engine.submit(order.append, n) for n in range(10)]
        for future in futures:
            future.result(5)
        self.assertEqual(order, list(range(10)))

    def test_a_command_cancelled_before_it_starts_never_runs(self):
        # The critical one. A REST request that timed out cancels its
        # future, and the change it asked for must either have happened
        # before the timeout or never happen at all -- not land seconds
        # later with nobody watching.
        #
        # Asserted on a side-effect list, never on timing: the loop is held
        # by a blocker waiting on an Event, so the victim is provably still
        # queued when it is cancelled, and a barrier command submitted
        # afterwards proves the victim's callback has already been dealt
        # with, because call_soon_threadsafe delivers in order.
        engine = self.start_engine()
        ran = []
        with self._blocked_loop(engine) as release:
            victim = engine.submit(ran.append, 'victim')
            self.assertTrue(victim.cancel())
            barrier = engine.submit(lambda: 'barrier')
            release()
            self.assertEqual(barrier.result(5), 'barrier')

        self.assertEqual(ran, [])
        self.assertTrue(victim.cancelled())

    def test_cancelling_several_queued_commands_runs_none_of_them(self):
        engine = self.start_engine()
        ran = []
        with self._blocked_loop(engine) as release:
            victims = [engine.submit(ran.append, n) for n in range(5)]
            survivor = engine.submit(ran.append, 'survivor')
            for victim in victims:
                self.assertTrue(victim.cancel())
            release()
            survivor.result(5)

        self.assertEqual(ran, ['survivor'])
        self.assertTrue(all(v.cancelled() for v in victims))
        # A cancelled command still came off the depth counter, or a
        # cancelling client would inflate the queue-depth health metric
        # forever.
        self.wait_until(lambda: engine.command_depth() == 0,
                        'cancelled commands leaving the depth counter')

    def test_a_command_already_running_completes(self):
        # Cancelling a command that has started is refused rather than
        # honoured: it is already half-applied, and finishing atomically is
        # the only honest option.
        engine = self.start_engine()
        with self._blocked_loop(engine) as release:
            blocker = self._blocker_future
            self.assertFalse(blocker.cancel())
            self.assertTrue(blocker.running())
            release()
        self.assertEqual(blocker.result(5), 'blocked')
        self.assertFalse(blocker.cancelled())

    def _blocked_loop(self, engine):
        """Hold the loop thread until the test lets it go.

        Returns a context manager yielding the release callable. The loop is
        genuinely blocked inside a submitted command, which is the only way
        to get a deterministic "this work is queued and has not started"
        state without depending on how fast the machine is.
        """
        fixture = self

        class _Blocked(object):
            def __enter__(self):
                self.entered = threading.Event()
                self.release = threading.Event()
                fixture._blocker_future = engine.submit(self._block)
                # Do not return until the blocker owns the loop, or the
                # commands submitted next might run before it.
                self.assertion = self.entered.wait(5)
                fixture.assertTrue(self.assertion,
                                   'the blocker never reached the loop')
                return self.release.set

            def _block(self):
                self.entered.set()
                self.release.wait(5)
                return 'blocked'

            def __exit__(self, *exc_info):
                self.release.set()
                return False

        return _Blocked()


class ConfigurationTestCase(EngineFixture):
    """Revisions, schema rejection, pruning and optimistic concurrency."""

    def setUp(self):
        self.engine = self.make_engine()

    def test_configure_returns_a_rising_revision(self):
        self.assertEqual(self.engine.configure(('ip', 'route', 'table'),
                                               300), 1)
        self.assertEqual(self.engine.configure(('ip', 'route', 'protocol'),
                                               200), 2)
        self.assertEqual(self.engine.revision, 2)

    def test_a_no_op_change_does_not_advance_the_revision(self):
        # A client polling for changes would otherwise see churn that did
        # not happen, and an ETag would move without the document moving.
        self.assertEqual(self.engine.configure(('ip', 'route', 'table'),
                                               300), 1)
        self.assertEqual(self.engine.configure(('ip', 'route', 'table'),
                                               300), 1)
        self.assertEqual(self.engine.revision, 1)

    def test_rewriting_a_whole_subtree_identically_is_a_no_op(self):
        body = {'next-hop': '10.0.0.254', 'metric': 7}
        self.engine.configure(('ip', 'route', 'static', '10.0.0.0/24'), body)
        revision = self.engine.revision
        self.engine.configure(('ip', 'route', 'static'),
                              {'10.0.0.0/24': dict(body)})
        self.assertEqual(self.engine.revision, revision)

    def test_a_dotted_string_path_is_accepted(self):
        self.assertEqual(self.engine.configure('ip.route.table', 300), 1)
        self.assertEqual(self.engine.running_config()['ip']['route']['table'],
                         300)

    def test_an_empty_path_is_refused(self):
        for path in ((), [], '', '...'):
            with self.assertRaises(ConfigError):
                self.engine.configure(path, 1)

    def test_a_path_that_is_neither_tuple_nor_string_is_refused(self):
        with self.assertRaises(ConfigError) as caught:
            self.engine.configure(7, 1)
        self.assertIn('dotted string', str(caught.exception))

    def test_running_config_is_a_copy(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        document = self.engine.running_config()
        document['ip']['route']['table'] = 999
        document['injected'] = True
        self.assertEqual(self.engine.running_config()['ip']['route']['table'],
                         300)
        self.assertNotIn('injected', self.engine.running_config())

    def test_configure_from_the_loop_thread_takes_the_direct_route(self):
        engine = self.start_engine()
        revision = engine.submit(engine.configure, ('ip', 'route', 'table'),
                                 300).result(5)
        self.assertEqual(revision, 1)
        self.assertEqual(engine.revision, 1)

    def test_store_value_falls_back_to_the_schema_default(self):
        # Defaults are resolved on read rather than written into the
        # document, so running-config shows what was configured and not the
        # hundred things that were not.
        store = self.engine.store
        self.assertEqual(store.value(('ip', 'route', 'protocol')), 190)
        self.assertEqual(store.value(('ip', 'route', 'table')), 254)
        self.assertIs(store.value(('ip', 'route', 'install')), False)
        self.assertIs(store.value(('ip', 'route', 'validate-next-hop')),
                      False)
        self.assertEqual(store.value(('api', 'max-page')), 10000)
        self.assertEqual(self.engine.running_config(), {})

    def test_store_value_prefers_a_configured_value(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        self.assertEqual(self.engine.store.value(('ip', 'route', 'table')),
                         300)

    def test_store_value_returns_the_callers_default_when_nothing_knows(self):
        self.assertIsNone(self.engine.store.value(('api', 'tls', 'cert')))
        self.assertEqual(self.engine.store.value(('api', 'tls', 'cert'),
                                                 'none'), 'none')
        self.assertEqual(self.engine.store.value(('no', 'such', 'path'), -1),
                         -1)

    def test_a_wrong_type_is_refused(self):
        self._refused(('ip', 'route', 'table'), 'three', 'integer')

    def test_an_unknown_key_is_refused(self):
        self._refused(('ip', 'route', 'nope'), 1, 'unknown key')

    def test_an_unknown_top_level_section_is_refused(self):
        self._refused(('nonsense',), {}, 'unknown key')

    def test_an_unknown_router_section_is_refused(self):
        # router has a fixed, initially empty key set, so with no plugins
        # registered every protocol section is unknown. That is the right
        # answer rather than an oversight: the legal configuration is
        # exactly the registered plugins' vocabulary.
        self._refused(('router', 'bgp'), {}, 'unknown key')

    def test_an_int_below_the_minimum_is_refused(self):
        self._refused(('ip', 'route', 'protocol'), 0, 'at least 1')

    def test_an_int_above_the_maximum_is_refused(self):
        self._refused(('api', 'max-page'), 1000001, 'at most 1000000')

    def test_a_bool_where_an_int_is_wanted_is_refused(self):
        # bool is a subclass of int in Python, so an int check that did not
        # exclude it would accept True as a routing table number.
        self._refused(('ip', 'route', 'table'), True, 'integer')

    def test_an_int_where_a_bool_is_wanted_is_refused(self):
        self._refused(('ip', 'route', 'retain-on-shutdown'), 1,
                      'true or false')
        self._refused(('ip', 'route', 'validate-next-hop'), 0,
                      'true or false')

    def test_a_bad_prefix_key_is_refused(self):
        self._refused(('ip', 'route', 'static'),
                      {'10.0.0.0/33': {'next-hop': '10.0.0.1'}},
                      'prefix length')

    def test_a_bad_name_key_is_refused(self):
        self._refused(('ip', 'prefix-list', 'bad name'), [], 'valid name')
        self._refused(('route-map', '-leading-dash'), [], 'valid name')

    def test_a_valid_name_key_is_accepted(self):
        self.assertEqual(
            self.engine.configure(('ip', 'prefix-list', 'allow-rfc1918'),
                                  [{'action': 'permit',
                                    'prefix': '10.0.0.0/8'}]), 1)

    def test_a_missing_required_key_is_refused(self):
        self._refused(('ip', 'prefix-list', 'broken'),
                      [{'prefix': '10.0.0.0/8'}], 'required')

    def test_a_bad_choice_is_refused(self):
        self._refused(('ip', 'prefix-list', 'broken'),
                      [{'action': 'maybe', 'prefix': '10.0.0.0/8'}],
                      'must be one of')

    def test_a_scalar_where_a_list_is_wanted_is_refused(self):
        self._refused(('ip', 'prefix-list', 'broken'), {}, 'expected a list')

    def test_a_scalar_where_an_object_is_wanted_is_refused(self):
        self._refused(('ip', 'route'), 7, 'expected an object')

    def test_a_prefix_where_a_bare_address_is_wanted_is_refused(self):
        self._refused(('ip', 'route', 'static'),
                      {'10.0.0.0/24': {'next-hop': '10.0.0.0/24'}},
                      'bare address')

    def test_setting_a_path_through_a_scalar_is_refused(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        revision = self.engine.revision
        with self.assertRaises(ConfigError) as caught:
            self.engine.configure(('ip', 'route', 'table', 'deeper'), 1)
        self.assertIn('not a section', str(caught.exception))
        self.assertEqual(self.engine.revision, revision)

    def test_unconfigure_prunes_the_sections_it_empties(self):
        # Pruning is what makes two documents that mean the same thing
        # compare equal, which the diff depends on.
        self.assertEqual(self.engine.configure(('ip', 'route', 'table'),
                                               300), 1)
        self.assertEqual(self.engine.unconfigure(('ip', 'route', 'table')), 2)
        self.assertNotIn('ip', self.engine.running_config())
        self.assertEqual(self.engine.running_config(), {})

    def test_unconfigure_keeps_a_section_that_still_has_keys(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        self.engine.configure(('ip', 'route', 'protocol'), 200)
        self.engine.unconfigure(('ip', 'route', 'table'))
        self.assertEqual(self.engine.running_config(),
                         {'ip': {'route': {'protocol': 200}}})

    def test_unconfigure_removes_a_whole_subtree(self):
        self.engine.configure(('ip', 'route', 'static', '10.0.0.0/24'),
                              {'next-hop': '10.0.0.254'})
        self.engine.configure(('ip', 'route', 'static', '10.1.0.0/24'),
                              {'next-hop': '10.0.0.254'})
        self.engine.unconfigure(('ip', 'route', 'static'))
        self.assertEqual(self.engine.running_config(), {})

    def test_unconfigure_of_an_absent_path_raises(self):
        with self.assertRaises(ConfigError) as caught:
            self.engine.unconfigure(('ip', 'route', 'table'))
        self.assertIn('nothing configured', str(caught.exception))
        self.assertEqual(self.engine.revision, 0)

    def test_unconfigure_twice_raises_the_second_time(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        self.engine.unconfigure(('ip', 'route', 'table'))
        revision = self.engine.revision
        with self.assertRaises(ConfigError):
            self.engine.unconfigure(('ip', 'route', 'table'))
        self.assertEqual(self.engine.revision, revision)

    def test_a_stale_if_revision_raises_and_reports_the_real_revision(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        self.engine.configure(('ip', 'route', 'protocol'), 200)
        with self.assertRaises(PreconditionFailed) as caught:
            self.engine.configure(('ip', 'route', 'table'), 400,
                                  if_revision=1)
        body = caught.exception.as_dict()
        self.assertEqual(body['expected'], 1)
        # The caller needs the real revision to re-read and retry, so it is
        # in the error body rather than only in the log.
        self.assertEqual(body['revision'], 2)
        self.assertEqual(body['error'], 'PreconditionFailed')
        self.assertEqual(self.engine.revision, 2)
        self.assertEqual(self.engine.running_config()['ip']['route']['table'],
                         300)

    def test_a_matching_if_revision_applies(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        self.assertEqual(self.engine.configure(('ip', 'route', 'table'), 400,
                                               if_revision=1), 2)

    def test_if_revision_accepts_a_numeric_string(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        self.assertEqual(self.engine.configure(('ip', 'route', 'table'), 400,
                                               if_revision='1'), 2)

    def test_unconfigure_honours_if_revision(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        with self.assertRaises(PreconditionFailed):
            self.engine.unconfigure(('ip', 'route', 'table'), if_revision=0)
        self.assertEqual(self.engine.unconfigure(('ip', 'route', 'table'),
                                                 if_revision=1), 2)

    def test_replace_config_honours_if_revision(self):
        with self.assertRaises(PreconditionFailed):
            self.engine.replace_config({}, if_revision=5)

    def test_replace_config_swaps_the_whole_document(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        revision = self.engine.replace_config(
            {'api': {'max-page': 500}})
        self.assertEqual(revision, 2)
        self.assertEqual(self.engine.running_config(),
                         {'api': {'max-page': 500}})

    def test_replace_config_with_an_empty_document_clears_everything(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        self.engine.replace_config({})
        self.assertEqual(self.engine.running_config(), {})

    def test_replace_config_with_none_clears_everything(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        self.engine.replace_config(None)
        self.assertEqual(self.engine.running_config(), {})

    def test_replace_config_rejects_a_non_object(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        revision = self.engine.revision
        with self.assertRaises(ConfigError) as caught:
            self.engine.replace_config([1, 2, 3])
        self.assertIn('must be an object', str(caught.exception))
        self.assertEqual(self.engine.revision, revision)

    def test_an_invalid_replacement_changes_nothing(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        before = self.engine.running_config(redact=False)
        with self.assertRaises(ConfigError):
            self.engine.replace_config({'ip': {'route': {'table': 'three'}}})
        self.assertUnchanged(self.engine, 1, before)

    def test_replace_config_is_a_no_op_when_the_document_matches(self):
        self.engine.configure(('ip', 'route', 'table'), 300)
        revision = self.engine.revision
        self.assertEqual(
            self.engine.replace_config(
                self.engine.running_config(redact=False)), revision)

    def _refused(self, path, value, fragment):
        """Assert one schema rejection and that it moved nothing."""
        before = self.engine.running_config(redact=False)
        revision = self.engine.revision
        with self.assertRaises(ConfigError) as caught:
            self.engine.configure(path, value)
        self.assertIn(fragment, str(caught.exception))
        # Every rejection carries the dotted location of the offending
        # value, which is what the API turns into a usable 400.
        self.assertIsNotNone(caught.exception.as_dict()['path'])
        self.assertUnchanged(self.engine, revision, before)


class CoreSemanticChecksTestCase(EngineFixture):
    """``_prepare_core``: what the schema cannot say, checked before apply."""

    def test_install_with_an_injected_non_writing_sink_is_a_conflict(self):
        # L-6: an injected sink wins and is never replaced, so asking it to
        # install when it cannot is a conflict with how the engine was
        # built (409), not a malformed document.
        engine = self.make_engine(sink=NullSink())
        with self.assertRaises(ConflictError) as caught:
            engine.configure(('ip', 'route', 'install'), True)
        self.assertIn('forwarding sink', str(caught.exception))
        self.assertEqual(caught.exception.as_dict()['path'],
                         'ip.route.install')
        self.assertEqual(engine.revision, 0)

    def test_install_where_the_host_cannot_is_refused(self):
        # L-6: with no injected sink the engine builds its own, and the
        # host is what decides. Pinned to "unsupported" so the answer does
        # not depend on which machine runs the test.
        engine = self.make_engine()
        with _netlink_capabilities(supported=False):
            with self.assertRaises(ConfigError) as caught:
                engine.configure(('ip', 'route', 'install'), True)
        self.assertIn('not available on this host', str(caught.exception))
        self.assertEqual(caught.exception.as_dict()['path'],
                         'ip.route.install')
        self.assertEqual(engine.revision, 0)
        self.assertEqual(engine.sink.name, 'null')

    def test_install_without_cap_net_admin_is_refused(self):
        engine = self.make_engine()
        with _netlink_capabilities(supported=True, privileged=False):
            with self.assertRaises(ConfigError) as caught:
                engine.configure(('ip', 'route', 'install'), True)
        self.assertIn('CAP_NET_ADMIN', str(caught.exception))
        self.assertEqual(engine.revision, 0)

    def test_install_is_accepted_when_the_sink_writes(self):
        engine = self.make_engine(sink=WritingSink())
        self.assertEqual(engine.configure(('ip', 'route', 'install'), True), 1)
        self.assertTrue(engine.status()['fib']['writes'])

    def test_install_false_is_always_accepted(self):
        engine = self.make_engine()
        self.assertEqual(engine.configure(('ip', 'route', 'install'), False),
                         1)

    def test_an_initial_document_asking_to_install_fails_at_construction(
            self):
        # Better at construction than at start: a configuration that could
        # never work should not survive long enough to look started.
        with _netlink_capabilities(supported=False):
            with self.assertRaises(ConfigError):
                Engine(config={'ip': {'route': {'install': True}}})

    def test_a_v4_static_route_with_a_v6_next_hop_is_refused(self):
        engine = self.make_engine()
        with self.assertRaises(ConfigError) as caught:
            engine.configure(('ip', 'route', 'static'),
                             {'10.0.0.0/24': {'next-hop': '2001:db8::1'}})
        self.assertIn('address family', str(caught.exception))
        self.assertEqual(engine.revision, 0)

    def test_a_v6_static_route_with_a_v4_next_hop_is_refused(self):
        engine = self.make_engine()
        with self.assertRaises(ConfigError):
            engine.configure(('ipv6', 'route', 'static'),
                             {'2001:db8::/32': {'next-hop': '10.0.0.1'}})
        self.assertEqual(engine.revision, 0)

    def test_a_same_family_static_route_is_accepted_in_both_families(self):
        engine = self.make_engine()
        self.assertEqual(
            engine.configure(('ip', 'route', 'static'),
                             {'10.0.0.0/24': {'next-hop': '10.0.0.254'}}), 1)
        self.assertEqual(
            engine.configure(('ipv6', 'route', 'static'),
                             {'2001:db8::/32': {'next-hop': '2001:db8::1'}}),
            2)

    def test_binding_the_api_off_host_without_auth_is_refused(self):
        engine = self.make_engine()
        with self.assertRaises(ConfigError) as caught:
            engine.configure(('api', 'bind'), '0.0.0.0:8179')
        self.assertIn('api.auth', str(caught.exception))
        self.assertEqual(caught.exception.as_dict()['path'], 'api.bind')
        self.assertEqual(engine.revision, 0)

    def test_binding_the_api_off_host_is_allowed_with_insecure(self):
        engine = self.make_engine()
        self.assertEqual(engine.configure(('api', 'insecure'), True), 1)
        self.assertEqual(engine.configure(('api', 'bind'), '0.0.0.0:8179'), 2)

    def test_binding_the_api_off_host_is_allowed_with_a_token(self):
        engine = self.make_engine()
        engine.configure(('api', 'auth', 'token'), 'k' * 24)
        self.assertEqual(engine.configure(('api', 'bind'), '0.0.0.0:8179'), 2)

    def test_binding_the_api_off_host_is_allowed_with_a_token_file(self):
        engine = self.make_engine()
        engine.configure(('api', 'auth', 'token-file'),
                         '/etc/rtengine/api.token')
        self.assertEqual(engine.configure(('api', 'bind'), '0.0.0.0:8179'), 2)

    def test_an_empty_auth_section_does_not_count_as_auth(self):
        engine = self.make_engine()
        engine.configure(('api', 'auth', 'allow-unauthenticated-health'),
                         True)
        # The section exists but holds no credential, which is exactly the
        # case a truthiness test on the section alone would get wrong.
        with self.assertRaises(ConfigError):
            engine.configure(('api', 'bind'), '0.0.0.0:8179')

    def test_binding_the_api_to_loopback_needs_no_auth(self):
        for bind in ('127.0.0.1:8179', 'localhost:8179', '[::1]:8179'):
            engine = self.make_engine()
            self.assertEqual(engine.configure(('api', 'bind'), bind), 1,
                             'refused loopback bind %r' % (bind,))

    def test_an_empty_bind_is_not_checked(self):
        engine = self.make_engine()
        self.assertEqual(engine.configure(('api', 'bind'), ''), 1)

    def test_removing_auth_from_under_an_off_host_bind_is_refused(self):
        # The semantic pass runs against the whole proposed document, not
        # against the change, so it catches a deletion that invalidates a
        # setting made earlier.
        engine = self.make_engine(config={
            'api': {'bind': '0.0.0.0:8179', 'auth': {'token': 'k' * 24}}})
        revision = engine.revision
        with self.assertRaises(ConfigError):
            engine.unconfigure(('api', 'auth', 'token'))
        self.assertEqual(engine.revision, revision)
        self.assertEqual(engine.running_config(redact=False)['api']['auth'],
                         {'token': 'k' * 24})


class SecretRedactionTestCase(EngineFixture):
    """Secrets are redacted on the way out and kept on the way back in."""

    def setUp(self):
        self.engine = self.make_engine()
        self.token = 'topsecrettoken12345'
        self.engine.configure(('api', 'auth', 'token'), self.token)

    def test_a_secret_is_redacted_in_running_config(self):
        self.assertEqual(
            self.engine.running_config()['api']['auth']['token'], REDACTED)

    def test_running_config_without_redaction_returns_the_secret(self):
        self.assertEqual(
            self.engine.running_config(redact=False)['api']['auth']['token'],
            self.token)

    def test_redaction_does_not_damage_the_stored_document(self):
        self.engine.running_config()
        self.engine.running_config()
        self.assertEqual(
            self.engine.running_config(redact=False)['api']['auth']['token'],
            self.token)

    def test_a_redacted_document_round_trips_without_losing_the_secret(self):
        # The property that matters: read the whole document, change one
        # unrelated field, put it back, and neither learn the key nor
        # destroy it.
        document = self.engine.running_config()
        document['api']['max-page'] = 500
        self.engine.replace_config(document)
        self.assertEqual(
            self.engine.running_config(redact=False)['api']['auth']['token'],
            self.token)
        self.assertEqual(self.engine.running_config()['api']['max-page'], 500)

    def test_writing_the_sentinel_directly_keeps_the_stored_value(self):
        revision = self.engine.revision
        # Identical after resolution, so it is a no-op and must not move the
        # revision either.
        self.assertEqual(
            self.engine.configure(('api', 'auth', 'token'), REDACTED),
            revision)
        self.assertEqual(
            self.engine.running_config(redact=False)['api']['auth']['token'],
            self.token)

    def test_the_sentinel_is_refused_when_nothing_is_stored(self):
        engine = self.make_engine()
        with self.assertRaises(ConfigError) as caught:
            engine.configure(('api', 'auth', 'token'), REDACTED)
        self.assertIn('no stored value to keep', str(caught.exception))
        self.assertEqual(engine.revision, 0)

    def test_the_sentinel_bypasses_the_minimum_length(self):
        # '<redacted>' is shorter than the 16 characters a token needs, and
        # the length check has to let it through or a redacted document
        # could never be written back.
        self.assertLess(len(REDACTED), 16)
        document = self.engine.running_config()
        self.engine.replace_config(document)

    def test_a_short_secret_is_refused(self):
        with self.assertRaises(ConfigError) as caught:
            self.engine.configure(('api', 'auth', 'token'), 'short')
        self.assertIn('at least 16 characters', str(caught.exception))

    def test_a_non_string_secret_is_refused(self):
        with self.assertRaises(ConfigError):
            self.engine.configure(('api', 'auth', 'token'), 12345678901234567)

    def test_a_plugin_secret_is_redacted_through_its_own_schema(self):
        # Redaction walks the schema rather than guessing from key names, so
        # a plugin's secret is covered the moment its schema is grafted in.
        plugin = RecordingPlugin(name='reds', section=('router', 'reds'),
                                 schema=PLUGIN_SCHEMA)
        engine = self.make_engine(plugins=[plugin])
        engine.configure(('router', 'reds', '65000'),
                         {'router-id': '10.0.0.1', 'password': 'sekrit'})
        document = engine.running_config()
        self.assertEqual(document['router']['reds']['65000']['password'],
                         REDACTED)
        self.assertEqual(document['router']['reds']['65000']['router-id'],
                         '10.0.0.1')
        self.assertEqual(
            engine.running_config(
                redact=False)['router']['reds']['65000']['password'],
            'sekrit')

    def test_a_plugin_secret_round_trips_through_a_redacted_document(self):
        plugin = RecordingPlugin(name='reds', section=('router', 'reds'),
                                 schema=PLUGIN_SCHEMA)
        engine = self.make_engine(plugins=[plugin])
        engine.configure(('router', 'reds', '65000'),
                         {'router-id': '10.0.0.1', 'password': 'sekrit'})
        document = engine.running_config()
        document['router']['reds']['65000']['router-id'] = '10.0.0.2'
        engine.replace_config(document)
        stored = engine.running_config(redact=False)['router']['reds']['65000']
        self.assertEqual(stored['password'], 'sekrit')
        self.assertEqual(stored['router-id'], '10.0.0.2')

    def test_redacted_copy_redacts_a_fragment_from_outside_the_store(self):
        fragment = {'api': {'auth': {'token': 'another-long-token-value'}}}
        copied = self.engine.store.redacted_copy(fragment)
        self.assertEqual(copied['api']['auth']['token'], REDACTED)
        # A copy: the caller's fragment is left alone, which matters when it
        # is about to be used for something other than logging.
        self.assertEqual(fragment['api']['auth']['token'],
                         'another-long-token-value')


class PluginRegistrationTestCase(EngineFixture):
    """What may register, what may not, and what registration wires up."""

    def test_a_plugin_instance_registers(self):
        plugin = RecordingPlugin()
        engine = self.make_engine(plugins=[plugin])
        self.assertIs(engine.plugin('recording'), plugin)
        self.assertEqual(engine.plugins(), [plugin])

    def test_a_plugin_class_is_instantiated_on_registration(self):
        class Simple(ProtocolPlugin):
            name = 'simple'

        engine = self.make_engine(plugins=[Simple])
        found = engine.plugin('simple')
        self.assertIsInstance(found, Simple)

    def test_register_plugin_returns_the_instance(self):
        engine = self.make_engine()
        plugin = RecordingPlugin()
        self.assertIs(engine.register_plugin(plugin), plugin)

    def test_plugins_returns_a_copy_in_registration_order(self):
        first = RecordingPlugin(name='first', section=('router', 'first'))
        second = RecordingPlugin(name='second', section=('router', 'second'))
        engine = self.make_engine(plugins=[first, second])
        listed = engine.plugins()
        self.assertEqual(listed, [first, second])
        listed.append('junk')
        self.assertEqual(len(engine.plugins()), 2)

    def test_an_unknown_plugin_name_returns_none(self):
        self.assertIsNone(self.make_engine().plugin('nope'))

    def test_a_non_plugin_is_refused(self):
        engine = self.make_engine()
        for candidate in (object(), 42, 'bgp', {'name': 'bgp'}):
            with self.assertRaises(ValueError) as caught:
                engine.register_plugin(candidate)
            self.assertIn('not a ProtocolPlugin', str(caught.exception))
        self.assertEqual(engine.plugins(), [])

    def test_a_plugin_without_a_name_is_refused(self):
        class Nameless(ProtocolPlugin):
            config_section = ('router', 'nameless')

        engine = self.make_engine()
        with self.assertRaises(ValueError) as caught:
            engine.register_plugin(Nameless)
        self.assertIn('must set a name', str(caught.exception))
        self.assertEqual(engine.plugins(), [])

    def test_a_plugin_whose_section_is_not_a_tuple_is_refused(self):
        class Stringly(ProtocolPlugin):
            name = 'stringly'
            config_section = 'router.stringly'

        with self.assertRaises(ValueError) as caught:
            self.make_engine().register_plugin(Stringly)
        self.assertIn('must be a tuple', str(caught.exception))

    def test_a_plugin_with_a_malformed_afi_safi_is_refused(self):
        class Malformed(ProtocolPlugin):
            name = 'malformed'

            def afi_safi(self):
                return ((AFI_IP,),)

        with self.assertRaises(ValueError) as caught:
            self.make_engine().register_plugin(Malformed)
        self.assertIn('(afi, safi) pairs', str(caught.exception))

    def test_a_duplicate_name_is_refused_and_does_not_register(self):
        engine = self.make_engine(plugins=[RecordingPlugin()])
        with self.assertRaises(ValueError) as caught:
            engine.register_plugin(RecordingPlugin())
        self.assertIn('already registered', str(caught.exception))
        self.assertEqual(len(engine.plugins()), 1)

    def test_two_plugins_claiming_one_section_are_refused(self):
        # Two owners would make a configuration diff ambiguous, so it is
        # refused at registration rather than becoming a race at apply.
        first = RecordingPlugin(name='first', section=('router', 'shared'),
                                schema=FLAT_SCHEMA)
        second = RecordingPlugin(name='second', section=('router', 'shared'),
                                 schema=FLAT_SCHEMA)
        engine = self.make_engine(plugins=[first])
        with self.assertRaises(ValueError) as caught:
            engine.register_plugin(second)
        self.assertIn('already claimed', str(caught.exception))
        # The rejected plugin is not half-registered: the section schema
        # still belongs to the first one and only it is listed.
        self.assertEqual(engine.plugins(), [first])
        engine.configure(('router', 'shared', 'v'), 1)
        self.assertEqual(len(first.committed), 1)
        self.assertEqual(second.committed, [])

    def test_a_section_the_core_owns_cannot_be_claimed(self):
        clash = RecordingPlugin(name='clash', section=('ip', 'route'),
                                schema=FLAT_SCHEMA)
        with self.assertRaises(ValueError) as caught:
            self.make_engine(plugins=[clash])
        self.assertIn('already claimed', str(caught.exception))

    def test_a_section_under_a_keyed_collection_cannot_be_claimed(self):
        # route-map is a keyed collection, not a fixed-key section, so there
        # is nowhere to graft a schema into it.
        clash = RecordingPlugin(name='clash',
                                section=('route-map', 'mine', 'deeper'),
                                schema=FLAT_SCHEMA)
        with self.assertRaises(ValueError):
            self.make_engine(plugins=[clash])

    def test_a_section_with_no_parent_cannot_be_claimed(self):
        clash = RecordingPlugin(name='clash', section=('nowhere', 'mine'),
                                schema=FLAT_SCHEMA)
        with self.assertRaises(ValueError) as caught:
            self.make_engine(plugins=[clash])
        self.assertIn('no schema section', str(caught.exception))

    def test_a_plugin_with_no_section_registers_and_grafts_nothing(self):
        plugin = RecordingPlugin(name='sectionless', section=())
        engine = self.make_engine(plugins=[plugin])
        self.assertIs(engine.plugin('sectionless'), plugin)
        self.assertEqual(engine.configure(('ip', 'route', 'table'), 300), 1)
        # Never consulted, because it owns nothing a diff can touch.
        self.assertEqual(plugin.prepared, [])
        self.assertEqual(plugin.committed, [])

    def test_a_plugin_with_no_schema_gets_an_open_section(self):
        # The escape hatch for a plugin that has not declared its
        # vocabulary yet: anything validates there, and nothing else moves.
        plugin = RecordingPlugin(name='open', section=('router', 'open'),
                                 schema=None)
        engine = self.make_engine(plugins=[plugin])
        engine.configure(('router', 'open'),
                         {'whatever': [1, 2, {'nested': True}]})
        self.assertEqual(engine.running_config()['router']['open'],
                         {'whatever': [1, 2, {'nested': True}]})

    def test_afi_safi_creates_the_tables_the_plugin_asks_for(self):
        plugin = RecordingPlugin(name='families',
                                 section=('router', 'families'),
                                 schema=FLAT_SCHEMA,
                                 afi_safi=((AFI_IP, 1), (AFI_IP, 2)))
        engine = self.make_engine(plugins=[plugin])
        # 1/1 and 2/1 exist by default; 1/2 is the one the plugin added.
        self.assertEqual(engine.status()['tables'], ['1/1', '1/2', '2/1'])
        self.assertIsNotNone(engine.global_rib.table(AFI_IP, 2))

    def test_a_plugin_asking_for_an_unknown_family_is_refused(self):
        plugin = RecordingPlugin(name='alien', section=('router', 'alien'),
                                 schema=FLAT_SCHEMA, afi_safi=((999, 1),))
        with self.assertRaises(ValueError):
            self.make_engine(plugins=[plugin])

    def test_registering_a_plugin_while_running_starts_it(self):
        engine = self.start_engine()
        plugin = RecordingPlugin(name='late', section=('router', 'late'),
                                 schema=FLAT_SCHEMA)
        engine.register_plugin(plugin)
        self.assertEqual(len(plugin.starts), 1)
        self.assertEqual(plugin.starts, [self.loop_ident(engine)])
        self.assertIs(plugin.engine, engine)
        # Its show handlers are live immediately, not at the next restart.
        self.assertEqual(engine.show('ip', 'late', 'summary')['what'],
                         'summary')


class PluginConfigurationTestCase(EngineFixture):
    """Two-phase apply: everybody validates, then everybody commits."""

    def test_a_plugin_schema_is_grafted_and_its_section_validates(self):
        engine = self.make_engine(plugins=[
            RecordingPlugin(name='graft', section=('router', 'graft'),
                            schema=PLUGIN_SCHEMA)])
        self.assertEqual(
            engine.configure(('router', 'graft', '65000'),
                             {'router-id': '10.0.0.1', 'hold-time': 90}), 1)
        self.assertEqual(
            engine.running_config()['router']['graft']['65000']['hold-time'],
            90)

    def test_an_unknown_key_inside_a_plugin_section_is_refused(self):
        engine = self.make_engine(plugins=[
            RecordingPlugin(name='graft', section=('router', 'graft'),
                            schema=PLUGIN_SCHEMA)])
        with self.assertRaises(ConfigError) as caught:
            engine.configure(('router', 'graft', '65000'),
                             {'nonsense': True})
        self.assertIn('unknown key', str(caught.exception))
        self.assertEqual(engine.revision, 0)

    def test_a_bad_key_type_inside_a_plugin_section_is_refused(self):
        engine = self.make_engine(plugins=[
            RecordingPlugin(name='graft', section=('router', 'graft'),
                            schema=PLUGIN_SCHEMA)])
        for bad in ('not-a-number', '0', '4294967296'):
            with self.assertRaises(ConfigError):
                engine.configure(('router', 'graft', bad),
                                 {'router-id': '10.0.0.1'})

    def test_an_out_of_range_value_inside_a_plugin_section_is_refused(self):
        engine = self.make_engine(plugins=[
            RecordingPlugin(name='graft', section=('router', 'graft'),
                            schema=PLUGIN_SCHEMA)])
        with self.assertRaises(ConfigError) as caught:
            engine.configure(('router', 'graft', '65000'), {'hold-time': 1})
        self.assertEqual(caught.exception.as_dict()['path'],
                         'router.graft.65000.hold-time')

    def test_max_keys_raises_conflict_rather_than_invalid(self):
        # The document is well formed; it collides with a stated limit. The
        # API turns that into 409 and not 400, so the distinction is part
        # of the contract rather than an implementation detail.
        engine = self.make_engine(plugins=[
            RecordingPlugin(name='graft', section=('router', 'graft'),
                            schema=PLUGIN_SCHEMA)])
        engine.configure(('router', 'graft', '65000'),
                         {'router-id': '10.0.0.1'})
        with self.assertRaises(ConflictError) as caught:
            engine.configure(('router', 'graft', '65001'),
                             {'router-id': '10.0.0.2'})
        self.assertNotIsInstance(caught.exception, ConfigError)
        self.assertEqual(caught.exception.as_dict()['error'], 'Conflict')
        self.assertEqual(caught.exception.as_dict()['path'], 'router.graft')
        self.assertEqual(engine.revision, 1)

    def test_prepare_config_sees_the_proposed_section_and_its_diff(self):
        plugin = RecordingPlugin(name='graft', section=('router', 'graft'),
                                 schema=FLAT_SCHEMA)
        engine = self.make_engine(plugins=[plugin])
        engine.configure(('router', 'graft', 'v'), 5)
        self.assertEqual(len(plugin.prepared), 1)
        section, changes = plugin.prepared[0]
        self.assertEqual(section, {'v': 5})
        self.assertEqual(changes, [{'path': 'router', 'new': {'graft':
                                                              {'v': 5}}}])
        self.assertEqual(plugin.committed[0][0], {'v': 5})

    def test_a_plugin_whose_section_is_untouched_is_not_consulted(self):
        touched = RecordingPlugin(name='touched',
                                  section=('router', 'touched'),
                                  schema=FLAT_SCHEMA)
        quiet = RecordingPlugin(name='quiet', section=('router', 'quiet'),
                                schema=FLAT_SCHEMA)
        engine = self.make_engine(plugins=[touched, quiet])
        # The baseline matters. On an empty document the first change
        # creates the whole ``router`` object, and that change sits *above*
        # both sections -- so both plugins are consulted, correctly. Only
        # once ``router`` exists is a change to one section reported at its
        # own path and the other plugin genuinely left alone.
        engine.replace_config({'router': {'touched': {'v': 1},
                                          'quiet': {'v': 1}}})
        self.assertEqual(len(quiet.committed), 1)

        engine.configure(('router', 'touched', 'v'), 2)
        engine.configure(('router', 'touched', 'v'), 3)
        self.assertEqual(len(touched.committed), 3)
        self.assertEqual(len(quiet.prepared), 1)
        self.assertEqual(len(quiet.committed), 1)

    def test_a_change_above_a_plugins_section_still_reaches_it(self):
        # Replacing the whole ``router`` object changes router.graft too,
        # and a plugin that only matched its own prefix would miss it.
        plugin = RecordingPlugin(name='graft', section=('router', 'graft'),
                                 schema=FLAT_SCHEMA)
        engine = self.make_engine(plugins=[plugin])
        engine.replace_config({'router': {'graft': {'v': 9}}})
        self.assertEqual(len(plugin.committed), 1)
        self.assertEqual(plugin.committed[0][1],
                         [{'path': 'router', 'new': {'graft': {'v': 9}}}])

    def test_a_prepare_rejection_leaves_everything_untouched(self):
        accepting, refusing, engine = self._pair()
        engine.replace_config({'router': {'alpha': {'v': 1},
                                          'beta': {'v': 1}}})
        before = engine.running_config(redact=False)
        revision = engine.revision
        committed = len(accepting.committed)

        refusing.fail_prepare = True
        with self.assertRaises(ConfigError) as caught:
            engine.replace_config({'router': {'alpha': {'v': 2},
                                              'beta': {'v': 2}}})
        self.assertIn('refuses this change', str(caught.exception))

        self.assertUnchanged(engine, revision, before)
        # And the other plugin was asked to validate but never to apply,
        # which is the whole reason prepare and commit are separate calls.
        self.assertEqual(len(accepting.committed), committed)
        self.assertEqual(len(accepting.prepared), 2)

    def test_a_commit_failure_rolls_the_earlier_plugin_back(self):
        accepting, failing, engine = self._pair()
        engine.replace_config({'router': {'alpha': {'v': 1},
                                          'beta': {'v': 1}}})
        before = engine.running_config(redact=False)
        revision = engine.revision
        self.assertEqual(len(accepting.committed), 1)

        failing.fail_commit = True
        with self.assertRaises(ApplyError) as caught:
            engine.replace_config({'router': {'alpha': {'v': 2},
                                              'beta': {'v': 2}}})
        body = caught.exception.as_dict()
        self.assertEqual(body['error'], 'ApplyFailed')
        self.assertTrue(body['rolled_back'])
        # The failing plugin is named, which is the only way an operator
        # can tell which protocol refused.
        self.assertIn('beta', body['detail'])

        self.assertUnchanged(engine, revision, before)

        # "Rolled back" is a claim; this is the evidence. The plugin that
        # had already committed was handed the inverse of exactly the diff
        # it committed, against the document as it was.
        self.assertEqual(len(accepting.committed), 3)
        applied = accepting.committed[1]
        undone = accepting.committed[2]
        self.assertEqual(applied[1], [{'path': 'router.alpha.v',
                                       'old': 1, 'new': 2}])
        self.assertEqual(undone[1], [{'path': 'router.alpha.v',
                                      'old': 2, 'new': 1}])
        # The section handed back with the inverse is the running document's,
        # so a plugin re-reading it sees the state it is being returned to.
        self.assertEqual(undone[0], {'v': 1})

    def test_a_rollback_that_itself_fails_is_reported_as_not_rolled_back(
            self):
        # Best effort, and labelled as such: a session a plugin already
        # reset cannot be un-reset, and pretending otherwise would tell an
        # operator the engine is consistent when it is not.
        accepting, failing, engine = self._pair()
        accepting.fail_rollback = True
        failing.fail_commit = True
        self.quiet_engine_log()
        with self.assertRaises(ApplyError) as caught:
            engine.replace_config({'router': {'alpha': {'v': 1},
                                              'beta': {'v': 1}}})
        self.assertFalse(caught.exception.rolled_back)
        self.assertFalse(caught.exception.as_dict()['rolled_back'])
        self.assertEqual(engine.revision, 0)
        self.assertEqual(engine.running_config(), {})

    def test_a_commit_failure_with_nobody_to_roll_back_still_reports(self):
        failing = RecordingPlugin(name='alpha', section=('router', 'alpha'),
                                  schema=FLAT_SCHEMA)
        failing.fail_commit = True
        engine = self.make_engine(plugins=[failing])
        with self.assertRaises(ApplyError) as caught:
            engine.configure(('router', 'alpha', 'v'), 1)
        # Nothing had committed, so there was nothing to undo and the claim
        # is trivially true.
        self.assertTrue(caught.exception.rolled_back)
        self.assertEqual(engine.revision, 0)

    def test_a_config_change_is_announced_on_the_bus(self):
        engine = self.make_engine()
        subscription = engine.subscribe(EV.CONFIG_CHANGE, maxsize=10)
        engine.configure(('ip', 'route', 'table'), 300)
        event, payload = subscription.get(timeout=1)
        self.assertEqual(event, EV.CONFIG_CHANGE)
        self.assertEqual(payload['revision'], 1)
        self.assertEqual(payload['changes'],
                         [{'path': 'ip', 'new': {'route': {'table': 300}}}])

    def test_a_rejected_change_is_not_announced(self):
        engine = self.make_engine()
        subscription = engine.subscribe(EV.CONFIG_CHANGE, maxsize=10)
        with self.assertRaises(ConfigError):
            engine.configure(('ip', 'route', 'table'), 'three')
        self.assertEqual(subscription.drain(), [])

    def _pair(self):
        """Two plugins whose sections one document can change together.

        The atomicity tests need a change that touches both plugins in one
        apply, which a single-path ``configure`` cannot do.
        """
        alpha = RecordingPlugin(name='alpha', section=('router', 'alpha'),
                                schema=FLAT_SCHEMA)
        beta = RecordingPlugin(name='beta', section=('router', 'beta'),
                               schema=FLAT_SCHEMA)
        return alpha, beta, self.make_engine(plugins=[alpha, beta])


class PluginLifecycleTestCase(EngineFixture):
    """A plugin is started and stopped once, on the engine's loop thread."""

    def test_a_plugin_is_started_once_on_the_loop_thread(self):
        plugin = RecordingPlugin()
        engine = self.make_engine(plugins=[plugin])
        self.assertEqual(plugin.starts, [])
        self.assertIsNone(plugin.engine)
        engine.start()
        self.assertEqual(plugin.starts, [self.loop_ident(engine)])
        self.assertIs(plugin.engine, engine)

    def test_a_plugin_is_stopped_once_and_detached(self):
        plugin = RecordingPlugin()
        engine = self.make_engine(plugins=[plugin])
        engine.start()
        engine.stop()
        self.assertEqual(len(plugin.stops), 1)
        self.assertIsNone(plugin.engine)

    def test_plugin_stop_runs_on_the_loop_thread(self):
        # KNOWN FAILURE, left in deliberately: this asserts the documented
        # contract, which the engine does not currently keep.
        #
        # ProtocolPlugin.stop says "Called on the loop thread", and
        # Engine._on_loop_stop is written on the assumption that it runs
        # there -- it tears down the health monitor, cancels the selection
        # task and shuts the FIB sink down, all of which touch state the
        # loop thread owns. But Engine.stop sets self._stopping = True
        # before calling self._call(self._on_loop_stop, ...), and _call
        # routes to a direct in-line call when `not self.is_running()`,
        # which is_running() now reports because _stopping is set. So the
        # whole teardown runs on whichever thread called stop() while the
        # loop is still spinning on its own thread -- a data race against
        # the engine's single-owner model, not merely a cosmetic mismatch.
        #
        # Starting and stopping is symmetric everywhere else, so the test is
        # written the way the docstring reads.
        plugin = RecordingPlugin()
        engine = self.make_engine(plugins=[plugin])
        engine.start()
        loop_ident = self.loop_ident(engine)
        engine.stop()
        self.assertEqual(plugin.stops, [loop_ident])

    def test_plugins_are_stopped_in_reverse_registration_order(self):
        order = []

        class Ordered(RecordingPlugin):
            def stop(self):
                order.append(self.name)
                RecordingPlugin.stop(self)

        first = Ordered(name='first', section=('router', 'first'))
        second = Ordered(name='second', section=('router', 'second'))
        engine = self.make_engine(plugins=[first, second])
        engine.start()
        engine.stop()
        self.assertEqual(order, ['second', 'first'])

    def test_a_plugin_that_raises_in_stop_does_not_leak_the_loop_thread(self):
        # A plugin misbehaving during shutdown must not prevent teardown:
        # the engine is going away either way, and a leaked thread is worse
        # than a logged traceback.
        plugin = RecordingPlugin(name='rude')
        plugin.fail_stop = True
        self.quiet_engine_log()
        engine = self.make_engine(plugins=[plugin], name='rude-engine')
        engine.start()
        self.assertTrue(engine.stop())
        self.assertFalse(engine.is_running())
        self.assertNotIn('rude-engine',
                         [t.name for t in threading.enumerate()])

    def test_restarting_starts_the_plugin_a_second_time(self):
        plugin = RecordingPlugin()
        engine = self.make_engine(plugins=[plugin])
        engine.start()
        engine.stop()
        engine.start()
        self.assertEqual(len(plugin.starts), 2)
        self.assertEqual(len(plugin.stops), 1)

    def test_engine_state_events_bracket_the_run(self):
        engine = self.make_engine()
        subscription = engine.subscribe(EV.ENGINE_STATE, maxsize=10)
        engine.start()
        engine.stop()
        states = [payload['state'] for _event, payload
                  in subscription.drain()]
        self.assertEqual(states, ['started', 'stopped'])

    def test_stopping_closes_the_bus_so_a_restart_is_clean(self):
        # A restarted engine must not keep delivering into a previous run's
        # queues; the subscriber of run one is gone by then.
        engine = self.make_engine()
        subscription = engine.subscribe(EV.CONFIG_CHANGE, maxsize=10)
        engine.start()
        engine.stop()
        self.assertFalse(subscription.active)
        subscription.drain()
        engine.start()
        engine.configure(('ip', 'route', 'table'), 300)
        self.assertEqual(subscription.drain(), [])


class OperationalSurfaceTestCase(EngineFixture):
    """``show`` and ``clear`` dispatch on the longest registered path."""

    def setUp(self):
        self.plugin = RecordingPlugin(name='proto',
                                      section=('router', 'proto'),
                                      schema=FLAT_SCHEMA)
        self.engine = self.start_engine(plugins=[self.plugin])

    def test_the_core_show_paths_are_registered(self):
        self.assertEqual(
            [p for p in self.engine.show_paths() if p[0] != 'ip'
             or p[1] != 'proto'],
            [('engine', 'health'), ('engine', 'status'),
             ('ip', 'as-path-access-list'), ('ip', 'prefix-list'),
             ('ip', 'route'), ('ipv6', 'prefix-list'), ('ipv6', 'route'),
             ('route-map',), ('running-config',)])

    def test_the_policy_show_paths_answer_from_the_core(self):
        # Policy is core state rather than a plugin's -- `ip prefix-list`
        # and `route-map` are configured outside every `router` section --
        # so these paths must be answered by an engine with no plugin
        # that uses them at all.
        self.assertEqual(self.engine.show('ip', 'prefix-list'),
                         {'items': []})
        self.assertEqual(self.engine.show('route-map'), {'items': []})
        self.assertEqual(self.engine.show('ip', 'as-path-access-list'),
                         {'items': []})

    def test_both_prefix_list_families_answer_from_one_document(self):
        # A name is looked up without the caller having to know which
        # family's namespace it landed in, so the v4 and v6 paths are the
        # same handler and each entry carries its own afi.
        self.engine.configure(
            ('ipv6', 'prefix-list', 'V6-ONLY'),
            [{'seq': 5, 'action': 'permit', 'prefix': '2001:db8::/32'}])
        doc = self.engine.show('ip', 'prefix-list', 'V6-ONLY')
        self.assertEqual(len(doc['items']), 1)
        self.assertEqual(doc['items'][0]['name'], 'V6-ONLY')

    def test_show_paths_includes_a_started_plugins_paths(self):
        paths = self.engine.show_paths()
        self.assertIn(('ip', 'proto', 'summary'), paths)
        self.assertIn(('ip', 'proto', 'neighbors'), paths)

    def test_show_engine_status_matches_the_status_call(self):
        self.assertEqual(self.engine.show('engine', 'status')['name'],
                         self.engine.status()['name'])
        self.assertEqual(
            self.engine.show('engine', 'status')['plugins'][0]['name'],
            'proto')

    def test_show_engine_health_matches_the_health_call(self):
        self.assertEqual(self.engine.show('engine', 'health')['status'],
                         self.engine.health()['status'])

    def test_show_running_config_is_redacted(self):
        self.engine.configure(('api', 'auth', 'token'), 'a-long-api-token-99')
        self.assertEqual(
            self.engine.show('running-config')['api']['auth']['token'],
            REDACTED)

    def test_a_plugin_show_handler_is_dispatched(self):
        self.assertEqual(self.engine.show('ip', 'proto', 'summary'),
                         {'what': 'summary', 'args': [], 'kwargs': {}})

    def test_trailing_segments_become_handler_arguments(self):
        # `show ip proto neighbors 10.0.0.2` reads as one handler with an
        # argument, not as an unregistered path. Without this the segment
        # would be silently ignored and the caller would get the whole
        # table back while believing it had asked about one neighbour.
        self.assertEqual(
            self.engine.show('ip', 'proto', 'neighbors', '10.0.0.2'),
            {'what': 'neighbors', 'args': ['10.0.0.2'], 'kwargs': {}})
        self.assertEqual(
            self.engine.show('ip', 'proto', 'neighbors', '10.0.0.2',
                             'detail')['args'],
            ['10.0.0.2', 'detail'])

    def test_keywords_reach_the_handler(self):
        self.assertEqual(
            self.engine.show('ip', 'proto', 'summary', limit=5)['kwargs'],
            {'limit': 5})

    def test_the_longest_registered_prefix_wins(self):
        # ('ip', 'proto') is registered as a clear handler and
        # ('ip', 'proto', 'summary') as a show handler; dispatch must not
        # settle for a shorter match when a longer one exists.
        self.assertEqual(self.engine.show('ip', 'proto', 'summary')['what'],
                         'summary')
        self.assertEqual(self.engine.clear('ip', 'proto')['what'], 'clear')
        self.assertEqual(self.engine.clear('ip', 'proto', 'summary')['args'],
                         ['summary'])

    def test_an_unknown_show_path_raises(self):
        with self.assertRaises(RtEngineError) as caught:
            self.engine.show('no', 'such')
        self.assertIn('no such show path: no such', str(caught.exception))

    def test_an_empty_show_path_raises(self):
        with self.assertRaises(RtEngineError):
            self.engine.show()

    def test_a_partial_core_show_path_raises(self):
        with self.assertRaises(RtEngineError):
            self.engine.show('ip')

    def test_an_unknown_clear_path_raises(self):
        with self.assertRaises(RtEngineError) as caught:
            self.engine.clear('no', 'such')
        self.assertIn('no such clear path: no such', str(caught.exception))

    def test_a_clear_handler_receives_keywords(self):
        self.assertEqual(
            self.engine.clear('ip', 'proto', soft='in'),
            {'what': 'clear', 'args': [], 'kwargs': {'soft': 'in'}})

    def test_show_works_from_the_loop_thread_too(self):
        result = self.engine.submit(self.engine.show, 'ip', 'proto',
                                    'summary').result(5)
        self.assertEqual(result['what'], 'summary')

    def test_show_works_on_a_stopped_engine(self):
        # A stopped engine can still answer for itself; the operational
        # surface is not gated on the loop, it just stops using it.
        self.engine.stop()
        self.assertFalse(self.engine.show('engine', 'status')['running'])
        self.assertEqual(self.engine.show('ip', 'route'),
                         {'items': [], 'next': None})


class DiffTestCase(unittest.TestCase):
    """The diff's granularity, direction and rendering.

    Built through ``ConfigStore.diff`` with a fully open schema. The
    granularity rules are a property of the documents, not of the core
    vocabulary, and using an open schema keeps each case down to the two
    documents whose difference is under test instead of a valid engine
    configuration that happens to contain it.
    """

    @staticmethod
    def _store(document):
        return ConfigStore(document, schema={'type': 'any'})

    def test_a_changed_scalar_is_reported_at_its_own_path(self):
        diff = self._store({'a': {'b': 1, 'c': 2}}).diff({'a': {'b': 1,
                                                                'c': 3}})
        self.assertEqual(diff.paths(), [('a', 'c')])
        self.assertEqual(diff.as_list(), [{'path': 'a.c', 'old': 2,
                                           'new': 3}])

    def test_a_whole_added_subtree_is_reported_once_at_its_root(self):
        # A plugin sees "this neighbour appeared" as one change rather than
        # as fifteen, which is what makes a diff usable as an instruction.
        diff = self._store({}).diff({'x': {'y': {'z': 1, 'w': 2}}})
        self.assertEqual(diff.paths(), [('x',)])
        self.assertEqual(diff.as_list(),
                         [{'path': 'x', 'new': {'y': {'z': 1, 'w': 2}}}])

    def test_a_whole_removed_subtree_is_reported_once_at_its_root(self):
        diff = self._store({'x': {'y': {'z': 1}}}).diff({})
        self.assertEqual(diff.paths(), [('x',)])
        self.assertEqual(diff.as_list(),
                         [{'path': 'x', 'old': {'y': {'z': 1}}}])

    def test_recursion_stops_where_one_side_stops_being_an_object(self):
        diff = self._store({'x': {'y': 1}}).diff({'x': 7})
        self.assertEqual(diff.as_list(), [{'path': 'x', 'old': {'y': 1},
                                           'new': 7}])

    def test_an_identical_document_produces_an_empty_diff(self):
        diff = self._store({'a': {'b': [1, 2]}}).diff({'a': {'b': [1, 2]}})
        self.assertEqual(len(diff), 0)
        self.assertFalse(diff)
        self.assertEqual(diff.as_list(), [])
        self.assertEqual(list(diff), [])
        self.assertIn('changes=0', repr(diff))

    def test_changes_are_ordered_by_path(self):
        diff = self._store({}).diff({'z': 1, 'a': 2, 'm': 3})
        self.assertEqual(diff.paths(), [('a',), ('m',), ('z',)])

    def test_under_returns_changes_at_or_below_the_prefix(self):
        diff = self._store({'a': {'b': 1, 'c': 2}, 'd': 3}).diff(
            {'a': {'b': 9, 'c': 2}, 'd': 4})
        self.assertEqual(diff.under(('a',)).paths(), [('a', 'b')])
        self.assertEqual(diff.under(('a', 'b')).paths(), [('a', 'b')])
        self.assertEqual(diff.under(('d',)).paths(), [('d',)])

    def test_under_excludes_a_sibling(self):
        diff = self._store({}).diff({'a': 1, 'b': 2})
        self.assertEqual(diff.under(('a',)).paths(), [('a',)])

    def test_under_includes_a_change_above_the_prefix(self):
        # Replacing the whole ``router`` object changes router.bgp too, and
        # a plugin that only looked for its own prefix would miss it.
        diff = self._store({}).diff({'router': {'bgp': {'65000': {}}}})
        self.assertEqual(diff.paths(), [('router',)])
        self.assertEqual(diff.under(('router', 'bgp')).paths(), [('router',)])
        self.assertEqual(diff.under(('router', 'bgp', '65000')).paths(),
                         [('router',)])

    def test_under_an_unrelated_prefix_is_empty(self):
        diff = self._store({}).diff({'a': 1})
        self.assertFalse(diff.under(('b',)))
        self.assertEqual(len(diff.under(('b',))), 0)

    def test_inverse_swaps_every_change(self):
        diff = self._store({'a': 1, 'gone': 2}).diff({'a': 2, 'added': 3})
        self.assertEqual(diff.inverse().as_list(),
                         [{'path': 'a', 'old': 2, 'new': 1},
                          {'path': 'added', 'old': 3},
                          {'path': 'gone', 'new': 2}])

    def test_inverse_of_inverse_is_the_original(self):
        diff = self._store({'a': 1, 'gone': 2}).diff({'a': 2, 'added': 3})
        self.assertEqual(diff.inverse().inverse().as_list(), diff.as_list())

    def test_as_list_distinguishes_set_to_null_from_removed(self):
        # MISSING becomes an absent key rather than a string, so a reader
        # can tell "configured as null" from "not configured at all".
        diff = self._store({'a': {'b': 1, 'c': 2}}).diff({'a': {'b': None}})
        rendered = diff.as_list()
        self.assertEqual(rendered[0], {'path': 'a.b', 'old': 1, 'new': None})
        self.assertIn('new', rendered[0])
        self.assertEqual(rendered[1], {'path': 'a.c', 'old': 2})
        self.assertNotIn('new', rendered[1])

    def test_a_missing_key_is_missing_on_both_sides_of_the_changes(self):
        changes = list(self._store({}).diff({'a': 1}))
        self.assertEqual(len(changes), 1)
        path, old, new = changes[0]
        self.assertEqual(path, ('a',))
        self.assertIs(old, MISSING)
        self.assertEqual(new, 1)
        # The sentinel is falsey and reprs readably, because it appears in
        # log lines and in debugger output.
        self.assertFalse(bool(MISSING))
        self.assertEqual(repr(MISSING), '<missing>')

    def test_one_and_true_count_as_a_change(self):
        # 1 == True in Python, so a diff comparing only values would call
        # this identical; a configuration that changed a flag from 1 to True
        # has changed, even if only cosmetically.
        diff = self._store({'flag': 1}).diff({'flag': True})
        self.assertEqual(diff.as_list(), [{'path': 'flag', 'old': 1,
                                           'new': True}])

    def test_an_int_and_an_equal_float_count_as_a_change(self):
        diff = self._store({'n': 1}).diff({'n': 1.0})
        self.assertEqual(diff.paths(), [('n',)])

    def test_integer_and_string_keys_sort_together(self):
        # Paths are joined for display and sorted by str, so a document with
        # both kinds of key must not raise on comparison.
        diff = self._store({}).diff({'a': {1: 'x', 'b': 'y'}})
        self.assertEqual(diff.paths(), [('a',)])

    def test_a_diff_built_by_hand_reports_its_own_changes(self):
        from packets.routing.rtengine.config import Diff

        diff = Diff([(('a', 'b'), 1, 2)])
        self.assertEqual(len(diff), 1)
        self.assertEqual(diff.paths(), [('a', 'b')])
        self.assertEqual(Diff().as_list(), [])


class RoutingThroughEngineTestCase(EngineFixture):
    """Offer, select, publish: the seam between the RIB and the surface."""

    def setUp(self):
        self.engine = self.make_engine()
        self.source = object()

    def test_an_offer_is_pending_until_selection_runs(self):
        # An offer does nothing observable by itself, which is what keeps a
        # burst of a million offers from becoming a million dispatches.
        self.engine.global_rib.offer(_route('192.0.2.0/24'))
        self.assertEqual(self.engine.global_rib.pending(), 1)
        self.assertEqual(self.engine.sink.installed, 0)
        self.assertEqual(self.engine.select(), 1)
        self.assertEqual(self.engine.global_rib.pending(), 0)
        self.assertEqual(self.engine.sink.installed, 1)

    def test_selection_reports_the_fib_state_the_sink_recorded(self):
        self.engine.global_rib.offer(_route('192.0.2.0/24'))
        self.engine.select()
        # L-7: a sink that writes nothing says so; it used to report
        # 'installed', which show ip route then repeated as if traffic
        # would follow the route.
        self.assertEqual(self.engine.sink.state_of('192.0.2.0/24'),
                         'not-installed')
        self.assertEqual(self.engine.sink.state_of('10.0.0.0/8'), 'none')
        self.assertEqual(self.engine.sink.stats()['present'], 1)
        self.assertEqual(self.engine.sink.stats()['status'], 'ok')

    def test_a_second_selection_pass_examines_nothing(self):
        self.engine.global_rib.offer(_route('192.0.2.0/24'))
        self.engine.select()
        self.assertEqual(self.engine.select(), 0)
        self.assertEqual(self.engine.sink.installed, 1)

    def test_select_with_a_limit_still_runs_to_completion(self):
        # ``limit`` bounds one pass per table, not the call: select() keeps
        # going until every queue is empty, which is what "synchronously"
        # means here.
        for i in range(5):
            self.engine.global_rib.offer(_route('192.0.2.%d/32' % i))
        self.assertEqual(self.engine.select(limit=1), 5)
        self.assertEqual(self.engine.global_rib.pending(), 0)

    def test_the_best_route_is_announced_with_its_predecessor(self):
        subscription = self.engine.subscribe(EV.ROUTE_BEST, maxsize=10)
        self.engine.global_rib.offer(_route('192.0.2.0/24',
                                            source=self.source))
        self.engine.select()
        event, payload = subscription.get(timeout=1)
        self.assertEqual(event, EV.ROUTE_BEST)
        self.assertEqual(payload['prefix'], '192.0.2.0/24')
        self.assertEqual(payload['afi'], AFI_IP)
        self.assertEqual(payload['route']['next-hop'], '10.0.0.1')
        self.assertEqual(payload['route']['protocol'], 'bgp')
        self.assertIsNone(payload['previous'])

        # Replacing the winner carries the route it replaced, because a
        # forwarding plane identifies a route by what it was given.
        self.engine.global_rib.offer(_route('192.0.2.0/24',
                                            protocol=T.PROTO_STATIC,
                                            distance=1,
                                            nexthop=NH_V4_ALT))
        self.engine.select()
        _event, payload = subscription.get(timeout=1)
        self.assertEqual(payload['route']['protocol'], 'static')
        self.assertEqual(payload['previous']['protocol'], 'bgp')

    def test_administrative_distance_decides_between_protocols(self):
        # The only cross-protocol decision the core makes on its own.
        self.engine.global_rib.offer(_route('192.0.2.0/24',
                                            protocol=T.PROTO_BGP,
                                            distance=20, nexthop=NH_V4))
        self.engine.global_rib.offer(_route('192.0.2.0/24',
                                            protocol=T.PROTO_STATIC,
                                            distance=1, nexthop=NH_V4_ALT))
        self.engine.select()
        best = self.engine.show('ip', 'route')['items'][0]['best']
        self.assertEqual(best['protocol'], 'static')
        self.assertEqual(best['next-hop'], '10.0.0.2')
        self.assertEqual(
            self.engine.global_rib.lpm(AFI_IP, b'\xc0\x00\x02\x07').protocol,
            T.PROTO_STATIC)

    def test_a_retraction_hands_the_prefix_to_the_remaining_protocol(self):
        bgp_source = object()
        self.engine.global_rib.offer(_route('192.0.2.0/24',
                                            protocol=T.PROTO_BGP,
                                            distance=20,
                                            source=bgp_source))
        self.engine.global_rib.offer(_route('192.0.2.0/24',
                                            protocol=T.PROTO_STATIC,
                                            distance=1, nexthop=NH_V4_ALT))
        self.engine.select()
        self.assertEqual(
            self.engine.global_rib.retract_all(T.PROTO_BGP, bgp_source), 1)
        self.engine.select()
        self.assertEqual(
            self.engine.show('ip', 'route')['items'][0]['best']['protocol'],
            'static')
        # Retracting a source that offered nothing is a no-op, not an error:
        # a plugin stopping does not know what it still holds.
        self.assertEqual(
            self.engine.global_rib.retract_all(T.PROTO_STATIC, None), 0)

    def test_withdrawing_the_last_route_empties_the_table_and_the_sink(self):
        withdrawals = self.engine.subscribe(EV.ROUTE_WITHDRAW, maxsize=10)
        route = _route('192.0.2.0/24', source=self.source)
        self.engine.global_rib.offer(route)
        self.engine.select()
        self.assertEqual(
            self.engine.global_rib.retract_all(T.PROTO_BGP, self.source), 1)
        self.engine.select()

        event, payload = withdrawals.get(timeout=1)
        self.assertEqual(event, EV.ROUTE_WITHDRAW)
        self.assertEqual(payload['prefix'], '192.0.2.0/24')
        self.assertEqual(self.engine.sink.withdrawn, 1)
        self.assertEqual(self.engine.sink.state_of('192.0.2.0/24'), 'none')
        self.assertEqual(self.engine.show('ip', 'route'),
                         {'items': [], 'next': None})

    def test_show_ip_route_lists_the_destinations_in_prefix_order(self):
        for text in ('192.0.2.3/32', '192.0.2.1/32', '192.0.2.2/32'):
            self.engine.global_rib.offer(_route(text))
        self.engine.select()
        listed = [item['prefix']
                  for item in self.engine.show('ip', 'route')['items']]
        self.assertEqual(listed, ['192.0.2.1/32', '192.0.2.2/32',
                                  '192.0.2.3/32'])
        self.assertIsNone(self.engine.show('ip', 'route')['next'])

    def test_show_ip_route_paginates_without_an_offset(self):
        # The caller passes the last prefix it saw rather than an index, so
        # a table that changed between requests still resumes correctly.
        for i in range(1, 4):
            self.engine.global_rib.offer(_route('192.0.2.%d/32' % i))
        self.engine.select()

        first = self.engine.show('ip', 'route', limit=2)
        self.assertEqual([i['prefix'] for i in first['items']],
                         ['192.0.2.1/32', '192.0.2.2/32'])
        # `next` is the last prefix returned, to be passed back as `after`
        # (P-4). It used to be the first prefix left out, which `after`,
        # being exclusive, then skipped.
        self.assertEqual(first['next'], '192.0.2.2/32')

        second = self.engine.show('ip', 'route', limit=2,
                                  after=parse_prefix(first['next']))
        self.assertEqual([i['prefix'] for i in second['items']],
                         ['192.0.2.3/32'])
        self.assertIsNone(second['next'])

    def test_show_a_prefix_reports_hit_and_miss(self):
        self.engine.global_rib.offer(_route('192.0.2.0/24'))
        self.engine.select()

        hit = self.engine.show('ip', 'route', '192.0.2.0/24')
        self.assertTrue(hit['found'])
        self.assertEqual(hit['prefix'], '192.0.2.0/24')
        self.assertEqual(hit['best']['protocol'], 'bgp')
        self.assertEqual(len(hit['routes']), 1)

        miss = self.engine.show('ip', 'route', '10.0.0.0/8')
        self.assertEqual(miss, {'prefix': '10.0.0.0/8', 'found': False,
                                'routes': []})

    def test_show_a_prefix_accepts_a_parsed_prefix_object(self):
        self.engine.global_rib.offer(_route('192.0.2.0/24'))
        self.engine.select()
        found = self.engine.show('ip', 'route',
                                 parse_prefix('192.0.2.0/24'))
        self.assertTrue(found['found'])

    def test_show_a_malformed_prefix_raises(self):
        with self.assertRaises(ValueError):
            self.engine.show('ip', 'route', 'not-a-prefix')

    def test_the_v6_table_is_shown_separately(self):
        self.engine.global_rib.offer(_route('2001:db8::/32', nexthop=NH_V6))
        self.engine.select()
        self.assertEqual(self.engine.show('ip', 'route')['items'], [])
        v6 = self.engine.show('ipv6', 'route')
        self.assertEqual([i['prefix'] for i in v6['items']],
                         ['2001:db8::/32'])
        self.assertTrue(
            self.engine.show('ipv6', 'route', '2001:db8::/32')['found'])

    def test_an_unresolvable_address_has_no_longest_prefix_match(self):
        self.engine.global_rib.offer(_route('192.0.2.0/24'))
        self.engine.select()
        self.assertIsNone(self.engine.global_rib.lpm(AFI_IP,
                                                     b'\x08\x08\x08\x08'))

    def test_offering_without_a_route_raises(self):
        with self.assertRaises(ValueError):
            self.engine.global_rib.offer(None)

    def test_schedule_select_drains_the_rib_on_the_loop(self):
        # The bulk path: a plugin offers and asks for a pass, and the
        # batcher runs it in slices without the plugin waiting for it.
        engine = self.start_engine(budget_ms=1.0)
        source = object()

        def offer():
            for i in range(200):
                engine.global_rib.offer(
                    _route('198.51.100.%d/32' % (i % 256),
                           metric=i, source=source))
            engine.schedule_select()
            return engine.global_rib.pending()

        self.assertEqual(engine.submit(offer).result(5), 200)
        self.wait_until(lambda: engine.global_rib.pending() == 0,
                        'the scheduled selection pass draining')
        self.assertEqual(engine.sink.installed, 200)
        self.assertGreaterEqual(engine.select_batcher.stats()['slices'], 1)

    def test_schedule_select_is_ignored_when_the_engine_is_down(self):
        # Nothing would drain the queue, and quietly doing nothing is
        # better than a plugin's shutdown path raising.
        self.engine.global_rib.offer(_route('192.0.2.0/24'))
        self.engine.schedule_select()
        self.assertEqual(self.engine.global_rib.pending(), 1)

    def test_rib_stats_report_what_selection_did(self):
        self.engine.global_rib.offer(_route('192.0.2.0/24',
                                            source=self.source))
        self.engine.select()
        stats = self.engine.global_rib.stats()
        self.assertEqual(stats['pending'], 0)
        self.assertEqual(stats['selected'], 1)
        self.assertEqual(stats['installed'], 1)
        self.assertEqual(stats['withdrawn'], 0)
        self.assertEqual(stats['published'], 1)
        self.assertEqual(stats['tables']['1/1']['prefixes'], 1)


class ResolverFromConfigurationTestCase(EngineFixture):
    """``ip.route.static`` and ``validate-next-hop`` drive the resolver."""

    def test_validation_is_off_by_default_and_everything_is_reachable(self):
        # A control-plane speaker with no forwarding plane and no IGP has
        # nothing to validate against, and answering False there would make
        # every learned path ineligible -- a far worse failure than
        # accepting a next-hop that is not locally reachable.
        engine = self.make_engine()
        self.assertFalse(engine.resolver.enabled)
        self.assertTrue(engine.resolver.reachable(AFI_IP, b'\x0b\x00\x00\x09'))
        self.assertTrue(engine.resolver.reachable(AFI_IP6, NH_V6))
        self.assertEqual(engine.resolver.igp_metric(AFI_IP,
                                                    b'\x0b\x00\x00\x09'), 0)

    def test_configuration_loads_static_entries_and_enables_validation(self):
        engine = self.make_engine(config={'ip': {'route': {
            'validate-next-hop': True,
            'static': {'10.0.0.0/24': {'next-hop': '10.0.0.254',
                                       'metric': 7}}}}})
        self.assertTrue(engine.resolver.enabled)
        self.assertTrue(engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))
        self.assertEqual(engine.resolver.igp_metric(AFI_IP,
                                                    b'\x0a\x00\x00\x09'), 7)
        self.assertFalse(
            engine.resolver.reachable(AFI_IP, b'\x0b\x00\x00\x09'))
        self.assertEqual(engine.resolver.igp_metric(AFI_IP,
                                                    b'\x0b\x00\x00\x09'), 0)

    def test_removing_a_static_entry_makes_its_cover_unreachable(self):
        # load_static replaces rather than merges, so a route deleted from
        # the document must stop resolving immediately.
        engine = self.make_engine(config={'ip': {'route': {
            'validate-next-hop': True,
            'static': {'10.0.0.0/24': {'next-hop': '10.0.0.254'}}}}})
        self.assertTrue(engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))
        engine.unconfigure(('ip', 'route', 'static', '10.0.0.0/24'))
        self.assertFalse(
            engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))
        self.assertEqual(engine.resolver.statics(AFI_IP), [])

    def test_adding_a_static_entry_at_runtime_takes_effect_immediately(self):
        engine = self.make_engine()
        engine.configure(('ip', 'route', 'validate-next-hop'), True)
        self.assertFalse(
            engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))
        engine.configure(('ip', 'route', 'static', '10.0.0.0/24'),
                         {'next-hop': '10.0.0.254', 'metric': 3})
        self.assertTrue(engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))
        self.assertEqual(engine.resolver.igp_metric(AFI_IP,
                                                    b'\x0a\x00\x00\x09'), 3)

    def test_turning_validation_off_again_reopens_everything(self):
        engine = self.make_engine(config={'ip': {'route': {
            'validate-next-hop': True}}})
        self.assertFalse(
            engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))
        engine.unconfigure(('ip', 'route', 'validate-next-hop'))
        self.assertFalse(engine.resolver.enabled)
        self.assertTrue(engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))

    def test_both_families_of_static_entry_are_loaded(self):
        engine = self.make_engine(config={
            'ip': {'route': {'validate-next-hop': True,
                             'static': {'10.0.0.0/24':
                                        {'next-hop': '10.0.0.254'}}}},
            'ipv6': {'route': {'static': {'2001:db8::/32':
                                          {'next-hop': '2001:db8::254'}}}}})
        self.assertTrue(engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))
        self.assertTrue(
            engine.resolver.reachable(AFI_IP6,
                                      parse_prefix('2001:db8::9').packed()))
        self.assertEqual(len(engine.resolver.statics(AFI_IP6)), 1)

    def test_the_resolver_falls_back_to_the_engines_own_winners(self):
        # Reachability is a property of everything the engine knows, not of
        # one protocol's table, which is why the RIB is consulted too.
        engine = self.make_engine(config={'ip': {'route': {
            'validate-next-hop': True}}})
        # Directly attached: an engine route's own next hop has to resolve
        # too (P-3), and 10.0.0.1 inside 10.0.0.0/24 would be a loop.
        engine.global_rib.offer(_route('10.0.0.0/24', nexthop=b''))
        engine.select()
        self.assertTrue(engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09'))
        resolution = engine.resolver.resolve(AFI_IP, b'\x0a\x00\x00\x09')
        self.assertEqual(resolution.source, 'rib')
        self.assertEqual(resolution.as_dict()['prefix'], '10.0.0.0/24')

    def test_a_static_entry_wins_over_the_rib(self):
        engine = self.make_engine(config={'ip': {'route': {
            'validate-next-hop': True,
            'static': {'10.0.0.0/8': {'next-hop': '10.0.0.254',
                                      'metric': 5}}}}})
        engine.global_rib.offer(_route('10.0.0.0/24'))
        engine.select()
        resolution = engine.resolver.resolve(AFI_IP, b'\x0a\x00\x00\x09')
        self.assertEqual(resolution.source, 'static')
        self.assertEqual(resolution.metric, 5)

    def test_resolver_stats_count_lookups_and_hits(self):
        engine = self.make_engine(config={'ip': {'route': {
            'validate-next-hop': True,
            'static': {'10.0.0.0/24': {'next-hop': '10.0.0.254'}}}}})
        engine.resolver.reachable(AFI_IP, b'\x0a\x00\x00\x09')
        engine.resolver.reachable(AFI_IP, b'\x0b\x00\x00\x09')
        stats = engine.resolver.stats()
        self.assertTrue(stats['enabled'])
        self.assertEqual(stats['lookups'], 2)
        self.assertEqual(stats['hits'], 1)
        self.assertEqual(stats['static'], {'1': 1, '2': 0})

    def test_a_wrong_width_address_is_refused(self):
        engine = self.make_engine()
        with self.assertRaises(ValueError):
            engine.resolver.resolve(AFI_IP, b'\x0a\x00\x00')
        with self.assertRaises(ValueError):
            engine.resolver.resolve(999, b'\x0a\x00\x00\x01')


class PluginRegistryTestCase(unittest.TestCase):
    """The built-in plugin registry: by name, never by import order.

    The registry is module-global and shared by every test in the process,
    so each test here removes exactly the names it added. Leaving one behind
    would change what ``available()`` and the ``KeyError`` message contain
    for any later test -- and for the standalone command, which enumerates
    from here.
    """

    #: Prefixed so it cannot collide with a real protocol name, now or when
    #: the BGP plugin lands.
    NAME = 'test-registry-probe'

    def setUp(self):
        self.added = []

    def tearDown(self):
        for name in self.added:
            registry._builtin.pop(name, None)

    def _register(self, name, factory):
        self.added.append(name)
        registry.register(name, factory)

    def test_a_registered_factory_is_visible_and_loadable(self):
        class Probe(ProtocolPlugin):
            name = 'probe'

        self._register(self.NAME, Probe)
        self.assertIn(self.NAME, registry.builtin())
        self.assertIn(self.NAME, registry.available())
        loaded = registry.load(self.NAME)
        self.assertIsInstance(loaded, Probe)
        # A new instance each time: two engines must not share one plugin's
        # state.
        self.assertIsNot(loaded, registry.load(self.NAME))

    def test_any_callable_may_be_registered(self):
        class Probe(ProtocolPlugin):
            name = 'probe'

        self._register(self.NAME, lambda: Probe())
        self.assertIsInstance(registry.load(self.NAME), Probe)

    def test_builtin_returns_a_copy(self):
        self._register(self.NAME, ProtocolPlugin)
        snapshot = registry.builtin()
        snapshot['injected'] = ProtocolPlugin
        self.assertNotIn('injected', registry.builtin())

    def test_a_duplicate_registration_is_refused(self):
        # Silently replacing a registration would make which plugin is in
        # use depend on import order.
        self._register(self.NAME, ProtocolPlugin)
        with self.assertRaises(ValueError) as caught:
            registry.register(self.NAME, ProtocolPlugin)
        self.assertIn('already registered', str(caught.exception))

    def test_loading_an_unknown_name_names_what_is_available(self):
        self._register(self.NAME, ProtocolPlugin)
        with self.assertRaises(KeyError) as caught:
            registry.load('no-such-protocol')
        message = str(caught.exception)
        self.assertIn('no-such-protocol', message)
        self.assertIn(self.NAME, message)

    def test_available_without_entry_points_does_not_scan(self):
        # The scan walks the whole working set, which a library import must
        # not pay for; it happens only when asked.
        self.assertEqual(registry.available(), registry.builtin())

    def test_a_registered_plugin_can_be_loaded_into_an_engine(self):
        class Probe(ProtocolPlugin):
            name = 'registry-probe'
            config_section = ('router', 'registry-probe')

            def config_schema(self):
                return FLAT_SCHEMA

        self._register(self.NAME, Probe)
        engine = Engine(plugins=[registry.load(self.NAME)])
        self.addCleanup(engine.stop)
        self.assertEqual(engine.configure(('router', 'registry-probe', 'v'),
                                          1), 1)


if __name__ == '__main__':
    unittest.main()
