# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""``Engine``: the loop, the tables, the plugins and the only way in.

One asyncio loop owns everything mutable -- sockets, timers, protocol state
machines, the RIB. Nothing outside that loop touches engine state. That is not
a style preference: in CPython only ``nogil`` work runs in parallel, so a
second thread would buy contention rather than concurrency, and locks on the
RIB would sit on the hottest path in the program. The cost of the choice is
that a long call blocks everything, which is why every bulk job goes through a
:class:`~packets.routing.rtengine.loop.Batcher` and why loop lag is a
first-class health metric.

**There are exactly two doors.** Code in the loop -- a plugin, a timer, a
protocol callback -- calls methods directly. Code anywhere else calls
:meth:`submit`, which hands a callable to the loop and returns a
``concurrent.futures.Future``. The public operations (:meth:`configure`,
:meth:`show`, :meth:`health`) work from either side: they detect which thread
they are on and route themselves accordingly, so an embedding application and
the REST layer in a later stage use the same calls without knowing about
threads.

**A submitted command that is cancelled before it starts never runs.** The
future is marked running at the top of the callback, and a caller that gave up
waiting -- an HTTP request that timed out -- cancels the future. Without that
check, a configuration change abandoned by its client would be applied
seconds later with nobody watching. A command cancelled *while* running
completes: it is already half-applied, and finishing atomically is the only
honest option.

**A configuration change is atomic across plugins.** Validate the whole
proposed document, diff it, offer the diff to every affected plugin's
``prepare_config``, and only then commit to any of them. Nothing moves if
anything objects. See ``config.py`` for the rest of that story.
"""

import asyncio
import concurrent.futures
import logging
import threading

# Every import here names a submodule rather than reaching for an attribute
# of the package. The package __init__ imports this module, so during that
# import the package is only half built, and on 3.6 a
# `from packets.routing.rtengine import config` in that state can fail where
# naming the submodule always resolves.
from packets.routing.rtengine.config import (MISSING, ConfigStore, get_path,
                                             is_loopback, parse_bind)
from packets.routing.rtengine.errors import (ApplyError, ConfigError,
                                             ConflictError, RtEngineError,
                                             UnavailableError)
from packets.routing.rtengine.events import (CONFIG_CHANGE, ENGINE_STATE,
                                             EventBus)
from packets.routing.rtengine.fib import factory as fib_factory
from packets.routing.rtengine.fib.sink import NullSink
from packets.routing.rtengine.health import HealthMonitor
from packets.routing.rtengine.loop import (Batcher, LoopThread, new_loop,
                                           shutdown_loop, wait_tasks)
from packets.routing.rtengine.plugin import ProtocolPlugin
from packets.routing.rtengine.policy.store import PolicyStore
from packets.routing.rtengine.rib.globalrib import GlobalRib
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, parse_prefix
from packets.routing.rtengine.rib.resolver import Resolver

_log = logging.getLogger('packets.rtengine.engine')

# How long stop() lets plugins finish closing -- BGP sessions writing their
# NOTIFICATION and hearing the peer's FIN -- before the loop is shut down.
# Each close is bounded on its own (peer.NOTIFY_LINGER); this bounds them
# all, so a shutdown with a thousand peers still takes seconds, not hours.
CLOSE_WAIT = 2.0

# E-5: how long a selection pass that raised waits before it is tried again.
# Long enough that a pass failing on every attempt costs a log line a second
# rather than the loop; short enough that a transient failure (a sink that
# hiccupped) does not leave the RIB unselected for long.
SELECT_RETRY_S = 1.0

# E-1: the longest the FIB pump sleeps inside its own task. A sink asking
# for a longer wait -- a retry backoff measured in seconds -- gets a timer
# instead, so an idle engine is not a task waking up to find nothing to do.
FIB_PUMP_MAX_SLEEP = 0.05


class Engine(object):
    """A routing engine: one loop, one RIB, zero or more protocol plugins.

    :param config: the initial configuration document. Validated here, so a
        bad document fails at construction rather than at start.
    :param loop: an event loop to use instead of creating one. For
        embedding in an application that already has a loop; that
        application is then responsible for running it.
    :param sink: a :class:`~packets.routing.rtengine.fib.sink.FibSink` to
        use instead of the one ``ip.route`` asks for. By default the engine
        builds its own (L-6, see :mod:`~packets.routing.rtengine.fib.factory`):
        a ``NullSink`` while ``ip route install`` is off, a netlink sink on
        Linux when it is on, rebuilt whenever the table, protocol or
        priorities change. An injected sink wins and is never replaced; the
        configuration only opens and closes it.
    :param plugins: plugin instances or classes to register immediately.
    :param budget_ms: the selection batcher's slice budget.
    :param lag_threshold_ms: loop lag above which health degrades.
    :param name: thread name and log prefix.
    :raises ConfigError: the initial configuration is invalid.
    """

    def __init__(self, config=None, loop=None, sink=None, plugins=(),
                 budget_ms=5.0, lag_threshold_ms=50.0, name='rtengine'):
        self.name = name
        self.store = ConfigStore(config)
        self.bus = EventBus()
        self._sink_injected = sink is not None
        self.sink = sink if sink is not None else NullSink()
        # What the engine-built sink was built from (fib_factory.sink_spec);
        # None is "install off", which the initial NullSink already is.
        self._fib_spec = None
        self.global_rib = GlobalRib(sink=self.sink, bus=self.bus)
        self.resolver = Resolver(global_rib=self.global_rib)
        # Prefix-lists, as-path lists and route-maps. Core state, not a
        # plugin's: ``ip prefix-list`` and ``route-map`` are configured
        # outside ``router bgp``, more than one protocol will want them,
        # and a plugin owning them would mean the second protocol had to
        # either depend on the first or invent a second vocabulary for
        # the same idea.
        self.policy = PolicyStore()
        self.select_batcher = Batcher(budget_ms=budget_ms, name='select')
        self.health_monitor = HealthMonitor(
            self, lag_threshold_ms=lag_threshold_ms)
        self.health_monitor.register_batcher(self.select_batcher)

        self._plugins = []
        self._show_handlers = {}
        self._clear_handlers = {}
        self._install_core_handlers()

        self._external_loop = loop is not None
        self._loop = loop
        self._thread = None
        self._loop_ident = None
        self._running = False
        self._stopping = False
        # E-6: true while _on_loop_start runs. The engine is not running
        # yet -- submit() still refuses -- but a plugin starting up may
        # already ask for selection.
        self._starting = False
        # True while run_forever() is driving the loop on the calling
        # thread. stop() must then stop the loop even when the loop was
        # given to the constructor: the engine is the one running it, and
        # run_forever() is documented to return once the engine is stopped.
        self._driving = False
        self._queued = 0
        # E-10: _queued is touched from every submitting thread and from
        # the loop thread, and += on an attribute is not atomic.
        self._queued_lock = threading.Lock()
        self._select_wanted = False
        self._select_task = None
        self._select_retry = None
        self._fib_task = None
        self._fib_timer = None
        # Plugin work still finishing after stop(), e.g. BGP sessions
        # getting their NOTIFICATION out; see _wait_for_closes.
        self._closing = []
        # What went wrong during the last stop(), empty when it was clean
        # (A-2): the command's exit status is read from it.
        self.stop_problems = []

        for plugin in plugins:
            self.register_plugin(plugin)

        # The schema was checked by the store; this is the semantic pass the
        # schema cannot express, run here so a configuration that could
        # never work fails at construction rather than at start.
        initial = self.store.document(redact=False)
        self._commit_core(self._prepare_core(initial))

    # --- plugins -----------------------------------------------------------

    def register_plugin(self, plugin):
        """Register a protocol plugin.

        Registration is what grafts the plugin's configuration schema into
        the document, so it must happen before a configuration mentioning
        that protocol can be accepted. Registering while running is allowed
        and starts the plugin immediately; registering the same name twice
        is not.

        :param plugin: a ``ProtocolPlugin`` instance or subclass.
        :return: the registered instance.
        :raises ValueError: not a plugin, incomplete, or a duplicate name.
        """
        if isinstance(plugin, type):
            plugin = plugin()
        if not isinstance(plugin, ProtocolPlugin):
            raise ValueError('%r is not a ProtocolPlugin'
                             % (type(plugin).__name__,))
        plugin.validate()
        if any(p.name == plugin.name for p in self._plugins):
            raise ValueError('a plugin named %r is already registered'
                             % (plugin.name,))

        schema = plugin.config_schema()
        if plugin.config_section:
            self.store.add_section_schema(plugin.config_section,
                                          schema or {'type': 'any'})
        self._plugins.append(plugin)

        for afi, safi in plugin.afi_safi():
            self.global_rib.ensure_table(afi, safi)

        if self._running:
            self._call(self._start_plugin, plugin)
        return plugin

    def plugins(self):
        """Return the registered plugins.

        :return: a list, in registration order.
        """
        return list(self._plugins)

    def plugin(self, name):
        """Return a registered plugin by name, or None.

        :param name: the protocol name.
        :return: the plugin, or None.
        """
        for found in self._plugins:
            if found.name == name:
                return found
        return None

    def _start_plugin(self, plugin):
        plugin.start(self)
        for path, handler in (plugin.show_handlers() or {}).items():
            self._show_handlers[tuple(path)] = handler
        for path, handler in (plugin.clear_handlers() or {}).items():
            self._clear_handlers[tuple(path)] = handler
        return plugin.name

    # --- lifecycle ---------------------------------------------------------

    def start(self, timeout=5.0):
        """Start the engine on its own thread and wait until it is up.

        :param timeout: seconds to wait for the loop to start.
        :return: self, so ``engine = Engine(...).start()`` reads sensibly.
        :raises RtEngineError: already running, or an externally supplied
            loop is in use -- that loop's owner runs it, and
            :meth:`attach` is the call for that case.
        """
        if self._running or self._starting:
            raise RtEngineError('engine is already running')
        if self._external_loop:
            raise RtEngineError('this engine was given an external loop; '
                                'run that loop and call attach() instead')
        self._loop = new_loop()
        self._thread = LoopThread(self._loop, name=self.name)
        self._thread.start(timeout=timeout)
        try:
            # E-6: _running is set by _on_loop_start once everything in it
            # has succeeded. Setting it first, as this used to, let a REST
            # request in before the plugins existed, and left an engine
            # whose start had failed reporting itself as running.
            self._call(self._on_loop_start)
        except BaseException:
            self._thread.stop(timeout=timeout)
            shutdown_loop(self._loop, timeout=timeout)
            self._thread = None
            self._loop = None
            self._loop_ident = None
            raise
        return self

    def attach(self):
        """Bring the engine up on a loop somebody else runs.

        For embedding in an application with its own asyncio loop. Must be
        called from that loop's thread, with the loop running.

        :return: self.
        :raises RtEngineError: no loop was supplied, or already running.
        """
        if self._running or self._starting:
            raise RtEngineError('engine is already running')
        if self._loop is None:
            raise RtEngineError('no loop to attach to')
        self._on_loop_start()
        return self

    def run_forever(self):
        """Run the engine on the calling thread until it is stopped.

        The standalone command's path. :meth:`stop` may be called from a
        signal handler or another thread.

        A loop this call created is shut down and closed when it returns
        (E-6): its tasks cancelled and given the chance to finish, its
        selector released. It used to be left open, which leaked the
        selector's descriptor and left every unfinished task to be
        destroyed pending at interpreter exit. A loop passed to the
        constructor belongs to its owner and is left alone.
        """
        if self._running or self._starting:
            raise RtEngineError('engine is already running')
        owned = self._loop is None
        self._loop = self._loop or new_loop()
        self._loop_ident = threading.get_ident()
        self._driving = True
        try:
            self._on_loop_start()
            self._loop.run_forever()
        finally:
            self._driving = False
            self._running = False
            loop = self._loop
            if owned and loop is not None and not loop.is_closed():
                shutdown_loop(loop)
                self._loop = None
            self._loop_ident = None

    def _on_loop_start(self):
        """Bring everything up on the loop thread; all or nothing.

        The forwarding plane opens first, so a kernel that refuses the
        socket fails the start before any session exists that would have
        to be torn down again, and so the first routes the plugins offer
        have somewhere to go. If anything fails, what already started is
        stopped again in reverse and the exception propagates: a half
        started engine reporting itself as running is the outcome this
        exists to prevent.
        """
        self._loop_ident = threading.get_ident()
        self._starting = True
        started = []
        try:
            self.health_monitor.start(self._loop)
            self._sync_fib_open(self.store.document(redact=False))
            for plugin in self._plugins:
                self._start_plugin(plugin)
                started.append(plugin)
            self._running = True
        except BaseException:
            for plugin in reversed(started):
                try:
                    plugin.stop()
                except Exception:
                    _log.exception('%s: plugin %s failed to stop after a '
                                   'failed start', self.name, plugin.name)
            self.health_monitor.stop()
            self._stop_fib_work()
            try:
                self.sink.shutdown(retain=False)
            except Exception:
                _log.exception('%s: fib sink failed to shut down after a '
                               'failed start', self.name)
            raise
        finally:
            self._starting = False
        self.bus.publish(ENGINE_STATE, {'state': 'started',
                                        'revision': self.revision})
        _log.info('%s started, %d plugin(s)', self.name, len(self._plugins))

    def stop(self, timeout=5.0, retain_fib=None):
        """Stop the engine: plugins, sink, loop, thread.

        Idempotent, and safe from any thread including a signal handler.

        Order is deliberate. Plugins stop first, so sessions close and
        routes are retracted while the loop still runs; then the forwarding
        plane is told, so a stopped speaker does not leave the kernel
        pointing at a next-hop nobody maintains; then the loop is drained
        and closed.

        :param timeout: seconds to allow for each stage.
        :param retain_fib: leave installed routes in place. Defaults to the
            ``ip.route.retain-on-shutdown`` setting.
        :return: True if the engine was running and is now stopped.
        """
        if not self._running or self._stopping:
            return False
        self._stopping = True
        problems = []
        if retain_fib is None:
            retain_fib = bool(self.store.value(('ip', 'route',
                                                'retain-on-shutdown'),
                                               False))
        try:
            # force=True: _stopping is already set, so without it this
            # teardown would take _call's inline branch and run on the
            # stopping thread while the loop is still spinning. See _call.
            problems.extend(self._call(self._on_loop_stop, retain_fib,
                                       timeout=timeout, force=True) or ())
        except Exception as exc:
            # A plugin misbehaving during shutdown must not prevent the
            # loop from being torn down; the engine is going away either
            # way and a leaked thread is worse than a logged traceback.
            _log.exception('%s: error while stopping plugins', self.name)
            problems.append('error while stopping plugins: %s: %s'
                            % (type(exc).__name__, exc))

        self._running = False
        closing, self._closing = self._closing, []
        if self._thread is not None:
            self._wait_for_closes(closing)
            if not self._thread.stop(timeout=timeout):
                problems.append('the loop thread did not exit within '
                                '%.3gs' % (timeout,))
            shutdown_loop(self._loop, timeout=timeout)
            self._thread = None
            self._loop = None
        elif (self._driving or not self._external_loop) \
                and self._loop is not None:
            if self._loop.is_running():
                self._loop.call_soon_threadsafe(self._stop_loop_after,
                                                self._loop, closing)
        self._loop_ident = None
        self.stop_problems = problems
        self._stopping = False
        return True

    def _wait_for_closes(self, tasks):
        """Give plugin closes up to ``CLOSE_WAIT`` before the loop stops.

        L-1: ``shutdown_loop`` cancels every task, and a BGP session's
        close cancelled there is a NOTIFICATION that may never be written
        and a socket closed with unread data -- a reset. Only possible
        from another thread; on the loop thread the wait cannot block, and
        :meth:`_stop_loop_after` does it asynchronously instead.
        """
        loop = self._loop
        if not tasks or loop is None or self.in_loop() or \
                not loop.is_running():
            return

        async def _wait():
            return await wait_tasks(loop, tasks, CLOSE_WAIT)

        try:
            left = asyncio.run_coroutine_threadsafe(_wait(), loop).result(
                CLOSE_WAIT + 1.0)
        except Exception as exc:
            _log.debug('%s: waiting for plugin closes failed: %s',
                       self.name, exc)
            return
        if left:
            _log.info('%s: %d close(s) still running after %.1fs; they '
                      'are cancelled with the loop', self.name, left,
                      CLOSE_WAIT)

    @staticmethod
    def _stop_loop_after(loop, tasks):
        """Stop a loop once plugin closes are done, bounded. Loop thread."""
        waiter = wait_tasks(loop, tasks, CLOSE_WAIT)
        waiter.add_done_callback(lambda _f: loop.stop())

    def _on_loop_stop(self, retain_fib):
        # Runs on the loop thread, always: it stops plugins (whose stop()
        # is documented as loop-thread), cancels the selection task
        # (Task.cancel is not thread-safe), shuts the sink down and closes
        # the bus -- all state the loop owns and may be using at that very
        # moment, since the loop is not asked to stop until stop() has
        # returned from here. Returns what went wrong, for stop_problems
        # (A-2): each failure is caught here so that the rest still stop.
        problems = []
        for plugin in reversed(self._plugins):
            try:
                plugin.stop()
            except Exception as exc:
                _log.exception('%s: plugin %s failed to stop', self.name,
                               plugin.name)
                problems.append('plugin %s failed to stop: %s: %s'
                                % (plugin.name, type(exc).__name__, exc))
            try:
                self._closing.extend(plugin.closing())
            except Exception:
                _log.exception('%s: plugin %s could not report its closes',
                               self.name, plugin.name)
        self.health_monitor.stop()
        if self._select_task is not None and not self._select_task.done():
            self._select_task.cancel()
        self._select_task = None
        self._stop_fib_work()
        try:
            self.sink.shutdown(retain=retain_fib)
        except Exception as exc:
            _log.exception('%s: fib sink failed to shut down', self.name)
            problems.append('the FIB sink failed to shut down: %s: %s'
                            % (type(exc).__name__, exc))
        self.bus.publish(ENGINE_STATE, {'state': 'stopped',
                                        'revision': self.revision})
        self.bus.close()
        return problems

    def is_running(self):
        """Return whether the engine is up.

        :return: True when the loop is running and the engine has not begun
            stopping.
        """
        return bool(self._running and not self._stopping)

    @property
    def loop(self):
        """The engine's event loop, or None when it is not running."""
        return self._loop

    # --- the thread boundary -----------------------------------------------

    def in_loop(self):
        """Return whether the caller is already on the loop thread.

        :return: True if a direct call is safe.
        """
        return (self._loop_ident is not None
                and threading.get_ident() == self._loop_ident)

    def submit(self, fn, *args, **kwargs):
        """Run a callable on the loop thread and return a Future.

        The only way for code outside the loop to touch engine state.

        A future cancelled before its callback starts is **not** run: the
        callback marks the future running first and returns if that fails.
        That is what makes a timed-out REST request safe -- the change it
        asked for either happened before the timeout or never happens at
        all, rather than landing later with nobody watching.

        :param fn: the callable.
        :param args: positional arguments.
        :param kwargs: keyword arguments.
        :return: a ``concurrent.futures.Future``.
        :raises UnavailableError: the engine is not running, so nothing
            would ever drain the queue.
        """
        if not self.is_running() or self._loop is None:
            raise UnavailableError('engine is not running')
        return self._submit_to_loop(fn, *args, **kwargs)

    def _submit_to_loop(self, fn, *args, **kwargs):
        """submit() without the is_running() gate.

        Shutdown needs to reach the loop after ``_stopping`` is set, which
        is exactly when the public gate refuses. Private so that the only
        caller able to bypass the gate is the teardown that has to.
        """
        future = concurrent.futures.Future()
        loop = self._loop
        if loop is None:
            raise UnavailableError('engine is not running')
        lock = self._queued_lock

        def runner():
            with lock:
                self._queued -= 1
            if not future.set_running_or_notify_cancel():
                return
            try:
                future.set_result(fn(*args, **kwargs))
            except BaseException as exc:
                future.set_exception(exc)

        # Counted before it is handed over, or the runner could finish and
        # decrement first; uncounted again if the hand-over fails (E-10),
        # which a loop closed under us does with RuntimeError -- and the
        # depth health reports would otherwise stay inflated for good.
        with lock:
            self._queued += 1
        try:
            loop.call_soon_threadsafe(runner)
        except RuntimeError as exc:
            with lock:
                self._queued -= 1
            raise UnavailableError('engine loop is not accepting work: %s'
                                   % exc)
        return future

    def command_depth(self):
        """Return how many submitted commands are waiting to run.

        :return: the queue depth; a health metric.
        """
        return self._queued

    def _loop_alive(self):
        """Return whether a loop thread is running that could serve a call.

        Deliberately *not* ``is_running()``: that reports the engine's
        public state, which goes false the moment ``stop()`` begins, while
        the loop itself keeps running until teardown has finished. The
        question ``_call`` has to answer is the physical one -- is there
        another thread executing engine code right now -- not the
        administrative one.
        """
        loop = self._loop
        return loop is not None and loop.is_running()

    def _call(self, fn, *args, **kwargs):
        """Run something on the loop, from whichever side the caller is on.

        Three cases, in order:

        * already on the loop thread -- call it directly.
        * no loop is running (before ``start()``, after ``stop()``) -- the
          caller's thread is the only one that can touch engine state, so
          inline is both safe and the only option.
        * a loop is running -- marshal, and wait.

        The middle case must not be reached while the loop is alive. It
        was, once: ``stop()`` sets ``_stopping`` before tearing down, which
        made ``is_running()`` false, which sent the whole teardown --
        plugin ``stop()``, ``Task.cancel()``, sink shutdown, bus close --
        down the inline branch on the stopping thread while the loop was
        still running its own callbacks. ``start()`` was routed correctly
        and ``stop()`` was not, and nothing in the shutdown path said which
        thread it had run on, so the asymmetry was invisible.

        :param timeout: seconds to wait when marshalling (keyword only).
        :param force: run even though the engine is stopping (keyword
            only). For the teardown itself, which is the one thing that
            must still reach the loop after ``_stopping`` is set.
        :raises UnavailableError: the engine is stopping and this is not
            the teardown. A request that arrives mid-shutdown is refused
            rather than quietly applied to an engine that is going away.
        """
        timeout = kwargs.pop('timeout', 30.0)
        force = kwargs.pop('force', False)
        if self.in_loop():
            return fn(*args, **kwargs)
        if not self._loop_alive():
            return fn(*args, **kwargs)
        if self._stopping and not force:
            raise UnavailableError('engine is stopping')
        return self._submit_to_loop(fn, *args, **kwargs).result(timeout)

    # --- configuration -----------------------------------------------------

    @property
    def revision(self):
        """The running configuration's revision."""
        return self.store.revision

    def running_config(self, redact=True):
        """Return the running configuration document.

        :param redact: replace secrets with ``"<redacted>"``. Leave it on
            unless the caller is writing the document to a protected file:
            the whole point is that a key cannot be read back out of the
            API.
        :return: a copy of the document.
        """
        return self.store.document(redact=redact)

    def configure(self, path, value, if_revision=None):
        """Set a configuration path and apply the change.

        :param path: dotted string or tuple of keys, e.g.
            ``'router.bgp.65000.neighbor.10.0.0.2.remote-as'`` is
            ambiguous, so a tuple is the reliable form for anything
            containing an address.
        :param value: the value, which may be a whole subtree.
        :param if_revision: only apply if this is the current revision.
        :return: the new revision, unchanged if the document did not change.
        :raises ConfigError: invalid, or rejected by a plugin.
        :raises ConflictError: it collides with a stated limit.
        :raises PreconditionFailed: ``if_revision`` did not match.
        :raises ApplyError: a plugin's commit failed.
        """
        return self._call(self._do_configure, _as_path(path), value,
                          if_revision)

    def unconfigure(self, path, if_revision=None):
        """Remove a configuration path and apply the change -- IOS ``no``.

        :param path: dotted string or tuple of keys.
        :param if_revision: only apply if this is the current revision.
        :return: the new revision.
        :raises ConfigError: nothing is configured there, or the result is
            invalid.
        """
        return self._call(self._do_unconfigure, _as_path(path), if_revision)

    def replace_config(self, document, if_revision=None):
        """Replace the whole configuration document atomically.

        :param document: the new document.
        :param if_revision: only apply if this is the current revision.
        :return: the new revision.
        """
        return self._call(self._do_replace, document, if_revision)

    def _do_configure(self, path, value, if_revision):
        self.store.check_revision(if_revision)
        return self._apply(self.store.propose_set(path, value))

    def _do_unconfigure(self, path, if_revision):
        self.store.check_revision(if_revision)
        return self._apply(self.store.propose_delete(path))

    def _do_replace(self, document, if_revision):
        self.store.check_revision(if_revision)
        return self._apply(self.store.propose_replace(document))

    def _apply(self, proposed):
        """Validate, prepare, commit. The whole atomicity story is here."""
        diff = self.store.diff(proposed)
        if not diff:
            # A no-op must not advance the revision: a client polling for
            # changes would see churn that did not happen, and an ETag
            # would change without the document changing.
            return self.store.revision

        affected = []
        for plugin in self._plugins:
            if not plugin.config_section:
                continue
            sub = diff.under(plugin.config_section)
            if sub:
                affected.append((plugin, sub))

        # Phase one: everybody validates, nobody applies. A rejection here
        # leaves the engine exactly as it was. The core's preparation may
        # build a new forwarding sink, but it never opens one.
        core = self._prepare_core(proposed)
        for plugin, sub in affected:
            section = get_path(proposed, plugin.config_section)
            if section is MISSING:
                section = {}
            plugin.prepare_config(section, sub)

        # Phase two: apply -- plugins, then the core, then the store, as
        # one transaction (E-3). A failure now is the expensive case, so
        # everything that already committed is handed back the document as
        # it was: the core re-applies it, the plugins get the inverse diff.
        # Best effort and labelled as such: a session a plugin already
        # reset cannot be un-reset. The core used to run outside this, so
        # a forwarding plane that refused to open left the plugins on the
        # new configuration and the store on the old one.
        committed = []
        in_core = False
        try:
            for plugin, sub in affected:
                section = get_path(proposed, plugin.config_section)
                if section is MISSING:
                    section = {}
                plugin.commit_config(section, sub)
                committed.append((plugin, sub))
            in_core = True
            self._commit_core(core)
        except Exception as exc:
            rolled_back = True
            current = self.store.document(redact=False)
            if in_core:
                rolled_back = self._roll_back_core(core, current)
            for plugin, sub in reversed(committed):
                section = get_path(current, plugin.config_section)
                if section is MISSING:
                    section = {}
                try:
                    plugin.commit_config(section, sub.inverse())
                except Exception:
                    rolled_back = False
                    _log.exception('%s: rollback failed for plugin %s',
                                   self.name, plugin.name)
            if in_core:
                raise ApplyError('the core configuration failed to apply: '
                                 '%s' % (exc,), rolled_back=rolled_back)
            raise ApplyError('plugin %s failed to commit: %s'
                             % (_plugin_name(committed, affected), exc),
                             rolled_back=rolled_back)

        revision = self.store.commit(proposed)
        # Redacted (E-2): the bus is read by whatever subscribed, and a
        # rotated token or a new neighbour password is not theirs to see.
        self.bus.publish(CONFIG_CHANGE, {
            'revision': revision,
            'changes': self.store.redacted_changes(diff)})
        return revision

    def _prepare_core(self, proposed):
        """Validate what the schema cannot express, before anything applies.

        The schema can say that ``install`` is a boolean; it cannot say
        that this build has no forwarding plane to install into, or that
        binding the API to a public address without a token is not
        something an operator can have meant.

        :param proposed: the whole proposed document.
        :return: a :class:`_CoreChange` for :meth:`_commit_core`.
        :raises ConfigError: the document is well formed but cannot work.
        :raises ConflictError: it asks an injected sink for something it
            cannot do.
        """
        # Policy first, and purely: an unknown match keyword or a
        # route-map naming a prefix-list that does not exist is a
        # rejection the operator can act on, and finding it out at commit
        # time would mean a half-applied document.
        self.policy.validate(proposed,
                             longest_as_path=self._longest_as_path(proposed))

        change = self._prepare_fib(proposed)

        static_v4 = get_path(proposed, ('ip', 'route', 'static'))
        static_v6 = get_path(proposed, ('ipv6', 'route', 'static'))
        for entries in (static_v4, static_v6):
            if entries is MISSING:
                continue
            for prefix_text, body in entries.items():
                nexthop = (body or {}).get('next-hop')
                if nexthop is None:
                    continue
                # Both sides parse cleanly on their own; what the schema
                # cannot check is that they are the same family, and a v6
                # next-hop for a v4 prefix would fail much later, inside a
                # sink, with nothing pointing at the configuration.
                if parse_prefix(prefix_text).afi \
                        != parse_prefix(nexthop).afi:
                    raise ConfigError(
                        'next-hop %s is not the same address family as %s'
                        % (nexthop, prefix_text),
                        path='route.static.%s.next-hop' % prefix_text)

        bind = get_path(proposed, ('api', 'bind'))
        if bind is not MISSING and bind:
            # parse_bind is the API server's own parser, used here so that
            # the address this judges is the address that will actually be
            # bound. A second implementation of "which part is the host"
            # would eventually disagree with the first, and the direction
            # it disagreed in would decide whether an unauthenticated
            # listener appeared on a network interface.
            host = parse_bind(bind)[0]
            insecure = get_path(proposed, ('api', 'insecure'))
            auth = get_path(proposed, ('api', 'auth'))
            has_auth = auth is not MISSING and bool(auth) and (
                auth.get('token') or auth.get('token-file'))
            if not is_loopback(host) and not has_auth \
                    and insecure is not True:
                raise ConfigError(
                    'binding the API to %s exposes it beyond this host, so '
                    'api.auth must be configured, or api.insecure set to '
                    'true to accept the risk deliberately' % (host,),
                    path='api.bind')
        return change

    def _prepare_fib(self, proposed):
        """The forwarding plane's share of :meth:`_prepare_core`.

        Judges ``ip route install`` against the sink the engine has or
        would build, and builds a new one -- unopened -- when the section
        asks for a different kind (L-6). An injected sink is never
        replaced, so asking it to install when it cannot write is a
        conflict with how the engine was constructed, not a malformed
        document.

        :param proposed: the whole proposed document.
        :return: a :class:`_CoreChange`.
        """
        route_cfg = get_path(proposed, ('ip', 'route'))
        if route_cfg is MISSING or not route_cfg:
            route_cfg = {}
        change = _CoreChange(proposed)
        if self._sink_injected:
            if route_cfg.get('install') is True \
                    and not getattr(self.sink, 'writes', False):
                raise ConflictError(
                    'kernel FIB install is enabled, but this engine was '
                    'given a forwarding sink (%s) that does not write, and '
                    'an injected sink is never replaced' % (self.sink.name,),
                    path='ip.route.install')
            return change
        fib_factory.check_installable(route_cfg)
        spec = fib_factory.sink_spec(route_cfg)
        if spec != self._fib_spec:
            change.sink = fib_factory.make_sink(route_cfg)
            change.spec = spec
        return change

    def _longest_as_path(self, proposed):
        """The longest AS path any plugin will hand to policy (S6-d).

        :param proposed: the whole proposed document.
        :return: the largest plugin answer, 0 if any plugin sets no limit,
            or None if no plugin hands AS paths to policy.
        """
        longest = None
        for plugin in self._plugins:
            found = plugin.longest_as_path(
                get_path(proposed, plugin.config_section))
            if found is None:
                continue
            if found == 0 or longest == 0:
                longest = 0
            else:
                longest = max(longest or 0, found)
        return longest

    def _commit_core(self, change):
        """Apply the core's own sections; the last step of a commit.

        The forwarding plane goes first. It is the one step here that can
        fail -- a kernel refusing the socket, a dump that times out -- and
        failing before anything else has changed is what keeps the
        rollback in :meth:`_apply` simple.

        :param change: what :meth:`_prepare_core` decided.
        """
        self._commit_fib(change)
        self._apply_core_sections(change.document)

    def _apply_core_sections(self, document):
        """Statics, next-hop validation and policy, from a document.

        :param document: the document being committed, or on a rollback
            the one being restored.
        """
        statics = {}
        for family in (('ip', 'route', 'static'), ('ipv6', 'route',
                                                   'static')):
            found = get_path(document, family)
            if found is not MISSING and found:
                statics.update(found)
        self.resolver.load_static(statics)
        self.resolver.enabled = (
            get_path(document, ('ip', 'route', 'validate-next-hop')) is True)
        self.resolver.resolve_via_default = (
            get_path(document, ('ip', 'route', 'resolve-via-default'))
            is True)

        before = self.policy.revision
        self.policy.load(document)
        if self.policy.revision != before:
            # Policy lives outside every plugin's section, so a commit
            # that only edited a route-map reaches no plugin's
            # commit_config at all. Without this hook such an edit would
            # sit in the store affecting nothing until something
            # unrelated happened to touch `router bgp` -- which is the
            # kind of defect an operator reports as "my filter did not
            # take effect until I bounced the session".
            for plugin in self._plugins:
                try:
                    plugin.policy_changed(self.policy)
                except Exception:
                    _log.exception('%s: plugin %s failed to apply a policy '
                                   'change', self.name, plugin.name)

    # --- the forwarding plane's lifecycle (L-6, E-3) ------------------------

    def _fib_live(self):
        """Whether a sink change must happen now, on a running engine.

        Before start (and after stop) a new sink is only recorded: the
        engine opens it in :meth:`_on_loop_start`. That is what keeps
        constructing an engine, and ``rtengine --check``, from touching the
        kernel at all.
        """
        return bool(self._running and not self._stopping
                    and self._loop is not None)

    def _set_sink(self, sink):
        self.sink = sink
        self.global_rib.sink = sink

    def _commit_fib(self, change):
        """Carry out the forwarding-plane half of a :class:`_CoreChange`.

        :param change: what :meth:`_prepare_fib` decided.
        :raises Exception: the new sink could not be opened or populated;
            the old one is back in place when this raises.
        """
        if change.sink is None:
            # The same sink: an injected one, or an engine-built one whose
            # kind did not change. Either only opens or closes with
            # ``install``.
            if self._fib_live():
                self._sync_fib_open(change.document)
            return
        old, old_spec = self.sink, self._fib_spec
        if self._fib_live():
            self._switch_sink(old, change.sink, change.document)
        else:
            self._set_sink(change.sink)
        self._fib_spec = change.spec
        change.previous = (old, old_spec)

    def _switch_sink(self, old, new, document):
        """Replace a running sink: open the new, empty the old, fill the new.

        In that order. Opening first means the one failure a kernel is
        likely to produce -- refusing the socket -- happens while the old
        sink is still serving. The old one is emptied before the new one is
        filled because they may share a table: a protocol or table change
        leaves the old routes keyed differently from the new ones, and
        nothing but their owner could remove them afterwards. ``install``
        turned off is this same path, with a ``NullSink`` as the new sink,
        and is why turning it off empties the table at once.

        :raises Exception: on failure, after putting ``old`` back.
        """
        wanted = get_path(document, ('ip', 'route', 'install')) is True
        opener = getattr(new, 'open', None)
        if wanted and getattr(new, 'writes', False) and opener is not None:
            opener()
        try:
            old.shutdown(retain=False)
        except Exception:
            _log.exception('%s: fib sink %s failed to shut down while being '
                           'replaced', self.name, old.name)
        self._set_sink(new)
        try:
            self._populate_sink(new)
        except Exception:
            self._set_sink(old)
            try:
                new.shutdown(retain=False)
            except Exception:
                _log.exception('%s: fib sink %s failed to shut down after a '
                               'failed switch', self.name, new.name)
            self._restore_sink(old)
            raise
        _log.info('%s: fib sink is now %s', self.name, new.name)

    def _restore_sink(self, sink):
        """Bring a sink this engine shut down back to its committed state."""
        try:
            if getattr(sink, 'writes', False):
                self._sync_fib_open(self.store.document(redact=False))
            else:
                self._populate_sink(sink)
        except Exception:
            _log.exception('%s: fib sink %s could not be restored',
                           self.name, sink.name)

    def _populate_sink(self, sink):
        """Hand a newly active sink everything the RIB has already chosen.

        Reconcile first -- adopt our routes a previous run left that still
        match, delete those that do not -- then install every current
        winner; an adopted route is recognised and costs nothing. Without
        the install, turning ``install`` on at runtime would only ever have
        reached the kernel with routes that changed afterwards.
        """
        current = []
        for afi in (AFI_IP, AFI_IP6):
            current.extend(self.global_rib.routes(afi))
        reconcile = getattr(sink, 'reconcile', None)
        if reconcile is not None and getattr(sink, 'writes', False):
            report = reconcile(current)
            _log.info('%s: fib sink %s reconciled: %s', self.name,
                      sink.name, report)
        for route in current:
            sink.install(route)
        self._kick_fib()

    def _sync_fib_open(self, document):
        """Open or close a writing sink to match ``ip route install``.

        What the engine used to do for an injected sink on every commit, at
        construction included. Now only on a running engine, and at start.

        :param document: the committed (or being committed) document.
        """
        sink = self.sink
        if not getattr(sink, 'writes', False):
            return
        opener = getattr(sink, 'open', None)
        if opener is None:
            return
        wanted = get_path(document, ('ip', 'route', 'install')) is True
        is_open = getattr(sink, 'is_open', None)
        already = bool(is_open()) if is_open is not None else None
        if wanted and already is not True:
            opener()
            try:
                self._populate_sink(sink)
            except Exception:
                closer = getattr(sink, 'close', None)
                if closer is not None:
                    closer()
                raise
        elif not wanted and already:
            # Turning install off is not the same as stopping: the routes
            # we put in the kernel are ours and nobody else will remove
            # them, so they go now rather than at shutdown.
            sink.shutdown(retain=False)

    def _roll_back_core(self, change, current):
        """Undo a :meth:`_commit_core` that failed part-way. Best effort.

        :param change: the change that was being committed.
        :param current: the document still in the store.
        :return: True if everything was restored.
        """
        restored = True
        if change.previous is not None:
            old, old_spec = change.previous
            try:
                if self._fib_live():
                    self._switch_sink(self.sink, old, current)
                else:
                    self._set_sink(old)
                self._fib_spec = old_spec
            except Exception:
                restored = False
                _log.exception('%s: the previous fib sink could not be '
                               'restored', self.name)
        try:
            self._apply_core_sections(current)
        except Exception:
            restored = False
            _log.exception('%s: the core configuration could not be '
                           'restored', self.name)
        return restored
    # --- routing -----------------------------------------------------------

    def schedule_select(self):
        """Ask for a selection pass, coalescing repeated requests.

        A plugin calls this after offering or retracting routes. Several
        calls inside one loop iteration produce one pass, and a call made
        while a pass is running makes that pass go round again rather than
        starting a second one -- selection is not re-entrant, and two
        concurrent passes over the same change queue would publish the same
        destination twice.
        """
        if self._loop is None or not self._accepting_work():
            return
        if self.in_loop():
            self._kick_select()
        else:
            self._loop.call_soon_threadsafe(self._kick_select)

    def _accepting_work(self):
        """Whether background work may be scheduled: up, or coming up."""
        return bool((self._running or self._starting)
                    and not self._stopping)

    def _kick_select(self):
        self._select_wanted = True
        if self._select_retry is not None:
            self._select_retry.cancel()
            self._select_retry = None
        if self._select_task is None or self._select_task.done():
            self._select_task = self._loop.create_task(self._drain_select())

    async def _drain_select(self):
        failed = False
        try:
            while self._select_wanted:
                self._select_wanted = False
                await self.global_rib.drain(self.select_batcher)
                self._kick_fib()
        except asyncio.CancelledError:
            raise
        except Exception:
            failed = True
            _log.exception('%s: selection pass failed; retrying in %.1fs',
                           self.name, SELECT_RETRY_S)
        finally:
            self._select_task = None
            if failed and self._accepting_work():
                # E-5: the queue the pass was draining, and any request
                # coalesced into it while it ran, are still owed a pass.
                # Dropping them here left the RIB unselected until some
                # unrelated change happened to ask again. Retried after a
                # pause rather than at once, so a pass that fails every
                # time costs a log line a second and not the loop.
                self._select_wanted = True
                self._select_retry = self._loop.call_later(
                    SELECT_RETRY_S, self._kick_select)
                # Whatever the pass did publish before failing is in the
                # sink's queue, and must not wait for the retry.
                self._kick_fib()

    # --- the forwarding-plane pump (E-1) ------------------------------------

    def _kick_fib(self):
        """Make sure the FIB pump is running, if there is a loop to run it."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        if self._fib_timer is not None:
            self._fib_timer.cancel()
            self._fib_timer = None
        if self._fib_task is None or self._fib_task.done():
            self._fib_task = loop.create_task(self._pump_fib())

    async def _pump_fib(self):
        """Flush the sink until it has nothing left to do.

        E-1: selection used to flush once at the end of a pass, and a
        netlink flush writes one bounded batch -- so a full table's
        convergence installed the first few hundred routes and left the
        rest in the queue until some later RIB event flushed again. This
        keeps going, yielding between flushes, for as long as the sink
        says there is work, and hands a long wait (a retry's backoff) to a
        timer rather than sleeping on it.
        """
        # No `finally: self._fib_task = None`: a pump cancelled by stop()
        # runs its finally later, and could clear the handle of a newer
        # pump. _kick_fib tests done(), which a finished pump always is.
        while True:
            self._flush_sink()
            delay = self._fib_delay()
            if delay is None:
                return
            if delay > FIB_PUMP_MAX_SLEEP:
                self._fib_timer = self._loop.call_later(delay,
                                                        self._kick_fib)
                return
            await asyncio.sleep(delay)

    def _fib_delay(self):
        """Ask the sink when it next has work; None for idle."""
        asker = getattr(self.sink, 'next_flush_in', None)
        if asker is None:
            return None
        try:
            delay = asker()
        except Exception:
            _log.exception('%s: fib sink %s could not say when to flush',
                           self.name, self.sink.name)
            return None
        if delay is None:
            return None
        return max(0.0, float(delay))

    def _stop_fib_work(self):
        """Cancel the pump, its timer and any selection retry. Loop thread."""
        for name in ('_fib_timer', '_select_retry'):
            handle = getattr(self, name)
            if handle is not None:
                handle.cancel()
                setattr(self, name, None)
        task = self._fib_task
        if task is not None and not task.done():
            task.cancel()
        self._fib_task = None

    def _flush_sink(self):
        """Give the forwarding sink a bounded turn after a selection pass.

        Selection only *queues* installs and withdrawals -- a sink that
        wrote to a kernel synchronously inside selection would put a
        syscall per route on the critical path and a blocking one at that.
        Something therefore has to drain the queue, and the end of a
        selection pass is the right place: it is exactly when there is
        something to drain, and it is already on the loop thread.

        Bounded by the sink, not by a count here: ``flush`` is documented
        to do at most one pass of sends and acks and to leave the rest for
        the next call, so this cannot hold the loop however deep the queue
        is. A sink with nothing to flush is a no-op.

        :return: whatever the sink reported, or 0 for a sink that does not
            implement flushing.
        """
        flush = getattr(self.sink, 'flush', None)
        if flush is None:
            return 0
        try:
            return flush()
        except Exception:
            # A forwarding plane that cannot be written to must not take
            # the control plane down with it. The sink's own counters and
            # its health status are how this surfaces; see fib/sink.py.
            _log.exception('%s: fib sink %s failed to flush', self.name,
                           self.sink.name)
            return 0

    def select(self, limit=0):
        """Run selection to completion synchronously.

        For tests and for start-up, where there is no loop to be polite to.
        A running engine's bulk paths use :meth:`schedule_select`, which
        yields between slices.

        :param limit: destinations to examine per table per pass, 0 for
            unbounded.
        :return: the number of destinations examined.
        """
        return self.global_rib.select(limit)

    # --- operational surface ------------------------------------------------

    def _install_core_handlers(self):
        self._show_handlers[('ip', 'route')] = self._show_ip_route
        self._show_handlers[('ipv6', 'route')] = self._show_ipv6_route
        self._show_handlers[('engine', 'status')] = lambda: self.status()
        self._show_handlers[('engine', 'health')] = lambda: self.health()
        self._show_handlers[('running-config',)] = \
            lambda: self.running_config()
        # Policy is shown from the core for the same reason it is stored
        # there. The hit counters are the point of these commands: a
        # prefix-list entry that has never matched anything is either
        # wrong or unnecessary, and there is no other way to tell.
        # Both families answer from one store and one renderer, which
        # carries an ``afi`` on every entry: an operator asking about a
        # name should not have to know which namespace it landed in, and
        # two handlers that filtered by family would make `show ip
        # prefix-list FOO` say "no such list" about a list that exists.
        self._show_handlers[('ip', 'prefix-list')] = \
            lambda *a, **k: self.policy.prefix_list_dict(
                a[0] if a else None)
        self._show_handlers[('ipv6', 'prefix-list')] = \
            self._show_handlers[('ip', 'prefix-list')]
        self._show_handlers[('route-map',)] = \
            lambda *a, **k: self.policy.route_map_dict(a[0] if a else None)
        self._show_handlers[('ip', 'as-path-access-list')] = \
            lambda *a, **k: self.policy.as_path_list_dict(
                a[0] if a else None)

    def _show_route(self, afi, args, kwargs):
        # A trailing path segment is a prefix to look up, the way `show ip
        # route 10.0.0.0/8` reads. Without this the segment would be
        # silently ignored and the caller would get the whole table back
        # while believing it had asked about one destination.
        if args:
            prefix = args[0]
            if not hasattr(prefix, 'afi'):
                prefix = parse_prefix(prefix)
            table = self.global_rib.table(afi)
            dest = table.get(prefix) if table is not None else None
            if dest is None or dest.best is None:
                return {'prefix': prefix.to_str(), 'found': False,
                        'routes': []}
            found = dest.as_dict()
            found['found'] = True
            return found
        # The cursor arrives as text from REST and from anyone typing it,
        # and the RIB compares it with Prefix objects (S6-b: a 500 for
        # every second page). Parsed here, like the trailing prefix above.
        after = kwargs.get('after')
        if after is not None and not hasattr(after, 'afi'):
            try:
                after = parse_prefix(after)
            except ValueError as exc:
                raise ConfigError('after: %s' % (exc,), path='after')
            kwargs['after'] = after
        if after is not None and after.afi != afi:
            raise ConfigError('after: %s is not an %s prefix'
                              % (after.to_str(),
                                 'IPv4' if afi == AFI_IP else 'IPv6'),
                              path='after')
        return self.global_rib.as_dict(afi, **kwargs)

    def _show_ip_route(self, *args, **kwargs):
        return self._show_route(AFI_IP, args, kwargs)

    def _show_ipv6_route(self, *args, **kwargs):
        return self._show_route(AFI_IP6, args, kwargs)

    def show(self, *path, **kwargs):
        """Answer an operational query.

        Dispatch matches the longest registered path and passes whatever is
        left over as arguments, so one handler serves
        ``show('ip', 'bgp', 'neighbors')`` and
        ``show('ip', 'bgp', 'neighbors', '10.0.0.2')``. The REST layer
        dispatches on the same table, which is what keeps the two surfaces
        from drifting apart.

        :param path: the path segments.
        :param kwargs: passed to the handler; ``limit`` and ``after`` for
            the paginated tables.
        :return: a dict of plain types.
        :raises RtEngineError: nothing handles that path.
        """
        return self._call(self._do_show, tuple(path), kwargs)

    def _do_show(self, path, kwargs):
        for split in range(len(path), 0, -1):
            handler = self._show_handlers.get(path[:split])
            if handler is not None:
                return handler(*path[split:], **kwargs)
        raise RtEngineError('no such show path: %s' % ' '.join(map(str,
                                                                   path)))

    def clear(self, *path, **kwargs):
        """Run an operational action -- IOS ``clear``.

        :param path: the path segments.
        :param kwargs: passed to the handler, e.g. ``soft='in'``.
        :return: a dict of plain types.
        :raises RtEngineError: nothing handles that path.
        """
        return self._call(self._do_clear, tuple(path), kwargs)

    def _do_clear(self, path, kwargs):
        for split in range(len(path), 0, -1):
            handler = self._clear_handlers.get(path[:split])
            if handler is not None:
                return handler(*path[split:], **kwargs)
        raise RtEngineError('no such clear path: %s' % ' '.join(map(str,
                                                                    path)))

    def show_paths(self):
        """Return every registered show path.

        :return: a sorted list of tuples. The REST layer and its OpenAPI
            conformance test both enumerate from here.
        """
        return sorted(self._show_handlers)

    def clear_paths(self):
        """Return every registered clear path.

        The counterpart of :meth:`show_paths`, and it exists for a reason
        beyond symmetry: the REST layer resolves a ``/clear/...`` URL
        against this list *before* dispatching, so an unrecognised path
        is a 404 rather than an action nobody asked for. Dispatch matches
        the longest registered prefix and passes the remainder as
        arguments, which means a mistyped segment on a path that happens
        to share a prefix with a real one would otherwise be handed to a
        handler as an argument.

        :return: a sorted list of tuples.
        """
        return sorted(self._clear_handlers)

    def subscribe(self, event='*', q=None, maxsize=10000,
                  overflow='drop-oldest', name=None):
        """Subscribe to engine events with a bounded queue.

        :param event: an event name, or ``'*'`` for all of them.
        :param q: an existing bounded queue to deliver into.
        :param maxsize: bound for a queue created here.
        :param overflow: ``'drop-oldest'`` or ``'drop-newest'``.
        :param name: label for health output.
        :return: a :class:`~packets.routing.rtengine.events.Subscription`.
        """
        return self.bus.subscribe(event=event, q=q, maxsize=maxsize,
                                  overflow=overflow, name=name)

    # --- reporting ---------------------------------------------------------

    def status(self):
        """Return a short description of what this engine is.

        Separate from :meth:`health` on purpose: this is identity and
        configuration, which a human reads once, while health is a
        measurement something polls.

        :return: a dict of plain types.
        """
        from packets.routing.rtengine import __version__

        return {
            'name': self.name,
            'version': __version__,
            'running': self.is_running(),
            'revision': self.revision,
            'plugins': [{'name': p.name,
                         'afi_safi': [list(pair) for pair in p.afi_safi()]}
                        for p in self._plugins],
            'fib': {'sink': self.sink.name, 'writes': self.sink.writes},
            'policy': self.policy.stats(),
            'tables': sorted('%d/%d' % key
                             for key in self.global_rib.tables()),
            'api': {'bind': self.store.value(('api', 'bind'))},
        }

    def health(self):
        """Return the health document.

        The same document the REST endpoint serves.

        :return: a dict of plain types, with a ``status`` of ``ok``,
            ``degraded`` or ``down``.
        """
        return self.health_monitor.document()

    def __repr__(self):
        return '<Engine %s running=%s revision=%d plugins=%s>' % (
            self.name, self.is_running(), self.revision,
            ','.join(p.name for p in self._plugins) or 'none')


def _as_path(path):
    """Accept a configuration path as a tuple or a dotted string.

    :param path: tuple, list, or dotted string.
    :return: a tuple of keys.
    :raises ConfigError: empty.
    """
    if isinstance(path, (tuple, list)):
        parts = tuple(path)
    elif isinstance(path, str):
        parts = tuple(p for p in path.split('.') if p)
    else:
        raise ConfigError('a configuration path must be a tuple or a '
                          'dotted string, not %s' % type(path).__name__)
    if not parts:
        raise ConfigError('a configuration path is required')
    return parts


class _CoreChange(object):
    """What ``_prepare_core`` decided, for ``_commit_core`` to carry out.

    :ivar document: the proposed document.
    :ivar sink: a new, unopened sink to switch to, or None to keep the
        current one.
    :ivar spec: the ``fib_factory.sink_spec`` the new sink was built from.
    :ivar previous: ``(sink, spec)`` replaced by the commit, set once the
        switch has happened, for the rollback.
    """

    __slots__ = ('document', 'sink', 'spec', 'previous')

    def __init__(self, document):
        self.document = document
        self.sink = None
        self.spec = None
        self.previous = None


def _plugin_name(committed, affected):
    """Return the name of the plugin whose commit raised.

    It is the next one after those that succeeded, which is the only way to
    identify it once the exception has unwound past the loop variable.

    :param committed: the (plugin, diff) pairs that succeeded.
    :param affected: every (plugin, diff) pair in order.
    :return: the plugin's name, or ``'unknown'``.
    """
    index = len(committed)
    if index < len(affected):
        return affected[index][0].name
    return 'unknown'
