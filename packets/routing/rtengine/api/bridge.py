# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The only way a request thread is allowed to touch the engine.

Flask is a synchronous WSGI application served by a pool of threads; the
engine is a single asyncio loop that owns every mutable thing in the process.
A handler that read ``engine.global_rib`` directly would be reading a
structure another thread is rewriting, and the failure mode of that is not an
exception but a wrong answer. So there is exactly one door, and this module
is it: :meth:`CommandBridge.call` hands a callable to the loop through
``Engine.submit`` and waits for the result.

**Waiting is the interesting part, not the marshalling.** An HTTP client can
give up, and the question of what happens to the work it asked for has three
different honest answers depending on when it gave up:

* The command had not started. It is cancelled and *never runs*: the
  configuration change the client abandoned does not land four seconds later
  with nobody watching. The response says ``state: cancelled`` and the client
  knows nothing happened.
* The command had started. It is not interrupted -- half-applying a
  configuration change is the one outcome this design exists to prevent -- so
  it runs to completion and the response says ``state: unknown`` and carries
  the revision as it was *before* the call. The client re-reads and finds out
  which way it went.
* The command finished in time. The ordinary case.

The distinction is not decorative. ``concurrent.futures.Future.cancel()``
returns False once the callback is running, which is precisely the
information needed, and :meth:`Engine.submit` closes the race from the other
side by marking the future running as the first thing its callback does.
There is therefore no window in which a command both starts and is reported
cancelled.

**One rule for callers, and it is not optional: a callable handed to this
bridge must not touch Flask's globals.** ``current_app``, ``request`` and
anything built on them -- including this package's own ``ctx()``,
``engine()`` and ``bridge()`` helpers -- resolve through a context that
belongs to the *request* thread. On Flask 0.12, which is what the deployment
target has, that context is a thread-local and the loop thread sees nothing:
the callable dies with ``RuntimeError: Working outside of application
context``. On Flask 3 the same code appears to work, because asyncio's
``call_soon_threadsafe`` copies the calling thread's ``contextvars`` and
Flask 3 keeps its context in one -- so this mistake passes every test on a
developer's machine and fails every request on the appliance. Resolve what
you need on the request thread and pass it in as an argument, which is why
every handler in this package hands the engine to its loop callable
explicitly instead of closing over ``engine()``.
"""

import concurrent.futures
import logging
import threading

from packets.routing.rtengine.errors import RtEngineError, UnavailableError

_log = logging.getLogger('packets.rtengine.api.bridge')

#: A command that timed out before it began. Nothing was applied.
CANCELLED = 'cancelled'

#: A command that timed out while running. It completed, or will, and the
#: client has to re-read to find out.
UNKNOWN = 'unknown'


class BridgeTimeout(RtEngineError):
    """A command did not finish inside the request's time budget.

    ``state`` is :data:`CANCELLED` or :data:`UNKNOWN`; ``revision`` is the
    configuration revision as it was when the call was made, so a client
    that sees ``unknown`` has something to compare against.
    """

    error = 'Timeout'

    def __init__(self, detail, state=UNKNOWN, revision=None, path=None):
        super(BridgeTimeout, self).__init__(detail, path)
        self.state = state
        self.revision = revision

    def as_dict(self):
        body = super(BridgeTimeout, self).as_dict()
        body['state'] = self.state
        body['revision'] = self.revision
        return body


#: Commands the bridge lets wait on the loop at once before refusing (A-5).
MAX_IN_FLIGHT = 64

#: The ``Retry-After`` a refused request is given, in seconds.
RETRY_AFTER_S = 1


class BridgeBusy(UnavailableError):
    """Too many commands are already waiting on the loop (A-5).

    A 503 like any other unavailability, plus how long to wait: the loop
    is alive, just behind, and a client that retries in a second is doing
    the right thing.

    :ivar retry_after: seconds, for the ``Retry-After`` header.
    """

    def __init__(self, detail, retry_after=RETRY_AFTER_S, path=None):
        super(BridgeBusy, self).__init__(detail, path)
        self.retry_after = retry_after


class CommandBridge(object):
    """Runs callables on the engine's loop on behalf of request threads.

    :param engine: the :class:`~packets.routing.rtengine.engine.Engine`.
    :param timeout: default seconds to wait for a command. Ten seconds is
        long enough for any configuration change this engine makes and
        short enough that a wedged loop is reported rather than holding a
        WSGI worker forever.
    :param max_in_flight: commands allowed to be queued or running on the
        loop at once; 0 for no cap. A command counts until it *finishes*,
        not until its caller stops waiting, so one that timed out while
        running still holds its place -- the loop is still paying for it.
        Without the cap, a client hammering a slow ``show`` piles
        callbacks onto the loop faster than it can run them, and every
        one of them is work the BGP sessions wait behind.
    """

    def __init__(self, engine, timeout=10.0, max_in_flight=MAX_IN_FLIGHT):
        self.engine = engine
        self.timeout = float(timeout)
        self.max_in_flight = int(max_in_flight)
        self._lock = threading.Lock()
        self.calls = 0
        self.timeouts = 0
        self.cancelled = 0
        self.unknown = 0
        self.inline = 0
        self.in_flight = 0
        self.refused = 0

    def call(self, fn, *args, **kwargs):
        """Run a callable on the loop thread and return its result.

        :param fn: the callable, which runs on the loop thread.
        :param args: positional arguments for it.
        :param kwargs: keyword arguments for it.
        :return: whatever the callable returned.
        :raises BridgeTimeout: it did not finish in time.
        :raises UnavailableError: the engine is not running.
        :raises Exception: whatever the callable raised, re-raised here.
        """
        return self.call_timeout(self.timeout, fn, *args, **kwargs)

    def call_timeout(self, timeout, fn, *args, **kwargs):
        """As :meth:`call`, with an explicit budget.

        A separate method rather than a ``timeout`` keyword because the
        callable has keywords of its own and a reserved name that silently
        shadowed one of them would be a trap set for the next caller.

        :param timeout: seconds to wait, or None to wait indefinitely.
        :param fn: the callable.
        :param args: positional arguments.
        :param kwargs: keyword arguments.
        :return: the callable's result.
        """
        engine = self.engine
        with self._lock:
            self.calls += 1

        # An engine running on the caller's own thread -- an embedded
        # application serving the API from inside its loop, and the
        # simplest tests -- has no marshalling to do, and submitting to
        # the loop we are already on would deadlock on the result.
        if engine.in_loop():
            with self._lock:
                self.inline += 1
            return fn(*args, **kwargs)

        with self._lock:
            if self.max_in_flight and self.in_flight >= self.max_in_flight:
                self.refused += 1
                raise BridgeBusy(
                    'the engine already has %d API commands waiting; '
                    'retry shortly' % (self.in_flight,))
            self.in_flight += 1
        before = engine.revision
        try:
            future = engine.submit(fn, *args, **kwargs)
        except BaseException:
            self._settled(None)
            raise
        # Released when the command finishes or is cancelled, on whichever
        # thread that happens -- not when this thread gives up on it.
        future.add_done_callback(self._settled)
        try:
            return future.result(timeout)
        except concurrent.futures.TimeoutError:
            # cancel() is the arbiter, not a timer: it succeeds only while
            # the callback has not started, because submit()'s runner
            # marks the future running before it touches anything.
            if future.cancel():
                with self._lock:
                    self.timeouts += 1
                    self.cancelled += 1
                raise BridgeTimeout(
                    'the engine did not start this command within %.3gs, '
                    'so it was cancelled and nothing was applied'
                    % (timeout,), state=CANCELLED, revision=before)
            with self._lock:
                self.timeouts += 1
                self.unknown += 1
            _log.warning('command %s exceeded %.3gs while running; the '
                         'client was told state=unknown',
                         getattr(fn, '__name__', fn), timeout)
            raise BridgeTimeout(
                'the engine was still running this command after %.3gs; it '
                'completes atomically, so re-read to see whether it applied'
                % (timeout,), state=UNKNOWN, revision=before)

    def show(self, *path, **kwargs):
        """Run an operational query. Convenience for the show blueprint.

        :param path: the show path segments.
        :param kwargs: handler keywords such as ``limit``.
        :return: the handler's document.
        """
        return self.call(self.engine.show, *path, **kwargs)

    def clear(self, *path, **kwargs):
        """Run an operational action. Convenience for the clear blueprint.

        :param path: the clear path segments.
        :param kwargs: handler keywords such as ``soft``.
        :return: the handler's document.
        """
        return self.call(self.engine.clear, *path, **kwargs)

    def require_running(self):
        """Raise if the engine cannot serve requests right now.

        Called by the blueprints before a read that does not otherwise
        touch the loop, so a stopped engine answers ``503 Unavailable``
        rather than a plausible-looking document assembled from state
        nobody is maintaining.

        :raises UnavailableError: the engine is not running.
        """
        if not self.engine.is_running():
            raise UnavailableError('the engine is not running')

    def _settled(self, _future):
        with self._lock:
            self.in_flight -= 1

    def stats(self):
        """Return bridge counters for the health document.

        :return: a dict of plain types.
        """
        with self._lock:
            return {
                'calls': self.calls,
                'inline': self.inline,
                'timeouts': self.timeouts,
                'cancelled': self.cancelled,
                'unknown': self.unknown,
                'timeout_s': self.timeout,
                'in_flight': self.in_flight,
                'max_in_flight': self.max_in_flight,
                'refused': self.refused,
            }

    def __repr__(self):
        return '<CommandBridge calls=%d timeouts=%d timeout=%.3gs>' % (
            self.calls, self.timeouts, self.timeout)
