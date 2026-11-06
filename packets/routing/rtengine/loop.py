# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""asyncio helpers for the 3.6 floor, and the deadline-bounded Batcher.

Two unrelated jobs live here because both are about the event loop.

**The 3.6 helpers.** The engine must run on Python 3.6.8 and on 3.11+, and
asyncio changed shape between them: ``asyncio.run``, ``get_running_loop`` and
``asyncio.all_tasks`` do not exist on 3.6, while ``Task.all_tasks`` and the
``loop=`` keyword on ``gather``/``sleep`` were removed by 3.10. Every one of
those differences is wrapped exactly once, here, so no other module has a
version test in it.

**The Batcher.** The engine runs one asyncio loop and does its heavy work --
applying a received table, running selection, diffing outbound state,
flushing the FIB -- in Cython, under the GIL, on that same thread. Cython
makes that work fast; it does not make it interruptible. A million-prefix
UPDATE burst processed in one call blocks the loop for as long as it takes,
and a loop that is blocked is not sending KEEPALIVEs: the peer holds us down
after its hold time and the table has to be relearned. That is the failure
mode the whole design is arranged to avoid.

So every bulk job is sliced by **time, not by item count**. A count-based
batch is a guess about how long an item takes, and it is wrong by orders of
magnitude between a /32 with one path and a prefix with eight candidate paths
on a loaded machine. The Batcher measures instead: it runs a step function in
slices, stops each slice when its wall-clock budget is spent, and hands
control back to the loop before starting the next one.

The budget adapts. If measured loop lag rises, the budget shrinks, so the
engine trades table-load throughput for responsiveness exactly when it is
falling behind; when lag is low it grows again, up to a cap. Slice count,
overruns and the worst slice are all reported so ``/engine/health`` can show
whether the batching is actually working rather than asserting that it does.
"""

import asyncio
import threading
import time

_monotonic = time.monotonic


def new_loop():
    """Create a fresh event loop without touching the process-wide policy.

    ``asyncio.new_event_loop()`` deliberately does not install the loop as
    the current one. The engine keeps it that way: an embedded library that
    replaced the importing application's event loop would be a very
    unpleasant surprise.

    :return: a new, unstarted event loop.
    """
    return asyncio.new_event_loop()


def all_tasks(loop):
    """Return the unfinished tasks on a loop, on any supported version.

    ``asyncio.all_tasks`` arrived in 3.7 and ``Task.all_tasks`` was removed
    in 3.9, so both spellings are needed and neither exists everywhere.

    :param loop: the loop to inspect.
    :return: a set of tasks, empty if the version exposes neither.
    """
    getter = getattr(asyncio, 'all_tasks', None)
    if getter is not None:
        try:
            return set(getter(loop))
        except RuntimeError:
            # 3.12 raises when there is no running loop and the argument is
            # not accepted positionally in some builds; fall through.
            pass
    legacy = getattr(asyncio.Task, 'all_tasks', None)
    if legacy is not None:
        return set(legacy(loop))
    return set()


def run_coroutine(loop, coro):
    """Schedule a coroutine on a loop from another thread.

    :param loop: the target loop, already running.
    :param coro: the coroutine to run.
    :return: a ``concurrent.futures.Future`` for the result.
    """
    return asyncio.run_coroutine_threadsafe(coro, loop)


def ensure_future(loop, coro):
    """Schedule a coroutine on a loop from inside that loop's thread.

    :param loop: the loop to schedule on.
    :param coro: the coroutine.
    :return: the resulting Task.
    """
    return asyncio.ensure_future(coro, loop=loop)


def wait_tasks(loop, tasks, timeout):
    """Return a future that resolves when every task is done, or on timeout.

    For waiting on work that must be allowed to finish -- a session
    getting its NOTIFICATION out -- without cancelling it on expiry, which
    is what ``asyncio.wait_for`` would do, and without ``asyncio.wait``'s
    lookup of the thread's default loop on 3.6, which is deliberately not
    the engine's.

    :param loop: the loop the tasks run on; must be called on its thread.
    :param tasks: the tasks or futures to wait for.
    :param timeout: seconds to wait at most.
    :return: a future whose result is the number of tasks still running.
    """
    waiter = loop.create_future()
    pending = set(t for t in tasks if not t.done())

    def _finish(_ignored=None):
        if not waiter.done():
            waiter.set_result(len([t for t in pending if not t.done()]))

    def _one_done(task):
        pending.discard(task)
        if not pending:
            _finish()

    if not pending:
        _finish()
        return waiter
    for task in list(pending):
        task.add_done_callback(_one_done)
    handle = loop.call_later(timeout, _finish)
    waiter.add_done_callback(lambda _f: handle.cancel())
    return waiter


def shutdown_loop(loop, timeout=5.0):
    """Cancel everything still running on a loop, then close it.

    Order matters and is the reason this is not three lines at the call
    site: tasks are cancelled first and then given the loop back so their
    ``finally`` blocks and ``CancelledError`` handlers actually run. Closing
    a loop with live tasks logs "Task was destroyed but it is pending" and
    skips that cleanup, which for this engine means sockets left open and
    peers left hanging.

    :param loop: a stopped, not yet closed loop.
    :param timeout: seconds to wait for cancellation to settle.
    :return: the number of tasks that were cancelled.
    """
    pending = [t for t in all_tasks(loop) if not t.done()]
    for task in pending:
        task.cancel()
    if pending:
        waiter = asyncio.wait(pending, timeout=timeout)
        try:
            loop.run_until_complete(waiter)
        except RuntimeError:
            # Already closed, or re-entered from inside the loop. Nothing
            # useful left to do, and raising here would mask the original
            # reason for the shutdown.
            pass
    try:
        shutdown_gens = getattr(loop, 'shutdown_asyncgens', None)
        if shutdown_gens is not None:
            loop.run_until_complete(shutdown_gens())
    except RuntimeError:
        pass
    loop.close()
    return len(pending)


class Batcher(object):
    """Runs a bulk job in slices bounded by wall-clock time.

    Usage is a step function that does a chunk of work and reports how many
    items it handled, with 0 meaning "nothing left"::

        batcher = Batcher(budget_ms=5.0, name='select')
        await batcher.drain(lambda chunk: table.reselect(chunk))

    :param budget_ms: how long one slice may hold the loop, in
        milliseconds. 5 ms is the default because it is well under the
        smallest timer the engine cares about (a 1 second keepalive
        interval at the RFC 4271 minimum hold time of 3 seconds) while
        still being long enough to amortise the per-slice overhead.
    :param chunk: how many items a step is asked for at a time. The budget,
        not this, decides when a slice ends; the chunk only bounds how far
        past the deadline a slice can run, since a step is never
        interrupted in the middle.
    :param name: label used in health output.
    :param min_budget_ms: floor for adaptation.
    :param max_budget_ms: ceiling for adaptation.
    """

    __slots__ = ('name', 'budget_ms', 'chunk', 'min_budget_ms',
                 'max_budget_ms', '_deadline', '_slice_start', 'slices',
                 'items', 'total_ms', 'max_slice_ms', 'overruns', 'yields')

    def __init__(self, budget_ms=5.0, chunk=256, name='batch',
                 min_budget_ms=0.5, max_budget_ms=50.0):
        if budget_ms <= 0.0:
            raise ValueError('budget_ms must be positive')
        if chunk < 1:
            raise ValueError('chunk must be at least 1')
        self.name = name
        self.budget_ms = float(budget_ms)
        self.chunk = int(chunk)
        self.min_budget_ms = float(min_budget_ms)
        self.max_budget_ms = float(max_budget_ms)
        self._deadline = 0.0
        self._slice_start = 0.0
        self.slices = 0
        self.items = 0
        self.total_ms = 0.0
        self.max_slice_ms = 0.0
        self.overruns = 0
        self.yields = 0

    def begin(self):
        """Open a slice and return its deadline."""
        self._slice_start = _monotonic()
        self._deadline = self._slice_start + self.budget_ms / 1000.0
        return self._deadline

    def expired(self):
        """Return whether the open slice has spent its budget.

        :return: True when the step loop should stop and yield.
        """
        return _monotonic() >= self._deadline

    def end(self, items=0):
        """Close a slice and fold it into the statistics.

        :param items: how many items the slice processed.
        :return: the slice duration in milliseconds.
        """
        elapsed_ms = (_monotonic() - self._slice_start) * 1000.0
        self.slices += 1
        self.items += items
        self.total_ms += elapsed_ms
        if elapsed_ms > self.max_slice_ms:
            self.max_slice_ms = elapsed_ms
        # An overrun is a slice that ran materially past its budget, which
        # means one step call alone cost more than the whole slice was
        # allowed. That is the signal to lower `chunk`, and it is worth
        # counting because it is invisible in an average.
        if elapsed_ms > self.budget_ms * 2.0:
            self.overruns += 1
        return elapsed_ms

    def run_slice(self, step):
        """Run one slice of a job synchronously.

        :param step: callable taking a chunk size and returning the number
            of items it processed; 0 means there is nothing left.
        :return: ``(items_processed, done)`` where ``done`` is True when the
            step reported nothing left to do.
        """
        done = False
        processed = 0
        self.begin()
        try:
            while True:
                n = step(self.chunk)
                if not n:
                    done = True
                    break
                processed += n
                if self.expired():
                    break
        finally:
            # Accounted even when the step raised, so a job that fails
            # mid-slice still shows up in the health numbers instead of
            # silently vanishing from them.
            self.end(processed)
        return processed, done

    async def drain(self, step):
        """Run a job to completion, yielding to the loop between slices.

        This is the form every bulk job in the engine uses. The
        ``sleep(0)`` between slices is not a pause: it is the point at which
        the loop gets to run its ready callbacks -- read a socket, fire a
        keepalive timer, answer a bridge command -- before the next slice
        starts.

        :param step: callable taking a chunk size and returning the number
            of items processed; 0 means done.
        :return: the total number of items processed.
        """
        total = 0
        while True:
            processed, done = self.run_slice(step)
            total += processed
            if done:
                return total
            self.yields += 1
            await asyncio.sleep(0)

    def adapt(self, lag_ms):
        """Resize the budget from the loop lag actually being observed.

        Lag well above the budget means the loop is not getting back often
        enough, so the budget halves -- responsiveness is bought with table
        throughput precisely when the engine is behind. Lag comfortably
        below it means there is headroom, so the budget grows, but by a
        quarter rather than by doubling: recovering slowly and degrading
        quickly is the right asymmetry when the cost of being wrong is a
        dropped session.

        :param lag_ms: most recently measured loop lag, in milliseconds.
        :return: the new budget in milliseconds.
        """
        if lag_ms > self.budget_ms * 2.0:
            self.budget_ms = max(self.min_budget_ms, self.budget_ms / 2.0)
        elif lag_ms < self.budget_ms * 0.5:
            self.budget_ms = min(self.max_budget_ms, self.budget_ms * 1.25)
        return self.budget_ms

    def stats(self):
        """Return the slice statistics for health output.

        :return: a dict of plain numbers.
        """
        mean = self.total_ms / self.slices if self.slices else 0.0
        return {
            'name': self.name,
            'budget_ms': round(self.budget_ms, 3),
            'chunk': self.chunk,
            'slices': self.slices,
            'items': self.items,
            'yields': self.yields,
            'mean_slice_ms': round(mean, 3),
            'max_slice_ms': round(self.max_slice_ms, 3),
            'overruns': self.overruns,
        }

    def reset_stats(self):
        """Zero the counters, keeping the current budget."""
        self.slices = 0
        self.items = 0
        self.total_ms = 0.0
        self.max_slice_ms = 0.0
        self.overruns = 0
        self.yields = 0

    def __repr__(self):
        return '<Batcher %s budget=%.2fms slices=%d items=%d>' % (
            self.name, self.budget_ms, self.slices, self.items)


class LoopThread(object):
    """A daemon thread that owns one event loop.

    The engine runs this way in embedded use: the importing application
    keeps its own thread (and possibly its own loop) and the engine's loop
    lives here, reachable only through thread-safe calls. Daemon, so a
    caller that forgets to stop the engine does not hang interpreter
    shutdown -- the engine is a component of someone else's program, not
    the program.

    :param loop: the loop to run.
    :param name: thread name, visible in tracebacks and ``ps``.
    """

    __slots__ = ('loop', 'name', '_thread', '_started')

    def __init__(self, loop, name='rtengine'):
        self.loop = loop
        self.name = name
        self._thread = None
        self._started = threading.Event()

    def start(self, timeout=5.0):
        """Start the thread and wait until the loop is actually running.

        Waiting matters: returning before the loop runs would let a caller
        submit work that sits in a queue nothing is draining yet, and the
        failure would look like a hang rather than a start-up error.

        :param timeout: seconds to wait for the loop to come up.
        :raises RuntimeError: already started, or the loop did not start.
        """
        if self._thread is not None:
            raise RuntimeError('loop thread already started')
        self._thread = threading.Thread(target=self._run, name=self.name)
        self._thread.daemon = True
        self._thread.start()
        if not self._started.wait(timeout):
            raise RuntimeError('event loop did not start within %.1fs'
                               % timeout)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.call_soon(self._started.set)
        try:
            self.loop.run_forever()
        finally:
            self._started.clear()

    def is_running(self):
        """Return whether the loop thread is alive and the loop is up."""
        return self._thread is not None and self._thread.is_alive() \
            and self._started.is_set()

    def stop(self, timeout=5.0):
        """Ask the loop to stop and join the thread.

        :param timeout: seconds to wait for the thread to exit.
        :return: True if the thread exited within the timeout.
        """
        if self._thread is None:
            return True
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout)
        alive = self._thread.is_alive()
        if not alive:
            self._thread = None
        return not alive
