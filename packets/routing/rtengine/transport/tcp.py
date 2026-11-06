# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The BGP transport: one socket per session, and who gets to touch it.

This module owns exactly two things -- getting a TCP connection to a
configured peer, and accepting one from a configured peer -- and it is
deliberately the smallest module in the transport. The finite state machine,
the message framer and the keepalive timers live above it, so nothing here
knows what a BGP message is. That boundary is what makes the module
testable: a socket pair is enough.

**The ordering rule, which is the whole reason this code exists.** Every
authentication and TTL option has to be on the socket *before the SYN goes
out*, because the kernel signs and stamps the handshake itself:

* TCP-MD5 and TCP-AO digests cover the SYN and the SYN-ACK. A key installed
  after ``connect`` protects nothing -- the handshake either fails outright
  or, worse, succeeds unauthenticated because the peer was not demanding it;
* GTSM's outbound TTL of 255 has to be on the SYN or the peer's inbound
  minimum drops it;
* the ``update-source`` bind has to happen before connect because the
  source address is part of what the peer's own key and its ACL match.

That is why :func:`connect` builds the socket with ``socket.socket`` and
drives it with ``loop.sock_connect`` instead of calling
``loop.create_connection``: ``create_connection`` resolves, creates,
options and connects the socket in one step, and there is no hook in the
middle where a key can be installed. ``sock_connect``/``sock_accept`` have
existed since 3.4, work unchanged on 3.11, and leave us owning the
descriptor for the whole of its life. The same applies on the passive side,
only more so: **a listener's per-peer keys must be installed before
``accept``, because the kernel signs the SYN-ACK before there is a
connection to hand to us.** :meth:`Listener.add_peer` therefore writes
through to the listening socket immediately when it is already open.

**Never blocking the loop.** The engine runs one asyncio loop and it is also
the thread that answers KEEPALIVEs; a blocking ``connect`` to an
unreachable peer would hold it for the duration of the TCP timeout and cost
every *other* session its hold time. So every socket here is non-blocking
from the moment it is created, before any option is set, and every wait is a
loop await with a timeout around it.

**Cancellation.** The FSM cancels connect attempts routinely -- that is what
a collision-detected open or a ``clear ip bgp`` looks like from here. Every
coroutine in this module closes the socket it owns on the way out, on
``CancelledError`` as much as on failure, because a descriptor leaked on a
cancelled connect is a descriptor leaked once per retry timer for the life
of the process.

**Unconfigured sources are not the FSM's problem.** An inbound connection
from an address no neighbor is configured for is closed here and counted in
``rejected_unknown``. Passing it up would mean the FSM allocating peer state
for whoever happened to dial port 179, which is a resource-exhaustion path
with no upside: BGP has no notion of a dynamic peer in this engine's v1
configuration.
"""

import asyncio
import errno
import ipaddress
import logging
import socket

from packets.routing.rtengine.transport import auth

_log = logging.getLogger('packets.rtengine.transport.tcp')

__all__ = ['BGP_PORT', 'DEFAULT_BACKLOG', 'Connection', 'Listener',
           'connect']

#: The BGP port, from RFC 4271. Configurable ports are a lab feature and
#: the FSM passes one through; this is the default everywhere else.
BGP_PORT = 179

#: Listen backlog. Sized for the case that matters -- a router reboot
#: somewhere upstream bringing every configured peer back at once -- rather
#: than for steady state, where one entry would do. It is cheap; a dropped
#: SYN costs a peer its connect-retry timer.
DEFAULT_BACKLOG = 64

#: How long the accept loop pauses after an error it cannot attribute to a
#: single connection. EMFILE is the case in mind: the loop would otherwise
#: spin at full speed re-failing the same accept and starve the very tasks
#: that might close a descriptor.
ACCEPT_ERROR_PAUSE = 0.1

#: The port we install keys with. The kernel matches an MD5 or AO key on
#: address (with prefix and ifindex), not on port, and a BGP session's
#: remote port is 179 in one direction and ephemeral in the other -- so a
#: key installed for a specific port would match one direction only if the
#: kernel ever started caring. Zero is the honest value for "any port".
KEY_MATCH_ANY_PORT = 0

# Whether asyncio.wait_for still accepts loop=. True on 3.6-3.9, where the
# keyword is needed because the engine's loop is not the thread's current
# loop and asyncio would otherwise call get_event_loop() and fail; False on
# 3.10+, where the keyword was removed and asyncio finds the running loop
# by itself. Resolved on first use rather than by a version test, and
# cached because the answer cannot change.
_WAIT_FOR_TAKES_LOOP = None


def _wait_for(awaitable, timeout, loop):
    """Return an awaitable that applies ``timeout``, on any version.

    Not a coroutine: the version probe has to happen at *call* time, not
    at await time, so that a :exc:`TypeError` from the rejected ``loop=``
    keyword is raised before ``awaitable`` has been consumed and can be
    handed to the second attempt untouched.

    :param awaitable: the future or coroutine to bound.
    :param timeout: seconds, or None for no timeout.
    :param loop: the engine's loop.
    :return: an awaitable yielding the original result, raising
        :exc:`asyncio.TimeoutError` on expiry.
    """
    global _WAIT_FOR_TAKES_LOOP
    if timeout is None:
        return awaitable
    if _WAIT_FOR_TAKES_LOOP is not False:
        try:
            bounded = asyncio.wait_for(awaitable, timeout, loop=loop)
        except TypeError:
            _WAIT_FOR_TAKES_LOOP = False
        else:
            _WAIT_FOR_TAKES_LOOP = True
            return bounded
    return asyncio.wait_for(awaitable, timeout)


async def _pause(loop, delay):
    """Sleep on a specific loop, without ``asyncio.sleep``'s loop lookup.

    ``asyncio.sleep`` calls ``get_event_loop()`` on 3.6 when no ``loop=``
    is passed, and the engine's loop is deliberately not installed as the
    thread's current loop (see ``loop.py``), so that call raises rather
    than sleeping. A future plus ``call_later`` is the same thing with the
    loop named explicitly, and it reads identically on 3.6 and 3.11.

    :param loop: the loop to sleep on.
    :param delay: seconds.
    """
    waiter = loop.create_future()
    handle = loop.call_later(delay, _wake, waiter)
    try:
        await waiter
    finally:
        handle.cancel()


def _wake(waiter):
    """Complete a :func:`_pause` waiter unless it was already cancelled."""
    if not waiter.done():
        waiter.set_result(None)


def _split_addr(addr):
    """Normalise an address to ``(family, text, scope_id)``.

    The text that comes back is the canonical form of the address with any
    ``%zone`` removed, which is what makes it usable as a dictionary key:
    the listener has to compare a configured neighbor address against what
    ``accept`` reports, and ``::1``, ``::0001`` and ``0:0:0:0:0:0:0:1`` are
    the same peer written three ways.

    An IPv4-mapped IPv6 address collapses to its IPv4 form. Nothing in this
    engine listens dual-stack (see :meth:`Listener.start` for why), so this
    is defence against a caller's configuration rather than a normal path,
    but silently treating ``::ffff:10.0.0.1`` as a different peer from
    ``10.0.0.1`` would be a security-relevant mistake in
    :meth:`Listener.add_peer`.

    :param addr: an address as text, optionally with an IPv6 ``%zone``.
    :return: ``(family, canonical_text, scope_id)``.
    :raises ValueError: the address does not parse.
    """
    family, _packed, scope = auth.parse_addr(addr)
    text = addr.decode('ascii') if isinstance(addr, bytes) else addr
    text = text.strip().partition('%')[0]
    ip = ipaddress.ip_address(text)
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        return socket.AF_INET, str(mapped), 0
    return family, str(ip), scope


def _sockaddr(family, text, port, scope=0):
    """Build the address tuple ``bind``/``sock_connect`` expects.

    IPv6 takes a four-tuple because the scope id has nowhere else to go,
    and a link-local BGP neighbor without its scope is not routable.

    :param family: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :param text: a canonical numeric address, no zone.
    :param port: TCP port.
    :param scope: IPv6 interface index, 0 for none.
    :return: a 2-tuple or a 4-tuple.
    """
    if family == socket.AF_INET6:
        return (text, int(port), 0, int(scope))
    return (text, int(port))


def _close_quietly(loop, sock):
    """Close a socket and take it off the loop first.

    The order is the point. ``sock_connect``, ``sock_accept`` and
    ``sock_recv`` register a reader or writer for the descriptor; closing
    the descriptor while the selector still watches it leaves the loop
    polling a number that the *next* socket will be handed, and the
    symptom is a wakeup delivered to the wrong session. Errors are
    swallowed because every caller is already on a failure or shutdown
    path and has something better to report.

    :param loop: the loop that may hold callbacks for this socket.
    :param sock: the socket to close; None is accepted.
    """
    if sock is None:
        return
    try:
        fd = sock.fileno()
    except OSError:
        fd = -1
    if fd != -1:
        try:
            loop.remove_reader(fd)
            loop.remove_writer(fd)
        except (OSError, ValueError, RuntimeError):
            # RuntimeError: the loop is already closed, which happens on
            # the shutdown path and means the selector is gone anyway.
            pass
    try:
        sock.close()
    except OSError:
        pass


def _apply_auth(sock, peer_text, auth_mode, auth_key):
    """Install the peer's authentication key on a socket.

    Called before connect and before accept, never after. See the module
    docstring for why that is not negotiable.

    ``auth_key`` is a string for MD5 and a **mapping** for AO, because AO
    is not one key: a key chain has ``send-id``, ``recv-id``, an algorithm
    and the master key, and RFC 5925 rollover means more than one of them
    can be installed at once. The mapping keeps the key-chain lookup in the
    caller, where the configuration lives, instead of teaching the
    transport what a key chain is.

    :param sock: an unconnected socket or a listener.
    :param peer_text: the peer's canonical address.
    :param auth_mode: one of ``auth.AUTH_MODES``, or None for no
        authentication.
    :param auth_key: the password, or the AO key mapping.
    :return: None.
    :raises ValueError: unknown mode, or an AO mode without a key mapping.
    :raises OSError: the kernel refused the key.
    """
    if not auth_mode or auth_mode == auth.AUTH_NONE:
        return
    if auth_mode in (auth.AUTH_MD5, auth.AUTH_MD5_AO_FALLBACK):
        auth.set_md5(sock, peer_text, KEY_MATCH_ANY_PORT, auth_key)
        return
    if auth_mode == auth.AUTH_AO:
        if not isinstance(auth_key, dict):
            raise ValueError('auth mode %r needs a key mapping with '
                             'send-id, recv-id and key, got %s'
                             % (auth_mode, type(auth_key).__name__))
        auth.set_ao(sock, peer_text, KEY_MATCH_ANY_PORT,
                    auth_key.get('send-id', 0),
                    auth_key.get('recv-id', 0),
                    auth_key.get('key'),
                    alg=auth_key.get('alg', auth.AO_ALG_DEFAULT),
                    ifindex=auth_key.get('ifindex', 0))
        return
    raise ValueError('unknown auth mode %r' % (auth_mode,))


def _clear_auth(sock, peer_text, auth_mode, auth_key):
    """Remove a peer's key from a socket, best effort.

    Used when a neighbor is deconfigured. Failures are logged and
    swallowed: the key the caller wants gone is either gone or was never
    there, and neither case is worth failing a configuration commit over.

    :param sock: the socket holding the key, normally the listener.
    :param peer_text: the peer's canonical address.
    :param auth_mode: the mode the key was installed with.
    :param auth_key: the key material or AO mapping it was installed with.
    """
    if not auth_mode or auth_mode == auth.AUTH_NONE:
        return
    try:
        if auth_mode in (auth.AUTH_MD5, auth.AUTH_MD5_AO_FALLBACK):
            auth.clear_md5(sock, peer_text, KEY_MATCH_ANY_PORT)
        elif auth_mode == auth.AUTH_AO and isinstance(auth_key, dict):
            auth.del_ao(sock, peer_text, KEY_MATCH_ANY_PORT,
                        auth_key.get('send-id', 0),
                        auth_key.get('recv-id', 0),
                        ifindex=auth_key.get('ifindex', 0))
    except (OSError, ValueError) as exc:
        _log.debug('could not remove the %s key for %s: %s',
                   auth_mode, peer_text, exc)


class Connection(object):
    """An established BGP TCP connection and the socket under it.

    Deliberately thin. It does not frame messages, does not know a
    KEEPALIVE from an UPDATE, and holds no buffers of its own: the framer
    and the FSM sit above it and would have to be bypassed by anything
    clever added here. What it does own is the descriptor's lifetime and
    the endpoint facts that outlive it.

    Those facts are snapshotted at construction rather than read from the
    socket on demand, because ``show ip bgp neighbors`` and the log line
    for a session that has just dropped both want to say which addresses
    were involved, and by then ``getpeername`` fails.

    :param loop: the engine's loop; the socket is driven through it.
    :param sock: a connected, non-blocking socket this object now owns.
    :param auth_mode: the mode the session was authenticated with, for
        display. One of ``auth.AUTH_MODES`` or None.
    :param peer_addr: override the peer address; the canonical form from
        the configuration is preferred over ``getpeername``'s when the two
        differ in spelling.
    """

    __slots__ = ('sock', 'peer_addr', 'peer_port', 'local_addr',
                 'local_port', 'family', 'auth_mode', '_loop', '_closed')

    def __init__(self, loop, sock, auth_mode=None, peer_addr=None):
        self._loop = loop
        self.sock = sock
        self.auth_mode = auth_mode
        self.family = sock.family
        self._closed = False
        peer = _endpoint(sock.getpeername)
        local = _endpoint(sock.getsockname)
        self.peer_addr = peer_addr or peer[0]
        self.peer_port = peer[1]
        self.local_addr = local[0]
        self.local_port = local[1]

    async def send(self, data):
        """Write a complete message, yielding until it has all gone.

        A coroutine rather than a fire-and-forget buffer, and that is a
        design choice worth defending: ``loop.sock_sendall`` already does
        the partial-write bookkeeping a hand-rolled output buffer would
        duplicate, and making the caller await it means back-pressure
        reaches the update group that is generating the messages instead of
        accumulating in a queue this class would have to bound. The FSM is
        already inside a coroutine every time it sends.

        One rule comes with that: a single connection must not have two
        concurrent senders. Two ``sock_sendall`` calls on one socket
        interleave their writes and corrupt the stream. The FSM serialises
        sends per session; nothing here can enforce it.

        :param data: the bytes to send.
        :return: the number of bytes written, always ``len(data)``.
        :raises OSError: the connection is closed, or the write failed.
        """
        if self._closed or self.sock is None:
            raise OSError(errno.EPIPE, 'connection to %s is closed'
                          % (self.peer_addr,))
        await self._loop.sock_sendall(self.sock, data)
        return len(data)

    def send_nowait(self, data):
        """Write what the kernel will take *now*, without yielding.

        The one write that does not go through the session's writer, and
        the reason it exists is the NOTIFICATION. Every way a session ends
        -- an operator's stop, a neighbour deleted, a hold timer, a decode
        error -- reaches the transport from synchronous code, and a write
        scheduled as a task from there is a write that may never run: the
        socket is closed in the same breath, or the loop is about to stop.
        A NOTIFICATION is at most a few dozen bytes and an idle socket's
        send buffer holds tens of kilobytes, so a single non-blocking
        ``send`` puts it on the wire in practice; whatever does not fit is
        returned to the caller to finish asynchronously.

        Only legal while no :meth:`send` is in progress -- the same
        single-sender rule, for the same reason.

        :param data: the bytes to send.
        :return: how many bytes the kernel accepted, possibly 0.
        :raises OSError: the connection is closed or the write failed.
        """
        if self._closed or self.sock is None:
            raise OSError(errno.EPIPE, 'connection to %s is closed'
                          % (self.peer_addr,))
        try:
            return self.sock.send(data)
        except (BlockingIOError, InterruptedError):
            return 0

    def shutdown_write(self):
        """Half-close: send our FIN after everything already written.

        The peer then reads the NOTIFICATION and an orderly end of stream,
        which is how a BGP speaker tells "the session was closed and here
        is why" from "the TCP connection failed".

        :return: True if the FIN was queued.
        """
        if self._closed or self.sock is None:
            return False
        try:
            self.sock.shutdown(socket.SHUT_WR)
            return True
        except OSError:
            return False

    async def drain(self, timeout):
        """Read and discard until the peer closes, or ``timeout`` passes.

        The step between a half-close and :meth:`close`, and the one that
        is easy to leave out. Closing a socket that still has unread data
        in its receive queue makes the kernel answer with a reset instead
        of a FIN (RFC 2525 s2.17), and on Linux the far end then discards
        whatever of ours it had not yet read -- the NOTIFICATION included.
        A peer that is still sending KEEPALIVEs when we close is the
        ordinary case, not a corner one.

        :param timeout: seconds to wait at most.
        :return: True if the peer closed its side, False on timeout.
        """
        deadline = self._loop.time() + timeout
        while not self._closed and self.sock is not None:
            remaining = deadline - self._loop.time()
            if remaining <= 0:
                return False
            try:
                data = await _wait_for(self._loop.sock_recv(self.sock, 65536),
                                       remaining, self._loop)
            except asyncio.TimeoutError:
                return False
            except OSError:
                # Reset or already gone: nothing more will arrive.
                return True
            if not data:
                return True
        return True

    def close(self):
        """Close the connection, at most once.

        Idempotent because every path that can fail calls it: the FSM on a
        NOTIFICATION, the framer on a malformed message, the listener when
        a callback raises, and ``stop()`` on everything still open. A
        second call returning quietly is what lets those paths stay simple.

        :return: True if this call was the one that closed it.
        """
        if self._closed:
            return False
        self._closed = True
        _close_quietly(self._loop, self.sock)
        return True

    def is_open(self):
        """Report whether the connection can still carry messages.

        Checks the descriptor as well as the flag, because a socket can be
        closed underneath us -- by a failed ``sock_sendall``, or by
        interpreter shutdown finalising it -- without this object being
        told.

        :return: True when the socket is still usable.
        """
        if self._closed or self.sock is None:
            return False
        try:
            return self.sock.fileno() != -1
        except OSError:
            return False

    def __repr__(self):
        return '<Connection %s:%d -> %s:%d auth=%s%s>' % (
            self.local_addr, self.local_port, self.peer_addr,
            self.peer_port, self.auth_mode or auth.AUTH_NONE,
            '' if self.is_open() else ' closed')


def _endpoint(getter):
    """Return ``(address, port)`` from ``getsockname``/``getpeername``.

    Tolerant on purpose: this is only ever called to fill in display
    fields, and a socket that has already failed should not turn a
    connection object into an exception. IPv6 returns a four-tuple, hence
    the indexing rather than unpacking.

    :param getter: the bound socket method to call.
    :return: ``(address_text, port)``, with ``('', 0)`` when unavailable.
    """
    try:
        info = getter()
    except (OSError, AttributeError):
        return ('', 0)
    if not info:
        return ('', 0)
    addr = info[0]
    port = info[1] if len(info) > 1 else 0
    if isinstance(addr, str) and '%' in addr:
        addr = addr.partition('%')[0]
    return (addr, port)


async def connect(loop, peer_addr, port=BGP_PORT, local_addr=None,
                  auth_mode=None, auth_key=None, ttl=None, gtsm_hops=None,
                  timeout=None):
    """Open an authenticated BGP connection to a peer.

    The order of operations in the body is the contract, not an
    implementation detail, and it is the single most common thing to get
    wrong in a BGP transport:

    1. create the socket, non-blocking from the start;
    2. ``SO_REUSEADDR`` and ``TCP_NODELAY``;
    3. **install the MD5 or AO key**;
    4. GTSM or plain multihop TTL;
    5. ``bind`` to ``update-source``;
    6. only now, ``loop.sock_connect``.

    Steps 3 to 5 must precede step 6 because the kernel signs and stamps
    the SYN itself and the source address is chosen when the socket
    connects. A key installed after the connect returns applies to no
    segment that mattered: if the peer requires authentication the session
    fails, and if it does not, the session comes up *unauthenticated* and
    looks healthy, which is the worse of the two outcomes and the reason
    this is spelled out here rather than left to a reviewer to notice.

    ``gtsm_hops`` and ``ttl`` are different features and the first wins if
    both are given. ``ttl-security`` sets the TTL *and* enforces a minimum
    on receipt; ``ebgp-multihop`` only raises the TTL. Silently applying
    multihop on top of GTSM would lower the outbound TTL below 255 and
    break the peer's inbound check.

    :param loop: the engine's event loop.
    :param peer_addr: the neighbor address as text; no names are resolved,
        because a BGP neighbor is an address and a DNS lookup here would be
        a blocking call on the engine's thread.
    :param port: the peer's port; 179 unless a lab configuration says
        otherwise.
    :param local_addr: ``update-source`` address, or None to let the
        kernel choose.
    :param auth_mode: one of ``auth.AUTH_MODES``, or None.
    :param auth_key: the MD5 password, or the AO key mapping described in
        :func:`_apply_auth`.
    :param ttl: outbound TTL for ``ebgp-multihop``.
    :param gtsm_hops: hop count for ``ttl-security``; enables GTSM in both
        directions.
    :param timeout: seconds to allow for the whole attempt, or None. The
        FSM always passes one: the kernel's own SYN timeout is over two
        minutes, which is longer than any BGP timer wants to wait.
    :return: an established :class:`Connection`.
    :raises asyncio.TimeoutError: the timeout expired.
    :raises OSError: the connection failed, or an option was refused.
    :raises ValueError: an address, key or hop count is unusable.
    """
    family, text, scope = _split_addr(peer_addr)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        # Non-blocking before anything else touches it: an option set on a
        # blocking socket is fine, but a connect on one is not, and there
        # is no reason to leave a window where the wrong call would work.
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        _apply_auth(sock, text, auth_mode, auth_key)

        if gtsm_hops is not None:
            auth.set_gtsm(sock, family, gtsm_hops)
        elif ttl is not None:
            auth.set_ttl(sock, family, ttl)

        if local_addr is not None:
            src_family, src_text, src_scope = _split_addr(local_addr)
            if src_family != family:
                raise ValueError('update-source %s is not in the same '
                                 'address family as neighbor %s'
                                 % (local_addr, peer_addr))
            sock.bind(_sockaddr(src_family, src_text, 0, src_scope))

        target = _sockaddr(family, text, port, scope)
        await _wait_for(loop.sock_connect(sock, target), timeout, loop)
        conn = Connection(loop, sock, auth_mode=auth_mode, peer_addr=text)
        _log.debug('connected to %s:%d from %s:%d, auth %s', text, port,
                   conn.local_addr, conn.local_port,
                   auth_mode or auth.AUTH_NONE)
        return conn
    except BaseException:
        # BaseException, not Exception, so that CancelledError and a
        # timeout take the same path. A cancelled connect attempt is
        # routine -- it is what a collision or `clear ip bgp` looks like
        # from here -- and a descriptor leaked on each one would accumulate
        # once per connect-retry timer for the life of the process.
        _close_quietly(loop, sock)
        raise


class Listener(object):
    """The passive side: one listening socket, a set of permitted peers.

    Two things make this more than a wrapper around ``accept``.

    **Keys go on before the accept.** The kernel computes the MD5 or AO
    digest of the SYN-ACK inside ``tcp_v4_send_synack``, which runs while
    the connection is still a request socket -- before ``accept`` returns
    anything we could install a key on. So the listening socket carries a
    key for every configured peer, and :meth:`add_peer` writes through to
    it the moment it is called on an already-started listener.

    **Unknown sources never reach the FSM.** An accepted connection whose
    source address matches no configured neighbor is closed immediately and
    counted. The alternative -- handing it up and letting the FSM decide --
    means peer state allocated on behalf of an arbitrary scanner.

    :param loop: the engine's event loop.
    :param bind_addr: the local address to listen on. One listener per
        address family: see :meth:`start`.
    :param port: the local port, 179 by default.
    :param backlog: listen backlog.
    """

    __slots__ = ('loop', 'bind_addr', 'port', 'backlog', 'family',
                 'accepted', 'rejected_unknown', 'errors', '_text',
                 '_scope', '_sock', '_peers', '_accept', '_tasks')

    def __init__(self, loop, bind_addr, port=BGP_PORT,
                 backlog=DEFAULT_BACKLOG):
        self.loop = loop
        self.bind_addr = bind_addr
        self.port = int(port)
        self.backlog = int(backlog)
        self.family, self._text, self._scope = _split_addr(bind_addr)
        self._sock = None
        self._accept = None
        self._peers = {}
        # Tasks started for coroutine accept callbacks. Held so they are
        # neither garbage collected mid-run nor left to finish with an
        # exception nobody retrieves; see _callback_done.
        self._tasks = set()
        self.accepted = 0
        self.rejected_unknown = 0
        self.errors = 0

    # --- the permitted peer set --------------------------------------------

    def add_peer(self, addr, auth_mode, auth_key, gtsm_hops=None):
        """Permit a peer, and install its key on the listening socket now.

        Idempotent: re-adding a peer replaces its entry, which is what a
        configuration change to a neighbor's password looks like from
        here. The old key is removed first, because the kernel keys on the
        address and would otherwise keep the previous one alongside the
        new one for AO -- meaning a rotated password would still accept
        the old one.

        :param addr: the neighbor address as text.
        :param auth_mode: one of ``auth.AUTH_MODES``, or None.
        :param auth_key: the MD5 password or the AO key mapping.
        :param gtsm_hops: ``ttl-security`` hop count for this peer, or
            None.
        :return: the canonical form of the address, which is the key
            :meth:`remove_peer` expects.
        :raises OSError: the kernel refused the key. The peer is not added
            in that case: a peer in the permitted set whose key failed to
            install would accept an unauthenticated session.
        :raises ValueError: the address or key is unusable.
        """
        family, text, _scope = _split_addr(addr)
        if family != self.family:
            raise ValueError('neighbor %s is not in the same address '
                             'family as listener %s' % (addr, self.bind_addr))
        # Popped, not read: if installing the new key fails the peer must
        # end up *out* of the permitted set. A peer that is permitted but
        # whose key never made it onto the listening socket is the one
        # combination that would accept an unauthenticated session and
        # report it as authenticated.
        old = self._peers.pop(text, None)
        if old is not None and self._sock is not None:
            _clear_auth(self._sock, text, old['auth_mode'], old['auth_key'])
        if self._sock is not None:
            _apply_auth(self._sock, text, auth_mode, auth_key)
        self._peers[text] = {'auth_mode': auth_mode, 'auth_key': auth_key,
                             'gtsm_hops': gtsm_hops}
        if self._sock is not None:
            self._apply_listener_gtsm()
        return text

    def remove_peer(self, addr):
        """Forget a peer and remove its key from the listening socket.

        :param addr: the neighbor address as text, in any spelling.
        :return: True if the peer was configured.
        """
        try:
            _family, text, _scope = _split_addr(addr)
        except ValueError:
            return False
        entry = self._peers.pop(text, None)
        if entry is None:
            return False
        if self._sock is not None:
            _clear_auth(self._sock, text, entry['auth_mode'],
                        entry['auth_key'])
            self._apply_listener_gtsm()
        return True

    def peers(self):
        """Return the canonical addresses currently permitted.

        :return: a sorted list of address strings.
        """
        return sorted(self._peers)

    # --- lifecycle ---------------------------------------------------------

    async def start(self, on_accept):
        """Listen, then accept forever, handing each connection up.

        Runs until cancelled or until :meth:`stop` closes the socket under
        it, so the caller schedules it as a task and keeps the handle. That
        shape, rather than a background task created here, is deliberate:
        the engine already owns task lifetime and cancellation (see
        ``loop.py``), and a module that spawns its own tasks is a module
        whose shutdown order nobody can reason about.

        The socket is bound with ``SO_REUSEADDR`` so a restart does not
        have to wait out TIME_WAIT on port 179, and with ``IPV6_V6ONLY``
        set on an IPv6 listener. The second is a real decision: a
        dual-stack listener would accept IPv4 peers as ``::ffff:a.b.c.d``,
        and an MD5 or AO key for such a peer has to be installed with an
        AF_INET sockaddr whose matching against a v4-mapped request socket
        has differed between kernel versions. One listener per family
        removes the question entirely, at the cost of a second socket.

        Errors are triaged rather than collapsed. A failure that belongs to
        one connection -- a refused option, a callback that raised -- closes
        that connection and counts it. A failure of ``accept`` itself is
        counted and followed by a short pause, because the case that
        produces it is EMFILE and spinning on it would starve the tasks
        that might release a descriptor.

        :param on_accept: called as ``on_accept(connection)`` for each
            accepted connection from a configured peer. May be a coroutine
            function; the result is awaited if it is awaitable. It takes
            ownership of the connection.
        :return: None, on :meth:`stop`.
        :raises OSError: bind or listen failed. Nothing is left open.
        :raises RuntimeError: the listener is already started.
        """
        if self._sock is not None:
            raise RuntimeError('listener on %s:%d is already started'
                               % (self.bind_addr, self.port))
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(_sockaddr(self.family, self._text, self.port,
                                self._scope))
            sock.listen(self.backlog)
        except BaseException:
            _close_quietly(self.loop, sock)
            raise

        self._sock = sock
        try:
            # Keys for peers configured before start(). add_peer() writes
            # through once the socket exists, so this is only the backlog
            # of peers added earlier -- which is the normal case, since the
            # configuration is applied before the engine starts listening.
            for text in sorted(self._peers):
                entry = self._peers[text]
                try:
                    _apply_auth(sock, text, entry['auth_mode'],
                                entry['auth_key'])
                except (OSError, ValueError) as exc:
                    # Counted and logged rather than fatal: one neighbor
                    # with a bad key must not stop the listener that the
                    # other sessions need. That peer will fail to
                    # authenticate and show its reason.
                    self.errors += 1
                    _log.error('could not install the %s key for %s on the '
                               'listening socket: %s', entry['auth_mode'],
                               text, exc)
            self._apply_listener_gtsm()
            _log.info('listening on %s:%d for %d configured peer(s)',
                      self._text, self.port, len(self._peers))
            await self._accept_loop(on_accept)
        except BaseException:
            _close_quietly(self.loop, self._sock)
            self._sock = None
            raise

    async def _accept_loop(self, on_accept):
        """Accept until the socket goes away. See :meth:`start`.

        The pending ``sock_accept`` is wrapped in a future and kept on the
        instance so that :meth:`stop` can cancel it. Closing the listening
        socket is *not* enough on its own: the loop registered a reader for
        the descriptor, and a close takes that registration away without
        ever completing the future, so the accept would wait forever and
        the task would be reported as destroyed while pending. One extra
        future per accepted connection is a cheap price for a listener that
        actually stops.
        """
        while True:
            sock = self._sock
            if sock is None:
                return
            accept = asyncio.ensure_future(self.loop.sock_accept(sock),
                                           loop=self.loop)
            self._accept = accept
            try:
                conn_sock, peer = await accept
            except asyncio.CancelledError:
                self._accept = None
                if self._sock is None:
                    # stop() cancelled the pending accept. Returning is
                    # the intended end of this coroutine, and it must not
                    # look like a failure to the caller awaiting start().
                    return
                raise
            except OSError as exc:
                self._accept = None
                if self._sock is None:
                    return
                self.errors += 1
                _log.warning('accept on %s:%d failed: %s', self._text,
                             self.port, exc)
                await _pause(self.loop, ACCEPT_ERROR_PAUSE)
                continue
            self._accept = None
            try:
                self._handle_accepted(conn_sock, peer, on_accept)
            except asyncio.CancelledError:
                _close_quietly(self.loop, conn_sock)
                raise
            except Exception:
                # One connection's problem must not end the listener that
                # every other session depends on. The descriptor is closed
                # here because nothing above took ownership of it.
                self.errors += 1
                _log.exception('failed to hand up the connection from %s',
                               peer and peer[0])
                _close_quietly(self.loop, conn_sock)

    def _handle_accepted(self, conn_sock, peer, on_accept):
        """Vet one accepted socket and hand it up, or close it.

        Synchronous on purpose: everything here is a ``setsockopt`` or a
        dictionary lookup, and awaiting in the middle would leave an
        un-vetted descriptor open across a scheduling point.
        """
        text = None
        try:
            text = _split_addr(peer[0])[1] if peer else None
        except ValueError:
            text = None
        entry = self._peers.get(text) if text else None
        if entry is None:
            # Not a configured neighbor. Closed here, counted, and never
            # shown to the FSM.
            self.rejected_unknown += 1
            _log.info('refused a connection from unconfigured source %s',
                      text or (peer and peer[0]))
            _close_quietly(self.loop, conn_sock)
            return
        try:
            conn_sock.setblocking(False)
            conn_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if entry['gtsm_hops'] is not None:
                # The exact per-peer threshold, which the listening socket
                # could only approximate. See _apply_listener_gtsm().
                auth.set_gtsm(conn_sock, self.family, entry['gtsm_hops'])
            conn = Connection(self.loop, conn_sock,
                              auth_mode=entry['auth_mode'], peer_addr=text)
        except (OSError, ValueError) as exc:
            self.errors += 1
            _log.warning('dropping the accepted connection from %s: %s',
                         text, exc)
            _close_quietly(self.loop, conn_sock)
            return
        self.accepted += 1
        try:
            result = on_accept(conn)
        except Exception:
            self.errors += 1
            _log.exception('the accept callback raised for %s; closing the '
                           'connection nobody took ownership of', text)
            conn.close()
            return
        if result is not None and hasattr(result, '__await__'):
            # A coroutine callback is scheduled rather than awaited: the
            # accept loop's job is to get back to accept(), and a callback
            # that runs the whole session would stop every other peer from
            # connecting. The task is kept, and its outcome logged, so a
            # failing callback is an error line rather than a
            # "Task exception was never retrieved" at garbage collection.
            task = self.loop.create_task(result)
            self._tasks.add(task)
            task.add_done_callback(self._callback_done)

    def _callback_done(self, task):
        self._tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None and not isinstance(exc, asyncio.CancelledError):
            self.errors += 1
            _log.error('an accept callback on %s:%d failed: %r',
                       self._text, self.port, exc)

    def _apply_listener_gtsm(self):
        """Apply the inbound TTL floor the listening socket can carry.

        GTSM on a shared listening socket is a compromise and it is worth
        being explicit about why. ``IP_MINTTL`` is a property of the
        socket, not of a peer, so a listener serving several neighbors can
        only enforce one threshold for all of them -- and the SYN is
        checked by the kernel long before ``accept`` tells us which
        neighbor it came from.

        So: the floor is applied **only when every configured peer asks
        for ``ttl-security``**, and then at the loosest of their
        thresholds, so no legitimate peer's SYN is dropped. The exact
        per-peer threshold is applied to the accepted socket in
        :meth:`_handle_accepted`, which covers every segment after the
        handshake. A mixed peer set gets no floor at all, because setting
        one would silently discard the SYNs of the peers that did not ask
        for GTSM -- a configuration error turning into an outage.

        An operator who wants the SYN itself checked runs the GTSM peers
        on their own listener, which is why ``bind_addr`` is per-Listener
        rather than a global.

        :return: the inbound minimum that was set, or None.
        """
        if self._sock is None or not self._peers:
            return None
        hops = [e['gtsm_hops'] for e in self._peers.values()]
        if not all(h is not None for h in hops):
            if any(h is not None for h in hops):
                _log.warning('ttl-security is configured for some but not '
                             'all peers on the listener at %s:%d; the '
                             'inbound TTL check cannot be applied to the '
                             'listening socket without dropping the other '
                             'peers, so it is enforced per session after '
                             'accept instead', self._text, self.port)
            return None
        try:
            return auth.set_gtsm(self._sock, self.family, max(hops))
        except (OSError, ValueError) as exc:
            self.errors += 1
            _log.error('could not apply the inbound TTL floor to the '
                       'listening socket at %s:%d: %s', self._text,
                       self.port, exc)
            return None

    def close(self):
        """Close the listening socket synchronously, without a loop.

        :meth:`stop` is the orderly shutdown and should be preferred
        wherever there is a loop left to await it on. This is the
        backstop for the case there is not: a plugin stopping as the
        engine's loop is itself stopping cannot rely on a task it creates
        ever being run, and a listener whose descriptor outlives the
        process's interest in it shows up as a ResourceWarning under test
        and as an address that cannot be rebound on restart.

        Idempotent, and safe to call after :meth:`stop`.

        :return: True if a descriptor was closed by this call.
        """
        sock = self._sock
        self._sock = None
        accept = self._accept
        if accept is not None and not accept.done():
            # No loop turn is available to let the cancelled accept run
            # its own cleanup, so the reader is unregistered here first.
            # Doing it before the close is the same ordering `stop` takes
            # care over, and for the same reason: an unregister after the
            # close could name a descriptor number already reissued to
            # another socket.
            try:
                self.loop.remove_reader(sock.fileno())
            except (OSError, ValueError, RuntimeError):
                pass
            accept.cancel()
        self._accept = None
        if sock is None:
            return False
        try:
            sock.close()
        except OSError:
            pass
        _log.info('no longer listening on %s:%d', self._text, self.port)
        return True

    async def stop(self):
        """Stop listening. Accepted connections are not touched.

        A coroutine, and it has to be. Cancelling the in-flight accept and
        closing the descriptor cannot happen in the same tick: the
        cancelled accept has its own cleanup to run, and that cleanup
        unregisters the loop's reader *by descriptor number*. Run after the
        close, it could unregister whichever socket had inherited the
        number in the meantime -- a wakeup silently stolen from another
        session. So the order is: forget the socket, cancel the accept,
        give the loop one turn, and only then close.

        Sessions already handed to ``on_accept`` belong to the FSM and
        outlive the listener: a configuration change that moves the listen
        address must not tear down established peerings.

        :return: None.
        """
        sock = self._sock
        self._sock = None
        accept = self._accept
        if accept is not None and not accept.done():
            accept.cancel()
            await _pause(self.loop, 0)
        if sock is not None:
            _log.info('no longer listening on %s:%d', self._text, self.port)
            _close_quietly(self.loop, sock)
        # A second turn lets the accept loop observe the closed listener
        # and return on its own, so a caller that awaits stop() and then
        # cancels the task does not race it and log a spurious error.
        await _pause(self.loop, 0)

    def is_listening(self):
        """Report whether the listening socket is open.

        :return: True when :meth:`start` has bound and not yet stopped.
        """
        return self._sock is not None

    def stats(self):
        """Return the listener's counters for health output.

        ``rejected_unknown`` climbing is not necessarily a fault -- port
        179 attracts scanners -- but it is also what a neighbor
        misconfigured with the wrong ``update-source`` looks like, so it is
        reported rather than merely logged.

        :return: a dict of plain types.
        """
        return {
            'address': self._text,
            'port': self.port,
            'listening': self._sock is not None,
            'peers': len(self._peers),
            'accepted': self.accepted,
            'rejected_unknown': self.rejected_unknown,
            'errors': self.errors,
        }

    def __repr__(self):
        return '<Listener %s:%d peers=%d accepted=%d rejected=%d%s>' % (
            self._text, self.port, len(self._peers), self.accepted,
            self.rejected_unknown,
            '' if self._sock is not None else ' stopped')
