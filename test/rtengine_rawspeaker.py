# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""A raw BGP speaker for negative tests against rtengine.

Not a test module (the name does not match ``test*.py``); the session and
codec tests import it. It is a port of the ``rawbgp.py`` script used to
reproduce the 2.3 review findings on cnp02, kept deliberately *dumb*: it
builds messages from bytes, sends exactly what a test tells it to, and
reports exactly what came back -- including how the connection ended.
rtengine's own codec is never used here, because a test that asks the
code under test to judge its own output cannot catch the code being
wrong.

The one thing it adds over a bare socket is the distinction between the
three ways a session can end, which is what the NOTIFICATION tests are
about:

* ``EOF`` -- the far end half-closed after whatever it sent (a FIN);
* ``RESET`` -- the far end reset the connection (an RST), which on Linux
  can discard a NOTIFICATION that was already in flight;
* a timeout -- nothing at all, which a test treats as a failure.

Blocking sockets with timeouts, on purpose: the engine under test runs
its own loop on its own thread, and a second asyncio loop here would only
add a scheduler to the list of things that can be wrong.
"""

import errno
import socket
import struct
import time


MARKER = b'\xff' * 16

OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4
ROUTE_REFRESH = 5

#: Pseudo message types :meth:`RawSpeaker.read` uses for how a
#: connection ended.
EOF = 'EOF'
RESET = 'RESET'

MSG_NAMES = {OPEN: 'OPEN', UPDATE: 'UPDATE', NOTIFICATION: 'NOTIFICATION',
             KEEPALIVE: 'KEEPALIVE', ROUTE_REFRESH: 'ROUTE-REFRESH',
             EOF: 'TCP-EOF', RESET: 'TCP-RESET'}

AFI_IP = 1
AFI_IP6 = 2
SAFI_UNICAST = 1


def msg(mtype, body=b'', length=None):
    """Frame one BGP message.

    :param length: override the header length field, to build messages
        whose header lies about their size.
    """
    if length is None:
        length = 19 + len(body)
    return MARKER + struct.pack('!HB', length, mtype) + body


def keepalive():
    """A well-formed KEEPALIVE."""
    return msg(KEEPALIVE)


def cap(code, value):
    """One capability TLV."""
    return bytes(bytearray([code, len(value)])) + value


def open_msg(asn, router_id, hold=30,
             families=((AFI_IP, SAFI_UNICAST), (AFI_IP6, SAFI_UNICAST))):
    """An OPEN with MP-BGP, route refresh and four-octet AS capabilities.

    :param asn: the speaker's AS; AS_TRANS goes in the two-octet field
        when it does not fit.
    :param router_id: dotted quad.
    :param hold: proposed hold time.
    :param families: ``(afi, safi)`` pairs to advertise.
    """
    caps = b''
    for afi, safi in families:
        caps += cap(1, struct.pack('!HBB', afi, 0, safi))
    caps += cap(2, b'') + cap(65, struct.pack('!I', asn))
    param = bytes(bytearray([2, len(caps)])) + caps
    my_as = asn if asn <= 0xffff else 23456
    body = (struct.pack('!BHH', 4, my_as, hold) +
            socket.inet_aton(router_id) +
            bytes(bytearray([len(param)])) + param)
    return msg(OPEN, body)


def attr(flags, code, value):
    """One path attribute, extended length when the flag says so."""
    if flags & 0x10:
        return bytes(bytearray([flags, code])) + \
            struct.pack('!H', len(value)) + value
    return bytes(bytearray([flags, code, len(value)])) + value


def origin_igp():
    return attr(0x40, 1, b'\x00')


def as_path(*asns):
    """An AS_SEQUENCE in four-octet encoding."""
    return attr(0x40, 2, bytes(bytearray([2, len(asns)])) +
                b''.join(struct.pack('!I', a) for a in asns))


def next_hop(address):
    return attr(0x40, 3, socket.inet_aton(address))


def update(withdrawn=b'', attrs=b'', nlri=b''):
    """An UPDATE from its three raw blocks."""
    body = (struct.pack('!H', len(withdrawn)) + withdrawn +
            struct.pack('!H', len(attrs)) + attrs + nlri)
    return msg(UPDATE, body)


def describe(messages):
    """Render ``(type, body)`` pairs for a failure message."""
    out = []
    for mtype, body in messages:
        if mtype == NOTIFICATION and len(body) >= 2:
            out.append('NOTIFICATION %d/%d data=%s'
                       % (bytearray(body)[0], bytearray(body)[1],
                          ''.join('%02x' % b for b in bytearray(body[2:]))))
        else:
            out.append(MSG_NAMES.get(mtype, str(mtype)))
    return out


class RawSpeaker(object):
    """One end of a BGP session driven byte by byte.

    :param asn: the speaker's AS.
    :param router_id: the speaker's BGP identifier, dotted quad.
    :param sock: an already connected socket to drive, for connections
        the engine opened to a :func:`listen` socket. None to connect
        later with :meth:`connect`.
    """

    def __init__(self, asn, router_id, sock=None):
        self.asn = asn
        self.router_id = router_id
        self.sock = sock
        self._buf = b''
        self.ended = None

    def connect(self, host, port, timeout=5.0, source=None):
        """Open a TCP connection to the engine."""
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if source is not None:
            sock.bind((source, 0))
        sock.connect((host, port))
        self.sock = sock
        return self

    def send(self, data):
        """Write raw bytes; returns False if the connection is gone."""
        try:
            self.sock.sendall(data)
            return True
        except (OSError, socket.error):
            return False

    def send_open(self, hold=30, **kwargs):
        return self.send(open_msg(self.asn, self.router_id, hold=hold,
                                  **kwargs))

    def read(self, timeout=2.0, until=None):
        """Read messages until a timeout, the end of the connection, or
        until a message of type ``until`` has been read.

        :return: a list of ``(type, body)``; the connection's end appears
            as ``(EOF, b'')`` or ``(RESET, b'')``.
        """
        out = []
        deadline = time.time() + timeout
        while True:
            while len(self._buf) >= 19:
                length, mtype = struct.unpack('!HB', self._buf[16:19])
                if length < 19 or len(self._buf) < length:
                    break
                out.append((mtype, self._buf[19:length]))
                self._buf = self._buf[length:]
                if until is not None and mtype == until:
                    return out
            if self.ended is not None:
                return out
            remaining = deadline - time.time()
            if remaining <= 0:
                return out
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65535)
            except socket.timeout:
                return out
            except (OSError, socket.error) as exc:
                if getattr(exc, 'errno', None) in (errno.ECONNRESET,
                                                   errno.EPIPE):
                    self.ended = RESET
                    out.append((RESET, b''))
                    return out
                raise
            if not chunk:
                self.ended = EOF
                out.append((EOF, b''))
                return out
            self._buf += chunk

    def handshake(self, hold=30, timeout=5.0, **kwargs):
        """Exchange OPEN and KEEPALIVE until the session is up.

        :return: everything read on the way, for diagnostics.
        :raises AssertionError: the engine did not complete it.
        """
        self.send_open(hold=hold, **kwargs)
        got = self.read(timeout, until=OPEN)
        if not any(t == OPEN for t, _ in got):
            raise AssertionError('no OPEN from the engine: %s'
                                 % describe(got))
        self.send(keepalive())
        more = self.read(timeout, until=KEEPALIVE)
        got += more
        if not any(t == KEEPALIVE for t, _ in more):
            raise AssertionError('no KEEPALIVE from the engine: %s'
                                 % describe(got))
        return got

    def expect_notification(self, code, subcode, timeout=5.0):
        """Assert that a NOTIFICATION arrives, and arrives *before* EOF.

        Anything else first -- KEEPALIVEs, UPDATEs -- is skipped, since a
        session that was up when it was torn down may well have sent
        them. A connection that ends without one, or that is reset, is
        the defect these tests exist for.

        :return: ``(code, subcode, data)`` of the NOTIFICATION.
        :raises AssertionError: no NOTIFICATION, the wrong one, or the
            connection ended first.
        """
        seen = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            got = self.read(max(0.0, deadline - time.time()),
                            until=NOTIFICATION)
            seen.extend(got)
            for mtype, body in got:
                if mtype == NOTIFICATION:
                    body = bytearray(body)
                    if (body[0], body[1]) != (code, subcode):
                        raise AssertionError(
                            'expected NOTIFICATION %d/%d, got %s'
                            % (code, subcode, describe(seen)))
                    return body[0], body[1], bytes(body[2:])
                if mtype in (EOF, RESET):
                    raise AssertionError(
                        'the connection ended before a NOTIFICATION '
                        '%d/%d arrived: %s'
                        % (code, subcode, describe(seen)))
        raise AssertionError('no NOTIFICATION %d/%d within %.1fs: %s'
                             % (code, subcode, timeout, describe(seen)))

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def listen(host='127.0.0.1', port=0):
    """A listening socket for connections the engine initiates.

    :return: ``(socket, port)``.
    """
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(4)
    return sock, sock.getsockname()[1]


def accept(listener, asn, router_id, timeout=10.0):
    """Wait for the engine to connect and wrap the connection.

    :return: a :class:`RawSpeaker` on the accepted socket.
    """
    listener.settimeout(timeout)
    conn, _ = listener.accept()
    conn.settimeout(timeout)
    return RawSpeaker(asn, router_id, sock=conn)
