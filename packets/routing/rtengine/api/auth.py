# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Who is allowed to talk to the API, and from where.

A routing control plane that anyone on the network can reconfigure is worse
than no API at all, so two rules are enforced here and both of them are
deliberately blunt.

**A bearer token, compared in constant time.** ``Authorization: Bearer
<token>`` on every request, checked with ``hmac.compare_digest`` so that a
wrong token cannot be found one byte at a time by measuring how long the
comparison took. The token comes from ``api.auth.token`` or, better, from
``api.auth.token-file`` -- a file has permissions, a configuration document
gets copied into support bundles. A token file is watched rather than read
once (A-3): at most once a second a request ``stat()``\ s it, and only a file
whose inode, size or modification time changed is read again, so rotating
the token is a matter of rewriting the file and no request ever waits on an
``open()`` that has nothing new to say. A rewrite that leaves the file
unreadable or empty keeps the previous token -- never an open API.

**A non-loopback bind demands one.** Binding to ``0.0.0.0`` with no token
configured is refused at start-up rather than served: the failure mode of
getting this wrong is silent and total. An operator who genuinely wants an
unauthenticated listener on a network interface -- behind a reverse proxy
that authenticates, say -- says so with ``api.insecure: true``, which is a
sentence someone has to type on purpose.

The health endpoint can be exempted with
``api.auth.allow-unauthenticated-health``, because the thing polling it is
usually a supervisor or a load balancer that has nowhere to keep a secret,
and the health document contains no key material by construction.
"""

import hmac
import logging
import os
import time

from packets.routing.rtengine.config import is_loopback, parse_bind
from packets.routing.rtengine.errors import ConfigError, RtEngineError

_log = logging.getLogger(__name__)

#: Seconds between looks at a token file for a rotation (A-3).
TOKEN_RECHECK_S = 1.0


class Unauthorized(RtEngineError):
    """A request arrived without a usable bearer token."""

    error = 'Unauthorized'


def _compare(given, expected):
    """Compare two tokens without leaking their contents through timing.

    :param given: what the client sent.
    :param expected: what is configured.
    :return: True if they match.
    """
    # compare_digest wants two objects of the same type and rejects
    # non-ASCII str on some versions, so both sides are encoded first.
    try:
        left = given.encode('utf-8')
        right = expected.encode('utf-8')
    except (AttributeError, UnicodeError):
        return False
    return hmac.compare_digest(left, right)


class TokenAuth(object):
    """The API's authentication policy, resolved from configuration.

    :param token: the bearer token, or None for an open API.
    :param allow_unauthenticated_health: serve ``/engine/health`` without
        a token even when one is configured.
    :param source: where the token came from, for logs and ``status``.
        Never the token itself.
    :param token_file: the file the token was read from, watched by
        :meth:`refresh`; None for an inline token or none.
    :param signature: that file's :func:`_file_signature` when it was read.
    :param clock: a monotonic clock, for tests.
    """

    def __init__(self, token=None, allow_unauthenticated_health=False,
                 source='none', token_file=None, signature=None,
                 clock=time.monotonic):
        self.token = token or None
        self.allow_unauthenticated_health = bool(
            allow_unauthenticated_health)
        self.source = source
        self.token_file = token_file
        self._signature = signature
        self._clock = clock
        self._checked = clock()
        self.reloads = 0

    @classmethod
    def from_config(cls, api_cfg):
        """Build the policy from the ``api`` configuration section.

        :param api_cfg: the ``api`` subtree, or None.
        :return: a :class:`TokenAuth`.
        :raises ConfigError: a token file was configured and cannot be
            read. Failing to start is the only safe response: starting
            without the token would serve an API the operator believes is
            protected.
        """
        cfg = api_cfg or {}
        auth = cfg.get('auth') or {}
        token = auth.get('token')
        source = 'config' if token else 'none'
        path = auth.get('token-file')
        signature = None
        if path:
            # The file wins. Configuring both is not an error -- an
            # operator may be migrating from one to the other -- but the
            # file is the one with permissions on it. The signature is
            # taken first: a rewrite racing the read then looks like a
            # change at the next check, and is read again.
            signature = _file_signature(path)
            token = _read_token_file(path)
            source = 'file:%s' % (path,)
        return cls(token=token,
                   allow_unauthenticated_health=bool(
                       auth.get('allow-unauthenticated-health')),
                   source=source, token_file=path or None,
                   signature=signature)

    def refresh(self, force=False):
        """Pick up a rewritten token file (A-3).

        Cheap enough for every request: between checks it is one clock
        read, and a check is one ``stat()``. The file is only opened when
        its signature changed.

        :param force: check now, whatever the clock says.
        :return: True if the token changed.
        """
        if not self.token_file:
            return False
        now = self._clock()
        if not force and now - self._checked < TOKEN_RECHECK_S:
            return False
        self._checked = now
        signature = _file_signature(self.token_file)
        if signature is None or signature == self._signature:
            # Unchanged -- or gone, which keeps the token in force: a
            # deleted file is an operator mid-rotation more often than an
            # operator asking for an open API.
            return False
        # Recorded either way, so a file that stays bad is reported once,
        # not on every request, and is read again as soon as it changes.
        self._signature = signature
        try:
            token = _read_token_file(self.token_file)
        except ConfigError as exc:
            _log.warning('%s; keeping the previous API token', exc)
            return False
        if token == self.token:
            return False
        self.token = token
        self.reloads += 1
        _log.info('API token reloaded from %s', self.token_file)
        return True

    @property
    def enabled(self):
        """Whether a token is required at all."""
        return self.token is not None

    def check_header(self, header):
        """Validate an ``Authorization`` header value.

        :param header: the raw header, or None.
        :raises Unauthorized: it is missing, malformed, or wrong. The
            three cases deliberately produce the same message: telling a
            caller that their token was well-formed but wrong is telling
            them they are close.
        """
        if not self.enabled:
            return
        if not header:
            raise Unauthorized('an Authorization: Bearer token is required')
        parts = header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != 'bearer' \
                or not _compare(parts[1].strip(), self.token):
            raise Unauthorized('an Authorization: Bearer token is required')

    def describe(self):
        """Return the policy for ``/engine/status``, without the secret.

        :return: a dict of plain types.
        """
        return {
            'required': self.enabled,
            'source': self.source,
            'allow-unauthenticated-health':
                self.allow_unauthenticated_health,
            'reloads': self.reloads,
        }

    def __repr__(self):
        return '<TokenAuth required=%s source=%s>' % (self.enabled,
                                                      self.source)


def _file_signature(path):
    """Return what identifies one version of a file, or None.

    The inode catches an atomic rename-into-place, the size and the
    nanosecond mtime an in-place rewrite.

    :param path: the file.
    :return: ``(inode, size, mtime_ns)``, or None if it cannot be stat'd.
    """
    try:
        st = os.stat(path)
    except (IOError, OSError):
        return None
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def _read_token_file(path):
    """Read a bearer token from a file.

    :param path: the file.
    :return: the token, whitespace stripped -- an editor's trailing
        newline is not part of anybody's password.
    :raises ConfigError: it cannot be read, or holds nothing.
    """
    try:
        with open(path, 'r') as handle:
            token = handle.read().strip()
    except (IOError, OSError) as exc:
        raise ConfigError('cannot read the API token file %s: %s'
                          % (path, exc), path='api.auth.token-file')
    if not token:
        raise ConfigError('the API token file %s is empty' % (path,),
                          path='api.auth.token-file')
    return token


def check_bind(api_cfg):
    """Refuse a network-facing bind that nothing authenticates.

    The same rule the engine applies when a configuration document is
    committed, applied again here because the API can also be started from
    a dict that never went through the engine -- an embedding application
    calling :func:`~packets.routing.rtengine.api.server.serve` directly.
    A security control that only one of two entry points enforces is not a
    security control.

    :param api_cfg: the ``api`` subtree, or None.
    :return: the ``(host, port)`` that will be bound.
    :raises ConfigError: the bind is exposed and unauthenticated.
    """
    cfg = api_cfg or {}
    host, port = parse_bind(cfg.get('bind') or '127.0.0.1:8179')
    if is_loopback(host):
        return host, port
    auth = cfg.get('auth') or {}
    if auth.get('token') or auth.get('token-file'):
        return host, port
    if cfg.get('insecure') is True:
        return host, port
    raise ConfigError(
        'binding the API to %s exposes it beyond this host, so api.auth '
        'must be configured, or api.insecure set to true to accept the '
        'risk deliberately' % (host,), path='api.bind')


def generate_token():
    """Return a new random bearer token: 240 bits, URL-safe text.

    :return: the token.
    """
    import base64
    return base64.urlsafe_b64encode(os.urandom(30)).decode('ascii')


def load_or_generate_token(path, mode=0o600):
    """Return the token in a file, creating one if the file is absent.

    For the standalone command's convenience: an operator who configures
    ``token-file`` and has not created the file yet gets a usable token
    rather than a refusal to start, and the token is only ever written
    where they pointed us.

    :param path: the token file.
    :param mode: permissions for a file created here.
    :return: ``(token, created)``.
    :raises ConfigError: the file cannot be read or written.
    """
    if os.path.exists(path):
        return _read_token_file(path), False
    token = generate_token()
    try:
        # Opened with O_EXCL so that two processes starting at once cannot
        # each believe they wrote the token, and the mode is set in the
        # open rather than afterwards so it is never briefly world
        # readable.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, (token + '\n').encode('ascii'))
        finally:
            os.close(fd)
    except (IOError, OSError) as exc:
        raise ConfigError('cannot create the API token file %s: %s'
                          % (path, exc), path='api.auth.token-file')
    return token, True
