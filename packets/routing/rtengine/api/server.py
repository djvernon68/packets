# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The API's own thread: a WSGI server beside the engine, not inside it.

``werkzeug.serving.make_server`` rather than a full web server, for the same
reason the engine has no external dependencies: this is a routing library
that happens to offer an API, and requiring an operator to deploy uWSGI to
read ``show ip bgp summary`` would be absurd. The server is threaded, the
threads are request threads, and every one of them reaches the engine only
through the bridge.

**The socket is bound before :meth:`ApiServer.start` returns.** That is why
``make_server`` is called in the constructor path rather than inside the
thread: a caller that asked for port 0 needs to know which port it actually
got, and a caller that asked for a port already in use needs to find out by
getting an exception from ``start()`` rather than by noticing later that
nothing is listening. Both of those are what a test does, and a start method
that cannot report failure is a start method that gets wrapped in a sleep.

**TLS is in-process and optional.** ``api.tls.cert`` and ``api.tls.key``
hand a context straight to the server. It is deliberately the simple
version: no client certificates, no cipher configuration, no renegotiation
policy. An operator who needs those puts a reverse proxy in front, which is
documented as the supported way to do anything sophisticated, and binds this
to loopback.

**Shutdown is ordered from the outside in.** The server stops accepting,
then the thread is joined, and only then may the engine stop: a request
thread that reached the bridge after the engine's loop had gone would get
``Unavailable`` -- which is correct, and is also a confusing thing to serve
during a clean shutdown.
"""

import logging
import threading

from packets.routing.rtengine.api.app import create_app
from packets.routing.rtengine.api.auth import check_bind
from packets.routing.rtengine.api.bridge import CommandBridge
from packets.routing.rtengine.config import parse_bind
from packets.routing.rtengine.errors import ConfigError, RtEngineError

_log = logging.getLogger('packets.rtengine.api.server')


class ApiServer(object):
    """Serves an engine's REST API on its own thread.

    :param engine: the engine to serve.
    :param api_config: the ``api`` configuration subtree. Defaults to the
        engine's own.
    :param app: a prebuilt Flask application, for a caller that wants to
        add its own routes first.
    :param bridge: a command bridge, or None to build one.
    :param spec_path: an OpenAPI document to serve instead of the shipped
        one.
    :param swagger_ui: directory of a Swagger UI build to mount at
        ``/api/v1/docs``.
    :param bind: override the configured ``host:port``.
    :raises ConfigError: the configuration cannot be served.
    """

    def __init__(self, engine, api_config=None, app=None, bridge=None,
                 spec_path=None, swagger_ui=None, bind=None):
        if api_config is None:
            api_config = engine.running_config(redact=False).get('api') or {}
        self.engine = engine
        self.config = dict(api_config or {})
        if bind:
            self.config['bind'] = bind
        # Checked before anything is built: a refusal has to happen
        # before a socket exists, or the window between binding and
        # noticing is a window in which the API was served.
        self.host, self.requested_port = check_bind(self.config)
        # Built here rather than at start(), so that half a TLS
        # configuration is refused before a caller has had a chance to
        # believe the API is going to come up encrypted.
        self.ssl_context = self._ssl_context()
        self.bridge = bridge if bridge is not None else CommandBridge(engine)
        self.app = app if app is not None else create_app(
            engine, bridge=self.bridge, api_config=self.config,
            spec_path=spec_path, swagger_ui=swagger_ui)
        self._server = None
        self._thread = None
        self._registered = False
        # Empty unless the last stop() left something behind (A-2).
        self.stop_problems = []

    # --- lifecycle ---------------------------------------------------------

    def start(self, timeout=5.0):
        """Bind the socket and start serving.

        :param timeout: seconds to wait for the serving thread to run.
        :return: self.
        :raises RtEngineError: already started.
        :raises OSError: the address is in use, or cannot be bound. Raised
            to the caller rather than logged: an engine whose API did not
            start is not the engine the operator asked for.
        """
        if self._server is not None:
            raise RtEngineError('the API server is already started')
        from werkzeug.serving import make_server

        self._server = make_server(self.host, self.requested_port, self.app,
                                   threaded=True,
                                   ssl_context=self.ssl_context)
        ready = threading.Event()

        def serve():
            ready.set()
            try:
                self._server.serve_forever()
            except Exception:
                # serve_forever raising is either a shutdown race or a
                # defect; either way the thread is ending and the log is
                # the only place that can say so.
                _log.exception('API server thread stopped unexpectedly')

        self._thread = threading.Thread(target=serve,
                                        name='rtengine-api')
        # Daemon so that a caller which forgets to stop the server still
        # exits. The standalone command does stop it; an embedding
        # application might not, and a routing engine that will not exit
        # is worse than one that leaves a socket to the OS.
        self._thread.daemon = True
        self._thread.start()
        ready.wait(timeout)
        self._register_health()
        _log.info('API listening on %s', self.url)
        return self

    def stop(self, timeout=5.0):
        """Stop serving and join the thread. Idempotent.

        :param timeout: seconds to wait for the thread.
        :return: True if it had been running.
        """
        if self._server is None:
            return False
        problems = []
        try:
            self._server.shutdown()
        except Exception as exc:
            _log.exception('error shutting down the API server')
            problems.append('error shutting down the API server: %s'
                            % (exc,))
        if self._thread is not None:
            self._thread.join(timeout)
            if self._thread.is_alive():
                problems.append('the API thread did not exit within %.3gs'
                                % (timeout,))
            self._thread = None
        try:
            self._server.server_close()
        except Exception as exc:
            _log.exception('error closing the API socket')
            problems.append('error closing the API socket: %s' % (exc,))
        self._server = None
        self.stop_problems = problems
        _log.info('API stopped')
        return True

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    # --- identity ----------------------------------------------------------

    @property
    def port(self):
        """The port actually bound, which differs when 0 was requested."""
        if self._server is None:
            return self.requested_port
        return self._server.socket.getsockname()[1]

    @property
    def scheme(self):
        """``http`` or ``https``."""
        return 'https' if self.ssl_context is not None else 'http'

    @property
    def url(self):
        """The base URL of the API, ready to paste into curl."""
        host = self.host
        if ':' in host:
            host = '[%s]' % (host,)
        return '%s://%s:%d/api/v1' % (self.scheme, host, self.port)

    def is_running(self):
        """Whether the server is serving."""
        return self._server is not None

    def stats(self):
        """Return the API's own health contribution.

        Merged into the engine's health document so that both surfaces --
        ``Engine.health()`` and ``GET /engine/health`` -- report the API
        identically. It does not set a status: an API that answered the
        request asking about it is evidently up, and the interesting
        failures it could report (a timing-out bridge) are already
        counted below.

        :return: a dict of plain types, with no key material in it.
        """
        return {
            'listening': self.is_running(),
            'bind': '%s:%d' % (self.host, self.port),
            'scheme': self.scheme,
            'auth': self.app.config['RTENGINE'].current_auth().describe(),
            'bridge': self.bridge.stats(),
        }

    # --- internals ---------------------------------------------------------

    def _ssl_context(self):
        """Build the ``ssl_context`` for ``make_server``.

        :return: a ``(cert, key)`` pair, or None.
        :raises ConfigError: only one half of the pair is configured. A
            certificate with no key is not a TLS configuration, and
            starting in plain HTTP because one line was missing is the
            failure this refuses to have.
        """
        tls = self.config.get('tls') or {}
        cert = tls.get('cert')
        key = tls.get('key')
        if not cert and not key:
            return None
        if not cert or not key:
            raise ConfigError('api.tls needs both cert and key',
                              path='api.tls')
        return (cert, key)

    def _register_health(self):
        """Have the engine's health document include the API's view."""
        if self._registered:
            return
        monitor = getattr(self.engine, 'health_monitor', None)
        register = getattr(monitor, 'register_component', None)
        if register is not None:
            register('api', self.stats)
            self._registered = True

    def __repr__(self):
        return '<ApiServer %s running=%s>' % (self.url, self.is_running())


def serve(engine, api_config=None, bind=None, **kwargs):
    """Build and start an :class:`ApiServer`.

    :param engine: the engine to serve.
    :param api_config: the ``api`` configuration subtree.
    :param bind: override the configured ``host:port``.
    :param kwargs: passed to :class:`ApiServer`.
    :return: the started server.
    """
    return ApiServer(engine, api_config=api_config, bind=bind,
                     **kwargs).start()


def bind_of(api_config):
    """Return the ``(host, port)`` a configuration would bind.

    Exposed for the standalone command's ``--api`` handling, which has to
    report the bind before the server exists.

    :param api_config: the ``api`` subtree.
    :return: ``(host, port)``.
    """
    return parse_bind((api_config or {}).get('bind') or '127.0.0.1:8179')
