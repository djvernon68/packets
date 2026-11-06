# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The Flask application: wiring, limits, error translation.

This module builds the app and owns everything the blueprints share. It
contains no routing logic of its own, because the four blueprints are the
four kinds of thing an operator does -- read the engine, change the
configuration, look at operational state, take an action -- and mixing them
would make the OpenAPI document harder to read than the code.

Four decisions are made here and nowhere else.

**The engine is never touched from this thread.** Every handler goes through
the :class:`~packets.routing.rtengine.api.bridge.CommandBridge`. There is no
fallback path that reads engine state directly when it looks safe, because
"looks safe" is exactly the judgement that goes wrong six months later.

**Errors are translated once.** The engine raises typed exceptions that
already carry ``error``, ``detail`` and ``path``; this module maps the token
to a status code and renders the body. A handler that wanted a 409 raises
``ConflictError`` rather than building a response, so the same failure
reported through ``Engine.configure`` and through the API says the same
thing. Werkzeug's own HTTP exceptions -- a 404 from the router, a 413 from
the body limit -- are rendered into the identical shape, so a client never
has to parse two different error formats.

**Limits are enforced before work happens.** ``MAX_CONTENT_LENGTH`` stops an
oversized body at the server, ``max-page`` caps a pagination request, and
both are configuration rather than constants because the sensible value for
an embedded engine and for a public-facing one are not the same number.

**The application works on the Flask that the deployment target has.** The
3.6.8 floor pins Flask to the 2.0.x line there, while a developer machine
has whatever is current. Nothing here uses an API that arrived after Flask
0.12 or was removed by Flask 3: no ``before_first_request``, no
``json_encoder``, no ``flask.escape``, and responses are built with
``jsonify`` and ``make_response`` only. That is a real constraint on this
file, and it is cheaper than maintaining two applications.
"""

import json
import logging
import os

from flask import Blueprint, Flask, current_app, jsonify, make_response, \
    request
from werkzeug.exceptions import HTTPException, default_exceptions

from packets.routing.rtengine.api import auth as auth_mod
from packets.routing.rtengine.api.bridge import CommandBridge
from packets.routing.rtengine.api.converters import CONVERTERS
from packets.routing.rtengine.errors import ConfigError, RtEngineError

_log = logging.getLogger('packets.rtengine.api')

#: Everything this application serves lives under here. Versioned in the
#: path rather than in a header: an operator pasting a URL into a bug
#: report should be pasting something unambiguous.
API_PREFIX = '/api/v1'

#: The OpenAPI document that describes this application, shipped beside it.
SPEC_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'openapi.yaml')

#: Error token to HTTP status. The tokens are the engine's, not HTTP's,
#: because a client that switches on ``error`` should not have to care
#: that "the document is invalid" and "that prefix is not a prefix" are
#: both 400.
STATUS = {
    'Invalid': 400,
    'Unauthorized': 401,
    'NotFound': 404,
    'MethodNotAllowed': 405,
    'Conflict': 409,
    'PreconditionFailed': 412,
    'PayloadTooLarge': 413,
    'ApplyFailed': 500,
    'Error': 500,
    'Unavailable': 503,
    'Timeout': 504,
}


class NotFound(RtEngineError):
    """No resource exists at this path.

    Distinct from ``ConfigError``: asking about a neighbour that is not
    configured is not an invalid request, and answering 400 would tell a
    client to fix a URL that is perfectly well formed.
    """

    error = 'NotFound'


class PayloadTooLarge(RtEngineError):
    """The request body is larger than ``api.max-body-bytes``."""

    error = 'PayloadTooLarge'


class ApiContext(object):
    """Everything a handler needs, hung off the application.

    Kept in ``app.config`` under one key rather than as a scatter of
    ``app.config['RTENGINE_*']`` entries, so that a second application in
    the same process -- two engines in one test -- cannot see the first
    one's engine.

    :param engine: the engine being served.
    :param bridge: the command bridge onto its loop.
    :param auth: the :class:`~packets.routing.rtengine.api.auth.TokenAuth`.
    :param max_body_bytes: request body limit.
    :param max_page: pagination cap.
    :param spec_path: the OpenAPI document to serve.
    """

    __slots__ = ('engine', 'bridge', 'auth', 'max_body_bytes', 'max_page',
                 'spec_path', '_spec', '_auth_revision')

    def __init__(self, engine, bridge, auth, max_body_bytes, max_page,
                 spec_path):
        self.engine = engine
        self.bridge = bridge
        self.auth = auth
        self.max_body_bytes = int(max_body_bytes)
        self.max_page = int(max_page)
        self.spec_path = spec_path
        self._spec = None
        self._auth_revision = engine.revision

    def current_auth(self):
        """Return the authentication policy, re-reading it if it changed.

        An operator who rotates ``api.auth.token`` through this API has
        rotated it; a policy resolved once at start-up would keep
        accepting the old token until somebody restarted the process,
        which is the opposite of what rotating a credential is for. The
        check is a comparison of the configuration revision -- an
        integer read, no lock and no work -- so the re-read happens once
        per configuration change rather than once per request.

        Two ways this deliberately does *not* fail: a re-read that
        cannot be completed keeps the previous policy rather than
        dropping to an open API, and an unreadable token file keeps the
        previous token rather than disabling authentication. Failing
        closed is the only acceptable direction for this function.

        :return: the :class:`~...api.auth.TokenAuth` now in force.
        """
        revision = self.engine.revision
        if revision == self._auth_revision:
            # A rewritten token file is a rotation too (A-3), and needs no
            # configuration change to take effect.
            self.auth.refresh()
            return self.auth
        try:
            section = self.bridge.call(_read_api_section, self.engine)
            policy = auth_mod.TokenAuth.from_config(section)
            page = section.get('max-page')
            body = section.get('max-body-bytes')
        except Exception:
            _log.exception('could not re-read the API configuration at '
                           'revision %s; keeping the previous policy',
                           revision)
            return self.auth
        self.auth = policy
        if page:
            self.max_page = int(page)
        if body:
            self.max_body_bytes = int(body)
        self._auth_revision = revision
        return self.auth

    def spec(self):
        """Return the OpenAPI document, parsed once and cached.

        :return: the spec as plain dicts and lists.
        :raises RtEngineError: PyYAML is unavailable or the file is not
            there. Reported rather than raised at start-up: an engine
            whose documentation endpoint is missing is still a working
            engine, and refusing to route BGP over it would be absurd.
        """
        if self._spec is None:
            self._spec = load_spec(self.spec_path)
        return self._spec


def _read_api_section(engine_obj):
    """Return the ``api`` subtree, unredacted. Runs on the loop thread.

    :param engine_obj: the engine.
    :return: the subtree, or an empty dict.
    """
    return engine_obj.running_config(redact=False).get('api') or {}


def load_spec(path=None):
    """Read and parse the OpenAPI document.

    :param path: the file, defaulting to the shipped one.
    :return: the parsed document.
    :raises RtEngineError: it cannot be read or parsed.
    """
    path = path or SPEC_FILE
    try:
        import yaml
    except ImportError:
        raise RtEngineError('PyYAML is not installed, so the OpenAPI '
                            'document cannot be served', path=path)
    try:
        with open(path, 'r') as handle:
            return yaml.safe_load(handle.read())
    except (IOError, OSError) as exc:
        raise RtEngineError('cannot read the OpenAPI document: %s' % (exc,),
                            path=path)


# --- access to the context --------------------------------------------------

def ctx():
    """Return the :class:`ApiContext` of the application serving this call.

    :return: the context.
    """
    return current_app.config['RTENGINE']


def engine():
    """Return the engine this application serves."""
    return ctx().engine


def bridge():
    """Return the command bridge onto the engine's loop."""
    return ctx().bridge


# --- request helpers --------------------------------------------------------

def json_body(required=True, default=None):
    """Read and parse the request body.

    Parsed here rather than through ``request.get_json`` so that the
    behaviour does not depend on the Flask version and on whether the
    client remembered ``Content-Type: application/json``: an operator
    with curl usually has not, and refusing their body over a header is
    pedantry rather than safety.

    :param required: raise when there is no body.
    :param default: returned for an absent body when it is not required.
    :return: the parsed value.
    :raises PayloadTooLarge: the body exceeds ``api.max-body-bytes``.
    :raises ConfigError: it is required and missing, or not valid JSON.
    """
    limit = ctx().max_body_bytes
    length = request.content_length
    if length is not None and length > limit:
        # Checked before reading rather than relying on the server to
        # notice: the point of a body limit is not to reject the request,
        # it is not to have buffered the body first.
        raise PayloadTooLarge('the request body is %d bytes; the limit is '
                              '%d' % (length, limit))
    if length is None:
        # No Content-Length: a chunked body, or a client that simply
        # streams until it closes (A-1). ``get_data`` would buffer all of
        # it before the size check below could run, so read one byte past
        # the limit and stop -- that byte is the proof it was too big.
        #
        # From the server's own input when it says the body is
        # terminated, not from ``request.stream``: a recent Werkzeug wraps
        # that in a stream which *ends* at MAX_CONTENT_LENGTH, so an
        # oversized body arrives cut short -- a different body, and one
        # that might even parse. Without that flag Werkzeug's stream is
        # empty (reading a socket to EOF could block forever), and so is
        # the body.
        environ = request.environ
        stream = environ['wsgi.input'] \
            if environ.get('wsgi.input_terminated') else request.stream
        raw = _read_bounded(stream, limit)
    else:
        raw = request.get_data(cache=False)
    if len(raw) > limit:
        raise PayloadTooLarge('the request body is %d bytes; the limit is '
                              '%d' % (len(raw), limit))
    if not raw.strip():
        if required:
            raise ConfigError('a JSON request body is required')
        return default
    try:
        return json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise ConfigError('the request body is not valid JSON: %s' % (exc,))


def _read_bounded(stream, limit, chunk=65536):
    """Read a stream to its end, or to one byte past ``limit``.

    :param stream: a file-like object with ``read(n)``.
    :param limit: the most bytes a valid body may have.
    :param chunk: the largest single read.
    :return: the bytes read; longer than ``limit`` only by the one byte
        that shows the body was over it.
    """
    parts = []
    remaining = limit + 1
    while remaining > 0:
        data = stream.read(min(chunk, remaining))
        if not data:
            break
        parts.append(data)
        remaining -= len(data)
    return b''.join(parts)


def page_args():
    """Return the pagination keywords from the query string.

    ``limit`` is capped rather than rejected -- a client asking for
    everything is asking a reasonable question badly -- but ``limit=0``
    is refused outright rather than capped, reinterpreted or passed
    along. A zero means "no rows" to the client and, in the common
    ``rows[:limit] if limit else rows`` idiom, "every row" to a handler,
    and the one request where those two readings differ most is the one
    against a full table. Making it an error costs a client one retry
    and cannot cost an engine a million-row response.

    Whether a cap is visible in the answer is the view's business, not
    this layer's: the BGP table reports ``returned`` and ``truncated``,
    the route tables return a ``next`` cursor, and some views report
    neither.

    :return: a dict suitable for passing to a show handler.
    :raises ConfigError: a value is not an integer, is negative, or is a
        ``limit`` of zero.
    """
    out = {}
    cap = ctx().max_page
    for name in ('limit', 'offset'):
        raw = request.args.get(name)
        if raw is None:
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise ConfigError('%s must be an integer, not %r' % (name, raw),
                              path=name)
        if value < 0:
            raise ConfigError('%s must not be negative' % (name,), path=name)
        if name == 'limit':
            if value == 0:
                raise ConfigError(
                    'limit must be at least 1; omit it to let the view '
                    'choose, because a limit of zero means "no rows" to '
                    'you and "no limit" to several of the handlers',
                    path='limit')
            value = min(value, cap)
        out[name] = value
    after = request.args.get('after')
    if after:
        out['after'] = after
    return out


def if_match_revision():
    """Return the revision an ``If-Match`` header demands, or None.

    :return: the revision as an int, or None when the header is absent or
        is ``*``.
    :raises ConfigError: the header is present and is not a revision.
    """
    raw = request.headers.get('If-Match')
    if not raw or raw.strip() == '*':
        return None
    value = raw.strip()
    if value.startswith('W/'):
        value = value[2:]
    value = value.strip('"')
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ConfigError('If-Match must be a configuration revision, such '
                          'as "3"; got %s' % (raw,))


# --- response helpers -------------------------------------------------------

def json_response(body, status=200, headers=None):
    """Render a document as a JSON response.

    :param body: a dict.
    :param status: the HTTP status.
    :param headers: extra headers.
    :return: a Flask response.
    """
    response = make_response(jsonify(body), status)
    for name, value in (headers or {}).items():
        response.headers[name] = value
    return response


def mutation(revision, path=None, extra=None, status=200):
    """Render the response to a change.

    Every mutating response carries the revision, because that is how a
    client tells its own change from somebody else's and how it builds
    the next ``If-Match``.

    :param revision: the revision after the change.
    :param path: the configuration path that was changed.
    :param extra: additional keys.
    :param status: the HTTP status.
    :return: a Flask response.
    """
    body = {'revision': revision}
    if path is not None:
        body['path'] = '.'.join(str(p) for p in path)
    if extra:
        body.update(extra)
    return json_response(body, status=status,
                         headers={'ETag': '"%d"' % (revision,)})


def error_response(exc):
    """Render one of the engine's exceptions.

    :param exc: an :class:`~packets.routing.rtengine.errors.RtEngineError`.
    :return: a Flask response.
    """
    body = exc.as_dict()
    body.setdefault('path', None)
    status = STATUS.get(body.get('error'), 500)
    headers = {}
    if status == 401:
        # Required by RFC 7235, and it is also the only hint a human
        # poking at the API with curl gets about what is missing.
        headers['WWW-Authenticate'] = 'Bearer realm="rtengine"'
    retry_after = getattr(exc, 'retry_after', None)
    if retry_after:
        # A bridge at its in-flight cap (A-5): busy, not broken.
        headers['Retry-After'] = str(int(retry_after))
    return json_response(body, status=status, headers=headers)


# --- the application --------------------------------------------------------

def create_app(engine, bridge=None, api_config=None, spec_path=None,
               swagger_ui=None, name='rtengine'):
    """Build the Flask application for an engine.

    :param engine: the engine to serve. It does not have to be running
        yet; requests that arrive while it is not are refused with 503
        rather than served from state nobody is maintaining.
    :param bridge: a command bridge, or None to build one.
    :param api_config: the ``api`` configuration subtree. Defaults to the
        engine's own, read unredacted because the token lives in it.
    :param spec_path: an OpenAPI document to serve instead of the
        shipped one.
    :param swagger_ui: a directory holding a Swagger UI build to mount at
        ``/api/v1/docs``. Off unless asked for: it is a pile of
        third-party JavaScript, and an API whose documentation endpoint
        is a supply-chain question by default is not a good default.
    :param name: the Flask application name.
    :return: the application.
    :raises ConfigError: the configuration cannot be served -- an
        unreadable token file, or an exposed bind with no authentication.
    """
    if api_config is None:
        api_config = engine.running_config(redact=False).get('api') or {}

    # Refused here as well as in the engine. The engine checks documents
    # it commits; this checks what is actually about to be served, which
    # is not the same thing when an embedding application passes a dict
    # straight to create_app.
    auth_mod.check_bind(api_config)
    policy = auth_mod.TokenAuth.from_config(api_config)

    store = getattr(engine, 'store', None)
    max_body = _setting(store, api_config, 'max-body-bytes', 1048576)
    max_page = _setting(store, api_config, 'max-page', 10000)

    app = Flask(name)
    app.url_map.converters.update(CONVERTERS)
    app.config['MAX_CONTENT_LENGTH'] = int(max_body)
    # On because these are machine-readable documents that humans read in
    # a terminal: sorted keys make two responses diffable, and the
    # ordering costs nothing at this scale.
    app.config['JSON_SORT_KEYS'] = True
    app.config['RTENGINE'] = ApiContext(
        engine=engine,
        bridge=bridge if bridge is not None else CommandBridge(engine),
        auth=policy,
        max_body_bytes=max_body,
        max_page=max_page,
        spec_path=spec_path or SPEC_FILE)

    # Imported here, not at module scope: the blueprints import this
    # module for its helpers, and importing them at the top would make
    # that a cycle. The cost is one import per application built, which
    # is once per process in every real deployment.
    from packets.routing.rtengine.api import (routes_clear, routes_config,
                                              routes_engine, routes_show)

    for blueprint in (routes_engine.blueprint, routes_config.blueprint,
                      routes_show.blueprint, routes_clear.blueprint):
        app.register_blueprint(blueprint, url_prefix=API_PREFIX)

    _install_auth(app)
    _install_error_handlers(app)
    if swagger_ui:
        _mount_swagger_ui(app, swagger_ui)
    return app


def _setting(store, api_config, key, fallback):
    """Read an ``api`` setting, preferring the explicit configuration.

    The schema's defaults live in the store, so they are used when the
    engine has one; a bare dict passed to :func:`create_app` falls back to
    the same numbers written here.
    """
    if key in (api_config or {}):
        return api_config[key]
    if store is not None:
        return store.value(('api', key), fallback)
    return fallback


def _install_auth(app):
    """Register the one authentication hook."""

    health_path = API_PREFIX + '/engine/health'

    @app.before_request
    def _authenticate():
        context = ctx()
        policy = context.current_auth()
        # Kept in step with the limit the context enforces, so that a
        # change to max-body-bytes is not half applied: this is the
        # server-side backstop and json_body is the explicit check.
        app.config['MAX_CONTENT_LENGTH'] = context.max_body_bytes
        if not policy.enabled:
            return None
        # No method is exempt (L-11). OPTIONS used to be, as if for a CORS
        # preflight -- but this API sends no CORS headers, so no browser
        # was ever helped by it, and an unauthenticated OPTIONS answers
        # "which methods exist here" for every path to anybody.
        if policy.allow_unauthenticated_health \
                and request.method in ('GET', 'HEAD') \
                and request.path.rstrip('/') == health_path:
            return None
        policy.check_header(request.headers.get('Authorization'))
        return None


def _install_error_handlers(app):
    """Translate every exception into the uniform error body.

    Registered three ways, and the redundancy is load-bearing rather
    than defensive. Flask's handler lookup keys on an exception's HTTP
    status *and* its class, and the two are not interchangeable: on
    Flask 0.12 a handler registered for ``HTTPException`` lands under
    "no status code" and is never consulted for a 404, which arrives
    with status 404 -- so a routing miss is served as Werkzeug's HTML
    page, and a client that has been promised a JSON envelope gets an
    HTML one at exactly the moment it is least able to cope. Registering
    every status in ``default_exceptions`` as well fixes that on 0.12
    and is harmless on 3.x, where the class registration already worked.
    """

    def handle_engine_error(exc):
        if STATUS.get(exc.error, 500) >= 500:
            _log.exception('request %s %s failed', request.method,
                           request.path)
        return error_response(exc)

    def handle_http_error(exc):
        token = {400: 'Invalid', 401: 'Unauthorized', 403: 'Unauthorized',
                 404: 'NotFound', 405: 'MethodNotAllowed',
                 409: 'Conflict', 412: 'PreconditionFailed',
                 413: 'PayloadTooLarge', 503: 'Unavailable',
                 504: 'Timeout'}.get(exc.code, 'Error')
        body = {'error': token,
                'detail': getattr(exc, 'description', str(exc)),
                'path': request.path}
        return json_response(body, status=exc.code or 500)

    def handle_unexpected(exc):
        # An exception nobody planned for is a defect in this engine, and
        # the response says so instead of pretending the client got
        # something wrong. The traceback goes to the log, not to the
        # client: it names files and line numbers.
        _log.exception('unhandled error serving %s %s', request.method,
                       request.path)
        return json_response({'error': 'Error',
                              'detail': 'internal error: %s'
                                        % type(exc).__name__,
                              'path': request.path}, status=500)

    app.register_error_handler(RtEngineError, handle_engine_error)
    for klass in _engine_error_classes():
        app.register_error_handler(klass, handle_engine_error)
    app.register_error_handler(HTTPException, handle_http_error)
    for code in sorted(default_exceptions):
        app.register_error_handler(code, handle_http_error)
    app.register_error_handler(ValueError, _bad_value)
    app.register_error_handler(Exception, handle_unexpected)


def _bad_value(exc):
    """A ValueError escaping a handler is a bad request, not a crash.

    ``parse_prefix`` and the integer conversions in the configuration
    tree raise it for input the URL converters could not already have
    rejected -- a next-hop in a body, a malformed community string.
    """
    return error_response(ConfigError(str(exc)))


def _engine_error_classes():
    """Return the concrete engine exception classes to register."""
    from packets.routing.rtengine import errors as core_errors
    from packets.routing.rtengine.api.auth import Unauthorized
    from packets.routing.rtengine.api.bridge import BridgeTimeout

    return (core_errors.ConfigError, core_errors.ConflictError,
            core_errors.ApplyError, core_errors.UnavailableError,
            core_errors.PreconditionFailed, NotFound, PayloadTooLarge,
            Unauthorized, BridgeTimeout)


def _mount_swagger_ui(app, directory):
    """Serve a Swagger UI build at ``/api/v1/docs``.

    Static files only, and only from the directory the operator named.
    The UI is pointed at this engine's own spec with a query parameter so
    that no file in the build has to be edited.

    :param app: the application.
    :param directory: a directory holding ``index.html`` and the rest.
    """
    from flask import send_from_directory

    root = os.path.abspath(directory)
    docs = Blueprint('docs', __name__)

    @docs.route('/docs')
    @docs.route('/docs/')
    def _index():
        return send_from_directory(root, 'index.html')

    @docs.route('/docs/<path:filename>')
    def _asset(filename):
        return send_from_directory(root, filename)

    app.register_blueprint(docs, url_prefix=API_PREFIX)
