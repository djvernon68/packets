#!/usr/bin/env python

"""Tests for the rtengine REST API: threads, credentials, revisions, errors.

``test_rtengine_engine.py`` pins what the engine promises; this module pins
what the *HTTP surface* promises on top of it, and those are not the same
list. An API can call every engine method correctly and still be wrong in
five ways that only exist because HTTP is involved, so the tests are shaped
around those five rather than around the route table:

  * **A request thread never touches engine state.** Every handler goes
    through :class:`CommandBridge`, and the bridge's interesting behaviour is
    not marshalling but *giving up*: a command cancelled before it starts
    must never run, and a command that times out while running must be
    reported as ``unknown`` rather than as failed. Those two are asserted
    with a blocked loop and a side-effect list, never with sleeps -- a
    timing-based version of this test passes by accident and then fails in
    CI at four in the morning. The property they protect is the one that
    makes a timed-out ``PUT`` safe: the configuration change the client
    abandoned either happened or did not, and the response says which.

  * **The credential is the one in the running configuration, now.** An
    operator who rotates ``api.auth.token`` through this API has rotated it:
    the old token stops working on the next request, and no restart is
    involved. The test rotates and then asserts both directions, because a
    policy cached at start-up passes a test that only checks the new token.

  * **A document with a secret in it survives a round trip.** Read the whole
    document, edit one unrelated field, write it back: the client must
    neither learn the secret nor destroy it. This is asserted against the
    engine's *unredacted* store afterwards, because "the response did not
    contain the token" is only half the property.

  * **Every failure looks the same.** One envelope -- ``error``, ``detail``,
    ``path`` -- for the engine's own exceptions, for Werkzeug's 404 and 405,
    and for a defect in a handler. A client that has to parse two error
    formats will parse one of them badly, and the format it gets wrong will
    be the one it sees during an outage. The 500 case additionally asserts
    that the body does *not* carry a traceback.

  * **``clear`` does what the URL said.** ``POST /clear/ip/bgp/10.0.0.2``
    looks like "clear this neighbour" and would dispatch to "soft-clear
    every session", because engine dispatch passes the trailing segment
    positionally and the BGP plugin reads its first positional argument as
    the soft directive. It is a 404 here, deliberately, and that is
    regression-tested by name.

Conventions follow ``test_rtengine_engine.py``: plain ``unittest``, no pytest
features, no syntax newer than 3.6.8, and every engine and server created
through a fixture that registers its own cleanup -- a leaked loop thread or a
listening socket does not fail one test, it hangs the run. The whole module
skips when Flask is absent, because the API is an optional extra and the
engine must remain installable without it.
"""

import json
import os
import socket
import stat
import tempfile
import threading
import unittest

from packets.routing.rtengine import ConfigError, Engine, ProtocolPlugin
from packets.routing.rtengine.config import REDACTED

try:
    import flask as _flask
except ImportError:                                  # pragma: no cover
    _flask = None

if _flask is not None:
    from packets.routing.rtengine.api import bridge as bridge_mod
    from packets.routing.rtengine.api.app import STATUS, create_app
    from packets.routing.rtengine.api.auth import TokenAuth
    from packets.routing.rtengine.api.server import ApiServer
    from packets.routing.rtengine.plugins.bgp.plugin import BGPPlugin

#: A token long enough for the schema's ``minlen`` on ``api.auth.token``.
TOKEN = 'a-token-that-is-long-enough'
OTHER_TOKEN = 'the-second-token-after-rotation'

#: A configuration with a BGP instance that will never peer: the neighbour
#: addresses are in a documentation range and nothing listens there. Every
#: test that needs a table needs configuration, not a session.
BGP_CONFIG = {
    'router': {
        'bgp': {
            '65000': {
                'router-id': '10.0.0.1',
                'neighbor': {
                    '10.0.0.2': {'remote-as': 65001,
                                 'description': 'peer-b'},
                },
                'address-family': {
                    'ipv4': {
                        'unicast': {
                            'network': {
                                '192.0.2.0/24': {},
                                '198.51.100.0/24': {},
                                '203.0.113.0/24': {},
                            },
                        },
                    },
                },
            },
        },
    },
}


class BoomPlugin(ProtocolPlugin):
    """A plugin whose show handler raises. For the 500 envelope test.

    A defect in a handler is the one error path that cannot be provoked
    through the front door, and mocking the Flask layer to fake it would
    test the mock. A plugin that raises is the real thing: the exception
    travels the same way a genuine defect would.
    """

    name = 'boom'
    config_section = ('boom',)

    def show_handlers(self):
        def explode(*args, **kwargs):
            raise ZeroDivisionError('a defect, not a bad request')

        return {('boom', 'now'): explode}


class ApiFixture(unittest.TestCase):
    """Builds engines, apps and servers that clean themselves up."""

    def make_engine(self, config=None, plugins=None, start=True):
        """Return an engine, with teardown registered.

        The document is applied with ``replace_config`` *after*
        construction rather than through the ``config`` argument, because
        the store validates before a plugin has grafted its schema on --
        so ``Engine(config={'router': {'bgp': ...}})`` is rejected as an
        unknown key. Every caller here needs a plugin section, so every
        caller needs this order.

        :param config: a document to apply, or None.
        :param plugins: plugins to register; a BGP plugin by default.
        :param start: whether to start the loop.
        :return: the engine.
        """
        if plugins is None:
            plugins = [BGPPlugin()]
        engine = Engine(name='api-test', plugins=plugins)
        self.addCleanup(engine.stop)
        if config:
            engine.replace_config(config)
        if start:
            engine.start()
        return engine

    def make_client(self, engine=None, api_config=None, **kwargs):
        """Return ``(engine, test_client)``.

        :param engine: an engine, or None to build one.
        :param api_config: the ``api`` subtree for the application.
        :param kwargs: passed to :meth:`make_engine`.
        :return: the engine and a Flask test client.
        """
        if engine is None:
            engine = self.make_engine(**kwargs)
        app = create_app(engine, api_config=api_config or {})
        app.config['PROPAGATE_EXCEPTIONS'] = False
        return engine, app.test_client()

    def make_server(self, engine=None, api_config=None, **kwargs):
        """Return a started :class:`ApiServer` on a loopback port 0.

        Port 0 always: a test that binds a fixed port fails when the
        machine happens to be using it, and the failure looks like a bug
        in the API.

        :param engine: an engine, or None to build one.
        :param api_config: the ``api`` subtree.
        :return: the server.
        """
        if engine is None:
            engine = self.make_engine(**kwargs)
        config = dict(api_config or {})
        config.setdefault('bind', '127.0.0.1:0')
        server = ApiServer(engine, api_config=config)
        self.addCleanup(server.stop)
        return server.start()

    # --- helpers -----------------------------------------------------------

    def body(self, response):
        """Return a response's JSON body.

        :param response: a Flask test response.
        :return: the parsed body.
        """
        text = response.data.decode('utf-8')
        try:
            return json.loads(text)
        except ValueError:
            self.fail('response was not JSON (%s): %r'
                      % (response.status_code, text[:200]))

    def assertError(self, response, status, token):
        """Assert the uniform error envelope, and return it.

        :param response: the response.
        :param status: the expected HTTP status.
        :param token: the expected ``error`` value.
        :return: the parsed body.
        """
        doc = self.body(response)
        self.assertEqual(status, response.status_code,
                         'expected %s, got %s: %s' % (status,
                                                      response.status_code,
                                                      doc))
        self.assertEqual(token, doc.get('error'))
        self.assertIn('detail', doc)
        self.assertIn('path', doc)
        self.assertTrue(doc['detail'], 'an error with no detail is a 500 '
                                       'with extra steps')
        return doc

    def put(self, client, url, value, **kwargs):
        """PUT a JSON value.

        :param client: the test client.
        :param url: the URL.
        :param value: the body, serialised here.
        :return: the response.
        """
        return client.put(url, data=json.dumps(value),
                          content_type='application/json', **kwargs)

    def patch(self, client, url, value, **kwargs):
        """PATCH a JSON value."""
        return client.patch(url, data=json.dumps(value),
                            content_type='application/json', **kwargs)


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class BridgeTestCase(ApiFixture):
    """The one door from a request thread onto the engine's loop."""

    def test_call_runs_on_the_loop_thread(self):
        """A bridged callable runs on the loop, not on the caller."""
        engine = self.make_engine()
        bridge = bridge_mod.CommandBridge(engine)
        where = bridge.call(lambda: threading.current_thread().name)
        self.assertNotEqual(threading.current_thread().name, where)
        # The engine's own predicate, rather than a thread name we would
        # then have to keep in step with loop.py's naming.
        self.assertIs(True, bridge.call(engine.in_loop))

    def test_inline_when_already_on_the_loop(self):
        """Called from the loop itself, it does not deadlock on itself."""
        engine = self.make_engine()
        bridge = bridge_mod.CommandBridge(engine)

        def from_the_loop():
            return bridge.call(lambda: 'nested')

        self.assertEqual('nested', engine.submit(from_the_loop).result(5))
        self.assertEqual(1, bridge.stats()['inline'])

    def test_timeout_before_start_cancels_and_never_runs(self):
        """A command that timed out before starting must not happen.

        This is the behaviour that makes an abandoned ``PUT`` safe, so it
        is asserted on a side-effect rather than on the exception alone.
        The loop is blocked on an event, the victim is submitted behind
        the block and timed out, and the queue is then drained with a
        barrier: because the loop's queue is FIFO, the barrier completing
        proves the victim's turn has already come and gone.
        """
        engine = self.make_engine()
        bridge = bridge_mod.CommandBridge(engine)
        blocked = threading.Event()
        ran = []

        engine.submit(blocked.wait)
        try:
            with self.assertRaises(bridge_mod.BridgeTimeout) as caught:
                bridge.call_timeout(0.05, lambda: ran.append('victim'))
            self.assertEqual(bridge_mod.CANCELLED, caught.exception.state)
            self.assertEqual(engine.revision, caught.exception.revision)
        finally:
            blocked.set()
        engine.submit(lambda: None).result(5)
        self.assertEqual([], ran, 'a cancelled command ran anyway')
        self.assertEqual(1, bridge.stats()['cancelled'])

    def test_timeout_while_running_is_unknown_not_cancelled(self):
        """A command already running is reported as ``unknown``.

        It is not interrupted -- half-applying a configuration change is
        the failure this design exists to prevent -- so the honest answer
        is "it is running, re-read to find out", with the revision as it
        was before the call so the client has something to compare.
        """
        engine = self.make_engine()
        bridge = bridge_mod.CommandBridge(engine)
        release = threading.Event()
        finished = []

        def slow():
            release.wait(5)
            finished.append(True)

        before = engine.revision
        try:
            with self.assertRaises(bridge_mod.BridgeTimeout) as caught:
                bridge.call_timeout(0.05, slow)
            self.assertEqual(bridge_mod.UNKNOWN, caught.exception.state)
            self.assertEqual(before, caught.exception.revision)
            body = caught.exception.as_dict()
            self.assertEqual('Timeout', body['error'])
            self.assertEqual(bridge_mod.UNKNOWN, body['state'])
        finally:
            release.set()
        engine.submit(lambda: None).result(5)
        self.assertEqual([True], finished, 'a running command was killed')
        self.assertEqual(1, bridge.stats()['unknown'])

    def test_timeout_maps_to_504(self):
        """The bridge's timeout is a 504 with the state in the body."""
        engine, client = self.make_client()
        blocked = threading.Event()
        engine.submit(blocked.wait)
        client.application.config['RTENGINE'].bridge.timeout = 0.05
        try:
            response = client.get('/api/v1/engine/status')
        finally:
            blocked.set()
        doc = self.assertError(response, 504, 'Timeout')
        self.assertEqual(bridge_mod.CANCELLED, doc['state'])

    def test_stopped_engine_is_unavailable(self):
        """A request to a stopped engine is 503, not a stale answer."""
        engine, client = self.make_client()
        engine.stop()
        self.assertError(client.get('/api/v1/engine/status'), 503,
                         'Unavailable')


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class AuthTestCase(ApiFixture):
    """Bearer tokens, the exposed-bind rule, and rotation."""

    def test_no_token_configured_serves_openly(self):
        """An engine with no ``api.auth`` needs no credential."""
        _engine, client = self.make_client()
        self.assertEqual(200, client.get('/api/v1/engine/status').status_code)

    def test_token_required_when_configured(self):
        """With a token configured, the header is the only way in."""
        _engine, client = self.make_client(
            api_config={'auth': {'token': TOKEN}})
        response = client.get('/api/v1/engine/status')
        self.assertError(response, 401, 'Unauthorized')
        self.assertIn('Bearer', response.headers.get('WWW-Authenticate', ''))
        self.assertEqual(200, client.get(
            '/api/v1/engine/status',
            headers={'Authorization': 'Bearer ' + TOKEN}).status_code)

    def test_malformed_and_near_miss_credentials_are_refused(self):
        """Every wrong credential fails the same way.

        Including a token that is a prefix of the real one: the compare
        is ``hmac.compare_digest``, and a length-dependent shortcut would
        show up here as a different message or a different status.
        """
        _engine, client = self.make_client(
            api_config={'auth': {'token': TOKEN}})
        details = set()
        for header in ('', 'Bearer', 'Bearer ', 'Basic ' + TOKEN,
                       'Bearer ' + TOKEN[:-1], 'Bearer ' + TOKEN + 'x',
                       TOKEN):
            doc = self.assertError(
                client.get('/api/v1/engine/status',
                           headers={'Authorization': header}),
                401, 'Unauthorized')
            details.add(doc['detail'])
        self.assertEqual(1, len(details),
                         'the failures differ, which tells a caller which '
                         'part of their credential was close: %s' % details)

    def test_health_may_be_exempted(self):
        """``allow-unauthenticated-health`` exempts health and nothing else.

        The thing polling health is usually a supervisor with nowhere to
        keep a secret; the rest of the API is not exempt, and that is the
        half of this option worth testing.
        """
        _engine, client = self.make_client(api_config={
            'auth': {'token': TOKEN, 'allow-unauthenticated-health': True}})
        self.assertEqual(200, client.get(
            '/api/v1/engine/health').status_code)
        self.assertError(client.get('/api/v1/engine/status'), 401,
                         'Unauthorized')
        self.assertError(client.get('/api/v1/running-config'), 401,
                         'Unauthorized')

    def test_rotation_takes_effect_on_the_next_request(self):
        """Rotating the token through the API rotates the token.

        A policy resolved once at start-up would keep honouring the old
        credential until somebody restarted the process, which is the
        opposite of what rotating a credential is for.
        """
        engine, client = self.make_client(
            api_config={'auth': {'token': TOKEN}})
        old = {'Authorization': 'Bearer ' + TOKEN}
        new = {'Authorization': 'Bearer ' + OTHER_TOKEN}
        self.assertEqual(200, client.get('/api/v1/engine/status',
                                         headers=old).status_code)
        self.assertEqual(200, self.put(client, '/api/v1/running-config',
                                       {'api': {'auth': {
                                           'token': OTHER_TOKEN}}},
                                       headers=old).status_code)
        self.assertError(client.get('/api/v1/engine/status', headers=old),
                         401, 'Unauthorized')
        self.assertEqual(200, client.get('/api/v1/engine/status',
                                         headers=new).status_code)

    def test_token_file_is_read_and_never_served(self):
        """A token from a file authenticates and does not leak.

        ``status`` reports where the token came from because an operator
        needs to know which file to rotate; it must not report what the
        token is.
        """
        path = os.path.join(tempfile.mkdtemp(), 'token')
        with open(path, 'w') as handle:
            handle.write(TOKEN + '\n')
        self.addCleanup(os.unlink, path)
        _engine, client = self.make_client(
            api_config={'auth': {'token-file': path}})
        response = client.get('/api/v1/engine/status',
                              headers={'Authorization': 'Bearer ' + TOKEN})
        self.assertEqual(200, response.status_code)
        text = response.data.decode('utf-8')
        self.assertNotIn(TOKEN, text)
        self.assertIn(path, text)

    def test_unreadable_token_file_refuses_to_start(self):
        """A configured token file that cannot be read is fatal.

        Starting anyway would serve an API the operator believes is
        protected, which is the one outcome worse than not starting.
        """
        engine = self.make_engine()
        with self.assertRaises(ConfigError):
            create_app(engine, api_config={
                'auth': {'token-file': '/nonexistent/rtengine-token'}})

    def test_exposed_bind_without_auth_is_refused(self):
        """``0.0.0.0`` with no credential does not come up."""
        engine = self.make_engine()
        with self.assertRaises(ConfigError) as caught:
            create_app(engine, api_config={'bind': '0.0.0.0:0'})
        self.assertEqual('api.bind', caught.exception.path)
        # ... and the two documented ways to say "I meant it".
        create_app(engine, api_config={'bind': '0.0.0.0:0',
                                       'auth': {'token': TOKEN}})
        create_app(engine, api_config={'bind': '0.0.0.0:0',
                                       'insecure': True})

    def test_loopback_forms_are_all_recognised(self):
        """Every spelling of loopback is allowed without a credential.

        If one of them were not recognised, the API would refuse to
        start on a configuration that is in fact safe -- and the operator
        would fix it by setting ``insecure``.
        """
        engine = self.make_engine()
        for bind in ('127.0.0.1:0', 'localhost:0', '[::1]:0', '127.1.2.3:0',
                     '127.0.0.1'):
            create_app(engine, api_config={'bind': bind})

    def test_describe_never_includes_the_secret(self):
        """The policy describes itself without the credential in it."""
        policy = TokenAuth.from_config({'auth': {'token': TOKEN}})
        described = json.dumps(policy.describe())
        self.assertNotIn(TOKEN, described)
        self.assertIn('"required": true', described)


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class ErrorEnvelopeTestCase(ApiFixture):
    """One error shape, whoever raised it."""

    def test_status_table_covers_every_token(self):
        """Every token the API can emit has a status mapped to it."""
        for token in ('Invalid', 'Unauthorized', 'NotFound', 'Conflict',
                      'PreconditionFailed', 'PayloadTooLarge', 'Timeout',
                      'ApplyFailed', 'Unavailable', 'Error',
                      'MethodNotAllowed'):
            self.assertIn(token, STATUS)

    def test_unrouted_url_is_json_not_html(self):
        """A 404 from the router wears the same envelope as ours.

        Flask's default is an HTML page, and a client that parses JSON
        would see it only when something had already gone wrong.
        """
        _engine, client = self.make_client()
        self.assertError(client.get('/api/v1/nope'), 404, 'NotFound')
        self.assertError(client.get('/nope'), 404, 'NotFound')

    def test_wrong_method_is_json(self):
        """405 too. ``show`` is a GET; posting to it is not a mystery."""
        _engine, client = self.make_client()
        self.assertError(client.post('/api/v1/show/engine/status'), 405,
                         'MethodNotAllowed')
        self.assertError(client.get('/api/v1/clear/ip/bgp'), 405,
                         'MethodNotAllowed')

    def test_malformed_json_body_is_invalid(self):
        """A body that is not JSON is a 400 that says so."""
        _engine, client = self.make_client()
        response = client.put('/api/v1/router/bgp/65000',
                              data='{not json',
                              content_type='application/json')
        doc = self.assertError(response, 400, 'Invalid')
        self.assertIn('not valid JSON', doc['detail'])

    def test_missing_body_is_invalid(self):
        """A PUT with no body is a 400, not an empty configuration."""
        _engine, client = self.make_client()
        self.assertError(client.put('/api/v1/router/bgp/65000'), 400,
                         'Invalid')

    def test_oversize_body_is_refused_by_the_limit(self):
        """``max-body-bytes`` is enforced, and the limit is in the error."""
        _engine, client = self.make_client(
            api_config={'max-body-bytes': 512})
        response = client.put('/api/v1/router/bgp/65000',
                              data=json.dumps({'router-id': '10.0.0.1',
                                               'pad': 'x' * 1024}),
                              content_type='application/json')
        doc = self.assertError(response, 413, 'PayloadTooLarge')
        self.assertIn('512', doc['detail'])

    def test_a_defect_in_a_handler_is_500_without_a_traceback(self):
        """An unplanned exception is reported as ours, and is not leaked.

        The body names the exception type so a bug report can be filed;
        the traceback goes to the log, because it names files and lines.
        """
        engine = self.make_engine(plugins=[BoomPlugin()])
        _engine, client = self.make_client(engine=engine)
        response = client.get('/api/v1/show/boom/now')
        doc = self.assertError(response, 500, 'Error')
        self.assertIn('ZeroDivisionError', doc['detail'])
        self.assertNotIn('Traceback', doc['detail'])
        self.assertNotIn('File "', doc['detail'])


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class ConfigResourceTestCase(ApiFixture):
    """The configuration tree: CRUD, revisions, redaction, atomicity."""

    def setUp(self):
        self.engine, self.client = self.make_client(config=BGP_CONFIG)

    def test_round_trip_on_a_neighbour(self):
        """PUT, GET, PATCH, DELETE, and the document follows along."""
        url = '/api/v1/router/bgp/65000/neighbor/10.0.0.3'
        created = self.put(self.client, url, {'remote-as': 65002})
        self.assertEqual(200, created.status_code)
        doc = self.body(created)
        self.assertEqual('router.bgp.65000.neighbor.10.0.0.3', doc['path'])
        self.assertEqual(self.engine.revision, doc['revision'])
        self.assertEqual('"%d"' % self.engine.revision,
                         created.headers['ETag'])

        self.assertEqual({'remote-as': 65002},
                         self.body(self.client.get(url)))

        self.assertEqual(200, self.patch(self.client, url,
                                         {'description': 'peer-c'}
                                         ).status_code)
        self.assertEqual({'remote-as': 65002, 'description': 'peer-c'},
                         self.body(self.client.get(url)))

        self.assertEqual(200, self.client.delete(url).status_code)
        self.assertError(self.client.get(url), 404, 'NotFound')
        self.assertError(self.client.delete(url), 404, 'NotFound')

    def test_patch_null_removes_a_key(self):
        """``null`` in a PATCH is IOS ``no`` for one leaf."""
        url = '/api/v1/router/bgp/65000/neighbor/10.0.0.2'
        self.assertEqual('peer-b', self.body(self.client.get(url))
                         ['description'])
        self.assertEqual(200, self.patch(self.client, url,
                                         {'description': None}).status_code)
        self.assertNotIn('description', self.body(self.client.get(url)))

    def test_patch_on_an_absent_resource_is_404(self):
        """Merging into nothing is a mistake, not an empty merge."""
        doc = self.assertError(
            self.patch(self.client,
                       '/api/v1/router/bgp/65000/neighbor/10.9.9.9',
                       {'remote-as': 1}), 404, 'NotFound')
        self.assertIn('PUT', doc['detail'])

    def test_a_rejected_write_moves_nothing(self):
        """An invalid change leaves the document and the revision alone.

        The engine's atomicity is tested in its own module; this asserts
        that the API does not have a path around it -- a handler that
        wrote before validating would pass every other test here.
        """
        before = self.engine.revision
        snapshot = self.engine.running_config()
        doc = self.assertError(
            self.put(self.client,
                     '/api/v1/router/bgp/65000/neighbor/10.0.0.4',
                     {'remote-as': 'not-a-number'}), 400, 'Invalid')
        self.assertIn('remote-as', doc['path'])
        self.assertEqual(before, self.engine.revision)
        self.assertEqual(snapshot, self.engine.running_config())

    def test_second_instance_is_a_conflict(self):
        """The v1 single-instance rule is a 409, not a 400.

        A client that can retry a 400 by fixing its body cannot fix this
        one: the request is well formed and the engine's state is what
        makes it impossible.
        """
        self.assertError(self.put(self.client, '/api/v1/router/bgp/65001',
                                  {'router-id': '10.0.0.9'}),
                         409, 'Conflict')

    def test_if_match_guards_a_write(self):
        """Stale ``If-Match`` is 412; the current revision goes through."""
        etag = self.client.get('/api/v1/running-config').headers['ETag']
        url = '/api/v1/router/bgp/65000/neighbor/10.0.0.5'
        self.assertError(self.put(self.client, url, {'remote-as': 65005},
                                  headers={'If-Match': '"0"'}),
                         412, 'PreconditionFailed')
        self.assertEqual(200, self.put(self.client, url,
                                       {'remote-as': 65005},
                                       headers={'If-Match': etag}
                                       ).status_code)
        # The tag has moved on, so the same header is now stale.
        self.assertError(self.put(self.client, url, {'remote-as': 65006},
                                  headers={'If-Match': etag}),
                         412, 'PreconditionFailed')

    def test_if_match_star_and_weak_tags_are_accepted(self):
        """``*`` means "I do not care", and ``W/"3"`` is still 3."""
        url = '/api/v1/router/bgp/65000/neighbor/10.0.0.6'
        self.assertEqual(200, self.put(self.client, url,
                                       {'remote-as': 65007},
                                       headers={'If-Match': '*'}
                                       ).status_code)
        etag = self.client.get('/api/v1/running-config').headers['ETag']
        self.assertEqual(200, self.patch(
            self.client, url, {'description': 'weak'},
            headers={'If-Match': 'W/' + etag}).status_code)

    def test_if_match_that_is_not_a_revision_is_invalid(self):
        """A garbage ``If-Match`` is refused rather than ignored.

        Ignoring it would turn a client's concurrency control into
        last-write-wins silently, which is the failure mode the header
        exists to prevent.
        """
        self.assertError(
            self.put(self.client, '/api/v1/router/bgp/65000/neighbor/'
                                  '10.0.0.7', {'remote-as': 65008},
                     headers={'If-Match': '"not-a-revision"'}),
            400, 'Invalid')

    def test_secret_round_trip_neither_leaks_nor_destroys(self):
        """Read the document, edit one field, write it back.

        The client never sees the token and does not lose it. Asserted
        against the engine's unredacted store, because "the response did
        not contain it" is only half of the property.
        """
        self.engine.configure(('api', 'auth', 'token'), TOKEN)
        headers = {'Authorization': 'Bearer ' + TOKEN}
        read = self.client.get('/api/v1/running-config', headers=headers)
        document = self.body(read)
        self.assertEqual(REDACTED, document['api']['auth']['token'])
        self.assertNotIn(TOKEN, read.data.decode('utf-8'))

        document['router']['bgp']['65000']['router-id'] = '10.0.0.77'
        written = self.put(self.client, '/api/v1/running-config', document,
                           headers=headers)
        self.assertEqual(200, written.status_code)

        stored = self.engine.running_config(redact=False)
        self.assertEqual(TOKEN, stored['api']['auth']['token'])
        self.assertEqual('10.0.0.77',
                         stored['router']['bgp']['65000']['router-id'])

    def test_running_config_etag_is_the_revision(self):
        """The entity tag is the revision, so HTTP's idiom is the engine's."""
        response = self.client.get('/api/v1/running-config')
        self.assertEqual('"%d"' % self.engine.revision,
                         response.headers['ETag'])

    def test_replace_config_is_guarded_too(self):
        """A whole-document write honours ``If-Match``."""
        self.assertError(self.put(self.client, '/api/v1/running-config',
                                  {}, headers={'If-Match': '"0"'}),
                         412, 'PreconditionFailed')

    def test_prefix_keys_are_matched_as_values(self):
        """Two spellings of one prefix are one resource.

        A document loaded from a file may hold ``2001:db8:0::/32``; a
        client will ask for ``2001:db8::/32``. Answering 404 while the
        operator is looking at the entry is not a defensible answer.
        """
        self.assertEqual(200, self.put(
            self.client, '/api/v1/ipv6/route/static/2001:db8:0::/32',
            {'next-hop': '2001:db8::1'}).status_code)
        self.assertEqual(
            200, self.client.get(
                '/api/v1/ipv6/route/static/2001:db8::/32').status_code)
        self.assertEqual(
            200, self.client.delete(
                '/api/v1/ipv6/route/static/2001:0db8:0000::/32'
            ).status_code)

    def test_prefix_in_a_url_is_one_segment(self):
        """``/network/192.0.2.0/24`` is a prefix, not two segments."""
        url = ('/api/v1/router/bgp/65000/address-family/ipv4/unicast'
               '/network/192.0.2.0/24')
        self.assertEqual(200, self.client.get(url).status_code)
        self.assertEqual(200, self.client.delete(url).status_code)
        self.assertError(self.client.get(url), 404, 'NotFound')

    def test_a_malformed_key_in_a_url_is_a_bad_request(self):
        """A-4: a key that cannot be valid is a 400 saying why.

        It used to be a 404 -- "no such neighbour" for an address that
        cannot exist, which sends an operator looking through the
        configuration for something that was never a question of
        configuration. The detail names the value.
        """
        for url, words in (
                ('/api/v1/router/bgp/65000/neighbor/10.0.0.999',
                 '10.0.0.999'),
                ('/api/v1/router/bgp/65000/neighbor/10.0.0.999',
                 'not a valid address'),
                ('/api/v1/ip/route/static/10.0.0.0/99', 'length 99'),
                ('/api/v1/ip/route/static/192.0.2.300/24', '192.0.2.300'),
                ('/api/v1/router/bgp/65000/address-family/ipv4/unicast/'
                 'network/10.0.0.0/33', 'length 33'),
                ('/api/v1/router/bgp/0', 'AS number'),
                ('/api/v1/router/bgp/99999999999', 'AS number')):
            for method in ('get', 'put', 'delete'):
                response = getattr(self.client, method)(url, data='{}')
                self.assertError(response, 400, 'Invalid')
                self.assertIn(words, self.body(response)['detail'])

    def test_a_url_that_names_nothing_is_still_a_404(self):
        """A-4 did not turn every miss into a 400.

        A well-formed key that is not configured, and a URL that matches
        no rule at all, are both still "not found".
        """
        for url in ('/api/v1/router/bgp/65000/neighbor/10.0.0.99',
                    '/api/v1/router/bgp/65000/neighbor/10.0.0.0/24',
                    '/api/v1/no/such/thing'):
            self.assertError(self.client.get(url), 404, 'NotFound')

    def test_no_two_rules_compete_for_a_converter_position(self):
        """What makes a converter's 400 safe (A-4).

        A converter that raises ends the match outright, where the
        ``ValidationError`` it used to raise let Werkzeug try the next
        rule. That loses nothing only while no two rules accept the same
        URL shape with a converter at the same position.
        """
        shapes = {}
        for rule in self.client.application.url_map.iter_rules():
            parts = rule.rule.strip('/').split('/')
            shape = tuple('<>' if p.startswith('<') else p for p in parts)
            if '<>' not in shape:
                continue
            shapes.setdefault(shape, []).append(rule.rule)
        clashes = {s: r for s, r in shapes.items() if len(r) > 1}
        self.assertEqual({}, clashes)

    def test_install_settings_report_what_is_in_effect(self):
        """``/ip/route/install`` answers with defaults filled in.

        The raw subtree of a fresh engine is ``{}``, and "is this engine
        writing the kernel table" must not be a question a client answers
        by knowing the schema's defaults.
        """
        doc = self.body(self.client.get('/api/v1/ip/route/install'))
        self.assertIs(False, doc['install'])
        self.assertEqual(254, doc['table'])
        self.assertEqual(190, doc['protocol'])
        self.assertEqual({'ebgp': 20, 'ibgp': 200}, doc['priority'])
        self.assertIn('sink', doc)

    def test_install_patch_is_narrow(self):
        """It takes the settings it documents, and nothing else.

        ``static`` in particular: it is a table of routes with its own
        resource, and merging it here would let a PATCH carrying one
        route delete the rest.
        """
        self.assertEqual(200, self.patch(self.client,
                                         '/api/v1/ip/route/install',
                                         {'table': 200}).status_code)
        self.assertEqual(200, self.body(self.client.get(
            '/api/v1/ip/route/install'))['table'])
        self.assertError(self.patch(self.client,
                                    '/api/v1/ip/route/install',
                                    {'nonsense': 1}), 400, 'Invalid')
        self.assertError(self.patch(self.client,
                                    '/api/v1/ip/route/install',
                                    {'static': {}}), 400, 'Invalid')

    def test_install_patch_keeps_the_static_routes(self):
        """Changing a setting does not disturb the static table."""
        self.assertEqual(200, self.put(
            self.client, '/api/v1/ip/route/static/10.9.0.0/24',
            {'next-hop': '10.0.0.254'}).status_code)
        self.assertEqual(200, self.patch(self.client,
                                         '/api/v1/ip/route/install',
                                         {'table': 201}).status_code)
        self.assertEqual(200, self.client.get(
            '/api/v1/ip/route/static/10.9.0.0/24').status_code)

    def test_a_list_resource_round_trips_as_an_array(self):
        """A prefix-list is an array, and PUT takes the array back."""
        entries = [{'seq': 5, 'action': 'permit', 'prefix': '10.0.0.0/8',
                    'le': 24}]
        self.assertEqual(200, self.put(self.client,
                                       '/api/v1/ip/prefix-list/PL-IN',
                                       entries).status_code)
        self.assertEqual(entries, self.body(self.client.get(
            '/api/v1/ip/prefix-list/PL-IN')))
        self.assertError(self.patch(self.client,
                                    '/api/v1/ip/prefix-list/PL-IN',
                                    {'seq': 5}), 405, 'MethodNotAllowed')

    def test_collections_are_readable(self):
        """The intermediate URLs answer, so a client can walk the tree."""
        for url in ('/api/v1/router/bgp',
                    '/api/v1/router/bgp/65000/neighbor',
                    '/api/v1/router/bgp/65000/address-family',
                    '/api/v1/router/bgp/65000/address-family/ipv4/unicast'
                    '/network'):
            self.assertEqual(200, self.client.get(url).status_code, url)


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class ShowTestCase(ApiFixture):
    """``GET /show/...``: the same documents the engine returns."""

    def setUp(self):
        self.engine, self.client = self.make_client(config=BGP_CONFIG)

    def test_index_lists_the_plugins_views(self):
        """The index is the engine's actual capability, not a fixed list."""
        views = self.body(self.client.get('/api/v1/show'))['views']
        paths = [tuple(view['path']) for view in views]
        self.assertIn(('ip', 'bgp', 'summary'), paths)
        self.assertIn(('engine', 'status'), paths)
        self.assertEqual(sorted(paths), [tuple(p) for p in
                                         self.engine.show_paths()])

    def test_a_view_matches_the_engines_own_answer(self):
        """The HTTP answer is the engine's answer, not a rendering of it."""
        for path in (('ip', 'bgp', 'summary'), ('engine', 'status'),
                     ('ip', 'route')):
            url = '/api/v1/show/' + '/'.join(path)
            self.assertEqual(self.engine.show(*path),
                             self.body(self.client.get(url)), url)

    def test_a_prefix_argument_survives_the_url(self):
        """``/show/ip/bgp/192.0.2.0/24`` asks about one prefix.

        The slash arrives as a path separator whatever the client did to
        it, so the last two segments are rejoined when they form a
        prefix -- which is the only position these commands take one.
        """
        self.assertEqual(
            self.engine.show('ip', 'bgp', '192.0.2.0/24'),
            self.body(self.client.get('/api/v1/show/ip/bgp/192.0.2.0/24')))

    def test_an_unknown_view_is_404_with_directions(self):
        """A mistyped view is a bad URL, not an empty answer."""
        doc = self.assertError(self.client.get('/api/v1/show/ip/nonsense'),
                               404, 'NotFound')
        self.assertIn('/api/v1/show', doc['detail'])

    def test_limit_is_capped_not_rejected(self):
        """A client asking for everything gets a page, not an error."""
        _engine, client = self.make_client(engine=self.engine,
                                           api_config={'max-page': 2})
        doc = self.body(client.get('/api/v1/show/ip/bgp?limit=1000'))
        self.assertLessEqual(len(doc['routes']), 2)

    def test_pagination_is_passed_through(self):
        """``limit`` and ``offset`` reach the handler that has them."""
        doc = self.body(self.client.get(
            '/api/v1/show/ip/bgp?limit=1&offset=1'))
        self.assertEqual(1, doc['offset'])
        self.assertEqual(1, len(doc['routes']))

    def test_a_parameter_the_view_does_not_have_is_400(self):
        """The error names the parameter, not our call stack."""
        doc = self.assertError(
            self.client.get('/api/v1/show/ip/route?offset=5'), 400,
            'Invalid')
        self.assertIn('offset', doc['detail'])
        self.assertNotIn('as_dict', doc['detail'])

    def test_a_non_numeric_page_argument_is_400(self):
        """``?limit=lots`` is a bad request, not a 500."""
        self.assertError(self.client.get('/api/v1/show/ip/bgp?limit=lots'),
                         400, 'Invalid')
        self.assertError(self.client.get('/api/v1/show/ip/bgp?offset=-1'),
                         400, 'Invalid')

    def test_limit_zero_is_refused_rather_than_interpreted(self):
        """``?limit=0`` is an error, not a guess.

        Zero means "no rows" to whoever typed it and "no limit" to the
        ``rows[:limit] if limit else rows`` idiom several handlers use,
        and the request where those two readings differ most is the one
        against a full table. An earlier version quietly read it as 1,
        which is a third answer that nobody asked for.
        """
        doc = self.assertError(
            self.client.get('/api/v1/show/ip/bgp?limit=0'), 400, 'Invalid')
        self.assertEqual('limit', doc['path'])
        self.assertEqual(200, self.client.get(
            '/api/v1/show/ip/bgp?limit=1').status_code)


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class ClearTestCase(ApiFixture):
    """``POST /clear/...``: the actions, and the one that looked safe."""

    def setUp(self):
        self.engine, self.client = self.make_client(config=BGP_CONFIG)

    def post(self, url, body=None):
        """POST an action, with an optional JSON body."""
        if body is None:
            return self.client.post(url)
        return self.client.post(url, data=json.dumps(body),
                                content_type='application/json')

    def test_index_lists_the_actions(self):
        """Enumerating what can be done does not do any of it."""
        actions = self.body(self.client.get('/api/v1/clear'))['actions']
        paths = [tuple(action['path']) for action in actions]
        self.assertIn(('ip', 'bgp'), paths)
        self.assertIn(('ip', 'bgp', 'neighbor'), paths)

    def test_clearing_one_neighbour_by_address(self):
        """The documented URL clears the neighbour it names."""
        doc = self.body(self.post('/api/v1/clear/ip/bgp/neighbor/10.0.0.2',
                                  {'soft': 'in'}))
        self.assertEqual('10.0.0.2', doc.get('neighbor'))

    def test_address_without_the_neighbor_segment_is_refused(self):
        """``POST /clear/ip/bgp/10.0.0.2`` must not clear everything.

        Engine dispatch would match ``('ip', 'bgp')`` and pass
        ``'10.0.0.2'`` to ``clear_all`` positionally, where it is read as
        the soft directive -- so a request that looks like "clear one
        neighbour" would soft-clear every session and say nothing about
        it. The URL is a 404 that names the right one instead.
        """
        doc = self.assertError(
            self.post('/api/v1/clear/ip/bgp/10.0.0.2', {'soft': 'in'}),
            404, 'NotFound')
        self.assertIn('/clear/ip/bgp/neighbor/10.0.0.2', doc['detail'])

    def test_soft_directions_are_validated_not_guessed(self):
        """A typo in ``soft`` is refused.

        Guessing wrong here is the difference between re-running policy
        and dropping every session in the room.
        """
        for value in ('inn', 'IN-OUT', 0, [], {'in': True}):
            self.assertError(self.post('/api/v1/clear/ip/bgp',
                                       {'soft': value}), 400, 'Invalid')

    def test_soft_spellings_that_are_accepted(self):
        """The three directions, and ``true`` for inbound."""
        for value in ('in', 'out', 'both', 'IN', True, False):
            self.assertEqual(200, self.post('/api/v1/clear/ip/bgp',
                                            {'soft': value}).status_code,
                             value)

    def test_an_unknown_body_key_is_refused(self):
        """A misspelled key is not silently ignored.

        ``{"softly": "in"}`` would otherwise be a hard clear of every
        session, requested by an operator who typed a soft one.
        """
        doc = self.assertError(self.post('/api/v1/clear/ip/bgp',
                                         {'softly': 'in'}), 400, 'Invalid')
        self.assertIn('softly', doc['detail'])

    def test_no_body_is_a_hard_clear(self):
        """Bodyless is allowed, and means what the CLI means."""
        self.assertEqual(200, self.post('/api/v1/clear/ip/bgp').status_code)

    def test_an_unknown_action_is_404(self):
        """An action this engine does not have is a bad URL."""
        self.assertError(self.post('/api/v1/clear/ip/nonsense'), 404,
                         'NotFound')

    def test_too_many_arguments_is_404(self):
        """Extra segments are refused rather than passed along."""
        self.assertError(
            self.post('/api/v1/clear/ip/bgp/neighbor/10.0.0.2/twice'),
            404, 'NotFound')


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class EngineDocumentTestCase(ApiFixture):
    """status, health, plugins: what a monitoring system reads."""

    def setUp(self):
        self.engine, self.client = self.make_client(config=BGP_CONFIG)

    def test_health_is_the_engines_document(self):
        """``GET /engine/health`` adds nothing to ``Engine.health()``.

        A monitoring rule written against one must hold for the other, so
        the keys are compared exactly. The values cannot be: the
        document carries loop lag and uptime, which move between two
        calls by design.
        """
        served = self.body(self.client.get('/api/v1/engine/health'))
        direct = self.engine.health()
        self.assertEqual(sorted(direct), sorted(served))
        self.assertEqual(sorted(direct['plugins']),
                         sorted(served['plugins']))
        self.assertEqual(direct['config']['revision'],
                         served['config']['revision'])
        self.assertIn(served['status'], ('ok', 'degraded', 'down'))

    def test_status_carries_the_api_layers_own_facts(self):
        """``status`` is where the REST layer's view belongs.

        Not health: the bind, the credential's source and the bridge's
        counters are configuration and identity, and mixing them into the
        health document would mean a probe saw different keys depending
        on which door it came through.
        """
        doc = self.body(self.client.get('/api/v1/engine/status'))
        self.assertEqual('api-test', doc['name'])
        self.assertEqual(self.engine.revision, doc['revision'])
        self.assertIn('auth', doc['api'])
        self.assertIn('bridge', doc['api'])
        self.assertIs(False, doc['api']['auth']['required'])

    def test_plugins_are_listed_with_their_families(self):
        """The plugin list names what each one carries."""
        plugins = self.body(self.client.get(
            '/api/v1/engine/plugins'))['plugins']
        self.assertEqual(['bgp'], [p['name'] for p in plugins])
        self.assertEqual([[1, 1]], plugins[0]['afi_safi'])
        self.assertEqual('router.bgp', plugins[0]['config_section'])

    def test_the_index_points_at_everything_else(self):
        """The base URL is discoverable rather than a 404."""
        links = self.body(self.client.get('/api/v1/'))['links']
        for url in links.values():
            self.assertTrue(url.startswith('/api/v1'), url)

    def test_the_schema_is_served_with_the_plugins_section_grafted(self):
        """The schema endpoint answers for *this* engine's vocabulary."""
        schema = self.body(self.client.get('/api/v1/engine/config-schema'))
        self.assertIn('router', schema['keys'])
        self.assertIn('bgp', schema['keys']['router']['keys'])


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class ServerTestCase(ApiFixture):
    """The socket: a real server, a real client, real concurrency."""

    def fetch(self, url, token=None, method='GET', body=None):
        """Make a real HTTP request. Returns ``(status, parsed body)``.

        ``urllib`` rather than ``requests``: the engine's dependency list
        is the point of this package, and a test that needs a third-party
        HTTP client to prove the server works has tested the wrong thing.
        """
        try:
            from urllib.request import Request, urlopen
            from urllib.error import HTTPError
        except ImportError:                          # pragma: no cover
            self.skipTest('no urllib')
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        data = None if body is None else json.dumps(body).encode('utf-8')
        request = Request(url, data=data, headers=headers, method=method)
        try:
            response = urlopen(request, timeout=10)
            return response.getcode(), json.loads(
                response.read().decode('utf-8'))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode('utf-8'))

    def test_port_zero_reports_the_port_it_got(self):
        """A caller that asked for any port is told which one."""
        server = self.make_server(config=BGP_CONFIG)
        self.assertNotEqual(0, server.port)
        self.assertTrue(server.url.startswith('http://127.0.0.1:'))
        self.assertTrue(server.is_running())

    def test_it_serves_over_the_socket(self):
        """The whole stack, through a socket, from another thread."""
        server = self.make_server(config=BGP_CONFIG)
        status, doc = self.fetch(server.url + '/engine/health')
        self.assertEqual(200, status)
        self.assertIn('status', doc)
        status, doc = self.fetch(server.url + '/show/ip/bgp/summary')
        self.assertEqual(200, status)
        self.assertEqual(65000, doc['local-as'])

    def test_a_write_over_the_socket_reaches_the_loop(self):
        """A PUT from a request thread changes the engine's document."""
        server = self.make_server(config=BGP_CONFIG)
        status, doc = self.fetch(
            server.url + '/router/bgp/65000/neighbor/10.0.0.8',
            method='PUT', body={'remote-as': 65009})
        self.assertEqual(200, status)
        self.assertEqual(server.engine.revision, doc['revision'])
        self.assertIn('10.0.0.8', server.engine.running_config()
                      ['router']['bgp']['65000']['neighbor'])

    def test_the_credential_is_enforced_over_the_socket(self):
        """Authentication is not a test-client artefact."""
        server = self.make_server(config=BGP_CONFIG,
                                  api_config={'auth': {'token': TOKEN}})
        self.assertEqual(401, self.fetch(server.url + '/engine/status')[0])
        self.assertEqual(200, self.fetch(server.url + '/engine/status',
                                         token=TOKEN)[0])

    def test_health_includes_the_api_once_a_server_is_running(self):
        """Both surfaces report the API, because the monitor does.

        The engine cannot ask a Flask server about itself without
        importing Flask, so the server registers a reporter with the
        health monitor. That keeps ``Engine.health()`` and
        ``GET /engine/health`` the same document, which is the property
        that would otherwise have been quietly broken by adding the
        API's facts in the endpoint.
        """
        server = self.make_server(config=BGP_CONFIG)
        direct = server.engine.health()
        self.assertIn('api', direct)
        self.assertIs(True, direct['api']['listening'])
        self.assertEqual('127.0.0.1:%d' % server.port,
                         direct['api']['bind'])
        served = self.fetch(server.url + '/engine/health')[1]
        self.assertEqual(sorted(direct), sorted(served))

    def test_stop_is_idempotent_and_actually_closes(self):
        """After ``stop()`` nothing listens, and stopping again is fine."""
        server = self.make_server(config=BGP_CONFIG)
        host, port = server.host, server.port
        self.assertTrue(server.stop())
        self.assertFalse(server.stop())
        self.assertFalse(server.is_running())
        probe = socket.socket()
        probe.settimeout(2)
        try:
            self.assertRaises(socket.error, probe.connect, (host, port))
        finally:
            probe.close()

    def test_half_a_tls_configuration_is_refused(self):
        """A certificate with no key is not a TLS configuration.

        Coming up in plain HTTP because one line was missing is the
        failure this refuses to have.
        """
        engine = self.make_engine()
        with self.assertRaises(ConfigError):
            ApiServer(engine, api_config={'bind': '127.0.0.1:0',
                                          'tls': {'cert': '/dev/null'}})

    def test_an_exposed_bind_is_refused_before_the_socket_exists(self):
        """The bind rule is enforced by the server too, not just the app."""
        engine = self.make_engine()
        with self.assertRaises(ConfigError):
            ApiServer(engine, api_config={'bind': '0.0.0.0:0'})

    def test_concurrent_readers_never_see_a_torn_document(self):
        """Sixteen readers and a writer, and every answer is coherent.

        The document a reader gets is a deep copy taken on the loop
        thread, so it is a snapshot of one revision -- never a mixture of
        two. A reader that saw a neighbour whose body was half written
        would be the symptom of reading engine state from a request
        thread, which is the mistake the bridge exists to make
        impossible.
        """
        server = self.make_server(config=BGP_CONFIG)
        url = server.url + '/running-config'
        stop = threading.Event()
        failures = []
        revisions = set()

        def read():
            try:
                while not stop.is_set():
                    status, document = self.fetch(url)
                    if status != 200:
                        failures.append((status, document))
                        return
                    peers = document['router']['bgp']['65000']['neighbor']
                    for addr, body in peers.items():
                        if not isinstance(body, dict) \
                                or 'remote-as' not in body:
                            failures.append(('torn', addr, body))
                            return
            except Exception as exc:                 # pragma: no cover
                failures.append(('reader', repr(exc)))

        def write():
            try:
                for index in range(20):
                    status, doc = self.fetch(
                        '%s/router/bgp/65000/neighbor/10.1.0.%d'
                        % (server.url, index + 1), method='PUT',
                        body={'remote-as': 65100 + index,
                              'description': 'writer-%d' % index})
                    if status != 200:
                        failures.append(('writer', status, doc))
                        return
                    revisions.add(doc['revision'])
            except Exception as exc:                 # pragma: no cover
                failures.append(('writer', repr(exc)))

        readers = [threading.Thread(target=read) for _ in range(16)]
        for thread in readers:
            thread.daemon = True
            thread.start()
        writer = threading.Thread(target=write)
        writer.daemon = True
        writer.start()
        writer.join(60)
        stop.set()
        for thread in readers:
            thread.join(30)
        self.assertEqual([], failures[:4])
        self.assertEqual(20, len(revisions),
                         'every write should have its own revision')
        self.assertEqual(20, len(server.engine.running_config()
                                 ['router']['bgp']['65000']['neighbor']) - 1)

    def test_the_bridge_counts_what_it_did(self):
        """The counters a running system is diagnosed with are real."""
        server = self.make_server(config=BGP_CONFIG)
        before = server.bridge.stats()['calls']
        self.fetch(server.url + '/engine/status')
        self.assertGreater(server.bridge.stats()['calls'], before)
        self.assertEqual(0, server.bridge.stats()['timeouts'])


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class TokenFileTestCase(ApiFixture):
    """``load_or_generate_token``: the file the operator never types."""

    def test_a_generated_token_is_private_and_usable(self):
        """Created 0600, in one step, and it authenticates."""
        from packets.routing.rtengine.api.auth import load_or_generate_token

        path = os.path.join(tempfile.mkdtemp(), 'token')
        token, created = load_or_generate_token(path)
        self.addCleanup(os.unlink, path)
        self.assertTrue(created)
        self.assertGreaterEqual(len(token), 32)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(0o600, mode, 'a token file must not be readable '
                                      'by anyone else: %o' % mode)
        again, created_again = load_or_generate_token(path)
        self.assertFalse(created_again)
        self.assertEqual(token, again)

        _engine, client = self.make_client(
            api_config={'auth': {'token-file': path}})
        self.assertEqual(200, client.get(
            '/api/v1/engine/status',
            headers={'Authorization': 'Bearer ' + token}).status_code)


if __name__ == '__main__':
    unittest.main()
