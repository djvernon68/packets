# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Stage 5 of the 2.3.0 route fixes: secrets, the API's edges, packaging.

One case per review item, named in its docstring:

* E-2  ``config-change`` events carry redacted diffs.
* L-11 ``OPTIONS`` needs the token like every other method.
* A-1  a body without a ``Content-Length`` is read only to the limit.
* A-3  a rewritten token file is picked up, and a bad one never opens the
       API.
* A-5  the command bridge refuses past its in-flight cap with 503 and
       ``Retry-After``.
* A-2  an unclean stop is reported, and the command exits 3.
* L-9  ``openapi.yaml`` is in the sdist and in ``package_data``.
* L-12 one version string, 2.3.0, everywhere it is reported.
* C-5  the classifiers cover the interpreters the suite runs on.

(L-10 and A-4 live beside the tests they changed, in
``test_rtengine_cli.py`` and ``test_rtengine_api.py``.)
"""

import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import shutil
import threading
import time
import unittest
from unittest import mock

import packets
from packets.commands import rtengine as command
from packets.routing import rtengine
from packets.routing.rtengine.config import REDACTED, Diff
from packets.routing.rtengine.engine import Engine
from packets.routing.rtengine.events import CONFIG_CHANGE
from packets.routing.rtengine.plugin import ProtocolPlugin
from packets.routing.rtengine.plugins.bgp.plugin import BGPPlugin

try:
    import flask as _flask
except ImportError:  # pragma: no cover - the API is an optional extra
    _flask = None

if _flask is not None:
    from packets.routing.rtengine.api import auth as auth_mod
    from packets.routing.rtengine.api.app import _read_bounded, create_app
    from packets.routing.rtengine.api.bridge import (BridgeBusy,
                                                     BridgeTimeout,
                                                     CommandBridge)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOKEN = 'a-token-that-is-long-enough'
NEW_TOKEN = 'the-token-after-the-rotation'

NEIGHBOR = ('router', 'bgp', '65000', 'neighbor', '10.0.0.2')


def _values_of(node, key):
    """Every value stored under ``key`` anywhere in a nested dict."""
    found = []
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                found.append(value)
            else:
                found.extend(_values_of(value, key))
    return found


def _wait_for(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


# --- E-2 --------------------------------------------------------------------

class ConfigChangeRedactionTestCase(unittest.TestCase):
    """E-2: the event bus is not a way to read a secret."""

    def setUp(self):
        # A neighbour password is refused at configuration time where the
        # kernel has no TCP-MD5 (macOS); that rule is not under test here,
        # what the event says about the password is.
        patcher = mock.patch(
            'packets.routing.rtengine.transport.auth.resolve_auth',
            lambda cfg: ('md5', cfg.get('password'), None))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.engine = Engine(name='e2', plugins=[BGPPlugin()])
        self.addCleanup(self.engine.stop)
        self.events = []
        self.engine.bus.on(CONFIG_CHANGE,
                           lambda _event, payload: self.events.append(payload))

    def last(self):
        return self.events[-1]['changes']

    def test_setting_and_rotating_the_api_token(self):
        """Both sides of a change *at* a secret are redacted."""
        self.engine.configure(('api', 'auth', 'token'), TOKEN)
        # The first token creates the section, so the change is the
        # subtree above it -- redacted inside.
        self.assertEqual([{'path': 'api',
                           'new': {'auth': {'token': REDACTED}}}],
                         self.last())
        self.engine.configure(('api', 'auth', 'token'), NEW_TOKEN)
        self.assertEqual([{'path': 'api.auth.token', 'old': REDACTED,
                           'new': REDACTED}], self.last())
        text = repr(self.events)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(NEW_TOKEN, text)
        # The store itself still holds the value; only the event is
        # redacted.
        self.assertEqual(NEW_TOKEN, self.engine.store.document(
            redact=False)['api']['auth']['token'])

    def test_a_subtree_holding_a_secret(self):
        """A change *above* a secret has the secret redacted inside it."""
        self.engine.configure(('router', 'bgp', '65000'), {
            'router-id': '10.0.0.1',
            'neighbor': {'10.0.0.2': {'remote-as': 65001,
                                      'description': 'peer-b',
                                      'password': 'md5-secret-one'}}})
        change, = self.last()
        # The whole router section is new, so that is the change.
        self.assertEqual('router', change['path'])
        neighbor = change['new']['bgp']['65000']['neighbor']['10.0.0.2']
        self.assertEqual(REDACTED, neighbor['password'])
        # What is not secret is still worth reading.
        self.assertEqual('peer-b', neighbor['description'])
        self.assertEqual(65001, neighbor['remote-as'])

        self.engine.configure(NEIGHBOR + ('password',), 'md5-secret-two')
        self.assertEqual([{'path': 'router.bgp.65000.neighbor.10.0.0.2.'
                                   'password',
                           'old': REDACTED, 'new': REDACTED}], self.last())

        self.engine.unconfigure(NEIGHBOR)
        change, = self.last()
        self.assertNotIn('new', change, 'a removal stays a removal')
        # The last neighbour takes the emptied ``neighbor`` dict with it,
        # so how deep the password sits depends on the pruning; look for
        # it rather than assume.
        self.assertEqual([REDACTED], _values_of(change['old'], 'password'))

        text = repr(self.events)
        self.assertNotIn('md5-secret-one', text)
        self.assertNotIn('md5-secret-two', text)

    def test_a_change_beside_a_secret_is_untouched(self):
        self.engine.configure(('router', 'bgp', '65000'), {
            'router-id': '10.0.0.1',
            'neighbor': {'10.0.0.2': {'remote-as': 65001,
                                      'password': 'md5-secret-one'}}})
        self.engine.configure(NEIGHBOR + ('description',), 'peer-b')
        self.assertEqual([{'path': 'router.bgp.65000.neighbor.10.0.0.2.'
                                   'description', 'new': 'peer-b'}],
                         self.last())

    def test_redacted_changes_on_its_own(self):
        store = self.engine.store
        diff = Diff([(('api', 'auth', 'token'), TOKEN, NEW_TOKEN),
                     (('api', 'bind'), '127.0.0.1:8179', '127.0.0.1:9000')])
        self.assertEqual(
            [{'path': 'api.auth.token', 'old': REDACTED, 'new': REDACTED},
             {'path': 'api.bind', 'old': '127.0.0.1:8179',
              'new': '127.0.0.1:9000'}],
            store.redacted_changes(diff))
        # The diff it was given is not altered.
        self.assertEqual(TOKEN, list(diff)[0][1])


# --- the API ----------------------------------------------------------------

@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class ApiFixture(unittest.TestCase):

    def make_engine(self):
        engine = Engine(name='api-hardening', plugins=[BGPPlugin()])
        self.addCleanup(engine.stop)
        engine.start()
        return engine

    def make_client(self, api_config=None, engine=None, bridge=None):
        engine = engine or self.make_engine()
        app = create_app(engine, bridge=bridge, api_config=api_config or {})
        app.config['PROPAGATE_EXCEPTIONS'] = False
        return engine, app.test_client()

    @staticmethod
    def bearer(token):
        return {'Authorization': 'Bearer ' + token}


class OptionsAuthTestCase(ApiFixture):
    """L-11: no method is exempt from authentication."""

    def test_options_needs_the_token(self):
        _engine, client = self.make_client({'auth': {'token': TOKEN}})
        for path in ('/api/v1/engine/status', '/api/v1/router/bgp/65000',
                     '/api/v1/show/ip/route', '/api/v1/clear/ip/bgp'):
            response = client.open(path, method='OPTIONS')
            self.assertEqual(401, response.status_code, path)
            self.assertIn('WWW-Authenticate', response.headers)
            response = client.open(path, method='OPTIONS',
                                   headers=self.bearer(TOKEN))
            self.assertEqual(200, response.status_code, path)
            self.assertTrue(response.headers.get('Allow'), path)

    def test_the_health_exemption_is_for_reading_it(self):
        _engine, client = self.make_client({'auth': {
            'token': TOKEN, 'allow-unauthenticated-health': True}})
        self.assertEqual(200, client.get('/api/v1/engine/health')
                         .status_code)
        self.assertEqual(401, client.open('/api/v1/engine/health',
                                          method='OPTIONS').status_code)
        self.assertEqual(401, client.get('/api/v1/engine/status')
                         .status_code)

    def test_an_open_api_still_answers_options(self):
        _engine, client = self.make_client()
        self.assertEqual(200, client.open('/api/v1/engine/status',
                                          method='OPTIONS').status_code)


class UnsizedBodyTestCase(ApiFixture):
    """A-1: a body with no Content-Length is not buffered past the limit."""

    URL = '/api/v1/router/bgp/65000'

    def make_client(self, api_config=None, engine=None, bridge=None):
        engine, client = super(UnsizedBodyTestCase, self).make_client(
            api_config, engine, bridge)
        app = client.application
        inner = app.wsgi_app

        def chunked(environ, start_response):
            # What a server hands the application for a chunked request:
            # no CONTENT_LENGTH at all -- not an empty one, which a recent
            # Werkzeug reads as 0 -- and the input marked as terminated,
            # the server having de-chunked it.
            environ.pop('CONTENT_LENGTH', None)
            environ['HTTP_TRANSFER_ENCODING'] = 'chunked'
            environ['wsgi.input_terminated'] = True
            return inner(environ, start_response)

        app.wsgi_app = chunked
        return engine, client

    def put_unsized(self, client, body):
        return client.put(self.URL, data=body)

    def test_over_the_limit_is_413(self):
        _engine, client = self.make_client({'max-body-bytes': 1024})
        body = b'{"router-id": "10.0.0.1", "x": "' + b'y' * 8192 + b'"}'
        with mock.patch('packets.routing.rtengine.api.app._read_bounded',
                        wraps=_read_bounded) as reader:
            response = self.put_unsized(client, body)
        self.assertEqual(413, response.status_code, response.data)
        self.assertEqual('PayloadTooLarge',
                         _flask.json.loads(response.data)['error'])
        reader.assert_called_once()
        self.assertEqual(1024, reader.call_args[0][1])

    def test_under_the_limit_is_read(self):
        engine, client = self.make_client({'max-body-bytes': 1024})
        response = self.put_unsized(client, b'{"router-id": "10.0.0.1"}')
        self.assertIn(response.status_code, (200, 201), response.data)
        self.assertEqual('10.0.0.1', engine.store.value(
            ('router', 'bgp', '65000', 'router-id')))

    def test_read_bounded_stops_one_byte_past_the_limit(self):
        class Endless(object):
            served = 0

            def read(self, n):
                self.served += n
                return b'x' * n

        stream = Endless()
        data = _read_bounded(stream, 1000, chunk=64)
        self.assertEqual(1001, len(data))
        self.assertEqual(1001, stream.served)
        self.assertEqual(b'abc', _read_bounded(io.BytesIO(b'abc'), 1000))


class TokenFileReloadTestCase(ApiFixture):
    """A-3: rotating a token file needs no restart, and fails closed."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='rtengine-a3-')
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        self.path = os.path.join(self.tmpdir, 'token')
        self.write(TOKEN)

    def write(self, text):
        # Write-and-rename, as a rotation should be done: a reader never
        # sees a half-written file, and the inode changes even when the
        # size and the mtime tick do not.
        tmp = self.path + '.new'
        with open(tmp, 'w') as handle:
            handle.write(text)
        os.rename(tmp, self.path)

    def policy(self):
        now = [1000.0]
        policy = auth_mod.TokenAuth.from_config(
            {'auth': {'token-file': self.path}})
        policy._clock = lambda: now[0]
        policy._checked = now[0]
        return policy, now

    def test_a_rewritten_file_is_picked_up_after_the_recheck(self):
        policy, now = self.policy()
        self.write(NEW_TOKEN + '\n')
        self.assertFalse(policy.refresh(), 'checked again within a second')
        self.assertEqual(TOKEN, policy.token)
        now[0] += auth_mod.TOKEN_RECHECK_S
        self.assertTrue(policy.refresh())
        self.assertEqual(NEW_TOKEN, policy.token)
        self.assertEqual(1, policy.describe()['reloads'])
        now[0] += auth_mod.TOKEN_RECHECK_S
        self.assertFalse(policy.refresh(), 'unchanged is not a reload')

    def test_an_empty_or_missing_file_keeps_the_token(self):
        policy, now = self.policy()
        self.write('')
        now[0] += auth_mod.TOKEN_RECHECK_S
        self.assertFalse(policy.refresh())
        self.assertEqual(TOKEN, policy.token)
        os.unlink(self.path)
        now[0] += auth_mod.TOKEN_RECHECK_S
        self.assertFalse(policy.refresh())
        self.assertTrue(policy.enabled)
        self.assertEqual(TOKEN, policy.token)
        self.write(NEW_TOKEN)
        now[0] += auth_mod.TOKEN_RECHECK_S
        self.assertTrue(policy.refresh(), 'a good file after a bad one')
        self.assertEqual(NEW_TOKEN, policy.token)

    def test_an_inline_token_is_never_rechecked(self):
        policy = auth_mod.TokenAuth.from_config({'auth': {'token': TOKEN}})
        self.assertFalse(policy.refresh(force=True))

    def test_through_the_api(self):
        with mock.patch.object(auth_mod, 'TOKEN_RECHECK_S', 0.0):
            _engine, client = self.make_client(
                {'auth': {'token-file': self.path}})
            url = '/api/v1/engine/status'
            self.assertEqual(200, client.get(
                url, headers=self.bearer(TOKEN)).status_code)
            self.write(NEW_TOKEN)
            self.assertEqual(401, client.get(
                url, headers=self.bearer(TOKEN)).status_code)
            response = client.get(url, headers=self.bearer(NEW_TOKEN))
            self.assertEqual(200, response.status_code)
            status = _flask.json.loads(response.data)
            self.assertEqual(1, status['api']['auth']['reloads'])
            self.assertNotIn(NEW_TOKEN, response.data.decode('utf-8'))


class BridgeCapTestCase(ApiFixture):
    """A-5: the bridge will not pile unbounded work onto the loop."""

    def occupy(self, bridge, count, gate):
        results = []

        def block():
            gate.wait(10)
            return 'done'

        threads = [threading.Thread(target=lambda: results.append(
            bridge.call(block))) for _ in range(count)]
        for thread in threads:
            thread.start()
        self.assertTrue(_wait_for(lambda: bridge.in_flight == count))
        return threads, results

    def test_calls_past_the_cap_are_refused_until_one_finishes(self):
        engine = self.make_engine()
        bridge = CommandBridge(engine, timeout=10, max_in_flight=2)
        gate = threading.Event()
        threads, results = self.occupy(bridge, 2, gate)
        with self.assertRaises(BridgeBusy) as caught:
            bridge.call(lambda: 1)
        self.assertEqual('Unavailable', caught.exception.error)
        self.assertEqual(1, caught.exception.retry_after)
        gate.set()
        for thread in threads:
            thread.join(10)
        self.assertEqual(['done', 'done'], results)
        self.assertTrue(_wait_for(lambda: bridge.in_flight == 0))
        self.assertEqual(2, bridge.call(lambda: 2))
        stats = bridge.stats()
        self.assertEqual(1, stats['refused'])
        self.assertEqual(2, stats['max_in_flight'])

    def test_a_timed_out_command_holds_its_place_until_it_ends(self):
        engine = self.make_engine()
        bridge = CommandBridge(engine, timeout=10, max_in_flight=4)
        gate = threading.Event()
        running = threading.Event()

        def block():
            running.set()
            gate.wait(10)

        caller = threading.Thread(target=lambda: self.assertRaises(
            BridgeTimeout, bridge.call_timeout, 0.05, block))
        caller.start()
        caller.join(10)
        self.assertTrue(running.is_set())
        self.assertEqual(1, bridge.in_flight,
                         'the loop is still running it')
        gate.set()
        self.assertTrue(_wait_for(lambda: bridge.in_flight == 0))

    def test_the_api_answers_503_with_retry_after(self):
        engine = self.make_engine()
        bridge = CommandBridge(engine, timeout=10, max_in_flight=1)
        _engine, client = self.make_client(engine=engine, bridge=bridge)
        gate = threading.Event()
        threads, _results = self.occupy(bridge, 1, gate)
        try:
            response = client.get('/api/v1/engine/status')
            self.assertEqual(503, response.status_code)
            self.assertEqual('1', response.headers.get('Retry-After'))
            self.assertEqual('Unavailable',
                             _flask.json.loads(response.data)['error'])
        finally:
            gate.set()
            for thread in threads:
                thread.join(10)
        self.assertEqual(200, client.get('/api/v1/engine/status')
                         .status_code)

    def test_a_stopped_engine_is_503_without_retry_after(self):
        engine = self.make_engine()
        _engine, client = self.make_client(engine=engine)
        engine.stop()
        response = client.get('/api/v1/engine/status')
        self.assertEqual(503, response.status_code)
        self.assertNotIn('Retry-After', response.headers)


# --- A-2 --------------------------------------------------------------------

class _StopRaises(ProtocolPlugin):
    name = 'stopraises'
    config_section = ('stopraises',)

    def stop(self):
        raise RuntimeError('will not stop')


class _Server(object):
    """Enough of an ApiServer for ``shutdown``."""

    def __init__(self, problems=()):
        self.stop_problems = list(problems)
        self.stopped = False

    def stop(self, timeout=5.0):
        self.stopped = True
        return True


class UncleanStopTestCase(unittest.TestCase):
    """A-2: a stop that left something behind is not exit status 0."""

    def engine(self, plugins):
        engine = Engine(name='a2', plugins=plugins)
        self.addCleanup(engine.stop)
        return engine

    def test_a_clean_stop_has_no_problems(self):
        engine = self.engine([])
        engine.start()
        self.assertTrue(engine.stop())
        self.assertEqual([], engine.stop_problems)

    def test_a_plugin_that_raises_is_a_problem(self):
        engine = self.engine([_StopRaises()])
        engine.start()
        self.assertTrue(engine.stop())
        self.assertEqual(1, len(engine.stop_problems))
        self.assertIn('stopraises', engine.stop_problems[0])
        self.assertIn('will not stop', engine.stop_problems[0])
        self.assertFalse(engine.is_running())

    def test_shutdown_collects_both_halves(self):
        engine = self.engine([_StopRaises()])
        engine.start()
        server = _Server(['the API thread did not exit within 5s'])
        problems = command.shutdown(engine, server)
        self.assertTrue(server.stopped)
        self.assertEqual(['api: the API thread did not exit within 5s'],
                         problems[:1])
        self.assertTrue(problems[1].startswith('engine: plugin stopraises'))

    def run_command(self, engine):
        def immediately(stopping):
            stopping.set()
            return []
        err = io.StringIO()
        with mock.patch.object(command, 'install_handlers', immediately), \
                mock.patch.object(sys, 'stderr', err):
            status = command.run(engine, None)
        return status, err.getvalue()

    def test_the_command_exits_3_on_an_unclean_stop(self):
        status, err = self.run_command(self.engine([_StopRaises()]))
        self.assertEqual(command.EXIT_UNCLEAN, status)
        self.assertEqual(3, status)
        self.assertIn('shutdown: engine: plugin stopraises', err)

    def test_the_command_exits_0_on_a_clean_one(self):
        status, err = self.run_command(self.engine([]))
        self.assertEqual(command.EXIT_OK, status)
        self.assertEqual('', err)


# --- L-12, L-9, C-5 ---------------------------------------------------------

def _source_version():
    with open(os.path.join(ROOT, 'packets', '_version.py')) as handle:
        return re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]",
                         handle.read(), re.M).group(1)


def _pyproject():
    import tomllib
    with open(os.path.join(ROOT, 'pyproject.toml'), 'rb') as handle:
        return tomllib.load(handle)


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, 'setup.py')),
                     'needs a source checkout')
class VersionTestCase(unittest.TestCase):
    """L-12: one version, written once."""

    def test_it_is_2_4_0(self):
        self.assertEqual('2.4.0', _source_version())

    def test_every_reader_agrees(self):
        self.assertEqual(_source_version(), packets.__version__)
        self.assertEqual(packets.__version__, rtengine.__version__)
        engine = Engine(name='l12')
        self.addCleanup(engine.stop)
        self.assertEqual(packets.__version__, engine.status()['version'])

    def test_pyproject_reads_it_rather_than_repeating_it(self):
        project = _pyproject()
        self.assertIn('version', project['project']['dynamic'])
        self.assertNotIn('version', project['project'])
        self.assertEqual({'attr': 'packets._version.__version__'},
                         project['tool']['setuptools']['dynamic']['version'])
        with open(os.path.join(ROOT, 'packets', 'routing', 'rtengine',
                               '__init__.py')) as handle:
            self.assertIsNone(re.search(r"^__version__\s*=", handle.read(),
                                        re.M),
                              'rtengine must import the version, not set '
                              'its own')


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, 'setup.py')),
                     'needs a source checkout')
class PackagingTestCase(unittest.TestCase):
    """L-9 and C-5."""

    SPEC = 'packets/routing/rtengine/api/openapi.yaml'

    def test_the_spec_is_declared_both_ways(self):
        self.assertEqual(
            ['openapi.yaml'],
            _pyproject()['tool']['setuptools']['package-data'][
                'packets.routing.rtengine.api'])
        with open(os.path.join(ROOT, 'MANIFEST.in')) as handle:
            self.assertIn('include ' + self.SPEC, handle.read().split('\n'))

    def test_the_floor_is_the_platform_python(self):
        """2.4 is the AlmaLinux 10.2 line: Python 3.12 and Cython 3.0.9."""
        project = _pyproject()
        self.assertEqual('>=3.12', project['project']['requires-python'])
        self.assertIn('Programming Language :: Python :: 3.12',
                      project['project']['classifiers'])
        self.assertIn('Cython>=3.0.9', project['build-system']['requires'])

    def test_nlri_path_id_is_as_documented(self):
        """C-5: docs/wireshark_field_audit.rst says this field reads None.

        If the dissector ever fills it in, that note -- and the golden
        records -- have to change with it.
        """
        import struct
        from packets.core.inetpkt import BGP
        nlri = struct.pack('!I', 7) + bytes([8, 10])
        body = struct.pack('!HH', 0, 0) + nlri
        raw = b'\xff' * 16 + struct.pack('!HB', 19 + len(body), 2) + body
        msg = BGP(raw, add_path=1)
        self.assertEqual('10.0.0.0', msg.get_field_val('bgp.nlri_prefix'))
        self.assertIsNone(msg.get_field_val('bgp.nlri_path_id'))
        with open(os.path.join(ROOT, 'docs',
                               'wireshark_field_audit.rst')) as handle:
            self.assertIn('``bgp.nlri_path_id`` is declared', handle.read())

    def test_the_sdist_contains_the_spec(self):
        """Built for real: the manifest rules are easy to get subtly wrong.

        ``egg_info --egg-base`` keeps the build's metadata out of the
        checkout, and the archive goes to a scratch directory.
        """
        tmp = tempfile.mkdtemp(prefix='rtengine-sdist-')
        self.addCleanup(shutil.rmtree, tmp, True)
        proc = subprocess.run(
            [sys.executable, 'setup.py', '-q', 'egg_info', '--egg-base', tmp,
             'sdist', '--formats=gztar', '-d', tmp],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=300)
        output = proc.stdout.decode('utf-8', 'replace')
        self.assertEqual(0, proc.returncode, output[-3000:])
        archives = [n for n in os.listdir(tmp) if n.endswith('.tar.gz')]
        self.assertEqual(['packets-%s.tar.gz' % _source_version()], archives)
        with tarfile.open(os.path.join(tmp, archives[0])) as tar:
            names = set(name.split('/', 1)[1] for name in tar.getnames()
                        if '/' in name)
        self.assertIn(self.SPEC, names)
        self.assertIn('packets/_version.py', names)
        self.assertIn('packets/routing/rtengine/api/app.py', names)


if __name__ == '__main__':
    unittest.main()
