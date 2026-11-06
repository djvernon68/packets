#!/usr/bin/env python

"""Tests for the ``rtengine`` command: what a process promises an operator.

``test_rtengine_api.py`` pins the HTTP surface and ``test_rtengine_engine.py``
pins the library. Neither covers the thing this command adds, which is not
routing at all: it is the handful of promises a *process* makes to whatever
starts it. Those promises, and nothing else, are what is asserted here.

  * **A refusal is a refusal, and it is legible.** ``--check`` exits non-zero
    on a document the engine will not take, and what it prints is the
    configuration path and the reason -- not a traceback. An operator editing
    a file by hand is the whole audience for that exit status, and a stack
    trace tells them about our frames rather than about their file.

  * **A plugin's own section is valid configuration.** A document naming
    ``router bgp`` has to be accepted, and it is accepted only because the
    command constructs the engine before it applies the document: the
    configuration store validates against a schema the plugins graft onto at
    registration, so the same document handed to ``Engine(config=...)`` is
    rejected for an unknown key. That ordering is invisible at the call site
    and a plausible-looking "simplification" away, so it is regression-tested
    by name.

  * **An exposed bind with no credential does not start.** Asserted through
    the command rather than against ``check_bind`` directly, because the
    property that matters is that the refusal survives the whole argument
    path -- a ``--bind`` override that reached the server without passing the
    rule would be a security control with a bypass in it.

  * **``--token-file`` writes a secret to a file and nowhere else.** The mode
    is asserted, and so is the absence of the token from everything the
    command emitted: a token in a journal is a token that leaked.

  * **It starts, serves, and stops when told.** One end-to-end case runs the
    real command in a subprocess, makes one real HTTP request over a real
    socket, sends it SIGTERM and requires a zero exit -- the only test here
    that proves the signal handling, the ordering of the shutdown and the
    exit status at all.

Conventions follow ``test_rtengine_api.py``: plain ``unittest``, no pytest
features, no syntax newer than 3.6.8, port 0 everywhere -- a fixed port fails
whenever the host is already using it, and it fails in CI rather than here --
and every process or file registered for cleanup, since a leaked engine does
not fail one test, it hangs the run. The module skips without Flask, because
the API is an optional extra.
"""

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from io import StringIO

try:
    import flask as _flask
except ImportError:                                  # pragma: no cover
    _flask = None

from packets.commands.rtengine import main

#: The repository root, which is what has to be on a child's PYTHONPATH.
#: Derived from this file rather than from the working directory: the suite
#: is discovered from more than one place and a child that cannot import
#: ``packets`` fails in a way that looks like the command is broken.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: A BGP instance that will never peer -- the neighbour is in a documentation
#: range and nothing listens there. It exists to make the document name a
#: plugin's section; the session is beside the point.
BGP_DOCUMENT = {
    'router': {
        'bgp': {
            '65000': {
                'router-id': '10.0.0.1',
                'neighbor': {
                    '10.0.0.2': {'remote-as': 65001},
                },
            },
        },
    },
}

#: The same document with a router-id that is not an address. Invalid in the
#: plugin's own subtree on purpose: an error from the core schema would pass
#: this test without the plugin schema ever having been grafted on.
BAD_DOCUMENT = {
    'router': {'bgp': {'65000': {'router-id': 'not-an-address'}}},
}

#: What the command logs once the API is up. The port is the point: port 0
#: means the child picks it, so this line is the only way to learn it.
URL_PATTERN = re.compile(r'API base URL (https?://\S+)')


class CommandFixture(unittest.TestCase):
    """Runs the command in-process or as a child, and cleans up after it."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='rtengine-cli-')
        self.addCleanup(shutil.rmtree, self.tmpdir, True)

    def write_document(self, document, name='rtengine.json'):
        """Write a configuration document and return its path.

        :param document: the document.
        :param name: the file name, which decides the parser.
        :return: the path.
        """
        path = os.path.join(self.tmpdir, name)
        with open(path, 'w') as handle:
            handle.write(json.dumps(document))
        return path

    def run_command(self, argv):
        """Run ``main`` in this process and collect everything it said.

        In-process for the cases that never bind or start anything: a
        subprocess for each of those would spend a second importing the
        engine to assert a string.

        The log is captured with a handler of our own rather than by
        letting ``main``'s ``basicConfig`` write to the replaced stderr,
        because ``basicConfig`` does nothing at all when the root logger
        already has a handler -- and under a test runner that configures
        logging it always does. The root's handlers and level are saved and
        restored so that neither this handler nor a level ``main`` did
        manage to set outlives the test.

        :param argv: the arguments, without the program name.
        :return: ``(status, output)``, output being stdout, stderr and the
            log together -- a test asserting a secret did not appear must
            look everywhere it could have appeared.
        """
        out, err = StringIO(), StringIO()
        records = logging.StreamHandler(StringIO())
        root = logging.getLogger()
        saved_handlers, saved_level = list(root.handlers), root.level
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        root.addHandler(records)
        root.setLevel(logging.DEBUG)
        try:
            status = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
            root.handlers, root.level = saved_handlers, saved_level
        return status, ''.join([out.getvalue(), err.getvalue(),
                                records.stream.getvalue()])

    def start_child(self, argv, timeout=20.0):
        """Start the command as a child and wait until its API is up.

        :param argv: the arguments, without the program name.
        :param timeout: seconds to wait for the API base URL.
        :return: ``(process, url, log_path)``.
        """
        env = dict(os.environ)
        existing = env.get('PYTHONPATH')
        env['PYTHONPATH'] = (ROOT if not existing
                             else ROOT + os.pathsep + existing)
        log_path = os.path.join(self.tmpdir, 'child.log')
        log = open(log_path, 'w')
        self.addCleanup(log.close)
        # Output to a file rather than a pipe: the child logs while it runs,
        # and a pipe nobody is draining fills and blocks it exactly when the
        # test is waiting for the line that says it is ready.
        child = subprocess.Popen(
            [sys.executable, '-m', 'packets.commands.rtengine'] + argv,
            stdout=log, stderr=subprocess.STDOUT, env=env, cwd=ROOT)
        self.addCleanup(self.reap, child)

        deadline = time.time() + timeout
        while time.time() < deadline:
            if child.poll() is not None:
                self.fail('the command exited with %d before serving:\n%s'
                          % (child.returncode, self.read(log_path)))
            found = URL_PATTERN.search(self.read(log_path))
            if found:
                return child, found.group(1), log_path
            time.sleep(0.05)
        self.fail('no API base URL within %gs:\n%s'
                  % (timeout, self.read(log_path)))

    @staticmethod
    def read(path):
        """Return a file's current contents, even while it is being written."""
        with open(path, 'r') as handle:
            return handle.read()

    @staticmethod
    def reap(child):
        """Make sure a child cannot outlive the test that started it.

        Registered as a cleanup before the test can fail, because a failure
        between starting the engine and signalling it would otherwise leave a
        routing engine and a listening socket behind for the rest of the run.
        """
        if child.poll() is not None:
            return
        child.kill()
        child.wait()


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class CheckTestCase(CommandFixture):
    """``--check``: what an operator gets for a document, without starting."""

    def test_valid_document_is_accepted(self):
        status, output = self.run_command(
            ['--check', '--config', self.write_document(BGP_DOCUMENT)])
        self.assertEqual(0, status, output)

    def test_plugin_section_is_valid_configuration(self):
        """``router bgp`` is accepted: the construct-then-apply ordering.

        The regression this guards is a one-line "simplification" --
        ``Engine(config=document, plugins=[BGPPlugin()])`` -- which rejects
        this document for an unknown ``router`` key, because the store
        validates in the constructor and the plugin has not grafted its
        schema on yet at that point.
        """
        path = self.write_document(BGP_DOCUMENT)
        status, output = self.run_command(['--check', '--config', path])
        self.assertEqual(0, status,
                         'a document naming a plugin section must be valid, '
                         'and is only valid if the engine is constructed '
                         'before the document is applied:\n%s' % output)

    def test_invalid_document_names_the_path_without_a_traceback(self):
        path = self.write_document(BAD_DOCUMENT)
        status, output = self.run_command(['--check', '--config', path])
        self.assertNotEqual(0, status)
        self.assertIn('router.bgp.65000.router-id', output)
        self.assertNotIn('Traceback', output)

    def test_unreadable_configuration_is_a_usage_error(self):
        missing = os.path.join(self.tmpdir, 'absent.json')
        with self.assertRaises(SystemExit) as caught:
            self.run_command(['--check', '--config', missing])
        self.assertNotEqual(0, caught.exception.code)

    def test_document_that_is_not_a_mapping_is_refused(self):
        path = os.path.join(self.tmpdir, 'list.json')
        with open(path, 'w') as handle:
            handle.write('[1, 2, 3]')
        status, output = self.run_command(['--check', '--config', path])
        self.assertNotEqual(0, status)
        self.assertNotIn('Traceback', output)


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class BindTestCase(CommandFixture):
    """The exposed-bind rule, reached through the command line."""

    def test_exposed_bind_without_auth_is_refused(self):
        status, output = self.run_command(['--check', '--bind', '0.0.0.0:0'])
        self.assertNotEqual(0, status)
        self.assertIn('api.bind', output)
        self.assertIn('0.0.0.0', output)
        self.assertNotIn('Traceback', output)

    def test_exposed_bind_with_a_token_file_is_allowed(self):
        path = os.path.join(self.tmpdir, 'token')
        status, output = self.run_command(
            ['--check', '--bind', '0.0.0.0:0', '--token-file', path])
        self.assertEqual(0, status, output)

    def test_loopback_bind_needs_nothing(self):
        status, output = self.run_command(
            ['--check', '--bind', '127.0.0.1:0'])
        self.assertEqual(0, status, output)


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class TokenFileTestCase(CommandFixture):
    """``--token-file``: a credential goes to the file and nowhere else."""

    def test_missing_token_file_is_created_private(self):
        """A run creates the file it was pointed at, mode 0600.

        A run, not ``--check``: that a check created the file was L-10.
        """
        path = os.path.join(self.tmpdir, 'token')
        child, url, log_path = self.start_child(
            ['--bind', '127.0.0.1:0', '--token-file', path])
        self.assertTrue(os.path.exists(path))

        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(0o600, mode,
                         'a generated token must not be readable by anyone '
                         'else: %o' % mode)

        token = self.read(path).strip()
        self.assertTrue(token)
        # And it is the token the API now demands.
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen
        with self.assertRaises(HTTPError) as caught:
            urlopen(url + '/engine/status', timeout=10)
        self.assertEqual(401, caught.exception.code)
        caught.exception.close()
        response = urlopen(Request(url + '/engine/status', headers={
            'Authorization': 'Bearer ' + token}), timeout=10)
        try:
            self.assertEqual(200, response.getcode())
        finally:
            response.close()

        child.terminate()
        self.assertEqual(0, child.wait(timeout=30), self.read(log_path))
        output = self.read(log_path)
        self.assertNotIn(token, output,
                         'the token was printed; the path is what an '
                         'operator needs and a journal is not a keystore')
        self.assertIn(path, output)

    def test_check_never_creates_a_token_file(self):
        """L-10: ``--check`` judges a missing token file, and writes nothing.

        It used to go through the run's create-if-absent path, so checking
        a document left a fresh secret on disk -- and the check passed
        either way, so it never said anything the run would not.
        """
        path = os.path.join(self.tmpdir, 'token')
        status, output = self.run_command(
            ['--check', '--bind', '0.0.0.0:0', '--token-file', path])
        self.assertEqual(0, status, output)
        self.assertFalse(os.path.exists(path),
                         '--check wrote %s' % (path,))
        self.assertEqual([], os.listdir(self.tmpdir))

    def test_check_refuses_a_token_file_a_run_could_not_create(self):
        """L-10: what the check does instead of creating the file."""
        path = os.path.join(self.tmpdir, 'no-such-dir', 'token')
        status, output = self.run_command(
            ['--check', '--bind', '0.0.0.0:0', '--token-file', path])
        self.assertEqual(2, status, output)
        self.assertIn('api.auth.token-file', output)
        self.assertFalse(os.path.exists(os.path.dirname(path)))

    def test_check_refuses_an_empty_token_file(self):
        """An existing file is judged as a run would judge it."""
        path = os.path.join(self.tmpdir, 'token')
        open(path, 'w').close()
        status, output = self.run_command(
            ['--check', '--bind', '0.0.0.0:0', '--token-file', path])
        self.assertEqual(2, status, output)
        self.assertIn('empty', output)
        self.assertEqual(0, os.path.getsize(path))

    def test_existing_token_file_is_left_alone(self):
        path = os.path.join(self.tmpdir, 'token')
        with open(path, 'w') as handle:
            handle.write('a-token-that-is-long-enough\n')
        status, output = self.run_command(
            ['--check', '--bind', '0.0.0.0:0', '--token-file', path])
        self.assertEqual(0, status, output)
        self.assertEqual('a-token-that-is-long-enough', self.read(path).strip())


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
class LifecycleTestCase(CommandFixture):
    """The process itself: it comes up, it answers, and it stops on SIGTERM."""

    def test_serves_and_exits_zero_on_sigterm(self):
        child, url, log_path = self.start_child(
            ['--config', self.write_document(BGP_DOCUMENT),
             '--bind', '127.0.0.1:0'])

        # A real socket and a real client, not a test client: the thing this
        # case exists to prove is that the process bound something and served
        # from its own thread, and a Flask test client proves neither.
        from urllib.request import urlopen
        response = urlopen(url + '/engine/health', timeout=10)
        try:
            body = response.read().decode('utf-8')
            self.assertEqual(200, response.getcode())
        finally:
            response.close()
        self.assertIsInstance(json.loads(body), dict)

        child.terminate()
        status = child.wait(timeout=30)
        self.assertEqual(0, status,
                         'SIGTERM must be a clean shutdown:\n%s'
                         % self.read(log_path))

    def test_second_signal_does_not_wedge_the_shutdown(self):
        child, _url, log_path = self.start_child(['--bind', '127.0.0.1:0'])
        child.terminate()
        # An operator who does not see it stop instantly signals again, and
        # the handler runs on whatever stack the second signal interrupts.
        # Setting an Event that is already set is what makes that harmless;
        # doing the teardown in the handler would not be.
        child.terminate()
        self.assertEqual(0, child.wait(timeout=30),
                         'a repeated signal must not change the outcome:\n%s'
                         % self.read(log_path))


if __name__ == '__main__':
    unittest.main()
