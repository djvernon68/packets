#!/usr/bin/env python
# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
rtengine
========
Run a routing engine, and its REST API, as a supervised process.

The engine is a library first: an application embeds it, holds the object
and decides when to stop it. This command is what is left when there is no
such application -- something an init system can start and signal -- so
almost all of it is lifecycle, and the routing is
:class:`~packets.routing.rtengine.engine.Engine` and
:class:`~packets.routing.rtengine.api.server.ApiServer` untouched.

Two orderings are the substance of the file, and both read as arbitrary
until they are the wrong way round. The engine is constructed before its
configuration document is applied, because a plugin grafts its schema in
at registration; the API is stopped before the engine, because a request
that outlives the engine's loop is answered ``Unavailable``. Neither is
visible at the call site, so both are commented where they happen.

Flask is imported only when an API is actually wanted. The engine must be
able to peer and route on a host that has never heard of Flask -- that is
what makes it embeddable -- so ``--no-api`` has to be a path that does not
touch the optional dependency, and a missing one has to be reported as the
extra it is rather than as an ImportError traceback.
"""

import argparse
import importlib
import json
import logging
import os
import signal
import sys
import threading

from packets.routing.rtengine.engine import Engine
from packets.routing.rtengine.errors import ConfigError, RtEngineError
from packets.routing.rtengine.plugins.bgp.plugin import BGPPlugin

_log = logging.getLogger('packets.rtengine.command')

#: A clean shutdown.
EXIT_OK = 0

#: A configuration the engine will not accept, or a bind it refuses. The
#: same status argparse uses for a usage error, because that is what this
#: is: the operator asked for something impossible and nothing started.
EXIT_CONFIG = 2

#: A shutdown that left something behind -- a plugin that raised while
#: stopping, a thread that would not exit (A-2). A supervisor restarting on
#: failure should see this as one, not as the clean stop 0 reported.
EXIT_UNCLEAN = 3

#: YAML is offered but never required, so a name is what decides which
#: parser has to succeed. Anything else is sniffed; see load_document.
YAML_SUFFIXES = ('.yaml', '.yml')


def readable_file(value):
    """argparse type that accepts the path of a readable file."""
    # The same helper netflow_player.py defines, repeated rather than
    # imported: importing that module would pull in the compiled pcap
    # extension, which this command has no use for and which need not be
    # built on a host that only runs the routing engine.
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError("{0} is not a file".format(value))
    if not os.access(value, os.R_OK):
        raise argparse.ArgumentTypeError("{0} is not readable".format(value))
    return value


def log_level(value):
    """argparse type that accepts a logging level by name or by number."""
    named = getattr(logging, str(value).upper(), None)
    if isinstance(named, int):
        return named
    try:
        return int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("{0} is not a logging level"
                                         "".format(value))


def api_module(name=''):
    """Import the optional API package, or one of its submodules.

    Imported on demand, not at module scope, because importing any part
    of that package imports Flask and ``--no-api`` exists precisely for
    the host where that would fail. The package's own ImportError already
    names the extra and the remedy, so it is turned into a ConfigError
    and reported as a message: an optional dependency nobody installed is
    something to install, not a crash to read a traceback of.

    :param name: a submodule of the API package, or '' for the package.
    :return: the imported module.
    :raises ConfigError: Flask is not installed.
    """
    full = 'packets.routing.rtengine.api'
    if name:
        full = '%s.%s' % (full, name)
    try:
        return importlib.import_module(full)
    except ImportError as exc:
        raise ConfigError(str(exc), path='api')


def parse_json(text, path):
    """Parse a configuration document as JSON.

    :param text: the file's contents.
    :param path: the file, for the error message.
    :return: the parsed document.
    :raises ConfigError: it is not JSON.
    """
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ConfigError('%s is not valid JSON: %s' % (path, exc),
                          path=path)


def parse_yaml(text, path):
    """Parse a configuration document as YAML.

    :param text: the file's contents.
    :param path: the file, for the error message.
    :return: the parsed document.
    :raises ConfigError: PyYAML is unavailable, or it is not YAML.
    """
    try:
        import yaml
    except ImportError:
        raise ConfigError('PyYAML is not installed, so %s cannot be read '
                          'as YAML; JSON is always understood' % (path,),
                          path=path)
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError('%s is not valid YAML: %s' % (path, exc),
                          path=path)


def load_document(path):
    """Read a configuration document from a file.

    JSON is always understood. YAML is understood when PyYAML can be
    imported, and which parser must succeed is decided by the name: a
    ``.yaml`` or ``.yml`` file is YAML and a missing PyYAML is then an
    error, while any other name is read as JSON and only falls back to
    YAML if it is not JSON at all. The fallback is there because an
    operator's ``rtengine.conf`` is usually YAML, and it is one-way
    because every JSON document is also YAML: sniffing in the other
    direction would report a misplaced comma in a ``.json`` file as a
    YAML complaint about a line the operator did not write.

    :param path: the file.
    :return: the document, as plain dicts and lists.
    :raises ConfigError: it cannot be read, does not parse, or is not a
        mapping.
    """
    try:
        with open(path, 'r') as handle:
            text = handle.read()
    except (IOError, OSError) as exc:
        raise ConfigError('cannot read %s: %s' % (path, exc), path=path)

    lowered = str(path).lower()
    if lowered.endswith(YAML_SUFFIXES):
        document = parse_yaml(text, path)
    elif lowered.endswith('.json'):
        document = parse_json(text, path)
    else:
        try:
            document = parse_json(text, path)
        except ConfigError:
            document = parse_yaml(text, path)

    if document is None:
        raise ConfigError('%s holds no configuration' % (path,), path=path)
    if not isinstance(document, dict):
        raise ConfigError('%s must hold a mapping of configuration '
                          'sections, not %s'
                          % (path, type(document).__name__), path=path)
    return document


def apply_overrides(document, args):
    """Fold the command line's API overrides into the document.

    They go into the document rather than into the ApiServer's own
    ``bind`` and auth arguments so that one thing decides what is served:
    the engine applies the exposed-bind rule to every document it
    commits, and an override that reached only the server would be an
    override that skipped that rule.

    :param document: the document, modified in place.
    :param args: the parsed arguments.
    :return: the document.
    :raises ConfigError: the token file can be neither read nor created.
    """
    if args.bind is None and args.token_file is None:
        return document
    api = document.setdefault('api', {})
    if args.bind is not None:
        api['bind'] = args.bind
    if args.token_file is not None:
        auth = api.setdefault('auth', {})
        auth['token-file'] = args.token_file
        if getattr(args, 'check', False):
            check_token_file(args.token_file, auth)
            return document
        # Generated before the engine sees the document, because the
        # document only has to name a file for the bind rule to consider
        # the API authenticated, while TokenAuth refuses to start on a
        # file that is not there. Creating it here makes --token-file a
        # request for authentication rather than a promise the operator
        # still has to keep, and the token is never logged: the file has
        # permissions, a terminal and a journal do not.
        created = api_module('auth').load_or_generate_token(
            args.token_file)[1]
        if created:
            _log.info('wrote a new API token to %s', args.token_file)
    return document


def check_token_file(path, auth):
    """``--check``'s reading of ``--token-file``: judge it, write nothing.

    L-10: the check used to go through the same create-if-absent path as
    a run, so validating a document left a fresh token file behind -- a
    secret nobody asked for, and a check that changed what the next run
    would do. Now an existing file must be readable and non-empty, as a
    run requires; an absent one must be creatable, which is all a run
    would need of it. In the second case an in-memory token stands in for
    the file the run would write, so the rest of the check -- the bind
    rule, building the server -- sees the authenticated API the run will
    have, and never tries to read a file that is not there.

    :param path: the ``--token-file`` path.
    :param auth: the document's ``api.auth`` section, adjusted in place.
    :raises ConfigError: the file exists and cannot be used, or it is
        absent and could not be created.
    """
    auth_mod = api_module('auth')
    if os.path.exists(path):
        auth_mod.TokenAuth.from_config({'auth': {'token-file': path}})
        return
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent) or not os.access(parent,
                                                  os.W_OK | os.X_OK):
        raise ConfigError('cannot create the API token file %s: %s is not '
                          'a writable directory' % (path, parent),
                          path='api.auth.token-file')
    del auth['token-file']
    auth['token'] = auth_mod.generate_token()
    _log.info('%s does not exist; a run would create it', path)


def build_engine(document):
    """Construct the engine and apply a configuration document to it.

    Two steps, and they cannot be one. ``Engine(config=document)``
    validates the document in the constructor, and the plugins passed to
    that same constructor have not registered yet when it does -- while
    registration is what grafts a plugin's schema into the document's
    schema. A document naming ``router bgp`` handed straight to the
    constructor is therefore rejected for an unknown key, the key being
    unknown only because the plugin that defines it is not there yet.
    Constructing first and replacing the configuration second validates
    it against the schema the plugins have contributed.

    :param document: the configuration document.
    :return: the engine, configured but not started.
    :raises RtEngineError: the document is invalid, conflicts with a
        stated limit, or a plugin refused it.
    """
    engine = Engine(plugins=[BGPPlugin()])
    engine.replace_config(document)
    return engine


def build_server(engine, args):
    """Build the API server for an engine, without binding anything.

    Separate from starting it so that everything a configuration can get
    wrong -- half a TLS pair, an unreadable token file, a bind this host
    must not serve -- is refused before the engine is started, and so
    that ``--check`` gets those refusals from the same code that a real
    run gets them from.

    :param engine: the configured engine.
    :param args: the parsed arguments.
    :return: an unstarted ApiServer, or None when ``--no-api``.
    :raises ConfigError: Flask is absent, or the API cannot be served.
    """
    if args.no_api:
        return None
    return api_module().ApiServer(engine, swagger_ui=args.swagger_ui)


def install_handlers(stopping):
    """Have SIGTERM and SIGINT ask for a clean shutdown.

    The handler sets an Event and does nothing else. The teardown it asks
    for stops threads and joins them, and a handler runs on whichever
    stack the signal interrupted, so doing that work here would join
    threads from inside an arbitrary frame of the main thread -- and
    would do it again, re-entrantly, if the operator's patience ran out
    and they signalled twice. Setting an Event that is already set is
    what makes the second signal harmless.

    :param stopping: the Event to set.
    :return: a list the handler appends the signal number to, so the
        reason for the shutdown can be logged once the main thread is
        back on its own stack rather than from inside the handler.
    """
    received = []

    def handle(signum, _frame):
        received.append(signum)
        stopping.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, handle)
        except ValueError:
            # Only the main thread may install handlers. A command
            # running on some other thread is a test harness or an
            # embedding application, and both of those already hold
            # something they can stop; refusing to run would serve
            # neither of them.
            _log.warning('not the main thread: signal %d will not stop '
                         'this engine', sig)
    return received


def shutdown(engine, server, timeout=5.0):
    """Stop the API, then the engine. Safe to call more than once.

    That order, and not the other one. The server stops accepting and
    joins its request threads first, so no request is left in flight to
    reach an engine whose loop has gone. Such a request is answered
    ``Unavailable``, which is both correct and a confusing thing to serve
    to a client during a shutdown it knows nothing about: the operator
    asked for a clean stop, and a 503 in the log of whatever was polling
    reads as a fault.

    :param engine: the engine.
    :param server: the API server, or None.
    :param timeout: seconds allowed for each stage.
    :return: what went wrong, as a list of messages; empty when the stop
        was clean (A-2).
    """
    problems = []
    for name, part in (('api', server), ('engine', engine)):
        if part is None:
            continue
        try:
            part.stop(timeout=timeout)
        except Exception as exc:
            # Still stop the other part: an API that failed to stop is no
            # reason to leave the sessions up.
            _log.exception('error stopping the %s', name)
            problems.append('%s: %s: %s' % (name, type(exc).__name__, exc))
            continue
        problems.extend('%s: %s' % (name, problem)
                        for problem in getattr(part, 'stop_problems', ()))
    return problems


def report(exc):
    """Print an engine error the way an operator needs to read it.

    Written to stderr rather than logged, for two reasons: a bad
    configuration file is the operator's mistake and not a fault to be
    correlated with a timestamp, and a message this important must not
    depend on ``--log-level``. No traceback, for the same reason -- the
    stack of a rejected document says nothing an operator can act on,
    while the detail and the path say exactly where to look.

    :param exc: an :class:`RtEngineError`.
    """
    sys.stderr.write('%s: %s\n' % (exc.path or 'configuration', exc.detail))


def run(engine, server):
    """Start everything, wait for a signal, and stop in the right order.

    :param engine: the configured engine.
    :param server: the API server, or None.
    :return: the process exit status.
    """
    stopping = threading.Event()
    received = install_handlers(stopping)
    # start() and not run_forever(), although the engine offers the
    # latter for exactly this case: run_forever puts the loop on the main
    # thread, which is also the only thread a signal handler can run on,
    # so a handler would be stopping the plugins on top of whichever loop
    # callback the signal interrupted. With the loop on its own thread
    # the handler has nothing to do but set an Event.
    engine.start()
    if server is not None:
        try:
            server.start()
        except OSError as exc:
            # The socket is bound inside start(), so this is 'that
            # address is in use' and nothing else: a bind that failed is
            # not a running engine with a degraded API, it is a process
            # the operator did not ask for.
            engine.stop()
            sys.stderr.write('api.bind: cannot listen on %s:%d: %s\n'
                             % (server.host, server.requested_port, exc))
            return EXIT_CONFIG
        _log.info('API base URL %s', server.url)
    _log.info('%s running at configuration revision %d', engine.name,
              engine.revision)

    stopping.wait()
    if received:
        _log.info('signal %d received, shutting down', received[0])
    problems = shutdown(engine, server)
    if problems:
        for problem in problems:
            sys.stderr.write('shutdown: %s\n' % (problem,))
        return EXIT_UNCLEAN
    return EXIT_OK


def parse_args(argv):
    """Parse the command line.

    :param argv: the arguments, without the program name.
    :return: the populated namespace.
    """
    parser = argparse.ArgumentParser(
        description='Run a routing engine and its REST API.')
    parser.add_argument('-c', '--config',
                        metavar='FILE',
                        type=readable_file,
                        help=("Configuration document to load. JSON is "
                              "always understood; YAML needs PyYAML, and "
                              "is required for a .yaml or .yml name and "
                              "tried for any other name whose contents "
                              "are not JSON. Without this the engine "
                              "starts on the schema's defaults."))
    parser.add_argument('--bind',
                        metavar='HOST:PORT',
                        help=("Override api.bind. Port 0 takes a free "
                              "one, which the reported API base URL then "
                              "names. A bind beyond this host needs "
                              "api.auth or api.insecure."))
    parser.add_argument('--token-file',
                        metavar='PATH',
                        help=("Override api.auth.token-file, creating the "
                              "file with a strong random token if it does "
                              "not exist (except under --check, which only "
                              "confirms it could). The path is reported; "
                              "the token is not."))
    parser.add_argument('--no-api',
                        action='store_true',
                        help=("Run the engine with no REST API at all, "
                              "and without importing Flask."))
    parser.add_argument('--check',
                        action='store_true',
                        help=("Validate the configuration and exit "
                              "without starting the engine or binding "
                              "anything."))
    parser.add_argument('--log-level',
                        metavar='LEVEL',
                        type=log_level,
                        default=logging.INFO,
                        help=("debug, info, warning, error or critical. "
                              "The default, info, is the level that "
                              "reports the API base URL."))
    parser.add_argument('--swagger-ui',
                        metavar='DIR',
                        help=("Directory holding a Swagger UI build to "
                              "serve at /api/v1/docs. Off unless asked "
                              "for: it is third-party JavaScript."))
    args = parser.parse_args(argv)
    if args.no_api and args.swagger_ui:
        parser.error('--swagger-ui has nothing to serve with --no-api')
    return args


def main(argv=None):
    """Run the engine until a signal stops it.

    :param argv: the arguments, without the program name. Defaults to
        this process's own.
    :return: the process exit status; 0 for a clean shutdown, 2 for a
        configuration the engine or the API refused, 3 for a shutdown
        that did not complete cleanly.
    """
    args = parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=args.log_level,
                        format='%(asctime)s %(levelname)s %(name)s '
                               '%(message)s')
    try:
        document = load_document(args.config) if args.config else {}
        apply_overrides(document, args)
        engine = build_engine(document)
        server = build_server(engine, args)
    except RtEngineError as exc:
        # Every deliberate refusal in the engine and the API is one of
        # these and carries a detail and a path, so one handler reports
        # them all. Anything else really is a defect and is left to
        # propagate with its traceback intact.
        report(exc)
        return EXIT_CONFIG

    if args.check:
        _log.info('the configuration is valid; nothing was started')
        return EXIT_OK
    return run(engine, server)


if __name__ == "__main__":
    sys.exit(main())
