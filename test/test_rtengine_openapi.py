#!/usr/bin/env python

"""Tests that the OpenAPI document and the application are the same API.

``openapi.yaml`` is written by hand and served to clients, which is two
reasons for it to drift and no mechanism to stop it. Nothing in the
application reads the document, so an endpoint added without a paragraph
here works perfectly and is invisible; a paragraph left behind after a
route is removed documents something that answers 404. Both failures are
found by the reader, in production, at the worst possible moment. This
module is the mechanism: it builds the real application, enumerates its
URL map and compares the two in both directions.

What is pinned, and why each of these and not a schema validator:

  * **Every route is documented and every documented path is a route.**
    Asserted both ways round, because the two failures have different
    causes -- the first is a developer who forgot, the second is a
    developer who tidied up -- and a test that only checked one of them
    would let the other through for a release. Werkzeug's ``<conv:name>``
    is translated to OpenAPI's ``{name}``, which is the only difference
    between the two spellings of the same URL.

  * **Every path variable has a parameter entry.** A ``{prefix}`` that
    nothing declares renders as an undocumented hole in generated client
    code and in Swagger UI, and the generator does not complain.

  * **Every ``$ref`` resolves.** The document is served as JSON to
    tooling that will follow those pointers; a dangling one is a
    traceback in somebody else's program. This is also what catches a
    components section that was half written.

  * **The ``error`` enum is the engine's status table.** A client
    switching on ``error`` can only do that safely if the documented set
    is the set the engine actually raises, so the enum is compared to
    ``app.STATUS`` itself rather than to a list copied out of it.

  * **Every declared 4xx and 5xx returns the error envelope.** One
    envelope everywhere is a promise this API makes in prose; this is the
    part of it a document can get wrong silently.

  * **The document on disk is the document served.** ``load_spec`` and
    ``GET /openapi.json`` are the two ways anybody obtains it, and a test
    that read only the file would pass on an engine whose endpoint was
    broken.

Every failure message names the offending path and method, because the
developer who sees it is the one who has just added an endpoint and does
not yet know which of its six methods the document is missing.

Conventions follow ``test_rtengine_api.py``: plain ``unittest``, no
pytest features, no syntax newer than 3.6.8, and every engine created
through a fixture that registers its own cleanup. The module skips when
Flask or PyYAML is absent, because both are optional extras and the
engine must remain installable without them.
"""

import json
import re
import unittest

from packets.routing.rtengine import Engine

try:
    import flask as _flask
except ImportError:                                  # pragma: no cover
    _flask = None

try:
    import yaml as _yaml
except ImportError:                                  # pragma: no cover
    _yaml = None

if _flask is not None and _yaml is not None:
    from packets.routing.rtengine.api.app import (API_PREFIX, SPEC_FILE,
                                                  STATUS, create_app,
                                                  load_spec)
    from packets.routing.rtengine.plugins.bgp.plugin import BGPPlugin

#: The keys in a path item that are operations. ``parameters`` and
#: ``summary`` are not, and iterating a path item without this set would
#: assert that ``parameters`` is an undocumented HTTP method.
OPERATIONS = ('get', 'put', 'post', 'patch', 'delete', 'head', 'options',
              'trace')

#: Werkzeug's ``<int:count>``, ``<prefix:prefix>`` or bare ``<name>``.
VARIABLE = re.compile(r'<(?:[^<>:]+:)?([^<>]+)>')

#: OpenAPI's ``{name}``.
PLACEHOLDER = re.compile(r'\{([^{}]+)\}')

#: What a documented error response has to return.
ERROR_REF = '#/components/schemas/Error'

#: A configuration with a BGP instance, so that the plugin's schema and
#: its show and clear paths are grafted on: the document describes an
#: engine with plugins registered, and an engine without them would have
#: a smaller URL map than the one being checked. Copied from
#: ``test_rtengine_api.py``; no ``password``, because macOS has no
#: TCP-MD5 and ``prepare_config`` refuses one it cannot honour.
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
                            'network': {'192.0.2.0/24': {}},
                        },
                    },
                },
            },
        },
    },
}


def resolve_ref(spec, ref):
    """Return the node a local ``$ref`` names.

    :param spec: the whole document.
    :param ref: the reference, e.g. ``#/components/schemas/Error``.
    :return: the node, or None when the reference does not resolve or is
        not a local one -- this document has no external references, so
        an external one is as much a defect as a dangling one.
    """
    if not ref.startswith('#/'):
        return None
    node = spec
    for part in ref[2:].split('/'):
        # RFC 6901 escaping. Nothing in this document needs it today; a
        # schema named after a path would.
        part = part.replace('~1', '/').replace('~0', '~')
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def iter_refs(node, where='#'):
    """Yield every ``(location, reference)`` pair in a document.

    :param node: the document, or a subtree of it.
    :param where: the location reached so far, for the message.
    :return: an iterator of pairs.
    """
    if isinstance(node, dict):
        for key in sorted(node):
            value = node[key]
            if key == '$ref' and isinstance(value, str):
                yield (where, value)
            else:
                for found in iter_refs(value, '%s/%s' % (where, key)):
                    yield found
    elif isinstance(node, list):
        for index, value in enumerate(node):
            for found in iter_refs(value, '%s/%d' % (where, index)):
                yield found


def render(operations):
    """Render operations for a failure message, most specific first.

    :param operations: an iterable of ``(path, method)``.
    :return: a string naming each one, or ``'none'``.
    """
    return ', '.join('%s %s' % (method.upper(), path)
                     for path, method in sorted(operations)) or 'none'


@unittest.skipUnless(_flask is not None, 'the REST API needs Flask')
@unittest.skipUnless(_yaml is not None, 'the OpenAPI document needs PyYAML')
class SpecFixture(unittest.TestCase):
    """Builds the real application and reads the shipped document."""

    def setUp(self):
        """Build an engine with BGP registered, and the app that serves it.

        The document is applied with ``replace_config`` after
        construction rather than through the ``config`` argument,
        because the store validates before a plugin has grafted its
        schema on -- the same order ``test_rtengine_api.py`` needs and
        for the same reason.
        """
        self.engine = Engine(name='openapi-test', plugins=[BGPPlugin()])
        self.addCleanup(self.engine.stop)
        self.engine.replace_config(BGP_CONFIG)
        self.engine.start()
        self.app = create_app(self.engine, api_config={})
        self.app.config['PROPAGATE_EXCEPTIONS'] = False
        self.spec = load_spec()

    # --- the two sides being compared --------------------------------------

    def live_operations(self):
        """Return every ``(path, method)`` the application actually serves.

        Paths are returned as the document spells them: without the
        ``/api/v1`` prefix, which lives in ``servers``, and with
        Werkzeug's converters translated to OpenAPI placeholders.

        ``HEAD`` and ``OPTIONS`` are dropped because Werkzeug adds them
        to every rule and no API documents them. Flask's ``static``
        endpoint and the Swagger UI rules are dropped because neither is
        part of this API: the first is Flask's, and the second only
        exists when ``create_app`` was given ``swagger_ui``.

        :return: a set of ``(path, method)`` with a lower-case method.
        """
        found = set()
        for rule in self.app.url_map.iter_rules():
            if rule.endpoint == 'static' \
                    or not rule.rule.startswith(API_PREFIX):
                continue
            path = rule.rule[len(API_PREFIX):] or '/'
            if path == '/docs' or path.startswith('/docs/'):
                continue
            path = VARIABLE.sub(r'{\1}', path)
            for method in rule.methods:
                if method in ('HEAD', 'OPTIONS'):
                    continue
                found.add((path, method.lower()))
        return found

    def spec_operations(self):
        """Return every ``(path, method)`` the document describes.

        :return: a set of ``(path, method)`` with a lower-case method.
        """
        found = set()
        for path, item in self.spec['paths'].items():
            for method in item:
                if method in OPERATIONS:
                    found.add((path, method))
        return found

    def declared_parameters(self, entries):
        """Return the path parameters a ``parameters`` list declares.

        References are followed, because every parameter in this
        document is a component and a test that only read inline ones
        would assert nothing at all.

        :param entries: the list, or None.
        :return: ``{name: required}`` for the ones in the path.
        """
        found = {}
        for entry in entries or ():
            if '$ref' in entry:
                entry = resolve_ref(self.spec, entry['$ref']) or {}
            if entry.get('in') == 'path':
                found[entry.get('name')] = bool(entry.get('required'))
        return found


class DocumentTestCase(SpecFixture):
    """The document itself: it parses, and it is the one being served."""

    def test_the_document_parses_and_has_its_top_level_sections(self):
        """A 3.x document with the three sections everything else needs."""
        self.assertIsInstance(self.spec, dict,
                              'the OpenAPI document is not a mapping')
        version = self.spec.get('openapi', '')
        self.assertTrue(version.startswith('3.'),
                        'openapi must be a 3.x version, got %r' % (version,))
        for section in ('info', 'paths', 'components'):
            self.assertIn(section, self.spec,
                          'the document has no %r section' % (section,))
        info = self.spec['info']
        for key in ('title', 'description', 'version'):
            self.assertTrue(info.get(key),
                            'info.%s is missing or empty' % (key,))

    def test_the_served_document_is_the_file_on_disk(self):
        """``load_spec`` and ``GET /openapi.json`` are the same document.

        Both are ways a client obtains this API's description, and a
        test that read only the file would pass on an engine whose
        endpoint was serving something else -- or nothing.
        """
        self.assertEqual(self.spec, load_spec(SPEC_FILE))
        response = self.app.test_client().get(API_PREFIX + '/openapi.json')
        self.assertEqual(200, response.status_code,
                         'GET %s/openapi.json answered %s'
                         % (API_PREFIX, response.status_code))
        served = json.loads(response.data.decode('utf-8'))
        self.assertEqual(self.spec, served,
                         'the document served differs from the one on disk')


class CoverageTestCase(SpecFixture):
    """The document and the URL map describe the same set of operations."""

    def test_every_route_is_documented(self):
        """Every rule the application serves has a path and a method here.

        The direction that catches the endpoint somebody added last
        week.
        """
        missing = self.live_operations() - self.spec_operations()
        self.assertEqual(set(), missing,
                         'the URL map serves %d operation(s) the OpenAPI '
                         'document does not describe: %s'
                         % (len(missing), render(missing)))

    def test_every_documented_operation_exists(self):
        """Every path and method here is a rule the application serves.

        The other direction, which catches the paragraph left behind
        after a route was removed or renamed -- documentation for
        something that answers 404.
        """
        extra = self.spec_operations() - self.live_operations()
        self.assertEqual(set(), extra,
                         'the OpenAPI document describes %d operation(s) '
                         'the URL map does not serve: %s'
                         % (len(extra), render(extra)))

    def test_every_path_variable_is_a_declared_parameter(self):
        """Each ``{name}`` is declared, at path or operation level.

        Required as well as present: a path parameter that is not
        required is not a path parameter, and tooling that believes the
        document will generate a client that omits it.
        """
        problems = []
        for path in sorted(self.spec['paths']):
            item = self.spec['paths'][path]
            shared = self.declared_parameters(item.get('parameters'))
            for method in sorted(item):
                if method not in OPERATIONS:
                    continue
                declared = dict(shared)
                declared.update(
                    self.declared_parameters(item[method].get('parameters')))
                for name in PLACEHOLDER.findall(path):
                    where = '%s %s: {%s}' % (method.upper(), path, name)
                    if name not in declared:
                        problems.append('%s is not declared' % (where,))
                    elif not declared[name]:
                        problems.append('%s is not required: true' % (where,))
        self.assertEqual([], problems,
                         'path variables without a usable parameter entry: '
                         '%s' % ('; '.join(problems),))


class ComponentsTestCase(SpecFixture):
    """The shared pieces: references, the error enum, the error bodies."""

    def test_every_reference_resolves(self):
        """No ``$ref`` points at a component that is not there.

        A dangling pointer is a traceback in whatever generator or UI
        reads this document, and it is what a half-written components
        section looks like from the outside.
        """
        broken = []
        for where, ref in iter_refs(self.spec):
            if resolve_ref(self.spec, ref) is None:
                broken.append('%s -> %s' % (where, ref))
        self.assertEqual([], broken,
                         '%d reference(s) do not resolve: %s'
                         % (len(broken), '; '.join(sorted(broken))))

    def test_the_error_enum_is_the_status_table(self):
        """The documented tokens are exactly the ones the engine raises.

        Compared against ``app.STATUS`` rather than a list written out
        here: a token added to the table and not to the document is a
        client switching on a value it was never told about, and a token
        in the document that the engine cannot raise is a branch nobody
        will ever reach.
        """
        schema = self.spec['components']['schemas']['Error']
        documented = schema['properties']['error'].get('enum')
        self.assertEqual(sorted(STATUS), sorted(documented or []),
                         'components.schemas.Error.properties.error.enum '
                         'does not match app.STATUS')

    def test_declared_error_responses_return_the_error_envelope(self):
        """Every 4xx and 5xx in the document returns an ``Error`` body.

        One envelope for every failure is the promise this API makes in
        prose; here is where a document could quietly break it.
        """
        problems = []
        for path in sorted(self.spec['paths']):
            item = self.spec['paths'][path]
            for method in sorted(item):
                if method not in OPERATIONS:
                    continue
                responses = item[method].get('responses') or {}
                for status in sorted(responses):
                    if not str(status).startswith(('4', '5')):
                        continue
                    response = responses[status]
                    if '$ref' in response:
                        response = resolve_ref(self.spec,
                                               response['$ref']) or {}
                    body = response.get('content') or {}
                    schema = (body.get('application/json') or {}).get(
                        'schema') or {}
                    if schema.get('$ref') != ERROR_REF:
                        problems.append('%s %s: %s does not return %s'
                                        % (method.upper(), path, status,
                                           ERROR_REF))
        self.assertEqual([], problems,
                         'error responses that are not the shared envelope: '
                         '%s' % ('; '.join(problems),))


if __name__ == '__main__':
    unittest.main()
