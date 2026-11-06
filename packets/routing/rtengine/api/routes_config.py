# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The configuration resource tree: the IOS hierarchy as URLs.

``router bgp 65000 / neighbor 10.0.0.2 / remote-as 65001`` becomes
``PUT /router/bgp/65000/neighbor/10.0.0.2`` with ``{"remote-as": 65001}``,
and ``no neighbor 10.0.0.2`` becomes ``DELETE`` on the same URL. The
vocabulary is not translated on the way through -- IOS keywords are the JSON
keys and the path segments -- so an operator who knows the CLI can guess the
URL, and ``show running-config`` and the API describe the same document in
the same words.

**Every resource is one configuration path, so there is one handler.** The
table below maps a URL rule to a path template; the four methods are
implemented once each against that template rather than six times each
against six near-identical resources. A copy-pasted handler that forgot its
``If-Match`` or its redaction is exactly the defect this shape cannot have.
It also means adding a resource is a line in a table, which is what keeps
the API honest as the configuration schema grows.

**Keys are matched as values, not as strings.** ``2001:db8:0::/32`` and
``2001:db8::/32`` are one destination; the URL converters canonicalise, and
:func:`~packets.routing.rtengine.api.converters.match_key` finds the key as
it is actually stored before a read or a delete. Otherwise a document loaded
from a file could contain an entry that the API insists does not exist.

**PATCH merges, and ``null`` removes.** A merge against the *redacted*
document is deliberate: the secret comes back as ``"<redacted>"``, writing
that back means "keep what is stored", and so a client can PATCH one field
of a neighbour that has a password without ever holding the password.
"""

from flask import Blueprint, request

from packets.routing.rtengine.api.app import (NotFound, bridge, engine,
                                              if_match_revision, json_body,
                                              json_response, mutation)
from packets.routing.rtengine.api.converters import match_key
from packets.routing.rtengine.config import MISSING, get_path
from packets.routing.rtengine.errors import ConfigError

blueprint = Blueprint('rtengine_config', __name__)

#: The resource table: ``(rule, path template, methods)``. A ``{name}``
#: in the template is filled from the URL variable of the same name.
#:
#: The shape follows the configuration document rather than the plan's
#: first sketch of it in two places, because the document is what the
#: engine validates and an API that disagreed with it would be a second
#: schema to keep in step:
#:
#: * an address family is two segments (``/address-family/ipv4/unicast``),
#:   matching the two nested keys ``config.py`` validates;
#: * per-neighbour, per-family settings hang off the *neighbour*
#:   (``/neighbor/10.0.0.2/address-family/ipv4/unicast``), which is where
#:   ``_neighbor_schema`` puts them.
RESOURCES = [
    ('/router/bgp', ('router', 'bgp'), ('GET',)),
    ('/router/bgp/<asn:asn>', ('router', 'bgp', '{asn}'),
     ('GET', 'PUT', 'PATCH', 'DELETE')),
    ('/router/bgp/<asn:asn>/neighbor',
     ('router', 'bgp', '{asn}', 'neighbor'), ('GET',)),
    ('/router/bgp/<asn:asn>/neighbor/<addr:addr>',
     ('router', 'bgp', '{asn}', 'neighbor', '{addr}'),
     ('GET', 'PUT', 'PATCH', 'DELETE')),
    ('/router/bgp/<asn:asn>/neighbor/<addr:addr>/address-family'
     '/<afi>/<safi>',
     ('router', 'bgp', '{asn}', 'neighbor', '{addr}', 'address-family',
      '{afi}', '{safi}'), ('GET', 'PUT', 'PATCH', 'DELETE')),
    ('/router/bgp/<asn:asn>/address-family',
     ('router', 'bgp', '{asn}', 'address-family'), ('GET',)),
    ('/router/bgp/<asn:asn>/address-family/<afi>/<safi>',
     ('router', 'bgp', '{asn}', 'address-family', '{afi}', '{safi}'),
     ('GET', 'PUT', 'PATCH', 'DELETE')),
    ('/router/bgp/<asn:asn>/address-family/<afi>/<safi>/network',
     ('router', 'bgp', '{asn}', 'address-family', '{afi}', '{safi}',
      'network'), ('GET',)),
    ('/router/bgp/<asn:asn>/address-family/<afi>/<safi>/network'
     '/<prefix:prefix>',
     ('router', 'bgp', '{asn}', 'address-family', '{afi}', '{safi}',
      'network', '{prefix}'), ('GET', 'PUT', 'PATCH', 'DELETE')),
    ('/ip/prefix-list', ('ip', 'prefix-list'), ('GET',)),
    ('/ip/prefix-list/<name>', ('ip', 'prefix-list', '{name}'),
     ('GET', 'PUT', 'DELETE')),
    ('/ipv6/prefix-list', ('ipv6', 'prefix-list'), ('GET',)),
    ('/ipv6/prefix-list/<name>', ('ipv6', 'prefix-list', '{name}'),
     ('GET', 'PUT', 'DELETE')),
    ('/route-map', ('route-map',), ('GET',)),
    ('/route-map/<name>', ('route-map', '{name}'),
     ('GET', 'PUT', 'DELETE')),
    ('/ip/route/static', ('ip', 'route', 'static'), ('GET',)),
    ('/ip/route/static/<prefix:prefix>',
     ('ip', 'route', 'static', '{prefix}'),
     ('GET', 'PUT', 'PATCH', 'DELETE')),
    ('/ipv6/route/static', ('ipv6', 'route', 'static'), ('GET',)),
    ('/ipv6/route/static/<prefix:prefix>',
     ('ipv6', 'route', 'static', '{prefix}'),
     ('GET', 'PUT', 'PATCH', 'DELETE')),
]

#: The keys ``/ip/route/install`` reports and accepts. ``static`` is
#: excluded on purpose: it is a table of routes with its own resource,
#: and merging it through the settings endpoint would let a PATCH
#: containing one static route silently delete the others.
INSTALL_KEYS = ('install', 'table', 'protocol', 'priority',
                'retain-on-shutdown', 'kernel-import', 'validate-next-hop')


def _resolve(template, variables):
    """Fill a path template from the URL variables.

    :param template: the template tuple.
    :param variables: the view's keyword arguments.
    :return: a tuple of configuration keys.
    """
    out = []
    for part in template:
        if part.startswith('{') and part.endswith('}'):
            out.append(str(variables[part[1:-1]]))
        else:
            out.append(part)
    return tuple(out)


def _stored_path(document, path):
    """Map a canonical path onto the keys the document actually uses.

    :param document: the running document.
    :param path: the canonical path.
    :return: the path as stored, falling back to the canonical form for
        anything not present.
    """
    out = []
    node = document
    for key in path:
        actual = match_key(node, key) if isinstance(node, dict) else key
        out.append(actual)
        node = node.get(actual) if isinstance(node, dict) else None
    return tuple(out)


def _snapshot():
    """Read the running document and revision in one trip to the loop.

    Two calls would be two revisions if a change landed between them,
    and an ``ETag`` that does not describe the body it is attached to is
    worse than no ``ETag``.

    :return: ``(document, revision)``; the document is redacted.
    """
    # The engine is passed in, never looked up: this callable runs on
    # the loop thread, where Flask's request-bound globals -- and so
    # this package's ``engine()`` helper -- do not resolve. See the rule
    # in bridge.py.
    def read(eng):
        return eng.running_config(redact=True), eng.revision

    return bridge().call(read, engine())


def _read(path):
    """GET one configuration resource."""
    document, revision = _snapshot()
    actual = _stored_path(document, path)
    value = get_path(document, actual)
    if value is MISSING:
        raise NotFound('nothing is configured at %s'
                       % '.'.join(actual), path='.'.join(actual))
    if not isinstance(value, (dict, list)):
        # A scalar leaf is wrapped so that every response from this API
        # is a JSON object or array and a client never has to handle a
        # bare number that means something only because of the URL.
        value = {'value': value}
    return json_response(value, headers={'ETag': '"%d"' % (revision,)})


def _write(path, value):
    """PUT one configuration resource: create or replace."""
    document, _revision = _snapshot()
    actual = _stored_path(document, path)
    revision = bridge().call(engine().configure, actual, value,
                             if_match_revision())
    return mutation(revision, actual)


def _merge(path, patch):
    """PATCH one configuration resource: merge, ``null`` removing a key."""
    if not isinstance(patch, dict):
        raise ConfigError('a PATCH body must be an object; use PUT to '
                          'replace a value outright')
    document, _revision = _snapshot()
    actual = _stored_path(document, path)
    current = get_path(document, actual)
    if current is MISSING:
        raise NotFound('nothing is configured at %s, so there is nothing '
                       'to merge into; use PUT to create it'
                       % '.'.join(actual), path='.'.join(actual))
    if not isinstance(current, dict):
        raise ConfigError('%s is a value, not an object; use PUT'
                          % '.'.join(actual), path='.'.join(actual))
    merged = _deep_merge(current, patch)
    revision = bridge().call(engine().configure, actual, merged,
                             if_match_revision())
    return mutation(revision, actual)


def _remove(path):
    """DELETE one configuration resource -- IOS ``no``."""
    document, _revision = _snapshot()
    actual = _stored_path(document, path)
    if get_path(document, actual) is MISSING:
        raise NotFound('nothing is configured at %s' % '.'.join(actual),
                       path='.'.join(actual))
    revision = bridge().call(engine().unconfigure, actual,
                             if_match_revision())
    return mutation(revision, actual)


def _deep_merge(current, patch):
    """Merge a patch into a copy of a subtree.

    :param current: the stored value, not modified.
    :param patch: the client's object; ``null`` removes a key, and a
        nested object merges rather than replacing -- replacing a nested
        object outright is what PUT on its own URL is for.
    :return: the merged value.
    """
    import copy

    merged = copy.deepcopy(current)
    for key, value in patch.items():
        if value is None:
            merged.pop(key, None)
        elif isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _make_view(template, methods):
    """Build the view function for one row of :data:`RESOURCES`."""

    def view(**variables):
        path = _resolve(template, variables)
        method = request.method
        if method == 'GET':
            return _read(path)
        if method == 'PUT':
            return _write(path, json_body())
        if method == 'PATCH':
            return _merge(path, json_body())
        return _remove(path)

    view.__name__ = 'config_' + '_'.join(
        part.strip('{}') for part in template)
    view.__doc__ = ('Configuration resource ``%s``. Methods: %s.'
                    % ('.'.join(template), ', '.join(methods)))
    return view


for _rule, _template, _methods in RESOURCES:
    blueprint.add_url_rule(_rule, view_func=_make_view(_template, _methods),
                           methods=list(_methods))


@blueprint.route('/ip/route/install', methods=['GET'])
def get_install():
    """The forwarding-plane settings, as they are in effect.

    Effective rather than configured: the schema's defaults are not
    written into the document, so a client reading the raw subtree of a
    fresh engine would see ``{}`` and have to know that ``install`` is
    False, the table is 254 and the protocol id is 190. The one question
    this endpoint exists to answer is "is this engine writing the kernel
    routing table, and as whom".
    """
    def read(eng):
        store = eng.store
        values = {}
        for key in INSTALL_KEYS:
            values[key] = store.value(('ip', 'route', key))
        values['priority'] = {
            'ebgp': store.value(('ip', 'route', 'priority', 'ebgp')),
            'ibgp': store.value(('ip', 'route', 'priority', 'ibgp')),
        }
        values['sink'] = {'name': eng.sink.name,
                          'writes': eng.sink.writes}
        return values, eng.revision

    values, revision = bridge().call(read, engine())
    return json_response(values, headers={'ETag': '"%d"' % (revision,)})


@blueprint.route('/ip/route/install', methods=['PATCH'])
def patch_install():
    """Change the forwarding-plane settings.

    This is not a flag to toggle idly and the endpoint does not pretend
    otherwise: turning ``install`` on opens a netlink socket and
    reconciles against the routes already in the kernel carrying our
    protocol id, and turning it off withdraws everything we installed,
    because those routes are ours and nothing else will ever remove
    them. Both happen inside the engine's commit, so the response
    arrives after the kernel agrees.
    """
    patch = json_body()
    if not isinstance(patch, dict):
        raise ConfigError('a PATCH body must be an object')
    unknown = [key for key in patch if key not in INSTALL_KEYS]
    if unknown:
        raise ConfigError('unknown setting(s) %s; known: %s'
                          % (', '.join(sorted(unknown)),
                             ', '.join(INSTALL_KEYS)),
                          path='ip.route')
    document, _revision = _snapshot()
    current = get_path(document, ('ip', 'route'))
    current = {} if current is MISSING else dict(current)
    statics = current.pop('static', MISSING)
    merged = _deep_merge(current, patch)
    if statics is not MISSING:
        merged['static'] = statics
    revision = bridge().call(engine().configure, ('ip', 'route'), merged,
                             if_match_revision())
    return mutation(revision, ('ip', 'route'))
