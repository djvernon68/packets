# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The configuration document: one JSON tree, revisioned, changed atomically.

The engine is configured by a nested dictionary whose keys are IOS keywords --
``router``, ``bgp``, ``neighbor``, ``remote-as``, ``address-family`` -- so the
same vocabulary serves the document on disk, the REST resource tree and
``show running-config``. There is no separate internal representation to keep
in step with the external one.

Three things here are worth reading the code for.

**Validation is against a schema the plugins extend.** The core declares
``ip``, ``ipv6``, ``route-map`` and ``api``; each protocol plugin contributes
the schema for its own section under ``router``. So the set of legal
configuration is exactly the set of registered plugins' vocabulary plus the
core's, and the OpenAPI request bodies in a later stage are generated from the
same declarations rather than written twice.

**A change is a diff, and it is applied in two phases.** Nothing is mutated in
place. A proposed change produces a new document, which is validated, diffed
against the running one, and the diff is routed to the plugins whose sections
it touches. Every plugin gets ``prepare_config`` first -- pure, may reject --
and only if all of them accept does any of them get ``commit_config``. A
rejection therefore leaves the running document and its revision exactly where
they were, which is the property acceptance criterion 10 asks for. If a commit
nevertheless fails, the plugins that already committed are handed the inverse
diff; that is best effort and says so, because a session a plugin already
reset cannot be un-reset.

**Secrets never leave.** Schema nodes marked ``secret`` are replaced with
``"<redacted>"`` in ``running-config``, ``show`` and health output. Writing
``"<redacted>"`` back means "keep what is stored", so a client can read the
whole document, change one unrelated field and PUT it back without either
learning the key or destroying it. Writing it where nothing is stored is an
error rather than a silent empty password.
"""

import copy
import re

from packets.routing.rtengine.errors import ConfigError, ConflictError

#: Placeholder a secret is rendered as, and the sentinel that means "keep the
#: stored value" when it is written back.
REDACTED = '<redacted>'


class _Missing(object):
    """Sentinel for "this path is absent", distinct from a None value.

    A configured ``None`` and an unconfigured key mean different things to a
    diff: one is a value to apply, the other is a deletion.
    """

    __slots__ = ()

    def __repr__(self):
        return '<missing>'

    def __bool__(self):
        return False


MISSING = _Missing()

_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-]*$')


# --- schema -----------------------------------------------------------------
# A schema node is a dict with a 'type' and type-specific keys:
#
#   dict     'keys': {name: node} for a fixed set of keys, or
#            'key_type' + 'value' for a keyed collection (neighbours by
#            address, networks by prefix, prefix-lists by name);
#            'max_keys' bounds a keyed collection -- this is how the v1
#            "one router bgp instance" rule is expressed rather than
#            special-cased in code.
#   list     'item': node
#   int      'min', 'max'
#   bool     -
#   str      'choices', 'pattern'
#   prefix   an address/length string in either family
#   addr     a bare address string
#   secret   a str that is redacted on the way out and keep-sentinelled on
#            the way in
#   any      unvalidated; an escape hatch for a plugin that has not declared
#            its section yet
#
# Every node may carry 'default', used by ConfigStore.value() rather than
# being materialised into the document: running-config shows what was
# configured, not what was defaulted, exactly as IOS does.


def _fail(path, detail):
    raise ConfigError(detail, path='.'.join(str(p) for p in path))


def _check_key(path, key, key_type):
    from packets.routing.rtengine.rib.prefix import parse_prefix

    if key_type == 'name':
        if not isinstance(key, str) or not _NAME_RE.match(key):
            _fail(path, 'not a valid name: %r' % (key,))
    elif key_type == 'prefix':
        try:
            parse_prefix(key)
        except ValueError as exc:
            _fail(path, str(exc))
    elif key_type == 'addr':
        try:
            p = parse_prefix(key)
        except ValueError as exc:
            _fail(path, str(exc))
        else:
            if not p.is_host:
                _fail(path, 'expected a bare address, not a prefix: %r'
                      % (key,))
    elif key_type == 'asn':
        # Autonomous system numbers arrive as JSON object keys, so they are
        # strings even though they are numbers. 4-octet range, and 0 and
        # 65535/4294967295 are reserved.
        if not (isinstance(key, str) and key.isdigit()):
            _fail(path, 'AS number must be digits: %r' % (key,))
        asn = int(key)
        if asn < 1 or asn > 4294967295:
            _fail(path, 'AS number %d out of range' % asn)
    elif key_type == 'afi':
        if key not in ('ipv4', 'ipv6'):
            _fail(path, "address family must be 'ipv4' or 'ipv6', not %r"
                  % (key,))
    elif key_type == 'safi':
        if key not in ('unicast',):
            _fail(path, "only 'unicast' is supported in v1, not %r" % (key,))
    elif key_type == 'str':
        if not isinstance(key, str):
            _fail(path, 'key must be a string: %r' % (key,))
    else:
        raise ValueError('unknown key_type %r in schema' % (key_type,))


def validate(document, schema, path=()):
    """Check a document, or a subtree of one, against a schema node.

    :param document: the value to check.
    :param schema: the schema node, or None to accept anything.
    :param path: the path reached so far, used in error messages.
    :raises ConfigError: the document does not match, with ``path`` set to
        the dotted location of the offending value.
    """
    from packets.routing.rtengine.rib.prefix import parse_prefix

    if schema is None:
        return
    kind = schema.get('type', 'any')

    if kind == 'any':
        return

    if kind == 'dict':
        if not isinstance(document, dict):
            _fail(path, 'expected an object, got %s'
                  % type(document).__name__)
        keys = schema.get('keys')
        if keys is not None:
            for key, value in document.items():
                if key not in keys:
                    _fail(path, 'unknown key %r; known: %s'
                          % (key, ', '.join(sorted(keys))))
                validate(value, keys[key], path + (key,))
            for key, node in keys.items():
                if node is not None and node.get('required') \
                        and key not in document:
                    _fail(path + (key,), 'required')
        else:
            key_type = schema.get('key_type', 'str')
            max_keys = schema.get('max_keys')
            if max_keys is not None and len(document) > max_keys:
                # ConflictError, not ConfigError: the document is
                # well-formed, it collides with a stated limit. The API
                # turns that into 409 rather than 400.
                raise ConflictError(
                    'at most %d entry is allowed here in v1, got %d'
                    % (max_keys, len(document)),
                    path='.'.join(str(p) for p in path))
            for key, value in document.items():
                _check_key(path, key, key_type)
                validate(value, schema.get('value'), path + (key,))
        return

    if kind == 'list':
        if not isinstance(document, list):
            _fail(path, 'expected a list, got %s' % type(document).__name__)
        for index, item in enumerate(document):
            validate(item, schema.get('item'), path + (index,))
        return

    if kind == 'bool':
        # Checked before int, because bool is a subclass of int in Python
        # and a schema that accepts an int would otherwise accept True.
        if not isinstance(document, bool):
            _fail(path, 'expected true or false, got %r' % (document,))
        return

    if kind == 'int':
        if isinstance(document, bool) or not isinstance(document, int):
            _fail(path, 'expected an integer, got %r' % (document,))
        low = schema.get('min')
        high = schema.get('max')
        if low is not None and document < low:
            _fail(path, 'must be at least %d' % low)
        if high is not None and document > high:
            _fail(path, 'must be at most %d' % high)
        return

    if kind in ('str', 'secret'):
        if not isinstance(document, str):
            _fail(path, 'expected a string, got %s'
                  % type(document).__name__)
        choices = schema.get('choices')
        if choices is not None and document not in choices:
            _fail(path, 'must be one of %s' % ', '.join(map(str, choices)))
        pattern = schema.get('pattern')
        if pattern is not None and not re.match(pattern, document):
            _fail(path, 'does not match %s' % pattern)
        minlen = schema.get('minlen')
        if minlen is not None and len(document) < minlen \
                and document != REDACTED:
            _fail(path, 'must be at least %d characters' % minlen)
        return

    if kind in ('prefix', 'addr'):
        if not isinstance(document, str):
            _fail(path, 'expected a string, got %s'
                  % type(document).__name__)
        try:
            parsed = parse_prefix(document)
        except ValueError as exc:
            _fail(path, str(exc))
        else:
            if kind == 'addr' and not parsed.is_host:
                _fail(path, 'expected a bare address, not a prefix')
        return

    raise ValueError('unknown schema type %r' % (kind,))


def schema_node(schema, path):
    """Return the schema node at a path, or None if the schema is open there.

    :param schema: the root schema node.
    :param path: tuple of keys.
    :return: the node, or None when nothing constrains that path.
    """
    node = schema
    for key in path:
        if node is None:
            return None
        kind = node.get('type')
        if kind != 'dict':
            return None
        keys = node.get('keys')
        if keys is not None:
            node = keys.get(key)
        else:
            node = node.get('value')
    return node


def secret_paths(schema, path=()):
    """Return every path in a schema that holds a secret.

    Used by redaction, which has to know where the secrets are rather than
    guessing from key names -- a key called ``password`` is obvious, a
    key-chain entry is not.

    :param schema: the root schema node.
    :param path: internal, the prefix reached so far.
    :return: a list of paths, each a tuple of keys where a key may be the
        wildcard ``None`` for a keyed collection.
    """
    found = []
    if schema is None:
        return found
    kind = schema.get('type', 'any')
    if kind == 'secret':
        found.append(path)
    elif kind == 'dict':
        keys = schema.get('keys')
        if keys is not None:
            for key, node in keys.items():
                found.extend(secret_paths(node, path + (key,)))
        else:
            found.extend(secret_paths(schema.get('value'), path + (None,)))
    elif kind == 'list':
        found.extend(secret_paths(schema.get('item'), path + (None,)))
    return found


def _matches(path, pattern):
    """Whether a concrete path is a :func:`secret_paths` pattern.

    :param path: a tuple of actual keys.
    :param pattern: a tuple of the same length, ``None`` matching any key.
    :return: True if every key matches.
    """
    return len(path) == len(pattern) and all(
        want is None or want == key for key, want in zip(path, pattern))


# --- the core schema --------------------------------------------------------

_PREFIX_LIST_ENTRY = {
    'type': 'dict',
    'keys': {
        'seq': {'type': 'int', 'min': 1, 'max': 4294967295},
        'action': {'type': 'str', 'choices': ('permit', 'deny'),
                   'required': True},
        'prefix': {'type': 'prefix', 'required': True},
        'le': {'type': 'int', 'min': 0, 'max': 128},
        'ge': {'type': 'int', 'min': 0, 'max': 128},
    },
}

_ROUTE_MAP_CLAUSE = {
    'type': 'dict',
    'keys': {
        'seq': {'type': 'int', 'min': 1, 'max': 65535},
        'action': {'type': 'str', 'choices': ('permit', 'deny'),
                   'required': True},
        # match/set contents are the policy engine's vocabulary and are
        # validated by it in the stage that implements it; accepting them
        # opaquely here keeps this schema from having to grow every time a
        # match clause is added.
        'match': {'type': 'any'},
        'set': {'type': 'any'},
    },
}

_STATIC_ROUTE = {
    'type': 'dict',
    'keys': {
        'next-hop': {'type': 'addr', 'required': True},
        'distance': {'type': 'int', 'min': 0, 'max': 255, 'default': 1},
        'metric': {'type': 'int', 'min': 0, 'max': 4294967295, 'default': 0},
    },
}

_ROUTE_INSTALL = {
    'type': 'dict',
    'keys': {
        # Off by default and deliberately so: importing a library must never
        # be enough to make it write the kernel routing table.
        'install': {'type': 'bool', 'default': False},
        'table': {'type': 'int', 'min': 0, 'max': 4294967295,
                  'default': 254},
        # 190: free on every deployment target checked, and clear of the
        # block iproute2 reserves for routing daemons (186 bgp, 187 isis,
        # 188 ospf, 189 rip, 192 eigrp). Our own id is what makes
        # NLM_F_REPLACE safe -- it can only ever replace our routes.
        'protocol': {'type': 'int', 'min': 1, 'max': 255, 'default': 190},
        'priority': {
            'type': 'dict',
            'keys': {
                'ebgp': {'type': 'int', 'min': 0, 'max': 4294967295,
                         'default': 20},
                'ibgp': {'type': 'int', 'min': 0, 'max': 4294967295,
                         'default': 200},
            },
        },
        'retain-on-shutdown': {'type': 'bool', 'default': False},
        'static': {'type': 'dict', 'key_type': 'prefix',
                   'value': _STATIC_ROUTE},
        # Off by default, and the default is the safe one rather than the
        # strict one: a control-plane speaker with no forwarding plane and
        # no IGP has nothing to validate a next-hop against, so turning
        # this on without a resolver table would make every learned path
        # ineligible. See rib/resolver.py.
        'validate-next-hop': {'type': 'bool', 'default': False},
        # FRR's `ip nht resolve-via-default` (P-3): whether a default
        # route may vouch for a next hop. Off, because a default covers
        # every address and so proves nothing about any of them.
        'resolve-via-default': {'type': 'bool', 'default': False},
        # Read-only import of the kernel's own routes into the resolver.
        # Accepted by the schema but not implemented yet: it is a second
        # Linux-only netlink path and it lands with the sink that already
        # needs one, so configuring it today changes nothing.
        'kernel-import': {'type': 'bool', 'default': False},
    },
}

#: Where the API listens unless told otherwise. Loopback, because an
#: engine that started serving its configuration to the network because
#: somebody imported a library would be indefensible.
DEFAULT_API_BIND = '127.0.0.1:8179'

#: The API's default port. 8179 is 179 -- BGP -- in the 8000 range, which
#: is a mnemonic rather than a registration.
DEFAULT_API_PORT = 8179


def parse_bind(text, default_port=DEFAULT_API_PORT):
    """Split a ``host:port`` bind string.

    IPv6 literals are bracketed, so the last colon is only a port
    separator when it falls outside the brackets -- ``::1`` has two colons
    and no port, and getting that wrong binds to a host called ``:``.

    :param text: the bind string; ``host``, ``host:port``, ``[v6]:port``
        or ``[v6]``.
    :param default_port: used when the string names no port.
    :return: ``(host, port)`` with the brackets stripped from a literal.
    :raises ConfigError: the port is not a number in range.
    """
    raw = str(text).strip()
    host = raw
    port = default_port
    if raw.startswith('['):
        end = raw.find(']')
        if end == -1:
            raise ConfigError('unterminated IPv6 literal in bind %r'
                              % (text,), path='api.bind')
        host = raw[1:end]
        rest = raw[end + 1:]
        if rest.startswith(':'):
            port = rest[1:]
    elif raw.count(':') == 1:
        host, port = raw.rsplit(':', 1)
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ConfigError('not a port number: %r' % (port,),
                          path='api.bind')
    if not 0 <= port <= 65535:
        raise ConfigError('port %d is out of range' % (port,),
                          path='api.bind')
    return host or '127.0.0.1', port


def is_loopback(host):
    """Return whether an address is reachable only from this host.

    Used to decide whether an unauthenticated API is acceptable, so it
    errs towards False: an address this cannot prove is loopback is
    treated as exposed. ``localhost`` is accepted on its name because
    resolving it here would make a security decision depend on the
    contents of ``/etc/hosts`` at start-up.

    :param host: the host part of a bind string.
    :return: True for the loopback interface.
    """
    name = str(host).strip().strip('[]').lower()
    if name in ('localhost', 'ip6-localhost', '::1', '0:0:0:0:0:0:0:1'):
        return True
    return name.startswith('127.')


_API = {
    'type': 'dict',
    'keys': {
        'bind': {'type': 'str', 'default': DEFAULT_API_BIND},
        'auth': {
            'type': 'dict',
            'keys': {
                'token': {'type': 'secret', 'minlen': 16},
                'token-file': {'type': 'str'},
                'allow-unauthenticated-health': {'type': 'bool',
                                                 'default': False},
            },
        },
        'insecure': {'type': 'bool', 'default': False},
        'tls': {
            'type': 'dict',
            'keys': {
                'cert': {'type': 'str'},
                'key': {'type': 'str'},
            },
        },
        'max-body-bytes': {'type': 'int', 'min': 1024, 'max': 67108864,
                           'default': 1048576},
        'max-page': {'type': 'int', 'min': 1, 'max': 1000000,
                     'default': 10000},
    },
}

#: The sections the core owns. Plugins add their own under ``router``.
CORE_SCHEMA = {
    'type': 'dict',
    'keys': {
        # Filled in per registered plugin; an empty keys dict rejects
        # everything, which is the right answer for an engine with no
        # plugins registered.
        'router': {'type': 'dict', 'keys': {}},
        'ip': {
            'type': 'dict',
            'keys': {
                'prefix-list': {'type': 'dict', 'key_type': 'name',
                                'value': {'type': 'list',
                                          'item': _PREFIX_LIST_ENTRY}},
                # Entries are the policy engine's to judge, as route-map
                # match/set bodies are: PolicyStore.validate checks the
                # keys, the regex/pattern synonym and the P-2 regex guard,
                # and names the rule a pattern broke. Without this key at
                # all (S6-a) no AS-path list could be configured.
                'as-path-access-list': {'type': 'dict', 'key_type': 'name',
                                        'value': {'type': 'list',
                                                  'item': {'type': 'any'}}},
                'route': _ROUTE_INSTALL,
            },
        },
        'ipv6': {
            'type': 'dict',
            'keys': {
                'prefix-list': {'type': 'dict', 'key_type': 'name',
                                'value': {'type': 'list',
                                          'item': _PREFIX_LIST_ENTRY}},
                'route': {
                    'type': 'dict',
                    'keys': {
                        'static': {'type': 'dict', 'key_type': 'prefix',
                                   'value': _STATIC_ROUTE},
                    },
                },
            },
        },
        'route-map': {'type': 'dict', 'key_type': 'name',
                      'value': {'type': 'list',
                                'item': _ROUTE_MAP_CLAUSE}},
        'api': _API,
    },
}


# --- documents and diffs ----------------------------------------------------

def get_path(document, path):
    """Read a path out of a document.

    :param document: the document.
    :param path: tuple of keys.
    :return: the value, or :data:`MISSING` if any key along the way is
        absent.
    """
    node = document
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return MISSING
        node = node[key]
    return node


def set_path(document, path, value):
    """Set a path in a document, creating intermediate objects.

    :param document: the document, modified in place.
    :param path: tuple of keys; must not be empty.
    :param value: the value to store.
    :raises ConfigError: an intermediate key exists and is not an object.
    """
    if not path:
        raise ConfigError('a configuration path is required')
    node = document
    for index, key in enumerate(path[:-1]):
        nxt = node.get(key)
        if nxt is None:
            nxt = {}
            node[key] = nxt
        elif not isinstance(nxt, dict):
            _fail(path[:index + 1], 'is a value, not a section')
        node = nxt
    node[path[-1]] = value


def del_path(document, path):
    """Remove a path from a document, pruning sections it empties.

    Pruning matters for the diff: a neighbour deleted from an
    address-family should not leave an empty ``neighbor`` object behind,
    because then the document no longer round-trips and two documents that
    mean the same thing would compare as different.

    :param document: the document, modified in place.
    :param path: tuple of keys.
    :return: True if something was removed.
    """
    if not path:
        raise ConfigError('a configuration path is required')
    chain = [document]
    node = document
    for key in path[:-1]:
        if not isinstance(node, dict) or key not in node:
            return False
        node = node[key]
        chain.append(node)
    if not isinstance(node, dict) or path[-1] not in node:
        return False
    del node[path[-1]]
    for index in range(len(chain) - 1, 0, -1):
        if chain[index]:
            break
        del chain[index - 1][path[index - 1]]
    return True


class Diff(object):
    """The difference between two configuration documents.

    A flat list of ``(path, old, new)`` where either side may be
    :data:`MISSING`. Granularity follows the documents: the comparison
    recurses while both sides are objects, so a changed scalar is reported
    at its own path while a whole added or removed section is reported once
    at its root. A plugin therefore sees "this neighbour appeared" as one
    change rather than as fifteen.

    :param changes: the change list.
    """

    __slots__ = ('changes',)

    def __init__(self, changes=None):
        self.changes = list(changes or ())

    def __len__(self):
        return len(self.changes)

    def __iter__(self):
        return iter(self.changes)

    def __bool__(self):
        return bool(self.changes)

    def under(self, prefix):
        """Return the sub-diff affecting a section.

        :param prefix: tuple of keys naming the section.
        :return: a new Diff containing the changes at or below ``prefix``,
            including a change *above* it that covers it -- replacing the
            whole ``router`` object changes ``router.bgp`` too, and a
            plugin that only looked for its own prefix would miss it.
        """
        n = len(prefix)
        out = []
        for path, old, new in self.changes:
            if path[:n] == prefix or prefix[:len(path)] == path:
                out.append((path, old, new))
        return Diff(out)

    def inverse(self):
        """Return the diff that undoes this one.

        :return: a new Diff with old and new swapped in every change.
        """
        return Diff([(path, new, old) for path, old, new in self.changes])

    def paths(self):
        """Return just the changed paths.

        :return: a list of tuples.
        """
        return [path for path, _old, _new in self.changes]

    def as_list(self):
        """Render for API and log output.

        :data:`MISSING` becomes an absent key rather than a string, so a
        reader can tell "set to null" from "removed".

        :return: a list of dicts.
        """
        out = []
        for path, old, new in self.changes:
            item = {'path': '.'.join(str(p) for p in path)}
            if old is not MISSING:
                item['old'] = old
            if new is not MISSING:
                item['new'] = new
            out.append(item)
        return out

    def __repr__(self):
        return '<Diff changes=%d>' % len(self.changes)


def diff_documents(old, new, path=()):
    """Compare two documents.

    :param old: the current document.
    :param new: the proposed document.
    :param path: internal, the prefix reached so far.
    :return: a :class:`Diff`.
    """
    return Diff(_diff_into(old, new, path))


def _diff_into(old, new, path):
    if isinstance(old, dict) and isinstance(new, dict):
        changes = []
        for key in sorted(set(old) | set(new), key=str):
            changes.extend(_diff_into(old.get(key, MISSING),
                                      new.get(key, MISSING),
                                      path + (key,)))
        return changes
    if old is MISSING and new is MISSING:
        return []
    if old == new and type(old) is type(new):
        # Type is compared as well because 1 == True and 1 == 1.0 in Python,
        # and a configuration that changed a flag from 1 to True has
        # changed, even if only cosmetically.
        return []
    return [(path, old, new)]


# --- the store --------------------------------------------------------------

class ConfigStore(object):
    """The running configuration document, its schema and its revision.

    Nothing here applies a change to the engine. It validates, diffs,
    redacts and holds the revision; the engine drives the two-phase apply
    across plugins, because only the engine knows which plugins exist.

    :param document: the initial document. Validated immediately, so an
        engine constructed with a bad configuration fails at construction
        rather than at start.
    :param schema: the root schema; defaults to :data:`CORE_SCHEMA`.
    :raises ConfigError: the initial document is invalid.
    """

    def __init__(self, document=None, schema=None):
        self.schema = copy.deepcopy(schema or CORE_SCHEMA)
        self.revision = 0
        doc = copy.deepcopy(document) if document else {}
        validate(doc, self.schema)
        self._document = doc

    # --- schema extension --------------------------------------------------

    def add_section_schema(self, path, node):
        """Graft a plugin's schema into the tree.

        :param path: where it belongs, e.g. ``('router', 'bgp')``.
        :param node: the schema node.
        :raises ValueError: the path's parent is not a fixed-key object, or
            something already claims that key -- two plugins owning one
            section would make a diff ambiguous, so it is refused at
            registration.
        """
        node_parent = self.schema
        for key in path[:-1]:
            keys = node_parent.get('keys')
            if keys is None or key not in keys:
                raise ValueError('no schema section at %r' % (key,))
            node_parent = keys[key]
        keys = node_parent.get('keys')
        if keys is None:
            raise ValueError('%s is a keyed collection, not a section'
                             % '.'.join(path[:-1]))
        if path[-1] in keys:
            raise ValueError('configuration section %s is already claimed'
                             % '.'.join(path))
        keys[path[-1]] = node

    # --- reads -------------------------------------------------------------

    def document(self, redact=True):
        """Return a copy of the running document.

        A copy, always: handing out the live document would let a caller --
        or an API handler -- mutate the running configuration without a
        revision, which is exactly what the revision exists to prevent.

        :param redact: replace secrets with ``"<redacted>"``.
        :return: the document.
        """
        doc = copy.deepcopy(self._document)
        if redact:
            self._redact_into(doc)
        return doc

    def value(self, path, default=None):
        """Read one configured value, falling back to the schema default.

        Defaults are resolved here rather than being written into the
        document, so ``running-config`` shows what an operator configured
        and not the hundred things they did not -- the same choice IOS
        makes.

        :param path: tuple of keys.
        :param default: returned when neither the document nor the schema
            has a value.
        :return: the value.
        """
        found = get_path(self._document, path)
        if found is not MISSING:
            return found
        node = schema_node(self.schema, path)
        if node is not None and 'default' in node:
            return node['default']
        return default

    # --- proposals ---------------------------------------------------------

    def propose_set(self, path, value):
        """Build the document that would result from setting a path.

        The running document is not touched. Secrets written as
        ``"<redacted>"`` are resolved against what is stored.

        :param path: tuple of keys.
        :param value: the value to set; may be a whole subtree.
        :return: the proposed document, already validated.
        :raises ConfigError: the result would be invalid, or a redaction
            sentinel was written where nothing is stored.
        """
        proposed = copy.deepcopy(self._document)
        set_path(proposed, tuple(path), copy.deepcopy(value))
        self._resolve_secrets(proposed)
        validate(proposed, self.schema)
        return proposed

    def propose_delete(self, path):
        """Build the document that would result from deleting a path.

        :param path: tuple of keys.
        :return: the proposed document, already validated.
        :raises ConfigError: there is nothing at that path.
        """
        proposed = copy.deepcopy(self._document)
        if not del_path(proposed, tuple(path)):
            raise ConfigError('nothing configured at this path',
                              path='.'.join(str(p) for p in path))
        validate(proposed, self.schema)
        return proposed

    def propose_replace(self, document):
        """Build a proposal that replaces the whole document.

        :param document: the new document.
        :return: the proposed document, already validated.
        :raises ConfigError: it is invalid.
        """
        proposed = copy.deepcopy(document) if document else {}
        if not isinstance(proposed, dict):
            raise ConfigError('a configuration document must be an object')
        self._resolve_secrets(proposed)
        validate(proposed, self.schema)
        return proposed

    def diff(self, proposed):
        """Diff a proposal against the running document.

        :param proposed: the proposed document.
        :return: a :class:`Diff`.
        """
        return diff_documents(self._document, proposed)

    def commit(self, proposed):
        """Install a proposal as the running document and bump the revision.

        Called by the engine only after every affected plugin has committed.

        :param proposed: the document to install.
        :return: the new revision.
        """
        self._document = proposed
        self.revision += 1
        return self.revision

    def check_revision(self, if_revision):
        """Enforce an optimistic-concurrency guard.

        :param if_revision: the revision the caller believes is current, or
            None to skip the check.
        :raises PreconditionFailed: it is not the current revision.
        """
        if if_revision is None:
            return
        if int(if_revision) != self.revision:
            from packets.routing.rtengine.errors import PreconditionFailed
            raise PreconditionFailed(
                'configuration has changed since revision %s'
                % (if_revision,), expected=int(if_revision),
                actual=self.revision)

    # --- secrets -----------------------------------------------------------

    def _walk_secrets(self, document, visit):
        for spath in secret_paths(self.schema):
            self._walk_one(document, spath, (), visit)

    def _walk_one(self, node, spath, sofar, visit):
        if not spath:
            return
        key = spath[0]
        rest = spath[1:]
        if not isinstance(node, dict):
            return
        if key is None:
            for actual in list(node):
                self._walk_one(node[actual], rest, sofar + (actual,), visit)
            return
        if key not in node:
            return
        if not rest:
            visit(node, key, sofar + (key,))
            return
        self._walk_one(node[key], rest, sofar + (key,), visit)

    def _redact_into(self, document):
        def visit(container, key, _path):
            if isinstance(container[key], str) and container[key]:
                container[key] = REDACTED
        self._walk_secrets(document, visit)

    def _resolve_secrets(self, proposed):
        """Turn a written-back ``"<redacted>"`` into the stored value."""
        stored = self._document

        def visit(container, key, path):
            if container[key] != REDACTED:
                return
            existing = get_path(stored, path)
            if existing is MISSING or existing == REDACTED:
                _fail(path, 'no stored value to keep: %s means "leave the '
                            'existing value alone", so it cannot be used to '
                            'set one' % REDACTED)
            container[key] = existing
        self._walk_secrets(proposed, visit)

    def redacted_copy(self, document):
        """Return a redacted copy of an arbitrary document.

        For log lines and health output that carry a configuration fragment
        which never went through :meth:`document`.

        :param document: the fragment.
        :return: a redacted deep copy.
        """
        doc = copy.deepcopy(document)
        self._redact_into(doc)
        return doc

    def redacted_changes(self, diff):
        """Render a diff the way :meth:`Diff.as_list` does, secrets redacted.

        What the ``config-change`` event carries (E-2). It used to carry the
        raw ``as_list()``, so rotating ``api.auth.token`` or setting a
        neighbour ``password`` put the plaintext on the event bus, where
        every subscriber -- a log shipper, a debugging websocket -- could
        read it. A change can sit at three heights relative to a secret,
        and each is handled: *at* it (``api.auth.token`` itself, whose old
        and new values are both redacted), *above* it (adding a whole
        neighbour, whose subtree is walked like a document), or beside it,
        which needs nothing. An absent side stays absent, so a reader can
        still tell "removed" from "set".

        :param diff: a :class:`Diff`.
        :return: a list of dicts, the shape of :meth:`Diff.as_list`.
        """
        secrets = secret_paths(self.schema)
        return Diff([(path, self._redact_value(path, old, secrets),
                      self._redact_value(path, new, secrets))
                     for path, old, new in diff]).as_list()

    def _redact_value(self, path, value, secrets):
        """Return one side of a change with any secret in it redacted.

        :param path: the change's path.
        :param value: its old or new value, possibly :data:`MISSING`.
        :param secrets: :func:`secret_paths` of this store's schema.
        :return: the value, or a redacted deep copy of it.
        """
        if value is MISSING or value is None:
            return value
        depth = len(path)
        below = []
        for spath in secrets:
            if depth >= len(spath):
                if _matches(path[:len(spath)], spath):
                    # At the secret, or (were a secret ever a container)
                    # inside it: nothing of it may be shown.
                    return REDACTED if value != '' else value
            elif _matches(path, spath[:depth]):
                below.append(spath[depth:])
        if not below:
            return value
        value = copy.deepcopy(value)

        def visit(container, key, _path):
            if isinstance(container[key], str) and container[key]:
                container[key] = REDACTED
        for rest in below:
            self._walk_one(value, rest, path, visit)
        return value

    def __repr__(self):
        return '<ConfigStore revision=%d sections=%s>' % (
            self.revision, ','.join(sorted(self._document)) or 'none')
