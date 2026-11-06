# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Everything the running configuration's policy says, as live objects.

One store per engine, owned by the core, holding the prefix-lists, the
AS-path access-lists and the route-maps a configuration document defines. It
has two jobs, and they are deliberately separate: :meth:`PolicyStore.validate`
decides whether a document is acceptable and changes nothing, and
:meth:`PolicyStore.load` makes the store match a document that has already
been accepted. The engine's ``prepare_config`` calls the first before a
commit and the second after it, which is why the first must be pure -- a
validation that half-applied a document would leave the engine filtering
against a configuration the operator's change was rejected for.

**Why version numbers are the hard part.** Every object here carries a
``version`` that is bumped on every mutation, and Stage 4's update groups key
a group on the versions of the policy objects the group depends on. That
makes the version numbers load-bearing in both directions:

* a version that fails to move when the configuration changed means peers
  keep being advertised routes computed under the old policy, and nothing
  ever corrects it -- the group's key still matches, so no recomputation is
  scheduled;
* a version that moves when the configuration did *not* change means the
  group's key changes, the whole table is re-evaluated and re-advertised to
  every peer in the group, and a configuration reload of an unrelated
  section becomes a full table refresh across the AS.

The second is the one that is easy to cause by accident, because the obvious
implementation of ``load`` -- throw the objects away and rebuild them from
the document -- does exactly that on every reload. Worse, a rebuilt object's
version restarts from zero, so a list that changed from one entry to a
different single entry comes back with the version it already had, which is
the *first* failure mode dressed up as the second. So ``load`` compares a
frozen snapshot of each object's configuration against the document and, for
anything that did not change, does nothing at all: the object keeps its
identity, its version, its counters and its trie. For anything that did
change, the *existing* object is cleared and refilled, so the version line
continues and every holder of a reference sees the new contents.

Object identity matters for the same reason. A peer or an update group holds
a reference to the route-map it applies, so replacing the object under a name
would leave them filtering against a detached copy forever.

**The two-pass load.** ``load`` validates first and then applies. Validation
builds throwaway objects with the same constructors and the same parsers the
apply pass uses, which is what makes "if validation passed, the apply cannot
fail" true by construction rather than by inspection -- and the apply pass
mutates live objects that peers are already using, so a failure in the middle
of it is not something to recover from politely. Parsing each document twice
costs microseconds on a path that runs once per configuration change.

**Reference integrity.** A route-map that names a prefix-list which does not
exist is rejected at validation. That is stricter than IOS, which accepts the
reference and treats the match as unmatched until the list appears, and the
strictness is the point: the failure mode of the permissive behaviour is a
filter that silently passes or blocks everything because of a typo in a name,
and a configuration document is submitted whole here rather than typed one
line at a time, so there is no half-built state to be tolerant of.
"""

from packets.routing.rtengine.errors import ConfigError
from packets.routing.rtengine.policy import aspath as _aspath
from packets.routing.rtengine.policy import routemap as _routemap
from packets.routing.rtengine.policy.aspath import AsPathList
from packets.routing.rtengine.policy.prefixlist import PrefixList
from packets.routing.rtengine.policy.routemap import RouteMap
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6

__all__ = ['PolicyStore', 'KINDS']

#: The object kinds :meth:`PolicyStore.version_of` and
#: :meth:`PolicyStore.names` speak. IPv4 and IPv6 prefix-lists are separate
#: kinds because they are separate namespaces -- ``ip prefix-list FOO`` and
#: ``ipv6 prefix-list FOO`` are two different lists -- and a caller citing a
#: version has to say which one it means.
KINDS = ('prefix-list', 'ipv6-prefix-list', 'route-map', 'as-path')

# Auto-numbering for an entry or clause that omits its sequence number. The
# steps are IOS': prefix-list entries come in fives and route-map clauses in
# tens, which leaves room to insert between them later. A document that
# numbers some entries and not others gets the positional number for the
# unnumbered ones, which may collide with an explicit one -- and a collision
# replaces, exactly as re-issuing a line on a router does.
_ENTRY_SEQ_STEP = 5
_CLAUSE_SEQ_STEP = 10

_PREFIX_ENTRY_KEYS = ('seq', 'action', 'prefix', 'le', 'ge')
_AS_PATH_ENTRY_KEYS = ('seq', 'action', 'regex', 'pattern')
_CLAUSE_KEYS = ('seq', 'action', 'match', 'set')


def _freeze(value):
    """Return an immutable, comparable snapshot of a document fragment.

    Used to answer one question -- "is this object's configuration the same
    as it was last time?" -- and it has to answer it without holding a
    reference into the caller's document, which the caller is free to mutate
    afterwards, and without depending on dict ordering, which two documents
    that mean the same thing need not share.

    Dicts become tuples of ``(key, frozen value)`` pairs in sorted key
    order, lists and tuples become tuples, and scalars are themselves. The
    result is hashable as well as comparable, which costs nothing here and
    lets a caller key on it later.

    :param value: any JSON-shaped fragment.
    :return: an immutable equivalent.
    """
    if isinstance(value, dict):
        # Sorted by the key's repr rather than by the key, so a document
        # with mixed key types cannot raise a TypeError here. Configuration
        # keys are strings, so this is the same order either way.
        return tuple((key, _freeze(value[key]))
                     for key in sorted(value, key=repr))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _fail(path, detail):
    """Raise a :class:`ConfigError` carrying the path it applies to.

    :param path: the dotted configuration path, e.g.
        ``'route-map.RM-IN.0.match'``.
    :param detail: the human-readable reason.
    :raises ConfigError: always.
    """
    raise ConfigError(detail, path=path)


def _section(document, *keys):
    """Read a nested section, returning an empty dict when it is absent.

    :param document: the configuration document, or None.
    :param keys: the path to walk.
    :return: the section, or ``{}`` if anything along the way is missing or
        is not a section.
    """
    node = document
    for key in keys:
        if not isinstance(node, dict):
            return {}
        node = node.get(key)
        if node is None:
            return {}
    return node


def _entry_args(entry, index, path):
    """Pull the five prefix-list entry fields out of a document entry.

    :param entry: the entry object from the document.
    :param index: its position in the list, for auto-numbering.
    :param path: the configuration path, for error messages.
    :return: ``(seq, action, prefix, le, ge)``.
    :raises ConfigError: not an object, an unknown key, or a missing
        required field.
    """
    if not isinstance(entry, dict):
        _fail(path, 'a prefix-list entry must be an object, not %s'
                    % type(entry).__name__)
    for key in sorted(entry):
        if key not in _PREFIX_ENTRY_KEYS:
            _fail(path, 'unknown prefix-list entry keyword %r; supported: %s'
                        % (key, ', '.join(_PREFIX_ENTRY_KEYS)))
    if 'action' not in entry:
        _fail(path, "a prefix-list entry needs an 'action'")
    if 'prefix' not in entry:
        _fail(path, "a prefix-list entry needs a 'prefix'")
    return (entry.get('seq', (index + 1) * _ENTRY_SEQ_STEP),
            entry['action'], entry['prefix'], entry.get('le', 0),
            entry.get('ge', 0))


def _as_path_args(entry, index, path):
    """Pull the three AS-path entry fields out of a document entry.

    ``regex`` is the documented spelling and ``pattern`` is accepted as a
    synonym, because both appear in configurations converted from other
    tools; naming both is cheaper than a support question. Exactly one must
    be present.

    :param entry: the entry object from the document.
    :param index: its position, for auto-numbering.
    :param path: the configuration path, for error messages.
    :return: ``(seq, action, regex)``.
    :raises ConfigError: not an object, an unknown key, a missing field, or
        both spellings of the regex at once.
    """
    if not isinstance(entry, dict):
        _fail(path, 'an as-path access-list entry must be an object, not %s'
                    % type(entry).__name__)
    for key in sorted(entry):
        if key not in _AS_PATH_ENTRY_KEYS:
            _fail(path, 'unknown as-path access-list keyword %r; supported: '
                        '%s' % (key, ', '.join(_AS_PATH_ENTRY_KEYS)))
    if 'action' not in entry:
        _fail(path, "an as-path access-list entry needs an 'action'")
    if 'regex' in entry and 'pattern' in entry:
        _fail(path, "an as-path access-list entry carries either 'regex' or "
                    "'pattern', not both")
    regex = entry.get('regex', entry.get('pattern'))
    if regex is None:
        _fail(path, "an as-path access-list entry needs a 'regex'")
    return (entry.get('seq', (index + 1) * _ENTRY_SEQ_STEP),
            entry['action'], regex)


def _clause_args(clause, index, path):
    """Pull the four route-map clause fields out of a document clause.

    :param clause: the clause object from the document.
    :param index: its position, for auto-numbering.
    :param path: the configuration path, for error messages.
    :return: ``(seq, action, match, set)``.
    :raises ConfigError: not an object, an unknown key, a missing action, or
        a ``continue``.
    """
    if not isinstance(clause, dict):
        _fail(path, 'a route-map clause must be an object, not %s'
                    % type(clause).__name__)
    for key in sorted(clause):
        if key == 'continue':
            # Its own message rather than "unknown keyword": the feature is
            # absent, the spelling is right, and ignoring it would change
            # what the policy does rather than what it is called.
            _fail(path, _routemap._CONTINUE_MESSAGE)
        if key not in _CLAUSE_KEYS:
            _fail(path, 'unknown route-map clause keyword %r; supported: %s'
                        % (key, ', '.join(_CLAUSE_KEYS)))
    if 'action' not in clause:
        _fail(path, "a route-map clause needs an 'action'")
    return (clause.get('seq', (index + 1) * _CLAUSE_SEQ_STEP),
            clause['action'], clause.get('match'), clause.get('set'))


class PolicyStore(object):
    """The engine's policy objects, loaded from a configuration document.

    Constructed empty. Nothing in here is protocol-specific and nothing in
    here talks to a plugin: a plugin is handed the objects it needs by name
    and consults them, which is what lets the same prefix-list filter a BGP
    session and a static-route redistribution.
    """

    __slots__ = ('_v4', '_v6', '_maps', '_as_paths', '_snapshots',
                 'revision', 'loads', 'changes')

    def __init__(self):
        self._v4 = {}
        self._v6 = {}
        self._maps = {}
        self._as_paths = {}
        # (kind, name) -> the frozen configuration the live object was built
        # from. This is what makes "unchanged means unchanged" decidable
        # without asking an object to describe itself back into document
        # form, which would be a second rendering to keep in step with the
        # parser.
        self._snapshots = {}
        #: Bumped once per :meth:`load` that changed anything.
        self.revision = 0
        self.loads = 0
        self.changes = 0

    def __repr__(self):
        return ('<PolicyStore revision=%d prefix-lists=%d/%d route-maps=%d '
                'as-path=%d>' % (self.revision, len(self._v4), len(self._v6),
                                 len(self._maps), len(self._as_paths)))

    # --- validation --------------------------------------------------------

    def validate(self, document, longest_as_path=None):
        """Check a whole document's policy sections, changing nothing.

        Called from the engine's ``prepare_config`` before a commit, so it
        must not touch this store: the document being validated may be
        rejected by a later plugin, and the running policy has to survive
        that untouched.

        Everything is validated by *building* it -- scratch prefix-lists,
        scratch as-path lists, the same match and set parsers a clause uses
        -- rather than by a second set of rules that agrees with the
        parsers by inspection. That is what makes a successful validation a
        guarantee that :meth:`load` cannot fail half-way through mutating
        live objects.

        :param document: the configuration document, or None.
        :param longest_as_path: the longest AS path, in ASNs, any protocol
            will hand to policy (BGP's ``maxas-limit``; 0 for no limit), or
            None when no protocol says. An AS-path regex whose work grows
            with the square of the path length is refused when this is 0 or
            above :data:`~packets.routing.rtengine.policy.aspath.QUADRATIC_MAX_ASNS`
            (S6-d).
        :raises ConfigError: a malformed section, an unknown match or set
            keyword, a bad community, regex, address or prefix, or a
            reference to a prefix-list or as-path list the same document
            does not define. ``path`` on the exception is the dotted
            configuration path of the offending value, e.g.
            ``'route-map.RM-IN.0.match'``.
        """
        if document is not None and not isinstance(document, dict):
            _fail(None, 'a configuration document must be an object, not %s'
                        % type(document).__name__)
        v4 = self._validate_prefix_lists(document, 'ip', AFI_IP)
        v6 = self._validate_prefix_lists(document, 'ipv6', AFI_IP6)
        as_paths = self._validate_as_paths(document)
        self._validate_route_maps(document, v4, v6, as_paths)
        if longest_as_path is not None:
            self._validate_as_path_lengths(document, longest_as_path)

    def _validate_as_path_lengths(self, document, longest):
        """Check every AS-path regex against the longest path (S6-d).

        A pass of its own, after the structural one has passed, because
        the answer depends on another section of the document -- BGP's
        ``maxas-limit`` -- and a regex appears in two places: an as-path
        access-list entry, and a route-map's inline ``match as-path``.

        :param document: the document, already validated structurally.
        :param longest: see :meth:`validate`.
        :raises ConfigError: at the entry or clause holding the pattern.
        """
        lists = _section(document, 'ip', 'as-path-access-list')
        for name in sorted(lists, key=repr):
            for index, entry in enumerate(lists[name]):
                regex = entry.get('regex', entry.get('pattern'))
                try:
                    _aspath.check_length(regex, longest)
                except ValueError as exc:
                    _fail('ip.as-path-access-list.%s.%d' % (name, index),
                          str(exc))
        maps = _section(document, 'route-map')
        for name in sorted(maps, key=repr):
            for index, clause in enumerate(maps[name]):
                found = (clause.get('match') or {}).get('as-path')
                if isinstance(found, str):
                    found = [found]
                if not isinstance(found, list):
                    continue
                for regex in found:
                    try:
                        _aspath.check_length(regex, longest)
                    except ValueError as exc:
                        _fail('route-map.%s.%d.match' % (name, index),
                              str(exc))

    def _validate_prefix_lists(self, document, section, afi):
        """Validate one family's prefix-lists and return their names.

        :param document: the document.
        :param section: ``'ip'`` or ``'ipv6'``.
        :param afi: the matching AFI.
        :return: a set of the names defined.
        :raises ConfigError: any malformed list or entry.
        """
        lists = _section(document, section, 'prefix-list')
        base = '%s.prefix-list' % section
        if not isinstance(lists, dict):
            _fail(base, 'prefix-list must be an object of name to entries')
        names = set()
        for name in sorted(lists, key=repr):
            entries = lists[name]
            path = '%s.%s' % (base, name)
            if not isinstance(name, str) or not name:
                _fail(base, 'a prefix-list name must be a non-empty string, '
                            'not %r' % (name,))
            if not isinstance(entries, list):
                _fail(path, 'a prefix-list must be a list of entries, not %s'
                            % type(entries).__name__)
            # A scratch object, not this store's: the same constructor and
            # the same add() the load pass uses, so nothing can be accepted
            # here and rejected there.
            scratch = PrefixList(name, afi)
            for index in range(len(entries)):
                entry_path = '%s.%d' % (path, index)
                args = _entry_args(entries[index], index, entry_path)
                try:
                    scratch.add(*args)
                except ValueError as exc:
                    _fail(entry_path, str(exc))
            names.add(name)
        return names

    def _validate_as_paths(self, document):
        """Validate the AS-path access-lists and return their names.

        :param document: the document.
        :return: a set of the names defined.
        :raises ConfigError: any malformed list or entry.
        """
        lists = _section(document, 'ip', 'as-path-access-list')
        base = 'ip.as-path-access-list'
        if not isinstance(lists, dict):
            _fail(base, 'as-path-access-list must be an object of name to '
                        'entries')
        names = set()
        for name in sorted(lists, key=repr):
            entries = lists[name]
            path = '%s.%s' % (base, name)
            if not isinstance(name, str) or not name:
                _fail(base, 'an as-path access-list name must be a '
                            'non-empty string, not %r' % (name,))
            if not isinstance(entries, list):
                _fail(path, 'an as-path access-list must be a list of '
                            'entries, not %s' % type(entries).__name__)
            scratch = AsPathList(name)
            for index in range(len(entries)):
                entry_path = '%s.%d' % (path, index)
                args = _as_path_args(entries[index], index, entry_path)
                try:
                    scratch.add(*args)
                except ValueError as exc:
                    _fail(entry_path, str(exc))
            names.add(name)
        return names

    def _validate_route_maps(self, document, v4, v6, as_paths):
        """Validate the route-maps, including every name they reference.

        The match and set clauses are parsed one part at a time rather than
        by building a whole clause, so that the path on a rejection names
        the part that was wrong -- ``route-map.RM-IN.0.set`` rather than the
        clause -- which is the difference between an operator finding the
        typo and searching for it.

        :param document: the document.
        :param v4: the IPv4 prefix-list names the document defines.
        :param v6: the IPv6 prefix-list names.
        :param as_paths: the as-path access-list names.
        :raises ConfigError: any malformed clause, or a reference to a name
            the document does not define.
        """
        maps = _section(document, 'route-map')
        if not isinstance(maps, dict):
            _fail('route-map', 'route-map must be an object of name to '
                               'clauses')
        defined = {'prefix-list': v4, 'ipv6-prefix-list': v6,
                   'as-path': as_paths}
        for name in sorted(maps, key=repr):
            clauses = maps[name]
            path = 'route-map.%s' % (name,)
            if not isinstance(name, str) or not name:
                _fail('route-map', 'a route-map name must be a non-empty '
                                   'string, not %r' % (name,))
            if not isinstance(clauses, list):
                _fail(path, 'a route-map must be a list of clauses, not %s'
                            % type(clauses).__name__)
            for index in range(len(clauses)):
                clause_path = '%s.%d' % (path, index)
                seq, action, match, edits = _clause_args(clauses[index],
                                                         index, clause_path)
                try:
                    _routemap.seq_number(seq)
                    _routemap.action_id(action)
                except ValueError as exc:
                    _fail(clause_path, str(exc))
                # The module's own parsers, reached directly so that the
                # match and the set can be reported separately. They are
                # private to the package, not to this module.
                try:
                    tests = _routemap._parse_match(match)
                except ValueError as exc:
                    _fail('%s.match' % clause_path, str(exc))
                try:
                    _routemap._parse_set(edits)
                except ValueError as exc:
                    _fail('%s.set' % clause_path, str(exc))
                for kind, target in sorted(_references(tests)):
                    if target not in defined[kind]:
                        _fail('%s.match' % clause_path,
                              'route-map %s references %s %r, which this '
                              'document does not define'
                              % (name, kind, target))

    # --- loading -----------------------------------------------------------

    def load(self, document):
        """Make this store match a document, preserving what did not change.

        Idempotent: loading the same document twice changes nothing the
        second time, and every object keeps its identity, its ``version``
        and its counters. That is not a nicety -- see the module docstring
        -- it is what keeps a configuration reload from re-advertising every
        table to every peer.

        The document is validated first, so a rejection happens before any
        live object is touched.

        :param document: the configuration document. None or an empty
            document removes everything, which is what deleting the last
            policy section means.
        :return: the number of objects created, changed or removed.
        :raises ConfigError: anything :meth:`validate` rejects. The store is
            unchanged when this is raised.
        """
        self.validate(document)
        changed = 0
        changed += self._load_prefix_lists(document, 'ip', AFI_IP, self._v4,
                                           'prefix-list')
        changed += self._load_prefix_lists(document, 'ipv6', AFI_IP6,
                                           self._v6, 'ipv6-prefix-list')
        changed += self._load_as_paths(document)
        changed += self._load_route_maps(document)
        self.loads += 1
        if changed:
            self.revision += 1
            self.changes += changed
        return changed

    def _load_prefix_lists(self, document, section, afi, table, kind):
        """Create, refresh and remove one family's prefix-lists.

        :param document: the document.
        :param section: ``'ip'`` or ``'ipv6'``.
        :param afi: the matching AFI.
        :param table: the dict of live lists for that family.
        :param kind: the snapshot kind, also what ``version_of`` is asked
            for.
        :return: the number of lists created, changed or removed.
        """
        wanted = _section(document, section, 'prefix-list')
        changed = 0
        for name in sorted(wanted):
            entries = wanted[name]
            snapshot = _freeze(entries)
            key = (kind, name)
            plist = table.get(name)
            if plist is not None and self._snapshots.get(key) == snapshot:
                # Byte for byte the same configuration. Touching it at all
                # would bump its version and re-advertise every table that
                # cites it.
                continue
            if plist is None:
                plist = PrefixList(name, afi)
                table[name] = plist
            else:
                # Cleared and refilled rather than replaced, so that the
                # version line continues and every peer holding a reference
                # sees the new entries.
                plist.clear()
            for index in range(len(entries)):
                plist.add(*_entry_args(entries[index], index,
                                       '%s.prefix-list.%s.%d'
                                       % (section, name, index)))
            self._snapshots[key] = snapshot
            changed += 1
        for name in sorted(table):
            if name not in wanted:
                del table[name]
                self._snapshots.pop((kind, name), None)
                changed += 1
        return changed

    def _load_as_paths(self, document):
        """Create, refresh and remove the AS-path access-lists.

        :param document: the document.
        :return: the number of lists created, changed or removed.
        """
        wanted = _section(document, 'ip', 'as-path-access-list')
        changed = 0
        for name in sorted(wanted):
            entries = wanted[name]
            snapshot = _freeze(entries)
            key = ('as-path', name)
            alist = self._as_paths.get(name)
            if alist is not None and self._snapshots.get(key) == snapshot:
                continue
            if alist is None:
                alist = AsPathList(name)
                self._as_paths[name] = alist
            else:
                alist.clear()
            for index in range(len(entries)):
                alist.add(*_as_path_args(entries[index], index,
                                         'ip.as-path-access-list.%s.%d'
                                         % (name, index)))
            self._snapshots[key] = snapshot
            changed += 1
        for name in sorted(self._as_paths):
            if name not in wanted:
                del self._as_paths[name]
                self._snapshots.pop(('as-path', name), None)
                changed += 1
        return changed

    def _load_route_maps(self, document):
        """Create, refresh and remove the route-maps.

        :param document: the document.
        :return: the number of maps created, changed or removed.
        """
        wanted = _section(document, 'route-map')
        changed = 0
        for name in sorted(wanted):
            clauses = wanted[name]
            snapshot = _freeze(clauses)
            key = ('route-map', name)
            rmap = self._maps.get(name)
            if rmap is not None and self._snapshots.get(key) == snapshot:
                continue
            if rmap is None:
                # `self` as the resolver: the clauses look their
                # prefix-lists and as-path lists up by name on every
                # application, so a list replaced later is picked up without
                # the map being rebuilt.
                rmap = RouteMap(name, self)
                self._maps[name] = rmap
            else:
                rmap.clear()
            for index in range(len(clauses)):
                rmap.add_clause(*_clause_args(clauses[index], index,
                                              'route-map.%s.%d'
                                              % (name, index)))
            self._snapshots[key] = snapshot
            changed += 1
        for name in sorted(self._maps):
            if name not in wanted:
                del self._maps[name]
                self._snapshots.pop(('route-map', name), None)
                changed += 1
        return changed

    # --- accessors ---------------------------------------------------------

    def prefix_list(self, name, afi=None):
        """Return a prefix-list, or None.

        :param name: the list name.
        :param afi: ``AFI_IP``, ``AFI_IP6``, or None to search IPv4 and
            then IPv6. The families are separate namespaces, so a caller
            that knows which it wants should say: a route-map's ``ip``
            clause asks for IPv4 explicitly, and would otherwise match
            against an IPv6 list of the same name.
        :return: the :class:`~..prefixlist.PrefixList`, or None if no list
            of that name exists in the family asked for. An unknown AFI is
            a miss rather than an error, for the same reason a family
            mismatch is a miss inside the list itself.
        """
        if afi is None:
            found = self._v4.get(name)
            if found is None:
                found = self._v6.get(name)
            return found
        if afi == AFI_IP:
            return self._v4.get(name)
        if afi == AFI_IP6:
            return self._v6.get(name)
        return None

    def route_map(self, name):
        """Return a route-map, or None.

        :param name: the map name.
        :return: the :class:`~..routemap.RouteMap`, or None.
        """
        return self._maps.get(name)

    def as_path_list(self, name):
        """Return an AS-path access-list, or None.

        :param name: the list name.
        :return: the :class:`~..aspath.AsPathList`, or None.
        """
        return self._as_paths.get(name)

    def names(self):
        """Return every defined name, by kind.

        :return: a dict keyed by the entries of :data:`KINDS`, each holding
            a sorted list of names.
        """
        return {
            'prefix-list': sorted(self._v4),
            'ipv6-prefix-list': sorted(self._v6),
            'route-map': sorted(self._maps),
            'as-path': sorted(self._as_paths),
        }

    def version_of(self, kind, name):
        """Return the version of one object, or None if it is not defined.

        This is what an update-group key is built from, so the "not
        defined" answer is a value rather than an exception: a group whose
        route-map has been deleted needs a key that differs from the one it
        had, not a traceback, and the deletion is handled by the group being
        rebuilt. None rather than 0 (P-6), because 0 is also the version of
        an object that exists and has never been edited -- a list defined
        with no entries -- and "absent" and "present but empty" can filter
        differently, so they must not share a key.

        :param kind: one of :data:`KINDS`.
        :param name: the object name.
        :return: the object's ``version``, or None when there is no such
            object.
        :raises ValueError: an unknown kind. Unlike an unknown name, that is
            a programming error rather than a configuration state.
        """
        if kind == 'prefix-list':
            found = self._v4.get(name)
        elif kind == 'ipv6-prefix-list':
            found = self._v6.get(name)
        elif kind == 'route-map':
            found = self._maps.get(name)
        elif kind == 'as-path':
            found = self._as_paths.get(name)
        else:
            raise ValueError('unknown policy kind %r; expected one of %s'
                             % (kind, ', '.join(KINDS)))
        return None if found is None else found.version

    # --- show helpers ------------------------------------------------------

    def prefix_list_dict(self, name=None):
        """Render the prefix-lists for ``show ip prefix-list``.

        Both families in one response, each entry carrying its own ``afi``,
        because the question an operator asks is about a name and they
        should not have to know which namespace it landed in.

        :param name: one list name, or None for all of them.
        :return: ``{'items': [...]}``; ``items`` is empty for a name that
            is not defined, which is what ``show`` of a nonexistent list
            should say rather than raising.
        """
        items = []
        for table in (self._v4, self._v6):
            for key in sorted(table):
                if name is None or key == name:
                    items.append(table[key].as_dict())
        return {'items': items}

    def route_map_dict(self, name=None):
        """Render the route-maps for ``show route-map``.

        :param name: one map name, or None for all of them.
        :return: ``{'items': [...]}``.
        """
        items = []
        for key in sorted(self._maps):
            if name is None or key == name:
                items.append(self._maps[key].as_dict())
        return {'items': items}

    def as_path_list_dict(self, name=None):
        """Render the AS-path access-lists for show output.

        :param name: one list name, or None for all of them.
        :return: ``{'items': [...]}``.
        """
        items = []
        for key in sorted(self._as_paths):
            if name is None or key == name:
                items.append(self._as_paths[key].as_dict())
        return {'items': items}

    def stats(self):
        """Return counters for health output.

        ``revision`` is the number a caller compares to decide whether any
        policy changed at all since it last looked, which is cheaper than
        asking every object for its version.

        :return: a dict of plain types.
        """
        return {
            'revision': self.revision,
            'loads': self.loads,
            'changes': self.changes,
            'prefix-lists': len(self._v4),
            'ipv6-prefix-lists': len(self._v6),
            'route-maps': len(self._maps),
            'as-path-lists': len(self._as_paths),
            'prefix-list-entries': sum(len(p) for p in self._v4.values())
            + sum(len(p) for p in self._v6.values()),
            'route-map-clauses': sum(len(m) for m in self._maps.values()),
        }


def _references(tests):
    """Collect the policy objects a tuple of compiled matchers depends on.

    :param tests: compiled match conditions.
    :return: a set of ``(kind, name)`` pairs.
    """
    found = set()
    for test in tests:
        found.update(test.references())
    return found
