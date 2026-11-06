# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Finding protocol plugins: by name, or by entry point if asked.

Two registration paths, for two very different callers.

**Built-in, by name.** The protocols that ship with the package register
themselves here and an engine asks for them by name. No scanning, no import
of anything the caller did not ask for: an embedded engine that only speaks
BGP should not pay to discover that nothing else is installed.

**Entry points, on request only.** A third-party protocol can advertise
itself under the ``packets.rtengine.plugins`` group, and :func:`discover`
will find it. That scan is *not* run automatically, and the distinction
matters more than it looks: ``pkg_resources`` walks the whole working set to
build its entry-point index, which on a large environment costs a noticeable
fraction of a second and pulls in every distribution's metadata. The
standalone command pays that once at start-up because it genuinely does not
know what the operator installed; a library import must not pay it at all.

``pkg_resources`` rather than ``importlib.metadata`` because the language
floor is 3.6, where ``importlib.metadata`` does not exist.
"""

import logging

_log = logging.getLogger('packets.rtengine.plugins')

#: Setuptools entry-point group third-party plugins advertise under.
ENTRY_POINT_GROUP = 'packets.rtengine.plugins'

_builtin = {}
_discovered = None


def register(name, factory):
    """Register a built-in plugin class or factory under a name.

    :param name: the protocol name, as it appears in configuration.
    :param factory: a ``ProtocolPlugin`` subclass, or any callable
        returning an instance.
    :raises ValueError: the name is already registered. Silently replacing
        a registration would make which plugin is in use depend on import
        order.
    """
    if name in _builtin:
        raise ValueError('plugin %r is already registered' % (name,))
    _builtin[name] = factory


def builtin():
    """Return the built-in registrations.

    :return: a dict of name to factory; a copy.
    """
    return dict(_builtin)


def discover(refresh=False):
    """Scan setuptools entry points for third-party plugins.

    Cached after the first call, because the scan is the expensive part and
    a process does not gain entry points while it runs.

    A plugin whose entry point fails to import is logged and skipped rather
    than raising: one broken third-party package must not stop an engine
    from starting with the protocols that do work.

    :param refresh: re-run the scan even if it has already been done.
    :return: a dict of name to factory, entry-point plugins only.
    """
    global _discovered

    if _discovered is not None and not refresh:
        return dict(_discovered)

    found = {}
    try:
        import pkg_resources
    except ImportError:
        _log.debug('pkg_resources unavailable; no entry-point plugins')
        _discovered = found
        return dict(found)

    for entry in pkg_resources.iter_entry_points(ENTRY_POINT_GROUP):
        try:
            found[entry.name] = entry.load()
        except Exception:
            _log.exception('could not load rtengine plugin %r', entry.name)
    _discovered = found
    return dict(found)


def available(include_entry_points=False):
    """Return every plugin that can be loaded by name.

    :param include_entry_points: also run the entry-point scan.
    :return: a dict of name to factory. Built-ins win a name collision, so
        an installed package cannot shadow a shipped protocol.
    """
    found = {}
    if include_entry_points:
        found.update(discover())
    found.update(_builtin)
    return found


def load(name, include_entry_points=False):
    """Instantiate a plugin by name.

    :param name: the protocol name.
    :param include_entry_points: also consider entry-point plugins.
    :return: a new plugin instance.
    :raises KeyError: no such plugin, with the known names in the message.
    """
    factories = available(include_entry_points)
    try:
        factory = factories[name]
    except KeyError:
        raise KeyError('no rtengine plugin named %r; available: %s'
                       % (name, ', '.join(sorted(factories)) or 'none'))
    return factory()
