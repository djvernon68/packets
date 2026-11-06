# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Which forwarding sink an ``ip.route`` section asks for (L-6).

The engine used to take whatever sink its constructor was handed and fall
back to a ``NullSink``, and the stock ``rtengine`` command never handed it
one -- so ``ip route install`` could be configured, but not from the
command or the REST API that exist to configure it. The engine now asks
this module instead, inside the same transaction that applies the rest of
the core configuration, so ``PATCH /ip/route {"install": true}`` and a
config file saying the same thing take the same path.

Three rules, and they are the whole module:

* **install off is a ``NullSink``.** Not an unopened ``NetlinkSink``: an
  engine that is not installing holds no netlink object at all, so there
  is nothing that could open a socket by mistake.
* **install on is a ``NetlinkSink``**, built from the section but never
  opened here -- the engine opens it once it is running, which keeps
  construction and ``--check`` free of side effects.
* **install on where it cannot work is a configuration error**, at the
  moment it is configured: not Linux, no netlink in this CPython, or a
  process without ``CAP_NET_ADMIN``. Accepting it would leave every route
  in ``fib-error`` with EPERM and an operator reading health to find out
  why.
"""

from packets.routing.rtengine.errors import ConfigError
from packets.routing.rtengine.fib import netlink
from packets.routing.rtengine.fib.sink import NullSink

__all__ = ['sink_spec', 'check_installable', 'make_sink']

# The kernel's own tables, refused as targets. 0 is RT_TABLE_UNSPEC, which a
# route add silently turns into "main" -- an operator who wrote 0 did not
# mean main, or they would have written 254. 255 is the local table, which
# the kernel populates with the host's own addresses; writing gateway routes
# there shadows them.
_REFUSED_TABLES = {netlink.RT_TABLE_UNSPEC: 'unspec',
                   netlink.RT_TABLE_LOCAL: 'local'}


def sink_spec(route_cfg):
    """Return what kind of sink a section asks for, as a comparable value.

    Two sections with the same spec need the same sink, so a commit that
    changes nothing in it -- a static route, ``retain-on-shutdown``, a
    route-map -- keeps the running one and its installed routes. Anything
    that changes how a route is keyed in the kernel (table, protocol,
    priorities) needs a new one, because the old routes cannot be renamed
    in place.

    :param route_cfg: the ``ip.route`` section, or None.
    :return: None when install is off, else a tuple.
    """
    cfg = route_cfg or {}
    if cfg.get('install') is not True:
        return None
    priority = cfg.get('priority') or {}
    return ('netlink',
            int(cfg.get('table', netlink.RT_TABLE_MAIN)),
            int(cfg.get('protocol', netlink.DEFAULT_PROTOCOL)),
            int(priority.get('ebgp', netlink.DEFAULT_PRIORITY_EBGP)),
            int(priority.get('ibgp', netlink.DEFAULT_PRIORITY_IBGP)))


def check_installable(route_cfg, capabilities=None):
    """Refuse an ``install: true`` this host or process cannot honour.

    Only probes when install is on: the probe opens (and closes) a netlink
    socket, and an engine that is not installing must not touch netlink at
    all.

    :param route_cfg: the ``ip.route`` section, or None.
    :param capabilities: a :func:`netlink.capabilities` answer to judge
        instead of probing; tests pass one.
    :raises ConfigError: install is on and cannot work here.
    """
    spec = sink_spec(route_cfg)
    if spec is None:
        return
    table = spec[1]
    if table in _REFUSED_TABLES:
        raise ConfigError(
            'routing table %d (%s) cannot be the install target; use 254 '
            '(main) or a table of your own' % (table, _REFUSED_TABLES[table]),
            path='ip.route.table')
    caps = capabilities if capabilities is not None \
        else netlink.capabilities()
    if not caps.get('supported'):
        raise ConfigError(
            'kernel FIB install is not available on this host (%s); '
            'ip.route.install needs Linux rtnetlink'
            % caps.get('reason', 'unsupported platform'),
            path='ip.route.install')
    if not caps.get('privileged'):
        raise ConfigError(
            'kernel FIB install needs CAP_NET_ADMIN, which this process '
            'does not have (%s)' % caps.get('reason', 'unprivileged'),
            path='ip.route.install')


def make_sink(route_cfg, **kwargs):
    """Build the sink a section asks for, unopened.

    :param route_cfg: the ``ip.route`` section, or None.
    :param kwargs: passed to :func:`netlink.make_sink` for a netlink sink;
        ``transport=`` is how a test substitutes a fake socket.
    :return: a ``NullSink``, or an unopened ``NetlinkSink``.
    :raises ConfigError: the table or protocol is out of range.
    """
    if sink_spec(route_cfg) is None:
        return NullSink()
    try:
        return netlink.make_sink(route_cfg, **kwargs)
    except ValueError as exc:
        raise ConfigError(str(exc), path='ip.route')
