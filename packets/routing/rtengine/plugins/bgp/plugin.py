# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""``BGPPlugin``: BGP as the engine sees it.

The core knows nothing about BGP. It knows there is a plugin that owns the
``router bgp`` section of the configuration, needs tables for certain
address families, offers protocol-neutral routes to the ``GlobalRib``, and
answers some ``show`` paths. Everything protocol-specific -- attributes,
the decision process, sessions, the RFC 7606 matrix -- lives behind this
class.

Three decisions shape the file.

**One BGP instance.** ``router bgp`` takes exactly one AS, enforced by the
schema rather than by code, so a second one is rejected with a path and a
message instead of silently winning. Multi-instance BGP means VRFs, and
VRFs are not a thing this engine has yet; allowing the configuration now
would mean inventing semantics we would have to break later.

**Configuration is two-phase, and the expensive half is the second.**
:meth:`prepare_config` is pure and does every check it can, because a
rejection there costs nothing while a failure in :meth:`commit_config`
leaves the engine rolling other plugins back. In particular, a neighbour
whose authentication cannot be satisfied on this kernel is rejected at
prepare time, not discovered at connect time.

**A configuration change resets only what it must.** Changing a
description, a maximum-prefix limit or a weight does not disturb a
session; changing the remote AS, the authentication, the update source or
the negotiated capability set does, because those are things the two ends
agreed on at OPEN and cannot renegotiate mid-session. The set of
session-affecting keys is a named constant rather than a condition buried
in the commit, because getting it wrong is either a session that flaps on
a cosmetic edit or one that silently keeps running with stale settings.
"""

import logging

from packets.routing.rtengine import errors as engine_errors
from packets.routing.rtengine import health as health_mod
from packets.routing.rtengine.plugin import ProtocolPlugin
from packets.routing.rtengine.rib.prefix import (
    AFI_IP, AFI_IP6, SAFI_UNICAST, parse_prefix)
from packets.routing.rtengine.rib.table import PROTO_BGP
from packets.routing.rtengine.plugins.bgp import (
    adjout as adjout_mod, attrs as attrs_mod, bestpath, capabilities,
    errors as bgp_errors, locrib as locrib_mod, peer as peer_mod,
    policy as policy_mod, show as show_mod, updategroup as ug_mod)
from packets.routing.rtengine.transport import auth as auth_mod
from packets.routing.rtengine.transport import tcp as tcp_mod


LOG = logging.getLogger(__name__)

# The configuration spells an address family as two nested keys,
# ``address-family.ipv4.unicast``, because that is the shape config.py
# already validates with its ``afi`` and ``safi`` key types -- the core
# defined that vocabulary for this plugin to use, and inventing a flat
# 'ipv4 unicast' key here would mean a second spelling of the same idea
# that the core could not check.
AFI_NAMES = {'ipv4': AFI_IP, 'ipv6': AFI_IP6}
SAFI_NAMES = {'unicast': SAFI_UNICAST}
AFI_LABELS = {AFI_IP: 'ipv4', AFI_IP6: 'ipv6'}
SAFI_LABELS = {SAFI_UNICAST: 'unicast'}


def _af_pair(afi_name, safi_name):
    """Turn two configuration keys into an ``(afi, safi)`` tuple.

    :param afi_name: ``ipv4`` or ``ipv6``.
    :param safi_name: ``unicast``.
    :return: the pair, or None if either name is unknown.
    """
    afi = AFI_NAMES.get(afi_name)
    safi = SAFI_NAMES.get(safi_name)
    if afi is None or safi is None:
        return None
    return (afi, safi)


def _af_families(block):
    """Walk a nested ``address-family`` block, yielding pair and body.

    :param block: the ``address-family`` subtree, possibly None.
    :return: an iterator of ``(afi_name, safi_name, (afi, safi), body)``;
        unknown names come back with a pair of None so the caller can
        report them against the right configuration path.
    """
    for afi_name, safi_block in (block or {}).items():
        for safi_name, body in (safi_block or {}).items():
            yield (afi_name, safi_name, _af_pair(afi_name, safi_name),
                   body or {})


# Changing any of these renegotiates something the two ends agreed on in
# OPEN, or changes the transport itself, so the session has to be reset.
# Everything not in this set is applied to a running session in place.
SESSION_AFFECTING = frozenset([
    'remote-as', 'local-as', 'password', 'ao', 'update-source',
    'ttl-security', 'ebgp-multihop', 'passive', 'shutdown', 'timers',
    'capability', 'port',
])

# How often the advertisement pass runs when there is work. This is the
# floor on how often anything is sent at all; a neighbour's
# ``advertisement-interval`` (RFC 4271's MRAI, applied per update group in
# ``updategroup.py``) damps it further, and is off by default precisely
# because this interval already collapses a flapping prefix into one
# message per pass.
ADVERTISE_INTERVAL = 0.5

# Directions, spelled once. The configuration, the policy chains and the
# `clear ... soft` argument all use these words, and a typo in one of
# three string literals is a filter that silently does nothing.
DIR_IN = 'in'
DIR_OUT = 'out'

DEFAULT_DISTANCE_EBGP = 20
DEFAULT_DISTANCE_IBGP = 200
DEFAULT_LOCAL_PREF = 100
DEFAULT_HOLD_TIME = 90


def resolve_timers(instance, nbr):
    """Return a neighbour's effective ``(hold, keepalive, connect-retry,
    delay-open)``: neighbour, then instance, then built-in (L-5).

    IOS's ``timers bgp`` under ``router bgp`` is the default for every
    neighbour that has no ``neighbor timers`` of its own; the instance
    block here was accepted, documented as that default, and ignored, so
    every neighbour proposed 90 seconds whatever the instance said. One
    function, used for validation and for building the session, so the
    two cannot disagree about which value applies.

    The keepalive follows the hold time it was configured with. A
    neighbour that sets its own hold time but no keepalive gets the
    derived one (a third), not the instance's keepalive, which was chosen
    for a different hold time and may not even be below this one.

    :param instance: the ``router bgp <asn>`` body, or None.
    :param nbr: the neighbour body.
    :return: a 4-tuple; keepalive may be None, meaning "hold / 3".
    """
    inst = (instance or {}).get('timers') or {}
    own = (nbr or {}).get('timers') or {}
    if 'hold-time' in own:
        hold = own['hold-time']
        keepalive = own.get('keepalive')
    else:
        hold = inst.get('hold-time', DEFAULT_HOLD_TIME)
        keepalive = own['keepalive'] if 'keepalive' in own \
            else inst.get('keepalive')
    return (hold, keepalive, own.get('connect-retry', 120),
            own.get('delay-open', 0))


def _check_timers(hold, keepalive, path):
    """Raise ConfigError for a hold/keepalive pair that cannot work."""
    if hold and hold < 3:
        raise engine_errors.ConfigError(
            'hold-time must be 0 to disable the timers, or at least 3',
            path=path + '.hold-time')
    if keepalive is not None and hold and keepalive >= hold:
        raise engine_errors.ConfigError(
            'keepalive %d must be less than hold-time %d, or this peer '
            'will time out before it sends' % (keepalive, hold),
            path=path + '.keepalive')


def _directional_name():
    """Return the schema for an ``in``/``out`` pair of policy names.

    One fragment, called by all three policy keys, so the three cannot
    drift apart and an operator only has to learn the shape once. A
    function rather than a constant for the reason :func:`_neighbor_schema`
    gives: the schema document is handed to the API layer, and a shared
    mutable fragment appearing at six places in it could be edited at one
    of them and change what the engine accepts at the other five.

    :return: a fresh schema dict.
    """
    return {
        'type': 'dict',
        'keys': {
            'in': {'type': 'str', 'minlen': 1},
            'out': {'type': 'str', 'minlen': 1},
        },
    }


def _neighbor_schema():
    """The schema for one ``neighbor`` entry.

    Written as a function rather than a module constant so the nested
    dicts are built once per call and cannot be mutated by a caller that
    got hold of the plugin's schema -- ``config.py`` hands this document
    to the API layer, and a shared mutable default that the API edited
    would change what the engine accepts.
    """
    return {
        'type': 'dict',
        'keys': {
            'remote-as': {'type': 'int', 'min': 1, 'max': 4294967295,
                          'required': True},
            'local-as': {'type': 'int', 'min': 1, 'max': 4294967295},
            'description': {'type': 'str'},
            'shutdown': {'type': 'bool', 'default': False},
            'passive': {'type': 'bool', 'default': False},
            'update-source': {'type': 'addr'},
            'port': {'type': 'int', 'min': 1, 'max': 65535,
                     'default': tcp_mod.BGP_PORT},
            # 'secret' rather than 'str' so config.py redacts it in
            # `show running-config` and in the API. A password that shows
            # up in a support bundle is a password that has to be rotated.
            'password': {'type': 'secret', 'minlen': 1},
            'ao': {
                'type': 'dict',
                'keys': {
                    'key-chain': {'type': 'str', 'required': True},
                    'send-id': {'type': 'int', 'min': 0, 'max': 255},
                    'recv-id': {'type': 'int', 'min': 0, 'max': 255},
                    'algorithm': {'type': 'str',
                                  'choices': ['cmac-aes-128', 'hmac-sha1']},
                    # Must be set explicitly, and only takes effect with a
                    # password configured. See Key Decision 8: a silent
                    # downgrade from AO to MD5 is a security regression,
                    # so it has to be asked for in writing.
                    'fallback-md5': {'type': 'bool', 'default': False},
                },
            },
            'ttl-security': {'type': 'int', 'min': 1, 'max': 254},
            'ebgp-multihop': {'type': 'int', 'min': 1, 'max': 255},
            'weight': {'type': 'int', 'min': 0, 'max': 65535, 'default': 0},
            # Inbound only: how many times *our* AS may appear in a path
            # we accept. It used to relax the outbound loop check too
            # (B-5); that is now `sender-loop-check`.
            'allowas-in': {'type': 'int', 'min': 0, 'max': 10, 'default': 0},
            # Suppress paths that already contain the peer's AS. Turned
            # off only for a peer configured to accept its own AS -- its
            # `allowas-in` -- which nothing on our side can see.
            'sender-loop-check': {'type': 'bool', 'default': True},
            'next-hop-self': {'type': 'bool', 'default': False},
            # true (IOS's plain form: only from a path that is entirely
            # private), false, or "all" (from any path). 'any' because the
            # schema language has no bool-or-string; _prepare_neighbor
            # checks it (B-4).
            'remove-private-as': {'type': 'any', 'default': False},
            'as-override': {'type': 'bool', 'default': False},
            'send-community': {'type': 'bool', 'default': True},
            # RFC 4271's MinRouteAdvertisementInterval. Default 0, and
            # deliberately not IOS's 30 seconds for an external peer: the
            # advertisement pass above already coalesces, and a default
            # that held the first full table for half a minute would make
            # every fresh session look broken. An operator who wants the
            # conventional damping configures it, which is also the only
            # way to be sure it is what they meant.
            'advertisement-interval': {'type': 'int', 'min': 0,
                                       'max': 600, 'default': 0},
            'maximum-prefix': {
                'type': 'dict',
                'keys': {
                    'limit': {'type': 'int', 'min': 1, 'max': 4294967295},
                    'warning-percent': {'type': 'int', 'min': 1, 'max': 100,
                                        'default': 75},
                },
            },
            'timers': {
                'type': 'dict',
                'keys': {
                    'hold-time': {'type': 'int', 'min': 0, 'max': 65535,
                                  'default': 90},
                    'keepalive': {'type': 'int', 'min': 0, 'max': 65535},
                    'connect-retry': {'type': 'int', 'min': 1, 'max': 65535,
                                      'default': 120},
                    'delay-open': {'type': 'int', 'min': 0, 'max': 65535,
                                   'default': 0},
                },
            },
            'capability': {
                'type': 'dict',
                'keys': {
                    'route-refresh': {'type': 'bool', 'default': True},
                    'extended-message': {'type': 'bool', 'default': False},
                    'add-path-receive': {'type': 'bool', 'default': False},
                    'graceful-restart': {'type': 'int', 'min': 1,
                                         'max': 4095},
                },
            },
            'address-family': {
                'type': 'dict',
                'key_type': 'afi',
                'value': {
                    'type': 'dict',
                    'key_type': 'safi',
                    'value': {
                        'type': 'dict',
                        'keys': {
                            'activate': {'type': 'bool', 'default': True},
                            # Policy is per neighbour *and* per family,
                            # which is where IOS puts it too: the same
                            # neighbour legitimately filters IPv4 and
                            # IPv6 differently, and a single per-neighbour
                            # route-map could not express that.
                            #
                            # Three objects rather than one because they
                            # answer different questions and compose:
                            # a prefix-list filters on the NLRI, a
                            # filter-list on the AS path, and a route-map
                            # can do both and rewrite attributes as well.
                            # They run in that order; see policy.py.
                            'route-map': _directional_name(),
                            'prefix-list': _directional_name(),
                            'filter-list': _directional_name(),
                            # Per-family override of the neighbour-wide
                            # setting, because next-hop-self is an IPv6
                            # question far more often than an IPv4 one.
                            'next-hop-self': {'type': 'bool'},
                            # The next hop to advertise in this family
                            # when we set it ourselves (L-4). Needed for
                            # IPv6 over an IPv4 session, which otherwise
                            # gets the IPv4-mapped form of our address.
                            'next-hop': {'type': 'addr'},
                        },
                    },
                },
            },
        },
    }


def _address_family_schema():
    """The schema for one ``address-family`` block."""
    return {
        'type': 'dict',
        'keys': {
            'network': {
                'type': 'dict',
                'key_type': 'prefix',
                'value': {
                    'type': 'dict',
                    'keys': {
                        # RFC 4271 requires a `network` to be backed by
                        # something in the IGP or the local table. Off by
                        # default here because a control-plane speaker
                        # with no forwarding plane has nothing to check
                        # against, which is the same reasoning the core
                        # applies to next-hop validation.
                        'import-check': {'type': 'bool', 'default': False},
                        'route-map': {'type': 'str'},
                    },
                },
            },
            'maximum-paths': {'type': 'int', 'min': 1, 'max': 64,
                              'default': 1},
            'maximum-paths-ibgp': {'type': 'int', 'min': 1, 'max': 64,
                                   'default': 1},
            'distance': {
                'type': 'dict',
                'keys': {
                    'external': {'type': 'int', 'min': 1, 'max': 255,
                                 'default': DEFAULT_DISTANCE_EBGP},
                    'internal': {'type': 'int', 'min': 1, 'max': 255,
                                 'default': DEFAULT_DISTANCE_IBGP},
                },
            },
        },
    }


class BGPPlugin(ProtocolPlugin):
    """The BGP protocol plugin.

    :param clock: monotonic clock, injected so the two-engine convergence
        test and the FSM tests can share one fake.
    """

    name = 'bgp'
    config_section = ('router', 'bgp')
    protocol_id = PROTO_BGP
    admin_distance = {'external': DEFAULT_DISTANCE_EBGP,
                      'internal': DEFAULT_DISTANCE_IBGP}

    def __init__(self, clock=None):
        ProtocolPlugin.__init__(self)
        self.clock = clock
        self.local_as = 0
        self.router_id = 0
        self.config = {}
        self.attr_table = attrs_mod.AttrTable()
        self.locribs = {}
        self.peers = {}
        self.networks = {}
        # The configured `network` statements, separate from the ones
        # actually originated above: see _sync_networks.
        self.network_config = {}
        self.bestpath_config = {}
        self.default_local_pref = DEFAULT_LOCAL_PREF
        self.maxas_limit = peer_mod.DEFAULT_MAXAS_LIMIT
        # Neighbours already warned about an IPv4-mapped IPv6 next hop.
        self._mapped_warned = set()
        self.listeners = []
        self.groups = ug_mod.UpdateGroupManager(clock=self._now)
        self.next_hop_validation = False
        # address -> {af: policy identity}, for the inbound direction.
        # See _inbound_policy and policy_changed.
        self._in_policy_id = {}
        self._af = set()
        self._task = None
        self._started = False
        # Closes of removed sessions still getting their NOTIFICATION out;
        # see closing().
        self._closing = set()
        # Sessions that have just come up and still owe an End-of-RIB.
        # Before Stage 4 this also meant "send this peer the whole table";
        # that part now belongs to the update group, which either has to
        # be seeded from the Loc-RIB because it is new or replays its
        # record to the new member because it is not.
        self._dirty_peers = set()
        # The GlobalRib selection counter and the resolver's generation as
        # of the last next-hop revalidation. Reachability can only have
        # changed if the core has selected something or the resolver's own
        # inputs changed since we last looked; see _revalidate. The
        # selection counter alone missed a static or resolve-via-default
        # change (S6-c), because statics never enter the GlobalRib.
        self._nh_marker = None

    # --- identity ----------------------------------------------------------

    def afi_safi(self):
        """Return the families configured under ``address-family``.

        Derived from configuration rather than fixed, so an IPv4-only
        deployment does not cause an empty IPv6 table to exist -- which is
        exactly the contract the core documents for this method.
        """
        if self._af:
            return tuple(sorted(self._af))
        return ((AFI_IP, SAFI_UNICAST),)

    def config_schema(self):
        """Return the ``router bgp`` schema.

        ``max_keys`` is 1: ``router bgp`` takes one AS. The core turns
        that into a 409 rather than a 400, because a second instance is a
        well-formed document that collides with a stated limit rather
        than a malformed one.
        """
        return {
            'type': 'dict',
            'key_type': 'asn',
            'max_keys': 1,
            'value': {
                'type': 'dict',
                'keys': {
                    'router-id': {'type': 'addr'},
                    'log-neighbor-changes': {'type': 'bool',
                                             'default': True},
                    # IOS `bgp default local-preference`: the LOCAL_PREF a
                    # path without one is ranked as, and given towards
                    # internal peers (B-7).
                    'default-local-preference': {
                        'type': 'int', 'min': 0, 'max': 4294967295,
                        'default': DEFAULT_LOCAL_PREF},
                    # IOS `bgp maxas-limit` (P-2): a received path with
                    # more ASNs than this is treated as withdrawn. On by
                    # default, unlike IOS, because it is also what bounds
                    # the string every AS-path regex runs over. 0 is off.
                    'maxas-limit': {
                        'type': 'int', 'min': 0, 'max': 2000,
                        'default': peer_mod.DEFAULT_MAXAS_LIMIT},
                    'bestpath': {
                        'type': 'dict',
                        'keys': {
                            'always-compare-med': {'type': 'bool',
                                                   'default': False},
                            'deterministic-med': {'type': 'bool',
                                                  'default': True},
                            'med-missing-as-worst': {'type': 'bool',
                                                     'default': False},
                            'compare-routerid': {'type': 'bool',
                                                 'default': False},
                            'as-path-ignore': {'type': 'bool',
                                               'default': False},
                            'as-path-multipath-relax': {'type': 'bool',
                                                        'default': False},
                        },
                    },
                    'timers': {
                        'type': 'dict',
                        'keys': {
                            'hold-time': {'type': 'int', 'min': 0,
                                          'max': 65535, 'default': 90},
                            'keepalive': {'type': 'int', 'min': 0,
                                          'max': 65535, 'default': 30},
                        },
                    },
                    'listen': {
                        'type': 'dict',
                        'keys': {
                            'address': {'type': 'addr'},
                            'port': {'type': 'int', 'min': 1, 'max': 65535,
                                     'default': tcp_mod.BGP_PORT},
                        },
                    },
                    # Next-hop validation for received paths, off by
                    # default for the same reason the core's is: a
                    # control-plane speaker with no forwarding plane has
                    # nothing to validate against, and refusing every
                    # path on a machine with no routes would be a
                    # spectacular own goal. With it on, a path whose next
                    # hop does not resolve in the GlobalRib stays in the
                    # table, wins nothing and is advertised to nobody.
                    'next-hop-validation': {'type': 'bool',
                                            'default': False},
                    'neighbor': {'type': 'dict', 'key_type': 'addr',
                                 'value': _neighbor_schema()},
                    'address-family': {
                        'type': 'dict',
                        'key_type': 'afi',
                        'value': {'type': 'dict', 'key_type': 'safi',
                                  'value': _address_family_schema()},
                    },
                },
            },
        }

    # --- configuration -----------------------------------------------------

    def prepare_config(self, section, diff):
        """Validate the proposed BGP configuration. Pure.

        Everything checkable happens here: the schema has already agreed
        the document is well-formed, so what is left is the semantics it
        cannot express -- an unknown address family, a neighbour asking
        for authentication this kernel cannot provide, a GTSM setting the
        platform cannot enforce inbound, a keepalive that would outlive
        its hold time.

        :param section: the proposed ``router bgp`` subtree.
        :param diff: the diff for this section.
        :raises ConfigError: the change is not acceptable.
        """
        if not section:
            return
        if len(section) > 1:
            raise engine_errors.ConfigError(
                'only one BGP instance is supported; got AS %s'
                % ', '.join(str(k) for k in sorted(section)))
        for asn, body in section.items():
            self._prepare_instance(asn, body)

    def _prepare_instance(self, asn, body):
        for afi_name, safi_name, af, af_body in _af_families(
                body.get('address-family')):
            if af is None:
                raise engine_errors.ConfigError(
                    'unsupported address family %s %s'
                    % (afi_name, safi_name),
                    path='router.bgp.%s.address-family.%s.%s'
                         % (asn, afi_name, safi_name))
            # B-1: the decision process can compute an equal-cost set, but
            # the core RIB carries one next hop per prefix and the FIB
            # writes one, so a multipath limit above 1 would show ECMP in
            # `show ip bgp` while forwarding over a single path. Refused
            # until RTA_MULTIPATH exists, rather than accepted and ignored.
            for key in ('maximum-paths', 'maximum-paths-ibgp'):
                limit = (af_body or {}).get(key, 1)
                if limit is not None and limit > 1:
                    raise engine_errors.ConfigError(
                        '%s %d is not supported: this release installs a '
                        'single best path per prefix (no ECMP), so only 1 '
                        'is accepted' % (key, limit),
                        path='router.bgp.%s.address-family.%s.%s.%s'
                             % (asn, afi_name, safi_name, key))
        inst = body.get('timers') or {}
        _check_timers(inst.get('hold-time', DEFAULT_HOLD_TIME),
                      inst.get('keepalive'),
                      'router.bgp.%s.timers' % asn)
        for addr, nbr in body.get('neighbor', {}).items():
            self._prepare_neighbor(asn, addr, nbr, body)
        self._prepare_listener_gtsm(asn, body)

    @staticmethod
    def _prepare_listener_gtsm(asn, body):
        """S-9: refuse a listener that mixes GTSM and non-GTSM neighbours.

        ``IP_MINTTL`` belongs to the listening socket, not to a peer, and
        the kernel checks the SYN before ``accept`` says who sent it. A
        listener serving both kinds of neighbour can therefore protect
        neither handshake: a floor would drop the plain peers' SYNs, no
        floor leaves the GTSM peers' handshakes unchecked. The transport
        used to pick the second and log a warning, which reads as GTSM in
        ``show`` while the property GTSM exists for -- an off-path SYN is
        never answered -- does not hold.
        """
        listen = body.get('listen') or {}
        address = listen.get('address')
        if not address:
            return
        family = _family_of(address)
        with_gtsm, without = [], []
        for addr, nbr in sorted(body.get('neighbor', {}).items()):
            if _family_of(addr) != family:
                continue
            (with_gtsm if nbr.get('ttl-security') else without).append(addr)
        if with_gtsm and without:
            raise engine_errors.ConfigError(
                'the listener on %s serves neighbours with ttl-security '
                '(%s) and without it (%s); the inbound TTL check applies to '
                'the whole listening socket, so it cannot protect either '
                'set. Configure ttl-security on all of them or none'
                % (address, ', '.join(with_gtsm), ', '.join(without)),
                path='router.bgp.%s.listen' % asn)

    def _prepare_neighbor(self, asn, addr, nbr, instance=None):
        base = 'router.bgp.%s.neighbor.%s' % (asn, addr)
        # The effective pair, inherited from the instance where the
        # neighbour is silent (L-5): an instance keepalive of 30 with a
        # neighbour hold time of 20 must be caught here, not at OPEN.
        hold, keepalive, _cr, _do = resolve_timers(instance, nbr)
        _check_timers(hold, keepalive, base + '.timers')

        try:
            adjout_mod.remove_private_mode(nbr.get('remove-private-as'))
        except ValueError as exc:
            raise engine_errors.ConfigError(
                str(exc), path=base + '.remove-private-as')

        # Authentication, fail-closed and at configuration time. Finding
        # out at connect time that the kernel has no TCP-AO leaves the
        # operator with a peer that will not come up and no explanation
        # attached to the thing they just typed.
        neighbor_auth = {}
        if nbr.get('password'):
            neighbor_auth['password'] = nbr['password']
        if nbr.get('ao'):
            neighbor_auth['ao'] = nbr['ao']
        if neighbor_auth:
            mode, _key, reason = auth_mod.resolve_auth(neighbor_auth)
            if mode is None:
                raise engine_errors.ConfigError(
                    'this neighbour cannot be authenticated as configured '
                    '(%s); either install a kernel that supports it or set '
                    'ao.fallback-md5 with a password' % reason,
                    path=base)

        hops = nbr.get('ttl-security')
        if hops:
            if nbr.get('ebgp-multihop'):
                raise engine_errors.ConfigError(
                    'ttl-security and ebgp-multihop both set the TTL and '
                    'contradict each other; configure one',
                    path=base + '.ttl-security')
            family = _family_of(addr)
            if not auth_mod.gtsm_inbound_supported(family):
                # Rejecting is the honest answer. Accepting would set the
                # outbound TTL to 255 and enforce nothing inbound, which
                # looks like GTSM in `show` and protects against nothing.
                raise engine_errors.ConfigError(
                    'this platform cannot enforce the inbound TTL, so '
                    'ttl-security would protect nothing',
                    path=base + '.ttl-security')

        carried = set(af for _a, _s, af, _b in _af_families(
            (instance or {}).get('address-family')) if af is not None)
        if not carried:
            carried.add((AFI_IP, SAFI_UNICAST))
        for afi_name, safi_name, af, entry in _af_families(
                nbr.get('address-family')):
            path = '%s.address-family.%s.%s' % (base, afi_name, safi_name)
            if af is None:
                raise engine_errors.ConfigError(
                    'unsupported address family %s %s'
                    % (afi_name, safi_name), path=path)
            if instance is not None and entry.get('activate', True) and \
                    af not in carried:
                # IOS refuses `neighbor X activate` under an address
                # family the instance does not have. Accepting it here
                # negotiated the family and then dropped every route the
                # peer sent in it, with nothing but a counter to show.
                raise engine_errors.ConfigError(
                    'neighbour %s activates %s %s, which this BGP instance '
                    'does not carry; add address-family.%s.%s to the '
                    'instance' % (addr, afi_name, safi_name, afi_name,
                                  safi_name), path=path)
            if entry.get('next-hop'):
                _check_next_hop(entry['next-hop'], af, path + '.next-hop')

    def commit_config(self, section, diff):
        """Apply an accepted BGP configuration.

        Written to be applicable in either direction, because the engine
        may hand back an inverse diff as rollback when a later plugin's
        commit failed. The irreversible work -- resetting sessions -- is
        last, so a failure earlier leaves nothing torn down.

        :param section: the new ``router bgp`` subtree.
        :param diff: the diff for this section.
        """
        if not section:
            self._shutdown_all('BGP removed from the configuration')
            self.config = {}
            return
        # The AS arrives as a JSON object key, so it is a string even
        # though it is a number -- which is exactly why config.py has an
        # 'asn' key type rather than an 'int' one.
        asn = sorted(section, key=lambda k: int(k))[0]
        body = section[asn]
        previous_as = self.local_as
        self.config = body
        self.local_as = int(asn)
        self.router_id = body.get('router-id') or self.router_id

        self._af = set()
        for _a, _s, af, _b in _af_families(body.get('address-family')):
            if af is not None:
                self._af.add(af)
        if not self._af:
            self._af.add((AFI_IP, SAFI_UNICAST))

        self.next_hop_validation = bool(body.get('next-hop-validation'))
        self.default_local_pref = body.get('default-local-preference',
                                           DEFAULT_LOCAL_PREF)
        self.maxas_limit = body.get('maxas-limit',
                                    peer_mod.DEFAULT_MAXAS_LIMIT)
        self._rebuild_bestpath_config(body)
        self._rebuild_locribs()
        self._rebuild_networks(body)

        if previous_as and previous_as != self.local_as:
            # The AS is in every OPEN we have sent. Nothing about an
            # existing session survives changing it.
            self._shutdown_all('local AS changed from %d to %d'
                               % (previous_as, self.local_as))
        self._reconcile_neighbors(body.get('neighbor', {}))
        # A `listen` block that arrives after the engine has started --
        # which is what happens whenever configuration is pushed to a
        # running engine rather than loaded from a file at boot -- must
        # still open its socket. Binding only in start() left such an
        # engine able to dial out but never able to accept, and the only
        # symptom was a peer that never connects inbound.
        if self._started and not self.listeners:
            self._start_listener()

    def _rebuild_bestpath_config(self, body):
        knobs = body.get('bestpath', {})
        for af in self._af:
            af_cfg = self._af_config(body, af)
            self.bestpath_config[af] = bestpath.BestpathConfig(
                local_as=self.local_as,
                router_id=_router_id_int(self.router_id),
                always_compare_med=knobs.get('always-compare-med', False),
                deterministic_med=knobs.get('deterministic-med', True),
                med_missing_as_worst=knobs.get('med-missing-as-worst',
                                               False),
                compare_router_id=knobs.get('compare-routerid', False),
                as_path_ignore=knobs.get('as-path-ignore', False),
                as_path_multipath_relax=knobs.get('as-path-multipath-relax',
                                                  False),
                maximum_paths=af_cfg.get('maximum-paths', 1),
                maximum_paths_ibgp=af_cfg.get('maximum-paths-ibgp', 1),
                default_local_pref=self.default_local_pref)

    def _af_config(self, body, af):
        """Return the ``address-family`` body for one ``(afi, safi)``."""
        for _a, _s, pair, af_body in _af_families(
                (body or {}).get('address-family')):
            if pair == af:
                return af_body
        return {}

    def _rebuild_locribs(self):
        """Create a Loc-RIB per configured family, dropping removed ones."""
        global_rib = getattr(self.engine, 'global_rib', None)
        for af in self._af:
            if af in self.locribs:
                # A knob changed on a running router must reach the table
                # that selects with it; this used to be skipped, and every
                # bestpath edit waited for a restart.
                self.locribs[af].set_config(self.bestpath_config[af])
                continue
            distance = self._af_config(self.config, af).get('distance', {})
            self.locribs[af] = locrib_mod.LocRib(
                af[0], af[1], self.attr_table, self.bestpath_config[af],
                global_rib=global_rib,
                events=getattr(self.engine, 'events', None),
                admin_distance_ebgp=distance.get(
                    'external', DEFAULT_DISTANCE_EBGP),
                admin_distance_ibgp=distance.get(
                    'internal', DEFAULT_DISTANCE_IBGP))
        for af in list(self.locribs):
            if af not in self._af:
                self.locribs.pop(af).clear()

    def _rebuild_networks(self, body):
        """Record the configured ``network`` statements and originate them.

        The configuration is kept separately from what is actually being
        originated, because the two can legitimately differ: a `network`
        with ``import-check`` set is only originated while something else
        in the routing table backs it, and that can change long after the
        configuration did. :meth:`_sync_networks` is what reconciles them.
        """
        self.network_config = {}
        for _a, _s, af, af_body in _af_families(
                body.get('address-family')):
            if af is None:
                continue
            for text, entry in (af_body.get('network') or {}).items():
                self.network_config[(af, text)] = entry or {}
        self._sync_networks()

    def _sync_networks(self):
        """Originate the networks that should be, withdraw those that
        should not.

        A `network` is a path like any other, with an empty AS_PATH, an
        ORIGIN of IGP and a source that wins the locally-originated
        tie-break. It goes through the same Loc-RIB and the same decision
        process as a learned path, which is what makes "my own network
        lost to a learned one" a visible, explicable outcome rather than
        a special case.

        Two things can stop one being originated, and both are re-examined
        on every pass rather than only at commit time:

        ``import-check`` asks whether anything else in the router's table
        actually reaches the prefix. RFC 4271 requires it, and the reason
        is that originating a prefix nobody can reach advertises a black
        hole with this AS's name on it. It is off by default because a
        control-plane speaker has no other source of routes to check
        against -- the same reasoning the core applies to next-hop
        validation.

        A ``route-map`` may rewrite the originated attributes, and may
        deny outright, in which case the network is not originated at all.
        That is IOS behaviour and it is the only way to originate a prefix
        with, say, a community or a non-default MED.

        :return: the number of networks added or removed.
        """
        wanted = {}
        for key, entry in self.network_config.items():
            af, text = key
            if af not in self.locribs:
                continue
            try:
                prefix = parse_prefix(text)
            except ValueError:
                # The schema validated it as a prefix, so this cannot
                # happen from configuration; it could from a future
                # caller, and originating nothing is better than raising
                # inside a commit.
                continue
            if entry.get('import-check') and not self._backed(af, prefix):
                continue
            attrs = self._network_attrs(af, prefix, entry)
            if attrs is None:
                continue
            wanted[key] = (prefix, attrs)

        changes = 0
        for key in list(self.networks):
            if key in wanted:
                continue
            af, text = key
            rib = self.locribs.get(af)
            if rib is not None:
                rib.remove_path(bestpath.LOCAL_PEER, parse_prefix(text),
                                path_id=0)
            del self.networks[key]
            changes += 1
        for key, (prefix, attrs) in wanted.items():
            previous = self.networks.get(key)
            if previous is not None and previous == attrs:
                continue
            rib = self.locribs.get(key[0])
            if rib is None:
                continue
            rib.add_path(bestpath.LOCAL_PEER, prefix, attrs, path_id=0,
                         source=bestpath.SRC_LOCAL,
                         recv_time=self._now())
            self.networks[key] = attrs
            changes += 1
        return changes

    def _backed(self, af, prefix):
        """Whether something outside BGP reaches this prefix.

        Two conditions, and the second is the one that matters. The core's
        table must hold a usable route for *exactly* this prefix -- IOS
        requires an exact match for ``import-check`` as well, and a
        covering route says nothing about whether this particular prefix
        is reachable -- and that route must not be BGP's own. Without the
        second test a `network` statement would back itself the moment it
        was originated, or be backed by the copy a neighbour advertised
        back to us, and ``import-check`` would mean nothing at all while
        appearing to work.

        :param af: the ``(afi, safi)`` pair.
        :param prefix: the :class:`rib.prefix.Prefix` to look for.
        :return: True when another protocol's route covers this prefix
            exactly.
        """
        rib = getattr(self.engine, 'global_rib', None)
        if rib is None:
            return False
        table = rib.table(af[0], af[1])
        if table is None:
            return False
        dest = table.get(prefix)
        if dest is None or dest.best is None:
            return False
        return dest.best.protocol != PROTO_BGP

    def _network_attrs(self, af, prefix, entry):
        """Build the attribute set for one originated network.

        :param af: the ``(afi, safi)`` pair.
        :param prefix: the prefix being originated.
        :param entry: its configuration body.
        :return: the :class:`attrs.AttrSet` to originate, or None when a
            route-map denied it.
        """
        attrs = attrs_mod.AttrSet(
            origin=attrs_mod.ORIGIN_IGP_V, as_path=b'',
            nexthop=b'\x00' * (4 if af[0] == AFI_IP else 16),
            has_local_pref=True, local_pref=100)
        name = entry.get('route-map')
        store = self._policy_store()
        if not name or store is None:
            return attrs
        chain = policy_mod.build_chain(
            policy_mod.DIR_IN, store, {'route-map': name},
            local_as=self.local_as, afi=af[0])
        outcome = chain.apply(prefix, attrs)
        if outcome is None:
            return None
        return outcome.attrs

    def _reconcile_neighbors(self, neighbors):
        """Add, remove and update neighbours to match the configuration."""
        for addr in list(self.peers):
            if addr not in neighbors:
                self._remove_peer(addr, 'neighbour removed',
                                  bgp_errors.CEASE_PEER_DECONFIGURED)
        for addr, nbr in neighbors.items():
            cfg = self._peer_config(addr, nbr)
            existing = self.peers.get(addr)
            if existing is None:
                self._add_peer(addr, cfg)
            elif self._needs_reset(existing.config, cfg):
                self._remove_peer(addr, 'configuration changed',
                                  bgp_errors.CEASE_OTHER_CONFIG_CHANGE)
                self._add_peer(addr, cfg)
            else:
                # Apply in place. A description or a weight change must
                # not cost a session and a full table relearn.
                existing.config = cfg
                # Policy and next-hop validation are read through the
                # session on every path that arrives, so a commit that
                # changed either has to reach a running session here. The
                # outbound half is reached by rejoining the update groups,
                # which is what the next pass does through _refresh_groups.
                existing.in_policy = self._inbound_policy(cfg)
                existing.nexthop_check = self._nexthop_checker()
        self._refresh_groups()

    def _needs_reset(self, old, new):
        """Whether a configuration change requires bouncing the session."""
        for key in SESSION_AFFECTING:
            attr = key.replace('-', '_')
            if attr == 'timers':
                if (old.hold_time, old.keepalive, old.connect_retry,
                        old.delay_open) != (new.hold_time, new.keepalive,
                                            new.connect_retry,
                                            new.delay_open):
                    return True
                continue
            if attr == 'capability':
                if (old.route_refresh, old.extended_message,
                        old.add_path_receive, old.graceful_restart) != (
                        new.route_refresh, new.extended_message,
                        new.add_path_receive, new.graceful_restart):
                    return True
                continue
            if getattr(old, attr, None) != getattr(new, attr, None):
                return True
        if old.afi_safi != new.afi_safi:
            return True
        return False

    def _peer_config(self, addr, nbr):
        """Translate one configured neighbour into a :class:`PeerConfig`."""
        hold, keepalive, connect_retry, delay_open = resolve_timers(
            self.config, nbr)
        cap = nbr.get('capability', {})
        maxpfx = nbr.get('maximum-prefix', {})
        activated = set()
        policy = {}
        next_hop_self_af = {}
        next_hop_af = {}
        af_block = nbr.get('address-family')
        if af_block:
            for _a, _s, af, entry in _af_families(af_block):
                if af is None:
                    continue
                if entry.get('activate', True):
                    activated.add(af)
                names = _policy_names(entry)
                if names:
                    policy[af] = names
                if entry.get('next-hop-self') is not None:
                    next_hop_self_af[af] = entry['next-hop-self']
                if entry.get('next-hop'):
                    next_hop_af[af] = entry['next-hop']
        else:
            # No per-neighbour address-family block means the neighbour
            # carries whatever the instance carries. IOS requires an
            # explicit activate for anything but IPv4 unicast; matching
            # that here would surprise anyone configuring IPv6 only.
            activated = set(self._af)
        return peer_mod.PeerConfig(
            address=addr,
            remote_as=nbr['remote-as'],
            local_as=nbr.get('local-as', self.local_as),
            router_id=self.router_id,
            description=nbr.get('description'),
            update_source=nbr.get('update-source'),
            password=nbr.get('password'),
            ao=nbr.get('ao'),
            ttl_security=nbr.get('ttl-security'),
            ebgp_multihop=nbr.get('ebgp-multihop'),
            passive=nbr.get('passive', False),
            shutdown=nbr.get('shutdown', False),
            hold_time=hold,
            keepalive=keepalive,
            connect_retry=connect_retry,
            delay_open=delay_open,
            afi_safi=activated or self._af,
            next_hop_self=nbr.get('next-hop-self', False),
            add_path_receive=cap.get('add-path-receive', False),
            extended_message=cap.get('extended-message', False),
            route_refresh=cap.get('route-refresh', True),
            graceful_restart=cap.get('graceful-restart', False),
            maximum_prefix=maxpfx.get('limit', 0),
            maximum_prefix_warning=maxpfx.get('warning-percent', 75) / 100.0,
            send_community=nbr.get('send-community', True),
            weight=nbr.get('weight', 0),
            allowas_in=nbr.get('allowas-in', 0),
            remove_private_as=nbr.get('remove-private-as', False),
            as_override=nbr.get('as-override', False),
            port=nbr.get('port', tcp_mod.BGP_PORT),
            advertisement_interval=nbr.get('advertisement-interval', 0),
            policy=policy,
            next_hop_self_af=next_hop_self_af,
            sender_loop_check=nbr.get('sender-loop-check', True),
            next_hop_af=next_hop_af,
            maxas_limit=self.maxas_limit)

    def _add_peer(self, addr, cfg):
        session = peer_mod.Peer(
            cfg, loop=getattr(self.engine, 'loop', None),
            locribs=self.locribs, attr_table=self.attr_table,
            clock=self.clock, events=getattr(self.engine, 'events', None),
            on_established=self._on_peer_established,
            on_session_down=self._on_peer_down,
            on_route_refresh=self._on_route_refresh,
            in_policy=self._inbound_policy(cfg),
            nexthop_check=self._nexthop_checker())
        # No Adj-RIB-Out is built here any more. It belongs to an update
        # group, the group is chosen by a key that includes things only
        # the negotiated session knows -- the message ceiling, the ASN
        # encoding, the local address we will advertise as a next hop --
        # and none of those exist until the peer has sent its OPEN. The
        # join therefore happens when the session reaches Established.
        self.peers[addr] = session
        for listener in self.listeners:
            listener.add_peer(addr, session.auth_mode, session._auth_key,
                              gtsm_hops=cfg.ttl_security)
        if self._started:
            session.start(loop=getattr(self.engine, 'loop', None))

    def _remove_peer(self, addr, reason, subcode=None):
        """Stop and forget one neighbour.

        :param subcode: the Cease subcode the peer is told (RFC 4486);
            None for Administrative Shutdown.
        """
        session = self.peers.pop(addr, None)
        self._in_policy_id.pop(addr, None)
        if session is None:
            return
        session.stop(reason, subcode=subcode)
        for task in session.lingering():
            self._closing.add(task)
            task.add_done_callback(self._closing.discard)
        # stop() releases the routes, which calls back into
        # _on_peer_down and leaves the groups; this is the backstop for a
        # session that never came up and so never had routes to release.
        self.groups.leave(session)
        for listener in self.listeners:
            listener.remove_peer(addr)

    def _on_peer_established(self, session):
        """Put a session that came up into its update groups."""
        self._dirty_peers.add(session.config.address)
        self._join_groups(session)

    def _on_peer_down(self, session):
        """Take a session that went down out of its update groups.

        The group keeps its record: the other members have been told what
        it says and are still up. Only when the last member leaves does
        the manager discard the group, and with it the record.

        A session that went down while it was still meant to be up is a
        flap, and is reported to the engine's health monitor (E-8), which
        used to keep a flap counter that nothing ever incremented. A stop,
        a shutdown or a deleted neighbour is not one.
        """
        self.groups.leave(session)
        self._dirty_peers.discard(session.config.address)
        if getattr(session, 'running', False):
            monitor = getattr(self.engine, 'health_monitor', None)
            if monitor is not None:
                monitor.note_peer_flap()

    def _on_route_refresh(self, session, af):
        """Honour a peer's ROUTE-REFRESH by replaying its group's record.

        One member, not the group: the peer asked to be told again, and
        the others did not. Replaying from the shared record rather than
        re-running selection is also the honest answer to the request --
        "everything I have told you" is exactly what the record holds.

        :param session: the asking :class:`peer.Peer`.
        :param af: the ``(afi, safi)`` pair it asked about.
        :return: the number of messages queued.
        """
        group = self.groups.group_of(session.config.address, af)
        if group is None:
            return 0
        sent = group.replay(session, force=True)
        session.send_end_of_rib(af)
        return sent

    # --- policy and update groups ------------------------------------------

    def _policy_store(self):
        """Return the engine's policy store, or None before start.

        Prefix-lists, as-path lists and route-maps are core objects --
        ``ip prefix-list`` and ``route-map`` are not under ``router bgp``
        -- so the plugin reads them from the engine rather than owning
        them. A plugin with no engine yet simply has no policy, which is
        the right answer for a peer configured before the engine ran.
        """
        return getattr(self.engine, 'policy', None)

    def _inbound_policy(self, cfg):
        """Build the inbound policy chains for one neighbour.

        :param cfg: the :class:`peer.PeerConfig`.
        :return: a dict of ``(afi, safi)`` to
            :class:`policy.PolicyChain`, containing only the families with
            something configured.
        """
        store = self._policy_store()
        chains = {}
        ids = {}
        if store is None:
            self._in_policy_id[cfg.address] = ids
            return chains
        for af in cfg.afi_safi:
            names = cfg.policy_names(af, DIR_IN)
            if not names:
                continue
            chains[af] = policy_mod.build_chain(
                policy_mod.DIR_IN, store, names, local_as=self.local_as,
                afi=af[0])
            ids[af] = self._policy_id(store, names, af[0])
        # Remembered so a later policy edit can tell whether it affected
        # *this* neighbour. The store bumps a version per object, and the
        # identity below is the same tuple the outbound group key uses;
        # comparing it is how policy_changed avoids replaying a full
        # Adj-RIB-In for every peer whenever any list anywhere changes.
        self._in_policy_id[cfg.address] = ids
        return chains

    def longest_as_path(self, section):
        """``maxas-limit`` of the proposed instance: no path longer reaches
        policy, because a longer one is treated as withdrawn before it.

        :param section: the proposed ``router.bgp`` section, or None.
        :return: the limit (0 for none), or None with no instance.
        """
        if not isinstance(section, dict) or not section:
            return None
        body = next(iter(section.values()))
        if not isinstance(body, dict):
            return None
        return body.get('maxas-limit', peer_mod.DEFAULT_MAXAS_LIMIT)

    def policy_changed(self, store):
        """Re-apply policy after a prefix-list or route-map was edited.

        Three things have to happen, and they are not the same thing.

        The inbound chains are rebuilt, and every neighbour whose inbound
        policy identity actually moved has its Adj-RIB-In replayed through
        the new rules. Rebuilding without replaying would apply the edit
        only to paths that arrive *after* it, which is the behaviour that
        makes an operator conclude the filter did not work.

        The outbound half needs no replay here: the version of every
        object a group's policy names is part of the group's key, so
        rejoining moves the affected peers into a differently-keyed group,
        and a new group is unseeded and gets the whole table staged into
        it on the next pass. That is the correct outbound re-advertisement,
        and it happens for exactly the peers whose policy changed.

        Originated networks are re-examined last, because a `network`
        statement may name a route-map too.

        :param store: the engine's policy store.
        :return: the number of neighbours whose inbound paths were
            replayed.
        """
        replayed = 0
        for addr, session in self.peers.items():
            before = dict(self._in_policy_id.get(addr) or {})
            session.in_policy = self._inbound_policy(session.config)
            after = self._in_policy_id.get(addr) or {}
            if before != after:
                session.soft_reset_in()
                replayed += 1
        self._refresh_groups()
        if self.network_config:
            self._sync_networks()
        if replayed:
            LOG.info('bgp: policy revision %s replayed %d neighbour(s)',
                     getattr(store, 'revision', '?'), replayed)
        return replayed

    def _policy_id(self, store, names, afi):
        """Return the group-key identity of a set of policy names.

        The version of each named object is part of the identity, not just
        its name: two peers naming one route-map are equivalent only while
        that route-map has not been edited. Without the version, editing a
        route-map would leave every peer in a group whose encoded stream
        was built under the old rules, and nothing would ever move them.

        :param store: the policy store, or None.
        :param names: the configured names for one direction.
        :param afi: the address family, for the prefix-list namespace.
        :return: a tuple of ``(kind, name, version)`` triples, sorted.
        """
        if not names or store is None:
            return ()
        kinds = (('prefix-list', 'prefix-list'),
                 ('filter-list', 'as-path'),
                 ('route-map', 'route-map'))
        out = []
        for key, kind in kinds:
            name = names.get(key)
            if not name:
                continue
            lookup = kind
            if kind == 'prefix-list' and afi == AFI_IP6:
                lookup = 'ipv6-prefix-list'
            out.append((kind, name, store.version_of(lookup, name)))
        # Ordered by kind and name only: the version of an undefined object
        # is None (P-6), which does not order against an int.
        return tuple(sorted(out, key=lambda triple: triple[:2]))

    def _outbound_spec(self, session, af):
        """Describe how one session's outbound stream is produced.

        :param session: the established :class:`peer.Peer`.
        :param af: the ``(afi, safi)`` pair.
        :return: an :class:`updategroup.OutboundSpec`.
        """
        cfg = session.config
        store = self._policy_store()
        names = cfg.policy_names(af, DIR_OUT)
        negotiated = session.negotiated
        max_size = (negotiated.max_message_size if negotiated is not None
                    else 4096)
        add_path_send = False
        if negotiated is not None:
            add_path_send = af in (negotiated.add_path_send or ())
        chain = policy_mod.PERMIT_ALL_OUT
        if names:
            chain = policy_mod.build_chain(
                policy_mod.DIR_OUT, store, names, local_as=self.local_as,
                afi=af[0])
        return ug_mod.OutboundSpec(
            afi=af[0], safi=af[1], is_ebgp=cfg.is_ebgp,
            peer_as=cfg.remote_as, local_as=cfg.local_as,
            router_id=_router_id_int(self.router_id),
            local_addr=self._local_next_hop(session, af),
            next_hop_self=cfg.next_hop_self_for(af),
            default_local_pref=self.default_local_pref,
            send_community=cfg.send_community,
            send_ext_community=cfg.send_ext_community,
            send_large_community=cfg.send_large_community,
            max_size=max_size, as4=True, add_path_send=add_path_send,
            remove_private_as=cfg.remove_private_as,
            as_override=cfg.as_override,
            sender_loop_check=cfg.sender_loop_check,
            mrai=cfg.advertisement_interval, policy=chain,
            policy_id=self._policy_id(store, names, af[0]))

    def _join_groups(self, session):
        """Put an established session in a group for every family.

        :param session: the :class:`peer.Peer`.
        :return: the number of groups joined.
        """
        if session.peer_ref is None:
            return 0
        families = session.config.afi_safi
        if session.negotiated is not None and session.negotiated.afi_safi:
            # Only the families both ends agreed on. Advertising into a
            # family the peer did not accept is a message it will discard
            # at best and reset the session over at worst.
            families = [af for af in families
                        if af in session.negotiated.afi_safi]
        joined = 0
        for af in sorted(families):
            try:
                self.groups.join(session, self._outbound_spec(session, af))
            except ValueError as exc:
                # A local address of the wrong width for the family. The
                # session stays up and this family simply advertises
                # nothing, which is visible in `show ip bgp
                # update-groups` and in the log, rather than taking the
                # session down over an outbound detail.
                LOG.error('bgp %s: no update group for %s: %s',
                          session.config.address,
                          capabilities.afi_safi_name(af[0], af[1]), exc)
                continue
            joined += 1
        return joined

    def _refresh_groups(self):
        """Recompute every established session's group membership.

        Called after a configuration commit. A peer whose key has not
        changed does not move and nothing is re-advertised, which is why
        this can be run unconditionally rather than guessing which edits
        matter.

        :return: the number of sessions re-examined.
        """
        seen = 0
        for session in self.peers.values():
            if not session.established:
                continue
            self._join_groups(session)
            seen += 1
        return seen

    def _local_next_hop(self, session, af):
        """Return the next hop to advertise when we rewrite it.

        In order of precedence (L-4):

        1. the neighbour's per-family ``next-hop``;
        2. ``update-source``, then the local address of the established
           connection, when it is of the family's width;
        3. for IPv6 only, the IPv4-mapped form ``::ffff:a.b.c.d`` of that
           IPv4 address -- what FRR sends over an IPv4 session -- with a
           warning, once per neighbour, because the peer can only use it
           if it has a route to the mapped address.

        The unspecified address is never the answer. It used to be, for
        every IPv6 family over an IPv4 session: the IPv4 transport address
        did not fit sixteen bytes, the packing fell back to zeros, and the
        peer dropped every IPv6 route as a martian. When nothing above
        applies -- IPv4 over an IPv6-only session with no ``next-hop`` --
        the zeros are returned and the Adj-RIB-Out refuses them, so the
        family advertises nothing and says why in the log.

        :param session: the :class:`peer.Peer`.
        :param af: the ``(afi, safi)`` pair.
        :return: packed next-hop bytes of the family's width. The choice
            and its source are recorded on ``session.next_hops`` for
            ``show ip bgp neighbors``.
        """
        import socket

        cfg = session.config
        width = 4 if af[0] == AFI_IP else 16
        candidates = []
        if cfg.next_hop_af.get(af):
            candidates.append((cfg.next_hop_af[af], 'configured'))
        if cfg.update_source:
            candidates.append((cfg.update_source, 'update-source'))
        if session.conn is not None and session.conn.local_addr:
            candidates.append((session.conn.local_addr, 'transport'))
        for text, source in candidates:
            packed = _addr_bytes_for_af(text, af)
            if packed.count(0) != width:
                session.next_hops[af] = {'address': text, 'source': source}
                return packed
        if af[0] == AFI_IP6:
            for text, _source in candidates:
                v4 = _addr_bytes_for_af(text, (AFI_IP, SAFI_UNICAST))
                if v4.count(0) == 4:
                    continue
                packed = b'\x00' * 10 + b'\xff\xff' + v4
                mapped = socket.inet_ntop(socket.AF_INET6, packed)
                if cfg.address not in self._mapped_warned:
                    self._mapped_warned.add(cfg.address)
                    LOG.warning(
                        'bgp %s: no IPv6 next hop for IPv6 unicast over an '
                        'IPv4 session; advertising the IPv4-mapped %s. '
                        'Configure address-family.ipv6.unicast.next-hop '
                        'for a global address', cfg.address, mapped)
                session.next_hops[af] = {'address': mapped,
                                         'source': 'ipv4-mapped'}
                return packed
        session.next_hops[af] = {'address': None, 'source': 'none'}
        return b'\x00' * width

    def _nexthop_checker(self):
        """Return the next-hop validation callable, or None.

        None rather than a function that always says "reachable", because
        the session tests for None once per batch and calling a function
        per path to learn nothing is the sort of cost that does not show
        up until the table is a million paths deep.

        :return: a callable ``(afi, nexthop) -> (resolved, metric)``, or
            None when validation is off.
        """
        if not self.next_hop_validation:
            return None
        return self._check_nexthop

    def _check_nexthop(self, afi, nexthop):
        """Ask the engine's resolver about one next hop.

        :param afi: the address family.
        :param nexthop: packed next-hop bytes.
        :return: ``(resolved, igp_metric)``. An absent next hop resolves:
            a path with no next hop is either locally originated or one
            the decoder has already judged, and answering "unreachable"
            here would hide the router's own networks.
        """
        resolver = getattr(self.engine, 'resolver', None)
        if resolver is None or not nexthop:
            return (True, 0)
        # As BGP: a BGP route may not vouch for a BGP next hop (P-3).
        resolution = resolver.resolve(afi, nexthop, protocol=PROTO_BGP)
        if resolution is None:
            return (False, 0)
        return (True, resolution.metric)

    def _revalidate(self):
        """Re-test next hops if the core has selected anything since, or
        the resolver's inputs have changed.

        :return: the number of destinations requeued.
        """
        rib = getattr(self.engine, 'global_rib', None)
        resolver = getattr(self.engine, 'resolver', None)
        marker = (getattr(rib, 'selected', 0) if rib is not None else 0,
                  getattr(resolver, 'generation', 0))
        if marker == self._nh_marker:
            return 0
        self._nh_marker = marker
        changed = 0
        for locrib in self.locribs.values():
            changed += locrib.revalidate(self._check_nexthop)
        return changed

    # --- lifecycle ---------------------------------------------------------

    def start(self, engine):
        """Attach to the engine and bring every neighbour up.

        :param engine: the running engine.
        """
        ProtocolPlugin.start(self, engine)
        self._started = True
        for rib in self.locribs.values():
            rib.global_rib = getattr(engine, 'global_rib', None)
        self._start_listener()
        loop = getattr(engine, 'loop', None)
        # Hand every session the loop as it starts. A neighbour that was
        # configured before the engine ran was built without one, and a
        # session with no loop can neither dial nor arm a timer -- it
        # would sit in Connect indefinitely. That is precisely the boot
        # order of any engine which loads its configuration from a file.
        for session in self.peers.values():
            session.start(loop=loop)
        if loop is not None and self._task is None:
            self._task = loop.create_task(self._advertise_loop())

    def _start_listener(self):
        loop = getattr(self.engine, 'loop', None)
        listen = self.config.get('listen') if self.config else None
        if loop is None or not listen or not listen.get('address'):
            return
        listener = tcp_mod.Listener(loop, listen['address'],
                                    port=listen.get('port',
                                                    tcp_mod.BGP_PORT))
        for addr, session in self.peers.items():
            listener.add_peer(addr, session.auth_mode, session._auth_key,
                              gtsm_hops=session.config.ttl_security)
        self.listeners.append(listener)
        loop.create_task(listener.start(self._on_accept))

    def _on_accept(self, conn):
        """Hand an accepted connection to the neighbour it belongs to."""
        session = self.peers.get(conn.peer_addr)
        if session is None:
            # The listener already filters by configured address, so this
            # is a race with a neighbour being removed rather than an
            # unknown peer. Close it; the far end will retry if it is
            # reconfigured back.
            conn.close()
            return
        session.adopt(conn, initiated=False)

    def stop(self):
        """Detach: stop sessions, retract routes, release the tables."""
        self._shutdown_all('BGP stopping')
        # peer._cancel, not task.cancel: on the 3.6 floor a task cancelled
        # while it is not suspended finishes holding a CancelledError that
        # nobody retrieves, and asyncio then logs a traceback on every
        # clean shutdown. See the note on that helper.
        peer_mod._cancel(self._task)
        self._task = None
        # Close the listening sockets here and now rather than scheduling
        # Listener.stop() as a task. stop() is frequently the last thing
        # that happens before the loop itself stops, and a task created at
        # that point may never be run -- leaving the socket open until the
        # interpreter exits, which shows up as a ResourceWarning in tests
        # and as a port that cannot be rebound in a restart. The coroutine
        # is still awaited when there is a live loop to await it on, so
        # the accept task is cancelled properly; the synchronous close is
        # the backstop that guarantees the descriptor goes.
        loop = getattr(self.engine, 'loop', None)
        for listener in self.listeners:
            if loop is not None and not loop.is_closed():
                loop.create_task(listener.stop())
            listener.close()
        self.listeners = []
        self._started = False
        ProtocolPlugin.stop(self)

    def _shutdown_all(self, reason):
        for addr in list(self.peers):
            self._remove_peer(addr, reason)
        for rib in self.locribs.values():
            rib.clear()
        # Every session has gone, so every group is empty; the manager
        # discards a group as its last member leaves, and asserting that
        # here rather than trusting it would be the same statement twice.
        # What is left is the originated networks, which the Loc-RIB
        # clear above has already taken out of the table.
        self.networks = {}

    def closing(self):
        """Return the session closes still in progress.

        Each is a NOTIFICATION being written, a half-close, or a drain
        waiting for the peer's FIN, bounded by ``peer.NOTIFY_LINGER``. The
        engine waits for them before stopping its loop: cancelled there,
        a NOTIFICATION that had not yet been written never would be.

        :return: a list of tasks.
        """
        tasks = [t for t in self._closing if not t.done()]
        for session in self.peers.values():
            tasks.extend(session.lingering())
        return tasks

    # --- the periodic pass -------------------------------------------------

    async def _advertise_loop(self):
        """Select, then tell every peer what changed.

        Selection and advertisement are one pass and in this order,
        because advertising from a Loc-RIB whose selection is half-done
        would send a peer a winner that is about to be replaced -- and
        BGP has no way to say "ignore that, I had not finished thinking".
        """
        loop = self.engine.loop
        while self._started:
            try:
                await _sleep(loop, ADVERTISE_INTERVAL)
            except Exception:
                return
            if not self._started:
                return
            try:
                self.run_pass()
            except Exception:
                LOG.exception('bgp: advertisement pass failed')

    def run_pass(self, limit=4096):
        """Run one selection-and-advertisement pass.

        Exposed rather than private because the two-engine convergence
        test needs to drive it deterministically instead of waiting for
        the interval to elapse.

        The order is deliberate throughout and each step depends on the
        one before it: reselect, so nothing is advertised from a
        half-decided table; revalidate next hops and re-examine the
        originated networks, both of which can change what the *next*
        pass selects; stage the changes into every update group; replay to
        members that owe a catch-up, before the flush rather than after,
        so a new member is not sent a delta against a record it has never
        seen; flush, subject to each group's advertisement interval; and
        only then send End-of-RIB, which by definition follows everything
        else.

        :param limit: how many destinations to reselect per family.
        :return: the number of UPDATE messages written to sessions. For a
            group of one member that is the number of messages encoded,
            which is what this returned before update groups existed; for
            a larger group it is the honest figure, because the same
            encoded message written to ten members is ten writes.
        """
        changed = {}
        offered = 0
        for af, rib in self.locribs.items():
            changed[af] = rib.reselect(limit)
            offered += len(changed[af])
        if offered and self.engine is not None:
            # The Loc-RIB has handed the GlobalRib candidates, which only
            # marks its destinations dirty; nothing is published until a
            # selection pass runs. Engine.schedule_select is the documented
            # way for a plugin to ask for one after offering or retracting,
            # and it coalesces, so calling it once per pass is correct
            # rather than merely cheap. Without it a BGP route reaches the
            # core and stops there: visible in `show ip bgp`, absent from
            # `show ip route`, for ever.
            self.engine.schedule_select()
        if self.next_hop_validation:
            self._revalidate()
        if self.network_config:
            self._sync_networks()

        self._stage(changed)
        return self._flush()

    def _stage(self, changed):
        """Offer this pass's changes to every update group.

        A group that has never been offered the table gets all of it --
        which is the case for a group created by the first session of its
        kind to come up -- and every other group gets only what changed.
        The distinction is the group's own, not the session's: several
        sessions joining one existing group must not each cause a
        table-wide re-announcement, and that is exactly what keying this
        off "the peer is new" used to do.

        :param changed: ``{af: [dest, ...]}`` from this pass's selection.
        :return: the number of groups whose staging area changed.
        """
        touched = 0
        for af, dests in changed.items():
            rib = self.locribs.get(af)
            for group in self.groups.groups_for(af):
                if not group.seeded:
                    if rib is not None:
                        for dest in rib:
                            group.announce(dest)
                    group.mark_seeded()
                    touched += 1
                    continue
                for dest in dests:
                    if dest.best is None:
                        group.withdraw(dest.prefix)
                    else:
                        group.announce(dest)
                if group.pending():
                    touched += 1
        return touched

    def _flush(self):
        """Replay to new members, flush every group, then send End-of-RIB.

        :return: the number of UPDATE messages written to sessions.
        """
        now = self._now()
        written = 0
        for group in self.groups.groups():
            for addr in group.catchup():
                session = self.peers.get(addr)
                if session is not None:
                    written += group.replay(session)
            written += group.flush(now=now)
        for addr in sorted(self._dirty_peers):
            session = self.peers.get(addr)
            if session is None or not session.established:
                continue
            # End-of-RIB per family, and only for the families the
            # session actually negotiated: a marker for a family the peer
            # did not agree to is a message about nothing.
            families = session.config.afi_safi
            if session.negotiated is not None and session.negotiated.afi_safi:
                families = [af for af in families
                            if af in session.negotiated.afi_safi]
            for af in sorted(families):
                session.send_end_of_rib(af)
        self._dirty_peers = set()
        return written

    def _now(self):
        if self.clock is not None:
            return self.clock()
        import time
        return time.monotonic()

    # --- operational surface ------------------------------------------------

    def show_handlers(self):
        """Return the ``show ip bgp ...`` handlers."""
        return show_mod.handlers(self)

    def clear_handlers(self):
        """Return the ``clear ip bgp ...`` handlers."""
        return {
            ('ip', 'bgp'): self.clear_all,
            ('ip', 'bgp', 'neighbor'): self.clear_neighbor,
        }

    def clear_all(self, *args, **kwargs):
        """Clear every session, hard or soft.

        :param soft: as for :meth:`clear_neighbor`.
        :return: a dict naming what was cleared.
        """
        soft = kwargs.get('soft', False)
        if args and not soft:
            # `clear ip bgp soft in` arrives as a trailing path segment
            # rather than a keyword when it comes from the CLI-shaped
            # dispatcher. Accepting both spellings costs one line and
            # saves an operator discovering that one of them silently
            # hard-cleared their whole router.
            soft = args[0]
        results = []
        for addr in sorted(self.peers):
            results.append(self.clear_neighbor(address=addr, soft=soft))
        return {'cleared': [r.get('neighbor') for r in results],
                'soft': _soft_label(soft), 'results': results}

    def clear_neighbor(self, address=None, soft=False, **kwargs):
        """Clear one session: hard, soft inbound, or soft outbound.

        Three different operations, and the distinction matters because
        two of them are cheap and one is not.

        A **hard** clear drops the session. Both ends forget everything
        and relearn it, which on a full table is a minute of CPU and a
        million paths of churn propagated to every other neighbour.

        A **soft inbound** clear re-runs inbound policy over the paths
        already in the Adj-RIB-In, and additionally sends ROUTE-REFRESH
        when the capability was negotiated. The replay is the part that
        makes a policy edit take effect immediately; the refresh is what
        recovers anything the *old* policy discarded, which the replay
        cannot conjure back because it was never stored.

        A **soft outbound** clear re-advertises what this router has
        chosen, for the peer alone, from its update group's record. It
        costs one pass over that record and nothing at all on the peer's
        side beyond reading it.

        :param address: the neighbour to clear.
        :param soft: False for a hard clear; True or ``'in'`` for soft
            inbound; ``'out'`` for soft outbound; ``'both'`` for both
            directions.
        :return: a dict describing what happened.
        """
        session = self.peers.get(address)
        if session is None:
            return {'error': 'no such neighbour: %s' % address}
        if not soft:
            session.stop('cleared by operator',
                         subcode=bgp_errors.CEASE_ADMIN_RESET)
            session.start()
            return {'neighbor': address, 'soft': False}

        label = _soft_label(soft)
        out = {'neighbor': address, 'soft': label}
        if label in (DIR_IN, 'both'):
            out['replayed'] = session.soft_reset_in()
            refreshed = [af for af in sorted(session.config.afi_safi)
                         if session.send_route_refresh(af)]
            out['refresh-sent'] = ['%d/%d' % af for af in refreshed]
            if not refreshed:
                # Not an error any more: the replay is the substance of a
                # soft inbound clear and it happened. Saying so is still
                # necessary, because what the replay cannot do is recover
                # a path the previous policy dropped.
                out['note'] = ('route refresh was not negotiated, so only '
                               'the paths still held were re-evaluated')
        if label in (DIR_OUT, 'both'):
            written = 0
            families = []
            for af in sorted(session.adjout):
                group = self.groups.group_of(address, af)
                if group is None:
                    continue
                written += group.replay(session, force=True)
                families.append('%d/%d' % af)
            out['re-advertised'] = written
            out['families'] = families
        return out

    def health(self):
        """Report BGP's health.

        Degraded rather than down when some sessions are up and some are
        not: a router with nine of ten peers established is impaired, not
        dead, and reporting it as down would make the signal useless for
        deciding whether to fail over.
        """
        total = len(self.peers)
        up = sum(1 for p in self.peers.values() if p.established)
        blocked = [p.config.address for p in self.peers.values()
                   if p.auth_blocked]
        if total == 0:
            status = health_mod.OK
        elif up == total:
            status = health_mod.OK
        elif up == 0:
            status = health_mod.DOWN
        else:
            status = health_mod.DEGRADED
        if blocked:
            # An unauthenticatable peer is never merely "down": it is a
            # configuration the platform cannot honour, and it must be
            # visible as such rather than looking like an unreachable
            # neighbour.
            status = health_mod.worst(status, health_mod.DEGRADED)
        out = {
            'status': status,
            'local-as': self.local_as,
            'router-id': self.router_id,
            'neighbors': total,
            'established': up,
            'attributes': self.attr_table.stats(),
            'update-groups': self.groups.stats(),
            'next-hop-validation': self.next_hop_validation,
            'networks': {'configured': len(self.network_config),
                         'originated': len(self.networks)},
            'families': {},
        }
        if blocked:
            out['auth-blocked'] = sorted(blocked)
        for af, rib in self.locribs.items():
            out['families']['%d/%d' % af] = rib.stats()
        return out

    def __repr__(self):
        return '<BGPPlugin as=%d neighbors=%d established=%d>' % (
            self.local_as, len(self.peers),
            sum(1 for p in self.peers.values() if p.established))


# --- helpers ----------------------------------------------------------------

def _router_id_int(value):
    """Accept a router id as an int or a dotted quad and return an int."""
    if isinstance(value, str):
        parts = value.split('.')
        if len(parts) == 4:
            return ((int(parts[0]) << 24) | (int(parts[1]) << 16) |
                    (int(parts[2]) << 8) | int(parts[3]))
        return 0
    return int(value or 0)


def _family_of(address):
    """Return the socket family a peer address belongs to."""
    import socket
    return socket.AF_INET6 if ':' in address else socket.AF_INET


def _addr_bytes_for_af(text, af):
    """Pack an address as a next hop of one family's width.

    :param text: the address as text, or None.
    :param af: the ``(afi, safi)`` pair the next hop is for.
    :return: packed bytes of the family's width. The unspecified address
        when there is nothing to pack or it does not parse -- which is
        not a usable next hop, and is why :meth:`BGPPlugin._local_next_hop`
        goes to some trouble to find a real one. A wrong-width answer
        would be worse than a useless one: ``AdjRibOut`` refuses to be
        constructed with it, and the family would advertise nothing at
        all.
    """
    import socket

    width = 4 if af[0] == AFI_IP else 16
    if not text:
        return b'\x00' * width
    family = socket.AF_INET6 if ':' in text else socket.AF_INET
    try:
        packed = socket.inet_pton(family, text)
    except (OSError, ValueError):
        return b'\x00' * width
    if len(packed) != width:
        return b'\x00' * width
    return packed


def _check_next_hop(text, af, path):
    """Validate a configured per-family next hop (L-4).

    It must be of the family's width and an address a peer can forward
    to: not unspecified, not multicast, and for IPv6 not link-local --
    RFC 2545 carries a link-local one only *alongside* a global address,
    which this version does not send.
    """
    import ipaddress

    try:
        addr = ipaddress.ip_address(str(text))
    except ValueError:
        raise engine_errors.ConfigError('%r is not an address' % (text,),
                                        path=path)
    want = 4 if af[0] == AFI_IP else 6
    if addr.version != want:
        raise engine_errors.ConfigError(
            'next-hop %s is IPv%d; this family needs IPv%d'
            % (text, addr.version, want), path=path)
    if addr.is_unspecified or addr.is_multicast or \
            (want == 6 and addr.is_link_local):
        raise engine_errors.ConfigError(
            'next-hop %s is not an address a peer can forward to' % text,
            path=path)


def _policy_names(entry):
    """Extract the policy names from one neighbour address-family block.

    :param entry: the block's body.
    :return: ``{'in': {...}, 'out': {...}}`` carrying only what is
        configured, or an empty dict when nothing is.
    """
    out = {}
    for direction in (DIR_IN, DIR_OUT):
        names = {}
        for key in ('route-map', 'prefix-list', 'filter-list'):
            value = (entry.get(key) or {}).get(direction)
            if value:
                names[key] = value
        if names:
            out[direction] = names
    return out


def _soft_label(soft):
    """Normalise the ``soft`` argument of a clear into a direction.

    ``True`` means inbound, because that is what ``clear ip bgp X soft``
    means on every implementation that accepts it bare, and because the
    inbound direction is the one an operator is nearly always after: it
    is the one that re-evaluates a policy edit against paths already
    received.

    :param soft: the argument as given.
    :return: ``'in'``, ``'out'``, ``'both'``, or False.
    """
    if soft is True:
        return DIR_IN
    if not soft:
        return False
    text = str(soft).lower()
    if text in (DIR_IN, DIR_OUT, 'both'):
        return text
    if text in ('true', 'yes', '1'):
        return DIR_IN
    return DIR_IN


def _sleep(loop, delay):
    """Sleep on a specific loop; see the identical helper in peer.py."""
    future = loop.create_future()

    def _wake():
        if not future.done():
            future.set_result(None)

    handle = loop.call_later(delay, _wake)
    future.add_done_callback(lambda _f: handle.cancel())
    return future
