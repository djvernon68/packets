# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""RFC 5492 capability negotiation: generous inbound, conservative outbound.

Capability negotiation is the one part of BGP where "be liberal in what you
accept, conservative in what you send" is not a style preference but the
protocol's own rule, and both halves of it are load-bearing.

**Generous on receive.** RFC 5492 requires that a capability we do not
recognise be ignored rather than rejected: an OPEN that advertises something
from a newer RFC, or a vendor's private code, is a perfectly valid OPEN. A
speaker that refuses such a session is not strict, it is broken, and it
breaks against precisely the peers that are newer than it is. Unrecognised
codes are therefore kept -- not merely tolerated -- in
:attr:`Capabilities.unknown`, so ``show`` can report what the peer claimed
and an operator can see why a family is missing without a packet capture.

**Conservative on send, and conservative on *assume*.** A capability we did
not advertise must never be treated as available just because the peer sent
it. The peer's advertisement says what the peer can do; it says nothing
about us. Getting this wrong does not produce a clean failure: we would send
a message the peer's configuration says we agreed not to send, and the peer
answers with a NOTIFICATION, so the symptom appears on the session rather
than at the line of code that assumed too much. Every field of
:class:`Negotiated` is therefore a function of *both* sides, and
:func:`negotiate` is the only place that combines them.

The direction reversal in ADD-PATH is the most common instance of that
mistake and has its own note in :func:`negotiate`.

This module defines no wire framing. The capability code and length octets,
the Optional Parameter that carries them in the OPEN, and the message size
limits belong to ``wire``; here a capability is a ``(code, value_bytes)``
pair and nothing else, which is also why the encoders return the value only.
"""

import struct

# Pre-compiled because these run once per capability per OPEN rather than per
# prefix, and because a compiled Struct is how the rest of the codec spells
# fixed-layout access.
_ST_MP_EXT = struct.Struct('!HBB')     # AFI, reserved, SAFI
_ST_ADD_PATH = struct.Struct('!HBB')   # AFI, SAFI, Send/Receive
_ST_U32 = struct.Struct('!I')
_ST_U16 = struct.Struct('!H')

# --- Capability codes (RFC 5492 and the IANA registry) ----------------------

CAP_MP_EXT = 1                     # RFC 4760
CAP_ROUTE_REFRESH = 2              # RFC 2918
CAP_EXT_NEXTHOP = 5                # RFC 8950
CAP_EXTENDED_MESSAGE = 6           # RFC 8654
CAP_GRACEFUL_RESTART = 64          # RFC 4724
CAP_AS4 = 65                       # RFC 6793
CAP_ADD_PATH = 69                  # RFC 7911
CAP_ENHANCED_ROUTE_REFRESH = 70    # RFC 7313
# Route Refresh as it was deployed before RFC 2918 got its code point.
# Still emitted by long-lived installations, and still recognised here for
# the same reason: refusing to understand it costs a refresh capability on a
# session that would otherwise have had one. We never advertise it.
CAP_ROUTE_REFRESH_CISCO = 128

_CAP_NAMES = {
    CAP_MP_EXT: 'Multiprotocol Extensions',
    CAP_ROUTE_REFRESH: 'Route Refresh',
    CAP_EXT_NEXTHOP: 'Extended Next Hop Encoding',
    CAP_EXTENDED_MESSAGE: 'Extended Message',
    CAP_GRACEFUL_RESTART: 'Graceful Restart',
    CAP_AS4: '4-octet AS Number',
    CAP_ADD_PATH: 'ADD-PATH',
    CAP_ENHANCED_ROUTE_REFRESH: 'Enhanced Route Refresh',
    CAP_ROUTE_REFRESH_CISCO: 'Route Refresh (pre-standard)',
}


def capability_name(code):
    """Return a readable name for a capability code.

    :param code: the capability code.
    :return: the registry name, or ``'Capability <n>'`` for a code we do
        not know. The number is kept in the string on purpose: for an
        unknown capability it is the only thing an operator can act on.
    """
    name = _CAP_NAMES.get(code)
    if name is None:
        return 'Capability %s' % (code,)
    return name


# --- Address families -------------------------------------------------------
# These are the IANA Address Family Numbers and SAFI values, which are the
# same numbers the engine's rib.prefix uses for its keys (see the comment on
# PFX_AFI_IP there). Keeping one numbering from the wire through to the RIB
# key means an (afi, safi) from a capability can be compared against a
# Prefix's family with no translation table in between -- and a translation
# table is exactly the sort of thing that develops a missing row.

AFI_IP = 1
AFI_IP6 = 2
SAFI_UNICAST = 1

_AFI_NAMES = {AFI_IP: 'IPv4', AFI_IP6: 'IPv6'}
_SAFI_NAMES = {SAFI_UNICAST: 'Unicast'}


def afi_safi_name(afi, safi):
    """Return a readable name for an address family pair.

    :param afi: IANA address family number.
    :param safi: subsequent address family identifier.
    :return: e.g. ``'IPv4 Unicast'``, or a numeric rendering for a pair the
        engine does not carry.
    """
    return '%s %s' % (_AFI_NAMES.get(afi, 'AFI %s' % (afi,)),
                      _SAFI_NAMES.get(safi, 'SAFI %s' % (safi,)))


# --- ADD-PATH directions (RFC 7911) -----------------------------------------
# The value is a direction *as the sender describes itself*: SEND means "I
# will send you multiple paths". See negotiate() for why that matters.

ADD_PATH_RECEIVE = 1
ADD_PATH_SEND = 2
ADD_PATH_BOTH = 3

_ADD_PATH_NAMES = {
    ADD_PATH_RECEIVE: 'receive',
    ADD_PATH_SEND: 'send',
    ADD_PATH_BOTH: 'both',
}

# The two message ceilings from RFC 4271 and RFC 8654. Private, because the
# named limits and the framing checks that enforce them belong to ``wire``;
# all this module does is decide which of the two applies to a session.
_MSG_SIZE = 4096
_MSG_SIZE_EXTENDED = 65535


# --- Encoders ---------------------------------------------------------------
# Each returns the capability *value* only. The caller writes the code and
# length octets, because the same value has to go into an OPEN's Optional
# Parameters with a different framing than anything else would use, and a
# value that already carried its own header could not be reused.
#
# These validate and raise, unlike the decoders below. Their input is our own
# configuration, not a peer's packet: a hold time of 70000 in a config file
# is a mistake somebody has to hear about, and silently truncating it would
# produce a session that works differently from what was asked for.


def encode_mp_ext(afi, safi):
    """Encode a Multiprotocol Extensions capability value (RFC 4760).

    :param afi: IANA address family number.
    :param safi: subsequent address family identifier.
    :return: four bytes: AFI, a reserved octet, SAFI.
    :raises ValueError: a value that does not fit its field.
    """
    if not 0 <= afi <= 0xffff:
        raise ValueError('afi %r out of range' % (afi,))
    if not 0 <= safi <= 0xff:
        raise ValueError('safi %r out of range' % (safi,))
    return _ST_MP_EXT.pack(afi, 0, safi)


def encode_as4(asn):
    """Encode a 4-octet AS Number capability value (RFC 6793).

    :param asn: our autonomous system number.
    :return: four bytes, network order.
    :raises ValueError: the ASN does not fit in 32 bits.
    """
    if not 0 <= asn <= 0xffffffff:
        raise ValueError('asn %r out of range' % (asn,))
    return _ST_U32.pack(asn)


def encode_add_path(pairs):
    """Encode an ADD-PATH capability value (RFC 7911).

    :param pairs: a sequence of ``(afi, safi, direction)``, where direction
        is one of the ``ADD_PATH_*`` constants and describes what *we* do.
    :return: four bytes per pair, in the order given. The order is the
        caller's so that a configured family list produces a
        byte-identical OPEN every time, which is what lets a test compare
        against a fixture.
    :raises ValueError: an out-of-range field or an unknown direction.
    """
    out = []
    for afi, safi, direction in pairs:
        if not 0 <= afi <= 0xffff:
            raise ValueError('afi %r out of range' % (afi,))
        if not 0 <= safi <= 0xff:
            raise ValueError('safi %r out of range' % (safi,))
        if direction not in _ADD_PATH_NAMES:
            raise ValueError('add-path direction %r is not one of 1, 2, 3'
                             % (direction,))
        out.append(_ST_ADD_PATH.pack(afi, safi, direction))
    return b''.join(out)


def encode_graceful_restart(restart_time, flags=0):
    """Encode a Graceful Restart capability value (RFC 4724).

    The value is four bits of flags followed by a twelve-bit Restart Time,
    optionally followed by one record per family whose forwarding state is
    preserved. No records are written here: advertising a family means
    promising to keep forwarding with stale routes across a restart, and a
    promise nothing in the engine implements yet would be a lie the peer
    acts on. A bare capability still has value -- it tells the peer we will
    hold *its* routes while it restarts.

    :param restart_time: seconds, 0 to 4095.
    :param flags: the four-bit flags field; bit 0x8 is Restart State.
    :return: two bytes.
    :raises ValueError: either field out of range.
    """
    if not 0 <= restart_time <= 0xfff:
        raise ValueError('restart_time %r out of range (0-4095)'
                         % (restart_time,))
    if not 0 <= flags <= 0xf:
        raise ValueError('flags %r out of range (0-15)' % (flags,))
    return _ST_U16.pack((flags << 12) | restart_time)


def encode_route_refresh():
    """Encode a Route Refresh capability value (RFC 2918).

    :return: ``b''``. The capability is its own statement; a zero-length
        value is the encoding, not a placeholder.
    """
    return b''


def encode_extended_message():
    """Encode an Extended Message capability value (RFC 8654).

    :return: ``b''``, for the same reason as Route Refresh.
    """
    return b''


# --- Decoders ---------------------------------------------------------------
# None of these raise. They run on the OPEN a stranger sent us, and an
# exception here would break the session at the moment we are deciding
# whether we can talk to the peer at all -- which is both the least
# informative failure available and a denial of service anyone could trigger
# with four bad bytes.
#
# The receive policy is uniform: a value shorter than the fixed part is
# malformed and reports None, while trailing bytes beyond it are ignored
# rather than treated as fatal. The latter is the generous half of RFC 5492
# applied one level down -- a longer value than we expect is most likely a
# field added by a document we have not read.


def decode_mp_ext(value):
    """Decode a Multiprotocol Extensions capability value.

    :param value: the capability value bytes.
    :return: ``(afi, safi)``, or None if the value is too short. The
        reserved octet is not returned and not checked: RFC 4760 requires
        the receiver to ignore it, and a peer that sets it has not said
        anything about its families.
    """
    try:
        if value is None or len(value) < _ST_MP_EXT.size:
            return None
        afi, _reserved, safi = _ST_MP_EXT.unpack_from(value, 0)
    except (struct.error, TypeError):
        return None
    return (afi, safi)


def decode_as4(value):
    """Decode a 4-octet AS Number capability value.

    AS 0 is returned unchanged even though RFC 7607 forbids it on the wire.
    Rejecting it here would report "malformed capability" for what is
    really a bad ASN, and the FSM needs the value so it can answer with
    OPEN/Bad Peer AS and log the number the peer actually claimed.

    :param value: the capability value bytes.
    :return: the ASN, or None if the value is too short.
    """
    try:
        if value is None or len(value) < _ST_U32.size:
            return None
        return _ST_U32.unpack_from(value, 0)[0]
    except (struct.error, TypeError):
        return None


def decode_add_path(value):
    """Decode an ADD-PATH capability value.

    :param value: the capability value bytes.
    :return: a list of ``(afi, safi, direction)``, empty when nothing could
        be read. The field is a repeating four-byte record, so a trailing
        partial record is dropped and the whole records before it are kept:
        losing every family because the last four bytes were three would
        turn a sender's off-by-one into our outage. A record with a
        direction outside 1-3 is skipped for the same reason -- it says
        nothing usable about that family, and says nothing at all about the
        others.
    """
    out = []
    if value is None:
        return out
    try:
        size = _ST_ADD_PATH.size
        end = len(value) - (len(value) % size)
        off = 0
        while off < end:
            afi, safi, direction = _ST_ADD_PATH.unpack_from(value, off)
            off += size
            if direction in _ADD_PATH_NAMES:
                out.append((afi, safi, direction))
    except (struct.error, TypeError):
        # Whatever was decoded before the fault is still true, so it is
        # kept rather than thrown away with the remainder.
        return out
    return out


class Capabilities(object):
    """What one side of a session advertises.

    Used for both ends: the local instance is built from configuration and
    encoded into the OPEN, the remote one is built by
    :meth:`from_tlvs` from the OPEN we received. Keeping one class for both
    is what lets :func:`negotiate` be a symmetric function of two objects
    instead of a method that quietly privileges one side.

    Every capability defaults to "not advertised". That direction of
    default is deliberate: an unset field means we promise nothing, so a
    field somebody forgets to wire up from configuration produces a session
    with fewer features rather than a session that claims a feature the
    engine has not implemented.

    :param asn: this side's autonomous system number, or None.
    :param afi_safi: an iterable of ``(afi, safi)`` pairs; stored as a set.
    :param as4: 4-octet AS number support.
    :param route_refresh: RFC 2918 Route Refresh.
    :param enhanced_route_refresh: RFC 7313 BoRR/EoRR demarcation.
    :param extended_message: RFC 8654 65535-octet messages.
    :param add_path: a dict of ``(afi, safi) -> direction`` describing what
        this side does, using the ``ADD_PATH_*`` constants.
    :param graceful_restart: False when not advertised; otherwise the
        Restart Time in seconds, with True standing for a Restart Time of
        zero. The field doubles as "was it advertised", and a zero restart
        time is a real advertisement (it means "expect nothing of me"), so
        it cannot be stored as the integer 0 without becoming invisible.
    :param unknown: a list of ``(code, value_bytes)`` this side sent that we
        do not implement. Only ever populated on the remote side.
    """

    __slots__ = ('asn', 'afi_safi', 'as4', 'route_refresh',
                 'enhanced_route_refresh', 'extended_message', 'add_path',
                 'graceful_restart', 'unknown')

    def __init__(self, asn=None, afi_safi=None, as4=False,
                 route_refresh=False, enhanced_route_refresh=False,
                 extended_message=False, add_path=None,
                 graceful_restart=False, unknown=None):
        self.asn = asn
        self.afi_safi = set(afi_safi) if afi_safi else set()
        self.as4 = bool(as4)
        self.route_refresh = bool(route_refresh)
        self.enhanced_route_refresh = bool(enhanced_route_refresh)
        self.extended_message = bool(extended_message)
        self.add_path = dict(add_path) if add_path else {}
        self.graceful_restart = graceful_restart
        self.unknown = list(unknown) if unknown else []

    def as_tlvs(self):
        """Return the capabilities to advertise, in order.

        The order is fixed rather than dictionary order so that one
        configuration always produces one byte sequence: an OPEN that
        differs between runs cannot be compared against a fixture, and a
        capture from a customer cannot be matched against a build.

        ``unknown`` is not emitted. Those codes came from the peer, and
        echoing a capability we do not implement back at it would promise
        behaviour we do not have -- the exact failure the module docstring
        opens with.

        :return: a list of ``(code, value_bytes)``.
        :raises ValueError: a field that does not fit the wire format, or
            ``as4`` set with no ASN to put in it.
        """
        tlvs = []
        # Families first: they are what the session is for, and a capture is
        # easier to read when they are at a predictable offset.
        for afi, safi in sorted(self.afi_safi):
            tlvs.append((CAP_MP_EXT, encode_mp_ext(afi, safi)))
        if self.route_refresh:
            tlvs.append((CAP_ROUTE_REFRESH, encode_route_refresh()))
        if self.extended_message:
            tlvs.append((CAP_EXTENDED_MESSAGE, encode_extended_message()))
        if self.graceful_restart:
            restart = 0 if self.graceful_restart is True \
                else int(self.graceful_restart)
            tlvs.append((CAP_GRACEFUL_RESTART,
                         encode_graceful_restart(restart)))
        if self.as4:
            # Advertising AS4 without an ASN would be an empty promise, and
            # the value is where a 4-byte ASN is actually carried: the
            # OPEN's own field is two octets and holds AS_TRANS for us.
            if self.asn is None:
                raise ValueError('as4 advertised without an asn')
            tlvs.append((CAP_AS4, encode_as4(self.asn)))
        if self.add_path:
            pairs = [(afi, safi, self.add_path[(afi, safi)])
                     for afi, safi in sorted(self.add_path)]
            tlvs.append((CAP_ADD_PATH, encode_add_path(pairs)))
        if self.enhanced_route_refresh:
            # Zero-length, like Route Refresh, and with no encoder of its
            # own: a helper that can only ever return b'' would be one more
            # name to look up for no information.
            tlvs.append((CAP_ENHANCED_ROUTE_REFRESH, b''))
        return tlvs

    @classmethod
    def from_tlvs(cls, tlvs, asn=None):
        """Build one side's capabilities from decoded ``(code, value)``.

        A capability code we recognise but whose value will not decode is
        ignored, leaving the field at its default: the peer then simply
        does not have that capability, which is both the RFC 5492 answer
        and the only answer that does not let four malformed bytes cost a
        session.

        :param tlvs: an iterable of ``(code, value_bytes)`` as read from
            the OPEN's Capabilities Optional Parameter.
        :param asn: the ASN from the OPEN header, used when the peer sends
            no 4-octet AS capability.
        :return: a new :class:`Capabilities`.
        """
        cap = cls(asn=asn)
        for code, value in tlvs:
            if code == CAP_MP_EXT:
                pair = decode_mp_ext(value)
                if pair is not None:
                    cap.afi_safi.add(pair)
            elif code == CAP_ROUTE_REFRESH:
                cap.route_refresh = True
            elif code == CAP_ROUTE_REFRESH_CISCO:
                # Treated as the standard capability, because that is what
                # the senders of it mean. It is recorded as unknown as well
                # so show output can tell an operator which of the two the
                # peer actually sent.
                cap.route_refresh = True
                cap.unknown.append((code, value))
            elif code == CAP_ENHANCED_ROUTE_REFRESH:
                cap.enhanced_route_refresh = True
            elif code == CAP_EXTENDED_MESSAGE:
                cap.extended_message = True
            elif code == CAP_AS4:
                peer_as = decode_as4(value)
                if peer_as is not None:
                    cap.as4 = True
                    # The capability wins over the header. A peer whose ASN
                    # does not fit in two octets is required to put
                    # AS_TRANS (23456) in the OPEN and its real ASN here,
                    # so trusting the header would give every such peer the
                    # same ASN. Whether the two agree for a peer that could
                    # have used the header is the FSM's check, not ours.
                    cap.asn = peer_as
            elif code == CAP_ADD_PATH:
                for afi, safi, direction in decode_add_path(value):
                    cap.add_path[(afi, safi)] = direction
            elif code == CAP_GRACEFUL_RESTART:
                if value is not None and len(value) >= _ST_U16.size:
                    restart = _ST_U16.unpack_from(value, 0)[0] & 0xfff
                    cap.graceful_restart = restart or True
            else:
                # Kept, not dropped. An unrecognised capability is a legal
                # capability (RFC 5492), and the list is what lets an
                # operator see that the peer offered something this build
                # does not speak.
                cap.unknown.append((code, value))
        return cap

    def as_dict(self):
        """Return the advertisement as plain types for show output.

        :return: a dict of plain types. Families appear both as numbers and
            as names: the numbers are what the wire and the RIB use, the
            names are what an operator reads. Unknown capabilities report
            their code, name and value length rather than their bytes,
            because a show line is not a packet capture.
        """
        return {
            'asn': self.asn,
            'afi_safi': [[afi, safi] for afi, safi in sorted(self.afi_safi)],
            'families': [afi_safi_name(afi, safi)
                         for afi, safi in sorted(self.afi_safi)],
            'as4': self.as4,
            'route_refresh': self.route_refresh,
            'enhanced_route_refresh': self.enhanced_route_refresh,
            'extended_message': self.extended_message,
            'add_path': [{'afi': afi, 'safi': safi,
                          'family': afi_safi_name(afi, safi),
                          'direction': _ADD_PATH_NAMES.get(
                              self.add_path[(afi, safi)], 'unknown')}
                         for afi, safi in sorted(self.add_path)],
            'graceful_restart': self.graceful_restart,
            'unknown': [{'code': code, 'name': capability_name(code),
                         'length': len(value) if value else 0}
                        for code, value in self.unknown],
        }

    def __repr__(self):
        return '<Capabilities asn=%s families=%d as4=%s>' % (
            self.asn, len(self.afi_safi), self.as4)


class Negotiated(object):
    """The result: what this session may actually do.

    Every field here is a decision about the session rather than a claim by
    one side, and the rest of the plugin reads only this. That is the
    invariant worth protecting: no code outside :func:`negotiate` should
    ever consult a peer's advertisement to decide what to send, because
    that is how a session ends up sending something only one of the two
    ends agreed to.

    :param afi_safi: the families in use, as a set of ``(afi, safi)``.
    :param as4: both sides speak 4-octet ASNs.
    :param route_refresh: the peer will honour a REFRESH request.
    :param enhanced_route_refresh: BoRR/EoRR demarcation is in use.
    :param extended_message: both sides agreed to large messages.
    :param add_path_recv: families for which we may *receive* more than one
        path per prefix.
    :param add_path_send: families for which we may *send* more than one.
    :param max_message_size: the ceiling for UPDATE, NOTIFICATION and
        ROUTE-REFRESH on this session.
    :param peer_asn: the peer's effective ASN.
    :param peer_as4: whether the peer advertised 4-octet AS support, which
        the encoder needs on its own: it decides whether AS4_PATH and
        AS4_AGGREGATOR have to be constructed for this peer, and that is
        not the same question as whether both sides support it.
    """

    __slots__ = ('afi_safi', 'as4', 'route_refresh',
                 'enhanced_route_refresh', 'extended_message',
                 'add_path_recv', 'add_path_send', 'max_message_size',
                 'peer_asn', 'peer_as4')

    def __init__(self, afi_safi=None, as4=False, route_refresh=False,
                 enhanced_route_refresh=False, extended_message=False,
                 add_path_recv=None, add_path_send=None,
                 max_message_size=_MSG_SIZE, peer_asn=None, peer_as4=False):
        self.afi_safi = set(afi_safi) if afi_safi else set()
        self.as4 = bool(as4)
        self.route_refresh = bool(route_refresh)
        self.enhanced_route_refresh = bool(enhanced_route_refresh)
        self.extended_message = bool(extended_message)
        self.add_path_recv = set(add_path_recv) if add_path_recv else set()
        self.add_path_send = set(add_path_send) if add_path_send else set()
        self.max_message_size = max_message_size
        self.peer_asn = peer_asn
        self.peer_as4 = bool(peer_as4)

    def as_dict(self):
        """Return the negotiated session parameters as plain types.

        :return: a dict of plain types for ``show ip bgp neighbors``.
        """
        return {
            'afi_safi': [[afi, safi] for afi, safi in sorted(self.afi_safi)],
            'families': [afi_safi_name(afi, safi)
                         for afi, safi in sorted(self.afi_safi)],
            'as4': self.as4,
            'route_refresh': self.route_refresh,
            'enhanced_route_refresh': self.enhanced_route_refresh,
            'extended_message': self.extended_message,
            'add_path_recv': [afi_safi_name(afi, safi)
                              for afi, safi in sorted(self.add_path_recv)],
            'add_path_send': [afi_safi_name(afi, safi)
                              for afi, safi in sorted(self.add_path_send)],
            'max_message_size': self.max_message_size,
            'peer_asn': self.peer_asn,
            'peer_as4': self.peer_as4,
        }

    def __repr__(self):
        return '<Negotiated peer_asn=%s families=%d max=%d>' % (
            self.peer_asn, len(self.afi_safi), self.max_message_size)


def negotiate(local, remote):
    """Combine two advertisements into what the session may do.

    :param local: our :class:`Capabilities`, from configuration.
    :param remote: the peer's, from :meth:`Capabilities.from_tlvs`.
    :return: a :class:`Negotiated`.
    """
    families = local.afi_safi & remote.afi_safi
    if not families and not remote.afi_safi:
        # RFC 4760 section 8: a speaker that sends no Multiprotocol
        # Extensions capability is an IPv4-unicast speaker, not a speaker
        # with no families. Intersecting with an empty set would leave the
        # session with nothing to carry and no error to report, which is
        # the worst of both -- so the default family is assumed, but only
        # if we configured it. Assuming it when we did not would be the
        # same mistake in the other direction.
        if (AFI_IP, SAFI_UNICAST) in local.afi_safi:
            families = set([(AFI_IP, SAFI_UNICAST)])

    # Every one of these is an AND, never an OR and never the peer's value
    # alone: a capability is a mutual agreement, and one side's willingness
    # is not an agreement. AS4 in particular changes how the AS_PATH is
    # encoded in both directions, so acting on the peer's advertisement
    # alone would put a path on the wire it cannot parse.
    as4 = bool(local.as4 and remote.as4)
    route_refresh = bool(local.route_refresh and remote.route_refresh)
    enhanced = bool(local.enhanced_route_refresh
                    and remote.enhanced_route_refresh)
    extended = bool(local.extended_message and remote.extended_message)

    # ADD-PATH is stated from the sender's point of view, so the two sides
    # have to be read crosswise: we may RECEIVE multiple paths for a family
    # when the PEER said SEND and WE said RECEIVE. Comparing like with like
    # -- our RECEIVE against the peer's RECEIVE -- is the classic ADD-PATH
    # bug, and it fails in the ugliest possible way: both ends think they
    # agreed, the peer sends path identifiers, and we parse them as part of
    # the NLRI, so every prefix in the UPDATE is garbage.
    add_path_recv = set()
    for family in families:
        peer_dir = remote.add_path.get(family, 0)
        local_dir = local.add_path.get(family, 0)
        if (peer_dir & ADD_PATH_SEND) and (local_dir & ADD_PATH_RECEIVE):
            add_path_recv.add(family)

    # Empty in v1: the engine advertises no ADD-PATH send capability, so
    # there is no family it may send multiple paths for. Computed as a set
    # rather than omitted so that turning it on later is a change here and
    # nowhere else.
    add_path_send = set()

    # RFC 8654. The raised ceiling applies only when both sides asked for
    # it -- sending 65535 octets to a peer with a 4096-octet buffer is a
    # reset, not a degradation. It also does not apply to every message
    # even then: OPEN and KEEPALIVE keep the original limits regardless,
    # because the OPEN is what negotiates this in the first place. Enforcing
    # that per message type is wire's job; this field is the UPDATE,
    # NOTIFICATION and ROUTE-REFRESH ceiling only.
    max_size = _MSG_SIZE_EXTENDED if extended else _MSG_SIZE

    return Negotiated(
        afi_safi=families,
        as4=as4,
        route_refresh=route_refresh,
        enhanced_route_refresh=enhanced,
        extended_message=extended,
        add_path_recv=add_path_recv,
        add_path_send=add_path_send,
        max_message_size=max_size,
        peer_asn=remote.asn,
        peer_as4=remote.as4,
    )


def missing_required(local, negotiated):
    """Name the locally configured families the peer did not support.

    The FSM uses this to decide whether to answer an OPEN with
    NOTIFICATION OPEN/Unsupported Capability, and to say why in the log.
    The strings are the point: "peer does not support IPv6 Unicast" is a
    line an operator can act on, whereas the NOTIFICATION alone sends them
    to a packet capture.

    :param local: our :class:`Capabilities`.
    :param negotiated: the result of :func:`negotiate`.
    :return: a list of readable strings, empty when nothing is missing.
    """
    missing = []
    for afi, safi in sorted(local.afi_safi):
        if (afi, safi) not in negotiated.afi_safi:
            missing.append('peer does not support %s'
                           % afi_safi_name(afi, safi))
    return missing
