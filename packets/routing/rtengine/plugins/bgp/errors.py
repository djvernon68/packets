# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""RFC 7606 error handling, as a table rather than as a reflex.

RFC 4271 had one answer for a malformed path attribute: send a NOTIFICATION
and drop the session. That answer is almost always wrong, and expensively
so. A reset does not punish the one route that carried the bad attribute --
it discards every route learned over that session, forces a full table
relearn in both directions, and on a full-feed peer that is hundreds of
thousands of prefixes and seconds to minutes of churn. Worse, optional
transitive attributes are propagated unchecked by speakers that do not
recognise them, so the session that breaks is frequently between two
innocent routers several hops from whoever originated the damage.

RFC 7606 replaces the reflex with a graded response, and this module is
that grading: **session reset** only when the UPDATE cannot be parsed far
enough to know which prefixes it was talking about, **treat-as-withdraw**
when the NLRI is readable but the attributes cannot be trusted (the
prefixes in that UPDATE are withdrawn, the session lives), and **attribute
discard** when the attribute has no bearing on what the route is or where
it points. The rule for choosing is simple to state and easy to get wrong
in an ``if`` chain: the response must be proportional to the damage.

So the mapping lives in a module-level dict keyed by attribute type code,
not in a chain of branches. A table can be read against the RFC line by
line in review, diffed when a new attribute is added, and -- unlike a
branch chain -- cannot grow a path that quietly falls through to "reset".

Two deliberate boundaries:

* **Nothing here raises, and nothing here decodes.** The decoder hands this
  module a type code and a reason and gets a string back. That keeps the
  matrix testable without a wire buffer, and keeps the packet-processing
  path free of exceptions: an exception escaping the decode of one peer's
  UPDATE would drop the session, which is precisely the outcome the RFC is
  trying to avoid.
* **The attribute type codes are not defined here.** ``wire`` owns them,
  along with message framing, attribute flags and the size limits. A second
  set of ``ATTR_*`` constants in this module would be a second source of
  truth to drift, so the table is keyed by the raw code with the name in a
  comment on the row.

The outcome vocabulary and the per-attribute reason are also what
``show ip bgp neighbors`` and ``/engine/health`` report, which is why
:class:`PeerErrorCounters` keeps them separately rather than summing them
into one "errors" number. "Forty-one attribute discards on one optional
attribute" and "forty-one withdrawn UPDATEs" are the same count and very
different problems.
"""

# --- NOTIFICATION error codes (RFC 4271 section 4.5) ------------------------
# On the wire these are one octet of code plus one of subcode. They are named
# here, rather than in the codec, because the FSM and the log lines use them
# far more than the codec does: almost every one of these is chosen by a
# policy decision somewhere above the wire format.

NOTIFY_HEADER = 1
NOTIFY_OPEN = 2
NOTIFY_UPDATE = 3
NOTIFY_HOLD_TIMER = 4
NOTIFY_FSM = 5
NOTIFY_CEASE = 6
NOTIFY_ROUTE_REFRESH = 7          # RFC 7313

# --- Message Header Error subcodes ------------------------------------------

HDR_CONN_NOT_SYNC = 1
HDR_BAD_LENGTH = 2
HDR_BAD_TYPE = 3

# --- OPEN Message Error subcodes --------------------------------------------
# 8, 9 and 10 are absent because they are not assigned: subcode 5
# (Authentication Failure) was deprecated by RFC 4271 but kept its number,
# and 11 (Role Mismatch) was added much later by RFC 9234. The gap is the
# registry's, not an omission here.

# Subcode 0, "Unspecific": an OPEN that cannot be parsed at all -- a
# truncated optional parameter, say -- is not *unsupported*, and calling it
# that sends the peer's operator looking for a capability mismatch.
OPEN_UNSPECIFIC = 0
OPEN_UNSUPPORTED_VERSION = 1
OPEN_BAD_PEER_AS = 2
OPEN_BAD_BGP_ID = 3
OPEN_UNSUPPORTED_OPT_PARAM = 4
OPEN_AUTH_FAILURE = 5
OPEN_UNACCEPTABLE_HOLD_TIME = 6
OPEN_UNSUPPORTED_CAPABILITY = 7   # RFC 5492
OPEN_ROLE_MISMATCH = 11           # RFC 9234

# --- UPDATE Message Error subcodes ------------------------------------------
# Subcode 7 (AS Routing Loop) is deprecated and deliberately not defined,
# which is why 8 follows 6 here. A loop is detected by finding our own ASN in
# the AS_PATH and is handled by dropping the route, not by breaking the
# session.

UPD_MALFORMED_ATTR_LIST = 1
UPD_UNRECOGNIZED_WELLKNOWN_ATTR = 2
UPD_MISSING_WELLKNOWN_ATTR = 3
UPD_ATTR_FLAGS = 4
UPD_ATTR_LENGTH = 5
UPD_INVALID_ORIGIN = 6
UPD_INVALID_NEXTHOP = 8
UPD_OPTIONAL_ATTR = 9
UPD_INVALID_NETWORK = 10
UPD_MALFORMED_AS_PATH = 11

# --- Cease subcodes (RFC 4486) ----------------------------------------------
# These exist so a shutdown says why. A peer that receives
# Cease/Administrative Shutdown knows not to retry aggressively; one that
# receives a bare Cease has to guess, and usually guesses "flap".

CEASE_MAX_PREFIXES = 1
CEASE_ADMIN_SHUTDOWN = 2
CEASE_PEER_DECONFIGURED = 3
CEASE_ADMIN_RESET = 4
CEASE_CONNECTION_REJECTED = 5
CEASE_OTHER_CONFIG_CHANGE = 6
CEASE_COLLISION_RESOLUTION = 7
CEASE_OUT_OF_RESOURCES = 8

# --- Human-readable names ---------------------------------------------------
# The spellings are the RFC's own, because an operator comparing our log
# line with a vendor's log line or with the RFC should not have to translate.

_CODE_NAMES = {
    NOTIFY_HEADER: 'Message Header Error',
    NOTIFY_OPEN: 'OPEN Message Error',
    NOTIFY_UPDATE: 'UPDATE Message Error',
    NOTIFY_HOLD_TIMER: 'Hold Timer Expired',
    NOTIFY_FSM: 'Finite State Machine Error',
    NOTIFY_CEASE: 'Cease',
    NOTIFY_ROUTE_REFRESH: 'ROUTE-REFRESH Message Error',
}

_SUBCODE_NAMES = {
    NOTIFY_HEADER: {
        HDR_CONN_NOT_SYNC: 'Connection Not Synchronized',
        HDR_BAD_LENGTH: 'Bad Message Length',
        HDR_BAD_TYPE: 'Bad Message Type',
    },
    NOTIFY_OPEN: {
        OPEN_UNSUPPORTED_VERSION: 'Unsupported Version Number',
        OPEN_BAD_PEER_AS: 'Bad Peer AS',
        OPEN_BAD_BGP_ID: 'Bad BGP Identifier',
        OPEN_UNSUPPORTED_OPT_PARAM: 'Unsupported Optional Parameter',
        OPEN_AUTH_FAILURE: 'Authentication Failure',
        OPEN_UNACCEPTABLE_HOLD_TIME: 'Unacceptable Hold Time',
        OPEN_UNSUPPORTED_CAPABILITY: 'Unsupported Capability',
        OPEN_ROLE_MISMATCH: 'Role Mismatch',
    },
    NOTIFY_UPDATE: {
        UPD_MALFORMED_ATTR_LIST: 'Malformed Attribute List',
        UPD_UNRECOGNIZED_WELLKNOWN_ATTR: 'Unrecognized Well-known Attribute',
        UPD_MISSING_WELLKNOWN_ATTR: 'Missing Well-known Attribute',
        UPD_ATTR_FLAGS: 'Attribute Flags Error',
        UPD_ATTR_LENGTH: 'Attribute Length Error',
        UPD_INVALID_ORIGIN: 'Invalid ORIGIN Attribute',
        UPD_INVALID_NEXTHOP: 'Invalid NEXT_HOP Attribute',
        UPD_OPTIONAL_ATTR: 'Optional Attribute Error',
        UPD_INVALID_NETWORK: 'Invalid Network Field',
        UPD_MALFORMED_AS_PATH: 'Malformed AS_PATH',
    },
    NOTIFY_CEASE: {
        CEASE_MAX_PREFIXES: 'Maximum Number of Prefixes Reached',
        CEASE_ADMIN_SHUTDOWN: 'Administrative Shutdown',
        CEASE_PEER_DECONFIGURED: 'Peer De-configured',
        CEASE_ADMIN_RESET: 'Administrative Reset',
        CEASE_CONNECTION_REJECTED: 'Connection Rejected',
        CEASE_OTHER_CONFIG_CHANGE: 'Other Configuration Change',
        CEASE_COLLISION_RESOLUTION: 'Connection Collision Resolution',
        CEASE_OUT_OF_RESOURCES: 'Out of Resources',
    },
    # RFC 7313 defines exactly one, and no constant is exported for it
    # because nothing in the engine chooses it by name yet.
    NOTIFY_ROUTE_REFRESH: {
        1: 'Invalid Message Length',
    },
}


def notify_name(code, subcode=None):
    """Return a readable name for a NOTIFICATION code and subcode.

    Used by ``show ip bgp neighbors`` (which reports the last NOTIFICATION
    in each direction) and by the FSM's log lines. An unregistered value is
    rendered numerically rather than replaced by 'unknown': when a peer
    sends something we have never heard of, the number is the only useful
    thing in the message and hiding it makes the log useless.

    :param code: the NOTIFICATION error code.
    :param subcode: the error subcode, or None to name the code alone.
    :return: e.g. ``'UPDATE Message Error/Malformed AS_PATH'``.
    """
    name = _CODE_NAMES.get(code)
    if name is None:
        name = 'Error Code %s' % (code,)
    if subcode is None:
        return name
    sub = _SUBCODE_NAMES.get(code, {}).get(subcode)
    if sub is None:
        # Subcode 0 is "unspecified" for every code, and is the correct
        # thing to send with Hold Timer Expired or an FSM error, so it is
        # not an unknown value.
        if subcode == 0:
            return name
        sub = 'Subcode %s' % (subcode,)
    return '%s/%s' % (name, sub)


# --- Outcomes ---------------------------------------------------------------
# Strings, not an enum, for the same reason the event names in events.py are
# strings: they appear verbatim in health output, in show output and in log
# lines, and a caller comparing against 'treat-as-withdraw' should not have
# to import a symbol to do it.

OUTCOME_OK = 'ok'
OUTCOME_DISCARD = 'attribute-discard'
OUTCOME_WITHDRAW = 'treat-as-withdraw'
OUTCOME_RESET = 'session-reset'

OUTCOMES = (OUTCOME_OK, OUTCOME_DISCARD, OUTCOME_WITHDRAW, OUTCOME_RESET)

# Severity order, least to most damaging. RFC 7606 presents its three
# approaches in exactly this order and requires that an UPDATE carrying
# several malformed attributes be handled by the most severe outcome any one
# of them selects -- discarding a stray attribute is no help if another
# attribute in the same message means the prefixes cannot be trusted.
# Two-phase decode (parse everything, then apply) is what makes that
# possible: every fault is known before anything is applied.
_SEVERITY = {
    OUTCOME_OK: 0,
    OUTCOME_DISCARD: 1,
    OUTCOME_WITHDRAW: 2,
    OUTCOME_RESET: 3,
}

# --- Reasons ----------------------------------------------------------------
# Why an attribute was rejected, as opposed to what we do about it. The pair
# (attribute, reason) is what a counter is keyed by, because "attribute 16
# rejected 900 times for bad length" points at one buggy sender while a bare
# per-attribute count does not.

REASON_FLAGS = 'attribute-flags'
REASON_LENGTH = 'attribute-length'
REASON_VALUE = 'attribute-value'
REASON_DUPLICATE = 'duplicate-attribute'
REASON_MISSING = 'missing-attribute'
REASON_UNPARSEABLE = 'unparseable'
# The old spelling of REASON_UNPARSEABLE, kept for one release so callers
# outside this package do not break; wire has only ever used the new one.
REASON_UNRESOLVABLE = REASON_UNPARSEABLE
# A well-formed MP_REACH_NLRI or MP_UNREACH_NLRI for an address family this
# session did not negotiate (or that rtengine does not carry at all). Its
# own reason, because it is not malformed: the peer is offering something
# we never agreed to take, and the answer is to ignore it. Filed under
# REASON_VALUE it fell to the MP rows of the matrix, which reset -- any peer
# could drop the session at will by offering VPNv4 (review finding L-3).
REASON_UNNEGOTIATED = 'unnegotiated-family'

REASONS = (REASON_FLAGS, REASON_LENGTH, REASON_VALUE, REASON_DUPLICATE,
           REASON_MISSING, REASON_UNPARSEABLE, REASON_UNNEGOTIATED)

# The attribute list as a whole, for a fault that belongs to no single
# attribute: a Total Path Attribute Length that runs past the message, or an
# attribute length that overruns the list. Negative so it can never collide
# with a real type code, which is an unsigned octet on the wire.
ATTR_LIST = -1

# Attributes that carry the NLRI itself (RFC 4760). A fault in one of these
# is not a fault in an attribute, it is a fault in the question the UPDATE
# was asking, so there is nothing to withdraw and nothing to discard.
_NLRI_ATTRS = frozenset((14, 15))

# iBGP-only attributes (RFC 4456). See attribute_outcome() for the
# precedence this takes over the table.
_IBGP_ONLY_ATTRS = frozenset((9, 10))

# Well-known mandatory attributes. NEXT_HOP is in the mandatory set for the
# IPv4-unicast NLRI in the UPDATE itself; RFC 4760 carries it inside
# MP_REACH_NLRI instead for every other family, which is why the decoder
# consults this only for the families it applies to.
#
# LOCAL_PREF is not here, on either kind of session. RFC 4271 s5.1.5 makes it
# well-known *discretionary*: a speaker SHALL include it towards internal
# peers, but a receiver that finds it missing applies its own default rather
# than declaring the UPDATE malformed. Listing it as mandatory on iBGP
# withdrew every route from an internal peer that omitted it (W-6).
_MANDATORY_EBGP = frozenset((1, 2, 3))        # ORIGIN, AS_PATH, NEXT_HOP
_MANDATORY_IBGP = _MANDATORY_EBGP
_MANDATORY_ANY = _MANDATORY_EBGP

# --- The matrix -------------------------------------------------------------
# Keyed by attribute type code. Values are the outcome for a *malformed*
# attribute of that type -- bad flags, bad length, or a value that cannot be
# interpreted. Reason-specific and peer-specific rules are applied around
# this table by attribute_outcome(); the table itself stays flat so it can be
# read against RFC 7606 sections 7.1 to 7.13 row by row.
#
# The type codes are wire's to name (see the module docstring), so each row
# carries its attribute name in a comment instead of a symbol.

ATTRIBUTE_MATRIX = {
    # Unrecoverable framing of the attribute list: we do not know where the
    # attributes end, so we do not know where the NLRI begins.
    ATTR_LIST: OUTCOME_RESET,

    # Well-known attributes, and the optional ones that decide where a route
    # points or how it is compared. The NLRI is still extractable, so the
    # prefixes in this UPDATE are withdrawn and the session survives. RFC
    # 7606 section 3 (e) is explicit that these cases must not reset even
    # though RFC 4271 said they should.
    1: OUTCOME_WITHDRAW,        # ORIGIN
    2: OUTCOME_WITHDRAW,        # AS_PATH
    3: OUTCOME_WITHDRAW,        # NEXT_HOP
    4: OUTCOME_WITHDRAW,        # MULTI_EXIT_DISC
    5: OUTCOME_WITHDRAW,        # LOCAL_PREF
    8: OUTCOME_WITHDRAW,        # COMMUNITIES
    9: OUTCOME_WITHDRAW,        # ORIGINATOR_ID   (but see the eBGP rule)
    10: OUTCOME_WITHDRAW,       # CLUSTER_LIST    (but see the eBGP rule)
    16: OUTCOME_WITHDRAW,       # EXTENDED_COMMUNITIES
    32: OUTCOME_WITHDRAW,       # LARGE_COMMUNITY

    # Attributes that annotate a route without changing it or its next hop.
    # Dropping the attribute loses information; dropping the route loses
    # reachability, so the attribute goes and the route stays.
    6: OUTCOME_DISCARD,         # ATOMIC_AGGREGATE
    7: OUTCOME_DISCARD,         # AGGREGATOR
    17: OUTCOME_DISCARD,        # AS4_PATH
    18: OUTCOME_DISCARD,        # AS4_AGGREGATOR

    # The NLRI lives inside these. Malformed past the point where prefixes
    # can be extracted there is nothing to withdraw, so the only honest
    # answer is NOTIFICATION and a reset.
    14: OUTCOME_RESET,          # MP_REACH_NLRI
    15: OUTCOME_RESET,          # MP_UNREACH_NLRI
}


def attribute_outcome(attr_type, reason, from_ebgp=False, optional=False,
                      transitive=False):
    """Decide what one malformed attribute costs.

    The order the rules are applied in is part of the specification, not an
    implementation detail, so it is spelled out here:

    1. A fault in the attribute list as a whole resets, whatever the reason.
    2. ORIGINATOR_ID and CLUSTER_LIST from an eBGP peer are discarded --
       **this overrides their treat-as-withdraw row in the table**. They are
       iBGP-only (RFC 4456), so receiving one over eBGP is a configuration
       fault on the far side. Withdrawing the peer's routes over it would
       punish the session for someone else's leaked route-reflector state,
       while the attribute itself means nothing to us and is dropped.
    3. A duplicate attribute is treat-as-withdraw (RFC 7606 section 3 (g)),
       except a duplicate MP_REACH_NLRI or MP_UNREACH_NLRI, which section
       3 (g) still requires be answered with Malformed Attribute List.
    4. A missing attribute withdraws when it was mandatory, and is not an
       error at all otherwise.
    5. Otherwise the table decides, and an attribute type the table does not
       list falls to the unknown-attribute rule: discard if the peer marked
       it optional, reset if it claims to be well-known, because an
       unrecognised well-known attribute (subcode 2) means we and the peer
       disagree about the base protocol.

    :param attr_type: the attribute type code, or ``ATTR_LIST``.
    :param reason: one of the ``REASON_*`` constants.
    :param from_ebgp: True when the sender is an eBGP peer.
    :param optional: the Optional bit the peer set on the attribute. Read
        from the wire, not from our own table: the rule for an attribute we
        do not recognise can only be based on what the sender claimed.
    :param transitive: the Transitive bit the peer set. It does not change
        the outcome -- an attribute we could not parse is not one we can
        re-advertise -- and is accepted so the caller can record it with
        the fault and so this signature does not have to change when
        propagation of unrecognised transitive attributes is added.
    :return: one of the ``OUTCOME_*`` constants.
    """
    if attr_type == ATTR_LIST:
        return OUTCOME_RESET

    if reason == REASON_UNNEGOTIATED:
        # Well formed, but for a family we did not agree to carry: ignore
        # it. Checked before the matrix, whose MP rows reset, because the
        # reset is for an MP attribute whose NLRI cannot be found -- and
        # this one's could be, it is simply not ours to take.
        return OUTCOME_DISCARD

    if from_ebgp and attr_type in _IBGP_ONLY_ATTRS:
        return OUTCOME_DISCARD

    if reason == REASON_DUPLICATE:
        if attr_type in _NLRI_ATTRS:
            return OUTCOME_RESET
        return OUTCOME_WITHDRAW

    if reason == REASON_MISSING:
        if attr_type in _MANDATORY_ANY:
            return OUTCOME_WITHDRAW
        # Nothing required it, so its absence is not a fault. Returning
        # OUTCOME_OK rather than raising keeps the caller free to ask about
        # any attribute it merely hoped for.
        return OUTCOME_OK

    outcome = ATTRIBUTE_MATRIX.get(attr_type)
    if outcome is not None:
        return outcome

    if optional:
        # An optional attribute we do not implement, whose flags or length
        # do not hold together. We have no idea what it meant, so the
        # attribute goes and the route stays. Read literally, RFC 7606
        # section 3 (c) asks for treat-as-withdraw on a flags conflict;
        # discarding is the narrower reading the plan calls for, on the
        # grounds that an unrecognised attribute had no influence on this
        # route in the first place, and that withdrawing over one is how a
        # single tunnelled bad attribute blackholes prefixes many hops from
        # wherever it was originated.
        return OUTCOME_DISCARD
    return OUTCOME_RESET


def worst_outcome(outcomes):
    """Return the most severe outcome in an iterable of outcomes.

    RFC 7606 requires that an UPDATE with several malformed attributes be
    handled by the most severe response any of them selects. This is how
    the two-phase decoder folds a list of faults into the one action it
    takes.

    :param outcomes: an iterable of ``OUTCOME_*`` constants.
    :return: the most severe of them, or ``OUTCOME_OK`` if empty.
    """
    worst = OUTCOME_OK
    rank = 0
    for outcome in outcomes:
        this = _SEVERITY.get(outcome, 0)
        if this > rank:
            rank = this
            worst = outcome
    return worst


def mandatory_attributes(is_ebgp):
    """Return the well-known mandatory attribute type codes for a session.

    :param is_ebgp: True for an eBGP session.
    :return: a frozenset of type codes: ORIGIN, AS_PATH and NEXT_HOP, on
        both kinds of session. LOCAL_PREF is discretionary even on iBGP
        (RFC 4271 s5.1.5); a missing one takes the configured default.
    """
    if is_ebgp:
        return _MANDATORY_EBGP
    return _MANDATORY_IBGP


class UpdateError(object):
    """One recorded fault from decoding one UPDATE.

    The decoder builds these while parsing and applies nothing until it has
    them all, which is what makes an UPDATE apply atomically: the worst
    outcome across the whole message is known before the first route is
    touched. They are also the unit the counters and ``show`` output are
    built from, so the fields are the ones an operator asks about -- which
    attribute, what was wrong with it, what it cost.

    :param attr_type: the attribute type code, or ``ATTR_LIST``.
    :param reason: one of the ``REASON_*`` constants.
    :param outcome: one of the ``OUTCOME_*`` constants, normally from
        :func:`attribute_outcome`.
    :param detail: optional human-readable specifics for the log line, for
        example the offending length. Never required, because the decoder
        builds these on the packet path where formatting a string for an
        UPDATE that will be discarded anyway is pure cost.
    """

    __slots__ = ('attr_type', 'reason', 'outcome', 'detail')

    def __init__(self, attr_type, reason, outcome, detail=None):
        self.attr_type = attr_type
        self.reason = reason
        self.outcome = outcome
        self.detail = detail

    def as_dict(self):
        """Return the fault as a dict of plain types.

        :return: a dict suitable for an event payload or a REST body.
        """
        return {
            'attr_type': self.attr_type,
            'reason': self.reason,
            'outcome': self.outcome,
            'detail': self.detail,
        }

    def __repr__(self):
        return '<UpdateError attr=%s %s -> %s>' % (
            self.attr_type, self.reason, self.outcome)


class PeerErrorCounters(object):
    """Per-session error counters for show output and engine health.

    Three separate breakdowns rather than one total, because they answer
    different questions. The per-outcome counts say how much the peer's
    mistakes cost us (discards are noise; withdraws are lost reachability;
    a reset is an outage). The per-(attribute, reason) counts say what is
    actually broken, which is what gets reported to whoever runs the far
    end. The NOTIFICATION counts, kept separately in each direction, say
    who ended the last session -- the single most common question asked of
    ``show ip bgp neighbors`` and the one a combined counter cannot answer.

    Counters are plain dicts and every method here is called on the loop
    thread, so there is no locking: ``stats()`` copies, and a reader on
    another thread goes through the engine's bridge like every other query.
    """

    __slots__ = ('outcomes', 'attributes', 'notify_sent', 'notify_received')

    def __init__(self):
        # Pre-seeded with every outcome so the keys in stats() exist from
        # the first poll. A health consumer plotting 'treat-as-withdraw'
        # should not have to cope with the key appearing only once the peer
        # has misbehaved.
        self.outcomes = dict((o, 0) for o in OUTCOMES)
        self.attributes = {}
        self.notify_sent = {}
        self.notify_received = {}

    def record(self, update_error):
        """Fold one fault into the counters.

        :param update_error: an :class:`UpdateError`.
        :return: the recorded outcome, so a decode loop can accumulate the
            worst one without reaching back into the object it just
            handed over.
        """
        outcome = update_error.outcome
        self.outcomes[outcome] = self.outcomes.get(outcome, 0) + 1
        key = (update_error.attr_type, update_error.reason)
        self.attributes[key] = self.attributes.get(key, 0) + 1
        return outcome

    def record_notification_sent(self, code, subcode):
        """Count a NOTIFICATION this side sent.

        :param code: the NOTIFICATION error code.
        :param subcode: the error subcode.
        :return: the new count for that pair.
        """
        key = (code, subcode)
        self.notify_sent[key] = self.notify_sent.get(key, 0) + 1
        return self.notify_sent[key]

    def record_notification_received(self, code, subcode):
        """Count a NOTIFICATION this side received.

        :param code: the NOTIFICATION error code.
        :param subcode: the error subcode.
        :return: the new count for that pair.
        """
        key = (code, subcode)
        self.notify_received[key] = self.notify_received.get(key, 0) + 1
        return self.notify_received[key]

    def total(self):
        """Return the number of attribute faults recorded.

        Counts every fault, including those whose outcome was
        ``OUTCOME_OK``, because a decoder that keeps asking about
        attributes that turn out to be fine is itself worth noticing.

        :return: the count. NOTIFICATIONs are not included; they are not
            attribute faults and are reported separately.
        """
        return sum(self.outcomes.values())

    def stats(self):
        """Return the counters as plain types for health and show output.

        The key names are a stable contract: ``/engine/health`` and
        ``show ip bgp neighbors`` both read this, and a renamed key is an
        API change. Tuple keys are expanded into lists of records rather
        than stringified, so the output is JSON-serialisable as it stands
        and a consumer never has to parse ``'(9, 1)'`` back apart.

        :return: a dict of plain types.
        """
        attributes = [{'attr_type': attr, 'reason': reason, 'count': n}
                      for (attr, reason), n
                      in sorted(self.attributes.items())]
        return {
            'faults': self.total(),
            'outcomes': dict(self.outcomes),
            'attributes': attributes,
            'notifications_sent': self._notify_records(self.notify_sent),
            'notifications_received':
                self._notify_records(self.notify_received),
        }

    @staticmethod
    def _notify_records(counts):
        return [{'code': code, 'subcode': subcode,
                 'name': notify_name(code, subcode), 'count': n}
                for (code, subcode), n in sorted(counts.items())]

    def reset(self):
        """Zero every counter.

        Called when a session is administratively cleared, so the numbers
        an operator reads after a ``clear ip bgp`` describe the session in
        front of them rather than its predecessor.
        """
        self.outcomes = dict((o, 0) for o in OUTCOMES)
        self.attributes = {}
        self.notify_sent = {}
        self.notify_received = {}

    def __repr__(self):
        return '<PeerErrorCounters faults=%d withdraw=%d reset=%d>' % (
            self.total(), self.outcomes.get(OUTCOME_WITHDRAW, 0),
            self.outcomes.get(OUTCOME_RESET, 0))
