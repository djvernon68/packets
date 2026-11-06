# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The per-peer Adj-RIB-Out: what one neighbour has been told, and why.

RFC 4271 names three RIBs and this is the third. The first two are shared --
every peer's received paths land in one Loc-RIB and one best path per prefix
comes out of it -- but the *outbound* view is per peer and cannot be shared,
because the same winning path becomes a different UPDATE for every
neighbour: a different AS_PATH, a different next hop, LOCAL_PREF present or
absent, MED kept or dropped. This module is that per-peer transform plus the
memory of its result.

**Why keep the memory at all.** Encoding straight from the Loc-RIB is
simpler and wrong in a way that only shows up under load. Selection re-runs
for a destination whenever *any* path for it changes, and the winner's
attributes usually do not change at all -- a second path arriving, a MED
moving on a path that was already losing, a next hop re-resolving. Without a
record of what each peer was actually sent, every one of those re-selections
becomes an UPDATE to every peer, the peers re-run their own selection, and
the churn multiplies outward across the AS. With the record, a re-selection
that produces the same outbound attribute set produces no message. That
comparison is the whole justification for this class: the staging call is
deliberately cheap and idempotent so callers can offer a destination as
often as they like.

**Whose table this is.** One per *update group* since Stage 4, not one per
peer: the group key (see ``updategroup.py``) is exactly the set of inputs
this transform reads, so every member of a group would compute the same
attribute set and encode the same bytes, and computing them once is the
whole point of the grouping. Nothing here knows about groups -- it is
handed a representative ``PeerRef`` and a policy chain and does the same
work it always did -- but two consequences follow from being shared and
are worth stating: :meth:`reset` now discards what a *group* was told, so
it must never be called for one member's teardown, and
:meth:`encode_advertised` exists so a single member can be caught up
without disturbing the shared record.

**What is deliberately not here.** MRAI (RFC 4271 s9.2.1.1) batching and
group membership live in ``updategroup.py``; this class stages, transforms
and encodes, and is told when to do it. Route reflection (RFC 4456) and
confederations (RFC 5065) are absent, and both are visible in the
suppression rules below: without a reflector there is nothing legitimate
to do with an iBGP-learned path except keep it, and without confederations
every eBGP peer is outside ours, so NO_EXPORT applies to all of them.

**The immutability contract.** An :class:`AttrSet` is interned and shared by
every path carrying the same attributes, and it is a live key in the
interning table. Mutating one to rewrite a next hop would corrupt every
other path using it and break the table's hash invariant in a way that
surfaces as a wrong route somewhere else entirely. Every transform here
therefore builds a *new* set through the keyword constructor, from a plain
dict of the fields it is keeping.
"""

from packets.routing.rtengine.plugins.bgp import attrs as _attrs
from packets.routing.rtengine.plugins.bgp import bestpath as _bestpath
from packets.routing.rtengine.plugins.bgp import policy as _policy
from packets.routing.rtengine.plugins.bgp import wire as _wire
from packets.routing.rtengine.rib import prefix as _prefix

# Well-known communities, RFC 1997. Matched against the packed bytes rather
# than a decoded list because this runs once per prefix per peer.
COMM_NO_EXPORT = 0xffffff01
COMM_NO_ADVERTISE = 0xffffff02
COMM_NO_EXPORT_SUBCONFED = 0xffffff03

_WIRE_NO_EXPORT = b'\xff\xff\xff\x01'
_WIRE_NO_ADVERTISE = b'\xff\xff\xff\x02'
_WIRE_NO_EXPORT_SUBCONFED = b'\xff\xff\xff\x03'

# `remove-private-as` modes. IOS's plain form strips private ASNs only from
# a path made of nothing else -- a customer's private AS behind us -- and
# leaves a mixed path alone, because removing the private hops from the
# middle of a public path changes its length and hides who carried it.
# `all` strips them wherever they are. The two used to be one behaviour,
# the second, under the first's name (B-4).
REMOVE_PRIVATE_OFF = 0
REMOVE_PRIVATE_IF_ALL_PRIVATE = 1
REMOVE_PRIVATE_ALL = 2


def remove_private_mode(value):
    """Normalise a configured ``remove-private-as`` value to a mode.

    :param value: False/None, True, ``'all'``, or a mode constant.
    :return: one of the ``REMOVE_PRIVATE_*`` constants.
    :raises ValueError: anything else.
    """
    if value in (None, False, REMOVE_PRIVATE_OFF):
        return REMOVE_PRIVATE_OFF
    if value is True or value == REMOVE_PRIVATE_IF_ALL_PRIVATE:
        return REMOVE_PRIVATE_IF_ALL_PRIVATE
    if value == 'all' or value == REMOVE_PRIVATE_ALL:
        return REMOVE_PRIVATE_ALL
    raise ValueError('remove-private-as must be true, false or "all", not '
                     '%r' % (value,))


def remove_private_text(mode):
    """Render a ``REMOVE_PRIVATE_*`` mode the way it is configured."""
    if mode == REMOVE_PRIVATE_ALL:
        return 'all'
    return mode == REMOVE_PRIVATE_IF_ALL_PRIVATE


# Private AS ranges, RFC 6996. Both are reserved for use inside one
# operator's network and are meaningless -- and non-unique -- once a route
# leaves it, which is what `remove_private_as` exists to clean up.
PRIVATE_AS2_FIRST = 64512
PRIVATE_AS2_LAST = 65534
PRIVATE_AS4_FIRST = 4200000000
PRIVATE_AS4_LAST = 4294967294

# The one-byte segment count in an AS_PATH segment header. A prepend into a
# full segment has to start a new one instead; see _prepend_as_path.
MAX_SEGMENT_ASNS = 255

# --- Suppression reasons ----------------------------------------------------
# Strings rather than an enum, for the same reason the event names in
# events.py are strings: they appear verbatim in `stats()` output and
# therefore in the REST API, and "why is this prefix not in my table" is a
# question an operator answers by reading them. The order below is the order
# the rules are evaluated in, and a path that trips several is counted
# against the first -- so the counts partition the suppressed paths rather
# than double-counting them.

SUPPRESS_FROM_PEER = 'from-peer'
SUPPRESS_AS_LOOP = 'as-loop'
SUPPRESS_IBGP_SPLIT_HORIZON = 'ibgp-split-horizon'
SUPPRESS_NO_ADVERTISE = 'no-advertise'
SUPPRESS_NO_EXPORT = 'no-export'
SUPPRESS_NO_EXPORT_SUBCONFED = 'no-export-subconfed'
SUPPRESS_UNRESOLVED = 'unresolved'
SUPPRESS_POLICY = 'policy'
# The transform produced attributes the codec refused -- an attribute set
# too large for the session's message ceiling. Counted at encode time, not
# at transform time, and the prefix is not recorded as advertised (B-6).
SUPPRESS_ENCODE = 'encode-error'

SUPPRESS_REASONS = (SUPPRESS_FROM_PEER, SUPPRESS_AS_LOOP,
                    SUPPRESS_IBGP_SPLIT_HORIZON, SUPPRESS_NO_ADVERTISE,
                    SUPPRESS_NO_EXPORT, SUPPRESS_NO_EXPORT_SUBCONFED,
                    SUPPRESS_UNRESOLVED, SUPPRESS_POLICY, SUPPRESS_ENCODE)

# RFC 7911 identifier used when ADD-PATH send is on. This version advertises
# only the best path, so the identifier must be *stable per prefix* rather
# than copied from the winning path: the receiver keys a path on
# (peer, path_id), so an id that changed when the winner changed would make
# it add a second path and keep the first forever. One constant id means a
# new winner replaces the old one, which is the behaviour a non-ADD-PATH
# session already has. Advertising genuinely multiple paths needs the update
# groups of Stage 4.
_BEST_PATH_ID = 1


def _addr_len_for_afi(afi):
    """Return the next-hop width one address family needs.

    :param afi: an IANA address family number.
    :return: 4 or 16, or 0 for a family this version cannot encode.
    """
    if afi == _prefix.AFI_IP:
        return 4
    if afi == _prefix.AFI_IP6:
        return 16
    return 0


def _has_community(packed, target):
    """Return whether a packed COMMUNITIES value holds one community.

    The membership test has to be *aligned*. A plain substring search finds
    ``ff ff ff 02`` straddling the boundary between ``0:65535`` and
    ``65282:0``, which is a pair of ordinary communities and not
    NO_ADVERTISE at all. The cheap unaligned search is kept as a prefilter
    because it is a C-level scan and almost always the answer is no.

    :param packed: the canonical 4-byte-per-community bytes.
    :param target: the 4 wire bytes of the community to look for.
    :return: True if present on a 4-byte boundary.
    """
    if not packed or target not in packed:
        return False
    for i in range(0, len(packed) - 3, 4):
        if packed[i:i + 4] == target:
            return True
    return False


def _count_as(segments, asn):
    """Count how often an AS appears across decoded AS_PATH segments.

    :param segments: ``[(seg_type, [asn, ...]), ...]``.
    :param asn: the AS to count.
    :return: the number of occurrences, in every segment type.
    """
    total = 0
    for _seg_type, asns in segments:
        for one in asns:
            if one == asn:
                total += 1
    return total


def _is_private_as(asn):
    """Return whether an AS is in one of the RFC 6996 private ranges.

    :param asn: the AS number.
    :return: True for 64512-65534 and 4200000000-4294967294.
    """
    if PRIVATE_AS2_FIRST <= asn <= PRIVATE_AS2_LAST:
        return True
    return PRIVATE_AS4_FIRST <= asn <= PRIVATE_AS4_LAST


def _all_private(segments):
    """Return whether a decoded AS_PATH holds private ASNs and no others.

    :param segments: ``[(seg_type, [asn, ...]), ...]``.
    :return: False for an empty path, which has nothing to remove.
    """
    seen = False
    for _seg_type, asns in segments:
        for one in asns:
            if not _is_private_as(one):
                return False
            seen = True
    return seen


def _is_unspecified(addr):
    """Whether packed next-hop bytes are the unspecified address.

    ``0.0.0.0`` or ``::``: what a locally originated ``network`` route
    carries as its next hop, and never a next hop a peer can use. RFC 4271
    s6.3 makes a NEXT_HOP of it semantically incorrect, and RFC 4760 gives
    MP_REACH no such meaning either. FRR and IOS drop such routes as
    martians (L-4).
    """
    return not addr or addr.count(0) == len(addr)


def _prepend_as_path(segments, local_as):
    """Prepend our AS to a decoded AS_PATH, the way RFC 4271 s5.1.2 says.

    Three cases, and getting any of them wrong corrupts loop detection
    silently -- the UPDATE still encodes, the neighbour still accepts it,
    and the AS_PATH simply no longer describes the route:

    * a leading AS_SEQUENCE takes the AS at its *front*. Appending would
      claim the route passed through us before it passed through the
      neighbour we learned it from, which reverses the path;
    * a leading AS_SET, or an empty path, gets a brand new AS_SEQUENCE in
      front. An AS_SET is unordered by definition, so putting our AS inside
      one would say "somewhere in this aggregate" instead of "we are the
      most recent hop", and the length count would not grow either, since
      an AS_SET counts as one AS however many it holds;
    * a leading AS_SEQUENCE already holding 255 ASNs also gets a new
      segment, because the segment count is one byte. Splitting is the
      normal encoding for a long path and means the same thing; raising
      here would fail on route data, which this module never does.

    :param segments: ``[(seg_type, [asn, ...]), ...]``, as decoded.
    :param local_as: our AS.
    :return: a new segment list; the input is not modified.
    """
    if segments and segments[0][0] == _attrs.SEG_AS_SEQUENCE \
            and len(segments[0][1]) < MAX_SEGMENT_ASNS:
        head = (segments[0][0], [local_as] + list(segments[0][1]))
        return [head] + list(segments[1:])
    return [(_attrs.SEG_AS_SEQUENCE, [local_as])] + list(segments)


def _map_as_path(segments, replace_as, replacement, drop_private):
    """Rewrite ASNs in a decoded AS_PATH for override and private removal.

    Both edits happen in one pass because both run before the prepend and
    neither may touch the AS we are about to add: ``remove_private_as``
    applied afterwards would strip our own AS when it is itself private,
    leaving a path that claims the route never crossed our network.

    A segment left with no ASNs is dropped rather than encoded empty. An
    empty AS_SEQUENCE is legal on the wire and means nothing; an empty
    AS_SET would be worse, since it would still count as one AS in every
    length comparison downstream.

    :param segments: ``[(seg_type, [asn, ...]), ...]``, as decoded.
    :param replace_as: the AS to replace, or 0 for none.
    :param replacement: what to replace it with.
    :param drop_private: drop ASNs in the RFC 6996 private ranges.
    :return: a new segment list.
    """
    out = []
    for seg_type, asns in segments:
        kept = []
        for one in asns:
            if replace_as and one == replace_as:
                one = replacement
            elif drop_private and _is_private_as(one):
                continue
            kept.append(one)
        if kept:
            out.append((seg_type, kept))
    return out


# The transform edits a dict and constructs one new AttrSet from it,
# instead of copying the object and assigning fields: a set may be interned
# and shared by a million paths, so there is no in-place edit that is safe.
# The dict builder lives in policy.py because the route-map `set` clauses
# need exactly the same thing, and two copies of a seventeen-field
# exploder is two places to forget a new attribute.
_attr_kwargs = _policy.attr_kwargs


class AdjRibOut(object):
    """One peer's outbound view: the transform, and what it last produced.

    Construct one per peer per address family. The object is used from the
    engine's loop thread only and takes no lock: the staging calls run
    inside a selection batch, and ``encode_pending`` runs when that batch
    commits.

    Staging is separate from encoding on purpose. A destination can be
    offered many times while a batch is being applied -- a burst of UPDATEs
    touching the same prefix re-selects it once per arrival -- and only the
    last outcome should reach the wire. Staging collapses those into one
    entry per prefix, and the encode step is what turns the surviving
    entries into messages and commits them to the advertised record.

    :param peer_ref: the :class:`~...bestpath.PeerRef` for this neighbour,
        which supplies its AS, its address and whether it is external.
    :param afi: address family of this table, from ``rib.prefix``.
    :param safi: subsequent address family; 1 (unicast) in this version.
    :param local_as: our AS, prepended outbound to an eBGP peer.
    :param router_id: our router id, kept for show output and for the
        originator id a Stage-4 reflector will need.
    :param local_addr: the next hop to advertise when we rewrite it; must
        be 4 bytes for IPv4 and 16 for IPv6.
    :param next_hop_self: rewrite the next hop for an iBGP peer too.
    :param default_local_pref: LOCAL_PREF given to an iBGP peer when the
        path has none.
    :param send_community: send COMMUNITIES.
    :param send_ext_community: send EXTENDED COMMUNITIES.
    :param send_large_community: send LARGE COMMUNITIES.
    :param max_size: the session's negotiated message ceiling.
    :param as4: the session carries 4-octet ASNs.
    :param add_path_send: negotiated ADD-PATH send for this family.
    :param remove_private_as: one of the ``REMOVE_PRIVATE_*`` modes, or a
        configured value :func:`remove_private_mode` accepts: strip RFC
        6996 private ASNs outbound, from an all-private path or from any.
    :param as_override: replace the peer's own AS in the AS_PATH with ours.
    :param sender_loop_check: suppress, towards an external peer, a path
        that already contains the peer's AS (the peer would discard it).
        On by default. Turned off for a peer configured with ``allowas-in``
        on *its* side; our own ``allowas-in`` is about what *we* accept and
        no longer leaks into what we send (B-5).
    :param policy: the outbound
        :class:`~packets.routing.rtengine.plugins.bgp.policy.PolicyChain`,
        or None for no policy. It runs *after* the eBGP/iBGP transform so
        a ``set next-hop`` beats ``next-hop-self`` and a ``set as-path
        prepend`` lands in front of the AS we prepended, and *before* the
        community filter so ``send-community`` still governs whether a
        community policy just set is actually sent.
    :raises ValueError: ``local_addr`` does not match the family width, is
        the unspecified address, or the family is one this version cannot
        encode. All are configuration errors caught at construction rather
        than per route.
    """

    __slots__ = ('peer', 'afi', 'safi', 'local_as', 'router_id',
                 'local_addr', 'next_hop_self', 'default_local_pref',
                 'send_community', 'send_ext_community',
                 'send_large_community', 'max_size', 'as4', 'add_path_send',
                 'remove_private_as', 'as_override', 'sender_loop_check',
                 'policy', '_advertised', '_announce', '_withdraw',
                 '_suppressed', '_messages', '_announced', '_withdrawn',
                 '_resets')

    def __init__(self, peer_ref, afi, safi, local_as, router_id, local_addr,
                 *, next_hop_self=False, default_local_pref=100,
                 send_community=True, send_ext_community=True,
                 send_large_community=True, max_size=4096, as4=True,
                 add_path_send=False, remove_private_as=False,
                 as_override=False, sender_loop_check=True, policy=None):
        width = _addr_len_for_afi(afi)
        if width == 0:
            raise ValueError('address family %r has no next-hop encoding '
                             'in this version' % (afi,))
        if len(local_addr) != width:
            raise ValueError('afi %d needs a %d byte local address, got %d'
                             % (afi, width, len(local_addr)))
        if _is_unspecified(local_addr):
            # L-4: the next hop we rewrite to is the unspecified address.
            # This is what an IPv6 family over an IPv4 session used to get,
            # and every route it carried was dropped by the peer as a
            # martian. Refusing here leaves the family advertising nothing,
            # with a log line, rather than advertising garbage.
            raise ValueError('afi %d has no usable local next hop (the '
                             'unspecified address); configure one' % afi)

        self.peer = peer_ref
        self.afi = afi
        self.safi = safi
        self.local_as = local_as
        self.router_id = router_id
        self.local_addr = local_addr
        self.next_hop_self = bool(next_hop_self)
        self.default_local_pref = default_local_pref
        self.send_community = bool(send_community)
        self.send_ext_community = bool(send_ext_community)
        self.send_large_community = bool(send_large_community)
        self.max_size = max_size
        self.as4 = bool(as4)
        self.add_path_send = bool(add_path_send)
        self.remove_private_as = remove_private_mode(remove_private_as)
        self.as_override = bool(as_override)
        self.sender_loop_check = bool(sender_loop_check)
        self.policy = policy

        # What the peer has been told: prefix -> the AttrSet it was sent
        # with. This is the entire reason the class exists, and it is also
        # the largest thing in it -- one entry per advertised prefix, with
        # the value shared with the Loc-RIB's interned set whenever the
        # transform was a no-op.
        self._advertised = {}
        # Staged, not yet encoded. A dict keyed by prefix rather than a
        # list, so offering the same destination twice in one batch leaves
        # one entry; the insertion order is the staging order, which makes
        # the encoded output reproducible for a given sequence of calls.
        self._announce = {}
        self._withdraw = {}

        self._suppressed = dict((r, 0) for r in SUPPRESS_REASONS)
        self._messages = 0
        self._announced = 0
        self._withdrawn = 0
        self._resets = 0

    # --- staging -----------------------------------------------------------

    def announce(self, dest):
        """Offer a destination's best path to this peer.

        Cheap and idempotent by design: the caller re-offers a destination
        after every selection, and the common outcome is that nothing about
        what this peer should hear has changed, in which case nothing is
        staged and no message is ever built. That is the difference between
        one UPDATE per *change* and one per *re-selection*.

        A destination whose best path is gone, or whose best path this peer
        must not be told about, is not simply ignored: if the peer was told
        about the prefix before, it has to be told the route is gone, so
        the call turns into a withdrawal. Leaving the peer with a route we
        have suppressed is a black hole that outlives the reason for it.

        :param dest: a :class:`~...bestpath.BgpDest` whose selection has
            already run, or None.
        :return: True if the staging area changed.
        """
        if dest is None:
            return False
        best = dest.best
        if best is None:
            return self.withdraw(dest.prefix)
        out = self._outbound_attrs(dest.prefix, best)
        if out is None:
            return self.withdraw(dest.prefix)
        return self._stage(dest.prefix, out)

    def withdraw(self, prefix):
        """Stage a withdrawal for a prefix, if this peer ever had it.

        Withdrawing something never advertised is a normal event, not an
        error: the Loc-RIB loses a prefix that every peer's transform had
        already suppressed, or a session comes up and immediately loses a
        route it never got as far as sending. BGP itself treats an
        unknown withdrawal as a no-op (RFC 4271 s9.1.2), and so does this.

        :param prefix: the :class:`~...rib.prefix.Prefix` to withdraw.
        :return: True if the staging area changed.
        """
        staged = self._announce.pop(prefix, None)
        if prefix not in self._advertised:
            # Never sent. Dropping a staged announcement still counts as a
            # change, because a message that would have been built now
            # will not be.
            return staged is not None
        if prefix in self._withdraw:
            return staged is not None
        self._withdraw[prefix] = True
        return True

    def _stage(self, prefix, out):
        """Record an outbound attribute set if it differs from the last.

        The comparison is against the *effective* state: an announcement
        already staged but not yet encoded, if there is one, otherwise what
        the peer was actually sent. Comparing against the advertised record
        alone would re-stage a change twice within one batch.

        :param prefix: the prefix.
        :param out: the transformed attribute set to advertise.
        :return: True if the staging area changed.
        """
        cancelled = self._withdraw.pop(prefix, None) is not None
        current = self._announce.get(prefix)
        if current is None:
            current = self._advertised.get(prefix)
        if current is not None and current == out:
            # Nothing new to say. The only thing that can have changed is
            # that a pending withdrawal for this prefix is now moot.
            return cancelled
        self._announce[prefix] = out
        return True

    # --- the outbound transform --------------------------------------------

    def _outbound_attrs(self, prefix, path):
        """Compute what this peer should hear for one path, or nothing.

        This is the substance of the module: the same winning path becomes
        a different attribute set for an internal and an external peer, and
        for some peers it must not become one at all. The suppression rules
        run first, in the order they are listed, and each one that fires is
        counted under its own key so ``stats()`` explains a peer that is
        being sent far less than the table holds.

        :param prefix: the destination being advertised. Carried in
            rather than read off the path because a ``BgpPath`` does not
            know its prefix -- the destination owns it -- and outbound
            policy has to match on it.
        :param path: the selected :class:`~...bestpath.BgpPath`.
        :return: a new :class:`AttrSet`, or None to advertise nothing.
        """
        peer = self.peer
        a = path.attrs
        src = path.peer

        # Split horizon, the plainest case of it: a route never goes back
        # out of the session it came in on. The neighbour already has it,
        # and AS_PATH loop detection would not catch the echo on an iBGP
        # session at all.
        if src is not None and (src is peer or
                                (peer.addr and src.addr == peer.addr)):
            return self._suppress(SUPPRESS_FROM_PEER)

        if (peer.is_ebgp and peer.peer_as and not self.as_override and
                self.sender_loop_check):
            # The peer will drop a path that already contains its own AS,
            # so sending it buys nothing and costs an update, the peer's
            # parse, and -- when the path flaps -- a permanent share of the
            # session's bandwidth.
            #
            # Two configurations say otherwise, and both have to be tested
            # here rather than after the transform, because suppression
            # would make them dead options. `as_override` rewrites the
            # peer's AS out of the path further down, so by the time the
            # UPDATE exists there is no loop left to detect -- and it is
            # the paths that *do* contain the peer's AS that the option
            # exists to deliver. `sender-loop-check` off is the other: the
            # peer has been configured to accept its own AS (its
            # `allowas-in`), typically a hub-and-spoke design where every
            # site shares one AS. That used to be inferred from *our*
            # `allowas-in`, which is about what we accept and says nothing
            # about the peer (B-5).
            if a.has_as(peer.peer_as):
                return self._suppress(SUPPRESS_AS_LOOP)

        if (not peer.is_ebgp and src is not None and
                path.source == _bestpath.SRC_PEER and not src.is_ebgp):
            # The iBGP split-horizon rule, RFC 4271 s9.2.1.1: a path
            # learned from an internal peer is never re-advertised to
            # another internal peer. iBGP is not transitive, and the reason
            # is that AS_PATH cannot help -- it does not change inside an
            # AS, so a path that went round a loop of internal speakers
            # would come back looking exactly as it left and no loop
            # detection could tell. The mesh is what keeps it correct:
            # every internal speaker hears every external path directly.
            # Route reflection (RFC 4456) is the standard way to relax this
            # and is not implemented in this version, so there is no
            # legitimate case for re-advertising here yet.
            return self._suppress(SUPPRESS_IBGP_SPLIT_HORIZON)

        if _has_community(a.communities, _WIRE_NO_ADVERTISE):
            # RFC 1997: not to any peer, internal or external. The sender
            # used it to mark a route as strictly local knowledge.
            return self._suppress(SUPPRESS_NO_ADVERTISE)

        if peer.is_ebgp and _has_community(a.communities, _WIRE_NO_EXPORT):
            # RFC 1997: not outside the AS, or outside the confederation
            # when there is one. This version implements no confederations,
            # so every external peer is outside ours and the test is simply
            # "is the peer external".
            return self._suppress(SUPPRESS_NO_EXPORT)

        if peer.is_ebgp and _has_community(a.communities,
                                           _WIRE_NO_EXPORT_SUBCONFED):
            # RFC 1997 NO_EXPORT_SUBCONFED (B-2): not to any external peer,
            # not even a confederation-external one. Without confederations
            # every external peer is outside our member AS, so it suppresses
            # exactly where NO_EXPORT does. It used to be ignored, and such
            # routes went to every eBGP neighbour.
            return self._suppress(SUPPRESS_NO_EXPORT_SUBCONFED)

        if not path.resolved:
            # An unresolved path has no usable next hop here, so whatever
            # next hop we advertised would be one we cannot forward to
            # ourselves. Announcing it draws the peer's traffic into a
            # black hole; best-path already refuses to install it.
            return self._suppress(SUPPRESS_UNRESOLVED)

        kwargs = _attr_kwargs(a)
        if peer.is_ebgp:
            self._transform_ebgp(kwargs, path)
        else:
            self._transform_ibgp(kwargs, path)
        out = _attrs.AttrSet(**kwargs)

        if self.policy is not None and not self.policy.empty:
            # Outbound policy sees the attributes as they would be sent,
            # which is the only view an operator can reason about: a
            # route-map that matches on next-hop or AS_PATH outbound is
            # written against what the neighbour will receive, not against
            # what we received.
            outcome = self.policy.apply(prefix, out)
            if outcome is None:
                return self._suppress(SUPPRESS_POLICY)
            out = outcome.attrs
            kwargs = _attr_kwargs(out)

        self._filter_communities(kwargs)
        return _attrs.AttrSet(**kwargs)

    def _transform_ebgp(self, kwargs, path):
        """Apply the external-peer rules to the attribute keywords.

        :param kwargs: the keyword dict, edited in place.
        :param path: the path being advertised.
        """
        a = path.attrs
        segments = a.as_path_list()
        drop_private = (
            self.remove_private_as == REMOVE_PRIVATE_ALL or
            (self.remove_private_as == REMOVE_PRIVATE_IF_ALL_PRIVATE and
             _all_private(segments)))
        if self.as_override or drop_private:
            # Both rewrite the path the neighbour will see, and both must
            # happen before the prepend so they cannot touch our own AS.
            #
            # as_override exists for the CPE case: a provider gives every
            # customer site the same AS, so a site would reject its
            # siblings' routes as a loop. Replacing the customer's AS with
            # ours keeps the path length honest while removing the loop
            # match. It is a deliberate weakening of loop detection and is
            # only safe because the customer's sites are leaves.
            segments = _map_as_path(
                segments,
                self.peer.peer_as if self.as_override else 0,
                self.local_as,
                drop_private)
        segments = _prepend_as_path(segments, self.local_as)
        kwargs['as_path'] = _attrs.make_as_path(segments)

        # RFC 4271 s5.1.5: LOCAL_PREF is never sent to an external peer. It
        # is our internal ranking, it is not comparable with theirs, and
        # sending it leaks how we value their routes.
        kwargs['has_local_pref'] = False
        kwargs['local_pref'] = 0

        if path.source == _bestpath.SRC_PEER:
            # A MED learned from one neighbour is a statement about *that*
            # neighbour's internal costs, denominated in their units, about
            # their entry points. Passing it to a different neighbour is
            # meaningless at best, and at worst it wins a comparison it has
            # no business being in -- one of the most common ways a MED
            # ends up somewhere it was never intended.
            kwargs['has_med'] = False
            kwargs['med'] = 0

        # ORIGINATOR_ID and CLUSTER_LIST are route-reflection bookkeeping
        # about the interior of our AS (RFC 4456 s7). They have no meaning
        # outside it and leak internal topology.
        kwargs['has_originator'] = False
        kwargs['originator_id'] = 0
        kwargs['cluster_list'] = b''

        # Always rewrite the next hop. The path's next hop is an address in
        # our AS or in a third party's, and the peer has no route to it
        # unless we happen to share a subnet with it -- and exploiting that
        # case is third-party next hop, which this version does not do.
        kwargs['nexthop'] = self.local_addr
        kwargs['nexthop_local'] = b''

    def _transform_ibgp(self, kwargs, path):
        """Apply the internal-peer rules to the attribute keywords.

        :param kwargs: the keyword dict, edited in place.
        :param path: the path being advertised.
        """
        a = path.attrs

        # The AS_PATH does not change inside an AS: it records inter-AS
        # hops, and prepending here would make our own AS appear once per
        # internal speaker the route crossed. as_override and
        # remove_private_as are ignored for the same reason.

        if not a.has_local_pref():
            # A path from an external peer arrives without LOCAL_PREF, and
            # every internal speaker has to see the same value or they will
            # pick different winners for the same prefix and forward to
            # each other -- a routing loop produced by disagreement rather
            # than by a protocol fault. The default is the value RFC 4271
            # s9.1.1 assumes when a path has none.
            kwargs['has_local_pref'] = True
            kwargs['local_pref'] = self.default_local_pref

        # MED is kept: inside the AS it is exactly the hint it was meant to
        # be, about how this AS's neighbour prefers to be entered, and
        # every internal speaker needs it to make the same choice.

        if (self.next_hop_self or len(a.nexthop) != len(self.local_addr) or
                _is_unspecified(a.nexthop)):
            # Normally the external next hop is left alone: the internal
            # peer usually has an IGP route to it, and rewriting it to
            # ourselves forces traffic through this router when it could
            # have gone direct. next_hop_self is for when it cannot -- the
            # external link is not in the IGP, which is the usual case at a
            # border router.
            #
            # The width test is a safety net rather than a policy: a path
            # with no next hop of this family's width cannot be encoded at
            # all (the codec would omit a mandatory NEXT_HOP, or refuse to
            # build MP_REACH), so ours is used instead of producing a
            # message the peer would reject. An unspecified next hop is the
            # same case: a locally originated `network` route carries
            # 0.0.0.0 or ::, and used to reach internal peers that way.
            kwargs['nexthop'] = self.local_addr
            kwargs['nexthop_local'] = b''

    def _filter_communities(self, kwargs):
        """Drop community attributes this session is not configured to send.

        Each of the three is separately controlled because they are
        separately used: an operator who strips ordinary communities on a
        customer session usually still wants the extended ones that carry
        route targets.

        Note the order of this against suppression: NO_EXPORT and
        NO_ADVERTISE are honoured *before* the filter, so turning community
        propagation off stops the community from being forwarded but does
        not stop it from applying to us. Reversing that would quietly
        export a route its origin marked as unexportable.

        :param kwargs: the keyword dict, edited in place.
        """
        if not self.send_community:
            kwargs['communities'] = b''
        if not self.send_ext_community:
            kwargs['ext_communities'] = b''
        if not self.send_large_community:
            kwargs['large_communities'] = b''

    def _suppress(self, reason):
        """Count one suppressed path and return the "advertise nothing".

        :param reason: one of the ``SUPPRESS_*`` keys.
        :return: None, so callers can ``return self._suppress(...)``.
        """
        self._suppressed[reason] += 1
        return None

    # --- encoding ----------------------------------------------------------

    def pending(self):
        """Return how many staged changes are waiting to be encoded.

        :return: staged announcements plus staged withdrawals. Prefixes,
            not messages: one message usually carries many.
        """
        return len(self._announce) + len(self._withdraw)

    def pending_announcements(self):
        """Return how many staged announcements are waiting.

        :return: the number of staged announcements.
        """
        return len(self._announce)

    def pending_withdrawals(self):
        """Return how many staged withdrawals are waiting.

        Asked by the advertisement interval, which exempts withdrawals:
        a delayed announcement is slower convergence, a delayed
        withdrawal is a black hole.

        :return: the number of staged withdrawals.
        """
        return len(self._withdraw)

    def advertised_count(self):
        """Return how many prefixes this table has been sent.

        :return: the size of the advertised record. Used to decide
            whether a peer joining an update group owes a catch-up
            replay, which is a question about the record rather than
            about the staging area.
        """
        return len(self._advertised)

    def encode_pending(self, withdrawals_only=False):
        """Turn the staging area into UPDATE messages and commit it.

        Two groupings, both of which are what makes the difference between
        one message and thousands.

        Withdrawals go together first, because a withdrawal carries no
        attributes and any withdrawal can share a message with any other.
        Sending them ahead of the announcements also means a prefix being
        replaced is never briefly absent in a way that matters, and it
        frees the peer's memory before we add to it.

        Announcements are grouped by attribute set, because an UPDATE *is*
        one attribute set applied to a list of prefixes. Grouping is what
        turns a full-table advertisement into roughly one message per
        distinct path rather than one per prefix, and it is nearly free
        here: the sets are interned, so equal sets are usually the same
        object and the grouping dict hashes a cached value.

        B-6: the advertised record is committed only for what was actually
        encoded. It used to be committed first, so an attribute set the
        codec refused -- too large for the session's ceiling -- left the
        record, and ``show``, claiming routes the peer was never sent, and
        the next re-selection found "nothing changed" and never retried.
        Such prefixes are now counted under ``encode-error`` and left out.
        What happens *after* encoding is the session's: the writer either
        delivers the bytes or the session fails, and a failed session takes
        :meth:`reset` with it -- so the record is honest for every session
        that is still up.

        :param withdrawals_only: encode the staged withdrawals and leave
            the staged announcements for later. B-10: the advertisement
            interval exempts withdrawals (RFC 4271 s9.2.1.1) but not
            announcements, and a pending withdrawal used to release both.
        :return: a list of encoded UPDATE messages, in send order. Empty
            when nothing was staged.
        """
        msgs = []

        if self._withdraw:
            prefixes = list(self._withdraw)
            if self.add_path_send:
                prefixes = [(p, _BEST_PATH_ID) for p in prefixes]
            # A withdrawal carries no attributes, so the only way to fail
            # is a ceiling too small for one prefix, which the session
            # negotiation never produces. It is allowed to raise.
            msgs.extend(_wire.encode_withdraw(prefixes, self.afi, self.safi,
                                              self.max_size,
                                              self.add_path_send))
            for prefix in self._withdraw:
                self._advertised.pop(prefix, None)
            self._withdrawn += len(self._withdraw)
            self._withdraw = {}

        if self._announce and not withdrawals_only:
            groups = {}
            order = []
            for prefix, out in self._announce.items():
                group = groups.get(out)
                if group is None:
                    group = []
                    groups[out] = group
                    order.append(out)
                group.append(prefix)
            self._announce = {}
            for out in order:
                group = groups[out]
                prefixes = group
                if self.add_path_send:
                    prefixes = [(p, _BEST_PATH_ID) for p in prefixes]
                try:
                    encoded = _wire.encode_announce(
                        prefixes, out, self.afi, self.safi, self.max_size,
                        self.as4, self.add_path_send, self.peer.is_ebgp)
                except ValueError:
                    self._suppressed[SUPPRESS_ENCODE] += len(group)
                    # The peer may still hold an older version of these
                    # prefixes; it must not keep a route we can no longer
                    # describe to it.
                    stale = [p for p in group if p in self._advertised]
                    if stale:
                        for p in stale:
                            del self._advertised[p]
                        if self.add_path_send:
                            stale = [(p, _BEST_PATH_ID) for p in stale]
                        msgs.extend(_wire.encode_withdraw(
                            stale, self.afi, self.safi, self.max_size,
                            self.add_path_send))
                    continue
                msgs.extend(encoded)
                for prefix in group:
                    self._advertised[prefix] = out
                self._announced += len(group)

        self._messages += len(msgs)
        return msgs

    def encode_advertised(self):
        """Re-encode the whole advertised record, changing nothing.

        For a peer that has to be told everything again without the rest
        of its update group being told anything: a member joining a group
        that already knows things, or one that asked for a route refresh.
        Neither may go through the staging area, because staging is shared
        and would re-advertise to every member; and neither may reset the
        record, because the other members' view of it is still true.

        The grouping is the same as :meth:`encode_pending`: one message
        per distinct attribute set, which for a full table is roughly one
        per distinct path rather than one per prefix.

        :return: a list of encoded UPDATE messages, in send order. Empty
            when nothing has been advertised.
        """
        if not self._advertised:
            return []
        groups = {}
        order = []
        for prefix, out in self._advertised.items():
            group = groups.get(out)
            if group is None:
                group = []
                groups[out] = group
                order.append(out)
            group.append(prefix)
        msgs = []
        for out in order:
            prefixes = groups[out]
            if self.add_path_send:
                prefixes = [(p, _BEST_PATH_ID) for p in prefixes]
            msgs.extend(_wire.encode_announce(
                prefixes, out, self.afi, self.safi, self.max_size,
                self.as4, self.add_path_send, self.peer.is_ebgp))
        self._messages += len(msgs)
        return msgs

    # --- inspection --------------------------------------------------------

    def advertised(self, prefix):
        """Return the attribute set this peer was last sent for a prefix.

        :param prefix: the prefix to look up.
        :return: the :class:`AttrSet`, or None if the peer has not been
            told about it. A staged but unencoded announcement does not
            count: the peer has not heard it yet.
        """
        return self._advertised.get(prefix)

    def entries(self):
        """Iterate what this peer currently holds.

        Backs ``show ip bgp neighbors <x> advertised-routes``, which is the
        only way to answer "did we actually send it" without a packet
        capture -- and the difference between this and the Loc-RIB is
        exactly the transform above, so the two views together also explain
        *why* a peer is missing a route.

        The order is the order prefixes were advertised, not a sorted one:
        sorting a full table for display belongs in the show layer, which
        can page it.

        :return: an iterator of ``(prefix, attrs)``.
        """
        return iter(self._advertised.items())

    def reset(self):
        """Forget everything this peer was told.

        Called when the session goes down. The peer discards its Adj-RIB-In
        for us on the way down, so the next session starts from nothing and
        every prefix must be re-advertised; an Adj-RIB-Out that survived
        would suppress precisely the announcements the new session needs.
        Staged changes go too, since they were computed for a session that
        no longer exists.

        The counters are kept. They are the peer's lifetime totals, and a
        flapping session's suppression counts are more interesting across
        the flaps than within one of them; ``resets`` says how many there
        were.
        """
        self._advertised = {}
        self._announce = {}
        self._withdraw = {}
        self._resets += 1

    def stats(self):
        """Return this peer's outbound counters for health and show output.

        :return: a dict of plain types, JSON-serialisable as it stands. The
            ``suppressed`` sub-dict always carries every reason key, zero
            included, so a caller can chart them without discovering a new
            series the first time a rule fires.
        """
        doc = {
            'afi': self.afi,
            'safi': self.safi,
            'advertised': len(self._advertised),
            'pending-announce': len(self._announce),
            'pending-withdraw': len(self._withdraw),
            'announcements': self._announced,
            'withdrawals': self._withdrawn,
            'suppressed': dict(self._suppressed),
            'suppressed-total': sum(self._suppressed.values()),
            'messages': self._messages,
            'resets': self._resets,
        }
        if self.policy is not None and not self.policy.empty:
            doc['policy'] = self.policy.stats()
        return doc

    def __len__(self):
        return len(self._advertised)

    def __repr__(self):
        return '<AdjRibOut afi=%d safi=%d %s advertised=%d pending=%d>' % (
            self.afi, self.safi,
            'external' if self.peer.is_ebgp else 'internal',
            len(self._advertised), self.pending())
