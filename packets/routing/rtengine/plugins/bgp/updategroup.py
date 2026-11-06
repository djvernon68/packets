# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Update groups: compute one outbound view, encode it once, send it to many.

Stage 3 gave every peer its own :class:`adjout.AdjRibOut`: its own copy of
the outbound transform, its own record of what it had been told, and its
own encoder. That is correct and it does not scale. Two hundred customers
under one policy produce two hundred identical attribute sets, two hundred
identical UPDATE messages built byte for byte from them, and two hundred
copies of a record that is the same record. FRR's update groups exist for
this reason and so do these: peers whose outbound encoding is *provably*
identical share one transform, one Adj-RIB-Out and one encoded message
stream, and the only per-peer work left is the write to the socket.

**"Provably" is the whole design, and it lives in the key.** Two peers may
share a group only if every input to the outbound transform is the same for
both -- the family, the peer type, the ASN encoding, the negotiated message
size and capabilities, the next-hop treatment, the community modes, the
outbound policy *and the revision of every list that policy names*. If any
component differs the peers are in different groups, so "encode once, send
N" is a statement about the group rather than a hope about the
configuration. :class:`UpdateGroupKey` is that tuple, and
:class:`OutboundSpec` is what the plugin fills in to compute it.

**The suppression invariant.** Sharing one staging area is only sound if
every path is either advertised to all the group's members or to none of
them, and three of ``adjout``'s suppression rules look per-peer at first
sight: split horizon (never send a path back to the peer it came from),
the eBGP AS-path loop check, and the iBGP split-horizon rule. The key
makes all three uniform:

* ``peer_as`` is in the key, so for an external group a path learned from
  one member carries that member's AS, which is *every* member's peer AS,
  and the loop check suppresses it for all of them -- the from-peer rule
  is subsumed rather than special-cased;
* ``is_ebgp`` is in the key, so an internal group's members all refuse an
  iBGP-learned path under the split-horizon rule, again including the
  member it came from;
* the two options that deliberately relax loop detection, ``as-override``
  and ``sender-loop-check`` turned off, force the peer into a group of its
  own through the key's ``unique`` component (``allowas-in`` used to be
  the second; it is about what *we* accept, and no longer touches what we
  send or how peers are grouped -- B-5). They exist precisely to send a
  peer paths that would otherwise be suppressed, which is the definition
  of not being equivalent to another peer. "A group of its own" has to
  mean *one* peer, so the component carries the peer's address as well as
  the reason; a constant marker would put every such peer in one group
  together, which is the failure this clause exists to prevent. The
  address is filled in by :meth:`UpdateGroupManager.join`, because that
  is where a peer's identity is known -- see :meth:`OutboundSpec.bind`.

So the invariant holds by construction, and the one case that would break
it cannot arise. It is worth stating because it is the only reason the
shared ``_advertised`` record is honest: it says "the group has been told",
and for every member that is the same sentence.

**MRAI, and what it is here.** RFC 4271 s9.2.1.1 rate-limits how often a
speaker may re-advertise routes for a destination. This implements it per
group rather than per prefix, which is the same simplification FRR makes
with its coalesce timer, and the trade is explicit: a group's flush is
deferred until its interval has elapsed since the last one, so a prefix
that flaps ten times inside the interval costs one message instead of ten,
while a prefix that changes once still waits up to the interval. Two
exemptions keep that from causing harm: the *first* flush of a quiet group
goes immediately, so a session that has just come up is not held back, and
a flush carrying withdrawals goes immediately, because a delayed
withdrawal is a black hole while a delayed announcement is only slower
convergence. The default interval is 0 -- see the schema comment in
``plugin.py`` -- because the advertisement pass already coalesces at its
own interval and a 30-second default would make a fresh session look
broken.

**Joining a group that already knows things.** A member that joins a group
whose ``_advertised`` record is not empty has itself been told nothing, and
the shared record would suppress exactly the announcements it needs. Such a
member is marked for catch-up and is sent the group's whole current record
once, encoded from the record rather than from the staging area, before it
takes part in the shared stream. That is the same mechanism a route-refresh
request uses for one member of a group, and it is why :meth:`replay`
exists.
"""

import logging
import time

from packets.routing.rtengine.plugins.bgp import adjout as _adjout

LOG = logging.getLogger(__name__)

#: Conventional minimum route advertisement intervals, for reference and
#: for anyone configuring ``advertisement-interval``: IOS uses 30 seconds
#: on an external session and 0 internally, on the reasoning that an
#: interior mesh is trusted to be stable and interior convergence matters
#: more than interior chatter. Neither is the shipped default; see the
#: module docstring.
CONVENTIONAL_MRAI_EBGP = 30.0
CONVENTIONAL_MRAI_IBGP = 0.0


class OutboundSpec(object):
    """Everything about how one peer's outbound stream is produced.

    Built by the plugin per ``(neighbour, family)`` from configuration and
    the negotiated session, and handed to
    :meth:`UpdateGroupManager.join`. It serves two purposes at once, and
    deliberately: :meth:`key` derives the group identity from it, and
    :meth:`build` constructs the group's Adj-RIB-Out from it. One object
    for both means the identity cannot claim two peers are equivalent
    while the thing built from it differs -- which is the failure mode
    that turns "encode once" into "send the wrong attributes to half a
    group".

    :param afi: address family number.
    :param safi: subsequent address family.
    :param is_ebgp: whether the session is external.
    :param peer_as: the neighbour's AS.
    :param local_as: our AS on the session.
    :param router_id: our router id, as a 32-bit int.
    :param local_addr: the next hop we advertise when we rewrite it.
    :param next_hop_self: rewrite the next hop for an internal peer too.
    :param default_local_pref: LOCAL_PREF given to an internal peer when
        the path carries none.
    :param send_community: send standard communities.
    :param send_ext_community: send extended communities.
    :param send_large_community: send large communities.
    :param max_size: the negotiated message ceiling.
    :param as4: the session carries 4-octet ASNs.
    :param add_path_send: ADD-PATH send is negotiated for this family.
    :param remove_private_as: strip RFC 6996 private ASNs outbound: False,
        True (only from an all-private path) or ``'all'``.
    :param as_override: replace the peer's AS with ours outbound.
    :param sender_loop_check: suppress paths that already contain the
        peer's AS; off only for a peer that accepts its own AS.
    :param mrai: minimum advertisement interval in seconds; 0 disables.
    :param policy: the outbound
        :class:`~packets.routing.rtengine.plugins.bgp.policy.PolicyChain`.
    :param policy_id: the identity of that policy for the group key: a
        tuple of ``(kind, name, version)`` triples. Versions matter as
        much as names -- two peers naming the same route-map are only
        equivalent while that route-map has not been edited, and a key
        that ignored the version would leave a peer in a group whose
        encoded stream no longer matches its policy.
    :param unique: a reason this peer may share a group with nobody.
        Defaulted from ``as_override``/``sender_loop_check``; see
        :meth:`bind` for how it becomes peer-specific.
    """

    __slots__ = ('afi', 'safi', 'is_ebgp', 'peer_as', 'local_as',
                 'router_id', 'local_addr', 'next_hop_self',
                 'default_local_pref', 'send_community',
                 'send_ext_community', 'send_large_community', 'max_size',
                 'as4', 'add_path_send', 'remove_private_as', 'as_override',
                 'sender_loop_check', 'mrai', 'policy', 'policy_id',
                 'unique', 'peer_addr')

    def __init__(self, afi, safi, is_ebgp, peer_as, local_as, router_id,
                 local_addr, next_hop_self=False, default_local_pref=100,
                 send_community=True, send_ext_community=True,
                 send_large_community=True, max_size=4096, as4=True,
                 add_path_send=False, remove_private_as=False,
                 as_override=False, sender_loop_check=True, mrai=0.0,
                 policy=None, policy_id=(), unique=None):
        self.afi = afi
        self.safi = safi
        self.is_ebgp = bool(is_ebgp)
        self.peer_as = peer_as
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
        self.remove_private_as = _adjout.remove_private_mode(
            remove_private_as)
        self.as_override = bool(as_override)
        self.sender_loop_check = bool(sender_loop_check)
        self.mrai = float(mrai)
        self.policy = policy
        self.policy_id = tuple(policy_id)
        # The singleton escape hatch, in two halves: the *reason* is
        # decided here and the peer it applies to is filled in by bind()
        # when the peer joins. See bind() for why the reason alone is not
        # enough.
        self.unique = unique
        if unique is None and (self.as_override or
                               not self.sender_loop_check):
            self.unique = 'relaxed-loop-detection'
        self.peer_addr = None

    def bind(self, address):
        """Attach the peer this spec was built for.

        Only the singleton component reads it, and only when there is a
        reason to be a singleton. That is the whole point: a peer with
        ``as-override`` or the sender loop check off must share its outbound
        stream with nobody, and a marker saying merely "this peer is special"
        would match every other special peer and put them all in one
        group -- where the group's single representative ``PeerRef``
        would then suppress, for all of them, the very paths those
        options exist to deliver. Which member's ref the group held
        depends on join order, so the symptom would move between
        restarts as well.

        Every other component is shared by construction, so binding an
        ordinary spec changes nothing about its key. That is why this is
        called unconditionally rather than only for the odd cases: a
        condition here would be one more place for the condition to be
        wrong.

        :param address: the neighbour's address.
        :return: self, so a caller can bind and key in one expression.
        """
        self.peer_addr = address
        return self

    def key(self):
        """Return the group identity this spec implies.

        :return: an :class:`UpdateGroupKey`.
        """
        return UpdateGroupKey(
            afi=self.afi, safi=self.safi, is_ebgp=self.is_ebgp,
            peer_as=self.peer_as, local_as=self.local_as,
            local_addr=self.local_addr, next_hop_self=self.next_hop_self,
            default_local_pref=self.default_local_pref,
            send_community=self.send_community,
            send_ext_community=self.send_ext_community,
            send_large_community=self.send_large_community,
            max_size=self.max_size, as4=self.as4,
            add_path_send=self.add_path_send,
            remove_private_as=self.remove_private_as,
            as_override=self.as_override,
            sender_loop_check=self.sender_loop_check,
            mrai=self.mrai, policy_id=self.policy_id,
            unique=self._unique_key())

    def _unique_key(self):
        """Return the singleton component of the key.

        :return: None when this peer may share a group, and a value
            carrying both the reason and the peer otherwise.
        """
        if self.unique is None:
            return None
        return '%s@%s' % (self.unique, self.peer_addr or '')

    def build(self, peer_ref):
        """Construct the Adj-RIB-Out this spec describes.

        :param peer_ref: a :class:`bestpath.PeerRef` for the group. Any
            member's ref serves: the transform reads only the peer AS, the
            address and the external flag, and the first two are in the
            key, so every member agrees on them. The address is the one
            exception and it is used only by the from-peer split-horizon
            test, which the AS-path and iBGP rules already subsume for a
            group -- see the module docstring.
        :return: an :class:`adjout.AdjRibOut`.
        :raises ValueError: the local address does not match the family
            width, which is a configuration error rather than a wire one.
        """
        return _adjout.AdjRibOut(
            peer_ref, self.afi, self.safi, self.local_as, self.router_id,
            self.local_addr, next_hop_self=self.next_hop_self,
            default_local_pref=self.default_local_pref,
            send_community=self.send_community,
            send_ext_community=self.send_ext_community,
            send_large_community=self.send_large_community,
            max_size=self.max_size, as4=self.as4,
            add_path_send=self.add_path_send,
            remove_private_as=self.remove_private_as,
            as_override=self.as_override,
            sender_loop_check=self.sender_loop_check,
            policy=self.policy)

    def __repr__(self):
        return '<OutboundSpec %d/%d %s as=%s%s>' % (
            self.afi, self.safi,
            'external' if self.is_ebgp else 'internal', self.peer_as,
            ' unique=%s' % (self.unique,) if self.unique else '')


class UpdateGroupKey(object):
    """The tuple that decides whether two peers share an update group.

    Hashable and comparable, and nothing else: it is a value. The fields
    are kept as a tuple internally so equality and hashing are one C-level
    comparison rather than eighteen attribute reads -- a peer's key is
    recomputed on every configuration commit, and a router with a thousand
    neighbours recomputes a thousand of them.

    Every keyword mirrors an :class:`OutboundSpec` field; see that class
    for what they mean and the module docstring for why each one has to be
    here.
    """

    __slots__ = ('_tuple',)

    def __init__(self, afi=0, safi=0, is_ebgp=False, peer_as=0, local_as=0,
                 local_addr=b'', next_hop_self=False,
                 default_local_pref=100, send_community=True,
                 send_ext_community=True, send_large_community=True,
                 max_size=4096, as4=True, add_path_send=False,
                 remove_private_as=False, as_override=False,
                 sender_loop_check=True, mrai=0.0, policy_id=(),
                 unique=None):
        # remove_private_as is the mode, not a bool: `true` and `all` are
        # different streams and must not share a group.
        self._tuple = (
            afi, safi, bool(is_ebgp), peer_as, local_as, local_addr,
            bool(next_hop_self), default_local_pref, bool(send_community),
            bool(send_ext_community), bool(send_large_community), max_size,
            bool(as4), bool(add_path_send),
            _adjout.remove_private_mode(remove_private_as),
            bool(as_override), bool(sender_loop_check), float(mrai),
            tuple(policy_id), unique)

    #: Field names in the order they appear in the tuple, so
    #: :meth:`as_dict` and a failing test can both say *which* component
    #: differed rather than printing two opaque tuples.
    FIELDS = ('afi', 'safi', 'is-ebgp', 'peer-as', 'local-as',
              'local-addr', 'next-hop-self', 'default-local-pref',
              'send-community', 'send-ext-community',
              'send-large-community', 'max-size', 'as4', 'add-path-send',
              'remove-private-as', 'as-override', 'sender-loop-check',
              'mrai', 'policy', 'unique')

    def __hash__(self):
        return hash(self._tuple)

    def __eq__(self, other):
        if not isinstance(other, UpdateGroupKey):
            return NotImplemented
        return self._tuple == other._tuple

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def differences(self, other):
        """Return the names of the components that differ from another key.

        The diagnostic that makes group membership explicable: "these two
        peers are not in one group" is a useless answer, and "they differ
        in send-community" is the whole answer.

        :param other: another key.
        :return: a list of field names, empty when the keys are equal.
        """
        if not isinstance(other, UpdateGroupKey):
            raise ValueError('not an UpdateGroupKey: %r' % (other,))
        return [name for name, mine, theirs
                in zip(self.FIELDS, self._tuple, other._tuple)
                if mine != theirs]

    def as_dict(self):
        """Render the key for ``show`` output.

        :return: a dict of plain types. ``local-addr`` is hex rather than
            raw bytes so the document stays JSON-serialisable.
        """
        out = {}
        for name, value in zip(self.FIELDS, self._tuple):
            if isinstance(value, bytes):
                value = value.hex() if value else None
            elif isinstance(value, tuple):
                value = [list(item) for item in value]
            elif name == 'remove-private-as':
                value = _adjout.remove_private_text(value)
            out[name] = value
        return out

    def __repr__(self):
        return '<UpdateGroupKey %d/%d %s as=%s policy=%s%s>' % (
            self._tuple[0], self._tuple[1],
            'external' if self._tuple[2] else 'internal', self._tuple[3],
            self._tuple[18] or 'none',
            ' unique=%s' % (self._tuple[19],) if self._tuple[19] else '')


class UpdateGroup(object):
    """One shared outbound transform, record and encoder, and its members.

    :param gid: a small integer identity, stable for the group's life and
        reported by ``show ip bgp neighbors`` so an operator can see which
        peers share a stream.
    :param spec: the :class:`OutboundSpec` every member agrees on.
    :param peer_ref: a member's :class:`bestpath.PeerRef`, for the
        transform.
    :param clock: monotonic clock, injected for tests.
    """

    __slots__ = ('gid', 'key', 'spec', 'out', 'members', 'clock',
                 '_catchup', '_seeded', 'last_send', 'flushes', 'messages',
                 'writes', 'deferrals', 'replays')

    def __init__(self, gid, spec, peer_ref, clock=None):
        self.gid = gid
        self.spec = spec
        self.key = spec.key()
        self.clock = clock if clock is not None else time.monotonic
        self.out = spec.build(peer_ref)
        self.members = {}
        # Members that have joined a group which already knows things, and
        # therefore owe a full replay of the shared record before the
        # shared stream means anything to them.
        self._catchup = set()
        # Whether anything has ever staged the table into this group. A
        # brand new group's record is empty *and* nobody has offered it
        # the table, so the plugin has to walk the Loc-RIB once; that is a
        # different condition from a member needing catch-up and is not
        # interchangeable with it.
        self._seeded = False
        self.last_send = 0.0
        self.flushes = 0
        self.messages = 0
        self.writes = 0
        self.deferrals = 0
        self.replays = 0

    # --- membership --------------------------------------------------------

    def add(self, peer):
        """Take a peer into the group.

        :param peer: the :class:`peer.Peer`. Its ``adjout`` mapping is
            pointed at this group's table for the group's family, so
            everything that already reads ``session.adjout[af]`` -- show
            output, the tests -- keeps working and reads the shared record
            rather than a private one.
        :return: True if the peer owes a catch-up replay.
        """
        addr = peer.config.address
        self.members[addr] = peer
        peer.adjout[(self.spec.afi, self.spec.safi)] = self.out
        if self.out.advertised_count():
            self._catchup.add(addr)
            return True
        return False

    def remove(self, addr):
        """Drop a member.

        The shared record is deliberately *not* reset. It describes what
        the group has been told, and the members still in it have been
        told it; resetting here would suppress nothing and re-advertise
        everything to every remaining peer, turning one session's flap
        into a table-wide re-advertisement -- the exact churn update
        groups exist to avoid. An empty group is discarded by the manager,
        which is where the record does go away.

        :param addr: the member's address.
        :return: True if the group is now empty.
        """
        peer = self.members.pop(addr, None)
        self._catchup.discard(addr)
        if peer is not None:
            peer.adjout.pop((self.spec.afi, self.spec.safi), None)
        return not self.members

    def member_addresses(self):
        """Return the member addresses, sorted.

        :return: a sorted list of addresses.
        """
        return sorted(self.members)

    # --- staging -----------------------------------------------------------

    @property
    def seeded(self):
        """Whether the group has been offered the whole table once."""
        return self._seeded

    def mark_seeded(self):
        """Record that the caller has staged the whole table."""
        self._seeded = True

    def announce(self, dest):
        """Offer a destination's best path to the group.

        :param dest: a :class:`bestpath.BgpDest`, or None.
        :return: True if the staging area changed.
        """
        return self.out.announce(dest)

    def withdraw(self, prefix):
        """Stage a withdrawal for the group.

        :param prefix: the :class:`rib.prefix.Prefix`.
        :return: True if the staging area changed.
        """
        return self.out.withdraw(prefix)

    def pending(self):
        """Return how many staged changes are waiting.

        :return: staged prefixes, announcements plus withdrawals.
        """
        return self.out.pending()

    # --- sending -----------------------------------------------------------

    def due(self, now=None):
        """Whether this group may send now.

        :param now: monotonic time, or None for the group's clock.
        :return: True when there is something staged and either the
            interval has elapsed, nothing has been sent yet, or the
            staging area holds a withdrawal. See the module docstring for
            why those two exemptions exist.
        """
        if not self.out.pending():
            return False
        if self.spec.mrai <= 0.0 or self.last_send <= 0.0:
            return True
        if self.out.pending_withdrawals():
            return True
        if now is None:
            now = self.clock()
        return (now - self.last_send) >= self.spec.mrai

    def _interval_open(self, now=None):
        """Whether announcements may go now, as far as MRAI is concerned."""
        if self.spec.mrai <= 0.0 or self.last_send <= 0.0:
            return True
        if now is None:
            now = self.clock()
        return (now - self.last_send) >= self.spec.mrai

    def due_in(self, now=None):
        """Return the seconds until this group may send.

        :param now: monotonic time, or None for the group's clock.
        :return: 0.0 when it may send now or has nothing to send; the
            remaining interval otherwise. The plugin's pass uses it to
            report why a group is holding messages rather than guessing.
        """
        if self.due(now):
            return 0.0
        if not self.out.pending():
            return 0.0
        if now is None:
            now = self.clock()
        return max(0.0, self.spec.mrai - (now - self.last_send))

    def flush(self, now=None, force=False):
        """Encode the staging area once and write it to every member.

        This is the point of the class. The encode happens exactly once
        however many members there are, and each member pays only for its
        own socket write.

        :param now: monotonic time, or None for the group's clock.
        :param force: ignore the advertisement interval. Used by a
            deliberate operator action -- a soft clear -- where waiting
            out a timer would make the command look like it did nothing.
        :return: the number of messages *written*, which is the number
            encoded multiplied by the members that took them. The encoded
            count is in ``stats()`` as ``group-messages``; the two
            together are the measure of what the grouping saved.
        """
        if not force and not self.due(now):
            if self.out.pending():
                self.deferrals += 1
            return 0
        # B-10: a staged withdrawal makes the group due, but only the
        # withdrawals are exempt from the interval. The announcements wait
        # out the rest of it, and the interval keeps running from the last
        # announcement rather than restarting.
        withdrawals_only = (not force and not self._interval_open(now) and
                            self.out.pending_withdrawals() > 0)
        messages = self.out.encode_pending(withdrawals_only=withdrawals_only)
        if withdrawals_only and self.out.pending():
            self.deferrals += 1
        if not messages:
            return 0
        self.flushes += 1
        self.messages += len(messages)
        if not withdrawals_only:
            self.last_send = self.clock() if now is None else now
        written = 0
        for peer in list(self.members.values()):
            if not peer.established:
                # A member that is down has nothing to be told and its
                # record is about to be dealt with by the manager when
                # the session's teardown reaches it. Skipping it here
                # rather than raising keeps a flush from depending on the
                # order two events happened in.
                continue
            written += peer.send_updates(messages)
        self.writes += written
        return written

    def catchup(self):
        """Return the members that owe a full replay.

        :return: a sorted list of addresses.
        """
        return sorted(self._catchup)

    def replay(self, peer, force=False):
        """Re-send the whole shared record to one member.

        Two callers, one mechanism. A peer that joined a group which
        already knew things has been told none of it, and a peer that
        asked for a route refresh has asked to be told all of it again;
        in both cases what it must receive is the group's current record,
        encoded for it alone, and in neither case may the shared staging
        area or the shared record be disturbed -- doing so would
        re-advertise to every other member as well.

        :param peer: the member to replay to.
        :param force: replay even if the member is not marked for
            catch-up, which is what a route-refresh request does.
        :return: the number of messages written.
        """
        addr = peer.config.address
        if not force and addr not in self._catchup:
            return 0
        self._catchup.discard(addr)
        if not peer.established:
            return 0
        messages = self.out.encode_advertised()
        self.replays += 1
        self.messages += len(messages)
        sent = peer.send_updates(messages)
        self.writes += sent
        return sent

    def reset(self):
        """Forget the shared record entirely.

        The group-wide counterpart of :meth:`replay`: correct when *every*
        member is to be re-advertised to, which happens when the group's
        policy changed under it and the manager has decided to rebuild
        rather than move the members. The next staging pass repopulates
        the record from the Loc-RIB, so the caller must also clear the
        seeded flag -- which this does.
        """
        self.out.reset()
        self._seeded = False
        self._catchup = set(self.members)

    # --- reporting ---------------------------------------------------------

    def stats(self):
        """Return this group's counters.

        :return: a dict of plain types.
        """
        out = self.out.stats()
        out.update({
            'id': self.gid,
            'members': self.member_addresses(),
            'member-count': len(self.members),
            'mrai': self.spec.mrai,
            'flushes': self.flushes,
            'group-messages': self.messages,
            'writes': self.writes,
            'deferrals': self.deferrals,
            'replays': self.replays,
            'catchup': self.catchup(),
            'seeded': self._seeded,
            'due-in': round(self.due_in(), 3),
        })
        return out

    def as_dict(self):
        """Render the group and its key for ``show``.

        :return: a dict of plain types.
        """
        doc = self.stats()
        doc['key'] = self.key.as_dict()
        doc['policy'] = (self.spec.policy.stats()
                         if self.spec.policy is not None
                         and not self.spec.policy.empty else None)
        return doc

    def __repr__(self):
        return '<UpdateGroup %d %d/%d members=%d advertised=%d pending=%d>' \
            % (self.gid, self.spec.afi, self.spec.safi, len(self.members),
               self.out.advertised_count(), self.out.pending())


class UpdateGroupManager(object):
    """Every update group, and which peer is in which.

    One manager per BGP plugin instance. It owns the group objects, moves
    a peer when its key changes, discards a group when its last member
    leaves, and is the single entry point the advertisement pass uses to
    stage and flush.

    :param clock: monotonic clock, injected for tests.
    """

    __slots__ = ('clock', '_groups', '_by_peer', '_next_id', 'joins',
                 'moves', 'leaves', 'created', 'destroyed')

    def __init__(self, clock=None):
        self.clock = clock if clock is not None else time.monotonic
        # key -> UpdateGroup. The key carries the family, so one dict
        # serves every family rather than a dict per family.
        self._groups = {}
        # (address, (afi, safi)) -> UpdateGroup, so a peer's teardown and
        # a key recomputation are both direct lookups. A peer with two
        # families is in two groups and they are usually not the same
        # group, because the family is in the key.
        self._by_peer = {}
        self._next_id = 1
        self.joins = 0
        self.moves = 0
        self.leaves = 0
        self.created = 0
        self.destroyed = 0

    # --- membership --------------------------------------------------------

    def join(self, peer, spec, peer_ref=None):
        """Put a peer in the group its spec implies, moving it if needed.

        Idempotent: a peer whose key has not changed stays where it is and
        nothing is re-advertised. That matters more than it looks --
        configuration commits recompute every peer's spec, and a join that
        rebuilt the group every time would re-advertise the table on every
        unrelated edit.

        :param peer: the :class:`peer.Peer`.
        :param spec: the :class:`OutboundSpec` for this peer and family.
        :param peer_ref: the peer's :class:`bestpath.PeerRef`, used when a
            new group has to be created. Defaults to the peer's own.
        :return: the :class:`UpdateGroup` the peer is now in.
        :raises ValueError: the spec cannot build a table -- a local
            address of the wrong width for the family. Raised rather than
            swallowed because it is a configuration error and a peer
            silently left out of every group would simply never advertise.
        """
        addr = peer.config.address
        af = (spec.afi, spec.safi)
        key = spec.bind(addr).key()
        current = self._by_peer.get((addr, af))
        if current is not None:
            if current.key == key:
                return current
            self._detach(addr, af, current)
            self.moves += 1

        group = self._groups.get(key)
        if group is None:
            group = UpdateGroup(self._next_id, spec,
                                peer_ref if peer_ref is not None
                                else peer.peer_ref, clock=self.clock)
            self._next_id += 1
            self._groups[key] = group
            self.created += 1
        group.add(peer)
        self._by_peer[(addr, af)] = group
        self.joins += 1
        return group

    def leave(self, peer, af=None):
        """Take a peer out of one group or all of them.

        :param peer: the :class:`peer.Peer`.
        :param af: an ``(afi, safi)`` pair, or None for every family.
        :return: the number of groups the peer left.
        """
        addr = peer.config.address
        if af is not None:
            group = self._by_peer.get((addr, af))
            if group is None:
                return 0
            self._detach(addr, af, group)
            self.leaves += 1
            return 1
        left = 0
        for key in [k for k in self._by_peer if k[0] == addr]:
            self._detach(addr, key[1], self._by_peer[key])
            left += 1
        self.leaves += left
        return left

    def _detach(self, addr, af, group):
        """Remove one membership and discard the group if it emptied."""
        self._by_peer.pop((addr, af), None)
        if group.remove(addr):
            self._groups.pop(group.key, None)
            self.destroyed += 1

    def group_of(self, address, af):
        """Return the group a peer is in for one family, or None.

        :param address: the neighbour's address.
        :param af: an ``(afi, safi)`` pair.
        :return: the :class:`UpdateGroup`, or None.
        """
        return self._by_peer.get((address, af))

    def groups_for(self, af):
        """Return every group for one family.

        :param af: an ``(afi, safi)`` pair.
        :return: a list of :class:`UpdateGroup`, in creation order, which
            is a stable order and therefore a reproducible send order.
        """
        return [g for g in sorted(self._groups.values(),
                                  key=lambda g: g.gid)
                if (g.spec.afi, g.spec.safi) == af]

    def groups(self):
        """Return every group, in creation order.

        :return: a list of :class:`UpdateGroup`.
        """
        return sorted(self._groups.values(), key=lambda g: g.gid)

    def __len__(self):
        return len(self._groups)

    # --- staging and sending -----------------------------------------------

    def announce(self, af, dest):
        """Offer a destination to every group of one family.

        :param af: an ``(afi, safi)`` pair.
        :param dest: a :class:`bestpath.BgpDest`.
        :return: the number of groups whose staging area changed.
        """
        changed = 0
        for group in self.groups_for(af):
            if group.announce(dest):
                changed += 1
        return changed

    def withdraw(self, af, prefix):
        """Stage a withdrawal in every group of one family.

        :param af: an ``(afi, safi)`` pair.
        :param prefix: the :class:`rib.prefix.Prefix`.
        :return: the number of groups whose staging area changed.
        """
        changed = 0
        for group in self.groups_for(af):
            if group.withdraw(prefix):
                changed += 1
        return changed

    def flush(self, now=None, force=False):
        """Flush every group that may send.

        :param now: monotonic time, or None for the manager's clock.
        :param force: ignore every advertisement interval.
        :return: the number of messages written across all groups.
        """
        if now is None:
            now = self.clock()
        total = 0
        for group in self.groups():
            total += group.flush(now=now, force=force)
        return total

    def pending(self):
        """Return how many staged prefixes are waiting across all groups.

        :return: the total, a health metric: a figure that does not fall
            between passes means policy or MRAI is holding messages that
            will never go.
        """
        return sum(g.pending() for g in self._groups.values())

    # --- reporting ---------------------------------------------------------

    def stats(self):
        """Return counters for health output.

        :return: a dict of plain types.
        """
        return {
            'groups': len(self._groups),
            'memberships': len(self._by_peer),
            'created': self.created,
            'destroyed': self.destroyed,
            'joins': self.joins,
            'moves': self.moves,
            'leaves': self.leaves,
            'pending': self.pending(),
        }

    def as_dict(self):
        """Render every group for ``show ip bgp update-groups``.

        :return: a dict of plain types.
        """
        doc = self.stats()
        doc['items'] = [g.as_dict() for g in self.groups()]
        return doc

    def __repr__(self):
        return '<UpdateGroupManager groups=%d memberships=%d>' % (
            len(self._groups), len(self._by_peer))
