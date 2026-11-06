# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Prefix-lists: ``permit``/``deny`` over a prefix and a length window.

A prefix-list is the oldest and most used filter in routing, and its
semantics are not quite what its syntax suggests. An entry names a prefix and
optionally a length window -- ``ge``, ``le``, or both -- and a candidate
prefix matches when it falls *inside* the entry's prefix and its own length
lies in the window. Four spellings, four different windows, and the
difference between them is the difference between filtering a /24 and
filtering everything beneath a /8::

    10.0.0.0/8              exactly 10.0.0.0/8 and nothing else
    10.0.0.0/8 ge 24        anything inside 10/8 with a length of 24 to 32
    10.0.0.0/8 le 16        anything inside 10/8 with a length of 8 to 16
    10.0.0.0/8 ge 16 le 24  anything inside 10/8 with a length of 16 to 24

The first entry in sequence order whose prefix covers the candidate *and*
whose window admits the candidate's length decides, and nothing later is
consulted. That last part is why this module is not a filter chain of
callables: an operator writes overlapping entries on purpose -- a specific
``deny`` at seq 5 in front of a general ``permit`` at seq 10 -- and the whole
behaviour depends on the earliest sequence number winning, not the most
specific prefix.

**Why a trie.** This is evaluated once per prefix per policy application:
accepting a full table through an inbound route-map is a million evaluations,
and a peer flapping re-runs them. A list scan is O(entries) per prefix, and
real prefix-lists at an exchange point have thousands of entries, so the scan
is where the time goes. The observation that fixes it is that *every* match
requires the entry's prefix to cover the candidate: the window's lower bound
is either the entry's own length (no ``ge``) or ``ge`` itself, and ``ge`` is
validated to be at least the entry length, so a matching entry can never be
longer than the candidate. The candidates are therefore exactly the entry
prefixes that cover the candidate prefix, and "all prefixes covering this
one" is a single root-to-node descent of a Patricia trie -- at most 32 or 128
nodes visited, in practice three or four.

So the index is the RIB's own :class:`~...rib.trie.Trie`, keyed by entry
prefix, with a list of entries per node because two entries may share a
prefix and differ only in their window. Reusing it rather than writing
another radix structure is deliberate: it is the same code the route table
and the resolver are already exercising, and it is the code whose node
lifetime has been reviewed. The descent is written here rather than added to
``Trie`` because it is a *collecting* walk -- it visits every covering node,
where ``node_lpm`` stops at the longest -- and because the decision it makes
at each node (does this node's entry list admit the candidate's length) is a
prefix-list concept that has no business inside the RIB.

**Memory.** Nothing in this module allocates C memory. Entries are Python
objects, the per-node entry list is a Python list, and the trie owns its
nodes and manages the references to those lists exactly as it does for the
route table. That is the other half of the argument for reusing the trie:
the leaks worth worrying about in a structure like this live in node
allocation and in the hand-rolled reference counting around a stored value,
and this module contains neither. ``remove`` drops the entry from its node's
list and removes the node when the list empties, so repeated rebuilds of a
list return the trie to zero nodes.
"""

from libc.stdint cimport uint32_t

from packets.routing.rtengine.rib.prefix cimport (Prefix, pfx_addr_bits,
                                                  pfx_addr_len, pfx_bit,
                                                  pfx_match)
from packets.routing.rtengine.rib.trie cimport TrieNode, trie_node_value

from packets.routing.rtengine.rib.prefix import Prefix as _Prefix, \
    parse_prefix
from packets.routing.rtengine.rib.trie import Trie as _Trie

# Python-visible spellings of the C constants in prefixlist.pxd. Every other
# policy module imports the pair from here rather than defining its own, so
# that an as-path list, a prefix-list and a route-map clause all speak the
# same two integers and a caller can compare results across them.
ACTION_DENY = PL_ACTION_DENY
ACTION_PERMIT = PL_ACTION_PERMIT

#: "No entry matched", the third outcome of a filter. A caller treats it as a
#: deny -- that is IOS' implicit deny and this engine does not change it --
#: but it is returned distinctly so that show and debug output can tell an
#: operator the difference between a prefix their configuration rejected and
#: a prefix their configuration never mentioned.
NO_MATCH = -1

#: Action id to the word an operator wrote. Used by every ``as_dict``, so
#: that show output never prints a bare 0 or 1.
ACTION_NAMES = {PL_ACTION_DENY: 'deny', PL_ACTION_PERMIT: 'permit'}

#: The reverse mapping, for parsing configuration.
ACTION_IDS = {'deny': PL_ACTION_DENY, 'permit': PL_ACTION_PERMIT}

# The widest sequence number an entry can carry. The configuration schema is
# stricter (it starts at 1, and PolicyStore auto-numbers in fives when the
# operator omits seq); this is only the width of the field.
MAX_SEQ = 0xffffffff


cdef int _coerce_action(object action) except -1:
    """Accept either the word an operator wrote or the integer it maps to.

    Both spellings are wanted: a configuration document carries
    ``'permit'``, while a caller that has already read an action off another
    entry has the int. Accepting both here keeps the conversion out of every
    call site.

    :param action: ``'permit'``, ``'deny'``, or 0 or 1.
    :return: the action id.
    :raises ValueError: anything else, including a bool -- ``True`` would
        otherwise silently mean permit.
    """
    if isinstance(action, str):
        try:
            return ACTION_IDS[action]
        except KeyError:
            raise ValueError("action must be 'permit' or 'deny', not %r"
                             % (action,))
    if isinstance(action, int) and not isinstance(action, bool):
        if action == PL_ACTION_DENY or action == PL_ACTION_PERMIT:
            return action
    raise ValueError("action must be 'permit', 'deny', %d or %d, not %r"
                     % (PL_ACTION_DENY, PL_ACTION_PERMIT, action))


cdef uint32_t _coerce_seq(object seq) except? 0:
    """Range-check a sequence number.

    :param seq: the sequence number.
    :return: it, as a 32-bit value.
    :raises ValueError: not an int, a bool, or outside the field width.
    """
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise ValueError('seq must be an integer, not %r' % (seq,))
    if seq < 0 or seq > MAX_SEQ:
        raise ValueError('seq %r is outside 0..%d' % (seq, MAX_SEQ))
    return <uint32_t>seq


cdef object _coerce_prefix(object prefix):
    """Accept a :class:`Prefix` or the text form an operator writes.

    :param prefix: a Prefix, or ``'10.0.0.0/8'`` as str or ASCII bytes.
    :return: the Prefix.
    :raises ValueError: unparseable text, or an object that is neither.
    """
    if isinstance(prefix, _Prefix):
        return prefix
    if isinstance(prefix, (str, bytes)):
        return parse_prefix(prefix)
    raise ValueError('prefix must be a Prefix or prefix text, not %s'
                     % type(prefix).__name__)


cdef int _coerce_bound(str which, object value, unsigned char abits) \
        except -1:
    """Range-check an ``le`` or ``ge`` bound against its address family.

    :param which: ``'le'`` or ``'ge'``, for the message.
    :param value: the bound, or 0 for "not configured".
    :param abits: 32 or 128.
    :return: the bound.
    :raises ValueError: not an int, a bool, negative, or wider than the
        family. 128 on an IPv4 entry is rejected rather than clamped: the
        configuration schema accepts 0..128 for both families because it
        does not know the family at that point, so this is the only place
        that can catch it.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError('%s must be an integer, not %r' % (which, value))
    if value < 0 or value > abits:
        raise ValueError('%s %r is outside 0..%d for this address family'
                         % (which, value, abits))
    return value


def action_id(action):
    """Convert a configured action to its id, for the Python policy modules.

    The conversion itself is a C function in this module, which is where the
    two constants live; this is its Python-visible form, so that the
    as-path lists and the route-maps do not each grow their own copy of the
    same four-line mapping and drift from it.

    :param action: ``'permit'``, ``'deny'``, or 0 or 1.
    :return: :data:`ACTION_DENY` or :data:`ACTION_PERMIT`.
    :raises ValueError: anything else, including a bool.
    """
    return _coerce_action(action)


def seq_number(seq):
    """Range-check a sequence number, for the Python policy modules.

    :param seq: the sequence number.
    :return: it, as an int.
    :raises ValueError: not an integer, a bool, or outside 0..4294967295.
    """
    return _coerce_seq(seq)


cdef class PrefixListEntry:
    """One ``seq action prefix [ge N] [le N]`` line of a prefix-list.

    Constructed by :meth:`PrefixList.add`, which is also where the family
    check against the owning list happens. It is public and directly
    constructible because all of the validation that does not need the list
    lives here, and a caller building an entry to inspect its derived window
    should not have to build a list around it.

    :param seq: sequence number; the first matching entry in ascending
        ``seq`` order decides the whole list.
    :param action: ``'permit'``, ``'deny'``, or the matching int.
    :param prefix: a :class:`Prefix` or its text form. The family of the
        entry is this prefix's family.
    :param le: inclusive upper bound on the candidate's prefix length; 0
        means "not configured", which is not the same as a bound of 0. A
        ``ge 0`` filter, which is the only thing the sentinel makes
        inexpressible, is spelled ``le 32`` (or ``le 128``) on a ``/0``
        entry and means the same thing.
    :param ge: inclusive lower bound, with the same sentinel.
    :raises ValueError: a bad action, seq or prefix; a bound wider than the
        family; a bound shorter than the entry's own prefix length; or
        ``ge`` greater than ``le``. A window that cannot admit anything is
        always a typo -- and a silently dead entry in a filter chain is the
        kind of mistake that is discovered by a route that should have been
        blocked.
    """

    def __init__(self, seq, action, prefix, le=0, ge=0):
        cdef Prefix p = <Prefix>_coerce_prefix(prefix)
        cdef unsigned char abits = pfx_addr_bits(p.afi)
        cdef int le_v = _coerce_bound('le', le, abits)
        cdef int ge_v = _coerce_bound('ge', ge, abits)

        if le_v and le_v < p.plen:
            raise ValueError('le %d is shorter than the prefix length of %s'
                             % (le_v, p.to_str()))
        if ge_v and ge_v < p.plen:
            raise ValueError('ge %d is shorter than the prefix length of %s'
                             % (ge_v, p.to_str()))
        if le_v and ge_v and ge_v > le_v:
            raise ValueError('ge %d is greater than le %d' % (ge_v, le_v))

        self.seq = _coerce_seq(seq)
        self.action = <unsigned char>_coerce_action(action)
        self.prefix = p
        self.le = <unsigned char>le_v
        self.ge = <unsigned char>ge_v
        # The four spellings collapse here, once, into one inclusive window.
        # Everything after this point tests `lo <= plen <= hi` and never asks
        # again which bounds were written.
        self.lo = <unsigned char>(ge_v if ge_v else p.plen)
        self.hi = <unsigned char>(le_v if le_v else
                                  (abits if ge_v else p.plen))
        self.hits = 0

    def __repr__(self):
        return '<PrefixListEntry %d %s %s le=%d ge=%d>' % (
            self.seq, ACTION_NAMES[self.action], self.prefix.to_str(),
            self.le, self.ge)

    cpdef dict as_dict(self):
        """Render the entry for ``show ip prefix-list``.

        ``le`` and ``ge`` are always present, as 0 when they were not
        configured, rather than being omitted: a caller rendering a table of
        entries would otherwise have to special-case the shape of every row.
        ``match`` is the derived window, which is what an operator actually
        wants to see when the question is why an entry did not fire.

        :return: a dict of plain types.
        """
        return {
            'seq': self.seq,
            'action': ACTION_NAMES[self.action],
            'prefix': self.prefix.to_str(),
            'le': self.le,
            'ge': self.ge,
            'match': [self.lo, self.hi],
            'hits': self.hits,
        }


cdef class PrefixList:
    """A named, ordered, single-family list of permit/deny prefix entries.

    :param name: the name the configuration and every reference use.
    :param afi: ``AFI_IP`` or ``AFI_IP6``. A prefix-list is single-family
        because IOS' is: ``ip prefix-list`` and ``ipv6 prefix-list`` are
        separate namespaces, and an entry has no way to say which family it
        meant beyond its own prefix.
    :raises ValueError: an empty name, or an unknown address family.
    """

    def __init__(self, str name, int afi):
        if not name:
            raise ValueError('a prefix-list name is required')
        if afi < 0 or afi > 255 or pfx_addr_len(<unsigned char>afi) == 0:
            raise ValueError('unsupported address family number %r' % (afi,))
        self.name = name
        self.afi = <unsigned char>afi
        self.abits = pfx_addr_bits(<unsigned char>afi)
        self.version = 0
        self.hits = 0
        self.matches = 0
        self.trie = _Trie(afi)
        self._entries = []

    def __len__(self):
        return len(self._entries)

    def __repr__(self):
        return '<PrefixList %s afi=%d entries=%d version=%d>' % (
            self.name, self.afi, len(self._entries), self.version)

    # --- mutation ----------------------------------------------------------
    # Every mutator bumps `version`, and that number is a contract, not a
    # diagnostic: an update-group key cites the version of every policy
    # object the group depends on, so a bump means "re-evaluate and possibly
    # re-advertise the table to every peer in this group". It must therefore
    # move on every real change -- and, just as importantly, must not move
    # when nothing changed, which is why PolicyStore compares configuration
    # before it touches a list at all rather than reloading it blindly.

    def add(self, seq, action, prefix, le=0, ge=0):
        """Add or replace one entry.

        A duplicate ``seq`` replaces the entry that held it, which is what
        re-issuing a line with the same sequence number does on a router.
        The replacement is unfiled from the index before the new entry is
        filed, so an entry whose prefix changed does not stay reachable
        under its old one.

        :param seq: sequence number, 0 to 4294967295.
        :param action: ``'permit'``, ``'deny'``, or the matching int.
        :param prefix: a :class:`Prefix` or its text form; its family must
            be the list's.
        :param le: inclusive upper length bound, 0 for unset.
        :param ge: inclusive lower length bound, 0 for unset.
        :return: the :class:`PrefixListEntry` that was stored.
        :raises ValueError: anything :class:`PrefixListEntry` rejects, or a
            prefix from the wrong address family.
        """
        cdef PrefixListEntry entry = PrefixListEntry(seq, action, prefix,
                                                     le, ge)
        cdef Py_ssize_t index

        if entry.prefix.afi != self.afi:
            raise ValueError('%s is not in the address family of prefix-list '
                             '%s' % (entry.prefix.to_str(), self.name))

        index = self._index_of(entry.seq)
        if index >= 0:
            self._unfile(<PrefixListEntry>self._entries[index])
            self._entries[index] = entry
        else:
            # _index_of returns the encoded insertion point for a miss, so
            # the list stays sorted by seq with one insert and no sort.
            self._entries.insert(-1 - index, entry)
        self._file(entry)
        self.version += 1
        return entry

    def remove(self, seq):
        """Remove the entry with a sequence number.

        :param seq: the sequence number.
        :return: True if an entry was removed, False if none held that seq.
            A removal of something absent is not an error: it is what
            applying a configuration diff twice looks like.
        :raises ValueError: a seq that is not an integer in range.
        """
        cdef Py_ssize_t index = self._index_of(_coerce_seq(seq))

        if index < 0:
            return False
        self._unfile(<PrefixListEntry>self._entries[index])
        del self._entries[index]
        self.version += 1
        return True

    def clear(self):
        """Drop every entry, keeping the object's identity and version line.

        This is how :class:`~..store.PolicyStore` reloads a list whose
        configuration changed. Replacing the object instead would be
        simpler and wrong twice over: every peer and update group holding a
        reference would keep filtering against the old contents, and the
        fresh object's ``version`` would start again from 0 -- so a list
        that went from one entry to a different single entry would come back
        with the same version it had before, and every update-group key
        citing it would conclude that nothing had changed.

        :return: the number of entries removed.
        """
        cdef Py_ssize_t removed = len(self._entries)

        self._entries = []
        # A fresh trie rather than a per-entry unfile: the old one releases
        # every node and every entry list in its deallocator, which is one
        # pass instead of a descent per entry.
        self.trie = _Trie(self.afi)
        if removed:
            self.version += 1
        return removed

    cdef int _file(self, PrefixListEntry entry) except -1:
        """Index one entry under its prefix, ordered by seq within the node.

        The per-node list is kept sorted so that the evaluation descent can
        stop at the first entry in a node whose window admits the candidate:
        it is then the lowest-seq match that node can offer.
        """
        cdef list bucket = <list>self.trie.get(entry.prefix)
        cdef Py_ssize_t i
        cdef PrefixListEntry other

        if bucket is None:
            self.trie.insert(entry.prefix, [entry])
            return 0
        for i in range(len(bucket)):
            other = <PrefixListEntry>bucket[i]
            if other.seq > entry.seq:
                bucket.insert(i, entry)
                return 0
        bucket.append(entry)
        return 0

    cdef int _unfile(self, PrefixListEntry entry) except -1:
        """Remove one entry from the index, dropping an emptied node.

        Dropping the node is what keeps a list that is rebuilt on every
        configuration change from growing the trie forever: the node itself
        is small, but it holds a reference to the entry list, and a node
        that is never removed is a node whose entries are never released.
        """
        cdef list bucket = <list>self.trie.get(entry.prefix)
        cdef Py_ssize_t i

        if bucket is None:
            return 0
        for i in range(len(bucket)):
            # Identity, not equality: two entries can be equal in every
            # configured field and still be distinct rows.
            if <PrefixListEntry>bucket[i] is entry:
                del bucket[i]
                break
        if not bucket:
            self.trie.remove(entry.prefix)
        return 0

    cdef Py_ssize_t _index_of(self, uint32_t seq):
        """Binary search ``_entries`` by seq.

        :return: the index of the entry holding ``seq``, or the encoded
            insertion point ``-1 - i`` when no entry does -- the same
            convention ``bisect`` would give, in one pass and without
            building a key list.
        """
        cdef Py_ssize_t lo = 0
        cdef Py_ssize_t hi = len(self._entries)
        cdef Py_ssize_t mid
        cdef PrefixListEntry entry

        while lo < hi:
            mid = (lo + hi) >> 1
            entry = <PrefixListEntry>self._entries[mid]
            if entry.seq == seq:
                return mid
            if entry.seq < seq:
                lo = mid + 1
            else:
                hi = mid
        return -1 - lo

    # --- evaluation --------------------------------------------------------

    cdef PrefixListEntry _lookup(self, Prefix p):
        """Return the lowest-seq entry matching ``p``, or None.

        One descent from the root towards ``p``, visiting exactly the nodes
        whose prefixes cover it. Every node on that path is a candidate and
        none off it can be: a matching entry's prefix always covers the
        candidate (see the module docstring), and a trie node that does not
        cover ``p`` has no descendant that does.

        The walk cannot stop at the first match. The entries it passes are
        ordered by prefix length, not by sequence number, so a shorter entry
        visited earlier may hold a higher seq than a longer one visited
        later -- which is exactly the overlapping-entry case an operator
        writes on purpose. It runs to the end of the path and keeps the
        lowest seq it saw; the path is at most 32 or 128 nodes and in
        practice three or four.
        """
        cdef TrieNode *n = self.trie.root
        cdef unsigned char plen = p.plen
        cdef PrefixListEntry best = None
        cdef PrefixListEntry entry
        cdef list bucket

        while n != NULL and n.plen <= plen:
            if not pfx_match(&n.addr[0], n.plen, &p.addr[0]):
                break
            if n.is_real:
                bucket = <list>trie_node_value(n)
                for entry in bucket:
                    if entry.lo <= plen and plen <= entry.hi:
                        if best is None or entry.seq < best.seq:
                            best = entry
                        # The node's entries are seq-ordered, so no later
                        # entry in this node can beat this one.
                        break
            if n.plen == plen:
                break
            # A node at length p branches on bit p of the key; path
            # compression means the child may be much longer, which is why
            # its own prefix is re-checked at the top of the loop.
            n = n.child[pfx_bit(&p.addr[0], n.plen)]
        return best

    cpdef int evaluate(self, object prefix) except -2:
        """Decide what this list says about one prefix.

        :param prefix: the candidate :class:`Prefix`.
        :return: :data:`ACTION_PERMIT`, :data:`ACTION_DENY`, or
            :data:`NO_MATCH` (-1) when no entry matched. The caller must
            treat no-match as a deny; it is distinct so that show and debug
            output can say which of the two happened.
        :raises ValueError: ``prefix`` is not a :class:`Prefix`. A prefix of
            the *wrong family* is not an error and reports no-match, which
            is what lets a route-map carrying an ``ip address prefix-list``
            clause be applied to an IPv6 prefix without the caller having to
            branch on the family first.
        """
        cdef Prefix p
        cdef PrefixListEntry entry

        if not isinstance(prefix, _Prefix):
            raise ValueError('a Prefix is required, not %s'
                             % type(prefix).__name__)
        p = <Prefix>prefix
        self.hits += 1
        # The literal rather than the module-level NO_MATCH: this is a C int
        # return, and naming the Python constant here would box and unbox an
        # integer on a path that runs once per prefix per peer.
        if p.afi != self.afi:
            return -1
        entry = self._lookup(p)
        if entry is None:
            return -1
        entry.hits += 1
        self.matches += 1
        return entry.action

    cpdef bint permits(self, object prefix) except -1:
        """Return whether this list permits a prefix.

        The convenience form for the common caller, which does not care why
        a prefix was rejected. Counted identically to :meth:`evaluate`,
        because it is one.

        :param prefix: the candidate :class:`Prefix`.
        :return: True only for an explicit permit; both deny and no-match
            are False.
        :raises ValueError: ``prefix`` is not a :class:`Prefix`.
        """
        return self.evaluate(prefix) == PL_ACTION_PERMIT

    # --- views -------------------------------------------------------------

    cpdef list entries(self):
        """Return every entry in ascending ``seq`` order.

        :return: a new list of :class:`PrefixListEntry`; the entries
            themselves are the live ones, so their hit counters keep moving.
        """
        return list(self._entries)

    cpdef dict as_dict(self):
        """Render the list for ``show ip prefix-list``.

        ``hits`` counts evaluations and ``matches`` counts the subset of
        them that found an entry, so ``hits - matches`` is how often the
        implicit deny fired -- the number an operator wants when a filter is
        dropping more than it should. ``matches`` is also the sum of the
        per-entry counters.

        :return: a dict of plain types.
        """
        return {
            'name': self.name,
            'afi': self.afi,
            'version': self.version,
            'entries': [e.as_dict() for e in self._entries],
            'hits': self.hits,
            'matches': self.matches,
        }
