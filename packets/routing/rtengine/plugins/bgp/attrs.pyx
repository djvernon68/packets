# cython: language_level=3

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Canonical BGP path attributes, and the table that interns them.

A full Internet table is about a million paths. Stored naively -- one
attribute object per path -- the attributes alone dominate the engine's
memory, and every best-path comparison re-reads bytes it has already read a
thousand times for the same neighbour. But those million paths carry only
tens of thousands of *distinct* attribute sets: everything learned from one
peer through one upstream shares an AS_PATH, an ORIGIN, a next hop and a
community list. FRR exploits this with its ``attrhash``; so does this
module, and it is the single reason the bytes-per-path budget in the plan is
achievable at all.

Interning only works if equal-meaning sets are byte-equal, so the decoder
never stores what it received. It stores a canonical form:

* AS_PATH is always 4-byte ASNs with AS4_PATH already merged, so a 2-octet
  session and a 4-octet session describing the same path agree;
* communities, extended communities and large communities are sorted,
  because their order is not information;
* CLUSTER_LIST is left alone, because its order *is* information;
* unknown optional-transitive attributes are preserved and sorted by type,
  because RFC 4271 requires them to survive re-advertisement.

Two derived numbers -- the AS-path length and the leftmost (neighbouring)
AS -- are computed once here rather than in the comparator. Best-path
compares paths pairwise across every destination in the table; a segment
walk inside that loop would be a parse per comparison, which is exactly the
cost interning exists to avoid paying twice.

Nothing in this module raises on odd input. It is downstream of the codec,
which has already applied the RFC 7606 matrix; a length that does not divide
evenly is truncated to whole records rather than rejected, because by this
point the alternative is losing a session over bytes that were already
accepted.
"""

from libc.stdint cimport uint16_t, uint32_t
from libc.string cimport memcmp

from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_GET_SIZE

# No cimport of attrs.pxd here: Cython applies a .pxd to the .pyx of the same
# name automatically, and cimporting yourself is an error rather than a
# no-op. Every name declared there -- the enums, the class layouts and the
# module-level cdef functions -- is already in scope.


# Python-visible mirrors of the .pxd constants. A cdef enum is a C constant
# and is invisible from Python, so without these no test could name
# ORIGIN_IGP and no show producer could label one. Same pattern as
# rib/prefix.pyx re-exporting AFI_IP.
ORIGIN_IGP_V = ORIGIN_IGP
ORIGIN_EGP_V = ORIGIN_EGP
ORIGIN_INCOMPLETE_V = ORIGIN_INCOMPLETE
SEG_AS_SET = AS_SET
SEG_AS_SEQUENCE = AS_SEQUENCE
SEG_AS_CONFED_SEQUENCE = AS_CONFED_SEQUENCE
SEG_AS_CONFED_SET = AS_CONFED_SET
AS_TRANS_V = AS_TRANS

HAS_MED = ATTRF_MED
HAS_LOCAL_PREF = ATTRF_LOCAL_PREF
HAS_ATOMIC_AGGREGATE = ATTRF_ATOMIC_AGGREGATE
HAS_ORIGINATOR_ID = ATTRF_ORIGINATOR_ID
IS_INTERNED = ATTRF_INTERNED

ORIGIN_NAMES = {ORIGIN_IGP: 'igp', ORIGIN_EGP: 'egp',
                ORIGIN_INCOMPLETE: 'incomplete'}

# The one-character ORIGIN code `show ip bgp` prints in its last column.
ORIGIN_CODES = {ORIGIN_IGP: 'i', ORIGIN_EGP: 'e', ORIGIN_INCOMPLETE: '?'}

SEGMENT_NAMES = {AS_SET: 'as-set', AS_SEQUENCE: 'as-sequence',
                 AS_CONFED_SEQUENCE: 'confed-sequence',
                 AS_CONFED_SET: 'confed-set'}


cdef inline uint32_t _rd32(const unsigned char *p) nogil:
    """Read a 32-bit network-order word from already-validated memory."""
    return ((<uint32_t>p[0] << 24) | (<uint32_t>p[1] << 16) |
            (<uint32_t>p[2] << 8) | <uint32_t>p[3])


cdef bytes _sort_groups(bytes v, Py_ssize_t width):
    """Sort a byte string as a sequence of fixed-width records.

    Communities are unordered sets that the wire happens to serialise as a
    list. Two peers advertising ``65000:1 65000:2`` and ``65000:2 65000:1``
    mean the same thing, and if the two forms hashed differently they would
    intern as two attribute sets and double the memory for no reason.

    Network-order fixed-width records compare bytewise in the same order
    they compare numerically, so a plain sort of the slices is also a
    numeric sort and no unpacking is needed.

    A trailing partial record is dropped rather than padded: it cannot be
    interpreted, it came through a decoder that already recorded the fault,
    and keeping it would make an attribute set that can never be re-encoded
    faithfully.

    :param v: the packed records.
    :param width: bytes per record.
    :return: the records, sorted and re-concatenated.
    """
    cdef Py_ssize_t n = len(v)
    cdef Py_ssize_t count = n // width
    cdef list groups
    cdef Py_ssize_t i
    cdef const unsigned char *p

    if count < 2:
        # 0 or 1 whole records: nothing to order. Still truncate, so the
        # "whole records only" invariant holds for every stored value.
        return v[:count * width]
    # Exporters almost always send communities already in order, and a
    # strictly ascending run is its own sorted, deduplicated form. Checking
    # that in place costs one memcmp per record, against a slice, a set, a
    # list and a join for the general case below.
    if n == count * width:
        p = <const unsigned char*>PyBytes_AS_STRING(v)
        i = 1
        while i < count and memcmp(p + (i - 1) * width, p + i * width,
                                   width) < 0:
            i += 1
        if i == count:
            return v
    # W-7: deduplicated as well as sorted. A community list is a set, so
    # `A B A` and `A B` mean the same thing; sorted but not deduplicated,
    # they interned as two attribute sets, and re-advertising either
    # repeated the duplicate. FRR's canonical form drops it too.
    groups = sorted(set([v[i * width:(i + 1) * width]
                         for i in range(count)]))
    return b''.join(groups)


cdef bytes _sort_unknown(bytes v):
    """Order preserved unknown attributes by type code.

    The run is a sequence of complete on-wire TLVs, exactly as the decoder
    saw them, including the flags byte -- which must be kept because the
    partial bit has to be set on re-advertisement and the extended-length
    bit tells the re-encoder how wide the length field was.

    Ordering them by type makes the canonical form independent of the order
    the sender happened to use, which is the same interning argument as the
    communities above. Parsing stops at the first TLV that does not fit and
    keeps what came before, because a truncated tail cannot be re-emitted.

    :param v: concatenated attribute TLVs.
    :return: the same TLVs, ordered by type code.
    """
    cdef Py_ssize_t n = len(v)
    cdef Py_ssize_t o = 0
    cdef Py_ssize_t vlen, hdr
    cdef unsigned char flags, atype
    cdef list tlvs = []
    cdef const unsigned char *p

    if n == 0:
        return v
    p = <const unsigned char*>PyBytes_AS_STRING(v)
    while o + 3 <= n:
        flags = p[o]
        atype = p[o + 1]
        if flags & 0x10:
            # Extended length: a two-byte length field, so the header is
            # four bytes rather than three.
            if o + 4 > n:
                break
            vlen = (<Py_ssize_t>p[o + 2] << 8) | <Py_ssize_t>p[o + 3]
            hdr = 4
        else:
            vlen = <Py_ssize_t>p[o + 2]
            hdr = 3
        if o + hdr + vlen > n:
            break
        tlvs.append((atype, v[o:o + hdr + vlen]))
        o += hdr + vlen
    if len(tlvs) < 2:
        return b''.join([t[1] for t in tlvs])
    tlvs.sort()
    return b''.join([t[1] for t in tlvs])


cdef int _walk_as_path(bytes path, uint32_t *length,
                       uint32_t *neighbor) except -1:
    """Derive the AS-path length and the neighbouring AS in one pass.

    Two rules that are easy to get wrong and are both load-bearing:

    * an AS_SET counts as **1** no matter how many ASNs it holds (RFC 4271
      s9.1.2.2), because it represents an aggregate whose real length is
      unknown, and counting its members would make aggregation look worse
      than the routes it replaced;
    * confederation segments count as **0** (RFC 5065), because they are
      internal to the confederation and invisible to the outside -- a
      confederation that counted its own hops would lose to an external
      path that is genuinely longer.

    The neighbouring AS is the leftmost AS of the first segment that is not
    a confederation segment, which is the MED grouping key: MED is only
    comparable between paths learned from the same neighbouring AS, so
    grouping by the wrong value silently makes MED comparisons meaningless.
    An AS_SET in leading position has no single leftmost AS; its first
    member is used, which is what every implementation does in practice.

    :param path: canonical 4-byte-ASN AS_PATH.
    :param length: out, the comparison length.
    :param neighbor: out, the neighbouring AS, or 0 for an empty path.
    :return: 0.
    """
    cdef Py_ssize_t n = PyBytes_GET_SIZE(path)
    cdef Py_ssize_t o = 0
    cdef const unsigned char *p
    cdef unsigned char seg_type, count
    cdef uint32_t total = 0
    cdef uint32_t nbr = 0
    cdef bint have_nbr = 0

    length[0] = 0
    neighbor[0] = 0
    if n == 0:
        return 0
    p = <const unsigned char*>PyBytes_AS_STRING(path)
    while o + 2 <= n:
        seg_type = p[o]
        count = p[o + 1]
        o += 2
        if o + (<Py_ssize_t>count * 4) > n:
            break
        if seg_type == AS_SEQUENCE:
            total += count
            if not have_nbr and count:
                nbr = _rd32(p + o)
                have_nbr = 1
        elif seg_type == AS_SET:
            total += 1
            if not have_nbr and count:
                nbr = _rd32(p + o)
                have_nbr = 1
        # AS_CONFED_SEQUENCE and AS_CONFED_SET add nothing to the length and
        # do not name the neighbouring AS: the next external segment does.
        o += <Py_ssize_t>count * 4
    length[0] = total
    neighbor[0] = nbr
    return 0


cdef long _hash_bytes(long h, bytes v):
    """Fold a byte string into an FNV-1a accumulator."""
    cdef Py_ssize_t n = PyBytes_GET_SIZE(v)
    cdef const unsigned char *p
    cdef Py_ssize_t i = 0
    cdef unsigned long acc = <unsigned long>h

    if n:
        p = <const unsigned char*>PyBytes_AS_STRING(v)
        while i < n:
            acc = (acc ^ p[i]) * 16777619UL
            i += 1
    # Length is folded in as well so that concatenating two fields cannot
    # collide with a different split of the same bytes.
    acc = (acc ^ <unsigned long>n) * 16777619UL
    return <long>acc


cdef long _hash_u32(long h, uint32_t v):
    """Fold a 32-bit value into an FNV-1a accumulator."""
    cdef unsigned long acc = <unsigned long>h
    acc = (acc ^ (v & 0xff)) * 16777619UL
    acc = (acc ^ ((v >> 8) & 0xff)) * 16777619UL
    acc = (acc ^ ((v >> 16) & 0xff)) * 16777619UL
    acc = (acc ^ ((v >> 24) & 0xff)) * 16777619UL
    return <long>acc


cdef class AttrSet:
    """An immutable, canonical BGP path attribute set.

    Construct one either through the keyword form below -- which is what
    local origination, policy and tests use -- or, inside Cython, through
    :c:func:`attrs_blank` and :c:func:`attrs_finalize`, which is what the
    decoder uses to avoid marshalling fourteen keyword arguments per UPDATE.

    :param origin: ORIGIN code; IGP, EGP or INCOMPLETE.
    :param as_path: canonical AS_PATH bytes (4-byte ASNs).
    :param nexthop: 4 or 16 next-hop bytes, or empty.
    :param nexthop_local: 16 link-local next-hop bytes, or empty.
    :param med: MULTI_EXIT_DISC; ignored unless ``has_med``.
    :param local_pref: LOCAL_PREF; ignored unless ``has_local_pref``.
    :param has_med: whether MED is present.
    :param has_local_pref: whether LOCAL_PREF is present.
    :param atomic_aggregate: whether ATOMIC_AGGREGATE is present.
    :param communities: packed 4-byte communities.
    :param ext_communities: packed 8-byte extended communities.
    :param large_communities: packed 12-byte large communities.
    :param originator_id: ORIGINATOR_ID; ignored unless ``has_originator``.
    :param has_originator: whether ORIGINATOR_ID is present.
    :param cluster_list: packed 4-byte cluster ids, order preserved.
    :param aggregator: 8-byte AGGREGATOR (4-byte AS + id), or empty.
    :param unknown: preserved unknown-transitive attribute TLVs.
    """

    def __init__(self, unsigned char origin=ORIGIN_IGP, bytes as_path=b'',
                 bytes nexthop=b'', bytes nexthop_local=b'',
                 uint32_t med=0, uint32_t local_pref=0,
                 bint has_med=False, bint has_local_pref=False,
                 bint atomic_aggregate=False,
                 bytes communities=b'', bytes ext_communities=b'',
                 bytes large_communities=b'',
                 uint32_t originator_id=0, bint has_originator=False,
                 bytes cluster_list=b'', bytes aggregator=b'',
                 bytes unknown=b''):
        self.origin = origin
        self.as_path = as_path
        self.nexthop = nexthop
        self.nexthop_local = nexthop_local
        self.med = med
        self.local_pref = local_pref
        self.communities = communities
        self.ext_communities = ext_communities
        self.large_communities = large_communities
        self.originator_id = originator_id
        self.cluster_list = cluster_list
        self.aggregator = aggregator
        self.unknown = unknown
        self.flags = 0
        if has_med:
            self.flags |= ATTRF_MED
        if has_local_pref:
            self.flags |= ATTRF_LOCAL_PREF
        if atomic_aggregate:
            self.flags |= ATTRF_ATOMIC_AGGREGATE
        if has_originator:
            self.flags |= ATTRF_ORIGINATOR_ID
        self.refs = 0
        attrs_finalize(self)

    # --- accessors ---------------------------------------------------------

    cpdef bint has_med(self):
        """Return whether MULTI_EXIT_DISC is present.

        :return: True when the attribute was carried, even if its value is
            zero -- absent and zero are different for both comparison and
            re-advertisement.
        """
        return (self.flags & ATTRF_MED) != 0

    cpdef bint has_local_pref(self):
        """Return whether LOCAL_PREF is present."""
        return (self.flags & ATTRF_LOCAL_PREF) != 0

    @property
    def atomic_aggregate(self):
        """Whether ATOMIC_AGGREGATE is present."""
        return (self.flags & ATTRF_ATOMIC_AGGREGATE) != 0

    @property
    def has_originator_id(self):
        """Whether ORIGINATOR_ID is present."""
        return (self.flags & ATTRF_ORIGINATOR_ID) != 0

    @property
    def interned(self):
        """Whether this instance is the shared canonical one."""
        return (self.flags & ATTRF_INTERNED) != 0

    @property
    def refcount(self):
        """How many paths currently claim this set."""
        return self.refs

    cpdef list as_path_list(self):
        """Decode the AS_PATH into segments.

        :return: a list of ``(seg_type, [asn, ...])``, in wire order. A
            truncated trailing segment is dropped.
        """
        cdef Py_ssize_t n = PyBytes_GET_SIZE(self.as_path)
        cdef Py_ssize_t o = 0
        cdef Py_ssize_t i
        cdef const unsigned char *p
        cdef unsigned char seg_type, count
        cdef list out = []
        cdef list asns

        if n == 0:
            return out
        p = <const unsigned char*>PyBytes_AS_STRING(self.as_path)
        while o + 2 <= n:
            seg_type = p[o]
            count = p[o + 1]
            o += 2
            if o + (<Py_ssize_t>count * 4) > n:
                break
            asns = []
            for i in range(count):
                asns.append(_rd32(p + o + i * 4))
            out.append((seg_type, asns))
            o += <Py_ssize_t>count * 4
        return out

    cpdef str as_path_str(self):
        """Render the AS_PATH the way IOS and FRR print it.

        Sequences are bare, sets are braced, confederation segments are
        parenthesised and bracketed. This string is also what the Stage-4
        as-path regex policy matches against, so its shape is a contract,
        not just presentation.

        :return: e.g. ``'65001 65002 {65003,65004}'``; empty for an empty
            path.
        """
        cdef list parts = []
        cdef list asns

        for seg_type, asns in self.as_path_list():
            text = ' '.join([str(a) for a in asns])
            if seg_type == AS_SET:
                parts.append('{%s}' % ','.join([str(a) for a in asns]))
            elif seg_type == AS_CONFED_SEQUENCE:
                parts.append('(%s)' % text)
            elif seg_type == AS_CONFED_SET:
                parts.append('[%s]' % ','.join([str(a) for a in asns]))
            else:
                if text:
                    parts.append(text)
        return ' '.join(parts)

    cpdef bint has_as(self, uint32_t asn):
        """Return whether an AS appears anywhere in the AS_PATH.

        This is BGP's loop detection: a path whose AS_PATH already contains
        our own AS came back to us and must be rejected. Confederation
        segments are searched too, because a confederation member's own AS
        appearing in a confed segment is just as much a loop.

        AS_TRANS never matches, even if it is the value asked for -- it is
        a placeholder for an AS that could not be represented, not an AS.

        :param asn: the AS to look for.
        :return: True if present.
        """
        cdef Py_ssize_t n = PyBytes_GET_SIZE(self.as_path)
        cdef Py_ssize_t o = 0
        cdef Py_ssize_t i
        cdef const unsigned char *p
        cdef unsigned char count

        if n == 0 or asn == AS_TRANS:
            return False
        p = <const unsigned char*>PyBytes_AS_STRING(self.as_path)
        while o + 2 <= n:
            count = p[o + 1]
            o += 2
            if o + (<Py_ssize_t>count * 4) > n:
                break
            for i in range(count):
                if _rd32(p + o + i * 4) == asn:
                    return True
            o += <Py_ssize_t>count * 4
        return False

    cpdef list community_list(self):
        """Decode COMMUNITIES into integers.

        :return: a sorted list of 32-bit community values.
        """
        cdef Py_ssize_t n = PyBytes_GET_SIZE(self.communities)
        cdef Py_ssize_t i
        cdef const unsigned char *p
        cdef list out = []

        if n < 4:
            return out
        p = <const unsigned char*>PyBytes_AS_STRING(self.communities)
        for i in range(n // 4):
            out.append(_rd32(p + i * 4))
        return out

    cpdef list cluster_ids(self):
        """Decode CLUSTER_LIST into integers, in wire order.

        :return: a list of 32-bit cluster ids; order is significant.
        """
        cdef Py_ssize_t n = PyBytes_GET_SIZE(self.cluster_list)
        cdef Py_ssize_t i
        cdef const unsigned char *p
        cdef list out = []

        if n < 4:
            return out
        p = <const unsigned char*>PyBytes_AS_STRING(self.cluster_list)
        for i in range(n // 4):
            out.append(_rd32(p + i * 4))
        return out

    cpdef dict as_dict(self):
        """Render for ``show`` output and events.

        Absent attributes are omitted rather than rendered as zero, so a
        reader can tell "no MED" from "MED 0" -- the same distinction the
        presence flags exist to keep.

        :return: a dict of plain types.
        """
        cdef dict out = {
            'origin': ORIGIN_NAMES.get(self.origin, self.origin),
            'as-path': self.as_path_str(),
            'as-path-length': self.as_path_len,
        }
        if self.neighbor_as:
            out['neighbor-as'] = self.neighbor_as
        if self.nexthop:
            out['next-hop'] = _addr_str(self.nexthop)
        if self.nexthop_local:
            out['next-hop-local'] = _addr_str(self.nexthop_local)
        if self.flags & ATTRF_MED:
            out['med'] = self.med
        if self.flags & ATTRF_LOCAL_PREF:
            out['local-preference'] = self.local_pref
        if self.flags & ATTRF_ATOMIC_AGGREGATE:
            out['atomic-aggregate'] = True
        if self.aggregator:
            out['aggregator'] = _aggregator_str(self.aggregator)
        if self.communities:
            out['communities'] = [_community_str(c)
                                  for c in self.community_list()]
        if self.ext_communities:
            out['extended-communities'] = _hex_groups(self.ext_communities, 8)
        if self.large_communities:
            out['large-communities'] = _large_list(self.large_communities)
        if self.flags & ATTRF_ORIGINATOR_ID:
            out['originator-id'] = _ipv4_str(self.originator_id)
        if self.cluster_list:
            out['cluster-list'] = [_ipv4_str(c) for c in self.cluster_ids()]
        if self.unknown:
            out['unknown-attributes'] = _unknown_types(self.unknown)
        return out

    # --- identity ----------------------------------------------------------

    def __hash__(self):
        return self._hash

    def __richcmp__(AttrSet self, other, int op):
        # Cython 0.28 has no __eq__ on cdef classes; __richcmp__ is the only
        # spelling that works on both the 0.28 floor and 0.29+.
        cdef int c
        if not isinstance(other, AttrSet):
            if op == 2:
                return False
            if op == 3:
                return True
            return NotImplemented
        c = attrs_cmp(self, <AttrSet>other)
        if op == 0:
            return c < 0
        if op == 1:
            return c <= 0
        if op == 2:
            return c == 0
        if op == 3:
            return c != 0
        if op == 4:
            return c > 0
        return c >= 0

    def __repr__(self):
        return '<AttrSet %s nh=%s len=%d refs=%d>' % (
            ORIGIN_CODES.get(self.origin, '?'),
            _addr_str(self.nexthop) if self.nexthop else '-',
            self.as_path_len, self.refs)


# --- rendering helpers ------------------------------------------------------
# Kept module-private and plain: these are show-path only, run once per
# displayed route rather than once per received one, so clarity beats speed.

cdef str _ipv4_str(uint32_t v):
    return '%d.%d.%d.%d' % ((v >> 24) & 0xff, (v >> 16) & 0xff,
                            (v >> 8) & 0xff, v & 0xff)


cdef str _addr_str(bytes a):
    """Render 4 raw bytes as dotted quad, 16 as an RFC 5952 IPv6 string."""
    cdef Py_ssize_t n = len(a)
    cdef list parts
    cdef Py_ssize_t i

    if n == 4:
        return '%d.%d.%d.%d' % (a[0], a[1], a[2], a[3])
    if n == 16:
        # socket.inet_ntop is not importable under nogil and this is not a
        # hot path, so the compression is done directly.
        parts = []
        for i in range(8):
            parts.append('%x' % ((a[i * 2] << 8) | a[i * 2 + 1]))
        return _compress_v6(parts)
    return a.hex() if n else ''


cdef str _compress_v6(list parts):
    """Apply the RFC 5952 longest-run-of-zeros rule to eight hextets."""
    cdef Py_ssize_t best_start = -1, best_len = 0
    cdef Py_ssize_t cur_start = -1, cur_len = 0
    cdef Py_ssize_t i

    for i in range(8):
        if parts[i] == '0':
            if cur_start < 0:
                cur_start = i
                cur_len = 0
            cur_len += 1
            if cur_len > best_len:
                best_len = cur_len
                best_start = cur_start
        else:
            cur_start = -1
            cur_len = 0
    if best_len < 2:
        return ':'.join(parts)
    head = ':'.join(parts[:best_start])
    tail = ':'.join(parts[best_start + best_len:])
    return '%s::%s' % (head, tail)


cdef str _community_str(uint32_t c):
    """Render a community as ``asn:value``, naming the well-known ones."""
    if c == 0xffffff01:
        return 'no-export'
    if c == 0xffffff02:
        return 'no-advertise'
    if c == 0xffffff03:
        return 'local-AS'
    if c == 0xffffff04:
        return 'no-peer'
    return '%d:%d' % ((c >> 16) & 0xffff, c & 0xffff)


cdef str _aggregator_str(bytes v):
    cdef const unsigned char *p
    if len(v) != 8:
        return v.hex()
    p = <const unsigned char*>PyBytes_AS_STRING(v)
    return '%d %s' % (_rd32(p), _ipv4_str(_rd32(p + 4)))


cdef list _hex_groups(bytes v, Py_ssize_t width):
    cdef Py_ssize_t i
    return [v[i * width:(i + 1) * width].hex()
            for i in range(len(v) // width)]


cdef list _large_list(bytes v):
    """Render large communities as ``global:local1:local2`` (RFC 8092)."""
    cdef const unsigned char *p
    cdef Py_ssize_t i
    cdef list out = []

    if len(v) < 12:
        return out
    p = <const unsigned char*>PyBytes_AS_STRING(v)
    for i in range(len(v) // 12):
        out.append('%d:%d:%d' % (_rd32(p + i * 12), _rd32(p + i * 12 + 4),
                                 _rd32(p + i * 12 + 8)))
    return out


cdef list _unknown_types(bytes v):
    """List the type codes of the preserved unknown attributes."""
    cdef Py_ssize_t n = len(v)
    cdef Py_ssize_t o = 0, vlen, hdr
    cdef const unsigned char *p
    cdef list out = []

    if n == 0:
        return out
    p = <const unsigned char*>PyBytes_AS_STRING(v)
    while o + 3 <= n:
        if p[o] & 0x10:
            if o + 4 > n:
                break
            vlen = (<Py_ssize_t>p[o + 2] << 8) | <Py_ssize_t>p[o + 3]
            hdr = 4
        else:
            vlen = <Py_ssize_t>p[o + 2]
            hdr = 3
        if o + hdr + vlen > n:
            break
        out.append(p[o + 1])
        o += hdr + vlen
    return out


# --- construction -----------------------------------------------------------

cdef AttrSet attrs_blank():
    """Allocate an AttrSet with every field at its empty default.

    ``__new__`` rather than ``__init__`` so the decoder pays for no keyword
    marshalling; the bytes fields are set to ``b''`` explicitly because a
    cdef object field starts as None and None would crash the hash.

    :return: an unfinalised AttrSet.
    """
    cdef AttrSet a = AttrSet.__new__(AttrSet)
    a.origin = ORIGIN_IGP
    a.flags = 0
    a.as_path = b''
    a.nexthop = b''
    a.nexthop_local = b''
    a.med = 0
    a.local_pref = 0
    a.communities = b''
    a.ext_communities = b''
    a.large_communities = b''
    a.originator_id = 0
    a.cluster_list = b''
    a.aggregator = b''
    a.unknown = b''
    a.as_path_len = 0
    a.neighbor_as = 0
    a.cluster_len = 0
    a._hash = 0
    a.refs = 0
    return a


cdef AttrSet attrs_finalize(AttrSet a):
    """Canonicalise, derive the cached fields and compute the hash.

    Must run exactly once, after the last field is written. Everything that
    makes two equal-meaning sets compare equal happens here, so an AttrSet
    that skipped it will fail to intern against its own duplicate and will
    quietly double the table's memory.

    :param a: the set to finalise, modified in place.
    :return: ``a``, so a decoder can finish with ``return attrs_finalize(a)``.
    """
    cdef long h
    cdef uint32_t length = 0
    cdef uint32_t neighbor = 0

    a.communities = _sort_groups(a.communities, 4)
    a.ext_communities = _sort_groups(a.ext_communities, 8)
    a.large_communities = _sort_groups(a.large_communities, 12)
    a.unknown = _sort_unknown(a.unknown)
    # Cluster list is length-checked but never reordered: it records the
    # route reflectors a path has traversed, in order, and is also the
    # reflection loop check.
    a.cluster_list = a.cluster_list[:(len(a.cluster_list) // 4) * 4]
    a.cluster_len = <uint16_t>(len(a.cluster_list) // 4)

    _walk_as_path(a.as_path, &length, &neighbor)
    a.as_path_len = length
    a.neighbor_as = neighbor

    h = <long>2166136261UL
    h = _hash_u32(h, a.origin)
    # Only the presence bits participate: ATTRF_INTERNED is bookkeeping and
    # would make an interned set hash differently from its own lookup key.
    h = _hash_u32(h, a.flags & <unsigned char>(ATTRF_MED |
                                               ATTRF_LOCAL_PREF |
                                               ATTRF_ATOMIC_AGGREGATE |
                                               ATTRF_ORIGINATOR_ID))
    h = _hash_bytes(h, a.as_path)
    h = _hash_bytes(h, a.nexthop)
    h = _hash_bytes(h, a.nexthop_local)
    if a.flags & ATTRF_MED:
        h = _hash_u32(h, a.med)
    if a.flags & ATTRF_LOCAL_PREF:
        h = _hash_u32(h, a.local_pref)
    h = _hash_bytes(h, a.communities)
    h = _hash_bytes(h, a.ext_communities)
    h = _hash_bytes(h, a.large_communities)
    if a.flags & ATTRF_ORIGINATOR_ID:
        h = _hash_u32(h, a.originator_id)
    h = _hash_bytes(h, a.cluster_list)
    h = _hash_bytes(h, a.aggregator)
    h = _hash_bytes(h, a.unknown)
    # -1 is CPython's error sentinel for tp_hash; returning it would make
    # every lookup of a legitimately -1 key re-enter the hash.
    a._hash = h if h != -1 else -2
    return a


cdef inline int _cmp_bytes(bytes x, bytes y):
    """Order two byte strings: shorter first, then memcmp."""
    cdef Py_ssize_t nx = PyBytes_GET_SIZE(x)
    cdef Py_ssize_t ny = PyBytes_GET_SIZE(y)
    cdef int c

    if nx != ny:
        return -1 if nx < ny else 1
    if nx == 0:
        return 0
    c = memcmp(PyBytes_AS_STRING(x), PyBytes_AS_STRING(y), nx)
    if c:
        return -1 if c < 0 else 1
    return 0


cdef int attrs_cmp(AttrSet a, AttrSet b):
    """Total order over attribute sets.

    Equality is what interning needs -- it is the comparison the interning
    dictionary performs on every hash collision -- and the rest of the
    order exists so show output and tests can sort deterministically.

    Fields are compared cheapest-first: the scalars and the presence bits
    before any byte string, and within the byte strings length before
    content, so two sets that differ at all usually differ before a single
    ``memcmp`` runs. The identity test at the top is not an optimisation
    for its own sake either -- after interning, the overwhelmingly common
    case is comparing a set with itself.

    :param a: left operand.
    :param b: right operand.
    :return: negative, zero or positive.
    """
    cdef int c
    cdef unsigned char fa, fb

    if a is b:
        return 0
    # Only the presence bits are ordered, never ATTRF_INTERNED: whether a
    # set happens to be the canonical instance is bookkeeping, and letting
    # it into the comparison would make an interned set unequal to the
    # freshly decoded set it is supposed to match.
    fa = a.flags & <unsigned char>(ATTRF_MED | ATTRF_LOCAL_PREF |
                                   ATTRF_ATOMIC_AGGREGATE |
                                   ATTRF_ORIGINATOR_ID)
    fb = b.flags & <unsigned char>(ATTRF_MED | ATTRF_LOCAL_PREF |
                                   ATTRF_ATOMIC_AGGREGATE |
                                   ATTRF_ORIGINATOR_ID)
    if a.origin != b.origin:
        return -1 if a.origin < b.origin else 1
    if fa != fb:
        return -1 if fa < fb else 1
    c = _cmp_bytes(a.as_path, b.as_path)
    if c:
        return c
    c = _cmp_bytes(a.nexthop, b.nexthop)
    if c:
        return c
    c = _cmp_bytes(a.nexthop_local, b.nexthop_local)
    if c:
        return c
    if (fa & ATTRF_MED) and a.med != b.med:
        return -1 if a.med < b.med else 1
    if (fa & ATTRF_LOCAL_PREF) and a.local_pref != b.local_pref:
        return -1 if a.local_pref < b.local_pref else 1
    c = _cmp_bytes(a.communities, b.communities)
    if c:
        return c
    c = _cmp_bytes(a.ext_communities, b.ext_communities)
    if c:
        return c
    c = _cmp_bytes(a.large_communities, b.large_communities)
    if c:
        return c
    if (fa & ATTRF_ORIGINATOR_ID) and a.originator_id != b.originator_id:
        return -1 if a.originator_id < b.originator_id else 1
    c = _cmp_bytes(a.cluster_list, b.cluster_list)
    if c:
        return c
    c = _cmp_bytes(a.aggregator, b.aggregator)
    if c:
        return c
    return _cmp_bytes(a.unknown, b.unknown)


cdef class AttrTable:
    """Interning table for attribute sets, with explicit refcounting.

    The table is self-keyed: an ``AttrSet`` is both the key and the value,
    so there is no parallel key object to build or to keep in step. A
    lookup costs the cached hash plus, on a hit, one :c:func:`attrs_cmp`.

    Refcounting is explicit rather than left to CPython because the
    question the table needs answered is not "does any Python reference
    exist" but "does any *path* still claim this". A show command holding a
    set alive for the duration of a render must not keep it in the table
    after the last route using it was withdrawn, or a long-lived monitor
    would pin a table that should have shrunk.

    Callers must pair every :meth:`intern` with exactly one :meth:`release`.
    Getting that wrong leaks (too few releases) or produces a table that
    hands out a set it has already forgotten (too many) -- which is why
    ``release`` treats an unknown set as a no-op rather than an error, and
    counts it.
    """

    def __init__(self):
        self._sets = {}
        self.hits = 0
        self.misses = 0
        self.releases = 0

    cpdef AttrSet intern(self, AttrSet a):
        """Return the canonical instance equal to ``a``, claiming a ref.

        :param a: a finalised attribute set.
        :return: the shared instance, which may be ``a`` itself on a miss.
        """
        cdef AttrSet found = self._sets.get(a)

        if found is not None:
            found.refs += 1
            self.hits += 1
            return found
        a.flags |= ATTRF_INTERNED
        a.refs = 1
        self._sets[a] = a
        self.misses += 1
        return a

    cpdef int release(self, AttrSet a) except? -1:
        """Drop one claim on a set, forgetting it when the last one goes.

        :param a: a previously interned set.
        :return: the remaining refcount, or -1 if the set was not held by
            this table -- which is a report, not an error, and is why the
            declaration is ``except? -1`` rather than ``except -1``.
        """
        cdef AttrSet found

        if a is None:
            return -1
        found = self._sets.get(a)
        if found is None or found is not a:
            # Either never interned, or an equal-but-distinct instance the
            # caller built separately. Neither is ours to free.
            return -1
        self.releases += 1
        found.refs -= 1
        if found.refs <= 0:
            del self._sets[a]
            found.flags &= <unsigned char>(~ATTRF_INTERNED)
            found.refs = 0
            return 0
        return found.refs

    cpdef Py_ssize_t count(self):
        """Return how many distinct attribute sets are held."""
        return len(self._sets)

    cpdef dict stats(self):
        """Return interning counters for health output.

        ``hit-rate`` is the number worth watching: on a real feed it should
        be well above 0.9, and a low value means the canonical form is
        failing to collapse something it should.

        :return: a dict of plain types.
        """
        cdef Py_ssize_t total = self.hits + self.misses
        cdef Py_ssize_t refs = 0
        cdef AttrSet a

        for a in self._sets.values():
            refs += a.refs
        return {
            'distinct': len(self._sets),
            'references': refs,
            'hits': self.hits,
            'misses': self.misses,
            'releases': self.releases,
            'hit-rate': round(float(self.hits) / total, 4) if total else 0.0,
        }

    def clear(self):
        """Forget every set. For engine shutdown and for tests."""
        self._sets = {}
        self.hits = 0
        self.misses = 0
        self.releases = 0

    def __len__(self):
        return len(self._sets)

    def __repr__(self):
        return '<AttrTable distinct=%d hits=%d misses=%d>' % (
            len(self._sets), self.hits, self.misses)


def make_as_path(segments):
    """Build canonical AS_PATH bytes from decoded segments.

    The inverse of :meth:`AttrSet.as_path_list`, for local origination,
    policy and tests -- the decoder writes the canonical bytes directly.

    W-3: an AS_SEQUENCE longer than 255 ASNs -- a heavy prepend, or a long
    path with one -- is split into consecutive segments of at most 255,
    which is the same path: AS_SEQUENCE segments in a row are one ordered
    sequence (RFC 4271 s5.1.2), and the path length is unchanged. An
    AS_SET cannot be split that way, because two sets count as two hops
    where one counted as one, so an oversized set still raises.

    :param segments: an iterable of ``(seg_type, [asn, ...])``. A bare list
        of integers is accepted as shorthand for one AS_SEQUENCE.
    :return: canonical 4-byte-ASN AS_PATH bytes.
    :raises ValueError: an AS_SET holds more than 255 ASNs.
    """
    cdef list out = []
    cdef list asns
    cdef list segs = list(segments)
    cdef Py_ssize_t start

    if segs and not isinstance(segs[0], (tuple, list)):
        segs = [(AS_SEQUENCE, segs)]
    for seg_type, asns in segs:
        asns = list(asns)
        if len(asns) > 255 and seg_type != AS_SEQUENCE:
            raise ValueError('AS_SET of %d exceeds the 255 the one-byte '
                             'count can express, and a set cannot be '
                             'split without lengthening the path'
                             % len(asns))
        for start in range(0, max(len(asns), 1), 255):
            chunk = asns[start:start + 255]
            out.append(bytes(bytearray([seg_type, len(chunk)])))
            for asn in chunk:
                out.append(bytes(bytearray([(asn >> 24) & 0xff,
                                            (asn >> 16) & 0xff,
                                            (asn >> 8) & 0xff,
                                            asn & 0xff])))
    return b''.join(out)


def make_communities(values):
    """Pack community integers into canonical sorted bytes.

    :param values: an iterable of 32-bit community values.
    :return: packed, sorted community bytes.
    """
    cdef list out = []

    for v in sorted(set(values)):
        out.append(bytes(bytearray([(v >> 24) & 0xff, (v >> 16) & 0xff,
                                    (v >> 8) & 0xff, v & 0xff])))
    return b''.join(out)
