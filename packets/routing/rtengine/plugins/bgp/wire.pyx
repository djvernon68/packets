# cython: language_level=3

# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The BGP codec: framing, typed decode, and encode into a ``PktWriter``.

This is rtengine's own codec. It deliberately does **not** go through the
``BGP`` dissector in ``packets.core.inetpkt``, even though that dissector
understands the same messages, because the two want opposite things: the
dissector renders every field as text for a human reading one packet, and
this wants typed objects for a machine applying a million prefixes a
second. Measured on the same stream, the shared primitives underneath run
about 35x faster than the text path (see the plan's benchmark table), and
that margin is the entire reason for the split.

What the two *do* share is the byte arithmetic. Every offset computed here
comes from the ``_bgp_*`` primitives in ``inetpkt.pxd`` -- the same
functions the dissector calls -- so there is exactly one implementation of
"where does the next NLRI start" in the repository, and the round-trip
tests cross-check this encoder against that dissector to keep it that way.

Three properties are worth knowing before reading the code.

**Decode is two-phase.** A decoder never touches a RIB. It parses the whole
message, records every fault in ``UpdateMsg.errors``, and returns; the
caller runs the RFC 7606 matrix over those faults and decides between
discarding an attribute, withdrawing the NLRI and resetting the session.
That is what makes an UPDATE apply atomically -- the alternative, applying
as you parse, leaves half an UPDATE in the table when the second half turns
out to be malformed.

**Nothing here raises on bad input.** A malformed message from a peer is an
ordinary event, not an exceptional one. Faults come back in ``errors``
lists and in the framer's latched ``error_code``.

**The session decides how bytes are read.** Whether AS_PATH holds 2- or
4-byte ASNs, whether NLRI carries a path id, and how large a message may be
are all per-session results of capability negotiation, so every decoder
takes a :class:`DecodeCtx` rather than consulting anything global.
"""

from libc.stdint cimport uint16_t, uint32_t, uint64_t
from libc.string cimport memset

from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_GET_SIZE

from packets.core.inetpkt cimport (
    PktWriter, w_acquire, w_release, w_u8, w_u16, w_u32, w_raw, w_bytes,
    w_zeros, w_set_u16, w_take, rd_u16, rd_u32, rd_bytes, _have_range,
    _bgp_msg_header, _bgp_open_fixed, _bgp_cap_next, _bgp_attr_next,
    _bgp_nlri_next, _bgp_mp_reach_hdr, _bgp_mp_unreach_hdr,
    _bgp_aspath_seg_next)
from packets.routing.rtengine.rib.prefix cimport (
    Prefix, pfx_new, pfx_addr_len, pfx_addr_bits, PFX_AFI_IP, PFX_AFI_IP6)
from packets.routing.rtengine.plugins.bgp.attrs cimport (
    AttrSet, attrs_blank, attrs_finalize, ORIGIN_IGP, ORIGIN_INCOMPLETE,
    AS_SET, AS_SEQUENCE, AS_CONFED_SEQUENCE, AS_CONFED_SET, AS_TRANS,
    ATTRF_MED, ATTRF_LOCAL_PREF, ATTRF_ATOMIC_AGGREGATE,
    ATTRF_ORIGINATOR_ID)


# --- Python-visible mirrors -------------------------------------------------
# A cdef enum is a C constant and cannot be named from Python, so the FSM,
# the peer and every test would otherwise have to hard-code these numbers.

OPEN = MSG_OPEN
UPDATE = MSG_UPDATE
NOTIFICATION = MSG_NOTIFICATION
KEEPALIVE = MSG_KEEPALIVE
ROUTE_REFRESH = MSG_ROUTE_REFRESH

VERSION = BGP_VERSION
HEADER_LEN = BGP_HEADER_LEN
MAX_MSG = BGP_MAX_MSG
MAX_MSG_EXT = BGP_MAX_MSG_EXT

MSG_NAMES = {MSG_OPEN: 'OPEN', MSG_UPDATE: 'UPDATE',
             MSG_NOTIFICATION: 'NOTIFICATION', MSG_KEEPALIVE: 'KEEPALIVE',
             MSG_ROUTE_REFRESH: 'ROUTE-REFRESH'}

TYPE_ORIGIN = ATTR_ORIGIN
TYPE_AS_PATH = ATTR_AS_PATH
TYPE_NEXT_HOP = ATTR_NEXT_HOP
TYPE_MED = ATTR_MED
TYPE_LOCAL_PREF = ATTR_LOCAL_PREF
TYPE_ATOMIC_AGGREGATE = ATTR_ATOMIC_AGGREGATE
TYPE_AGGREGATOR = ATTR_AGGREGATOR
TYPE_COMMUNITIES = ATTR_COMMUNITIES
TYPE_ORIGINATOR_ID = ATTR_ORIGINATOR_ID
TYPE_CLUSTER_LIST = ATTR_CLUSTER_LIST
TYPE_MP_REACH = ATTR_MP_REACH
TYPE_MP_UNREACH = ATTR_MP_UNREACH
TYPE_EXT_COMMUNITIES = ATTR_EXT_COMMUNITIES
TYPE_AS4_PATH = ATTR_AS4_PATH
TYPE_AS4_AGGREGATOR = ATTR_AS4_AGGREGATOR
TYPE_LARGE_COMMUNITY = ATTR_LARGE_COMMUNITY

FLAG_OPTIONAL = AFLAG_OPTIONAL
FLAG_TRANSITIVE = AFLAG_TRANSITIVE
FLAG_PARTIAL = AFLAG_PARTIAL
FLAG_EXT_LEN = AFLAG_EXT_LEN

ATTR_NAMES = {
    ATTR_ORIGIN: 'ORIGIN', ATTR_AS_PATH: 'AS_PATH',
    ATTR_NEXT_HOP: 'NEXT_HOP', ATTR_MED: 'MULTI_EXIT_DISC',
    ATTR_LOCAL_PREF: 'LOCAL_PREF',
    ATTR_ATOMIC_AGGREGATE: 'ATOMIC_AGGREGATE',
    ATTR_AGGREGATOR: 'AGGREGATOR', ATTR_COMMUNITIES: 'COMMUNITIES',
    ATTR_ORIGINATOR_ID: 'ORIGINATOR_ID', ATTR_CLUSTER_LIST: 'CLUSTER_LIST',
    ATTR_MP_REACH: 'MP_REACH_NLRI', ATTR_MP_UNREACH: 'MP_UNREACH_NLRI',
    ATTR_EXT_COMMUNITIES: 'EXTENDED_COMMUNITIES', ATTR_AS4_PATH: 'AS4_PATH',
    ATTR_AS4_AGGREGATOR: 'AS4_AGGREGATOR',
    ATTR_LARGE_COMMUNITY: 'LARGE_COMMUNITY',
}

# The 16 all-ones bytes RFC 4271 s4.1 requires at the head of every message.
# Authentication moved to TCP-MD5 and TCP-AO long ago, so the marker is now
# purely a resynchronisation aid -- but it is still mandatory, and a peer
# that gets it wrong is a peer whose framing cannot be trusted.
MARKER = b'\xff' * 16

# Fault reasons recorded in an errors list. These mirror the REASON_*
# constants in errors.py; they are spelled here as well so this extension
# imports with no Python dependency of its own, and test_rtengine_wire.py
# asserts the two sets are identical so the duplication cannot drift.
REASON_FLAGS = 'attribute-flags'
REASON_LENGTH = 'attribute-length'
REASON_VALUE = 'attribute-value'
REASON_DUPLICATE = 'duplicate-attribute'
REASON_MISSING = 'missing-attribute'
REASON_UNPARSEABLE = 'unparseable'
REASON_UNNEGOTIATED = 'unnegotiated-family'

# AS_TRANS (RFC 6793) as it appears in the stored 8-byte AGGREGATOR form:
# four bytes of AS, widened from the two-octet header field.
_AGGREGATOR_AS_TRANS = b'\x00\x00\x5b\xa0'

# ADD-PATH, the one capability whose value grows with the configuration.
# Named for the error message: RFC 7911 s4 requires every family in a single
# instance, so a value too large for one capability cannot be split.
_CAP_ADD_PATH = 69

# The 4-octet AS capability code (RFC 6793). capabilities.py owns the
# public name and the rest of the capability vocabulary; this one value is
# mirrored here because decode_open has to honour it to report the peer's
# real AS, and reaching into a Python module from the codec to read one
# integer would be a worse dependency than a documented duplicate. The
# codec tests assert the two agree.
_CAP_AS4 = 65

# Attribute type used in an errors entry when the fault is the attribute
# *list* rather than any one attribute -- a withdrawn-routes length that
# overruns the message, say, where no single attribute is to blame. Negative
# so it can never collide with a real type, which is an unsigned octet.
# errors.ATTR_LIST holds the same value and the two are asserted equal.
ATTR_LIST = -1


cdef inline void _fault(list errors, int atype, str reason, str detail):
    """Record one decode fault, for the RFC 7606 matrix to judge later.

    Named ``_fault`` rather than the obvious ``_err`` on purpose. Cython's
    bundled MemoryView utility defines its own module-level ``cdef _err``,
    which is emitted into every module that uses a typed memoryview under
    the C name ``__pyx_memoryview_err``. A user function of the same name
    collides with it during prototype generation: the utility's definition
    is still emitted but its forward declaration is silently dropped, and
    the generated C fails to compile on any toolchain that treats an
    implicit function declaration as an error -- which clang 16 and later
    do by default. The symptom points at Cython's own generated code and
    not at anything in this file, so it is worth the sentence.
    """
    errors.append((atype, reason, detail))


cdef inline Py_ssize_t _nlri_addr_bytes(unsigned char plen):
    """Bytes an NLRI of this prefix length occupies on the wire."""
    return (<Py_ssize_t>plen + 7) // 8


# --- NLRI ------------------------------------------------------------------

cdef int _read_nlri(const unsigned char[:] mv, Py_ssize_t s, Py_ssize_t e,
                    bint add_path, unsigned char afi, list out,
                    Py_ssize_t *host_bits) except -2:
    """Read a run of length-prefixed prefixes into ``out``.

    NLRI is self-delimiting: each entry's length field says how many address
    bytes follow it. That makes a single bad length unrecoverable -- every
    subsequent offset is computed from it -- which is why a short read here
    is reported rather than skipped, and why the RFC 7606 matrix escalates
    an unparseable NLRI run all the way to a session reset.

    :param mv: the message buffer.
    :param s: first byte of the run.
    :param e: one past the last byte of the run.
    :param add_path: entries are preceded by a 4-byte RFC 7911 path id.
    :param afi: address family, which caps the address width.
    :param out: list appended with ``(Prefix, path_id)`` tuples.
    :param host_bits: incremented once per entry whose last byte has bits
        set past the prefix length (W-8). They are masked off either way.
    :return: the number of prefixes read, or -1 if the run was malformed.
    """
    cdef Py_ssize_t o = s
    cdef Py_ssize_t nxt, addr_start = 0
    cdef uint32_t path_id = 0
    cdef unsigned char plen = 0
    cdef Py_ssize_t count = 0
    cdef Py_ssize_t alen = pfx_addr_len(afi)
    cdef unsigned char maxbits = pfx_addr_bits(afi)
    cdef const unsigned char *base

    if alen == 0:
        return -1
    if s >= e:
        return 0
    base = &mv[0]
    while o < e:
        nxt = _bgp_nlri_next(mv, o, e, add_path, alen, &path_id, &plen,
                             &addr_start)
        if nxt < 0 or nxt <= o:
            # Either the header did not fit or the entry claimed more
            # address bytes than the family allows. Both mean the rest of
            # the run cannot be located.
            return -1
        if plen > maxbits:
            return -1
        if addr_start + _nlri_addr_bytes(plen) > e:
            return -1
        if (plen & 7) and (base[addr_start + _nlri_addr_bytes(plen) - 1] &
                           (0xff >> (plen & 7))):
            host_bits[0] += 1
        # pfx_new reads exactly (plen + 7) / 8 bytes and zero-fills the
        # rest, which is precisely the truncated form on the wire, so the
        # Prefix is built straight out of the parse buffer with no staging
        # copy.
        out.append((pfx_new(afi, plen, base + addr_start), path_id))
        count += 1
        o = nxt
    if o != e:
        return -1
    return count


# --- AS_PATH ----------------------------------------------------------------

cdef bytes _canon_as_path(const unsigned char[:] mv, Py_ssize_t s,
                          Py_ssize_t e, bint as4):
    """Widen an on-wire AS_PATH to the canonical 4-byte-ASN form.

    Canonicalising here rather than at comparison time is what lets a
    2-octet session and a 4-octet session intern to the same ``AttrSet``.
    A 2-byte ASN widens by zero extension, which is correct because a
    2-octet speaker cannot express anything above 65535 in the first place;
    where it needed to, it wrote AS_TRANS and put the real value in
    AS4_PATH, and :c:func:`_merge_as4` puts that back.

    :param mv: the message buffer.
    :param s: first byte of the attribute value.
    :param e: one past its last byte.
    :param as4: ASNs on the wire are 4 bytes rather than 2.
    :return: canonical AS_PATH bytes, or None if the value is malformed.
    """
    cdef Py_ssize_t o = s
    cdef Py_ssize_t nxt, asn_start = 0
    cdef Py_ssize_t i
    cdef Py_ssize_t width = 4 if as4 else 2
    cdef unsigned char seg_type = 0, count = 0
    cdef uint32_t asn
    cdef bytearray out = bytearray()

    if s > e:
        return None
    while o < e:
        nxt = _bgp_aspath_seg_next(mv, o, e, as4, &seg_type, &count,
                                   &asn_start)
        if nxt < 0 or nxt <= o:
            return None
        if (seg_type != AS_SEQUENCE and seg_type != AS_SET and
                seg_type != AS_CONFED_SEQUENCE and
                seg_type != AS_CONFED_SET):
            return None
        # RFC 4271 s4.3: a segment carries at least one AS. A zero count is
        # not merely useless, it is how a malformed path pads itself out to
        # the declared length while carrying nothing.
        if count == 0:
            return None
        if asn_start + (<Py_ssize_t>count * width) > e:
            return None
        o = nxt
        if as4:
            continue
        out.append(seg_type)
        out.append(count)
        for i in range(count):
            asn = rd_u16(mv, asn_start + i * 2)
            out.append(0)
            out.append(0)
            out.append(<unsigned char>((asn >> 8) & 0xff))
            out.append(<unsigned char>(asn & 0xff))
    if o != e:
        return None
    if as4:
        # The canonical form is the 4-octet wire form, and the walk above
        # has just checked the value is exactly a run of well formed
        # segments, so it is copied out whole. Rebuilding it one byte at a
        # time was a bytearray resize per byte on every UPDATE.
        return rd_bytes(mv, s, e)
    return bytes(out)


cdef list _split_segments(bytes path):
    """Split canonical AS_PATH bytes into ``[(seg_type, [asn, ...])]``."""
    cdef Py_ssize_t n = PyBytes_GET_SIZE(path)
    cdef Py_ssize_t o = 0, i
    cdef const unsigned char *p
    cdef unsigned char seg_type, count
    cdef list out = []
    cdef list asns

    if n == 0:
        return out
    p = <const unsigned char*>PyBytes_AS_STRING(path)
    while o + 2 <= n:
        seg_type = p[o]
        count = p[o + 1]
        o += 2
        if o + (<Py_ssize_t>count * 4) > n:
            break
        asns = []
        for i in range(count):
            asns.append(((<uint32_t>p[o + i * 4] << 24) |
                         (<uint32_t>p[o + i * 4 + 1] << 16) |
                         (<uint32_t>p[o + i * 4 + 2] << 8) |
                         <uint32_t>p[o + i * 4 + 3]))
        out.append((seg_type, asns))
        o += <Py_ssize_t>count * 4
    return out


cdef bytes _join_segments(list segments):
    """Rebuild canonical AS_PATH bytes from split segments.

    W-3: a segment is written in chunks of at most 255 ASNs, because its
    count is one byte and ``<unsigned char>len(asns)`` used to wrap. Only
    an AS_SEQUENCE can be longer here -- the RFC 6793 merge concatenates
    sequences -- and consecutive sequences are the same path.
    """
    cdef bytearray out = bytearray()
    cdef list asns
    cdef uint32_t asn
    cdef Py_ssize_t start, stop, i

    for seg_type, asns in segments:
        if not asns:
            continue
        for start in range(0, len(asns), 255):
            stop = min(start + 255, len(asns))
            out.append(<unsigned char>seg_type)
            out.append(<unsigned char>(stop - start))
            for i in range(start, stop):
                asn = asns[i]
                out.append(<unsigned char>((asn >> 24) & 0xff))
                out.append(<unsigned char>((asn >> 16) & 0xff))
                out.append(<unsigned char>((asn >> 8) & 0xff))
                out.append(<unsigned char>(asn & 0xff))
    return bytes(out)


cdef Py_ssize_t _count_asns(list segments):
    """Count AS numbers for the RFC 6793 merge.

    Counts hops the way the merge does: an AS_SET is one hop, confederation
    segments are not counted at all. This is the same rule
    ``AttrSet.as_path_len`` uses, and it must stay the same rule -- the
    merge splices two paths at a hop offset, so a mismatch would splice in
    the wrong place.
    """
    cdef Py_ssize_t total = 0
    cdef list asns

    for seg_type, asns in segments:
        if seg_type == AS_SEQUENCE:
            total += len(asns)
        elif seg_type == AS_SET:
            total += 1
    return total


cdef bytes _merge_as4(bytes as_path, bytes as4_path):
    """Reconstruct a 4-octet AS_PATH from the RFC 6793 pair.

    When a 4-octet speaker's announcement crosses a 2-octet speaker, every
    AS it could not represent became AS_TRANS in AS_PATH and the true
    sequence was carried alongside in AS4_PATH. RFC 6793 s4.2.3 says to take
    the leading hops from AS_PATH -- the part the 2-octet speakers
    legitimately prepended -- and the trailing AS4_PATH hops, spliced at the
    length difference.

    If AS4_PATH is *longer* than AS_PATH it is discarded entirely. That
    looks like an odd special case and is not: AS_PATH is authoritative for
    length because every speaker on the way maintained it, so an AS4_PATH
    claiming more hops than exist is evidence of a broken or hostile
    sender, and honouring it would let that sender lengthen a competitor's
    path at will.

    :param as_path: canonical AS_PATH, already widened.
    :param as4_path: canonical AS4_PATH.
    :return: the merged canonical AS_PATH.
    """
    cdef list segs = _split_segments(as_path)
    cdef list segs4 = _split_segments(as4_path)
    cdef Py_ssize_t n = _count_asns(segs)
    cdef Py_ssize_t n4 = _count_asns(segs4)
    cdef Py_ssize_t keep
    cdef Py_ssize_t taken = 0
    cdef list head = []
    cdef list asns
    cdef Py_ssize_t room

    if not segs4:
        return as_path
    if n4 > n:
        return as_path
    keep = n - n4
    for seg_type, asns in segs:
        if seg_type == AS_CONFED_SEQUENCE or seg_type == AS_CONFED_SET:
            # Confederation segments are local to the confederation and are
            # not part of the hop count the splice is measured in, so they
            # ride along in the head untouched.
            head.append((seg_type, list(asns)))
            continue
        if taken >= keep:
            break
        if seg_type == AS_SET:
            head.append((seg_type, list(asns)))
            taken += 1
            continue
        room = keep - taken
        if room >= len(asns):
            head.append((seg_type, list(asns)))
            taken += len(asns)
        else:
            head.append((seg_type, list(asns)[:room]))
            taken = keep
    return _join_segments(head + segs4)


cdef bytes _downgrade_as_path(bytes as_path, bint *needs_as4):
    """Narrow a canonical AS_PATH to 2-byte ASNs for a 2-octet peer.

    Any AS above 65535 becomes AS_TRANS, and ``needs_as4`` comes back true
    so the encoder knows it must also emit the untouched AS4_PATH alongside.

    :param as_path: canonical 4-byte-ASN AS_PATH.
    :param needs_as4: out, whether any AS had to be replaced.
    :return: the 2-byte-ASN wire form.
    """
    cdef list segs = _split_segments(as_path)
    cdef bytearray out = bytearray()
    cdef list asns
    cdef uint32_t asn
    cdef Py_ssize_t start, stop, i

    needs_as4[0] = 0
    for seg_type, asns in segs:
        if not asns:
            continue
        # Chunked like _join_segments (W-3); canonical segments never
        # exceed 255, so this is a guard rather than a path taken.
        for start in range(0, len(asns), 255):
            stop = min(start + 255, len(asns))
            out.append(<unsigned char>seg_type)
            out.append(<unsigned char>(stop - start))
            for i in range(start, stop):
                asn = asns[i]
                if asn > 0xffff:
                    needs_as4[0] = 1
                    asn = AS_TRANS
                out.append(<unsigned char>((asn >> 8) & 0xff))
                out.append(<unsigned char>(asn & 0xff))
    return bytes(out)


# --- Session context --------------------------------------------------------

cdef class DecodeCtx:
    """Per-session decode settings, from capability negotiation.

    :param as4: the session carries 4-octet ASNs in AS_PATH.
    :param is_ebgp: the peer is in a different AS.
    :param local_as: our AS, for loop detection by the caller.
    :param peer_as: the peer's AS.
    :param add_path: iterable of ``(afi, safi)`` we may receive multiple
        paths for.
    :param max_msg: the negotiated message-size ceiling.
    :param families: iterable of the ``(afi, safi)`` pairs negotiated for
        the session. An MP attribute for any other family is recorded as
        unnegotiated and ignored. Omitted or empty: no restriction, for
        decoding outside a session (tests, the benchmark).
    """

    def __init__(self, bint as4=True, bint is_ebgp=True, uint32_t local_as=0,
                 uint32_t peer_as=0, add_path=None,
                 Py_ssize_t max_msg=BGP_MAX_MSG, families=None):
        self.as4 = as4
        self.is_ebgp = is_ebgp
        self.local_as = local_as
        self.peer_as = peer_as
        self.add_path = frozenset(add_path or ())
        self.max_msg = max_msg
        self.families = frozenset(tuple(f) for f in (families or ()))

    cdef bint _add_path_for(self, uint16_t afi, unsigned char safi):
        if not self.add_path:
            return 0
        return (afi, safi) in self.add_path

    def add_path_for(self, afi, safi):
        """Return whether ADD-PATH receive applies to a family."""
        return bool(self._add_path_for(afi, safi))

    def __repr__(self):
        return '<DecodeCtx as4=%d ebgp=%d peer_as=%d max=%d>' % (
            self.as4, self.is_ebgp, self.peer_as, self.max_msg)


# --- Framing ----------------------------------------------------------------

cdef inline bint _length_fits_type(unsigned char mtype, uint16_t mlen):
    """RFC 4271 s6.1's per-type length rules (L-8).

    The framer's range check only knows the session ceiling; these are the
    floors and exact sizes each type implies. A 20-byte KEEPALIVE used to
    be accepted, which says the peer's framing is not what ours is -- and
    a framer that agrees to disagree is one that will mis-split the next
    message.
    """
    if mtype == MSG_KEEPALIVE:
        return mlen == BGP_HEADER_LEN
    if mtype == MSG_OPEN:
        return BGP_MIN_OPEN <= mlen <= BGP_MAX_MSG
    if mtype == MSG_UPDATE:
        return mlen >= BGP_MIN_UPDATE
    if mtype == MSG_NOTIFICATION:
        return mlen >= BGP_HEADER_LEN + 2
    if mtype == MSG_ROUTE_REFRESH:
        return mlen >= BGP_HEADER_LEN + 4
    return 1


cdef inline bytes _u16_bytes(uint16_t value):
    """A 16-bit value in network order, for a NOTIFICATION data field."""
    return bytes(bytearray([(value >> 8) & 0xff, value & 0xff]))


cdef class Framer:
    """Splits a TCP byte stream into whole BGP messages.

    Feed it whatever the socket returned and take whole messages out. The
    buffer is a ``bytearray`` with a moving start index rather than a
    repeatedly re-sliced one, because a full-table load delivers tens of
    thousands of messages and `buf = buf[n:]` per message is a copy of the
    entire remaining buffer per message.

    These faults latch and cannot be recovered from, so all of them stop
    the framer and must reset the session:

    * a bad marker, because the stream is no longer aligned and nothing
      downstream can tell data from header;
    * a length outside ``[19, max_msg]``, because that is either a
      corrupted stream or a peer exceeding what it negotiated, and in
      either case the next message boundary is unknown;
    * an unknown message type (1/3);
    * a length the message type cannot have (1/2, RFC 4271 s6.1): a
      KEEPALIVE is exactly 19 bytes, an OPEN 29 to 4096 whatever Extended
      Message says (RFC 8654), an UPDATE at least 23, a NOTIFICATION at
      least 21 and a ROUTE-REFRESH at least 23. These are judged from the
      header alone, before the body arrives.

    All of them set :attr:`error_code`/:attr:`error_subcode` to the
    NOTIFICATION the caller must send, and :attr:`error_data` to its data
    field: the offending Length or Type, as RFC 4271 s6.1 requires.

    :param max_msg: the largest message this session may carry, from
        capability negotiation (4096, or 65535 with Extended Message).
    """

    def __init__(self, Py_ssize_t max_msg=BGP_MAX_MSG):
        self._buf = bytearray()
        self._start = 0
        self.max_msg = max_msg
        self.messages = 0
        self.bytes_in = 0
        self.error_code = 0
        self.error_subcode = 0
        self.error_detail = None
        self.error_data = None

    cdef int _fault(self, int code, int subcode, str detail,
                    bytes data) except -1:
        # First fault wins: the ones that follow are consequences of a
        # stream that is already unusable, and reporting the last would
        # hide the cause.
        if not self.error_code:
            self.error_code = code
            self.error_subcode = subcode
            self.error_detail = detail
            self.error_data = data
        return 0

    @property
    def failed(self):
        """Whether the stream has latched an unrecoverable framing fault."""
        return self.error_code != 0

    @property
    def pending(self):
        """Bytes buffered but not yet formed into a whole message."""
        return len(self._buf) - self._start

    def set_max_msg(self, Py_ssize_t max_msg):
        """Raise the ceiling once Extended Message has been negotiated.

        Only ever called between OPEN and the first UPDATE: the limit is a
        property of the session, and changing it mid-stream would mean the
        two ends disagreed about what was legal.
        """
        self.max_msg = max_msg

    def feed(self, data):
        """Add received bytes to the buffer.

        :param data: bytes from the socket.
        :return: the number of bytes buffered.
        """
        if not data:
            return 0
        self._buf += data
        self.bytes_in += len(data)
        return len(data)

    def next_message(self):
        """Take the next complete message, if one is buffered.

        :return: ``(mtype, message_bytes)`` including the 19-byte header, or
            None when more bytes are needed or the framer has failed.
        """
        cdef const unsigned char[:] mv
        cdef Py_ssize_t avail, i
        cdef uint16_t mlen = 0
        cdef unsigned char mtype = 0
        cdef bytes out

        if self.error_code:
            return None
        avail = len(self._buf) - self._start
        if avail < BGP_HEADER_LEN:
            self._compact()
            return None
        mv = self._buf
        # The marker is checked before the length, because a stream that
        # has lost alignment will usually produce a plausible-looking
        # length and an implausible marker.
        for i in range(16):
            if mv[self._start + i] != 0xff:
                self._fault(1, 1, 'connection not synchronised: marker byte '
                            '%d is 0x%02x' % (i, mv[self._start + i]), None)
                return None
        if _bgp_msg_header(mv, self._start, self._start + avail,
                           &mlen, &mtype) < 0:
            self._compact()
            return None
        if mlen < BGP_HEADER_LEN or mlen > self.max_msg:
            self._fault(1, 2, 'bad message length %d (allowed %d..%d)'
                        % (mlen, BGP_HEADER_LEN, self.max_msg),
                        _u16_bytes(mlen))
            return None
        if mtype < MSG_OPEN or mtype > MSG_ROUTE_REFRESH:
            self._fault(1, 3, 'bad message type %d' % mtype,
                        bytes(bytearray([mtype])))
            return None
        if not _length_fits_type(mtype, mlen):
            self._fault(1, 2, 'bad message length %d for %s'
                        % (mlen, MSG_NAMES.get(mtype, mtype)),
                        _u16_bytes(mlen))
            return None
        if avail < mlen:
            self._compact()
            return None
        out = bytes(self._buf[self._start:self._start + mlen])
        self._start += mlen
        self.messages += 1
        return (mtype, out)

    def messages_available(self):
        """Drain every complete message currently buffered.

        :return: a list of ``(mtype, message_bytes)``, oldest first. Stops
            early if a framing fault latches, so the caller should check
            :attr:`failed` after iterating.
        """
        cdef list out = []
        item = self.next_message()
        while item is not None:
            out.append(item)
            item = self.next_message()
        return out

    def _compact(self):
        # Reclaim the consumed prefix, but only once it is worth the copy.
        # Doing it per message would reintroduce exactly the cost the
        # moving start index exists to avoid.
        if self._start and (self._start >= 65536 or
                            self._start * 2 >= len(self._buf)):
            del self._buf[:self._start]
            self._start = 0

    def reset(self):
        """Discard buffered bytes and clear the fault, for a session reset."""
        self._buf = bytearray()
        self._start = 0
        self.error_code = 0
        self.error_subcode = 0
        self.error_detail = None
        self.error_data = None

    def stats(self):
        """Return framing counters for health output."""
        return {
            'messages': self.messages,
            'bytes': self.bytes_in,
            'buffered': len(self._buf) - self._start,
            'max-message': self.max_msg,
            'error': self.error_detail,
        }

    def __repr__(self):
        return '<Framer msgs=%d buffered=%d max=%d%s>' % (
            self.messages, len(self._buf) - self._start, self.max_msg,
            ' FAILED' if self.error_code else '')


# --- Typed messages ---------------------------------------------------------

cdef class OpenMsg:
    """A decoded OPEN.

    ``my_as`` is the AS to use: the 2-byte header field unless a 4-octet AS
    capability overrode it. ``my_as_wire`` keeps the header value, because
    RFC 6793 requires the header to read AS_TRANS when the capability
    carries an AS above 65535 and a peer that got that wrong is worth being
    able to report.
    """

    def as_dict(self):
        """Render for ``show ip bgp neighbors`` and for logging."""
        return {
            'version': self.version,
            'my-as': self.my_as,
            'hold-time': self.hold_time,
            'router-id': '%d.%d.%d.%d' % ((self.bgp_id >> 24) & 0xff,
                                          (self.bgp_id >> 16) & 0xff,
                                          (self.bgp_id >> 8) & 0xff,
                                          self.bgp_id & 0xff),
            'capabilities': [c[0] for c in self.capabilities],
        }

    def __repr__(self):
        return '<OpenMsg as=%d hold=%d caps=%d>' % (
            self.my_as, self.hold_time, len(self.capabilities))


cdef class UpdateMsg:
    """A fully parsed, not-yet-applied UPDATE."""

    def counts(self):
        """Return ``(announced, withdrawn)`` across all families."""
        cdef Py_ssize_t a = len(self.nlri)
        cdef Py_ssize_t w = len(self.withdrawn)
        if self.mp_reach is not None:
            a += len(self.mp_reach[4])
        if self.mp_unreach is not None:
            w += len(self.mp_unreach[2])
        return (a, w)

    def __repr__(self):
        cdef Py_ssize_t a, w
        a, w = self.counts()
        return '<UpdateMsg +%d -%d%s%s>' % (
            a, w, ' eor' if self.end_of_rib else '',
            ' errors=%d' % len(self.errors) if self.errors else '')


cdef class NotificationMsg:
    """A decoded NOTIFICATION."""

    def __repr__(self):
        return '<NotificationMsg %d/%d %dB>' % (self.code, self.subcode,
                                                len(self.data))


cdef class RouteRefreshMsg:
    """A decoded ROUTE-REFRESH, including the RFC 7313 subtypes."""

    def __repr__(self):
        return '<RouteRefreshMsg afi=%d safi=%d subtype=%d>' % (
            self.afi, self.safi, self.subtype)


# --- Decoders ---------------------------------------------------------------

cdef inline Py_ssize_t _ext_param_next(const unsigned char[:] mv,
                                       Py_ssize_t o, Py_ssize_t e,
                                       unsigned char *ptype, Py_ssize_t *vs,
                                       Py_ssize_t *ve):
    """Step over one RFC 9072 optional parameter: type(1), length(2).

    In the extended format every parameter's length is two octets, not
    just the block's (RFC 9072 s2). Capabilities inside a parameter keep
    their one-octet lengths, which is why ``_bgp_cap_next`` still walks
    those.

    :return: the offset after the parameter, or -1 if it overruns ``e``.
    """
    if o + 3 > e:
        return -1
    ptype[0] = mv[o]
    vs[0] = o + 3
    ve[0] = o + 3 + rd_u16(mv, o + 1)
    if ve[0] > e:
        return -1
    return ve[0]


def decode_open(bytes msg):
    """Decode an OPEN message.

    RFC 9072's extended optional-parameter length is honoured, which is the
    one place rtengine deliberately reads more than the text dissector
    does: the dissector is frozen on the one-byte form so its output stays
    byte-identical, and the primitive takes ``allow_ext`` precisely so the
    two can differ on the same bytes.

    :param msg: a complete OPEN, header included.
    :return: an :class:`OpenMsg`; check its ``errors`` list before use.
    """
    cdef const unsigned char[:] mv = msg
    cdef Py_ssize_t n = len(msg)
    cdef Py_ssize_t opt_start = -1, opt_end = -1
    cdef Py_ssize_t o, o2, nxt, vs = 0, ve = 0, cnxt, cvs = 0, cve = 0
    cdef bint extended
    cdef unsigned char ver = 0, ptype = 0, ccode = 0
    cdef uint16_t my_as = 0, hold = 0
    cdef uint32_t bgp_id = 0
    cdef OpenMsg m = OpenMsg.__new__(OpenMsg)

    m.capabilities = []
    m.unsupported_params = []
    m.errors = []
    m.version = 0
    m.my_as = 0
    m.my_as_wire = 0
    m.hold_time = 0
    m.bgp_id = 0

    if n < BGP_MIN_OPEN:
        _fault(m.errors, ATTR_LIST, REASON_LENGTH,
               'OPEN is %d bytes, minimum is %d' % (n, BGP_MIN_OPEN))
        return m
    if _bgp_open_fixed(mv, BGP_HEADER_LEN, n, 1, &ver, &my_as, &hold,
                       &bgp_id, &opt_start, &opt_end) < 0:
        _fault(m.errors, ATTR_LIST, REASON_LENGTH, 'truncated OPEN body')
        return m
    m.version = ver
    m.my_as = my_as
    m.my_as_wire = my_as
    m.hold_time = hold
    m.bgp_id = bgp_id
    if opt_end > n:
        _fault(m.errors, ATTR_LIST, REASON_LENGTH,
               'optional parameters claim %d bytes, %d present'
               % (opt_end - opt_start, n - opt_start))
        opt_end = n

    # Optional parameters and capabilities have the same (code, length,
    # value) shape, so one primitive walks both levels -- except in RFC
    # 9072's extended format, where the parameter length is two octets.
    # _bgp_open_fixed reports that format by starting the parameters 3
    # bytes later; reading them with one-octet lengths, as this used to,
    # misparses every extended OPEN.
    extended = opt_start == BGP_HEADER_LEN + 13
    o = opt_start
    while o < opt_end:
        if extended:
            nxt = _ext_param_next(mv, o, opt_end, &ptype, &vs, &ve)
        else:
            nxt = _bgp_cap_next(mv, o, opt_end, &ptype, &vs, &ve)
        if nxt < 0 or nxt <= o:
            _fault(m.errors, ATTR_LIST, REASON_UNPARSEABLE,
                   'truncated optional parameter at offset %d' % o)
            break
        if ve > opt_end:
            # _bgp_cap_next clamps the *next* offset but reports the value
            # end the length octet claims. Walking capabilities up to that
            # claim read past the parameter -- and past the message, with
            # bounds checks off: an AS4 capability straddling the end
            # pulled the peer's AS out of whatever followed the buffer.
            _fault(m.errors, ATTR_LIST, REASON_LENGTH,
                   'optional parameter at offset %d claims %d bytes, %d '
                   'present' % (o, ve - vs, opt_end - vs))
            break
        if ptype == 2:
            cnxt = vs
            while cnxt < ve:
                o2 = cnxt
                cnxt = _bgp_cap_next(mv, o2, ve, &ccode, &cvs, &cve)
                if cnxt < 0 or cnxt <= o2:
                    _fault(m.errors, ATTR_LIST, REASON_UNPARSEABLE,
                           'truncated capability at offset %d' % o2)
                    break
                if cve > ve:
                    _fault(m.errors, ATTR_LIST, REASON_LENGTH,
                           'capability %d at offset %d claims %d bytes, %d '
                           'present' % (ccode, o2, cve - cvs, ve - cvs))
                    break
                if ccode == _CAP_AS4 and cve - cvs == 4:
                    # RFC 6793 s4.1: a speaker whose AS does not fit in
                    # the 16-bit header field writes AS_TRANS there and
                    # puts the real value in this capability. Resolving
                    # it here rather than in every caller is the point of
                    # `my_as`: a peer reported as AS 23456 would never
                    # match its configured remote-as, so every 4-octet
                    # neighbour would be refused. `my_as_wire` keeps the
                    # header value so a peer that filled it in wrongly
                    # can still be diagnosed.
                    m.my_as = rd_u32(mv, cvs)
                m.capabilities.append((ccode, msg[cvs:cve]))
        else:
            # RFC 5492 deprecated every optional parameter except
            # capabilities, but an unknown one is kept rather than dropped:
            # the FSM has to answer with NOTIFICATION "Unsupported Optional
            # Parameter" and cannot name what it did not record.
            m.unsupported_params.append((ptype, msg[vs:ve]))
        o = nxt
    return m


def decode_notification(bytes msg):
    """Decode a NOTIFICATION message.

    :param msg: a complete NOTIFICATION, header included.
    :return: a :class:`NotificationMsg`. A truncated one still returns an
        object, with zeros, because the session is ending either way and
        logging "peer sent a malformed NOTIFICATION" beats raising.
    """
    cdef NotificationMsg m = NotificationMsg.__new__(NotificationMsg)
    cdef Py_ssize_t n = len(msg)

    m.code = 0
    m.subcode = 0
    m.data = b''
    if n >= BGP_HEADER_LEN + 1:
        m.code = msg[BGP_HEADER_LEN]
    if n >= BGP_HEADER_LEN + 2:
        m.subcode = msg[BGP_HEADER_LEN + 1]
    if n > BGP_HEADER_LEN + 2:
        m.data = msg[BGP_HEADER_LEN + 2:]
    return m


def decode_route_refresh(bytes msg):
    """Decode a ROUTE-REFRESH message.

    :param msg: a complete ROUTE-REFRESH, header included.
    :return: a :class:`RouteRefreshMsg`, or None if the 4-byte body is not
        all present.
    """
    cdef const unsigned char[:] mv = msg
    cdef Py_ssize_t n = len(msg)
    cdef RouteRefreshMsg m

    if n < BGP_HEADER_LEN + 4:
        return None
    m = RouteRefreshMsg.__new__(RouteRefreshMsg)
    m.afi = rd_u16(mv, BGP_HEADER_LEN)
    # RFC 2918 called this byte Reserved and required it to be zero; RFC
    # 7313 gave it meaning as the subtype. Reading it as a subtype is
    # backward compatible precisely because the old rule forced it to 0,
    # which is the "normal request" subtype.
    m.subtype = mv[BGP_HEADER_LEN + 2]
    m.safi = mv[BGP_HEADER_LEN + 3]
    return m


def decode_update(bytes msg, DecodeCtx ctx):
    """Decode an UPDATE message completely, applying nothing.

    Everything the RFC 7606 matrix needs to judge the message ends up in
    ``UpdateMsg.errors`` as ``(attr_type, reason, detail)``. The decoder
    makes no policy decision of its own -- it does not know whether this
    peer is one whose malformed COMMUNITIES should cost it a session -- and
    that separation is what lets the matrix be a table rather than a set of
    branches scattered through the parse.

    :param msg: a complete UPDATE, header included.
    :param ctx: the session's decode settings.
    :return: an :class:`UpdateMsg`.
    """
    cdef const unsigned char[:] mv = msg
    cdef Py_ssize_t n = len(msg)
    cdef Py_ssize_t o, wend, tend, nxt, vs = 0, ve = 0, vclamp
    cdef uint16_t wlen, tpalen
    cdef unsigned char flags = 0, atype = 0
    cdef UpdateMsg m = UpdateMsg.__new__(UpdateMsg)
    cdef AttrSet a = attrs_blank()
    cdef bint add_path_v4
    cdef Py_ssize_t rc
    cdef Py_ssize_t host_bits = 0
    # Attribute types already decoded, as a 256 bit set: a Python set of
    # boxed ints was an allocation per UPDATE and two lookups per attribute.
    cdef uint64_t seen[4]
    cdef bint saw_origin = 0, saw_as_path = 0, saw_nexthop = 0
    # AS4_PATH and AS4_AGGREGATOR are carried out of the per-attribute
    # decoder in a two-slot list rather than through `bytes *` out
    # parameters. Taking the address of a Cython object variable hands the
    # callee a raw PyObject** and the assignment through it skips the
    # reference counting the compiler would otherwise emit -- a use-after-
    # free that surfaces somewhere else entirely, much later.
    cdef list carry = [None, None]

    m.withdrawn = []
    m.nlri = []
    m.errors = []
    m.attrs = None
    m.has_attrs = 0
    m.mp_reach = None
    m.mp_unreach = None
    m.end_of_rib = 0
    m.host_bits = 0
    memset(seen, 0, sizeof(seen))

    if n < BGP_MIN_UPDATE:
        _fault(m.errors, ATTR_LIST, REASON_LENGTH,
               'UPDATE is %d bytes, minimum is %d' % (n, BGP_MIN_UPDATE))
        return m

    add_path_v4 = ctx._add_path_for(PFX_AFI_IP, 1)

    # --- withdrawn routes --------------------------------------------------
    o = BGP_HEADER_LEN
    wlen = rd_u16(mv, o)
    o += 2
    wend = o + wlen
    if wend > n:
        # The field claims more than the message holds. Nothing after it can
        # be located, so this is one of the unrecoverable length errors the
        # matrix escalates to a session reset.
        _fault(m.errors, ATTR_LIST, REASON_LENGTH,
               'withdrawn-routes length %d exceeds the message' % wlen)
        return m
    rc = _read_nlri(mv, o, wend, add_path_v4, PFX_AFI_IP, m.withdrawn,
                    &host_bits)
    if rc < 0:
        _fault(m.errors, ATTR_LIST, REASON_UNPARSEABLE,
               'malformed withdrawn-routes field')
        return m

    # --- total path attribute length ---------------------------------------
    o = wend
    if o + 2 > n:
        _fault(m.errors, ATTR_LIST, REASON_LENGTH,
               'no room for the path-attribute length field')
        return m
    tpalen = rd_u16(mv, o)
    o += 2
    tend = o + tpalen
    if tend > n:
        _fault(m.errors, ATTR_LIST, REASON_LENGTH,
               'path-attribute length %d exceeds the message' % tpalen)
        return m

    # --- path attributes ---------------------------------------------------
    while o < tend:
        nxt = _bgp_attr_next(mv, o, tend, &flags, &atype, &vs, &ve)
        if nxt < 0 or nxt <= o:
            _fault(m.errors, ATTR_LIST, REASON_UNPARSEABLE,
                   'truncated path attribute at offset %d' % o)
            break
        # `ve` is what the length field claims; it may exceed the readable
        # span. Clamping separately keeps "the attribute lied about its
        # length" distinguishable from "the attribute is simply long".
        vclamp = ve if ve <= tend else tend
        if ve > tend:
            _fault(m.errors, atype, REASON_LENGTH,
                   '%s claims %d bytes, %d readable'
                   % (ATTR_NAMES.get(atype, atype), ve - vs, vclamp - vs))
            o = nxt
            continue
        if seen[atype >> 6] & (<uint64_t>1 << (atype & 63)):
            # RFC 7606 s3g: a repeated attribute is an error. Which error is
            # the matrix's decision; the decoder only records that it
            # happened and keeps the first occurrence.
            _fault(m.errors, atype, REASON_DUPLICATE,
                   'duplicate %s' % ATTR_NAMES.get(atype, atype))
            o = nxt
            continue
        seen[atype >> 6] |= <uint64_t>1 << (atype & 63)
        _decode_attr(mv, msg, ctx, m, a, flags, atype, vs, vclamp, carry,
                     &saw_origin, &saw_as_path, &saw_nexthop)
        o = nxt
    m.has_attrs = tpalen > 0

    # --- NLRI --------------------------------------------------------------
    o = tend
    rc = _read_nlri(mv, o, n, add_path_v4, PFX_AFI_IP, m.nlri, &host_bits)
    m.host_bits += host_bits
    if rc < 0:
        _fault(m.errors, ATTR_LIST, REASON_UNPARSEABLE, 'malformed NLRI field')
        return m

    # --- post-processing ---------------------------------------------------
    # RFC 6793 s4.2.3 (W-1): an AGGREGATOR that names a real AS -- anything
    # but AS_TRANS -- means the 2-octet speaker that last touched the route
    # aggregated it itself, after whoever attached AS4_AGGREGATOR. Both AS4
    # attributes are then stale, and the RFC has AS4_AGGREGATOR *and*
    # AS4_PATH ignored. Taking AS4_AGGREGATOR unconditionally, as this did,
    # let an old attribute overwrite the aggregator and the path.
    if (carry[1] is not None and a.aggregator and
            a.aggregator[:4] != _AGGREGATOR_AS_TRANS):
        carry[0] = None
        carry[1] = None
    # AS4_PATH is merged after the whole attribute list is known, because
    # the merge needs both attributes and they can arrive in either order.
    if carry[0] is not None:
        a.as_path = _merge_as4(a.as_path, <bytes>carry[0])
    if carry[1] is not None:
        a.aggregator = <bytes>carry[1]

    _check_mandatory(m, ctx, saw_origin, saw_as_path, saw_nexthop)

    m.attrs = attrs_finalize(a)
    m.end_of_rib = _is_end_of_rib(m, tpalen)
    return m


cdef bint _is_end_of_rib(UpdateMsg m, uint16_t tpalen):
    """Recognise the RFC 4724 End-of-RIB marker.

    For IPv4 unicast it is a completely empty UPDATE: no withdrawn routes,
    no attributes, no NLRI. For any other family it is an UPDATE whose only
    content is an MP_UNREACH_NLRI naming the family and carrying no
    prefixes. Both mean "my initial table for this family is complete",
    which the peer needs in order to stop waiting.
    """
    if m.nlri or m.withdrawn:
        return 0
    if m.mp_reach is not None:
        return 0
    if m.mp_unreach is not None:
        return len(m.mp_unreach[2]) == 0
    return tpalen == 0


cdef int _check_mandatory(UpdateMsg m, DecodeCtx ctx, bint saw_origin,
                          bint saw_as_path, bint saw_nexthop) except -1:
    """Record any missing well-known mandatory attribute.

    Only checked when the UPDATE actually announces something -- classic
    NLRI, or prefixes in MP_REACH_NLRI. A withdraw-only UPDATE carries no
    attributes by design, and demanding ORIGIN of it would reject
    perfectly legal messages.

    L-2: "announces" used to mean the classic NLRI field only, so an UPDATE
    announcing through MP_REACH alone skipped the check entirely, and the
    blank attribute set's IGP origin and empty AS_PATH were installed as if
    the peer had sent them. ORIGIN and AS_PATH are mandatory for every
    family (RFC 4760 s3, RFC 7606 s3.d); missing either is
    treat-as-withdraw, which needs the prefixes -- and they are extracted
    regardless, so there is always something to withdraw.

    NEXT_HOP is required only for the IPv4 NLRI field. An MP_REACH-only
    UPDATE carries its next hop inside MP_REACH, and RFC 4760 explicitly
    says the NEXT_HOP attribute is then absent -- requiring it is a
    classic way to break IPv6 peering. LOCAL_PREF is discretionary (RFC
    4271 s5.1.5) and never demanded.
    """
    cdef bint mp_announces = (m.mp_reach is not None and
                              len(<list>m.mp_reach[4]) > 0)
    if not m.nlri and not mp_announces:
        return 0
    if not saw_origin:
        _fault(m.errors, ATTR_ORIGIN, REASON_MISSING, 'ORIGIN is missing')
    if not saw_as_path:
        _fault(m.errors, ATTR_AS_PATH, REASON_MISSING, 'AS_PATH is missing')
    if m.nlri and not saw_nexthop:
        _fault(m.errors, ATTR_NEXT_HOP, REASON_MISSING, 'NEXT_HOP is missing')
    return 0


cdef int _decode_attr(const unsigned char[:] mv, bytes msg, DecodeCtx ctx,
                      UpdateMsg m, AttrSet a, unsigned char flags,
                      unsigned char atype, Py_ssize_t vs, Py_ssize_t ve,
                      list carry, bint *saw_origin, bint *saw_as_path,
                      bint *saw_nexthop) except -1:
    """Decode one path attribute into the attribute set under construction.

    Every branch follows the same shape: check the flags, check the length,
    then read. Flags are checked first because RFC 7606 s4 makes a wrong
    optional/transitive bit its own error independent of whether the value
    would have parsed, and because a well-known attribute arriving marked
    optional is a sign the sender's notion of the attribute differs from
    ours.

    :param mv: the message buffer.
    :param msg: the same bytes, for slicing values out.
    :param ctx: session decode settings.
    :param m: the message being built, for its errors list and MP fields.
    :param a: the attribute set being filled.
    :param flags: attribute flags byte.
    :param atype: attribute type code.
    :param vs: first byte of the value.
    :param ve: one past the last readable value byte.
    :param carry: two-slot out list; slot 0 takes the canonical AS4_PATH
        and slot 1 the 4-octet AS4_AGGREGATOR, both merged after the whole
        attribute list has been read.
    :param saw_origin: out, ORIGIN was present.
    :param saw_as_path: out, AS_PATH was present.
    :param saw_nexthop: out, NEXT_HOP was present.
    :return: 0.
    """
    cdef Py_ssize_t vlen = ve - vs
    cdef bytes canon
    cdef bint optional = (flags & AFLAG_OPTIONAL) != 0
    cdef bint transitive = (flags & AFLAG_TRANSITIVE) != 0
    # W-10: RFC 4271 s4.3 -- "for well-known attributes ... the Partial bit
    # MUST be set to 0". A well-known attribute cannot have been carried
    # through a speaker that did not understand it, so a Partial bit on one
    # is a flags conflict like a wrong Optional or Transitive bit (s6.3).
    cdef bint bad_well_known = optional or not transitive or \
        (flags & AFLAG_PARTIAL) != 0

    if atype == ATTR_ORIGIN:
        saw_origin[0] = 1
        if bad_well_known:
            _fault(m.errors, atype, REASON_FLAGS,
                   'ORIGIN is well-known (flags 0x%02x)' % flags)
            return 0
        if vlen != 1:
            _fault(m.errors, atype, REASON_LENGTH,
                   'ORIGIN length %d, must be 1' % vlen)
            return 0
        if mv[vs] > ORIGIN_INCOMPLETE:
            _fault(m.errors, atype, REASON_VALUE,
                   'ORIGIN value %d is not 0, 1 or 2' % mv[vs])
            return 0
        a.origin = mv[vs]

    elif atype == ATTR_AS_PATH:
        saw_as_path[0] = 1
        if bad_well_known:
            _fault(m.errors, atype, REASON_FLAGS,
                   'AS_PATH is well-known (flags 0x%02x)' % flags)
            return 0
        canon = _canon_as_path(mv, vs, ve, ctx.as4)
        if canon is None:
            _fault(m.errors, atype, REASON_VALUE, 'malformed AS_PATH segments')
            return 0
        a.as_path = canon

    elif atype == ATTR_NEXT_HOP:
        saw_nexthop[0] = 1
        if bad_well_known:
            _fault(m.errors, atype, REASON_FLAGS,
                   'NEXT_HOP is well-known (flags 0x%02x)' % flags)
            return 0
        if vlen != 4:
            _fault(m.errors, atype, REASON_LENGTH,
                   'NEXT_HOP length %d, must be 4' % vlen)
            return 0
        a.nexthop = msg[vs:ve]

    elif atype == ATTR_MED:
        if not optional or transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'MULTI_EXIT_DISC is optional non-transitive')
            return 0
        if vlen != 4:
            _fault(m.errors, atype, REASON_LENGTH,
                   'MULTI_EXIT_DISC length %d, must be 4' % vlen)
            return 0
        a.med = rd_u32(mv, vs)
        a.flags |= ATTRF_MED

    elif atype == ATTR_LOCAL_PREF:
        if bad_well_known:
            _fault(m.errors, atype, REASON_FLAGS,
                   'LOCAL_PREF is well-known (flags 0x%02x)' % flags)
            return 0
        if vlen != 4:
            _fault(m.errors, atype, REASON_LENGTH,
                   'LOCAL_PREF length %d, must be 4' % vlen)
            return 0
        # RFC 4271 s5.1.5: LOCAL_PREF must not cross an eBGP boundary. It is
        # recorded rather than silently dropped so the matrix can decide,
        # but an eBGP peer sending it is either misconfigured or trying to
        # influence our internal preference from outside.
        if ctx.is_ebgp:
            _fault(m.errors, atype, REASON_VALUE,
                   'LOCAL_PREF received from an eBGP peer')
            return 0
        a.local_pref = rd_u32(mv, vs)
        a.flags |= ATTRF_LOCAL_PREF

    elif atype == ATTR_ATOMIC_AGGREGATE:
        if bad_well_known:
            _fault(m.errors, atype, REASON_FLAGS,
                   'ATOMIC_AGGREGATE is well-known (flags 0x%02x)' % flags)
            return 0
        if vlen != 0:
            _fault(m.errors, atype, REASON_LENGTH,
                   'ATOMIC_AGGREGATE length %d, must be 0' % vlen)
            return 0
        a.flags |= ATTRF_ATOMIC_AGGREGATE

    elif atype == ATTR_AGGREGATOR:
        if not optional or not transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'AGGREGATOR is optional transitive')
            return 0
        # 6 bytes on a 2-octet session, 8 on a 4-octet one. Both are stored
        # in the 8-byte form so nothing downstream has to know which.
        if ctx.as4:
            if vlen != 8:
                _fault(m.errors, atype, REASON_LENGTH,
                       'AGGREGATOR length %d, must be 8 on a 4-octet session'
                       % vlen)
                return 0
            a.aggregator = msg[vs:ve]
        else:
            if vlen != 6:
                _fault(m.errors, atype, REASON_LENGTH,
                       'AGGREGATOR length %d, must be 6 on a 2-octet session'
                       % vlen)
                return 0
            a.aggregator = (b'\x00\x00' + msg[vs:vs + 2] +
                            msg[vs + 2:vs + 6])

    elif atype == ATTR_COMMUNITIES:
        if not optional or not transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'COMMUNITIES is optional transitive')
            return 0
        if vlen % 4:
            _fault(m.errors, atype, REASON_LENGTH,
                   'COMMUNITIES length %d is not a multiple of 4' % vlen)
            return 0
        a.communities = msg[vs:ve]

    elif atype == ATTR_ORIGINATOR_ID:
        if not optional or transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'ORIGINATOR_ID is optional non-transitive')
            return 0
        if vlen != 4:
            _fault(m.errors, atype, REASON_LENGTH,
                   'ORIGINATOR_ID length %d, must be 4' % vlen)
            return 0
        if ctx.is_ebgp:
            _fault(m.errors, atype, REASON_VALUE,
                   'ORIGINATOR_ID received from an eBGP peer')
            return 0
        a.originator_id = rd_u32(mv, vs)
        a.flags |= ATTRF_ORIGINATOR_ID

    elif atype == ATTR_CLUSTER_LIST:
        if not optional or transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'CLUSTER_LIST is optional non-transitive')
            return 0
        if vlen % 4:
            _fault(m.errors, atype, REASON_LENGTH,
                   'CLUSTER_LIST length %d is not a multiple of 4' % vlen)
            return 0
        if ctx.is_ebgp:
            _fault(m.errors, atype, REASON_VALUE,
                   'CLUSTER_LIST received from an eBGP peer')
            return 0
        a.cluster_list = msg[vs:ve]

    elif atype == ATTR_EXT_COMMUNITIES:
        if not optional or not transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'EXTENDED_COMMUNITIES is optional transitive')
            return 0
        if vlen % 8:
            _fault(m.errors, atype, REASON_LENGTH,
                   'EXTENDED_COMMUNITIES length %d is not a multiple of 8'
                   % vlen)
            return 0
        a.ext_communities = msg[vs:ve]

    elif atype == ATTR_LARGE_COMMUNITY:
        if not optional or not transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'LARGE_COMMUNITY is optional transitive')
            return 0
        if vlen % 12:
            _fault(m.errors, atype, REASON_LENGTH,
                   'LARGE_COMMUNITY length %d is not a multiple of 12' % vlen)
            return 0
        a.large_communities = msg[vs:ve]

    elif atype == ATTR_AS4_PATH:
        if not optional or not transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'AS4_PATH is optional transitive')
            return 0
        # AS4_PATH always carries 4-byte ASNs regardless of the session.
        canon = _canon_as_path(mv, vs, ve, 1)
        if canon is None:
            _fault(m.errors, atype, REASON_VALUE,
                   'malformed AS4_PATH segments')
            return 0
        if ctx.as4:
            # RFC 6793 s4.2.3: a 4-octet session must ignore AS4_PATH
            # entirely. Accepting it would let a sender override the
            # authoritative AS_PATH it also sent.
            return 0
        carry[0] = canon

    elif atype == ATTR_AS4_AGGREGATOR:
        if not optional or not transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'AS4_AGGREGATOR is optional transitive')
            return 0
        if vlen != 8:
            _fault(m.errors, atype, REASON_LENGTH,
                   'AS4_AGGREGATOR length %d, must be 8' % vlen)
            return 0
        if ctx.as4:
            return 0
        carry[1] = msg[vs:ve]

    elif atype == ATTR_MP_REACH:
        # W-4: RFC 4760 s3 makes both MP attributes optional non-transitive.
        # Wrong flags mean the sender's idea of the attribute is not ours,
        # and an MP attribute is the one place that disagreement cannot be
        # contained: its NLRI is the question the UPDATE asks, so the matrix
        # resets rather than guessing which prefixes it meant.
        if not optional or transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'MP_REACH_NLRI is optional non-transitive (flags 0x%02x)'
                   % flags)
            return 0
        _decode_mp_reach(mv, msg, ctx, m, a, vs, ve)

    elif atype == ATTR_MP_UNREACH:
        if not optional or transitive:
            _fault(m.errors, atype, REASON_FLAGS,
                   'MP_UNREACH_NLRI is optional non-transitive (flags 0x%02x)'
                   % flags)
            return 0
        _decode_mp_unreach(mv, ctx, m, vs, ve)

    else:
        # Unknown. Optional-transitive attributes are preserved verbatim so
        # a re-advertisement carries them onward with the partial bit set,
        # which RFC 4271 s5 requires; optional non-transitive ones are
        # dropped, which it also requires. A well-known attribute we do not
        # recognise is a protocol violation the matrix escalates.
        if not optional:
            _fault(m.errors, atype, REASON_VALUE,
                   'unrecognised well-known attribute %d' % atype)
        elif transitive:
            a.unknown = a.unknown + _reencode_attr(flags | AFLAG_PARTIAL,
                                                   atype, msg[vs:ve])
    return 0


cdef bytes _reencode_attr(unsigned char flags, unsigned char atype,
                          bytes value):
    """Rebuild one attribute TLV, choosing the narrowest legal length."""
    cdef Py_ssize_t vlen = PyBytes_GET_SIZE(value)
    cdef bytearray out = bytearray()

    if vlen > 255:
        flags |= AFLAG_EXT_LEN
    else:
        flags &= <unsigned char>(~AFLAG_EXT_LEN)
    out.append(flags)
    out.append(atype)
    if flags & AFLAG_EXT_LEN:
        out.append(<unsigned char>((vlen >> 8) & 0xff))
        out.append(<unsigned char>(vlen & 0xff))
    else:
        out.append(<unsigned char>vlen)
    out += value
    return bytes(out)


cdef inline bint _family_ok(DecodeCtx ctx, uint16_t afi, unsigned char safi):
    """Whether an MP attribute's family is one this session takes.

    The AFI is compared whole before anything narrows it: the address
    helpers take an ``unsigned char``, and AFI 257 cast to one is AFI 1.
    """
    if (afi != PFX_AFI_IP and afi != PFX_AFI_IP6) or safi != 1:
        return 0
    if ctx.families and (afi, safi) not in ctx.families:
        return 0
    return 1


cdef int _decode_mp_reach(const unsigned char[:] mv, bytes msg,
                          DecodeCtx ctx, UpdateMsg m, AttrSet a,
                          Py_ssize_t vs, Py_ssize_t ve) except -1:
    """Decode MP_REACH_NLRI (RFC 4760).

    The next hop lives inside this attribute rather than in NEXT_HOP, and
    for IPv6 it may be 16 bytes (global only) or 32 (global plus
    link-local). The two are kept apart rather than concatenated because
    only the global one can be resolved or installed.
    """
    cdef uint16_t afi = 0
    cdef unsigned char safi = 0
    cdef Py_ssize_t nh_start = -1, nh_end = -1, nlri_start = -1
    cdef Py_ssize_t nhlen
    cdef list prefixes = []
    cdef Py_ssize_t rc
    cdef Py_ssize_t host_bits = 0
    cdef bytes nexthop = b'', nexthop_local = b''

    if _bgp_mp_reach_hdr(mv, vs, ve, &afi, &safi, &nh_start, &nh_end,
                         &nlri_start) < 0:
        _fault(m.errors, ATTR_MP_REACH, REASON_LENGTH,
               'MP_REACH_NLRI too short for its AFI/SAFI header')
        return 0
    if nh_start < 0 or nh_end > ve or nlri_start < 0:
        _fault(m.errors, ATTR_MP_REACH, REASON_LENGTH,
               'MP_REACH_NLRI next-hop field is truncated')
        return 0
    if not _family_ok(ctx, afi, safi):
        # L-3: a family we do not carry, or did not negotiate with this
        # peer. Recorded under its own reason, which the matrix answers by
        # ignoring the attribute: the NLRI is not ours to take but the
        # message is otherwise well formed, and a session must not drop
        # because a peer offered us VPNv4. Filed as a bad value it used to
        # reset the session, which gave every peer a reset button.
        _fault(m.errors, ATTR_MP_REACH, REASON_UNNEGOTIATED,
               'unnegotiated AFI/SAFI %d/%d' % (afi, safi))
        return 0
    nhlen = nh_end - nh_start
    if afi == PFX_AFI_IP and nhlen == 4:
        nexthop = msg[nh_start:nh_end]
    elif afi == PFX_AFI_IP6 and nhlen == 16:
        nexthop = msg[nh_start:nh_end]
    elif afi == PFX_AFI_IP6 and nhlen == 32:
        nexthop = msg[nh_start:nh_start + 16]
        nexthop_local = msg[nh_start + 16:nh_end]
    else:
        _fault(m.errors, ATTR_MP_REACH, REASON_LENGTH,
               'MP_REACH_NLRI next-hop length %d is not valid for AFI %d'
               % (nhlen, afi))
        return 0
    rc = _read_nlri(mv, nlri_start, ve,
                    ctx._add_path_for(afi, safi), <unsigned char>afi,
                    prefixes, &host_bits)
    m.host_bits += host_bits
    if rc < 0:
        # RFC 7606 s5.1: when the NLRI cannot be extracted from MP_REACH
        # there is nothing to withdraw and no way to know what was meant,
        # so this is one of the few remaining session resets.
        _fault(m.errors, ATTR_MP_REACH, REASON_UNPARSEABLE,
               'MP_REACH_NLRI prefixes are unparseable')
        return 0
    a.nexthop = nexthop
    a.nexthop_local = nexthop_local
    m.mp_reach = (afi, safi, nexthop, nexthop_local, prefixes)
    return 0


cdef int _decode_mp_unreach(const unsigned char[:] mv, DecodeCtx ctx,
                            UpdateMsg m, Py_ssize_t vs,
                            Py_ssize_t ve) except -1:
    """Decode MP_UNREACH_NLRI (RFC 4760)."""
    cdef uint16_t afi = 0
    cdef unsigned char safi = 0
    cdef Py_ssize_t nlri_start = -1
    cdef list prefixes = []
    cdef Py_ssize_t rc
    cdef Py_ssize_t host_bits = 0

    if _bgp_mp_unreach_hdr(mv, vs, ve, &afi, &safi, &nlri_start) < 0:
        _fault(m.errors, ATTR_MP_UNREACH, REASON_LENGTH,
               'MP_UNREACH_NLRI too short for its AFI/SAFI header')
        return 0
    if not _family_ok(ctx, afi, safi):
        _fault(m.errors, ATTR_MP_UNREACH, REASON_UNNEGOTIATED,
               'unnegotiated AFI/SAFI %d/%d' % (afi, safi))
        return 0
    rc = _read_nlri(mv, nlri_start, ve,
                    ctx._add_path_for(afi, safi), <unsigned char>afi,
                    prefixes, &host_bits)
    m.host_bits += host_bits
    if rc < 0:
        _fault(m.errors, ATTR_MP_UNREACH, REASON_UNPARSEABLE,
               'MP_UNREACH_NLRI prefixes are unparseable')
        return 0
    m.mp_unreach = (afi, safi, prefixes)
    return 0


# --- Encoders ---------------------------------------------------------------
# Everything is written into a pooled PktWriter and taken out once, rather
# than built as a tree of bytes objects and joined. That is the same rule
# the rest of the library follows (see the PktWriter comment in
# inetpkt.pxd), and it matters more here than anywhere else: a full-table
# advertisement is tens of thousands of messages.

cdef inline int _w_header(PktWriter w, unsigned char mtype) except -1:
    """Write the 19-byte header with a placeholder length."""
    cdef int i
    for i in range(16):
        w_u8(w, 0xff)
    w_u16(w, 0)          # length, patched by _w_finish
    w_u8(w, mtype)
    return 0


cdef inline bytes _w_finish(PktWriter w, Py_ssize_t start):
    """Patch the length field and take the message out of the writer."""
    cdef Py_ssize_t total = w.n - start
    w_set_u16(w, start + 16, <uint16_t>total)
    return w_take(w, start)


def encode_keepalive():
    """Encode a KEEPALIVE.

    It is always the same 19 bytes, so it is built once at import and
    handed out. A session at the RFC minimum hold time sends one every
    second per peer, and there is no reason for any of them to allocate.

    :return: the KEEPALIVE message.
    """
    return _KEEPALIVE


def encode_notification(int code, int subcode, bytes data=b''):
    """Encode a NOTIFICATION.

    :param code: the RFC 4271 error code.
    :param subcode: the error subcode.
    :param data: diagnostic payload; truncated if it would push the message
        past the 4096-byte floor, because a NOTIFICATION that cannot be
        sent is worse than one missing its diagnostic tail.
    :return: the NOTIFICATION message.
    """
    cdef PktWriter w = w_acquire()
    cdef Py_ssize_t start = w.n
    cdef Py_ssize_t room = BGP_MAX_MSG - BGP_HEADER_LEN - 2

    try:
        if len(data) > room:
            data = data[:room]
        _w_header(w, MSG_NOTIFICATION)
        w_u8(w, <unsigned char>code)
        w_u8(w, <unsigned char>subcode)
        if data:
            w_bytes(w, data)
        return _w_finish(w, start)
    finally:
        w_release(w)


def encode_route_refresh(int afi, int safi, int subtype=0):
    """Encode a ROUTE-REFRESH.

    :param afi: address family.
    :param safi: subsequent address family.
    :param subtype: 0 for a plain RFC 2918 request, or the RFC 7313
        BoRR (1) / EoRR (2) demarcation.
    :return: the ROUTE-REFRESH message.
    """
    cdef PktWriter w = w_acquire()
    cdef Py_ssize_t start = w.n

    try:
        _w_header(w, MSG_ROUTE_REFRESH)
        w_u16(w, <uint16_t>afi)
        w_u8(w, <unsigned char>subtype)
        w_u8(w, <unsigned char>safi)
        return _w_finish(w, start)
    finally:
        w_release(w)


def encode_open(my_as, hold_time, bgp_id, capabilities=(),
                bint extended=False):
    """Encode an OPEN.

    An OPEN is never allowed past 4096 bytes, whatever was negotiated --
    Extended Message cannot apply to the message that negotiates it (RFC
    8654 s3). Capabilities are emitted one per optional parameter, which is
    what FRR and every widely deployed implementation does and what the
    most conservative receivers expect.

    W-2: every length is range-checked before it is written. They used to
    be cast to one octet unchecked, so a large capability -- ADD-PATH grows
    four bytes per family -- silently wrapped and the OPEN described
    something else. A capability value has one length octet and RFC 7911
    s4 keeps all of ADD-PATH in one instance, so nothing is split: a value
    that does not fit raises. So does an optional-parameter block over 255
    bytes unless ``extended`` is set, because RFC 9072's extended format is
    only safe towards a peer that understands it -- and the OPEN is the
    message sent before anything is known about the peer.

    :param my_as: our AS. Written as AS_TRANS in the header when it does
        not fit in 16 bits, with the real value in the 4-octet AS
        capability, per RFC 6793.
    :param hold_time: proposed hold time in seconds.
    :param bgp_id: our router id, as a 32-bit integer or a dotted quad.
    :param capabilities: an iterable of ``(code, value_bytes)``.
    :param extended: allow RFC 9072's extended optional parameters when the
        block does not fit in 255 bytes. Classic encoding is still used
        whenever it fits, as RFC 9072 s2 asks.
    :return: the OPEN message.
    :raises ValueError: a capability value is over 255 bytes; the
        parameters need the extended format and ``extended`` is false; or
        the message would exceed 4096 bytes.
    """
    cdef PktWriter w
    cdef Py_ssize_t start, params_len, vlen
    cdef bytearray params = bytearray()
    cdef list caps = []
    cdef bint use_ext = 0
    cdef bytes out, cap

    for code, value in capabilities:
        vlen = len(value)
        if vlen > 255:
            raise ValueError(
                'capability %d is %d bytes; a capability value has a one-'
                'octet length%s' % (code, vlen,
                                    ' and RFC 7911 keeps ADD-PATH in one '
                                    'instance' if code == _CAP_ADD_PATH
                                    else ''))
        caps.append(bytes(bytearray([code & 0xff, vlen])) + bytes(value))
    # Classic form first: a parameter holds one capability, so each needs
    # its value plus two header bytes to fit the parameter's length octet.
    for cap in caps:
        if len(cap) > 255:
            use_ext = 1
        params.append(2)
        params.append(len(cap) & 0xff)
        params += cap
    if use_ext or len(params) > 255:
        if not extended:
            raise ValueError(
                'the optional parameters need %d bytes; more than 255 needs '
                'RFC 9072 extended parameters, which a peer that does not '
                'support them misreads' % len(params))
        use_ext = 1
        params = bytearray()
        for cap in caps:
            params.append(2)
            params.append((len(cap) >> 8) & 0xff)
            params.append(len(cap) & 0xff)
            params += cap
    params_len = len(params)

    w = w_acquire()
    start = w.n
    try:
        _w_header(w, MSG_OPEN)
        w_u8(w, BGP_VERSION)
        w_u16(w, <uint16_t>(my_as if my_as <= 0xffff else AS_TRANS))
        w_u16(w, <uint16_t>hold_time)
        w_u32(w, <uint32_t>_router_id(bgp_id))
        if not use_ext:
            w_u8(w, <unsigned char>params_len)
        else:
            # RFC 9072: a Non-Ext OP Len of 255 followed by a Non-Ext OP
            # Type of 255 announces the two-octet extended length, and
            # every parameter after it has a two-octet length too. The
            # first 255 must be non-zero and is otherwise ignored.
            if params_len > 0xffff:
                raise ValueError('optional parameters of %d bytes do not '
                                 'fit even the extended format'
                                 % params_len)
            w_u8(w, 255)
            w_u8(w, 255)
            w_u16(w, <uint16_t>params_len)
        if params_len:
            w_bytes(w, bytes(params))
        out = _w_finish(w, start)
    finally:
        w_release(w)
    if len(out) > BGP_MAX_MSG:
        raise ValueError('OPEN would be %d bytes; RFC 8654 caps it at %d '
                         'regardless of Extended Message'
                         % (len(out), BGP_MAX_MSG))
    return out


cdef uint32_t _router_id(value) except? 0:
    """Accept a router id as an int or a dotted quad."""
    cdef list parts
    if isinstance(value, str):
        parts = value.split('.')
        if len(parts) != 4:
            raise ValueError('router id %r is not a dotted quad' % value)
        return ((int(parts[0]) << 24) | (int(parts[1]) << 16) |
                (int(parts[2]) << 8) | int(parts[3]))
    if isinstance(value, (bytes, bytearray)) and len(value) == 4:
        return ((value[0] << 24) | (value[1] << 16) | (value[2] << 8) |
                value[3])
    return <uint32_t>value


cdef int _w_attr_hdr(PktWriter w, unsigned char flags, unsigned char atype,
                     Py_ssize_t vlen) except -1:
    """Write an attribute header, widening the length field if needed."""
    if vlen > 255:
        flags |= AFLAG_EXT_LEN
    w_u8(w, flags)
    w_u8(w, atype)
    if flags & AFLAG_EXT_LEN:
        w_u16(w, <uint16_t>vlen)
    else:
        w_u8(w, <unsigned char>vlen)
    return 0


cdef int _w_attrs(PktWriter w, AttrSet a, bint as4, bint with_nexthop,
                  bint is_ebgp) except -1:
    """Write the path attributes of an announcement.

    Attributes are emitted in ascending type order. Nothing requires that,
    but a deterministic order means two encoders fed the same attribute set
    produce the same bytes, which is what makes the Stage-4 update groups'
    "encode once, send to many" verifiable and what makes a round-trip test
    a byte comparison rather than a semantic one.

    :param w: the writer.
    :param a: the attribute set.
    :param as4: the session carries 4-octet ASNs.
    :param with_nexthop: emit the IPv4 NEXT_HOP attribute. False when the
        next hop belongs in MP_REACH instead.
    :param is_ebgp: the peer is external, so LOCAL_PREF must not be sent.
    :return: 0.
    """
    cdef bytes path
    cdef bint needs_as4 = 0
    # Unrecognised transitive attributes, sorted by type so they slot in
    # among ours (W-10). Empty for nearly every route, so the cost is one
    # truth test.
    cdef list unknown = _split_unknown(a.unknown) if a.unknown else None
    cdef Py_ssize_t ui = 0

    if unknown is not None:
        ui = _w_unknown_below(w, unknown, ui, ATTR_ORIGIN)
    w_u8(w, AFLAG_TRANSITIVE)
    w_u8(w, ATTR_ORIGIN)
    w_u8(w, 1)
    w_u8(w, a.origin)

    if as4:
        path = a.as_path
    else:
        path = _downgrade_as_path(a.as_path, &needs_as4)
    _w_attr_hdr(w, AFLAG_TRANSITIVE, ATTR_AS_PATH, len(path))
    if path:
        w_bytes(w, path)

    if with_nexthop and a.nexthop and len(a.nexthop) == 4:
        w_u8(w, AFLAG_TRANSITIVE)
        w_u8(w, ATTR_NEXT_HOP)
        w_u8(w, 4)
        w_bytes(w, a.nexthop)

    if a.flags & ATTRF_MED:
        w_u8(w, AFLAG_OPTIONAL)
        w_u8(w, ATTR_MED)
        w_u8(w, 4)
        w_u32(w, a.med)

    # LOCAL_PREF is internal-only. Sending it to an eBGP peer would leak
    # our internal preference and is forbidden by RFC 4271 s5.1.5.
    if (a.flags & ATTRF_LOCAL_PREF) and not is_ebgp:
        w_u8(w, AFLAG_TRANSITIVE)
        w_u8(w, ATTR_LOCAL_PREF)
        w_u8(w, 4)
        w_u32(w, a.local_pref)

    if a.flags & ATTRF_ATOMIC_AGGREGATE:
        w_u8(w, AFLAG_TRANSITIVE)
        w_u8(w, ATTR_ATOMIC_AGGREGATE)
        w_u8(w, 0)

    if a.aggregator and len(a.aggregator) == 8:
        if as4:
            _w_attr_hdr(w, AFLAG_OPTIONAL | AFLAG_TRANSITIVE,
                        ATTR_AGGREGATOR, 8)
            w_bytes(w, a.aggregator)
        else:
            _w_attr_hdr(w, AFLAG_OPTIONAL | AFLAG_TRANSITIVE,
                        ATTR_AGGREGATOR, 6)
            if (a.aggregator[0] or a.aggregator[1]):
                w_u16(w, AS_TRANS)
                needs_as4 = 1
            else:
                w_bytes(w, a.aggregator[2:4])
            w_bytes(w, a.aggregator[4:8])

    if a.communities:
        _w_attr_hdr(w, AFLAG_OPTIONAL | AFLAG_TRANSITIVE, ATTR_COMMUNITIES,
                    len(a.communities))
        w_bytes(w, a.communities)

    if (a.flags & ATTRF_ORIGINATOR_ID) and not is_ebgp:
        w_u8(w, AFLAG_OPTIONAL)
        w_u8(w, ATTR_ORIGINATOR_ID)
        w_u8(w, 4)
        w_u32(w, a.originator_id)

    if a.cluster_list and not is_ebgp:
        _w_attr_hdr(w, AFLAG_OPTIONAL, ATTR_CLUSTER_LIST,
                    len(a.cluster_list))
        w_bytes(w, a.cluster_list)

    if unknown is not None:
        # Everything we emit from here on is type 16 or above.
        ui = _w_unknown_below(w, unknown, ui, ATTR_EXT_COMMUNITIES)

    if a.ext_communities:
        _w_attr_hdr(w, AFLAG_OPTIONAL | AFLAG_TRANSITIVE,
                    ATTR_EXT_COMMUNITIES, len(a.ext_communities))
        w_bytes(w, a.ext_communities)

    if needs_as4:
        # The peer is a 2-octet speaker and the path holds an AS it cannot
        # represent, so the true path rides alongside in AS4_PATH.
        _w_attr_hdr(w, AFLAG_OPTIONAL | AFLAG_TRANSITIVE, ATTR_AS4_PATH,
                    len(a.as_path))
        if a.as_path:
            w_bytes(w, a.as_path)
        if a.aggregator and len(a.aggregator) == 8 and (a.aggregator[0] or
                                                        a.aggregator[1]):
            _w_attr_hdr(w, AFLAG_OPTIONAL | AFLAG_TRANSITIVE,
                        ATTR_AS4_AGGREGATOR, 8)
            w_bytes(w, a.aggregator)

    if unknown is not None:
        ui = _w_unknown_below(w, unknown, ui, ATTR_LARGE_COMMUNITY)

    if a.large_communities:
        _w_attr_hdr(w, AFLAG_OPTIONAL | AFLAG_TRANSITIVE,
                    ATTR_LARGE_COMMUNITY, len(a.large_communities))
        w_bytes(w, a.large_communities)

    if unknown is not None:
        _w_unknown_below(w, unknown, ui, 256)
    return 0


cdef list _split_unknown(bytes blob):
    """Split the stored unknown-attribute TLVs into ``(type, tlv)``, sorted.

    They are stored in arrival order, which is whatever the peer sent.
    Sorting is stable, so two of the same type -- which the decoder never
    produces, but a hand-built AttrSet could -- keep their order.
    """
    cdef list out = []
    cdef const unsigned char[:] mv = blob
    cdef Py_ssize_t o = 0, n = len(blob), hdr, vlen
    while o + 3 <= n:
        if mv[o] & AFLAG_EXT_LEN:
            if o + 4 > n:
                break
            hdr = 4
            vlen = (<Py_ssize_t>mv[o + 2] << 8) | mv[o + 3]
        else:
            hdr = 3
            vlen = mv[o + 2]
        out.append((<int>mv[o + 1], blob[o:o + hdr + vlen]))
        o += hdr + vlen
    out.sort(key=_first)
    return out


def _first(item):
    return item[0]


cdef Py_ssize_t _w_unknown_below(PktWriter w, list unknown, Py_ssize_t ui,
                                 int below) except -1:
    """Write the sorted unknown attributes whose type is below ``below``.

    :return: the index of the first one not yet written.
    """
    cdef Py_ssize_t n = len(unknown)
    while ui < n and <int>(<tuple>unknown[ui])[0] < below:
        w_bytes(w, <bytes>(<tuple>unknown[ui])[1])
        ui += 1
    return ui


cdef inline int _w_prefix(PktWriter w, Prefix p, uint32_t path_id,
                          bint add_path) except -1:
    """Write one NLRI entry in its truncated wire form."""
    if add_path:
        w_u32(w, path_id)
    w_u8(w, p.plen)
    w_raw(w, &p.addr[0], _nlri_addr_bytes(p.plen))
    return 0


cdef inline Py_ssize_t _prefix_wire_len(Prefix p, bint add_path):
    """Bytes one NLRI entry will occupy, for the split arithmetic."""
    return 1 + _nlri_addr_bytes(p.plen) + (4 if add_path else 0)


def encode_withdraw(prefixes, int afi=PFX_AFI_IP, int safi=1,
                    Py_ssize_t max_size=BGP_MAX_MSG, bint add_path=False):
    """Encode withdrawals, splitting across as many UPDATEs as needed.

    IPv4 unicast withdrawals go in the UPDATE's own withdrawn-routes field;
    every other family goes in an MP_UNREACH_NLRI attribute. Both are
    produced here so a caller does not branch on the family.

    :param prefixes: an iterable of ``Prefix`` or ``(Prefix, path_id)``.
    :param afi: address family.
    :param safi: subsequent address family.
    :param max_size: the session's message ceiling.
    :param add_path: prepend RFC 7911 path identifiers.
    :return: a list of UPDATE messages, possibly empty.
    """
    cdef list items = _as_pairs(prefixes)
    cdef list out = []
    cdef Py_ssize_t i = 0, n = len(items)
    cdef Py_ssize_t budget, used, start, lenpos, attrlenpos
    cdef PktWriter w
    cdef Prefix p
    cdef uint32_t pid
    cdef object item

    if n == 0:
        return out
    while i < n:
        w = w_acquire()
        start = w.n
        try:
            _w_header(w, MSG_UPDATE)
            if afi == PFX_AFI_IP and safi == 1:
                lenpos = w.n
                w_u16(w, 0)
                # header + withdrawn length + the empty attribute length
                budget = max_size - BGP_HEADER_LEN - 4
                used = 0
                while i < n:
                    item = items[i]
                    if isinstance(item, Prefix):
                        p = <Prefix>item
                        pid = 0
                    else:
                        p = <Prefix>(<tuple>item)[0]
                        pid = (<tuple>item)[1]
                    if used + _prefix_wire_len(p, add_path) > budget:
                        break
                    _w_prefix(w, p, pid, add_path)
                    used += _prefix_wire_len(p, add_path)
                    i += 1
                if used == 0:
                    # One prefix alone does not fit the negotiated size.
                    # That cannot happen for unicast at 4096 and would be a
                    # silent infinite loop if it ever did.
                    raise ValueError('a single withdrawal does not fit in '
                                     'the %d-byte message limit' % max_size)
                w_set_u16(w, lenpos, <uint16_t>used)
                w_u16(w, 0)          # total path attribute length
            else:
                w_u16(w, 0)          # no IPv4 withdrawals
                lenpos = w.n
                w_u16(w, 0)          # total path attribute length
                # MP_UNREACH is always written with the extended length
                # field: the split loop has to reserve the header before it
                # knows how many prefixes fit, and a one-byte length that
                # later needed two would mean moving every byte after it.
                w_u8(w, AFLAG_OPTIONAL | AFLAG_EXT_LEN)
                w_u8(w, ATTR_MP_UNREACH)
                attrlenpos = w.n
                w_u16(w, 0)
                w_u16(w, <uint16_t>afi)
                w_u8(w, <unsigned char>safi)
                budget = max_size - BGP_HEADER_LEN - 4 - 4 - 3
                used = 0
                while i < n:
                    item = items[i]
                    if isinstance(item, Prefix):
                        p = <Prefix>item
                        pid = 0
                    else:
                        p = <Prefix>(<tuple>item)[0]
                        pid = (<tuple>item)[1]
                    if used + _prefix_wire_len(p, add_path) > budget:
                        break
                    _w_prefix(w, p, pid, add_path)
                    used += _prefix_wire_len(p, add_path)
                    i += 1
                if used == 0:
                    raise ValueError('a single withdrawal does not fit in '
                                     'the %d-byte message limit' % max_size)
                w_set_u16(w, attrlenpos, <uint16_t>(used + 3))
                w_set_u16(w, lenpos, <uint16_t>(used + 3 + 4))
            out.append(_w_finish(w, start))
        finally:
            w_release(w)
    return out


def encode_announce(prefixes, AttrSet attrs, int afi=PFX_AFI_IP, int safi=1,
                    Py_ssize_t max_size=BGP_MAX_MSG, bint as4=True,
                    bint add_path=False, bint is_ebgp=True,
                    bytes nexthop=None):
    """Encode announcements, splitting across as many UPDATEs as needed.

    Every message repeats the full attribute set, because that is what an
    UPDATE means: one attribute set applying to the NLRI in that message.
    The split is therefore "as many prefixes as fit after the attributes",
    and a message whose attributes alone exceed the limit is an error the
    caller must fix rather than something to silently truncate.

    :param prefixes: an iterable of ``Prefix`` or ``(Prefix, path_id)``.
    :param attrs: the attribute set to advertise them with.
    :param afi: address family.
    :param safi: subsequent address family.
    :param max_size: the session's message ceiling.
    :param as4: the session carries 4-octet ASNs.
    :param add_path: prepend RFC 7911 path identifiers.
    :param is_ebgp: suppress internal-only attributes.
    :param nexthop: override the attribute set's next hop, for
        next-hop-self. Must match the family's address width.
    :return: a list of UPDATE messages, possibly empty.
    :raises ValueError: the attributes alone do not fit ``max_size``.
    """
    cdef list items = _as_pairs(prefixes)
    cdef list out = []
    cdef Py_ssize_t i = 0, n = len(items)
    # mpstart is only meaningful when `mp`; initialised so that gcc can see
    # it is never read unset (W-12), which it cannot prove through the two
    # separate `if mp` tests that bracket its use.
    cdef Py_ssize_t start, lenpos, attrlenpos, mpstart = -1, used, budget
    cdef Py_ssize_t attrs_len
    cdef PktWriter w
    cdef Prefix p
    cdef uint32_t pid
    cdef object item
    cdef bytes nh
    cdef bint mp = not (afi == PFX_AFI_IP and safi == 1)

    if n == 0:
        return out
    nh = nexthop if nexthop is not None else attrs.nexthop
    if mp and not nh:
        raise ValueError('MP_REACH_NLRI needs a next hop for AFI %d' % afi)
    if mp and nh.count(0) == len(nh):
        # L-4: never `::`. It reached the wire for every IPv6 route over an
        # IPv4 session, and peers drop it as a martian. The Adj-RIB-Out no
        # longer produces it; this is the last line, and a refused message
        # is counted there rather than sent.
        raise ValueError('MP_REACH_NLRI next hop for AFI %d is the '
                         'unspecified address' % afi)

    while i < n:
        w = w_acquire()
        start = w.n
        try:
            _w_header(w, MSG_UPDATE)
            w_u16(w, 0)                      # no IPv4 withdrawals
            lenpos = w.n
            w_u16(w, 0)                      # total path attribute length
            attrlenpos = w.n
            # Ordering here is load-bearing. MP_REACH_NLRI is one
            # attribute whose *value* ends with the NLRI, so the NLRI has
            # to be the last thing written and MP_REACH has to be the last
            # attribute opened. Writing ORIGIN and AS_PATH after the
            # MP_REACH header instead puts them inside its value, and the
            # length patched in at the end then covers them too -- which
            # produces a message that decodes as a malformed MP_REACH and
            # costs the session. IPv4 unicast has the opposite shape: its
            # NLRI lives outside the attribute block entirely.
            _w_attrs(w, attrs, as4, not mp, is_ebgp)
            if mp:
                w_u8(w, AFLAG_OPTIONAL | AFLAG_EXT_LEN)
                w_u8(w, ATTR_MP_REACH)
                mpstart = w.n
                w_u16(w, 0)
                w_u16(w, <uint16_t>afi)
                w_u8(w, <unsigned char>safi)
                w_u8(w, <unsigned char>len(nh))
                w_bytes(w, nh)
                w_u8(w, 0)                   # reserved
            attrs_len = w.n - attrlenpos
            budget = max_size - (w.n - start)
            if budget <= 0:
                raise ValueError('path attributes alone are %d bytes, over '
                                 'the %d-byte message limit'
                                 % (attrs_len, max_size))
            used = 0
            while i < n:
                item = items[i]
                if isinstance(item, Prefix):
                    p = <Prefix>item
                    pid = 0
                else:
                    p = <Prefix>(<tuple>item)[0]
                    pid = (<tuple>item)[1]
                if used + _prefix_wire_len(p, add_path) > budget:
                    break
                _w_prefix(w, p, pid, add_path)
                used += _prefix_wire_len(p, add_path)
                i += 1
            if used == 0:
                raise ValueError('no prefix fits alongside %d bytes of path '
                                 'attributes in a %d-byte message'
                                 % (attrs_len, max_size))
            if mp:
                # The NLRI is inside MP_REACH, so both its length and the
                # total attribute length grow with it.
                w_set_u16(w, mpstart, <uint16_t>(w.n - mpstart - 2))
                w_set_u16(w, lenpos, <uint16_t>(w.n - attrlenpos))
            else:
                w_set_u16(w, lenpos, <uint16_t>attrs_len)
            out.append(_w_finish(w, start))
        finally:
            w_release(w)
    return out


def encode_end_of_rib(int afi=PFX_AFI_IP, int safi=1):
    """Encode the RFC 4724 End-of-RIB marker for one family.

    :param afi: address family.
    :param safi: subsequent address family.
    :return: the UPDATE message.
    """
    cdef PktWriter w = w_acquire()
    cdef Py_ssize_t start = w.n

    try:
        _w_header(w, MSG_UPDATE)
        w_u16(w, 0)
        if afi == PFX_AFI_IP and safi == 1:
            # For IPv4 unicast the marker is a completely empty UPDATE.
            w_u16(w, 0)
        else:
            # For anything else it is an MP_UNREACH naming the family and
            # carrying no prefixes.
            w_u16(w, 6)
            w_u8(w, AFLAG_OPTIONAL)
            w_u8(w, ATTR_MP_UNREACH)
            w_u8(w, 3)
            w_u16(w, <uint16_t>afi)
            w_u8(w, <unsigned char>safi)
        return _w_finish(w, start)
    finally:
        w_release(w)


cdef list _as_pairs(prefixes):
    """Normalise a prefix iterable to a list of ``Prefix`` (path id 0) or
    ``(Prefix, path_id)``."""
    cdef list out = []

    # A bare Prefix is kept as it is, not wrapped as (prefix, 0): the
    # encoders branch on the item type instead. A tuple per prefix, built
    # here and indexed generically there, was most of the per-prefix cost
    # of a full-table advertisement. Pairs are typed here, so a bad item
    # fails before any of the UPDATE is written.
    for item in prefixes:
        if isinstance(item, Prefix):
            out.append(item)
        else:
            out.append((<Prefix?>item[0], <uint32_t>item[1]))
    return out


# Built once: see encode_keepalive.
cdef bytes _build_keepalive():
    cdef PktWriter w = w_acquire()
    cdef Py_ssize_t start = w.n
    try:
        _w_header(w, MSG_KEEPALIVE)
        return _w_finish(w, start)
    finally:
        w_release(w)


_KEEPALIVE = _build_keepalive()
