#!/usr/bin/env python3
"""A minimal MRT TABLE_DUMP_V2 reader, and an UPDATE stream built from it.

The routing benchmarks need a *real* table, not a generated one. A synthetic
stream can be made arbitrarily large but it cannot be made representative:
its prefixes are evenly spread where a real table is clumped, and -- much
more importantly for this engine -- every path in it shares one attribute
set, where a real table has tens of thousands of distinct ones over roughly
a million paths. Attribute interning is a load-bearing part of the design,
and a corpus with one attribute set would make interning look free and the
bytes-per-path budget look trivially met.

So this module reads the public MRT archives (RFC 6396 TABLE_DUMP_V2), the
format RouteViews and RIPE RIS both publish, and turns one collector peer's
view into a stream of BGP UPDATE messages.

Three things about the format are worth knowing before reading the code,
because each of them will silently produce a wrong answer rather than an
error if it is got wrong:

1. **A RIB dump is not an UPDATE stream.** Each record holds a prefix and,
   for every peer of the collector, that peer's path attributes for it. The
   attributes are already in ordinary BGP attribute encoding, so rebuilding
   real UPDATEs out of them is faithful rather than approximate -- which is
   what makes it fair to hand the same bytes to another implementation's
   parser and compare.

2. **One dump holds many peers' tables at once.** A collector with 20-odd
   full-table peers holds 20-odd million paths for about a million
   prefixes. Feeding all of them to a benchmark that reports "prefixes/s"
   would inflate every number by the peer count. This reader therefore
   takes exactly one peer, and says which one it took.

3. **TABLE_DUMP_V2 AS_PATHs are always 4-octet**, whatever the original
   session negotiated (RFC 6396 s4.3.4). A decoder told otherwise parses
   garbage ASNs without complaining, because a 2-octet reading of 4-octet
   ASNs is still structurally valid.

The IPv6 half needs one more step. RouteViews' main collector carries only
IPv4; IPv6 lives on a separate IPv6-peered collector, and in its records
the prefix appears **twice**: in the record header, and again inside the
stored MP_REACH_NLRI attribute. That second copy is what makes every IPv6
attribute block unique, and normalising it away is not cosmetic. Left in,
it would report a million distinct attribute sets for a million paths --
turning a corpus chosen *because* it exercises attribute interning into one
that cannot exercise it at all, and one prefix per UPDATE instead of the
hundreds a real speaker packs. So MP_REACH is stripped at load time, its
next hop kept, and a fresh MP_REACH is built around our own NLRI when the
messages are assembled -- which is exactly what a speaker does when it
re-advertises, so the result is a real message rather than a doctored one.

Usage as a command, to inspect a corpus before benchmarking against it::

    PYTHONPATH=. python3 bench/mrt.py /path/to/rib.20260918.2200.bz2
    PYTHONPATH=. python3 bench/mrt.py --afi 6 --limit 200000 /path/to/rib6.bz2

`bench/rtengine_bench.py --corpus FILE` is the real consumer.

The corpora themselves are not in the repository and never should be. They
are fetched from the public archives, whose layout is stable::

    https://routeviews.org/route-views2/bgpdata/YYYY.MM/RIBS/rib.*.bz2
    https://routeviews.org/route-views6/bgpdata/YYYY.MM/RIBS/rib.*.bz2
    https://data.ris.ripe.net/rrcNN/YYYY.MM/bview.*.gz

and cached wherever ``PACKETS_MRT_CACHE`` points. Note that the main
RouteViews collector carries IPv4 only; its IPv6 table is a separate,
IPv6-peered collector, which is why an IPv6 benchmark names a second file
rather than a second address family of the first.
"""

from __future__ import print_function

import argparse
import bz2
import collections
import gzip
import os
import struct
import sys
import time

# MRT record types and TABLE_DUMP_V2 subtypes (RFC 6396 s4.3, s5).
MRT_TABLE_DUMP_V2 = 13

ST_PEER_INDEX_TABLE = 1
ST_RIB_IPV4_UNICAST = 2
ST_RIB_IPV4_MULTICAST = 3
ST_RIB_IPV6_UNICAST = 4
ST_RIB_IPV6_MULTICAST = 5
ST_RIB_GENERIC = 6
# RFC 8050 added ADD-PATH forms of each of the above. We do not consume them
# -- one path per prefix per peer is what the benchmark wants -- but they
# must be recognised, because their entry layout differs by a 4-byte path id
# and parsing one as its non-ADD-PATH twin yields plausible nonsense.
ST_RIB_IPV4_UNICAST_ADDPATH = 8
ST_RIB_IPV4_MULTICAST_ADDPATH = 9
ST_RIB_IPV6_UNICAST_ADDPATH = 10
ST_RIB_IPV6_MULTICAST_ADDPATH = 11

ADDPATH_SUBTYPES = frozenset((
    ST_RIB_IPV4_UNICAST_ADDPATH, ST_RIB_IPV4_MULTICAST_ADDPATH,
    ST_RIB_IPV6_UNICAST_ADDPATH, ST_RIB_IPV6_MULTICAST_ADDPATH))

SUBTYPE_FOR_AFI = {4: ST_RIB_IPV4_UNICAST, 6: ST_RIB_IPV6_UNICAST}

# BGP attribute types this module has to recognise in order to rewrite the
# multiprotocol ones. Everything else is copied through untouched, which is
# the point: the benchmark should decode the attributes a real peer sent,
# including the ones we have no opinion about.
ATTR_MP_REACH = 14
ATTR_MP_UNREACH = 15
AFLAG_OPTIONAL = 0x80
AFLAG_EXT_LEN = 0x10

AFI_IPV6 = 2
SAFI_UNICAST = 1

BGP_MARKER = b'\xff' * 16
BGP_UPDATE = 2
BGP_MAX_MSG = 4096

# Where a downloaded dump is kept. Deliberately not inside the checkout: a
# RIB dump is ~100 MB compressed and must never be committed. Overridable,
# because the path that suits a workstation does not suit a test host.
CACHE_ENV = 'PACKETS_MRT_CACHE'
DEFAULT_CACHE = os.path.join('~', '.cache', 'packets-mrt')


class MrtError(Exception):
    """A corpus that cannot be read as TABLE_DUMP_V2."""


def cache_dir():
    """Return the corpus cache directory.

    :return: an expanded path; not created.
    """
    return os.path.expanduser(os.environ.get(CACHE_ENV, DEFAULT_CACHE))


# --- container handling -----------------------------------------------------

def open_corpus(path):
    """Open a dump, decompressing by content rather than by file name.

    RouteViews publishes bzip2 and RIPE RIS publishes gzip, and a cached
    copy may have been decompressed already. Sniffing the magic bytes means
    all three work and a renamed file cannot mislead us.

    :param path: the dump.
    :return: a binary file object positioned at the first record.
    """
    handle = open(path, 'rb')
    magic = handle.read(3)
    handle.seek(0)
    if magic[:3] == b'BZh':
        handle.close()
        return bz2.BZ2File(path, 'rb')
    if magic[:2] == b'\x1f\x8b':
        handle.close()
        return gzip.GzipFile(path, 'rb')
    return handle


def iter_records(handle):
    """Yield every MRT record in a stream.

    :param handle: a binary file object.
    :return: an iterator of ``(timestamp, type, subtype, body)``.
    """
    read = handle.read
    unpack = struct.unpack
    while True:
        header = read(12)
        if not header:
            return
        if len(header) < 12:
            raise MrtError('truncated MRT header (%d bytes)' % len(header))
        stamp, rtype, subtype, length = unpack('!IHHI', header)
        body = read(length)
        if len(body) != length:
            raise MrtError('truncated MRT record: want %d, got %d'
                           % (length, len(body)))
        yield stamp, rtype, subtype, body


# --- the peer index ---------------------------------------------------------

class PeerEntry(object):
    """One peer of the collector, from the PEER_INDEX_TABLE."""

    __slots__ = ('index', 'bgp_id', 'addr', 'asn', 'is_ipv6')

    def __init__(self, index, bgp_id, addr, asn, is_ipv6):
        self.index = index
        self.bgp_id = bgp_id
        self.addr = addr
        self.asn = asn
        self.is_ipv6 = is_ipv6

    def addr_str(self):
        """Render the peer address.

        :return: dotted quad or colon-separated hex.
        """
        if self.is_ipv6:
            parts = [('%02x%02x' % (self.addr[i], self.addr[i + 1]))
                     for i in range(0, 16, 2)]
            return ':'.join(parts)
        return '.'.join(str(b) for b in self.addr)

    def __repr__(self):
        return ('<peer %d %s AS%d>'
                % (self.index, self.addr_str(), self.asn))


def parse_peer_index(body):
    """Parse a PEER_INDEX_TABLE record.

    :param body: the record body.
    :return: ``(collector_bgp_id, view_name, [PeerEntry, ...])``.
    """
    off = 4
    collector = body[0:4]
    view_len, = struct.unpack_from('!H', body, off)
    off += 2
    view = bytes(body[off:off + view_len])
    off += view_len
    count, = struct.unpack_from('!H', body, off)
    off += 2

    peers = []
    for index in range(count):
        ptype = body[off]
        off += 1
        bgp_id = bytes(body[off:off + 4])
        off += 4
        # Bit 0 of the type byte selects the address width and bit 1 the AS
        # width, independently: a v4-addressed peer can have a 4-byte AS.
        is_ipv6 = bool(ptype & 1)
        width = 16 if is_ipv6 else 4
        addr = bytes(body[off:off + width])
        off += width
        if ptype & 2:
            asn, = struct.unpack_from('!I', body, off)
            off += 4
        else:
            asn, = struct.unpack_from('!H', body, off)
            off += 2
        peers.append(PeerEntry(index, bgp_id, addr, asn, is_ipv6))

    if off != len(body):
        raise MrtError('peer index table consumed %d of %d bytes'
                       % (off, len(body)))
    return collector, view, peers


# --- RIB entries ------------------------------------------------------------

def mp_reach_parts(value):
    """Split an MP_REACH_NLRI value into its next hop and its NLRI.

    :param value: the attribute value bytes.
    :return: ``(afi, safi, nexthop, nlri_bytes)``, or ``None`` if short.
    """
    if len(value) < 5:
        return None
    afi, safi, nh_len = struct.unpack_from('!HBB', value, 0)
    off = 4 + nh_len
    if off + 1 > len(value):
        return None
    nexthop = bytes(value[4:off])
    off += 1                     # the reserved byte
    return afi, safi, nexthop, bytes(value[off:])


def iter_rib_entries(body, add_path=False):
    """Walk the per-peer entries of one RIB record.

    :param body: the record body.
    :param add_path: whether the subtype carries a 4-byte path id per entry.
    :return: ``(plen, prefix_bytes, [(peer_index, orig_time, attrs), ...])``.
    """
    off = 4                      # sequence number, unused
    plen = body[off]
    off += 1
    nbytes = (plen + 7) >> 3
    prefix = bytes(body[off:off + nbytes])
    off += nbytes
    count, = struct.unpack_from('!H', body, off)
    off += 2

    entries = []
    for _ in range(count):
        peer_index, = struct.unpack_from('!H', body, off)
        off += 2
        orig_time, = struct.unpack_from('!I', body, off)
        off += 4
        if add_path:
            off += 4
        attr_len, = struct.unpack_from('!H', body, off)
        off += 2
        entries.append((peer_index, orig_time,
                        bytes(body[off:off + attr_len])))
        off += attr_len
    return plen, prefix, entries


def split_attributes(attrs):
    """Split an attribute block into its TLVs.

    :param attrs: the attribute bytes of one RIB entry.
    :return: a list of ``(flags, type, value_bytes)``.
    """
    out = []
    off = 0
    total = len(attrs)
    while off + 2 <= total:
        flags = attrs[off]
        atype = attrs[off + 1]
        off += 2
        if flags & AFLAG_EXT_LEN:
            if off + 2 > total:
                raise MrtError('truncated extended attribute length')
            length, = struct.unpack_from('!H', attrs, off)
            off += 2
        else:
            if off + 1 > total:
                raise MrtError('truncated attribute length')
            length = attrs[off]
            off += 1
        if off + length > total:
            raise MrtError('attribute %d overruns its block' % atype)
        out.append((flags, atype, bytes(attrs[off:off + length])))
        off += length
    return out


# --- corpus -----------------------------------------------------------------

class Corpus(object):
    """One peer's table, read out of a dump and held as raw material."""

    __slots__ = ('path', 'afi', 'peer', 'peers', 'collector', 'view',
                 'prefixes', 'peer_counts', 'read_seconds', 'records',
                 'truncated', 'mp_mismatch', 'no_mp_reach')

    def __init__(self):
        self.path = None
        self.afi = 4
        self.peer = None
        self.peers = []
        self.collector = b''
        self.view = b''
        # [(plen, prefix_bytes, attribute_bytes, nexthop_bytes)], in dump
        # order, which is ascending prefix order: the same order a real
        # full-table load arrives in, and the order the trie is least
        # happy about.
        #
        # For IPv4 the attribute bytes are exactly what the dump stored and
        # the next hop is empty, because NEXT_HOP is one of those bytes.
        # For IPv6 the multiprotocol attributes have been removed and their
        # next hop lifted out, so that two paths which differ only in the
        # prefix inside MP_REACH compare equal -- see the module docstring.
        self.prefixes = []
        self.peer_counts = collections.Counter()
        self.read_seconds = 0.0
        self.records = 0
        # Set when a --limit stopped the pass early. The per-peer counts are
        # then counts over a prefix of the dump, not over the dump, so the
        # "is this really the fullest peer" check must not fire on them.
        self.truncated = False
        # IPv6 paths whose MP_REACH NLRI disagreed with the record header,
        # and paths with no MP_REACH at all. Both are counted rather than
        # tolerated silently: either would mean the reader misunderstands
        # the dump, and a benchmark should say so instead of averaging it in.
        self.mp_mismatch = 0
        self.no_mp_reach = 0

    def __len__(self):
        return len(self.prefixes)

    def distinct_attrs(self):
        """Count distinct attribute blocks.

        This is the number attribute interning exists to exploit, and the
        ratio of paths to it is the honest statement of how much interning
        can possibly save on this corpus.

        :return: ``(distinct, total)``.
        """
        seen = set()
        for _plen, _prefix, attrs, nexthop in self.prefixes:
            seen.add((attrs, nexthop))
        return len(seen), len(self.prefixes)


def choose_peer(path, afi, sample=50000):
    """Pick the peer with the fullest table, from a sample of records.

    A collector's peers are not equivalent: some carry a full table, some
    carry a handful of routes, and one entry in the index is the collector
    itself. Taking the first peer, or the lowest index, would quietly
    benchmark a 30-route table.

    Sampling rather than counting the whole dump is deliberate -- a
    decompression pass over the whole file costs about as much as the
    benchmark it is preparing -- and it is safe because a full-table peer
    is full-table throughout. :func:`load` re-counts every peer as it goes
    and reports if the sample chose wrong, so the shortcut cannot hide.

    :param path: the dump.
    :param afi: 4 or 6.
    :param sample: how many RIB records to look at.
    :return: ``(peer_index, counts)``.
    """
    want = SUBTYPE_FOR_AFI[afi]
    counts = collections.Counter()
    seen = 0
    handle = open_corpus(path)
    try:
        for _stamp, rtype, subtype, body in iter_records(handle):
            if rtype != MRT_TABLE_DUMP_V2 or subtype != want:
                continue
            _plen, _prefix, entries = iter_rib_entries(body)
            for peer_index, _orig, _attrs in entries:
                counts[peer_index] += 1
            seen += 1
            if seen >= sample:
                break
    finally:
        handle.close()
    if not counts:
        raise MrtError('no IPv%d unicast RIB records in %s' % (afi, path))
    return counts.most_common(1)[0][0], counts


def load(path, afi=4, peer_index=None, limit=None, sample=50000,
         progress=None):
    """Read one peer's table out of a dump.

    :param path: the dump.
    :param afi: 4 or 6.
    :param peer_index: the peer to take, or ``None`` to choose the fullest.
    :param limit: stop after this many prefixes.
    :param sample: records to sample when choosing a peer.
    :param progress: optional callable taking a prefix count.
    :return: a :class:`Corpus`.
    """
    if afi not in SUBTYPE_FOR_AFI:
        raise MrtError('afi must be 4 or 6, not %r' % (afi,))
    want = SUBTYPE_FOR_AFI[afi]

    if peer_index is None:
        peer_index, _sampled = choose_peer(path, afi, sample)

    corpus = Corpus()
    corpus.path = path
    corpus.afi = afi

    start = time.time()
    handle = open_corpus(path)
    add_path_seen = 0
    try:
        for _stamp, rtype, subtype, body in iter_records(handle):
            if rtype != MRT_TABLE_DUMP_V2:
                continue
            if subtype == ST_PEER_INDEX_TABLE:
                (corpus.collector, corpus.view,
                 corpus.peers) = parse_peer_index(body)
                continue
            if subtype in ADDPATH_SUBTYPES:
                add_path_seen += 1
                continue
            if subtype != want:
                continue
            corpus.records += 1
            plen, prefix, entries = iter_rib_entries(body)
            for entry_peer, _orig, attrs in entries:
                corpus.peer_counts[entry_peer] += 1
                if entry_peer != peer_index:
                    continue
                if afi == 4:
                    corpus.prefixes.append((plen, prefix, attrs, b''))
                    continue
                plain, nexthop = _strip_mp(corpus, attrs, plen, prefix)
                if nexthop:
                    corpus.prefixes.append((plen, prefix, plain, nexthop))
            if progress is not None and not corpus.records % 100000:
                progress(len(corpus.prefixes))
            if limit is not None and len(corpus.prefixes) >= limit:
                corpus.truncated = True
                break
    finally:
        handle.close()
    corpus.read_seconds = time.time() - start

    for peer in corpus.peers:
        if peer.index == peer_index:
            corpus.peer = peer
            break

    if not corpus.prefixes:
        raise MrtError('peer index %d contributed no IPv%d routes'
                       % (peer_index, afi))
    if add_path_seen:
        print('note: skipped %d ADD-PATH records (not used by the benchmark)'
              % add_path_seen, file=sys.stderr)
    return corpus


def _strip_mp(corpus, attrs, plen, prefix):
    """Remove the multiprotocol attributes, returning the rest and the nexthop.

    :param corpus: the corpus being loaded, for its counters.
    :param attrs: the stored attribute bytes.
    :param plen: the record header's prefix length, for the cross-check.
    :param prefix: the record header's prefix bytes.
    :return: ``(plain_attribute_bytes, nexthop_bytes)``.
    """
    nexthop = b''
    keep = []
    for flags, atype, value in split_attributes(attrs):
        if atype == ATTR_MP_UNREACH:
            continue
        if atype == ATTR_MP_REACH:
            parts = mp_reach_parts(value)
            if parts is None:
                continue
            nexthop = parts[2]
            # The NLRI copy inside the attribute should name the same
            # prefix as the record header. Where it does not, the reader
            # has misread one of the two and the path is dropped rather
            # than guessed at.
            if parts[3] and parts[3] != _pack_prefix(plen, prefix):
                corpus.mp_mismatch += 1
                return b'', b''
            continue
        keep.append(_encode_attr(flags, atype, value))
    if not nexthop:
        corpus.no_mp_reach += 1
    return b''.join(keep), nexthop


# --- UPDATE synthesis -------------------------------------------------------

def _encode_attr(flags, atype, value):
    """Encode one attribute TLV, choosing the length form by size.

    :param flags: attribute flags, without the extended-length bit.
    :param atype: attribute type code.
    :param value: the value bytes.
    :return: the encoded attribute.
    """
    if len(value) > 255:
        return (struct.pack('!BBH', flags | AFLAG_EXT_LEN, atype, len(value))
                + value)
    return struct.pack('!BBB', flags & ~AFLAG_EXT_LEN, atype,
                       len(value)) + value


def _pack_prefix(plen, prefix):
    """Pack one NLRI entry.

    :param plen: prefix length in bits.
    :param prefix: the significant bytes, exactly as the dump stored them.
    :return: the encoded NLRI.
    """
    return bytes(bytearray([plen])) + prefix


def _message(body):
    """Wrap an UPDATE body in a BGP header.

    :param body: the UPDATE body.
    :return: a complete message.
    """
    return BGP_MARKER + struct.pack('!HB', 19 + len(body), BGP_UPDATE) + body


def build_updates(corpus, max_msg=BGP_MAX_MSG):
    """Turn a corpus into a back-to-back UPDATE stream.

    Prefixes sharing an attribute block are packed into one UPDATE until the
    message limit is reached, which is what a speaker does and what makes
    the message count realistic: a table that produced one UPDATE per prefix
    would measure header parsing, not attribute parsing.

    Attribute bytes are reused verbatim for IPv4. For IPv6 a fresh MP_REACH
    is built around each batch of NLRI, carrying the next hop the dump
    stored; every other attribute, including ones neither we nor the dump's
    author understood, is copied through untouched.

    :param corpus: a loaded :class:`Corpus`.
    :param max_msg: the session message limit to split at.
    :return: ``(stream_bytes, message_count, prefix_count)``.
    """
    chunks = []
    messages = 0
    packed = 0

    for (attrs, nexthop), members in _group_by_attrs(corpus.prefixes):
        if not nexthop:
            # IPv4: the attribute block is complete as stored, NEXT_HOP
            # included, and the NLRI goes after it.
            #   header + withdrawn-length + attribute-length + attributes
            room = max_msg - 19 - 2 - 2 - len(attrs)
            if room <= 0:
                raise MrtError('attribute block of %d bytes cannot fit in a '
                               '%d-byte message' % (len(attrs), max_msg))
            for nlri, count in _fill(members, room, _pack_prefix):
                body = (struct.pack('!H', 0) +
                        struct.pack('!H', len(attrs)) + attrs + nlri)
                chunks.append(_message(body))
                messages += 1
                packed += count
            continue

        # IPv6: rebuild MP_REACH around this batch of NLRI. Its own header
        # costs afi + safi + next-hop length + next hop + reserved, and the
        # attribute costs up to four more bytes of TLV header.
        mp_fixed = 2 + 1 + 1 + len(nexthop) + 1
        room = max_msg - 19 - 2 - 2 - len(attrs) - 4 - mp_fixed
        if room <= 0:
            raise MrtError('IPv6 attribute block of %d bytes leaves no room '
                           'for NLRI' % len(attrs))
        for nlri, count in _fill(members, room, _pack_prefix):
            mp_value = (struct.pack('!HBB', AFI_IPV6, SAFI_UNICAST,
                                    len(nexthop)) + nexthop +
                        b'\x00' + nlri)
            attrs_out = attrs + _encode_attr(AFLAG_OPTIONAL, ATTR_MP_REACH,
                                             mp_value)
            body = (struct.pack('!H', 0) +
                    struct.pack('!H', len(attrs_out)) + attrs_out)
            chunks.append(_message(body))
            messages += 1
            packed += count
    return b''.join(chunks), messages, packed


def _group_by_attrs(prefixes):
    """Group prefixes by identical attributes, preserving first-seen order.

    Grouping by identity rather than by adjacency matters: a real table
    interleaves paths from many origins, so adjacent-only grouping would
    produce far more, far smaller UPDATEs than a speaker would send.

    :param prefixes: ``[(plen, prefix, attrs, nexthop), ...]``.
    :return: ``[((attrs, nexthop), [(plen, prefix), ...]), ...]``.
    """
    groups = collections.OrderedDict()
    for plen, prefix, attrs, nexthop in prefixes:
        key = (attrs, nexthop)
        members = groups.get(key)
        if members is None:
            members = []
            groups[key] = members
        members.append((plen, prefix))
    return list(groups.items())


def _fill(members, room, pack):
    """Pack members into byte runs no larger than ``room``.

    :param members: ``[(plen, prefix), ...]``.
    :param room: bytes available for NLRI in one message.
    :param pack: callable turning a member into bytes.
    :return: an iterator of ``(nlri_bytes, member_count)``.
    """
    buf = []
    used = 0
    count = 0
    for plen, prefix in members:
        item = pack(plen, prefix)
        if used + len(item) > room and count:
            yield b''.join(buf), count
            buf = []
            used = 0
            count = 0
        buf.append(item)
        used += len(item)
        count += 1
    if count:
        yield b''.join(buf), count


# --- command ----------------------------------------------------------------

def summarise(corpus, stream_info=None):
    """Print what was read, in enough detail to defend a benchmark number.

    :param corpus: a loaded :class:`Corpus`.
    :param stream_info: optional ``(bytes, messages, prefixes)``.
    """
    peer = corpus.peer
    print('corpus           : %s' % corpus.path)
    print('records          : %d IPv%d unicast'
          % (corpus.records, corpus.afi))
    print('collector peers  : %d in the index, %d contributing'
          % (len(corpus.peers), len(corpus.peer_counts)))
    if peer is not None:
        print('peer selected    : index %d, %s AS%d'
              % (peer.index, peer.addr_str(), peer.asn))
    fullest = corpus.peer_counts.most_common(1)[0]
    chosen = corpus.peer_counts[peer.index] if peer is not None else 0
    if corpus.truncated:
        print('peer routes      : %d (limit reached; the dump holds more)'
              % chosen)
    else:
        print('peer routes      : %d (fullest peer in the dump has %d)'
              % (chosen, fullest[1]))
        if peer is not None and fullest[0] != peer.index:
            print('  WARNING: a fuller peer exists; the sample chose peer %d'
                  % peer.index)
    if corpus.mp_mismatch or corpus.no_mp_reach:
        print('mp_reach         : %d dropped for a prefix mismatch, '
              '%d with no MP_REACH'
              % (corpus.mp_mismatch, corpus.no_mp_reach))
    distinct, total = corpus.distinct_attrs()
    print('attribute sets   : %d distinct over %d paths (%.1f paths/set)'
          % (distinct, total, float(total) / max(distinct, 1)))
    print('read time        : %.1f s' % corpus.read_seconds)
    if stream_info is not None:
        data, messages, packed = stream_info
        print('update stream    : %d messages, %d prefixes, %.1f MB '
              '(%.1f prefixes/message)'
              % (messages, packed, len(data) / (1024.0 * 1024.0),
                 float(packed) / max(messages, 1)))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='inspect an MRT TABLE_DUMP_V2 corpus')
    parser.add_argument('path', help='rib.*.bz2 / bview.*.gz / raw .mrt')
    parser.add_argument('--afi', type=int, choices=(4, 6), default=4)
    parser.add_argument('--peer', type=int, default=None,
                        help='peer index (default: the fullest table)')
    parser.add_argument('--limit', type=int, default=None,
                        help='stop after N prefixes')
    parser.add_argument('--max-msg', type=int, default=BGP_MAX_MSG)
    args = parser.parse_args(argv)

    corpus = load(args.path, afi=args.afi, peer_index=args.peer,
                  limit=args.limit)
    stream = build_updates(corpus, max_msg=args.max_msg)
    summarise(corpus, stream)
    return 0


if __name__ == '__main__':
    sys.exit(main())
