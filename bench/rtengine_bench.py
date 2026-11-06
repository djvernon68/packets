#!/usr/bin/env python3
"""The rtengine benchmark: decode, insert, best-path, loop lag and memory.

This script began life as the Stage-2 architecture gate -- one claim, that
bulk work sliced by a time budget leaves the asyncio loop responsive enough
to service its timers, measured rather than asserted -- and it still is
that. A routing speaker that misses keepalives is dropped by its peers and
has to relearn the whole table, which is the failure the batching exists to
prevent, so the gate stays in place and still sets the exit status.

It now also answers the questions the gate deliberately deferred, because
the gate ran before there was a BGP plugin to measure:

* the gate's "decode + insert" figure was driven from Python with one
  ``Prefix`` and one ``Route`` built per prefix, and said so -- a floor, not
  the engine's own path. The codec phase below runs the shipped decoder;
* the gate's bytes-per-route figure covered the protocol-neutral RIB alone,
  with no attributes, no retained pre-policy table and therefore no
  attribute interning -- the very mechanism the plan's memory budget
  assumes. The Loc-RIB phase builds all three;
* the gate ran on a synthetic stream in which every path shared one
  attribute set. A real table has tens of thousands of distinct sets over
  about a million paths, which is a different workload for interning, for
  the allocator and for the comparator.

Phases, over the same UPDATE stream (synthetic or a real MRT corpus):

1. **decode only** -- ``bgpcore.scan_updates``, the ``nogil`` primitives
   walking the stream and touching no Python object. The ceiling.
2. **codec decode** -- ``wire.decode_update``, the decoder the engine
   actually runs, building typed messages and interned attribute sets.
3. **decode + RIB insert** -- primitives plus a ``Prefix``, a ``Route`` and
   a ``RouteTable.offer`` per prefix, driven from Python. The gate's
   number, kept identical so the gate remains comparable over time.
4. **Loc-RIB build** -- the codec feeding ``LocRib.add_path`` with a
   retained raw Adj-RIB-In beside it: the memory shape the plan budgets.
5. **select + publish** -- the change queue drained through the ``Batcher``
   on a real event loop, with an independent probe measuring how long the
   loop was unable to run. The lag number.
6. **memory** -- resident-set growth per route, per phase.
7. **ExaBGP** (optional) -- another implementation's parser over the same
   bytes, for scale.

Pass criteria, from the plan's acceptance criterion 11:

    decode + insert >= 100,000 prefixes/s/core   (half the final target)
    loop lag         <  50 ms

Exit status is 0 on pass and 1 on fail, so it can gate a stage rather than
just print numbers.

Usage::

    PYTHONPATH=. python3 bench/rtengine_bench.py [options]

      --corpus FILE       MRT TABLE_DUMP_V2 dump; synthetic stream if absent
      --peer N            collector peer index (default: the fullest table)
      --prefixes N        cap the prefix count (default: 1000000 synthetic,
                          the whole corpus otherwise)
      --per-message N     prefixes per UPDATE, synthetic only (default 100)
      --budget-ms X       Batcher slice budget (default 5.0)
      --probe-ms X        loop-lag probe interval (default 5.0)
      --afi 4|6           address family (default 4)
      --exabgp            also time ExaBGP's parser on the same stream
      --skip-locrib       omit phase 4 (it is the slowest and the greediest)
      --no-raw            phase 4 without the retained raw Adj-RIB-In, so
                          that it and the decision structures can be
                          priced separately
      --quick             a 50k-prefix run, for a smoke check

On a host where the library is also installed system-wide, run it with
``PYTHONPATH`` pointing at the checkout: Python puts the *script's*
directory on ``sys.path``, not the working directory, so an installed copy
wins otherwise. The header prints the file it actually imported, which is
the cheapest way to notice.
"""

from __future__ import print_function

import argparse
import gc
import os
import platform
import struct
import sys
import time

# asyncio is imported lazily in the selection phase: on 3.6 importing it
# costs enough to show up in a short run's start-up, and a --skip run
# should not pay for it.
import packets
from packets.core import bgpcore
from packets.routing.rtengine.fib.sink import NullSink
from packets.routing.rtengine.health import rss_bytes
from packets.routing.rtengine.loop import Batcher
from packets.routing.rtengine.rib.globalrib import GlobalRib
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, Prefix
from packets.routing.rtengine.rib.table import PROTO_BGP, Route

MARKER = b'\xff' * 16
BGP_UPDATE = 2
ATTR_MP_REACH = 14

# The gate, not a target. The target is twice this; half of it is what the
# plan asked Stage 2 to clear before Stage 3 opened.
GATE_PREFIXES_PER_S = 100000
GATE_LAG_MS = 50.0

# The plan's non-functional targets, reported against but not gated on:
# missing a tuning target is a finding, not a build failure.
TARGET_PREFIXES_PER_S = 200000
TARGET_TABLE_SECONDS = 10.0
TARGET_BYTES_PER_PATH = 300.0

DEFAULT_PREFIXES = 1000000
DEFAULT_PER_MESSAGE = 100

try:
    _PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
except (AttributeError, ValueError, OSError):
    _PAGE_SIZE = 4096


def current_rss():
    """Return the process's *current* resident set size in bytes.

    Not ``health.rss_bytes()``, which returns ``ru_maxrss`` -- a high-water
    mark. That is the right thing for a health document, which wants to
    report the worst the process has ever been, and the wrong thing here:
    a phase that allocates less than some earlier phase already peaked at
    shows up as costing nothing at all, and a decomposition built on it
    reports zero bytes for its first layers and hands the whole total to
    the last one. Measured, not assumed -- the first attempt at pricing
    this engine's per-path memory did exactly that.

    Falls back to the peak where ``/proc`` is unavailable, which on a Mac
    it is; the caller says which it got.

    :return: current RSS in bytes, or 0 if neither can be read.
    """
    try:
        with open('/proc/self/statm', 'rb') as handle:
            return int(handle.read().split()[1]) * _PAGE_SIZE
    except (IOError, OSError, IndexError, ValueError):
        return rss_bytes()


def rss_is_current():
    """Whether :func:`current_rss` is a live reading or a high-water mark.

    :return: ``True`` if ``/proc/self/statm`` is readable.
    """
    return os.path.exists('/proc/self/statm')


# --- the synthetic stream ---------------------------------------------------
# The offline fallback, for a host with no corpus. It is shaped to be
# pessimistic where that matters and realistic where it is cheap:
#
#   * every prefix is distinct, and they are spread across many /8s rather
#     than packed under one, so the trie actually branches near the root and
#     the insert path walks a realistic depth instead of one long chain;
#   * /24s, which is what most of a real IPv4 table is;
#   * one attribute set shared by the whole stream. This is the one place
#     the synthetic stream is *not* realistic, and it flatters interning
#     and the allocator both -- which is why the corpus exists.

def _pa(flags, atype, value):
    return bytes(bytearray([flags, atype, len(value)])) + value


def _attrs():
    """ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, COMMUNITIES."""
    asns = b''.join(struct.pack('!H', 65000 + i) for i in range(4))
    return (_pa(0x40, 1, bytes(bytearray([0]))) +
            _pa(0x40, 2, bytes(bytearray([2, 4])) + asns) +
            _pa(0x40, 3, bytes(bytearray([10, 0, 0, 1]))) +
            _pa(0x80, 4, struct.pack('!I', 100)) +
            _pa(0x40, 5, struct.pack('!I', 200)) +
            _pa(0xC0, 8, struct.pack('!II', 0xFFFFFF01, 0xFFFF029A)))


def _nlri_v4(index):
    # 200 distinct second octets before wrapping into the third, so a
    # million prefixes occupy 200 /8s rather than one.
    return bytes(bytearray([24, 8 + ((index >> 16) % 200),
                            (index >> 8) & 0xff, index & 0xff]))


def _nlri_v6(index):
    # /56s out of 2001:db8::/32, the same spread argument as IPv4. /56
    # rather than the more typical /48 for a mundane reason: a /48 leaves
    # only two variable bytes, so a million of them would not be a million
    # distinct prefixes.
    return bytes(bytearray([56, 0x20, 0x01, 0x0d, 0xb8,
                            (index >> 16) & 0xff, (index >> 8) & 0xff,
                            index & 0xff]))


def make_stream(prefixes, per_message, afi):
    """Build a back-to-back UPDATE stream carrying ``prefixes`` prefixes.

    :param prefixes: total prefixes across the stream.
    :param per_message: prefixes per UPDATE.
    :param afi: 1 for IPv4, 2 for IPv6.
    :return: ``(stream_bytes, message_count)``.
    """
    nlri_of = _nlri_v4 if afi == AFI_IP else _nlri_v6
    attrs = _attrs()
    chunks = []
    written = 0
    messages = 0
    while written < prefixes:
        count = min(per_message, prefixes - written)
        nlri = b''.join(nlri_of(written + i) for i in range(count))
        body = (struct.pack('!H', 0) +
                struct.pack('!H', len(attrs)) + attrs + nlri)
        chunks.append(MARKER + struct.pack('!H', 19 + len(body)) +
                      bytes(bytearray([BGP_UPDATE])) + body)
        written += count
        messages += 1
    return b''.join(chunks), messages


def corpus_stream(path, afi, limit, peer_index):
    """Build an UPDATE stream from a real MRT RIB dump.

    :param path: the dump.
    :param afi: 4 or 6.
    :param limit: prefix cap, or ``None`` for the whole table.
    :param peer_index: collector peer, or ``None`` to choose the fullest.
    :return: ``(stream_bytes, messages, prefixes, corpus)``.
    """
    import mrt                      # noqa: E402  (bench/ is on sys.path)
    corpus = mrt.load(path, afi=afi, peer_index=peer_index, limit=limit)
    stream, messages, packed = mrt.build_updates(corpus)
    return stream, messages, packed, corpus


# --- framing ----------------------------------------------------------------

def _messages(stream):
    """Yield each complete message's span.

    Framing by the header's own length field, exactly as the engine's
    framer does: the stream is a byte stream, not a list of messages.

    :param stream: the UPDATE stream.
    :return: an iterator of ``(start, end)``.
    """
    total = len(stream)
    offset = 0
    while offset + 19 <= total:
        length = struct.unpack_from('!H', stream, offset + 16)[0]
        end = offset + length
        if length < 19 or end > total:
            return
        yield offset, end
        offset = end


def _nlri_spans(stream, afi):
    """Yield the NLRI span of every UPDATE in the stream.

    For IPv4 that is everything after the attributes. For IPv6 it is
    inside MP_REACH_NLRI, after the next hop and the reserved byte, so the
    attributes have to be walked to find it -- there is no shortcut, and
    taking the IPv4 path on an IPv6 stream silently yields an empty span
    rather than failing.

    :param stream: the UPDATE stream.
    :param afi: ``AFI_IP`` or ``AFI_IP6``.
    :return: an iterator of ``(nlri_start, nlri_end)``.
    """
    unpack_from = struct.unpack_from
    for offset, end in _messages(stream):
        if stream[offset + 18] != BGP_UPDATE:
            continue
        body = offset + 19
        withdrawn_len = unpack_from('!H', stream, body)[0]
        attr_off = body + 2 + withdrawn_len
        attr_len = unpack_from('!H', stream, attr_off)[0]
        attr_start = attr_off + 2
        attr_end = attr_start + attr_len
        if afi == AFI_IP:
            yield attr_end, end
            continue
        pos = attr_start
        while pos + 2 <= attr_end:
            flags = stream[pos]
            atype = stream[pos + 1]
            pos += 2
            if flags & 0x10:
                length = unpack_from('!H', stream, pos)[0]
                pos += 2
            else:
                length = stream[pos]
                pos += 1
            if atype == ATTR_MP_REACH:
                # afi(2) safi(1) nexthop-length(1) nexthop reserved(1)
                yield pos + 5 + stream[pos + 3], pos + length
                break
            pos += length


# --- phase 1: the primitives ------------------------------------------------

def bench_decode_only(stream, expected):
    """Time the primitives alone over the whole stream.

    :param stream: the UPDATE stream.
    :param expected: prefixes the scan must find, as a correctness check --
        a decoder that quietly stopped early would otherwise look fast.
    :return: ``(seconds, prefixes_seen)``.
    """
    counts = bgpcore.scan_updates(stream)
    seen = counts[2]
    best = None
    for _ in range(3):
        start = time.perf_counter()
        bgpcore.scan_updates(stream)
        elapsed = time.perf_counter() - start
        if best is None or elapsed < best:
            best = elapsed
    if expected is not None and seen != expected:
        # IPv6 prefixes live in MP_REACH, which the IPv4-shaped scan does
        # not count, so this is a check only where the two agree.
        print('   note: scan counted %d IPv4 NLRI, stream carries %d '
              'prefixes' % (seen, expected))
    return best, seen


# --- phase 2: the shipped codec ---------------------------------------------

def bench_codec(stream, peer_as, as4, is_ebgp):
    """Time ``wire.decode_update`` over the stream.

    This is the decode number that describes the engine: typed messages,
    canonicalised AS_PATHs, an ``AttrSet`` per distinct attribute block and
    a ``Prefix`` per NLRI entry, with the RFC 7606 error list populated on
    the way past. It is much slower than phase 1 and that is the point --
    phase 1 is the ceiling the codec is measured against, not a claim about
    what the engine does per UPDATE.

    :param stream: the UPDATE stream.
    :param peer_as: the AS the corpus peer used, for the decode context.
    :param as4: whether AS_PATH on this stream is 4-octet.
    :param is_ebgp: whether to decode as an external session.
    :return: a dict of results.
    """
    from packets.routing.rtengine.plugins.bgp import wire

    ctx = wire.DecodeCtx(as4=as4, is_ebgp=is_ebgp, local_as=65000,
                         peer_as=peer_as)
    decode = wire.decode_update
    prefixes = 0
    faulted = 0
    messages = 0

    gc.collect()
    start = time.perf_counter()
    for begin, end in _messages(stream):
        update = decode(stream[begin:end], ctx)
        messages += 1
        if update.errors:
            faulted += 1
        prefixes += len(update.nlri)
        if update.mp_reach is not None:
            prefixes += len(update.mp_reach[4])
    elapsed = time.perf_counter() - start

    return {
        'elapsed': elapsed,
        'messages': messages,
        'prefixes': prefixes,
        'faulted': faulted,
    }


# --- phase 3: the gate ------------------------------------------------------

def bench_decode_insert(stream, table, expected):
    """Time decode plus RIB insert: the gate's measurement.

    One ``Prefix``, one ``Route`` and one ``offer`` per prefix, with the
    address sliced out of the stream the way a Python driver must. The
    address is zero-extended to the family width here because the wire
    carries only the significant bytes of a prefix; the Cython constructor
    a real codec uses takes the truncated form directly and skips both the
    slice and the pad.

    Message framing is inside the timed region, not precomputed: walking
    the length fields is part of what a speaker pays per UPDATE, and
    hoisting it out would flatter the result.

    Unchanged from the Stage-2 gate on purpose. The point of a gate is that
    it measures the same thing every time it is run.

    :param stream: the UPDATE stream.
    :param table: the table to insert into.
    :param expected: prefixes that must be inserted, or ``None``.
    :return: ``(seconds, inserted)``.
    """
    afi = table.afi
    width = 4 if afi == AFI_IP else 16
    pad = bytes(width)
    nexthop = bytes(bytearray([10, 0, 0, 1])) if afi == AFI_IP else bytes(16)
    source = object()

    gc.collect()
    start = time.perf_counter()
    for nlri_start, nlri_end in _nlri_spans(stream, afi):
        for _path_id, plen, addr_start in bgpcore.iter_nlri(
                stream, nlri_start, nlri_end, False, width):
            nbytes = (plen + 7) >> 3
            raw = stream[addr_start:addr_start + nbytes]
            table.offer(Route(Prefix(afi, plen, raw + pad[nbytes:]),
                              PROTO_BGP, 20, 0, nexthop, source))
    elapsed = time.perf_counter() - start

    if expected is not None and table.route_count != expected:
        print('   note: inserted %d routes for %d prefixes (duplicates in '
              'the corpus)' % (table.route_count, expected))
    return elapsed, table.route_count


def _check_inserted(inserted, prefixes):
    """Refuse to report a rate for work that did not happen.

    A phase that inserts nothing runs arbitrarily fast and, left alone,
    prints an impressive number and a PASS. That is the single worst thing
    a benchmark can do, so it is checked rather than trusted.

    :param inserted: routes actually in the table.
    :param prefixes: prefixes the stream carried.
    :return: ``None``, or a message describing the discrepancy.
    """
    if inserted == 0 and prefixes:
        return ('inserted 0 routes for %d prefixes -- the phase did no '
                'work and its rate is meaningless' % prefixes)
    if prefixes and inserted < prefixes * 0.9:
        return ('inserted %d routes for %d prefixes -- more than a tenth '
                'of the stream was not seen' % (inserted, prefixes))
    return None


# --- phase 4: the BGP Loc-RIB -----------------------------------------------

def bench_locrib(stream, afi, peer_as, as4, is_ebgp, keep_raw=True):
    """Time the codec feeding a real Loc-RIB, and measure what it costs.

    This is the phase the plan's memory budget is actually about. Three
    things exist per prefix here that phase 3 does not build:

    * the interned ``AttrSet``, shared by every path carrying the same
      attributes -- the mechanism the ``< 300 bytes/path`` budget assumes;
    * the ``BgpPath`` and its ``BgpDest``, the decision process's objects;
    * the retained raw Adj-RIB-In entry, which the plan requires to be kept
      always (Key Decision 11) and therefore has to be paid for here.

    :param stream: the UPDATE stream.
    :param afi: 4 or 6.
    :param peer_as: the corpus peer's AS.
    :param as4: whether AS_PATH on this stream is 4-octet.
    :param is_ebgp: whether to decode as an external session.
    :param keep_raw: retain a raw Adj-RIB-In beside the Loc-RIB.
    :return: a dict of results.
    """
    from packets.routing.rtengine.plugins.bgp import (attrs as attrs_mod,
                                                      bestpath, locrib, wire)

    rib_afi = AFI_IP if afi == 4 else AFI_IP6
    attr_table = attrs_mod.AttrTable()
    config = bestpath.BestpathConfig(local_as=65000, router_id=0x0a0a0a0a)
    rib = locrib.LocRib(rib_afi, 1, attr_table, config)
    peer_ref = bestpath.PeerRef(peer_as=peer_as, local_as=65000,
                                router_id=0x0a000001,
                                addr=bytes(bytearray([10, 0, 0, 1])),
                                is_ebgp=is_ebgp)
    ctx = wire.DecodeCtx(as4=as4, is_ebgp=is_ebgp, local_as=65000,
                         peer_as=peer_as)
    decode = wire.decode_update
    add_path = rib.add_path
    intern = attr_table.intern
    raw_in = {} if keep_raw else None
    paths = 0

    gc.collect()
    before = current_rss()
    start = time.perf_counter()
    for begin, end in _messages(stream):
        update = decode(stream[begin:end], ctx)
        entries = update.nlri
        if update.mp_reach is not None:
            entries = entries + update.mp_reach[4]
        if not entries:
            continue
        attrs = update.attrs
        now = time.time()
        if raw_in is not None:
            shared = intern(attrs)
            for prefix, path_id in entries:
                raw_in[(prefix, path_id)] = (shared, now)
        for prefix, path_id in entries:
            add_path(peer_ref, prefix, attrs, path_id=path_id,
                     recv_time=now)
            paths += 1
    elapsed = time.perf_counter() - start
    gc.collect()
    after = current_rss()

    stats = attr_table.stats()
    return {
        'elapsed': elapsed,
        'paths': paths,
        'rss_before': before,
        'rss_after': after,
        'attr_sets': attr_table.count(),
        'attr_stats': stats,
        'raw_entries': len(raw_in) if raw_in is not None else 0,
        'rib': rib,
    }


# --- phase 5: selection and loop lag ----------------------------------------

def bench_select(rib, sink, budget_ms, probe_ms):
    """Drain selection through the Batcher, measuring loop lag alongside.

    The probe is deliberately independent of the work: it reschedules
    itself at a fixed interval and records how late it actually ran. That
    drift is the time the loop could not run anything, which is exactly
    what a missed keepalive would be made of, and it needs no cooperation
    from the code being measured.

    :param rib: the global RIB, with a full change queue.
    :param sink: its FIB sink, read for the install count.
    :param budget_ms: the Batcher's slice budget.
    :param probe_ms: probe interval.
    :return: a dict of results.
    """
    import asyncio

    batcher = Batcher(budget_ms=budget_ms, name='select')
    loop = asyncio.new_event_loop()
    lags = []
    interval = probe_ms / 1000.0

    async def run():
        due = [loop.time() + interval]

        def probe():
            now = loop.time()
            lags.append(max(0.0, (now - due[0]) * 1000.0))
            due[0] = now + interval
            if rib.pending():
                loop.call_at(due[0], probe)

        loop.call_at(due[0], probe)
        start = time.perf_counter()
        examined = await rib.drain(batcher)
        return examined, time.perf_counter() - start

    try:
        examined, elapsed = loop.run_until_complete(run())
    finally:
        loop.close()

    return {
        'examined': examined,
        'elapsed': elapsed,
        'installed': sink.installed,
        'batcher': batcher.stats(),
        'probes': len(lags),
        'max_lag_ms': max(lags) if lags else 0.0,
        'mean_lag_ms': (sum(lags) / len(lags)) if lags else 0.0,
    }


# --- phase 7: another implementation ----------------------------------------

def bench_exabgp(stream, peer_as):
    """Time ExaBGP's UPDATE parser over the same bytes.

    Not a like-for-like contest and not presented as one: ExaBGP is pure
    Python and builds a much richer object per message, while our decoder
    is Cython over ``nogil`` primitives. The number is here for scale, and
    because the plan asks for it -- a factor is easier to argue about than
    an adjective.

    What makes the comparison fair is only that both parsers see the same
    bytes, in the same process conditions, on the same interpreter. Where
    the interpreter cannot be the same, the caller records that.

    :param stream: the UPDATE stream.
    :param peer_as: the AS the stream's paths came from.
    :return: a dict of results, or one carrying ``error``.
    """
    problem = _exabgp_environment()
    if problem is not None:
        return {'error': problem}

    try:
        from exabgp.bgp.message import Update
        from exabgp.bgp.message.open.asn import ASN
        from exabgp.bgp.message.open.capability.negotiated import Negotiated
    except ImportError as exc:
        return {'error': 'import failed: %s' % (exc,)}

    try:
        from exabgp.reactor.protocol import Direction
    except ImportError:
        Direction = None

    try:
        import exabgp.version as version_mod
        version = getattr(version_mod, 'version', 'unknown')
    except ImportError:
        version = 'unknown'

    negotiated = _exabgp_negotiated(Negotiated, ASN, peer_as)
    if negotiated is None:
        return {'error': 'could not build a Negotiated for this ExaBGP',
                'version': version}

    unpack = Update.unpack_message
    direction = getattr(Direction, 'IN', None) if Direction else None
    bodies = [stream[begin + 19:end] for begin, end in _messages(stream)]

    # Which argument shape this ExaBGP wants is version-dependent, so it is
    # discovered once on a real message rather than guessed from a version
    # string, which would go stale.
    call = None
    for candidate in (lambda b: unpack(b, direction, negotiated),
                      lambda b: unpack(b, negotiated, direction),
                      lambda b: unpack(b, negotiated)):
        try:
            candidate(bodies[0])
        except TypeError:
            continue
        except Exception as exc:                        # noqa: BLE001
            return {'error': 'parser raised %s: %s'
                             % (type(exc).__name__, exc), 'version': version}
        call = candidate
        break
    if call is None:
        return {'error': 'no known unpack_message signature matched',
                'version': version}

    prefixes = 0
    gc.collect()
    start = time.perf_counter()
    for body in bodies:
        message = call(body)
        nlri = getattr(message, 'nlris', None)
        if nlri is not None:
            prefixes += len(nlri)
    elapsed = time.perf_counter() - start

    return {
        'elapsed': elapsed,
        'messages': len(bodies),
        'prefixes': prefixes,
        'version': version,
    }


def _exabgp_environment():
    """Initialise ExaBGP's global environment, as its own commands do.

    ExaBGP keeps its settings in a process-global initialised by whichever
    ``main()`` started it, and its message classes read that global at
    import time. Importing the parser into someone else's process without
    doing so raises ``RuntimeError`` from deep inside an unrelated module,
    so it is done here explicitly and early: its own ``tojson`` utility
    does exactly this. The module path moved between releases, hence the
    list.

    :return: ``None`` on success, or a message explaining the failure.
    """
    for module in ('exabgp.configuration.setup',
                   'exabgp.configuration.environment',
                   'exabgp.environment'):
        try:
            mod = __import__(module, fromlist=['environment'])
        except ImportError:
            continue
        setup = getattr(getattr(mod, 'environment', mod), 'setup', None)
        if setup is None:
            continue
        try:
            setup('')
        except Exception as exc:                        # noqa: BLE001
            return 'environment setup failed: %s' % (exc,)
        return None
    return 'no ExaBGP environment module found'


def _exabgp_negotiated(negotiated_cls, asn_cls, peer_as):
    """Build the minimum ExaBGP session state its parser insists on.

    ExaBGP decodes an UPDATE against a negotiated session, because whether
    AS_PATH is 2- or 4-octet and whether ADD-PATH is in play changes the
    bytes' meaning -- the same reason our own decoder takes a
    ``DecodeCtx``. Constructing one outside a real session differs between
    releases, so each known shape is tried in turn.

    :param negotiated_cls: ``exabgp...capability.negotiated.Negotiated``.
    :param asn_cls: ``exabgp...open.asn.ASN``.
    :param peer_as: the peer's AS.
    :return: a negotiated object, or ``None``.
    """
    try:
        from exabgp.bgp.neighbor import Neighbor
    except ImportError:
        Neighbor = None

    try:
        from exabgp.protocol.family import AFI, SAFI
        families = [(AFI.ipv4, SAFI.unicast), (AFI.ipv6, SAFI.unicast)]
    except Exception:                                   # noqa: BLE001
        families = None

    for build in (lambda: negotiated_cls(Neighbor()),
                  lambda: negotiated_cls(None)):
        try:
            negotiated = build()
        except Exception:                               # noqa: BLE001
            continue
        # Without a negotiated family list ExaBGP rejects MP_REACH as a
        # "non-negotiated family" and no IPv6 message parses at all. Real
        # sessions learn this from the OPEN capabilities; there is no OPEN
        # here, so both families are declared up front.
        if families is not None:
            try:
                negotiated.families = list(families)
            except Exception:                           # noqa: BLE001
                pass
        # Tell it the peers speak 4-octet AS, which every TABLE_DUMP_V2
        # AS_PATH does by definition (RFC 6396 s4.3.4). Attribute names
        # differ across releases; setting what exists is enough, because
        # ExaBGP defaults the rest.
        for name, value in (('asn4', True), ('local_as', asn_cls(65000)),
                            ('peer_as', asn_cls(peer_as))):
            try:
                setattr(negotiated, name, value)
            except Exception:                           # noqa: BLE001
                pass
        return negotiated
    return None


# --- reporting --------------------------------------------------------------

def _thousands(value):
    """Format a rate the way a human reads it.

    :param value: the rate.
    :return: e.g. ``'1.23M'`` or ``'456k'``.
    """
    if value >= 1000000:
        return '%.2fM' % (value / 1000000.0)
    if value >= 1000:
        return '%.0fk' % (value / 1000.0)
    return '%.0f' % value


def _mb(value):
    return value / (1024.0 * 1024.0)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='rtengine benchmark: decode, insert, best-path, lag')
    parser.add_argument('--corpus', default=None,
                        help='MRT TABLE_DUMP_V2 dump to replay')
    parser.add_argument('--peer', type=int, default=None,
                        help='collector peer index (default: fullest)')
    parser.add_argument('--prefixes', type=int, default=None)
    parser.add_argument('--per-message', type=int,
                        default=DEFAULT_PER_MESSAGE)
    parser.add_argument('--budget-ms', type=float, default=5.0)
    parser.add_argument('--probe-ms', type=float, default=5.0)
    parser.add_argument('--afi', type=int, choices=(4, 6), default=4)
    parser.add_argument('--exabgp', action='store_true',
                        help="also time ExaBGP's parser on the same stream")
    parser.add_argument('--skip-locrib', action='store_true',
                        help='omit the Loc-RIB phase')
    parser.add_argument('--no-raw', action='store_true',
                        help='build the Loc-RIB without a retained raw '
                             'Adj-RIB-In, to price the two separately')
    parser.add_argument('--quick', action='store_true',
                        help='50k prefixes, for a smoke check')
    args = parser.parse_args(argv)

    if args.quick:
        args.prefixes = 50000
    afi = AFI_IP if args.afi == 4 else AFI_IP6

    print('interpreter      : %s %s on %s'
          % (platform.python_implementation(), platform.python_version(),
             platform.machine()))
    print('host             : %s %s' % (platform.node(), platform.system()))
    # The import that actually happened, not the one intended. On a host
    # carrying an installed copy of the library this is the difference
    # between benchmarking the checkout and benchmarking last release.
    print('packets          : %s' % (os.path.dirname(packets.__file__),))

    peer_as = 65000
    corpus = None
    # Both of these describe the *stream*, so both follow it rather than
    # being fixed, and getting either wrong is quiet rather than loud.
    #
    #   as4: TABLE_DUMP_V2 stores every AS_PATH with 4-octet ASNs (RFC 6396
    #   s4.3.4); the synthetic generator above writes 2-octet ones, as a
    #   pre-RFC-6793 peer would. Told the wrong one, the decoder does not
    #   fail -- it parses a plausible, wrong AS_PATH and files a finding.
    #
    #   is_ebgp: the synthetic stream carries LOCAL_PREF, which RFC 4271
    #   forbids between ASes, so it is an internal session's stream and
    #   decoding it as external makes the codec object to every message --
    #   correctly. A collector's peers are external and their paths carry
    #   no LOCAL_PREF, so the corpus is the other way round. This was
    #   invisible until Stage 6, because the Stage-2 gate never ran the
    #   codec over its own stream at all.
    as4 = bool(args.corpus)
    is_ebgp = bool(args.corpus)
    if args.corpus:
        stream, messages, prefixes, corpus = corpus_stream(
            args.corpus, args.afi, args.prefixes, args.peer)
        peer_as = corpus.peer.asn if corpus.peer is not None else 65000
        print('workload         : MRT corpus, IPv%d' % args.afi)
        print('corpus           : %s' % os.path.basename(args.corpus))
        print('peer             : index %d, %s AS%d'
              % (corpus.peer.index, corpus.peer.addr_str(), peer_as))
        distinct, total = corpus.distinct_attrs()
        print('attribute sets   : %d distinct over %d paths (%.1f paths/set)'
              % (distinct, total, float(total) / max(distinct, 1)))
    else:
        want = args.prefixes if args.prefixes else DEFAULT_PREFIXES
        stream, messages = make_stream(want, args.per_message, afi)
        prefixes = want
        print('workload         : synthetic, %d prefixes, %d per UPDATE, '
              'IPv%d' % (prefixes, args.per_message, args.afi))
    print('stream           : %d messages, %.1f MB, %.1f prefixes/message'
          % (messages, _mb(len(stream)),
             float(prefixes) / max(messages, 1)))
    print('')

    # The same RIB serves phases 3 and 5: the point of the split is that
    # inserting and selecting are separate costs, not that they happen to
    # different data. The bus is None because event fan-out is measured by
    # its own subscribers, not here -- a subscriber-less bus would only add
    # a dict lookup per destination and hide the selection cost.
    sink = NullSink()
    rib = GlobalRib(sink=sink, bus=None, afi_safi=((afi, 1),))
    table = rib.table(afi)

    expected = prefixes if args.afi == 4 else None
    decode, scanned = bench_decode_only(stream, expected)
    print('1. decode only (bgpcore.scan_updates, nogil)')
    print('   %.4f s  %s prefixes/s  (%d IPv4 NLRI seen)'
          % (decode, _thousands(prefixes / decode), scanned))
    print('')

    codec = bench_codec(stream, peer_as, as4, is_ebgp)
    codec_rate = codec['prefixes'] / codec['elapsed']
    print('2. codec decode (wire.decode_update, the shipped decoder; '
          '%s, as4=%s)' % ('eBGP' if is_ebgp else 'iBGP', as4))
    print('   %.3f s   %s prefixes/s   %s messages/s'
          % (codec['elapsed'], _thousands(codec_rate),
             _thousands(codec['messages'] / codec['elapsed'])))
    print('   %d prefixes, %d messages with RFC 7606 findings'
          % (codec['prefixes'], codec['faulted']))
    if codec['faulted']:
        # Not fatal -- a real feed does carry malformed UPDATEs, and
        # handling them is a feature. But on a corpus built from a
        # collector's own accepted table it should be zero, and anything
        # else means the stream or the decode context is wrong.
        print('   WARNING: %.1f%% of messages had findings; check the '
              'decode context' % (100.0 * codec['faulted'] /
                                  max(codec['messages'], 1)))
    print('   %.0fx slower than the primitives alone'
          % (codec['elapsed'] / decode))
    print('')

    gc.collect()
    rss_before = current_rss()
    insert, inserted = bench_decode_insert(stream, table, prefixes)
    gc.collect()
    rss_after = current_rss()
    insert_rate = prefixes / insert
    complaint = _check_inserted(inserted, prefixes)
    print('3. decode + RIB insert (the gate)')
    print('   %.3f s   %s prefixes/s   %d routes'
          % (insert, _thousands(insert_rate), inserted))
    if complaint:
        print('   INVALID: %s' % complaint)
    else:
        print('   %.1f%% of the elapsed time is object construction, not '
              'decode' % (100.0 * (1.0 - decode / insert)))
    print('')

    locrib_result = None
    if not args.skip_locrib:
        locrib_result = bench_locrib(stream, args.afi, peer_as, as4,
                                     is_ebgp, keep_raw=not args.no_raw)
        lr = locrib_result
        grew = lr['rss_after'] - lr['rss_before']
        per_path = float(grew) / max(lr['paths'], 1)
        stats = lr['attr_stats']
        print('4. codec + Loc-RIB%s'
              % ('' if args.no_raw else ' + retained raw Adj-RIB-In'))
        print('   %.3f s   %s paths/s   %d paths, %d raw entries'
              % (lr['elapsed'], _thousands(lr['paths'] / lr['elapsed']),
                 lr['paths'], lr['raw_entries']))
        print('   attribute sets: %d interned, %d hits, %d misses'
              % (lr['attr_sets'], stats.get('hits', 0),
                 stats.get('misses', 0)))
        print('   rss %.1f MB -> %.1f MB, %.0f bytes/path (target < %.0f)'
              % (_mb(lr['rss_before']), _mb(lr['rss_after']), per_path,
                 TARGET_BYTES_PER_PATH))
        print('')

    result = bench_select(rib, sink, args.budget_ms, args.probe_ms)
    stats = result['batcher']
    print('5. selection through the Batcher')
    print('   %.3f s   %s dests/s   %d slices, %d yields, %d overruns'
          % (result['elapsed'],
             _thousands(result['examined'] / result['elapsed']),
             stats['slices'], stats['yields'], stats['overruns']))
    print('   slice budget %.2f ms, mean %.3f ms, worst %.3f ms'
          % (stats['budget_ms'], stats['mean_slice_ms'],
             stats['max_slice_ms']))
    print('   loop lag: %d probes, mean %.3f ms, worst %.3f ms'
          % (result['probes'], result['mean_lag_ms'], result['max_lag_ms']))
    print('')

    per_route = 0.0
    if rss_after > rss_before and table.route_count:
        per_route = float(rss_after - rss_before) / table.route_count
    print('6. memory (protocol-neutral RIB only; phase 4 has the real one)')
    print('   rss %.1f MB -> %.1f MB, %.0f bytes/route%s'
          % (_mb(rss_before), _mb(rss_after), per_route,
             '' if rss_is_current() else '  [peak RSS: no /proc]'))
    print('   trie: %d prefixes, %d nodes (%.2f nodes/prefix)'
          % (table.trie.size(), table.trie.nodes,
             float(table.trie.nodes) / max(table.trie.size(), 1)))
    print('')

    if args.exabgp:
        other = bench_exabgp(stream, peer_as)
        print('7. ExaBGP parser, same bytes, same interpreter')
        if 'error' in other:
            print('   unavailable: %s' % other['error'])
        else:
            rate = other['prefixes'] / other['elapsed']
            print('   ExaBGP %s: %.3f s   %s prefixes/s'
                  % (other['version'], other['elapsed'], _thousands(rate)))
            print('   rtengine codec is %.1fx faster on the same stream'
                  % (codec_rate / rate if rate else 0.0))
        print('')

    total_load = insert + result['elapsed']
    print('table load       : %.2f s insert, %.2f s including selection '
          '(target < %.0f s)' % (insert, total_load, TARGET_TABLE_SECONDS))

    ok_rate = insert_rate >= GATE_PREFIXES_PER_S and complaint is None
    ok_lag = result['max_lag_ms'] < GATE_LAG_MS
    print('gate: decode+insert %s prefixes/s (need >= %s)  %s'
          % (_thousands(insert_rate), _thousands(GATE_PREFIXES_PER_S),
             'PASS' if ok_rate else 'FAIL'))
    if complaint is not None:
        print('      FAILED because the phase did not do the work: %s'
              % complaint)
    print('gate: worst loop lag %.3f ms (need < %.0f)        %s'
          % (result['max_lag_ms'], GATE_LAG_MS,
             'PASS' if ok_lag else 'FAIL'))
    print('gate: %s' % ('PASS' if (ok_rate and ok_lag) else 'FAIL'))
    print('target: decode+insert >= %s prefixes/s            %s'
          % (_thousands(TARGET_PREFIXES_PER_S),
             'met' if insert_rate >= TARGET_PREFIXES_PER_S else 'NOT met'))
    return 0 if (ok_rate and ok_lag) else 1


if __name__ == '__main__':
    sys.exit(main())
