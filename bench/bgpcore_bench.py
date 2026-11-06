#!/usr/bin/env python3
"""Decode throughput of the nogil BGP primitives, and of the text dissector.

Two numbers, measured over the same synthetic UPDATE stream:

  * ``bgpcore.scan_updates`` -- the primitives alone, walking the whole stream
    inside a single ``with nogil`` block. No Python object is touched between
    entry and exit, so this is the decode rate of the byte arithmetic itself.
    It is the figure the routing engine's architecture gate is compared
    against.
  * ``BGP(...)`` -- the same bytes through the Wireshark-style dissector,
    which allocates a BGP object, a BGPParam per attribute and a rendered
    string per enum. Reported alongside because the interesting quantity is
    the ratio: it is what the routing engine avoids by using the primitives
    rather than the dissector.

Prefixes per second, not messages per second, is the unit that matters for a
routing engine, so both are reported per prefix as well as per message.

Usage:
    PYTHONPATH=. python3 bench/bgpcore_bench.py [messages] [prefixes_per_msg]
"""

from __future__ import print_function

import platform
import struct
import sys
import time

from packets.core import bgpcore
from packets.core.inetpkt import BGP

MARKER = b'\xff' * 16
# 500 messages keeps the dissector's recursive message chaining to a
# reasonable depth -- BGP() decodes the first message and chains the rest,
# one native frame per message -- while still being a stream rather than a
# packet. The primitive scan is indifferent to the depth; it iterates.
DEFAULT_MESSAGES = 500
DEFAULT_PREFIXES = 20
# Best of this many timed rounds, each round auto-scaled to at least
# MIN_ROUND_SECONDS so the result is not a measurement of clock resolution.
REPEATS = 5
MIN_ROUND_SECONDS = 0.2


def _pa(flags, atype, value):
    return bytes([flags, atype, len(value)]) + value


def _attrs(as_path_len=4):
    """A realistic well-known attribute set: ORIGIN, AS_PATH, NEXT_HOP, MED,
    LOCAL_PREF, COMMUNITIES."""
    asns = b''.join(struct.pack('!H', 65000 + i) for i in range(as_path_len))
    return (_pa(0x40, 1, bytes([0])) +
            _pa(0x40, 2, bytes([2, as_path_len]) + asns) +
            _pa(0x40, 3, bytes([9, 9, 9, 9])) +
            _pa(0x80, 4, struct.pack('!I', 100)) +
            _pa(0x40, 5, struct.pack('!I', 200)) +
            _pa(0xC0, 8, struct.pack('!II', 0xFFFFFF01, 0xFFFF029A)))


def _nlri(count, seed=0):
    """``count`` distinct /24s, so no two prefixes share address bytes."""
    out = []
    for i in range(count):
        n = seed + i
        out.append(bytes([24, 10, (n >> 8) & 0xff, n & 0xff]))
    return b''.join(out)


def make_stream(messages, prefixes_per_msg):
    """A back-to-back stream of UPDATEs, as a BGP speaker would send it."""
    chunks = []
    attrs = _attrs()
    for m in range(messages):
        nlri = _nlri(prefixes_per_msg, seed=m * prefixes_per_msg)
        body = (struct.pack('!H', 0) +                    # no withdrawn
                struct.pack('!H', len(attrs)) + attrs + nlri)
        chunks.append(MARKER + struct.pack('!H', 19 + len(body)) +
                      bytes([2]) + body)
    return b''.join(chunks)


def _calibrate(fn):
    """How many calls of ``fn`` are needed to fill MIN_ROUND_SECONDS.

    Without this the primitive scan finishes inside the clock's resolution --
    a few tens of microseconds for a stream this size -- and the reported
    rate becomes a property of time.perf_counter rather than of the decoder.
    """
    calls = 1
    while True:
        t0 = time.perf_counter()
        for _ in range(calls):
            fn()
        dt = time.perf_counter() - t0
        if dt >= MIN_ROUND_SECONDS or calls >= 1 << 22:
            return max(calls, 1), dt
        # Aim straight at the target rather than doubling blindly, with a
        # floor so a zero measurement still makes progress.
        calls = max(calls * 2, int(calls * MIN_ROUND_SECONDS / max(dt, 1e-9)))


def _best_of(fn, repeats=REPEATS):
    """Best per-call time over ``repeats`` auto-scaled rounds.

    Best rather than mean: the quantity of interest is how fast the decode
    can go, and every source of noise on a shared machine only ever adds
    time.
    """
    calls, dt = _calibrate(fn)
    best = dt / calls
    for _ in range(repeats - 1):
        t0 = time.perf_counter()
        for _ in range(calls):
            fn()
        per_call = (time.perf_counter() - t0) / calls
        if per_call < best:
            best = per_call
    return best


def bench_primitives(stream, expected_prefixes):
    counts = bgpcore.scan_updates(stream)
    if counts[2] != expected_prefixes:
        raise SystemExit('scan_updates saw %d prefixes, expected %d'
                         % (counts[2], expected_prefixes))
    return _best_of(lambda: bgpcore.scan_updates(stream))


def bench_dissector(stream):
    # One BGP() call parses the first message and chains the rest, so this
    # walks the same bytes the primitive scan does.
    return _best_of(lambda: BGP(stream))


def main(argv):
    messages = int(argv[1]) if len(argv) > 1 else DEFAULT_MESSAGES
    prefixes_per_msg = int(argv[2]) if len(argv) > 2 else DEFAULT_PREFIXES
    total_prefixes = messages * prefixes_per_msg

    stream = make_stream(messages, prefixes_per_msg)

    prim = bench_primitives(stream, total_prefixes)
    diss = bench_dissector(stream)

    print('interpreter      : %s %s on %s' %
          (platform.python_implementation(), platform.python_version(),
           platform.machine()))
    print('stream           : %d messages, %d prefixes, %d bytes' %
          (messages, total_prefixes, len(stream)))
    print('')
    print('bgpcore.scan_updates (nogil primitives)')
    print('  elapsed        : %.4f s' % prim)
    print('  messages/s     : %.0f' % (messages / prim))
    print('  prefixes/s     : %.0f' % (total_prefixes / prim))
    print('  MB/s           : %.1f' % (len(stream) / prim / (1024 * 1024)))
    print('')
    print('BGP() text dissector')
    print('  elapsed        : %.4f s' % diss)
    print('  messages/s     : %.0f' % (messages / diss))
    print('  prefixes/s     : %.0f' % (total_prefixes / diss))
    print('  MB/s           : %.1f' % (len(stream) / diss / (1024 * 1024)))
    print('')
    print('primitives are %.1fx the dissector' % (diss / prim))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
