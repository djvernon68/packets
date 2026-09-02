#!/usr/bin/env python3
"""Measure retained parse allocations and model current bulk buffer copies.

The modeled byte count follows the current Ethernet/IPv4/UDP fast path in
``inetpkt.pyx``: one final raw-payload copy plus temporary and retained copies
of the two six-byte MAC addresses. It is a source-derived byte-movement
estimate, not a hardware counter.

Usage:
    python3 bench/allocation_bench.py [objects]
"""

from __future__ import print_function

import gc
import json
import sys
import tracemalloc

from packets.core.inetpkt import Ethernet, IP, IP_CONST, NullPkt, UDP


C = IP_CONST()
PAYLOAD_SIZES = (0, 64, 512, 1400)


def make_raw(payload_size):
    payload = bytes((i & 0xff) for i in range(payload_size))
    packet = Ethernet(
        dst_mac='03:02:03:04:05:06', src_mac='06:05:04:03:02:03',
        payload=IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                   payload=UDP(sport=34567, dport=53,
                               payload=NullPkt(payload))))
    return packet.pkt2net({'csum': 1, 'update': 1})


def modeled_copy_bytes(raw_length):
    return max(0, raw_length - 42) + 24


def measure(raw, object_count):
    for _ in range(100):
        Ethernet(raw)
    gc.collect()
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    objects = [Ethernet(raw) for _ in range(object_count)]
    after = tracemalloc.take_snapshot()
    current, peak = tracemalloc.get_traced_memory()
    differences = after.compare_to(before, 'traceback')
    positive_bytes = sum(item.size_diff for item in differences
                         if item.size_diff > 0)
    positive_allocations = sum(item.count_diff for item in differences
                               if item.count_diff > 0)
    tracemalloc.stop()
    if len(objects) != object_count or not objects[-1].payload.payload:
        raise RuntimeError('parsed objects did not retain their layer graph')
    return {
        'traced_net_bytes_per_packet': positive_bytes / object_count,
        'traced_net_allocations_per_packet': (
            positive_allocations / object_count),
        'traced_current_bytes_per_packet': current / object_count,
        'traced_peak_bytes_per_packet': peak / object_count,
    }


def main():
    object_count = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    if object_count <= 0:
        raise ValueError('objects must be positive')

    results = {
        'objects_per_sample': object_count,
        'copy_model': (
            'one NullPkt payload copy + temporary and retained copies of '
            'two 6-byte MAC addresses'),
        'rows': [],
    }
    for payload_size in PAYLOAD_SIZES:
        raw = make_raw(payload_size)
        row = {
            'payload_bytes': payload_size,
            'wire_bytes': len(raw),
            'modeled_copy_bytes_per_packet': modeled_copy_bytes(len(raw)),
        }
        row.update(measure(raw, object_count))
        results['rows'].append(row)
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()