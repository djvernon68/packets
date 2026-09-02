#!/usr/bin/env python3
"""Measure PcapQuery scaling as the requested field count grows.

Usage:
    python3 bench/query_bench.py [packets] [repeats]
"""

from __future__ import print_function

import gc
import os
import statistics
import sys
import tempfile
import time

from packets.core.inetpkt import Ethernet, IP, IP_CONST, NullPkt, UDP
from packets.core.pcap import PCAPWriter
from packets.query.pcap_query import PcapQuery


C = IP_CONST()
FIELD_SETS = (
    ('query_width_1', (
        'eth.src',
    )),
    ('query_width_4', (
        'eth.src', 'eth.dst', 'ip.src', 'ip.dst',
    )),
    ('query_width_8', (
        'eth.src', 'eth.dst', 'ip.src', 'ip.dst',
        'udp.srcport', 'udp.dstport', 'udp.length', 'udp.checksum',
    )),
    ('query_width_16', (
        'eth.src', 'eth.dst', 'ip.src', 'ip.dst',
        'udp.srcport', 'udp.dstport', 'udp.length', 'udp.checksum',
        'frame.time_epoch', 'frame.len', 'frame.caplen', 'eth.type',
        'ip.version', 'ip.hdr_len', 'ip.len', 'ip.ttl',
    )),
)


def make_packet():
    payload = bytes((i & 0xff) for i in range(256))
    packet = Ethernet(
        dst_mac='03:02:03:04:05:06', src_mac='06:05:04:03:02:03',
        payload=IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                   payload=UDP(sport=34567, dport=53,
                               payload=NullPkt(payload))))
    return packet.pkt2net({'csum': 1, 'update': 1})


def make_corpus(packet_count):
    descriptor, path = tempfile.mkstemp(prefix='packets_query_bench_',
                                        suffix='.pcap')
    os.close(descriptor)
    os.remove(path)
    writer = PCAPWriter(filename=path, snaplen=65535)
    raw = make_packet()
    for packet_number in range(packet_count):
        writer.dump_pkt(raw, 1700000000, packet_number)
    writer.close()
    return path


def run_query(path, fields):
    query = PcapQuery(filename=path, wshark_fields=list(fields))
    return len(query.query())


def bench(label, path, fields, packet_count, repeats):
    samples = []
    gc.disable()
    try:
        for _ in range(repeats):
            start = time.perf_counter()
            rows = run_query(path, fields)
            elapsed = time.perf_counter() - start
            if rows != packet_count:
                raise RuntimeError('%s returned %d rows, expected %d' %
                                   (label, rows, packet_count))
            samples.append(elapsed)
    finally:
        gc.enable()
    best = min(samples)
    median = statistics.median(samples)
    best_usec = best / packet_count * 1e6
    median_usec = median / packet_count * 1e6
    median_pps = packet_count / median
    print('%-16s fields=%2d median %8.3f us/pkt  best %8.3f  %10.0f pkt/s' %
          (label, len(fields), median_usec, best_usec, median_pps))


def main():
    packet_count = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    repeats = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    if packet_count <= 0 or repeats <= 0:
        raise ValueError('packets and repeats must be positive')

    path = make_corpus(packet_count)
    try:
        print('packets=%d repeats=%d (median and best)' %
              (packet_count, repeats))
        print('-' * 82)
        for label, fields in FIELD_SETS:
            bench(label, path, fields, packet_count, repeats)
    finally:
        if os.path.exists(path):
            os.remove(path)


if __name__ == '__main__':
    main()