#!/usr/bin/env python3
"""Measure PcapQuery across the field sets whose cost differs by shape.

query_bench.py measures how cost scales with the *number* of columns, all of
them Ethernet/IPv4/UDP. This measures the shapes where the extraction route
itself differs:

  * frame-only : columns that need no decode at all
  * tcp-fields : TCP columns, which had no compiled descriptor before 2.1.3
  * ipv6-fields: IPv6 columns, likewise
  * mixed-wide : columns spanning layers that not every packet carries, so
                 most cells are the None a missing layer produces

The corpus is a repeating TCP/UDP/IPv6 mix, so every set has packets that
carry its layer and packets that do not.

Usage:
    python3 bench/query_fields_bench.py [packets] [repeats]
"""

from __future__ import print_function

import gc
import os
import statistics
import sys
import tempfile
import time

from packets.core.inetpkt import Ethernet, IP, IP6, IP_CONST, NullPkt, TCP, \
    UDP
from packets.core.pcap import PCAPWriter
from packets.query.pcap_query import PcapQuery

C = IP_CONST()

FIELD_SETS = (
    ('frame-only', (
        'frame.time_epoch', 'frame.len', 'frame.caplen',
    )),
    ('tcp-fields', (
        'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.ack',
        'tcp.flags', 'tcp.window_size_value',
    )),
    ('ipv6-fields', (
        'ipv6.src', 'ipv6.dst', 'ipv6.plen', 'ipv6.nxt',
        'ipv6.hlim', 'ipv6.version',
    )),
    ('mixed-wide', (
        'frame.time_epoch', 'frame.len', 'eth.src', 'eth.dst',
        'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
        'udp.srcport', 'udp.dstport', 'ipv6.src', 'ipv6.dst',
    )),
)
PAYLOAD = bytes((i & 0xff) for i in range(256))


def make_packet(proto):
    """One frame of each shape the corpus mixes."""
    if proto == 'tcp':
        packet = Ethernet(
            dst_mac='03:02:03:04:05:06', src_mac='06:05:04:03:02:03',
            payload=IP(proto=C.PROTO_TCP, src='10.1.2.3', dst='10.3.2.1',
                       payload=TCP(sport=34567, dport=80,
                                   payload=NullPkt(PAYLOAD))))
    elif proto == 'ipv6':
        packet = Ethernet(
            dst_mac='03:02:03:04:05:06', src_mac='06:05:04:03:02:03',
            type=0x86dd,
            payload=IP6(src='fe80::', dst='fe80::1', nxt=C.PROTO_UDP,
                        payload=UDP(sport=34567, dport=53,
                                    payload=NullPkt(PAYLOAD))))
    else:
        packet = Ethernet(
            dst_mac='03:02:03:04:05:06', src_mac='06:05:04:03:02:03',
            payload=IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                       payload=UDP(sport=34567, dport=53,
                                   payload=NullPkt(PAYLOAD))))
    return packet.pkt2net({'csum': 1, 'update': 1})


def make_corpus(packet_count):
    descriptor, path = tempfile.mkstemp(prefix='packets_query_fields_',
                                        suffix='.pcap')
    os.close(descriptor)
    os.remove(path)
    writer = PCAPWriter(filename=path, snaplen=65535)
    shapes = (make_packet('tcp'), make_packet('udp'), make_packet('ipv6'))
    for packet_number in range(packet_count):
        writer.dump_pkt(shapes[packet_number % 3], 1700000000, packet_number)
    writer.close()
    return path


def bench(label, path, fields, packet_count, repeats):
    samples = []
    rows = 0
    gc.disable()
    try:
        for _ in range(repeats):
            query = PcapQuery(filename=path, wshark_fields=list(fields))
            start = time.perf_counter()
            rows = len(query.query())
            samples.append(time.perf_counter() - start)
    finally:
        gc.enable()
    # Per input packet, not per output row: a set whose layer is missing from
    # two thirds of the corpus still reads all of it.
    median_ns = statistics.median(samples) / packet_count * 1e9
    print('%-14s fields=%2d rows=%6d median %9.3f ns/pkt' %
          (label, len(fields), rows, median_ns))


def main():
    packet_count = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    repeats = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    path = make_corpus(packet_count)
    try:
        print('packets=%d repeats=%d (median)' % (packet_count, repeats))
        print('-' * 66)
        for label, fields in FIELD_SETS:
            bench(label, path, fields, packet_count, repeats)
    finally:
        if os.path.exists(path):
            os.remove(path)


if __name__ == '__main__':
    main()
