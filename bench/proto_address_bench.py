#!/usr/bin/env python3
"""Measure the address formatting inside the NetFlow and DHCP decoders.

The protocol modules did not share the core's C address writer, because it
was private to inetpkt.pyx: NetFlow v1/v5/v7 records went through
socket.inet_ntoa on a per address bytes copy, the v9/IPFIX data path called
the platform inet_ntop, and the four BOOTP address properties called
socket.inet_ntop. All three now call _fmt_ipv4_buf from inetpkt.pxd.

Every workload here is synthesized, so the numbers do not depend on a capture
that is not in this repository:

  * v5-1rec  : the sparse datagram shape, one record, three addresses
  * v5-30rec : the dense shape a real exporter sends, 90 addresses
  * v9-ipv4  : a v9 data set of records carrying four IPv4 fields each
  * v9-ipv6  : the same shape in IPv6 -- the control, deliberately left on
               inet_ntop, so it should not move
  * dhcp-decode : decode alone, which never formats an address
  * dhcp-4addr  : decode plus the four address columns a query reads

Usage:
    python3 bench/proto_address_bench.py [iterations] [repeats]
"""

from __future__ import print_function

import gc
import statistics
import struct
import sys
import time

from packets.protos.dhcp import DHCP, DHCP_MAGIC
from packets.protos.netflow import Netflow, NetflowDecodeContext

EXPORTER = '198.51.100.1'
V5_RECORDS = 30
V9_RECORDS = 30
# sourceIPv4Address, destinationIPv4Address, ipNextHopIPv4Address,
# bgpNextHopIPv4Address -- four of them, as a router template carries.
V9_IPV4_FIELDS = ((8, 4), (12, 4), (15, 4), (18, 4), (2, 4))
# sourceIPv6Address, destinationIPv6Address, ipNextHopIPv6Address.
V9_IPV6_FIELDS = ((27, 16), (28, 16), (62, 16), (2, 4))


def v5_datagram(record_count):
    """A v5 datagram of record_count identical records, three addresses each."""
    wire = struct.pack('!HHIIIIBBH', 5, record_count, 100, 200, 300, 0,
                       0, 0, 0)
    body = (b'\x0a\x01\x02\x03' + b'\xc0\xa8\x64\xc8' + b'\x08\x08\x08\x08' +
            struct.pack('!HHIIIIHHBBBBHHBBH', 1, 2, 3, 4, 5, 6, 443, 51000,
                        0, 0x18, 6, 0, 100, 200, 24, 24, 0))
    return wire + body * record_count


def v9_datagrams(template_id, fields, record_count):
    """The template datagram and the data datagram that follows it."""
    template_body = struct.pack('!HH', template_id, len(fields))
    for element_id, length in fields:
        template_body += struct.pack('!HH', element_id, length)
    template_set = (struct.pack('!HH', 0, 4 + len(template_body)) +
                    template_body)
    template_wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 1, 42) +
                     template_set)

    record = b''.join(bytes((length + index) & 0xff for index in
                            range(length))
                      for _element_id, length in fields)
    data_body = record * record_count
    data_set = (struct.pack('!HH', template_id, 4 + len(data_body)) +
                data_body)
    data_wire = (struct.pack('!HHIIII', 9, record_count, 101, 201, 2, 42) +
                 data_set)
    return template_wire, data_wire


def dhcp_datagram():
    return struct.pack(
        '!BBBBIHH4s4s4s4s16s64s128sI',
        1, 1, 6, 0, 0x89abcdef, 12, 0x8000,
        b'\x0a\x00\x00\x63', b'\x0a\x00\x00\x64',
        b'\x0a\x00\x00\x01', b'\x0a\x00\x00\xfe',
        b'\x00\x11\x22\x33\x44\x55' + b'\x00' * 10,
        b'server' + b'\x00' * 58,
        b'boot.img' + b'\x00' * 120,
        DHCP_MAGIC) + b'\x35\x01\x05\x36\x04\x0a\x00\x00\x01\xff'


def bench(label, operation, iterations, repeats, per_call, unit):
    samples = []
    gc.disable()
    try:
        for _ in range(repeats):
            start = time.perf_counter()
            operation(iterations)
            samples.append(time.perf_counter() - start)
    finally:
        gc.enable()
    median_ns = statistics.median(samples) / (iterations * per_call) * 1e9
    print('%-14s median %9.3f ns/%s' % (label, median_ns, unit))


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    repeats = int(sys.argv[2]) if len(sys.argv) > 2 else 7

    sparse = v5_datagram(1)
    dense = v5_datagram(V5_RECORDS)
    v4_template, v4_data = v9_datagrams(256, V9_IPV4_FIELDS, V9_RECORDS)
    v6_template, v6_data = v9_datagrams(257, V9_IPV6_FIELDS, V9_RECORDS)
    wire = dhcp_datagram()

    # One context per family, primed with its template, so the timed loop
    # decodes data records only -- which is what an exporter mostly sends.
    v4_context = NetflowDecodeContext()
    Netflow(v4_template, context=v4_context, exporter=EXPORTER)
    v6_context = NetflowDecodeContext()
    Netflow(v6_template, context=v6_context, exporter=EXPORTER)
    for wire_bytes, context, expected in ((v4_data, v4_context, V9_RECORDS),
                                          (v6_data, v6_context, V9_RECORDS)):
        decoded = Netflow(wire_bytes, context=context, exporter=EXPORTER)
        if len(decoded.records) != expected:
            raise SystemExit('v9 fixture resolved %d of %d records' %
                             (len(decoded.records), expected))

    def run_v5_sparse(count):
        for _ in range(count):
            Netflow(sparse)

    def run_v5_dense(count):
        for _ in range(count):
            Netflow(dense)

    def run_v9_ipv4(count):
        for _ in range(count):
            Netflow(v4_data, context=v4_context, exporter=EXPORTER)

    def run_v9_ipv6(count):
        for _ in range(count):
            Netflow(v6_data, context=v6_context, exporter=EXPORTER)

    def run_dhcp_decode(count):
        for _ in range(count):
            DHCP(wire)

    def run_dhcp_addresses(count):
        for _ in range(count):
            packet = DHCP(wire)
            packet.ciaddr
            packet.yiaddr
            packet.siaddr
            packet.giaddr

    print('iterations=%d repeats=%d (median)' % (iterations, repeats))
    print('-' * 48)
    bench('v5-1rec', run_v5_sparse, iterations, repeats, 1, 'datagram')
    bench('v5-30rec', run_v5_dense, max(iterations // 10, 1), repeats,
          V5_RECORDS, 'record')
    bench('v9-ipv4', run_v9_ipv4, max(iterations // 10, 1), repeats,
          V9_RECORDS, 'record')
    bench('v9-ipv6', run_v9_ipv6, max(iterations // 10, 1), repeats,
          V9_RECORDS, 'record')
    bench('dhcp-decode', run_dhcp_decode, iterations, repeats, 1, 'packet')
    bench('dhcp-4addr', run_dhcp_addresses, iterations, repeats, 1, 'packet')


if __name__ == '__main__':
    main()
