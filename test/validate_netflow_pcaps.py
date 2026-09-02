#!/usr/bin/env python

from __future__ import print_function

import argparse
from collections import Counter
import os

from packets.core.inetpkt import Ethernet
from packets.core.pcap import PCAPReader
from packets.protos.netflow import Netflow, NetflowDecodeContext, NetflowSimple


def check_capture(filename, ports):
    context = NetflowDecodeContext()
    l7_ports = {port: Netflow for port in ports}
    counts = Counter()
    versions = Counter()

    reader = PCAPReader(filename=filename, decode_context=context)
    while True:
        try:
            unused_timestamp, unused_header, wire_data = next(reader)
        except StopIteration:
            break
        except Exception as error:
            counts['capture_errors'] += 1
            counts['first_capture_error'] = repr(error)
            break
        counts['frames'] += 1
        try:
            frame = Ethernet(wire_data, l7_ports=l7_ports,
                             decode_context=context)
            packet = frame.get_layer('Netflow')
            if not isinstance(packet, Netflow):
                packet = frame.get_layer('NetflowSimple')
                if not isinstance(packet, NetflowSimple):
                    continue
            counts['netflow'] += 1
            versions[packet.version] += 1
            if isinstance(packet, NetflowSimple):
                counts['simple'] += 1
            else:
                counts['structured'] += 1
                counts['records'] += len(packet.records)
                counts['templates'] += sum(
                    len(flowset.templates) for flowset in packet.flowsets)
            if frame.pkt2net({}) != wire_data:
                counts['roundtrip_failures'] += 1
        except Exception as error:
            counts['decode_errors'] += 1
            if counts['decode_errors'] == 1:
                counts['first_error'] = repr(error)
    reader.close()
    return counts, versions


def main():
    parser = argparse.ArgumentParser(
        description='Validate NetFlow PCAP dispatch and round trips.')
    parser.add_argument('capture', nargs='+')
    parser.add_argument('--port', action='append', type=int,
                        default=[2003, 2033, 2055])
    args = parser.parse_args()

    failed = False
    for filename in args.capture:
        counts, versions = check_capture(filename, args.port)
        print('{}: versions={} frames={} netflow={} structured={} simple={} '
              'templates={} records={} capture_errors={} decode_errors={} '
              'roundtrip_failures={}'
              .format(os.path.basename(filename), dict(versions),
                      counts['frames'], counts['netflow'],
                      counts['structured'], counts['simple'],
                      counts['templates'], counts['records'],
                      counts['capture_errors'],
                      counts['decode_errors'], counts['roundtrip_failures']))
        if counts['capture_errors']:
            print('  capture error: {}'.format(
                counts['first_capture_error']))
        if counts['decode_errors']:
            print('  first error: {}'.format(counts['first_error']))
        failed = failed or bool(counts['capture_errors'] or
                                counts['decode_errors'] or
                                counts['roundtrip_failures'])
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())