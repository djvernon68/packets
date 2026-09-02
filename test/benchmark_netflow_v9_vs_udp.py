#!/usr/bin/env python

from __future__ import print_function

import argparse
from collections import Counter
import os
import statistics
import timeit

from packets.core.inetpkt import Ethernet
from packets.core.pcap import PCAPReader
from packets.protos.netflow import Netflow, NetflowDecodeContext, NetflowSimple


DEFAULT_PORTS = (2003, 2033, 2055)


def load_v9_frames(filenames, ports, packet_limit):
    context = NetflowDecodeContext()
    l7_ports = {port: Netflow for port in ports}
    frames = []
    counts = Counter()
    capture_errors = []

    for filename in filenames:
        reader = PCAPReader(filename=filename, decode_context=context)
        try:
            while len(frames) < packet_limit:
                try:
                    unused_timestamp, unused_header, wire_data = next(reader)
                except StopIteration:
                    break
                except Exception as error:
                    capture_errors.append((filename, error))
                    break

                counts['frames_examined'] += 1
                try:
                    frame = Ethernet(wire_data, l7_ports=l7_ports,
                                     decode_context=context)
                    packet = frame.get_layer('Netflow')
                    if isinstance(packet, Netflow) and packet.version == 9:
                        frames.append(bytes(wire_data))
                        counts['structured_v9'] += 1
                        counts['records'] += len(packet.records)
                        continue
                    packet = frame.get_layer('NetflowSimple')
                    if (isinstance(packet, NetflowSimple) and
                            packet.version == 9):
                        counts['v9_fallback_skipped'] += 1
                except Exception:
                    counts['decode_errors'] += 1
        finally:
            reader.close()
        if len(frames) >= packet_limit:
            break

    return frames, counts, capture_errors


def benchmark(frames, ports, number, repeat):
    l7_ports = {port: Netflow for port in ports}
    context = NetflowDecodeContext()

    # Prime the stateful registry before timing so data flowsets use their
    # generated record classes rather than measuring cold template discovery.
    for wire_data in frames:
        Ethernet(wire_data, l7_ports=l7_ports, decode_context=context)

    def decode_udp_set():
        packet = None
        for wire_data in frames:
            packet = Ethernet(wire_data)
        return packet

    def decode_netflow_v9_set():
        packet = None
        for wire_data in frames:
            packet = Ethernet(wire_data, l7_ports=l7_ports,
                              decode_context=context)
        return packet

    cases = (
        ('udp_only', decode_udp_set),
        ('netflow_v9', decode_netflow_v9_set),
    )
    results = {}
    for unused_name, operation in cases:
        operation()
    for name, operation in cases:
        samples = timeit.Timer(operation).repeat(repeat=repeat, number=number)
        per_packet = [sample * 1000000.0 / (number * len(frames))
                      for sample in samples]
        results[name] = (statistics.median(per_packet), min(per_packet))
    return results


def print_results(frames, counts, capture_errors, number, repeat, results):
    total_bytes = sum(len(frame) for frame in frames)
    median_size = statistics.median([len(frame) for frame in frames])
    print('packet_set={} bytes={} median_frame_bytes={} records={}'.format(
        len(frames), total_bytes, median_size, counts['records']))
    print('frames_examined={} v9_fallback_skipped={} decode_errors={}'.format(
        counts['frames_examined'], counts['v9_fallback_skipped'],
        counts['decode_errors']))
    for filename, error in capture_errors:
        print('capture_warning {}: {}'.format(os.path.basename(filename),
                                              error))
    print('samples={} set_decodes_per_sample={}'.format(repeat, number))
    print('case          median us/packet  best us/packet  median packets/s')
    print('------------  ----------------  --------------  ----------------')
    for name in ('udp_only', 'netflow_v9'):
        median, best = results[name]
        print('{:<12}  {:>16.3f}  {:>14.3f}  {:>16,.0f}'.format(
            name, median, best, 1000000.0 / median))
    udp_median = results['udp_only'][0]
    netflow_median = results['netflow_v9'][0]
    print('netflow_v9/udp={:.2f}x incremental={:.3f} us/packet'.format(
        netflow_median / udp_median, netflow_median - udp_median))
    if counts['records']:
        print('records_per_packet={:.2f} incremental={:.3f} us/record'.format(
            float(counts['records']) / len(frames),
            (netflow_median - udp_median) * len(frames) /
            counts['records']))


def main():
    parser = argparse.ArgumentParser(
        description='Compare stateful NetFlow v9 and generic UDP decoding '
                    'over the same captured frames.')
    parser.add_argument('capture', nargs='+')
    parser.add_argument('--packets', type=int, default=1000,
                        help='maximum structured v9 frames (default: 1000)')
    parser.add_argument('--number', type=int, default=1,
                        help='set decodes per sample (default: 1)')
    parser.add_argument('--repeat', type=int, default=7,
                        help='sample count (default: 7)')
    parser.add_argument('--port', action='append', type=int, dest='ports',
                        help='NetFlow UDP port; may be repeated')
    args = parser.parse_args()
    if args.packets < 1 or args.number < 1 or args.repeat < 1:
        parser.error('--packets, --number, and --repeat must be positive')
    ports = tuple(args.ports) if args.ports else DEFAULT_PORTS

    frames, counts, capture_errors = load_v9_frames(
        args.capture, ports, args.packets)
    if not frames:
        parser.error('no structured NetFlow v9 frames found')
    results = benchmark(frames, ports, args.number, args.repeat)
    print_results(frames, counts, capture_errors, args.number, args.repeat,
                  results)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())