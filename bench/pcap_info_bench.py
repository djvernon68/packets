#!/usr/bin/env python3
"""Measure repeated complete pcap_info scans.

Usage:
    python3 bench/pcap_info_bench.py --pcap PCAP [--seconds N] [--repeats N]
"""

from __future__ import print_function

import argparse
import statistics
import time

from packets.core.pcap import pcap_info


def sample(path, duration):
    packet_count = 0
    scans = 0
    started = time.perf_counter()
    while time.perf_counter() - started < duration:
        info = pcap_info(path)
        packet_count += info['total_packets']
        scans += 1
    elapsed = time.perf_counter() - started
    return elapsed / packet_count * 1e6, packet_count / elapsed, scans


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', required=True,
                        help='capture file to scan')
    parser.add_argument('--seconds', type=float, default=3.0,
                        help='minimum duration of each sample')
    parser.add_argument('--repeats', type=int, default=5,
                        help='number of samples')
    args = parser.parse_args()
    path = args.pcap
    duration = args.seconds
    repeats = args.repeats
    if duration <= 0 or repeats <= 0:
        parser.error('seconds and repeats must be positive')

    values = [sample(path, duration) for _ in range(repeats)]
    usecs = [value[0] for value in values]
    rates = [value[1] for value in values]
    print('pcap=%s seconds=%.1f repeats=%d' % (path, duration, repeats))
    print('pcap_info median %.4f us/pkt best %.4f  %d pkt/s  scans=%s' %
          (statistics.median(usecs), min(usecs),
           statistics.median(rates),
           ','.join(str(value[2]) for value in values)))


if __name__ == '__main__':
    main()