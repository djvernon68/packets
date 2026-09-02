#!/usr/bin/env python3
"""Measure offline PCAPReader throughput with a competing Python thread.

Usage:
    python3 bench/reader_gil_bench.py --pcap PCAP [--seconds N] [--repeats N]
"""

from __future__ import print_function

import argparse
import statistics
import threading
import time

from packets.core.pcap import PCAPReader


def scan_until(path, duration, with_worker):
    stop = threading.Event()
    worker_count = [0]

    def compete():
        count = 0
        while not stop.is_set():
            count += 1
        worker_count[0] = count

    worker = None
    if with_worker:
        worker = threading.Thread(target=compete)
        worker.start()

    packet_count = 0
    started = time.perf_counter()
    deadline = started + duration
    try:
        while time.perf_counter() < deadline:
            reader = PCAPReader(filename=path)
            for _ in reader:
                packet_count += 1
                if ((packet_count & 4095) == 0 and
                        time.perf_counter() >= deadline):
                    reader.close()
                    break
    finally:
        elapsed = time.perf_counter() - started
        stop.set()
        if worker is not None:
            worker.join()

    return packet_count / elapsed, worker_count[0] / elapsed


def run_case(label, path, duration, repeats, with_worker):
    reader_rates = []
    worker_rates = []
    for _ in range(repeats):
        reader_rate, worker_rate = scan_until(path, duration, with_worker)
        reader_rates.append(reader_rate)
        worker_rates.append(worker_rate)
    print('%-16s reader median %10.0f pkt/s  best %10.0f' %
          (label, statistics.median(reader_rates), max(reader_rates)))
    if with_worker:
        print('%-16s worker median %10.0f loops/s best %10.0f' %
              ('', statistics.median(worker_rates), max(worker_rates)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', required=True,
                        help='capture file to read')
    parser.add_argument('--seconds', type=float, default=3.0,
                        help='minimum duration of each case')
    parser.add_argument('--repeats', type=int, default=5,
                        help='number of samples per case')
    args = parser.parse_args()
    path = args.pcap
    duration = args.seconds
    repeats = args.repeats
    if duration <= 0 or repeats <= 0:
        parser.error('seconds and repeats must be positive')

    print('pcap=%s seconds=%.1f repeats=%d' % (path, duration, repeats))
    run_case('reader_only', path, duration, repeats, False)
    run_case('with_worker', path, duration, repeats, True)


if __name__ == '__main__':
    main()