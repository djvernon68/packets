#!/usr/bin/env python3
"""Cross-library benchmark: selected packets build vs impacket, scapy, dpkt.

Measures operations where each library supports them:
  * parse  - decode a raw Ethernet/IPv4/UDP frame into layer objects
  * build  - construct the same frame from field values and serialize to
             wire bytes (recomputing checksums / lengths)
  * pcaprd - read every raw packet from a pcap file (streaming)
  * pcapdec_ctor - read and decode every packet, then discard the object
  * pcapdec_rawmac - additionally access the six source-MAC bytes on the wire
  * pcapdec - additionally access the library's formatted source MAC
  * pcapdec_udp - additionally detect UDP and access its source port

``--netflow-pcap`` adds a NetFlow decode smoke test over a capture of export
datagrams, which is a different kind of work than the frame operations above:

  * nf_pcaprd - read every raw packet of the NetFlow capture (streaming)
  * nf_simple - decode each datagram without resolving its data sets
  * nf_decode - decode the datagrams with template state shared across the
                whole capture, which is what turns v9/IPFIX data sets into
                flow records

Only a library with a v9/IPFIX decoder can do the last part. The others are
recorded as ``unsupported`` for that operation rather than compared on some
cheaper operation that would look deceptively quick.

``--l7-pcap`` adds a full layer-7 decode comparison over a capture whose frames
carry valid application-layer messages on well-known ports (build it with
``make_corpus.py --l7``). Unlike the frame benchmarks above -- whose opaque L4
ports deliberately keep the payload from being interpreted -- every frame here
decodes all the way to L7, one row per protocol:

  * l7_dns     - DNS over UDP/53
  * l7_dns_tcp - DNS over TCP/53 (packets only; see the fairness note)
  * l7_http    - HTTP request/response over TCP/80
  * l7_dhcp    - BOOTP/DHCPv4 over UDP/67
  * l7_dhcp6   - DHCPv6 over UDP/547
  * l7_netflow - NetFlow v9 over UDP/2055 (template state shared per bucket)

Each library decodes only the protocols it actually supports; a protocol it
cannot decode is recorded as ``unsupported``. The L7 timing is in-memory: the
frames are read once (untimed) and bucketed by protocol, then each op decodes
its bucket from bytes, so the numbers are a pure decode comparison that is not
skewed by each library's different pcap-reader speed (read cost is already the
``pcaprd`` rows over ``--pcap``).

``--gre-pcap`` adds a GRE decode comparison over a capture of GRE frames (build
it with ``make_corpus.py --gre``), one row:

  * gre - decode Ethernet/IPv4|IPv6/GRE and confirm the GRE layer resolved

GRE is dispatched from the IP protocol number (47), which packets, dpkt and
scapy all decode; impacket has no GRE decoder and the libpcap ceiling is only a
frame counter, so both are recorded as ``unsupported``. Timing is in-memory,
like the L7 rows. The point of this comparison is regression detection -- to
catch the packets GRE path drifting toward the pure-Python libraries early --
rather than to prove a win.

Run with PYTHONPATH pointed at the packets build directory.

Expect a full run to take several minutes: every pcap operation samples for at
least ``--pcap-seconds`` and re-reads the whole capture as many times as fit in
that window, and the pure-Python comparison libraries are one to two orders of
magnitude slower per packet than a compiled build. A progress log is written to
stderr as each sample completes so a slow run is distinguishable from a stall;
use ``--libs`` to measure only the libraries of interest.

Fairness notes:
  * packets decodes L2-L4 eagerly and L7 lazily; the ``pcapdec_*`` variants
    exist so the comparison is against equivalent work in each other library
    (raw read, construct-and-discard, raw-MAC access, formatted-MAC access,
    UDP-port access) rather than a single decode depth that would flatter one
    library's laziness.
  * the dpkt ``build`` row presets the wire lengths by hand
    (``udp.ulen``/``ip.len``) before serializing, because dpkt does not
    recompute them. packets and scapy recompute lengths and checksums during
    serialization, so dpkt's build number reflects strictly less work; read
    the build comparison with that caveat in mind.
  * the ``libpcap dispatch`` rows are the C-level ceiling (count / batched
    count / count-plus-touch-MAC via ``pcap_dispatch``); they need the
    ``bench/pcap_dispatch_bench`` extension built first with
    ``python3 bench/setup_dispatch.py build_ext --inplace``.
  * the ``l7_*`` rows carry *valid* protocol payloads, so a full decode is
    representative work for every library (no eager-dissector thrash on random
    bytes). ``l7_dns_tcp`` is packets-only because packets decodes DNS-over-TCP
    from the raw message while dpkt/scapy require the 2-byte length prefix, so
    a single frame cannot feed both fairly; the shared DNS comparison is
    therefore ``l7_dns`` over UDP.
"""
from __future__ import print_function
import argparse
import atexit
import json
import os
import sys
import time
import gc
import statistics

LIB_KEYS = ('packets', 'libpcap', 'impacket', 'scapy', 'dpkt')

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--pcap', required=True,
                    help='capture file used for streaming benchmarks')
parser.add_argument('--netflow-pcap', '--netflow_pcap', dest='netflow_pcap',
                    help='capture of NetFlow/IPFIX export datagrams. When '
                         'given, a NetFlow decode smoke test runs after the '
                         'frame benchmarks. Use a capture that is not cut '
                         'short, since a truncated tail is a reader error '
                         'rather than a measurement.')
parser.add_argument('--netflow-ports', default='2003,2033,2055',
                    help='comma-separated collector UDP ports carrying '
                         'NetFlow in --netflow-pcap (default: %(default)s)')
parser.add_argument('--netflow-seconds', type=float, default=1.0,
                    help='minimum duration of each NetFlow sample. It is a '
                         'smoke test, so this defaults below --pcap-seconds.')
parser.add_argument('--l7-pcap', '--l7_pcap', dest='l7_pcap',
                    help='capture whose frames carry valid application-layer '
                         'payloads on well-known ports (build it with '
                         'make_corpus.py --l7). When given, a full L7 decode '
                         'comparison runs per protocol.')
parser.add_argument('--l7-seconds', type=float, default=1.0,
                    help='minimum duration of each L7 decode sample '
                         '(default: %(default)s)')
parser.add_argument('--gre-pcap', '--gre_pcap', dest='gre_pcap',
                    help='capture of GRE frames (build it with '
                         'make_corpus.py --gre). When given, a GRE decode '
                         'comparison runs against dpkt and scapy.')
parser.add_argument('--gre-seconds', type=float, default=1.0,
                    help='minimum duration of each GRE decode sample '
                         '(default: %(default)s)')
parser.add_argument('--iterations', type=int, default=50000)
parser.add_argument('--repeats', type=int, default=5)
parser.add_argument('--pcap-seconds', type=float, default=3.0,
                    help='minimum duration of each pcap sample')
parser.add_argument('--packets-label', default='packets 2.1',
                    help='result label for the packets build on PYTHONPATH')
parser.add_argument('--libs', default='all',
                    help='comma-separated subset of %s to measure, or "all" '
                         '(default). scapy alone is roughly 70%%%% of a full '
                         'run.' % ','.join(LIB_KEYS))
parser.add_argument('--skip-libs', default='',
                    help='comma-separated libraries to exclude, applied after '
                         '--libs')
parser.add_argument('--out',
                    help='write JSON results to this file instead of stdout. '
                         'Partial results are flushed after every operation, '
                         'so an interrupted run still leaves usable data.')
parser.add_argument('--quiet', action='store_true',
                    help='suppress the stderr progress log')
args = parser.parse_args()
if args.iterations <= 0 or args.repeats <= 0 or args.pcap_seconds <= 0:
    parser.error('iterations, repeats, and pcap-seconds must be positive')
if args.netflow_seconds <= 0:
    parser.error('netflow-seconds must be positive')


def _parse_lib_list(value):
    names = [name.strip() for name in value.split(',') if name.strip()]
    unknown = [name for name in names if name not in LIB_KEYS and name != 'all']
    if unknown:
        parser.error('unknown library name(s): %s (choose from %s)'
                     % (','.join(unknown), ','.join(LIB_KEYS)))
    if 'all' in names:
        return list(LIB_KEYS)
    return names


def _parse_port_list(value):
    ports = []
    for item in value.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError:
            parser.error('--netflow-ports takes integers, got %r' % item)
        if not 0 < port < 65536:
            parser.error('--netflow-ports value out of range: %d' % port)
        if port not in ports:
            ports.append(port)
    if not ports:
        parser.error('--netflow-ports listed no ports')
    return ports


ENABLED_LIBS = [key for key in _parse_lib_list(args.libs)
                if key not in _parse_lib_list(args.skip_libs)]
if not ENABLED_LIBS:
    parser.error('--libs/--skip-libs excluded every library')
if not os.path.isfile(args.pcap):
    parser.error('no such capture file: %s' % args.pcap)
if args.netflow_pcap and not os.path.isfile(args.netflow_pcap):
    parser.error('no such capture file: %s' % args.netflow_pcap)
if args.l7_pcap and not os.path.isfile(args.l7_pcap):
    parser.error('no such capture file: %s' % args.l7_pcap)
if args.l7_seconds <= 0:
    parser.error('l7-seconds must be positive')
if args.gre_pcap and not os.path.isfile(args.gre_pcap):
    parser.error('no such capture file: %s' % args.gre_pcap)
if args.gre_seconds <= 0:
    parser.error('gre-seconds must be positive')

PCAP = args.pcap
NETFLOW_PCAP = args.netflow_pcap
L7_PCAP = args.l7_pcap
GRE_PCAP = args.gre_pcap
NETFLOW_PORTS = _parse_port_list(args.netflow_ports)
PACKETS_LABEL = args.packets_label

SMAC = "00:11:22:33:44:55"
DMAC = "66:77:88:99:aa:bb"
SMAC_B = bytes(bytearray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
DMAC_B = bytes(bytearray([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]))
SIP = "10.1.2.3"
DIP = "10.3.2.1"
SPORT = 34567
DPORT = 53
PAYLOAD = b"benchmark-payload"

N_PARSE = args.iterations
N_BUILD = args.iterations
N_PCAP_PASSES = args.repeats
PCAP_SAMPLE_SECONDS = args.pcap_seconds
NETFLOW_SAMPLE_SECONDS = args.netflow_seconds
L7_SAMPLE_SECONDS = args.l7_seconds
GRE_SAMPLE_SECONDS = args.gre_seconds

RUN_T0 = time.perf_counter()


def log(fmt, *fmt_args):
    """Write a timestamped progress line to stderr and flush it.

    The benchmark emits a single JSON document when it finishes, so without a
    heartbeat a healthy multi-minute run is indistinguishable from a hang -
    especially when stdout is redirected to a file that stays empty until the
    very last write.
    """
    if args.quiet:
        return
    message = fmt % fmt_args if fmt_args else fmt
    sys.stderr.write('[%7.1fs] %s\n' % (time.perf_counter() - RUN_T0, message))
    sys.stderr.flush()


def enabled(key):
    return key in ENABLED_LIBS


def timeit(fn, n, label=''):
    # warm up
    for _ in range(100):
        fn()
    samples = []
    gc.disable()
    try:
        for index in range(args.repeats):
            t0 = time.perf_counter()
            for _ in range(n):
                fn()
            elapsed = time.perf_counter() - t0
            samples.append(elapsed)
            # Logged after the measurement is captured, so the write is never
            # part of a timed region.
            log('    %s sample %d/%d: %.2fs (%.3f us/op)',
                label, index + 1, args.repeats, elapsed, elapsed / n * 1e6)
    finally:
        gc.enable()
    return samples


def time_pcap(fn, passes, label='', seconds=None, source=None):
    # seconds/source are parameters because the NetFlow smoke test samples a
    # different capture for a shorter window than the frame benchmarks.
    seconds = PCAP_SAMPLE_SECONDS if seconds is None else seconds
    source = PCAP if source is None else source
    elapsed_samples = []
    packet_samples = []
    gc.disable()
    try:
        for index in range(passes):
            t0 = time.perf_counter()
            npkts = 0
            file_passes = 0
            while True:
                npkts += fn()
                file_passes += 1
                elapsed = time.perf_counter() - t0
                if elapsed >= seconds:
                    break
            if npkts <= 0:
                # Fail loudly here instead of dividing by zero in record()
                # after the whole run has already been paid for.
                raise RuntimeError('%s read 0 packets from %s'
                                   % (label or 'pcap benchmark', source))
            elapsed_samples.append(elapsed)
            packet_samples.append(npkts)
            log('    %s sample %d/%d: %.2fs, %d packets, %d file pass(es) '
                '(%.3f us/pkt)', label, index + 1, passes, elapsed, npkts,
                file_passes, elapsed / npkts * 1e6)
    finally:
        gc.enable()
    return elapsed_samples, packet_samples


results = {}   # lib -> {op: (per_pkt_us, pkts_per_sec)}
_stdout_written = [False]
_final_written = [False]


def record(lib, op, total_time, count):
    if not isinstance(total_time, (list, tuple)):
        total_time = [total_time]
    if not isinstance(count, (list, tuple)):
        count = [count] * len(total_time)
    for elapsed, packets in zip(total_time, count):
        if elapsed <= 0 or packets <= 0:
            raise ValueError('%s/%s produced an unusable sample '
                             '(%r packets in %r s)' % (lib, op, packets,
                                                       elapsed))
    per_usec = [elapsed / packets * 1e6
                for elapsed, packets in zip(total_time, count)]
    rates = [packets / elapsed
             for elapsed, packets in zip(total_time, count)]
    results.setdefault(lib, {})[op] = {
        'best_us_per_packet': min(per_usec),
        'median_us_per_packet': statistics.median(per_usec),
        'best_packets_per_sec': max(rates),
        'median_packets_per_sec': statistics.median(rates),
        'samples': len(per_usec),
        'sample_packets': list(count),
    }


def dump_results(final=False):
    """Serialize whatever has been measured so far.

    Called after every operation so that ``--out`` always holds current data,
    and registered with atexit so an interrupted or failed run still reports
    the samples it did complete.
    """
    results['_config'] = {
        'iterations': args.iterations,
        'repeats': args.repeats,
        'pcap_min_seconds_per_sample': args.pcap_seconds,
        'pcap': args.pcap,
        'netflow_pcap': args.netflow_pcap,
        'netflow_ports': list(NETFLOW_PORTS),
        'netflow_min_seconds_per_sample': args.netflow_seconds,
        'l7_pcap': args.l7_pcap,
        'l7_min_seconds_per_sample': args.l7_seconds,
        'gre_pcap': args.gre_pcap,
        'gre_min_seconds_per_sample': args.gre_seconds,
        'libs': list(ENABLED_LIBS),
        'elapsed_seconds': round(time.perf_counter() - RUN_T0, 3),
    }
    if final:
        if _final_written[0]:
            return
        _final_written[0] = True
    text = json.dumps(results, indent=2)
    if args.out:
        partial = args.out + '.part'
        with open(partial, 'w') as handle:
            handle.write(text + '\n')
        os.rename(partial, args.out)
        if final:
            log('results written to %s', args.out)
    elif final and not _stdout_written[0]:
        _stdout_written[0] = True
        sys.stdout.write(text + '\n')
        sys.stdout.flush()


atexit.register(dump_results, True)


def bench_op(lib, op, fn, n=None):
    """Time a per-operation benchmark, logging and checkpointing around it."""
    n = N_PARSE if n is None else n
    label = '%s/%s' % (lib, op)
    log('%s: %d iterations x %d repeats', label, n, args.repeats)
    record(lib, op, timeit(fn, n, label), n)
    dump_results()


def bench_pcap_op(lib, op, fn, passes=None, seconds=None, source=None):
    """Time a streaming pcap benchmark, logging and checkpointing around it."""
    passes = N_PCAP_PASSES if passes is None else passes
    seconds = PCAP_SAMPLE_SECONDS if seconds is None else seconds
    label = '%s/%s' % (lib, op)
    log('%s: %d samples of >=%.1fs each', label, passes, seconds)
    elapsed_samples, packet_samples = time_pcap(fn, passes, label, seconds,
                                                source)
    record(lib, op, elapsed_samples, packet_samples)
    dump_results()


def section_skipped(lib, key):
    log('%s: skipped, %s not selected by --libs/--skip-libs', lib, key)
    results.setdefault(lib, {})['skipped'] = 'not selected'


def section_failed(lib, exc):
    # The failure used to be visible only inside the final JSON, so a library
    # that never imported looked like a library that was simply fast.
    log('%s: FAILED, %s: %s', lib, exc.__class__.__name__, exc)
    results.setdefault(lib, {})['error'] = str(exc)
    dump_results()


def section_missing_extension(lib, hint):
    # A not-yet-built benchmark extension is an operator step, not a crash, so
    # it is logged as a plain instruction rather than a scary FAILED/traceback.
    log('%s: not built -- %s', lib, hint)
    results.setdefault(lib, {})['error'] = hint
    dump_results()


DISPATCH_BUILD_HINT = ('build bench/pcap_dispatch_bench first: '
                       'python3 bench/setup_dispatch.py build_ext --inplace')


log('pcap=%s (%.1f MiB)', PCAP, os.path.getsize(PCAP) / 1048576.0)
log('libs=%s iterations=%d repeats=%d pcap-seconds=%.1f',
    ','.join(ENABLED_LIBS), args.iterations, args.repeats, args.pcap_seconds)
log('each selected library runs up to 5 pcap operations of %d x >=%.1fs, so a '
    'full run takes minutes; scapy is by far the slowest',
    args.repeats, args.pcap_seconds)
if NETFLOW_PCAP:
    log('netflow-pcap=%s (%.2f MiB) ports=%s netflow-seconds=%.1f',
        NETFLOW_PCAP, os.path.getsize(NETFLOW_PCAP) / 1048576.0,
        ','.join(str(port) for port in NETFLOW_PORTS), args.netflow_seconds)
else:
    log('netflow smoke test disabled; pass --netflow-pcap to enable it')
if L7_PCAP:
    log('l7-pcap=%s (%.2f MiB) l7-seconds=%.1f',
        L7_PCAP, os.path.getsize(L7_PCAP) / 1048576.0, args.l7_seconds)
else:
    log('L7 decode comparison disabled; pass --l7-pcap to enable it')
if GRE_PCAP:
    log('gre-pcap=%s (%.2f MiB) gre-seconds=%.1f',
        GRE_PCAP, os.path.getsize(GRE_PCAP) / 1048576.0, args.gre_seconds)
else:
    log('GRE decode comparison disabled; pass --gre-pcap to enable it')


# ----------------------------------------------------------------- packets 2.1
# Imported unconditionally: the reference frame built here is the input for
# every other library's parse benchmark.
from packets.core.inetpkt import Ethernet, IP, UDP
from packets.core.pcap import PCAPReader

_e = Ethernet(src_mac=SMAC, dst_mac=DMAC)
_e.payload = IP(proto=17, src=SIP, dst=DIP,
                payload=UDP(sport=SPORT, dport=DPORT, payload=PAYLOAD))
RAW = _e.pkt2net({'csum': 1, 'update': 1})


def build_packets():
    e = Ethernet(src_mac=SMAC, dst_mac=DMAC)
    e.payload = IP(proto=17, src=SIP, dst=DIP,
                   payload=UDP(sport=SPORT, dport=DPORT, payload=PAYLOAD))
    return e.pkt2net({'csum': 1, 'update': 1})


def parse_packets():
    e = Ethernet(RAW)
    return e.payload.payload.sport


def pcap_packets():
    r = PCAPReader(filename=PCAP)
    n = 0
    for _ in r:
        n += 1
    r.close()
    return n


def pcap_decode_packets():
    r = PCAPReader(filename=PCAP)
    n = 0
    for _ts, _hdr, raw in r:
        pkt = Ethernet(raw)
        if isinstance(pkt, Ethernet) and pkt.src_mac:
            n += 1
    r.close()
    return n


def pcap_decode_construct_packets():
    r = PCAPReader(filename=PCAP)
    n = 0
    for _ts, _hdr, raw in r:
        pkt = Ethernet(raw)
        if isinstance(pkt, Ethernet):
            n += 1
    r.close()
    return n


def pcap_decode_raw_mac_packets():
    r = PCAPReader(filename=PCAP)
    n = 0
    for _ts, _hdr, raw in r:
        pkt = Ethernet(raw)
        if isinstance(pkt, Ethernet) and raw[6:12]:
            n += 1
    r.close()
    return n


def pcap_decode_udp_packets():
    r = PCAPReader(filename=PCAP)
    n = 0
    for _ts, _hdr, raw in r:
        pkt = Ethernet(raw)
        if (isinstance(pkt, Ethernet) and isinstance(pkt.payload, IP) and
                isinstance(pkt.payload.payload, UDP)):
            _sport = pkt.payload.payload.sport
        n += 1
    r.close()
    return n


if enabled('packets'):
    log('=== %s ===', PACKETS_LABEL)
    bench_op(PACKETS_LABEL, "build", build_packets, N_BUILD)
    bench_op(PACKETS_LABEL, "parse", parse_packets, N_PARSE)
    bench_pcap_op(PACKETS_LABEL, "pcaprd", pcap_packets)
    bench_pcap_op(PACKETS_LABEL, "pcapdec_ctor", pcap_decode_construct_packets)
    bench_pcap_op(PACKETS_LABEL, "pcapdec_rawmac", pcap_decode_raw_mac_packets)
    bench_pcap_op(PACKETS_LABEL, "pcapdec", pcap_decode_packets)
    bench_pcap_op(PACKETS_LABEL, "pcapdec_udp", pcap_decode_udp_packets)
else:
    section_skipped(PACKETS_LABEL, 'packets')


# ---------------------------------------------------- direct libpcap dispatch
if not enabled('libpcap'):
    section_skipped("libpcap dispatch", 'libpcap')
else:
    log('=== libpcap dispatch ===')
    try:
        from pcap_dispatch_bench import scan_batch, scan_count, scan_extract

        for _batch_size in (16, 64, 256):
            bench_pcap_op("libpcap dispatch", "count_%d" % _batch_size,
                          lambda size=_batch_size: scan_count(PCAP, size))
            bench_pcap_op("libpcap dispatch", "batch_%d" % _batch_size,
                          lambda size=_batch_size: scan_batch(PCAP, size))

            def extract_count(size=_batch_size):
                return scan_extract(PCAP, size)[0]

            bench_pcap_op("libpcap dispatch", "extract_%d" % _batch_size,
                          extract_count)
    except ImportError:
        section_missing_extension("libpcap dispatch", DISPATCH_BUILD_HINT)
    except Exception as e:
        section_failed("libpcap dispatch", e)


# ------------------------------------------------------------------- impacket
if not enabled('impacket'):
    section_skipped("impacket 0.13.1", 'impacket')
else:
    log('=== impacket 0.13.1 ===')
    try:
        from impacket import ImpactPacket
        from impacket.ImpactDecoder import EthDecoder
        _dec = EthDecoder()

        def build_impacket():
            eth = ImpactPacket.Ethernet()
            eth.set_ether_shost(bytearray(SMAC_B))
            eth.set_ether_dhost(bytearray(DMAC_B))
            eth.set_ether_type(0x0800)
            ip = ImpactPacket.IP()
            ip.set_ip_src(SIP)
            ip.set_ip_dst(DIP)
            udp = ImpactPacket.UDP()
            udp.set_uh_sport(SPORT)
            udp.set_uh_dport(DPORT)
            udp.contains(ImpactPacket.Data(PAYLOAD))
            ip.contains(udp)
            eth.contains(ip)
            return eth.get_packet()

        def parse_impacket():
            p = _dec.decode(RAW)
            return p.child().child().get_uh_sport()

        bench_op("impacket 0.13.1", "build", build_impacket, N_BUILD)
        bench_op("impacket 0.13.1", "parse", parse_impacket, N_PARSE)
        for _unsupported_op in ('pcaprd', 'pcapdec_ctor', 'pcapdec_rawmac',
                                'pcapdec', 'pcapdec_udp'):
            results["impacket 0.13.1"][_unsupported_op] = {
                'unsupported': 'impacket has no native pcap file reader'
            }
        dump_results()
    except Exception as e:
        section_failed("impacket 0.13.1", e)


# ---------------------------------------------------------------------- scapy
if not enabled('scapy'):
    section_skipped("scapy 2.5.0", 'scapy')
else:
    log('=== scapy 2.5.0 (slowest section, ~70% of a full run) ===')
    try:
        from scapy.all import Ether, IP as ScIP, UDP as ScUDP, Raw
        from scapy.utils import RawPcapReader
        import scapy.all as _scapy_all

        def build_scapy():
            pkt = (Ether(src=SMAC, dst=DMAC) /
                   ScIP(src=SIP, dst=DIP) /
                   ScUDP(sport=SPORT, dport=DPORT) /
                   Raw(PAYLOAD))
            return bytes(pkt)

        def parse_scapy():
            pkt = Ether(RAW)
            return pkt[ScUDP].sport

        def pcap_scapy():
            n = 0
            rdr = RawPcapReader(PCAP)
            for _ in rdr:
                n += 1
            rdr.close()
            return n

        def pcap_decode_scapy():
            n = 0
            rdr = RawPcapReader(PCAP)
            for raw, _meta in rdr:
                pkt = Ether(raw)
                if Ether in pkt and pkt[Ether].src:
                    n += 1
            rdr.close()
            return n

        def pcap_decode_construct_scapy():
            n = 0
            rdr = RawPcapReader(PCAP)
            for raw, _meta in rdr:
                pkt = Ether(raw)
                if Ether in pkt:
                    n += 1
            rdr.close()
            return n

        def pcap_decode_raw_mac_scapy():
            n = 0
            rdr = RawPcapReader(PCAP)
            for raw, _meta in rdr:
                pkt = Ether(raw)
                if Ether in pkt and raw[6:12]:
                    n += 1
            rdr.close()
            return n

        def pcap_decode_udp_scapy():
            n = 0
            rdr = RawPcapReader(PCAP)
            for raw, _meta in rdr:
                pkt = Ether(raw)
                if ScUDP in pkt:
                    _sport = pkt[ScUDP].sport
                n += 1
            rdr.close()
            return n

        bench_op("scapy 2.5.0", "build", build_scapy, N_BUILD)
        bench_op("scapy 2.5.0", "parse", parse_scapy, N_PARSE)
        bench_pcap_op("scapy 2.5.0", "pcaprd", pcap_scapy)
        bench_pcap_op("scapy 2.5.0", "pcapdec_ctor",
                      pcap_decode_construct_scapy)
        bench_pcap_op("scapy 2.5.0", "pcapdec_rawmac",
                      pcap_decode_raw_mac_scapy)
        bench_pcap_op("scapy 2.5.0", "pcapdec", pcap_decode_scapy)
        bench_pcap_op("scapy 2.5.0", "pcapdec_udp", pcap_decode_udp_scapy)
    except Exception as e:
        section_failed("scapy 2.5.0", e)


# ----------------------------------------------------------------------- dpkt
if not enabled('dpkt'):
    section_skipped("dpkt 1.9.8", 'dpkt')
else:
    log('=== dpkt 1.9.8 ===')
    try:
        import dpkt
        import socket as _sock

        _sip_b = _sock.inet_aton(SIP)
        _dip_b = _sock.inet_aton(DIP)

        def build_dpkt():
            udp = dpkt.udp.UDP(sport=SPORT, dport=DPORT, data=PAYLOAD)
            udp.ulen = 8 + len(PAYLOAD)
            ip = dpkt.ip.IP(src=_sip_b, dst=_dip_b, p=17, data=udp)
            ip.len = 20 + udp.ulen
            eth = dpkt.ethernet.Ethernet(src=SMAC_B, dst=DMAC_B,
                                         type=0x0800, data=ip)
            return bytes(eth)

        def parse_dpkt():
            eth = dpkt.ethernet.Ethernet(RAW)
            return eth.data.data.sport

        def pcap_dpkt():
            n = 0
            f = open(PCAP, 'rb')
            for _ts, _buf in dpkt.pcap.Reader(f):
                n += 1
            f.close()
            return n

        def pcap_decode_dpkt():
            n = 0
            f = open(PCAP, 'rb')
            for _ts, raw in dpkt.pcap.Reader(f):
                pkt = dpkt.ethernet.Ethernet(raw)
                if isinstance(pkt, dpkt.ethernet.Ethernet) and pkt.src:
                    n += 1
            f.close()
            return n

        def pcap_decode_construct_dpkt():
            n = 0
            f = open(PCAP, 'rb')
            for _ts, raw in dpkt.pcap.Reader(f):
                pkt = dpkt.ethernet.Ethernet(raw)
                if isinstance(pkt, dpkt.ethernet.Ethernet):
                    n += 1
            f.close()
            return n

        def pcap_decode_raw_mac_dpkt():
            n = 0
            f = open(PCAP, 'rb')
            for _ts, raw in dpkt.pcap.Reader(f):
                pkt = dpkt.ethernet.Ethernet(raw)
                if isinstance(pkt, dpkt.ethernet.Ethernet) and raw[6:12]:
                    n += 1
            f.close()
            return n

        def pcap_decode_udp_dpkt():
            n = 0
            f = open(PCAP, 'rb')
            for _ts, raw in dpkt.pcap.Reader(f):
                pkt = dpkt.ethernet.Ethernet(raw)
                if (isinstance(pkt.data, dpkt.ip.IP) and
                        isinstance(pkt.data.data, dpkt.udp.UDP)):
                    _sport = pkt.data.data.sport
                n += 1
            f.close()
            return n

        bench_op("dpkt 1.9.8", "build", build_dpkt, N_BUILD)
        bench_op("dpkt 1.9.8", "parse", parse_dpkt, N_PARSE)
        bench_pcap_op("dpkt 1.9.8", "pcaprd", pcap_dpkt)
        bench_pcap_op("dpkt 1.9.8", "pcapdec_ctor", pcap_decode_construct_dpkt)
        bench_pcap_op("dpkt 1.9.8", "pcapdec_rawmac", pcap_decode_raw_mac_dpkt)
        bench_pcap_op("dpkt 1.9.8", "pcapdec", pcap_decode_dpkt)
        bench_pcap_op("dpkt 1.9.8", "pcapdec_udp", pcap_decode_udp_dpkt)
    except Exception as e:
        section_failed("dpkt 1.9.8", e)


# ------------------------------------------------- NetFlow decode smoke test
# A NetFlow export capture exercises a decode path the frame benchmarks never
# reach. Every datagram is UDP payload that has to be walked flowset by
# flowset, and a v9/IPFIX data set only becomes flow records once the template
# announced in some other datagram of the same capture has been learned, so
# the decoder has to carry state across the file. Libraries without a v9/IPFIX
# decoder are recorded as unsupported here: timing them on a header peek they
# cannot resolve would read as a win rather than as a missing feature.
NETFLOW_OPS = ('nf_pcaprd', 'nf_simple', 'nf_decode')


def netflow_unsupported(lib, reason, ops=NETFLOW_OPS):
    for op in ops:
        results.setdefault(lib, {})[op] = {'unsupported': reason}
    log('%s: %s', lib, reason)
    dump_results()


def netflow_datagram_probe(fn):
    """Build a probe reporting the datagram count one pass of fn produced."""
    def probe():
        return {'datagrams': fn()}
    return probe


def bench_netflow_op(lib, op, fn, probe=None):
    """Verify with one untimed pass, then time the operation.

    A decoder that quietly produced nothing would otherwise be timed as the
    fastest of the group, so the probe counts what came out before any
    measurement is taken and its counts are kept beside the timings. The
    failure is scoped to one operation because a library can read the file
    and walk the datagrams and still not resolve a template in it.
    """
    try:
        if probe is not None:
            counts = probe()
            log('  %s/%s decoded: %s', lib, op, ' '.join(
                '%s=%s' % (name, counts[name]) for name in sorted(counts)))
            results.setdefault(lib, {})['%s_counts' % op] = dict(counts)
            dump_results()
            if not counts.get('datagrams'):
                raise RuntimeError('decoded no NetFlow datagrams from %s'
                                   % NETFLOW_PCAP)
        bench_pcap_op(lib, op, fn, seconds=NETFLOW_SAMPLE_SECONDS,
                      source=NETFLOW_PCAP)
    except Exception as exc:
        log('%s/%s: FAILED, %s: %s', lib, op, exc.__class__.__name__, exc)
        results.setdefault(lib, {})[op] = {'error': str(exc)}
        dump_results()


if not NETFLOW_PCAP:
    log('=== NetFlow decode smoke test: skipped, no --netflow-pcap ===')
else:
    log('=== NetFlow decode smoke test: %s ===',
        os.path.basename(NETFLOW_PCAP))

    # ------------------------------------------------------------ packets 2.1
    if not enabled('packets'):
        log('%s: NetFlow smoke test skipped, packets not selected',
            PACKETS_LABEL)
    else:
        try:
            from packets.protos.netflow import (Netflow, NetflowDecodeContext,
                                                NetflowSimple)

            NF_L7_PORTS = {port: Netflow for port in NETFLOW_PORTS}

            def netflow_read_packets():
                r = PCAPReader(filename=NETFLOW_PCAP)
                n = 0
                for _ in r:
                    n += 1
                r.close()
                return n

            def netflow_simple_packets():
                # force_simple bypasses template learning, so this is the
                # header-only cost with the data sets left as wire bytes.
                context = NetflowDecodeContext(force_simple=True)
                r = PCAPReader(filename=NETFLOW_PCAP, decode_context=context)
                n = 0
                for _ts, _hdr, raw in r:
                    frame = Ethernet(raw, l7_ports=NF_L7_PORTS,
                                     decode_context=context)
                    if isinstance(frame.get_layer('NetflowSimple'),
                                  NetflowSimple):
                        n += 1
                r.close()
                return n

            def netflow_decode_packets():
                # One context for the whole file: data sets decode structurally
                # once their template has been seen.
                context = NetflowDecodeContext()
                r = PCAPReader(filename=NETFLOW_PCAP, decode_context=context)
                n = 0
                for _ts, _hdr, raw in r:
                    frame = Ethernet(raw, l7_ports=NF_L7_PORTS,
                                     decode_context=context)
                    if isinstance(frame.get_layer('Netflow'), Netflow):
                        n += 1
                r.close()
                return n

            def netflow_counts_packets():
                counts = {'frames': 0, 'datagrams': 0, 'structured': 0,
                          'fallback': 0, 'templates': 0, 'records': 0}
                context = NetflowDecodeContext()
                r = PCAPReader(filename=NETFLOW_PCAP, decode_context=context)
                for _ts, _hdr, raw in r:
                    counts['frames'] += 1
                    frame = Ethernet(raw, l7_ports=NF_L7_PORTS,
                                     decode_context=context)
                    packet = frame.get_layer('Netflow')
                    if isinstance(packet, Netflow):
                        counts['datagrams'] += 1
                        counts['structured'] += 1
                        counts['records'] += len(packet.records)
                        counts['templates'] += sum(
                            len(flowset.templates)
                            for flowset in packet.flowsets)
                    elif isinstance(frame.get_layer('NetflowSimple'),
                                    NetflowSimple):
                        # A data set that arrives before its template falls
                        # back to NetflowSimple, which is expected at the head
                        # of a capture that re-announces templates later.
                        counts['datagrams'] += 1
                        counts['fallback'] += 1
                r.close()
                return counts

            bench_netflow_op(PACKETS_LABEL, 'nf_pcaprd', netflow_read_packets)
            bench_netflow_op(PACKETS_LABEL, 'nf_simple',
                             netflow_simple_packets,
                             netflow_datagram_probe(netflow_simple_packets))
            bench_netflow_op(PACKETS_LABEL, 'nf_decode',
                             netflow_decode_packets, netflow_counts_packets)
        except Exception as e:
            section_failed(PACKETS_LABEL, e)

    # --------------------------------------------------------------- libpcap
    if enabled('libpcap'):
        try:
            from pcap_dispatch_bench import scan_count

            bench_netflow_op("libpcap dispatch", 'nf_pcaprd',
                             lambda: scan_count(NETFLOW_PCAP, 64))
            netflow_unsupported("libpcap dispatch",
                                'libpcap dispatch hands frames to a counter; '
                                'it has no NetFlow decoder',
                                ('nf_simple', 'nf_decode'))
        except ImportError:
            section_missing_extension("libpcap dispatch", DISPATCH_BUILD_HINT)
        except Exception as e:
            section_failed("libpcap dispatch", e)

    # -------------------------------------------------------------- impacket
    if enabled('impacket'):
        netflow_unsupported("impacket 0.13.1",
                            'impacket has no native pcap file reader and no '
                            'NetFlow decoder')

    # ----------------------------------------------------------------- scapy
    if enabled('scapy'):
        try:
            from scapy.all import Ether as NfEther
            from scapy.config import conf as scapy_conf
            from scapy.utils import RawPcapReader as NfRawPcapReader
            try:
                # 2.4.4 and later ship the NetFlow layer in scapy.layers.
                from scapy.layers.netflow import (NetflowHeader,
                                                  NetflowFlowsetV9,
                                                  NetflowDataflowsetV9,
                                                  netflowv9_defragment)
            except ImportError:
                from scapy.contrib.netflow import (NetflowHeader,
                                                   NetflowFlowsetV9,
                                                   NetflowDataflowsetV9,
                                                   netflowv9_defragment)

            # A data set seen before its template warns once per pass
            # otherwise, which would both spam the log and be timed.
            scapy_conf.verb = 0

            def netflow_read_scapy():
                n = 0
                rdr = NfRawPcapReader(NETFLOW_PCAP)
                for _ in rdr:
                    n += 1
                rdr.close()
                return n

            def netflow_simple_scapy():
                # scapy has no header-only mode: dissection walks the flowsets
                # but leaves each data set as one raw pseudo-record until
                # netflowv9_defragment resolves it against a template.
                n = 0
                rdr = NfRawPcapReader(NETFLOW_PCAP)
                for raw, _meta in rdr:
                    pkt = NfEther(raw)
                    if NetflowHeader in pkt:
                        n += 1
                rdr.close()
                return n

            def netflow_decode_scapy():
                # Known scapy limitation to expect here: it generates a record
                # class per template and its metaclass builds an inspect
                # signature from the field names, so a template whose fields
                # map to a repeated scapy name - an options template often
                # does - raises ValueError instead of decoding. Only this
                # operation is recorded as failed when that happens.
                rdr = NfRawPcapReader(NETFLOW_PCAP)
                plist = [NfEther(raw) for raw, _meta in rdr]
                rdr.close()
                # Templates and data sets are matched across the whole list,
                # which is scapy's equivalent of a shared decode context.
                netflowv9_defragment(plist)
                n = 0
                for pkt in plist:
                    if NetflowHeader in pkt:
                        n += 1
                return n

            def netflow_counts_scapy():
                counts = {'frames': 0, 'datagrams': 0, 'templates': 0,
                          'records': 0}
                rdr = NfRawPcapReader(NETFLOW_PCAP)
                plist = []
                for raw, _meta in rdr:
                    counts['frames'] += 1
                    plist.append(NfEther(raw))
                rdr.close()
                netflowv9_defragment(plist)
                for pkt in plist:
                    if NetflowHeader not in pkt:
                        continue
                    counts['datagrams'] += 1
                    layer = pkt.getlayer(NetflowFlowsetV9)
                    while layer is not None:
                        counts['templates'] += len(layer.templates)
                        layer = layer.payload.getlayer(NetflowFlowsetV9)
                    layer = pkt.getlayer(NetflowDataflowsetV9)
                    while layer is not None:
                        counts['records'] += len(layer.records)
                        layer = layer.payload.getlayer(NetflowDataflowsetV9)
                return counts

            bench_netflow_op("scapy 2.5.0", 'nf_pcaprd', netflow_read_scapy)
            bench_netflow_op("scapy 2.5.0", 'nf_simple', netflow_simple_scapy,
                             netflow_datagram_probe(netflow_simple_scapy))
            bench_netflow_op("scapy 2.5.0", 'nf_decode', netflow_decode_scapy,
                             netflow_counts_scapy)
        except Exception as e:
            section_failed("scapy 2.5.0", e)

    # ------------------------------------------------------------------ dpkt
    if enabled('dpkt'):
        try:
            import dpkt as nf_dpkt

            def netflow_read_dpkt():
                n = 0
                f = open(NETFLOW_PCAP, 'rb')
                for _ts, _buf in nf_dpkt.pcap.Reader(f):
                    n += 1
                f.close()
                return n

            bench_netflow_op("dpkt 1.9.8", 'nf_pcaprd', netflow_read_dpkt)
            netflow_unsupported("dpkt 1.9.8",
                                'dpkt.netflow models v1/v5/v6/v7 only and has '
                                'no template handling, so it cannot decode a '
                                'v9/IPFIX datagram',
                                ('nf_simple', 'nf_decode'))
        except Exception as e:
            section_failed("dpkt 1.9.8", e)


# ------------------------------------------------ full layer-7 decode compare
# The --l7-pcap capture carries valid application-layer messages on well-known
# ports, so decoding it exercises the full L2..L7 stack rather than the opaque
# payload the frame benchmarks leave alone. Each library decodes every protocol
# it actually supports; a protocol a library cannot decode is recorded as
# unsupported rather than timed on a cheaper peek that would read as a win.
#
# Timing is in-memory: the raw frames are read once (untimed) and bucketed by
# protocol, then each per-protocol op decodes its bucket from bytes. Read cost
# is deliberately excluded so the number is a pure decode comparison and is not
# skewed by each library's different pcap reader speed (that read cost is
# already reported by the pcaprd rows over --pcap).
L7_OPS = ('l7_dns', 'l7_dns_tcp', 'l7_http', 'l7_dhcp', 'l7_dhcp6',
          'l7_netflow')

# (l4 proto, dst port) -> bucket name. Every shape the make_corpus --l7 writer
# emits lands its well-known port on the destination side, so dport classifies.
L7_CLASSIFY = {
    ('udp', 53): 'dns_udp',
    ('tcp', 53): 'dns_tcp',
    ('tcp', 80): 'http',
    ('udp', 67): 'dhcp',
    ('udp', 547): 'dhcp6',
    ('udp', 2055): 'netflow',
}
L7_BUCKET_ORDER = ('dns_udp', 'dns_tcp', 'http', 'dhcp', 'dhcp6', 'netflow')


def _l7_classify(raw):
    """Return the bucket name for a raw frame, or None if it is not L7 corpus.

    A tiny struct-free parse (Ethernet II + IPv4/IPv6 + UDP/TCP) is enough for
    this capture and stays library-agnostic, so the same buckets feed every
    library without any one library's decoder shaping the classification.
    """
    if len(raw) < 14:
        return None
    ethtype = (raw[12] << 8) | raw[13]
    offset = 14
    if ethtype == 0x0800:
        if len(raw) < offset + 20:
            return None
        proto = raw[offset + 9]
        offset += (raw[offset] & 0x0f) * 4
    elif ethtype == 0x86dd:
        if len(raw) < offset + 40:
            return None
        proto = raw[offset + 6]
        offset += 40
    else:
        return None
    if proto == 17:
        name = 'udp'
    elif proto == 6:
        name = 'tcp'
    else:
        return None
    if len(raw) < offset + 4:
        return None
    dport = (raw[offset + 2] << 8) | raw[offset + 3]
    return L7_CLASSIFY.get((name, dport))


def _load_l7_buckets():
    buckets = dict((name, []) for name in L7_BUCKET_ORDER)
    reader = PCAPReader(filename=L7_PCAP)
    try:
        for _ts, _hdr, raw in reader:
            frame = bytes(raw)
            name = _l7_classify(frame)
            if name is not None:
                buckets[name].append(frame)
    finally:
        reader.close()
    return buckets


def _l7_probe(fn):
    """Wrap a decode fn so bench_l7_op can verify it resolved something."""
    def probe():
        return {'decoded': fn()}
    return probe


def bench_l7_op(lib, op, fn, verify=None):
    """Verify one untimed decode pass resolves, then time the operation."""
    try:
        if verify is not None:
            counts = verify()
            log('  %s/%s decoded: %s', lib, op, ' '.join(
                '%s=%s' % (name, counts[name]) for name in sorted(counts)))
            results.setdefault(lib, {})['%s_counts' % op] = dict(counts)
            dump_results()
            if not counts.get('decoded'):
                raise RuntimeError('%s decoded nothing from %s' % (op, L7_PCAP))
        bench_pcap_op(lib, op, fn, seconds=L7_SAMPLE_SECONDS, source=L7_PCAP)
    except Exception as exc:
        log('%s/%s: FAILED, %s: %s', lib, op, exc.__class__.__name__, exc)
        results.setdefault(lib, {})[op] = {'error': str(exc)}
        dump_results()


def l7_unsupported(lib, ops, reason):
    for op in ops:
        results.setdefault(lib, {})[op] = {'unsupported': reason}
    log('%s: %s', lib, reason)
    dump_results()


if not L7_PCAP:
    log('=== full L7 decode comparison: skipped, no --l7-pcap ===')
else:
    log('=== full L7 decode comparison: %s ===', os.path.basename(L7_PCAP))
    L7_BUCKETS = _load_l7_buckets()
    log('l7 buckets: %s', ' '.join(
        '%s=%d' % (name, len(L7_BUCKETS[name])) for name in L7_BUCKET_ORDER))
    _empty = [name for name in L7_BUCKET_ORDER if not L7_BUCKETS[name]]
    if _empty:
        log('l7 capture is missing protocols: %s -- rebuild it with '
            'make_corpus.py --l7', ','.join(_empty))

    # ------------------------------------------------------------ packets 2.1
    if not enabled('packets'):
        log('%s: L7 decode skipped, packets not selected', PACKETS_LABEL)
    else:
        # Import each protocol module independently so a packets build that
        # lacks one still benches the protocols it does have, marking the rest
        # unsupported, instead of failing the whole column. This makes the L7
        # comparison capability-aware across releases: e.g. 2.0.2 ships only
        # packets.protos.dns (no dhcp/http/netflow), and the v9 netflow module
        # arrived at 2.1.6, so an older build contributes just its DNS row.
        L7_PORTS = {}
        _l7_missing = {}
        try:
            from packets.protos.dns import DNS as L7DNS
            L7_PORTS[53] = L7DNS
        except ImportError as _exc:
            L7DNS = None
            _l7_missing['dns'] = str(_exc)
        try:
            from packets.protos.http import HTTP as L7HTTP
            L7_PORTS[80] = L7HTTP
        except ImportError as _exc:
            L7HTTP = None
            _l7_missing['http'] = str(_exc)
        try:
            from packets.protos.dhcp import DHCP as L7DHCP, DHCP6 as L7DHCP6
            L7_PORTS[67] = L7DHCP
            L7_PORTS[547] = L7DHCP6
        except ImportError as _exc:
            L7DHCP = None
            L7DHCP6 = None
            _l7_missing['dhcp'] = str(_exc)
        try:
            from packets.protos.netflow import (Netflow as L7Netflow,
                                                NetflowDecodeContext)
            L7_PORTS[2055] = L7Netflow
        except ImportError as _exc:
            L7Netflow = None
            NetflowDecodeContext = None
            _l7_missing['netflow'] = str(_exc)

        def _packets_decode(bucket, name, cls):
            n = 0
            for raw in L7_BUCKETS[bucket]:
                frame = Ethernet(raw, l7_ports=L7_PORTS)
                if isinstance(frame.get_layer(name), cls):
                    n += 1
            return n

        def _packets_netflow():
            # One decode context for the whole bucket: a data set resolves
            # once the template (emitted periodically by the generator) has
            # been learned, exactly as a live collector would carry state.
            context = NetflowDecodeContext()
            n = 0
            for raw in L7_BUCKETS['netflow']:
                frame = Ethernet(raw, l7_ports=L7_PORTS,
                                 decode_context=context)
                if isinstance(frame.get_layer('Netflow'), L7Netflow):
                    n += 1
            return n

        def _packets_decoder(bucket, name, cls):
            # bind the loop values so each op decodes its own bucket/class.
            return lambda: _packets_decode(bucket, name, cls)

        # (op, module key, decode fn). A protocol whose module did not import
        # is recorded unsupported with the ImportError reason, not benched.
        _packets_l7_ops = (
            ('l7_dns', 'dns', _packets_decoder('dns_udp', 'DNS', L7DNS)),
            ('l7_dns_tcp', 'dns', _packets_decoder('dns_tcp', 'DNS', L7DNS)),
            ('l7_http', 'http', _packets_decoder('http', 'HTTP', L7HTTP)),
            ('l7_dhcp', 'dhcp', _packets_decoder('dhcp', 'DHCP', L7DHCP)),
            ('l7_dhcp6', 'dhcp', _packets_decoder('dhcp6', 'DHCP6', L7DHCP6)),
            ('l7_netflow', 'netflow', _packets_netflow),
        )
        for _op, _key, _fn in _packets_l7_ops:
            if _key in _l7_missing:
                l7_unsupported(PACKETS_LABEL, (_op,),
                               'this packets build has no packets.protos.%s '
                               '(%s)' % (_key, _l7_missing[_key]))
            else:
                bench_l7_op(PACKETS_LABEL, _op, _fn, _l7_probe(_fn))

    # ----------------------------------------------------------- libpcap
    if enabled('libpcap'):
        l7_unsupported("libpcap dispatch", L7_OPS,
                       'libpcap dispatch is a C frame counter, not an L7 '
                       'decoder')

    # ---------------------------------------------------------- impacket
    if enabled('impacket'):
        l7_unsupported("impacket 0.13.1", L7_OPS,
                       'impacket has no native pcap reader and no DNS/HTTP/'
                       'DHCP/NetFlow decoders')

    # ------------------------------------------------------------- dpkt
    if enabled('dpkt'):
        try:
            import dpkt
            import dpkt.dns
            import dpkt.dhcp
            import dpkt.http
            import dpkt.ethernet

            def _dpkt_l4_payload(raw):
                eth = dpkt.ethernet.Ethernet(raw)
                return bytes(eth.data.data.data)

            def _dpkt_dns():
                n = 0
                for raw in L7_BUCKETS['dns_udp']:
                    msg = dpkt.dns.DNS(_dpkt_l4_payload(raw))
                    if msg.qd or msg.an:
                        n += 1
                return n

            def _dpkt_http():
                n = 0
                for raw in L7_BUCKETS['http']:
                    payload = _dpkt_l4_payload(raw)
                    try:
                        dpkt.http.Request(payload)
                    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
                        dpkt.http.Response(payload)
                    n += 1
                return n

            def _dpkt_dhcp():
                n = 0
                for raw in L7_BUCKETS['dhcp']:
                    dpkt.dhcp.DHCP(_dpkt_l4_payload(raw))
                    n += 1
                return n

            bench_l7_op("dpkt 1.9.8", 'l7_dns', _dpkt_dns,
                        _l7_probe(_dpkt_dns))
            bench_l7_op("dpkt 1.9.8", 'l7_http', _dpkt_http,
                        _l7_probe(_dpkt_http))
            bench_l7_op("dpkt 1.9.8", 'l7_dhcp', _dpkt_dhcp,
                        _l7_probe(_dpkt_dhcp))
            l7_unsupported("dpkt 1.9.8", ('l7_dns_tcp',),
                           'DNS-over-TCP framing differs: this corpus carries '
                           'the raw message packets decodes, without the '
                           '2-byte length prefix dpkt requires')
            l7_unsupported("dpkt 1.9.8", ('l7_dhcp6',),
                           'dpkt has no DHCPv6 decoder')
            l7_unsupported("dpkt 1.9.8", ('l7_netflow',),
                           'dpkt.netflow models v1/v5/v6/v7 only, with no v9 '
                           'template handling')
        except Exception as e:
            section_failed("dpkt 1.9.8", e)

    # ------------------------------------------------------------ scapy
    if enabled('scapy'):
        try:
            from scapy.all import Ether as L7Ether
            from scapy.config import conf as l7_conf
            from scapy.layers.dns import DNS as ScDNS
            from scapy.layers.dhcp import BOOTP as ScBOOTP
            from scapy.layers.dhcp6 import DHCP6 as ScDHCP6
            # Importing the http layer registers the port-80 bindings, so a
            # plain Ether(raw) dissects the request/response through to HTTP.
            from scapy.layers.http import HTTP as ScHTTP
            try:
                from scapy.layers.netflow import (NetflowHeader as ScNfHeader,
                                                  netflowv9_defragment)
            except ImportError:
                from scapy.contrib.netflow import (NetflowHeader as ScNfHeader,
                                                   netflowv9_defragment)

            l7_conf.verb = 0

            def _scapy_haslayer(bucket, layer):
                n = 0
                for raw in L7_BUCKETS[bucket]:
                    if layer in L7Ether(raw):
                        n += 1
                return n

            def _scapy_dhcp6():
                # DHCPv6 messages dissect to per-type subclasses (DHCP6_Solicit
                # ...), so match on the family by layer-name prefix rather than
                # a single class, which stays robust across scapy versions.
                n = 0
                for raw in L7_BUCKETS['dhcp6']:
                    pkt = L7Ether(raw)
                    if any(cls.__name__.startswith('DHCP6')
                           for cls in pkt.layers()):
                        n += 1
                return n

            def _scapy_netflow():
                # netflowv9_defragment matches data sets to templates across
                # the whole list, scapy's equivalent of a shared decode state.
                plist = [L7Ether(raw) for raw in L7_BUCKETS['netflow']]
                netflowv9_defragment(plist)
                n = 0
                for pkt in plist:
                    if ScNfHeader in pkt:
                        n += 1
                return n

            _scapy_dns = lambda: _scapy_haslayer('dns_udp', ScDNS)
            _scapy_http = lambda: _scapy_haslayer('http', ScHTTP)
            _scapy_dhcp = lambda: _scapy_haslayer('dhcp', ScBOOTP)

            bench_l7_op("scapy 2.5.0", 'l7_dns', _scapy_dns,
                        _l7_probe(_scapy_dns))
            bench_l7_op("scapy 2.5.0", 'l7_http', _scapy_http,
                        _l7_probe(_scapy_http))
            bench_l7_op("scapy 2.5.0", 'l7_dhcp', _scapy_dhcp,
                        _l7_probe(_scapy_dhcp))
            bench_l7_op("scapy 2.5.0", 'l7_dhcp6', _scapy_dhcp6,
                        _l7_probe(_scapy_dhcp6))
            bench_l7_op("scapy 2.5.0", 'l7_netflow', _scapy_netflow,
                        _l7_probe(_scapy_netflow))
            l7_unsupported("scapy 2.5.0", ('l7_dns_tcp',),
                           'DNS-over-TCP framing differs: this corpus carries '
                           'the raw message packets decodes, without the '
                           '2-byte length prefix scapy requires')
        except Exception as e:
            section_failed("scapy 2.5.0", e)


# ------------------------------------------------------ GRE decode comparison
# The --gre-pcap capture (build it with make_corpus.py --gre) carries standard
# GRE frames -- plain, keyed, sequenced, checksummed, over IPv6, and NVGRE/TEB.
# GRE is dispatched from the IP protocol number (47), which packets, dpkt and
# scapy all decode, so every frame re-parses across the three; impacket has no
# GRE decoder and libpcap dispatch is only a frame counter, so both are marked
# unsupported. This is the routing-protocol analogue of the L7 comparison: the
# reason for it is regression detection -- catching the packets GRE decode path
# slowing down toward the pure-Python libraries early -- not proving a win.
#
# Timing is in-memory, matching the L7 section: the frames are read once
# (untimed) and kept in a list, then each op decodes that list from bytes, so
# the number is a pure decode comparison unaffected by each library's pcap
# reader speed (that read cost is the pcaprd rows over --pcap).
GRE_OPS = ('gre',)


def bench_gre_op(lib, op, fn, verify=None):
    """Verify one untimed decode pass resolves, then time the operation."""
    try:
        if verify is not None:
            counts = verify()
            log('  %s/%s decoded: %s', lib, op, ' '.join(
                '%s=%s' % (name, counts[name]) for name in sorted(counts)))
            results.setdefault(lib, {})['%s_counts' % op] = dict(counts)
            dump_results()
            if not counts.get('decoded'):
                raise RuntimeError('%s decoded nothing from %s'
                                   % (op, GRE_PCAP))
        bench_pcap_op(lib, op, fn, seconds=GRE_SAMPLE_SECONDS, source=GRE_PCAP)
    except Exception as exc:
        log('%s/%s: FAILED, %s: %s', lib, op, exc.__class__.__name__, exc)
        results.setdefault(lib, {})[op] = {'error': str(exc)}
        dump_results()


def gre_unsupported(lib, reason, ops=GRE_OPS):
    for op in ops:
        results.setdefault(lib, {})[op] = {'unsupported': reason}
    log('%s: %s', lib, reason)
    dump_results()


def _is_gre_frame(raw):
    """Return True for an Ethernet II frame whose IPv4/IPv6 payload is GRE.

    A tiny struct-free parse keeps the classification library-agnostic, so the
    same frame list feeds every library without any one decoder shaping it.
    """
    if len(raw) < 14:
        return False
    ethtype = (raw[12] << 8) | raw[13]
    offset = 14
    if ethtype == 0x0800:
        if len(raw) < offset + 20:
            return False
        return raw[offset + 9] == 47
    elif ethtype == 0x86dd:
        if len(raw) < offset + 40:
            return False
        return raw[offset + 6] == 47
    return False


def _load_gre_frames():
    frames = []
    reader = PCAPReader(filename=GRE_PCAP)
    try:
        for _ts, _hdr, raw in reader:
            frame = bytes(raw)
            if _is_gre_frame(frame):
                frames.append(frame)
    finally:
        reader.close()
    return frames


if not GRE_PCAP:
    log('=== GRE decode comparison: skipped, no --gre-pcap ===')
else:
    log('=== GRE decode comparison: %s ===', os.path.basename(GRE_PCAP))
    GRE_FRAMES = _load_gre_frames()
    log('gre frames: %d', len(GRE_FRAMES))
    if not GRE_FRAMES:
        log('gre capture has no GRE frames -- rebuild it with '
            'make_corpus.py --gre')

    # ------------------------------------------------------------ packets 2.1
    if not enabled('packets'):
        log('%s: GRE decode skipped, packets not selected', PACKETS_LABEL)
    else:
        try:
            # GRE is dispatched from IP proto 47, so Ethernet(raw) decodes it
            # without an l7_ports map, exactly as ICMP/IGMP are. Import GRE so
            # a build that predates it is marked unsupported rather than
            # failing the whole column.
            from packets.core.inetpkt import GRE as PktGRE

            def _packets_gre():
                n = 0
                for raw in GRE_FRAMES:
                    frame = Ethernet(raw)
                    if isinstance(frame.get_layer('GRE'), PktGRE):
                        n += 1
                return n

            bench_gre_op(PACKETS_LABEL, 'gre', _packets_gre,
                         _l7_probe(_packets_gre))
        except ImportError as e:
            gre_unsupported(PACKETS_LABEL,
                            'this packets build has no GRE decoder (%s)' % e)
        except Exception as e:
            section_failed(PACKETS_LABEL, e)

    # --------------------------------------------------------------- libpcap
    if enabled('libpcap'):
        gre_unsupported("libpcap dispatch",
                        'libpcap dispatch is a C frame counter, not a GRE '
                        'decoder')

    # -------------------------------------------------------------- impacket
    if enabled('impacket'):
        gre_unsupported("impacket 0.13.1",
                        'impacket has no native pcap reader and no GRE '
                        'decoder')

    # ------------------------------------------------------------------ dpkt
    if enabled('dpkt'):
        try:
            import dpkt
            import dpkt.gre

            def _dpkt_gre():
                n = 0
                for raw in GRE_FRAMES:
                    try:
                        l3 = dpkt.ethernet.Ethernet(raw).data
                        if isinstance(l3.data, dpkt.gre.GRE):
                            n += 1
                    except Exception:
                        # A frame dpkt cannot walk is simply not counted; the
                        # never-raise loop keeps the timing over the rest.
                        pass
                return n

            bench_gre_op("dpkt 1.9.8", 'gre', _dpkt_gre, _l7_probe(_dpkt_gre))
        except Exception as e:
            section_failed("dpkt 1.9.8", e)

    # ----------------------------------------------------------------- scapy
    if enabled('scapy'):
        try:
            from scapy.all import Ether as GreEther, GRE as ScGRE
            from scapy.config import conf as gre_conf

            gre_conf.verb = 0

            def _scapy_gre():
                n = 0
                for raw in GRE_FRAMES:
                    try:
                        if ScGRE in GreEther(raw):
                            n += 1
                    except Exception:
                        pass
                return n

            bench_gre_op("scapy 2.5.0", 'gre', _scapy_gre,
                         _l7_probe(_scapy_gre))
        except Exception as e:
            section_failed("scapy 2.5.0", e)


# --------------------------------------------------------------------- output
log('done in %.1fs', time.perf_counter() - RUN_T0)
dump_results(final=True)
