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

Run with PYTHONPATH pointed at the packets build directory.
"""
from __future__ import print_function
import argparse
import time
import gc
import statistics

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--pcap', required=True,
                    help='capture file used for streaming benchmarks')
parser.add_argument('--iterations', type=int, default=50000)
parser.add_argument('--repeats', type=int, default=5)
parser.add_argument('--pcap-seconds', type=float, default=3.0,
                    help='minimum duration of each pcap sample')
parser.add_argument('--packets-label', default='packets 2.1',
                    help='result label for the packets build on PYTHONPATH')
args = parser.parse_args()
if args.iterations <= 0 or args.repeats <= 0 or args.pcap_seconds <= 0:
    parser.error('iterations, repeats, and pcap-seconds must be positive')

PCAP = args.pcap
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


def timeit(fn, n):
    # warm up
    for _ in range(100):
        fn()
    samples = []
    gc.disable()
    try:
        for _ in range(args.repeats):
            t0 = time.perf_counter()
            for _ in range(n):
                fn()
            samples.append(time.perf_counter() - t0)
    finally:
        gc.enable()
    return samples


def time_pcap(fn, passes):
    elapsed_samples = []
    packet_samples = []
    gc.disable()
    try:
        for _ in range(passes):
            t0 = time.perf_counter()
            npkts = 0
            while True:
                npkts += fn()
                elapsed = time.perf_counter() - t0
                if elapsed >= PCAP_SAMPLE_SECONDS:
                    break
            elapsed_samples.append(elapsed)
            packet_samples.append(npkts)
    finally:
        gc.enable()
    return elapsed_samples, packet_samples


results = {}   # lib -> {op: (per_pkt_us, pkts_per_sec)}


def record(lib, op, total_time, count):
    if not isinstance(total_time, (list, tuple)):
        total_time = [total_time]
    if not isinstance(count, (list, tuple)):
        count = [count] * len(total_time)
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


# ----------------------------------------------------------------- packets 2.1
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


record(PACKETS_LABEL, "build", timeit(build_packets, N_BUILD), N_BUILD)
record(PACKETS_LABEL, "parse", timeit(parse_packets, N_PARSE), N_PARSE)
_t, _n = time_pcap(pcap_packets, N_PCAP_PASSES)
record(PACKETS_LABEL, "pcaprd", _t, _n)
_t, _n = time_pcap(pcap_decode_construct_packets, N_PCAP_PASSES)
record(PACKETS_LABEL, "pcapdec_ctor", _t, _n)
_t, _n = time_pcap(pcap_decode_raw_mac_packets, N_PCAP_PASSES)
record(PACKETS_LABEL, "pcapdec_rawmac", _t, _n)
_t, _n = time_pcap(pcap_decode_packets, N_PCAP_PASSES)
record(PACKETS_LABEL, "pcapdec", _t, _n)
_t, _n = time_pcap(pcap_decode_udp_packets, N_PCAP_PASSES)
record(PACKETS_LABEL, "pcapdec_udp", _t, _n)


# ---------------------------------------------------- direct libpcap dispatch
try:
    from pcap_dispatch_bench import scan_batch, scan_count, scan_extract

    for _batch_size in (16, 64, 256):
        _t, _n = time_pcap(
            lambda size=_batch_size: scan_count(PCAP, size),
            N_PCAP_PASSES)
        record("libpcap dispatch", "count_%d" % _batch_size, _t, _n)

        _t, _n = time_pcap(
            lambda size=_batch_size: scan_batch(PCAP, size),
            N_PCAP_PASSES)
        record("libpcap dispatch", "batch_%d" % _batch_size, _t, _n)

        def extract_count(size=_batch_size):
            return scan_extract(PCAP, size)[0]

        _t, _n = time_pcap(extract_count, N_PCAP_PASSES)
        record("libpcap dispatch", "extract_%d" % _batch_size, _t, _n)
except Exception as e:
    results.setdefault("libpcap dispatch", {})["error"] = str(e)


# ------------------------------------------------------------------- impacket
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

    record("impacket 0.13.1", "build",
           timeit(build_impacket, N_BUILD), N_BUILD)
    record("impacket 0.13.1", "parse",
           timeit(parse_impacket, N_PARSE), N_PARSE)
    for _unsupported_op in ('pcaprd', 'pcapdec_ctor', 'pcapdec_rawmac',
                            'pcapdec', 'pcapdec_udp'):
        results["impacket 0.13.1"][_unsupported_op] = {
            'unsupported': 'impacket has no native pcap file reader'
        }
except Exception as e:
    results.setdefault("impacket 0.13.1", {})["error"] = str(e)


# ---------------------------------------------------------------------- scapy
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

    record("scapy 2.5.0", "build", timeit(build_scapy, N_BUILD), N_BUILD)
    record("scapy 2.5.0", "parse", timeit(parse_scapy, N_PARSE), N_PARSE)
    _t, _n = time_pcap(pcap_scapy, N_PCAP_PASSES)
    record("scapy 2.5.0", "pcaprd", _t, _n)
    _t, _n = time_pcap(pcap_decode_construct_scapy, N_PCAP_PASSES)
    record("scapy 2.5.0", "pcapdec_ctor", _t, _n)
    _t, _n = time_pcap(pcap_decode_raw_mac_scapy, N_PCAP_PASSES)
    record("scapy 2.5.0", "pcapdec_rawmac", _t, _n)
    _t, _n = time_pcap(pcap_decode_scapy, N_PCAP_PASSES)
    record("scapy 2.5.0", "pcapdec", _t, _n)
    _t, _n = time_pcap(pcap_decode_udp_scapy, N_PCAP_PASSES)
    record("scapy 2.5.0", "pcapdec_udp", _t, _n)
except Exception as e:
    results.setdefault("scapy 2.5.0", {})["error"] = str(e)


# ----------------------------------------------------------------------- dpkt
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

    record("dpkt 1.9.8", "build", timeit(build_dpkt, N_BUILD), N_BUILD)
    record("dpkt 1.9.8", "parse", timeit(parse_dpkt, N_PARSE), N_PARSE)
    _t, _n = time_pcap(pcap_dpkt, N_PCAP_PASSES)
    record("dpkt 1.9.8", "pcaprd", _t, _n)
    _t, _n = time_pcap(pcap_decode_construct_dpkt, N_PCAP_PASSES)
    record("dpkt 1.9.8", "pcapdec_ctor", _t, _n)
    _t, _n = time_pcap(pcap_decode_raw_mac_dpkt, N_PCAP_PASSES)
    record("dpkt 1.9.8", "pcapdec_rawmac", _t, _n)
    _t, _n = time_pcap(pcap_decode_dpkt, N_PCAP_PASSES)
    record("dpkt 1.9.8", "pcapdec", _t, _n)
    _t, _n = time_pcap(pcap_decode_udp_dpkt, N_PCAP_PASSES)
    record("dpkt 1.9.8", "pcapdec_udp", _t, _n)
except Exception as e:
    results.setdefault("dpkt 1.9.8", {})["error"] = str(e)


# --------------------------------------------------------------------- output
import json
results['_config'] = {
    'iterations': args.iterations,
    'repeats': args.repeats,
    'pcap_min_seconds_per_sample': args.pcap_seconds,
    'pcap': args.pcap,
}
print(json.dumps(results, indent=2))
