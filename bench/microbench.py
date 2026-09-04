#!/usr/bin/env python3
"""Micro-benchmarks for the packets library hot paths.

Measures the operations Phase 1+ target:
  * construct: build the Ethernet/IP/L4 object graph from kwargs, no serialize
  * build  : construct an Ethernet/IP/L4 packet from kwargs + pkt2net(csum,update)
  * parse  : Ethernet(raw_bytes) full decode down to L4
  * parse_<layer>: single-layer decode for the layers that are not on the
    Ethernet/IP/UDP path (ARP, ICMP, IGMP v2/v3, MPLS, NetflowSimple, DNS)
  * access_*: repeated formatted address access on one parsed packet
  * parse_udp_p*: parse scaling across UDP payload sizes
  * query_udp_p*: UDP payload-offset query scaling across payload sizes

construct_* is reported separately because it is ~70% of build: measuring only
build dilutes a construction-path change by the serialize cost that rides
along with it.

The parse_<layer> rows exist because parse_udp/parse_tcp only exercise
Ethernet/IP/UDP/TCP: a change to the ARP or IGMP parser is completely
invisible in them.

Reports median and best ns/packet plus packets/sec. Deterministic corpus so runs
are comparable.

Usage:
    python3 bench/microbench.py [iterations] [repeats]
    python3 bench/microbench.py --json [iterations] [repeats]

With --json the human table is written to stderr and a machine-diffable
{label: {median_ns, best_ns, pps}} document is written to stdout, which is what
regression.py consumes.
"""
import argparse
import json
import sys
import gc
import statistics
import time
from array import array

from packets.core.inetpkt import IP_CONST, Ethernet, ARP, IP, IP6, UDP, TCP, \
    ICMP, ICMP6, ICMP6Opt, IGMP, IGMPGroupRecord, MLDv2AddressRecord, MPLS, \
    NetflowSimple, NullPkt
from packets.protos.dns import DNS, DNSQuery, DNSResource, \
    DNSTYPE_A, DNSTYPE_CNAME, RCLASS_IN

C = IP_CONST()

UDP_PAYLOAD = bytes((i & 0xff) for i in range(200))
TCP_PAYLOAD = bytes((i & 0xff) for i in range(200))
PAYLOAD_SIZES = (0, 64, 512, 1400)


def make_udp():
    return Ethernet(
        dst_mac='03:02:03:04:05:06', src_mac='06:05:04:03:02:03',
        payload=IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                   payload=UDP(sport=34567, dport=53,
                               payload=NullPkt(UDP_PAYLOAD))))


def make_tcp():
    return Ethernet(
        dst_mac='05:02:03:04:05:06', src_mac='06:05:04:03:02:05',
        payload=IP(proto=C.PROTO_TCP, src='10.1.2.5', dst='10.5.2.1',
                   payload=TCP(sport=34567, dport=80, sequence=200, flag_syn=1,
                                 payload=NullPkt(TCP_PAYLOAD))))


def make_ip6_udp(ext_headers=b'', next_header=None):
    if next_header is None:
        next_header = C.PROTO_UDP
    return Ethernet(
        dst_mac='03:02:03:04:05:07', src_mac='06:05:04:03:02:07',
        payload=IP6(next_header=next_header, ext_headers=ext_headers,
                    src='2001:db8::1', dst='2001:db8::2',
                    payload=UDP(sport=34567, dport=53,
                                payload=NullPkt(UDP_PAYLOAD))))


def make_ip6_tcp():
    return Ethernet(
        dst_mac='05:02:03:04:05:08', src_mac='06:05:04:03:02:08',
        payload=IP6(next_header=C.PROTO_TCP,
                    src='2001:db8::3', dst='2001:db8::4',
                    payload=TCP(sport=34567, dport=80, sequence=200,
                                flag_syn=1, payload=NullPkt(TCP_PAYLOAD))))


def make_udp_with_payload(payload):
    return Ethernet(
        dst_mac='03:02:03:04:05:06', src_mac='06:05:04:03:02:03',
        payload=IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                   payload=UDP(sport=34567, dport=53,
                               payload=NullPkt(payload))))


def access_eth_src_16(pkt):
    value = None
    for _ in range(16):
        value = pkt.src_mac
    return value


def access_ip_src_16(pkt):
    value = None
    for _ in range(16):
        value = pkt.src
    return value


def make_layer_corpus():
    """Raw bytes for the layers parse_udp/parse_tcp never touch.

    Built through the library's own serializers so the corpus is
    deterministic and needs no capture files on the appliance.
    """
    embedded = IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                  payload=UDP(sport=34567, dport=53)).pkt2net({'csum': 1,
                                                               'update': 1})
    return {
        'arp': ARP(operation=1,
                   sender_hw_addr='06:05:04:03:02:03',
                   sender_proto_addr='10.1.2.3',
                   target_hw_addr='00:00:00:00:00:00',
                   target_proto_addr='10.3.2.1').pkt2net({}),
        'icmp_echo': ICMP(type=C.ICMP_TYPE_ECHO, code=0, identifier=1,
                          sequence=2,
                          echo_data=UDP_PAYLOAD).pkt2net({'csum': 1}),
        'icmp_du': ICMP(type=C.ICMP_TYPE_DU, code=4, mtu=1500,
                        hdr_pkt=IP(embedded)).pkt2net({'csum': 1}),
        'igmp_v2': IGMP(version=2, type=C.IGMP_V2_MEMBER_REPORT, max_resp=100,
                        group_address='224.1.1.1').pkt2net({'csum': 1}),
        'igmp_v3': IGMP(version=3, type=C.IGMP_V3_MEMBER_REPORT,
                        num_records=2,
                        group_records=[
                            IGMPGroupRecord(type=1,
                                            group_address='224.1.1.1',
                                            source_addresses=['10.1.1.1',
                                                              '10.1.1.2']),
                            IGMPGroupRecord(type=2,
                                            group_address='224.1.1.2'),
                        ]).pkt2net({'csum': 1}),
        'mpls': MPLS(label=0xabcde, tc=5, s=1, ttl=64,
                     payload=IP(embedded)).pkt2net({}),
        'netflow': NetflowSimple(version=5, count=30, sys_uptime=1000,
                                 unix_secs=1500000000,
                                 unix_nano_seconds=1,
                                 payload=UDP_PAYLOAD).pkt2net({}),
        'dns': make_dns_response(),
    }


def make_dns():
    """A DNS response with two answers, so label compression, the
    resource-record writer and the A-record path are all exercised. The
    second answer's name is a suffix of the first, which is what gives the
    compression path something to find.
    """
    dns = DNS()
    dns.ident = 0x1234
    dns.query_resp = 1
    dns.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
    dns.answers.append(DNSResource('www.example.com', DNSTYPE_CNAME,
                                   RCLASS_IN, 300, 0, 'host.example.com'))
    dns.answers.append(DNSResource('host.example.com', DNSTYPE_A,
                                   RCLASS_IN, 300, 4, '10.1.2.3'))
    return dns


def make_dns_response():
    """The same message as wire bytes, for the parse_dns row."""
    return make_dns().pkt2net({'update': 1, 'compress': 1})


def make_phase_c2_corpus():
    """Deterministic direct-layer and representative stack inputs."""
    dns_raw = make_dns_response()
    udp_dns = UDP(sport=40000, dport=53, payload=NullPkt(dns_raw))
    tcp_dns = TCP(sport=40000, dport=53, sequence=1,
                  payload=NullPkt(dns_raw))
    ip4_udp = IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                 payload=UDP(sport=34567, dport=53,
                             payload=NullPkt(UDP_PAYLOAD)))
    ip4_tcp = IP(proto=C.PROTO_TCP, src='10.1.2.5', dst='10.5.2.1',
                 payload=TCP(sport=34567, dport=80, sequence=200, flag_syn=1,
                             options=b'\x02\x04\x05\xb4',
                             payload=NullPkt(TCP_PAYLOAD)))
    ip6_udp = make_ip6_udp().payload
    ip6_tcp = make_ip6_tcp().payload
    # One 8-byte Hop-by-Hop header whose next-header byte selects UDP.
    ip6_ext_udp = make_ip6_udp(bytes([C.PROTO_UDP, 0]) + b'\x00' * 6,
                               next_header=0)
    icmp6_echo = ICMP6(type=C.ICMP6_ECHO_REQUEST, identifier=1, sequence=2,
                       echo_data=UDP_PAYLOAD)
    nd_option = ICMP6Opt(type=C.ICMP6_OPT_SRC_LLADDR,
                         link_layer_address='00:11:22:33:44:55')
    icmp6_nd = ICMP6(type=C.ICMP6_ND_NEIGHBOR_SOLICIT,
                     target_address='fe80::1', options=[nd_option])
    mld_record = MLDv2AddressRecord(
        type=4, multicast_address='ff05::1',
        source_addresses=['2001:db8::10'])
    icmp6_mld = ICMP6(type=C.ICMP6_MLDV2_REPORT, records=[mld_record])
    igmp_record = IGMPGroupRecord(type=1, group_address='224.1.1.1',
                                  source_addresses=['10.1.1.1', '10.1.1.2'])
    arp = ARP(operation=1, sender_hw_addr='06:05:04:03:02:03',
              sender_proto_addr='10.1.2.3',
              target_hw_addr='00:00:00:00:00:00',
              target_proto_addr='10.3.2.1')
    igmp = IGMP(version=3, type=C.IGMP_V3_MEMBER_REPORT, num_records=1,
                group_records=[igmp_record])
    netflow = NetflowSimple(version=5, count=30, sys_uptime=1000,
                            unix_secs=1500000000, unix_nano_seconds=1,
                            payload=UDP_PAYLOAD)
    mpls_ip6 = Ethernet(
        dst_mac='03:02:03:04:05:09', src_mac='06:05:04:03:02:09',
        payload=MPLS(label=100, s=0, ttl=64,
                     payload=MPLS(label=200, s=1, ttl=63,
                                  payload=ip6_udp)))
    vlan_tcp = Ethernet(
        dst_mac='03:02:03:04:05:10', src_mac='06:05:04:03:02:10',
        tpid=C.ETH_TYPE_8021Q, vlan_id=37, payload=ip4_tcp)
    dns_udp4 = Ethernet(
        dst_mac='03:02:03:04:05:11', src_mac='06:05:04:03:02:11',
        payload=IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                   payload=udp_dns))
    dns_tcp4 = Ethernet(
        dst_mac='03:02:03:04:05:12', src_mac='06:05:04:03:02:12',
        payload=IP(proto=C.PROTO_TCP, src='10.1.2.3', dst='10.3.2.1',
                   payload=tcp_dns))
    eth_arp = Ethernet(
        dst_mac='ff:ff:ff:ff:ff:ff', src_mac='06:05:04:03:02:03',
        payload=arp)
    eth_icmp4 = Ethernet(
        dst_mac='03:02:03:04:05:13', src_mac='06:05:04:03:02:13',
        payload=IP(proto=C.PROTO_ICMP, src='10.1.2.3', dst='10.3.2.1',
                   payload=ICMP(type=C.ICMP_TYPE_ECHO, identifier=1,
                                sequence=2, echo_data=UDP_PAYLOAD)))
    eth_igmp = Ethernet(
        dst_mac='01:00:5e:01:01:01', src_mac='06:05:04:03:02:14',
        payload=IP(proto=C.PROTO_IGMP, src='10.1.2.3', dst='224.1.1.1',
                   payload=igmp))
    eth_icmp6_nd = Ethernet(
        dst_mac='33:33:00:00:00:01', src_mac='06:05:04:03:02:15',
        payload=IP6(next_header=C.PROTO_ICMPV6,
                    src='2001:db8::1', dst='ff02::1', payload=icmp6_nd))
    eth_icmp6_mld = Ethernet(
        dst_mac='33:33:00:00:00:16', src_mac='06:05:04:03:02:16',
        payload=IP6(next_header=C.PROTO_ICMPV6,
                    src='2001:db8::1', dst='ff02::16', payload=icmp6_mld))
    eth_netflow = Ethernet(
        dst_mac='03:02:03:04:05:17', src_mac='06:05:04:03:02:17',
        payload=IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                   payload=UDP(sport=40000, dport=2055,
                               payload=NullPkt(netflow.pkt2net({})))))
    kwargs = {'csum': 1, 'update': 1}
    return {
        'nullpkt': UDP_PAYLOAD,
        'udp_layer': udp_dns.pkt2net({'update': 1}),
        'tcp_layer': tcp_dns.pkt2net({'update': 1}),
        'ip4_udp': ip4_udp.pkt2net(kwargs),
        'ip4_tcp': ip4_tcp.pkt2net(kwargs),
        'ip6_udp': ip6_udp.pkt2net(kwargs),
        'ip6_tcp': ip6_tcp.pkt2net(kwargs),
        'ip6_ext_udp': ip6_ext_udp.pkt2net(kwargs),
        'icmp6_echo': icmp6_echo.pkt2net({}),
        'icmp6_nd': icmp6_nd.pkt2net({}),
        'icmp6_opt': nd_option.pkt2net({}),
        'mld_record': mld_record.pkt2net({}),
        'icmp6_mld': icmp6_mld.pkt2net({}),
        'igmp_record': igmp_record.pkt2net({}),
        'mpls_ip6': mpls_ip6.pkt2net(kwargs),
        'vlan_tcp': vlan_tcp.pkt2net(kwargs),
        'dns_udp4': dns_udp4.pkt2net(kwargs),
        'dns_tcp4': dns_tcp4.pkt2net(kwargs),
        'eth_arp': eth_arp.pkt2net(kwargs),
        'eth_icmp4': eth_icmp4.pkt2net(kwargs),
        'eth_igmp': eth_igmp.pkt2net(kwargs),
        'eth_icmp6_nd': eth_icmp6_nd.pkt2net(kwargs),
        'eth_icmp6_mld': eth_icmp6_mld.pkt2net(kwargs),
        'eth_netflow': eth_netflow.pkt2net(kwargs),
    }


# Number of untimed warm-up calls before each measurement, mirroring
# compare_libs.timeit so the first timed pass is not charged one-time
# allocation/JIT-of-the-interpreter costs the later passes never pay.
WARMUP = 100

# Populated by every bench() call: label -> {median_ns, best_ns, pps}. Emitted
# as JSON when --json is given.
RESULTS = {}

# Stream the human-readable table is written to. Redirected to stderr in --json
# mode so stdout carries only the JSON document.
_table = sys.stdout


def _row(text):
    _table.write(text + '\n')
    _table.flush()


def bench(label, fn, iterations, repeats):
    # warm up
    for _ in range(WARMUP):
        fn()
    samples = []
    gc.disable()
    try:
        for _ in range(repeats):
            t0 = time.perf_counter()
            for _ in range(iterations):
                fn()
            samples.append(time.perf_counter() - t0)
    finally:
        gc.enable()
    best = min(samples)
    median = statistics.median(samples)
    best_ns = best / iterations * 1e9
    median_ns = median / iterations * 1e9
    median_pps = iterations / median
    RESULTS[label] = {'median_ns': median_ns, 'best_ns': best_ns,
                      'pps': median_pps}
    _row('%-22s median %10.1f ns/pkt  best %10.1f  %12.0f pkt/s' %
         (label, median_ns, best_ns, median_pps))
    return median_ns


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('iterations', nargs='?', type=int, default=50000)
    parser.add_argument('repeats', nargs='?', type=int, default=5)
    parser.add_argument('--json', action='store_true',
                        help='emit {label: {median_ns, best_ns, pps}} as JSON '
                             'on stdout; the human table goes to stderr')
    args = parser.parse_args()
    iterations = args.iterations
    repeats = args.repeats
    if iterations <= 0 or repeats <= 0:
        parser.error('iterations and repeats must be positive')

    global _table
    if args.json:
        _table = sys.stderr

    udp_raw = make_udp().pkt2net({'csum': 1, 'update': 1})
    tcp_raw = make_tcp().pkt2net({'csum': 1, 'update': 1})

    _row('iterations=%d repeats=%d (median and best)  udp_len=%d tcp_len=%d'
         % (iterations, repeats, len(udp_raw), len(tcp_raw)))
    _row('-' * 82)
    bench('construct_udp', make_udp, iterations, repeats)
    bench('construct_tcp', make_tcp, iterations, repeats)
    bench('build_udp+csum', lambda: make_udp().pkt2net({'csum': 1, 'update': 1}),
          iterations, repeats)
    bench('build_tcp+csum', lambda: make_tcp().pkt2net({'csum': 1, 'update': 1}),
          iterations, repeats)
    # serialize_* holds one already constructed packet and only re-emits it.
    # build_* mixes construction and serialization, so a change to pkt2net
    # alone shows up there diluted by roughly a factor of two; these rows are
    # the direct measure of the serialize path (plan item C / Phase 14).
    udp_pkt = make_udp()
    tcp_pkt = make_tcp()
    bench('serialize_udp+csum',
          lambda: udp_pkt.pkt2net({'csum': 1, 'update': 1}),
          iterations, repeats)
    bench('serialize_tcp+csum',
          lambda: tcp_pkt.pkt2net({'csum': 1, 'update': 1}),
          iterations, repeats)
    bench('serialize_udp_nocsum', lambda: udp_pkt.pkt2net({}),
          iterations, repeats)
    bench('parse_udp', lambda: Ethernet(udp_raw), iterations, repeats)
    bench('parse_tcp', lambda: Ethernet(tcp_raw), iterations, repeats)

    parsed_udp = Ethernet(udp_raw)
    parsed_ip = parsed_udp.payload
    _row('-' * 82)
    bench('access_eth_src_x1', lambda: parsed_udp.src_mac,
          iterations, repeats)
    bench('access_eth_src_x16', lambda: access_eth_src_16(parsed_udp),
          iterations, repeats)
    bench('access_ip_src_x1', lambda: parsed_ip.src, iterations, repeats)
    bench('access_ip_src_x16', lambda: access_ip_src_16(parsed_ip),
          iterations, repeats)

    payload_field = 'udp.payload.offset[0:32]'
    for payload_size in PAYLOAD_SIZES:
        payload = bytes((i & 0xff) for i in range(payload_size))
        payload_raw = make_udp_with_payload(payload).pkt2net(
            {'csum': 1, 'update': 1})
        payload_pkt = Ethernet(payload_raw)
        payload_udp = payload_pkt.payload.payload
        bench('parse_udp_p%d' % payload_size,
              lambda raw=payload_raw: Ethernet(raw), iterations, repeats)
        bench('query_udp_p%d' % payload_size,
              lambda udp=payload_udp: udp.get_field_val(payload_field),
              iterations, repeats)

    corpus = make_layer_corpus()
    phase_c2 = make_phase_c2_corpus()
    _row('-' * 82)
    bench('parse_arp', lambda: ARP(corpus['arp']), iterations, repeats)
    bench('parse_icmp_echo', lambda: ICMP(corpus['icmp_echo']),
          iterations, repeats)
    bench('parse_icmp_du', lambda: ICMP(corpus['icmp_du']),
          iterations, repeats)
    bench('parse_igmp_v2', lambda: IGMP(corpus['igmp_v2']),
          iterations, repeats)
    bench('parse_igmp_v3', lambda: IGMP(corpus['igmp_v3']),
          iterations, repeats)
    bench('parse_mpls', lambda: MPLS(corpus['mpls']), iterations, repeats)
    bench('parse_netflow', lambda: NetflowSimple(corpus['netflow']),
          iterations, repeats)
    bench('parse_dns', lambda: DNS(corpus['dns']), iterations, repeats)
    bench('parse_nullpkt', lambda: NullPkt(phase_c2['nullpkt']),
          iterations, repeats)
    bench('parse_udp_layer', lambda: UDP(phase_c2['udp_layer']),
          iterations, repeats)
    bench('parse_tcp_layer', lambda: TCP(phase_c2['tcp_layer']),
          iterations, repeats)
    bench('parse_ip4_udp', lambda: IP(phase_c2['ip4_udp']),
          iterations, repeats)
    bench('parse_ip4_tcp', lambda: IP(phase_c2['ip4_tcp']),
          iterations, repeats)
    bench('parse_ip6_udp', lambda: IP6(phase_c2['ip6_udp']),
          iterations, repeats)
    bench('parse_ip6_tcp', lambda: IP6(phase_c2['ip6_tcp']),
          iterations, repeats)
    bench('parse_ip6_ext_udp', lambda: Ethernet(phase_c2['ip6_ext_udp']),
          iterations, repeats)
    bench('parse_icmp6_echo', lambda: ICMP6(phase_c2['icmp6_echo']),
          iterations, repeats)
    bench('parse_icmp6_nd', lambda: ICMP6(phase_c2['icmp6_nd']),
          iterations, repeats)
    bench('parse_icmp6_opt', lambda: ICMP6Opt(phase_c2['icmp6_opt']),
          iterations, repeats)
    bench('parse_mld_record',
          lambda: MLDv2AddressRecord(phase_c2['mld_record']),
          iterations, repeats)
    bench('parse_icmp6_mld', lambda: ICMP6(phase_c2['icmp6_mld']),
          iterations, repeats)
    bench('parse_igmp_record',
          lambda: IGMPGroupRecord(phase_c2['igmp_record']),
          iterations, repeats)
    bench('parse_mpls_ip6', lambda: Ethernet(phase_c2['mpls_ip6']),
          iterations, repeats)
    bench('parse_vlan_tcp', lambda: Ethernet(phase_c2['vlan_tcp']),
          iterations, repeats)
    bench('parse_dns_udp4',
          lambda: Ethernet(phase_c2['dns_udp4'], l7_ports={53: DNS}),
          iterations, repeats)
    bench('parse_dns_tcp4',
          lambda: Ethernet(phase_c2['dns_tcp4'], l7_ports={53: DNS}),
          iterations, repeats)
    bench('parse_eth_arp', lambda: Ethernet(phase_c2['eth_arp']),
          iterations, repeats)
    bench('parse_eth_icmp4', lambda: Ethernet(phase_c2['eth_icmp4']),
          iterations, repeats)
    bench('parse_eth_igmp', lambda: Ethernet(phase_c2['eth_igmp']),
          iterations, repeats)
    bench('parse_eth_icmp6_nd', lambda: Ethernet(phase_c2['eth_icmp6_nd']),
          iterations, repeats)
    bench('parse_eth_icmp6_mld',
          lambda: Ethernet(phase_c2['eth_icmp6_mld']), iterations, repeats)
    bench('parse_eth_netflow',
          lambda: Ethernet(phase_c2['eth_netflow'],
                           l7_ports={2055: NetflowSimple}),
          iterations, repeats)

    # Re-emit the same layers. parse_* and serialize_* together cover the
    # read and write halves of every class that is not on the Ethernet/IP/L4
    # path.
    arp_pkt = ARP(corpus['arp'])
    icmp_du_pkt = ICMP(corpus['icmp_du'])
    igmp_v3_pkt = IGMP(corpus['igmp_v3'])
    mpls_pkt = MPLS(corpus['mpls'])
    _row('-' * 82)
    bench('serialize_arp', lambda: arp_pkt.pkt2net({}), iterations, repeats)
    bench('serialize_icmp_du', lambda: icmp_du_pkt.pkt2net({'csum': 1}),
          iterations, repeats)
    bench('serialize_igmp_v3', lambda: igmp_v3_pkt.pkt2net({'csum': 1}),
          iterations, repeats)
    bench('serialize_mpls', lambda: mpls_pkt.pkt2net({}), iterations, repeats)
    # DNS is measured both ways because the compression pointer search and
    # the per-label writing are separate costs: with compress=0 no candidate
    # names are built at all, so the two rows bracket the name writer.
    dns_pkt = make_dns()
    bench('serialize_dns',
          lambda: dns_pkt.pkt2net({'update': 1, 'compress': 1}),
          iterations, repeats)
    bench('serialize_dns_nocompress',
          lambda: dns_pkt.pkt2net({'update': 1, 'compress': 0}),
          iterations, repeats)

    if args.json:
        json.dump(RESULTS, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write('\n')
        sys.stdout.flush()


if __name__ == '__main__':
    main()
