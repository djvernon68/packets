#!/usr/bin/env python3
"""Generate the reproducible capture corpus the streaming benchmarks need.

The pcap operations in ``compare_libs.py`` (and ``reader_gil_bench.py`` /
``pcap_info_bench.py``) measure *per-packet* cost, so they need a capture with
many packets. Re-reading a tiny 4-packet file mostly measures the cost of
opening and closing the file, not decoding frames.

This tool writes two deterministic captures, entirely from library code, so no
external capture files are required on the appliance:

  * ``--frames PATH --count N`` -- a mixed L2/L3/L4 capture cycling through
    TCP, UDP, IPv6, 802.1Q VLAN and MPLS shapes across a range of payload
    sizes, so every layer the frame benchmarks touch appears. Field values are
    fixed (no RNG), so the file is byte-for-byte reproducible.

  * ``--netflow PATH [--netflow-records N]`` -- a NetFlow v9 export capture
    built with ``packets.commands.netflow_generator.NetflowV9Generator`` using
    a fixed seed, so templates precede data and ``nf_decode`` resolves records
    reproducibly. Its default collector port (2055) matches
    ``compare_libs.py``'s default ``--netflow-ports``.

  * ``--l7 PATH [--l7-count N]`` -- a capture whose frames carry *valid*
    application-layer payloads on well-known ports (DNS/53, HTTP/80, DHCP/67,
    DHCPv6/547, NetFlow v9/2055), so an ``l7_ports`` dict (and each peer
    library's port-based dispatch) resolves them to a real layer-7 decode.
    This is what ``compare_libs.py --l7-pcap`` needs: unlike the ``--frames``
    capture, whose opaque L4 ports deliberately keep the payload from being
    interpreted, every frame here decodes all the way to L7. Field values are
    fixed and the NetFlow frames come from the same seeded generator, so the
    file is byte-for-byte reproducible with template-before-data ordering.

  * ``--gre PATH [--gre-count N]`` -- a capture of GRE (RFC 2784/2890/2637/
    7637) frames for ``compare_libs.py --gre-pcap``. It cycles the well-known
    GRE variants (plain, with key, with sequence number, with checksum,
    tunnelled over IPv6, and NVGRE / Transparent Ethernet Bridging), each built
    from packets' own ``GRE`` constructor and carrying an inner IPv4/UDP packet.
    GRE is dispatched from the IP protocol number (47), which packets, dpkt and
    scapy all decode, so the standard wire bytes re-parse across every library.
    Field values are fixed, so the file is byte-for-byte reproducible.

Usage (run from the packets checkout root, with the build on PYTHONPATH):

    python3 bench/make_corpus.py --frames frames.pcap --count 50000 \
                                 --netflow netflow.pcap --l7 l7.pcap

then feed the printed paths to compare_libs.py:

    python3 bench/compare_libs.py --pcap frames.pcap \
                                  --netflow-pcap netflow.pcap --l7-pcap l7.pcap
"""
from __future__ import print_function
import argparse
import sys

from packets.core.inetpkt import IP_CONST, Ethernet, IP, IP6, UDP, TCP, \
    MPLS, GRE, NullPkt
from packets.core.pcap import PCAPWriter

C = IP_CONST()

# ethertype for a single MPLS unicast label stack
ETH_TYPE_MPLS = 0x8847
# tag protocol id for an 802.1Q VLAN tag
ETH_TPID_8021Q = 0x8100

# Fixed timestamp base so the capture is byte-for-byte reproducible. The
# per-packet microsecond field carries the packet index, which is deterministic.
BASE_TV_SEC = 1700000000

# Payload sizes cycled across the shapes so parse cost is exercised at several
# frame lengths rather than one.
PAYLOAD_SIZES = (0, 64, 256, 512, 1024, 1400)

# L4 ports for the generated frames. These are deliberately *not* well-known
# L7 ports: the payload is synthetic (incrementing bytes), so a well-known port
# such as 53 makes an eager library (scapy binds UDP/53 -> DNS) run its L7
# dissector on non-protocol bytes and thrash pathologically (tens of ms/pkt on
# a 1400-byte frame), which measures a DNS-parser artifact rather than decode
# cost. Opaque ports keep the payload as L7 bytes for every library, so the
# cross-library comparison stays an apples-to-apples L2-L4 decode.
L4_SPORT = 34567
L4_DPORT = 40000

# Well-known L7 ports for the --l7 capture. Unlike the frames capture above,
# these are chosen precisely so a port-based L7 dispatch (packets' l7_ports, or
# each peer library's own bindings) resolves the payload to a real
# application-layer decode. Every value here carries a *valid* protocol
# message, so decoding is representative work rather than a thrash on random
# bytes.
L7_DNS_PORT = 53
L7_HTTP_PORT = 80
L7_DHCP_SERVER_PORT = 67
L7_DHCP_CLIENT_PORT = 68
L7_DHCP6_SERVER_PORT = 547
L7_DHCP6_CLIENT_PORT = 546
L7_NETFLOW_PORT = 2055
# Ephemeral source port used by the L7 frames (opaque, so it never collides
# with a well-known destination port during classification).
L7_SPORT = 41000


def _payload(size):
    """Deterministic payload bytes of the requested length."""
    return bytes(bytearray((i & 0xff) for i in range(size)))


def _tcp_frame(payload):
    return Ethernet(
        dst_mac='02:00:00:00:00:01', src_mac='02:00:00:00:00:02',
        payload=IP(proto=C.PROTO_TCP, src='10.1.2.3', dst='10.3.2.1',
                   payload=TCP(sport=L4_SPORT, dport=L4_DPORT, sequence=1000,
                               flag_syn=1,
                               payload=NullPkt(payload))))


def _udp_frame(payload):
    return Ethernet(
        dst_mac='02:00:00:00:00:03', src_mac='02:00:00:00:00:04',
        payload=IP(proto=C.PROTO_UDP, src='10.1.2.5', dst='10.5.2.1',
                   payload=UDP(sport=L4_SPORT, dport=L4_DPORT,
                               payload=NullPkt(payload))))


def _ipv6_frame(payload):
    return Ethernet(
        dst_mac='02:00:00:00:00:05', src_mac='02:00:00:00:00:06',
        type=0x86dd,
        payload=IP6(next_header=C.PROTO_UDP,
                    src='2001:db8::1', dst='2001:db8::2',
                    payload=UDP(sport=L4_SPORT, dport=L4_DPORT,
                                payload=NullPkt(payload))))


def _vlan_frame(payload):
    return Ethernet(
        dst_mac='02:00:00:00:00:07', src_mac='02:00:00:00:00:08',
        tpid=ETH_TPID_8021Q, vlan_id=100, priority_code=3,
        payload=IP(proto=C.PROTO_UDP, src='10.1.2.7', dst='10.7.2.1',
                   payload=UDP(sport=L4_SPORT, dport=L4_DPORT,
                               payload=NullPkt(payload))))


def _mpls_frame(payload):
    return Ethernet(
        dst_mac='02:00:00:00:00:09', src_mac='02:00:00:00:00:0a',
        type=ETH_TYPE_MPLS,
        payload=MPLS(label=0xabcde, tc=5, s=1, ttl=64,
                     payload=IP(proto=C.PROTO_UDP,
                                src='10.1.2.9', dst='10.9.2.1',
                                payload=UDP(sport=L4_SPORT, dport=L4_DPORT,
                                            payload=NullPkt(payload)))))


# Order matters only for reproducibility; every builder is exercised.
SHAPE_BUILDERS = (
    ('tcp', _tcp_frame),
    ('udp', _udp_frame),
    ('ipv6', _ipv6_frame),
    ('vlan', _vlan_frame),
    ('mpls', _mpls_frame),
)


def _build_shape_table():
    """Serialize one frame per (shape, payload size) combination.

    Serializing up front keeps generation fast: writing N packets is then just
    cycling this fixed table, so make_corpus stays IO-bound rather than
    re-running the builders for every packet.
    """
    frames = []
    for size in PAYLOAD_SIZES:
        payload = _payload(size)
        for _name, builder in SHAPE_BUILDERS:
            frames.append(builder(payload).pkt2net({'csum': 1, 'update': 1}))
    return frames


def write_frames(path, count):
    """Write `count` mixed frames to `path`, cycling the shape table."""
    if count <= 0:
        raise ValueError('--count must be positive')
    frames = _build_shape_table()
    writer = PCAPWriter(filename=path, snaplen=65535)
    try:
        for packet_number in range(count):
            frame = frames[packet_number % len(frames)]
            writer.dump_pkt(frame, BASE_TV_SEC, packet_number)
    finally:
        writer.close()
    return count


def write_netflow(path, records):
    """Write a deterministic NetFlow v9 export capture to `path`."""
    if records <= 0:
        raise ValueError('--netflow-records must be positive')
    # Imported lazily so a frames-only run does not require the generator.
    from packets.commands.netflow_generator import NetflowV9Generator
    generator = NetflowV9Generator(seed=1234, base_unix_secs=BASE_TV_SEC)
    return generator.generate_pcap(path, total_records=records,
                                   records_per_packet=20,
                                   template_interval=10)


# --------------------------------------------------------------- L7 corpus
# The frames below carry valid application-layer messages so that decoding
# them all the way to L7 is representative work. They are built from the same
# library constructors packets ships, then serialized to wire bytes; peer
# libraries (dpkt/scapy) re-parse those same standard wire bytes, so the
# capture is a fair cross-library input rather than a packets-specific format.

def _dns_wire():
    """A DNS response with a CNAME + A answer (label compression exercised)."""
    from packets.protos.dns import DNS, DNSQuery, DNSResource, \
        DNSTYPE_A, DNSTYPE_CNAME, RCLASS_IN
    dns = DNS()
    dns.ident = 0x1234
    dns.query_resp = 1
    dns.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
    dns.answers.append(DNSResource('www.example.com', DNSTYPE_CNAME,
                                   RCLASS_IN, 300, 0, 'host.example.com'))
    dns.answers.append(DNSResource('host.example.com', DNSTYPE_A,
                                   RCLASS_IN, 300, 4, '10.1.2.3'))
    return dns.pkt2net({'update': 1, 'compress': 1})


# HTTP request/response as literal wire bytes: dpkt and scapy parse the exact
# same octets, so no library-specific framing sneaks into the comparison.
HTTP_REQUEST_WIRE = (
    b'GET /index.html HTTP/1.1\r\n'
    b'Host: www.example.com\r\n'
    b'User-Agent: packets-bench/1.0\r\n'
    b'Accept: */*\r\n'
    b'\r\n')
HTTP_RESPONSE_WIRE = (
    b'HTTP/1.1 200 OK\r\n'
    b'Server: packets-bench\r\n'
    b'Content-Type: text/plain\r\n'
    b'Content-Length: 13\r\n'
    b'\r\n'
    b'hello, world!')


def _dhcp_wire():
    """A BOOTP/DHCPv4 REQUEST (client -> server) with standard options."""
    from packets.protos.dhcp import DHCP, DHCPOption, DHCP_MAGIC, \
        DHCP_OPT_MESSAGE_TYPE, DHCP_OPT_END
    packet = DHCP(
        op=1, htype=1, hlen=6, hops=0, xid=0x89abcdef,
        secs=0, flags=0x8000,
        ciaddr='0.0.0.0', yiaddr='0.0.0.0',
        siaddr='0.0.0.0', giaddr='0.0.0.0',
        chaddr=b'\x00\x11\x22\x33\x44\x55',
        sname=b'', file=b'', magic=DHCP_MAGIC,
        options=[
            DHCPOption(code=DHCP_OPT_MESSAGE_TYPE, data=b'\x03'),
            DHCPOption(code=54, data=b'\x0a\x00\x00\x01'),
            DHCPOption(code=50, data=b'\x0a\x00\x00\x64'),
            DHCPOption(code=DHCP_OPT_END),
        ])
    return packet.pkt2net({})


def _dhcp6_wire():
    """A DHCPv6 SOLICIT with one option."""
    from packets.protos.dhcp import DHCP6, DHCP6Option, DHCP6_SOLICIT
    packet = DHCP6(
        msg_type=DHCP6_SOLICIT, transaction_id=0x0abcde,
        options=[DHCP6Option(code=1, data=b'\x00\x01\x00\x0e' + b'\x00' * 10)])
    return packet.pkt2net({})


def _dns_udp_frame(dns_wire):
    return Ethernet(
        dst_mac='02:00:00:00:07:01', src_mac='02:00:00:00:07:02',
        payload=IP(proto=C.PROTO_UDP, src='10.7.0.1', dst='10.7.0.2',
                   payload=UDP(sport=L7_SPORT, dport=L7_DNS_PORT,
                               payload=NullPkt(dns_wire))))


def _dns_tcp_frame(dns_wire):
    # NOTE: packets decodes DNS-over-TCP from the raw payload, without the
    # 2-byte length prefix that dpkt/scapy require, so this frame is a
    # packets-only coverage case in compare_libs.py.
    return Ethernet(
        dst_mac='02:00:00:00:07:03', src_mac='02:00:00:00:07:04',
        payload=IP(proto=C.PROTO_TCP, src='10.7.0.3', dst='10.7.0.4',
                   payload=TCP(sport=L7_SPORT, dport=L7_DNS_PORT, sequence=1,
                               payload=NullPkt(dns_wire))))


def _http_frame(http_wire, tag):
    return Ethernet(
        dst_mac='02:00:00:00:07:%02x' % (0x10 + tag),
        src_mac='02:00:00:00:07:%02x' % (0x20 + tag),
        payload=IP(proto=C.PROTO_TCP, src='10.7.0.5', dst='10.7.0.6',
                   payload=TCP(sport=L7_SPORT, dport=L7_HTTP_PORT, sequence=1,
                               payload=NullPkt(http_wire))))


def _dhcp_frame(dhcp_wire):
    # client -> server, so the collector-side well-known port (67) is the
    # destination and the capture classifies cleanly on dport.
    return Ethernet(
        dst_mac='02:00:00:00:07:31', src_mac='02:00:00:00:07:32',
        payload=IP(proto=C.PROTO_UDP, src='10.7.0.100', dst='10.7.0.1',
                   payload=UDP(sport=L7_DHCP_CLIENT_PORT,
                               dport=L7_DHCP_SERVER_PORT,
                               payload=NullPkt(dhcp_wire))))


def _dhcp6_frame(dhcp6_wire):
    return Ethernet(
        dst_mac='02:00:00:00:07:41', src_mac='02:00:00:00:07:42',
        type=0x86dd,
        payload=IP6(next_header=C.PROTO_UDP,
                    src='2001:db8:7::1', dst='2001:db8:7::2',
                    payload=UDP(sport=L7_DHCP6_CLIENT_PORT,
                                dport=L7_DHCP6_SERVER_PORT,
                                payload=NullPkt(dhcp6_wire))))


def _netflow_frames(cycles):
    """Ordered NetFlow v9 frame bytes with periodic templates.

    Reuses the same seeded generator as ``--netflow`` and ``build_frame`` so
    every datagram lands on the collector port and a template precedes the
    data sets that reference it. A short, self-contained list is enough: it is
    cycled by the writer, and each cycle restarts on a template datagram.
    """
    from packets.commands.netflow_generator import NetflowV9Generator
    generator = NetflowV9Generator(seed=1234, base_unix_secs=BASE_TV_SEC)
    frames = []
    for packet in generator.generate_packets(total_records=cycles * 20,
                                             records_per_packet=20,
                                             template_interval=10):
        frames.append(generator.build_frame(packet, dport=L7_NETFLOW_PORT,
                                            sport=L7_SPORT))
    return frames


# Order matters: the NetFlow list must be walked in order so its templates are
# learned before the data sets that reference them. Every cycle emits one frame
# of each shape, so the protocols appear in equal numbers.
L7_SHAPES = ('dns_udp', 'dns_tcp', 'http_req', 'http_resp',
             'dhcp', 'dhcp6', 'netflow')


def _build_l7_table(netflow_frames):
    """Return an ordered list of (name, frame_bytes) for one full cycle."""
    dns_wire = _dns_wire()
    dhcp_wire = _dhcp_wire()
    dhcp6_wire = _dhcp6_wire()
    kwargs = {'csum': 1, 'update': 1}
    fixed = {
        'dns_udp': _dns_udp_frame(dns_wire).pkt2net(kwargs),
        'dns_tcp': _dns_tcp_frame(dns_wire).pkt2net(kwargs),
        'http_req': _http_frame(HTTP_REQUEST_WIRE, 0).pkt2net(kwargs),
        'http_resp': _http_frame(HTTP_RESPONSE_WIRE, 1).pkt2net(kwargs),
        'dhcp': _dhcp_frame(dhcp_wire).pkt2net(kwargs),
        'dhcp6': _dhcp6_frame(dhcp6_wire).pkt2net(kwargs),
    }
    table = []
    for index in range(len(netflow_frames)):
        for name in L7_SHAPES:
            if name == 'netflow':
                table.append((name, netflow_frames[index]))
            else:
                table.append((name, fixed[name]))
    return table


def write_l7(path, count):
    """Write `count` L7 frames to `path`, cycling the protocol shape table."""
    if count <= 0:
        raise ValueError('--l7-count must be positive')
    # A modest number of NetFlow cycles keeps the template state realistic
    # while the whole table is small enough to cycle cheaply to `count`.
    netflow_frames = _netflow_frames(cycles=10)
    table = _build_l7_table(netflow_frames)
    writer = PCAPWriter(filename=path, snaplen=65535)
    try:
        for packet_number in range(count):
            _name, frame = table[packet_number % len(table)]
            writer.dump_pkt(frame, BASE_TV_SEC, packet_number)
    finally:
        writer.close()
    return count


# --------------------------------------------------------------- GRE corpus
# GRE (RFC 2784/2890/2637/7637) frames for the cross-library GRE comparison in
# compare_libs.py --gre-pcap. GRE is dispatched from the IP protocol number
# (47) by packets, by dpkt (dpkt.ip -> dpkt.gre) and by scapy (IP -> GRE), so
# these standard frames re-parse across all three. Every frame is built from
# packets' own GRE constructor and carries an inner IPv4/UDP packet, so the
# capture stays self-contained and byte-for-byte reproducible. All the
# well-known variants appear: plain, with key, with sequence number, with
# checksum, tunnelled over IPv6, and NVGRE / Transparent Ethernet Bridging
# (whose protocol type is TEB, so the payload is a full inner Ethernet frame).
GRE_SPORT = 44000
GRE_DPORT = 45000


def _gre_inner_udp(payload, src='10.8.0.1', dst='10.8.0.2'):
    """The encapsulated IPv4/UDP packet every GRE shape carries."""
    return IP(proto=C.PROTO_UDP, src=src, dst=dst,
              payload=UDP(sport=GRE_SPORT, dport=GRE_DPORT,
                          payload=NullPkt(payload)))


def _gre_plain_frame(payload):
    return Ethernet(
        dst_mac='02:00:00:00:08:01', src_mac='02:00:00:00:08:02',
        payload=IP(proto=C.PROTO_GRE, src='10.8.1.1', dst='10.8.1.2',
                   payload=GRE(payload=_gre_inner_udp(payload))))


def _gre_key_frame(payload):
    return Ethernet(
        dst_mac='02:00:00:00:08:03', src_mac='02:00:00:00:08:04',
        payload=IP(proto=C.PROTO_GRE, src='10.8.1.3', dst='10.8.1.4',
                   payload=GRE(key=0x11223344,
                               payload=_gre_inner_udp(payload))))


def _gre_seq_frame(payload):
    return Ethernet(
        dst_mac='02:00:00:00:08:05', src_mac='02:00:00:00:08:06',
        payload=IP(proto=C.PROTO_GRE, src='10.8.1.5', dst='10.8.1.6',
                   payload=GRE(sequence_number=0x0000abcd,
                               payload=_gre_inner_udp(payload))))


def _gre_cksum_frame(payload):
    # The C bit is set (a checksum keyword), so pkt2net({'csum': 1}) recomputes
    # the GRE checksum during serialization.
    return Ethernet(
        dst_mac='02:00:00:00:08:07', src_mac='02:00:00:00:08:08',
        payload=IP(proto=C.PROTO_GRE, src='10.8.1.7', dst='10.8.1.8',
                   payload=GRE(checksum=0,
                               payload=_gre_inner_udp(payload))))


def _gre6_frame(payload):
    # GRE over IPv6: the IPv6 next-header is 47, the same protocol-number
    # dispatch every library follows.
    return Ethernet(
        dst_mac='02:00:00:00:08:09', src_mac='02:00:00:00:08:0a',
        type=0x86dd,
        payload=IP6(next_header=C.PROTO_GRE,
                    src='2001:db8:8::1', dst='2001:db8:8::2',
                    payload=GRE(payload=_gre_inner_udp(payload))))


def _gre_nvgre_frame(payload):
    # NVGRE / Transparent Ethernet Bridging: the GRE key carries a 24-bit
    # Virtual Subnet ID and an 8-bit FlowID, and the protocol type is TEB
    # (0x6558), so the payload is a full inner Ethernet frame.
    inner = Ethernet(
        dst_mac='02:00:00:00:08:cc', src_mac='02:00:00:00:08:dd',
        payload=_gre_inner_udp(payload, src='10.8.2.1', dst='10.8.2.2'))
    return Ethernet(
        dst_mac='02:00:00:00:08:0b', src_mac='02:00:00:00:08:0c',
        payload=IP(proto=C.PROTO_GRE, src='10.8.1.9', dst='10.8.1.10',
                   payload=GRE(vsid=0x123456, flowid=0x78, payload=inner)))


# Order matters only for reproducibility; every builder is exercised.
GRE_SHAPES = (
    ('gre_plain', _gre_plain_frame),
    ('gre_key', _gre_key_frame),
    ('gre_seq', _gre_seq_frame),
    ('gre_cksum', _gre_cksum_frame),
    ('gre6', _gre6_frame),
    ('gre_nvgre', _gre_nvgre_frame),
)


def _build_gre_table():
    """Serialize one GRE frame per (shape, payload size) combination."""
    frames = []
    for size in PAYLOAD_SIZES:
        payload = _payload(size)
        for _name, builder in GRE_SHAPES:
            frames.append(builder(payload).pkt2net({'csum': 1, 'update': 1}))
    return frames


def write_gre(path, count):
    """Write `count` GRE frames to `path`, cycling the GRE shape table."""
    if count <= 0:
        raise ValueError('--gre-count must be positive')
    frames = _build_gre_table()
    writer = PCAPWriter(filename=path, snaplen=65535)
    try:
        for packet_number in range(count):
            frame = frames[packet_number % len(frames)]
            writer.dump_pkt(frame, BASE_TV_SEC, packet_number)
    finally:
        writer.close()
    return count


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--frames', metavar='PATH',
                        help='write the mixed L2/L3/L4 frames capture here')
    parser.add_argument('--count', type=int, default=50000,
                        help='number of frames to write (default: %(default)s)')
    parser.add_argument('--netflow', metavar='PATH',
                        help='write the NetFlow v9 export capture here')
    parser.add_argument('--netflow-records', '--netflow_records',
                        dest='netflow_records', type=int, default=20000,
                        help='NetFlow records to generate '
                             '(default: %(default)s)')
    parser.add_argument('--l7', metavar='PATH',
                        help='write the L7 protocol capture (DNS/HTTP/DHCP/'
                             'DHCPv6/NetFlow on well-known ports) here')
    parser.add_argument('--l7-count', '--l7_count', dest='l7_count',
                        type=int, default=49000,
                        help='number of L7 frames to write, cycled from the '
                             'protocol shape table (default: %(default)s)')
    parser.add_argument('--gre', metavar='PATH',
                        help='write the GRE capture (plain/key/seq/checksum/'
                             'IPv6/NVGRE variants) here')
    parser.add_argument('--gre-count', '--gre_count', dest='gre_count',
                        type=int, default=49000,
                        help='number of GRE frames to write, cycled from the '
                             'GRE shape table (default: %(default)s)')
    args = parser.parse_args()

    if not args.frames and not args.netflow and not args.l7 and not args.gre:
        parser.error('nothing to do: pass --frames, --netflow, --l7 '
                     'and/or --gre')

    if args.frames:
        n = write_frames(args.frames, args.count)
        print('frames: wrote %d packets to %s' % (n, args.frames))
        print('  compare_libs.py --pcap %s' % args.frames)

    if args.netflow:
        n = write_netflow(args.netflow, args.netflow_records)
        print('netflow: wrote %d packets (%d records) to %s'
              % (n, args.netflow_records, args.netflow))
        print('  compare_libs.py --netflow-pcap %s' % args.netflow)

    if args.l7:
        n = write_l7(args.l7, args.l7_count)
        print('l7: wrote %d packets (%d protocols) to %s'
              % (n, len(L7_SHAPES), args.l7))
        print('  compare_libs.py --l7-pcap %s' % args.l7)

    if args.gre:
        n = write_gre(args.gre, args.gre_count)
        print('gre: wrote %d packets (%d variants) to %s'
              % (n, len(GRE_SHAPES), args.gre))
        print('  compare_libs.py --gre-pcap %s' % args.gre)

    return 0


if __name__ == '__main__':
    sys.exit(main())
