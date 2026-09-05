#!/usr/bin/env python3
"""Correctness / golden harness for the packets library.

Emits a deterministic JSON blob of parsed field values, checksums, and full
serialized-hex round-trips for a corpus of packets. Run it against a known-good
build to capture a baseline, then re-run after a change and diff the JSON. Any
difference is a behavior change.

Deliberately exercises checksum(): the corpus varies payload length across
even/odd sizes so the odd-byte padding path is covered, for IP/UDP/TCP/ICMP.

Usage:
    python3 bench/correctness.py            # print JSON to stdout
    python3 bench/correctness.py > base.json
    python3 bench/correctness.py | diff base.json -
"""
import json
import hashlib
from array import array

from packets.core.inetpkt import IP_CONST, Ethernet, ARP, IP, IP6, UDP, TCP, \
    NullPkt
try:
    # GRE ships only in builds that carry the routing codecs. Importing it
    # optionally lets this harness run unchanged against a pre-GRE baseline
    # (regression.py measures both builds with this one current harness), where
    # the GRE golden records are simply absent from the emitted JSON.
    from packets.core.inetpkt import GRE
except ImportError:
    GRE = None
try:
    # OSPF ships with the Stage 2 routing codecs. Import optionally so the
    # harness still runs against a pre-OSPF baseline (the OSPF golden records
    # are simply absent from the emitted JSON there).
    from packets.core.inetpkt import OSPFv2, OSPFv3
except ImportError:
    OSPFv2 = None
    OSPFv3 = None
try:
    # BGP ships with the Stage 3 routing codecs. Import optionally so the
    # harness still runs against a pre-BGP baseline (the BGP golden records
    # are simply absent from the emitted JSON there).
    from packets.core.inetpkt import BGP
except ImportError:
    BGP = None
try:
    # RIP/RIPng/HSRP ship with the Stage 4 routing codecs. Import optionally
    # so the harness still runs against a pre-Stage-4 baseline (those golden
    # records are simply absent from the emitted JSON there).
    from packets.core.inetpkt import RIP, RIPng, HSRP
except ImportError:
    RIP = None
    RIPng = None
    HSRP = None
from packets.protos.dns import DNS, DNSQuery, DNSResource, \
    DNSTYPE_A, DNSTYPE_AAAA, DNSTYPE_CNAME, DNSTYPE_NS, DNSTYPE_PTR, \
    DNSTYPE_SOA, DNSTYPE_TXT, RCLASS_IN

C = IP_CONST()


def build_udp(plen, sport, dport, src, dst):
    payload = bytes((i & 0xff) for i in range(plen))
    eth = Ethernet(dst_mac='03:02:03:04:05:06', src_mac='06:05:04:03:02:03')
    eth.payload = IP(proto=C.PROTO_UDP, src=src, dst=dst,
                     payload=UDP(sport=sport, dport=dport,
                                 payload=NullPkt(payload)))
    return eth


def build_tcp(plen, sport, dport, src, dst):
    payload = bytes((i & 0xff) for i in range(plen))
    eth = Ethernet(dst_mac='05:02:03:04:05:06', src_mac='06:05:04:03:02:05')
    eth.payload = IP(proto=C.PROTO_TCP, src=src, dst=dst,
                     payload=TCP(sport=sport, dport=dport, sequence=200,
                                 flag_syn=1, payload=NullPkt(payload)))
    return eth


def record_l3l4(name, eth):
    """Serialize with checksum+update, reparse, and capture key values."""
    wire = eth.pkt2net({'csum': 1, 'update': 1})
    copy = Ethernet(wire)
    ip = copy.get_layer('IP')
    l4 = None
    for cand in ('UDP', 'TCP'):
        layer = copy.get_layer(cand)
        if layer.pkt_name == cand:
            l4 = layer
            break
    rec = {
        'wire_len': len(wire),
        'wire_sha1': hashlib.sha1(wire).hexdigest(),
        'ip.src': ip.src,
        'ip.dst': ip.dst,
        'ip.proto': ip.proto,
        'ip.total_len': ip.total_len,
        'ip.checksum': ip.checksum,
    }
    if l4 is not None:
        rec['l4.name'] = l4.pkt_name
        rec['l4.sport'] = l4.sport
        rec['l4.dport'] = l4.dport
        rec['l4.checksum'] = l4.checksum
    return name, rec


def corpus():
    out = {}
    # Vary payload length across even/odd (odd-byte checksum padding path).
    for plen in list(range(0, 34)) + [63, 64, 100, 511, 1400]:
        n, r = record_l3l4('udp_%04d' % plen,
                           build_udp(plen, 34567, 53, '10.1.2.3', '10.3.2.1'))
        out[n] = r
        n, r = record_l3l4('tcp_%04d' % plen,
                           build_tcp(plen, 34567, 80, '10.1.2.5', '10.5.2.1'))
        out[n] = r

    # ICMP echo (fixed vector from the test suite).
    icmp_echo = array('B', [0, 11, 134, 99, 252, 32, 8, 0, 39, 64, 45, 200, 8,
                            0, 69, 0, 0, 28, 0, 0, 0, 0, 64, 1, 202, 227, 10,
                            38, 25, 153, 10, 38, 130, 25, 8, 0, 61, 86, 15,
                            255, 170, 170])
    e = Ethernet(icmp_echo)
    icmp = e.get_layer_by_type(C.PQ_ICMP)
    out['icmp_echo'] = {
        'type': icmp.type, 'identifier': icmp.identifier,
        'sequence': icmp.sequence, 'checksum': icmp.checksum,
        'reserialize_sha1': hashlib.sha1(e.pkt2net({})).hexdigest(),
    }

    # ARP round-trip.
    arp_eth = Ethernet(dst_mac='ff:ff:ff:ff:ff:ff', src_mac='06:05:04:03:02:02')
    arp_eth.type = C.ETH_TYPE_ARP
    arp_eth.payload = ARP(sender_hw_addr='06:05:04:03:02:02',
                          sender_proto_addr='1.2.3.4',
                          target_hw_addr='00:00:00:00:00:00',
                          target_proto_addr='4.3.2.1')
    arp_wire = arp_eth.pkt2net({})
    a = Ethernet(arp_wire).get_layer('ARP')
    out['arp'] = {
        'wire_sha1': hashlib.sha1(arp_wire).hexdigest(),
        'sender_hw': a.sender_hw_addr, 'sender_proto': a.sender_proto_addr,
        'target_hw': a.target_hw_addr, 'target_proto': a.target_proto_addr,
    }

    out.update(dns_corpus())
    if GRE is not None:
        out.update(gre_corpus())
    if OSPFv2 is not None:
        out.update(ospf_corpus())
    if BGP is not None:
        out.update(bgp_corpus())
    if RIP is not None:
        out.update(rip_corpus())
    return out


def _gre_inner():
    """The inner IPv4/UDP packet the GRE round-trips carry."""
    return IP(proto=C.PROTO_UDP, src='10.8.0.1', dst='10.8.0.2',
              payload=UDP(sport=44000, dport=45000,
                          payload=NullPkt(b'gre-correctness')))


def _gre_eth_wrap(gre, v6=False):
    """Wrap a GRE layer in an Ethernet/IPv4 (or IPv6) frame."""
    eth = Ethernet(dst_mac='02:00:00:00:08:01', src_mac='02:00:00:00:08:02')
    if v6:
        eth.type = 0x86dd
        eth.payload = IP6(next_header=C.PROTO_GRE,
                          src='2001:db8:8::1', dst='2001:db8:8::2',
                          payload=gre)
    else:
        eth.payload = IP(proto=C.PROTO_GRE, src='10.8.1.1', dst='10.8.1.2',
                         payload=gre)
    return eth


def record_gre(name, eth, out):
    """Serialize a GRE frame with checksum+update, reparse it, and capture the
    GRE fields and inner layer the reader recovered plus the full wire hash.

    GRE auto-dispatches from IP proto 47, so Ethernet(wire) walks the GRE
    header and its payload without an l7_ports map. Optional fields report None
    when their presence bit is clear, which is the behaviour the golden diff
    locks down.
    """
    wire = eth.pkt2net({'csum': 1, 'update': 1})
    copy = Ethernet(wire)
    gre = copy.get_layer('GRE')
    out[name] = {
        'wire_len': len(wire),
        'wire_sha1': hashlib.sha1(wire).hexdigest(),
        'gre.proto': gre.get_field_val('gre.proto'),
        'gre.checksum': gre.get_field_val('gre.checksum'),
        'gre.key': gre.get_field_val('gre.key'),
        'gre.key.vsid': gre.get_field_val('gre.key.vsid'),
        'gre.key.flowid': gre.get_field_val('gre.key.flowid'),
        'gre.sequence_number': gre.get_field_val('gre.sequence_number'),
        'gre.ack_number': gre.get_field_val('gre.ack_number'),
        'gre.flags.c': gre.get_field_val('gre.flags.c'),
        'gre.flags.k': gre.get_field_val('gre.flags.k'),
        'gre.flags.s': gre.get_field_val('gre.flags.s'),
        'gre.version': gre.version,
        'gre.malformed': gre.malformed,
        'inner': gre.payload.pkt_name,
    }


def gre_corpus():
    """GRE read/write coverage across every optional-word combination.

    Each variant is serialized, reparsed and captured, so the golden diff sees
    a change to the GRE header layout, the NVGRE key split, the enhanced-GRE
    ack, or the inner-ethertype dispatch. All values are fixed, so the bytes
    are byte-for-byte reproducible.
    """
    out = {}
    record_gre('gre_plain', _gre_eth_wrap(GRE(payload=_gre_inner())), out)
    record_gre('gre_key',
               _gre_eth_wrap(GRE(key=0x11223344, payload=_gre_inner())), out)
    record_gre('gre_seq',
               _gre_eth_wrap(GRE(sequence_number=0x0000abcd,
                                 payload=_gre_inner())), out)
    record_gre('gre_cksum',
               _gre_eth_wrap(GRE(checksum=0, payload=_gre_inner())), out)
    # NVGRE / Transparent Ethernet Bridging: the key is a 24-bit VSID + 8-bit
    # FlowID and the payload is a full inner Ethernet frame (TEB, 0x6558).
    inner_eth = Ethernet(dst_mac='02:00:00:00:08:cc',
                         src_mac='02:00:00:00:08:dd', payload=_gre_inner())
    record_gre('gre_nvgre',
               _gre_eth_wrap(GRE(vsid=0x123456, flowid=0x78,
                                 payload=inner_eth)), out)
    record_gre('gre6', _gre_eth_wrap(GRE(payload=_gre_inner()), v6=True), out)
    # PPTP enhanced GRE (version 1): the acknowledgment number is present with
    # the sequence number, and the protocol type is PPP (0x880b).
    record_gre('gre_enhanced',
               _gre_eth_wrap(GRE(version=1, sequence_number=0x1111,
                                 ack_number=0x2222, proto=0x880b,
                                 payload=NullPkt(b'ppp-payload'))), out)
    return out


# --- OSPF golden corpus -----------------------------------------------------
# OSPFv2 rides on IPv4 proto 89 and OSPFv3 on IPv6 next-header 89, so wrapping
# a raw OSPF packet in an Ethernet/IP(6) frame and reparsing it walks the
# hardcoded dispatch, the common header, the per-type body and the LSAs the
# reader recovered, plus the full wire hash -- so the golden diff sees any
# change to the header layout, an LSA body, the enum renderings or the
# never-raise/round-trip contract.

def _ip4b(addr):
    return bytes(int(x) for x in addr.split('.'))


def _ospf2_hello_bytes():
    body = (_ip4b('255.255.255.0') + b'\x00\x0a' + bytes([0x02, 1]) +
            b'\x00\x00\x00\x28' + _ip4b('1.1.1.1') + _ip4b('0.0.0.0') +
            _ip4b('2.2.2.2'))
    length = 24 + len(body)
    return (bytes([2, 1]) + bytes([length >> 8, length & 0xff]) +
            _ip4b('1.1.1.1') + _ip4b('0.0.0.0') + b'\x00\x00' + b'\x00\x00' +
            b'\x00' * 8 + body)


def _ospf2_lsupdate_bytes():
    def lsa(age, opt, typ, lsid, adv, seq, lbody):
        L = 20 + len(lbody)
        return (bytes([age >> 8, age & 0xff, opt, typ]) + _ip4b(lsid) +
                _ip4b(adv) + bytes([(seq >> 24) & 0xff, (seq >> 16) & 0xff,
                                    (seq >> 8) & 0xff, seq & 0xff]) +
                b'\x00\x00' + bytes([L >> 8, L & 0xff]) + lbody)
    rbody = (b'\x00\x00\x00\x01' + _ip4b('10.0.0.1') +
             _ip4b('255.255.255.255') + bytes([1, 0]) + b'\x00\x05')
    rlsa = lsa(1, 0x02, 1, '1.1.1.1', '1.1.1.1', 0x80000001, rbody)
    ebody = (_ip4b('255.255.255.0') + bytes([0x80, 0, 0, 0x14]) +
             _ip4b('9.9.9.9') + b'\x00\x00\x00\x64')
    elsa = lsa(2, 0x02, 5, '20.0.0.0', '2.2.2.2', 0x80000002, ebody)
    body = b'\x00\x00\x00\x02' + rlsa + elsa
    length = 24 + len(body)
    return (bytes([2, 4]) + bytes([length >> 8, length & 0xff]) +
            _ip4b('1.1.1.1') + _ip4b('0.0.0.0') + b'\x00\x00' + b'\x00\x00' +
            b'\x00' * 8 + body)


def _ospf3_hello_bytes():
    body = (b'\x00\x00\x00\x05' + bytes([1]) + bytes([0, 0, 0x13]) +
            b'\x00\x0a' + b'\x00\x28' + _ip4b('1.1.1.1') +
            _ip4b('0.0.0.0') + _ip4b('2.2.2.2'))
    length = 16 + len(body)
    return (bytes([3, 1]) + bytes([length >> 8, length & 0xff]) +
            _ip4b('1.1.1.1') + _ip4b('0.0.0.0') + b'\x00\x00' + bytes([0, 0]) +
            body)


def record_ospf(name, eth, pq_type, out):
    """Serialize an OSPF frame with update, reparse it, and capture the common
    header, the packet-type/LSA fields and the full wire hash the reader
    recovered. Fields that do not apply to a given packet report None, which
    is exactly the shape the golden diff should pin.
    """
    wire = eth.pkt2net({'csum': 1, 'update': 1})
    copy = Ethernet(wire)
    o = copy.get_layer_by_type(pq_type)
    rec = {
        'wire_len': len(wire),
        'wire_sha1': hashlib.sha1(wire).hexdigest(),
        'ospf.version': o.get_field_val('ospf.version'),
        'ospf.msg': o.get_field_val('ospf.msg'),
        'ospf.packet_length': o.get_field_val('ospf.packet_length'),
        'ospf.srcrouter': o.get_field_val('ospf.srcrouter'),
        'ospf.area_id': o.get_field_val('ospf.area_id'),
        'ospf.lsa_count': len(o.lsas),
        'ospf.malformed': o.malformed,
    }
    if o.lsas:
        rec['lsa0.type'] = o.lsas[0].get_field_val('ospf.lsa.type') \
            if pq_type == C.PQ_OSPF \
            else o.lsas[0].get_field_val('ospf.v3.lsa.type')
        rec['lsa0.id'] = o.lsas[0].get_field_val('ospf.lsa.id')
        rec['lsa0.seqnum'] = o.lsas[0].get_field_val('ospf.lsa.seqnum')
    return name, rec


def ospf_corpus():
    """OSPFv2/v3 read/write coverage: a v2 Hello, a v2 LS Update carrying a
    Router-LSA and an AS-External-LSA, and a v3 Hello over IPv6.
    """
    out = {}
    for label, raw in (('ospf2_hello', _ospf2_hello_bytes()),
                       ('ospf2_lsupdate', _ospf2_lsupdate_bytes())):
        eth = Ethernet(dst_mac='01:00:5e:00:00:05',
                       src_mac='02:00:00:00:00:01')
        eth.payload = IP(proto=C.PROTO_OSPF, src='10.8.1.1', dst='224.0.0.5',
                         payload=OSPFv2(raw))
        n, r = record_ospf(label, eth, C.PQ_OSPF, out)
        out[n] = r
    eth6 = Ethernet(dst_mac='33:33:00:00:00:05',
                    src_mac='02:00:00:00:00:02')
    eth6.payload = IP6(next_header=C.PROTO_OSPF, src='fe80::1', dst='ff02::5',
                       payload=OSPFv3(_ospf3_hello_bytes()))
    n, r = record_ospf('ospf3_hello', eth6, C.PQ_OSPFV3, out)
    out[n] = r
    return out


# --- BGP golden corpus ------------------------------------------------------
# BGP rides on TCP port 179, so each message is wrapped in an Ethernet/IP/TCP
# frame and reparsed with l7_ports={179: BGP}. Reparsing walks the TCP L7
# dispatch, the 19-byte header, the per-type body and the path
# attributes/capabilities the reader recovered, plus the full wire hash -- so
# the golden diff catches any change to the header layout, an attribute body,
# the enum renderings or the never-raise/round-trip contract.

def _bgp_bytes(mtype, body):
    import struct as _s
    return b'\xff' * 16 + _s.pack('!H', 19 + len(body)) + bytes([mtype]) + body


def _bgp_open_bytes():
    import struct as _s
    caps = (bytes([1, 4]) + _s.pack('!H', 1) + bytes([0, 1]) +      # MP v4 unicast
            bytes([65, 4]) + _s.pack('!I', 65001) +                 # 4-octet AS
            bytes([69, 4]) + _s.pack('!H', 1) + bytes([1, 3]))      # add-path Both
    optparams = bytes([2, len(caps)]) + caps
    body = (bytes([4]) + _s.pack('!H', 65001) + _s.pack('!H', 180) +
            _ip4b('1.1.1.1') + bytes([len(optparams)]) + optparams)
    return _bgp_bytes(1, body)


def _bgp_update_bytes():
    import struct as _s
    def pa(flags, t, v):
        return bytes([flags, t, len(v)]) + v
    attrs = (pa(0x40, 1, bytes([0])) +
             pa(0x40, 2, bytes([2, 1]) + _s.pack('!H', 65010)) +
             pa(0x40, 3, _ip4b('9.9.9.9')) +
             pa(0x80, 4, _s.pack('!I', 100)) +
             pa(0xC0, 8, _s.pack('!I', 0xFFFFFF01)))
    body = (_s.pack('!H', 0) + _s.pack('!H', len(attrs)) + attrs +
            bytes([8, 10]))
    return _bgp_bytes(2, body)


def record_bgp(name, raw, out):
    """Wrap a BGP message in Ethernet/IP/TCP(179), serialize with update, and
    reparse it with l7_ports so the TCP L7 dispatch surfaces the BGP layer.
    """
    eth = Ethernet(dst_mac='02:00:00:00:00:02', src_mac='02:00:00:00:00:01')
    eth.payload = IP(proto=C.PROTO_TCP, src='10.8.1.1', dst='10.8.1.2',
                     payload=TCP(sport=50000, dport=179, payload=raw))
    wire = eth.pkt2net({'csum': 1, 'update': 1})
    copy = Ethernet(wire, l7_ports={179: BGP})
    b = copy.get_layer_by_type(C.PQ_BGP)
    rec = {
        'wire_len': len(wire),
        'wire_sha1': hashlib.sha1(wire).hexdigest(),
        'bgp.type': b.get_field_val('bgp.type'),
        'bgp.length': b.get_field_val('bgp.length'),
        'bgp.malformed': b.malformed,
        'bgp.param_count': len(b.params),
        'bgp.open.myas': b.get_field_val('bgp.open.myas'),
        'bgp.open.identifier': b.get_field_val('bgp.open.identifier'),
        'bgp.cap.ap.sendreceive': b.get_field_val('bgp.cap.ap.sendreceive'),
        'bgp.origin': b.get_field_val('bgp.update.path_attribute.origin'),
        'bgp.next_hop': b.get_field_val('bgp.update.path_attribute.next_hop'),
        'bgp.community': b.get_field_val('bgp.update.path_attribute.community'),
        'bgp.nlri_prefix': b.get_field_val('bgp.nlri_prefix'),
    }
    out[name] = rec


def bgp_corpus():
    """BGP read/write coverage: an OPEN with MP/4-octet-AS/add-path
    capabilities and an UPDATE carrying ORIGIN/AS_PATH/NEXT_HOP/MED/COMMUNITIES
    plus one NLRI, each dispatched via TCP port 179.
    """
    out = {}
    record_bgp('bgp_open', _bgp_open_bytes(), out)
    record_bgp('bgp_update', _bgp_update_bytes(), out)
    return out


# --- RIP / RIPng / HSRP golden corpus ---------------------------------------
# Each message rides on a UDP port (RIP 520, RIPng 521, HSRP 1985), so wrapping
# it in an Ethernet/IP(6)/UDP frame and reparsing with l7_ports walks the UDP
# L7 dispatch, the header, the entries/TLVs the reader recovered and the full
# wire hash -- so the golden diff catches any change to a layout, an enum
# rendering or the never-raise/round-trip contract.

def _rip_route_bytes(af, tag, ip, mask, nh, metric):
    import struct as _s
    return (_s.pack('!HH', af, tag) + _ip4b(ip) + _ip4b(mask) + _ip4b(nh) +
            _s.pack('!I', metric))


def _rip_response_bytes():
    import struct as _s
    body = _s.pack('!HH', 0xFFFF, 2) + (b'secret' + b'\x00' * 16)[:16]  # auth
    body += _rip_route_bytes(2, 0, '192.168.1.0', '255.255.255.0',
                             '0.0.0.0', 1)
    return bytes([2, 2, 0, 0]) + body


def _ripng_response_bytes():
    import struct as _s
    import socket as _sock
    rte = (_sock.inet_pton(_sock.AF_INET6, '2001:db8::') +
           _s.pack('!HBB', 0, 64, 1))
    nh = (_sock.inet_pton(_sock.AF_INET6, '::') + _s.pack('!HBB', 0, 0, 255))
    return bytes([2, 1, 0, 0]) + rte + nh


def _hsrpv1_hello_bytes():
    return (bytes([0, 0, 8, 3, 10, 120, 1, 0]) + b'cisco\x00\x00\x00' +
            _ip4b('10.0.0.1'))


def _hsrp2_group_state_bytes():
    import struct as _s
    value = (bytes([2, 0, 6, 4]) + _s.pack('!H', 1) +
             bytes.fromhex('00000c070ac0') +
             _s.pack('!III', 120, 3000, 10000) + _ip4b('192.168.0.1') +
             b'\x00' * 12)
    return bytes([1, len(value)]) + value


def record_rip(name, raw, cls, pq_type, port, out, v6=False):
    """Wrap a RIP/RIPng/HSRP message in Ethernet/IP(6)/UDP, serialize with
    update, and reparse with l7_ports so the UDP L7 dispatch surfaces the
    routing layer; capture representative fields and the wire hash.
    """
    eth = Ethernet(dst_mac='02:00:00:00:00:02', src_mac='02:00:00:00:00:01')
    udp = UDP(sport=port, dport=port, payload=raw)
    if v6:
        eth.type = 0x86dd
        eth.payload = IP6(next_header=C.PROTO_UDP, src='2001:db8::1',
                          dst='ff02::9', payload=udp)
    else:
        eth.payload = IP(proto=C.PROTO_UDP, src='10.0.0.1', dst='224.0.0.9',
                         payload=udp)
    wire = eth.pkt2net({'csum': 1, 'update': 1})
    p = Ethernet(wire, l7_ports={port: cls}).get_layer_by_type(pq_type)
    rec = {
        'wire_len': len(wire),
        'wire_sha1': hashlib.sha1(wire).hexdigest(),
        'pkt_name': p.pkt_name,
        'malformed': p.malformed,
    }
    if pq_type == C.PQ_RIP:
        rec['rip.command'] = p.get_field_val('rip.command')
        rec['rip.version'] = p.get_field_val('rip.version')
        rec['rip.auth.type'] = p.get_field_val('rip.auth.type')
        rec['rip.auth.passwd'] = p.get_field_val('rip.auth.passwd')
        rec['rip.ip'] = p.get_field_val('rip.ip')
        rec['rip.netmask'] = p.get_field_val('rip.netmask')
        rec['rip.metric'] = p.get_field_val('rip.metric')
        rec['rip.entries'] = len(p.entries)
    elif pq_type == C.PQ_RIPNG:
        rec['ripng.cmd'] = p.get_field_val('ripng.cmd')
        rec['ripng.rte.ipv6_prefix'] = \
            p.get_field_val('ripng.rte.ipv6_prefix')
        rec['ripng.rte.prefix_length'] = \
            p.get_field_val('ripng.rte.prefix_length')
        rec['ripng.rte.metric'] = p.get_field_val('ripng.rte.metric')
        rec['ripng.rtes'] = len(p.rtes)
    else:                       # HSRP
        rec['hsrp.opcode'] = p.get_field_val('hsrp.opcode')
        rec['hsrp.state'] = p.get_field_val('hsrp.state')
        rec['hsrp.virt_ip'] = p.get_field_val('hsrp.virt_ip')
        rec['hsrp2.opcode'] = p.get_field_val('hsrp2.opcode')
        rec['hsrp2.state'] = p.get_field_val('hsrp2.state')
        rec['hsrp2.virt_ip'] = p.get_field_val('hsrp2.virt_ip')
        rec['hsrp.is_v2'] = p.is_v2
    out[name] = rec


def rip_corpus():
    """RIP/RIPng/HSRP read/write coverage: a RIPv2 Response with a simple-
    password auth entry and a route, a RIPng Response with a route and a
    next-hop RTE, an HSRPv1 Hello, and an HSRPv2 Group-State TLV -- each
    dispatched via its UDP port.
    """
    out = {}
    record_rip('rip_response', _rip_response_bytes(), RIP, C.PQ_RIP, 520, out)
    record_rip('ripng_response', _ripng_response_bytes(), RIPng, C.PQ_RIPNG,
               521, out, v6=True)
    record_rip('hsrp_v1_hello', _hsrpv1_hello_bytes(), HSRP, C.PQ_HSRP, 1985,
               out)
    record_rip('hsrp_v2_group_state', _hsrp2_group_state_bytes(), HSRP,
               C.PQ_HSRP, 1985, out)
    return out


def make_dns_answers():
    """One DNS response per resource type the writer branches on.

    Names are chosen so later ones are suffixes of earlier ones -- that is the
    only thing that makes a compression pointer appear, and a pointer with the
    wrong offset is the failure mode this whole section exists to catch.
    """
    dns = DNS()
    dns.ident = 0x1234
    dns.query_resp = 1
    dns.recursion_available = 1
    dns.queries.append(DNSQuery('www.example.com', DNSTYPE_A, RCLASS_IN))
    dns.answers.append(DNSResource('www.example.com', DNSTYPE_CNAME,
                                   RCLASS_IN, 300, 0, 'host.example.com'))
    dns.answers.append(DNSResource('host.example.com', DNSTYPE_A,
                                   RCLASS_IN, 300, 4, '10.1.2.3'))
    dns.answers.append(DNSResource('host.example.com', DNSTYPE_AAAA,
                                   RCLASS_IN, 300, 16, 'fc00::1'))
    dns.answers.append(DNSResource('txt.example.com', DNSTYPE_TXT,
                                   RCLASS_IN, 300, 0, 'v=spf1 -all'))
    dns.authority.append(DNSResource('example.com', DNSTYPE_NS,
                                     RCLASS_IN, 300, 0, 'ns1.example.com'))
    dns.authority.append(DNSResource('3.2.1.10.in-addr.arpa', DNSTYPE_PTR,
                                     RCLASS_IN, 300, 0, 'host.example.com'))
    return dns


def make_dns_soa():
    """An SOA answer on its own: two names plus five 32 bit words, and the
    only record whose resource data is reassembled from a printable string.
    """
    dns = DNS()
    dns.ident = 0x4321
    dns.query_resp = 1
    dns.queries.append(DNSQuery('example.com', DNSTYPE_SOA, RCLASS_IN))
    dns.answers.append(DNSResource(
        'example.com', DNSTYPE_SOA, RCLASS_IN, 300, 0,
        'SOA mname: ns1.example.com, rname: root@example.com, serial: 2018,'
        ' refresh: 7200, retry: 600, expire: 86400, minimum: 300'))
    return dns


def record_dns(name, dns, kwargs, out, reparse=True):
    """Serialize a DNS message, reparse it, and capture the bytes and the
    fields the reader recovered from them.

    reparse is off for the update=0 case: that writes the rdlength values the
    caller set rather than the real ones, so the reader cannot be expected to
    walk the result. The bytes are still worth locking down.
    """
    wire = dns.pkt2net(dict(kwargs))
    if not reparse:
        out[name] = {'wire_len': len(wire), 'wire_hex': wire.hex()}
        return
    back = DNS(wire)
    out[name] = {
        'wire_len': len(wire),
        'wire_hex': wire.hex(),
        'ident': back.ident,
        'query_count': back.query_count,
        'answer_count': back.answer_count,
        'auth_count': back.auth_count,
        'queries': [(q.query_name, q.query_type, q.query_class)
                    for q in back.queries],
        'answers': [(r.domain_name, r.res_type, r.res_class, r.res_ttl,
                     r.res_len, r.res_data) for r in back.answers],
        'authority': [(r.domain_name, r.res_type, r.res_class, r.res_ttl,
                       r.res_len, r.res_data) for r in back.authority],
    }


def dns_corpus():
    """DNS write path coverage.

    The harness had none, which meant the golden diff -- the check the
    serialize-writer work leans on -- could not see a DNS change at all.
    Both compression settings are captured, and the last case carries the
    message inside a full Ethernet/IP/UDP frame: nested in a frame the DNS
    message no longer starts at offset zero of the output buffer, so a
    compression pointer measured from the wrong origin shows up only there.
    """
    out = {}
    record_dns('dns_answers_compressed', make_dns_answers(),
               {'update': 1, 'compress': 1}, out)
    record_dns('dns_answers_uncompressed', make_dns_answers(),
               {'update': 1, 'compress': 0}, out)
    record_dns('dns_answers_noupdate', make_dns_answers(),
               {'compress': 1}, out, reparse=False)
    record_dns('dns_soa_compressed', make_dns_soa(),
               {'update': 1, 'compress': 1}, out)
    record_dns('dns_soa_uncompressed', make_dns_soa(),
               {'update': 1, 'compress': 0}, out)
    record_dns('dns_root_name', root_name_dns(),
               {'update': 1, 'compress': 1}, out)

    for label, plen in (('dns_in_frame', 0), ('dns_in_frame_odd', 1)):
        eth = Ethernet(dst_mac='03:02:03:04:05:06',
                       src_mac='06:05:04:03:02:03')
        eth.payload = IP(proto=C.PROTO_UDP, src='10.1.2.3', dst='10.3.2.1',
                         payload=UDP(sport=34567 + plen, dport=53,
                                     payload=make_dns_answers()))
        wire = eth.pkt2net({'csum': 1, 'update': 1, 'compress': 1})
        # DNS is not auto-registered on port 53; the caller supplies the
        # layer 7 map, exactly as the test suite and pcap_query do.
        copy = Ethernet(wire, l7_ports={53: DNS})
        back = copy.get_layer('DNS')
        out[label] = {
            'wire_len': len(wire),
            'wire_sha1': hashlib.sha1(wire).hexdigest(),
            'udp.checksum': copy.get_layer('UDP').checksum,
            'dns.ident': back.ident,
            'dns.answers': [(r.domain_name, r.res_type, r.res_len, r.res_data)
                            for r in back.answers],
            'dns.authority': [(r.domain_name, r.res_type, r.res_len,
                               r.res_data) for r in back.authority],
        }
    return out


def root_name_dns():
    """A record whose owner is the root zone: the empty name, written as a
    lone zero length label. Its own branch in the name writer, and only
    reachable through DNSResource -- DNSQuery rejects an empty query name.
    """
    dns = DNS()
    dns.ident = 0x0001
    dns.query_resp = 1
    dns.answers.append(DNSResource('', DNSTYPE_NS, RCLASS_IN, 300, 0,
                                   'ns1.example.com'))
    return dns


if __name__ == '__main__':
    print(json.dumps(corpus(), indent=2, sort_keys=True))
