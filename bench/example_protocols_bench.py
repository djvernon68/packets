#!/usr/bin/env python3
"""Focused direct and Layer-7 timings for the example protocol modules."""

from __future__ import print_function

import statistics
import sys
import timeit

from packets.core.inetpkt import NullPkt, TCP, UDP
from packets.protos.dhcp import DHCP, DHCP6, DHCP6Option, DHCPOption, \
    DHCP_OPT_END, DHCP_OPT_MESSAGE_TYPE, DHCP6_RELAY_FORWARD
from packets.protos.http import HTTP


PAYLOAD_SIZES = (0, 64, 512, 1400)


def _payload(size):
    return bytes((i & 0xff) for i in range(size))


def _dhcp4_options(size):
    """Split large values at the one-byte DHCPv4 option length boundary."""
    result = [DHCPOption(code=DHCP_OPT_MESSAGE_TYPE, data=b'\x01')]
    remaining = size
    while remaining:
        length = min(remaining, 255)
        result.append(DHCPOption(code=222,
                                 data=_payload(length)))
        remaining -= length
    result.append(DHCPOption(code=DHCP_OPT_END))
    return result


def _chunked_wire(payload):
    """Use two chunks so the benchmark includes repeated framing work."""
    if not payload:
        return b'0\r\n\r\n'
    split = max(1, len(payload) // 2)
    first = payload[:split]
    second = payload[split:]
    wire = ('{0:x}'.format(len(first)).encode('ascii') + b'\r\n' +
            first + b'\r\n')
    if second:
        wire += ('{0:x}'.format(len(second)).encode('ascii') + b'\r\n' +
                 second + b'\r\n')
    return wire + b'0\r\nX-End: done\r\n\r\n'


def _corpus():
    dhcp4 = DHCP(
        xid=1,
        options=[DHCPOption(code=DHCP_OPT_MESSAGE_TYPE, data=b'\x01'),
                 DHCPOption(code=DHCP_OPT_END)]).pkt2net({})
    dhcp6 = DHCP6(
        msg_type=1, transaction_id=1,
        options=[DHCP6Option(code=65000, data=b'x')]).pkt2net({})
    request = (b'GET / HTTP/1.1\r\nHost: example.test\r\n'
               b'Content-Length: 0\r\n\r\n')
    response = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
                b'4\r\ndata\r\n0\r\n\r\n')
    corpus = {
        'dhcp4': dhcp4,
        'dhcp6': dhcp6,
        'request': request,
        'response': response,
        'udp4': UDP(sport=68, dport=67,
                    payload=NullPkt(dhcp4)).pkt2net({'update': 1}),
        'udp6': UDP(sport=546, dport=547,
                    payload=NullPkt(dhcp6)).pkt2net({'update': 1}),
        'tcp_request': TCP(sport=40000, dport=80,
                           payload=NullPkt(request)).pkt2net({'update': 1}),
        'tcp_response': TCP(sport=80, dport=40000,
                            payload=NullPkt(response)).pkt2net({'update': 1}),
    }
    for size in PAYLOAD_SIZES:
        suffix = 'p{0}'.format(size)
        payload = _payload(size)

        dhcp4_scaled = DHCP(
            xid=1, options=_dhcp4_options(size)).pkt2net({})
        dhcp6_scaled = DHCP6(
            msg_type=1, transaction_id=1,
            options=[DHCP6Option(code=65000,
                                 data=payload)]).pkt2net({})
        dhcp6_relay = DHCP6(
            msg_type=DHCP6_RELAY_FORWARD, hop_count=1,
            link_address='2001:db8::1', peer_address='fe80::1',
            options=[DHCP6Option(code=9, data=payload)]).pkt2net({})

        request_fixed = (
            b'POST /fixed HTTP/1.1\r\nHost: example.test\r\n'
            b'Content-Length: ' + str(size).encode('ascii') +
            b'\r\n\r\n' + payload)
        request_chunked = (
            b'POST /chunked HTTP/1.1\r\nHost: example.test\r\n'
            b'Transfer-Encoding: chunked\r\n\r\n' +
            _chunked_wire(payload))
        response_fixed = (
            b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
            b'Content-Length: ' + str(size).encode('ascii') +
            b'\r\n\r\n' + payload)
        response_chunked = (
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' +
            _chunked_wire(payload))
        response_close = (
            b'HTTP/1.0 200 OK\r\nServer: example.test\r\n\r\n' + payload)

        messages = {
            'dhcp4_opts_' + suffix: (dhcp4_scaled, 'udp4'),
            'dhcp6_opts_' + suffix: (dhcp6_scaled, 'udp6'),
            'dhcp6_relay_' + suffix: (dhcp6_relay, 'udp6'),
            'http_req_fixed_' + suffix: (request_fixed, 'tcp_request'),
            'http_req_chunked_' + suffix: (request_chunked, 'tcp_request'),
            'http_resp_fixed_' + suffix: (response_fixed, 'tcp_response'),
            'http_resp_chunked_' + suffix: (response_chunked, 'tcp_response'),
            'http_resp_close_' + suffix: (response_close, 'tcp_response'),
        }
        for name, item in messages.items():
            message, transport = item
            corpus[name] = message
            if transport == 'udp4':
                corpus[name + '_transport'] = UDP(
                    sport=68, dport=67,
                    payload=NullPkt(message)).pkt2net({'update': 1})
            elif transport == 'udp6':
                corpus[name + '_transport'] = UDP(
                    sport=546, dport=547,
                    payload=NullPkt(message)).pkt2net({'update': 1})
            elif transport == 'tcp_request':
                corpus[name + '_transport'] = TCP(
                    sport=40000, dport=80,
                    payload=NullPkt(message)).pkt2net({'update': 1})
            else:
                corpus[name + '_transport'] = TCP(
                    sport=80, dport=40000,
                    payload=NullPkt(message)).pkt2net({'update': 1})

    corpus['http09'] = b'GET /legacy\r\n'
    corpus['http09_transport'] = TCP(
        sport=40000, dport=80,
        payload=NullPkt(corpus['http09'])).pkt2net({'update': 1})
    corpus['http_resp_204'] = b'HTTP/1.1 204 No Content\r\n\r\nNEXT'
    corpus['http_resp_204_transport'] = TCP(
        sport=80, dport=40000,
        payload=NullPkt(corpus['http_resp_204'])).pkt2net({'update': 1})
    return corpus


def _bench(label, function, iterations, repeats):
    samples = timeit.repeat(function, number=iterations, repeat=repeats)
    median = statistics.median(samples) * 1000000000.0 / iterations
    best = min(samples) * 1000000000.0 / iterations
    print('{0:<24} median {1:8.1f} ns best {2:8.1f} ns'.format(
        label, median, best))


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    repeats = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    corpus = _corpus()
    dhcp4_ports = {67: DHCP}
    dhcp6_ports = {547: DHCP6}
    http_ports = {80: HTTP}

    cases = [
        ('dhcp4_direct', lambda: DHCP(corpus['dhcp4'])),
        ('dhcp4_udp_l7',
         lambda: UDP(corpus['udp4'], l7_ports=dhcp4_ports)),
        ('dhcp6_direct', lambda: DHCP6(corpus['dhcp6'])),
        ('dhcp6_udp_l7',
         lambda: UDP(corpus['udp6'], l7_ports=dhcp6_ports)),
        ('http_request_direct', lambda: HTTP(corpus['request'])),
        ('http_request_tcp_l7',
         lambda: TCP(corpus['tcp_request'], l7_ports=http_ports)),
        ('http_response_direct', lambda: HTTP(corpus['response'])),
        ('http_response_tcp_l7',
         lambda: TCP(corpus['tcp_response'], l7_ports=http_ports)),
    ]

    parsed = {
        'dhcp4': DHCP(corpus['dhcp4']),
        'dhcp6': DHCP6(corpus['dhcp6']),
        'http_request': HTTP(corpus['request']),
        'http_response': HTTP(corpus['response']),
    }
    cases.extend((
        ('dhcp4_serialize', lambda: parsed['dhcp4'].pkt2net({})),
        ('dhcp6_serialize', lambda: parsed['dhcp6'].pkt2net({})),
        ('http_request_serialize',
         lambda: parsed['http_request'].pkt2net({})),
        ('http_response_serialize',
         lambda: parsed['http_response'].pkt2net({})),
    ))

    def add_dhcp4(name):
        packet = DHCP(corpus[name])
        cases.extend((
            (name + '_direct', lambda wire=corpus[name]: DHCP(wire)),
            (name + '_udp_l7',
             lambda wire=corpus[name + '_transport']:
             UDP(wire, l7_ports=dhcp4_ports)),
            (name + '_serialize', lambda value=packet: value.pkt2net({})),
        ))

    def add_dhcp6(name):
        packet = DHCP6(corpus[name])
        cases.extend((
            (name + '_direct', lambda wire=corpus[name]: DHCP6(wire)),
            (name + '_udp_l7',
             lambda wire=corpus[name + '_transport']:
             UDP(wire, l7_ports=dhcp6_ports)),
            (name + '_serialize', lambda value=packet: value.pkt2net({})),
        ))

    def add_http(name):
        packet = HTTP(corpus[name])
        cases.extend((
            (name + '_direct', lambda wire=corpus[name]: HTTP(wire)),
            (name + '_tcp_l7',
             lambda wire=corpus[name + '_transport']:
             TCP(wire, l7_ports=http_ports)),
            (name + '_serialize', lambda value=packet: value.pkt2net({})),
        ))

    for size in PAYLOAD_SIZES:
        suffix = 'p{0}'.format(size)
        add_dhcp4('dhcp4_opts_' + suffix)
        add_dhcp6('dhcp6_opts_' + suffix)
        add_dhcp6('dhcp6_relay_' + suffix)
        add_http('http_req_fixed_' + suffix)
        add_http('http_req_chunked_' + suffix)
        add_http('http_resp_fixed_' + suffix)
        add_http('http_resp_chunked_' + suffix)
        add_http('http_resp_close_' + suffix)

    add_http('http09')
    add_http('http_resp_204')
    print('iterations={0} repeats={1}'.format(iterations, repeats))
    for label, function in cases:
        _bench(label, function, iterations, repeats)


if __name__ == '__main__':
    main()
