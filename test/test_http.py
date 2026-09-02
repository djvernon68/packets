#!/usr/bin/env python

import gc
import unittest
from array import array

from packets.core.inetpkt import Ethernet, IP, NullPkt, TCP
from packets.protos.http import (
    HTTP, HTTPBodyFragment, HTTPRequest, HTTPResponse, get_http_streams)


class HTTPTestCase(unittest.TestCase):

    def test_request_content_length_duplicate_headers_and_pipeline(self):
        wire = (
            b'POST /submit?x=1 HTTP/1.1\r\n'
            b'Host: example.test\r\n'
            b'X-Trace: first\r\n'
            b'x-trace: second\r\n'
            b'Content-Length: 4\r\n'
            b'\r\n'
            b'data'
            b'GET /next HTTP/1.1\r\n\r\n')
        request = HTTPRequest(wire)

        self.assertEqual(request.method, b'POST')
        self.assertEqual(request.target, b'/submit?x=1')
        self.assertEqual(request.version, b'HTTP/1.1')
        self.assertEqual(request.body, b'data')
        self.assertEqual(request.data, b'GET /next HTTP/1.1\r\n\r\n')
        self.assertEqual(request.get_header(b'HOST'), b'example.test')
        self.assertEqual(request.get_headers('x-trace'), [b'first', b'second'])
        self.assertEqual(request.headers[1][0], b'X-Trace')
        self.assertEqual(request.headers[2][0], b'x-trace')
        self.assertEqual(request.pkt2net({}), wire)

    def test_http09_request(self):
        request = HTTPRequest(b'GET /legacy\r\n')
        self.assertEqual(request.method, b'GET')
        self.assertEqual(request.target, b'/legacy')
        self.assertEqual(request.version, b'HTTP/0.9')
        self.assertEqual(request.headers, [])
        self.assertEqual(request.body, b'')
        self.assertEqual(request.pkt2net({}), b'GET /legacy\r\n')

    def test_chunked_response_preserves_wire_and_trailers(self):
        wire = (
            b'HTTP/1.1 200 OK\r\n'
            b'Transfer-Encoding: gzip, chunked\r\n'
            b'X-Test: value\r\n'
            b'\r\n'
            b'4;foo=bar\r\nWiki\r\n'
            b'5\r\npedia\r\n'
            b'0\r\n'
            b'X-Checksum: done\r\n'
            b'\r\n'
            b'HTTP/1.1 204 No Content\r\n\r\n')
        response = HTTPResponse(wire)

        self.assertEqual(response.version, b'HTTP/1.1')
        self.assertEqual(response.status, b'200')
        self.assertEqual(response.reason, b'OK')
        self.assertEqual(response.body, b'Wikipedia')
        self.assertEqual(response.trailers, [(b'X-Checksum', b'done')])
        self.assertTrue(response.data.startswith(b'HTTP/1.1 204'))
        self.assertEqual(response.pkt2net({}), wire)

    def test_chunked_body_change_uses_canonical_framing(self):
        response = HTTPResponse(
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
            b'3;old=yes\r\nold\r\n0\r\nX-End: one\r\n\r\n')
        response.body = b'new body'
        response.trailers = [(b'X-End', b'two')]
        expected = (
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
            b'8\r\nnew body\r\n0\r\nX-End: two\r\n\r\n')
        self.assertEqual(response.pkt2net({}), expected)

    def test_response_close_delimited_and_bodyless_status(self):
        close_wire = b'HTTP/1.0 200 Fine\r\nServer: example\r\n\r\nbody'
        close_response = HTTPResponse(close_wire)
        self.assertEqual(close_response.body, b'body')
        self.assertEqual(close_response.data, b'')
        self.assertEqual(close_response.pkt2net({}), close_wire)

        empty_wire = b'HTTP/1.1 204 No Content\r\n\r\nNEXT'
        empty_response = HTTPResponse(empty_wire)
        self.assertEqual(empty_response.body, b'')
        self.assertEqual(empty_response.data, b'NEXT')
        self.assertEqual(empty_response.pkt2net({}), empty_wire)

    def test_fixed_body_split_by_mtu_is_partial_not_rejected(self):
        # A Content-Length body split across TCP segments by the path MTU means
        # a single captured packet carries only the leading part of the body.
        # The partial bytes are kept, data is empty, body_complete is false, and
        # the fragment still serializes back to the exact captured wire.
        response_wire = (
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Length: 1000\r\n'
            b'\r\n' + b'X' * 400)
        response = HTTPResponse(response_wire)
        self.assertEqual(response.status, b'200')
        self.assertEqual(response.body, b'X' * 400)
        self.assertEqual(response.data, b'')
        self.assertFalse(response.body_complete)
        self.assertEqual(response.pkt2net({}), response_wire)

        request_wire = (
            b'POST /upload HTTP/1.1\r\n'
            b'Content-Length: 10\r\n'
            b'\r\n'
            b'abc')
        request = HTTPRequest(request_wire)
        self.assertEqual(request.method, b'POST')
        self.assertEqual(request.body, b'abc')
        self.assertEqual(request.data, b'')
        self.assertFalse(request.body_complete)
        self.assertEqual(request.pkt2net({}), request_wire)

        # A fully present fixed body still reports as complete.
        whole = HTTPResponse(
            b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody')
        self.assertTrue(whole.body_complete)
        self.assertEqual(whole.body, b'body')

        # Dispatch through HTTP preserves the partial-body semantics.
        dispatched = HTTP(response_wire)
        self.assertIsInstance(dispatched.message, HTTPResponse)
        self.assertFalse(dispatched.message.body_complete)
        self.assertEqual(dispatched.pkt2net({}), response_wire)

    def test_body_continuation_fragment_is_kept_not_rejected(self):
        # A packet carrying only the middle or the end of a body has no HTTP
        # start line.  The dispatcher must keep those bytes as an
        # HTTPBodyFragment instead of raising, so a caller can reassemble.
        middle = b'\x00\x01middle body bytes\xff\xfe'
        fragment = HTTP(middle)
        self.assertIsInstance(fragment.message, HTTPBodyFragment)
        self.assertEqual(fragment.message.data, middle)
        self.assertFalse(fragment.message.body_complete)
        # The opaque bytes serialize back verbatim.
        self.assertEqual(fragment.pkt2net({}), middle)

        # A final segment that ends a body, even one that contains CRLFs but no
        # valid start line, is also kept rather than rejected.
        tail = b'trailing body chunk\r\nnot a start line'
        tail_fragment = HTTP(tail)
        self.assertIsInstance(tail_fragment.message, HTTPBodyFragment)
        self.assertEqual(tail_fragment.message.data, tail)
        self.assertEqual(tail_fragment.pkt2net({}), tail)

    def test_body_fragment_direct_construction(self):
        raw = b'\x89PNG\r\n\x1a\n a chunk of image body'
        fragment = HTTPBodyFragment(raw)
        self.assertEqual(fragment.data, raw)
        self.assertFalse(fragment.body_complete)
        self.assertEqual(fragment.get_header(b'Content-Type'), None)
        self.assertEqual(fragment.get_headers(b'Content-Type'), [])
        self.assertEqual(fragment.get_field_val('http.body_length'), len(raw))
        self.assertIsNone(fragment.get_field_val('http.request.method'))
        self.assertEqual(fragment.pkt2net({}), raw)

        keyword = HTTPBodyFragment(data=raw)
        self.assertEqual(keyword.data, raw)
        self.assertEqual(keyword.pkt2net({}), raw)

    def test_body_fragment_over_tcp_owner(self):
        # The real caller reaches HTTP through a transport packet with
        # l7_ports={80: HTTP}; a continuation segment must decode there too.
        payload = b'raw continuation of a split body with no start line'
        tcp_wire = TCP(sport=40000, dport=80,
                       payload=NullPkt(payload)).pkt2net({'update': 1})
        tcp = TCP(tcp_wire, l7_ports={80: HTTP})
        child = tcp.payload
        self.assertIsInstance(child, HTTP)
        self.assertIsInstance(child.message, HTTPBodyFragment)
        del tcp
        gc.collect()
        self.assertEqual(child.message.data, payload)
        self.assertEqual(child.pkt2net({}), payload)

    def test_reassemble_mtu_split_response_from_fragments(self):
        # A response whose Content-Length body is split across three captured
        # packets: the first has the start line plus a body prefix, the next
        # two carry the body's middle and end with no framing of their own.
        header = b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n'
        body = b'ABCDEFGHIJKLMNOPQRST'
        full = header + body
        seg1 = full[:len(header) + 8]
        seg2 = full[len(header) + 8:len(header) + 15]
        seg3 = full[len(header) + 15:]

        first = HTTP(seg1)
        self.assertIsInstance(first.message, HTTPResponse)
        self.assertFalse(first.message.body_complete)
        self.assertEqual(first.message.body, body[:8])

        mid = HTTP(seg2)
        self.assertIsInstance(mid.message, HTTPBodyFragment)
        self.assertEqual(mid.message.data, body[8:15])

        end = HTTP(seg3)
        self.assertIsInstance(end.message, HTTPBodyFragment)
        self.assertEqual(end.message.data, body[15:])

        # A caller reassembles the body from the first message's partial body
        # plus each following fragment's bytes, in capture order.
        reassembled = first.message.body + mid.message.data + end.message.data
        self.assertEqual(reassembled, body)

        # Concatenating the losslessly serialized pieces rebuilds the wire, and
        # the reassembled body reconstructs a complete, well-formed response.
        self.assertEqual(
            first.pkt2net({}) + mid.pkt2net({}) + end.pkt2net({}), full)
        rebuilt = HTTPResponse(
            version=b'HTTP/1.1', status=b'200', reason=b'OK',
            headers=[(b'Content-Length', b'20')], body=reassembled)
        self.assertTrue(rebuilt.body_complete)
        self.assertEqual(rebuilt.pkt2net({}), full)

    def test_construct_request_and_response(self):
        request = HTTPRequest(
            method=b'PUT', target=b'/resource', version=b'HTTP/1.1',
            headers=[(b'Host', b'example.test'),
                     (b'Content-Length', b'3')],
            body=b'new')
        self.assertEqual(
            request.pkt2net({}),
            b'PUT /resource HTTP/1.1\r\nHost: example.test\r\n'
            b'Content-Length: 3\r\n\r\nnew')

        response = HTTPResponse(
            version=b'HTTP/1.1', status=b'404', reason=b'Not Found',
            headers=[(b'Content-Length', b'0')])
        self.assertEqual(
            response.pkt2net({}),
            b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')

    def test_dispatch_direct_mutable_and_tcp_owner(self):
        wire = b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'
        mutable = array('B', wire)
        packet = HTTP(mutable)
        mutable[0] = ord('P')
        self.assertIsInstance(packet.message, HTTPRequest)
        self.assertEqual(packet.message.method, b'GET')
        self.assertEqual(packet.pkt2net({}), wire)

        tcp_wire = TCP(sport=40000, dport=80,
                       payload=NullPkt(wire)).pkt2net({'update': 1})
        tcp = TCP(tcp_wire, l7_ports={80: HTTP})
        child = tcp.payload
        self.assertIsInstance(child, HTTP)
        self.assertIsInstance(child.message, HTTPRequest)
        del tcp
        gc.collect()
        self.assertEqual(child.pkt2net({}), wire)

        response = HTTP(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        self.assertIsInstance(response.message, HTTPResponse)

    def test_rejects_malformed_start_headers_and_lengths(self):
        bad_messages = [
            b'',
            b'GET\r\n',
            b'GET / HTTP/1.1\r\nHost: x\r\n',
            b'GET / HTTP/1.1\r\nBad Header: x\r\n\r\n',
            b'GET / HTTP/1.1\r\nNoColon\r\n\r\n',
            b'POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n',
            b'POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n',
            b'POST / HTTP/1.1\r\nContent-Length: 2\r\n'
            b'Content-Length: 3\r\n\r\nabc',
        ]
        for wire in bad_messages:
            with self.subTest(wire=wire):
                with self.assertRaises(ValueError):
                    HTTPRequest(wire)

        for wire in (b'NOTHTTP\r\n\r\n',
                     b'HTTP/1.1 only-two\r\n\r\n',
                     b'HTTP/1.1 xyz Bad\r\n\r\n'):
            with self.subTest(wire=wire):
                with self.assertRaises(ValueError):
                    HTTPResponse(wire)

    def test_rejects_malformed_chunked_bodies(self):
        prefix = (b'HTTP/1.1 200 OK\r\n'
                  b'Transfer-Encoding: chunked\r\n\r\n')
        for body in (b'', b'xyz\r\n', b'3\r\nab', b'3\r\nabcX',
                     b'0\r\nBad Trailer\r\n\r\n'):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    HTTPResponse(prefix + body)

    def test_query_fields_resolve(self):
        request = HTTP(b'GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n')
        response = HTTP(
            b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        for field in HTTP.query_info()[1]:
            self.assertTrue(
                request.get_field_val(field) is not None or
                response.get_field_val(field) is not None,
                field)

    # --- get_http_streams TCP stream reassembly ----------------------------

    @staticmethod
    def _segment(src, sport, dst, dport, seq, payload, syn=False, ack=False):
        """Build a decoded Ethernet/IP/TCP packet carrying an HTTP payload.

        The frame is serialized and re-parsed with ``l7_ports={80: HTTP}`` so
        the result matches exactly what a caller feeds ``get_http_streams``:
        a top-level packet whose TCP payload has decoded to ``HTTP``.
        """
        tcp = TCP(sport=sport, dport=dport, sequence=seq,
                  payload=NullPkt(payload))
        if syn:
            tcp.flag_syn = 1
        if ack:
            tcp.flag_ack = 1
        ip = IP(src=src, dst=dst, proto=6, payload=tcp)
        eth = Ethernet(src_mac='00:11:22:33:44:55',
                       dst_mac='66:77:88:99:aa:bb', payload=ip)
        return Ethernet(eth.pkt2net({'update': 1}), l7_ports={80: HTTP})

    def test_get_http_streams_reassembles_split_response(self):
        # A GET request from the client, and a Content-Length response whose
        # body the path MTU split across three server->client segments.
        client, server = '10.0.0.1', '10.0.0.2'
        cport, sport = 40000, 80
        req_wire = (b'GET /file HTTP/1.1\r\nHost: h\r\n\r\n')
        body = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        resp = (b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n'
                % len(body)) + body
        head = resp[:len(resp) - 30]
        mid = resp[len(resp) - 30:len(resp) - 12]
        tail = resp[len(resp) - 12:]

        packets = [
            self._segment(client, cport, server, sport, 1000, req_wire),
            self._segment(server, sport, client, cport, 5000, head),
            self._segment(server, sport, client, cport, 5000 + len(head), mid),
            self._segment(server, sport, client, cport,
                          5000 + len(head) + len(mid), tail),
        ]
        streams = get_http_streams(packets)
        self.assertEqual(len(streams), 1)
        key = next(iter(streams))
        # The key carries the 5-tuple (both endpoints) plus the sequence-based
        # unique id from each direction's initial sequence number.
        self.assertIn('10.0.0.1:40000', key)
        self.assertIn('10.0.0.2:80', key)
        self.assertIn('isn=1000,5000', key)

        pairs = streams[key]
        self.assertEqual(len(pairs), 1)
        request, response = pairs[0]
        self.assertIsInstance(request.message, HTTPRequest)
        self.assertEqual(request.message.method, b'GET')
        self.assertIsInstance(response.message, HTTPResponse)
        # The three segments reassemble into one complete response body.
        self.assertTrue(response.message.body_complete)
        self.assertEqual(response.message.body, body)
        self.assertEqual(response.pkt2net({}), resp)

    def test_get_http_streams_orders_and_dedups_segments(self):
        # Segments arrive out of order, and the middle one is retransmitted.
        client, server = '192.168.0.5', '192.168.0.9'
        cport = 51000
        body = b'0123456789abcdefghij'
        resp = (b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n'
                % len(body)) + body
        s1 = resp[:len(resp) - 14]
        s2 = resp[len(resp) - 14:len(resp) - 6]
        s3 = resp[len(resp) - 6:]
        base = 7000
        seg1 = self._segment(server, 80, client, cport, base, s1)
        seg2 = self._segment(server, 80, client, cport, base + len(s1), s2)
        seg3 = self._segment(server, 80, client, cport,
                             base + len(s1) + len(s2), s3)
        seg2_dup = self._segment(server, 80, client, cport,
                                 base + len(s1), s2)
        req = self._segment(client, cport, server, 80, 100,
                            b'GET / HTTP/1.1\r\n\r\n')

        # Deliver third, first, duplicate-second, second, plus the request.
        streams = get_http_streams([seg3, seg1, seg2_dup, req, seg2])
        self.assertEqual(len(streams), 1)
        pairs = next(iter(streams.values()))
        self.assertEqual(len(pairs), 1)
        request, response = pairs[0]
        self.assertIsInstance(request.message, HTTPRequest)
        self.assertTrue(response.message.body_complete)
        self.assertEqual(response.message.body, body)
        self.assertEqual(response.pkt2net({}), resp)

    def test_get_http_streams_keep_alive_pipeline(self):
        # Two requests and two responses over one keep-alive connection are
        # returned as two ordered (request, response) exchange pairs.
        client, server = '10.1.1.1', '10.1.1.2'
        cport = 33333
        reqs = (b'GET /one HTTP/1.1\r\nHost: h\r\n\r\n'
                b'GET /two HTTP/1.1\r\nHost: h\r\n\r\n')
        resps = (b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc'
                 b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
        packets = [
            self._segment(client, cport, server, 80, 1, reqs),
            self._segment(server, 80, client, cport, 1, resps),
        ]
        streams = get_http_streams(packets)
        pairs = next(iter(streams.values()))
        self.assertEqual(len(pairs), 2)

        first_req, first_resp = pairs[0]
        self.assertEqual(first_req.message.target, b'/one')
        self.assertEqual(first_resp.message.status, b'200')
        self.assertEqual(first_resp.message.body, b'abc')
        # Each exchange element is a clean single message: serializing it
        # reproduces only that message, not the following pipelined one.
        self.assertEqual(
            first_req.pkt2net({}), b'GET /one HTTP/1.1\r\nHost: h\r\n\r\n')

        second_req, second_resp = pairs[1]
        self.assertEqual(second_req.message.target, b'/two')
        self.assertEqual(second_resp.message.status, b'404')

    def test_get_http_streams_missing_segment_is_partial(self):
        # The head of the response body is captured but a later segment is
        # missing: the exchange is still returned, flagged incomplete.
        client, server = '172.16.0.1', '172.16.0.2'
        cport = 44444
        body = b'X' * 40
        resp = (b'HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n') + body
        head = resp[:len(resp) - 20]
        # The final 20 body bytes (a segment) are never provided -> a hole.
        packets = [
            self._segment(client, cport, server, 80, 1,
                          b'GET / HTTP/1.1\r\n\r\n'),
            self._segment(server, 80, client, cport, 9000, head),
        ]
        streams = get_http_streams(packets)
        pairs = next(iter(streams.values()))
        self.assertEqual(len(pairs), 1)
        _, response = pairs[0]
        self.assertIsInstance(response.message, HTTPResponse)
        self.assertFalse(response.message.body_complete)
        # Only the 20 body bytes that were captured are kept.
        self.assertEqual(response.message.body, b'X' * 20)

    def test_get_http_streams_unique_id_disambiguates_reused_5tuple(self):
        # Two separate connections reuse the exact same 5-tuple; their
        # different initial sequence numbers keep them in distinct entries.
        client, server = '10.9.9.1', '10.9.9.2'
        cport = 55555
        req = b'GET / HTTP/1.1\r\nHost: h\r\n\r\n'
        resp = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi'

        # Each connection opens with a client SYN and server SYN-ACK, which is
        # what lets a reused 5-tuple be told apart as two separate instances.
        conn_a = [
            self._segment(client, cport, server, 80, 100, b'', syn=True),
            self._segment(server, 80, client, cport, 200, b'',
                          syn=True, ack=True),
            self._segment(client, cport, server, 80, 101, req),
            self._segment(server, 80, client, cport, 201, resp),
        ]
        conn_b = [
            self._segment(client, cport, server, 80, 90000, b'', syn=True),
            self._segment(server, 80, client, cport, 80000, b'',
                          syn=True, ack=True),
            self._segment(client, cport, server, 80, 90001, req),
            self._segment(server, 80, client, cport, 80001, resp),
        ]
        streams = get_http_streams(conn_a + conn_b)
        self.assertEqual(len(streams), 2)
        ids = sorted(key.split('isn=')[1] for key in streams)
        self.assertEqual(ids, ['100,200', '90000,80000'])
        for pairs in streams.values():
            self.assertEqual(len(pairs), 1)
            request, response = pairs[0]
            self.assertEqual(response.message.body, b'hi')

    def test_get_http_streams_uses_syn_initial_sequence(self):
        # When a SYN is present its sequence number is the stream's true ISN
        # and is used for the unique id even though it carries no payload.
        client, server = '10.5.5.1', '10.5.5.2'
        cport = 60000
        packets = [
            self._segment(client, cport, server, 80, 1000, b'', syn=True),
            self._segment(server, 80, client, cport, 7000, b'',
                          syn=True, ack=True),
            self._segment(client, cport, server, 80, 1001,
                          b'GET / HTTP/1.1\r\n\r\n'),
            self._segment(server, 80, client, cport, 7001,
                          b'HTTP/1.1 204 No Content\r\n\r\n'),
        ]
        streams = get_http_streams(packets)
        self.assertEqual(len(streams), 1)
        key = next(iter(streams))
        self.assertIn('isn=1000,7000', key)

    def test_get_http_streams_ignores_non_tcp_and_non_http(self):
        # A UDP packet and a TCP segment on a non-HTTP port are both ignored;
        # only the HTTP exchange is traced.
        client, server = '10.2.2.1', '10.2.2.2'
        udp_ip = IP(src=client, dst=server, proto=17,
                    payload=NullPkt(b'not http'))
        udp_eth = Ethernet(src_mac='00:11:22:33:44:55',
                           dst_mac='66:77:88:99:aa:bb', payload=udp_ip)
        udp_pkt = Ethernet(udp_eth.pkt2net({'update': 1}),
                           l7_ports={80: HTTP})
        other_tcp = self._segment(client, 12345, server, 22, 1,
                                  b'SSH-2.0-x\r\n')
        http_req = self._segment(client, 40000, server, 80, 1,
                                 b'GET / HTTP/1.1\r\n\r\n')
        http_resp = self._segment(server, 80, client, 40000, 1,
                                  b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        streams = get_http_streams([udp_pkt, other_tcp, http_req, http_resp])
        self.assertEqual(len(streams), 1)
        key = next(iter(streams))
        self.assertIn(':80', key)
        pairs = streams[key]
        self.assertEqual(len(pairs), 1)
        request, response = pairs[0]
        self.assertEqual(request.message.method, b'GET')
        self.assertEqual(response.message.status, b'200')

    def test_get_http_streams_empty_input(self):
        self.assertEqual(get_http_streams([]), {})


if __name__ == '__main__':
    unittest.main()
