#!/usr/bin/env python

import gc
import unittest
from array import array

from packets.core.inetpkt import NullPkt, TCP
from packets.protos.http import HTTP, HTTPRequest, HTTPResponse


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
            b'POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabc',
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


if __name__ == '__main__':
    unittest.main()
