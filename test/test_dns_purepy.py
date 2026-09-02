import unittest
import struct
import socket
from array import array
from packets.protos.dns_purepy import DNS, DNSQuery, DNSResource, DNSTYPES, DNSRCLASS

class TestDNSPurePy(unittest.TestCase):
    def test_import(self):
        # Regression test for the blocker: the module should import without error.
        import packets.protos.dns_purepy as dns_purepy
        self.assertTrue(hasattr(dns_purepy, 'DNS'))

    def test_parse_query(self):
        # ID: 0x1234
        # Flags: 0x0100 (Standard query, Recursion desired)
        # Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
        header = struct.pack('!6H', 0x1234, 0x0100, 1, 0, 0, 0)
        # Query: www.example.com (3www7example3com0), Type: A, Class: IN
        query = b'\x03www\x07example\x03com\x00' + struct.pack('!HH', DNSTYPES.A, DNSRCLASS.IN)
        
        pkt = DNS(header + query)
        self.assertEqual(pkt.ident, 0x1234)
        self.assertEqual(pkt.query_resp, 0)
        self.assertEqual(pkt.recursion_requested, 1)
        self.assertEqual(pkt.query_count, 1)
        self.assertEqual(len(pkt.queries), 1)
        self.assertEqual(pkt.queries[0].query_name, 'www.example.com')
        self.assertEqual(pkt.queries[0].query_type, DNSTYPES.A)

    def test_parse_response_with_compression(self):
        # ID: 0x1234
        # Flags: 0x8180 (Standard query response, Recursion desired, Recursion available)
        # Questions: 1, Answer RRs: 1, Authority RRs: 0, Additional RRs: 0
        header = struct.pack('!6H', 0x1234, 0x8180, 1, 1, 0, 0)
        # Query: www.example.com
        query = b'\x03www\x07example\x03com\x00' + struct.pack('!HH', DNSTYPES.A, DNSRCLASS.IN)
        # Answer: www.example.com (Pointer to offset 12), Type: A, Class: IN, TTL: 300, Len: 4, Data: 1.2.3.4
        answer = struct.pack('!H', 0xc00c) + struct.pack('!HHIH', DNSTYPES.A, DNSRCLASS.IN, 300, 4) + socket.inet_aton('1.2.3.4')
        
        pkt = DNS(header + query + answer)
        self.assertEqual(pkt.ident, 0x1234)
        self.assertEqual(pkt.query_resp, 1)
        self.assertEqual(pkt.answer_count, 1)
        self.assertEqual(len(pkt.answers), 1)
        self.assertEqual(pkt.answers[0].domain_name, 'www.example.com')
        self.assertEqual(pkt.answers[0].res_data, '1.2.3.4')

    def test_malformed_pointer(self):
        # Pointer pointing to itself (offset 12)
        header = struct.pack('!6H', 0x1234, 0x0100, 1, 0, 0, 0)
        query = b'\xc0\x0c' + struct.pack('!HH', DNSTYPES.A, DNSRCLASS.IN)
        
        with self.assertRaises(ValueError) as cm:
            DNS(header + query)
        self.assertIn("compression pointer", str(cm.exception))

    def test_query_info(self):
        pq_type, fields = DNS.query_info()
        self.assertEqual(pq_type, 53)
        self.assertIsInstance(fields, tuple)
        self.assertIsInstance(fields[0], str)
        self.assertIn('dns.resp_code', fields)
        self.assertNotIn(b'dns.resp_code', fields)

    def test_get_field_val(self):
        pkt = DNS(ident=0xabcd, resp_code=3)
        self.assertEqual(pkt.get_field_val('dns.ident'), 0xabcd)
        self.assertEqual(pkt.get_field_val('dns.resp_code'), 3)

    def test_pkt2net_roundtrip(self):
        pkt = DNS(ident=0x5678, query_resp=1)
        pkt.queries.append(DNSQuery('mail.example.com', DNSTYPES.A, DNSRCLASS.IN))
        pkt.answers.append(DNSResource('mail.example.com', DNSTYPES.A, DNSRCLASS.IN, 600, 4, '5.6.7.8'))
        
        wire = pkt.pkt2net({'update': 1, 'compress': 1})
        self.assertIsInstance(wire, bytes)
        
        pkt2 = DNS(wire)
        self.assertEqual(pkt2.ident, 0x5678)
        self.assertEqual(pkt2.query_resp, 1)
        self.assertEqual(pkt2.query_count, 1)
        self.assertEqual(pkt2.queries[0].query_name, 'mail.example.com')
        self.assertEqual(pkt2.answers[0].domain_name, 'mail.example.com')
        self.assertEqual(pkt2.answers[0].res_data, '5.6.7.8')
        self.assertEqual(pkt2.answers[0].res_ttl, 600)

if __name__ == '__main__':
    unittest.main()
