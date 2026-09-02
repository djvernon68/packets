#!/usr/bin/env python

import io
import os
import contextlib
import unittest

from packets.commands import netflow_player

CAPTURE = os.path.join(os.path.dirname(__file__), 'igmp_v2.pcap')


class TestNetflowPlayerArgs(unittest.TestCase):
    """The netflow-player console script parser.

    Every case here was a defect: the two 'required arguments' were not
    required, parse_args ignored the argv it was handed, none of the four
    integer options were range checked, and a usage error came out as a
    traceback.
    """

    def defaults(self, *extra):
        return ['--file', CAPTURE, '--dest_ip', '10.0.0.1'] + list(extra)

    @contextlib.contextmanager
    def usage_error(self):
        """Expect argparse to exit 2, without its message on the console."""
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as cm:
                yield
        self.assertEqual(cm.exception.code, 2)

    def test_parse_args_uses_its_argument(self):
        # The body called parser.parse_args() with no arguments, so it read
        # sys.argv no matter what it was passed.
        args = netflow_player.parse_args(self.defaults('--dest_port', '9995'))
        self.assertEqual(args.file, CAPTURE)
        self.assertEqual(args.dest_ip, '10.0.0.1')
        self.assertEqual(args.dest_port, 9995)

    def test_defaults(self):
        args = netflow_player.parse_args(self.defaults())
        self.assertEqual(args.pcap_dst_port, 2055)
        self.assertEqual(args.dest_port, 2055)
        self.assertEqual(args.new_type, 0)
        self.assertEqual(args.new_version, 0)
        self.assertEqual(args.blast, 0)
        self.assertFalse(args.spoofing)
        self.assertEqual(args.src_ip, '')
        self.assertEqual(args.src_mac, '')
        self.assertEqual(args.dest_mac, 'ff:ff:ff:ff:ff:ff')

    def test_file_is_required(self):
        # Omitted, this passed None to a cpdef str parameter and died on a
        # TypeError from Cython instead of on argparse's own message.
        with self.usage_error():
            netflow_player.parse_args(['--dest_ip', '10.0.0.1'])

    def test_dest_ip_is_required(self):
        with self.usage_error():
            netflow_player.parse_args(['--file', CAPTURE])

    def test_file_must_exist(self):
        with self.usage_error():
            netflow_player.parse_args(['--file', CAPTURE + '.nope',
                                       '--dest_ip', '10.0.0.1'])

    def test_dest_ip_must_be_an_address(self):
        for bad in ('not.an.ip', '2001:db8::xyz', '1.2.3'):
            with self.usage_error():
                netflow_player.parse_args(['--file', CAPTURE,
                                           '--dest_ip', bad])

    def test_ipv6_destination(self):
        args = netflow_player.parse_args(
            ['--file', CAPTURE, '--dest_ip', '2001:db8::20'])
        self.assertEqual(args.dest_ip, '2001:db8::20')

    def test_new_type_range(self):
        # The help promised a segfault above 255. Cython range checks the
        # conversion, so it was really an OverflowError traceback; either
        # way it is a usage error and belongs to the parser.
        args = netflow_player.parse_args(self.defaults('--new_type', '255'))
        self.assertEqual(args.new_type, 255)
        for bad in ('256', '-1'):
            with self.usage_error():
                netflow_player.parse_args(self.defaults('--new_type', bad))

    def test_sixteen_bit_ranges(self):
        for opt in ('--new_version', '--dest_port', '--pcap_dst_port'):
            args = netflow_player.parse_args(self.defaults(opt, '65535'))
            self.assertEqual(getattr(args, opt.lstrip('-')), 65535)
            for bad in ('65536', '-1'):
                with self.usage_error():
                    netflow_player.parse_args(self.defaults(opt, bad))

    def test_no_segfault_claim_in_help(self):
        # --new_type's help advertised a segfault that cannot happen.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                netflow_player.parse_args(['--help'])
        self.assertNotIn('segfault', buf.getvalue())

    def test_mac_validation(self):
        args = netflow_player.parse_args(
            self.defaults('--dest_mac', '00:11:22:33:44:55'))
        self.assertEqual(args.dest_mac, '00:11:22:33:44:55')
        for bad in ('00:11:22:33:44', 'zz:11:22:33:44:55', '001122334455'):
            with self.usage_error():
                netflow_player.parse_args(self.defaults('--dest_mac', bad))

    def test_optional_addresses_accept_unset(self):
        # '' means 'not set' for the two spoofing addresses, and argparse
        # runs type= over a str default as well as over user input.
        args = netflow_player.parse_args(self.defaults())
        self.assertEqual(args.src_ip, '')
        self.assertEqual(args.src_mac, '')

    def test_spoofing_without_device_is_a_usage_error(self):
        # This used to raise ValueError out of main() as a traceback.
        with self.usage_error():
            netflow_player.parse_args(self.defaults('--spoofing'))

    def test_spoofing_with_device(self):
        args = netflow_player.parse_args(
            self.defaults('--spoofing', '--device', 'lo0',
                          '--src_ip', '10.0.0.2',
                          '--src_mac', 'aa:bb:cc:dd:ee:ff'))
        self.assertTrue(args.spoofing)
        self.assertEqual(args.device, 'lo0')
        self.assertEqual(args.src_ip, '10.0.0.2')
        self.assertEqual(args.src_mac, 'aa:bb:cc:dd:ee:ff')

    def test_spoofing_with_ipv6_source(self):
        args = netflow_player.parse_args(
            ['--file', CAPTURE, '--dest_ip', '2001:db8::20',
             '--spoofing', '--device', 'lo0',
             '--src_ip', '2001:db8::10'])
        self.assertEqual(args.src_ip, '2001:db8::10')

    def test_spoofing_source_must_be_an_address(self):
        with self.usage_error():
            netflow_player.parse_args(
                self.defaults('--spoofing', '--device', 'lo0',
                              '--src_ip', '2001:db8::xyz'))

    def test_spoofing_source_and_destination_families_must_match(self):
        cases = [('10.0.0.1', '2001:db8::10'),
                 ('2001:db8::20', '10.0.0.2')]
        for dest_ip, src_ip in cases:
            with self.usage_error():
                netflow_player.parse_args(
                    ['--file', CAPTURE, '--dest_ip', dest_ip,
                     '--spoofing', '--device', 'lo0', '--src_ip', src_ip])


if __name__ == '__main__':
    unittest.main()
