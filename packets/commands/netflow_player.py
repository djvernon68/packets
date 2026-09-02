#!/usr/bin/env python

import os
import sys
import socket
import argparse

from packets.core.pcap import netflow_replay_raw_sock, \
    netflow_replay_system_sock


def bounded_int(low, high):
    """Build an argparse type that accepts an int in [low, high].

    The replay functions take C integers of a fixed width. Without this the
    parser hands an out of range value to Cython, which reports it as an
    OverflowError traceback rather than as a usage error.

    Args:
        :low (int): Smallest accepted value.
        :high (int): Largest accepted value.

    Returns:
        :function: Callable suitable for argparse's type= argument.
    """
    def check(value):
        try:
            ival = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("{0} is not an integer"
                                             "".format(value))
        if ival < low or ival > high:
            raise argparse.ArgumentTypeError("{0} is out of range {1}-{2}"
                                             "".format(ival, low, high))
        return ival
    return check


def readable_file(value):
    """argparse type that accepts the path of a readable file."""
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError("{0} is not a file".format(value))
    if not os.access(value, os.R_OK):
        raise argparse.ArgumentTypeError("{0} is not readable".format(value))
    return value


def address_family(value):
    """Return the socket family for an IPv4 or IPv6 address."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return family
        except (socket.error, OSError, ValueError):
            pass
    raise argparse.ArgumentTypeError("{0} is not an IPv4 or IPv6 address"
                                     "".format(value))


def ipv4_address(value):
    """argparse type that accepts an IPv4 or IPv6 address."""
    address_family(value)
    return value


def optional_ipv4_address(value):
    """As ipv4_address but also accepts '', which means 'not set'."""
    if value == '':
        return value
    return ipv4_address(value)


def mac_address(value):
    """argparse type that accepts a colon separated MAC address."""
    parts = value.split(':')
    if len(parts) != 6:
        raise argparse.ArgumentTypeError("{0} is not a MAC address"
                                         "".format(value))
    for part in parts:
        if len(part) != 2:
            raise argparse.ArgumentTypeError("{0} is not a MAC address"
                                             "".format(value))
        try:
            int(part, 16)
        except ValueError:
            raise argparse.ArgumentTypeError("{0} is not a MAC address"
                                             "".format(value))
    return value


def optional_mac_address(value):
    """As mac_address but also accepts '', which means 'not set'."""
    if value == '':
        return value
    return mac_address(value)


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Netflow Replayer.')
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument('-f', '--file',
                          help=("Full path to the pcap file you want to "
                                "replay."),
                          type=readable_file,
                          required=True)
    required.add_argument('--dest_ip',
                          help="IP address to the send packets to.",
                          type=ipv4_address,
                          required=True)
    optional.add_argument('--spoofing',
                          dest='spoofing',
                          action='store_true',
                          help=("If specified then source spoofing is "
                                "enabled. The allows you to specify the src "
                                "IP address, source port, and dest MAC and "
                                "the local network device to use. On most "
                                "systems this feature requires root access. "
                                "The default is --no-spoofing"))
    optional.add_argument('--no-spoofing',
                          dest='spoofing',
                          action='store_false')
    optional.set_defaults(spoofing=False)
    optional.add_argument('--pcap_dst_port',
                          help=("Destination port for the packets in the pcap "
                                "file that should be replayed. Default is "
                                "2055."),
                          type=bounded_int(0, 65535),
                          default=2055)
    optional.add_argument('--dest_port',
                        help=("Destination port for the destination IP. "
                              "Default is 2055."),
                        type=bounded_int(0, 65535),
                        default=2055)
    optional.add_argument('--device',
                          help=("The name of the network interface to use to "
                                "send packets. This setting is ignored if "
                                "--spoofing is not specified."),
                          type=str,
                          default='')
    optional.add_argument('--dest_mac',
                          help=("MAC address to set as the dst_mac of all "
                                "packets sent. This setting is ignored if "
                                "--spoofing is not specified. Default is"
                                "broadcast ('ff:ff:ff:ff:ff:ff')"),
                          type=mac_address,
                          default='ff:ff:ff:ff:ff:ff')
    optional.add_argument('--src_ip',
                          help=("The src IP that should be set for all "
                                "outbound packets. This setting is ignored if "
                                "--spoofing is not specified."),
                          type=optional_ipv4_address,
                          default='')
    optional.add_argument('--src_mac',
                          help=("The src MAC that should be set for all "
                                "outbound packets. This setting is ignored if "
                                "--spoofing is not specified."),
                          type=optional_mac_address,
                          default='')
    optional.add_argument('--blast',
                        help=("Boolian value. If not set to 0 will result in "
                              "the packets being sent as fast as possible."),
                        type=bounded_int(0, 1),
                        default=0)
    optional.add_argument('--new_version',
                        help=("unsigned 16 bit value. Re-write the netflow version "
                              "for all netflow packets sent to this value unless this is "
                              "is set to 0 (the default)"),
                        type=bounded_int(0, 65535),
                        default=0)
    optional.add_argument('--new_type',
                        help=("unsigned 8 bit value. Re-write the netflow engine type "
                              "for all netflow packets sent to this value unless this is "
                              "is set to 0 (the default)"),
                        type=bounded_int(0, 255),
                        default=0)
    args = parser.parse_args(argv)
    if args.spoofing and args.device == '':
        parser.error("A valid network device must be specified with --device "
                     "in order to use spoofing.")
    if (args.spoofing and args.src_ip and
            address_family(args.src_ip) != address_family(args.dest_ip)):
        parser.error("--src_ip and --dest_ip must use the same address family "
                     "when spoofing.")
    return args


def main():
    args = parse_args(sys.argv[1:])
    if args.spoofing:
        rval = netflow_replay_raw_sock(args.device,
                                       args.file,
                                       args.pcap_dst_port,
                                       args.dest_ip,
                                       args.dest_mac,
                                       args.dest_port,
                                       new_version=args.new_version,
                                       new_type=args.new_type,
                                       src_ip=args.src_ip,
                                       src_mac=args.src_mac,
                                       blast_mode=args.blast)
    else:
        rval = netflow_replay_system_sock(args.file,
                                          args.pcap_dst_port,
                                          args.dest_ip,
                                          args.dest_port,
                                          new_version=args.new_version,
                                          new_type=args.new_type,
                                          blast_mode=args.blast)
    sys.exit(rval)

if __name__ == "__main__":
    main()
