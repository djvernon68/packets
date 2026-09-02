# Copyright (c) 2019-2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License"). This software is distributed "AS IS"
# as set forth in the License.

"""
NetFlow v9 Packet Generator
===========================
Utilities to generate synthetic, realistic, nearly-random NetFlow v9 records
and packets conforming to any user-supplied template or standard Cisco templates.
"""

import random
import socket
import struct
import time
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from packets.core.inetpkt import Ethernet, IP, UDP, IP_CONST
from packets.core.pcap import PCAPWriter
from packets.protos.netflow import (
    Netflow,
    NetflowDataRecord,
    NetflowFlowSet,
    NetflowTemplate,
    NetflowTemplateField,
    NetflowV9Header,
)


# Standard Cisco NetFlow v9 template fields:
# - IN_BYTES (Field Type 1, length 4): Total incoming octets
# - IN_PKTS (Field Type 2, length 4): Total incoming packets
# - PROTOCOL (Field Type 4, length 1): IP protocol (e.g., 6 TCP, 17 UDP)
# - SRC_ADDR (Field Type 8, length 4): Source IPv4 address
# - SRC_PORT (Field Type 7, length 2): Source port
# - DST_ADDR (Field Type 12, length 4): Destination IPv4 address
# - DST_PORT (Field Type 11, length 2): Destination port
# - INPUT_SNMP (Field Type 10, length 2): Input interface index
# - OUTPUT_SNMP (Field Type 14, length 2): Output interface index
# - TCP_FLAGS (Field Type 5, length 1): Cumulative TCP flags / ToS
CISCO_NETFLOW_V9_FIELD_SPECS: List[Tuple[int, int]] = [
    (1, 4),   # IN_BYTES (octetDeltaCount)
    (2, 4),   # IN_PKTS (packetDeltaCount)
    (4, 1),   # PROTOCOL (protocolIdentifier)
    (8, 4),   # SRC_ADDR (sourceIPv4Address)
    (7, 2),   # SRC_PORT (sourceTransportPort)
    (12, 4),  # DST_ADDR (destinationIPv4Address)
    (11, 2),  # DST_PORT (destinationTransportPort)
    (10, 2),  # INPUT_SNMP (ingressInterface)
    (14, 2),  # OUTPUT_SNMP (egressInterface)
    (5, 1),   # TCP_FLAGS / ipClassOfService
]


def create_cisco_netflow_v9_template(template_id: int = 256) -> NetflowTemplate:
    """Create a standard Cisco NetFlow v9 template.

    :param template_id: NetFlow v9 template ID (>= 256).
    :return: Configured NetflowTemplate instance.
    """
    fields = [NetflowTemplateField(elem_id, length)
              for elem_id, length in CISCO_NETFLOW_V9_FIELD_SPECS]
    return NetflowTemplate(template_id=template_id, fields=fields, version=9)


def normalize_template(
    template: Optional[Union[NetflowTemplate, Sequence[Union[NetflowTemplateField, Tuple[int, int]]]]] = None,
    template_id: int = 256,
) -> NetflowTemplate:
    """Normalize user input into a valid NetflowTemplate instance.

    :param template: Existing NetflowTemplate, list of NetflowTemplateField,
                     or list of (element_id, field_length) tuples.
    :param template_id: Template ID (default 256) if creating a new template.
    :return: NetflowTemplate instance conforming to NetFlow v9.
    """
    if template is None:
        return create_cisco_netflow_v9_template(template_id=template_id)

    if isinstance(template, NetflowTemplate):
        return template

    # If sequence of fields or tuples:
    fields = []
    for item in template:
        if isinstance(item, NetflowTemplateField):
            fields.append(item)
        elif isinstance(item, (tuple, list)) and len(item) >= 2:
            elem_id, length = item[0], item[1]
            pen = item[2] if len(item) > 2 else None
            fields.append(NetflowTemplateField(elem_id, length, enterprise_number=pen))
        else:
            raise TypeError(f"Invalid template field specification: {item!r}")

    return NetflowTemplate(template_id=template_id, fields=fields, version=9)


class NetflowV9Generator:
    """Generator for large sets of nearly-random NetFlow v9 records and packets."""

    # Common realistic protocol IDs
    COMMON_PROTOCOLS = [6, 6, 6, 17, 17, 1, 47, 50, 89]  # Weighted TCP/UDP
    # Common realistic port numbers
    COMMON_PORTS = [80, 443, 22, 53, 8080, 8443, 2055, 3306, 5432, 21, 25]
    # Common realistic TCP flags combinations
    COMMON_TCP_FLAGS = [0x02, 0x12, 0x10, 0x18, 0x11, 0x14, 0x04]

    def __init__(
        self,
        template: Optional[Union[NetflowTemplate, Sequence[Union[NetflowTemplateField, Tuple[int, int]]]]] = None,
        template_id: int = 256,
        source_id: int = 1,
        seed: Optional[int] = None,
        base_uptime: int = 100000,
        base_unix_secs: Optional[int] = None,
        base_sequence: int = 1,
        ip_network_pool: Optional[Sequence[str]] = None,
    ):
        """Initialize the NetFlow v9 generator.

        :param template: NetflowTemplate, list of NetflowTemplateField, or list
                         of (element_id, length) tuples. Defaults to standard Cisco v9.
        :param template_id: Template ID (default 256).
        :param source_id: Exporter source ID / Observation Domain ID (default 1).
        :param seed: Optional random seed for reproducible packet generation.
        :param base_uptime: Starting sys_uptime in milliseconds.
        :param base_unix_secs: Starting unix timestamp in seconds. Defaults to current time.
        :param base_sequence: Starting sequence number (default 1).
        :param ip_network_pool: Optional list of IP prefix strings (e.g. ['10.0', '192.168.1']).
        """
        self.template = normalize_template(template, template_id=template_id)
        self.template_id = self.template.template_id
        self.source_id = source_id
        self.rng = random.Random(seed)
        self.uptime = base_uptime
        self.unix_secs = base_unix_secs if base_unix_secs is not None else int(time.time())
        self.sequence = base_sequence
        self.ip_network_pool = ip_network_pool

    def _random_ipv4(self) -> str:
        if self.ip_network_pool:
            prefix = self.rng.choice(self.ip_network_pool)
            parts = prefix.split('.')
            while len(parts) < 4:
                parts.append(str(self.rng.randint(1, 254)))
            return '.'.join(parts[:4])
        # Generate private or public IP
        first_octet = self.rng.choice([10, 172, 192, 198, 203, self.rng.randint(11, 160)])
        if first_octet == 10:
            return f"10.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
        elif first_octet == 172:
            return f"172.{self.rng.randint(16, 31)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
        elif first_octet == 192:
            return f"192.168.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
        return f"{first_octet}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"

    def _random_ipv6(self) -> str:
        return (f"2001:db8:{self.rng.randint(0, 0xffff):x}:{self.rng.randint(0, 0xffff):x}:"
                f"{self.rng.randint(0, 0xffff):x}:{self.rng.randint(0, 0xffff):x}:"
                f"{self.rng.randint(0, 0xffff):x}:{self.rng.randint(1, 0xffff):x}")

    def _random_mac(self) -> str:
        return ":".join(f"{self.rng.randint(0, 255):02x}" for _ in range(6))

    def _random_port(self) -> int:
        if self.rng.random() < 0.4:
            return self.rng.choice(self.COMMON_PORTS)
        return self.rng.randint(1024, 65535)

    def _random_value_for_field(self, field: NetflowTemplateField, pkts: Optional[int] = None) -> Any:
        elem_id = field.element_id
        dtype = field.data_type
        flen = field.field_length

        if dtype == 'ipv4':
            return self._random_ipv4()
        if dtype == 'ipv6':
            return self._random_ipv6()
        if dtype == 'mac':
            return self._random_mac()
        if dtype == 'string':
            length = min(flen if not field.variable_length else 8, 16)
            chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
            return "".join(self.rng.choice(chars) for _ in range(max(1, length)))

        if dtype == 'unsigned':
            # Element-specific realism
            if elem_id in (7, 11, 180, 181, 182, 183):  # Ports
                return self._random_port()
            if elem_id in (4, 60):  # Protocol
                return self.rng.choice(self.COMMON_PROTOCOLS)
            if elem_id in (5, 6):  # TCP flags / ToS / Class of Service
                return self.rng.choice(self.COMMON_TCP_FLAGS)
            if elem_id in (10, 14):  # Interface SNMP indices
                return self.rng.randint(1, 65535 if flen >= 2 else 255)
            if elem_id in (2, 86):  # Packet counts
                return self.rng.randint(1, 10000)
            if elem_id in (1, 85):  # Byte counts
                pkt_count = pkts if pkts is not None else self.rng.randint(1, 1000)
                return pkt_count * self.rng.randint(40, 1500)
            if elem_id in (21, 22, 150, 151, 152, 153):  # Flow timestamps
                return self.uptime + self.rng.randint(0, 5000)

            # Generic unsigned bounded by field length
            max_val = (1 << (8 * min(flen, 8))) - 1
            return self.rng.randint(0, max_val)

        # Fallback raw bytes
        if hasattr(self.rng, 'randbytes'):
            return self.rng.randbytes(flen)
        return bytes(self.rng.randint(0, 255) for _ in range(flen))

    def generate_record_fields(self) -> Dict[Any, Any]:
        """Generate a dictionary of random field values matching the template."""
        values: Dict[Any, Any] = {}
        # Pre-determine packet count if present for realistic byte correlation
        pkts = self.rng.randint(1, 5000)

        for field in self.template.fields:
            key = field.name if field.name is not None else (
                (field.enterprise_number, field.element_id)
                if field.enterprise_number is not None else field.element_id
            )
            val = self._random_value_for_field(field, pkts=pkts)
            values[key] = val
        return values

    def generate_record(self) -> NetflowDataRecord:
        """Generate a single NetflowDataRecord conforming to the template."""
        fields = self.generate_record_fields()
        return self.template.record_class(
            template_id=self.template_id,
            fields=fields,
            template=self.template,
            codec_plan=self.template.codec_plan,
        )

    def generate_records(self, count: int) -> List[NetflowDataRecord]:
        """Generate a list of N NetflowDataRecord instances."""
        return [self.generate_record() for _ in range(count)]

    def generate_packet(
        self,
        records: Optional[Union[int, Sequence[NetflowDataRecord]]] = None,
        include_template: bool = False,
        uptime_increment: int = 100,
        time_increment: int = 1,
    ) -> Netflow:
        """Generate a single Netflow v9 packet containing template/data flowsets.

        :param records: Number of records to generate (int) or list of NetflowDataRecord.
                        Defaults to 20 records.
        :param include_template: If True, prepend a template flowset (Set ID 0).
        :param uptime_increment: Milliseconds to advance sys_uptime.
        :param time_increment: Seconds to advance unix_secs.
        :return: Constructed Netflow packet.
        """
        if records is None:
            records = 20

        if isinstance(records, int):
            record_list = self.generate_records(records)
        else:
            record_list = list(records)

        flowsets = []
        if include_template:
            template_set = NetflowFlowSet(
                set_id=0,
                templates=[self.template],
                version=9
            )
            flowsets.append(template_set)

        data_set = NetflowFlowSet(
            set_id=self.template_id,
            records=record_list,
            version=9
        )
        flowsets.append(data_set)

        packet = Netflow(
            header=NetflowV9Header(
                sys_uptime=self.uptime,
                unix_secs=self.unix_secs,
                sequence=self.sequence,
                source_id=self.source_id,
            ),
            flowsets=flowsets,
        )

        # Advance state
        self.sequence += 1
        self.uptime += uptime_increment
        self.unix_secs += time_increment

        return packet

    def generate_packets(
        self,
        total_records: int = 1000,
        records_per_packet: int = 20,
        template_interval: int = 10,
        uptime_increment_per_packet: int = 100,
    ) -> Iterator[Netflow]:
        """Yield a stream of NetFlow v9 packets covering total_records.

        :param total_records: Total flow records to produce across all packets.
        :param records_per_packet: Number of flow records per NetFlow datagram.
        :param template_interval: Transmit template flowset every N packets (1 = every packet).
        :param uptime_increment_per_packet: Sys_uptime increase per packet (ms).
        :return: Generator yielding Netflow packets.
        """
        records_generated = 0
        packet_index = 0

        while records_generated < total_records:
            batch_size = min(records_per_packet, total_records - records_generated)
            include_tmpl = (packet_index % max(1, template_interval)) == 0
            packet = self.generate_packet(
                records=batch_size,
                include_template=include_tmpl,
                uptime_increment=uptime_increment_per_packet,
                time_increment=1 if packet_index % 5 == 0 else 0,
            )
            yield packet
            records_generated += batch_size
            packet_index += 1

    @staticmethod
    def build_frame(
        netflow_packet: Netflow,
        src_ip: str = "192.0.2.1",
        dst_ip: str = "198.51.100.20",
        sport: int = 50000,
        dport: int = 2055,
        src_mac: str = "00:11:22:33:44:55",
        dst_mac: str = "66:77:88:99:aa:bb",
    ) -> bytes:
        """Wrap a Netflow packet in Ethernet / IP / UDP wire frame bytes.

        :param netflow_packet: Netflow instance.
        :param src_ip: Exporter source IPv4 address.
        :param dst_ip: Collector destination IPv4 address.
        :param sport: Source UDP port.
        :param dport: Destination UDP port (default 2055).
        :param src_mac: Source MAC address.
        :param dst_mac: Destination MAC address.
        :return: Serialized Ethernet frame bytes.
        """
        payload = netflow_packet.pkt2net({"update": 1})
        udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        ip = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0) +
              socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + udp)
        mac_bytes = (bytes(int(x, 16) for x in dst_mac.split(":")) +
                     bytes(int(x, 16) for x in src_mac.split(":")) +
                     b"\x08\x00")
        return mac_bytes + ip

    def generate_pcap(
        self,
        filename: str,
        total_records: int = 1000,
        records_per_packet: int = 20,
        template_interval: int = 10,
        src_ip: str = "192.0.2.1",
        dst_ip: str = "198.51.100.20",
        sport: int = 50000,
        dport: int = 2055,
        snaplen: int = 65535,
    ) -> int:
        """Generate a complete PCAP file containing NetFlow v9 packets.

        :param filename: Output .pcap file path.
        :param total_records: Total flow records to generate.
        :param records_per_packet: Records per NetFlow packet.
        :param template_interval: Template packet interval.
        :param src_ip: Source IPv4 address.
        :param dst_ip: Collector IPv4 address.
        :param sport: Source UDP port.
        :param dport: Collector UDP port.
        :param snaplen: PCAP snapshot length.
        :return: Total number of packets written.
        """
        writer = PCAPWriter(filename=filename, snaplen=snaplen)
        packet_count = 0
        current_time = self.unix_secs

        try:
            for pkt in self.generate_packets(
                total_records=total_records,
                records_per_packet=records_per_packet,
                template_interval=template_interval,
            ):
                frame_bytes = self.build_frame(
                    pkt,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    sport=sport,
                    dport=dport,
                )
                tv_sec = current_time + (packet_count // 10)
                tv_usec = (packet_count % 10) * 100000
                writer.dump_pkt(frame_bytes, tv_sec, tv_usec)
                packet_count += 1
        finally:
            writer.close()

        return packet_count


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for NetFlow v9 generator."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate synthetic NetFlow v9 packets conforming to standard Cisco or custom templates."
    )
    parser.add_argument(
        "-c", "--count", type=int, default=1000,
        help="Total number of NetFlow records to generate (default: 1000)"
    )
    parser.add_argument(
        "-r", "--records-per-packet", type=int, default=20,
        help="Number of records per NetFlow packet (default: 20)"
    )
    parser.add_argument(
        "-o", "--out", type=str, default=None,
        help="Output PCAP file path"
    )
    parser.add_argument(
        "--template-id", type=int, default=256,
        help="NetFlow v9 template ID (default: 256)"
    )
    parser.add_argument(
        "--template-interval", type=int, default=10,
        help="Interval of packets between template flowsets (default: 10)"
    )
    parser.add_argument(
        "--source-id", type=int, default=1,
        help="Source ID / Observation Domain ID (default: 1)"
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for deterministic output"
    )
    parser.add_argument(
        "--src-ip", type=str, default="192.0.2.1",
        help="Exporter source IPv4 address (default: 192.0.2.1)"
    )
    parser.add_argument(
        "--dst-ip", type=str, default="198.51.100.20",
        help="Collector destination IPv4 address (default: 198.51.100.20)"
    )
    parser.add_argument(
        "--sport", type=int, default=50000,
        help="Exporter source UDP port (default: 50000)"
    )
    parser.add_argument(
        "--dport", type=int, default=2055,
        help="Collector destination UDP port (default: 2055)"
    )
    parser.add_argument(
        "--send", type=str, default=None,
        help="Send UDP datagrams to IP:PORT (e.g. 127.0.0.1:2055)"
    )

    args = parser.parse_args(argv)

    gen = NetflowV9Generator(
        template_id=args.template_id,
        source_id=args.source_id,
        seed=args.seed,
    )

    if args.send:
        host, port_str = args.send.split(":")
        target_port = int(port_str)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent = 0
        for pkt in gen.generate_packets(
            total_records=args.count,
            records_per_packet=args.records_per_packet,
            template_interval=args.template_interval,
        ):
            wire = pkt.pkt2net({"update": 1})
            sock.sendto(wire, (host, target_port))
            sent += 1
        sock.close()
        print(f"Sent {sent} NetFlow v9 packets ({args.count} records) to {args.send}")
        return 0

    if args.out:
        total_packets = gen.generate_pcap(
            filename=args.out,
            total_records=args.count,
            records_per_packet=args.records_per_packet,
            template_interval=args.template_interval,
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
            sport=args.sport,
            dport=args.dport,
        )
        print(f"Generated {total_packets} NetFlow v9 packets ({args.count} records) to {args.out}")
        return 0

    # If neither --out nor --send, count packets generated in memory
    total_pkts = sum(1 for _ in gen.generate_packets(
        total_records=args.count,
        records_per_packet=args.records_per_packet,
        template_interval=args.template_interval,
    ))
    print(f"Successfully generated {total_pkts} NetFlow v9 packets ({args.count} records)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
