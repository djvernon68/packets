#!/usr/bin/env python

from __future__ import print_function

import argparse
import statistics
import struct
import timeit

from packets.core.inetpkt import Ethernet
from packets.protos import netflow as netflow_module
from packets.protos.netflow import Netflow, NetflowDecodeContext, \
    NetflowSimple, NetflowTemplate, NetflowTemplateField


EXPORTER = '192.0.2.10'
SOURCE_ID = 42


def netflow_frame(payload):
    udp = struct.pack('!HHHH', 50000, 2055, 8 + len(payload), 0) + payload
    ip = (struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(udp), 0, 0,
                      64, 17, 0) + b'\xc0\x00\x02\x0a' +
          b'\xc6\x33\x64\x14' + udp)
    return (b'\x00\x11\x22\x33\x44\x55' +
            b'\x66\x77\x88\x99\xaa\xbb\x08\x00' + ip)


def fixtures():
    fixed = {
        'fixed_v1': struct.pack('!HHIII', 1, 1, 1, 2, 3) + b'\x00' * 48,
        'fixed_v5': struct.pack('!HHIIIIBBH', 5, 1, 1, 2, 3, 4,
                                0, 0, 0) + b'\x00' * 48,
        'fixed_v7': struct.pack('!HHIIIII', 7, 1, 1, 2, 3, 4, 0) +
        b'\x00' * 52,
    }
    fields = struct.pack('!HHHHHH', 256, 2, 8, 4, 2, 4)
    template_set = struct.pack('!HH', 0, 4 + len(fields)) + fields
    template_wire = (struct.pack('!HHIIII', 9, 1, 100, 200, 10,
                                 SOURCE_ID) + template_set)
    data_body = b'\xc0\x00\x02\x01' + struct.pack('!I', 7)
    data_set = struct.pack('!HH', 256, 4 + len(data_body)) + data_body
    data_wire = (struct.pack('!HHIIII', 9, 1, 101, 201, 11,
                             SOURCE_ID) + data_set)
    return fixed, template_wire, data_wire, data_body


def benchmark_cases():
    fixed, template_wire, data_wire, data_body = fixtures()
    fixed_packets = {name: Netflow(wire) for name, wire in fixed.items()}
    context = NetflowDecodeContext()
    template_packet = Netflow.dispatch(template_wire, context=context,
                                       exporter=EXPORTER)
    template = template_packet.flowsets[0].templates[0]
    data_packet = Netflow.dispatch(data_wire, context=context,
                                   exporter=EXPORTER)
    decoded = template.codec_plan.decode(data_body, 0, template)[0]
    interpreted = netflow_module._decode_interpreted(template, data_body)[0]
    if decoded.fields != interpreted.fields:
        raise AssertionError('generated and interpreted fields differ')
    forced_context = NetflowDecodeContext(force_simple=True)
    unknown_context = NetflowDecodeContext()
    frame = netflow_frame(data_wire)
    template_counter = [256]

    def cold_template():
        template_counter[0] += 1
        candidate = NetflowTemplate(
            template_counter[0],
            [NetflowTemplateField(8, 4), NetflowTemplateField(2, 4)],
            version=9)
        NetflowDecodeContext().register_template(
            EXPORTER, SOURCE_ID, candidate, version=9)
        return candidate.record_class

    return [
        ('fixed_v1', lambda: Netflow(fixed['fixed_v1']), 1),
        ('fixed_v5', lambda: Netflow(fixed['fixed_v5']), 1),
        ('fixed_v7', lambda: Netflow(fixed['fixed_v7']), 1),
        ('fixed_v5_write',
         lambda: fixed_packets['fixed_v5'].pkt2net({}), 1),
        ('cold_template_generation', cold_template, 10),
        ('warm_generated_decode',
         lambda: template.codec_plan.decode(data_body, 0, template), 1),
        ('warm_generated_write', lambda: decoded.pkt2net({}), 1),
        ('generated_name_lookup',
         lambda: decoded.fields['sourceIPv4Address'], 1),
        ('generated_identity_lookup',
         lambda: decoded.fields[(0, 8)], 1),
        ('dict_name_lookup',
         lambda: interpreted.fields['sourceIPv4Address'], 1),
        ('dict_identity_lookup',
         lambda: interpreted.fields[(0, 8)], 1),
        ('interpreted_decode',
         lambda: netflow_module._decode_interpreted(template, data_body), 1),
        ('known_template_datagram',
         lambda: Netflow.dispatch(data_wire, context=context,
                                  exporter=EXPORTER), 1),
        ('known_template_write', lambda: data_packet.pkt2net({}), 1),
        ('unknown_template_fallback',
         lambda: Netflow.dispatch(data_wire, context=unknown_context,
                                  exporter=EXPORTER), 1),
        ('nested_ethernet_dispatch',
         lambda: Ethernet(frame, l7_ports={2055: Netflow},
                          decode_context=context), 1),
        ('forced_simple_dispatch',
         lambda: Netflow.dispatch(data_wire, context=forced_context,
                                  exporter=EXPORTER), 1),
        ('direct_netflow_simple', lambda: NetflowSimple(data_wire), 1),
    ]


def run(number, repeat):
    print('case                              median us/op    best us/op')
    print('--------------------------------  ------------  ------------')
    for name, operation, divisor in benchmark_cases():
        case_number = max(1, number // divisor)
        timeit.Timer(operation).timeit(max(1, case_number // 20))
        samples = timeit.Timer(operation).repeat(repeat=repeat,
                                                 number=case_number)
        per_operation = [sample * 1000000.0 / case_number
                         for sample in samples]
        print('{:<32}  {:>12.3f}  {:>12.3f}'.format(
            name, statistics.median(per_operation), min(per_operation)))


def main():
    parser = argparse.ArgumentParser(
        description='Repeated Packets NetFlow microbenchmarks.')
    parser.add_argument('--number', type=int, default=1000,
                        help='operations per sample (default: 1000)')
    parser.add_argument('--repeat', type=int, default=5,
                        help='sample count (default: 5)')
    args = parser.parse_args()
    if args.number < 1 or args.repeat < 1:
        parser.error('--number and --repeat must be positive')
    run(args.number, args.repeat)


if __name__ == '__main__':
    main()