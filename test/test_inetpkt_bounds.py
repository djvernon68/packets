# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""C-1: every decoder survives truncated and corrupted input.

``rd_u16``/``rd_u32`` in ``core/inetpkt.pxd`` read without a bounds check,
so each of their callers has to have proved the bytes are there. Until the
directives became ``with`` blocks they were silently checked, and a caller
that relied on that would now read past its buffer -- usually into harmless
heap, which is exactly why no ordinary test notices.

So the decoders are driven here with every truncation of a set of valid
packets and with seeded random corruption of their headers, and with
random buffers aimed at every packet class directly. In an ordinary build
that proves only what it can see: a decoder raises rather than crashing.
In a *checked* build -- ``CFLAGS=-DPACKETS_RD_CHECK=1`` -- an out-of-bounds
read stops the process with its offset instead, so the same run becomes a
proof that no input here reaches one. Each group runs in a child process so
that an abort is a failed test naming the decoder and the input, not a dead
test run.

The seeds are the golden corpus of ``bench/correctness.py``, captured as it
is built, so a protocol added there is fuzzed here without another list.
"""

import os
import random
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

#: Groups, each run in its own child.
GROUPS = ('frames', 'layers', 'bgp', 'netflow', 'dhcp', 'random')

#: Truncations below this many bytes are all tried; past it only the whole
#: packet is, since every header in the corpus ends well before it.
CUT_LIMIT = 160

#: Corrupted variants per seed.
MUTATIONS = 64


# --- the seeds --------------------------------------------------------------

def _wire(pkt):
    try:
        return bytes(pkt.pkt2net({'update': 1, 'csum': 1}))
    except Exception:
        return bytes(pkt.pkt2net({}))


def corpus_seeds():
    """Capture the raw packets ``bench/correctness.py`` builds.

    :return: ``(frames, layers)``: Ethernet frames, and ``(class, bytes)``
        pairs for the layers it builds on their own (BGP, RIP, DNS, ...).
    """
    sys.path.insert(0, os.path.join(ROOT, 'bench'))
    try:
        import correctness
    finally:
        sys.path.pop(0)
    frames = []
    layers = []
    saved = {}

    def patch(name, fn):
        if hasattr(correctness, name):
            saved[name] = getattr(correctness, name)
            setattr(correctness, name, fn)

    def l3l4(name, eth):
        frames.append(_wire(eth))
        return name, {}

    def gre(name, eth, out):
        frames.append(_wire(eth))

    def ospf(name, eth, pq_type, out):
        frames.append(_wire(eth))
        return name, {}

    def bgp(name, raw, out):
        layers.append((correctness.BGP, bytes(raw)))

    def rip(name, raw, cls, pq_type, port, out, v6=False):
        layers.append((cls, bytes(raw)))

    def dns(name, pkt, kwargs, out, reparse=True):
        try:
            layers.append((type(pkt), bytes(pkt.pkt2net(kwargs))))
        except Exception:
            layers.append((type(pkt), _wire(pkt)))

    patch('record_l3l4', l3l4)
    patch('record_gre', gre)
    patch('record_ospf', ospf)
    patch('record_bgp', bgp)
    patch('record_rip', rip)
    patch('record_dns', dns)
    try:
        correctness.corpus()
    finally:
        for name, fn in saved.items():
            setattr(correctness, name, fn)
    frames.extend(extra_frames())
    return frames, layers


def extra_frames():
    """The two corpus packets built without a ``record_*`` call."""
    # The ICMP echo vector the golden corpus and the suite share.
    icmp_echo = bytes([0, 11, 134, 99, 252, 32, 8, 0, 39, 64, 45, 200, 8, 0,
                       69, 0, 0, 28, 0, 0, 0, 0, 64, 1, 202, 227, 10, 38, 25,
                       153, 10, 38, 130, 25, 8, 0, 61, 86, 15, 255, 170,
                       170])
    arp = bytes(12) + b'\x08\x06' + b'\x00\x01\x08\x00\x06\x04\x00\x01'
    arp += b'\x06\x05\x04\x03\x02\x02' + b'\x01\x02\x03\x04'
    arp += bytes(6) + b'\x04\x03\x02\x01'
    return [icmp_echo, arp]


def dhcp_seeds():
    """A DHCPv4 discover and a DHCPv6 solicit, built by hand."""
    v4 = bytearray(236)
    v4[0:4] = b'\x01\x01\x06\x00'
    v4[4:8] = b'\x12\x34\x56\x78'
    v4[28:34] = b'\x02\x00\x00\x00\x00\x01'
    v4 += b'\x63\x82\x53\x63'
    v4 += b'\x35\x01\x01'                       # message type: discover
    v4 += b'\x3d\x07\x01\x02\x00\x00\x00\x00\x01'  # client id
    v4 += b'\x37\x04\x01\x03\x06\x0f'           # parameter request list
    v4 += b'\x0c\x04host'                       # host name
    v4 += b'\xff'
    v6 = bytearray(b'\x01\xab\xcd\xef')         # solicit, transaction id
    v6 += b'\x00\x01\x00\x0a\x00\x03\x00\x01\x02\x00\x00\x00\x00\x01'
    v6 += b'\x00\x06\x00\x04\x00\x17\x00\x18'   # option request
    v6 += b'\x00\x08\x00\x02\x00\x00'           # elapsed time
    v6 += b'\x00\x03\x00\x0c\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x15\x18'
    return bytes(v4), bytes(v6)


def variants(seed, rng, mutations=MUTATIONS):
    """Every short truncation of a seed, then seeded corruptions of it."""
    n = len(seed)
    for cut in range(min(n, CUT_LIMIT) + 1):
        yield seed[:cut]
    if n > CUT_LIMIT:
        yield seed
    for _ in range(mutations):
        buf = bytearray(seed)
        if buf:
            for _ in range(rng.randint(1, 4)):
                buf[rng.randrange(min(len(buf), 96))] = rng.randrange(256)
        if rng.random() < 0.5:
            buf = buf[:rng.randint(0, len(buf))]
        yield bytes(buf)


def touch(obj, depth=0):
    """Read every public attribute of a decoded object and its payloads.

    Some fields decode on first access, so constructing the packet is not
    the whole of decoding it.
    """
    if obj is None or depth > 12:
        return
    for name in dir(obj):
        if name.startswith('_'):
            continue
        try:
            value = getattr(obj, name)
        except Exception:
            continue
        if isinstance(value, (list, tuple)) and depth < 12:
            for item in value[:8]:
                if hasattr(item, '__dict__') or hasattr(item, 'pkt_name'):
                    touch(item, depth + 1)
    payload = getattr(obj, 'payload', None)
    if payload is not None and not isinstance(payload, (bytes, bytearray,
                                                        str)):
        touch(payload, depth + 1)


# --- the child --------------------------------------------------------------

class Trace(object):
    """The case being decoded, kept in a file the parent reads on a crash."""

    def __init__(self, path):
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

    def note(self, label, data):
        record = ('%s\n%s\n' % (label, data.hex())).encode('ascii')
        os.pwrite(self.fd, record, 0)
        os.ftruncate(self.fd, len(record))


def _decode_all(trace, label, decode, seeds, rng, touch_every=3):
    count = 0
    for seed in seeds:
        for data in variants(seed, rng):
            trace.note(label, data)
            try:
                obj = decode(data)
                if count % touch_every == 0:
                    touch(obj)
            except Exception:
                pass
            count += 1
    return count


def _packet_classes():
    from packets.core import inetpkt
    from packets.protos import dhcp, dns, netflow
    found = []
    for module in (inetpkt, dns, dhcp, netflow):
        for name in sorted(dir(module)):
            cls = getattr(module, name)
            if (isinstance(cls, type) and issubclass(cls, inetpkt.PKT) and
                    cls is not inetpkt.PKT):
                found.append(cls)
    return found


def run_group(group, trace):
    """Decode one group's inputs; return how many were tried."""
    from packets.core import inetpkt
    rng = random.Random('C-1/' + group)
    if group == 'frames':
        frames, _layers = corpus_seeds()
        return _decode_all(trace, 'Ethernet', inetpkt.Ethernet, frames, rng)
    if group == 'layers':
        _frames, layers = corpus_seeds()
        count = 0
        for cls, raw in layers:
            count += _decode_all(trace, cls.__name__, cls, [raw], rng)
        return count
    if group == 'bgp':
        return _run_bgp(trace, rng)
    if group == 'netflow':
        return _run_netflow(trace, rng)
    if group == 'dhcp':
        from packets.protos.dhcp import DHCP, DHCP6
        v4, v6 = dhcp_seeds()
        return (_decode_all(trace, 'DHCP', DHCP, [v4], rng) +
                _decode_all(trace, 'DHCP6', DHCP6, [v6], rng))
    if group == 'random':
        count = 0
        for cls in _packet_classes():
            for _ in range(400):
                data = bytes(rng.randrange(256)
                             for _ in range(rng.randint(0, 96)))
                trace.note(cls.__name__, data)
                try:
                    touch(cls(data))
                except Exception:
                    pass
                count += 1
        return count
    raise ValueError('unknown group %r' % (group,))


def _run_bgp(trace, rng):
    """The scanning core and the routing engine's codec, on BGP seeds."""
    from packets.core import bgpcore
    from packets.routing.rtengine.plugins.bgp import wire
    _frames, layers = corpus_seeds()
    seeds = [raw for cls, raw in layers if cls.__name__ == 'BGP']
    count = 0

    def core(data):
        n = len(data)
        # Ranges from the caller are not trusted either (C-2): an end past
        # the buffer must be clamped by bgpcore._end, not believed. The
        # primitives themselves take that as a precondition, which a
        # checked build enforces.
        for s, e in ((0, -1), (0, n + 64), (19, n), (23, n + 9), (n, n + 4)):
            for fn in (bgpcore.msg_header, bgpcore.iter_caps,
                       bgpcore.iter_attrs, bgpcore.iter_nlri,
                       bgpcore.iter_aspath, bgpcore.mp_reach_hdr,
                       bgpcore.mp_unreach_hdr):
                try:
                    fn(data, s, e)
                except Exception:
                    pass
        for add_path in (0, 1):
            try:
                bgpcore.scan_updates(data, add_path)
            except Exception:
                pass

    def codec(data):
        ctx = wire.DecodeCtx()
        for fn in (wire.decode_open, wire.decode_notification,
                   wire.decode_route_refresh):
            try:
                fn(data)
            except Exception:
                pass
        try:
            wire.decode_update(data, ctx)
        except Exception:
            pass
        framer = wire.Framer()
        try:
            framer.feed(data)
        except Exception:
            pass

    count += _decode_all(trace, 'bgpcore', core, seeds, rng)
    count += _decode_all(trace, 'wire', codec, seeds, rng)
    return count


def _run_netflow(trace, rng):
    from packets.commands.netflow_generator import NetflowV9Generator
    from packets.protos.netflow import Netflow, NetflowDecodeContext
    gen = NetflowV9Generator(seed=7)
    seeds = [bytes(gen.generate_packet(records=n, include_template=True)
                   .pkt2net({'update': 1})) for n in (1, 3)]
    # One context for the whole run, so a template corrupted by one case is
    # what a later case's data records are decoded against -- the path a
    # hostile exporter would take.
    ctx = NetflowDecodeContext()

    def decode(data):
        return Netflow.dispatch(data, context=ctx, exporter='192.0.2.1')

    count = _decode_all(trace, 'Netflow', decode, seeds, rng, touch_every=1)
    count += _decode_all(trace, 'Netflow(no context)', Netflow, seeds, rng)
    return count


# --- the parent -------------------------------------------------------------

def _checked_build():
    from packets.core import inetpkt
    return bool(getattr(inetpkt, 'RD_CHECK', 0))


class DecoderBoundsTestCase(unittest.TestCase):
    """C-1: no input reaches past a decoder's buffer, or crashes it."""

    def run_child(self, group):
        handle, trace = tempfile.mkstemp(prefix='c1-trace-')
        os.close(handle)
        try:
            proc = subprocess.run(
                [sys.executable, os.path.abspath(__file__), '--child', group,
                 trace], cwd=ROOT, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=600)
            with open(trace) as fh:
                last = fh.read().strip()
        finally:
            os.unlink(trace)
        if proc.returncode != 0:
            self.fail('group %s: child exited %d (%s build) while decoding '
                      '%s\nstderr: %s' % (
                          group, proc.returncode,
                          'checked' if _checked_build() else 'unchecked',
                          last.replace('\n', ' '),
                          proc.stderr.decode('utf-8', 'replace')[-2000:]))
        tried = int(proc.stdout.decode().split()[-1])
        self.assertGreater(tried, 100)

    def test_ethernet_frames(self):
        self.run_child('frames')

    def test_layers_on_their_own(self):
        self.run_child('layers')

    def test_bgp_scanning_core_and_codec(self):
        self.run_child('bgp')

    def test_netflow_v9_with_a_hostile_template(self):
        self.run_child('netflow')

    def test_dhcp(self):
        self.run_child('dhcp')

    def test_random_buffers_at_every_packet_class(self):
        self.run_child('random')


if __name__ == '__main__':
    if sys.argv[1:2] == ['--child']:
        sys.path.insert(0, ROOT)
        print('tried', run_group(sys.argv[2], Trace(sys.argv[3])))
    else:
        unittest.main()
