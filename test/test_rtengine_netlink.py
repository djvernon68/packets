#!/usr/bin/env python

"""Tests for the Linux rtnetlink FIB sink in packets.routing.rtengine.fib.

This module writes the kernel's routing table, so the suite is built around
the ways that can go wrong rather than around the source layout:

  * **The bytes are the contract.** A hand-packed uapi struct with a wrong
    offset does not fail, it installs a different route than the one
    intended. So the install request is asserted against a byte string
    built here from literal ``struct`` formats -- independently of the
    module's own packers, which are the thing under test -- and the three
    structure sizes and both alignment rules are pinned separately.

  * **Ownership is the safety property.** Every write carries our protocol
    id and our priority, because the kernel's route identity is
    ``(table, destination, tos, priority)`` and that pair is the only
    reason ``NLM_F_REPLACE`` cannot take over another daemon's route.
    Several tests exist purely to pin those two fields, including the one
    that catches the consequence nobody expects: changing a route's metric
    creates a *second* kernel route rather than replacing the first, so the
    old one has to be deleted explicitly.

  * **A failure is per route.** An injected ``EEXIST`` or ``ENETUNREACH``
    ack must mark exactly the route it names, with its errno, and leave
    every other route installed. There is no rollback to test; the absence
    of one is what is asserted.

  * **Everything is exercised without a kernel.** The sink talks to a
    transport with three methods, so a fake that records requests and
    replays canned acks and dumps drives message construction, ack
    matching, backoff, reconciliation and shutdown on macOS. The clock is
    injected too, so the 1..60 second backoff is tested by moving time
    rather than by waiting.

  * **The real-kernel tests are separate and guarded.** They run only on
    Linux with CAP_NET_ADMIN, they use a spare routing table (190) that no
    ``ip rule`` sends traffic to, so the host's live forwarding is never
    touched, and each one purges that table on the way in and on the way
    out so an earlier failure cannot poison a later test.

Written as plain ``unittest.TestCase`` with no pytest features and no
syntax newer than Python 3.6.8: the verification host runs this through
``python3 -m unittest discover -s test``.
"""

import errno
import logging
import socket
import struct
import time
import unittest

from collections import deque

from packets.routing.rtengine.fib import netlink
from packets.routing.rtengine.fib.netlink import (NetlinkSink,
                                                  NetlinkUnsupported,
                                                  make_sink)
from packets.routing.rtengine.fib.sink import FibSink
from packets.routing.rtengine.rib.prefix import AFI_IP, parse_prefix
from packets.routing.rtengine.rib.resolver import Resolver
from packets.routing.rtengine.rib.table import (FIB_STATE_ERROR,
                                                FIB_STATE_INSTALLED,
                                                FIB_STATE_NONE,
                                                FIB_STATE_PENDING,
                                                PROTO_BGP, PROTO_STATIC,
                                                Route)

# The table the real-kernel tests write. Nothing routes to it unless an
# `ip rule` says so, and none is created here, so a route installed in it
# cannot affect the host's forwarding even while the test is running.
SPARE_TABLE = 190
#: Our protocol id in the guarded tests; the module default.
OUR_PROTO = netlink.DEFAULT_PROTOCOL
#: An id belonging to nobody, used to plant a route we must not touch.
FOREIGN_PROTO = 191

# TEST-NET-2 and TEST-NET-3 (RFC 5737): guaranteed not to be real
# destinations, so a test that leaked one would still route nowhere.
TEST_PREFIX = '198.51.100.0/24'
OTHER_PREFIX = '203.0.113.0/24'

# What an empty non-blocking socket raises. 11 on Linux, 35 on Darwin; the
# local value is the right one because the fake stands in for a local
# socket, not for the kernel's reply.
_EAGAIN = errno.EAGAIN

_LINUX = netlink.supported()
_CAN_WRITE = _LINUX and netlink.privileged()
_KERNEL_REASON = 'needs Linux with CAP_NET_ADMIN: %s' % (
    netlink.capabilities().get('reason'),)


_log = logging.getLogger('packets.rtengine.fib.netlink')
_log_level = _log.level


def setUpModule():
    """Silence the sink's own warnings for the duration of the module.

    Half these tests inject a kernel rejection deliberately, and each one
    logs a warning that would otherwise be printed by the root logger's
    last-resort handler and read as a failure in an otherwise green run.
    """
    _log.setLevel(logging.CRITICAL)


def tearDownModule():
    """Restore the logger, so a later module sees what it expects."""
    _log.setLevel(_log_level)


# --- helpers ----------------------------------------------------------------


def v4(text):
    """Pack a dotted-quad address.

    :param text: e.g. ``'192.0.2.1'``.
    :return: four bytes.
    """
    return socket.inet_aton(text)


def route(prefix, nexthop='192.0.2.1', distance=20, metric=0,
          protocol=PROTO_BGP, source=None):
    """Build a Route with every field the sink reads pinned.

    ``distance`` defaults to the external-BGP value because that is what
    selects the ``ebgp`` priority, and the priority is half of the route's
    identity to the kernel.

    :param prefix: the destination as ``address/length`` text.
    :param nexthop: the next-hop as text, or '' for none.
    :param distance: administrative distance.
    :param metric: the protocol's metric, which is *not* the kernel
        priority.
    :param protocol: the rtengine protocol id.
    :param source: the offering plugin's token.
    :return: a :class:`Route`.
    """
    packed = v4(nexthop) if nexthop else b''
    return Route(parse_prefix(prefix), protocol, distance, metric, packed,
                 source if source is not None else object(), 100.0)


def ack_message(seq, code=0):
    """Build the ``NLMSG_ERROR`` the kernel answers a request with.

    The kernel sends the errno *negated*, and zero for success; the
    original request header follows it and is echoed back but not read by
    the sink, so sixteen zero bytes stand in for it here.

    :param seq: the sequence number being answered.
    :param code: the positive errno, or 0 for success.
    :return: one complete netlink message.
    """
    body = struct.pack('=i', -code) + (b'\x00' * netlink.SIZEOF_NLMSGHDR)
    return netlink.pack_message(netlink.NLMSG_ERROR, 0, seq, 0, body)


def route_message(seq, prefix, gateway='', table=SPARE_TABLE,
                  protocol=OUR_PROTO, priority=20, oif=0,
                  rtype=netlink.RTN_UNICAST, with_table_attr=True):
    """Build one ``RTM_NEWROUTE`` as a dump would carry it.

    :param seq: the dump's sequence number.
    :param prefix: the destination as text.
    :param gateway: the next-hop as text, or '' for none.
    :param table: the table id to report.
    :param protocol: the ``rtm_protocol`` to report.
    :param priority: the ``RTA_PRIORITY`` to report.
    :param oif: the interface index to report, or 0 to omit it.
    :param rtype: ``rtm_type``.
    :param with_table_attr: also carry ``RTA_TABLE``, as a modern kernel
        does.
    :return: one complete netlink message.
    """
    parsed = parse_prefix(prefix)
    body = struct.pack('=BBBBBBBBI', netlink.AF_INET, parsed.plen, 0, 0,
                       table if table <= 255 else netlink.RT_TABLE_COMPAT,
                       protocol, netlink.RT_SCOPE_UNIVERSE, rtype, 0)
    body += netlink.pack_attr(netlink.RTA_DST, parsed.packed())
    if gateway:
        body += netlink.pack_attr(netlink.RTA_GATEWAY, v4(gateway))
    if oif:
        body += netlink.pack_u32_attr(netlink.RTA_OIF, oif)
    body += netlink.pack_u32_attr(netlink.RTA_PRIORITY, priority)
    if with_table_attr:
        body += netlink.pack_u32_attr(netlink.RTA_TABLE, table)
    return netlink.pack_message(netlink.RTM_NEWROUTE, netlink.NLM_F_MULTI,
                                seq, 0, body)


def done_message(seq):
    """Build the ``NLMSG_DONE`` that terminates a dump."""
    return netlink.pack_message(netlink.NLMSG_DONE, netlink.NLM_F_MULTI,
                                seq, 0, struct.pack('=i', 0))


def decode(data):
    """Decode a request the sink sent into something assertable.

    :param data: the bytes handed to ``transport.send``.
    :return: a dict of header fields, ``rtmsg`` fields and attributes.
    """
    messages = netlink.parse_messages(data)
    assert len(messages) == 1, 'expected one message, got %d' % len(messages)
    msg_type, flags, seq, portid, body = messages[0]
    (family, dst_len, src_len, tos, table, protocol, scope, rtype,
     rtflags) = struct.unpack_from('=BBBBBBBBI', body, 0)
    attrs = netlink.parse_attrs(body, netlink.SIZEOF_RTMSG)
    return {
        'type': msg_type, 'flags': flags, 'seq': seq, 'portid': portid,
        'family': family, 'dst_len': dst_len, 'src_len': src_len,
        'tos': tos, 'table': table, 'protocol': protocol, 'scope': scope,
        'rtype': rtype, 'rtflags': rtflags, 'attrs': attrs,
        'dst': attrs.get(netlink.RTA_DST),
        'gateway': attrs.get(netlink.RTA_GATEWAY),
        'priority': (struct.unpack('=I', attrs[netlink.RTA_PRIORITY])[0]
                     if netlink.RTA_PRIORITY in attrs else None),
        'table_attr': (struct.unpack('=I', attrs[netlink.RTA_TABLE])[0]
                       if netlink.RTA_TABLE in attrs else None),
        'oif': (struct.unpack('=I', attrs[netlink.RTA_OIF])[0]
                if netlink.RTA_OIF in attrs else None),
        'raw': data,
    }


class FakeTransport(object):
    """The substitute socket every platform-independent test runs against.

    The contract is the sink's: ``send(bytes)``, ``recv(size)``,
    ``close()``, and an optional ``wait(timeout)`` which this deliberately
    does *not* implement, so the blocking paths are exercised through their
    pollless branch as well.

    :param auto_ack: answer every write immediately, which is what the
        kernel does and what most tests want. Turn it off to control the
        timing and ordering of acks by hand.
    :param errno_for: callable taking a decoded request and returning the
        errno to answer it with; None means success.
    """

    __slots__ = ('sent', 'raw', 'replies', 'closed', 'auto_ack',
                 'errno_for', 'send_error', 'fail_send_for', 'silent',
                 'dump_replies')

    def __init__(self, auto_ack=True, errno_for=None):
        self.sent = []
        self.raw = []
        self.replies = deque()
        self.closed = False
        self.auto_ack = auto_ack
        self.errno_for = errno_for
        #: An OSError every send raises, for testing backpressure.
        self.send_error = None
        #: callable(request) -> errno, to fail one write and not another.
        self.fail_send_for = None
        #: Accept writes and never answer them, like a wedged kernel.
        self.silent = False
        self.dump_replies = []

    def send(self, data):
        """Record a request and, when asked, answer it."""
        if self.send_error is not None:
            raise self.send_error
        request = decode(data)
        if self.fail_send_for is not None:
            code = self.fail_send_for(request)
            if code:
                # Raised before recording: a send that failed did not
                # happen, and counting it would make the next assertion
                # about what reached the kernel a lie.
                raise OSError(code, 'refused')
        self.sent.append(request)
        self.raw.append(data)
        if self.silent:
            return len(data)
        if request['type'] == netlink.RTM_GETROUTE:
            for reply in self.dump_replies:
                self.replies.append(reply(request['seq'])
                                    if callable(reply) else reply)
            self.replies.append(done_message(request['seq']))
        elif self.auto_ack:
            code = 0
            if self.errno_for is not None:
                code = self.errno_for(request) or 0
            self.replies.append(ack_message(request['seq'], code))
        return len(data)

    def recv(self, size):
        """Return the next canned reply, or report that it would block."""
        if not self.replies:
            raise OSError(_EAGAIN, 'would block')
        return self.replies.popleft()

    def close(self):
        """Record that the sink closed its socket."""
        self.closed = True

    # --- test-side helpers -------------------------------------------------

    def queue_ack(self, seq, code=0):
        """Make an ack for ``seq`` available to the next receive."""
        self.replies.append(ack_message(seq, code))

    def queue_raw(self, data):
        """Make an arbitrary reply available to the next receive."""
        self.replies.append(data)

    def writes(self, msg_type=None):
        """Return the decoded requests sent, optionally of one type."""
        if msg_type is None:
            return list(self.sent)
        return [r for r in self.sent if r['type'] == msg_type]

    def last(self):
        """Return the most recent decoded request."""
        return self.sent[-1]


class FakeClock(object):
    """A monotonic clock a test can move by hand.

    The backoff is measured in tens of seconds and the ack timeout in
    tens of seconds more; waiting for either would make the suite unusable
    and would make it flaky as well.
    """

    __slots__ = ('now',)

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        """Move time forward.

        :param seconds: how far.
        """
        self.now += seconds


def open_sink(**kwargs):
    """Build an opened sink on a fake transport.

    :param kwargs: overrides for :class:`NetlinkSink`.
    :return: ``(sink, transport)``.
    """
    transport = kwargs.pop('transport', None)
    if transport is None:
        transport = FakeTransport(auto_ack=kwargs.pop('auto_ack', True),
                                  errno_for=kwargs.pop('errno_for', None))
    params = {'table': SPARE_TABLE, 'protocol': OUR_PROTO,
              'transport': transport, 'timeout': 0.2}
    params.update(kwargs)
    sink = NetlinkSink(**params)
    sink.open()
    return sink, transport


# --- the wire layer ---------------------------------------------------------


class StructLayoutTestCase(unittest.TestCase):
    """The three hand-packed structures, and both alignment rules."""

    def test_the_three_structure_sizes_are_the_uapi_sizes(self):
        sizes = netlink.struct_sizes()
        self.assertEqual(sizes['nlmsghdr'], 16)
        self.assertEqual(sizes['rtmsg'], 12)
        self.assertEqual(sizes['rtattr'], 4)
        self.assertEqual(sizes['nlmsghdr'], netlink.SIZEOF_NLMSGHDR)
        self.assertEqual(sizes['rtmsg'], netlink.SIZEOF_RTMSG)
        self.assertEqual(sizes['rtattr'], netlink.SIZEOF_RTATTR)

    def test_alignment_rounds_up_to_four(self):
        for raw, aligned in ((0, 0), (1, 4), (4, 4), (5, 8), (16, 16),
                             (17, 20)):
            self.assertEqual(netlink.nlmsg_align(raw), aligned)
            self.assertEqual(netlink.rta_align(raw), aligned)

    def test_an_attribute_length_excludes_its_padding(self):
        # The classic netlink bug: rta_len counts the header and payload
        # but not the padding, while the message length counts everything.
        attr = netlink.pack_attr(netlink.RTA_DST, b'\x0a')
        self.assertEqual(len(attr), 8)
        length, attr_type = struct.unpack_from('=HH', attr, 0)
        self.assertEqual(length, 5)
        self.assertEqual(attr_type, netlink.RTA_DST)
        self.assertEqual(attr[5:], b'\x00\x00\x00')

    def test_an_address_attribute_needs_no_padding(self):
        attr = netlink.pack_attr(netlink.RTA_DST, b'\x0a\x00\x00\x00')
        self.assertEqual(len(attr), 8)
        self.assertEqual(struct.unpack_from('=H', attr, 0)[0], 8)

    def test_a_u32_attribute_is_native_order(self):
        attr = netlink.pack_u32_attr(netlink.RTA_PRIORITY, 20)
        self.assertEqual(len(attr), 8)
        self.assertEqual(struct.unpack_from('=HH', attr, 0),
                         (8, netlink.RTA_PRIORITY))
        self.assertEqual(struct.unpack_from('=I', attr, 4)[0], 20)

    def test_a_message_length_counts_everything(self):
        body = netlink.pack_attr(netlink.RTA_DST, b'\x0a')
        message = netlink.pack_message(netlink.RTM_NEWROUTE, 0, 7, 0, body)
        self.assertEqual(len(message), 24)
        self.assertEqual(struct.unpack_from('=I', message, 0)[0], 24)

    def test_several_messages_in_one_buffer_are_split(self):
        buf = ack_message(1) + ack_message(2, 17)
        parsed = netlink.parse_messages(buf)
        self.assertEqual([m[2] for m in parsed], [1, 2])
        self.assertEqual([m[0] for m in parsed],
                         [netlink.NLMSG_ERROR, netlink.NLMSG_ERROR])

    def test_a_truncated_tail_is_dropped_rather_than_raising(self):
        buf = ack_message(1) + b'\x08\x00'
        self.assertEqual(len(netlink.parse_messages(buf)), 1)

    def test_a_lying_attribute_length_ends_the_parse(self):
        # A length beyond the buffer must stop the walk, not loop and not
        # read past the end: every byte here came off a socket.
        body = struct.pack('=HH', 4000, netlink.RTA_DST) + b'\x0a\x00\x00\x00'
        self.assertEqual(netlink.parse_attrs(body), {})

    def test_a_zero_attribute_length_ends_the_parse(self):
        body = struct.pack('=HH', 0, netlink.RTA_DST)
        self.assertEqual(netlink.parse_attrs(body), {})

    def test_the_ipv6_family_number_is_linux_and_not_the_local_one(self):
        # 10 on Linux, 30 on Darwin. rtm_family is a Linux ABI field and
        # this module packs it on the development host as well, so it must
        # not be socket.AF_INET6.
        self.assertEqual(netlink.AF_INET6, 10)
        self.assertEqual(netlink.AF_INET, 2)


# --- what gets written ------------------------------------------------------


class InstallRequestTestCase(unittest.TestCase):
    """The bytes of an install, field by field."""

    def test_an_install_request_is_byte_for_byte_what_is_expected(self):
        sink, transport = open_sink(auto_ack=False)
        sink.install(route('10.0.0.0/8', '192.0.2.1'))
        sink.flush()

        expected = struct.pack('=IHHII', 60, 24, 0x505, 1, 0)
        expected += struct.pack('=BBBBBBBBI', 2, 8, 0, 0, SPARE_TABLE,
                                OUR_PROTO, 0, 1, 0)
        expected += struct.pack('=HH', 8, 1) + b'\x0a\x00\x00\x00'
        expected += struct.pack('=HH', 8, 5) + v4('192.0.2.1')
        expected += struct.pack('=HH', 8, 6) + struct.pack('=I', 20)
        expected += struct.pack('=HH', 8, 15) + struct.pack('=I', SPARE_TABLE)
        self.assertEqual(transport.raw[0], expected)

    def test_an_install_names_our_protocol_and_our_priority(self):
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        request = transport.last()
        # These two fields together are the whole ownership argument:
        # another daemon's route for 10/8 has a different priority, so it
        # is a different route to the kernel and REPLACE cannot reach it.
        self.assertEqual(request['protocol'], OUR_PROTO)
        self.assertEqual(request['priority'], 20)

    def test_an_install_is_create_and_replace_with_an_ack_requested(self):
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        flags = transport.last()['flags']
        for bit in (netlink.NLM_F_REQUEST, netlink.NLM_F_ACK,
                    netlink.NLM_F_CREATE, netlink.NLM_F_REPLACE):
            self.assertTrue(flags & bit, 'missing flag 0x%x' % bit)
        self.assertFalse(flags & netlink.NLM_F_EXCL)
        self.assertEqual(transport.last()['type'], netlink.RTM_NEWROUTE)

    def test_the_destination_length_and_family_come_from_the_prefix(self):
        sink, transport = open_sink()
        sink.install(route('10.1.2.0/24'))
        sink.flush()
        request = transport.last()
        self.assertEqual(request['dst_len'], 24)
        self.assertEqual(request['family'], netlink.AF_INET)
        self.assertEqual(request['dst'], b'\x0a\x01\x02\x00')

    def test_an_ipv6_install_carries_the_linux_family_number(self):
        sink, transport = open_sink()
        nexthop = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
        sink.install(Route(parse_prefix('2001:db8:1::/48'), PROTO_BGP, 20, 0,
                           nexthop, object(), 100.0))
        sink.flush()
        request = transport.last()
        self.assertEqual(request['family'], 10)
        self.assertEqual(request['dst_len'], 48)
        self.assertEqual(request['gateway'], nexthop)

    def test_a_route_with_no_next_hop_carries_no_gateway(self):
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8', nexthop=''))
        sink.flush()
        self.assertIsNone(transport.last()['gateway'])

    def test_a_zero_next_hop_is_not_a_gateway(self):
        # 0.0.0.0 is how BGP spells "via me". Sending it as RTA_GATEWAY
        # would install a route to nowhere.
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8', nexthop='0.0.0.0'))
        sink.flush()
        self.assertIsNone(transport.last()['gateway'])

    def test_an_interface_index_is_written_only_when_known(self):
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertIsNone(transport.last()['oif'])

        sink, transport = open_sink(oif_fn=lambda r: 7)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(transport.last()['oif'], 7)

    def test_a_table_below_256_appears_in_both_places(self):
        sink, transport = open_sink(table=200)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        request = transport.last()
        self.assertEqual(request['table'], 200)
        self.assertEqual(request['table_attr'], 200)

    def test_a_table_above_255_uses_rt_table_unspec_in_the_byte(self):
        # The byte cannot hold it. Truncating would put the route in a
        # wrong-but-valid table on a kernel that ignores RTA_TABLE;
        # RT_TABLE_UNSPEC makes such a kernel reject it instead.
        sink, transport = open_sink(table=1000)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        request = transport.last()
        self.assertEqual(request['table'], netlink.RT_TABLE_UNSPEC)
        self.assertEqual(request['table_attr'], 1000)

    def test_an_install_is_always_unicast_at_universe_scope(self):
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(transport.last()['rtype'], netlink.RTN_UNICAST)
        self.assertEqual(transport.last()['scope'],
                         netlink.RT_SCOPE_UNIVERSE)

    def test_a_next_hop_of_the_wrong_width_is_refused_without_a_write(self):
        # An RFC 5549 IPv6 next-hop for an IPv4 prefix has no expression in
        # RTA_GATEWAY; failing the one route beats a message the kernel
        # rejects for a reason nobody can read.
        sink, transport = open_sink()
        bad = Route(parse_prefix('10.0.0.0/8'), PROTO_BGP, 20, 0,
                    b'\x20\x01' + b'\x00' * 14, object(), 100.0)
        sink.install(bad)
        sink.flush()
        self.assertEqual(transport.writes(), [])
        self.assertEqual(bad.fib_state, FIB_STATE_ERROR)
        self.assertEqual(bad.fib_errno, netlink.EAFNOSUPPORT)


class WithdrawRequestTestCase(unittest.TestCase):
    """The bytes of a withdrawal."""

    def setUp(self):
        self.sink, self.transport = open_sink()
        self.route = route('10.0.0.0/8')
        self.sink.install(self.route)
        self.sink.flush()
        self.transport.sent = []
        self.transport.raw = []

    def test_a_withdraw_is_a_delroute_with_an_ack_requested(self):
        self.sink.withdraw(self.route)
        self.sink.flush()
        request = self.transport.last()
        self.assertEqual(request['type'], netlink.RTM_DELROUTE)
        self.assertTrue(request['flags'] & netlink.NLM_F_REQUEST)
        self.assertTrue(request['flags'] & netlink.NLM_F_ACK)
        self.assertFalse(request['flags'] & netlink.NLM_F_CREATE)
        self.assertFalse(request['flags'] & netlink.NLM_F_REPLACE)

    def test_a_withdraw_repeats_every_field_the_kernel_matches_on(self):
        self.sink.withdraw(self.route)
        self.sink.flush()
        request = self.transport.last()
        self.assertEqual(request['protocol'], OUR_PROTO)
        self.assertEqual(request['priority'], 20)
        self.assertEqual(request['dst'], b'\x0a\x00\x00\x00')
        self.assertEqual(request['gateway'], v4('192.0.2.1'))
        self.assertEqual(request['table_attr'], SPARE_TABLE)

    def test_a_withdraw_matches_any_scope(self):
        # RT_SCOPE_NOWHERE on a delete means "whatever scope it has". A
        # delete naming RT_SCOPE_UNIVERSE would miss a route the kernel
        # recorded at link scope.
        self.sink.withdraw(self.route)
        self.sink.flush()
        self.assertEqual(self.transport.last()['scope'],
                         netlink.RT_SCOPE_NOWHERE)

    def test_withdrawing_an_unsent_route_writes_nothing(self):
        sink, transport = open_sink()
        pending = route('10.9.0.0/16')
        sink.install(pending)
        sink.withdraw(pending)
        sink.flush()
        self.assertEqual(transport.writes(), [])
        self.assertEqual(pending.fib_state, FIB_STATE_NONE)

    def test_withdrawing_something_never_installed_is_harmless(self):
        sink, transport = open_sink()
        unknown = route('10.8.0.0/16')
        sink.withdraw(unknown)
        sink.flush()
        self.assertEqual(transport.writes(), [])
        self.assertEqual(unknown.fib_state, FIB_STATE_NONE)


class PriorityTestCase(unittest.TestCase):
    """The distance-to-priority mapping, which is half of route identity."""

    def test_the_external_distance_selects_the_ebgp_priority(self):
        sink, _t = open_sink(priority_ebgp=20, priority_ibgp=200)
        self.assertEqual(sink.priority_for(route('10.0.0.0/8', distance=20)),
                         20)

    def test_the_internal_distance_selects_the_ibgp_priority(self):
        sink, _t = open_sink(priority_ebgp=20, priority_ibgp=200)
        self.assertEqual(sink.priority_for(route('10.0.0.0/8', distance=200)),
                         200)

    def test_any_other_distance_takes_the_documented_default(self):
        # A connected or static route, or a protocol that does not exist
        # yet: the default is the ibgp priority unless configured.
        sink, _t = open_sink(priority_ebgp=20, priority_ibgp=200)
        self.assertEqual(sink.priority_for(
            route('10.0.0.0/8', distance=1, protocol=PROTO_STATIC)), 200)

        sink, _t = open_sink(priority_ebgp=20, priority_ibgp=200,
                             priority_default=1000)
        self.assertEqual(sink.priority_for(
            route('10.0.0.0/8', distance=1, protocol=PROTO_STATIC)), 1000)

    def test_the_mapping_is_data_and_can_be_replaced_wholesale(self):
        sink, _t = open_sink(priority_map={5: 55}, priority_default=99)
        self.assertEqual(sink.priority_for(route('10.0.0.0/8', distance=5)),
                         55)
        self.assertEqual(sink.priority_for(route('10.0.0.0/8', distance=20)),
                         99)

    def test_a_callable_overrides_the_mapping_entirely(self):
        sink, transport = open_sink(priority_fn=lambda r: 4242)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(transport.last()['priority'], 4242)


class MetricChangeTestCase(unittest.TestCase):
    """The trap: a new priority is a new route, not a replacement."""

    def test_changing_the_priority_deletes_the_route_it_replaces(self):
        sink, transport = open_sink()
        first = route('10.0.0.0/8', distance=20)
        sink.install(first)
        sink.flush()
        transport.sent = []

        second = route('10.0.0.0/8', distance=200)
        sink.install(second)
        sink.flush()

        kinds = [(r['type'], r['priority']) for r in transport.sent]
        # Add first, delete second: the prefix is never unrouted in
        # between, which it would be the other way round.
        self.assertEqual(kinds, [(netlink.RTM_NEWROUTE, 200),
                                 (netlink.RTM_DELROUTE, 20)])
        self.assertEqual(second.fib_state, FIB_STATE_INSTALLED)

    def test_the_stale_key_is_gone_from_the_sinks_own_state(self):
        sink, _t = open_sink()
        sink.install(route('10.0.0.0/8', distance=20))
        sink.flush()
        sink.install(route('10.0.0.0/8', distance=200))
        sink.flush()
        prefix = parse_prefix('10.0.0.0/8')
        self.assertEqual(sink.entry_state(prefix, 20), 'none')
        self.assertEqual(sink.entry_state(prefix, 200), netlink.ST_INSTALLED)

    def test_an_unsent_route_at_the_old_priority_is_simply_dropped(self):
        # Nothing reached the kernel, so there is nothing to delete.
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8', distance=20))
        sink.install(route('10.0.0.0/8', distance=200))
        sink.flush()
        self.assertEqual(len(transport.writes()), 1)
        self.assertEqual(transport.last()['priority'], 200)


# --- queueing, flushing and acknowledgements --------------------------------


class BatchingTestCase(unittest.TestCase):
    """install/withdraw queue; flush does a bounded amount of work."""

    def test_install_writes_nothing_by_itself(self):
        sink, transport = open_sink()
        marked = route('10.0.0.0/8')
        sink.install(marked)
        self.assertEqual(transport.writes(), [])
        self.assertEqual(marked.fib_state, FIB_STATE_PENDING)
        self.assertEqual(sink.queued_count(), 1)

    def test_a_flush_sends_at_most_one_batch(self):
        sink, transport = open_sink(batch=2)
        for octet in range(5):
            sink.install(route('10.%d.0.0/16' % octet))
        self.assertEqual(sink.queued_count(), 5)

        sink.flush()
        self.assertEqual(len(transport.writes()), 2)
        self.assertEqual(sink.queued_count(), 3)
        sink.flush()
        self.assertEqual(len(transport.writes()), 4)
        sink.flush()
        self.assertEqual(len(transport.writes()), 5)
        self.assertEqual(sink.queued_count(), 0)

    def test_a_prefix_offered_many_times_is_written_once(self):
        sink, transport = open_sink()
        for _i in range(100):
            sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(len(transport.writes()), 1)

    def test_the_in_flight_window_stops_the_sender(self):
        sink, transport = open_sink(auto_ack=False, window=2, batch=100)
        for octet in range(5):
            sink.install(route('10.%d.0.0/16' % octet))
        sink.flush()
        self.assertEqual(len(transport.writes()), 2)
        self.assertEqual(sink.pending_count(), 2)

        # A flush sends before it reads, so the window reopens for the
        # *next* flush rather than inside this one. That is the bounded
        # behaviour on purpose: one flush is one pass, not a loop that
        # runs until the queue drains.
        for request in transport.writes():
            transport.queue_ack(request['seq'])
        sink.flush()
        self.assertEqual(sink.pending_count(), 0)
        self.assertEqual(len(transport.writes()), 2)

        sink.flush()
        self.assertEqual(sink.pending_count(), 2)
        self.assertEqual(len(transport.writes()), 4)

    def test_a_would_block_send_leaves_the_request_at_the_front(self):
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8'))
        sink.install(route('10.1.0.0/16'))
        transport.send_error = OSError(_EAGAIN, 'would block')
        sink.flush()
        self.assertEqual(sink.queued_count(), 2)

        transport.send_error = None
        sink.flush()
        self.assertEqual(len(transport.writes()), 2)
        self.assertEqual(sink.queued_count(), 0)

    def test_a_flush_on_an_unopened_sink_does_nothing(self):
        sink = NetlinkSink(table=SPARE_TABLE, transport=FakeTransport())
        sink.install(route('10.0.0.0/8'))
        self.assertEqual(sink.flush(), 0)


class AckMatchingTestCase(unittest.TestCase):
    """Acks are matched to routes by netlink sequence number."""

    def test_each_request_gets_its_own_sequence_number(self):
        sink, transport = open_sink(auto_ack=False)
        for octet in range(3):
            sink.install(route('10.%d.0.0/16' % octet))
        sink.flush()
        seqs = [r['seq'] for r in transport.writes()]
        self.assertEqual(len(set(seqs)), 3)
        self.assertNotIn(0, seqs)

    def test_an_ack_marks_the_route_its_sequence_names(self):
        sink, transport = open_sink(auto_ack=False)
        routes = [route('10.%d.0.0/16' % i) for i in range(3)]
        for entry in routes:
            sink.install(entry)
        sink.flush()
        self.assertTrue(all(r.fib_state == FIB_STATE_PENDING
                            for r in routes))

        # Acknowledge the middle one only.
        middle = transport.writes()[1]
        transport.queue_ack(middle['seq'])
        self.assertEqual(sink.flush(), 1)
        self.assertEqual(routes[1].fib_state, FIB_STATE_INSTALLED)
        self.assertEqual(routes[0].fib_state, FIB_STATE_PENDING)
        self.assertEqual(routes[2].fib_state, FIB_STATE_PENDING)

    def test_acks_out_of_order_are_matched_correctly(self):
        sink, transport = open_sink(auto_ack=False)
        routes = [route('10.%d.0.0/16' % i) for i in range(3)]
        for entry in routes:
            sink.install(entry)
        sink.flush()
        for request in reversed(transport.writes()):
            transport.queue_ack(request['seq'])
        self.assertEqual(sink.flush(), 3)
        self.assertTrue(all(r.fib_state == FIB_STATE_INSTALLED
                            for r in routes))

    def test_an_ack_for_an_unknown_sequence_is_counted_and_ignored(self):
        sink, transport = open_sink(auto_ack=False)
        marked = route('10.0.0.0/8')
        sink.install(marked)
        sink.flush()
        transport.queue_ack(9999)
        self.assertEqual(sink.flush(), 0)
        self.assertEqual(marked.fib_state, FIB_STATE_PENDING)
        self.assertEqual(sink.stats()['stale-acks'], 1)

    def test_several_acks_in_one_datagram_are_all_applied(self):
        sink, transport = open_sink(auto_ack=False)
        routes = [route('10.%d.0.0/16' % i) for i in range(2)]
        for entry in routes:
            sink.install(entry)
        sink.flush()
        blob = b''.join(ack_message(r['seq']) for r in transport.writes())
        transport.queue_raw(blob)
        self.assertEqual(sink.flush(), 2)
        self.assertTrue(all(r.fib_state == FIB_STATE_INSTALLED
                            for r in routes))

    def test_an_unsolicited_route_message_is_not_an_acknowledgement(self):
        sink, transport = open_sink(auto_ack=False)
        marked = route('10.0.0.0/8')
        sink.install(marked)
        sink.flush()
        transport.queue_raw(route_message(transport.last()['seq'],
                                          '10.0.0.0/8'))
        self.assertEqual(sink.flush(), 0)
        self.assertEqual(marked.fib_state, FIB_STATE_PENDING)


class PerRouteErrorTestCase(unittest.TestCase):
    """One rejected route marks itself and nothing else."""

    def _sink_failing(self, prefix_bytes, code):
        """A sink whose kernel rejects exactly one destination."""

        def errno_for(request):
            if request['dst'] == prefix_bytes:
                return code
            return 0

        return open_sink(errno_for=errno_for)

    def test_a_rejected_route_is_marked_with_its_errno_and_no_other_is(self):
        sink, _t = self._sink_failing(b'\x0a\x01\x00\x00',
                                      netlink.EEXIST)
        good_a = route('10.0.0.0/16')
        bad = route('10.1.0.0/16')
        good_b = route('10.2.0.0/16')
        for entry in (good_a, bad, good_b):
            sink.install(entry)
        sink.flush()

        self.assertEqual(bad.fib_state, FIB_STATE_ERROR)
        self.assertEqual(bad.fib_errno, netlink.EEXIST)
        # No rollback: routes are independent and the others are correct.
        self.assertEqual(good_a.fib_state, FIB_STATE_INSTALLED)
        self.assertEqual(good_b.fib_state, FIB_STATE_INSTALLED)
        self.assertEqual(good_a.fib_errno, 0)

    def test_an_unreachable_next_hop_is_reported_as_enetunreach(self):
        enetunreach = 101
        sink, _t = self._sink_failing(b'\x0a\x01\x00\x00', enetunreach)
        bad = route('10.1.0.0/16')
        sink.install(bad)
        sink.install(route('10.2.0.0/16'))
        sink.flush()
        self.assertEqual(bad.fib_state, FIB_STATE_ERROR)
        self.assertEqual(bad.fib_errno, enetunreach)
        stats = sink.stats()
        self.assertEqual(stats['errors'], 1)
        self.assertEqual(stats['in-error'], 1)
        self.assertEqual(stats['installed'], 1)

    def test_a_delete_of_a_route_that_is_already_gone_is_a_success(self):
        # ESRCH from fib_table_delete means the route is not there, which
        # is what the delete was for.
        def errno_for(request):
            if request['type'] == netlink.RTM_DELROUTE:
                return netlink.ESRCH
            return 0

        sink, _t = open_sink(errno_for=errno_for)
        marked = route('10.0.0.0/8')
        sink.install(marked)
        sink.flush()
        sink.withdraw(marked)
        sink.flush()
        self.assertEqual(marked.fib_state, FIB_STATE_NONE)
        self.assertEqual(sink.stats()['errors'], 0)
        self.assertEqual(sink.stats()['withdrawn'], 1)

    def test_a_send_that_fails_outright_marks_only_that_route(self):
        # EMSGSIZE on one absurd route must not stall the queue behind it.
        sink, transport = open_sink()
        first = route('10.0.0.0/16')
        second = route('10.1.0.0/16')
        transport.fail_send_for = (
            lambda r: 90 if r['dst'] == b'\x0a\x00\x00\x00' else 0)
        sink.install(first)
        sink.install(second)
        sink.flush()
        self.assertEqual(first.fib_state, FIB_STATE_ERROR)
        self.assertEqual(first.fib_errno, 90)
        self.assertEqual(second.fib_state, FIB_STATE_INSTALLED)


class BackoffTestCase(unittest.TestCase):
    """Retries are exponential and clamped to one second and one minute."""

    def test_the_delay_doubles_between_the_documented_bounds(self):
        self.assertEqual(netlink.backoff_delay(1), 1.0)
        self.assertEqual(netlink.backoff_delay(2), 2.0)
        self.assertEqual(netlink.backoff_delay(3), 4.0)
        self.assertEqual(netlink.backoff_delay(7), 60.0)
        for attempts in range(1, 200):
            delay = netlink.backoff_delay(attempts)
            self.assertGreaterEqual(delay, netlink.RETRY_MIN_S)
            self.assertLessEqual(delay, netlink.RETRY_MAX_S)

    def test_a_failed_route_is_not_retried_before_its_backoff(self):
        clock = FakeClock()
        failures = {'count': 0}

        def errno_for(_request):
            failures['count'] += 1
            return netlink.EEXIST

        sink, transport = open_sink(errno_for=errno_for, clock=clock)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(len(transport.writes()), 1)

        clock.advance(0.5)
        sink.flush()
        self.assertEqual(len(transport.writes()), 1)

        clock.advance(0.6)
        sink.flush()
        self.assertEqual(len(transport.writes()), 2)
        self.assertEqual(sink.stats()['retries'], 1)

    def test_a_retry_that_succeeds_clears_the_error(self):
        clock = FakeClock()
        state = {'fail': True}

        def errno_for(_request):
            return netlink.EEXIST if state['fail'] else 0

        sink, _t = open_sink(errno_for=errno_for, clock=clock)
        marked = route('10.0.0.0/8')
        sink.install(marked)
        sink.flush()
        self.assertEqual(marked.fib_state, FIB_STATE_ERROR)
        self.assertEqual(sink.stats()['status'], 'degraded')

        state['fail'] = False
        clock.advance(2.0)
        sink.flush()
        self.assertEqual(marked.fib_state, FIB_STATE_INSTALLED)
        self.assertEqual(marked.fib_errno, 0)
        stats = sink.stats()
        self.assertEqual(stats['in-error'], 0)
        self.assertEqual(stats['recovered'], 1)
        self.assertEqual(stats['status'], 'ok')

    def test_repeated_failures_lengthen_the_wait_up_to_the_ceiling(self):
        clock = FakeClock()
        sink, transport = open_sink(errno_for=lambda r: netlink.EEXIST,
                                    clock=clock)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        for expected in (1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0):
            before = len(transport.writes())
            clock.advance(expected - 0.01)
            sink.flush()
            self.assertEqual(len(transport.writes()), before,
                             'retried early after %.2fs' % expected)
            clock.advance(0.02)
            sink.flush()
            self.assertEqual(len(transport.writes()), before + 1)

    def test_a_request_the_kernel_never_answers_is_retried(self):
        clock = FakeClock()
        sink, transport = open_sink(auto_ack=False, clock=clock,
                                    ack_timeout=30.0)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(sink.pending_count(), 1)

        clock.advance(31.0)
        sink.flush()
        self.assertEqual(len(transport.writes()), 2)
        self.assertEqual(sink.stats()['ack-timeouts'], 1)

    def test_the_late_ack_of_a_timed_out_request_is_not_applied_twice(self):
        clock = FakeClock()
        sink, transport = open_sink(auto_ack=False, clock=clock,
                                    ack_timeout=30.0)
        marked = route('10.0.0.0/8')
        sink.install(marked)
        sink.flush()
        first = transport.last()['seq']
        clock.advance(31.0)
        sink.flush()
        transport.queue_ack(first)
        sink.flush()
        self.assertEqual(sink.stats()['stale-acks'], 1)
        self.assertEqual(marked.fib_state, FIB_STATE_PENDING)


# --- reconciliation ---------------------------------------------------------


class ReconcileTestCase(unittest.TestCase):
    """What a previous run of this process left behind."""

    def _sink_with_dump(self, *messages):
        sink, transport = open_sink()
        transport.dump_replies = list(messages)
        return sink, transport

    def test_an_identical_route_is_adopted_and_not_rewritten(self):
        wanted = route('10.0.0.0/8', '192.0.2.1')
        sink, transport = self._sink_with_dump(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      priority=20))
        report = sink.reconcile([wanted])
        self.assertEqual(report['adopted'], 1)
        self.assertEqual(report['removed'], 0)
        self.assertEqual(wanted.fib_state, FIB_STATE_INSTALLED)
        self.assertEqual(transport.writes(netlink.RTM_NEWROUTE), [])
        self.assertEqual(transport.writes(netlink.RTM_DELROUTE), [])

        # And the first install of the adopted route writes nothing.
        sink.install(wanted)
        sink.flush()
        self.assertEqual(transport.writes(netlink.RTM_NEWROUTE), [])
        self.assertEqual(sink.stats()['skipped'], 1)

    def test_an_interface_the_kernel_chose_does_not_block_adoption(self):
        # We asked for no particular interface and the kernel picked one.
        # That is agreement, not a difference, and rewriting the route
        # would drop the interface the kernel had resolved.
        wanted = route('10.0.0.0/8', '192.0.2.1')
        sink, transport = self._sink_with_dump(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      priority=20, oif=7))
        self.assertEqual(sink.reconcile([wanted])['adopted'], 1)
        sink.install(wanted)
        sink.flush()
        self.assertEqual(transport.writes(netlink.RTM_NEWROUTE), [])
        self.assertEqual(transport.writes(netlink.RTM_DELROUTE), [])

    def test_a_route_with_a_different_gateway_is_deleted(self):
        wanted = route('10.0.0.0/8', '192.0.2.1')
        sink, transport = self._sink_with_dump(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.99',
                                      priority=20))
        report = sink.reconcile([wanted])
        self.assertEqual(report['adopted'], 0)
        self.assertEqual(report['removed'], 1)
        deletes = transport.writes(netlink.RTM_DELROUTE)
        self.assertEqual(len(deletes), 1)
        # The delete has to name the *kernel's* gateway and priority, not
        # ours, or it would not match the route it is removing.
        self.assertEqual(deletes[0]['gateway'], v4('192.0.2.99'))
        self.assertEqual(deletes[0]['priority'], 20)

    def test_a_route_we_no_longer_want_at_all_is_deleted(self):
        sink, transport = self._sink_with_dump(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1'))
        report = sink.reconcile([])
        self.assertEqual(report['removed'], 1)
        self.assertEqual(len(transport.writes(netlink.RTM_DELROUTE)), 1)

    def test_a_route_at_a_different_priority_is_not_the_same_route(self):
        wanted = route('10.0.0.0/8', '192.0.2.1', distance=20)
        sink, transport = self._sink_with_dump(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      priority=999))
        report = sink.reconcile([wanted])
        self.assertEqual(report['adopted'], 0)
        self.assertEqual(report['removed'], 1)
        self.assertEqual(transport.writes(netlink.RTM_DELROUTE)[0]['priority'],
                         999)

    def test_a_foreign_protocol_id_is_ignored_entirely(self):
        sink, transport = self._sink_with_dump(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      protocol=FOREIGN_PROTO),
            lambda seq: route_message(seq, '172.16.0.0/12', '192.0.2.1',
                                      protocol=netlink.RTPROT_KERNEL))
        report = sink.reconcile([])
        self.assertEqual(report['ours'], 0)
        self.assertEqual(report['foreign'], 2)
        self.assertEqual(report['removed'], 0)
        self.assertEqual(transport.writes(netlink.RTM_DELROUTE), [])

    def test_our_protocol_in_another_table_is_ignored(self):
        sink, transport = self._sink_with_dump(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      table=netlink.RT_TABLE_MAIN))
        report = sink.reconcile([])
        self.assertEqual(report['ours'], 0)
        self.assertEqual(transport.writes(netlink.RTM_DELROUTE), [])

    def test_the_dump_request_is_a_getroute_dump(self):
        sink, transport = self._sink_with_dump()
        sink.reconcile([])
        request = transport.writes(netlink.RTM_GETROUTE)[0]
        self.assertTrue(request['flags'] & netlink.NLM_F_REQUEST)
        self.assertTrue(request['flags'] & netlink.NLM_F_DUMP)

    def test_an_orphan_leaves_the_sink_degraded(self):
        sink, _t = self._sink_with_dump(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1'))
        sink.reconcile([])
        stats = sink.stats()
        self.assertEqual(stats['orphans'], 1)
        self.assertEqual(stats['removed'], 1)
        self.assertEqual(stats['status'], 'degraded')

    def test_reconciling_before_opening_is_refused(self):
        sink = NetlinkSink(table=SPARE_TABLE, transport=FakeTransport())
        self.assertRaises(NetlinkUnsupported, sink.reconcile, [])

    def test_a_dump_that_never_finishes_times_out(self):
        # A dump that stopped at the first empty read would return a
        # prefix of the table and reconciliation would then delete routes
        # it had simply not seen yet, so an incomplete dump has to be an
        # error rather than a short answer.
        sink, transport = open_sink(timeout=0.05)
        transport.silent = True
        self.assertRaises(OSError, sink.reconcile, [])


# --- shutdown ---------------------------------------------------------------


class ShutdownTestCase(unittest.TestCase):
    """Stopping must not leave the kernel forwarding into a hole."""

    def test_shutdown_withdraws_everything_and_closes(self):
        sink, transport = open_sink()
        routes = [route('10.%d.0.0/16' % i) for i in range(3)]
        for entry in routes:
            sink.install(entry)
        sink.flush()
        transport.sent = []

        self.assertEqual(sink.shutdown(), 3)
        deletes = transport.writes(netlink.RTM_DELROUTE)
        self.assertEqual(len(deletes), 3)
        self.assertTrue(all(r.fib_state == FIB_STATE_NONE for r in routes))
        self.assertTrue(transport.closed)
        self.assertFalse(sink.is_open())

    def test_retain_leaves_the_routes_and_still_closes(self):
        sink, transport = open_sink()
        marked = route('10.0.0.0/8')
        sink.install(marked)
        sink.flush()
        transport.sent = []

        self.assertEqual(sink.shutdown(retain=True), 0)
        self.assertEqual(transport.writes(netlink.RTM_DELROUTE), [])
        self.assertEqual(marked.fib_state, FIB_STATE_INSTALLED)
        self.assertTrue(transport.closed)

    def test_the_configured_default_decides_when_retain_is_not_given(self):
        sink, transport = open_sink(retain_on_shutdown=True)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        transport.sent = []
        self.assertEqual(sink.shutdown(), 0)
        self.assertEqual(transport.writes(netlink.RTM_DELROUTE), [])

    def test_a_queued_but_unsent_route_needs_no_delete(self):
        sink, transport = open_sink()
        sink.install(route('10.0.0.0/8'))
        self.assertEqual(sink.shutdown(), 0)
        self.assertEqual(transport.writes(), [])

    def test_shutting_down_a_sink_that_never_opened_is_harmless(self):
        sink = NetlinkSink(table=SPARE_TABLE, transport=FakeTransport())
        self.assertEqual(sink.shutdown(), 0)

    def test_shutdown_is_idempotent(self):
        sink, _t = open_sink()
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(sink.shutdown(), 1)
        self.assertEqual(sink.shutdown(), 0)


# --- reporting and configuration --------------------------------------------


class StatsTestCase(unittest.TestCase):
    """The document health and `show ip route` read."""

    def test_the_stats_shape_is_stable_and_serialisable(self):
        import json

        sink, _t = open_sink()
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        stats = sink.stats()
        for key in ('name', 'writes', 'status', 'installed', 'withdrawn',
                    'errors', 'retries', 'queued', 'acks-pending',
                    'adopted', 'removed', 'protocol', 'table', 'priority',
                    'open', 'enabled', 'supported', 'privileged',
                    'present', 'in-error', 'orphans'):
            self.assertIn(key, stats)
        self.assertEqual(stats['name'], 'netlink')
        self.assertTrue(stats['writes'])
        self.assertEqual(stats['table'], SPARE_TABLE)
        self.assertEqual(stats['protocol'], OUR_PROTO)
        self.assertEqual(stats['priority'],
                         {'ebgp': 20, 'ibgp': 200, 'default': 200})
        self.assertEqual(stats['installed'], 1)
        self.assertEqual(stats['present'], 1)
        # Must survive the REST layer.
        json.loads(json.dumps(stats))

    def test_a_healthy_sink_reports_ok(self):
        sink, _t = open_sink()
        self.assertEqual(sink.stats()['status'], 'ok')
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(sink.stats()['status'], 'ok')

    def test_a_route_in_error_degrades_the_sink(self):
        sink, _t = open_sink(errno_for=lambda r: netlink.EEXIST)
        sink.install(route('10.0.0.0/8'))
        sink.flush()
        self.assertEqual(sink.stats()['status'], 'degraded')

    def test_the_sink_declares_itself_a_writer(self):
        sink, _t = open_sink()
        self.assertTrue(isinstance(sink, FibSink))
        self.assertTrue(sink.writes)
        self.assertEqual(sink.name, 'netlink')


class CapabilityTestCase(unittest.TestCase):
    """Platform and privilege are probed, never assumed."""

    def test_support_follows_the_platform(self):
        self.assertEqual(netlink.supported(),
                         netlink.capabilities()['supported'])
        if not _LINUX:
            self.assertFalse(netlink.supported())

    def test_the_probe_explains_itself(self):
        netlink.reset_probe_cache()
        caps = netlink.capabilities()
        for key in ('supported', 'privileged', 'reason', 'platform',
                    'euid'):
            self.assertIn(key, caps)
        self.assertTrue(isinstance(caps['reason'], str))
        self.assertTrue(caps['reason'])

    def test_the_probe_is_cached_and_resettable(self):
        first = netlink.capabilities()
        self.assertEqual(first, netlink.capabilities())
        netlink.reset_probe_cache()
        self.assertEqual(first, netlink.capabilities())

    def test_the_caller_cannot_corrupt_the_cached_probe(self):
        caps = netlink.capabilities()
        caps['supported'] = 'nonsense'
        self.assertNotEqual(netlink.capabilities()['supported'], 'nonsense')

    @unittest.skipIf(_LINUX, 'this asserts the non-Linux refusal')
    def test_opening_without_a_transport_is_refused_off_linux(self):
        sink = NetlinkSink(table=SPARE_TABLE)
        self.assertRaises(NetlinkUnsupported, sink.open)
        self.assertFalse(sink.is_open())

    def test_constructing_a_sink_opens_nothing_anywhere(self):
        # The whole safety property: a sink can be built from a
        # configuration document on any host, and only an explicit open()
        # touches the kernel.
        sink = make_sink({'install': True, 'table': SPARE_TABLE})
        self.assertFalse(sink.is_open())
        self.assertEqual(sink.fileno(), -1)


class MakeSinkTestCase(unittest.TestCase):
    """The factory engine.py calls."""

    def test_an_empty_configuration_takes_the_schema_defaults(self):
        sink = make_sink({})
        self.assertEqual(sink.table, netlink.RT_TABLE_MAIN)
        self.assertEqual(sink.protocol, netlink.DEFAULT_PROTOCOL)
        self.assertEqual(sink.priority_ebgp, 20)
        self.assertEqual(sink.priority_ibgp, 200)
        self.assertFalse(sink.retain_on_shutdown)
        self.assertFalse(sink.enabled)

    def test_none_behaves_like_an_absent_section(self):
        self.assertEqual(make_sink(None).table, netlink.RT_TABLE_MAIN)

    def test_every_configured_key_reaches_the_sink(self):
        sink = make_sink({
            'install': True,
            'table': 42,
            'protocol': 77,
            'priority': {'ebgp': 5, 'ibgp': 500},
            'retain-on-shutdown': True,
        })
        self.assertEqual(sink.table, 42)
        self.assertEqual(sink.protocol, 77)
        self.assertEqual(sink.priority_ebgp, 5)
        self.assertEqual(sink.priority_ibgp, 500)
        self.assertTrue(sink.retain_on_shutdown)
        self.assertTrue(sink.enabled)
        self.assertFalse(sink.is_open())

    def test_a_keyword_overrides_the_configuration(self):
        transport = FakeTransport()
        sink = make_sink({'table': 42}, transport=transport, table=43)
        self.assertEqual(sink.table, 43)

    def test_an_impossible_protocol_id_is_refused(self):
        # rtm_protocol is one byte, and 0 would make every route on the
        # box look like ours.
        self.assertRaises(ValueError, make_sink, {'protocol': 0})
        self.assertRaises(ValueError, make_sink, {'protocol': 256})

    def test_an_impossible_table_id_is_refused(self):
        self.assertRaises(ValueError, make_sink, {'table': -1})


# --- the resolver's read-only import ----------------------------------------


class ResolverKernelImportTestCase(unittest.TestCase):
    """``ip.route.kernel-import``: read-only, ranked below statics."""

    def _transport(self, *messages):
        transport = FakeTransport()
        transport.dump_replies = list(messages)
        return transport

    def test_the_import_is_refused_unless_it_was_enabled(self):
        resolver = Resolver(enabled=True)
        self.assertRaises(RuntimeError, resolver.load_kernel,
                          transport=self._transport())

    def test_the_kernel_routes_become_resolvable_entries(self):
        resolver = Resolver(enabled=True, kernel_import=True)
        transport = self._transport(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      table=netlink.RT_TABLE_MAIN,
                                      protocol=netlink.RTPROT_KERNEL,
                                      priority=7))
        self.assertEqual(resolver.load_kernel(transport=transport), 1)
        found = resolver.resolve(AFI_IP, v4('10.1.2.3'))
        self.assertIsNotNone(found)
        self.assertEqual(found.source, 'kernel')
        self.assertEqual(found.metric, 7)
        self.assertEqual(found.prefix.to_str(), '10.0.0.0/8')
        self.assertTrue(resolver.reachable(AFI_IP, v4('10.1.2.3')))
        self.assertEqual(resolver.igp_metric(AFI_IP, v4('10.1.2.3')), 7)

    def test_the_import_writes_nothing(self):
        resolver = Resolver(enabled=True, kernel_import=True)
        transport = self._transport(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1'))
        resolver.load_kernel(transport=transport)
        kinds = set(r['type'] for r in transport.sent)
        self.assertEqual(kinds, set([netlink.RTM_GETROUTE]))

    def test_a_configured_static_beats_an_imported_route(self):
        # The operator's document is the truth about a prefix; a snapshot
        # of somebody else's table is not allowed to displace it.
        resolver = Resolver(enabled=True, kernel_import=True)
        resolver.add_static('10.0.0.0/8', '198.51.100.9', metric=3)
        transport = self._transport(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      priority=7))
        resolver.load_kernel(transport=transport)
        found = resolver.resolve(AFI_IP, v4('10.1.2.3'))
        self.assertEqual(found.source, 'static')
        self.assertEqual(found.nexthop, v4('198.51.100.9'))
        self.assertEqual(found.metric, 3)
        self.assertEqual(resolver.stats()['kernel-shadowed'], 1)

    def test_a_more_specific_import_still_loses_only_on_its_own_prefix(self):
        resolver = Resolver(enabled=True, kernel_import=True)
        resolver.add_static('10.0.0.0/8', '198.51.100.9')
        transport = self._transport(
            lambda seq: route_message(seq, '172.16.0.0/12', '192.0.2.1'))
        resolver.load_kernel(transport=transport)
        self.assertEqual(resolver.resolve(AFI_IP, v4('10.1.2.3')).source,
                         'static')
        self.assertEqual(resolver.resolve(AFI_IP, v4('172.16.1.1')).source,
                         'kernel')

    def test_non_unicast_entries_are_not_next_hops(self):
        resolver = Resolver(enabled=True, kernel_import=True)
        transport = self._transport(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      rtype=netlink.RTN_BROADCAST),
            lambda seq: route_message(seq, '172.16.0.0/12', '192.0.2.1',
                                      rtype=netlink.RTN_UNREACHABLE))
        self.assertEqual(resolver.load_kernel(transport=transport), 0)
        self.assertIsNone(resolver.resolve(AFI_IP, v4('10.1.2.3')))

    def test_a_second_import_replaces_the_first(self):
        resolver = Resolver(enabled=True, kernel_import=True)
        resolver.load_kernel(transport=self._transport(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1')))
        resolver.load_kernel(transport=self._transport(
            lambda seq: route_message(seq, '172.16.0.0/12', '192.0.2.1')))
        self.assertIsNone(resolver.resolve(AFI_IP, v4('10.1.2.3')))
        self.assertIsNotNone(resolver.resolve(AFI_IP, v4('172.16.1.1')))
        self.assertEqual(len(resolver.kernels(AFI_IP)), 1)

    def test_the_import_can_be_limited_to_one_table(self):
        resolver = Resolver(enabled=True, kernel_import=True)
        transport = self._transport(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1',
                                      table=netlink.RT_TABLE_MAIN),
            lambda seq: route_message(seq, '172.16.0.0/12', '192.0.2.1',
                                      table=SPARE_TABLE))
        resolver.load_kernel(transport=transport,
                             table=netlink.RT_TABLE_MAIN)
        self.assertEqual(len(resolver.kernels(AFI_IP)), 1)
        self.assertEqual(resolver.kernels(AFI_IP)[0].prefix.to_str(),
                         '10.0.0.0/8')

    def test_clearing_the_import_removes_every_entry(self):
        resolver = Resolver(enabled=True, kernel_import=True)
        resolver.load_kernel(transport=self._transport(
            lambda seq: route_message(seq, '10.0.0.0/8', '192.0.2.1')))
        self.assertEqual(resolver.clear_kernel(), 1)
        self.assertIsNone(resolver.resolve(AFI_IP, v4('10.1.2.3')))

    def test_the_existing_behaviour_and_stats_keys_are_untouched(self):
        resolver = Resolver()
        self.assertTrue(resolver.reachable(AFI_IP, v4('10.1.2.3')))
        self.assertEqual(resolver.igp_metric(AFI_IP, v4('10.1.2.3')), 0)
        resolver.add_static('10.0.0.0/8', '192.0.2.1', metric=4)
        resolver.enabled = True
        found = resolver.resolve(AFI_IP, v4('10.1.2.3'))
        self.assertEqual(found.source, 'static')
        self.assertTrue(resolver.remove_static('10.0.0.0/8'))
        stats = resolver.stats()
        for key in ('enabled', 'use_rib', 'static', 'lookups', 'hits'):
            self.assertIn(key, stats)
        for key in ('kernel-import', 'kernel', 'kernel-loads',
                    'kernel-imported', 'kernel-shadowed', 'kernel-errors',
                    'sources'):
            self.assertIn(key, stats)
        self.assertFalse(stats['kernel-import'])
        self.assertEqual(stats['sources']['kernel'], 0)

    def test_a_failed_import_is_counted_and_raised(self):
        resolver = Resolver(enabled=True, kernel_import=True)
        transport = FakeTransport()
        transport.send_error = OSError(1, 'operation not permitted')
        self.assertRaises(OSError, resolver.load_kernel,
                          transport=transport)
        stats = resolver.stats()
        self.assertEqual(stats['kernel-errors'], 1)
        self.assertTrue(stats['kernel-last-error'])


# --- against a real kernel --------------------------------------------------


class RawNetlink(object):
    """A minimal writer used only to set up and clean up kernel tests.

    It shares the module's wire helpers, which is deliberate: a test fixture
    that hand-rolled its own packing would be a second implementation to
    keep correct, and the pieces it reuses are the ones the earlier tests
    have already pinned byte for byte.

    :param table: the routing table to operate on.
    """

    def __init__(self, table):
        self.table = table
        self.transport = netlink.NetlinkTransport.open()
        self.seq = 1000

    def _send(self, msg_type, flags, kroute):
        self.seq += 1
        table_byte = self.table if self.table <= 255 \
            else netlink.RT_TABLE_UNSPEC
        scope = (netlink.RT_SCOPE_NOWHERE if msg_type == netlink.RTM_DELROUTE
                 else netlink.RT_SCOPE_UNIVERSE)
        body = struct.pack('=BBBBBBBBI', kroute['family'], kroute['dst_len'],
                           0, 0, table_byte, kroute['protocol'], scope,
                           netlink.RTN_UNICAST, 0)
        body += netlink.pack_attr(netlink.RTA_DST, kroute['dst'])
        if kroute.get('gateway'):
            body += netlink.pack_attr(netlink.RTA_GATEWAY,
                                      kroute['gateway'])
        if kroute.get('oif'):
            body += netlink.pack_u32_attr(netlink.RTA_OIF, kroute['oif'])
        body += netlink.pack_u32_attr(netlink.RTA_PRIORITY,
                                      kroute['priority'])
        body += netlink.pack_u32_attr(netlink.RTA_TABLE, self.table)
        self.transport.send(netlink.pack_message(msg_type, flags, self.seq,
                                                 0, body))
        return self._ack(self.seq)

    def _ack(self, seq, timeout=2.0):
        import time as _time

        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            self.transport.wait(0.1)
            try:
                data = self.transport.recv(netlink.DEFAULT_RECV_SIZE)
            except OSError:
                continue
            for msg_type, _f, msg_seq, _p, body in \
                    netlink.parse_messages(data):
                if msg_seq == seq and msg_type == netlink.NLMSG_ERROR:
                    return -struct.unpack_from('=i', body, 0)[0]
        raise AssertionError('no acknowledgement for sequence %d' % seq)

    def add(self, prefix, protocol, priority, gateway=b'', oif=0):
        """Install a route directly, for a fixture."""
        parsed = parse_prefix(prefix)
        return self._send(netlink.RTM_NEWROUTE,
                          netlink.NLM_F_REQUEST | netlink.NLM_F_ACK
                          | netlink.NLM_F_CREATE | netlink.NLM_F_REPLACE,
                          {'family': netlink.AF_INET, 'dst': parsed.packed(),
                           'dst_len': parsed.plen, 'protocol': protocol,
                           'priority': priority, 'gateway': gateway,
                           'oif': oif})

    def routes(self):
        """Dump the table this writer owns."""
        return netlink.kernel_routes(table=self.table,
                                     transport=self.transport)

    def purge(self):
        """Remove everything from the table, whoever wrote it."""
        for kroute in self.routes():
            self._send(netlink.RTM_DELROUTE,
                       netlink.NLM_F_REQUEST | netlink.NLM_F_ACK,
                       {'family': kroute.family, 'dst': kroute.dst,
                        'dst_len': kroute.dst_len,
                        'protocol': kroute.protocol,
                        'priority': kroute.priority,
                        'gateway': kroute.gateway, 'oif': kroute.oif})

    def close(self):
        """Release the socket."""
        self.transport.close()


@unittest.skipUnless(_CAN_WRITE, _KERNEL_REASON)
class LinuxKernelTestCase(unittest.TestCase):
    """The real thing, in a spare table nothing forwards through.

    Table 190 is used because no ``ip rule`` sends traffic to it unless
    somebody writes one, and none is written here: a route installed by
    these tests cannot change what the host does with a packet even while
    the test is running. The table is purged before and after every test,
    so a failure part way through cannot leave state for the next one.
    """

    def setUp(self):
        self.raw = RawNetlink(SPARE_TABLE)
        self.addCleanup(self.raw.close)
        self.raw.purge()
        self.addCleanup(self.raw.purge)
        # A route through the loopback interface: it needs no reachable
        # gateway, so the test does not depend on the host's own routing.
        self.oif = socket.if_nametoindex('lo')
        self.sink = NetlinkSink(table=SPARE_TABLE, protocol=OUR_PROTO,
                                oif_fn=lambda r: self.oif, timeout=2.0)
        self.sink.open()
        self.addCleanup(self.sink.close)

    def _settle(self, entry, limit=100):
        """Flush until the kernel has answered, or give up.

        The sink's socket is non-blocking by design, so an ack is not
        necessarily readable in the same flush that sent the request.
        Spinning without a pause would burn the budget before the kernel
        scheduled the reply and would make these tests fail on a loaded
        box for a reason that has nothing to do with the code.

        :param entry: the route to wait on.
        :param limit: maximum flushes.
        """
        for _i in range(limit):
            self.sink.flush()
            if entry.fib_state != FIB_STATE_PENDING:
                return
            time.sleep(0.01)

    def _install(self, prefix, distance=20):
        entry = route(prefix, nexthop='', distance=distance)
        self.sink.install(entry)
        self._settle(entry)
        return entry

    def _present(self, prefix, protocol=None, priority=None):
        parsed = parse_prefix(prefix)
        found = []
        for kroute in self.raw.routes():
            if kroute.prefix != parsed:
                continue
            if protocol is not None and kroute.protocol != protocol:
                continue
            if priority is not None and kroute.priority != priority:
                continue
            found.append(kroute)
        return found

    def test_an_installed_route_appears_in_a_dump_and_can_be_withdrawn(self):
        entry = self._install(TEST_PREFIX)
        self.assertEqual(entry.fib_state, FIB_STATE_INSTALLED,
                         'errno %d' % entry.fib_errno)
        found = self._present(TEST_PREFIX, protocol=OUR_PROTO)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].priority, 20)
        self.assertEqual(found[0].table, SPARE_TABLE)

        self.sink.withdraw(entry)
        self._settle(entry)
        self.assertEqual(entry.fib_state, FIB_STATE_NONE)
        self.assertEqual(self._present(TEST_PREFIX), [])

    def test_a_foreign_route_at_another_metric_survives_untouched(self):
        # The ownership claim, against a real kernel: our REPLACE cannot
        # reach a route whose priority differs, because the kernel's route
        # identity includes the priority.
        self.assertEqual(self.raw.add(TEST_PREFIX, FOREIGN_PROTO, 4242,
                                      oif=self.oif), 0)
        entry = self._install(TEST_PREFIX)
        self.assertEqual(entry.fib_state, FIB_STATE_INSTALLED,
                         'errno %d' % entry.fib_errno)

        foreign = self._present(TEST_PREFIX, protocol=FOREIGN_PROTO)
        self.assertEqual(len(foreign), 1)
        self.assertEqual(foreign[0].priority, 4242)
        self.assertEqual(len(self._present(TEST_PREFIX, protocol=OUR_PROTO)),
                         1)

    def test_a_stale_route_of_ours_is_removed_at_reconciliation(self):
        self.assertEqual(self.raw.add(OTHER_PREFIX, OUR_PROTO, 20,
                                      oif=self.oif), 0)
        self.assertEqual(len(self._present(OTHER_PREFIX)), 1)

        report = self.sink.reconcile([])
        self.assertEqual(report['removed'], 1)
        self.assertEqual(report['adopted'], 0)
        self.assertEqual(self._present(OTHER_PREFIX), [])

    def test_a_matching_route_of_ours_is_adopted_rather_than_removed(self):
        self.assertEqual(self.raw.add(TEST_PREFIX, OUR_PROTO, 20,
                                      oif=self.oif), 0)
        wanted = route(TEST_PREFIX, nexthop='', distance=20)
        report = self.sink.reconcile([wanted])
        self.assertEqual(report['adopted'], 1)
        self.assertEqual(report['removed'], 0)
        self.assertEqual(wanted.fib_state, FIB_STATE_INSTALLED)
        self.assertEqual(len(self._present(TEST_PREFIX)), 1)

    def test_a_foreign_route_is_left_alone_by_reconciliation(self):
        self.assertEqual(self.raw.add(TEST_PREFIX, FOREIGN_PROTO, 4242,
                                      oif=self.oif), 0)
        report = self.sink.reconcile([])
        self.assertEqual(report['ours'], 0)
        self.assertEqual(report['removed'], 0)
        self.assertEqual(len(self._present(TEST_PREFIX,
                                           protocol=FOREIGN_PROTO)), 1)

    def test_shutdown_removes_what_it_installed(self):
        self._install(TEST_PREFIX)
        self.assertEqual(len(self._present(TEST_PREFIX)), 1)
        self.assertEqual(self.sink.shutdown(), 1)
        self.assertEqual(self._present(TEST_PREFIX), [])

    def test_a_kernel_refusal_carries_the_kernels_reason(self):
        # E-7: with NETLINK_EXT_ACK the kernel says why. A gateway nothing
        # routes to, and no interface to reach it through, is refused with
        # "Nexthop has invalid gateway" (or similar) on 4.18; the exact
        # wording is the kernel's, so only its presence is asserted.
        sink = NetlinkSink(table=SPARE_TABLE, protocol=OUR_PROTO,
                           timeout=2.0)
        sink.open()
        self.addCleanup(sink.close)
        self.assertTrue(sink.stats()['ext-ack'])
        entry = route(TEST_PREFIX, nexthop='203.0.113.77')
        sink.install(entry)
        for _i in range(100):
            sink.flush()
            if entry.fib_state != FIB_STATE_PENDING:
                break
            time.sleep(0.01)
        self.assertEqual(entry.fib_state, FIB_STATE_ERROR)
        last = sink.stats()['last-error']
        self.assertEqual(last['errno'], entry.fib_errno)
        self.assertTrue(last['message'],
                        'errno %d came without a reason' % entry.fib_errno)

    def test_the_resolver_can_import_the_kernels_own_routes(self):
        self.raw.add(TEST_PREFIX, FOREIGN_PROTO, 11, oif=self.oif)
        resolver = Resolver(enabled=True, kernel_import=True)
        loaded = resolver.load_kernel(table=SPARE_TABLE)
        self.assertGreaterEqual(loaded, 1)
        found = resolver.resolve(AFI_IP, v4('198.51.100.7'))
        self.assertIsNotNone(found)
        self.assertEqual(found.source, 'kernel')


if __name__ == '__main__':
    unittest.main()
