# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The Linux forwarding plane: rtnetlink, hand-packed, queued and reconciled.

This is the one module in the engine that can change what a machine does
with a packet. Everything about it is shaped by that, starting with the
fact that constructing a :class:`NetlinkSink` opens nothing: the socket
appears in :meth:`NetlinkSink.open`, which the engine calls only when
``ip route install`` is true. A library that wrote the kernel routing table
because it was imported, or because an object was constructed, would be
indefensible; on a host already running another routing daemon it would be
an outage.

**Why the structs are hand-packed.** ``struct nlmsghdr``, ``struct rtmsg``
and ``struct rtattr`` are uapi types, CPython's ``socket`` module wraps none
of them, and the build hosts do not carry a kernel-headers package worth
reading them out of. So the layouts are written out here as ``struct``
format strings with the byte offsets spelled out, exactly as
:mod:`packets.routing.rtengine.transport.auth` does for ``tcp_md5sig``, and
for the same reason. The consequence is the same too: **a wrong offset does
not fail, it installs a different route than the one intended**, which is
why :func:`struct_sizes` exists and why the test suite asserts the bytes of
a request rather than only its effect.

**Why the address family numbers are ours and not the socket module's.**
``rtm_family`` is a Linux ABI field. ``AF_INET`` is 2 everywhere, but
``AF_INET6`` is 10 on Linux and 30 on Darwin, and this module builds and
parses messages on the development Mac in every test that does not need a
kernel. Using ``socket.AF_INET6`` would produce messages that pass the test
suite on macOS and address the wrong family on the target. The numbers below
are Linux's, written out, and :func:`supported` is what keeps them from ever
being handed to a non-Linux kernel.

**Ownership: why replacing is safe.** A kernel route's identity is
``(table, destination, tos, priority)``. We write ours with our own
``rtm_protocol`` -- 190 by default, clear of the block iproute2 reserves for
routing daemons -- *and* our own priority, taken from the configured
``ebgp``/``ibgp`` pair by the route's administrative distance. Together they
mean ``NLM_F_REPLACE`` can only ever replace a route we wrote: another
daemon's route for the same prefix has a different priority, so it is a
different route to the kernel and it survives untouched. The same pair is
what makes a delete safe, because a delete that named only the destination
would remove whichever route happened to be there.

The priority is also the sharpest edge in the module. Because it is part of
the identity, *changing* a route's metric does not replace anything: it
creates a second kernel route beside the first, and the first stays there
forever, which is a black hole with a lower or higher metric than the truth.
:meth:`NetlinkSink.install` therefore notices that the priority for a prefix
has changed and queues a delete of the old key behind the add of the new
one -- add first, so the prefix is never momentarily unrouted.

**Batching.** ``install`` and ``withdraw`` are called on the loop thread
from inside a selection batch, once per best-route change, potentially a
million times during a full-table load. They queue and return; they never
syscall. :meth:`NetlinkSink.flush` does a bounded amount of work per call --
send at most ``batch`` requests, then read at most ``ack_batch``
acknowledgements from a non-blocking socket -- so the loop keeps its
deadlines whatever the table size. A read that would block simply means the
acks have not arrived yet and the next flush will find them.

**Per-route errors, no rollback.** Every request carries a sequence number
and is remembered with the route it refers to, so an ``NLMSG_ERROR`` can be
attributed. Errno 0 in that message is the success ack; a negative errno is
that one route's failure. The route is marked ``fib-error`` with its errno
and retried with exponential backoff between 1 and 60 seconds, and nothing
else is touched: routes are independent, and a failed install leaves the
other 999,999 correct. A retry that succeeds clears the error.

**Reconciliation.** Routes in the kernel carrying our protocol id that we
did not write are ours from a previous run of this process.
:meth:`NetlinkSink.reconcile` dumps the table, keeps only those, adopts the
ones that match what we would install and deletes the rest. Adoption is not
an optimisation: re-installing an identical route is harmless, but *leaving*
a route that no longer matches is a black hole for the entire life of the
process, because nothing else will ever revisit it.

**Wiring it up.** :func:`make_sink` takes the core's ``ip.route``
configuration dict -- ``install``, ``table``, ``protocol``,
``priority.ebgp``, ``priority.ibgp``, ``retain-on-shutdown`` -- and returns
a configured, *unopened* sink::

    sink = make_sink(store.value(('ip', 'route'), {}))
    engine = Engine(config=document, sink=sink)
    # when ip.route.install is true, on the loop thread, before any offer:
    sink.open()
    sink.reconcile(engine.global_rib.routes(AFI_IP)
                   + engine.global_rib.routes(AFI_IP6))
    # then, from the selection batch or a periodic callback:
    sink.flush()
    # Engine.stop() already calls this:
    sink.shutdown(retain=...)

**Testing without a kernel.** Every syscall in the module goes through a
transport object with three methods -- ``send(bytes)``, ``recv(size)``,
``close()`` -- and an optional ``wait(timeout)`` used only by the blocking
dump and shutdown paths. Passing ``transport=`` to the constructor replaces
the socket entirely, so message construction, ack matching, backoff,
reconciliation and shutdown are all exercised on macOS against a fake that
records requests and replays canned replies. That is deliberate: the parts
of this module that can corrupt a forwarding table are the parts that do no
I/O at all.
"""

import errno
import logging
import os
import select
import socket
import struct
import sys
import time

from collections import OrderedDict

from packets.routing.rtengine.errors import UnavailableError
from packets.routing.rtengine.fib.sink import FibSink
from packets.routing.rtengine.health import DEGRADED, OK
from packets.routing.rtengine.rib.prefix import AFI_IP, AFI_IP6, Prefix
from packets.routing.rtengine.rib.table import (DEFAULT_ADMIN_DISTANCE,
                                                FIB_STATE_ERROR,
                                                FIB_STATE_INSTALLED,
                                                FIB_STATE_NONE,
                                                FIB_STATE_PENDING)

_log = logging.getLogger('packets.rtengine.fib.netlink')

__all__ = ['NETLINK_ROUTE', 'NLMSG_ERROR', 'NLMSG_DONE', 'RTM_NEWROUTE',
           'RTM_DELROUTE', 'RTM_GETROUTE', 'NLM_F_REQUEST', 'NLM_F_ACK',
           'NLM_F_CREATE', 'NLM_F_REPLACE', 'NLM_F_EXCL', 'NLM_F_DUMP',
           'RTA_DST', 'RTA_OIF', 'RTA_GATEWAY', 'RTA_PRIORITY', 'RTA_TABLE',
           'RT_TABLE_UNSPEC', 'RT_TABLE_MAIN', 'RTN_UNICAST',
           'RT_SCOPE_UNIVERSE', 'RT_SCOPE_NOWHERE', 'RTPROT_UNSPEC',
           'RTPROT_KERNEL', 'RTPROT_BOOT', 'RTPROT_STATIC',
           'DEFAULT_PROTOCOL', 'DEFAULT_PRIORITY_EBGP',
           'DEFAULT_PRIORITY_IBGP', 'RETRY_MIN_S', 'RETRY_MAX_S',
           'SIZEOF_NLMSGHDR', 'SIZEOF_RTMSG', 'SIZEOF_RTATTR',
           'NetlinkUnsupported', 'KernelRoute', 'NetlinkTransport',
           'NetlinkSink', 'make_sink', 'supported', 'privileged',
           'capabilities', 'reset_probe_cache', 'nlmsg_align', 'rta_align',
           'pack_attr', 'pack_u32_attr', 'parse_attrs', 'parse_messages',
           'parse_ext_ack',
           'parse_route', 'dump_routes', 'kernel_routes', 'struct_sizes']


# --- kernel ABI numbers -----------------------------------------------------
#
# From include/uapi/linux/{netlink,rtnetlink}.h. Written out rather than
# imported because there is nothing to import them from, and probed rather
# than assumed at the one point where it matters -- see supported().

NETLINK_ROUTE = 0                # the rtnetlink protocol family

#: sizeof(struct nlmsghdr): u32 len, u16 type, u16 flags, u32 seq, u32 pid.
SIZEOF_NLMSGHDR = 16
#: sizeof(struct rtmsg): eight u8 then a u32 of flags.
SIZEOF_RTMSG = 12
#: sizeof(struct rtattr): u16 len (header included), u16 type.
SIZEOF_RTATTR = 4

# Netlink aligns every message and every attribute to four bytes, and the
# padding is *not* counted in the length fields of an attribute but *is*
# counted in the length of a message. Getting that asymmetry wrong shifts
# every attribute after the first by a byte or two, which the kernel reads
# as a differently typed attribute rather than as an error.
NLMSG_ALIGNTO = 4
RTA_ALIGNTO = 4

NLMSG_NOOP = 1                   # ignore this message
NLMSG_ERROR = 2                  # an errno, or 0 -- the ack we ask for
NLMSG_DONE = 3                   # end of a multipart dump
NLMSG_OVERRUN = 4                # the socket lost data

RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26

NLM_F_REQUEST = 0x01             # this is a request
NLM_F_MULTI = 0x02               # part of a multipart message
NLM_F_ACK = 0x04                 # reply with NLMSG_ERROR even on success
NLM_F_ECHO = 0x08                # echo the request back
NLM_F_DUMP_INTR = 0x10           # set on a dump that raced a table change

# GET-request modifiers.
NLM_F_ROOT = 0x100               # return the whole table, not one entry
NLM_F_MATCH = 0x200              # return every entry matching the criteria
NLM_F_ATOMIC = 0x400
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

# NEW-request modifiers. They reuse the same bit values as the GET
# modifiers above, which is not a collision: the kernel interprets the high
# flag bits according to the message type, so 0x100 means "dump from the
# root" on RTM_GETROUTE and "replace an existing entry" on RTM_NEWROUTE.
# The two sets must never be mixed in one message.
NLM_F_REPLACE = 0x100
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLM_F_APPEND = 0x800

# The same high bits once more, on an NLMSG_ERROR (E-7): CAPPED says the
# echoed request was cut to its header, ACK_TLVS that extended-ack
# attributes follow it. Linux 4.12+, so present on the 4.18 target.
NLM_F_CAPPED = 0x100
NLM_F_ACK_TLVS = 0x200

NLMSGERR_ATTR_MSG = 1            # NUL-terminated text: why it was refused
NLMSGERR_ATTR_OFFS = 2           # u32 offset of the offending attribute

# Socket options, at level SOL_NETLINK. EXT_ACK asks the kernel to say *why*
# a request failed -- "Nexthop has invalid gateway" rather than a bare
# EINVAL -- and CAP_ACK stops it echoing the whole request back with every
# error, which during a failing full-table install is most of the receive
# buffer.
SOL_NETLINK = 270
NETLINK_CAP_ACK = 10
NETLINK_EXT_ACK = 11

#: Seconds between flushes while requests are written but not yet
#: acknowledged. rtnetlink answers inside the sendmsg, so an ack still
#: missing after one poll is usually one the receive buffer dropped.
ACK_POLL_S = 0.01

# rtattr types for a route message (enum rtattr_type_t). Only the ones this
# module writes or reads are listed; an unknown type in a dump is kept as
# raw bytes rather than dropped.
RTA_UNSPEC = 0
RTA_DST = 1
RTA_SRC = 2
RTA_IIF = 3
RTA_OIF = 4                      # u32 interface index
RTA_GATEWAY = 5
RTA_PRIORITY = 6                 # u32; the "metric" of `ip route`
RTA_PREFSRC = 7
RTA_METRICS = 8
RTA_MULTIPATH = 9
RTA_FLOW = 11
RTA_CACHEINFO = 12
RTA_TABLE = 15                   # u32; the table id when it exceeds a byte

RT_TABLE_UNSPEC = 0
RT_TABLE_COMPAT = 252
RT_TABLE_DEFAULT = 253
RT_TABLE_MAIN = 254
RT_TABLE_LOCAL = 255

RTN_UNSPEC = 0
RTN_UNICAST = 1
RTN_LOCAL = 2
RTN_BROADCAST = 3
RTN_BLACKHOLE = 6
RTN_UNREACHABLE = 7

RT_SCOPE_UNIVERSE = 0            # a gateway route: reachable from anywhere
RT_SCOPE_SITE = 200
RT_SCOPE_LINK = 253
RT_SCOPE_HOST = 254
RT_SCOPE_NOWHERE = 255           # on a delete: "match whatever scope it has"

RTPROT_UNSPEC = 0
RTPROT_REDIRECT = 1
RTPROT_KERNEL = 2                # the kernel installed it itself
RTPROT_BOOT = 3                  # what plain `ip route add` writes
RTPROT_STATIC = 4                # an administrator, via a config file
RTPROT_RA = 9
RTPROT_DHCP = 16

#: Our own ``rtm_protocol``. 190 is free on every deployment target checked
#: and clear of the block iproute2 reserves for routing daemons (186 bgp,
#: 187 isis, 188 ospf, 189 rip, 192 eigrp). It matches the default in
#: ``config.py``; changing one without the other changes which routes the
#: sink believes are its own.
DEFAULT_PROTOCOL = 190

#: Kernel priorities for our routes, matching ``ip.route.priority`` in
#: ``config.py``. They double as the Cisco-conventional administrative
#: distances for external and internal BGP, which is what lets the mapping
#: below be expressed as distance -> priority without naming BGP.
DEFAULT_PRIORITY_EBGP = 20
DEFAULT_PRIORITY_IBGP = 200

#: Retry bounds for a route the kernel rejected. One second is short enough
#: that a transient rejection (the next-hop's interface still coming up)
#: heals before anyone notices, and a minute is long enough that a
#: permanently broken route costs one syscall a minute rather than a
#: syscall a flush.
RETRY_MIN_S = 1.0
RETRY_MAX_S = 60.0

#: CAP_NET_ADMIN's bit position in the capability masks of
#: ``/proc/self/status``. Reading it there is the only way to answer "can we
#: write routes?" from the standard library: ``capget(2)`` is not wrapped by
#: CPython and this module does not use ctypes.
CAP_NET_ADMIN = 12

# Linux address family numbers, deliberately not socket.AF_*. AF_INET is 2
# on every platform, but AF_INET6 is 10 on Linux and 30 on Darwin and the
# BSDs, and rtm_family is a Linux ABI field that this module also packs on
# the development host. See the module docstring.
AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 10

_AFI_TO_AF = {AFI_IP: AF_INET, AFI_IP6: AF_INET6}
_AF_TO_AFI = {AF_INET: AFI_IP, AF_INET6: AFI_IP6}
_AF_ADDR_LEN = {AF_INET: 4, AF_INET6: 16}

# '=' is native byte order with standard sizes and no alignment padding.
# Netlink is native-endian by design (a message never leaves the host), and
# suppressing the padding is what makes the offsets in the comments above
# the literal offsets the kernel reads.
_NLMSGHDR = struct.Struct('=IHHII')
_RTMSG = struct.Struct('=BBBBBBBBI')
_RTATTR = struct.Struct('=HH')
_S32 = struct.Struct('=i')
_U32 = struct.Struct('=I')

# A netlink datagram is not reassembled: a receive buffer smaller than the
# datagram loses the tail and sets MSG_TRUNC. 64 KiB holds any ack and any
# single dump chunk the kernel emits.
DEFAULT_RECV_SIZE = 65536

#: Seconds a blocking dump or a shutdown drain waits for the kernel. Both
#: run outside the event loop -- at start and at stop -- so blocking is
#: correct there and nowhere else.
DEFAULT_TIMEOUT_S = 5.0

# The errno values are read through getattr with the Linux number as the
# fallback, the way auth.py does it: the module is imported on macOS, where
# a few of these differ, and the ones that travel in a netlink ack are the
# kernel's numbers rather than the local libc's.
ENOBUFS = getattr(errno, 'ENOBUFS', 105)
EEXIST = getattr(errno, 'EEXIST', 17)
ESRCH = getattr(errno, 'ESRCH', 3)
ENOENT = getattr(errno, 'ENOENT', 2)
ETIMEDOUT = getattr(errno, 'ETIMEDOUT', 110)
EAFNOSUPPORT = getattr(errno, 'EAFNOSUPPORT', 97)

# errnos that mean "the read would block", i.e. the acks are not here yet.
_WOULD_BLOCK = frozenset([
    getattr(errno, 'EAGAIN', 11),
    getattr(errno, 'EWOULDBLOCK', 11),
    getattr(errno, 'EINTR', 4),
])

# A delete that reports "no such route" has achieved what it was for. Both
# spellings occur: fib_table_delete answers ESRCH, and a missing table
# answers ENOENT.
_ALREADY_GONE = frozenset([ESRCH, ENOENT])

_monotonic = time.monotonic


class NetlinkUnsupported(UnavailableError):
    """This host cannot write routes, so the sink refuses to open.

    Deliberately an :class:`~packets.routing.rtengine.errors.UnavailableError`
    rather than a new top-level error: from an operator's point of view the
    forwarding plane is unavailable, and the REST layer's existing mapping
    already says so. It is raised from :meth:`NetlinkSink.open` and never at
    import time, so the module is importable on macOS -- which is where most
    of it is tested.
    """

    error = 'Unavailable'


# --- the wire layer ---------------------------------------------------------


def nlmsg_align(length):
    """Round a message length up to the netlink alignment.

    :param length: the unaligned length in bytes.
    :return: the length rounded up to a multiple of 4.
    """
    return (length + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)


def rta_align(length):
    """Round an attribute length up to the rtattr alignment.

    :param length: the unaligned length in bytes.
    :return: the length rounded up to a multiple of 4.
    """
    return (length + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1)


def pack_attr(attr_type, payload):
    """Pack one ``struct rtattr`` and its payload, with padding.

    ``rta_len`` counts the 4-byte header and the payload but **not** the
    padding that follows, while the enclosing message length counts
    everything. That asymmetry is the classic netlink bug: a writer that
    puts the padded length in ``rta_len`` makes the kernel read the next
    attribute's header from inside the padding.

    :param attr_type: an ``RTA_*`` value.
    :param payload: the attribute body as bytes.
    :return: header, payload and up to three padding bytes.
    """
    length = SIZEOF_RTATTR + len(payload)
    pad = rta_align(length) - length
    return _RTATTR.pack(length, attr_type) + payload + (b'\x00' * pad)


def pack_u32_attr(attr_type, value):
    """Pack a four-byte attribute in host byte order.

    ``RTA_OIF``, ``RTA_PRIORITY`` and ``RTA_TABLE`` are kernel-internal
    numbers and travel in native order, unlike the address attributes,
    which are already network order because they came off a wire.

    :param attr_type: an ``RTA_*`` value.
    :param value: the unsigned 32-bit value.
    :return: an eight-byte attribute.
    """
    return pack_attr(attr_type, _U32.pack(int(value) & 0xffffffff))


def pack_message(msg_type, flags, seq, portid, body):
    """Pack an ``nlmsghdr`` around an already-built body.

    :param msg_type: ``RTM_*``.
    :param flags: the ``NLM_F_*`` bits.
    :param seq: the request's sequence number; the ack carries it back.
    :param portid: the sending socket's port id, 0 for "the kernel knows".
    :param body: the ``rtmsg`` and its attributes.
    :return: the complete message, padded to the netlink alignment.
    """
    length = SIZEOF_NLMSGHDR + len(body)
    pad = nlmsg_align(length) - length
    return (_NLMSGHDR.pack(length, msg_type, flags, seq, portid) + body
            + (b'\x00' * pad))


def parse_messages(buf):
    """Split a received buffer into individual netlink messages.

    A single ``recv`` can return several messages, and a dump returns many.
    A trailing fragment too short to be a message is dropped rather than
    raising: that is what a truncated datagram looks like, and the caller
    recovers by reading again or by timing out, not by crashing the loop.

    :param buf: the bytes returned by one receive.
    :return: a list of ``(type, flags, seq, portid, body)`` tuples, where
        the body excludes the 16-byte header.
    """
    out = []
    offset = 0
    total = len(buf)
    while offset + SIZEOF_NLMSGHDR <= total:
        length, msg_type, flags, seq, portid = _NLMSGHDR.unpack_from(buf,
                                                                     offset)
        if length < SIZEOF_NLMSGHDR or offset + length > total:
            break
        out.append((msg_type, flags, seq, portid,
                    buf[offset + SIZEOF_NLMSGHDR:offset + length]))
        offset += nlmsg_align(length)
    return out


def parse_attrs(buf, offset=0):
    """Parse a run of ``rtattr`` TLVs into ``{type: payload}``.

    Duplicate types keep the first occurrence, which is what the kernel
    does for the attributes this module reads. A malformed length ends the
    parse instead of looping: every byte count here came off a socket and
    none of it is trusted.

    :param buf: the message body.
    :param offset: where the attributes start, past the fixed header.
    :return: a dict of attribute type to raw payload bytes.
    """
    attrs = {}
    total = len(buf)
    while offset + SIZEOF_RTATTR <= total:
        length, attr_type = _RTATTR.unpack_from(buf, offset)
        if length < SIZEOF_RTATTR or offset + length > total:
            break
        if attr_type not in attrs:
            attrs[attr_type] = buf[offset + SIZEOF_RTATTR:offset + length]
        offset += rta_align(length)
    return attrs


def parse_ext_ack(body, flags):
    """Return the kernel's text from an extended ack, or None.

    The layout (``struct nlmsgerr`` plus TLVs) is: a 4-byte errno, the
    request's own header -- and the rest of the request unless
    ``NLM_F_CAPPED`` -- and then, when ``NLM_F_ACK_TLVS`` is set, the
    ``NLMSGERR_ATTR_*`` attributes. Every length is checked against the
    buffer; a reply that does not fit is reported as having no text.

    :param body: an NLMSG_ERROR body, the 16-byte header excluded.
    :param flags: that message's header flags.
    :return: the message, decoded, or None.
    """
    if not flags & NLM_F_ACK_TLVS or len(body) < 4 + SIZEOF_NLMSGHDR:
        return None
    if flags & NLM_F_CAPPED:
        offset = 4 + SIZEOF_NLMSGHDR
    else:
        echoed = _NLMSGHDR.unpack_from(body, 4)[0]
        if echoed < SIZEOF_NLMSGHDR:
            return None
        offset = 4 + nlmsg_align(echoed)
    if offset >= len(body):
        return None
    raw = parse_attrs(body, offset).get(NLMSGERR_ATTR_MSG)
    if not raw:
        return None
    text = raw.split(b'\0', 1)[0].decode('utf-8', 'replace').strip()
    return text or None


def struct_sizes():
    """Return the packed sizes of the three structures, for a test.

    The whole module rests on these three numbers being 16, 12 and 4. A
    format string that quietly grew alignment padding would produce
    messages the kernel misreads rather than rejects, so the sizes are
    exported to be asserted rather than trusted.

    :return: ``{'nlmsghdr': 16, 'rtmsg': 12, 'rtattr': 4}``.
    """
    return {
        'nlmsghdr': _NLMSGHDR.size,
        'rtmsg': _RTMSG.size,
        'rtattr': _RTATTR.size,
    }


class KernelRoute(object):
    """One route as the kernel described it in a dump.

    Not a :class:`~packets.routing.rtengine.rib.table.Route`: it carries
    what the kernel said and nothing the engine believes, and it is the
    input to reconciliation and to the resolver's read-only import.

    :param family: the ``rtm_family`` value.
    :param dst_len: the prefix length.
    :param table: the table id, from ``RTA_TABLE`` when present and from
        ``rtm_table`` otherwise.
    :param protocol: ``rtm_protocol``; our own id identifies our routes.
    :param scope: ``rtm_scope``.
    :param rtype: ``rtm_type``; ``RTN_UNICAST`` is the only one we write.
    :param flags: ``rtm_flags``.
    :param dst: the destination address, padded to the family width.
    :param gateway: the next-hop address, or empty for none.
    :param oif: the outgoing interface index, or 0.
    :param priority: ``RTA_PRIORITY``, 0 when absent.
    """

    __slots__ = ('family', 'dst_len', 'table', 'protocol', 'scope', 'rtype',
                 'flags', 'dst', 'gateway', 'oif', 'priority', 'prefix')

    def __init__(self, family, dst_len, table, protocol, scope, rtype,
                 flags, dst, gateway, oif, priority):
        self.family = family
        self.dst_len = dst_len
        self.table = table
        self.protocol = protocol
        self.scope = scope
        self.rtype = rtype
        self.flags = flags
        self.dst = dst
        self.gateway = gateway
        self.oif = oif
        self.priority = priority
        afi = _AF_TO_AFI.get(family)
        # A family the engine has no AFI for -- AF_MPLS, AF_BRIDGE -- keeps
        # its raw fields and gets no Prefix, so a caller filtering on
        # `prefix is None` drops it without having to know the family
        # numbers.
        self.prefix = Prefix(afi, dst_len, dst) if afi is not None else None

    def as_dict(self):
        """Render for show output and for a test's failure message.

        :return: a dict of plain types.
        """
        return {
            'prefix': self.prefix.to_str() if self.prefix is not None
            else '',
            'table': self.table,
            'protocol': self.protocol,
            'type': self.rtype,
            'priority': self.priority,
            'oif': self.oif,
            'gateway': _addr_text(self.family, self.gateway),
        }

    def __repr__(self):
        return '<KernelRoute %s via %s table=%d proto=%d metric=%d>' % (
            self.prefix.to_str() if self.prefix is not None else '?',
            _addr_text(self.family, self.gateway) or 'dev',
            self.table, self.protocol, self.priority)


def parse_route(body):
    """Parse the body of an ``RTM_NEWROUTE`` message.

    :param body: the message body, ``rtmsg`` followed by attributes.
    :return: a :class:`KernelRoute`, or None if the body is too short to
        hold an ``rtmsg`` at all.
    """
    if len(body) < SIZEOF_RTMSG:
        return None
    (family, dst_len, _src_len, _tos, table, protocol, scope, rtype,
     flags) = _RTMSG.unpack_from(body, 0)
    attrs = parse_attrs(body, SIZEOF_RTMSG)

    width = _AF_ADDR_LEN.get(family, 0)
    dst = attrs.get(RTA_DST, b'')
    if width:
        # A default route carries no RTA_DST at all, and some families
        # report a truncated destination. Padding to the family width is
        # what lets a Prefix be built without a special case per length.
        dst = (dst + b'\x00' * width)[:width]
    gateway = attrs.get(RTA_GATEWAY, b'')
    oif = _attr_u32(attrs, RTA_OIF)
    priority = _attr_u32(attrs, RTA_PRIORITY)
    if RTA_TABLE in attrs:
        # RTA_TABLE wins over rtm_table whenever it is present: rtm_table
        # is a byte and cannot express a table above 255, so the kernel
        # reports RT_TABLE_COMPAT (252) there and the real id here.
        table = _attr_u32(attrs, RTA_TABLE, table)
    return KernelRoute(family, dst_len, table, protocol, scope, rtype,
                       flags, dst, gateway, oif, priority)


def _attr_u32(attrs, attr_type, default=0):
    """Read a four-byte attribute, tolerating a short or absent one.

    Length-checked rather than unpacked directly because every byte here
    came off a socket: a truncated attribute must not take out the dump.

    :param attrs: the parsed attribute dict.
    :param attr_type: the ``RTA_*`` wanted.
    :param default: what to return when it is missing or malformed.
    :return: the value, or ``default``.
    """
    payload = attrs.get(attr_type)
    if payload is None or len(payload) < 4:
        return default
    return _U32.unpack_from(payload, 0)[0]


def _addr_text(family, packed):
    """Render a packed address for show output, tolerating anything.

    :param family: the netlink ``AF_*`` number.
    :param packed: the address bytes, possibly empty.
    :return: the text form, or '' when there is no address.
    """
    if not packed:
        return ''
    try:
        if family == AF_INET and len(packed) == 4:
            return socket.inet_ntop(socket.AF_INET, packed)
        if family == AF_INET6 and len(packed) == 16:
            return socket.inet_ntop(socket.AF_INET6, packed)
    except (OSError, ValueError):
        pass
    return repr(packed)


# --- capability probing -----------------------------------------------------


_caps = None


def reset_probe_cache():
    """Forget the cached capability probe.

    Test support only, exactly as in
    :mod:`packets.routing.rtengine.transport.auth`: the answer cannot
    change inside one process, but a test that wants both branches of a
    caller needs to be able to re-probe.
    """
    global _caps
    _caps = None


def supported():
    """Report whether this host can speak rtnetlink at all.

    Two questions, both cheap and neither of them a syscall: is this Linux,
    and does the running CPython know ``AF_NETLINK``. The second is not
    redundant -- a CPython built against headers without netlink omits the
    constant, and referring to it would raise ``AttributeError`` at the
    worst possible moment.

    :return: True on a Linux host whose socket module has AF_NETLINK.
    """
    return bool(sys.platform.startswith('linux')
                and hasattr(socket, 'AF_NETLINK'))


def privileged():
    """Report whether this process could actually write routes.

    :return: True when the process has CAP_NET_ADMIN or is root.
    """
    return bool(capabilities().get('privileged'))


def capabilities(refresh=False):
    """Probe, once, what this host and process can do with rtnetlink.

    A dict rather than a bool because the engine surfaces this in health
    and an operator who turned ``ip route install`` on and got nothing
    needs to be told *which* of the three possible reasons applies: the
    wrong platform, a kernel without netlink, or a process without
    CAP_NET_ADMIN. The probe opens and immediately closes a netlink socket,
    which is harmless -- binding one neither joins a multicast group nor
    changes any state -- and is the only way to distinguish a kernel
    without ``NETLINK_ROUTE`` from a container that forbids the family.

    ``privileged`` is answered from ``CapEff`` in ``/proc/self/status``,
    falling back to a euid test. Both are needed: root in a container
    without CAP_NET_ADMIN cannot write routes, and a non-root process that
    was granted the capability can.

    :param refresh: re-run the probe instead of returning the cached
        answer.
    :return: ``{'supported': bool, 'privileged': bool, 'reason': str,
        'platform': str, 'euid': int}``. ``reason`` is ``'ok'`` when
        everything is available.
    """
    global _caps
    if _caps is None or refresh:
        _caps = _probe()
        _log.debug('netlink capabilities probed: %s', _caps)
    return dict(_caps)


def _probe():
    """Run the capability probe once. See :func:`capabilities`."""
    euid = os.geteuid() if hasattr(os, 'geteuid') else -1
    answer = {'supported': False, 'privileged': False, 'platform':
              sys.platform, 'euid': euid, 'reason': 'ok'}
    if not sys.platform.startswith('linux'):
        answer['reason'] = 'not-linux (%s)' % sys.platform
        return answer
    if not hasattr(socket, 'AF_NETLINK'):
        answer['reason'] = 'this python has no AF_NETLINK'
        return answer
    sock = None
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                             NETLINK_ROUTE)
    except OSError as exc:
        answer['reason'] = 'netlink socket refused: %s' % exc.strerror
        return answer
    finally:
        if sock is not None:
            sock.close()
    answer['supported'] = True
    if _has_cap_net_admin() or euid == 0:
        answer['privileged'] = True
    else:
        answer['reason'] = 'no CAP_NET_ADMIN (euid %d)' % euid
    return answer


def _has_cap_net_admin():
    """Read CAP_NET_ADMIN out of ``/proc/self/status``.

    :return: True when the effective capability set contains it.
    """
    try:
        with open('/proc/self/status', 'r') as handle:
            for line in handle:
                if line.startswith('CapEff:'):
                    return bool(int(line.split()[1], 16)
                                & (1 << CAP_NET_ADMIN))
    except (OSError, IOError, ValueError, IndexError):
        # No procfs, an unreadable one, or a format we do not recognise.
        # The euid test in _probe() is the fallback; claiming the
        # capability here would turn a clear "not privileged" into a
        # confusing EPERM per route.
        return False
    return False


# --- the socket, and the seam a test replaces -------------------------------


class NetlinkTransport(object):
    """A non-blocking ``NETLINK_ROUTE`` socket behind three methods.

    The seam the whole test strategy depends on. Anything with ``send``,
    ``recv`` and ``close`` can stand in for this, and a fake that records
    requests and replays canned replies exercises every line of the sink
    that is not a syscall. ``wait`` is optional in a substitute: only the
    two blocking paths (a dump and the shutdown drain) call it, and they
    treat its absence as "poll instead".

    :param sock: an already-created socket, for a caller that wants to set
        its own buffer sizes.
    """

    __slots__ = ('_sock', 'port_id', 'ext_ack')

    def __init__(self, sock):
        self._sock = sock
        self.port_id = 0
        # Whether the kernel agreed to explain its errors (E-7).
        self.ext_ack = False

    @classmethod
    def open(cls, sndbuf=0, rcvbuf=0):
        """Create, bind and return a non-blocking rtnetlink transport.

        The socket is bound with a zero port id so the kernel assigns one;
        binding explicitly to ``os.getpid()`` is the traditional idiom and
        is wrong in any process that opens two netlink sockets, because the
        second bind then fails with EADDRINUSE.

        No multicast group is joined. We want acks for our own requests and
        nothing else, and a subscriber to ``RTNLGRP_IPV4_ROUTE`` on a busy
        box spends its life draining notifications it does not read.

        :param sndbuf: ``SO_SNDBUF`` override, or 0 for the default.
        :param rcvbuf: ``SO_RCVBUF`` override, or 0 for the default. Worth
            raising for a large table: an overflowing receive buffer costs
            acks, which this module recovers from by retrying, but slowly.
        :return: an open :class:`NetlinkTransport`.
        :raises NetlinkUnsupported: this host has no netlink.
        :raises OSError: the kernel refused the socket or the bind.
        """
        if not supported():
            raise NetlinkUnsupported(
                'rtnetlink is Linux-only: %s'
                % capabilities().get('reason', 'unsupported platform'))
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                             NETLINK_ROUTE)
        try:
            if sndbuf:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
            if rcvbuf:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
            sock.bind((0, 0))
            sock.setblocking(False)
        except OSError:
            sock.close()
            raise
        transport = cls(sock)
        transport.port_id = sock.getsockname()[0]
        # Best effort, both: a kernel without them still answers with an
        # errno, which is what this module ran on before they existed.
        for option in (NETLINK_CAP_ACK, NETLINK_EXT_ACK):
            try:
                sock.setsockopt(SOL_NETLINK, option, 1)
            except OSError:
                continue
            if option == NETLINK_EXT_ACK:
                transport.ext_ack = True
        return transport

    def send(self, data):
        """Send one request.

        :param data: the complete netlink message.
        :return: the number of bytes sent.
        :raises OSError: EAGAIN when the send buffer is full, which the
            sink treats as backpressure rather than as an error.
        """
        return self._sock.send(data)

    def recv(self, size):
        """Read whatever is waiting, without blocking.

        :param size: the buffer size; a datagram longer than this loses
            its tail, so it must be large.
        :return: the bytes read.
        :raises OSError: EAGAIN when nothing is waiting.
        """
        return self._sock.recv(size)

    def wait(self, timeout):
        """Block until the socket is readable or the timeout expires.

        Only the start-up dump and the shutdown drain use this; the flush
        path never blocks.

        :param timeout: seconds to wait.
        :return: True if the socket became readable.
        """
        try:
            readable, _w, _x = select.select([self._sock], [], [], timeout)
        except (OSError, ValueError):
            return False
        return bool(readable)

    def fileno(self):
        """Return the socket's descriptor, for an external poller.

        :return: the file descriptor, or -1 once closed.
        """
        try:
            return self._sock.fileno()
        except (OSError, ValueError):
            return -1

    def close(self):
        """Close the socket. Idempotent."""
        try:
            self._sock.close()
        except OSError:
            pass


# --- dumps ------------------------------------------------------------------


def dump_routes(transport, family=AF_UNSPEC, seq=1, timeout=None,
                recv_size=DEFAULT_RECV_SIZE):
    """Run one ``RTM_GETROUTE|NLM_F_DUMP`` and parse every reply.

    Blocking, and deliberately so: the two callers are start-up
    reconciliation and the resolver's one-shot import, neither of which
    runs inside the event loop. A dump of a large table arrives as many
    multipart messages terminated by ``NLMSG_DONE``, so this reads until it
    sees that marker rather than until the socket is empty -- a dump that
    stopped at the first empty read would silently return a prefix of the
    table and reconciliation would then delete routes it simply had not
    seen yet.

    :param transport: anything with ``send``/``recv``; ``wait`` is used
        when present, and a plain poll is used when it is not.
    :param family: ``AF_UNSPEC`` for every family, or one of ``AF_INET``
        and ``AF_INET6``. The kernel treats it as a hint and may answer
        with more than was asked for, so callers filter anyway.
    :param seq: the sequence number to use; replies carrying another are
        ignored, which is what keeps a late ack from a previous request
        out of the result.
    :param timeout: seconds to wait for the dump to complete.
    :param recv_size: receive buffer size per read.
    :return: a list of :class:`KernelRoute`.
    :raises OSError: the kernel refused the dump, or it did not complete
        within the timeout.
    """
    if timeout is None:
        timeout = DEFAULT_TIMEOUT_S
    body = _RTMSG.pack(family, 0, 0, 0, 0, 0, 0, 0, 0)
    transport.send(pack_message(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP,
                                seq, 0, body))

    waiter = getattr(transport, 'wait', None)
    deadline = _monotonic() + timeout
    routes = []
    while True:
        data = None
        try:
            data = transport.recv(recv_size)
        except OSError as exc:
            if exc.errno not in _WOULD_BLOCK:
                raise
        if data:
            for msg_type, _flags, msg_seq, _pid, msg in parse_messages(data):
                if msg_seq != seq:
                    continue
                if msg_type == NLMSG_DONE:
                    return routes
                if msg_type == NLMSG_ERROR:
                    code = _S32.unpack_from(msg, 0)[0] if len(msg) >= 4 else 0
                    if code:
                        raise OSError(-code, 'route dump refused: %s'
                                      % os.strerror(-code))
                    # errno 0 on a dump is an ack for the request itself,
                    # which only arrives if NLM_F_ACK was set; harmless.
                    continue
                if msg_type in (RTM_NEWROUTE, RTM_DELROUTE):
                    parsed = parse_route(msg)
                    if parsed is not None:
                        routes.append(parsed)
            continue
        remaining = deadline - _monotonic()
        if remaining <= 0:
            raise OSError(ETIMEDOUT,
                          'route dump did not complete within %.1fs'
                          % timeout)
        if waiter is not None:
            waiter(min(remaining, 0.25))
        else:
            time.sleep(min(remaining, 0.005))


def kernel_routes(table=None, protocol=None, unicast_only=True,
                  family=AF_UNSPEC, transport=None, timeout=None):
    """Read the kernel's routes. Read-only, Linux-only, one shot.

    The entry point the resolver's ``ip.route.kernel-import`` uses, kept
    here so there is exactly one dump parser in the engine. It opens its
    own transport when none is given and always closes it: a read-only
    consumer has no reason to hold a netlink socket open between imports.

    :param table: keep only this table id, or None for every table.
    :param protocol: keep only routes carrying this ``rtm_protocol``.
    :param unicast_only: drop anything that is not ``RTN_UNICAST`` --
        broadcast, local and unreachable entries are not next-hops and the
        local table is full of them.
    :param family: ``AF_UNSPEC``, ``AF_INET`` or ``AF_INET6``.
    :param transport: a transport to use instead of opening one.
    :param timeout: seconds to wait for the dump.
    :return: a list of :class:`KernelRoute`.
    :raises NetlinkUnsupported: this host has no netlink and no transport
        was supplied.
    :raises OSError: the dump failed.
    """
    owned = None
    if transport is None:
        owned = transport = NetlinkTransport.open()
    try:
        routes = dump_routes(transport, family=family, timeout=timeout)
    finally:
        if owned is not None:
            owned.close()
    kept = []
    for route in routes:
        if route.prefix is None:
            continue
        if unicast_only and route.rtype != RTN_UNICAST:
            continue
        if table is not None and route.table != table:
            continue
        if protocol is not None and route.protocol != protocol:
            continue
        kept.append(route)
    return kept


# --- the sink ---------------------------------------------------------------

OP_ADD = 'add'
OP_DEL = 'del'

ST_QUEUED = 'queued'
ST_SENT = 'sent'
ST_INSTALLED = 'installed'
ST_ERROR = 'error'
ST_RETRY = 'retry'


class _Entry(object):
    """Everything the sink believes about one kernel route key.

    One object per ``(prefix, priority)`` -- which is the kernel's own
    notion of route identity minus the table and tos, both of which are
    constant for a sink -- moved between the queue, the in-flight map and
    the retry map rather than copied, so there is exactly one place to look
    for the state of a route.

    :param key: the ``(Prefix, priority)`` identity.
    :param kind: ``OP_ADD`` or ``OP_DEL``.
    :param route: the engine's Route, or None for a stale kernel route
        being cleaned up at start-up.
    :param gateway: the packed next-hop, or empty.
    :param priority: the kernel priority this route is written with.
    :param oif: the outgoing interface index, or 0 for none.
    :param family: the netlink address family of the destination.
    :param dst_len: the prefix length.
    :param dst: the packed destination address.
    """

    __slots__ = ('key', 'kind', 'route', 'gateway', 'priority', 'oif',
                 'family', 'dst_len', 'dst', 'state', 'seq', 'sent_at',
                 'attempts', 'due', 'errno', 'written')

    def __init__(self, key, kind, route, gateway, priority, oif, family,
                 dst_len, dst):
        self.key = key
        self.kind = kind
        self.route = route
        self.gateway = gateway
        self.priority = priority
        self.oif = oif
        self.family = family
        self.dst_len = dst_len
        self.dst = dst
        self.state = ST_QUEUED
        self.seq = 0
        self.sent_at = 0.0
        self.attempts = 0
        self.due = 0.0
        self.errno = 0
        # Whether an add for this key has ever reached the kernel. It is
        # what decides, when the key is retired, between "forget it" and
        # "the kernel has it and must be told".
        self.written = False

    def matches(self, gateway, oif):
        """Return whether an installed entry already says what we want.

        The priority is not compared because it is part of the key.

        :param gateway: the packed next-hop wanted.
        :param oif: the interface index wanted.
        :return: True when nothing needs to be written.
        """
        return self.gateway == gateway and self.oif == oif

    def __repr__(self):
        return '<_Entry %s/%d prio=%d %s %s>' % (
            _addr_text(self.family, self.dst), self.dst_len, self.priority,
            self.kind, self.state)


class NetlinkSink(FibSink):
    """Install the engine's winning routes into a Linux routing table.

    Constructing one touches nothing: see :meth:`open`.

    :param table: the routing table id to write, 254 (main) by default.
        Any other table only forwards traffic if an ``ip rule`` sends
        traffic to it, which is exactly why it is the right place to test.
    :param protocol: our ``rtm_protocol``, 1..255. Route ownership rests on
        this and on the priority; see the module docstring.
    :param priority_ebgp: the kernel priority for a route whose
        administrative distance is the external one.
    :param priority_ibgp: the kernel priority for every other distance,
        unless ``priority_map`` says otherwise.
    :param priority_default: the priority for a route whose administrative
        distance appears in neither entry of the map -- a connected or
        static route, or any future protocol. Defaults to
        ``priority_ibgp``, which is the conservative choice: the less
        preferred of the two, so a route from a protocol nobody has
        configured a priority for cannot outrank one that has.
    :param priority_map: ``{administrative distance: kernel priority}``,
        replacing the pair above entirely. The mapping is data rather than
        an ``if protocol == BGP`` precisely so that an OSPF plugin needs no
        change here.
    :param priority_fn: a callable taking a Route and returning a
        priority, overriding everything above. The last resort for an
        embedder with its own policy.
    :param oif_fn: a callable taking a Route and returning an outgoing
        interface index, or 0. The protocol-neutral Route carries no
        interface -- a BGP next-hop is an address -- so ``RTA_OIF`` is only
        written when an embedder can supply one.
    :param retain_on_shutdown: the default for :meth:`shutdown`.
    :param enabled: what ``ip.route.install`` said. Reported in
        :meth:`stats` and otherwise unused: this object never opens itself.
    :param transport: a substitute for the netlink socket. When given,
        :meth:`open` uses it and performs no platform check, which is what
        makes the whole module testable off Linux.
    :param transport_factory: a callable returning a transport, called by
        :meth:`open`. Defaults to :meth:`NetlinkTransport.open`.
    :param batch: requests written per :meth:`flush`.
    :param ack_batch: acknowledgements processed per :meth:`flush`.
    :param window: requests allowed in flight at once. Beyond it the flush
        reads acks instead of writing, which is the only backpressure the
        kernel's socket buffer gives us before it starts answering ENOBUFS.
    :param ack_timeout: seconds after which an unanswered request is
        assumed lost and retried. The kernel always answers a request with
        ``NLM_F_ACK``, so this only fires when a reply was dropped by a
        full receive buffer -- rare, and silent in every way except this.
    :param clock: the monotonic clock, injectable so a test can move time
        without sleeping.
    :raises ValueError: the table or protocol id is out of range.
    """

    name = 'netlink'
    writes = True

    def __init__(self, table=RT_TABLE_MAIN, protocol=DEFAULT_PROTOCOL,
                 priority_ebgp=DEFAULT_PRIORITY_EBGP,
                 priority_ibgp=DEFAULT_PRIORITY_IBGP,
                 priority_default=None, priority_map=None, priority_fn=None,
                 oif_fn=None, retain_on_shutdown=False, enabled=False,
                 transport=None, transport_factory=None, batch=256,
                 ack_batch=1024, window=1024, ack_timeout=30.0,
                 recv_size=DEFAULT_RECV_SIZE, timeout=DEFAULT_TIMEOUT_S,
                 clock=None):
        table = int(table)
        protocol = int(protocol)
        if not 0 <= table <= 0xffffffff:
            raise ValueError('routing table id must be 0..4294967295, got %d'
                             % table)
        if not 1 <= protocol <= 255:
            # rtm_protocol is a single byte, and 0 is RTPROT_UNSPEC, which
            # would make every route on the box look like ours.
            raise ValueError('rtm_protocol must be 1..255, got %d' % protocol)

        self.table = table
        self.protocol = protocol
        self.priority_ebgp = int(priority_ebgp)
        self.priority_ibgp = int(priority_ibgp)
        self.priority_default = (self.priority_ibgp
                                 if priority_default is None
                                 else int(priority_default))
        if priority_map is None:
            priority_map = {
                DEFAULT_ADMIN_DISTANCE['ebgp']: self.priority_ebgp,
                DEFAULT_ADMIN_DISTANCE['ibgp']: self.priority_ibgp,
            }
        self.priority_map = dict(priority_map)
        self.priority_fn = priority_fn
        self.oif_fn = oif_fn
        self.retain_on_shutdown = bool(retain_on_shutdown)
        self.enabled = bool(enabled)

        self.batch = int(batch)
        self.ack_batch = int(ack_batch)
        self.window = int(window)
        self.ack_timeout = float(ack_timeout)
        self.recv_size = int(recv_size)
        self.timeout = float(timeout)
        self.clock = clock or _monotonic

        self._transport = transport
        self._factory = transport_factory or NetlinkTransport.open
        self._open = False

        # Sequence numbers start at 1: zero is what the kernel uses for an
        # unsolicited notification, so a zero-sequence reply is never an
        # answer to anything we asked.
        self._seq = 0

        self._entries = {}
        self._queue = OrderedDict()
        self._pending = OrderedDict()
        self._retry = OrderedDict()
        # Which key each prefix currently occupies, so that a metric change
        # can retire the key the prefix used to have. Without it, changing
        # a route's metric leaves the old route in the kernel forever.
        self._prefix_key = {}

        self.installed = 0
        self.withdrawn = 0
        self.errors = 0
        self.retries = 0
        self.recovered = 0
        self.skipped = 0
        self.adopted = 0
        self.removed = 0
        self.orphans = 0
        self.flushes = 0
        self.sends = 0
        self.acks = 0
        self.stale_acks = 0
        self.ack_timeouts = 0
        self.overruns = 0
        # The last refusal, with the kernel's own explanation when it gave
        # one (E-7); what health shows next to the error count.
        self.last_error = None

    # --- lifecycle ---------------------------------------------------------

    def open(self):
        """Open the netlink socket. Idempotent.

        Separated from construction on purpose. The engine builds a sink
        from configuration whether or not ``ip route install`` is true, and
        calls this only when it is; a test on a non-Linux host constructs
        one with a fake transport and calls this freely. The platform check
        lives here and nowhere else, which is what lets the module be
        imported anywhere.

        :return: self, so ``sink.open().reconcile(...)`` reads naturally.
        :raises NetlinkUnsupported: not Linux, or no netlink in this
            CPython, and no substitute transport was supplied.
        :raises OSError: the kernel refused the socket.
        """
        if self._open:
            return self
        if self._transport is None:
            if not supported():
                raise NetlinkUnsupported(
                    'cannot install routes: %s'
                    % capabilities().get('reason', 'unsupported platform'))
            self._transport = self._factory()
        self._open = True
        _log.info('netlink sink open: table %d, protocol %d, priorities '
                  'ebgp=%d ibgp=%d', self.table, self.protocol,
                  self.priority_ebgp, self.priority_ibgp)
        return self

    #: ``start()`` is the engine's vocabulary for the same thing.
    start = open

    def is_open(self):
        """Return whether the socket is open.

        :return: True between :meth:`open` and :meth:`close`.
        """
        return self._open

    def close(self):
        """Close the socket without withdrawing anything. Idempotent.

        Not the same as :meth:`shutdown`: this leaves the kernel exactly as
        it is and only releases the descriptor. Use it after a shutdown, or
        when handing the process over.

        A substitute transport is closed too. It was handed to us, but a
        fake that is not told the sink has finished with it cannot assert
        that the sink closed its socket, which is half of what the shutdown
        contract promises.
        """
        if self._transport is not None:
            closer = getattr(self._transport, 'close', None)
            if closer is not None:
                closer()
        self._transport = None
        self._open = False

    def fileno(self):
        """Return the transport's descriptor, for a loop reader.

        An embedder that wants acks processed the moment they arrive can
        register this with ``loop.add_reader`` and call :meth:`flush` from
        the callback. The engine does not: it flushes from the selection
        batch, where the work already is.

        :return: the descriptor, or -1 when closed or faked.
        """
        getter = getattr(self._transport, 'fileno', None)
        return getter() if getter is not None else -1

    # --- the FibSink surface -----------------------------------------------

    def install(self, route):
        """Queue a route for installation. Never blocks, never syscalls.

        Called on the loop thread once per best-route change, so the only
        work done here is deriving the kernel's view of the route and
        putting it in a queue keyed by that view. A prefix offered a
        thousand times inside one selection batch is written once, because
        the queue is keyed and the last write wins.

        Two cases are worth knowing about:

        * an identical route that is already installed -- after adoption at
          start-up, or a re-offer with no change -- is skipped entirely.
        * a change of *priority* for a prefix is not a replacement. The
          kernel keys a route by ``(table, destination, tos, priority)``,
          so the new priority is a new route and the old one would survive
          on its own. The old key is therefore queued for deletion behind
          the new add, in that order, so the prefix is never unrouted in
          between.

        :param route: the route now best for its prefix.
        """
        gateway, priority, oif = self._attrs(route)
        prefix = route.prefix
        if gateway is None:
            # A next-hop of a different width than the destination family
            # (an RFC 5549 IPv6 next-hop for an IPv4 prefix) has no
            # expression in RTA_GATEWAY. Refusing it here marks the one
            # route rather than sending a message the kernel answers with
            # EINVAL for a reason nobody can read.
            self._fail_route(route, EAFNOSUPPORT)
            return

        key = (prefix, priority)
        previous = self._prefix_key.get(prefix)
        entry = self._entries.get(key)
        if (entry is not None and entry.kind == OP_ADD
                and entry.state == ST_INSTALLED and entry.matches(gateway,
                                                                  oif)):
            entry.route = route
            route.fib_state = FIB_STATE_INSTALLED
            route.fib_errno = 0
            self.skipped += 1
        else:
            entry = self._entry_for(key, OP_ADD, route, gateway, priority,
                                    oif)
            entry.kind = OP_ADD
            entry.route = route
            entry.gateway = gateway
            entry.oif = oif
            entry.errno = 0
            self._enqueue(entry)
            route.fib_state = FIB_STATE_PENDING
            route.fib_errno = 0
        self._prefix_key[prefix] = key
        if previous is not None and previous != key:
            self._retire(previous)

    def withdraw(self, route):
        """Queue the removal of a route. Never blocks, never syscalls.

        The delete is built from what we *installed*, not from what the
        route says now: the kernel matches a delete on the priority, and a
        route whose metric changed after installation would otherwise
        delete a route that does not exist and leave the one that does.

        :param route: the route that is no longer best, or whose prefix has
            no best route at all.
        """
        prefix = route.prefix
        key = self._prefix_key.pop(prefix, None)
        if key is None:
            route.fib_state = FIB_STATE_NONE
            route.fib_errno = 0
            return
        entry = self._entries.get(key)
        if entry is None:
            route.fib_state = FIB_STATE_NONE
            route.fib_errno = 0
            return
        entry.route = route
        if not entry.written:
            # Queued but never sent: dropping it is the whole withdrawal,
            # and sending a delete for a route the kernel never had would
            # cost a syscall and an ESRCH.
            self._forget(entry)
            route.fib_state = FIB_STATE_NONE
            route.fib_errno = 0
            self.withdrawn += 1
            return
        entry.kind = OP_DEL
        entry.errno = 0
        self._enqueue(entry)
        route.fib_state = FIB_STATE_PENDING

    def flush(self):
        """Write queued requests and process acknowledgements, boundedly.

        Four bounded phases per call: promote retries whose backoff has
        expired, re-queue requests whose ack never came, send at most
        ``batch`` requests, then read at most ``ack_batch``
        acknowledgements. Nothing here waits: a read that would block means
        the acks have not arrived and the next flush will collect them,
        which is the whole reason the socket is non-blocking.

        :return: the number of routes whose FIB state changed.
        """
        if not self._open:
            return 0
        self.flushes += 1
        changed = self._promote_retries()
        changed += self._sweep_timeouts()
        self._send_batch()
        changed += self._read_acks(self.ack_batch)
        return changed

    def next_flush_in(self):
        """Say when :meth:`flush` next has work, for the engine's pump.

        :return: 0 while requests are queued, :data:`ACK_POLL_S` while
            acks are outstanding, the time to the earliest retry when only
            retries remain, and None when there is nothing to do -- or the
            sink is closed.
        """
        if not self._open:
            return None
        if self._queue:
            return 0.0
        if self._pending:
            return ACK_POLL_S
        if self._retry:
            due = min(entry.due for entry in self._retry.values())
            return max(0.0, due - self.clock())
        return None

    def reconcile(self, current):
        """Adopt or remove the routes a previous run of this process left.

        Called once, at start, before anything is installed, and blocking
        on purpose: until it returns, the kernel may be forwarding a prefix
        through a next-hop this process has no intention of maintaining.
        Leaving one behind is not a leak, it is a black hole for the entire
        life of the process -- nothing in the steady-state path ever
        revisits a prefix the engine has no route for.

        The dump is filtered to routes carrying *our* protocol id *in our
        table*. Everything else on the box, including another daemon's
        route for a prefix we also have, is invisible here and is left
        alone. Of what remains, a route that matches what we would install
        -- same destination, same gateway, same priority -- is adopted, its
        engine-side Route marked installed so the first flush does not
        rewrite it, and anything else is deleted.

        :param current: iterable of routes the engine wants installed.
        :return: ``{'adopted': N, 'removed': N, 'ours': N, 'scanned': N,
            'foreign': N}``.
        :raises OSError: the dump failed. A sink that cannot read the table
            it is about to write must not start.
        """
        self._require_open()
        desired = {}
        for route in current or ():
            gateway, priority, oif = self._attrs(route)
            if gateway is None:
                continue
            desired[(route.prefix, priority)] = (route, gateway, oif)

        found = dump_routes(self._transport, seq=self._next_seq(),
                            timeout=self.timeout, recv_size=self.recv_size)
        scanned = len(found)
        ours = []
        for kroute in found:
            if kroute.prefix is None or kroute.protocol != self.protocol:
                continue
            if kroute.table != self.table:
                continue
            ours.append(kroute)

        adopted = 0
        removed = 0
        deletes = []
        for kroute in ours:
            key = (kroute.prefix, kroute.priority)
            want = desired.get(key)
            if want is not None and want[1] == kroute.gateway \
                    and (not kroute.oif or not want[2]
                         or kroute.oif == want[2]):
                route, gateway, oif = want
                entry = self._entry_for(key, OP_ADD, route, gateway,
                                        kroute.priority, oif)
                # The adopted entry records what *we* would write, not
                # what the kernel reported, so the first install() of the
                # same route compares equal and writes nothing. Recording
                # the kernel's interface index here instead would make
                # every adopted route look changed and be rewritten.
                entry.gateway = gateway
                entry.oif = oif
                entry.state = ST_INSTALLED
                entry.written = True
                entry.route = route
                route.fib_state = FIB_STATE_INSTALLED
                route.fib_errno = 0
                self._prefix_key[kroute.prefix] = key
                adopted += 1
                continue
            deletes.append(kroute)

        for kroute in deletes:
            entry = _Entry((kroute.prefix, kroute.priority), OP_DEL, None,
                           kroute.gateway, kroute.priority, kroute.oif,
                           kroute.family, kroute.dst_len, kroute.dst)
            entry.written = True
            self._entries[entry.key] = entry
            self._enqueue(entry)
            removed += 1

        self.adopted += adopted
        self.orphans += removed
        if deletes:
            # Drained here rather than left to the first flush: the point of
            # reconciliation is that no stale forwarding state outlives it.
            self._drain(self.timeout)
        _log.info('netlink reconcile: %d route(s) in table %d carry protocol '
                  '%d; adopted %d, removed %d', len(ours), self.table,
                  self.protocol, adopted, removed)
        return {'adopted': adopted, 'removed': removed, 'ours': len(ours),
                'scanned': scanned, 'foreign': scanned - len(ours)}

    def shutdown(self, retain=None):
        """Withdraw everything we installed, or deliberately leave it.

        Runs with no event loop -- the engine calls it from its teardown,
        after the loop has stopped scheduling anything else -- so it sends
        and drains synchronously rather than queueing. It closes the socket
        either way.

        ``retain`` is for a planned restart, where a few seconds of a stale
        route is better than a few seconds of no route at all. It is not a
        default anywhere: a stopped speaker that leaves the kernel
        forwarding through a next-hop nobody maintains is a black hole, and
        the only person who can judge that trade is the operator.

        :param retain: leave the routes in place; None means use the
            configured ``retain-on-shutdown``.
        :return: the number of routes withdrawn.
        """
        if retain is None:
            retain = self.retain_on_shutdown
        if not self._open:
            self._entries.clear()
            self._queue.clear()
            self._pending.clear()
            self._retry.clear()
            self._prefix_key.clear()
            return 0
        if retain:
            _log.warning('netlink sink retaining %d route(s) in table %d on '
                         'shutdown; nothing will maintain them',
                         len(self._prefix_key), self.table)
            self.close()
            return 0

        before = self.withdrawn
        self._queue.clear()
        self._retry.clear()
        for entry in list(self._entries.values()):
            if not entry.written:
                self._forget(entry)
                continue
            entry.kind = OP_DEL
            entry.attempts = 0
            self._enqueue(entry)
        try:
            self._drain(self.timeout)
        except OSError:
            # The routes outlive us either way; a socket error on the way
            # out is worth a log line and nothing more.
            _log.exception('netlink sink failed to withdraw cleanly')
        # Counted from the acknowledgements rather than from what was
        # queued: a drain that timed out has not withdrawn the remainder,
        # and saying it did would be the one lie an operator reading a
        # shutdown log cannot check.
        count = self.withdrawn - before
        for entry in list(self._entries.values()):
            if entry.route is not None:
                entry.route.fib_state = FIB_STATE_NONE
                entry.route.fib_errno = 0
        self._entries.clear()
        self._queue.clear()
        self._pending.clear()
        self._prefix_key.clear()
        self.close()
        return count

    def stats(self):
        """Return counters, configuration and status for health output.

        The keys are stable and every value is JSON-serialisable, because
        health and ``show ip route`` both read this document.

        ``status`` is ``degraded`` when any route is in error or any orphan
        was found at start-up. The second half is deliberate and it is not
        a transient: an orphan means a previous run of this process left
        the kernel forwarding a prefix it should not have been, and that is
        worth an operator's attention for the life of the process even
        though it has already been repaired.

        :return: a dict of plain types.
        """
        in_error = 0
        present = 0
        for entry in self._entries.values():
            if entry.state == ST_INSTALLED:
                present += 1
            elif entry.state in (ST_ERROR, ST_RETRY):
                in_error += 1
        status = OK
        if in_error or self.orphans:
            status = DEGRADED
        return {
            'name': self.name,
            'writes': True,
            'status': status,
            'open': self._open,
            'enabled': self.enabled,
            'supported': supported(),
            'privileged': privileged() if supported() else False,
            'table': self.table,
            'protocol': self.protocol,
            'priority': {
                'ebgp': self.priority_ebgp,
                'ibgp': self.priority_ibgp,
                'default': self.priority_default,
            },
            'installed': self.installed,
            'withdrawn': self.withdrawn,
            'errors': self.errors,
            'retries': self.retries,
            'recovered': self.recovered,
            'skipped': self.skipped,
            'queued': len(self._queue),
            'acks-pending': len(self._pending),
            'acks': self.acks,
            'ack-timeouts': self.ack_timeouts,
            'stale-acks': self.stale_acks,
            'overruns': self.overruns,
            'in-error': in_error,
            'present': present,
            'adopted': self.adopted,
            'removed': self.removed,
            'orphans': self.orphans,
            'flushes': self.flushes,
            'sends': self.sends,
            'retain-on-shutdown': self.retain_on_shutdown,
            'ext-ack': bool(getattr(self._transport, 'ext_ack', False)),
            'last-error': dict(self.last_error)
            if self.last_error is not None else None,
        }

    # --- route attributes --------------------------------------------------

    def priority_for(self, route):
        """Return the kernel priority a route is written with.

        Ownership rests on this number as much as on the protocol id, so it
        must be derived the same way every time for the same route: the
        priority the route was installed with is the only handle the delete
        has on it.

        The rule is a map from administrative distance to priority, not a
        test for BGP. A route at the external distance gets the ``ebgp``
        priority, one at the internal distance gets ``ibgp``, and anything
        else -- connected, static, a protocol that does not exist yet --
        gets ``priority_default``, which is the ``ibgp`` value unless
        configured otherwise.

        :param route: the route about to be written.
        :return: the kernel priority, an unsigned 32-bit value.
        """
        if self.priority_fn is not None:
            return int(self.priority_fn(route)) & 0xffffffff
        found = self.priority_map.get(route.admin_distance)
        if found is None:
            found = self.priority_default
        return int(found) & 0xffffffff

    def oif_for(self, route):
        """Return the outgoing interface index for a route, or 0.

        :param route: the route about to be written.
        :return: an interface index, 0 when unknown.
        """
        if self.oif_fn is None:
            return 0
        try:
            return int(self.oif_fn(route)) & 0xffffffff
        except (TypeError, ValueError):
            return 0

    def _attrs(self, route):
        """Derive the kernel's view of a route.

        :param route: the engine's route.
        :return: ``(gateway, priority, oif)``, where the gateway is None
            when the next-hop cannot be expressed for this family.
        """
        gateway = route.nexthop or b''
        if gateway:
            width = _AF_ADDR_LEN.get(_AFI_TO_AF.get(route.prefix.afi), 0)
            if len(gateway) != width:
                return None, 0, 0
            if gateway == b'\x00' * width:
                # 0.0.0.0 is how BGP spells "via me" in a next-hop, and it
                # is not a gateway. Writing it would be a route to nowhere;
                # dropping it leaves a route that needs an interface.
                gateway = b''
        return gateway, self.priority_for(route), self.oif_for(route)

    # --- message construction ----------------------------------------------

    def _build(self, entry, seq):
        """Build the netlink request for one queued entry.

        Both verbs share a body; what differs is worth stating because
        each half is a trap:

        * **install** is ``NLM_F_CREATE|NLM_F_REPLACE``. Replace is safe
          only because the identity includes our priority and our protocol
          id; without them it would silently take over another daemon's
          route.
        * **delete** carries ``rtm_scope = RT_SCOPE_NOWHERE``, which means
          "whatever scope it has" rather than any real scope. A delete that
          named ``RT_SCOPE_UNIVERSE`` would not match a route the kernel
          had recorded at link scope. It also repeats the protocol,
          priority and gateway, all of which the kernel matches on, so a
          delete cannot remove a route that is not ours.

        The table is written twice on purpose. ``rtm_table`` is a byte and
        cannot hold an id above 255, so the real id goes in ``RTA_TABLE``
        and the byte carries the id when it fits and ``RT_TABLE_UNSPEC``
        when it does not. Writing the truncated low byte instead would put
        the route in a wrong-but-valid table on a kernel too old to read
        ``RTA_TABLE``; ``RT_TABLE_UNSPEC`` makes such a kernel reject the
        request instead, which is the failure we can see.

        :param entry: the queued entry.
        :param seq: its sequence number.
        :return: the complete message.
        """
        if entry.kind == OP_ADD:
            msg_type = RTM_NEWROUTE
            flags = (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE
                     | NLM_F_REPLACE)
            scope = RT_SCOPE_UNIVERSE
            protocol = self.protocol
        else:
            msg_type = RTM_DELROUTE
            flags = NLM_F_REQUEST | NLM_F_ACK
            scope = RT_SCOPE_NOWHERE
            protocol = self.protocol

        table_byte = self.table if self.table <= 255 else RT_TABLE_UNSPEC
        body = _RTMSG.pack(entry.family, entry.dst_len, 0, 0, table_byte,
                           protocol, scope, RTN_UNICAST, 0)
        # The destination is always sent, including for a default route
        # where iproute2 omits it: the kernel masks nothing and rejects a
        # destination with bits set outside rtm_dst_len, which Prefix's
        # construction-time masking already makes impossible.
        body += pack_attr(RTA_DST, entry.dst)
        if entry.gateway:
            body += pack_attr(RTA_GATEWAY, entry.gateway)
        if entry.oif:
            body += pack_u32_attr(RTA_OIF, entry.oif)
        body += pack_u32_attr(RTA_PRIORITY, entry.priority)
        body += pack_u32_attr(RTA_TABLE, self.table)
        return pack_message(msg_type, flags, seq, 0, body)

    # --- the queue ---------------------------------------------------------

    def _next_seq(self):
        """Return the next request sequence number, never zero."""
        self._seq = (self._seq + 1) & 0x7fffffff
        if self._seq == 0:
            self._seq = 1
        return self._seq

    def _entry_for(self, key, kind, route, gateway, priority, oif):
        """Return the entry for a key, creating it if there is none."""
        entry = self._entries.get(key)
        if entry is None:
            prefix = key[0]
            entry = _Entry(key, kind, route, gateway, priority, oif,
                           _AFI_TO_AF.get(prefix.afi, AF_UNSPEC),
                           prefix.plen, prefix.packed())
            self._entries[key] = entry
        return entry

    def _enqueue(self, entry):
        """Put an entry in the send queue, replacing any earlier position.

        Re-queueing moves the entry to the back rather than keeping its
        place. That is the right order for a churning prefix: the newest
        intention is also the least urgent, because the kernel is already
        holding a recent version of it.
        """
        entry.state = ST_QUEUED
        self._retry.pop(entry.key, None)
        self._queue.pop(entry.key, None)
        self._queue[entry.key] = entry

    def _forget(self, entry):
        """Drop an entry entirely, from every container it can be in."""
        self._queue.pop(entry.key, None)
        self._retry.pop(entry.key, None)
        self._entries.pop(entry.key, None)
        if entry.seq:
            self._pending.pop(entry.seq, None)

    def _retire(self, key):
        """Remove the kernel route a prefix used to occupy.

        Reached when a prefix's priority changes, which the kernel sees as
        a different route rather than as a replacement.
        """
        entry = self._entries.get(key)
        if entry is None:
            return
        if not entry.written:
            self._forget(entry)
            return
        entry.kind = OP_DEL
        entry.attempts = 0
        entry.errno = 0
        self._enqueue(entry)

    def _fail_route(self, route, code):
        """Mark one route in error without having sent anything."""
        route.fib_state = FIB_STATE_ERROR
        route.fib_errno = code
        self.errors += 1

    # --- flush phases ------------------------------------------------------

    def _promote_retries(self):
        """Move retries whose backoff has expired back into the queue.

        :return: 0; a promotion changes no route's state, only its timing.
        """
        if not self._retry:
            return 0
        now = self.clock()
        due = []
        # Scanned rather than kept in due order: the map is ordered by
        # when each route last failed, and two routes that failed in that
        # order can be due in the opposite one because their attempt
        # counts differ. The scan is bounded by the number of routes
        # currently in error, which is the count health is degrading on.
        for key, entry in self._retry.items():
            if entry.due <= now:
                due.append(entry)
            if len(due) >= self.batch:
                break
        for entry in due:
            self._retry.pop(entry.key, None)
            self.retries += 1
            self._enqueue(entry)
        return 0

    def _sweep_timeouts(self):
        """Re-queue requests the kernel never answered.

        The pending map is in sequence order, which is send order, so the
        sweep stops at the first request young enough to still be waiting.

        :return: 0; a timeout changes no route's state, only its timing.
        """
        if not self._pending:
            return 0
        now = self.clock()
        expired = []
        for seq, entry in self._pending.items():
            if now - entry.sent_at < self.ack_timeout:
                break
            expired.append((seq, entry))
            if len(expired) >= self.batch:
                break
        for seq, entry in expired:
            self._pending.pop(seq, None)
            self.ack_timeouts += 1
            _log.warning('netlink request %d for %s went unanswered for %.0fs'
                         '; retrying', seq, entry, self.ack_timeout)
            self._enqueue(entry)
        return 0

    def _send_batch(self):
        """Write at most ``batch`` queued requests.

        Stops early on backpressure: a full socket send buffer answers
        EAGAIN, and the right response is to leave the request at the front
        of the queue and read acks instead, which is what frees the buffer.
        """
        sent = 0
        while self._queue and sent < self.batch \
                and len(self._pending) < self.window:
            key, entry = self._queue.popitem(last=False)
            if not self._send(entry):
                self._queue[key] = entry
                self._queue.move_to_end(key, last=False)
                break
            sent += 1
        return sent

    def _send(self, entry):
        """Send one entry's request and record it as in flight.

        :param entry: the entry to write.
        :return: True when it was sent or definitively failed, False when
            the socket would block and it must stay queued.
        """
        seq = self._next_seq()
        message = self._build(entry, seq)
        try:
            self._transport.send(message)
        except OSError as exc:
            if exc.errno in _WOULD_BLOCK or exc.errno == ENOBUFS:
                return False
            # Anything else is this route's problem, not the queue's: an
            # EMSGSIZE on one absurd route must not stall the other
            # 999,999.
            self._record_error(entry, exc.errno or 0)
            return True
        self.sends += 1
        entry.seq = seq
        entry.state = ST_SENT
        entry.sent_at = self.clock()
        if entry.kind == OP_ADD:
            entry.written = True
        self._pending[seq] = entry
        return True

    def _recv(self):
        """Read one datagram, or None when the socket would block."""
        try:
            return self._transport.recv(self.recv_size)
        except OSError as exc:
            if exc.errno in _WOULD_BLOCK:
                return None
            if exc.errno == ENOBUFS:
                # The receive buffer overflowed and the kernel dropped
                # messages. Some of them were our acks; the timeout sweep
                # is what recovers those, so this only has to be counted.
                self.overruns += 1
                return None
            raise

    def _read_acks(self, limit):
        """Read and apply up to ``limit`` acknowledgements.

        :param limit: the maximum number of messages to process.
        :return: the number of routes whose FIB state changed.
        """
        changed = 0
        processed = 0
        while processed < limit:
            data = self._recv()
            if not data:
                break
            for msg_type, flags, seq, _pid, body in parse_messages(data):
                processed += 1
                changed += self._handle(msg_type, seq, body, flags)
        return changed

    def _handle(self, msg_type, seq, body, flags=0):
        """Apply one reply to the entry it belongs to.

        :param msg_type: the reply's netlink type.
        :param seq: the sequence number it carries back.
        :param body: the reply body.
        :param flags: the reply's header flags, which say whether an
            error carries extended-ack text.
        :return: 1 if a route's FIB state changed, else 0.
        """
        if msg_type != NLMSG_ERROR:
            # RTM_NEWROUTE arriving here would be a notification from a
            # multicast group we never joined, or the tail of a dump that
            # timed out. Neither is an answer to a request.
            return 0
        entry = self._pending.pop(seq, None)
        if entry is None or entry.seq != seq or entry.state != ST_SENT:
            # A reply to a request whose entry has already moved on --
            # retired by a metric change, or re-queued by the timeout
            # sweep. Applying it would overwrite a newer intention.
            self.stale_acks += 1
            return 0
        self.acks += 1
        code = -_S32.unpack_from(body, 0)[0] if len(body) >= 4 else 0
        if code > 0:
            return self._record_error(entry, code,
                                      parse_ext_ack(body, flags))
        return self._record_success(entry)

    def _record_success(self, entry):
        """Apply a zero-errno ack.

        :param entry: the entry the ack answers.
        :return: 1 if a route's FIB state changed, else 0.
        """
        route = entry.route
        if entry.kind == OP_ADD:
            entry.state = ST_INSTALLED
            entry.errno = 0
            self.installed += 1
            if entry.attempts:
                # A retry that worked: the route is no longer in error, and
                # the operator's degraded status clears with it.
                self.recovered += 1
                entry.attempts = 0
            if route is not None:
                route.fib_state = FIB_STATE_INSTALLED
                route.fib_errno = 0
                return 1
            return 0
        self.withdrawn += 1
        if entry.route is None:
            # A stale kernel route removed at start-up, with no engine-side
            # Route to mark.
            self.removed += 1
        self._forget(entry)
        if route is not None:
            route.fib_state = FIB_STATE_NONE
            route.fib_errno = 0
            return 1
        return 0

    def _record_error(self, entry, code, message=None):
        """Apply a negative-errno ack, or a failed send.

        There is no rollback. The route is marked, counted and scheduled
        for a retry, and every other route stays exactly as it was: they
        are independent, and a failed install leaves the rest correct.

        :param entry: the entry that failed.
        :param code: the positive errno.
        :param message: the kernel's extended-ack text, if it sent one.
        :return: 1 if a route's FIB state changed, else 0.
        """
        if entry.kind == OP_DEL and code in _ALREADY_GONE:
            # "No such route" from a delete is success by another name.
            return self._record_success(entry)
        entry.attempts += 1
        entry.errno = code
        entry.state = ST_ERROR
        self.errors += 1
        route = entry.route
        touched = 0
        if route is not None:
            route.fib_state = FIB_STATE_ERROR
            route.fib_errno = code
            touched = 1
        entry.due = self.clock() + backoff_delay(entry.attempts)
        entry.state = ST_RETRY
        self._queue.pop(entry.key, None)
        self._retry[entry.key] = entry
        self.last_error = {
            'op': entry.kind,
            'entry': repr(entry),
            'errno': code,
            'error': os.strerror(code) if code else '',
            'message': message,
        }
        _log.warning('netlink %s of %s failed with errno %d (%s)%s; retry %d '
                     'in %.0fs', entry.kind, entry,
                     code, os.strerror(code) if code else '',
                     ': %s' % message if message else '',
                     entry.attempts, backoff_delay(entry.attempts))
        return touched

    # --- the blocking paths ------------------------------------------------

    def _drain(self, timeout):
        """Send everything queued and wait for every ack, or time out.

        Only reconciliation and shutdown use this. Both run outside the
        event loop, and both are meaningless if they return before the
        kernel has acted.

        :param timeout: seconds to allow in total.
        :return: the number of routes whose state changed.
        """
        waiter = getattr(self._transport, 'wait', None)
        # Wall time, not the injectable clock: this deadline protects
        # against a kernel that never answers, which is a real duration and
        # not a logical one. The retry backoff is the opposite case and
        # uses the injectable clock precisely so a test can skip an hour.
        deadline = _monotonic() + timeout
        changed = 0
        while self._queue or self._pending:
            acked = self.acks
            sent = self._send_batch()
            changed += self._read_acks(self.ack_batch)
            if not self._queue and not self._pending:
                break
            if sent or self.acks != acked:
                # Progress was made, so go round again immediately rather
                # than sleeping: a full table's withdrawal is thousands of
                # iterations and a sleep per iteration would dominate it.
                continue
            if _monotonic() >= deadline:
                _log.warning('netlink drain timed out with %d queued and %d '
                             'unacknowledged', len(self._queue),
                             len(self._pending))
                break
            if waiter is not None:
                waiter(0.05)
            else:
                # A substitute transport with no wait(): sleep briefly
                # rather than burn the deadline in a tight loop.
                time.sleep(0.001)
        return changed

    def _require_open(self):
        """Raise unless the sink has been opened."""
        if not self._open or self._transport is None:
            raise NetlinkUnsupported('the netlink sink is not open; call '
                                     'open() first')

    # --- introspection -----------------------------------------------------

    def entry_state(self, prefix, priority=None):
        """Return what the sink believes about one prefix, for tests.

        :param prefix: the :class:`Prefix` to look up.
        :param priority: the priority it was written with; None means
            whichever one the prefix currently occupies.
        :return: one of the ``ST_*`` strings, or ``'none'``.
        """
        key = (prefix, priority) if priority is not None \
            else self._prefix_key.get(prefix)
        if key is None:
            return 'none'
        entry = self._entries.get(key)
        return entry.state if entry is not None else 'none'

    def pending_count(self):
        """Return how many requests are awaiting an acknowledgement.

        :return: the in-flight count.
        """
        return len(self._pending)

    def queued_count(self):
        """Return how many requests are waiting to be written.

        :return: the queue depth.
        """
        return len(self._queue)

    def __repr__(self):
        return ('<NetlinkSink table=%d proto=%d open=%s queued=%d '
                'pending=%d>' % (self.table, self.protocol, self._open,
                                 len(self._queue), len(self._pending)))


def backoff_delay(attempts, minimum=RETRY_MIN_S, maximum=RETRY_MAX_S):
    """Return the retry delay after ``attempts`` consecutive failures.

    Exponential from one second and clamped at a minute. Clamped at both
    ends: the lower bound keeps a route that fails instantly from becoming
    a spin loop, and the upper bound keeps the shift from overflowing into
    a delay measured in years, which a route that has been failing all week
    would otherwise reach.

    :param attempts: how many times this route has failed, 1 for the first.
    :param minimum: the first delay.
    :param maximum: the ceiling.
    :return: seconds to wait.
    """
    if attempts <= 1:
        return minimum
    # Bound the shift before computing it: 2 ** 10000 is a perfectly valid
    # Python int and a perfectly useless delay.
    steps = min(int(attempts) - 1, 32)
    return min(maximum, minimum * (2 ** steps))


def make_sink(config=None, **kwargs):
    """Build an unopened :class:`NetlinkSink` from ``ip.route``.

    The one function ``engine.py`` needs to know about. It takes the
    core's ``ip.route`` configuration dict and returns a sink that has
    touched nothing::

        sink = make_sink(store.value(('ip', 'route'), {}))

    ``install`` is read but not acted on: it is recorded as ``enabled`` and
    reported in :meth:`NetlinkSink.stats`, and the caller decides whether
    to call :meth:`NetlinkSink.open`. That split is the safety property the
    whole module is built around, and a factory that opened a socket
    because a dict said ``install: true`` would give it away.

    :param config: the ``ip.route`` section: ``install``, ``table``,
        ``protocol``, ``priority`` (``ebgp``, ``ibgp``, optionally
        ``default``) and ``retain-on-shutdown``. Missing keys take the
        schema's defaults, so ``{}`` and an absent section behave alike.
    :param kwargs: passed to :class:`NetlinkSink`, overriding anything
        derived from the configuration. ``transport=`` is how a test
        substitutes a fake socket.
    :return: a configured, unopened :class:`NetlinkSink`.
    :raises ValueError: the table or protocol id is out of range.
    """
    cfg = config or {}
    priority = cfg.get('priority') or {}
    params = {
        'table': cfg.get('table', RT_TABLE_MAIN),
        'protocol': cfg.get('protocol', DEFAULT_PROTOCOL),
        'priority_ebgp': priority.get('ebgp', DEFAULT_PRIORITY_EBGP),
        'priority_ibgp': priority.get('ibgp', DEFAULT_PRIORITY_IBGP),
        'priority_default': priority.get('default'),
        'retain_on_shutdown': cfg.get('retain-on-shutdown') is True,
        'enabled': cfg.get('install') is True,
    }
    params.update(kwargs)
    return NetlinkSink(**params)
