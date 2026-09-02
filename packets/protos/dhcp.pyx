# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Small, lossless DHCPv4 and DHCPv6 packet examples.

The module is deliberately laid out from leaf TLVs to their enclosing packet:
DHCPOption, DHCP, DHCP6Option, then DHCP6.  It models wire framing and the few
fields useful to packet queries; interpreting every option is deliberately out
of scope.  Keeping options generic is what lets new and private option codes
round-trip without waiting for this example module to learn their semantics.
"""

import socket

from libc.stdint cimport uint8_t, uint16_t, uint32_t
cimport cython

from packets.core.inetpkt cimport PKT, PktWriter, need_bytes, rd_u16, \
    rd_u32, rd_bytes, w_u8, w_u16, w_u32, w_bytes, w_zeros, w_take, \
    _serialize


cdef Py_ssize_t DHCP_FIXED_LEN = 240
cdef Py_ssize_t DHCP_CHADDR_LEN = 16
cdef Py_ssize_t DHCP_SNAME_LEN = 64
cdef Py_ssize_t DHCP_FILE_LEN = 128
cdef Py_ssize_t DHCP6_NORMAL_LEN = 4
cdef Py_ssize_t DHCP6_RELAY_LEN = 34


cdef inline bytes _owned_bytes(object value):
    """Return an immutable copy when value can be changed by its caller."""
    if isinstance(value, bytes):
        return value
    return bytes(value)


cdef inline int _write_fixed(PktWriter w, bytes value,
                             Py_ssize_t width) except -1:
    """Write a BOOTP byte field using a documented truncate/zero-pad policy.

    Public values omit wire padding.  Values longer than the RFC field are
    truncated, and shorter values get zero padding in the shared writer.  A
    parsed field has trailing NULs stripped, so ordinary strings and hardware
    addresses have the same useful public shape before and after a round-trip.
    """
    cdef bytes clipped = value[:width]
    w_bytes(w, clipped)
    w_zeros(w, width - len(clipped))
    return 0


cdef inline bytes _option_wire(DHCPOption option):
    """Serialize one v4 option through its sole writer implementation."""
    cdef PktWriter w = PktWriter()
    option._write(w)
    return w_take(w, 0)


cdef inline bytes _option6_wire(DHCP6Option option):
    """Serialize one v6 option through its sole writer implementation."""
    cdef PktWriter w = PktWriter()
    option._write(w)
    return w_take(w, 0)


@cython.final
cdef class DHCPOption:
    """A generic RFC 2132 option, including the one-byte PAD and END forms."""

    def __init__(self, *args, **kwargs):
        cdef:
            bytes raw
            const unsigned char[:] mv
            Py_ssize_t length

        # Positional bytes preserve the public constructor convention used by
        # packet examples.  Keyword data cannot mean a raw option because it
        # is also the documented value field in DHCPOption(code=..., data=...).
        if len(args) == 1:
            raw = _owned_bytes(args[0])
            mv = raw
            need_bytes(mv, 1, 'DHCP option')
            self.code = mv[0]
            if self.code == DHCP_OPT_PAD or self.code == DHCP_OPT_END:
                if len(raw) != 1:
                    raise ValueError('DHCP option: marker has trailing bytes')
                self.data = b''
                return

            # Every unchecked reader in inetpkt is intentionally fast, so the
            # length byte and then its complete value are guarded before read.
            need_bytes(mv, 2, 'DHCP option')
            length = mv[1]
            if len(raw) < 2 + length:
                raise ValueError('DHCP option: truncated value')
            if len(raw) != 2 + length:
                raise ValueError('DHCP option: trailing bytes')
            # Option values are owned bytes rather than views.  They remain
            # valid after an enclosing UDP/frame owner is released and callers
            # cannot mutate a parsed packet through a source bytearray.
            self.data = rd_bytes(mv, 2, 2 + length)
            return
        elif len(args) != 0:
            raise TypeError('DHCPOption accepts one raw buffer or keywords')

        self.code = kwargs.get('code', DHCP_OPT_PAD)
        self.data = _owned_bytes(kwargs.get('data', b''))

    def __repr__(self):
        return 'DHCPOption(code={0}, data={1!r})'.format(self.code, self.data)

    cpdef bytes pkt2net(self, dict kwargs):
        # Leaf objects are not PKT subclasses, so they allocate a small writer
        # directly; _write remains the one serialization route used standalone
        # and while embedded in a DHCP packet.
        return _option_wire(self)

    cdef int _write(self, PktWriter w) except -1:
        cdef Py_ssize_t length = len(self.data)
        w_u8(w, self.code)
        if self.code == DHCP_OPT_PAD or self.code == DHCP_OPT_END:
            return 0
        if length > 255:
            raise ValueError('DHCP option value exceeds 255 bytes')
        w_u8(w, <uint8_t>length)
        w_bytes(w, self.data)
        return 0


@cython.final
cdef class DHCP(PKT):
    """The 240-byte BOOTP/DHCPv4 header, options, and bytes after END."""

    def __init__(self, *args, **kwargs):
        cdef:
            object candidate = None
            bytes owner
            const unsigned char[:] mv
            bint use_buffer = 0

        self._base_l7(kwargs)
        self.pkt_name = 'DHCP'
        self.pq_type, self.query_fields = DHCP.query_info()

        # Public construction supports DHCP(raw), including mutable arrays
        # which are copied immediately.  A lone data= value at least as large
        # as the fixed header also retains PKT's historical keyword-buffer
        # shape; with other field keywords data= is the documented post-END
        # payload instead.
        if len(args) == 1:
            candidate = args[0]
            use_buffer = 1
        elif len(args) != 0:
            raise TypeError('DHCP accepts one raw buffer or field keywords')
        elif 'data' in kwargs and len(kwargs) <= (2 if 'l7_ports' in kwargs
                                                  else 1):
            candidate = kwargs['data']
            try:
                use_buffer = len(candidate) >= DHCP_FIXED_LEN
            except TypeError:
                use_buffer = 0

        self.options = list()
        self.data = b''
        self._ciaddr = b'\x00\x00\x00\x00'
        self._yiaddr = b'\x00\x00\x00\x00'
        self._siaddr = b'\x00\x00\x00\x00'
        self._giaddr = b'\x00\x00\x00\x00'

        if use_buffer:
            # bytes(array/bytearray) is the ownership boundary for direct
            # constructors.  Parsing then uses a message-relative view of that
            # immutable owner and never adjusts offsets against an outer frame.
            owner = _owned_bytes(candidate)
            mv = owner
            self._parse_message(mv)
            return

        self.op = kwargs.get('op', DHCP_BOOTREQUEST)
        self.htype = kwargs.get('htype', 1)
        self.hlen = kwargs.get('hlen', 6)
        self.hops = kwargs.get('hops', 0)
        self.xid = kwargs.get('xid', 0)
        self.secs = kwargs.get('secs', 0)
        self.flags = kwargs.get('flags', 0)
        self.ciaddr = kwargs.get('ciaddr', '0.0.0.0')
        self.yiaddr = kwargs.get('yiaddr', '0.0.0.0')
        self.siaddr = kwargs.get('siaddr', '0.0.0.0')
        self.giaddr = kwargs.get('giaddr', '0.0.0.0')
        self.chaddr = _owned_bytes(kwargs.get('chaddr', b''))
        self.sname = _owned_bytes(kwargs.get('sname', b''))
        self.file = _owned_bytes(kwargs.get('file', b''))
        self.magic = kwargs.get('magic', DHCP_MAGIC)
        self.options = list(kwargs.get('options', ()))
        self.data = _owned_bytes(kwargs.get('data', b''))

    @classmethod
    def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                    dict l7_ports):
        cdef:
            DHCP pkt
            const unsigned char[:] mv
            const unsigned char[:] message

        if start < 0 or end < start or end > len(owner):
            raise ValueError('DHCP: invalid owner range')

        # This Python-visible private hook is the explicit Layer-7 opt-in used
        # by UDP.  The passed registry is retained exactly, and slicing the
        # typed view is zero-copy: all parse offsets start at this DHCP message.
        pkt = cls.__new__(cls)
        pkt.l7_ports = l7_ports
        pkt.pkt_name = 'DHCP'
        pkt.pq_type, pkt.query_fields = DHCP.query_info()
        pkt.options = list()
        pkt.data = b''
        pkt._ciaddr = b'\x00\x00\x00\x00'
        pkt._yiaddr = b'\x00\x00\x00\x00'
        pkt._siaddr = b'\x00\x00\x00\x00'
        pkt._giaddr = b'\x00\x00\x00\x00'
        mv = owner
        message = mv[start:end]
        pkt._parse_message(message)
        return pkt

    cdef int _parse_message(self, const unsigned char[:] mv) except -1:
        cdef:
            Py_ssize_t offset = DHCP_FIXED_LEN
            Py_ssize_t length
            uint8_t code
            DHCPOption option

        # The single fixed-header preflight must precede every direct indexed
        # read because rd_u16/rd_u32 intentionally disable bounds checking.
        need_bytes(mv, DHCP_FIXED_LEN, 'DHCP')
        self.op = mv[0]
        self.htype = mv[1]
        self.hlen = mv[2]
        self.hops = mv[3]
        self.xid = rd_u32(mv, 4)
        self.secs = rd_u16(mv, 8)
        self.flags = rd_u16(mv, 10)
        self._ciaddr = rd_bytes(mv, 12, 16)
        self._yiaddr = rd_bytes(mv, 16, 20)
        self._siaddr = rd_bytes(mv, 20, 24)
        self._giaddr = rd_bytes(mv, 24, 28)
        self.chaddr = rd_bytes(mv, 28, 44).rstrip(b'\x00')
        self.sname = rd_bytes(mv, 44, 108).rstrip(b'\x00')
        self.file = rd_bytes(mv, 108, 236).rstrip(b'\x00')
        self.magic = rd_u32(mv, 236)
        self.options = list()
        self.data = b''

        # Options are walked exactly once. PAD and END become real list entries;
        # unknown codes use the same generic class and are never discarded.
        while offset < mv.shape[0]:
            code = mv[offset]
            option = DHCPOption.__new__(DHCPOption)
            option.code = code
            option.data = b''
            self.options.append(option)
            offset += 1
            if code == DHCP_OPT_PAD:
                continue
            if code == DHCP_OPT_END:
                self.data = rd_bytes(mv, offset, -1)
                return 0

            # Check for the length octet before reading it, then check the full
            # value before copying it to owned bytes.
            if offset >= mv.shape[0]:
                raise ValueError('DHCP option: truncated length')
            length = mv[offset]
            offset += 1
            if offset + length > mv.shape[0]:
                raise ValueError('DHCP option: truncated value')
            option.data = rd_bytes(mv, offset, offset + length)
            offset += length
        return 0

    property ciaddr:
        def __get__(self):
            return socket.inet_ntop(socket.AF_INET, self._ciaddr)
        def __set__(self, str value):
            self._ciaddr = socket.inet_pton(socket.AF_INET, value)

    property yiaddr:
        def __get__(self):
            return socket.inet_ntop(socket.AF_INET, self._yiaddr)
        def __set__(self, str value):
            self._yiaddr = socket.inet_pton(socket.AF_INET, value)

    property siaddr:
        def __get__(self):
            return socket.inet_ntop(socket.AF_INET, self._siaddr)
        def __set__(self, str value):
            self._siaddr = socket.inet_pton(socket.AF_INET, value)

    property giaddr:
        def __get__(self):
            return socket.inet_ntop(socket.AF_INET, self._giaddr)
        def __set__(self, str value):
            self._giaddr = socket.inet_pton(socket.AF_INET, value)

    property message_type:
        def __get__(self):
            cdef DHCPOption option
            for option in self.options:
                if (option.code == DHCP_OPT_MESSAGE_TYPE and
                        len(option.data) > 0):
                    return option.data[0]
            return None

    @classmethod
    def query_info(cls):
        # Query metadata is intentionally scalar. Raw option lists and trailing
        # bytes remain available on the object but are outside pcap-query's
        # fixed-field model.
        return (DHCP_PACKET_TYPE,
                ('dhcp.op', 'dhcp.htype', 'dhcp.hlen', 'dhcp.hops',
                 'dhcp.xid', 'dhcp.secs', 'dhcp.flags', 'dhcp.ciaddr',
                 'dhcp.yiaddr', 'dhcp.siaddr', 'dhcp.giaddr',
                 'dhcp.message_type'))

    @classmethod
    def default_ports(cls):
        # Both directions are included: clients and servers swap source and
        # destination ports during the exchange.
        return [DHCP_SERVER_PORT, DHCP_CLIENT_PORT]

    cpdef object get_field_val(self, str field):
        if field == 'dhcp.op':
            return self.op
        elif field == 'dhcp.htype':
            return self.htype
        elif field == 'dhcp.hlen':
            return self.hlen
        elif field == 'dhcp.hops':
            return self.hops
        elif field == 'dhcp.xid':
            return self.xid
        elif field == 'dhcp.secs':
            return self.secs
        elif field == 'dhcp.flags':
            return self.flags
        elif field == 'dhcp.ciaddr':
            return self.ciaddr
        elif field == 'dhcp.yiaddr':
            return self.yiaddr
        elif field == 'dhcp.siaddr':
            return self.siaddr
        elif field == 'dhcp.giaddr':
            return self.giaddr
        elif field == 'dhcp.message_type':
            return self.message_type
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef object item

        # _serialize acquires one growable writer for the whole enclosing frame;
        # this method appends fields, options, and tail without concatenating
        # intermediate bytes objects.
        w_u8(w, self.op)
        w_u8(w, self.htype)
        w_u8(w, self.hlen)
        w_u8(w, self.hops)
        w_u32(w, self.xid)
        w_u16(w, self.secs)
        w_u16(w, self.flags)
        w_bytes(w, self._ciaddr)
        w_bytes(w, self._yiaddr)
        w_bytes(w, self._siaddr)
        w_bytes(w, self._giaddr)
        _write_fixed(w, self.chaddr, DHCP_CHADDR_LEN)
        _write_fixed(w, self.sname, DHCP_SNAME_LEN)
        _write_fixed(w, self.file, DHCP_FILE_LEN)
        w_u32(w, self.magic)
        for item in self.options:
            if not isinstance(item, DHCPOption):
                raise TypeError('DHCP options must be DHCPOption instances')
            (<DHCPOption>item)._write(w)
        w_bytes(w, self.data)
        return 0


@cython.final
cdef class DHCP6Option:
    """A generic RFC 8415 option with 16-bit code and byte length."""

    def __init__(self, *args, **kwargs):
        cdef:
            bytes raw
            const unsigned char[:] mv
            Py_ssize_t length

        if len(args) == 1:
            raw = _owned_bytes(args[0])
            mv = raw
            # Guard both 16-bit fields before using the unchecked readers.
            need_bytes(mv, 4, 'DHCP6 option')
            self.code = rd_u16(mv, 0)
            length = rd_u16(mv, 2)
            if len(raw) < 4 + length:
                raise ValueError('DHCP6 option: truncated value')
            if len(raw) != 4 + length:
                raise ValueError('DHCP6 option: trailing bytes')
            self.data = rd_bytes(mv, 4, 4 + length)
            return
        elif len(args) != 0:
            raise TypeError('DHCP6Option accepts one raw buffer or keywords')

        self.code = kwargs.get('code', 0)
        self.data = _owned_bytes(kwargs.get('data', b''))

    def __repr__(self):
        return 'DHCP6Option(code={0}, data={1!r})'.format(self.code,
                                                          self.data)

    cpdef bytes pkt2net(self, dict kwargs):
        return _option6_wire(self)

    cdef int _write(self, PktWriter w) except -1:
        cdef Py_ssize_t length = len(self.data)
        if length > 65535:
            raise ValueError('DHCP6 option value exceeds 65535 bytes')
        w_u16(w, self.code)
        w_u16(w, <uint16_t>length)
        w_bytes(w, self.data)
        return 0


@cython.final
cdef class DHCP6(PKT):
    """A normal or relay DHCPv6 message with generic options."""

    def __init__(self, *args, **kwargs):
        cdef:
            object candidate = None
            bytes owner
            const unsigned char[:] mv
            bint use_buffer = 0
            object transaction_id

        self._base_l7(kwargs)
        self.pkt_name = 'DHCP6'
        self.pq_type, self.query_fields = DHCP6.query_info()

        # DHCP6 has no packet-level data field, so both DHCP6(raw) and the
        # standard DHCP6(data=raw) constructor forms are unambiguous.
        if len(args) == 1:
            candidate = args[0]
            use_buffer = 1
        elif len(args) != 0:
            raise TypeError('DHCP6 accepts one raw buffer or field keywords')
        elif 'data' in kwargs:
            candidate = kwargs['data']
            use_buffer = 1

        self.options = list()
        self._link_address = b'\x00' * 16
        self._peer_address = b'\x00' * 16
        self.hop_count = 0
        self.transaction_id = 0

        if use_buffer:
            owner = _owned_bytes(candidate)
            mv = owner
            self._parse_message(mv)
            return

        self.msg_type = kwargs.get('msg_type', DHCP6_SOLICIT)
        transaction_id = kwargs.get('transaction_id', 0)
        if transaction_id < 0 or transaction_id > 0xffffff:
            raise ValueError('DHCP6 transaction_id must fit in 24 bits')
        self.transaction_id = transaction_id
        self.hop_count = kwargs.get('hop_count', 0)
        self.link_address = kwargs.get('link_address', '::')
        self.peer_address = kwargs.get('peer_address', '::')
        self.options = list(kwargs.get('options', ()))

    @classmethod
    def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                    dict l7_ports):
        cdef:
            DHCP6 pkt
            const unsigned char[:] mv
            const unsigned char[:] message

        if start < 0 or end < start or end > len(owner):
            raise ValueError('DHCP6: invalid owner range')

        # As with DHCPv4, this hook opts into UDP's immutable owner/range path.
        # Only option values become copies; the parser itself reads a zero-copy,
        # message-relative view and preserves the caller's registry object.
        pkt = cls.__new__(cls)
        pkt.l7_ports = l7_ports
        pkt.pkt_name = 'DHCP6'
        pkt.pq_type, pkt.query_fields = DHCP6.query_info()
        pkt.options = list()
        pkt._link_address = b'\x00' * 16
        pkt._peer_address = b'\x00' * 16
        pkt.hop_count = 0
        pkt.transaction_id = 0
        mv = owner
        message = mv[start:end]
        pkt._parse_message(message)
        return pkt

    cdef int _parse_message(self, const unsigned char[:] mv) except -1:
        cdef:
            Py_ssize_t offset
            Py_ssize_t length
            DHCP6Option option

        # One byte is enough to choose the header shape, but each complete
        # shape is checked before any remaining direct reads.
        need_bytes(mv, 1, 'DHCP6')
        self.msg_type = mv[0]
        if (self.msg_type == DHCP6_RELAY_FORWARD or
                self.msg_type == DHCP6_RELAY_REPLY):
            need_bytes(mv, DHCP6_RELAY_LEN, 'DHCP6 relay')
            self.hop_count = mv[1]
            self.transaction_id = 0
            self._link_address = rd_bytes(mv, 2, 18)
            self._peer_address = rd_bytes(mv, 18, 34)
            offset = DHCP6_RELAY_LEN
        else:
            need_bytes(mv, DHCP6_NORMAL_LEN, 'DHCP6')
            self.transaction_id = ((<uint32_t>mv[1] << 16) |
                                   (<uint32_t>mv[2] << 8) | mv[3])
            self.hop_count = 0
            self._link_address = b'\x00' * 16
            self._peer_address = b'\x00' * 16
            offset = DHCP6_NORMAL_LEN

        self.options = list()
        # DHCPv6 has no marker options, so every remainder must be a complete
        # TLV. Unknown codes are retained in order with owned byte values.
        while offset < mv.shape[0]:
            if offset + 4 > mv.shape[0]:
                raise ValueError('DHCP6 option: truncated header')
            option = DHCP6Option.__new__(DHCP6Option)
            option.code = rd_u16(mv, offset)
            length = rd_u16(mv, offset + 2)
            offset += 4
            if offset + length > mv.shape[0]:
                raise ValueError('DHCP6 option: truncated value')
            option.data = rd_bytes(mv, offset, offset + length)
            self.options.append(option)
            offset += length
        return 0

    property link_address:
        def __get__(self):
            return socket.inet_ntop(socket.AF_INET6, self._link_address)
        def __set__(self, str value):
            self._link_address = socket.inet_pton(socket.AF_INET6, value)

    property peer_address:
        def __get__(self):
            return socket.inet_ntop(socket.AF_INET6, self._peer_address)
        def __set__(self, str value):
            self._peer_address = socket.inet_pton(socket.AF_INET6, value)

    @classmethod
    def query_info(cls):
        # Both normal and relay fields are listed. Inapplicable fields have
        # stable neutral values (zero or ::), keeping every advertised query
        # field resolvable without protocol-shape special cases.
        return (DHCP6_PACKET_TYPE,
                ('dhcp6.msg_type', 'dhcp6.transaction_id',
                 'dhcp6.hop_count', 'dhcp6.link_address',
                 'dhcp6.peer_address'))

    @classmethod
    def default_ports(cls):
        return [DHCP6_SERVER_PORT, DHCP6_CLIENT_PORT]

    cpdef object get_field_val(self, str field):
        if field == 'dhcp6.msg_type':
            return self.msg_type
        elif field == 'dhcp6.transaction_id':
            return self.transaction_id
        elif field == 'dhcp6.hop_count':
            return self.hop_count
        elif field == 'dhcp6.link_address':
            return self.link_address
        elif field == 'dhcp6.peer_address':
            return self.peer_address
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef object item

        w_u8(w, self.msg_type)
        if (self.msg_type == DHCP6_RELAY_FORWARD or
                self.msg_type == DHCP6_RELAY_REPLY):
            w_u8(w, self.hop_count)
            w_bytes(w, self._link_address)
            w_bytes(w, self._peer_address)
        else:
            if self.transaction_id > 0xffffff:
                raise ValueError('DHCP6 transaction_id must fit in 24 bits')
            w_u8(w, <uint8_t>(self.transaction_id >> 16))
            w_u8(w, <uint8_t>(self.transaction_id >> 8))
            w_u8(w, <uint8_t>self.transaction_id)

        for item in self.options:
            if not isinstance(item, DHCP6Option):
                raise TypeError('DHCP6 options must be DHCP6Option instances')
            (<DHCP6Option>item)._write(w)
        return 0
