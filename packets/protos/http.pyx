# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Lossless-enough HTTP/0.9 and HTTP/1.x packet examples.

HTTP syntax is byte syntax, so every public wire field is ``bytes`` rather than
``str``.  Decoding header values would require an application-specific choice
of character set and could make a packet impossible to reproduce.  Likewise,
headers and trailers are ordered lists of ``(original_name, value)`` tuples:
the list preserves order and duplicates, while the original name bytes retain
case for serialization.

This is deliberately a packet/message example, not an HTTP stack.  It does not
perform TCP stream reassembly, TLS, HTTP/2, content decompression, routing, or
server/client behavior.  Callers must supply one complete message buffer; any
bytes belonging to a later pipelined message are exposed as ``data``.

A fixed ``Content-Length`` body may still be split across TCP segments by the
path MTU, so a single captured packet can carry only the leading part of it.
Rather than reject such a fragment, whatever bytes are present are kept as the
(partial) ``body``, ``data`` is left empty, and ``body_complete`` is set to
false so callers can tell that stream reassembly is required to see the rest.

The remaining segments of that body -- the packets carrying its middle or its
end -- have no start line of their own.  The ``HTTP`` dispatcher does not reject
them either: a buffer with no parseable request or response start line becomes
an ``HTTPBodyFragment`` whose opaque bytes are kept in ``data`` (with
``body_complete`` false).  A caller can therefore collect the first message plus
its follow-on fragments in capture order and reassemble the whole body itself;
this module still performs no TCP stream reassembly inside the decoder.

For callers that want that reassembly done for them, the module-level
``get_http_streams`` helper is the deliberately-separate layer above the
per-packet decoder: it groups decoded packets into bidirectional TCP
connections, orders each direction by sequence number, concatenates the
``HTTPRequest`` / ``HTTPResponse`` / ``HTTPBodyFragment`` payloads back into a
continuous stream, and re-parses whole request/response ``HTTP`` objects from
it.  See its docstring for the returned mapping.
"""

cimport cython

from packets.core.inetpkt cimport PKT, PktWriter, rd_bytes, w_bytes, \
    _serialize


cdef bytes _CRLF = b'\r\n'
cdef bytes _TOKEN_EXTRA = b"!#$%&'*+-.^_`|~"


cdef inline bytes _owned_bytes(object value):
    """Copy mutable byte providers and retain already immutable bytes."""
    if isinstance(value, bytes):
        return value
    return bytes(value)


cdef bint _is_token(bytes value):
    """Validate an RFC token without relying on locale-sensitive text APIs."""
    cdef:
        const unsigned char[:] mv = value
        Py_ssize_t i
        unsigned char ch

    if mv.shape[0] == 0:
        return 0
    for i in range(mv.shape[0]):
        ch = mv[i]
        if ((ch >= 48 and ch <= 57) or
                (ch >= 65 and ch <= 90) or
                (ch >= 97 and ch <= 122) or
                ch in _TOKEN_EXTRA):
            continue
        return 0
    return 1


cdef bint _is_decimal(bytes value):
    cdef:
        const unsigned char[:] mv = value
        Py_ssize_t i

    if mv.shape[0] == 0:
        return 0
    for i in range(mv.shape[0]):
        if mv[i] < 48 or mv[i] > 57:
            return 0
    return 1


cdef bint _is_hex(bytes value):
    cdef:
        const unsigned char[:] mv = value
        Py_ssize_t i
        unsigned char ch

    if mv.shape[0] == 0:
        return 0
    for i in range(mv.shape[0]):
        ch = mv[i]
        if ((ch >= 48 and ch <= 57) or
                (ch >= 65 and ch <= 70) or
                (ch >= 97 and ch <= 102)):
            continue
        return 0
    return 1


cdef bint _is_field_value(bytes value):
    """Reject bare controls while retaining opaque visible and obs-text bytes."""
    cdef:
        const unsigned char[:] mv = value
        Py_ssize_t i
        unsigned char ch

    for i in range(mv.shape[0]):
        ch = mv[i]
        if ch == 9 or (ch >= 32 and ch != 127):
            continue
        return 0
    return 1


cdef bint _is_request_target(bytes value):
    """A request target is nonempty and cannot contain whitespace/controls."""
    cdef:
        const unsigned char[:] mv = value
        Py_ssize_t i
        unsigned char ch

    if mv.shape[0] == 0:
        return 0
    for i in range(mv.shape[0]):
        ch = mv[i]
        if ch <= 32 or ch == 127:
            return 0
    return 1


cdef bint _is_http1_version(bytes value):
    cdef bytes minor
    if not value.startswith(b'HTTP/1.'):
        return 0
    minor = value[7:]
    return _is_decimal(minor)


@cython.boundscheck(False)
@cython.wraparound(False)
cdef Py_ssize_t _find_crlf(const unsigned char[:] mv,
                           Py_ssize_t start):
    """Find a complete CRLF without reading beyond a truncated buffer."""
    cdef Py_ssize_t i = start
    while i + 1 < mv.shape[0]:
        if mv[i] == 13 and mv[i + 1] == 10:
            return i
        i += 1
    return -1


cdef list _owned_headers(object values):
    """Validate field-built headers and own both elements of every tuple."""
    cdef:
        list result = list()
        object item
        bytes name
        bytes value

    for item in values:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError('HTTP headers must be (name, value) tuples')
        name = _owned_bytes(item[0])
        value = _owned_bytes(item[1])
        if not _is_token(name):
            raise ValueError('HTTP: invalid header name')
        if not _is_field_value(value):
            raise ValueError('HTTP: invalid header value')
        result.append((name, value))
    return result


cdef tuple _parse_headers(const unsigned char[:] mv, Py_ssize_t start,
                          str section):
    """Parse one CRLF-terminated header or trailer block.

    Every line is bounded before it is copied.  Obsolete continuation lines
    and names containing separators or controls are rejected rather than
    ambiguously folded.  Values lose only surrounding SP/HTAB; their remaining
    bytes, duplicate occurrence, and original name case are preserved.
    """
    cdef:
        list result = list()
        Py_ssize_t line_end
        Py_ssize_t colon
        bytes line
        bytes name
        bytes value

    while True:
        line_end = _find_crlf(mv, start)
        if line_end < 0:
            raise ValueError('HTTP: incomplete %s' % section)
        if line_end == start:
            return result, start + 2
        line = rd_bytes(mv, start, line_end)
        colon = line.find(b':')
        if colon <= 0:
            raise ValueError('HTTP: invalid %s line' % section)
        name = line[:colon]
        if not _is_token(name):
            raise ValueError('HTTP: invalid %s name' % section)
        value = line[colon + 1:].strip(b' \t')
        if not _is_field_value(value):
            raise ValueError('HTTP: invalid %s value' % section)
        result.append((name, value))
        start = line_end + 2


cdef bytes _lookup_name(object name):
    """Allow convenient text lookup while keeping all stored syntax bytes."""
    if isinstance(name, bytes):
        return (<bytes>name).lower()
    if isinstance(name, str):
        return (<str>name).encode('ascii').lower()
    return bytes(name).lower()


cdef list _get_headers(list headers, object name):
    cdef:
        bytes wanted = _lookup_name(name)
        list values = list()
        object item

    for item in headers:
        if (<bytes>item[0]).lower() == wanted:
            values.append(item[1])
    return values


cdef object _content_length(list headers):
    """Return the agreed Content-Length, rejecting every ambiguous spelling."""
    cdef:
        object agreed = None
        object item
        bytes value
        bytes part
        object parsed

    # Multiple fields and comma lists are legal only when every value agrees.
    # Signs, empty list elements, and non-decimal forms are invalid; this also
    # rejects negative lengths before they can affect a bounds calculation.
    for item in headers:
        if (<bytes>item[0]).lower() != b'content-length':
            continue
        value = item[1]
        for part in value.split(b','):
            part = part.strip(b' \t')
            if not _is_decimal(part):
                raise ValueError('HTTP: invalid Content-Length')
            parsed = int(part)
            if agreed is None:
                agreed = parsed
            elif agreed != parsed:
                raise ValueError('HTTP: conflicting Content-Length')
    return agreed


cdef bint _has_final_chunked(list headers):
    cdef:
        list codings = list()
        object item
        bytes part

    # Transfer-Encoding fields combine in wire order.  Chunk framing applies
    # only when the final coding token is chunked; earlier codings remain opaque
    # because decompression is intentionally outside this packet example.
    for item in headers:
        if (<bytes>item[0]).lower() != b'transfer-encoding':
            continue
        for part in (<bytes>item[1]).split(b','):
            part = part.strip(b' \t').lower()
            if part:
                codings.append(part)
    return bool(codings and codings[-1] == b'chunked')


cdef tuple _parse_chunks(const unsigned char[:] mv, Py_ssize_t start):
    """Decode chunks and retain the exact framing range for lossless replay."""
    cdef:
        Py_ssize_t offset = start
        Py_ssize_t line_end
        Py_ssize_t size
        Py_ssize_t body_end
        bytes line
        bytes size_part
        object parsed_size
        list chunks = list()
        list trailers
        tuple parsed

    while True:
        line_end = _find_crlf(mv, offset)
        if line_end < 0:
            raise ValueError('HTTP: incomplete chunk size')
        line = rd_bytes(mv, offset, line_end)
        # Extensions are wire metadata for this example.  They are ignored for
        # semantics but remain byte-for-byte in the saved framing below.
        size_part = line.split(b';', 1)[0]
        if not _is_hex(size_part):
            raise ValueError('HTTP: malformed chunk size')
        parsed_size = int(size_part, 16)
        if parsed_size > mv.shape[0]:
            raise ValueError('HTTP: incomplete chunk data')
        size = parsed_size
        offset = line_end + 2

        if size == 0:
            parsed = _parse_headers(mv, offset, 'trailers')
            trailers = parsed[0]
            offset = parsed[1]
            # The exact size spelling, extensions, chunk boundaries, CRLFs,
            # and trailer formatting can now be reused while semantic fields
            # remain unchanged.
            return (b''.join(chunks), trailers, offset,
                    rd_bytes(mv, start, offset))

        body_end = offset + size
        if body_end > mv.shape[0]:
            raise ValueError('HTTP: incomplete chunk data')
        if body_end + 2 > mv.shape[0]:
            raise ValueError('HTTP: incomplete chunk CRLF')
        if mv[body_end] != 13 or mv[body_end + 1] != 10:
            raise ValueError('HTTP: malformed chunk CRLF')
        chunks.append(rd_bytes(mv, offset, body_end))
        offset = body_end + 2


cdef int _write_headers(PktWriter w, list headers) except -1:
    cdef:
        object item
        bytes name
        bytes value

    for item in headers:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError('HTTP headers must be (name, value) tuples')
        name = _owned_bytes(item[0])
        value = _owned_bytes(item[1])
        if not _is_token(name):
            raise ValueError('HTTP: invalid header name')
        if not _is_field_value(value):
            raise ValueError('HTTP: invalid header value')
        w_bytes(w, name)
        w_bytes(w, b': ')
        w_bytes(w, value)
        w_bytes(w, _CRLF)
    return 0


cdef int _write_canonical_chunks(PktWriter w, bytes body,
                                 list trailers) except -1:
    cdef bytes size_line

    # Rewriting semantic chunk content intentionally chooses one deterministic
    # chunk with lowercase hexadecimal.  Parsed framing is used instead when
    # body and trailers still match their snapshots.
    if body:
        size_line = ('%x' % len(body)).encode('ascii')
        w_bytes(w, size_line)
        w_bytes(w, _CRLF)
        w_bytes(w, body)
        w_bytes(w, _CRLF)
    w_bytes(w, b'0\r\n')
    _write_headers(w, trailers)
    w_bytes(w, _CRLF)
    return 0


cdef bint _looks_like_response(const unsigned char[:] mv,
                               Py_ssize_t start, Py_ssize_t end):
    return (end - start >= 5 and mv[start] == 72 and mv[start + 1] == 84 and
            mv[start + 2] == 84 and mv[start + 3] == 80 and
            mv[start + 4] == 47)


cdef Py_ssize_t _find_crlf_within(const unsigned char[:] mv,
                                  Py_ssize_t start, Py_ssize_t end):
    """Find a CRLF inside an explicit [start, end) range only."""
    cdef Py_ssize_t i = start
    while i + 1 < end:
        if mv[i] == 13 and mv[i + 1] == 10:
            return i
        i += 1
    return -1


cdef bint _looks_like_response_line(const unsigned char[:] mv,
                                    Py_ssize_t start, Py_ssize_t end):
    """Confirm a CRLF-terminated ``HTTP/1.x <status> <reason>`` start line.

    The dispatcher must tell a genuine response apart from body bytes that
    merely happen to begin with ``HTTP/``, so the whole status line is checked
    rather than only its first five bytes.
    """
    cdef:
        Py_ssize_t line_end
        bytes line
        list parts

    if not _looks_like_response(mv, start, end):
        return 0
    line_end = _find_crlf_within(mv, start, end)
    if line_end < 0:
        return 0
    line = rd_bytes(mv, start, line_end)
    parts = line.split(b' ', 2)
    if len(parts) != 3 or not _is_http1_version(parts[0]):
        return 0
    if len(parts[1]) != 3 or not _is_decimal(parts[1]):
        return 0
    return 1


cdef bint _looks_like_request_line(const unsigned char[:] mv,
                                   Py_ssize_t start, Py_ssize_t end):
    """Confirm a CRLF-terminated request start line before dispatching.

    A continuation packet carrying only the middle or end of a body has no
    parseable start line, so the dispatcher checks that the first line is a
    valid ``method target [version]`` before handing the bytes to
    ``HTTPRequest``; otherwise the bytes are kept as an ``HTTPBodyFragment``.
    """
    cdef:
        Py_ssize_t line_end
        bytes line
        list parts

    line_end = _find_crlf_within(mv, start, end)
    if line_end < 0:
        return 0
    line = rd_bytes(mv, start, line_end)
    parts = line.split(b' ')
    if len(parts) != 2 and len(parts) != 3:
        return 0
    if not _is_token(parts[0]) or not _is_request_target(parts[1]):
        return 0
    if len(parts) == 3 and not _is_http1_version(parts[2]):
        return 0
    return 1


@cython.final
cdef class HTTPRequest(PKT):
    """An HTTP/0.9 or HTTP/1.x request and any following stream bytes."""

    def __init__(self, *args, **kwargs):
        cdef:
            bytes owner
            const unsigned char[:] mv

        self._base_l7(kwargs)
        self.pkt_name = 'HTTPRequest'
        self.pq_type, self.query_fields = HTTPRequest.query_info()
        self.headers = list()
        self.trailers = list()
        self.body = b''
        self.data = b''
        self.body_complete = 1
        self._chunked = 0
        self._chunk_wire = b''
        self._chunk_body = b''
        self._chunk_trailers = tuple()

        # A single positional provider is the unambiguous raw-buffer form.
        # bytes(array/bytearray) establishes immutable ownership before parsing;
        # field construction separately owns every mutable value it receives.
        if len(args) == 1:
            owner = _owned_bytes(args[0])
            mv = owner
            self._parse_message(mv)
            return
        elif len(args) != 0:
            raise TypeError('HTTPRequest accepts one raw buffer or keywords')

        self.method = _owned_bytes(kwargs.get('method', b'GET'))
        self.target = _owned_bytes(kwargs.get('target', b'/'))
        self.version = _owned_bytes(kwargs.get('version', b'HTTP/1.1'))
        self.headers = _owned_headers(kwargs.get('headers', ()))
        self.body = _owned_bytes(kwargs.get('body', b''))
        self.data = _owned_bytes(kwargs.get('data', b''))
        self.trailers = _owned_headers(kwargs.get('trailers', ()))
        self.body_complete = 1
        self._chunked = _has_final_chunked(self.headers)
        _content_length(self.headers)

    @classmethod
    def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                    dict l7_ports):
        cdef:
            HTTPRequest pkt
            const unsigned char[:] mv
            const unsigned char[:] message

        if start < 0 or end < start or end > len(owner):
            raise ValueError('HTTPRequest: invalid owner range')

        # UDP/TCP Layer-7 opt-in passes an immutable outer owner and offsets.
        # The typed slice is a zero-copy, message-relative view; public fields
        # are copied as owned bytes so the result never depends on outer life.
        pkt = cls.__new__(cls)
        pkt.l7_ports = l7_ports
        pkt.pkt_name = 'HTTPRequest'
        pkt.pq_type, pkt.query_fields = HTTPRequest.query_info()
        pkt.headers = list()
        pkt.trailers = list()
        pkt.body = b''
        pkt.data = b''
        pkt.body_complete = 1
        pkt._chunked = 0
        pkt._chunk_wire = b''
        pkt._chunk_body = b''
        pkt._chunk_trailers = tuple()
        mv = owner
        message = mv[start:end]
        pkt._parse_message(message)
        return pkt

    cdef int _parse_message(self, const unsigned char[:] mv) except -1:
        cdef:
            Py_ssize_t line_end
            Py_ssize_t offset
            Py_ssize_t body_end
            bytes line
            list parts
            tuple parsed
            object content_length

        self.body_complete = 1
        line_end = _find_crlf(mv, 0)
        if line_end < 0:
            raise ValueError('HTTP request: missing or incomplete start line')
        line = rd_bytes(mv, 0, line_end)
        parts = line.split(b' ')
        if len(parts) != 2 and len(parts) != 3:
            raise ValueError('HTTP request: invalid start line')
        if not _is_token(parts[0]) or not _is_request_target(parts[1]):
            raise ValueError('HTTP request: invalid start line')
        self.method = parts[0]
        self.target = parts[1]
        offset = line_end + 2

        if len(parts) == 2:
            # HTTP/0.9 has no header section.  This parser does not guess where
            # another stream message starts, so all remainder is explicit data.
            # Expose an explicit version for queries even though it is implied,
            # not present, on the wire; the writer still emits two tokens.
            self.version = b'HTTP/0.9'
            self.headers = list()
            self.trailers = list()
            self.body = b''
            self.data = rd_bytes(mv, offset, -1)
            return 0

        self.version = parts[2]
        if not _is_http1_version(self.version):
            raise ValueError('HTTP request: invalid HTTP/1.x version')
        parsed = _parse_headers(mv, offset, 'headers')
        self.headers = parsed[0]
        offset = parsed[1]
        content_length = _content_length(self.headers)
        self._chunked = _has_final_chunked(self.headers)

        if self._chunked:
            parsed = _parse_chunks(mv, offset)
            self.body = parsed[0]
            self.trailers = parsed[1]
            body_end = parsed[2]
            self._chunk_wire = parsed[3]
            self._chunk_body = self.body
            self._chunk_trailers = tuple(self.trailers)
            self.data = rd_bytes(mv, body_end, -1)
        elif content_length is not None:
            if content_length > mv.shape[0] - offset:
                # The declared body is longer than the bytes present: this is a
                # fragment split across TCP segments by the path MTU.  Keep the
                # partial body instead of rejecting it and flag it incomplete.
                self.body = rd_bytes(mv, offset, -1)
                self.body_complete = 0
                self.trailers = list()
                self.data = b''
            else:
                body_end = offset + content_length
                self.body = rd_bytes(mv, offset, body_end)
                self.trailers = list()
                self.data = rd_bytes(mv, body_end, -1)
        else:
            # Requests without framing have no safely attributable body.  The
            # remainder may be a pipeline and is therefore preserved as data.
            self.body = b''
            self.trailers = list()
            self.data = rd_bytes(mv, offset, -1)
        return 0

    cpdef object get_header(self, object name, object default=None):
        cdef list values = _get_headers(self.headers, name)
        if values:
            return values[0]
        return default

    cpdef list get_headers(self, object name):
        return _get_headers(self.headers, name)

    @classmethod
    def query_info(cls):
        # Only scalar, shape-valid fields are advertised by this concrete type.
        return (HTTP_PACKET_TYPE,
                ('http.request.method', 'http.request.target',
                 'http.request.version', 'http.body_length'))

    @classmethod
    def default_ports(cls):
        return [HTTP_PACKET_PORT]

    cpdef object get_field_val(self, str field):
        if field == 'http.request.method':
            return self.method
        elif field == 'http.request.target':
            return self.target
        elif field == 'http.request.version':
            return self.version
        elif field == 'http.body_length':
            return len(self.body)
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        # _serialize allocates/acquires the one writer used by every nested
        # route; _write never constructs a second whole-message bytes object.
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef:
            bint chunked
            bint http09 = (self.version == b'HTTP/0.9' or
                            self.version == b'')

        if (not _is_token(self.method) or
                not _is_request_target(self.target)):
            raise ValueError('HTTP request: invalid start line')
        w_bytes(w, self.method)
        w_bytes(w, b' ')
        w_bytes(w, self.target)
        if not http09:
            if not _is_http1_version(self.version):
                raise ValueError('HTTP request: invalid HTTP/1.x version')
            w_bytes(w, b' ')
            w_bytes(w, self.version)
        w_bytes(w, _CRLF)

        if not http09:
            _write_headers(w, self.headers)
            w_bytes(w, _CRLF)
            _content_length(self.headers)
            chunked = _has_final_chunked(self.headers)
            if chunked:
                if (self._chunked and self.body == self._chunk_body and
                        tuple(self.trailers) == self._chunk_trailers):
                    w_bytes(w, self._chunk_wire)
                else:
                    _write_canonical_chunks(w, self.body, self.trailers)
            else:
                w_bytes(w, self.body)
        else:
            w_bytes(w, self.body)
        # Bytes after the framed message are never silently discarded.
        w_bytes(w, self.data)
        return 0


@cython.final
cdef class HTTPResponse(PKT):
    """An HTTP/1.x response with fixed, chunked, or close-delimited body."""

    def __init__(self, *args, **kwargs):
        cdef:
            bytes owner
            const unsigned char[:] mv

        self._base_l7(kwargs)
        self.pkt_name = 'HTTPResponse'
        self.pq_type, self.query_fields = HTTPResponse.query_info()
        self.headers = list()
        self.trailers = list()
        self.body = b''
        self.data = b''
        self.body_complete = 1
        self._chunked = 0
        self._chunk_wire = b''
        self._chunk_body = b''
        self._chunk_trailers = tuple()

        if len(args) == 1:
            owner = _owned_bytes(args[0])
            mv = owner
            self._parse_message(mv)
            return
        elif len(args) != 0:
            raise TypeError('HTTPResponse accepts one raw buffer or keywords')

        self.version = _owned_bytes(kwargs.get('version', b'HTTP/1.1'))
        self.status = _owned_bytes(kwargs.get('status', b'200'))
        self.reason = _owned_bytes(kwargs.get('reason', b'OK'))
        self.headers = _owned_headers(kwargs.get('headers', ()))
        self.body = _owned_bytes(kwargs.get('body', b''))
        self.data = _owned_bytes(kwargs.get('data', b''))
        self.trailers = _owned_headers(kwargs.get('trailers', ()))
        self.body_complete = 1
        self._chunked = _has_final_chunked(self.headers)
        _content_length(self.headers)

    @classmethod
    def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                    dict l7_ports):
        cdef:
            HTTPResponse pkt
            const unsigned char[:] mv
            const unsigned char[:] message

        if start < 0 or end < start or end > len(owner):
            raise ValueError('HTTPResponse: invalid owner range')

        pkt = cls.__new__(cls)
        pkt.l7_ports = l7_ports
        pkt.pkt_name = 'HTTPResponse'
        pkt.pq_type, pkt.query_fields = HTTPResponse.query_info()
        pkt.headers = list()
        pkt.trailers = list()
        pkt.body = b''
        pkt.data = b''
        pkt.body_complete = 1
        pkt._chunked = 0
        pkt._chunk_wire = b''
        pkt._chunk_body = b''
        pkt._chunk_trailers = tuple()
        mv = owner
        message = mv[start:end]
        pkt._parse_message(message)
        return pkt

    cdef int _parse_message(self, const unsigned char[:] mv) except -1:
        cdef:
            Py_ssize_t line_end
            Py_ssize_t offset
            Py_ssize_t body_end
            bytes line
            list parts
            tuple parsed
            object content_length
            int status_code

        self.body_complete = 1
        line_end = _find_crlf(mv, 0)
        if line_end < 0:
            raise ValueError('HTTP response: missing or incomplete start line')
        line = rd_bytes(mv, 0, line_end)
        parts = line.split(b' ', 2)
        if len(parts) != 3 or not _is_http1_version(parts[0]):
            raise ValueError('HTTP response: invalid start line')
        if len(parts[1]) != 3 or not _is_decimal(parts[1]):
            raise ValueError('HTTP response: invalid status')
        self.version = parts[0]
        self.status = parts[1]
        self.reason = parts[2]
        if not _is_field_value(self.reason):
            raise ValueError('HTTP response: invalid reason')
        status_code = int(self.status)
        offset = line_end + 2

        parsed = _parse_headers(mv, offset, 'headers')
        self.headers = parsed[0]
        offset = parsed[1]
        content_length = _content_length(self.headers)
        self._chunked = _has_final_chunked(self.headers)

        if self._chunked:
            parsed = _parse_chunks(mv, offset)
            self.body = parsed[0]
            self.trailers = parsed[1]
            body_end = parsed[2]
            self._chunk_wire = parsed[3]
            self._chunk_body = self.body
            self._chunk_trailers = tuple(self.trailers)
            self.data = rd_bytes(mv, body_end, -1)
        elif content_length is not None:
            if content_length > mv.shape[0] - offset:
                # The declared body is longer than the bytes present: this is a
                # fragment split across TCP segments by the path MTU.  Keep the
                # partial body instead of rejecting it and flag it incomplete.
                self.body = rd_bytes(mv, offset, -1)
                self.body_complete = 0
                self.trailers = list()
                self.data = b''
            else:
                body_end = offset + content_length
                self.body = rd_bytes(mv, offset, body_end)
                self.trailers = list()
                self.data = rd_bytes(mv, body_end, -1)
        elif ((status_code >= 100 and status_code < 200) or
              status_code == 204 or status_code == 304):
            # These statuses have no close-delimited payload; remaining bytes
            # can therefore be preserved as a subsequent pipelined message.
            self.body = b''
            self.trailers = list()
            self.data = rd_bytes(mv, offset, -1)
        else:
            # Without explicit framing, HTTP/1.x defines the connection close
            # as the body delimiter.  The supplied complete buffer is consumed.
            self.body = rd_bytes(mv, offset, -1)
            self.trailers = list()
            self.data = b''
        return 0

    cpdef object get_header(self, object name, object default=None):
        cdef list values = _get_headers(self.headers, name)
        if values:
            return values[0]
        return default

    cpdef list get_headers(self, object name):
        return _get_headers(self.headers, name)

    @classmethod
    def query_info(cls):
        return (HTTP_PACKET_TYPE,
                ('http.response.version', 'http.response.status',
                 'http.response.reason', 'http.body_length'))

    @classmethod
    def default_ports(cls):
        return [HTTP_PACKET_PORT]

    cpdef object get_field_val(self, str field):
        if field == 'http.response.version':
            return self.version
        elif field == 'http.response.status':
            return self.status
        elif field == 'http.response.reason':
            return self.reason
        elif field == 'http.body_length':
            return len(self.body)
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        cdef bint chunked

        if (not _is_http1_version(self.version) or len(self.status) != 3 or
                not _is_decimal(self.status) or
                not _is_field_value(self.reason)):
            raise ValueError('HTTP response: invalid start line')
        w_bytes(w, self.version)
        w_bytes(w, b' ')
        w_bytes(w, self.status)
        w_bytes(w, b' ')
        w_bytes(w, self.reason)
        w_bytes(w, _CRLF)
        _write_headers(w, self.headers)
        w_bytes(w, _CRLF)
        _content_length(self.headers)
        chunked = _has_final_chunked(self.headers)
        if chunked:
            if (self._chunked and self.body == self._chunk_body and
                    tuple(self.trailers) == self._chunk_trailers):
                w_bytes(w, self._chunk_wire)
            else:
                _write_canonical_chunks(w, self.body, self.trailers)
        else:
            w_bytes(w, self.body)
        w_bytes(w, self.data)
        return 0


@cython.final
cdef class HTTPBodyFragment(PKT):
    """Opaque continuation bytes from a packet with no HTTP start line.

    A fixed-length or chunked body can be spread across several TCP segments by
    the path MTU.  Only the first segment carries the request or response start
    line; a segment holding the middle or the end of the body has no parseable
    framing of its own.  Rather than reject such a packet, the dispatcher keeps
    its bytes verbatim in ``data`` and leaves ``body_complete`` false, so a
    caller can gather these fragments in capture order and reassemble the whole
    message from the stream.  This type never appears for a buffer that begins a
    valid request or response; it is produced only by the ``HTTP`` dispatcher.
    """

    def __init__(self, *args, **kwargs):
        self._base_l7(kwargs)
        self.pkt_name = 'HTTPBodyFragment'
        self.pq_type, self.query_fields = HTTPBodyFragment.query_info()
        self.data = b''
        # A continuation fragment is, by definition, an incomplete message.
        self.body_complete = 0

        if len(args) == 1:
            self.data = _owned_bytes(args[0])
            return
        elif len(args) != 0:
            raise TypeError(
                'HTTPBodyFragment accepts one raw buffer or data=')

        self.data = _owned_bytes(kwargs.get('data', b''))

    @classmethod
    def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                    dict l7_ports):
        cdef:
            HTTPBodyFragment pkt
            const unsigned char[:] mv

        if start < 0 or end < start or end > len(owner):
            raise ValueError('HTTPBodyFragment: invalid owner range')

        # The range is copied to an owned bytes object so the fragment survives
        # the outer packet exactly like a parsed message's public byte fields.
        pkt = cls.__new__(cls)
        pkt.l7_ports = l7_ports
        pkt.pkt_name = 'HTTPBodyFragment'
        pkt.pq_type, pkt.query_fields = HTTPBodyFragment.query_info()
        pkt.body_complete = 0
        mv = owner
        pkt.data = rd_bytes(mv, start, end)
        return pkt

    cpdef object get_header(self, object name, object default=None):
        # A continuation fragment carries no header section.
        return default

    cpdef list get_headers(self, object name):
        return list()

    @classmethod
    def query_info(cls):
        return (HTTP_PACKET_TYPE, ('http.body_length',))

    @classmethod
    def default_ports(cls):
        return [HTTP_PACKET_PORT]

    cpdef object get_field_val(self, str field):
        if field == 'http.body_length':
            return len(self.data)
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        # The bytes are opaque, so serialization is a verbatim round trip.
        w_bytes(w, self.data)
        return 0


@cython.final
cdef class HTTP(PKT):
    """Request/response dispatcher intended for ``l7_ports={80: HTTP}``.

    A buffer that begins a valid response or request becomes an ``HTTPResponse``
    or ``HTTPRequest``.  A buffer with no parseable start line -- a packet that
    carries only the middle or the end of a body split by the path MTU --
    becomes an ``HTTPBodyFragment`` instead of raising, so a caller scanning a
    capture can collect the pieces and reassemble the stream itself.
    """

    def __init__(self, *args, **kwargs):
        cdef:
            bytes owner
            const unsigned char[:] mv

        self._base_l7(kwargs)
        self.pkt_name = 'HTTP'
        self.pq_type, self.query_fields = HTTP.query_info()

        if len(args) == 1:
            # Direct dispatch owns mutable input once.  Child owner hooks parse
            # ranges without first allocating a second payload bytes object.
            owner = _owned_bytes(args[0])
            mv = owner
            if _looks_like_response_line(mv, 0, len(owner)):
                self.message = HTTPResponse._from_owner(
                    owner, 0, len(owner), self.l7_ports)
            elif _looks_like_request_line(mv, 0, len(owner)):
                self.message = HTTPRequest._from_owner(
                    owner, 0, len(owner), self.l7_ports)
            else:
                # No parseable start line: keep the bytes for reassembly.
                self.message = HTTPBodyFragment._from_owner(
                    owner, 0, len(owner), self.l7_ports)
            return
        elif len(args) != 0:
            raise TypeError('HTTP accepts one raw buffer or message=')

        self.message = kwargs.get('message', None)
        if not isinstance(
                self.message,
                (HTTPRequest, HTTPResponse, HTTPBodyFragment)):
            raise TypeError('HTTP message must be HTTPRequest, HTTPResponse, '
                            'or HTTPBodyFragment')

    @classmethod
    def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                    dict l7_ports):
        cdef:
            HTTP pkt
            const unsigned char[:] mv

        if start < 0 or end < start or end > len(owner):
            raise ValueError('HTTP: invalid owner range')

        # The dispatcher inspects the start line in the outer immutable owner
        # and passes the original range onward.  No owner[start:end] Python
        # bytes allocation occurs on the Layer-7 path.
        pkt = cls.__new__(cls)
        pkt.l7_ports = l7_ports
        pkt.pkt_name = 'HTTP'
        pkt.pq_type, pkt.query_fields = HTTP.query_info()
        mv = owner
        if _looks_like_response_line(mv, start, end):
            pkt.message = HTTPResponse._from_owner(
                owner, start, end, l7_ports)
        elif _looks_like_request_line(mv, start, end):
            pkt.message = HTTPRequest._from_owner(
                owner, start, end, l7_ports)
        else:
            # No parseable start line: keep the bytes for reassembly.
            pkt.message = HTTPBodyFragment._from_owner(
                owner, start, end, l7_ports)
        return pkt

    cpdef object get_header(self, object name, object default=None):
        return self.message.get_header(name, default)

    cpdef list get_headers(self, object name):
        return self.message.get_headers(name)

    @classmethod
    def query_info(cls):
        # The dispatcher advertises a stable union.  get_field_val returns None
        # for fields belonging to the other shape rather than raising, which is
        # the query engine's expected heterogeneous-packet contract.
        return (HTTP_PACKET_TYPE,
                ('http.request.method', 'http.request.target',
                 'http.request.version', 'http.response.version',
                 'http.response.status', 'http.response.reason',
                 'http.body_length'))

    @classmethod
    def default_ports(cls):
        return [HTTP_PACKET_PORT]

    cpdef object get_field_val(self, str field):
        return self.message.get_field_val(field)

    cpdef bytes pkt2net(self, dict kwargs):
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        # Delegate into the same writer rather than calling child.pkt2net(),
        # which would allocate and copy a complete intermediate message.
        cdef:
            HTTPRequest request
            HTTPResponse response
            HTTPBodyFragment fragment
        if isinstance(self.message, HTTPRequest):
            request = self.message
            return request._write(w, kwargs)
        elif isinstance(self.message, HTTPResponse):
            response = self.message
            return response._write(w, kwargs)
        elif isinstance(self.message, HTTPBodyFragment):
            fragment = self.message
            return fragment._write(w, kwargs)
        raise TypeError('HTTP message must be HTTPRequest, HTTPResponse, '
                        'or HTTPBodyFragment')


# --- TCP stream reassembly helper -------------------------------------------
# The classes above are per-message/per-packet: each looks only at the one
# buffer it is handed and never carries state between packets.  A body split
# across TCP segments by the path MTU therefore arrives as a first message
# (partial ``body``, ``body_complete`` false) followed by ``HTTPBodyFragment``
# continuation packets.  ``get_http_streams`` is the caller-side layer that was
# deliberately left out of the decoder: it groups packets into TCP connections,
# orders each direction's segments by sequence number, concatenates their bytes
# back into a continuous stream, and re-parses that stream into whole HTTP
# messages.  The decoder itself still performs no reassembly on its own.

# 32-bit wrap mask for TCP sequence-number arithmetic.
DEF _SEQ_MASK = 0xffffffff


def _stream_ip_addresses(pkt):
    """Return ``(src, dst)`` address strings for a decoded packet, or Nones.

    IPv4 and IPv6 are both supported; a packet with neither layer (for example
    ARP) yields ``(None, None)`` and is skipped by the caller.
    """
    ip = pkt.get_layer('IP')
    if ip is not None and ip.pkt_name == 'IP':
        return (ip.get_field_val('ip.src'), ip.get_field_val('ip.dst'))
    ip6 = pkt.get_layer('IP6')
    if ip6 is not None and ip6.pkt_name == 'IP6':
        return (ip6.get_field_val('ipv6.src'), ip6.get_field_val('ipv6.dst'))
    return (None, None)


def _reassemble_direction(direction):
    """Rebuild one direction's byte stream from its captured segments.

    ``direction`` is the accumulator built in ``get_http_streams`` -- a dict
    with a ``segments`` list of ``(sequence, bytes)`` pairs and an ``isn``.
    Segments are ordered by sequence number and concatenated into the longest
    gap-free run that starts at the lowest sequence seen; retransmissions and
    overlaps are dropped.  A missing segment (a hole in the sequence space)
    stops assembly at the contiguous prefix, which is the best-effort partial
    the caller asked to keep rather than discard.

    :return: ``(assembled_bytes, isn)`` where ``isn`` identifies the stream.
    """
    if direction is None or not direction['segments']:
        return (b'', None if direction is None else direction['isn'])

    segments = direction['segments']
    # The lowest sequence number is the first byte of the stream we hold.  A
    # capture that spans the 4 GiB sequence space in one direction would need
    # to wrap, which an HTTP capture never does, so a plain minimum is safe.
    base = min(seq for seq, _ in segments)
    ordered = sorted(segments, key=lambda item: (item[0] - base) & _SEQ_MASK)

    assembled = bytearray()
    next_off = 0
    for seq, data in ordered:
        off = (seq - base) & _SEQ_MASK
        end = off + len(data)
        if off > next_off:
            # A segment is missing: keep the contiguous prefix and stop.
            break
        if end <= next_off:
            # Wholly duplicate bytes (a retransmission); nothing new to add.
            continue
        assembled += data[next_off - off:]
        next_off = end

    isn = direction['isn'] if direction['isn'] is not None else base
    return (bytes(assembled), isn)


def _split_http_messages(stream):
    """Split a reassembled direction into successive whole ``HTTP`` messages.

    A keep-alive or pipelined direction carries several messages back to back;
    a parsed request/response exposes any following bytes as ``data``, so each
    message's own wire is the buffer up to that leftover.  Every element is a
    fresh ``HTTP`` object built from just its own bytes, so serializing it
    reproduces that one message and its ``body_complete`` flag reflects whether
    the body was fully reassembled.  A trailing run with no parseable start
    line (a stream whose head was not captured, or a body cut short) is kept as
    a single ``HTTPBodyFragment`` so nothing is silently dropped.
    """
    messages = list()
    buf = stream
    while buf:
        try:
            message = HTTP(buf)
        except ValueError:
            # Malformed or incomplete framing (for example a chunked body cut
            # short by the capture): keep the remainder verbatim and stop.
            messages.append(HTTP(message=HTTPBodyFragment(buf)))
            break
        leftover = getattr(message.message, 'data', b'') or b''
        consumed = len(buf) - len(leftover)
        if consumed <= 0:
            # No forward progress -- a body fragment with no start line owns the
            # whole remainder.  Keep it as one partial message and stop.
            messages.append(HTTP(buf))
            break
        own = buf[:consumed]
        messages.append(HTTP(own))
        buf = leftover
    return messages


def _direction_role(messages):
    """Classify a direction as 'request' or 'response' by its first message."""
    for message in messages:
        inner = message.message
        if isinstance(inner, HTTPRequest):
            return 'request'
        if isinstance(inner, HTTPResponse):
            return 'response'
    return None


def get_http_streams(packets):
    """Trace the TCP streams in decoded packets and reassemble HTTP exchanges.

    This is the caller-side reassembly layer the decoder deliberately omits.
    Hand it an iterable of already-decoded packets -- top-level ``PKT`` objects
    such as ``Ethernet`` or ``IP`` parsed with ``l7_ports={80: HTTP}`` so their
    TCP payloads decode to ``HTTP`` -- and it groups them into bidirectional TCP
    connections, orders each direction by TCP sequence number, concatenates the
    ``HTTPRequest`` / ``HTTPResponse`` / ``HTTPBodyFragment`` payloads back into
    a continuous stream, and re-parses that stream into whole HTTP messages.

    The result is a dict keyed by a string built from the connection's 5-tuple
    plus a unique id derived from the two directions' initial sequence numbers,
    so a later reuse of the same 5-tuple does not collide::

        'TCP 10.0.0.1:54321<->10.0.0.2:80 isn=1000,2000'

    Each value is a list of ``(request, response)`` pairs, in order, covering
    keep-alive and pipelined connections; each element is an ``HTTP`` object (or
    ``None`` when only one side of an exchange was captured).  A message that
    could not be fully reassembled -- a hole in the capture, or a body cut short
    -- is still returned, with ``body_complete`` false, rather than dropped.

    Packets without a TCP layer, and TCP segments whose payload did not decode
    to HTTP (a different port, or a pure ACK), are ignored.

    :param packets: an iterable of decoded ``PKT`` packets.
    :return: dict mapping a stream key string to a list of ``(request,
        response)`` ``HTTP`` pairs.
    """
    active = dict()      # canonical 5-tuple -> the currently open connection
    instances = list()   # every connection instance, in first-seen order

    for pkt in packets:
        if pkt is None:
            continue
        tcp = pkt.get_layer('TCP')
        if tcp is None or tcp.pkt_name != 'TCP':
            continue

        src_ip, dst_ip = _stream_ip_addresses(pkt)
        if src_ip is None or dst_ip is None:
            continue

        sport = tcp.get_field_val('tcp.srcport')
        dport = tcp.get_field_val('tcp.dstport')
        seq = tcp.get_field_val('tcp.seq')
        is_syn = bool(tcp.get_field_val('tcp.flags.syn'))
        is_ack = bool(tcp.get_field_val('tcp.flags.ack'))

        src_ep = (src_ip, sport)
        dst_ep = (dst_ip, dport)
        # Canonical (order-independent) key groups both directions together.
        conn_key = (src_ep, dst_ep) if src_ep <= dst_ep else (dst_ep, src_ep)

        instance = active.get(conn_key)
        # A bare SYN (SYN without ACK) opens a new connection.  A reused
        # 5-tuple therefore starts a fresh instance instead of merging with the
        # earlier one, which is what makes the sequence-based id below unique;
        # the server's SYN-ACK and ordinary segments stay with the open one.
        if instance is None or (is_syn and not is_ack):
            instance = {'endpoints': conn_key, 'dirs': dict()}
            active[conn_key] = instance
            instances.append(instance)

        flow = (src_ep, dst_ep)
        direction = instance['dirs'].get(flow)
        if direction is None:
            direction = {'segments': list(), 'isn': None}
            instance['dirs'][flow] = direction

        if is_syn:
            # The SYN (or SYN-ACK) carries the true initial sequence number;
            # data begins at the following byte.  It is the most stable id.
            direction['isn'] = seq

        http = pkt.get_layer('HTTP')
        if http is None or http.pkt_name != 'HTTP':
            continue
        payload = http.pkt2net({})
        if payload:
            direction['segments'].append((seq, payload))

    streams = dict()
    for instance in instances:
        ep_a, ep_b = instance['endpoints']
        directions = instance['dirs']
        flow_ab = (ep_a, ep_b)
        flow_ba = (ep_b, ep_a)

        stream_ab, isn_ab = _reassemble_direction(directions.get(flow_ab))
        stream_ba, isn_ba = _reassemble_direction(directions.get(flow_ba))

        messages_ab = _split_http_messages(stream_ab)
        messages_ba = _split_http_messages(stream_ba)
        if not messages_ab and not messages_ba:
            # A TCP connection that carried no HTTP payload (a different port,
            # or only SYN/ACK control segments) is not an HTTP stream.
            continue

        role_ab = _direction_role(messages_ab)
        role_ba = _direction_role(messages_ba)
        if role_ab == 'request' or role_ba == 'response':
            requests, responses = messages_ab, messages_ba
        elif role_ba == 'request' or role_ab == 'response':
            requests, responses = messages_ba, messages_ab
        else:
            # Neither side had a parseable start line (only body fragments).
            # The lower port is conventionally the server, so requests flow
            # toward it; this is only a tie-breaker for otherwise opaque data.
            if ep_a[1] <= ep_b[1]:
                requests, responses = messages_ba, messages_ab
            else:
                requests, responses = messages_ab, messages_ba

        pairs = list()
        for i in range(max(len(requests), len(responses))):
            request = requests[i] if i < len(requests) else None
            response = responses[i] if i < len(responses) else None
            pairs.append((request, response))

        key = 'TCP {0}:{1}<->{2}:{3} isn={4},{5}'.format(
            ep_a[0], ep_a[1], ep_b[0], ep_b[1], isn_ab, isn_ba)
        streams[key] = pairs

    return streams
