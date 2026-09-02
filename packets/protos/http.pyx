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
                raise ValueError('HTTP request: incomplete fixed body')
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
                raise ValueError('HTTP response: incomplete fixed body')
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
cdef class HTTP(PKT):
    """Request/response dispatcher intended for ``l7_ports={80: HTTP}``."""

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
            if _looks_like_response(mv, 0, len(owner)):
                self.message = HTTPResponse._from_owner(
                    owner, 0, len(owner), self.l7_ports)
            else:
                self.message = HTTPRequest._from_owner(
                    owner, 0, len(owner), self.l7_ports)
            return
        elif len(args) != 0:
            raise TypeError('HTTP accepts one raw buffer or message=')

        self.message = kwargs.get('message', None)
        if not isinstance(self.message, (HTTPRequest, HTTPResponse)):
            raise TypeError('HTTP message must be HTTPRequest or HTTPResponse')

    @classmethod
    def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                    dict l7_ports):
        cdef:
            HTTP pkt
            const unsigned char[:] mv

        if start < 0 or end < start or end > len(owner):
            raise ValueError('HTTP: invalid owner range')

        # The dispatcher examines five bytes in the outer immutable owner and
        # passes the original range onward.  No owner[start:end] Python bytes
        # allocation occurs on the Layer-7 path.
        pkt = cls.__new__(cls)
        pkt.l7_ports = l7_ports
        pkt.pkt_name = 'HTTP'
        pkt.pq_type, pkt.query_fields = HTTP.query_info()
        mv = owner
        if _looks_like_response(mv, start, end):
            pkt.message = HTTPResponse._from_owner(
                owner, start, end, l7_ports)
        else:
            pkt.message = HTTPRequest._from_owner(
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
        if isinstance(self.message, HTTPRequest):
            request = self.message
            return request._write(w, kwargs)
        elif isinstance(self.message, HTTPResponse):
            response = self.message
            return response._write(w, kwargs)
        raise TypeError('HTTP message must be HTTPRequest or HTTPResponse')
