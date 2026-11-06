# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Python-callable wrappers over the nogil BGP decode primitives in
packets.core.inetpkt.

The primitives are ``cdef`` functions, which means nothing outside a Cython
module can call them: they could not be unit tested, benchmarked, or used
without going through the text dissector. This module is the smallest thing
that fixes that. Every function here does one ``cimport``ed call and packs the
out-parameters into a tuple of plain integers -- no rendering, no value_string
lookups, no bytes copies -- so a test asserts on the wire arithmetic itself and
a benchmark measures the decoder rather than the formatter.

Offsets are absolute offsets into the buffer that was passed in, not relative
to the ``s`` argument, because that is what the primitives return and hiding it
would make the numbers harder to check against a hexdump.

Two conventions worth knowing before reading the signatures:

  * ``e`` defaults to -1, meaning "to the end of the buffer".
  * ``ve`` in a capability or attribute tuple is the end the on-wire length
    field *claims*, so it can exceed ``e``; the declared length is
    ``ve - vs`` and the readable span is ``[vs, min(ve, e))``. The iterators
    stop at the clamped offset. See the contract comment above the primitive
    definitions in inetpkt.pyx.

Nothing here raises for malformed input -- that is the whole point of the
primitives -- so a caller distinguishes success from failure by the ``rc``
element of the returned tuple, or by an empty list from an iterator.
"""

from libc.stdint cimport uint16_t, uint32_t
cimport cython

from packets.core.inetpkt cimport _bgp_msg_header, _bgp_open_fixed, \
    _bgp_cap_next, _bgp_attr_next, _bgp_nlri_next, _bgp_mp_reach_hdr, \
    _bgp_mp_unreach_hdr, _bgp_aspath_seg_next, _have_range, rd_u16


cdef inline Py_ssize_t _end(const unsigned char[:] mv, Py_ssize_t e):
    """Resolve the caller's ``e``: -1 means the end of the buffer."""
    if e < 0 or e > mv.shape[0]:
        return mv.shape[0]
    return e


def msg_header(const unsigned char[:] buf, Py_ssize_t s=0, Py_ssize_t e=-1):
    """Read a 19-byte BGP message header.

    :return: ``(rc, length, mtype)``. ``rc`` is 0 on success and -1 when
        fewer than 19 bytes are available, in which case length and type are
        0. ``length`` is the on-wire length field and is deliberately not
        validated against the buffer.
    """
    cdef:
        Py_ssize_t end = _end(buf, e)
        uint16_t length = 0
        unsigned char mtype = 0
        int rc
    rc = _bgp_msg_header(buf, s, end, &length, &mtype)
    return (rc, length, mtype)


def open_fixed(const unsigned char[:] buf, bint allow_ext=0, Py_ssize_t s=0,
               Py_ssize_t e=-1):
    """Read the fixed 10 bytes of an OPEN body and locate its parameters.

    ``s`` is the first byte of the OPEN *body*, i.e. past the 19-byte message
    header, so a whole message is passed as ``open_fixed(msg, 0, 19)``.

    :param allow_ext: honour the RFC 9072 extended optional-parameter length.
        The dissector passes 0; the routing engine passes 1. On the same bytes
        the two settings give different ``opt_start``/``opt_end``, which is
        exactly what the Stage 1 tests pin.
    :return: ``(rc, ver, my_as, hold, bgp_id, opt_start, opt_end)`` with
        ``bgp_id`` as a 32-bit integer and ``opt_end`` the declared end, which
        may exceed the buffer.
    """
    cdef:
        Py_ssize_t end = _end(buf, e)
        unsigned char ver = 0
        uint16_t my_as = 0
        uint16_t hold = 0
        uint32_t bgp_id = 0
        Py_ssize_t opt_start = -1
        Py_ssize_t opt_end = -1
        int rc
    rc = _bgp_open_fixed(buf, s, end, allow_ext, &ver, &my_as, &hold,
                         &bgp_id, &opt_start, &opt_end)
    return (rc, ver, my_as, hold, bgp_id, opt_start, opt_end)


def iter_caps(const unsigned char[:] buf, Py_ssize_t s=0, Py_ssize_t e=-1):
    """Walk the capability TLVs in ``[s, e)``.

    :return: a list of ``(code, vs, ve)``, one per capability, stopping at the
        first TLV header that does not fit. An empty list means there was not
        even one capability.
    """
    cdef:
        Py_ssize_t end = _end(buf, e)
        Py_ssize_t o = s
        Py_ssize_t nxt, vs = 0, ve = 0
        unsigned char code = 0
        list out = []
    while True:
        nxt = _bgp_cap_next(buf, o, end, &code, &vs, &ve)
        # -1 is the stop signal and o may itself be negative if the caller
        # passed a negative offset, so both tests are needed: `nxt <= o`
        # alone would accept -1 as progress from -2.
        if nxt < 0 or nxt <= o:
            break
        out.append((code, vs, ve))
        o = nxt
    return out


def iter_attrs(const unsigned char[:] buf, Py_ssize_t s=0, Py_ssize_t e=-1):
    """Walk the UPDATE path attributes in ``[s, e)``.

    :return: a list of ``(flags, atype, vs, ve)``, one per attribute. The
        extended-length bit is handled inside the primitive, so ``vs`` is 3 or
        4 bytes past the attribute start depending on it.
    """
    cdef:
        Py_ssize_t end = _end(buf, e)
        Py_ssize_t o = s
        Py_ssize_t nxt, vs = 0, ve = 0
        unsigned char flags = 0, atype = 0
        list out = []
    while True:
        nxt = _bgp_attr_next(buf, o, end, &flags, &atype, &vs, &ve)
        if nxt < 0 or nxt <= o:
            break
        out.append((flags, atype, vs, ve))
        o = nxt
    return out


def iter_nlri(const unsigned char[:] buf, Py_ssize_t s=0, Py_ssize_t e=-1,
              bint add_path=0, Py_ssize_t max_addr_bytes=4):
    """Walk a run of length-prefixed prefixes in ``[s, e)``.

    :param add_path: each prefix is preceded by a 4-byte RFC 7911 path id.
    :param max_addr_bytes: 4 for IPv4 (what the dissector allows), 16 for
        IPv6. A prefix length needing more address bytes than this ends the
        run, because the entries are self-delimiting and one bad length makes
        every following offset meaningless.
    :return: a list of ``(path_id, plen, addr_start)``. ``path_id`` is 0 when
        ``add_path`` is clear. The address bytes are ``buf[addr_start:
        addr_start + (plen + 7) // 8]``.
    """
    cdef:
        Py_ssize_t end = _end(buf, e)
        Py_ssize_t o = s
        Py_ssize_t nxt, addr_start = 0
        uint32_t path_id = 0
        unsigned char plen = 0
        list out = []
    while True:
        nxt = _bgp_nlri_next(buf, o, end, add_path, max_addr_bytes,
                             &path_id, &plen, &addr_start)
        if nxt < 0 or nxt <= o:
            break
        out.append((path_id, plen, addr_start))
        o = nxt
    return out


def mp_reach_hdr(const unsigned char[:] buf, Py_ssize_t s=0,
                 Py_ssize_t e=-1):
    """Read an MP_REACH_NLRI (attribute 14) header.

    :return: ``(rc, afi, safi, nh_start, nh_end, nlri_start)``. ``rc`` is 0
        once afi and safi are readable; the three offsets stay -1 unless the
        next hop was fully present, so test ``nh_start >= 0`` rather than
        ``rc`` before slicing a next hop.
    """
    cdef:
        Py_ssize_t end = _end(buf, e)
        uint16_t afi = 0
        unsigned char safi = 0
        Py_ssize_t nh_start = -1, nh_end = -1, nlri_start = -1
        int rc
    rc = _bgp_mp_reach_hdr(buf, s, end, &afi, &safi, &nh_start, &nh_end,
                           &nlri_start)
    return (rc, afi, safi, nh_start, nh_end, nlri_start)


def mp_unreach_hdr(const unsigned char[:] buf, Py_ssize_t s=0,
                   Py_ssize_t e=-1):
    """Read an MP_UNREACH_NLRI (attribute 15) header.

    :return: ``(rc, afi, safi, nlri_start)``; there is no next hop.
    """
    cdef:
        Py_ssize_t end = _end(buf, e)
        uint16_t afi = 0
        unsigned char safi = 0
        Py_ssize_t nlri_start = -1
        int rc
    rc = _bgp_mp_unreach_hdr(buf, s, end, &afi, &safi, &nlri_start)
    return (rc, afi, safi, nlri_start)


def iter_aspath(const unsigned char[:] buf, Py_ssize_t s=0, Py_ssize_t e=-1,
                bint as4=0):
    """Walk the segments of an AS_PATH value in ``[s, e)``.

    :param as4: AS numbers are 4 bytes wide (AS4_PATH, or an RFC 6793
        session) rather than 2.
    :return: a list of ``(seg_type, count, asn_start)``. ``count`` is a count
        of AS numbers, not of bytes, and is what the segment claims -- a
        truncated segment still reports its claim, so a caller reading the
        ASNs bounds each read itself.
    """
    cdef:
        Py_ssize_t end = _end(buf, e)
        Py_ssize_t o = s
        Py_ssize_t nxt, asn_start = 0
        unsigned char seg_type = 0, count = 0
        list out = []
    while True:
        nxt = _bgp_aspath_seg_next(buf, o, end, as4, &seg_type, &count,
                                   &asn_start)
        if nxt < 0 or nxt <= o:
            break
        out.append((seg_type, count, asn_start))
        o = nxt
    return out


def scan_updates(const unsigned char[:] buf, bint add_path=0,
                 Py_ssize_t max_addr_bytes=4):
    """Decode a whole stream of back-to-back BGP messages under one ``nogil``.

    This is not part of the primitive surface -- it exists because the
    per-element wrappers above cannot measure the primitives. A tuple
    allocation and a Python call dwarf the handful of integer operations a
    primitive performs, so timing ``iter_nlri`` in a loop would time CPython.
    This walks the entire buffer inside a single ``with nogil`` block, touching
    no Python object between entry and exit, and returns only counters. It is
    what bench/bgpcore_bench.py measures and what the Stage 2 architecture gate
    is compared against.

    Messages are framed by their own length field; a message whose length
    overruns the buffer, or is below the 19-byte minimum, ends the scan.

    :param add_path: prefixes carry RFC 7911 path identifiers.
    :param max_addr_bytes: address width, 4 for IPv4 and 16 for IPv6.
    :return: ``(messages, attributes, prefixes, withdrawn)``.
    """
    cdef:
        Py_ssize_t end = buf.shape[0]
        Py_ssize_t o = 0, msg_end, body, wend, tend, nxt
        Py_ssize_t vs = 0, ve = 0, addr_start = 0
        uint16_t mlen = 0, wlen, tpalen
        unsigned char mtype = 0, flags = 0, atype = 0, plen = 0
        uint32_t path_id = 0
        Py_ssize_t messages = 0, attributes = 0, prefixes = 0, withdrawn = 0
    with nogil:
        while True:
            if _bgp_msg_header(buf, o, end, &mlen, &mtype) < 0:
                break
            if mlen < 19 or o + mlen > end:
                break
            msg_end = o + mlen
            messages += 1
            if mtype == 2:
                body = o + 19
                # Withdrawn routes: 2-byte length, then a prefix run.
                if not _have_range(body, msg_end, 2):
                    o = msg_end
                    continue
                wlen = rd_u16(buf, body)
                body += 2
                wend = body + wlen
                if wend > msg_end:
                    wend = msg_end
                while True:
                    nxt = _bgp_nlri_next(buf, body, wend, add_path,
                                         max_addr_bytes, &path_id, &plen,
                                         &addr_start)
                    if nxt < 0 or nxt <= body:
                        break
                    withdrawn += 1
                    body = nxt
                body = wend
                # Path attributes: 2-byte length, then a TLV run.
                if not _have_range(body, msg_end, 2):
                    o = msg_end
                    continue
                tpalen = rd_u16(buf, body)
                body += 2
                tend = body + tpalen
                if tend > msg_end:
                    tend = msg_end
                while True:
                    nxt = _bgp_attr_next(buf, body, tend, &flags, &atype,
                                         &vs, &ve)
                    if nxt < 0 or nxt <= body:
                        break
                    attributes += 1
                    body = nxt
                body = tend
                # NLRI: the rest of the message.
                while True:
                    nxt = _bgp_nlri_next(buf, body, msg_end, add_path,
                                         max_addr_bytes, &path_id, &plen,
                                         &addr_start)
                    if nxt < 0 or nxt <= body:
                        break
                    prefixes += 1
                    body = nxt
            o = msg_end
    return (messages, attributes, prefixes, withdrawn)
