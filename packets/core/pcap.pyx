# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint32_t, uint64_t, uint16_t

import sys
import time
import socket
import struct
from threading import Event

from packets.core.inetpkt cimport Ethernet, IP, IP6, UDP, PKT, \
    NetflowSimple, PQ_NETFLOW_SIMPLE

from packets.protos.netflow import Netflow, NetflowDecodeContext

DEF USECCONST = 1000000.00
DEF ERRBUF_SZ = 256

VERSION_MAJOR = 2
VERSION_MINOR = 4
ERRBUF_SIZE = 256
ERROR = -1
ERROR_BREAK = -2
ERROR_NOT_ACTIVATED = -3
ERROR_ACTIVATED = -4
ERROR_NO_SUCH_DEVICE = -5
ERROR_RFMON_NOTSUP = -6
ERROR_NOT_RFMON = -7
ERROR_PERM_DENIED = -8
ERROR_IFACE_NOT_UP = -9
ERROR_CANTSET_TSTAMP_TYPE = -10
ERROR_PROMISC_PERM_DENIED = -11
ERROR_TSTAMP_PRECISION_NOTSUP = -12
WARNING = 1
WARNING_PROMISC_NOTSUP = 2
WARNING_TSTAMP_TYPE_NOTSUP = 3
NETMASK_UNKNOWN = 0xffffffff
TSTAMP_HOST = 0
TSTAMP_HOST_LOWPREC = 1
TSTAMP_HOST_HIPREC = 2
TSTAMP_ADAPTER = 3
TSTAMP_ADAPTER_UNSYNCED = 4
TSTAMP_PRECISION_MICRO = 0
TSTAMP_PRECISION_NANO = 1
ETH_NULL = 0
ETH_EN10MB = 1
ETH_IEEE802 = 6
ETH_ARCNET = 7
ETH_SLIP = 8
ETH_PPP = 9
ETH_FDDI = 10
ETH_ATM_RFC1483 = 11
ETH_RAW = 12
ETH_PPP_SERIAL = 50
ETH_PPP_ETHER = 51
ETH_C_HDLC = 104
ETH_IEEE802_11 = 105
ETH_LOOP = 108
ETH_LINUX_SLL = 113
ETH_LTALK = 114
PCAP_NETMASK_UNKNOWN = 0xffffffff
# libpcap's own MAXIMUM_SNAPLEN, and the value tcpdump passes for "capture
# the whole frame". snaplen is a hard cap on the bytes libpcap copies out of
# each frame, so a snaplen of 0 does not mean "no limit": libpcap before 1.9
# takes it literally and hands back caplen 0 for every packet, an entirely
# empty capture. Newer libpcap silently substitutes this value instead, so
# the meaning of the documented default used to depend on the libpcap the
# extension happened to link against. See _resolve_snaplen below.
MAX_SNAPLEN = 262144


cpdef int _resolve_snaplen(int snaplen):
    """Turn a caller's snaplen into one libpcap will not read as "nothing".

    Callers who want every byte of every frame say ``snaplen=0``, which is
    the documented default. Only libpcap 1.9 and later reads that as "the
    maximum"; older releases cap the capture at zero bytes and the caller
    gets a live capture in which every packet is empty. Mapping the value
    here makes the default mean the same thing on every libpcap.

    Args:
        :snaplen (int): the caller's requested snaplen.

    Returns:
        :int: snaplen if it is a usable positive length, else MAX_SNAPLEN.
    """
    if snaplen <= 0 or snaplen > MAX_SNAPLEN:
        return MAX_SNAPLEN
    return snaplen


cdef int _check_setter(int rval, str call, str keyword) except? -1:
    """Report a libpcap setter that could not take effect.

    pcap_set_snaplen(), pcap_set_promisc() and pcap_set_timeout() only
    apply between pcap_create() and pcap_activate(). PCAPSocket opens its
    handle with pcap_open_live(), which does all three in one step, so the
    handle a caller reaches these through is already activated and libpcap
    answers PCAP_ERROR_ACTIVATED and changes nothing. The return code was
    handed straight back and is easy to drop, so a caller was left thinking
    the capture had been reconfigured when it had not.
    """
    if rval == ERROR_ACTIVATED:
        raise ValueError(
            "PCAPSocket.{0}() cannot change a capture that is already "
            "running; libpcap only accepts this before the handle is "
            "activated. Pass {1} to PCAPSocket() instead."
            "".format(call, keyword))
    if rval < 0:
        raise ValueError("PCAPSocket.{0}() failed: libpcap returned {1}"
                         "".format(call, rval))
    return rval


cdef int _need_handle(pcap_t * handle, str call) except -1:
    """Refuse to hand libpcap a NULL pcap_t *.

    close() NULLs the handle it just freed, and nothing stops a caller from
    reaching for the object afterwards. libpcap does not check its handle
    argument, so passing NULL through is undefined behaviour: the process
    dies inside libpcap rather than raising something the caller can catch.
    """
    if handle is NULL:
        raise ValueError("{0} on a closed capture handle".format(call))
    return 0


cdef object _netflow_decode_context(dict kwargs):
    cdef object context = kwargs.get('decode_context')

    if context is None:
        # NetflowDecodeContext is imported at module scope; the function local
        # import this used to repeat was a sys.modules lookup and a dict
        # lookup per reader, for a name already bound.
        context = NetflowDecodeContext()
    return context


cdef struct PcapInfoState:
    uint64_t packets
    uint64_t byte_count
    double first_ts
    double last_ts


cdef void _pcap_info_callback(u_char *user,
                              const pcap_pkthdr *hdr,
                              const u_char *pkt) nogil:
    cdef:
        PcapInfoState *state = <PcapInfoState *>user
        double ts

    if hdr[0].ts.tv_usec > 0:
        ts = hdr[0].ts.tv_sec + (hdr[0].ts.tv_usec / USECCONST)
    else:
        ts = hdr[0].ts.tv_sec
    if state.packets == 0:
        state.first_ts = ts
    state.last_ts = ts
    state.packets += 1
    state.byte_count += hdr[0].caplen


cdef class PCAP_CONST:
    def __cinit__(self):
        # Values taken from pcap.h. Names have leading PCAP_ removed in order
        # to avoid collisions with #define macros
        self.VERSION_MAJOR = VERSION_MAJOR
        self.VERSION_MINOR = VERSION_MINOR
        self.ERRBUF_SIZE = ERRBUF_SIZE
        self.ERROR = ERROR
        self.ERROR_BREAK = ERROR_BREAK
        self.ERROR_NOT_ACTIVATED = ERROR_NOT_ACTIVATED
        self.ERROR_ACTIVATED = ERROR_ACTIVATED
        self.ERROR_NO_SUCH_DEVICE = ERROR_NO_SUCH_DEVICE
        self.ERROR_RFMON_NOTSUP = ERROR_RFMON_NOTSUP
        self.ERROR_NOT_RFMON = ERROR_NOT_RFMON
        self.ERROR_PERM_DENIED = ERROR_PERM_DENIED
        self.ERROR_IFACE_NOT_UP = ERROR_IFACE_NOT_UP
        self.ERROR_CANTSET_TSTAMP_TYPE = ERROR_CANTSET_TSTAMP_TYPE
        self.ERROR_PROMISC_PERM_DENIED = ERROR_PROMISC_PERM_DENIED
        self.ERROR_TSTAMP_PRECISION_NOTSUP = ERROR_TSTAMP_PRECISION_NOTSUP
        self.WARNING = WARNING
        self.WARNING_PROMISC_NOTSUP = WARNING_PROMISC_NOTSUP
        self.WARNING_TSTAMP_TYPE_NOTSUP = WARNING_TSTAMP_TYPE_NOTSUP
        self.NETMASK_UNKNOWN = NETMASK_UNKNOWN
        self.TSTAMP_HOST = TSTAMP_HOST
        self.TSTAMP_HOST_LOWPREC = TSTAMP_HOST_LOWPREC
        self.TSTAMP_HOST_HIPREC = TSTAMP_HOST_HIPREC
        self.TSTAMP_ADAPTER = TSTAMP_ADAPTER
        self.TSTAMP_ADAPTER_UNSYNCED = TSTAMP_ADAPTER_UNSYNCED
        self.TSTAMP_PRECISION_MICRO = TSTAMP_PRECISION_MICRO
        self.TSTAMP_PRECISION_NANO = TSTAMP_PRECISION_NANO
        self.ETH_NULL = ETH_NULL
        self.ETH_EN10MB = ETH_EN10MB
        self.ETH_IEEE802 = ETH_IEEE802
        self.ETH_ARCNET = ETH_ARCNET
        self.ETH_SLIP = ETH_SLIP
        self.ETH_PPP = ETH_PPP
        self.ETH_FDDI = ETH_FDDI
        self.ETH_ATM_RFC1483 = ETH_ATM_RFC1483
        self.ETH_RAW = ETH_RAW
        self.ETH_PPP_SERIAL = ETH_PPP_SERIAL
        self.ETH_PPP_ETHER = ETH_PPP_ETHER
        self.ETH_C_HDLC = ETH_C_HDLC
        self.ETH_IEEE802_11 = ETH_IEEE802_11
        self.ETH_LOOP = ETH_LOOP
        self.ETH_LINUX_SLL = ETH_LINUX_SLL
        self.ETH_LTALK = ETH_LTALK

cpdef uint32_t ip2int(str addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


cpdef str int2ip(uint32_t addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


cpdef char *lookupdev(char *errtext):
    cdef:
        char * device
    device = pcap_lookupdev(errtext)
    if not device:
        return NULL
    else:
        return device

cpdef int findalldevs(list devices, char *errtext):
    cdef:
        int rval
        pcap_if_t * ifaces = NULL
        pcap_if_t * current
    rval = ERROR
    rval = pcap_findalldevs(&ifaces, errtext)
    if not rval:
        try:
            current = ifaces
            while current:
                devices.append(current.name)
                current = current.next
        finally:
            # pcap_findalldevs mallocs the whole pcap_if_t chain, addresses
            # and names included, and hands ownership to us. The names
            # appended above are Cython's own copies of those C strings, so
            # the chain has to go back: without this every device lookup -
            # including the valid_dev() check PcapQuery does on construction
            # - leaked the entire interface list.
            pcap_freealldevs(ifaces)
    return rval

cpdef list list_devices():
    """Names of the capture devices libpcap can see on this host.

    findalldevs() is the C shaped call - it fills a list handed to it and
    needs an error buffer - so anything outside this module that just wants
    to know whether a device name is real had no reasonable way to ask.

    Returns:
        :list: device names as str, empty if libpcap could not enumerate
            them. An empty list means 'could not tell', not 'none exist':
            an unprivileged process is usually not allowed to look.
    """
    cdef:
        list raw = []
        char errors[ERRBUF_SZ]

    if findalldevs(raw, errors):
        return []
    return [name.decode('utf-8', 'replace') for name in raw]


cdef int lookupnet(const char *device,
                   bpf_u_int32 * net,
                   bpf_u_int32 * mask,
                   char *errtext):
    cdef:
        int status
    status = pcap_lookupnet(device, net, mask, errtext)
    if status:
        net[0] = 0
        mask[0] = 0
    return status

cdef pcap_t *open_live(const char * device,
                       int snaplen,
                       int promisc,
                       int to_ms,
                       char *errtext):
    cdef:
        bpf_u_int32 net, mask
        int status
        pcap_t * pcap_live

    with nogil:
        pcap_live = pcap_open_live(device, snaplen, promisc, to_ms, errtext)
    if not pcap_live:
        return NULL
    else:
        return pcap_live

cdef pcap_t *open_offline(const char * filename,
                          char *errtext):
    cdef:
        pcap_t * pcap_offline

    with nogil:
        pcap_offline = pcap_open_offline(filename, errtext)
    if not pcap_offline:
        return NULL
    else:
        return pcap_offline

cdef pcap_t *open_dead(int linktype,
                       int snaplen):
    cdef:
        pcap_t * pcap_dead

    pcap_dead = pcap_open_dead(linktype, snaplen)
    return pcap_dead

cpdef pcap_pkthdr_t get_pkts_header(double ts, bytes data):
    cdef:
        pcap_pkthdr_t hdr
        uint32_t pkt_len = len(data)
        uint32_t t_sec = <uint32_t>ts
        # fractional seconds -> microseconds, rounded (add 0.5 before truncate)
        uint32_t t_usec = <uint32_t>((ts - <double>t_sec) * USECCONST + 0.5)

    # guard against a rounding carry landing exactly on 1_000_000 usec
    if t_usec >= <uint32_t>USECCONST:
        t_sec += 1
        t_usec = 0
    hdr.ts.tv_sec = t_sec
    hdr.ts.tv_usec = t_usec
    hdr.caplen = hdr.len = pkt_len
    return hdr


cdef class PCAPBase:
    def __cinit__(self, *args, **kwargs):
        self.dumper = NULL
        self.have_dumper = 0
        self.start_ts = 0
        self.end_ts = 0

    def __dealloc__(self):
        # A caller who never calls close() would otherwise leak the dumper.
        # Subclasses close their own handles and NULL this first, so by the
        # time we run there is usually nothing left to do.
        if self.dumper is not NULL:
            pcap_dump_close(self.dumper)
            self.dumper = NULL
            self.have_dumper = 0

    cdef int _open_pcap_dumper(self, str file_name, pcap_t * sock) except -1:
        cdef:
            char * filename = b''
            bytes encoded

        encoded = file_name.encode()
        filename = encoded
        self.dumper = pcap_dump_open(sock, filename)
        if self.dumper is NULL:
            # Raising, not returning ERROR. A caller who did not inspect the
            # return value carried on dumping into a NULL dumper, which
            # dump_hdr_pkt quietly ignores, so a run that looked entirely
            # successful wrote an empty file - or no file at all.
            raise IOError("Could not open {0} for writing: {1}"
                          "".format(file_name,
                                    pcap_geterr(sock).decode('utf-8',
                                                             'replace')))
        self.have_dumper = 1
        return 0

    cpdef void close_pcap_dumper(self):
        if self.dumper is not NULL:
            pcap_dump_close(self.dumper)
        self.dumper = NULL
        self.have_dumper = 0

    cpdef void dump_hdr_pkt(self,
                            pcap_pkthdr_t hdr,
                            bytes data,
                            uint32_t tv_sec=0,
                            uint32_t tv_usec=0):
        cdef:
            const pcap_pkthdr * pcap_hdr
            unsigned char * buff

        if tv_sec:
            hdr.ts.tv_sec = tv_sec
            hdr.ts.tv_usec = tv_usec
        buff = data
        pcap_hdr = &hdr
        if self.dumper is not NULL:
            pcap_dump(<u_char *>self.dumper ,pcap_hdr , buff)

    cpdef void dump_pkt(self,
                        bytes data,
                        uint32_t tv_sec=0,
                        uint32_t tv_usec=0):
        cdef:
            const pcap_pkthdr * pcap_hdr
            pcap_pkthdr_t hdr
            unsigned char * buff

        hdr = get_pkts_header(time.time(), data)
        if tv_sec:
            hdr.ts.tv_sec = tv_sec
            hdr.ts.tv_usec = tv_usec
        buff = data
        pcap_hdr = &hdr
        if self.dumper is not NULL:
            pcap_dump(<u_char *>self.dumper ,pcap_hdr , buff)

    cdef int _add_bpf_filter(self,
                             str bpf_filter,
                             pcap_t * sock,
                             bpf_u_int32 mask) except -1:
        cdef:
            bpf_program bpfprog
            int rval
            bytes encoded
            char* fltr = b''

        encoded = bpf_filter.encode()
        fltr = encoded
        rval = pcap_compile(sock, &bpfprog, fltr, 1, mask)

        if rval == ERROR:
            raise Exception("Failed to compile BPF filter: {0}"
                            "".format(pcap_geterr(sock).decode('utf-8',
                                                               'replace')))
        rval = pcap_setfilter(sock, &bpfprog)
        # pcap_compile mallocs the bpf_insn program; free it once installed.
        pcap_freecode(&bpfprog)
        if rval == ERROR:
            # Unchecked, a filter that fails to install leaves the caller
            # replaying or querying everything on the source.
            raise Exception("Failed to install BPF filter: {0}"
                            "".format(pcap_geterr(sock).decode('utf-8',
                                                               'replace')))
        return rval

    cpdef int add_bpf_filter(self, str bpf_filter) except -1:
        return 0

cdef class PCAPSocket(PCAPBase):
    def __cinit__(self, *args, **kwargs):
        self.dumper = NULL
        self.have_dumper = 0
        self.sock = NULL

    def __init__(self, *args, **kwargs):
        cdef:
            char errors[ERRBUF_SZ]
            const char * dev
            object v_err
            int snaplen, promisc, to_ms, status

        errors[0] = 0
        self.decode_context = _netflow_decode_context(kwargs)
        # self.devicename owns the encoded name for the life of the object;
        # dev is only valid while that reference is held.
        self.devicename = kwargs.get('devicename', '').encode()
        dev = self.devicename
        # 0, the documented default, means "the whole frame". libpcap only
        # reads it that way from 1.9 on, so resolve it here instead.
        snaplen = _resolve_snaplen(kwargs.get('snaplen', 0))
        promisc = kwargs.get('promisc', 1)
        to_ms = kwargs.get('to_ms', 100)
        self.sock = open_live(dev,
                              snaplen,
                              promisc,
                              to_ms,
                              errors)

        if self.sock is NULL:
            v_err = ValueError(
                "PCAPSocket failed to open device {0}. Error was: {1}"
                "".format(self.devicename.decode('utf-8', 'replace'),
                          (<char *>errors).decode('utf-8', 'replace')))
            raise v_err
        else:
            self.net = self.mask = 0
            status = lookupnet(dev,
                               &self.net, &self.mask,
                               errors)
            if status == ERROR:
                self.mask = PCAP_NETMASK_UNKNOWN
        self.stop_event = Event()

    def __dealloc__(self):
        if self.dumper is not NULL:
            pcap_dump_close(self.dumper)
            self.dumper = NULL
            self.have_dumper = 0
        if self.sock is not NULL:
            pcap_close(self.sock)
            self.sock = NULL

    property network:
        """
        get and set payload bytes
        """
        def __get__(self):
            cdef:
                uint32_t net
            net = socket.ntohl(self.net)
            return int2ip(net)

    property netmask:
        """
        get and set payload bytes
        """
        def __get__(self):
            cdef:
                uint32_t mask
            mask = socket.ntohl(self.mask)
            return int2ip(mask)

    # These all reach libpcap through self.sock, which close() sets to NULL.
    # They need the except clause as much as the guard: a cpdef int with no
    # declared exception value cannot propagate, so Cython would print the
    # ValueError raised below and return to the caller as though nothing had
    # happened. -1 is also a real libpcap return code, hence 'except?'.
    cpdef int set_snaplen(self, int snaplen) except? -1:
        _need_handle(self.sock, 'PCAPSocket.set_snaplen()')
        return _check_setter(pcap_set_snaplen(self.sock, snaplen),
                             'set_snaplen', 'snaplen')

    cpdef int set_promisc(self, int promisc) except? -1:
        _need_handle(self.sock, 'PCAPSocket.set_promisc()')
        return _check_setter(pcap_set_promisc(self.sock, promisc),
                             'set_promisc', 'promisc')

    cpdef int set_timeout(self, int timeout) except? -1:
        _need_handle(self.sock, 'PCAPSocket.set_timeout()')
        return _check_setter(pcap_set_timeout(self.sock, timeout),
                             'set_timeout', 'to_ms')

    cpdef int getnonblock(self) except? -1:
        cdef:
            char errors[ERRBUF_SZ]
            int rval
        _need_handle(self.sock, 'PCAPSocket.getnonblock()')
        rval = pcap_getnonblock(self.sock, errors)
        return rval

    cpdef int setnonblock(self, int nonblock) except? -1:
        cdef:
            char errors[ERRBUF_SZ]
            int rval

        _need_handle(self.sock, 'PCAPSocket.setnonblock()')
        rval = pcap_setnonblock(self.sock, nonblock, errors)
        return rval

    cpdef int sendpacket(self, bytes pktdata) except -1:
        cdef:
            const unsigned char * buff = b''
            pcap_t * sock
            int rval, _len

        _need_handle(self.sock, 'PCAPSocket.sendpacket()')
        sock = self.sock
        buff = pktdata
        _len = len(pktdata)
        with nogil:
            rval = pcap_sendpacket(sock, buff, _len)

        if rval == ERROR:
            raise Exception("pcap_sendpacket failed: {0}"
                            "".format(pcap_geterr(self.sock).decode(
                                'utf-8', 'replace')))
        else:
            return _len

    cpdef int open_pcap_dumper(self, str file_name) except? -1:
        _need_handle(self.sock, 'PCAPSocket.open_pcap_dumper()')
        return self._open_pcap_dumper(file_name, self.sock)

    cpdef int add_bpf_filter(self, str bpf_filter) except -1:
        _need_handle(self.sock, 'PCAPSocket.add_bpf_filter()')
        return self._add_bpf_filter(bpf_filter, self.sock, self.mask)

    def __iter__(self):
        return self

    def __next__(self):
        cdef:
            pcap_pkthdr * hdr = NULL
            const unsigned char * buff
            pcap_t * sock = self.sock
            int err = 1
            double ts
            bytes pkt = b''
            str err_txt

        if sock is NULL or self.stop_event.is_set():
            self.close()
            raise StopIteration
        # The read blocks for up to to_ms milliseconds; holding the GIL for
        # that long stalls every other thread in the process.
        with nogil:
            err = pcap_next_ex(sock, &hdr, &buff)
        if err == ERROR:
            # A capture error is not the end of the capture. Read the
            # message before close() invalidates the handle.
            err_txt = pcap_geterr(sock).decode('utf-8', 'replace')
            self.close()
            raise IOError("pcap_next_ex failed on device {0}: {1}"
                          "".format(
                              self.devicename.decode('utf-8', 'replace'),
                              err_txt))
        elif err == ERROR_BREAK or self.stop_event.is_set():
            self.close()
            raise StopIteration
        elif err == 0:
            # read timeout: no packet arrived, but the capture is still live.
            return 0, None, None
        else:
            if hdr[0].ts.tv_usec > 0:
                ts = (hdr[0].ts.tv_sec + (hdr[0].ts.tv_usec / USECCONST))
            else:
                ts = hdr[0].ts.tv_sec
            pkt = <bytes> buff[:hdr[0].caplen]
            return ts, hdr[0], pkt

    cpdef void close(self):
        if self.dumper is not NULL:
            self.close_pcap_dumper()
        self.stop_event.set()
        if self.sock is not NULL:
            pcap_close(self.sock)
        self.sock = NULL

cdef class PCAPReader(PCAPBase):
    def __cinit__(self, *args, **kwargs):
        self.dumper = NULL
        self.reader = NULL

    def __init__(self, *args, **kwargs):
        cdef:
            char errors[ERRBUF_SZ]
            const char * fname_p
            str fname_srt
            object v_err

        errors[0] = 0
        self.decode_context = _netflow_decode_context(kwargs)
        fname_srt = kwargs.get('filename', '')
        # self.filename owns the encoded name for the life of the object;
        # fname_p is only valid while that reference is held.
        self.filename = fname_srt.encode()
        fname_p = self.filename
        self.have_dumper = 0
        self.reader = open_offline(fname_p, errors)

        if self.reader is NULL:
            v_err = ValueError(
                "PCAPReader failed to open {0} for reading. Error was: {1}"
                "".format(fname_srt,
                          (<char *>errors).decode('utf-8', 'replace')))
            raise v_err

    def __dealloc__(self):
        if self.dumper is not NULL:
            pcap_dump_close(self.dumper)
            self.dumper = NULL
            self.have_dumper = 0
        if self.reader is not NULL:
            pcap_close(self.reader)
            self.reader = NULL

    cpdef int open_pcap_dumper(self, str file_name) except? -1:
        _need_handle(self.reader, 'PCAPReader.open_pcap_dumper()')
        return self._open_pcap_dumper(file_name, self.reader)

    cpdef int add_bpf_filter(self, str bpf_filter) except -1:
        _need_handle(self.reader, 'PCAPReader.add_bpf_filter()')
        return self._add_bpf_filter(bpf_filter, self.reader, NETMASK_UNKNOWN)

    def __iter__(self):
        return self

    def __next__(self):
        cdef:
            pcap_pkthdr * hdr = NULL
            const unsigned char * buff
            pcap_t * reader = self.reader
            int err = 1
            double ts
            bytes pkt = b''
            str err_txt

        if reader is NULL:
            raise StopIteration
        err = pcap_next_ex(reader, &hdr, &buff)
        if err == ERROR:
            # -1 is a read error, not end of file. Reporting it as EOF hid
            # truncated and corrupt captures. Read the message first: close()
            # invalidates the handle pcap_geterr() reads from.
            err_txt = pcap_geterr(reader).decode('utf-8', 'replace')
            self.close()
            raise IOError("pcap_next_ex failed reading {0}: {1}"
                          "".format(self.filename.decode('utf-8', 'replace'),
                                    err_txt))
        elif err != 1:
            self.close()
            raise StopIteration
        else:
            if hdr[0].ts.tv_usec > 0:
                ts = (hdr[0].ts.tv_sec + (hdr[0].ts.tv_usec / USECCONST))
            else:
                ts = hdr[0].ts.tv_sec
            pkt = <bytes> buff[:hdr[0].caplen]
            return ts, hdr[0], pkt

    cpdef list pkts(self):
        return list(self)

    cpdef void close(self):
        if self.dumper is not NULL:
            self.close_pcap_dumper()
        if self.reader is not NULL:
            pcap_close(self.reader)
            self.reader = NULL


cdef class PCAPWriter(PCAPBase):
    def __cinit__(self, *args, **kwargs):
        self.dumper = NULL
        self.pcap_dead = NULL

    def __init__(self, *args, **kwargs):
        cdef:
            object v_err
            int rval
            str fn

        # Not run through _resolve_snaplen: this is the snaplen recorded in
        # the file header of a capture we write, not a cap on a live read,
        # and the field is a uint16_t that MAX_SNAPLEN would overflow.
        self.snaplen = kwargs.get('snaplen', 0)
        fn = kwargs.get('filename', '')

        self.have_dumper = 0
        self.pcap_dead = open_dead(ETH_EN10MB, self.snaplen)

        if self.pcap_dead is NULL:
            v_err = ValueError("PCAPWriter failed to open a dead pcap_t *")
            raise v_err
        if fn:
            # _open_pcap_dumper raises on failure, so there is no return
            # value left to check here.
            self.open_pcap_dumper(fn)

    cpdef int open_pcap_dumper(self, str file_name) except? -1:
        _need_handle(self.pcap_dead, 'PCAPWriter.open_pcap_dumper()')
        return self._open_pcap_dumper(file_name, self.pcap_dead)

    cpdef void close(self):
        if self.dumper is not NULL:
            self.close_pcap_dumper()
        if self.pcap_dead is not NULL:
            pcap_close(self.pcap_dead)
            self.pcap_dead = NULL

    def __dealloc__(self):
        if self.dumper is not NULL:
            pcap_dump_close(self.dumper)
            self.dumper = NULL
            self.have_dumper = 0
        if self.pcap_dead is not NULL:
            pcap_close(self.pcap_dead)
            self.pcap_dead = NULL


cpdef dict pcap_info(str filename):
    """Helper function used by PCAP managers to obtain information about
    pcap files.

    Args:
        :filename (str)

    Returns:
        :dict: Keys are first_timestamp, last_timestamp, total_packets,
            and total_bytes and will contain those metrics from the PCAP file
            named by filename. An empty capture reports zero for all four.
    """
    cdef:
        PCAPReader rdr
        PcapInfoState state
        pcap_t * handle
        int status
        str err_txt
        dict rval

    rdr = PCAPReader(filename=filename)
    handle = rdr.reader
    state.packets = 0
    state.byte_count = 0
    state.first_ts = 0
    state.last_ts = 0
    try:
        while True:
            # nogil: _pcap_info_callback touches nothing but the C struct it
            # is handed, and this loop walks an entire capture file, so
            # holding the interpreter lock across it stalled every other
            # thread for the length of the scan.
            with nogil:
                status = pcap_dispatch(handle, 256, _pcap_info_callback,
                                       <u_char *>&state)
            if status == 0:
                break
            if status == ERROR_BREAK:
                # pcap_breakloop() was called on this handle. A deliberate
                # stop, not a read failure - it used to be reported as one.
                break
            if status < 0:
                err_txt = pcap_geterr(handle).decode('utf-8', 'replace')
                raise IOError("pcap_dispatch failed reading {0}: {1}"
                              "".format(filename, err_txt))
    finally:
        rdr.close()
    rval = {'first_timestamp': state.first_ts,
            'last_timestamp': state.last_ts,
            'total_packets': state.packets,
            'total_bytes': state.byte_count}
    return rval


cdef int _retime_netflow_simple(object nf, double now) except -1:
    """Move a NetflowSimple header's export timestamp forward to ``now``.

    NetflowSimple names its five header fields after the v1-v8 layout, but v9
    and IPFIX put different things in the same bytes, so which field carries
    the export time - and which must be left alone - depends on the version:

      * v1-v8: unix_secs / unix_nano_seconds are the export timestamp.
      * v9 (RFC 3954): unix_secs is still the export time, but the bytes
        NetflowSimple calls unix_nano_seconds are the flow sequence number.
      * IPFIX / v10 (RFC 7011): the header is version, length, exportTime,
        sequenceNumber, observationDomainID. Only sys_uptime lines up with
        exportTime; unix_secs and unix_nano_seconds are the sequence number
        and the observation domain id, and rewriting either corrupts the
        stream for the collector.
    """
    if nf.version == 10:
        nf.sys_uptime = int(now)
        return 0
    nf.unix_secs = int(now)
    if nf.version != 9:
        nf.unix_nano_seconds = int((now % 1) * 1000000)
    return 0


cdef object _replay_netflow_layer(Ethernet eth):
    """The NetflowSimple layer of a captured frame, or None.

    The BPF filter a replay installs constrains only the UDP destination
    port, so everything else sent to that port arrives here too - and 2055
    sees plenty. get_layer_by_type() answers with an empty NullPkt when the
    layer is absent, and a decode context that does not force the simple
    representation produces a full Netflow instead, which keeps its header
    fields on a separate header object. Neither has the five header fields
    the rewrite below assigns, so reaching for them raised AttributeError
    part way through a replay and abandoned the rest of the capture.
    """
    cdef PKT layer = eth.get_layer_by_type(PQ_NETFLOW_SIMPLE)
    if isinstance(layer, NetflowSimple):
        return layer
    return None


cdef int _require_simple_context(object decode_context, str call) except -1:
    """A replay needs the simple NetFlow representation, not a decoded one.

    Replay rewrites header fields by name and re-serializes the datagram
    byte for byte, which is what NetflowSimple is for. A context that lets
    the full decoder run yields a Netflow whose header fields live on a
    header object, so every frame would be skipped as unusable; saying so
    up front beats reporting a capture's worth of skipped packets.
    """
    if decode_context is not None and not decode_context.force_simple:
        raise ValueError(
            "{0} needs a NetflowDecodeContext(force_simple=True); replay "
            "rewrites the NetFlow header in place and re-sends the original "
            "bytes".format(call))
    return 0


cdef int _address_family(str address) except -1:
    try:
        socket.inet_pton(socket.AF_INET, address)
        return socket.AF_INET
    except (OSError, ValueError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return socket.AF_INET6
    except (OSError, ValueError):
        raise ValueError("invalid IPv4 or IPv6 address: {0}".format(address))


cdef bytes _build_netflow_replay_frame_for_family(
        bytes pkt,
        int family,
        str dest_ip,
        str dest_mac,
        uint16_t dest_port,
        str src_ip,
        str src_mac,
        uint16_t pcap_dst_port,
        double now,
        uint16_t new_version,
        unsigned char new_type,
        object decode_context):
    cdef:
        Ethernet captured_eth, replay_eth
        object captured_ip, captured_udp, nf, replay_ip
        UDP replay_udp
        str replay_src_ip, replay_src_mac
        bytes the_flow

    captured_eth = Ethernet(pkt, l7_ports={pcap_dst_port: Netflow},
                            decode_context=decode_context)
    nf = _replay_netflow_layer(captured_eth)
    if nf is None:
        return None
    captured_ip = captured_eth.payload
    captured_udp = captured_ip.payload

    if src_ip:
        replay_src_ip = src_ip
    else:
        replay_src_ip = captured_ip.src
        if _address_family(replay_src_ip) != family:
            raise ValueError(
                "src_ip is required when replay changes address family")
    if src_mac:
        replay_src_mac = src_mac
    else:
        replay_src_mac = captured_eth.src_mac

    _retime_netflow_simple(nf, now)
    if new_type > 0 and nf.version in (5, 6, 7, 8):
        the_flow = nf.payload
        if len(the_flow) >= 5:
            nf.payload = (the_flow[:4] + new_type.to_bytes(1, 'big') +
                          the_flow[5:])
    if new_version > 0:
        nf.version = new_version

    replay_udp = UDP(sport=captured_udp.sport, dport=dest_port, payload=nf)
    if family == socket.AF_INET6:
        replay_ip = IP6(src=replay_src_ip, dst=dest_ip, next_header=17,
                        payload=replay_udp)
    else:
        replay_ip = IP(src=replay_src_ip, dst=dest_ip, proto=17,
                       payload=replay_udp)
    replay_eth = Ethernet(src_mac=replay_src_mac, dst_mac=dest_mac,
                          payload=replay_ip)
    return replay_eth.pkt2net({'csum': 1, 'update': 1})


def _build_netflow_replay_frame(bytes pkt,
                                str dest_ip,
                                str dest_mac,
                                uint16_t dest_port,
                                str src_ip='',
                                str src_mac='',
                                uint16_t pcap_dst_port=2055,
                                double now=0,
                                uint16_t new_version=0,
                                unsigned char new_type=0,
                                decode_context=None):
    """Build one replay carrier without opening a raw socket."""
    cdef int family = _address_family(dest_ip)
    cdef bytes frame
    _require_simple_context(decode_context, '_build_netflow_replay_frame()')
    if decode_context is None:
        decode_context = NetflowDecodeContext(force_simple=True)
    if src_ip and _address_family(src_ip) != family:
        raise ValueError("src_ip and dest_ip must use the same address family")
    frame = _build_netflow_replay_frame_for_family(
        pkt, family, dest_ip, dest_mac, dest_port, src_ip, src_mac,
        pcap_dst_port, now, new_version, new_type, decode_context)
    if frame is None:
        # The replay loops count and skip these; a caller asking for one
        # frame has nothing to be handed back, so say why.
        raise ValueError("packet carries no NetFlow payload on UDP port "
                         "{0}".format(pcap_dst_port))
    return frame

cpdef int netflow_replay_raw_sock(str device,
                                  str pcap_file,
                                  uint16_t pcap_dst_port,
                                  str dest_ip,
                                  str dest_mac,
                                  uint16_t dest_port,
                                  uint16_t new_version=0,
                                  unsigned char new_type=0,
                                  str src_ip='',
                                  str src_mac='',
                                  unsigned char blast_mode=0,
                                  object decode_context=None) except -1:
    """
    Function to replay pcap files containing netflow versions 1-9.
    :param device: Device to bind our outgoing socket to.
    :param pcap_file: The file containing the packets we want to replay.
    :param pcap_dst_port: The UDP src port of the netflow packets we are 
           interested in.

    :param dest_ip: The IP address we want to send these packets to.
    :param dest_mac: The MAC address of the destination IP.
    :param dest_port: The port that the recipient device will be listening on.
    :param new_version: re-write the netflow version to be new_version IF 
           new_version is a positive uint16_t.
    :param new_type: re-write the netflow v.5-8 engine_type to be new_type IF 
           new_type is a positive unsigned char.
    :param src_ip: The IP address we want to send these packets from.
    :param src_mac: The MAC address we want to send these packets from.
    :param blast_mode: bool value. 0 == play at the same pace as in the pcap or
           at the speed defined by speedup. 1 means blast as fast as possible.
           Overrides speedup if set.
    :param speedup: divide the inter-packet gap by this number.
    :param decode_context: optional NetflowDecodeContext. It must have
           force_simple set: replay rewrites the NetFlow header in place and
           re-sends the original bytes, which is what NetflowSimple is for.
    :return: std unix 0 or 1 for all is well and something went wrong. 1 is
           also returned when nothing matched pcap_dst_port, when a send
           failed, or when a matched packet carried no NetFlow and was
           skipped; each case is described on stderr.
    """

    cdef:
        PCAPSocket sender
        PCAPReader reader
        unsigned char first
        int family
        double now, ts, offset, add
        pcap_pkthdr_t hdr
        bytes pkt, frame
        uint32_t sent, failed, skipped

    _require_simple_context(decode_context, 'netflow_replay_raw_sock()')
    if decode_context is None:
        decode_context = NetflowDecodeContext(force_simple=True)
    family = _address_family(dest_ip)
    if src_ip and _address_family(src_ip) != family:
        raise ValueError("src_ip and dest_ip must use the same address family")

    sender = PCAPSocket(devicename=device)
    sender.setnonblock(1)

    reader = PCAPReader(filename=pcap_file)
    reader.add_bpf_filter('udp dst port {0}'.format(pcap_dst_port))

    first = 1
    offset = 0
    sent = failed = skipped = 0
    # There used to be a copy of this body ahead of the loop, to establish
    # offset from the first packet. It had drifted: it applied neither
    # src_mac nor src_ip - the two things --spoofing exists for - nor
    # new_type, so the first flow of every replay went out with the
    # capture's own identity. Establishing offset inside the loop keeps one
    # copy of the rewrite. It also means an empty capture, or a
    # pcap_dst_port matching nothing, no longer raises StopIteration at the
    # caller.
    for ts, hdr, pkt in reader:
        now = time.time()
        if first:
            offset = now - ts
            first = 0
        elif not blast_mode and ts + offset >= now:
            add = (ts + offset) - now
            time.sleep(add)
            now += add
        # 'udp dst port N' matches anything sent to that port, NetFlow or
        # not, and a datagram too short to hold a NetFlow header fails the
        # decode outright. Either way it is one packet to account for, not a
        # reason to abandon the rest of the capture.
        try:
            frame = _build_netflow_replay_frame_for_family(
                pkt, family, dest_ip, dest_mac, dest_port, src_ip, src_mac,
                pcap_dst_port, now, new_version, new_type, decode_context)
        except (ValueError, AttributeError) as e:
            frame = None
            if not skipped:
                sys.stderr.write("netflow_replay_raw_sock: skipping a packet "
                                 "that did not decode as NetFlow: {0}\n"
                                 "".format(e))
        if frame is None:
            skipped += 1
            continue
        try:
            sender.sendpacket(frame)
            sent += 1
        except Exception as e:
            # The socket is non-blocking, so in blast mode a full send
            # buffer drops packets. Silently returning 0 hid that.
            failed += 1
            if failed == 1:
                sys.stderr.write("netflow_replay_raw_sock: send failed: "
                                 "{0}\n".format(e))
    if first:
        sys.stderr.write("netflow_replay_raw_sock: no packets in {0} matched "
                         "'udp dst port {1}'\n".format(pcap_file,
                                                       pcap_dst_port))
        return 1
    if failed:
        sys.stderr.write("netflow_replay_raw_sock: {0} of {1} packets failed "
                         "to send\n".format(failed,
                                            sent + failed + skipped))
        return 1
    if skipped:
        sys.stderr.write("netflow_replay_raw_sock: {0} of {1} packets matched "
                         "'udp dst port {2}' but carried no NetFlow and were "
                         "skipped\n".format(skipped, sent + skipped,
                                            pcap_dst_port))
        return 1
    return 0


cpdef int netflow_replay_system_sock(str pcap_file,
                                     uint16_t pcap_dst_port,
                                     str dest_ip,
                                     uint16_t dest_port,
                                     uint16_t new_version=0,
                                     unsigned char new_type=0,
                                     unsigned char blast_mode=0,
                                     object decode_context=None) except -1:
    """
    Function to replay pcap files containing netflow versions 1-9.
    :param pcap_file: The file containing the packets we want to replay.
    :param pcap_dst_port: The UDP src port of the netflow packets we are 
           interested in.
    :param dest_ip: The IP address we want to send these packets to.
    :param dest_port: The port that the recipient device will be listening on.
    :param new_version: re-write the netflow version to be new_version IF 
           new_version is a positive uint16_t.
    :param new_type: re-write the netflow v.5-8 engine_type to be new_type IF 
           new_type is a positive unsigned char.
    :param blast_mode: bool value. 0 == play at the same pace as in the pcap or
           at the speed defined by speedup. 1 means blast as fast as possible.
           Overrides speedup if set.
    :param decode_context: optional NetflowDecodeContext. It must have
           force_simple set: see netflow_replay_raw_sock.
    :return: std unix 0 or 1 for all is well and something went wrong. 1 is
           also returned when nothing matched pcap_dst_port, when a send
           failed, or when a matched packet carried no NetFlow and was
           skipped; each case is described on stderr.
    """

    cdef:
        object sender
        PCAPReader reader
        unsigned char first
        int family
        double now, ts, offset, add
        pcap_pkthdr_t hdr
        bytes pkt, the_flow, type_byte
        dict l7_ports
        Ethernet eth
        object nf
        uint32_t sent, failed, skipped

    _require_simple_context(decode_context, 'netflow_replay_system_sock()')
    if decode_context is None:
        decode_context = NetflowDecodeContext(force_simple=True)
    family = _address_family(dest_ip)
    sender = socket.socket(family, socket.SOCK_DGRAM)

    reader = PCAPReader(filename=pcap_file)
    reader.add_bpf_filter('udp dst port {0}'.format(pcap_dst_port))

    l7_ports = {pcap_dst_port: Netflow}
    type_byte = new_type.to_bytes(1, 'big')

    first = 1
    offset = 0
    sent = failed = skipped = 0
    # As in netflow_replay_raw_sock: the pre-loop send this replaces had
    # drifted from the loop body and applied neither new_type nor
    # new_version, so the first flow of every replay carried the capture's
    # own engine type and version.
    for ts, hdr, pkt in reader:
        now = time.time()
        if first:
            offset = now - ts
            first = 0
        elif not blast_mode and ts + offset >= now:
            add = (ts + offset) - now
            time.sleep(add)
            now += add
        # As in netflow_replay_raw_sock: the BPF filter constrains only the
        # destination port, so account for a packet that is not NetFlow
        # rather than letting it end the replay.
        nf = None
        try:
            eth = Ethernet(pkt, l7_ports=l7_ports,
                           decode_context=decode_context)
            nf = _replay_netflow_layer(eth)
            if nf is not None:
                _retime_netflow_simple(nf, now)
                if new_type > 0 and nf.version in (5, 6, 7, 8):
                    the_flow = nf.payload
                    if len(the_flow) >= 5:
                        nf.payload = the_flow[:4] + type_byte + the_flow[5:]
                if new_version > 0:
                    nf.version = new_version
        except (ValueError, AttributeError) as e:
            nf = None
            if not skipped:
                sys.stderr.write("netflow_replay_system_sock: skipping a "
                                 "packet that did not decode as NetFlow: "
                                 "{0}\n".format(e))
        if nf is None:
            skipped += 1
            continue
        try:
            sender.sendto(nf.pkt2net({}), (dest_ip, dest_port))
            sent += 1
        except OSError as e:
            failed += 1
            if failed == 1:
                sys.stderr.write("netflow_replay_system_sock: send failed: "
                                 "{0}\n".format(e))
    if first:
        sys.stderr.write("netflow_replay_system_sock: no packets in {0} "
                         "matched 'udp dst port {1}'\n"
                         "".format(pcap_file, pcap_dst_port))
        return 1
    if failed:
        sys.stderr.write("netflow_replay_system_sock: {0} of {1} packets "
                         "failed to send\n".format(failed,
                                                   sent + failed + skipped))
        return 1
    if skipped:
        sys.stderr.write("netflow_replay_system_sock: {0} of {1} packets "
                         "matched 'udp dst port {2}' but carried no NetFlow "
                         "and were skipped\n".format(skipped, sent + skipped,
                                                     pcap_dst_port))
        return 1
    return 0