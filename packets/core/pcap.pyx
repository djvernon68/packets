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


cdef object _netflow_decode_context(dict kwargs):
    cdef object context = kwargs.get('decode_context')

    if context is None:
        from packets.protos.netflow import NetflowDecodeContext
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
        pcap_if_t * ifaces
        pcap_if_t * current
        pcap_addr * cur_addr
    rval = ERROR
    rval = pcap_findalldevs(&ifaces, errtext)
    if not rval:
        current = ifaces
        while current:
            devices.append(current.name)
            current = current.next
    return rval

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

    cdef int _open_pcap_dumper(self, str file_name, pcap_t * sock):
        cdef:
            char * filename = b''
            bytes encoded

        encoded = file_name.encode()
        filename = encoded
        self.dumper = pcap_dump_open(sock, filename)
        if self.dumper is NULL:
            return ERROR
        else:
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
                            "".format(pcap_geterr(sock).decode()))
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
        snaplen = kwargs.get('snaplen', 0)
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

    cpdef int set_snaplen(self, int snaplen):
        return pcap_set_snaplen(self.sock, snaplen)

    cpdef int set_promisc(self, int promisc):
        return pcap_set_promisc(self.sock, promisc)

    cpdef int set_timeout(self, int timeout):
        return pcap_set_timeout(self.sock, timeout)


    cpdef int getnonblock(self):
        cdef:
            char errors[ERRBUF_SZ]
            int rval
        rval = pcap_getnonblock(self.sock, errors)
        return rval

    cpdef int setnonblock(self, int nonblock):
        cdef:
            char errors[ERRBUF_SZ]
            int rval

        rval = pcap_setnonblock(self.sock, nonblock, errors)
        return rval

    cpdef int sendpacket(self, bytes pktdata) except -1:
        cdef:
            const unsigned char * buff = b''
            pcap_t * sock = self.sock
            int rval, _len

        buff = pktdata
        _len = len(pktdata)
        with nogil:
            rval = pcap_sendpacket(sock, buff, _len)

        if rval == ERROR:
            raise Exception("pcap_sendpacket failed: {0}"
                            "".format(pcap_geterr(self.sock).decode()))
        else:
            return _len

    cpdef int open_pcap_dumper(self, str file_name):
        return self._open_pcap_dumper(file_name, self.sock)

    cpdef int add_bpf_filter(self, str bpf_filter) except -1:
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

    cpdef int open_pcap_dumper(self, str file_name):
        return self._open_pcap_dumper(file_name, self.reader)

    cpdef int add_bpf_filter(self, str bpf_filter) except -1:
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

        self.snaplen = kwargs.get('snaplen', 0)
        fn = kwargs.get('filename', '')

        self.have_dumper = 0
        self.pcap_dead = open_dead(ETH_EN10MB, self.snaplen)

        if self.pcap_dead is NULL:
            v_err = ValueError("PCAPWriter failed to open a dead pcap_t *")
            raise v_err
        if fn:
            rval = self.open_pcap_dumper(fn)
            if rval:
                v_err = ValueError("PCAPWriter could not open a pcap_dumper_t")
                raise v_err

    cpdef int open_pcap_dumper(self, str file_name):
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
        int status
        str err_txt
        dict rval

    rdr = PCAPReader(filename=filename)
    state.packets = 0
    state.byte_count = 0
    state.first_ts = 0
    state.last_ts = 0
    try:
        while True:
            status = pcap_dispatch(rdr.reader, 256, _pcap_info_callback,
                                   <u_char *>&state)
            if status == 0:
                break
            if status < 0:
                err_txt = pcap_geterr(rdr.reader).decode('utf-8', 'replace')
                raise IOError("pcap_next_ex failed reading {0}: {1}"
                              "".format(filename, err_txt))
    finally:
        rdr.close()
    rval = {'first_timestamp': state.first_ts,
            'last_timestamp': state.last_ts,
            'total_packets': state.packets,
            'total_bytes': state.byte_count}
    return rval


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
    captured_ip = captured_eth.payload
    captured_udp = captured_ip.payload
    nf = captured_udp.payload

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

    nf.unix_secs = int(now)
    if new_type > 0 and nf.version in (5, 6, 7, 8):
        the_flow = nf.payload
        if len(the_flow) >= 5:
            nf.payload = (the_flow[:4] + new_type.to_bytes(1, 'big') +
                          the_flow[5:])
    if nf.version != 9:
        nf.unix_nano_seconds = int((now % 1) * 1000000)
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
    if decode_context is None:
        decode_context = NetflowDecodeContext(force_simple=True)
    if src_ip and _address_family(src_ip) != family:
        raise ValueError("src_ip and dest_ip must use the same address family")
    return _build_netflow_replay_frame_for_family(
        pkt, family, dest_ip, dest_mac, dest_port, src_ip, src_mac,
        pcap_dst_port, now, new_version, new_type, decode_context)

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
    :return: std unix 0 or 1 for all is well and something went wrong.
    """

    cdef:
        PCAPSocket sender
        PCAPReader reader
        unsigned char first
        int family
        double now, ts, offset, add
        pcap_pkthdr_t hdr
        bytes pkt, frame
        uint32_t sent, failed

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
    sent = failed = 0
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
        frame = _build_netflow_replay_frame_for_family(
            pkt, family, dest_ip, dest_mac, dest_port, src_ip, src_mac,
            pcap_dst_port, now, new_version, new_type, decode_context)
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
                         "to send\n".format(failed, sent + failed))
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
    :return: std unix 0 or 1 for all is well and something went wrong.
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
        uint32_t sent, failed

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
    sent = failed = 0
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
        eth = Ethernet(pkt, l7_ports=l7_ports,
                       decode_context=decode_context)
        nf = eth.get_layer_by_type(PQ_NETFLOW_SIMPLE)
        nf.unix_secs = int(now)
        if nf.version != 9:
            nf.unix_nano_seconds = int((now % 1) * 1000000)
        if new_type > 0 and nf.version in (5, 6, 7, 8):
            the_flow = nf.payload
            if len(the_flow) >= 5:
                nf.payload = the_flow[:4] + type_byte + the_flow[5:]
        if new_version > 0:
            nf.version = new_version
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
                         "failed to send\n".format(failed, sent + failed))
        return 1
    return 0