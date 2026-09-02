# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

# all of the previous pcap code has been moved out because all of our
# pcap processing is not based on a direct wrap of libpcap's pcap.h and
# related files

# Note: This means that socket operations (open_live) have been added to
# pcap's set of features.

from libc.stdio cimport FILE
from libc.time cimport time_t
from libc.stdint cimport uint16_t, uint32_t

DEF BUFFSIZE = 256
DEF PCAP_NETMASK_UNKNOWN = 0xffffffff

cdef:
    char VERSION_MAJOR
    char VERSION_MINOR
    uint16_t ERRBUF_SIZE
    char ERROR
    char ERROR_BREAK
    char ERROR_NOT_ACTIVATED
    char ERROR_ACTIVATED
    char ERROR_NO_SUCH_DEVICE
    char ERROR_RFMON_NOTSUP
    char ERROR_NOT_RFMON
    char ERROR_PERM_DENIED
    char ERROR_IFACE_NOT_UP
    char ERROR_CANTSET_TSTAMP_TYPE
    char ERROR_PROMISC_PERM_DENIED
    char ERROR_TSTAMP_PRECISION_NOTSUP
    char WARNING
    char WARNING_PROMISC_NOTSUP
    char WARNING_TSTAMP_TYPE_NOTSUP
    uint32_t NETMASK_UNKNOWN
    char TSTAMP_HOST
    char TSTAMP_HOST_LOWPREC
    char TSTAMP_HOST_HIPREC
    char TSTAMP_ADAPTER
    char TSTAMP_ADAPTER_UNSYNCED
    char TSTAMP_PRECISION_MICRO
    char TSTAMP_PRECISION_NANO
    char ETH_NULL
    char ETH_EN10MB
    char ETH_IEEE802
    char ETH_ARCNET
    char ETH_SLIP
    char ETH_PPP
    char ETH_FDDI
    char ETH_ATM_RFC1483
    char ETH_RAW
    char ETH_PPP_SERIAL
    char ETH_PPP_ETHER
    char ETH_C_HDLC
    char ETH_IEEE802_11
    char ETH_LOOP
    char ETH_LINUX_SLL
    char ETH_LTALK
    uint32_t PCAP_NETMASK_UNKNOWN

cdef class PCAP_CONST:
    cdef:
        readonly char VERSION_MAJOR
        readonly char VERSION_MINOR
        uint16_t ERRBUF_SIZE
        readonly char ERROR
        readonly char ERROR_BREAK
        readonly char ERROR_NOT_ACTIVATED
        readonly char ERROR_ACTIVATED
        readonly char ERROR_NO_SUCH_DEVICE
        readonly char ERROR_RFMON_NOTSUP
        readonly char ERROR_NOT_RFMON
        readonly char ERROR_PERM_DENIED
        readonly char ERROR_IFACE_NOT_UP
        readonly char ERROR_CANTSET_TSTAMP_TYPE
        readonly char ERROR_PROMISC_PERM_DENIED
        readonly char ERROR_TSTAMP_PRECISION_NOTSUP
        readonly char WARNING
        readonly char WARNING_PROMISC_NOTSUP
        readonly char WARNING_TSTAMP_TYPE_NOTSUP
        uint32_t NETMASK_UNKNOWN
        readonly char TSTAMP_HOST
        readonly char TSTAMP_HOST_LOWPREC
        readonly char TSTAMP_HOST_HIPREC
        readonly char TSTAMP_ADAPTER
        readonly char TSTAMP_ADAPTER_UNSYNCED
        readonly char TSTAMP_PRECISION_MICRO
        readonly char TSTAMP_PRECISION_NANO
        readonly char ETH_NULL
        readonly char ETH_EN10MB
        readonly char ETH_IEEE802
        readonly char ETH_ARCNET
        readonly char ETH_SLIP
        readonly char ETH_PPP
        readonly char ETH_FDDI
        readonly char ETH_ATM_RFC1483
        readonly char ETH_RAW
        readonly char ETH_PPP_SERIAL
        readonly char ETH_PPP_ETHER
        readonly char ETH_C_HDLC
        readonly char ETH_IEEE802_11
        readonly char ETH_LOOP
        readonly char ETH_LINUX_SLL
        readonly char ETH_LTALK

# General Types used
ctypedef unsigned char __uint8_t
ctypedef short __int16_t
ctypedef unsigned short __uint16_t
ctypedef int __int32_t
ctypedef unsigned int __uint32_t
ctypedef long long __int64_t
ctypedef unsigned long long __uint64_t
ctypedef __uint8_t sa_family_t
ctypedef unsigned short u_short
ctypedef unsigned char u_char
ctypedef unsigned int bpf_u_int32
ctypedef int bpf_int32
ctypedef unsigned int u_int


cdef extern from "<sys/time.h>" nogil:
    struct timeval:
        time_t tv_sec
        time_t tv_usec

cdef extern from "<signal.h>" nogil:
    ctypedef int sig_atomic_t

cdef extern from "<sys/socket.h>" nogil:
    struct sockaddr:
        __uint8_t sa_len
        sa_family_t sa_family
        char sa_data[14]


cdef extern from "<pcap/bpf.h>" nogil:
    struct bpf_insn:
        u_short code
        u_char jt
        u_char jf
        bpf_u_int32 k

    struct bpf_program:
        u_int bf_len
        bpf_insn *bf_insns

cdef extern from "<pcap.h>" nogil:

    ctypedef pcap pcap_t
    ctypedef pcap_dumper pcap_dumper_t
    ctypedef pcap_if pcap_if_t
    ctypedef pcap_addr pcap_addr_t

    struct pcap_pkthdr:
        timeval ts
        bpf_u_int32 caplen
        bpf_u_int32 len

    ctypedef void (*pcap_handler)(u_char *,
                                  const pcap_pkthdr *,
                                  const u_char *)

    char *pcap_lookupdev(char *)
    int pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *)
    pcap_t *pcap_create(const char *, char *)

    int pcap_set_snaplen(pcap_t *, int)
    int pcap_set_promisc(pcap_t *, int)
    int pcap_can_set_rfmon(pcap_t *)
    int pcap_set_rfmon(pcap_t *, int)
    int pcap_set_timeout(pcap_t *, int)
    int pcap_set_tstamp_type(pcap_t *, int)
    int pcap_set_immediate_mode(pcap_t *, int)
    int pcap_set_buffer_size(pcap_t *, int)
    int pcap_set_tstamp_precision(pcap_t *, int)
    int pcap_get_tstamp_precision(pcap_t *)
    int pcap_activate(pcap_t *)
    pcap_t *pcap_open_live(const char *, int, int, int, char *)
    pcap_t *pcap_open_offline(const char *, char *)
    pcap_t *pcap_open_dead(int, int)
    void pcap_close(pcap_t *)
    int pcap_loop(pcap_t *, int, pcap_handler, u_char *)
    int pcap_dispatch(pcap_t *, int, pcap_handler, u_char *)
    const u_char* pcap_next(pcap_t *, pcap_pkthdr *)
    int pcap_next_ex(pcap_t *, pcap_pkthdr **, const u_char **)
    void pcap_breakloop(pcap_t *)
    int pcap_stats(pcap_t *, pcap_stat *)
    int pcap_setfilter(pcap_t *, bpf_program *)
    int pcap_setdirection(pcap_t *, pcap_direction_t)
    int pcap_getnonblock(pcap_t *, char *)
    int pcap_setnonblock(pcap_t *, int, char *)
    int pcap_sendpacket(pcap_t *, const u_char *, int)
    int pcap_compile(pcap_t *, bpf_program *,
                     const char *, int,
                     bpf_u_int32)
    int pcap_compile_nopcap(int, int, bpf_program *,
                            const char *, int,
                            bpf_u_int32)
    void pcap_freecode(bpf_program *);
    int pcap_offline_filter(const bpf_program *,
                            const pcap_pkthdr *,
                            const u_char *)
    int pcap_snapshot(pcap_t *)
    int pcap_is_swapped(pcap_t *)
    int pcap_major_version(pcap_t *)
    int pcap_minor_version(pcap_t *)
    char *pcap_geterr(pcap_t *)

    FILE *pcap_file(pcap_t *)
    int pcap_fileno(pcap_t *)

    pcap_dumper_t *pcap_dump_open(pcap_t *, const char *)
    pcap_dumper_t *pcap_dump_fopen(pcap_t *, FILE *fp)
    FILE *pcap_dump_file(pcap_dumper_t *)
    long pcap_dump_ftell(pcap_dumper_t *)
    int pcap_dump_flush(pcap_dumper_t *)
    void pcap_dump_close(pcap_dumper_t *)
    void pcap_dump(u_char *, const pcap_pkthdr *, const u_char *)

    int pcap_findalldevs(pcap_if_t **, char *)
    void pcap_freealldevs(pcap_if_t *)
    const char *pcap_lib_version()

    # Only doing Linux and MACOS so we will declare bpf_filter
    uint32_t bpf_filter(const bpf_insn *, const u_char *, u_int, u_int)
    int bpf_validate(const bpf_insn *f, int len)
    char *bpf_image(const bpf_insn *, int)
    void bpf_dump(const bpf_program *, int)

    pcap_dumper_t *pcap_dump_open(pcap_t *, const char *)
    int	pcap_dump_flush(pcap_dumper_t *);
    void pcap_dump_close(pcap_dumper_t *);
    void pcap_dump(u_char *, const pcap_pkthdr *, const u_char *);

    struct pcap_dumper

    # pcap_t is opaque. This used to carry a hand copy of libpcap's private
    # struct, guarded by a per-OS IF - deprecated in Cython 3 - because the
    # layout differs between platforms and between libpcap releases. Nothing
    # here dereferences it, so declaring it opaque removes both the warning
    # and the dependency on a layout we do not control.
    struct pcap

    struct pcap_file_header:
        bpf_u_int32 magic
        u_short version_major
        u_short version_minor
        bpf_int32 thiszone
        bpf_u_int32 sigfigs
        bpf_u_int32 snaplen
        bpf_u_int32 linktype

    cdef enum pcap_direction_t:
       PCAP_D_INOUT = 0
       PCAP_D_IN = 1
       PCAP_D_OUT = 2

    struct pcap_stat:
        u_int ps_recv
        u_int ps_drop
        u_int ps_ifdrop

    struct pcap_if:
        pcap_if * next
        char * name
        char * description
        pcap_addr * addresses
        bpf_u_int32 flags

    struct pcap_addr:
        pcap_addr * next
        sockaddr * addr
        sockaddr * netmask
        sockaddr * broadaddr
        sockaddr * dstaddr

    struct pcap_timeval:
        bpf_int32 tv_sec
        bpf_int32 tv_usec

    struct pcap_sf_pkthdr:
        pcap_timeval ts
        bpf_u_int32 caplen
        bpf_u_int32 len

    struct pcap_sf_patched_pkthdr:
        pcap_timeval ts
        bpf_u_int32 caplen
        bpf_u_int32 len
        int index
        unsigned short protocol
        unsigned char pkt_type

    struct oneshot_userdata:
        pcap_pkthdr *hdr
        const u_char **pkt
        pcap_t *pd

cdef struct pcapdumper:
    pcap_dumper_t * dumper

ctypedef pcap_pkthdr pcap_pkthdr_t

cpdef uint32_t ip2int(str addr)
cpdef str int2ip(uint32_t addr)

cpdef char *lookupdev(char *errtext)
cpdef int findalldevs(list devices, char *errtext)
cpdef list list_devices()
cdef int lookupnet(const char *device,
                   bpf_u_int32 *net,
                   bpf_u_int32 *mask,
                   char *errtext)
cdef pcap_t *open_live(const char * device,
                       int snaplen,
                       int promisc,
                       int to_ms,
                       char *errtext)
cdef pcap_t *open_offline(const char * filename,
                          char *errtext)
cdef pcap_t *open_dead(int linktype,
                       int snaplen)


cdef class PCAPBase:
    cdef:
        pcap_dumper_t * dumper
        bint have_dumper
        double start_ts, end_ts

    # except -1: a dumper that could not be opened has to reach the caller.
    # Returning ERROR left dump_hdr_pkt() silently discarding every packet.
    cdef int _open_pcap_dumper(self, str file_name, pcap_t * sock) except -1
    cpdef void close_pcap_dumper(self)
    cpdef void dump_hdr_pkt(self,
                            pcap_pkthdr_t hdr,
                            bytes data,
                            uint32_t tv_sec=*,
                            uint32_t tv_usec=*)
    cpdef void dump_pkt(self,
                        bytes data,
                        uint32_t tv_sec=*,
                        uint32_t tv_usec=*)
    # except -1: a bad filter raises. Without the except clause a cdef int
    # function cannot propagate, and Cython 0.28 merely prints the exception
    # and returns, leaving the caller reading everything on the source.
    cdef int _add_bpf_filter(self,
                             str bpf_filter,
                             pcap_t * sock,
                             bpf_u_int32 mask) except -1
    cpdef int add_bpf_filter(self, str bpf_filter) except -1


cdef class PCAPSocket(PCAPBase):
    cdef:
        public object stop_event
        public object decode_context
        # owns the encoded device name; a bare char* here dangled once
        # __init__ returned and its local bytes object was collected.
        bytes devicename
        pcap_t * sock
        bpf_u_int32 net
        bpf_u_int32 mask

    # except? -1 on all of these: close() NULLs self.sock, and libpcap does
    # not check its handle argument, so each of them has to be able to say
    # 'closed' rather than crash inside libpcap. Without an exception value
    # a cdef int function cannot propagate at all - Cython 0.28 prints the
    # exception and returns as though it had not happened. The '?' is there
    # because -1 is also a genuine libpcap return code.
    cpdef int set_snaplen(self, int snaplen) except? -1
    cpdef int set_promisc(self, int promisc) except? -1
    cpdef int set_timeout(self, int timeout) except? -1
    cpdef int getnonblock(self) except? -1
    cpdef int setnonblock(self, int nonblock) except? -1
    # except -1: as add_bpf_filter, a failed send must reach the caller.
    cpdef int sendpacket(self, bytes pktdata) except -1
    cpdef int add_bpf_filter(self, str bpf_filter) except -1
    cpdef int open_pcap_dumper(self, str file_name) except? -1
    cpdef void close(self)


cdef class PCAPReader(PCAPBase):
    cdef:
        public object decode_context
        # owns the encoded file name; see the note on PCAPSocket.devicename.
        bytes filename
        pcap_t * reader


    cpdef list pkts(self)
    cpdef void close(self)
    cpdef int open_pcap_dumper(self, str file_name) except? -1
    cpdef int add_bpf_filter(self, str bpf_filter) except -1


cdef class PCAPWriter(PCAPBase):
    cdef:
        pcap_t * pcap_dead
        uint16_t snaplen


    cpdef void close(self)
    cpdef int open_pcap_dumper(self, str file_name) except? -1


cpdef pcap_pkthdr_t get_pkts_header(double ts, bytes data)

cpdef dict pcap_info(str filename)

cpdef int netflow_replay_raw_sock(str device,
                                  str pcap_file,
                                  uint16_t pcap_dst_port,
                                  str dest_ip,
                                  str dest_mac,
                                  uint16_t dest_port,
                                  uint16_t new_version=*,
                                  unsigned char new_type=*,
                                  str src_ip=*,
                                  str src_mac=*,
                                  unsigned char blast_mode=*,
                                  object decode_context=*) except -1

cpdef int netflow_replay_system_sock(str pcap_file,
                                     uint16_t pcap_dst_port,
                                     str dest_ip,
                                     uint16_t dest_port,
                                     uint16_t new_version=*,
                                     unsigned char new_type=*,
                                     unsigned char blast_mode=*,
                                     object decode_context=*) except -1
