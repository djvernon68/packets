# cython: language_level=3
"""libpcap C-level ceiling used by ``compare_libs.py``.

This is a tiny, self-contained Cython extension that reads a capture with
``pcap_open_offline`` + ``pcap_dispatch`` and does the least possible work per
packet (count, or count + touch the six source-MAC bytes). It measures the
floor that any Python packet library sits above: the cost of libpcap handing
frames to a C callback with no Python object created per packet.

It deliberately declares its own ``cdef extern from "<pcap.h>"`` block instead
of importing ``packets.core.pcap`` so it has zero coupling to the package build
and loads whenever the ``bench`` directory is importable.

Build in place (run from the packets checkout root) with:

    python3 bench/setup_dispatch.py build_ext --inplace

Then ``compare_libs.py --libs libpcap`` imports ``scan_count``/``scan_batch``/
``scan_extract`` from here.
"""

DEF ERRBUF_SIZE = 256


cdef extern from "<sys/time.h>" nogil:
    struct timeval:
        long tv_sec
        long tv_usec


cdef extern from "<pcap.h>" nogil:
    ctypedef struct pcap_t

    struct pcap_pkthdr:
        timeval ts
        unsigned int caplen
        unsigned int len

    ctypedef void (*pcap_handler)(unsigned char *,
                                  const pcap_pkthdr *,
                                  const unsigned char *)

    pcap_t *pcap_open_offline(const char *, char *)
    void pcap_close(pcap_t *)
    int pcap_dispatch(pcap_t *, int, pcap_handler, unsigned char *)
    char *pcap_geterr(pcap_t *)


cdef struct scan_state:
    unsigned long count
    unsigned long mac_accum


cdef void _count_cb(unsigned char *user,
                    const pcap_pkthdr *hdr,
                    const unsigned char *pkt) nogil:
    (<scan_state *> user).count += 1


cdef void _extract_cb(unsigned char *user,
                      const pcap_pkthdr *hdr,
                      const unsigned char *pkt) nogil:
    cdef scan_state *st = <scan_state *> user
    st.count += 1
    # Touch the six source-MAC bytes (offset 6..11) so the "extract" variant
    # pays for reading wire bytes, matching pcapdec_rawmac in compare_libs.py.
    if hdr.caplen >= 12:
        st.mac_accum += (pkt[6] + pkt[7] + pkt[8] +
                         pkt[9] + pkt[10] + pkt[11])


cdef bytes _to_bytes(path):
    if isinstance(path, bytes):
        return path
    return path.encode('utf-8')


cdef int _dispatch_all(pcap_t *handle, pcap_handler cb,
                       scan_state *st, int batch) nogil:
    # pcap_dispatch processes up to `batch` packets per call and returns the
    # number processed, 0 at end-of-file for an offline capture, or a negative
    # error/breakloop code. Loop in batch-sized chunks until EOF.
    cdef int rc
    while True:
        rc = pcap_dispatch(handle, batch, cb, <unsigned char *> st)
        if rc < 0:
            return rc
        if rc == 0:
            return 0


cdef scan_state _scan(path, int batch, pcap_handler cb) except *:
    cdef bytes bpath = _to_bytes(path)
    cdef char errbuf[ERRBUF_SIZE]
    cdef scan_state st
    cdef pcap_t *handle
    cdef int rc

    if batch < 1:
        batch = 1
    st.count = 0
    st.mac_accum = 0
    errbuf[0] = 0

    handle = pcap_open_offline(bpath, errbuf)
    if handle == NULL:
        raise RuntimeError('pcap_open_offline(%r) failed: %s'
                           % (path, errbuf.decode('utf-8', 'replace')))
    try:
        with nogil:
            rc = _dispatch_all(handle, cb, &st, batch)
        if rc < 0:
            raise RuntimeError('pcap_dispatch(%r) failed: %s'
                               % (path,
                                  pcap_geterr(handle).decode('utf-8',
                                                             'replace')))
    finally:
        pcap_close(handle)
    return st


def scan_count(path, batch):
    """Count every packet in `path`, dispatching in `batch`-sized chunks."""
    cdef scan_state st = _scan(path, batch, _count_cb)
    return st.count


def scan_batch(path, batch):
    """Count packets via batched dispatch (same work as scan_count).

    Kept as a distinct entry point so compare_libs.py can label the batched
    dispatch pass separately from the plain count pass.
    """
    cdef scan_state st = _scan(path, batch, _count_cb)
    return st.count


def scan_extract(path, batch):
    """Count packets and touch the six source-MAC bytes of each.

    Returns a tuple whose ``[0]`` is the packet count (the value
    compare_libs.py records) followed by the MAC-byte accumulator, kept so the
    read cannot be optimized away.
    """
    cdef scan_state st = _scan(path, batch, _extract_cb)
    return (st.count, st.mac_accum)
