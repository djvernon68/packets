packets.core.pcap API
=====================

The pcap module wraps libpcap. It provides a live capture socket, a capture
file reader, and a capture file writer. Because libpcap does the decoding of
the file format, every format libpcap reads, including PCAPNG, is readable
here. Writing is always libpcap PCAP format with an Ethernet link layer.

All three classes take their arguments as keywords, and all three open their
own device or file. None of them accept an already open Python file object.

.. currentmodule:: packets.core.pcap

:py:class:`PCAPSocket` Class
----------------------------

A live capture socket. Iterating it yields a three element tuple of the packet
timestamp as a double, the libpcap ``pcap_pkthdr`` for the packet, and the
packet data as ``bytes``. When the read times out without a packet arriving the
tuple is ``(0, None, None)`` rather than an exception, so a caller can tell a
quiet interval apart from the end of a capture. A libpcap read error raises
``IOError`` carrying the message from ``pcap_geterr``; ``StopIteration`` means
the capture is over, and nothing else.

.. autoclass:: PCAPSocket
    :members:

    .. automethod:: __init__(devicename='', snaplen=0, promisc=1, to_ms=100)

:py:class:`PCAPReader` Class
----------------------------

A capture file reader. Iterating it yields the same three element tuple as
PCAPSocket. At the end of the file it closes itself and raises
``StopIteration``. A libpcap read error is reported separately, as an
``IOError``: a truncated or corrupt capture is not the same thing as a capture
that ended.

.. autoclass:: PCAPReader
    :members:

    .. automethod:: __init__(filename='')

:py:class:`PCAPWriter` Class
----------------------------

A capture file writer. It opens a dead Ethernet ``pcap_t`` and a dumper on the
named file. Packets are written with ``dump_hdr_pkt(hdr, data)``, which
preserves the timestamps of a header obtained from a reader or socket, or with
``dump_pkt(data, tv_sec, tv_usec)``, which generates a header for you.

.. autoclass:: PCAPWriter
    :members:

    .. automethod:: __init__(filename='', snaplen=0)

Module functions
----------------

.. autofunction:: pcap_info(filename)
.. autofunction:: get_pkts_header(ts, data)
.. autofunction:: ip2int(addr)
.. autofunction:: int2ip(addr)
.. autofunction:: netflow_replay_raw_sock
.. autofunction:: netflow_replay_system_sock

The two ``netflow_replay_*`` functions back the ``netflow-player`` console
script. Both are IPv4 only. Both return 0 when every packet was sent, and 1 if
any send failed or if no packet in the file matched ``pcap_dst_port``; the
detail goes to stderr.

All four classes release their libpcap handles when they are collected, so a
forgotten ``close()`` is no longer a leak. Calling ``close()`` yourself is
still the right thing to do, because it is the only way to know when the
capture file is flushed and complete.
