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

``snaplen`` is a hard cap on the bytes libpcap copies out of each frame, and
the default of 0 means the whole frame. Only libpcap 1.9 and later reads 0
that way; older releases take it literally and hand back an empty capture, so
since 2.1.2 a snaplen of 0 - or any value above ``MAX_SNAPLEN`` - is resolved
to ``MAX_SNAPLEN`` (262144, libpcap's own maximum) before the device is
opened. The default no longer depends on which libpcap the extension is
linked against.

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
any send failed, if no packet in the file matched ``pcap_dst_port``, or if a
packet that did match carried no NetFlow; the detail goes to stderr.

That last case exists because the BPF filter a replay installs constrains only
the UDP destination port, so anything else sent to that port is handed to the
replay too. Since 2.1.2 such a packet is counted and skipped rather than
ending the replay: a datagram too short to hold a NetFlow header used to fail
the decode outright, and anything longer reached a layer without the header
fields the rewrite assigns. A ``decode_context`` is also checked up front and
must have ``force_simple`` set, because replay rewrites the NetFlow header in
place and re-sends the original bytes. ``netflow-player`` checks its
``--device`` against the devices libpcap reports and answers with a usage error
naming the real ones; before 2.1.2 only an empty value was caught, so a typo
surfaced from the middle of the replay.

``pcap_info()`` scans the whole file with the interpreter lock released; the
callback that accumulates the counts is pure C. A deliberate
``pcap_breakloop()`` during the scan ends it cleanly instead of being reported
as a read error.

All four classes release their libpcap handles when they are collected, so a
forgotten ``close()`` is no longer a leak. Calling ``close()`` yourself is
still the right thing to do, because it is the only way to know when the
capture file is flushed and complete. Since 2.1.2 the methods that reach
libpcap through the handle - ``set_snaplen``, ``set_promisc``,
``set_timeout``, ``getnonblock``, ``setnonblock``, ``sendpacket``,
``open_pcap_dumper`` and ``add_bpf_filter`` - raise ``ValueError`` once the
object has been closed. libpcap does not check its handle argument, so calling
them on a closed object previously crashed the process.

``set_snaplen``, ``set_promisc`` and ``set_timeout`` cannot change a capture
that is already running. libpcap accepts those three only between
``pcap_create()`` and ``pcap_activate()``, and ``PCAPSocket`` opens its handle
with ``pcap_open_live()``, which does all of it in one step. Since 2.1.2 they
raise ``ValueError`` naming the constructor keyword to use instead; before that
libpcap answered ``PCAP_ERROR_ACTIVATED``, changed nothing, and the code handed
that back as a return value a caller could easily drop. ``getnonblock`` and
``setnonblock`` are not pre-activation settings and work as before.

``open_pcap_dumper`` raises ``IOError`` when the dump file cannot be opened,
and ``PCAPWriter`` does the same for its ``filename``. It used to return
``ERROR``, and since dumping quietly does nothing when there is no dumper, a
caller who did not inspect that ran to completion and wrote an empty file.

``list_devices()`` returns the capture device names libpcap reports, as ``str``.
An empty list means libpcap would not say - an unprivileged process is usually
not allowed to look - rather than that the host has no interfaces.
