packets.query.pcap_query API
============================

pcap_query provides a class to enable quick queryies over Ethernet packets in
a PCAP file. The query is extensible with additional
packets.core.inetpkt.PKT based packet classes.

In order to be compatible with PcapQuery a PKT based class must be a layer 7
protocol and implement the query_info() and default_ports() classmethod
methods and also implement the get_field_val(field_name) instance method.
Field names are ``str`` and are registered and looked up in full; there is no
limit on their length. Adding support for PKT based classes at other levels
would require submitting changes to Ethernet or IP classes. And that is
something, for the record, that we encourage. Please see the packets tutorial
for info.

A PcapQuery reads from exactly one source, named by either ``filename`` or
``devicename``. Results can be taken all at once with ``query()`` or one row at
a time by iterating the object.

The two sources end differently, and deliberately so. A file query stops at the
end of the file. A live query does not stop because the wire went quiet: a read
that times out without a packet is not the end of the capture, so both
``query()`` and the iterator wait for the next one. A live query is ended by
``endtime``, by ``num_packets``, or by setting the ``stop_event`` passed to the
constructor -- which is the only one of the three available to another thread.

.. currentmodule:: packets.query.pcap_query

:py:class:`PcapQuery` Class
----------------------------

.. autoclass:: PcapQuery
    :members:

    .. automethod:: __init__(filename='', devicename='', wshark_fields=[], pkt_classes=[], l7_ports={}, bpf_filter='', snaplen=0, promisc=1, to_ms=50, stop_event=None)
    .. automethod:: query(starttime=0.0, endtime=0.0, num_packets=0, dataframe=0)
    .. automethod:: show_fields
    .. automethod:: fields_supported(field_names)