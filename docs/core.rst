packets.core.inetpkt API
========================

The inetpkt module defines the basic set of packets packet classes

.. currentmodule:: packets.core.inetpkt


:py:class:`PKT` Class
---------------------
PKT serves as the base class for all packet classes. In addition
to the functions detailed below it also provides stub implementations of two
class methods and an instance function required to support PcapQuery:

- PKT.query_info():" Returns a two element tuple. The first element is the PKT
  protocol type ID. The second element is a tuple of field names supported by
  this PKT type's get_field_val(field) function.

- PKT.default_ports(): Returns a list of layer 4 ports and is used by PcapQuery
  to build a l7_ports argument when decoding packets. Returns an empty list if
  not implemented by a PKT subclass

- Instance.get_field_val(field): Returns this packet's value for the field name
  passed in. Returned as an object. PKT class instances return None.

In addition PKT supports pkt2net(kwargs). Each PKT class subclass must
implement this method. It provides a way for PKT classes to write themselves in
network order either to sockets or PCAP files.

Note the calling convention: pkt2net takes one positional argument, a dict,
not Python keyword arguments. Its keys are ``str``, and a layer passes the same
dict down to the layers below it, so ``pkt.pkt2net({'csum': 1, 'update': 1})``
recalculates checksums and lengths for the whole stack. It returns ``bytes``.
The option names documented per class below are the keys of that dict.

Query field names are also ``str``, both in the tuple returned by query_info()
and in the argument to get_field_val(). They are registered and matched in
full, so there is no limit on the length of a field name.

.. autoclass:: PKT
   :members: __init__ get_layer get_layer_by_type from_buffer

   .. automethod:: __init__(*args, dict l7_ports={}, **kwargs)
   .. automethod:: get_layer(name, instance=1, found=0)
   .. automethod:: get_layer_by_type(pq_type, instance=1, found=0)
   .. automethod:: from_buffer(args, kwargs)

from_buffer(args, kwargs) takes the subclass's own ``args`` tuple and
``kwargs`` dict and returns a two element tuple: a flag saying whether this
instance is being built from packet data rather than from keyword arguments,
and that data as an ``array('B')``. A subclass may be given either ``bytes`` or
an ``array('B')``; from_buffer normalizes both to the array. Packet instances
do not retain the buffer after ``__init__`` returns.

PKT also provides a read/write ``trailer`` attribute, holding the bytes that
followed a layer's own declared length.

A layer is handed whatever the layer above it had left over, which is not the
same as the length the layer's own header declares. Every Ethernet NIC pads a
frame out to a 60 byte minimum, and captures can carry a trailer, so for short
packets the leftover bytes routinely run past the end of the real datagram.
:py:class:`IP`, :py:class:`IP6` and :py:class:`UDP` therefore parse only as far
as ``total_len``, ``payload_len`` and ``ulen`` say, and keep the remaining
bytes in ``trailer`` rather than reporting them as payload.

Those bytes are written back out after the payload, so a padded frame still
serializes to exactly what was parsed, and they are excluded from the lengths
and checksums recomputed by ``pkt2net({'update': 1, 'csum': 1})``.
``trailer`` is empty for a layer with no length field, for a layer whose length
field accounted for every byte, and for any packet built from keyword
arguments.

A declared length *longer* than the bytes present is not an error: a capture
cut short by snaplen and the header quoted inside an ICMP error both look that
way, and both stay readable. A declared length too short to cover the layer's
own header raises ``ValueError``.

NOTE: ``from_buffer()`` copies an ``array('B')`` a caller passes in rather than
adopting it, so mutating that array afterwards cannot change an already parsed
packet. The owner and offset constructors already snapshot their input; this
is the same guarantee for the classes still parsing the older way.


:py:class:`Ethernet` Class
--------------------------
.. autoclass:: Ethernet
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

Ethernet PcapQuery supported fields:
   - eth.type: returns Ethernet.type
   - eth.src: returns Ethernet.src_mac
   - eth.dst: returns Ethernet.dst_mac

NOTE: ``l7_ports`` is forwarded to every layer below, MPLS included. Until
2.1.2 the MPLS branch dropped it, so MPLS encapsulated TCP and UDP arriving in
a frame never reached a registered layer 7 class while the same labels parsed
through :py:class:`MPLS` directly did.


:py:class:`IP` Class
--------------------
RFC 791 Internet Protocol with flag bit zero implemented as x or 'evil' bit.::

   +0                   1                   2                   3  +
   +0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1+
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

.. autoclass:: IP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(csum=0, update=0, ipv4_pheader=None)

IP PcapQuery supported fields:
   - ip.version: returns IP.version
   - ip.hdr_len: returns IP.iphl
   - ip.tos: returns IP.tos
   - ip.len: returns IP.total_len
   - ip.id: returns IP.ident
   - ip.flags: returns IP.flags
   - ip.flags.df: returns IP.flag_d
   - ip.flags.mf: returns IP.flag_m
   - ip.frag_offset: returns IP.frag_offset
   - ip.ttl: returns IP.ttl
   - ip.proto: returns IP.proto
   - ip.src: returns IP.src
   - ip.dst: returns IP.dst
   - ip.checksum: returns IP.checksum

NOTE: ``total_len`` bounds the parse. Bytes behind it - Ethernet padding, or a
capture trailer - are kept in ``PKT.trailer`` rather than decoded as payload.
See the :py:class:`PKT` section above.

NOTE: ``iphl`` is where the layer 4 header begins, so a value below the 5 word
minimum header raises ``ValueError`` rather than starting the layer 4 parse
inside the IPv4 header. So does an ``iphl`` claiming option bytes the capture
does not carry.

NOTE: ``pkt2net({'update': 1})`` derives ``iphl`` from the length of
``options`` and takes ``total_len`` from the bytes actually written, so the two
always describe the header that went out. Serializing *without* ``update``
emits the values as set, which is how a deliberately malformed header is
produced.


:py:class:`IP6` Class
---------------------
RFC 8200 Internet Protocol version 6. The 40 byte fixed header::

   +0                   1                   2                   3  +
   +0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1+
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |               Flow Label              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                        Source Address                         |
   |                          (128 bits)                           |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Destination Address                       |
   |                          (128 bits)                           |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP6 is reachable everywhere IP is: directly under Ethernet, behind an 802.1Q
VLAN tag, and at the bottom of an MPLS label stack.

.. autoclass:: IP6
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(csum=0, update=0)

IP6 PcapQuery supported fields:
   - ipv6.version: returns IP6.version
   - ipv6.tclass: returns IP6.tclass
   - ipv6.flow: returns IP6.flow
   - ipv6.plen: returns IP6.plen
   - ipv6.nxt: returns IP6.nxt
   - ipv6.hlim: returns IP6.hlim
   - ipv6.src: returns IP6.src
   - ipv6.dst: returns IP6.dst

NOTE: ``payload_len`` bounds the parse, and is applied before the extension
header chain is walked so trailing frame bytes cannot be mistaken for another
extension header. Bytes behind it are kept in ``PKT.trailer``. A
``payload_len`` of zero means jumbogram, whose real length lives in a hop by
hop option, and is treated as unstated.

NOTE: the readonly ``ext_hdrs_truncated`` attribute is True when the extension
header chain ran past the bytes present. The real upper layer protocol is then
unknowable and the remainder is kept as an opaque :py:class:`NullPkt`, which is
also what an upper layer protocol this library does not decode produces - the
attribute is what tells the two apart.


:py:class:`ARP` Class
---------------------
Implements RFC 826 Address Resolution Protocol. See schematic to follow::

   +0                   1                   2                   3  +
   +0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1+
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Hardware Type        |         Protocol Type         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Hardware Len |    Proto Len  |           Operation           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Sender Hardware Addr (Hardware Len Bytes)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Sender Protocol Addr (Proto Len Bytes)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Target Hardware Addr (Hardware Len Bytes)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Target Protocol Addr (Proto Len Bytes)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

.. autoclass:: ARP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

ARP PcapQuery supported fields:
   - arp.hw.type: returns ARP.hardware_type
   - arp.proto.type: returns ARP.proto_type
   - arp.hw.size: returns ARP.hardware_len
   - arp.proto.size: returns ARP.proto_len
   - arp.opcode: returns ARP.operation
   - arp.src.hw_mac: returns ARP.sender_hw_addr
   - arp.src.proto_ipv4: returns ARP.sender_proto_addr
   - arp.dst.hw_mac: returns ARP.target_hw_addr
   - arp.dst.proto_ipv4: returns ARP.target_proto_addr


:py:class:`UDP` Class
---------------------
Implements RFC 768 User Datagram Protocol. See schematic to follow::

   +0      7 8     15 16    23 24    31+
   +--------+--------+--------+--------+
   |     Source      |   Destination   |
   |      Port       |      Port       |
   +--------+--------+--------+--------+
   |                 |                 |
   |     Length      |    Checksum     |
   +--------+--------+--------+--------+
   |
   |          data octets ...
   +---------------- ...

.. autoclass:: UDP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

UDP PcapQuery supported fields:
   - udp.srcport: returns UDP.sport
   - udp.dstport: returns UDP.dport
   - udp.length: returns UDP.ulen
   - udp.checksum: returns UDP.checksum
   - udp.payload: returns UDP.payload as bytes
   - udp.payload.offset[x:y]: returns UDP.payload bytes x to y as bytes

NOTE: ``ulen`` bounds the parse, so Ethernet padding behind a short datagram is
kept in ``PKT.trailer`` instead of being reported as payload and handed to a
registered layer 7 class. See the :py:class:`PKT` section above.

NOTE: RFC 768 reserves a checksum of zero to mean 'no checksum sent', so when
the computed checksum comes out zero ``0xffff`` is written instead. The two
validate identically. Over IPv6 the checksum is not optional at all (RFC 8200
section 8.1), so zero there would be an invalid datagram. A checksum of zero
is still written when no checksum was requested.


:py:class:`TCP` Class
---------------------
Implements RFC 793 Transmission Control Protocol with some additions and
limited options support. See schematic to follow::

   +0                   1                   2                   3  +
   +0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1+
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |     |N|C|E|U|A|P|R|S|F|                               |
   | Offset| Res |S|W|C|R|C|S|S|Y|I|            Window             |
   |       |     | |R|E|G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

.. autoclass:: TCP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

TCP PcapQuery supported fields:
   - tcp.srcport: returns TCP.sport
   - tcp.dstcport: returns TCP.dport
   - tcp.seq: returns TCP.sequence
   - tcp.ack: returns TCP.acknowledgment
   - tcp.hdr_len: returns TCP.data_offset
   - tcp.len: returns TCP.ws_len
   - tcp.flags: returns TCP.flags
   - tcp.flags.urg: returns TCP.flag_urg
   - tcp.flags.ack: returns TCP.flag_ack
   - tcp.flags.push: returns TCP.flag_psh
   - tcp.flags.reset: returns TCP.flag_rst
   - tcp.flags.syn: returns TCP.flag_syn
   - tcp.flags.fin: returns TCP.flag_fin
   - tcp.window_size_va: returns TCP.window
   - tcp.checksum: returns TCP.checksum
   - tcp.urgent_pointer: returns TCP.urg_ptr
   - tcp.payload: returns TCP.payload as bytes
   - tcp.payload.offset[x:y: returns TCP.payload bytes x to y as bytes

NOTE: parsing fewer than 20 bytes raises ``ValueError``, with one exception:
exactly 8 bytes is the partial header an ICMP error quotes, and only sport,
dport and sequence are read from it.

NOTE: ``data_offset`` is where the payload begins, so a value below the 5 word
minimum header, or one pointing past the captured bytes, raises ``ValueError``
rather than being clamped.


:py:class:`ICMP` Class
----------------------
Implements RFC 792 Internet Control Message Protocol. Which fields carry
meaning depends on the message type.

.. autoclass:: ICMP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

ICMP PcapQuery supported fields:
   - icmp.type
   - icmp.code
   - icmp.checksum
   - icmp.ident
   - icmp.seq
   - icmp.mtu
   - icmp.pointer
   - icmp.redir_gw
   - icmp.originate_timestamp
   - icmp.receive_timestamp
   - icmp.transmit_timestamp


:py:class:`ICMP6` Class
-----------------------
Implements RFC 4443 ICMPv6, with the Neighbor Discovery messages of RFC 4861
and the Multicast Listener Discovery messages of RFC 2710 and RFC 3810 parsed
into named fields rather than kept as an opaque body.

Which fields are populated depends on the message type:

   - types 1-4 (Destination Unreachable, Packet Too Big, Time Exceeded,
     Parameter Problem) carry the quoted packet, parsed and reachable as
     ``hdr_pkt``. The quoted packet is never rewritten when the outer packet
     is serialized with checksum or length updates.
   - types 128 and 129 (Echo Request and Reply) carry identifier and
     sequence number.
   - types 130-132 and 143 (MLD Query, Report, Done, and MLDv2 Report) carry
     the MLD fields; an MLDv2 Report carries a list of
     :py:class:`MLDv2AddressRecord <MLDv2AddressRecord>`.
   - types 133-137 (Router Solicitation and Advertisement, Neighbor
     Solicitation and Advertisement, Redirect) carry the Neighbor Discovery
     fields plus a list of :py:class:`ICMP6Opt <ICMP6Opt>` options.

.. autoclass:: ICMP6
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

ICMP6 PcapQuery supported fields:
   - icmpv6.type
   - icmpv6.code
   - icmpv6.checksum
   - icmpv6.echo.identifier
   - icmpv6.echo.sequence_number
   - icmpv6.mtu
   - icmpv6.pointer
   - icmpv6.nd.ra.cur_hop_limit
   - icmpv6.nd.ra.flag.m
   - icmpv6.nd.ra.flag.o
   - icmpv6.nd.ra.router_lifetime
   - icmpv6.nd.ra.reachable_time
   - icmpv6.nd.ra.retrans_timer
   - icmpv6.nd.ns.target_address
   - icmpv6.nd.na.target_address
   - icmpv6.nd.na.flag.r
   - icmpv6.nd.na.flag.s
   - icmpv6.nd.na.flag.o
   - icmpv6.nd.rd.target_address
   - icmpv6.nd.rd.destination_address
   - icmpv6.mld.maximum_response_delay
   - icmpv6.mld.multicast_address
   - icmpv6.mld.flag.s
   - icmpv6.mld.qrv
   - icmpv6.mld.qqic
   - icmpv6.mld.nb_sources
   - icmpv6.mld.source_address
   - icmpv6.mldr.nb_mcast_records


:py:class:`ICMP6Opt` Class
--------------------------
A single Neighbor Discovery option, in the type/length/value form of RFC 4861
section 4.6. The option value is kept verbatim, so an option this library does
not interpret still round trips byte for byte. Accessors are provided for the
link layer address, MTU and Prefix Information options.

.. autoclass:: ICMP6Opt
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

ICMP6Opt PcapQuery supported fields:
   - icmpv6.opt.type
   - icmpv6.opt.length
   - icmpv6.opt.linkaddr
   - icmpv6.opt.mtu
   - icmpv6.opt.prefix.length
   - icmpv6.opt.prefix.flag.l
   - icmpv6.opt.prefix.flag.a
   - icmpv6.opt.prefix.valid_lifetime
   - icmpv6.opt.prefix.preferred_lifetime
   - icmpv6.opt.prefix.prefix


:py:class:`MLDv2AddressRecord` Class
------------------------------------
A single Multicast Address Record from an MLDv2 Report, RFC 3810 section 5.2.
This is the IPv6 counterpart of :py:class:`IGMPGroupRecord <IGMPGroupRecord>`.

NOTE: per RFC 3810 section 5.2.10 this class counts Aux Data Len in 32 bit
words, the same as :py:class:`IGMPGroupRecord <IGMPGroupRecord>`.

.. autoclass:: MLDv2AddressRecord
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

MLDv2AddressRecord PcapQuery supported fields:
   - icmpv6.mldr.mar.record_type
   - icmpv6.mldr.mar.aux_data_len
   - icmpv6.mldr.mar.nb_sources
   - icmpv6.mldr.mar.multicast_address
   - icmpv6.mldr.mar.source_address
   - icmpv6.mldr.mar.auxiliary_data


:py:class:`IGMP` Class
----------------------
Implements the Internet Group Management Protocol, versions 1 through 3.

.. autoclass:: IGMP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

IGMP PcapQuery supported fields:
   - igmp.version
   - igmp.type
   - igmp.max_resp
   - igmp.checksum
   - igmp.maddr
   - igmp.saddr
   - igmp.s
   - igmp.qrv
   - igmp.num_src
   - igmp.num_grp_recs
   - igmp.obj.saddr
   - igmp.obj.grecs


:py:class:`IGMPGroupRecord` Class
---------------------------------
A single Group Record from an IGMPv3 Membership Report.

NOTE: per RFC 3376 section 4.2.6 ``aux_data_len`` counts the auxiliary data in
32 bit words, not bytes, the same as
:py:class:`MLDv2AddressRecord <MLDv2AddressRecord>`. Four bytes of
``aux_data`` means ``aux_data_len`` of 1. Before 2.1.2 this class read the
field as a byte count, which truncated ``aux_data`` and, because IGMP walks
its record list by adding ``byte_len`` to a running offset, started the
following record inside the aux data of the one before it. A record claiming
more auxiliary data than the datagram contains now raises ``ValueError``
instead of returning the bytes that followed the datagram in the frame.

.. autoclass:: IGMPGroupRecord
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

IGMPGroupRecord PcapQuery supported fields:
   - igmpv3grouprecord.type
   - igmpv3grouprecord.aux_data_len
   - igmpv3grouprecord.num_src
   - igmpv3grouprecord.group_address
   - igmpv3grouprecord.source_addresses
   - igmpv3grouprecord.aux_data


:py:class:`MPLS` Class
----------------------
.. autoclass:: MPLS
   :members: __init__ query_info default_ports get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: default_ports
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

MPLS PcapQuery supported fields:
   - mpls.top.label: returns first MPLS.label where MPLS.s is 0
   - mpls.top.tc: returns first MPLS.tc where MPLS.s is 0
   - mpls.top.stack_bit: returns first MPLS.s where MPLS.s is 0
   - mpls.top.ttl: returns first MPLS.ttl where MPLS.s is 0
   - mpls.bottom.label: returns MPLS.label where MPLS.s is 1
   - mpls.bottom.tc: returns MPLS.tc where MPLS.s is 1
   - mpls.bottom.stack_bit: returns MPLS.s where MPLS.s is 1
   - mpls.bottom.ttl: returns MPLS.ttl where MPLS.s is 1

NOTE: There should only ever be a single MPLS layer in a packet with the s bit
set to 1. There can be a number with bottom of stack bit set to 0

NOTE: RFC 3031 does not bound the label stack, so the parser does. At most
``IP_CONST.MPLS_MAX_STACK_DEPTH`` labels become :py:class:`MPLS` layers; a
longer stack keeps the remaining labels as an opaque :py:class:`NullPkt`
payload, which still serializes back to the original bytes.



:py:class:`NullPkt` Class
-------------------------
.. autoclass:: NullPkt
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, data=b'')
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)


:py:class:`Ip4Ph` Class
-----------------------
.. autoclass:: Ip4Ph
   :members:

   .. automethod:: __init__(src, dst, reserved, proto, payload_len)


:py:class:`Ip6Ph` Class
-----------------------
The IPv6 pseudo header of RFC 8200, used when checksumming a layer 4 payload
carried over IP6.

.. autoclass:: Ip6Ph
   :members:


:py:class:`NetflowSimple` Class
-------------------------------
.. autoclass:: NetflowSimple
   :members: __init__ query_info default_ports get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: default_ports
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

NetflowSimple PcapQuery supported fields:
   - netflow.version: returns NetflowSimple.version
   - netflow.count: returns NetflowSimple.count
   - netflow.sys_uptime: returns NetflowSimple.sys_uptime
   - netflow.unix_secs: returns NetflowSimple.unix_secs
   - netflow.unix_nano_seconds: returns NetflowSimple.unix_nano_seconds