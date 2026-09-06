========================================
Wireshark Field-Name Compatibility Audit
========================================

``pcap_query`` shares a field-identifier *language* with Wireshark: every
field name exposed through a packet class's ``query_info()`` /
``get_field_val()`` is intended to be byte-for-byte identical to the
Wireshark display-filter abbreviation registered by the matching
``epan/dissectors/packet-*.c`` dissector.

This document is the checked-in record of the cross-cutting audit that
brought every exposed field into line with Wireshark. Per the project
decision (Q11), any pre-existing name that did **not** match Wireshark was a
bug and was **hard-renamed with no deprecated alias** -- callers must update
their queries using the mapping below. The companion test
``test/test_wireshark_field_names.py`` asserts that every advertised field
is either a known Wireshark abbreviation or one of the documented
extensions listed at the end, so future protocols cannot drift.

Renamed fields (old ``packets`` name -> Wireshark abbrev)
-------------------------------------------------------

DNS (packet-dns.c)
~~~~~~~~~~~~~~~~~~

::

    dns.ident               -> dns.id
    dns.query_resp          -> dns.flags.response
    dns.op_code             -> dns.flags.opcode
    dns.authoritative       -> dns.flags.authoritative
    dns.truncated           -> dns.flags.truncated
    dns.recursion_requested -> dns.flags.recdesired
    dns.recursion_available -> dns.flags.recavail
    dns.authentic_data      -> dns.flags.authenticated
    dns.check_disabled      -> dns.flags.checkdisable
    dns.resp_code           -> dns.flags.rcode
    dns.query_count         -> dns.count.queries
    dns.answer_count        -> dns.count.answers
    dns.auth_count          -> dns.count.auth_rr
    dns.ad_count            -> dns.count.add_rr

DHCP (packet-dhcp.c)
~~~~~~~~~~~~~~~~~~~~

::

    dhcp.op           -> dhcp.type
    dhcp.htype        -> dhcp.hw.type
    dhcp.hlen         -> dhcp.hw.len
    dhcp.xid          -> dhcp.id
    dhcp.ciaddr       -> dhcp.ip.client
    dhcp.yiaddr       -> dhcp.ip.your
    dhcp.siaddr       -> dhcp.ip.server
    dhcp.giaddr       -> dhcp.ip.relay
    dhcp.message_type -> dhcp.option.dhcp

DHCPv6 (packet-dhcpv6.c)
~~~~~~~~~~~~~~~~~~~~~~~~

::

    dhcp6.msg_type       -> dhcpv6.msgtype
    dhcp6.transaction_id -> dhcpv6.xid
    dhcp6.hop_count      -> dhcpv6.hopcount
    dhcp6.link_address   -> dhcpv6.linkaddr
    dhcp6.peer_address   -> dhcpv6.peeraddr

NetFlow / IPFIX (packet-netflow.c)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    netflow.version           -> cflow.version
    netflow.count             -> cflow.count
    netflow.sys_uptime        -> cflow.sysuptime
    netflow.unix_secs         -> cflow.unix_secs
    netflow.unix_nano_seconds -> cflow.unix_nsecs
    netflow.sequence          -> cflow.sequence
    netflow.source_id         -> cflow.source_id

IGMPv3 group record (packet-igmp.c)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    igmpv3grouprecord.type             -> igmp.record_type
    igmpv3grouprecord.aux_data_len     -> igmp.aux_data_len
    igmpv3grouprecord.num_src          -> igmp.num_src
    igmpv3grouprecord.group_address    -> igmp.maddr
    igmpv3grouprecord.source_addresses -> igmp.saddr
    igmpv3grouprecord.aux_data         -> igmp.aux_data

MPLS (packet-mpls.c)
~~~~~~~~~~~~~~~~~~~~

The previous ``mpls.top.*`` / ``mpls.bottom.*`` split is replaced by
Wireshark's single repeated label field set; each label in the stack is
its own layer (select the Nth with the query engine's layer instance)::

    mpls.top.label,  mpls.bottom.label       -> mpls.label
    mpls.top.tc,     mpls.bottom.tc          -> mpls.exp
    mpls.top.stack_bit, mpls.bottom.stack_bit -> mpls.bottom
    mpls.top.ttl,    mpls.bottom.ttl         -> mpls.ttl

Ethernet 802.1Q VLAN (packet-vlan.c)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    eth.vlan.cfi -> vlan.cfi
    eth.vlan.id  -> vlan.id
    eth.vlan.pri -> vlan.priority

HTTP (packet-http.c)
~~~~~~~~~~~~~~~~~~~~

::

    http.request.target  -> http.request.uri
    http.response.status -> http.response.code
    http.response.reason -> http.response.phrase

ICMPv6 (packet-icmpv6.c)
~~~~~~~~~~~~~~~~~~~~~~~~

::

    icmpv6.nd.rd.destination_address -> icmpv6.rd.na.destination_address
    icmpv6.mld.qrv                   -> icmpv6.mld.flag.qrv
    icmpv6.mld.qqic                  -> icmpv6.mld.qqi
    icmpv6.opt.prefix.prefix         -> icmpv6.opt.prefix

GRE (packet-gre.c)
~~~~~~~~~~~~~~~~~~

::

    gre.flags.k -> gre.flags.key
    gre.flags.s -> gre.flags.sequence_number
    gre.flags.c -> gre.flags.checksum

OSPF (packet-ospf.c)
~~~~~~~~~~~~~~~~~~~~

::

    ospf.lsa.type              -> ospf.lsa
    ospf.lsa.network.attachrtr -> ospf.lsa.network.attchrtr
    ospf.v3.lsa.metric         -> ospf.metric

BGP (packet-bgp.c)
~~~~~~~~~~~~~~~~~~

::

    bgp.open.opt_param_len     -> bgp.open.opt.len
    bgp.route_refresh.reserved -> bgp.route_refresh.subtype

Retained packets-only extensions (no Wireshark equivalent)
---------------------------------------------------------

These carry real data that Wireshark does not expose under a distinct
display-filter name. By project decision they are kept as documented
``packets`` extensions and are whitelisted by the drift test::

    gre.key.vsid             NVGRE Virtual Subnet ID (RFC 7637); Wireshark decodes only the raw 32-bit gre.key
    gre.key.flowid           NVGRE FlowID (RFC 7637); no distinct Wireshark abbrev
    tcp.payload.offset[x:y]  byte-slice accessor into the TCP payload; not a Wireshark field
    udp.payload.offset[x:y]  byte-slice accessor into the UDP payload; not a Wireshark field
    igmp.obj.saddr           list accessor returning all source addresses of a record
    igmp.obj.grecs           list accessor returning the group-record objects
    http.body_length         decoded HTTP body length (Wireshark exposes http.content_length instead)
    eth.vlan.tpid            802.1Q Tag Protocol ID; in Wireshark this is the triggering ethertype, not a vlan.* field

