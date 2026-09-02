NetFlow and IPFIX
=================

``packets.protos.netflow`` provides structured, editable packet models for
NetFlow v1, v5, v7, v9, and IPFIX (v10). Unchanged packets serialize
deterministically, and ``pkt2net({'update': 1})`` applies version-specific
count, length, and sequence updates.

Fixed versions
--------------

``Netflow`` dispatches fixed-format packets to ``NetflowV1Header``,
``NetflowV5Header``, or ``NetflowV7Header`` and the corresponding record
models. Header and record attributes can be read or edited before calling
``pkt2net``.

Templates and generated records
-------------------------------

NetFlow v9 and IPFIX packets expose ``NetflowFlowSet``, ``NetflowTemplate``,
``NetflowOptionsTemplate``, and ``NetflowTemplateField`` objects. Learning a
template creates a cached Python ``NetflowDataRecord`` subclass with a stable,
collision-safe name and an immutable ``NetflowCodecPlan``. The plan performs
prevalidated decoding and writing for subsequent data records.

Generated records expose typed values through ``record.fields``. Known IANA
elements use readable names such as ``sourceIPv4Address``,
``destinationTransportPort``, and ``packetDeltaCount``. The same values can be
looked up with ``record.fields[(pen_or_zero, element_id)]`` so callers do not
depend on generated names. IPv4, IPv6, MAC, unsigned integer, and string types
are decoded where catalogued.

Unknown standard fields and all uncatalogued enterprise fields remain raw
bytes and retain their element ID, length, and Private Enterprise Number. The
catalog contains standards-based IANA definitions only; no vendor-specific
dictionary is bundled.

The top bit of a template field specifier means different things per version.
RFC 7011 section 3.2 makes it the IPFIX Enterprise bit: when set, the low 15
bits are the element ID and a 4 byte Private Enterprise Number follows.
RFC 3954 section 8 gives NetFlow v9 no such bit, so all 16 bits are the field
type and values of 32768 and above are ordinary vendor field types - Cisco ASA
NSEL exports 33000-33002 and 40000 and above. Element IDs in that range are
therefore preserved whole for v9 and looked up as ``record.fields[element_id]``
or ``record.fields[(0, element_id)]``. Before 2.1.2 the IPFIX rule was applied
to v9 as well, which failed such template sets outright.

Sharing decode state
--------------------

v9/IPFIX data sets require a reusable ``NetflowDecodeContext``::

  from packets.protos.netflow import Netflow, NetflowDecodeContext

  context = NetflowDecodeContext()
  template_packet = Netflow.dispatch(template_bytes, context=context,
                                     exporter='192.0.2.10')
  data_packet = Netflow.dispatch(data_bytes, context=context,
                                 exporter='192.0.2.10')

Registry keys include protocol version, normalized exporter transport scope,
observation domain or v9 source ID, and template ID. Replacement and
withdrawal therefore do not leak across independent exporters, versions, or
contexts.

The codec plan and the generated record class built for a template shape are
cached module-wide, keyed on the field signature, so exporters sending the
same template share one of each. That cache is deliberately wider than any one
context and ``context.clear()`` does not touch it, so it is bounded and used in
least recently used order; an evicted signature costs one rebuild the next time
it is seen. ``template_artifact_cache_info()`` reports ``(entries, limit)``,
``set_template_artifact_cache_limit(n)`` changes the limit and evicts down to
it, and ``clear_template_artifact_cache()`` empties it. Before 2.1.2 the cache
was unbounded, so a long lived collector seeing many exporters or template
revisions grew one pinned Python class per distinct template forever.

``PCAPReader`` and ``PCAPSocket`` create a context by default and accept one
through ``decode_context``. ``PcapQuery`` keeps one context for its lifetime,
and nested ``Ethernet``/IP/UDP decoding propagates it automatically. Pass the
same explicit context when separately decoding packets from one stream.

Fallback and lightweight decoding
---------------------------------

Use ``Netflow.dispatch`` when fallback policy matters. A v9/IPFIX datagram
whose required template is still unknown is returned as ``NetflowSimple`` and
round-trips byte-for-byte. Templates present later in the same datagram are
registered before data sets are decoded, and later packets become structured
as soon as the shared context learns their templates.

A datagram containing any flowset this parser cannot read takes the same
fallback, whether that is a set header whose length does not fit the datagram
or a template set whose field specifiers do not parse. Constructing
``Netflow`` directly still returns the partially decoded packet with
``flowset.malformed`` set on the flowsets in question, and it still
round-trips byte-for-byte; only ``dispatch`` applies the policy.

Set ``NetflowDecodeContext(force_simple=True)`` to deliberately bypass template
learning and structured decoding. The ``netflow-player`` command uses this
policy for both replay paths. ``NetflowSimple`` is defined in
``packets.core.inetpkt``, where the core Layer-7 dispatch has a direct
owner/offset decode path for it, and is re-exported from this protocol module
so either import returns the same class.

``NetflowSimple`` names its five header fields after the v1-v8 layout, but the
later versions reuse those bytes, so replay only rewrites the field that really
carries the export time: ``sys_uptime`` for IPFIX (``exportTime``),
``unix_secs`` for v9, and both ``unix_secs`` and ``unix_nano_seconds`` for
v1-v8. The v9 flow sequence and the IPFIX sequence number and observation
domain id are left as captured.

Building packets
----------------

v9 and IPFIX carry records inside a data flowset, which is what supplies the
set ID naming the template they were encoded against, so records go in a
``NetflowFlowSet`` and the flowset goes on the packet. ``Netflow.records`` is
the flattened view of those flowsets that parsing builds; a record listed there
and in no flowset has nowhere to be written and ``pkt2net()`` raises
``ValueError`` rather than silently emitting a header and nothing else. v1, v5
and v7 have no flowsets and take their records from ``Netflow.records``
directly.

Both :py:class:`Netflow` and ``NetflowSimple`` list port 2055 in
``default_ports()``. A caller merging both into one ``l7_ports`` mapping keeps
whichever went in last, silently, and the two are not interchangeable: this
class decodes flowsets and records, ``NetflowSimple`` keeps the datagram opaque
behind its header, which is what replay and pass-through want. Choose per port,
for instance ``{2005: NetflowSimple, 2055: Netflow}``.

RFC 3954 section 5.3 and RFC 7011 section 3.3.1 allow a data set to be padded
to a 4 byte boundary, so up to 3 trailing bytes may not be a record. How long a
record is comes from the template, so a short all zero record is decoded rather
than discarded; before 2.1.2 the decision was made on length alone and a
template of one 2 byte field carrying two zero valued flows lost the second,
leaving ``header.count`` one short of the wire.

Query fields
------------

Structured NetFlow packets support ``netflow.version``, ``netflow.count``,
``netflow.sequence``, ``netflow.source_id``, ``netflow.sys_uptime``, and
``netflow.unix_secs`` through ``PcapQuery``. Fields not present in a particular
version return ``None``.

Performance and capture checks
------------------------------

Run ``test/benchmark_netflow.py`` after building the Cython extensions. It
reports repeated per-operation timings for fixed versions, cold template/class
generation, warm generated decode/write, the retained interpreted baseline,
known and unknown-template datagrams, nested dispatch, and forced lightweight
decoding. ``--number`` and ``--repeat`` control sample size and repetitions.

Run ``test/validate_netflow_pcaps.py`` with one or more PCAP paths to check
stateful decoding and deterministic round trips against real captures.