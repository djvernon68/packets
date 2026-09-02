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

Set ``NetflowDecodeContext(force_simple=True)`` to deliberately bypass template
learning and structured decoding. The ``netflow-player`` command uses this
policy for both replay paths. ``NetflowSimple`` remains import-compatible from
``packets.core.inetpkt`` as well as its protocol module.

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