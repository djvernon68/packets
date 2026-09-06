"""Cross-cutting Wireshark field-name compatibility guard.

``pcap_query`` shares a field-identifier *language* with Wireshark: every field
name a packet class advertises through ``query_info()`` is meant to be
byte-for-byte identical to the Wireshark display-filter abbreviation registered
by the matching ``epan/dissectors/packet-*.c`` dissector. The one-time audit
that brought every field into line is recorded in
``docs/wireshark_field_audit.rst``; this test keeps it from drifting.

The authoritative, checked-in inventory lives in
``test/wireshark_field_names.json`` with two disjoint sets:

* ``wireshark``  -- audited byte-exact Wireshark abbreviations.
* ``extensions`` -- the small, documented set of ``packets``-only fields that
  carry real data Wireshark has no distinct abbreviation for (e.g. the NVGRE
  ``gre.key.vsid`` / ``gre.key.flowid`` break-outs and the ``*.payload``
  byte-slice accessors).

The tests assert that the *live* set of advertised fields (collected by
introspecting every ``PKT`` subclass) is exactly this inventory, that the two
sets stay disjoint, and that none of the pre-audit legacy names ever come back.
A developer adding a new protocol therefore has to add its fields to the JSON
(and, if any are non-Wireshark, to the documented extension list), which forces
the audit to be repeated for the new names.
"""

import json
import os
import unittest

# Importing these modules registers every queryable class as a PKT subclass so
# that PKT.__subclasses__() below sees the whole protocol set.
from packets.core.inetpkt import PKT
import packets.core.inetpkt          # noqa: F401  (core protocols)
import packets.protos.dns            # noqa: F401
import packets.protos.dhcp           # noqa: F401
import packets.protos.http           # noqa: F401
import packets.protos.netflow        # noqa: F401


_HERE = os.path.dirname(os.path.abspath(__file__))
_INVENTORY = os.path.join(_HERE, 'wireshark_field_names.json')


# The exact set of documented packets-only extensions. Kept in lock-step with
# docs/wireshark_field_audit.rst and the JSON inventory; changing it must be a
# conscious, reviewed act.
DOCUMENTED_EXTENSIONS = frozenset({
    'gre.key.vsid',
    'gre.key.flowid',
    'tcp.payload.offset[x:y]',
    'udp.payload.offset[x:y]',
    'igmp.obj.saddr',
    'igmp.obj.grecs',
    'http.body_length',
    'eth.vlan.tpid',
})


# Pre-audit names that were hard-renamed to their Wireshark abbreviation (no
# alias). None of these may ever be advertised again. See the mapping in
# docs/wireshark_field_audit.rst.
LEGACY_RENAMED_NAMES = frozenset({
    # DNS
    'dns.ident', 'dns.query_resp', 'dns.op_code', 'dns.authoritative',
    'dns.truncated', 'dns.recursion_requested', 'dns.recursion_available',
    'dns.authentic_data', 'dns.check_disabled', 'dns.resp_code',
    'dns.query_count', 'dns.answer_count', 'dns.auth_count', 'dns.ad_count',
    # DHCP
    'dhcp.op', 'dhcp.htype', 'dhcp.hlen', 'dhcp.xid', 'dhcp.ciaddr',
    'dhcp.yiaddr', 'dhcp.siaddr', 'dhcp.giaddr', 'dhcp.message_type',
    # DHCPv6
    'dhcp6.msg_type', 'dhcp6.transaction_id', 'dhcp6.hop_count',
    'dhcp6.link_address', 'dhcp6.peer_address',
    # NetFlow / IPFIX
    'netflow.version', 'netflow.count', 'netflow.sys_uptime',
    'netflow.unix_secs', 'netflow.unix_nano_seconds', 'netflow.sequence',
    'netflow.source_id',
    # IGMPv3 group record
    'igmpv3grouprecord.type', 'igmpv3grouprecord.aux_data_len',
    'igmpv3grouprecord.num_src', 'igmpv3grouprecord.group_address',
    'igmpv3grouprecord.source_addresses', 'igmpv3grouprecord.aux_data',
    # MPLS
    'mpls.top.label', 'mpls.top.tc', 'mpls.top.stack_bit', 'mpls.top.ttl',
    'mpls.bottom.label', 'mpls.bottom.tc', 'mpls.bottom.stack_bit',
    'mpls.bottom.ttl',
    # 802.1Q VLAN
    'eth.vlan.cfi', 'eth.vlan.id', 'eth.vlan.pri',
    # HTTP
    'http.request.target', 'http.response.status', 'http.response.reason',
    # ICMPv6
    'icmpv6.nd.rd.destination_address', 'icmpv6.mld.qrv', 'icmpv6.mld.qqic',
    'icmpv6.opt.prefix.prefix',
    # GRE
    'gre.flags.k', 'gre.flags.s', 'gre.flags.c',
    # OSPF
    'ospf.lsa.type', 'ospf.lsa.network.attachrtr', 'ospf.v3.lsa.metric',
    # BGP
    'bgp.open.opt_param_len', 'bgp.route_refresh.reserved',
})


def _all_pkt_subclasses():
    seen = set()
    stack = [PKT]
    while stack:
        cls = stack.pop()
        for sub in cls.__subclasses__():
            if sub not in seen:
                seen.add(sub)
                stack.append(sub)
    return seen


def _live_advertised_fields():
    """Return {field_name: [class_name, ...]} for every advertised field.

    Only real library classes are inventoried; test-defined mock subclasses
    (e.g. the query-engine's ``_DynamicQueryProtocol`` fixture) live outside the
    ``packets`` package and are skipped.
    """
    fields = {}
    for cls in _all_pkt_subclasses():
        if not (getattr(cls, '__module__', '') or '').startswith('packets'):
            continue
        try:
            info = cls.query_info()
        except Exception:
            continue
        if not info or len(info) < 2 or not info[1]:
            continue
        for name in info[1]:
            fields.setdefault(name, []).append(cls.__name__)
    return fields


class WiresharkFieldNameAuditTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(_INVENTORY) as fh:
            data = json.load(fh)
        cls.wireshark = frozenset(data['wireshark'])
        cls.extensions = frozenset(data['extensions'])
        cls.live = _live_advertised_fields()
        cls.live_names = frozenset(cls.live)

    def test_inventory_sets_are_disjoint(self):
        overlap = self.wireshark & self.extensions
        self.assertEqual(
            overlap, frozenset(),
            'Field(s) listed as both Wireshark abbrev and extension: %s'
            % sorted(overlap))

    def test_extensions_match_documented_set(self):
        self.assertEqual(
            self.extensions, DOCUMENTED_EXTENSIONS,
            'test/wireshark_field_names.json extensions must match the set '
            'documented in docs/wireshark_field_audit.rst. Diff: only in '
            'JSON=%s only in doc=%s'
            % (sorted(self.extensions - DOCUMENTED_EXTENSIONS),
               sorted(DOCUMENTED_EXTENSIONS - self.extensions)))

    def test_every_advertised_field_is_audited(self):
        approved = self.wireshark | self.extensions
        unaudited = sorted(self.live_names - approved)
        detail = ['%s (from %s)' % (f, ','.join(sorted(set(self.live[f]))))
                  for f in unaudited]
        self.assertEqual(
            unaudited, [],
            'These advertised fields are neither a known Wireshark abbrev nor '
            'a documented extension. Audit them against the matching '
            'epan/dissectors/packet-*.c, then add them to '
            'test/wireshark_field_names.json (and docs/wireshark_field_audit'
            '.rst if non-Wireshark):\n  ' + '\n  '.join(detail))

    def test_inventory_has_no_stale_entries(self):
        approved = self.wireshark | self.extensions
        stale = sorted(approved - self.live_names)
        self.assertEqual(
            stale, [],
            'test/wireshark_field_names.json lists field(s) no class advertises '
            'anymore -- remove them: %s' % stale)

    def test_no_legacy_renamed_names_return(self):
        regressed = sorted(self.live_names & LEGACY_RENAMED_NAMES)
        detail = ['%s (from %s)' % (f, ','.join(sorted(set(self.live[f]))))
                  for f in regressed]
        self.assertEqual(
            regressed, [],
            'Pre-audit field name(s) reappeared -- these were hard-renamed to '
            'their Wireshark abbrev with no alias:\n  ' + '\n  '.join(detail))


if __name__ == '__main__':
    unittest.main()
