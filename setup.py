# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The C extensions of packets.

Everything else - name, version, dependencies, entry points, package data -
is in pyproject.toml (PEP 621). setuptools 69, the AlmaLinux 10.2 version,
cannot declare extension modules there.

The extensions are built through cythonize() so that compiler_directives
are applied. Until 2.1.2 they were passed as Extension(cython_directives=),
a keyword distutils does not know and dropped with "Unknown Extension
options", so no directive was ever applied that way.
"""
from Cython.Build import cythonize
from setuptools import Extension, setup

#: Cython directives for every module. language_level 3 is also each file's
#: own header; stating it here keeps a file that lost its header from being
#: built as Python 2.
DIRECTIVES = {
    'language_level': 3,
}

EXTENSIONS = [
    # inetpkt.pxd carries the bodies of the shared readers (rd_u16, rd_u32,
    # rd_bytes, _have_range, _fmt_ipv4_buf, the w_* writers) so every module
    # below inlines the same code rather than its own copy. That makes each of
    # them stale the moment the .pxd changes, and distutils only tracks the
    # .pyx, so editing the .pxd used to leave already built objects in place
    # and produce a module built against the old declarations. 'depends'
    # is what makes the timestamp check see it.
    Extension("packets.core.pcap",
              sources=["packets/core/pcap.pyx"],
              libraries=["pcap"]),
    Extension("packets.core.inetpkt",
              sources=["packets/core/inetpkt.pyx"],
              depends=["packets/core/inetpkt.pxd"]),
    # Python-callable wrappers over inetpkt's nogil BGP decode
    # primitives. A cdef function is not reachable from Python, so
    # without this module the primitives could be neither unit tested
    # nor benchmarked. No .pxd of its own: nothing cimports it.
    Extension("packets.core.bgpcore",
              sources=["packets/core/bgpcore.pyx"],
              depends=["packets/core/inetpkt.pxd"]),
    Extension("packets.query.pcap_query",
              sources=["packets/query/pcap_query.pyx"],
              depends=["packets/core/inetpkt.pxd"]),
    Extension("packets.protos.dns",
              sources=["packets/protos/dns.pyx"],
              depends=["packets/core/inetpkt.pxd"]),
    Extension("packets.protos.netflow",
              sources=["packets/protos/netflow.pyx"],
              depends=["packets/core/inetpkt.pxd"]),
    Extension("packets.protos.dhcp",
              sources=["packets/protos/dhcp.pyx"],
              depends=["packets/core/inetpkt.pxd"]),
    Extension("packets.protos.http",
              sources=["packets/protos/http.pyx"],
              depends=["packets/core/inetpkt.pxd"]),
    # rtengine's protocol-neutral RIB. Three extensions rather than one
    # because prefix.pxd and trie.pxd are the cross-module contract: the
    # policy prefix-lists and each protocol plugin's own RIB cimport them
    # too, and a single module would make every one of those a consumer of
    # the route table as well. 'depends' lists each .pxd a module
    # cimports, not just its own, because inlined code and cdef class
    # layouts from any of them are compiled into the module: editing
    # prefix.pxd invalidates trie and table just as much as prefix.
    Extension("packets.routing.rtengine.rib.prefix",
              sources=["packets/routing/rtengine/rib/prefix.pyx"],
              depends=["packets/routing/rtengine/rib/prefix.pxd"]),
    Extension("packets.routing.rtengine.rib.trie",
              sources=["packets/routing/rtengine/rib/trie.pyx"],
              depends=["packets/routing/rtengine/rib/prefix.pxd",
                       "packets/routing/rtengine/rib/trie.pxd"]),
    Extension("packets.routing.rtengine.rib.table",
              sources=["packets/routing/rtengine/rib/table.pyx"],
              depends=["packets/routing/rtengine/rib/prefix.pxd",
                       "packets/routing/rtengine/rib/trie.pxd",
                       "packets/routing/rtengine/rib/table.pxd"]),
    # The protocol-neutral policy engine. One compiled module: only the
    # prefix-lists are hot enough to need C, and they need it because a
    # prefix-list is consulted once per prefix per policy application.
    # It cimports prefix.pxd and trie.pxd -- the entries are indexed in
    # a Trie and the evaluation descent reads TrieNode directly -- so
    # both are listed as dependencies, for the reason given above the
    # RIB entries: an inlined helper or a cdef class layout from either
    # .pxd is compiled into this module.
    Extension("packets.routing.rtengine.policy.prefixlist",
              sources=[
                  "packets/routing/rtengine/policy/prefixlist.pyx"],
              depends=["packets/routing/rtengine/rib/prefix.pxd",
                       "packets/routing/rtengine/rib/trie.pxd",
                       "packets/routing/rtengine/policy/prefixlist.pxd"]),
    # The BGP plugin's own typed core. Three extensions for the same
    # reason the RIB is three: attrs.pxd is cimported by wire and by
    # bestpath, so it is a cross-module contract and not an
    # implementation detail of one module. The dependency order is
    # attrs <- wire and attrs <- bestpath; nothing cimports wire, whose
    # output is plain Python objects by the time anything else sees it.
    Extension("packets.routing.rtengine.plugins.bgp.attrs",
              sources=["packets/routing/rtengine/plugins/bgp/attrs.pyx"],
              depends=["packets/routing/rtengine/plugins/bgp/attrs.pxd"]),
    Extension("packets.routing.rtengine.plugins.bgp.wire",
              sources=["packets/routing/rtengine/plugins/bgp/wire.pyx"],
              depends=["packets/core/inetpkt.pxd",
                       "packets/routing/rtengine/rib/prefix.pxd",
                       "packets/routing/rtengine/plugins/bgp/attrs.pxd",
                       "packets/routing/rtengine/plugins/bgp/wire.pxd"]),
    Extension("packets.routing.rtengine.plugins.bgp.bestpath",
              sources=[
                  "packets/routing/rtengine/plugins/bgp/bestpath.pyx"],
              depends=["packets/routing/rtengine/rib/prefix.pxd",
                       "packets/routing/rtengine/plugins/bgp/attrs.pxd",
                       "packets/routing/rtengine/plugins/bgp/"
                       "bestpath.pxd"]),
]

setup(ext_modules=cythonize(EXTENSIONS, compiler_directives=DIRECTIVES))
