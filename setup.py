# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
packets
====================
Cython implemented classes for reading and, in most cases writing pcap, pcapng
Ethernet, IP, TCP, and UDP. Plus other packet data like MPLS, ARP and a subset
of SMB (at time of writing).

"""
import os
import re

from setuptools import setup, Extension

try:
    from setuptools import find_packages
except ImportError:
    raise ImportError(
        'The setuptools package is required to install this library. See '
        '"https://pypi.python.org/pypi/setuptools#installation-instructions" '
        'for further instructions.'
    )


def read_version():
    """Return ``__version__`` from packets/_version.py, the only copy (L-12).

    Read as text rather than imported: importing ``packets`` needs nothing
    built today, but a build that depended on that staying true would break
    the day it stopped.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'packets', '_version.py')
    with open(path) as handle:
        match = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]",
                          handle.read(), re.M)
    if match is None:
        raise RuntimeError('no __version__ in %s' % (path,))
    return match.group(1)


# Build scripts automatically
scripts = {'console_scripts': [
    'netflow-player = packets.commands.netflow_player:main',
    'netflow-generator = packets.commands.netflow_generator:main',
    'rtengine = packets.commands.rtengine:main',
]}

# Floors, not pins. The appliance this ships to runs Flask 0.12.2 and
# Werkzeug 0.12.2 from the platform's own RPMs, and the API is written to
# that floor deliberately - no idiom newer than 0.12 - so an '==' on
# anything later would either clobber a platform-managed package or make
# the extra uninstallable on the one host that needs it. 2.0.3 is the last
# Flask that supports Python 3.6 at all and is therefore the effective
# ceiling on that interpreter, left unwritten because nothing here
# requires it. The API's test module passes at both ends of the range,
# 0.12.2 on the appliance and 3.x on a developer machine, which is what
# makes a floor honest rather than optimistic. PyYAML is here for the
# command's --config, which reads JSON with or without it.
extras = {
    'rtengine': [
        'Flask>=0.12',
        'Werkzeug>=0.12',
        'PyYAML>=3.12',
    ],
}

setup_args = {
    'name':                'packets',
    'version':             read_version(),

    # Update the following as needed
    'author':              'David Vernon',
    'author_email':        'dvernon@riverbed.com',
    'url':                 'https://github.com/djvernon68/packets',
    'license':             'MIT',
    'description':         'Base PCAP and inet packet classes.',
    'long_description':    __doc__,

    'packages': find_packages(),
    'zip_safe': False,
    'extras_require': extras,
    'test_suite': '',
    'include_package_data': True,
    # Data the code opens from beside itself (L-9). include_package_data
    # only installs what MANIFEST.in put in the sdist, and nothing put
    # this there, so an installed rtengine served no /openapi.json.
    # Listed here as well so a wheel built straight from a checkout has
    # it too.
    'package_data': {
        'packets.routing.rtengine.api': ['openapi.yaml'],
    },
    # pcap.pxd carries both the Linux and the macOS shape of the libpcap
    # headers and the extension builds on either, so claiming Linux only
    # was wrong.
    'platforms': ['Linux', 'MacOS'],
    'classifiers': [
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        # The floor and the versions the suite is run on (C-5).
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Cython',
        'Topic :: System :: Networking',
    ],
    'setup_requires': [
        # Pinned below 3. The extensions depend on Cython 0.x semantics in
        # places that Cython 3 changes by default - notably the language
        # level, the handling of a cdef function with no declared exception
        # value, and binding for cdef class methods - so an unpinned build
        # could silently produce a different module.
        'cython>=0.28,<3',
        'setuptools>=18.0'
    ],
    # NOTE: these carried cython_directives={'embedsignature': True,
    # 'binding': True} until 2.1.2. distutils does not know that keyword and
    # dropped it with 'UserWarning: Unknown Extension options', so neither
    # directive was ever applied to any of these modules - UDP.__init__ has
    # no embedded signature in a built extension, which is how it was
    # caught. It is removed rather than repaired: turning binding on now
    # would change how every cdef class method is exposed. To apply
    # directives for real, build through cythonize(..., compiler_directives=
    # {...}) instead of passing them to Extension().
    # inetpkt.pxd carries the bodies of the shared readers (rd_u16, rd_u32,
    # rd_bytes, _have_range, _fmt_ipv4_buf, the w_* writers) so every module
    # below inlines the same code rather than its own copy. That makes each of
    # them stale the moment the .pxd changes, and distutils only tracks the
    # .pyx, so editing the .pxd used to leave already built objects in place
    # and produce a module built against the old declarations. 'depends'
    # is what makes the timestamp check see it.
    'ext_modules': [
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
    ],
    'entry_points': scripts
}

setup(**setup_args)
