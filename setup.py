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
from setuptools import setup, Extension

try:
    from setuptools import find_packages
except ImportError:
    raise ImportError(
        'The setuptools package is required to install this library. See '
        '"https://pypi.python.org/pypi/setuptools#installation-instructions" '
        'for further instructions.'
    )


# Build scripts automatically
scripts = {'console_scripts': [
    'netflow-player = packets.commands.netflow_player:main'
]}

setup_args = {
    'name':                'packets',
    'version':             '2.1.3',

    # Update the following as needed
    'author':              'David Vernon',
    'author_email':        'dvernon@riverbed.com',
    'url':                 'https://github.com/djvernon68/packets',
    'license':             'MIT',
    'description':         'Base PCAP and inet packet classes.',
    'long_description':    __doc__,

    'packages': find_packages(),
    'zip_safe': False,
    'extras_require': None,
    'test_suite': '',
    'include_package_data': True,
    # pcap.pxd carries both the Linux and the macOS shape of the libpcap
    # headers and the extension builds on either, so claiming Linux only
    # was wrong.
    'platforms': ['Linux', 'MacOS'],
    'classifiers': [
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
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
    'ext_modules': [
        Extension("packets.core.pcap",
                  sources=["packets/core/pcap.pyx"],
                  libraries=["pcap"]),
        Extension("packets.core.inetpkt",
                  sources=["packets/core/inetpkt.pyx"]),
        Extension("packets.query.pcap_query",
                  sources=["packets/query/pcap_query.pyx"]),
        Extension("packets.protos.dns",
                  sources=["packets/protos/dns.pyx"]),
        Extension("packets.protos.netflow",
                  sources=["packets/protos/netflow.pyx"]),
        Extension("packets.protos.dhcp",
                  sources=["packets/protos/dhcp.pyx"]),
        Extension("packets.protos.http",
                  sources=["packets/protos/http.pyx"]),
    ],
    'entry_points': scripts
}

setup(**setup_args)
