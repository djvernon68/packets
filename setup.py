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

install_requires = (
    'tzlocal',
)


# Build scripts automatically
scripts = {'console_scripts': [
    'netflow-player = packets.commands.netflow_player:main'
]}

setup_args = {
    'name':                'packets',
    'version':             '2.0.2',

    # Update the following as needed
    'author':              'David Vernon',
    'author_email':        'dvernon@riverbed.com',
    'url':                 'https://github.com/djvernon68/packets',
    'license':             'MIT',
    'description':         'Base PCAP and inet packet classes.',
    'long_description':    __doc__,

    'packages': find_packages(),
    'zip_safe': False,
    'install_requires': install_requires,
    'extras_require': None,
    'test_suite': '',
    'include_package_data': True,
    'platforms': 'Linux',
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
        'cython',
        'setuptools>=18.0'
    ],
    'ext_modules': [
        Extension("packets.core.pcap",
                  sources=["packets/core/pcap.pyx"],
                  libraries=["pcap"],
                  cython_directives={"embedsignature": True,
                                     "binding": True}),
        Extension("packets.core.inetpkt",
                  sources=["packets/core/inetpkt.pyx"],
                  cython_directives={"embedsignature": True,
                                     "binding": True}),
        Extension("packets.query.pcap_query",
                  sources=["packets/query/pcap_query.pyx"],
                  cython_directives={"embedsignature": True,
                                     "binding": True}),
        Extension("packets.protos.dns",
                  sources=["packets/protos/dns.pyx"],
                  cython_directives={"embedsignature": True,
                                     "binding": True}),
    ],
    'entry_points': scripts
}

setup(**setup_args)
