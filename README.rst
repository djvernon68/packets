Packets
=======

This package provides Cython extensions for python to assist in parsing
PCAP and PCAPNG files. It also includes a library of basic internet packet
types including Ethernet, IP, IPv6, TCP, UDP, ICMP, ICMPv6, IGMP, ARP, MPLS,
and others.

This package began as a fork of Riverbed's SteelScript Packets. It no longer
lives in the ``steelscript`` namespace and does not depend on SteelScript: the
import path is ``packets``, for example
``from packets.core.inetpkt import Ethernet``.

License
=======

Copyright (c) 2019 Riverbed Technology, Inc.

Packets is licensed under the terms and conditions of the MIT License
accompanying the software ("License").  Packets is distributed "AS IS" as set
forth in the License.

Install packets:
================

These installation instructions assume you already have a functioning python 3
environment on your machine.

Requirements:

1. Python 3.6 or later
2. Development tools for your OS
3. Cython
4. libpcap headers. See note below on installing libpcap on MacOS and Linux.

Steps:

1. Install development tools and libpcap as shown below.
2. $ pip install Cython
3. $ pip install .

Because this package builds Cython extensions against libpcap, it is installed
from a source checkout rather than from an index.


Notes on installing development tools and libpcap on MacOS and Linux:

:MacOS:

::

  Installing the development environment is a matter of installing Xcode and
  then installing the Xcode command line tools

  The simplest way to get these headers installed is to use HomeBrew or
  MacPorts.
  $ sudo homebrew install lippcap
  or
  $ sudo port install libpcap

:Linux (Debian based):

::

  The meta package name for the base development tools is usually called
  ‘build-essential’ so the following command should get everything you
  need:
  $ sudo apt-get install libpcap-dev build-essential

:Linux (RedHat based):

::

  The meta package name (group name) on RedHat based systems is usually
  ‘Development Tools” The following commands should get everything you need
  installed.
  $ sudo yum group install "Development Tools"
  $ sudo yum install libpcap-devel

  It is possible your yum config may have optional groups disabled. If the
  "Development Tools" install fails then simply add
  ‘--setopt=group_package_types=mandatory,default,optional’ to your yum
  command.
