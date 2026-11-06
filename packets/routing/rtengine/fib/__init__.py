# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Forwarding-information-base sinks.

``sink.py`` defines the ``FibSink`` interface the ``GlobalRib`` publishes its
winners to, and ``NullSink``, the default: it accounts for what it was asked
to do and touches nothing. An engine with no FIB sink configured is a pure
control-plane speaker, which is the shipped default -- an embedded library
must not write the kernel routing table because it was imported.

``netlink.py`` is the Linux rtnetlink sink: ``NetlinkSink`` plus the
``make_sink`` factory that builds one from the ``ip.route`` configuration.
It is imported here and it is safe to import anywhere -- it names no
``AF_NETLINK`` and opens no socket until ``open()`` is called, and it
refuses to open at all on a host that cannot write routes. That is what
lets the engine construct a sink from configuration on any platform and
decide separately, from ``ip route install``, whether to start it.
"""

from packets.routing.rtengine.fib.netlink import (NetlinkSink,
                                                  NetlinkUnsupported,
                                                  make_sink)
from packets.routing.rtengine.fib.sink import FibSink, NullSink

__all__ = ['FibSink', 'NullSink', 'NetlinkSink', 'NetlinkUnsupported',
           'make_sink']
