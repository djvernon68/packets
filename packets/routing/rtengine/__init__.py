# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""rtengine -- a protocol-agnostic routing engine.

The engine owns peers, RIBs, best-path selection, policy, an optional kernel
FIB sink and health reporting. Protocols arrive as plugins: the core knows
nothing about BGP, OSPF or RIP. It owns the trie, a protocol-neutral
``Route`` (prefix, next-hop, administrative distance, metric), the
``GlobalRib`` that selects across protocols by administrative distance, the
FIB sink, health and the event bus. Each plugin runs its own protocol RIB and
its own selection algorithm, and offers protocol-neutral winners to the
``GlobalRib``.

Layout::

    engine.py     Engine: lifecycle, command submission, config, show, health
    loop.py       3.6-safe asyncio helpers and the deadline-bounded Batcher
    plugin.py     ProtocolPlugin: the interface every protocol implements
    config.py     revisioned IOS-shaped config document, diff, apply driver
    events.py     EventBus: bounded fan-out queues for importers
    health.py     HealthMonitor: loop lag, batch cost, queue depth, roll-up
    errors.py     the exceptions the control plane raises
    rib/          protocol-neutral RIB: prefix.pyx, trie.pyx, table.pyx,
                  globalrib.py, resolver.py
    fib/          FibSink interface and NullSink
    plugins/      plugin registry; protocol plugins live under here

Typical embedded use::

    from packets.routing.rtengine import Engine

    engine = Engine(config={'ip': {'route': {'install': False}}})
    engine.start()                       # own thread, own asyncio loop
    ...
    engine.stop()

Importing this package imports the compiled RIB extensions, because ``Engine``
needs them. Code that only wants to subclass ``ProtocolPlugin`` or read an
exception type can import ``packets.routing.rtengine.plugin`` or
``.errors`` directly and pay nothing.
"""

from packets.routing.rtengine.engine import Engine
from packets.routing.rtengine.errors import (ApplyError, ConfigError,
                                             ConflictError,
                                             PreconditionFailed,
                                             RtEngineError, UnavailableError)
from packets.routing.rtengine.plugin import ProtocolPlugin

__all__ = ['Engine', 'ProtocolPlugin', 'RtEngineError', 'ConfigError',
           'ConflictError', 'ApplyError', 'UnavailableError',
           'PreconditionFailed', '__version__']

# Tracks the packets version it ships with rather than versioning
# separately; rtengine is not independently released. Imported, not
# written here (L-12): a second copy is how an early build of 2.3.0 came
# to report 2.2.1.
from packets._version import __version__  # noqa: E402
