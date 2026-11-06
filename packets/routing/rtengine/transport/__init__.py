# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The authenticated TCP transport a BGP session runs over.

Two modules, split along the line between policy and plumbing:

``auth.py``     TCP-MD5 (RFC 2385), TCP-AO (RFC 5925) and GTSM (RFC 5082)
                socket options, with the kernel structs hand-packed and
                every capability probed at runtime. It also holds
                ``resolve_auth``, the fail-closed decision about how -- or
                whether -- a neighbor is allowed to peer.
``tcp.py``      ``connect``, ``Listener`` and ``Connection``: sockets the
                engine creates and options itself before the loop is
                allowed to touch them.

The split exists because the two halves have different audiences.
``auth.py`` answers questions the configuration layer asks before any
socket exists -- can this platform enforce ``ttl-security``? is this
``ao`` stanza usable on this kernel? -- while ``tcp.py`` is only ever
called by the session FSM. Keeping the policy out of the socket code means
a peer can be refused at configuration time rather than discovered to be
unauthenticatable halfway through a handshake.

Nothing above this package appears here. Framing, the FSM, timers and peer
state are all layers up; this package's entire contract is "a socket that
is already authenticated, or an honest error". Importing it costs a
``socket`` and an ``asyncio`` import and runs no probes: the capability
probes are lazy, so importing on a platform without TCP-MD5 -- macOS, where
this is developed -- is silent and harmless.
"""

from packets.routing.rtengine.transport.auth import (AUTH_AO, AUTH_MD5,
                                                     AUTH_MD5_AO_FALLBACK,
                                                     AUTH_MODES, AUTH_NONE,
                                                     ao_supported,
                                                     gtsm_inbound_supported,
                                                     md5_supported,
                                                     resolve_auth)
from packets.routing.rtengine.transport.tcp import (BGP_PORT, Connection,
                                                    Listener, connect)

__all__ = ['AUTH_NONE', 'AUTH_MD5', 'AUTH_AO', 'AUTH_MD5_AO_FALLBACK',
           'AUTH_MODES', 'resolve_auth', 'md5_supported', 'ao_supported',
           'gtsm_inbound_supported', 'BGP_PORT', 'Connection', 'Listener',
           'connect']
