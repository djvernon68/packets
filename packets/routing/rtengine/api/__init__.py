# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""rtengine's REST API: a Flask application beside the engine's loop.

The API is an optional extra, and this package is the only part of rtengine
that imports Flask. The engine itself must build, start, peer and route on a
machine where Flask is not installed -- that is what makes it embeddable --
so nothing under ``packets.routing.rtengine`` outside this directory may
import anything from here at module scope.

Layout::

    bridge.py         CommandBridge: the one door from a request thread
    auth.py           bearer token, constant-time compare, bind policy
    converters.py     URL converters for prefixes, addresses, AS numbers
    app.py            create_app: wiring, limits, error translation
    routes_engine.py  status, health, plugins, running-config, openapi.json
    routes_config.py  the IOS-shaped configuration resource tree
    routes_show.py    GET /show/... operational views
    routes_clear.py   POST /clear/... actions
    server.py         ApiServer: werkzeug server on its own thread
    openapi.yaml      the specification, hand-maintained, test-enforced

Typical use, from an application that already has an engine::

    from packets.routing.rtengine.api import ApiServer

    server = ApiServer(engine, bind='127.0.0.1:8179').start()
    ...
    server.stop()

Importing this package requires Flask; importing
``packets.routing.rtengine.api.bridge`` does not, which is what lets a
non-HTTP front end reuse the thread-crossing rules without the dependency.
"""

try:
    from packets.routing.rtengine.api.app import (API_PREFIX, NotFound,
                                                  PayloadTooLarge,
                                                  create_app, load_spec)
    from packets.routing.rtengine.api.server import ApiServer, serve
except ImportError as exc:                       # pragma: no cover
    # Re-raised with the remedy in the message. The bare failure names
    # ``flask`` or ``werkzeug``, which tells an operator what is missing
    # but not that it is optional or how this package expects it to be
    # installed.
    raise ImportError(
        "%s -- rtengine's REST API needs Flask and Werkzeug, which ship as "
        "an optional extra: pip install 'packets[rtengine]'. The extra is a "
        "floor rather than a pin (Flask >= 0.12), because the API is "
        "written to work with whatever the platform already has: 0.12.2 on "
        "the appliance, 2.0.3 as the last release supporting Python 3.6, "
        "3.x on a developer machine" % (exc,))

from packets.routing.rtengine.api.auth import TokenAuth, Unauthorized
from packets.routing.rtengine.api.bridge import (CANCELLED, UNKNOWN,
                                                 BridgeTimeout,
                                                 CommandBridge)

__all__ = ['ApiServer', 'serve', 'create_app', 'load_spec', 'API_PREFIX',
           'CommandBridge', 'BridgeTimeout', 'CANCELLED', 'UNKNOWN',
           'TokenAuth', 'Unauthorized', 'NotFound', 'PayloadTooLarge']
