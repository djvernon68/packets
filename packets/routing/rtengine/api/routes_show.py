# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""``GET /show/...``: the operational surface, as URLs.

``show ip bgp summary`` is ``GET /api/v1/show/ip/bgp/summary``. One rule
serves all of them, and that is the design decision worth explaining,
because the obvious alternative -- a Flask route per command -- is wrong
here.

The set of ``show`` commands is not fixed at import time. It is the union of
the core's own views and every registered plugin's ``show_handlers()``, so an
engine with BGP registered answers more paths than one without, and a third
protocol added later answers more still. Routes generated from that set would
make the URL map depend on plugin registration order, and the OpenAPI
document -- which is a static file, hand-maintained on purpose -- could never
be right for more than one configuration. So there is one documented rule,
``/show/{path}``, and ``GET /show`` enumerates what this particular engine
actually answers. That endpoint is the discovery mechanism the per-command
routes would have been.

**A path is resolved before it is dispatched.** ``Engine.show`` matches the
longest registered prefix and hands the remainder to the handler as
arguments, which is right for a CLI and too permissive for a URL: a mistyped
segment would arrive at a handler as an argument and be reported as a
missing neighbour rather than as a bad URL. So the path is checked against
``Engine.show_paths()`` first, and an unresolvable one is a 404 that lists
what is available.

**A prefix in a path is put back together.** ``/show/ip/bgp/10.0.0.0/8``
arrives here as four segments, because a WSGI server has already decoded
``%2F`` and there is no way to tell an encoded slash from a real one. The
last two segments are rejoined when, and only when, they form a valid
prefix -- which is also the only position any of these commands takes one.
"""

import re

from flask import Blueprint, request

from packets.routing.rtengine.api.app import (API_PREFIX, NotFound, bridge,
                                              engine, json_response,
                                              page_args)
from packets.routing.rtengine.errors import ConfigError
from packets.routing.rtengine.rib.prefix import parse_prefix

blueprint = Blueprint('rtengine_show', __name__)


@blueprint.route('/show', methods=['GET'], strict_slashes=False)
def index():
    """Every operational view this engine answers.

    Includes the plugins', because that is the point: the list is the
    engine's actual capability rather than what the documentation
    happened to know about when it was written.

    One rule with ``strict_slashes=False`` rather than two rules, one
    per spelling: registering ``/show`` *and* ``/show/`` makes Werkzeug
    treat the bare form as the branch of a directory and answer it with
    a 301 to the trailing-slash form. A redirect is a reasonable thing
    to serve a browser and a poor thing to serve an API client, which
    may not follow it, and will certainly not follow it on a POST.
    """
    paths = bridge().call(engine().show_paths)
    return json_response({
        'views': [{'path': list(path),
                   'command': 'show ' + ' '.join(path),
                   'url': '%s/show/%s' % (API_PREFIX, '/'.join(path))}
                  for path in paths],
    })


@blueprint.route('/show/<path:command>', methods=['GET'])
def show(command):
    """Answer one operational query.

    :param command: the remainder of the URL, e.g. ``ip/bgp/summary``.
    :return: the handler's document, unaltered. The API adds nothing: the
        contract is that ``engine.show(...)`` and this endpoint return
        the same document for the same command.
    """
    segments = rejoin_prefix([part for part in command.split('/') if part])
    if not segments:
        return index()
    registered = bridge().call(engine().show_paths)
    resolve(segments, registered, 'show')
    kwargs = page_args()
    return json_response(call_view(engine().show, segments, kwargs))


def rejoin_prefix(segments):
    """Rejoin a trailing ``address/length`` pair into one prefix.

    :param segments: the URL segments.
    :return: the segments, with the last two joined when they form a
        prefix and the address alone does not already.
    """
    if len(segments) < 2:
        return segments
    tail = segments[-2] + '/' + segments[-1]
    try:
        parse_prefix(tail)
    except (ValueError, TypeError):
        return segments
    return segments[:-2] + [tail]


def resolve(segments, registered, verb):
    """Check that a path names something, and return the handler's prefix.

    :param segments: the requested path.
    :param registered: the paths the engine has handlers for.
    :param verb: ``'show'`` or ``'clear'``, for the error message.
    :return: ``(matched prefix, extra segments)``.
    :raises NotFound: nothing handles that path.
    """
    path = tuple(segments)
    known = [tuple(entry) for entry in registered]
    for split in range(len(path), 0, -1):
        if path[:split] in known:
            return path[:split], path[split:]
    raise NotFound(
        '%r is not a %s command this engine answers; GET %s/%s lists the '
        'ones it does' % (' '.join(segments), verb, API_PREFIX, verb),
        path=request.path)


def call_view(fn, segments, kwargs):
    """Invoke a show or clear handler, translating its argument errors.

    Handlers take the keywords that make sense for them -- the BGP table
    pages by ``offset``, the core's route table by ``after``, and several
    take neither -- so a client that sends one the view does not have
    gets told which keyword that was, rather than a 500 with a
    ``TypeError`` in the log. Only the "unexpected keyword" form is
    translated: any other ``TypeError`` is a defect in the handler and is
    left to be reported as one.

    **This catches less than it looks like it does, and the gap is the
    plugins'.** A handler declared ``(*args, **kwargs)`` -- which every
    BGP view is -- accepts any keyword and quietly ignores the ones it
    does not use, so ``?after=x`` on the BGP table returns an unpaged
    document with a 200 rather than an error. Nothing here can see that:
    by the time the keyword has been swallowed there is no signal left
    to report. Rejecting keywords against a fixed list instead would be
    worse, because the set of views is whatever the registered plugins
    provide and a core-side list would start refusing a new plugin's
    legitimate parameters. The honest position is that this translation
    fires for views that declare their parameters, the OpenAPI document
    says so in as many words, and the real repair is in the plugins'
    signatures.

    :param fn: ``engine.show`` or ``engine.clear``.
    :param segments: the path segments.
    :param kwargs: the keywords.
    :return: the handler's document.
    """
    try:
        return bridge().call(fn, *segments, **kwargs)
    except TypeError as exc:
        match = re.search(r"unexpected keyword argument '([^']+)'", str(exc))
        if match:
            # Reported as the parameter's name rather than as the
            # interpreter's message, which names the handler's class and
            # method and is a fact about our internals, not about the
            # request that arrived.
            raise ConfigError("%r does not accept the query parameter %r"
                              % (' '.join(segments), match.group(1)),
                              path=match.group(1))
        raise
