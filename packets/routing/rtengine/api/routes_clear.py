# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""``POST /clear/...``: the actions, which are not idempotent reads.

``clear ip bgp`` is the most dangerous command an operator types at a BGP
speaker, and the difference between its three forms is the difference
between a free operation and a minute of churn propagated to every peer:

* ``{"soft": "in"}`` re-runs inbound policy over the paths already held and
  sends a ROUTE-REFRESH when the capability was negotiated. Cheap.
* ``{"soft": "out"}`` re-advertises this router's choices from the update
  group's record. Cheap.
* no body at all, or ``{"soft": false}``, drops the session. Both ends
  forget everything and relearn it.

So this blueprint's job is to make sure the operator gets the one they asked
for, and that is why it resolves the URL strictly instead of handing it
straight to ``Engine.clear``.

**The strict resolution is a fix, not caution.** Engine dispatch matches the
longest registered prefix and passes the rest as positional arguments, and
the BGP plugin's ``clear_all`` accepts its first positional argument *as the
soft directive* -- which it must, because ``clear ip bgp soft in`` is a real
CLI spelling. Put those two together and ``POST /clear/ip/bgp/10.0.0.2``,
which looks exactly like a request to clear one neighbour, resolves to
"clear **every** session, softly, because the address is not one of the
words ``in``/``out``/``both`` so it means ``in``". Nothing in the response
would say so. Here, a trailing segment is accepted only when it cannot be
confused with a longer registered path, and that request is a 404 naming
``/clear/ip/bgp/neighbor/10.0.0.2`` instead.
"""

from flask import Blueprint, request

from packets.routing.rtengine.api.app import (API_PREFIX, NotFound, bridge,
                                              engine, json_body,
                                              json_response)
from packets.routing.rtengine.api.routes_show import (call_view,
                                                      rejoin_prefix)
from packets.routing.rtengine.errors import ConfigError

blueprint = Blueprint('rtengine_clear', __name__)

#: The directions ``soft`` accepts. ``true`` means ``in``, which is what
#: every implementation that takes the bare word means by it.
SOFT_VALUES = ('in', 'out', 'both')


@blueprint.route('/clear', methods=['GET'], strict_slashes=False)
def index():
    """Every action this engine offers.

    A GET, even though the actions themselves are POSTs: enumerating what
    can be done must not do any of it. One rule rather than two, for the
    reason given on the show index: two spellings make the bare one a
    301.
    """
    paths = bridge().call(engine().clear_paths)
    return json_response({
        'actions': [{'path': list(path),
                     'command': 'clear ' + ' '.join(path),
                     'url': '%s/clear/%s' % (API_PREFIX, '/'.join(path))}
                    for path in paths],
    })


@blueprint.route('/clear/<path:command>', methods=['POST'])
def clear(command):
    """Run one action.

    :param command: the remainder of the URL, e.g. ``ip/bgp/neighbor/
        10.0.0.2``.
    :return: the handler's report, which names what was actually cleared
        and in which direction -- the only way for a client to confirm
        that a soft clear was soft.
    """
    segments = rejoin_prefix([part for part in command.split('/') if part])
    if not segments:
        raise NotFound('no action named', path=request.path)
    registered = [tuple(path) for path in bridge().call(engine().clear_paths)]
    matched, extra = _resolve_action(segments, registered)
    kwargs = {}
    soft = _soft_from_body()
    if soft is not None:
        kwargs['soft'] = soft
    return json_response(call_view(engine().clear, list(matched) + list(extra),
                                   kwargs))


def _resolve_action(segments, registered):
    """Resolve a clear path, refusing anything ambiguous.

    :param segments: the requested path.
    :param registered: every registered clear path.
    :return: ``(matched, extra)``.
    :raises NotFound: nothing handles the path, or a trailing segment sits
        where a longer registered path was expected -- see the module
        docstring for why that case must not be dispatched.
    """
    path = tuple(segments)
    matched = None
    for split in range(len(path), 0, -1):
        if path[:split] in registered:
            matched = path[:split]
            break
    if matched is None:
        raise NotFound(
            '%r is not a clear command this engine offers; GET %s/clear '
            'lists the ones it does' % (' '.join(segments), API_PREFIX),
            path=request.path)

    extra = path[len(matched):]
    if not extra:
        return matched, extra

    # Longer registered paths under the match are the sub-commands this
    # one has. If there are any, the next segment has to be one of them:
    # the alternative is passing an address to a handler that will read
    # it as something else entirely.
    longer = sorted(entry for entry in registered
                    if len(entry) > len(matched)
                    and entry[:len(matched)] == matched)
    if longer and extra[0] not in [entry[len(matched)] for entry in longer]:
        suggestions = ['%s/clear/%s/%s' % (API_PREFIX, '/'.join(entry),
                                           '/'.join(extra))
                       for entry in longer]
        raise NotFound(
            'clear %s has sub-commands, and %r is not one of them; did you '
            'mean %s?' % (' '.join(matched), extra[0],
                          ' or '.join(suggestions)),
            path=request.path)
    if len(extra) > 1:
        raise NotFound('clear %s takes one argument, not %d'
                       % (' '.join(matched), len(extra)), path=request.path)
    return matched, extra


def _soft_from_body():
    """Read the ``soft`` directive from the request body.

    :return: ``'in'``, ``'out'``, ``'both'``, False for an explicit hard
        clear, or None when the body says nothing -- which the handlers
        already treat as a hard clear, so the distinction is only about
        not putting a keyword in their way.
    :raises ConfigError: the body is not an object, or ``soft`` is not a
        direction. A typo is rejected rather than interpreted: guessing
        wrong here is the difference between a soft clear and dropping
        every session.
    """
    body = json_body(required=False, default=None)
    if body is None:
        return None
    if not isinstance(body, dict):
        raise ConfigError('the request body must be an object, e.g. '
                          '{"soft": "in"}')
    unknown = [key for key in body if key != 'soft']
    if unknown:
        raise ConfigError('unknown key(s) %s; this action only takes "soft"'
                          % ', '.join(sorted(unknown)))
    if 'soft' not in body:
        return None
    soft = body['soft']
    if soft is False or soft is None:
        return False
    if soft is True:
        return True
    if isinstance(soft, str) and soft.lower() in SOFT_VALUES:
        return soft.lower()
    raise ConfigError('soft must be one of %s, or true for inbound, or '
                      'false for a hard clear; got %r'
                      % (', '.join(SOFT_VALUES), soft), path='soft')
