# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Endpoints about the engine itself: status, health, plugins, the document.

These are the endpoints something *else* reads -- a supervisor, a monitoring
system, a deployment tool -- rather than the ones an operator drives, so two
properties matter more here than anywhere else in the API.

**The health document is the engine's, unaltered.** ``GET /engine/health``
returns exactly what ``Engine.health()`` returns, byte for byte, because a
monitoring rule written against one must hold for the other. Anything the
API layer knows and the engine does not -- how many bridge calls timed out,
where the token came from -- goes in ``/engine/status``, which is the
endpoint for identity and configuration rather than for measurement.

**``/running-config`` is a resource with an ``ETag``.** The revision is the
entity tag, so the ordinary HTTP idiom -- read, edit, write back with
``If-Match`` -- is exactly the optimistic concurrency the engine already
implements, and a client that skips the header gets last-write-wins, which
is the behaviour it asked for by skipping the header.
"""

from flask import Blueprint

from packets.routing.rtengine import __version__
from packets.routing.rtengine.api.app import (bridge, ctx, engine,
                                              if_match_revision, json_body,
                                              json_response, mutation)

blueprint = Blueprint('rtengine_engine', __name__)


@blueprint.route('/', methods=['GET'], strict_slashes=False)
def index():
    """What this is and where the rest of it lives.

    An unauthenticated client still needs a way to discover the spec, and
    a human who typed the base URL into a browser deserves better than a
    404 -- or than the 301 that ``/api/v1`` without the trailing slash
    would otherwise get.
    """
    return json_response({
        'name': 'rtengine',
        'version': __version__,
        'links': {
            'openapi': '/api/v1/openapi.json',
            'status': '/api/v1/engine/status',
            'health': '/api/v1/engine/health',
            'running-config': '/api/v1/running-config',
            'show': '/api/v1/show',
            'clear': '/api/v1/clear',
        },
    })


@blueprint.route('/engine/status', methods=['GET'])
def status():
    """Identity and configuration: what this engine is.

    The engine's own ``status()`` document with the API thread's view
    merged into its ``api`` section -- the bind, the authentication
    policy and the bridge's counters are facts about the REST layer that
    the engine has no way to know, and putting them anywhere else would
    mean polling two endpoints to answer one question.
    """
    context = ctx()
    document = bridge().call(engine().status)
    api = document.setdefault('api', {})
    api['auth'] = context.current_auth().describe()
    api['max-body-bytes'] = context.max_body_bytes
    api['max-page'] = context.max_page
    api['bridge'] = context.bridge.stats()
    return json_response(document)


@blueprint.route('/engine/health', methods=['GET'])
def health():
    """The health document, unmodified.

    Acceptance criterion 5: this and ``Engine.health()`` are the same
    document. Nothing is added here, however tempting -- a probe that
    alerts on ``status`` must not see a different answer depending on
    which door it came through.
    """
    return json_response(bridge().call(engine().health))


@blueprint.route('/engine/plugins', methods=['GET'])
def plugins():
    """The registered protocol plugins and the families they carry."""
    # The engine is an argument rather than something the callable looks
    # up, because this runs on the loop thread where Flask's globals do
    # not exist. See the rule in bridge.py: it is the one mistake in
    # this package that a developer's Flask 3 forgives and the
    # appliance's Flask 0.12 does not.
    def collect(eng):
        found = []
        for plugin in eng.plugins():
            found.append({
                'name': plugin.name,
                'afi_safi': [list(pair) for pair in plugin.afi_safi()],
                'admin_distance': dict(plugin.admin_distance or {}),
                'config_section': '.'.join(plugin.config_section or ()),
            })
        return {'plugins': found}

    return json_response(bridge().call(collect, engine()))


@blueprint.route('/running-config', methods=['GET'])
def get_running_config():
    """The whole configuration document, secrets redacted.

    The ``ETag`` is the revision. A client that reads here, edits and
    POSTs back with ``If-Match`` cannot silently overwrite a change
    somebody else made in between.
    """
    def read(eng):
        return eng.running_config(redact=True), eng.revision

    document, revision = bridge().call(read, engine())
    return json_response(document, headers={'ETag': '"%d"' % (revision,)})


@blueprint.route('/running-config', methods=['POST', 'PUT'])
def replace_running_config():
    """Replace the whole document atomically.

    Validate, prepare with every affected plugin, then commit: a
    rejection anywhere leaves the running configuration and its revision
    exactly as they were. Secrets written back as ``"<redacted>"`` keep
    their stored values, which is what makes read-edit-write safe for a
    document containing a password the client is not allowed to see.
    """
    document = json_body()
    revision = bridge().call(engine().replace_config, document,
                             if_match_revision())
    return mutation(revision)


@blueprint.route('/openapi.json', methods=['GET'])
def openapi():
    """The OpenAPI 3.0 document describing this application.

    Served as JSON from a YAML source: YAML is what a human maintains
    and JSON is what tooling reads, and converting on the way out means
    there is only ever one document to keep true.
    """
    return json_response(ctx().spec())


@blueprint.route('/engine/config-schema', methods=['GET'])
def config_schema():
    """The configuration schema, core sections plus every plugin's.

    Not in the plan's endpoint table, and included because the schema is
    the only complete answer to "what may I put in this document". The
    OpenAPI spec describes the *shape* of each resource; this is the
    vocabulary, and it grows when a plugin is registered, which a static
    document cannot express.
    """
    def read(eng):
        return eng.store.schema

    return json_response(bridge().call(read, engine()))
