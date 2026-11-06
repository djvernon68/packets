Routing Engine
==============

``rtengine`` is a protocol-agnostic routing engine that ships inside
``packets``. The rest of the library decodes routing protocols off the wire;
``rtengine`` speaks them.

Overview
--------

The engine core owns configuration, revisions, the event bus, the
protocol-neutral RIB, the operational ``show`` and ``clear`` surface, health
reporting and the optional kernel FIB sink. It knows nothing about any
particular routing protocol. A protocol arrives as a plugin implementing
``ProtocolPlugin``: the plugin owns its own protocol RIB and its own best-path
algorithm, and offers protocol-neutral ``Route`` candidates to the
``GlobalRib``, which selects across protocols by administrative distance.

BGP-4 is the first plugin. It is the only one shipped today.

Two properties are worth stating up front, because they shape everything else:

* **Control plane by default.** The engine peers, applies policy and computes
  best paths without touching the kernel routing table. Installing into the
  Linux FIB is opt-in, off by default, and needs privileges you have to grant
  deliberately. You can run the engine as a route collector, a policy
  laboratory or a route server and never give it ``CAP_NET_ADMIN``.
* **Cython where it is hot, Python where it is read.** Prefix storage, the
  trie, table lookup and path comparison are Cython. Configuration, policy
  evaluation, the state machine and the API are Python, because those are the
  parts a human has to reason about and modify.

There are two ways to use it: embed the ``Engine`` object in a python program,
or run the ``rtengine`` console script as a daemon and drive it over REST. The
REST layer is a thin translation of the embedding API and adds no behaviour of
its own.

Quick start: embedded
---------------------

The engine runs its own thread and its own asyncio event loop. ``start()``
returns once the loop is up.

.. code-block:: python

    from packets.routing.rtengine.engine import Engine
    from packets.routing.rtengine.plugins.bgp.plugin import BGPPlugin

    engine = Engine(plugins=[BGPPlugin()])
    engine.replace_config({
        'router': {
            'bgp': {
                '65000': {
                    'router-id': '10.0.0.1',
                    'neighbor': {
                        '10.0.0.2': {
                            'remote-as': 65001,
                            'address-family': {
                                'ipv4': {'unicast': {'activate': True}},
                            },
                        },
                    },
                    'address-family': {
                        'ipv4': {'unicast': {}},
                    },
                },
            },
        },
    })
    engine.start()

Note the order. Plugins are supplied when the engine is built, because a
plugin contributes the configuration schema for its own section, and the
``router bgp`` section cannot be validated until the BGP plugin is present.
Import ``BGPPlugin`` from ``plugins.bgp.plugin``: the plugin package
deliberately imports nothing in its ``__init__``, so that an engine configured
without BGP never pays for loading its compiled modules.

Subscribe to the event bus to see what the engine is doing. Subscriptions are
bounded queues; the bus never blocks a protocol thread waiting for a consumer.

.. code-block:: python

    sub = engine.subscribe('route-best', maxsize=1000)
    while True:
        ev = sub.get(timeout=1.0)
        if ev is None:
            continue
        print('best path', ev)

And to shut down:

.. code-block:: python

    engine.stop()

``stop()`` withdraws any routes the engine installed into the kernel, unless
``retain-on-shutdown`` is configured or you pass ``retain_fib=True``.

Quick start: standalone
-----------------------

The ``packets[rtengine]`` extra installs Flask and PyYAML and the ``rtengine``
console script:

.. code-block:: bash

    $ pip install .[rtengine]

Run it against a configuration document:

.. code-block:: bash

    $ rtengine --config bgp.json --bind 127.0.0.1:8179 --token-file /etc/rtengine.token

The flags are:

``-c PATH``, ``--config PATH``
    The configuration document. JSON is always accepted. YAML is accepted when
    PyYAML is installed, and is required for a ``.yaml`` or ``.yml`` file - if
    PyYAML is missing, a YAML file is an error rather than a silent JSON parse
    failure.

``--bind HOST:PORT``
    Where the REST API listens. Overrides ``api.bind`` in the document.

``--token-file PATH``
    Read the API bearer token from a file. Overrides ``api.auth.token-file``.
    Preferred over an inline token, because a token in the document is a token
    in your configuration management. If the file does not exist, a run
    creates it (mode ``0600``) with a random token and logs the path, never
    the token. ``--check`` does not create it: it checks that the file could
    be created and leaves the disk alone.

``--no-api``
    Run the engine with no REST API at all. Useful for a pure collector, or
    when something else in the process is already serving.

``--check``
    Validate the configuration document and exit without starting anything.
    Exit status 0 means the document would be accepted; 2 means it would not,
    and the reason is printed. A check writes nothing: no token file, no
    netlink socket, no listening socket. An existing token file must be
    readable and non-empty, as a run requires; a missing one must be in a
    writable directory.

``--log-level LEVEL``
    Standard ``logging`` level name.

``--swagger-ui``
    Serve a Swagger UI browser for the OpenAPI document. Combining this with
    ``--no-api`` is an argparse error, since there would be nothing to browse.

Exit status is 0 for a clean shutdown and 2 for a configuration the engine
refused. A bind failure - a port already in use, or a privileged port without
the privilege - stops the engine and exits 2 rather than leaving a running
engine with no way to reach it. Exit status 3 is a shutdown that did not
finish cleanly: a plugin that raised while stopping, a kernel route cleanup
that failed, or the loop or API thread still running when its time ran out.
Each problem is printed to stderr as a ``shutdown:`` line. A supervisor that
restarts on failure should treat 3 as a failure.

The console script registers ``BGPPlugin`` explicitly and builds the engine
*before* applying the document. That ordering matters: a plugin contributes its
own configuration schema, so the ``router bgp`` section of your document cannot
be validated until the BGP plugin is registered. If you build your own
embedding, register plugins before you configure.

The script calls ``engine.start()`` rather than ``run_forever()``, so the main
thread stays free and ``SIGINT``/``SIGTERM`` land where you expect.

Configuration
-------------

Configuration is a single JSON (or YAML) document whose keys mirror IOS
configuration hierarchy. An operator who can read a router configuration can
read this one. The document is revisioned and applied atomically; see
`Revisions and atomicity`_.

Defaults are **not** materialised into the document. ``running-config`` shows
what you configured, not what the engine inferred - again like IOS. The
defaults listed below are what the engine uses when a key is absent.

Core sections
~~~~~~~~~~~~~

``ip.prefix-list`` and ``ipv6.prefix-list``
    Named prefix lists, keyed by list name. Referenced from policy.

``route-map``
    Keyed by route-map name, each mapping to an ordered list of clauses. A
    clause has ``seq``, ``action`` (``permit`` or ``deny``), and ``match`` and
    ``set`` bodies.

``ip.as-path-access-list``
    Named AS-path access-lists, keyed by list name, each an ordered list of
    ``seq``, ``action`` and ``regex`` entries; see `AS-path regexes`_.
    Referenced from a neighbour's ``filter-list`` and a route-map's ``match
    as-path``. A name may be referenced before the list exists, as in IOS;
    until it does, a ``filter-list`` naming it denies every path. A
    ``filter-list`` change applies to paths received from then on; ``clear
    ip bgp neighbor X soft in`` applies it to the paths already held.

``ip.route.static`` and ``ipv6.route.static``
    Static routes keyed by prefix. Each takes a required ``next-hop``, plus
    ``distance`` (default ``1``) and ``metric`` (default ``0``).

``ip.route`` - kernel install knobs
    ``install`` (default ``false``), ``table`` (default ``254``, the main
    table), ``protocol`` (default ``190``), ``priority.ebgp`` (default ``20``)
    and ``priority.ibgp`` (default ``200``), ``retain-on-shutdown`` (default
    ``false``), ``validate-next-hop`` (default ``false``) and
    ``resolve-via-default`` (default ``false``).

    Note that ``ipv6.route`` carries **only** ``static``. There is no
    IPv6-specific install subtree: the knobs under ``ip.route`` govern kernel
    install for both address families.

``api``
    ``bind`` (default ``127.0.0.1:8179``), ``auth.token`` (a secret, minimum
    length 16), ``auth.token-file``, ``auth.allow-unauthenticated-health``
    (default ``false``), ``insecure`` (default ``false``), ``tls.cert`` and
    ``tls.key``, ``max-body-bytes`` (default ``1048576``) and ``max-page``
    (default ``10000``).

AS-path regexes
~~~~~~~~~~~~~~~

An AS-path regex is matched, as in IOS, anywhere in the path as it is printed:
ASNs separated by single spaces, an AS_SET as ``{65003,65004}``, a
confederation sequence as ``(65001 65002)`` and a confederation set as
``[65003,65004]``. ``^`` and ``$`` are the start and end of the whole path, and
an empty path is the empty string.

``_`` means what it does in IOS: the start or end of the path, a space, a
comma, a brace, a parenthesis or a bracket. So ``_65001_`` matches ``65001``,
``1 65001 2`` and ``{2,65001}``, and not ``165001``. ``\_`` and an underscore
inside ``[...]`` are a literal underscore, which never appears in a path.

A regex runs on the engine's own thread against a path chosen by a peer, so
one that could take too long on a long path is refused when it is configured,
with a message naming the reason:

* longer than 256 characters;
* a backreference (``\1``, ``(?P=name)``) or a group conditional;
* a repeated group that itself repeats, unless every pass starts or ends with
  a delimiter (``_``, a space, a comma) that nothing repeated inside it can
  match. ``^[0-9]+(_[0-9]+)*$`` is accepted and ``([0-9]+)+`` is refused;
* a repeated alternation whose branches can match the same text, like ``(1
  |1 )+`` or ``(a|ab)+``. The test is conservative: branches must differ in
  the first character after what they have in common, and that common part
  must not contain a repeat;
* work that could grow faster than the square of the path length. Each
  repeat that can run across a delimiter, like ``.*`` or ``(_[0-9]+)*``,
  multiplies the work by the length of the path, and so does the search
  trying every starting point, unless the regex starts with ``^``. A repeat
  that stays inside one ASN, like ``[0-9]+``, does not count. So a regex may
  hold at most one such repeat, or two if it starts with ``^``:
  ``_65001_.*_65002_`` and ``^65001_.*_65002_.*_65003_`` are accepted, and
  ``_65001_.*_65002_.*_65003_`` is refused;
* work that grows with the square of the path length (one such repeat, or
  two after a ``^``), when ``maxas-limit`` lets through paths longer than 255
  ASNs or is off. With ``maxas-limit`` at its default such a regex is
  accepted. Raising the limit while such a regex is configured is refused
  too, naming the regex. A regex that starts with ``^`` and holds at most
  one such repeat, like ``^[0-9]+(_[0-9]+)*$``, is accepted at any limit.

A leading ``.*`` (or ``^.*``) and a trailing ``.*`` (or ``.*$``) are dropped
first: they change nothing about which paths match, and they were the most
expensive part. ``.*_65001_.*`` is run as ``_65001_``. Dropping ``^.*`` drops
its ``^`` too, so ``^.*_65001_.*_65002_`` counts as unanchored. Measured on
the deployment target, the slowest accepted regex on the slowest path takes
about 16 ms at the default ``maxas-limit``, and under a millisecond at a
``maxas-limit`` of 2000; ``bench/aspath_guard_bench.py`` repeats that
measurement. A regex with an unbounded repeat also remembers its answers for
the last 4096 distinct paths, so each path is matched once however many
prefixes share it.

BGP: instance
~~~~~~~~~~~~~

The BGP section is ``router.bgp``, keyed by autonomous system number. **Only
one AS instance may be configured.** Attempting to configure a second one is a
conflict, not a validation error: over REST it is a ``409``, not a ``400``.

Instance-level keys:

``router-id``
    Dotted-quad router ID.

``log-neighbor-changes``
    Default ``true``.

``default-local-preference``
    Default ``100``. IOS ``bgp default local-preference``: the LOCAL_PREF a
    path without one is ranked as, and the value such a path is given towards
    internal peers. One value for both, so this router and its iBGP
    neighbours rank the path the same way.

``maxas-limit``
    Default ``255``; ``0`` turns it off, the maximum is ``2000``. IOS ``bgp
    maxas-limit``: a received path whose AS_PATH holds more ASNs than this is
    treated as withdrawn, and counted in the neighbour's
    ``maxas-limit-dropped``. Every ASN counts, AS_SET and confederation
    members included. It also bounds the string AS-path regexes run over,
    which is why a value above 255, or 0, is refused while a regex that
    needs the shorter bound is configured; see `AS-path regexes`_. A change applies to paths received from then
    on: a path already refused comes back only when the peer sends it
    again, for example after a route refresh.

``bestpath``
    ``always-compare-med``, ``deterministic-med`` (default ``true``),
    ``med-missing-as-worst``, ``compare-routerid``, ``as-path-ignore``,
    ``as-path-multipath-relax``.

``timers``
    ``hold-time`` (default ``90``), ``keepalive`` (default ``30``). The default
    for every neighbour that sets no ``timers`` of its own, like IOS
    ``timers bgp``. A neighbour ``hold-time`` overrides both; its keepalive
    is then its own ``keepalive``, or a third of its hold time, never the
    instance keepalive, which was chosen for a different hold time. Changing
    the instance timers resets the sessions that inherit them, as changing a
    neighbour's own timers does.

``listen``
    ``address``, ``port`` (default ``179``). Binding 179 needs privileges; see
    `Security posture`_.

``next-hop-validation``
    Default ``false``. When on, a path is only eligible if its next hop
    resolves. A next hop resolves through a configured static first, then
    an imported kernel route, then the engine's own routes, longest match
    first in each. A BGP route never resolves a BGP next hop. A default
    route counts only with ``ip.route.resolve-via-default``. A route learned
    by a protocol counts only if its own next hop resolves in turn, at most
    four levels deep and never in a loop. A static entry ends the chain: it
    is the operator's word, and rtengine knows no connected routes to check
    its next hop against. Every held path is re-tested within one
    advertisement pass (half a second) of anything that can change the
    answer: a route selected in the core, a static added or removed, a
    kernel import, or ``resolve-via-default`` turned on or off. No clear is
    needed.

``maximum-paths`` / ``maximum-paths-ibgp``
    Both default ``1``, and ``1`` is the only value accepted in this release:
    the core RIB and the kernel sink carry one next hop per prefix, so a
    larger value would show an equal-cost set in ``show ip bgp`` while
    forwarding over a single path. It is refused at configuration time
    rather than accepted and ignored. ECMP install (``RTA_MULTIPATH``) is
    planned for a later release.

``distance``
    ``external`` (default ``20``), ``internal`` (default ``200``).

``address-family``
    **Two nested keys, not one.** The address family is addressed as
    ``address-family.<afi>.<safi>`` - for example
    ``address-family.ipv4.unicast``, never ``address-family["ipv4 unicast"]``.
    Under a family: ``network``, keyed by prefix, each with ``import-check``
    and ``route-map``.

``neighbor``
    Keyed by neighbour address; see below.

BGP: neighbour
~~~~~~~~~~~~~~

Under ``router.bgp.<asn>.neighbor.<address>``:

Session identity and transport
    ``remote-as`` (**required**), ``local-as``, ``description``, ``shutdown``,
    ``passive``, ``update-source``, ``port`` (default ``179``).

Authentication
    ``password`` (TCP-MD5; a secret), and ``ao`` for kernel TCP-AO with
    ``key-chain`` (required if ``ao`` is present), ``send-id``, ``recv-id``,
    ``algorithm`` (``cmac-aes-128`` or ``hmac-sha1``) and ``fallback-md5``
    (default ``false``).

Reachability hardening
    ``ttl-security`` (GTSM), ``ebgp-multihop``.

Policy and attributes
    ``weight`` (default ``0``), ``allowas-in`` (default ``0``, maximum ``10``),
    ``sender-loop-check`` (default ``true``), ``next-hop-self``,
    ``remove-private-as``, ``as-override``, ``send-community`` (default
    ``true``).

    ``allowas-in`` is about what *this* router accepts: how many times its
    own AS may appear in a received path. It does not change what is sent.
    ``sender-loop-check`` is the outbound side: with it on, a path that
    already contains the peer's AS is not sent to that peer, which would
    drop it. Turn it off only for a peer configured to accept its own AS,
    for example a hub-and-spoke site with ``allowas-in`` on its side. Such a
    peer gets an update group of its own.

    ``remove-private-as`` takes ``true``, ``false`` or ``"all"``. ``true`` is
    IOS's plain form: private ASNs (RFC 6996) are removed only from a path
    made of nothing else, typically a customer's private AS behind this
    router, and a mixed public and private path is left alone. ``"all"``
    removes them from any path.

``advertisement-interval``
    Default **0**, deliberately. IOS defaults this to 30 seconds for eBGP; the
    engine does not. Update packing here comes from update groups and the
    batcher, not from an artificial delay, and a default delay mostly makes
    convergence measurements confusing. Set it explicitly if you want damping
    behaviour.

``maximum-prefix``
    ``limit``, ``warning-percent`` (default ``75``).

``timers``
    ``hold-time`` (default ``90``), ``keepalive``, ``connect-retry`` (default
    ``120``), ``delay-open`` (default ``0``).

``capability``
    ``route-refresh`` (default ``true``), ``extended-message``,
    ``add-path-receive``, ``graceful-restart``. ``route-refresh`` is RFC 2918
    route refresh. Enhanced Route Refresh (RFC 7313) is not advertised; a
    peer's BoRR or EoRR marker is ignored and counted under the neighbour's
    ``refresh-markers-in``, never answered as a request.

``address-family``
    **Neighbour-first.** Per-neighbour address-family settings live under the
    neighbour, not under the instance's address family:
    ``neighbor.<addr>.address-family.<afi>.<safi>``. Under it: ``activate``
    (default ``true``), ``route-map``, ``prefix-list`` and ``filter-list``
    (each taking ``in`` and/or ``out``), ``next-hop-self`` and ``next-hop``.
    A neighbour may only activate a family the instance carries (an
    ``address-family`` block under ``router.bgp.<asn>``, or IPv4 unicast when
    there is none). Activating any other family is a configuration error, as
    it is in IOS.

    ``next-hop`` is the address advertised in that family whenever rtengine
    sets the next hop itself: to every external peer, for its own
    ``network`` routes, and with ``next-hop-self``. Without it the next hop
    is ``update-source``, then the session's local address, when that is of
    the family's kind. An IPv6 family over an IPv4 session gets the
    IPv4-mapped form ``::ffff:a.b.c.d`` of the local IPv4 address, which is
    what FRR sends. A warning is logged once per neighbour, and ``show ip bgp
    neighbors`` reports it under ``next-hops`` with source ``ipv4-mapped``.
    Configure ``address-family.ipv6.unicast.next-hop`` with a global IPv6
    address to give such peers a next hop they can reach directly. The
    unspecified address ``::`` is never advertised.

Some neighbour keys cannot be changed without re-establishing the session -
``remote-as``, the authentication keys, and the transport settings among them.
The engine keeps an explicit set of session-affecting keys; changing one of
those resets the session, and changing anything else applies in place with no
session flap. Policy changes take effect through a refresh, not a reset.

A worked example
~~~~~~~~~~~~~~~~

.. code-block:: json

    {
      "ip": {
        "prefix-list": {
          "CUSTOMER-IN": [
            {"seq": 5, "action": "permit", "prefix": "198.51.100.0/24"},
            {"seq": 10, "action": "deny", "prefix": "0.0.0.0/0", "le": 32}
          ]
        },
        "route": {
          "install": true,
          "table": 254,
          "protocol": 190,
          "priority": {"ebgp": 20, "ibgp": 200},
          "retain-on-shutdown": false,
          "static": {
            "192.0.2.0/24": {"next-hop": "10.0.0.254", "distance": 1}
          }
        }
      },
      "route-map": {
        "SET-LP": [
          {"seq": 10, "action": "permit", "set": {"local-preference": 200}}
        ]
      },
      "router": {
        "bgp": {
          "65000": {
            "router-id": "10.0.0.1",
            "log-neighbor-changes": true,
            "bestpath": {"deterministic-med": true},
            "timers": {"hold-time": 90, "keepalive": 30},
            "address-family": {
              "ipv4": {
                "unicast": {
                  "network": {"203.0.113.0/24": {}},
                  "maximum-paths": 1,
                  "distance": {"external": 20, "internal": 200}
                }
              }
            },
            "neighbor": {
              "10.0.0.2": {
                "remote-as": 65001,
                "description": "customer A",
                "password": "correct-horse-battery",
                "ttl-security": 1,
                "remove-private-as": true,
                "maximum-prefix": {"limit": 5000, "warning-percent": 75},
                "address-family": {
                  "ipv4": {
                    "unicast": {
                      "activate": true,
                      "prefix-list": {"in": "CUSTOMER-IN"},
                      "route-map": {"in": "SET-LP"}
                    }
                  }
                }
              },
              "10.0.0.3": {
                "remote-as": 65000,
                "update-source": "lo0",
                "address-family": {
                  "ipv4": {"unicast": {"activate": true,
                                       "next-hop-self": true}}
                }
              }
            }
          }
        }
      },
      "api": {
        "bind": "127.0.0.1:8179",
        "auth": {"token-file": "/etc/rtengine/token"},
        "max-body-bytes": 1048576,
        "max-page": 10000
      }
    }

Revisions and atomicity
-----------------------

Every configuration change goes through the same four steps, whether it
arrives from ``configure()``, ``unconfigure()``, ``replace_config()`` or a REST
call:

1. **Validate.** The proposed document is checked against the core schema plus
   every registered plugin's schema. A document that fails validation is
   rejected whole; nothing is applied.
2. **Prepare.** The engine diffs current against proposed, then asks the core
   and every affected plugin to *prepare* the change. Prepare is where a
   subsystem does everything that can fail - allocating, resolving, checking
   feasibility - without committing to anything.
3. **Commit.** Once every prepare has succeeded, the engine commits, in turn,
   to the core and to each affected plugin.
4. **Roll back by inverse diff.** If a commit fails after earlier commits have
   already succeeded, the engine hands the already-committed subsystems the
   inverse diff to undo their part. This is best-effort by construction - a
   subsystem that failed to commit may also fail to un-commit - and it is
   logged and reported as best-effort rather than presented as a guarantee.

The engine carries a monotonically increasing ``revision`` counter. A change
that is a genuine no-op does **not** advance it.

All three mutating entry points take an optional ``if_revision``. If the
current revision does not match, the change is refused with
``PreconditionFailed`` and nothing is applied. Over REST this is the standard
``ETag`` / ``If-Match`` pair: read a resource, get its ``ETag``, send it back
as ``If-Match``, and get a ``412`` if somebody else changed the configuration
in between. This is the supported way for two operators, or two automation
systems, to share one engine.

Secrets and the keep-sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Secrets - neighbour passwords, the API token - are never emitted. Where a
secret is stored, ``running-config`` and the REST API return the literal string
``"<redacted>"``.

That would make ``running-config`` useless as input to ``replace_config`` if
the sentinel did not round-trip, so it does: writing ``"<redacted>"`` back into
a field that already holds a secret means *keep what is stored*. Writing it
into a field where nothing is stored is an error, not a silent no-op, because
that is almost always a configuration-management mistake rather than an
intention.

The practical consequence is that ``GET /running-config`` followed by an edit
and a ``PUT`` is safe, and never downgrades a password to the string
``<redacted>``.

REST API
--------

The API is mounted under ``/api/v1`` and described by an OpenAPI 3 document
which is served from the engine itself:

.. code-block:: bash

    $ curl -H 'Authorization: Bearer '"$TOKEN" \
        http://127.0.0.1:8179/api/v1/openapi.json

The document describes 31 paths and 61 operations. With ``--swagger-ui`` the
same document is browsable in a UI.

The spec, ``packets/routing/rtengine/api/openapi.yaml``, ships inside the
package. It is listed in both ``package_data`` and ``MANIFEST.in``, so a pip
install, a wheel or an RPM built from the sdist all serve
``/api/v1/openapi.json``. ``GET /engine/status`` reports the packets version,
which is set once in ``packets/_version.py``.

URL tree
~~~~~~~~

All paths below are relative to ``/api/v1``.

Engine and meta
    ``/``, ``/openapi.json``, ``/engine/status``, ``/engine/health``,
    ``/engine/plugins``, ``/engine/config-schema``

Whole-document configuration
    ``/running-config`` (``GET``, ``PUT``, ``POST``)

Core configuration
    ``/ip/prefix-list``, ``/ip/prefix-list/{name}``,
    ``/ipv6/prefix-list``, ``/ipv6/prefix-list/{name}``,
    ``/route-map``, ``/route-map/{name}``,
    ``/ip/route/static``, ``/ip/route/static/{prefix}``,
    ``/ipv6/route/static``, ``/ipv6/route/static/{prefix}``,
    ``/ip/route/install`` (``GET``, ``PATCH``)

BGP configuration
    ``/router/bgp``, ``/router/bgp/{asn}``,
    ``/router/bgp/{asn}/address-family``,
    ``/router/bgp/{asn}/address-family/{afi}/{safi}``,
    ``/router/bgp/{asn}/address-family/{afi}/{safi}/network``,
    ``/router/bgp/{asn}/address-family/{afi}/{safi}/network/{prefix}``,
    ``/router/bgp/{asn}/neighbor``,
    ``/router/bgp/{asn}/neighbor/{addr}``,
    ``/router/bgp/{asn}/neighbor/{addr}/address-family/{afi}/{safi}``

Operational
    ``/show``, ``/show/{command}``, ``/clear``, ``/clear/{command}``

``GET /show`` and ``GET /clear`` with no command enumerate the available
commands, which is how a client discovers the operational surface without
hard-coding it. ``/show/{command}`` and ``/clear/{command}`` take the rest of
the command as path segments, so ``show ip bgp summary`` is
``GET /api/v1/show/ip/bgp/summary``.

Authentication
~~~~~~~~~~~~~~

Authentication is a bearer token:

.. code-block:: bash

    $ curl -H 'Authorization: Bearer '"$TOKEN" \
        http://127.0.0.1:8179/api/v1/engine/health

The token comes from ``api.auth.token`` in the document or, preferably, from a
file named by ``api.auth.token-file`` or ``--token-file``. If both are
configured the file wins; that is not an error, because a deployment commonly
carries an inline token in a template and overrides it with a file on the box.
An unreadable token file at start-up is a refusal to start, not a fallback to
no authentication.

The file is watched while the engine runs. At most once a second a request
checks the file's inode, size and modification time, and reads the file again
only if one of them changed. To rotate the token, write the new one to a
temporary file and rename it over the old one. A rewrite that leaves the
file empty, unreadable or missing keeps the previous token in force and logs
a warning; it never opens the API. ``GET /engine/status`` counts reloads
under ``api.auth.reloads``.

Comparison uses ``hmac.compare_digest``, so the time it takes does not show
how many leading characters of a guess were right. It can show the token's
*length*, so use a long random token (a generated one is 40 characters) and
do not rely on the length being secret.

Every method needs the token, ``OPTIONS`` included. This API sends no CORS
headers, so there is no browser preflight to let through unauthenticated.

The bind address determines whether authentication is optional:

* Bound to loopback, with no token configured: the API serves unauthenticated.
  This is the development case, and the default bind is ``127.0.0.1:8179``.
* Bound to anything that is not loopback: you must either configure a token or
  set ``api.insecure: true``. There is no third option and no warning-and-
  continue. Exposing an unauthenticated routing control plane to a network
  should require you to write the word ``insecure`` down.

The loopback test errs towards "not loopback" when it cannot tell, and accepts
the name ``localhost`` without resolving it.

``api.auth.allow-unauthenticated-health`` (default ``false``) exempts
``GET`` (and ``HEAD``) of ``/engine/health`` from authentication, for
supervisors and load balancers that cannot carry a token. Other methods on
that path still need it.

Token rotation does not need a restart. Authentication settings, ``max-page``
and ``max-body-bytes`` are re-read whenever the configuration revision changes,
and a token file is re-read when it changes on disk (see above).

TLS, and the reverse-proxy boundary
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Setting ``api.tls.cert`` and ``api.tls.key`` serves the API over TLS in
process. Both must be set or neither; one alone is a configuration error.

That is the whole of the TLS surface. There is no client-certificate support,
no cipher suite configuration, no renegotiation policy and no protocol version
selection. This is deliberate. The in-process TLS exists so that a simple
deployment does not have to run a proxy to avoid sending a bearer token in
clear text over a management network. **Anything beyond that is a reverse
proxy's job**, and running the engine behind nginx, HAProxy or Apache is the
supported answer for mutual TLS, cipher policy, rate limiting, request logging
or certificate rotation without a restart. Bind the engine to loopback and let
the proxy own the network-facing socket.

Limits, pagination and errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A request body larger than ``api.max-body-bytes`` (default 1 MiB) is rejected
with ``413``. A body with no ``Content-Length`` - a chunked upload - is read
only up to one byte past the limit and then rejected the same way, so the
limit holds whether or not the client declares a length. Collection endpoints
accept ``limit`` and ``offset``; ``limit``
is capped at ``api.max-page`` (default ``10000``). A ``limit`` of ``0`` is
**rejected as invalid**, not silently treated as unlimited and not silently
capped - an explicit zero is far more often a bug in the caller than a request
for an empty page.

Every error has the same envelope:

.. code-block:: json

    {
      "error": "NotFound",
      "detail": "no such neighbor: 10.0.0.9",
      "path": "/api/v1/router/bgp/65000/neighbor/10.0.0.9"
    }

The ``error`` token maps onto the status code:

====================== ======
``Invalid``            400
``Unauthorized``       401
``NotFound``           404
``MethodNotAllowed``   405
``Conflict``           409
``PreconditionFailed`` 412
``PayloadTooLarge``    413
``ApplyFailed``        500
``Error``              500
``Unavailable``        503
``Timeout``            504
====================== ======

Errors raised by the framework itself - a bad method, a malformed URL - are
rendered into the same envelope, so a client never has to parse two error
formats or an HTML error page.

A key in a URL that cannot be valid is a ``400 Invalid`` whose detail says
why: ``/neighbor/10.0.0.256``, ``/ip/route/static/192.0.2.0/33``,
``/router/bgp/0``. A well-formed key that is not configured is still a
``404``. The difference tells you whether to fix the URL or the configuration.

``503 Unavailable`` means one of two things. Either the engine is not
running, or 64 API commands are already queued or running on its loop. In
the second case the response carries ``Retry-After: 1``. A command counts
against the 64 until it finishes, even if its own request has already timed
out. ``GET /engine/status`` reports ``in_flight``, ``max_in_flight`` and
``refused`` under ``api.bridge``.

Why ``POST /clear/ip/bgp/{addr}`` is a 404
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Clearing a neighbour is ``POST /api/v1/clear/ip/bgp/neighbor/{addr}``. The
shorter, more obvious-looking ``POST /api/v1/clear/ip/bgp/{addr}`` returns a
``404`` whose detail points at the correct path. This is deliberate, and it is
worth understanding why, because it looks like an oversight.

``clear ip bgp`` takes trailing directives - ``soft``, ``in``, ``out``. The
command dispatcher resolves a clear URL by longest registered prefix. If a bare
address were accepted directly under ``clear/ip/bgp``, then the segment after
``bgp`` would be ambiguous between "an address" and "a directive", and the
failure mode is not a clean error: a mistyped or unexpected segment would be
read as a soft directive and would soft-clear **every** session, at a moment
when the operator believed they were clearing exactly one peer. Requiring the
``neighbor`` segment removes the ambiguity entirely. Clear URLs are resolved
against the enumerated clear paths *before* dispatch, so a mistyped segment is
a ``404`` rather than an unintended action.

Security posture
----------------

**Bind.** The default bind is ``127.0.0.1:8179``. A non-loopback bind requires
a token or an explicit ``insecure: true``; see `Authentication`_.

**Secrets.** Neighbour passwords, TCP-AO key material and the API token are
never printed. They do not appear in ``show`` output, in ``running-config``, in
``GET /running-config``, in the OpenAPI examples, or in logs at any log level,
including debug. What you get instead is ``"<redacted>"``, which round-trips
(see `Revisions and atomicity`_).

**TCP-MD5 and TCP-AO.** ``neighbor.<addr>.password`` configures classic TCP-MD5
(RFC 2385) through the kernel socket option. ``neighbor.<addr>.ao`` configures
kernel TCP-AO (RFC 5925), which needs a kernel that supports it.

TCP-AO **fails closed**. If AO is configured and the kernel cannot provide it,
the session does not come up. It does not quietly downgrade to MD5, and it does
not quietly come up unauthenticated - either would turn a security control into
a suggestion. The single exception is explicit: ``ao.fallback-md5: true``
*together with* a configured ``password`` allows a fall back to MD5. Both are
required. ``fallback-md5`` with no password is a configuration error, not a
fall back to nothing.

Peers where authentication could not be established are counted separately and
listed in health output under ``auth-blocked``, so a fail-closed session does
not look like an ordinary session that happens to be down.

**GTSM.** ``ttl-security`` implements the Generalized TTL Security Mechanism
(RFC 5082): packets arrive with a TTL high enough to prove the peer is within
the configured number of hops. It is the cheapest defence available against
off-path spoofing of a BGP session, and it costs nothing at runtime. It is
mutually exclusive with ``ebgp-multihop`` in the usual way.

The inbound TTL floor (``IP_MINTTL`` / ``IPV6_MINHOPCOUNT``) belongs to the
listening socket, not to a neighbour, and the kernel checks the SYN before
``accept`` says who sent it. A listener therefore serves either neighbours
that all use ``ttl-security`` or neighbours that all do not: a configuration
that mixes the two on one ``listen`` address is rejected, naming both sets,
because no setting of the floor could protect either handshake.

**Closing a session.** Every close puts a NOTIFICATION on the wire first,
then half-closes the connection and reads until the peer closes its side
(bounded at one second), so the peer sees the reason followed by an orderly
end of stream rather than a reset. The Cease subcodes follow RFC 4486:

=============================  ==========================================
What happened                  NOTIFICATION
=============================  ==========================================
engine stop (SIGTERM)          Cease / Administrative Shutdown (6/2)
neighbour deleted              Cease / Peer De-configured (6/3)
hard ``clear``                 Cease / Administrative Reset (6/4)
session-affecting change       Cease / Other Configuration Change (6/6)
connection collision loser     Cease / Connection Collision Resolution (6/7)
hold timer expired             Hold Timer Expired (4/0)
=============================  ==========================================

Connection collisions are settled by BGP identifier (RFC 4271 s6.8): a second
connection is held, runs its own OPEN exchange, and whichever connection the
identifiers favour survives; the other hears Cease/7. A second connection to an
Established session is always the one refused.

**Malformed and out-of-contract messages.** Inbound UPDATEs are judged by the
RFC 7606 matrix, with these rules worth knowing:

* An UPDATE that announces prefixes, whether in the classic NLRI field or in
  MP_REACH_NLRI, must carry ORIGIN and AS_PATH; NEXT_HOP is required only for
  classic NLRI. A missing one withdraws the announced prefixes
  (treat-as-withdraw). Attributes are never invented to fill the gap.
* An MP_REACH_NLRI or MP_UNREACH_NLRI for an address family the session did
  not negotiate is ignored and counted under the neighbour's errors (reason
  ``unnegotiated-family``), and logged once per family per session. The
  session stays up. An MP attribute whose prefixes cannot be parsed, or whose
  flags are not optional non-transitive, still resets the session.
* LOCAL_PREF is well-known *discretionary*. An internal peer that omits it is
  not in error, and the default local preference applies.
* Bits set past the prefix length in an NLRI entry are masked off, as RFC 4271
  allows, and counted in ``nlri-host-bits`` in ``show ip bgp neighbors``.
* Every message type has its own length rule: a KEEPALIVE is exactly 19
  bytes, an OPEN 29 to 4096 bytes even with Extended Message, an UPDATE at
  least 23, a NOTIFICATION at least 21 and a ROUTE-REFRESH at least 23. A
  violation draws NOTIFICATION 1/2 carrying the offending length, and an
  unknown type draws 1/3 carrying the type.
* An OPEN is graded per RFC 4271 s6.2: 2/1 for a version other than 4
  (data ``0x0004``), 2/2 for the wrong AS, 2/3 for a zero identifier or an
  internal peer using ours, 2/4 for a non-capability optional parameter, 2/6
  for a hold time of 1 or 2, and 2/0 (Unspecific) for an OPEN that cannot be
  parsed.

rtengine never sends RFC 9072 extended optional parameters, because the OPEN
goes out before anything is known about whether the peer can read them. It
reads them correctly when a peer sends them.

**Privileges.** Two things need privilege, and only those two:

* Listening on TCP 179 needs ``CAP_NET_BIND_SERVICE`` or root. Configure
  ``listen.port`` to something above 1024 to peer without it, where the peer
  can be told to use a different port.
* Installing routes into the kernel needs ``CAP_NET_ADMIN``. Without FIB
  install, the engine needs no capabilities at all.

Neither is required for a control-plane-only deployment listening on a high
port, which is the deployment we recommend where the peer permits it.

The Flask floor
~~~~~~~~~~~~~~~

The ``packets[rtengine]`` extra declares::

    Flask>=3.1
    Werkzeug>=3.1
    PyYAML>=6.0

These are a **floor, not a pin**: the AlmaLinux 10.2 platform ships Flask
3.1.2, Werkzeug 3.1.3 and PyYAML 6.0.1 as RPMs, and an ``==`` would either
replace a platform-managed package or make the extra uninstallable where it is
needed. (The 2.3.x line, for AlmaLinux 8.x, floors at Flask 0.12.)

Two design choices from the 0.12 era remain, because they are still right:

* Authentication, the body-size limit and the pagination cap are implemented in
  our own code, not in framework middleware or a third-party extension, so
  their behaviour does not depend on the framework version.
* The framework surface is deliberately small - blueprints, a request object, a
  response object.

The operational guidance is unchanged: bind to loopback and put a maintained
reverse proxy in front of anything network-facing; see `TLS, and the
reverse-proxy boundary`_.

Operations
----------

``show``
~~~~~~~~

``show`` is a command tree. The core registers:

* ``show ip route``
* ``show ipv6 route``
* ``show ip prefix-list``
* ``show ipv6 prefix-list``
* ``show ip as-path-access-list``
* ``show route-map``
* ``show engine status``
* ``show engine health``
* ``show running-config``

and each plugin registers its own - the BGP plugin adds the ``show ip bgp``
subtree. Dispatch is by longest registered prefix, so a plugin can register
``ip bgp`` and receive everything below it.

From python:

.. code-block:: python

    print(engine.show('ip', 'bgp', 'summary'))
    print(engine.show('engine', 'status'))

Over REST, the same commands are path segments:

.. code-block:: bash

    $ curl -H "Authorization: Bearer $TOKEN" \
        http://127.0.0.1:8179/api/v1/show/ip/bgp/summary

``engine.show_paths()`` and ``GET /api/v1/show`` enumerate what is available.

``clear``
~~~~~~~~~

``clear`` follows the same dispatch rules and the same enumeration through
``engine.clear_paths()`` and ``GET /api/v1/clear``.

The important argument is ``soft``. A soft clear re-applies policy without
tearing down the session; a hard clear resets the session. ``soft`` takes
``in``, ``out`` or ``both``. A bare truth value - ``soft=True``, or ``soft``
with no value in a URL - means ``in``, which is both the IOS convention and the
safe reading: an inbound soft clear re-evaluates what you have already received
and cannot cause the peer to resend anything.

.. code-block:: python

    engine.clear('ip', 'bgp', 'neighbor', '10.0.0.2')
    engine.clear('ip', 'bgp', 'neighbor', '10.0.0.2', soft='in')
    engine.clear('ip', 'bgp', 'neighbor', '10.0.0.2', soft='both')

Health
~~~~~~

``GET /api/v1/engine/health``, ``show engine health`` and ``Engine.health()``
all return the same document:

``status``
    The roll-up: ``ok``, ``degraded`` or ``down``. It is the worst status among
    all contributors, so one unhealthy subsystem is visible in one field.

``pid``, ``uptime_s``, ``rss_bytes``
    Process facts. ``rss_bytes`` is normalised: ``ru_maxrss`` is kilobytes on
    Linux and bytes on macOS, and the engine corrects for that so the field
    means the same thing on both.

``loop``
    ``status``, ``running``, ``lag_ms``, ``mean_lag_ms``, ``max_lag_ms``,
    ``lag_threshold_ms`` (default ``50.0``), ``probes``, ``over_threshold``,
    ``stalled_ms``. Loop lag is measured by a probe that records how late it
    was scheduled: it is the single best indicator that the control plane is
    falling behind. ``stalled_ms`` is how overdue the *next* probe is at the
    moment the document is built, which is how a loop that has stopped
    running callbacks altogether shows up to a caller on another thread.

``batches``
    Batcher statistics - how work is being coalesced.

``peer_flaps``, ``recent_peer_flaps``
    Sessions that went down while they were meant to be up: the lifetime
    count, and the count inside the last five minutes. An administrative
    stop, a ``shutdown`` or a deleted neighbour is not a flap. A flapping
    peer is not down, but it is not healthy either.

``commands.queued``
    Depth of the command queue into the loop.

``events``
    Event-bus counters, including per-subscription drops.

``rib``, ``resolver``, ``fib``
    RIB sizes, next-hop resolution state, and FIB install state including
    per-route errors.

Plus a block per registered plugin.

What degrades the status:

* Loop lag over ``lag_threshold_ms`` on the latest probe (so sustained lag
  keeps it degraded).
* Loop lag over ten times ``lag_threshold_ms`` on three consecutive probes,
  or a probe overdue by three intervals, is ``down``: a loop that busy cannot
  keep sessions alive. A single spike stays ``degraded``.
* Any peer flap in the last five minutes; it ages out by itself.
* Event-queue drops, or an exception raised by a subscriber callback.
* FIB install errors.
* A stopped engine, which is ``down``.
* For BGP, ``auth_blocked`` peers force at least ``degraded``.

One wrinkle to know about
"""""""""""""""""""""""""

The BGP plugin reports ``down`` when it has peers configured and **none** of
them are established - that is, ``total > 0 and up == 0``. This is the right
answer for a running router that has lost every session. It is also, briefly,
the answer at start-up, before the first session has come up, on a perfectly
healthy engine.

So a supervisor that polls ``/engine/health`` immediately after boot can see
``down`` on an engine that is fine and will be ``ok`` a few seconds later. If
you are wiring this into a process supervisor or an orchestrator readiness
probe, give it a start-up grace period, or require several consecutive ``down``
results before acting. This is a known wrinkle rather than a deliberate design
and may change; do not build anything that depends on the start-up ``down``
being present.

FIB install
-----------

Kernel FIB install is **off by default**; the default sink is a null sink that
accepts routes and writes nothing, and reports every selected route as
``not-installed`` so ``show ip route`` does not suggest traffic will follow
it. Enable install with ``ip.route.install: true``, in the configuration file
or at runtime with ``PATCH /ip/route/install``; both take the same path. It
is Linux-only, over netlink.

The engine builds the sink itself from ``ip.route``, as part of the same
transaction that applies the rest of the configuration:

* While ``install`` is off there is no netlink object at all, and no socket.
* Turning it on opens a socket and installs every route that is already
  best; turning it off withdraws everything the engine installed, at once.
* Changing ``table``, ``protocol`` or ``priority`` builds a new sink: the old
  routes are withdrawn, then the current ones installed under the new
  identity. ``retain-on-shutdown`` and the static routes do not.
* If the kernel refuses the socket, the whole commit is rolled back - the
  plugins and the stored configuration included - and the old sink keeps
  running.
* Nothing is opened before the engine starts, so ``rtengine --check`` never
  touches the kernel.

An embedder that passes ``Engine(sink=...)`` keeps that sink: it is never
replaced, only opened and closed with ``install``, and asking a sink that
cannot write to install is a ``409`` conflict.

Only routes learned from a neighbour are offered to the kernel. A
``network`` statement (or an aggregate) is BGP's copy of a route that is
already in the system under its own protocol; it is advertised but never
installed. ``local-unoffered`` in the BGP table statistics counts them.

Route ownership
~~~~~~~~~~~~~~~

Two fields make a route ours:

``rtm_protocol``
    Default ``190``, configurable via ``ip.route.protocol``. This is the
    conventional "who installed this" marker.

``rtm_priority``
    ``20`` for external routes and ``200`` for internal, from
    ``ip.route.priority.ebgp`` and ``ip.route.priority.ibgp`` - the same
    numbers as the default administrative distances, so kernel preference and
    engine preference agree.

Both are load-bearing, and this is the part that surprises people. The kernel's
identity for a route is ``(table, dst, tos, priority)`` - the protocol field is
*not* part of it. So priority alone is not enough to tell our route from
someone else's, and protocol alone is not enough to address a route uniquely in
the kernel. The engine needs both: protocol to decide whether a route is ours
to touch, and priority to address the right one. Changing ``priority`` while
routes are installed therefore changes their identity, and is treated
accordingly.

Reconciliation, withdrawal and errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

At start-up the engine dumps the table and reconciles: leftovers from a
previous run that match what it intends to install are **adopted** rather than
deleted and re-added, and the rest of our leftovers are removed. A crash
followed by a restart therefore does not blackhole traffic while routes are
torn down and rebuilt, and it does not leave stale routes behind.

At shutdown the engine withdraws everything it installed, unless
``ip.route.retain-on-shutdown`` is ``true``. Retaining is the right choice when
something else will take over, or when an engine restart should not be a
traffic event; it also means stale routes survive a crash until the next
start-up reconciliation cleans them up.

A route the kernel rejects gets a per-route ``fib-error`` carrying the errno,
and is retried with exponential backoff from 1 second up to a 60-second
ceiling. It does **not** roll back other routes and it does not fail the
commit. One route the kernel will not accept - an unreachable next hop, a
conflicting route from another daemon - should not take down the installation
of everything else.

The socket asks for netlink extended acks (Linux 4.12+), so the kernel's own
explanation - ``Nexthop has invalid gateway`` rather than a bare
``ENETUNREACH`` - is logged and shown as ``fib.last-error.message`` in
health. The engine keeps flushing the sink until it is idle, so a full table
reaches the kernel without waiting for some later route change to push the
rest of the queue.

Capabilities
~~~~~~~~~~~~

FIB install needs ``CAP_NET_ADMIN``. The engine reads ``CapEff`` from
``/proc/self/status`` and checks bit 12, falling back to a euid check if that
is unavailable. ``install: true`` is validated against that probe when it is
configured, so the three distinct failures - wrong platform, no netlink, no
capability - are three distinct ``400`` messages instead of every route
ending up in ``fib-error`` with an opaque ``EPERM``. Tables ``0`` (unspec)
and ``255`` (local) are refused as install targets.

Embedding API
-------------

``Engine`` is the whole of the public embedding surface. The REST layer calls
these methods and nothing else.

``Engine(config=None, loop=None, sink=None, plugins=())``
    Build an engine. Supplying ``plugins`` at construction is the usual way.
    Leave ``sink`` out to have the engine build its forwarding sink from
    ``ip.route``; see FIB install.

``register_plugin(plugin)``
    Register a ``ProtocolPlugin`` after construction. Do this before
    configuring, so the plugin's schema is available to validation.

``start(timeout=5.0)`` / ``stop(timeout=5.0, retain_fib=None)``
    Start the engine in its own thread with its own loop, or stop it. ``stop``
    withdraws installed routes unless retained. A plugin that fails to start
    fails ``start()``: the plugins that had started are stopped again, and
    the engine is not left reporting itself as running.

``run_forever()``
    Run the loop in the calling thread instead, until ``stop()``. ``start()``
    is usually what you want; the console script uses ``start()`` so that
    signals land on the main thread. A loop ``run_forever`` created is shut
    down and closed when it returns; one passed to the constructor is stopped
    but left open for its owner.

``configure(path, value, if_revision=None)``
    Set one subtree, addressed by path.

``unconfigure(path, if_revision=None)``
    Remove one subtree.

``replace_config(document, if_revision=None)``
    Replace the whole document.

``running_config(redact=True)``
    The configuration as configured, with secrets replaced by ``<redacted>``.

``revision``
    The current revision counter.

``show(*path, **kwargs)`` / ``clear(*path, **kwargs)``
    Run an operational command.

``show_paths()`` / ``clear_paths()``
    Enumerate the operational surface.

``status()``
    Name, version, running flag, revision, plugins, FIB state, policy state,
    table sizes and ``api.bind``.

``health()``
    The health document described in `Health`_.

``subscribe(event='*', q=None, maxsize=10000, overflow='drop-oldest', name=None)``
    Subscribe to the event bus.

``plugins`` / ``plugin(name)``
    The registered plugins.

Events
~~~~~~

The event types are ``route-best``, ``route-withdraw``, ``peer-state``,
``fib-result``, ``config-change`` and ``engine-state``; ``'*'`` subscribes to
all of them.

A ``config-change`` event carries the new revision and the list of changes,
each as ``path``, ``old`` and ``new``. A side that did not exist is left out,
so a removal has no ``new``. Secrets are redacted to ``"<redacted>"``. That
applies to a change to the secret itself, such as a new ``api.auth.token``,
and to a change that contains one, such as adding a whole neighbour with a
``password``. A subscriber can see that a secret changed, but not what it is.

Subscriptions are **bounded queues**. This is the central design decision of
the event bus: the bus never blocks. A slow or stalled consumer cannot apply
back-pressure to a protocol thread, because a routing control plane that stops
processing updates because a log shipper is slow is worse than a log shipper
that misses entries.

``maxsize`` bounds the queue (default ``10000``) and ``overflow`` decides what
happens when it is full: ``drop-oldest`` (the default) or ``drop-newest``.
Drops are **counted, and surfaced in health**, so a consumer that cannot keep
up is visible rather than silently lossy.

.. code-block:: python

    sub = engine.subscribe('peer-state', maxsize=500,
                           overflow='drop-newest', name='auditor')

    ev = sub.get(timeout=0.5)      # None on timeout
    pending = sub.drain()          # list of everything queued right now

Synchronous callbacks also exist, but they are an engine-internal mechanism:
they run on the engine's own thread, must not mutate RIB state and must not
raise. If you are embedding, use a subscription.

Writing a protocol plugin
-------------------------

A protocol implements ``ProtocolPlugin``. The contract is that the plugin owns
its protocol - its own RIB, its own best-path algorithm, its own timers and
state machine - and hands the core protocol-neutral ``Route`` candidates
(prefix, next hop, administrative distance, metric). The ``GlobalRib`` selects
across protocols by administrative distance. The core never learns what a
``LOCAL_PREF`` is, and the plugin never learns how routes get into the kernel.

The methods:

``afi_safi()``
    Which address families this plugin handles.

``config_schema()``
    The configuration section this plugin owns - the section key, its schema,
    and any constraints such as a maximum number of keys. This is what makes
    ``router bgp`` validate.

``prepare_config(section, diff)``
    Do everything that can fail. Do not commit.

``commit_config(section, diff)``
    Commit. This should not fail; if it does, the engine will hand the
    already-committed subsystems an inverse diff on a best-effort basis.

``policy_changed(store)``
    Core policy objects - prefix lists, route maps - changed. Re-evaluate.

``start(engine)`` / ``stop()``
    Lifecycle, called with the engine available.

``show_handlers()`` / ``clear_handlers()``
    Register operational command subtrees. Registration is by prefix and
    dispatch is longest-match, so returning ``ip bgp`` claims everything below
    it.

``health()``
    The plugin's contribution to the health roll-up. Return a status no better
    than the truth: the roll-up takes the worst.

``validate()``
    Self-check.

Splitting configuration into ``prepare_config`` and ``commit_config`` is what
makes an all-or-nothing apply possible across an arbitrary set of plugins, so a
plugin that does real work in ``commit_config`` weakens the guarantee for
everybody. Put the work in prepare.

Limitations and non-goals
-------------------------

Not implemented in this version:

* Only BGP-4. No OSPF, IS-IS, RIP or any IGP.
* No MPLS, no L3VPN or EVPN address families, no VRFs.
* No RPKI / RTR origin validation.
* No BMP.
* No BFD.
* No flowspec.
* No add-path *send* (add-path receive is negotiable).
* No ``default-originate``.
* No ``continue`` in route maps.
* No graceful restart *helper* beyond capability negotiation.
* No IPv6 kernel install subtree of its own - the ``ip.route`` knobs cover both
  families.

Two known gaps in the shipped behaviour, deliberately left as they are for this
version and recorded here because they are visible from outside:

* **Unsupported query parameters on BGP show handlers.** A query parameter that
  a BGP ``show`` handler does not understand is ignored, and the handler
  returns ``200`` with an unpaged result, rather than rejecting the request.
  If you send ``limit`` or ``offset`` to a BGP show endpoint, you may get the
  whole result set. Do not assume pagination applies to the ``show ip bgp``
  subtree.
* **Readiness is signalled before the server accepts.** The API server sets its
  readiness event immediately *before* calling ``serve_forever()``, not after.
  The listening socket is bound earlier, in ``start()`` - which is why a port
  conflict or a privileged port is reported synchronously rather than swallowed
  by the server thread - so connections are queued by the kernel and not
  refused. But a client that races the readiness signal very aggressively can
  connect before the server loop is accepting. Retry the first request.

Note that ``remove-private-as`` and ``as-override`` **are** implemented and
supported; they are configured per neighbour and are part of update-group
identity. ``NO_EXPORT_SUBCONFED`` is honoured like ``NO_EXPORT``: with no
confederations, every external peer is outside the member AS. A route whose
attributes cannot be encoded within the session's message size is not sent,
is counted under ``encode-error`` in ``show ip bgp update-groups``, and is
withdrawn if the peer held an earlier version. With an
``advertisement-interval``, withdrawals are sent at once and announcements
wait out the interval, even when both are pending.

Differences from IOS
--------------------

The configuration uses IOS keywords, so an operator who knows IOS will expect
IOS behaviour. These are the places where rtengine behaves differently. Each
one is either refused when it is configured or documented here, so none of them
fails silently.

**Refused when configured.**

* ``route-map ... continue``. Clauses are evaluated in sequence order and the
  first match decides. Writing ``continue`` is refused with a message saying so.
* ``maximum-paths`` greater than 1. ECMP install (``RTA_MULTIPATH``) is not
  implemented yet, so multipath is refused rather than accepted and ignored.
* A neighbour that activates an address family its ``router bgp`` instance
  does not carry.
* A neighbour password where the kernel has no TCP-MD5, and TCP-AO where the
  kernel has no TCP-AO (unless ``ao.fallback-md5`` is set).
* ``set as-path prepend 0``.
* An AS-path regex that could stall the engine on a long path; see
  `AS-path regexes`_.
* Two neighbours that share a listening address but disagree about GTSM
  (``ttl-security``). The kernel's minimum-TTL option belongs to the socket,
  so one listener cannot apply it to some peers and not others.

**Not available.**

* Named or numbered community-lists (``ip community-list``). A route-map
  ``match community`` takes its communities inline, with ``exact-match`` as an
  option.
* Confederations, route reflection, ``default-originate``, add-path *send*,
  and the graceful restart *helper* (the capability is negotiated, and that
  is all).
* Enhanced Route Refresh (RFC 7313). Plain route refresh is supported.
* There is no CLI. Configuration is a JSON document, changed through the REST
  API, and every command has a URL; see `REST API`_.

**Behaves differently.**

* Communities are sorted and duplicates removed when a route is learned, as
  FRR does. A peer that sent ``65000:2 65000:1 65000:1`` sees ``65000:1
  65000:2`` passed on.
* ``remove-private-as`` strips private ASNs only when the whole path is
  private, as IOS does without ``all``. ``remove-private-as: "all"`` strips
  every private ASN.
* ``allowas-in`` affects only what is accepted. The outbound check - not
  sending a path to a peer whose AS is already in it - is a separate knob,
  ``sender-loop-check``, on by default. IOS has no knob for it.
* An IPv6 route sent over an IPv4 session with no IPv6 next hop configured
  gets the IPv4-mapped address (``::ffff:a.b.c.d``) and a warning, as FRR
  does. IOS would need a route-map. ``::`` is never sent.
* Neighbour timers inherit the instance's ``timers``, and a neighbour's own
  value wins, as in IOS. An instance with no ``timers`` uses 90/30.
* ``maxas-limit`` is on by default, at 255 ASNs. IOS has no limit until one
  is configured. Raising it above 255, or turning it off, narrows which
  AS-path regexes are accepted; see `AS-path regexes`_.
* The API's own access control is a bearer token, not AAA; see
  `Authentication`_.

Platform notes
--------------

**Python.** The floor is Python 3.12, the AlmaLinux 10.2 platform version.
The 2.3.x releases are the line for AlmaLinux 8.x and Python 3.6.8.

**Cython.** The extensions build with Cython 3.0.9, likewise the platform
version, and with ``-Werror`` on GCC 14.

**Linux-only paths.** Netlink FIB install, TCP-MD5 and kernel TCP-AO are Linux
kernel features. On macOS the engine runs as a control-plane speaker: the
protocol machinery, policy, RIB and API all work, FIB install is unavailable,
and TCP-AO is unavailable. Kernel TCP-AO needs Linux 6.7 or later; on an older
kernel, which has TCP-MD5 but not TCP-AO, AO's fail-closed behaviour is what
applies.

Running the tests
~~~~~~~~~~~~~~~~~

Run the suite from the checkout root, after building the extensions in place
(``python3 setup.py build_ext --inplace``). Either runner works:

.. code-block:: bash

    $ python3 -m unittest discover -s test
    $ python3 -m pytest -q test/

Both find the same tests. Running from another directory, or before the
extensions are built, gives import errors, or a run that quietly tests an
installed copy instead (see the next paragraph).

A related trap: if a ``packets`` RPM is installed on the machine, it sits in
``site-packages`` and **shadows your checkout** for a script run as
``python3 bench/...`` or any other script outside the package. The symptom is
confusing - your changes appear to have no effect - and the fix is to be
explicit:

.. code-block:: bash

    $ PYTHONPATH=. python3 bench/rtengine_bench.py

Check which one you actually imported if anything looks stale:

.. code-block:: bash

    $ python3 -c "import packets; print(packets.__file__)"
