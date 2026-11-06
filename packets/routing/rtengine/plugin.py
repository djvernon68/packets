# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""``ProtocolPlugin``: the only thing the core knows about a protocol.

The core owns the trie, the protocol-neutral route table, the ``GlobalRib``,
policy primitives, the FIB sink, health and the API mounting. It does not know
what BGP is. A protocol arrives as a plugin that:

* declares which configuration section it owns and what belongs in it;
* validates a pending change to that section before anything is applied, and
  applies it afterwards -- two separate calls, which is what makes a
  configuration change atomic across several plugins;
* runs its own protocol RIB and its own best-path algorithm, and offers the
  winners to the ``GlobalRib`` as protocol-neutral ``Route`` candidates;
* answers ``show`` and ``clear`` requests for its own vocabulary;
* reports its own health.

There is deliberately **no** ``path_comparator`` hook. An earlier shape of
this interface had the core compare paths on the plugins' behalf, which meant
the core needed somewhere to keep BGP's attributes and one comparator had to
serve protocols whose selection rules have nothing in common -- BGP's
tie-break ladder, OSPF's SPF, RIP's hop count. Each plugin selects for itself
and hands over winners; the core only ever chooses *between* protocols, by
administrative distance. That is the boundary that lets OSPF and RIP be added
without the core changing.

Everything here runs on the engine's loop thread. A plugin must not block it:
no synchronous socket reads, no ``time.sleep``, and every bulk job through a
``Batcher`` so the loop gets control back. A plugin that blocks the loop stops
every other protocol's timers too.
"""


class ProtocolPlugin(object):
    """Base class for a routing protocol.

    Subclasses set :attr:`name` and :attr:`config_section` and override the
    methods they need. The defaults are all inert, so a minimal plugin is
    genuinely minimal: a name, a section, and whatever it actually does.

    :param engine: set by :meth:`start`; None until then.
    """

    #: Short protocol name, as it appears in configuration, ``show`` paths,
    #: health output and log lines. Required.
    name = None

    #: The configuration path this plugin owns, as a tuple of keys --
    #: ``('router', 'bgp')`` for BGP. The engine routes a configuration diff
    #: to a plugin by matching this prefix, so two plugins claiming
    #: overlapping sections is a registration error rather than a race.
    config_section = ()

    #: The rtengine protocol id from ``rib.table`` (``RT_PROTO_BGP`` and
    #: friends), used on every ``Route`` this plugin offers and as the last
    #: selection tie-break. Required for a plugin that offers routes.
    protocol_id = 0

    #: Default administrative distances this plugin offers routes at.
    #: Conventionally keyed by whatever distinctions the protocol makes --
    #: BGP uses ``{'external': 20, 'internal': 200}``. Configuration may
    #: override them; the plugin, not the core, decides which key applies to
    #: a given route.
    admin_distance = {}

    def __init__(self):
        self.engine = None

    # --- identity ----------------------------------------------------------

    def afi_safi(self):
        """Return the address families this plugin needs tables for.

        The engine creates a protocol-neutral ``RouteTable`` for every pair
        any plugin asks for, so a plugin that will never carry IPv6 does not
        cause an empty IPv6 table to exist.

        :return: an iterable of ``(afi, safi)`` tuples.
        """
        return ()

    def config_schema(self):
        """Return the schema for this plugin's configuration section.

        The same document drives validation in ``config.py`` and the
        request bodies in the OpenAPI specification, so the API and the
        engine cannot disagree about what a valid neighbour looks like. See
        ``config.py`` for the node vocabulary.

        :return: a schema dict, or None if the section takes anything.
        """
        return None

    # --- configuration, in two phases --------------------------------------

    def prepare_config(self, section, diff):
        """Validate a pending change without applying any of it.

        Must be **pure**. The engine calls this on every affected plugin
        before it calls :meth:`commit_config` on any of them, so that a
        change rejected by the last plugin leaves the first one untouched.
        Raise :class:`~packets.routing.rtengine.errors.ConfigError` to
        reject; the running configuration and its revision do not move.

        Anything that can be checked belongs here rather than in the
        commit: a commit that fails is the expensive case, because it
        leaves the engine rolling other plugins back.

        :param section: this plugin's section of the *proposed* document.
        :param diff: the :class:`~packets.routing.rtengine.config.Diff` for
            this section.
        :raises ConfigError: the change is not acceptable.
        """

    def commit_config(self, section, diff):
        """Apply a change that every plugin has already accepted.

        May also be called with an inverse diff, as best-effort rollback
        when a later plugin's commit failed -- so it should be written to
        be applicable in either direction, and should do its irreversible
        work (resetting a session) last.

        :param section: this plugin's section of the *new* document.
        :param diff: the :class:`~packets.routing.rtengine.config.Diff` for
            this section.
        """

    def policy_changed(self, store):
        """React to an edited prefix-list, as-path list or route-map.

        Called after a commit in which the engine's policy store changed,
        and *only* then. It exists because policy is configured outside
        every plugin's section -- ``ip prefix-list`` and ``route-map`` are
        core keys -- so an edit to a filter a plugin is using reaches no
        ``commit_config`` at all, and a plugin that only rebuilt its
        policy there would go on filtering by the previous version until
        something unrelated happened to touch its own section.

        Implementations should rebuild whatever they compiled from the
        store and re-evaluate what the change affects. They should not
        assume the change is relevant to them: the store cannot know which
        plugin named which object, so every plugin is told and each
        decides.

        The default does nothing, which is correct for a protocol that
        does not use policy.

        :param store: the engine's
            :class:`~packets.routing.rtengine.policy.store.PolicyStore`.
        """

    def longest_as_path(self, section):
        """The longest AS path, in ASNs, this plugin will hand to policy.

        The core judges an AS-path regex by how its cost grows with the
        path it runs over (S6-d), and only a protocol knows how long that
        can be. Called while a document is being prepared, with this
        plugin's section of the *proposed* document, so a change that would
        let longer paths reach a regex already configured is refused.

        The default, None, means this plugin hands no AS paths to policy.

        :param section: this plugin's section of the proposed document, or
            None.
        :return: an int, 0 for no limit, or None.
        """
        return None

    # --- lifecycle ---------------------------------------------------------

    def start(self, engine):
        """Attach to a running engine.

        Called on the loop thread once the engine's tables, event bus and
        FIB sink exist. ``engine.global_rib.offer()`` and ``retract()`` are
        the only ways a plugin puts routes into the core; reaching into a
        ``RouteTable`` directly bypasses selection and the FIB.

        :param engine: the engine, kept as ``self.engine``.
        """
        self.engine = engine

    def stop(self):
        """Detach: close sessions, cancel timers, retract offered routes.

        Called on the loop thread. The engine retracts nothing on a
        plugin's behalf -- a plugin that leaves routes behind leaves them
        in the ``GlobalRib`` and, if install is on, in the kernel.
        """
        self.engine = None

    def closing(self):
        """Return tasks still finishing what :meth:`stop` started.

        For a protocol that owes its neighbours a goodbye on the wire --
        BGP's NOTIFICATION -- and cannot write it synchronously. The engine
        waits for these, bounded, before it stops the loop. Most plugins
        have nothing to finish.

        :return: a list of tasks; empty by default.
        """
        return []

    # --- operational surface ------------------------------------------------

    def show_handlers(self):
        """Return this plugin's ``show`` handlers.

        Keys are the IOS-shaped path tuples the engine and the REST API
        both dispatch on, so ``engine.show('ip', 'bgp', 'summary')`` and
        ``GET /api/v1/show/ip/bgp/summary`` reach the same function and
        cannot drift apart.

        :return: ``{path_tuple: callable(*args) -> dict}``.
        """
        return {}

    def clear_handlers(self):
        """Return this plugin's ``clear`` handlers.

        :return: ``{path_tuple: callable(*args, **kwargs) -> dict}``.
        """
        return {}

    def health(self):
        """Report this plugin's own health.

        Merged into the engine document under this plugin's name. Include a
        ``status`` of ``ok``, ``degraded`` or ``down``: the engine's overall
        status is the worst of its own and every plugin's, so a plugin that
        omits it is assumed ``ok`` and can hide a real problem.

        :return: a dict of plain types.
        """
        return {'status': 'ok'}

    # --- plumbing ----------------------------------------------------------

    def validate(self):
        """Check that the class is filled in enough to register.

        Called by ``Engine.register_plugin`` so a missing ``name`` is a
        clear error at registration rather than a ``None`` key appearing in
        show output much later.

        :raises ValueError: the class is incomplete.
        """
        if not self.name:
            raise ValueError('%s must set a name' % type(self).__name__)
        if not isinstance(self.config_section, tuple):
            raise ValueError('%s.config_section must be a tuple of keys'
                             % type(self).__name__)
        for pair in self.afi_safi():
            if len(pair) != 2:
                raise ValueError('%s.afi_safi must yield (afi, safi) pairs'
                                 % type(self).__name__)

    def __repr__(self):
        return '<%s name=%s started=%s>' % (type(self).__name__, self.name,
                                            self.engine is not None)
