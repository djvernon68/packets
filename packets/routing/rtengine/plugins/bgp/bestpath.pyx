# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The BGP decision process, and the knobs operators expect to find on it.

RFC 4271 s9.1.2.2 specifies a handful of tie-breaks and leaves the rest to
the implementation. What actually runs in every network is the longer
vendor sequence -- weight, local preference, locally originated, AS-path
length, origin, MED, external over internal, IGP metric, age, router id,
cluster length, peer address -- and an engine that implements only the RFC
list will pick different paths from the router next to it. So this
implements the full sequence, in that order, with the knobs that change it.

Three of those knobs deserve more than a mention, because each exists to
fix a way the default is genuinely wrong rather than merely conservative.

**deterministic-med.** MED is only comparable between paths from the same
neighbouring AS, which makes the comparison non-transitive: with paths A
and B from AS 1 and C from AS 2, whether A or B survives to meet C depends
on the order they were compared, and therefore on the order they arrived.
Two routers with identical configuration and identical paths can and do
disagree. Grouping by neighbouring AS first and comparing group winners
removes the order dependence, at the cost of a grouping pass.

**med-missing-as-worst.** A path with no MED is treated as MED 0 by
default -- the best possible value -- so a neighbour that omits MED beats
one that sends an honest low number. Inverting it to 2^32-1 is usually what
an operator means.

**compare-routerid.** The default age tie-break prefers the path that has
been up longest, which is stable (a flapping session cannot steal the best
path back) but not deterministic across reboots. Comparing router ids
instead is deterministic but lets a session restart change the winner.
Which is right depends on the network; both are here.

Everything in the comparator reads precomputed fields. ``as_path_len`` and
``neighbor_as`` were derived once when the ``AttrSet`` was interned, so no
comparison ever parses an AS_PATH. That matters: this is the hottest loop
in the engine, running once per candidate pair per destination across a
million destinations on a full table load.
"""

from libc.stdint cimport uint32_t, uint64_t
from libc.string cimport memcmp

from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_GET_SIZE

from packets.routing.rtengine.rib.prefix cimport Prefix
from packets.routing.rtengine.plugins.bgp.attrs cimport (
    AttrSet, ATTRF_MED, ATTRF_LOCAL_PREF, ATTRF_ORIGINATOR_ID)


# Python-visible mirrors of the .pxd enums. A cdef enum is a C constant
# and cannot be named from Python, so without these a test or a show
# producer would have to hard-code the numbers -- and a renumbering would
# then change behaviour silently instead of failing.
SRC_LOCAL = PATH_SRC_LOCAL
SRC_AGGREGATE = PATH_SRC_AGGREGATE
SRC_REDIST = PATH_SRC_REDIST
SRC_PEER = PATH_SRC_PEER

# The plan's names for the same values, so a caller may use either.
PATH_SRC_LOCAL_V = PATH_SRC_LOCAL
PATH_SRC_AGGREGATE_V = PATH_SRC_AGGREGATE
PATH_SRC_REDIST_V = PATH_SRC_REDIST
PATH_SRC_PEER_V = PATH_SRC_PEER

STEP_NONE_V = STEP_NONE
STEP_RESOLVED_V = STEP_RESOLVED
STEP_WEIGHT_V = STEP_WEIGHT
STEP_LOCAL_PREF_V = STEP_LOCAL_PREF
STEP_ORIGINATED_V = STEP_ORIGINATED
STEP_AS_PATH_V = STEP_AS_PATH
STEP_ORIGIN_V = STEP_ORIGIN
STEP_MED_V = STEP_MED
STEP_EXTERNAL_V = STEP_EXTERNAL
STEP_IGP_METRIC_V = STEP_IGP_METRIC
STEP_AGE_V = STEP_AGE
STEP_ROUTER_ID_V = STEP_ROUTER_ID
STEP_CLUSTER_LIST_V = STEP_CLUSTER_LIST
STEP_PEER_ADDR_V = STEP_PEER_ADDR

SOURCE_NAMES = {
    PATH_SRC_LOCAL: 'local', PATH_SRC_AGGREGATE: 'aggregate',
    PATH_SRC_REDIST: 'redistributed', PATH_SRC_PEER: 'peer',
}

# The human-readable reason `show ip bgp <prefix>` prints next to the best
# path. Phrased as the winner's advantage, because that is how the question
# is asked: not "step 5 differed" but "shorter AS path".
STEP_REASONS = {
    STEP_NONE: 'no distinguishing criterion',
    STEP_RESOLVED: 'only resolvable next hop',
    STEP_WEIGHT: 'higher weight',
    STEP_LOCAL_PREF: 'higher local preference',
    STEP_ORIGINATED: 'locally originated',
    STEP_AS_PATH: 'shorter AS path',
    STEP_ORIGIN: 'lower origin',
    STEP_MED: 'lower MED',
    STEP_EXTERNAL: 'external peer',
    STEP_IGP_METRIC: 'lower IGP metric to next hop',
    STEP_AGE: 'older path',
    STEP_ROUTER_ID: 'lower router ID',
    STEP_CLUSTER_LIST: 'shorter cluster list',
    STEP_PEER_ADDR: 'lower neighbour address',
}

# The last step at which two paths may still be considered equal-cost for
# multipath. Everything after it -- age, router id, cluster length, peer
# address -- is an arbitrary tie-break whose only job is to produce *a*
# winner, and excluding paths from a multipath set on that basis would mean
# installing one path where the operator asked for several.
MULTIPATH_BOUNDARY = STEP_IGP_METRIC

MED_WORST = 0xffffffff


cdef inline uint32_t _med_of(AttrSet a, BestpathConfig cfg):
    """The MED to compare with, honouring med-missing-as-worst."""
    if a.flags & ATTRF_MED:
        return a.med
    return MED_WORST if cfg.med_missing_as_worst else 0


cdef inline uint32_t _router_id_of(BgpPath p):
    """The router id to tie-break on.

    ORIGINATOR_ID when a route reflector set one, because it names the
    router that actually originated the path; the reflector's own id would
    make every reflected path look like it came from the reflector and
    collapse a tie-break that is supposed to distinguish origins.
    """
    if p.attrs.flags & ATTRF_ORIGINATOR_ID:
        return p.attrs.originator_id
    return p.peer.router_id


cdef inline int _cmp_addr(bytes x, bytes y):
    """Order two peer addresses, shorter family first then bytewise."""
    cdef Py_ssize_t nx = PyBytes_GET_SIZE(x)
    cdef Py_ssize_t ny = PyBytes_GET_SIZE(y)
    cdef int c

    if nx != ny:
        return -1 if nx < ny else 1
    if nx == 0:
        return 0
    c = memcmp(PyBytes_AS_STRING(x), PyBytes_AS_STRING(y), nx)
    if c:
        return -1 if c < 0 else 1
    return 0


cdef class PeerRef:
    """The peer facts the decision process needs, shared by its paths.

    One of these per session, referenced by every path that session
    contributed. Immutable: a router-id or AS change is a session reset in
    BGP anyway, so the peer builds a new ref rather than mutating one that
    a million paths are reading.

    :param peer: the owning session object, held opaquely and never called.
    :param peer_as: the peer's AS.
    :param local_as: our AS on this session, which may differ from the
        router's AS when ``local-as`` is configured.
    :param router_id: the peer's BGP identifier.
    :param addr: the peer's address, 4 or 16 raw bytes.
    :param is_ebgp: the peer is in another AS.
    """

    def __init__(self, object peer=None, uint32_t peer_as=0,
                 uint32_t local_as=0, uint32_t router_id=0,
                 bytes addr=b'', bint is_ebgp=True):
        self.peer = peer
        self.peer_as = peer_as
        self.local_as = local_as
        self.router_id = router_id
        self.addr = addr
        self.is_ebgp = is_ebgp

    def as_dict(self):
        """Render for ``show ip bgp neighbors``."""
        return {
            'peer': _addr_str(self.addr),
            'peer-as': self.peer_as,
            'local-as': self.local_as,
            'router-id': _ipv4_str(self.router_id),
            'type': 'external' if self.is_ebgp else 'internal',
        }

    def __repr__(self):
        return '<PeerRef %s as=%d %s>' % (
            _addr_str(self.addr), self.peer_as,
            'ebgp' if self.is_ebgp else 'ibgp')


# The ref a locally originated path carries. Marked internal so it loses
# the eBGP-over-iBGP comparison, which is correct: a local path has already
# won at the "locally originated" step and should never reach step 8, and
# if it somehow does, claiming to be external would be a lie about where
# the route came from. Having a real ref rather than None means the
# comparator never tests for it.
LOCAL_PEER = PeerRef(peer=None, peer_as=0, local_as=0, router_id=0,
                     addr=b'', is_ebgp=False)


cdef class BgpPath:
    """One candidate path for one prefix.

    :param attrs: the interned attribute set.
    :param peer: the :class:`PeerRef` this path arrived through. Required
        even for a locally originated path, which uses a ref standing for
        the local router, so the comparator never has to test for None on
        its hottest line.
    :param path_id: RFC 7911 path identifier, 0 without ADD-PATH.
    :param weight: Cisco-style local weight; highest wins first.
    :param source: one of the ``PATH_SRC_*`` codes.
    :param igp_metric: cost to reach the next hop, from next-hop tracking.
    :param recv_time: arrival time, for the age tie-break.
    :param resolved: the next hop currently resolves.
    """

    def __init__(self, AttrSet attrs, PeerRef peer=None,
                 uint32_t path_id=0, uint32_t weight=0,
                 unsigned char source=PATH_SRC_PEER, uint32_t igp_metric=0,
                 double recv_time=0.0, bint resolved=True):
        self.attrs = attrs
        self.peer = peer if peer is not None else LOCAL_PEER
        self.path_id = path_id
        self.weight = weight
        self.source = source
        self.igp_metric = igp_metric
        self.recv_time = recv_time
        self.resolved = resolved
        self.best = False
        self.multipath = False
        self.version = 0

    cpdef dict as_dict(self):
        """Render for ``show ip bgp`` and for events.

        :return: a dict of plain types, with the attribute set inlined.
        """
        cdef dict out = self.attrs.as_dict()
        out['peer-as'] = self.peer.peer_as
        out['peer'] = _addr_str(self.peer.addr)
        out['router-id'] = _ipv4_str(_router_id_of(self))
        out['type'] = 'external' if self.peer.is_ebgp else 'internal'
        out['source'] = SOURCE_NAMES.get(self.source, self.source)
        out['weight'] = self.weight
        out['igp-metric'] = self.igp_metric
        out['resolved'] = bool(self.resolved)
        out['best'] = bool(self.best)
        if self.multipath:
            out['multipath'] = True
        if self.path_id:
            out['path-id'] = self.path_id
        return out

    @property
    def is_ebgp(self):
        """Whether this path came from an external peer."""
        return bool(self.peer.is_ebgp)

    def __repr__(self):
        return '<BgpPath via %s as-path=%r%s%s>' % (
            _addr_str(self.peer.addr), self.attrs.as_path_str(),
            ' best' if self.best else '',
            '' if self.resolved else ' unresolved')


cdef str _ipv4_str(uint32_t v):
    return '%d.%d.%d.%d' % ((v >> 24) & 0xff, (v >> 16) & 0xff,
                            (v >> 8) & 0xff, v & 0xff)


cdef str _addr_str(bytes a):
    cdef Py_ssize_t n = len(a)
    if n == 4:
        return '%d.%d.%d.%d' % (a[0], a[1], a[2], a[3])
    if n == 16:
        return ':'.join(['%02x%02x' % (a[i * 2], a[i * 2 + 1])
                         for i in range(8)])
    return a.hex() if n else '-'


cdef class BestpathConfig:
    """The decision-process knobs for one address family.

    :param local_as: our AS.
    :param router_id: our BGP identifier, used when we originated a path.
    :param always_compare_med: compare MED across neighbouring ASes.
    :param deterministic_med: group by neighbouring AS before comparing.
    :param med_missing_as_worst: an absent MED sorts worst, not best.
    :param compare_router_id: tie-break eBGP paths on router id, not age.
    :param as_path_ignore: skip the AS-path length comparison.
    :param as_path_multipath_relax: allow different equal-length AS paths
        into one multipath set.
    :param maximum_paths: eBGP multipath limit; 1 disables multipath.
    :param maximum_paths_ibgp: iBGP multipath limit.
    :param default_local_pref: the LOCAL_PREF assumed for a path that has
        none, 100 unless configured.
    """

    def __init__(self, uint32_t local_as=0, uint32_t router_id=0,
                 bint always_compare_med=False,
                 bint deterministic_med=True,
                 bint med_missing_as_worst=False,
                 bint compare_router_id=False,
                 bint as_path_ignore=False,
                 bint as_path_multipath_relax=False,
                 unsigned char maximum_paths=1,
                 unsigned char maximum_paths_ibgp=1,
                 uint32_t default_local_pref=100):
        self.local_as = local_as
        self.default_local_pref = default_local_pref
        self.router_id = router_id
        self.always_compare_med = always_compare_med
        # Defaulting this ON is a deliberate departure from IOS, which
        # defaults it off. Off means the winner depends on arrival order,
        # which makes a full-table load non-reproducible and makes any test
        # that loads paths in a different order flaky for a real reason
        # that looks like a bug. The grouping pass is cheap next to that.
        self.deterministic_med = deterministic_med
        self.med_missing_as_worst = med_missing_as_worst
        self.compare_router_id = compare_router_id
        self.as_path_ignore = as_path_ignore
        self.as_path_multipath_relax = as_path_multipath_relax
        self.maximum_paths = maximum_paths if maximum_paths else 1
        self.maximum_paths_ibgp = (maximum_paths_ibgp
                                   if maximum_paths_ibgp else 1)

    def as_dict(self):
        """Render for ``show ip bgp summary`` and configuration display."""
        return {
            'local-as': self.local_as,
            'router-id': _ipv4_str(self.router_id),
            'always-compare-med': bool(self.always_compare_med),
            'deterministic-med': bool(self.deterministic_med),
            'med-missing-as-worst': bool(self.med_missing_as_worst),
            'compare-router-id': bool(self.compare_router_id),
            'as-path-ignore': bool(self.as_path_ignore),
            'as-path-multipath-relax': bool(self.as_path_multipath_relax),
            'default-local-preference': self.default_local_pref,
            'maximum-paths': self.maximum_paths,
            'maximum-paths-ibgp': self.maximum_paths_ibgp,
        }

    def __repr__(self):
        return '<BestpathConfig as=%d rid=%s%s%s>' % (
            self.local_as, _ipv4_str(self.router_id),
            ' det-med' if self.deterministic_med else '',
            ' always-med' if self.always_compare_med else '')


cdef class BestpathResult:
    """The outcome of one selection.

    ``reason`` is the ``STEP_*`` code that separated the winner from the
    runner-up, not from the field as a whole -- that is the comparison an
    operator is actually asking about.
    """

    @property
    def reason_text(self):
        """The reason as the string ``show`` output prints."""
        return STEP_REASONS.get(self.reason, 'unknown')

    def as_dict(self):
        """Render for ``show ip bgp <prefix>``."""
        return {
            'best': self.best.as_dict() if self.best is not None else None,
            'reason': self.reason_text,
            'multipath': len(self.multipath),
            'considered': self.considered,
            'comparisons': self.comparisons,
        }

    def __repr__(self):
        return '<BestpathResult %s reason=%s of %d>' % (
            'none' if self.best is None else repr(self.best),
            self.reason_text, self.considered)


cdef int path_cmp(BgpPath a, BgpPath b, BestpathConfig cfg,
                  int *step) except -2:
    """Run the decision process over two paths.

    :param a: left candidate.
    :param b: right candidate.
    :param cfg: the knobs.
    :param step: out, the ``STEP_*`` code that decided.
    :return: negative if ``a`` wins, positive if ``b`` wins, 0 if the two
        are indistinguishable on every criterion -- which happens only for
        two paths from the same peer with the same attributes, and is the
        caller's signal that it has a duplicate rather than a tie.
    """
    cdef uint32_t ma, mb
    cdef uint32_t ra, rb
    cdef int c

    # Step 1: a path whose next hop does not resolve is not a candidate at
    # all. It stays in the table -- next-hop tracking may resolve it a
    # second later, and withdrawing it on every IGP blink would be worse --
    # but it cannot win.
    step[0] = STEP_RESOLVED
    if a.resolved != b.resolved:
        return -1 if a.resolved else 1

    step[0] = STEP_WEIGHT
    if a.weight != b.weight:
        return -1 if a.weight > b.weight else 1

    # LOCAL_PREF is absent on paths from eBGP peers, where it must not
    # cross the boundary. An absent LOCAL_PREF compares as the configured
    # default (100 unless set), rather than 0: treating it as 0 would make
    # every eBGP path lose to every iBGP path before the process reached the
    # comparison that is supposed to decide that. It used to be a literal
    # 100 here while the outbound side used the configured value, so a
    # router with `default local-preference 200` ranked an eBGP path below
    # the copy of it its own iBGP peers were told was worth 200 (B-7).
    step[0] = STEP_LOCAL_PREF
    ma = (a.attrs.local_pref if (a.attrs.flags & ATTRF_LOCAL_PREF)
          else cfg.default_local_pref)
    mb = (b.attrs.local_pref if (b.attrs.flags & ATTRF_LOCAL_PREF)
          else cfg.default_local_pref)
    if ma != mb:
        return -1 if ma > mb else 1

    step[0] = STEP_ORIGINATED
    if a.source != b.source:
        return -1 if a.source < b.source else 1

    if not cfg.as_path_ignore:
        step[0] = STEP_AS_PATH
        if a.attrs.as_path_len != b.attrs.as_path_len:
            return -1 if a.attrs.as_path_len < b.attrs.as_path_len else 1

    step[0] = STEP_ORIGIN
    if a.attrs.origin != b.attrs.origin:
        return -1 if a.attrs.origin < b.attrs.origin else 1

    # MED is only meaningful between paths from the same neighbouring AS,
    # because it expresses that neighbour's internal costs in units only it
    # defines. always-compare-med overrides that, which is safe only in a
    # network where every neighbour is known to use the same scale.
    step[0] = STEP_MED
    if cfg.always_compare_med or a.attrs.neighbor_as == b.attrs.neighbor_as:
        ma = _med_of(a.attrs, cfg)
        mb = _med_of(b.attrs, cfg)
        if ma != mb:
            return -1 if ma < mb else 1

    step[0] = STEP_EXTERNAL
    if a.peer.is_ebgp != b.peer.is_ebgp:
        return -1 if a.peer.is_ebgp else 1

    step[0] = STEP_IGP_METRIC
    if a.igp_metric != b.igp_metric:
        return -1 if a.igp_metric < b.igp_metric else 1

    # --- below here the criteria exist only to break a tie ----------------
    # Nothing past this line says one path is *better*; they say one is
    # arbitrarily chosen. That is why MULTIPATH_BOUNDARY sits exactly here.

    # Age applies only between two external paths, and only when the
    # operator has not asked for router-id determinism instead. Preferring
    # the established path means a session that flaps cannot repeatedly
    # take the best path back and re-announce it to the whole network.
    if (not cfg.compare_router_id) and a.peer.is_ebgp and b.peer.is_ebgp:
        step[0] = STEP_AGE
        if a.recv_time != b.recv_time:
            return -1 if a.recv_time < b.recv_time else 1

    step[0] = STEP_ROUTER_ID
    ra = _router_id_of(a)
    rb = _router_id_of(b)
    if ra != rb:
        return -1 if ra < rb else 1

    step[0] = STEP_CLUSTER_LIST
    if a.attrs.cluster_len != b.attrs.cluster_len:
        return -1 if a.attrs.cluster_len < b.attrs.cluster_len else 1

    step[0] = STEP_PEER_ADDR
    c = _cmp_addr(a.peer.addr, b.peer.addr)
    if c:
        return c

    step[0] = STEP_NONE
    return 0


def compare(BgpPath a, BgpPath b, BestpathConfig cfg):
    """Compare two paths, for tests and for ``show`` explanations.

    :param a: left candidate.
    :param b: right candidate.
    :param cfg: the knobs.
    :return: ``(result, step, reason_text)`` where result is negative when
        ``a`` wins.
    """
    cdef int step = STEP_NONE
    cdef int c = path_cmp(a, b, cfg, &step)
    return (c, step, STEP_REASONS.get(step, 'unknown'))


def select(list paths, BestpathConfig cfg):
    """Choose the best path, and the multipath set alongside it.

    With ``deterministic_med`` the paths are first grouped by neighbouring
    AS and a winner found within each group, then the group winners are
    compared. That is not an optimisation -- it changes the answer. MED is
    only comparable within a group, so a straight linear scan can eliminate
    the path that would have won purely because of the order it met its
    rivals in, and two routers with the same paths in a different order
    reach different conclusions.

    :param paths: the candidate paths for one prefix.
    :param cfg: the knobs.
    :return: a :class:`BestpathResult`. ``best`` is None when the list is
        empty or every path is unresolved.
    """
    cdef BestpathResult res = BestpathResult.__new__(BestpathResult)
    cdef list eligible = []
    cdef list winners
    cdef BgpPath p, best = None
    cdef Py_ssize_t comparisons = 0
    cdef Py_ssize_t i
    cdef int reason = STEP_NONE
    cdef int step = STEP_NONE
    cdef int c

    res.multipath = []
    res.best = None
    res.reason = STEP_NONE
    res.considered = len(paths)
    res.comparisons = 0

    for p in paths:
        p.best = False
        p.multipath = False
        if p.resolved:
            eligible.append(p)
    if not eligible:
        # Every path is unresolved. The prefix stays in the table and will
        # be reselected when next-hop tracking says something changed.
        return res
    if len(eligible) == 1:
        best = <BgpPath>eligible[0]
        best.best = True
        res.best = best
        res.reason = (STEP_RESOLVED if len(paths) > 1 else STEP_NONE)
        return res

    if cfg.deterministic_med:
        winners = _med_group_winners(eligible, cfg, &comparisons)
    else:
        winners = eligible

    best = <BgpPath>winners[0]
    for i in range(1, len(winners)):
        p = <BgpPath>winners[i]
        c = path_cmp(best, p, cfg, &step)
        comparisons += 1
        if c > 0:
            best = p
    best.best = True
    res.best = best
    # The reason is computed against the whole eligible field rather than
    # tracked through the loop above. Tracking it there reported nothing
    # at all in the most ordinary case there is: with deterministic-med
    # on, two paths from one upstream collapse into a single group, the
    # cross-group loop never executes, and `show ip bgp <prefix>` printed
    # "no distinguishing criterion" for a destination that had a perfectly
    # good reason. It would also have reported whichever comparison ran
    # last rather than the one that mattered.
    res.reason = _decisive_reason(eligible, best, cfg)
    res.comparisons = comparisons + len(eligible) - 1
    _fill_multipath(res, eligible, best, cfg)
    return res


cdef int _decisive_reason(list eligible, BgpPath best, BestpathConfig cfg):
    """Return the step by which the winner beat its closest rival.

    "Closest" means the rival the comparison had to work hardest to
    separate -- the one decided at the *latest* step. That is the honest
    answer to "why is this path best": if the winner beats one path on
    weight and another only on router id, the router id is what is
    actually holding it in front, and reporting the weight would send an
    operator looking at the wrong attribute.

    :param eligible: every resolvable candidate, winner included.
    :param best: the winner.
    :param cfg: the knobs.
    :return: a ``STEP_*`` code; ``STEP_NONE`` when there was no rival.
    """
    cdef BgpPath p
    cdef int step = STEP_NONE
    cdef int latest = STEP_NONE

    for p in eligible:
        if p is best:
            continue
        path_cmp(best, p, cfg, &step)
        if step > latest:
            latest = step
    return latest


cdef list _med_group_winners(list eligible, BestpathConfig cfg,
                             Py_ssize_t *comparisons):
    """Reduce each neighbouring-AS group to its best path.

    Grouping is by ``neighbor_as``, the leftmost AS of the AS_PATH, which
    is what makes two MEDs comparable in the first place. Locally
    originated paths have an empty AS_PATH and a neighbour AS of 0, so they
    form their own group -- correctly, since they carry no neighbour's MED.

    :param eligible: resolvable candidates.
    :param cfg: the knobs.
    :param comparisons: in/out, incremented per comparison performed.
    :return: one winner per group, in ascending neighbouring-AS order so
        the cross-group pass is itself order independent.
    """
    cdef dict groups = {}
    cdef BgpPath p, cur
    cdef int step = STEP_NONE
    cdef list out = []
    cdef uint32_t key

    for p in eligible:
        key = p.attrs.neighbor_as
        cur = <BgpPath>groups.get(key)
        if cur is None:
            groups[key] = p
            continue
        if path_cmp(cur, p, cfg, &step) > 0:
            groups[key] = p
        comparisons[0] += 1
    for key in sorted(groups.keys()):
        out.append(groups[key])
    return out


cdef int _fill_multipath(BestpathResult res, list eligible, BgpPath best,
                         BestpathConfig cfg) except -1:
    """Mark the paths that are equal-cost with the winner.

    A path joins the set when it is indistinguishable from the best path
    down to :data:`MULTIPATH_BOUNDARY` -- every criterion that expresses a
    real preference. Beyond that the comparator is only manufacturing a
    winner, and excluding a path because its peer address sorts higher
    would install one route where the operator configured several.

    Two additional rules, both of which surprise people:

    * the AS paths must be identical, not merely the same length, unless
      ``as-path-multipath-relax`` is set. Two same-length paths through
      different ASes are different paths in every way that matters for
      traffic engineering, and load-sharing across them is a decision an
      operator must opt into;
    * the set is all-external or all-internal, with its own limit each,
      because mixing them means some traffic takes an extra internal hop.
    """
    cdef BgpPath p
    cdef int step = STEP_NONE
    cdef Py_ssize_t limit
    cdef list out = []

    limit = (cfg.maximum_paths if best.peer.is_ebgp
             else cfg.maximum_paths_ibgp)
    if limit <= 1:
        return 0
    out.append(best)
    for p in eligible:
        if p is best:
            continue
        if len(out) >= limit:
            break
        if p.peer.is_ebgp != best.peer.is_ebgp:
            continue
        if not cfg.as_path_multipath_relax:
            if p.attrs.as_path != best.attrs.as_path:
                continue
        path_cmp(best, p, cfg, &step)
        if step > MULTIPATH_BOUNDARY or step == STEP_NONE:
            out.append(p)
            p.multipath = True
    if len(out) > 1:
        best.multipath = True
        res.multipath = out
    return 0


cdef class BgpDest:
    """Every path the plugin holds for one prefix, plus the winner.

    A path's identity here is ``(peer, path_id)``, never its attributes.
    That is what makes a re-advertisement replace rather than accumulate:
    a peer resending 10.0.0.0/8 with a new MED has changed its single
    path, and a container that keyed on attributes would grow a path per
    update until the session dropped. Without ADD-PATH every path id is 0
    and the key collapses to the peer, which is exactly the pre-ADD-PATH
    rule of one path per prefix per peer.

    The path list is a plain list, not a dict. A destination holds one
    path per peer and the overwhelming majority hold two or three; a
    linear scan over three entries beats hashing a two-part key, and the
    list is also the iteration order the selector wants.

    :param prefix: the destination.
    """

    def __init__(self, Prefix prefix):
        self.prefix = prefix
        self.paths = []
        self.best = None
        self.multipath = []
        self.reason = STEP_NONE
        self.version = 0
        self.queued = 0

    cpdef BgpPath find(self, PeerRef peer, uint32_t path_id):
        """Return the path from this peer with this id, if any.

        :param peer: the contributing peer.
        :param path_id: the RFC 7911 identifier, 0 without ADD-PATH.
        :return: the path, or None.
        """
        cdef BgpPath p

        for p in self.paths:
            if p.peer is peer and p.path_id == path_id:
                return p
        return None

    cpdef BgpPath add(self, BgpPath path):
        """Add a path, replacing any it supersedes.

        :param path: the new path.
        :return: the path it replaced, or None if it is new. The caller
            needs this to release the replaced path's interned attribute
            set -- dropping it on the floor is the leak that makes an
            AttrTable grow without bound on a flapping peer.
        """
        cdef BgpPath old
        cdef Py_ssize_t i

        for i in range(len(self.paths)):
            old = <BgpPath>self.paths[i]
            if old.peer is path.peer and old.path_id == path.path_id:
                self.paths[i] = path
                return old
        self.paths.append(path)
        return None

    cpdef BgpPath remove(self, PeerRef peer, uint32_t path_id):
        """Withdraw one path.

        :param peer: the contributing peer.
        :param path_id: the RFC 7911 identifier.
        :return: the removed path, or None if there was none. Again the
            caller owns releasing its attribute set.
        """
        cdef BgpPath p
        cdef Py_ssize_t i

        for i in range(len(self.paths)):
            p = <BgpPath>self.paths[i]
            if p.peer is peer and p.path_id == path_id:
                del self.paths[i]
                return p
        return None

    cpdef Py_ssize_t remove_peer(self, PeerRef peer):
        """Withdraw every path from one peer, for a session teardown.

        :param peer: the departing peer.
        :return: how many paths were removed.
        """
        cdef list keep = []
        cdef BgpPath p
        cdef Py_ssize_t removed = 0

        for p in self.paths:
            if p.peer is peer:
                removed += 1
            else:
                keep.append(p)
        if removed:
            self.paths = keep
        return removed

    cpdef BestpathResult reselect(self, BestpathConfig cfg):
        """Re-run the decision process and record the outcome.

        :param cfg: the knobs.
        :return: the :class:`BestpathResult`, also cached on this object
            so ``show`` can report the winner and the reason without
            re-selecting.
        """
        cdef BestpathResult res = select(self.paths, cfg)

        self.best = res.best
        self.multipath = res.multipath
        self.reason = res.reason
        return res

    @property
    def reason_text(self):
        """Why the current best path won."""
        return STEP_REASONS.get(self.reason, 'unknown')

    def as_dict(self):
        """Render for ``show ip bgp <prefix>``."""
        return {
            'prefix': self.prefix.to_str(),
            'paths': [p.as_dict() for p in self.paths],
            'reason': self.reason_text,
            'multipath': len(self.multipath),
        }

    def __len__(self):
        return len(self.paths)

    def __iter__(self):
        return iter(self.paths)

    def __repr__(self):
        return '<BgpDest %s paths=%d%s>' % (
            self.prefix.to_str(), len(self.paths),
            '' if self.best is None else ' best via %s'
            % _addr_str(self.best.peer.addr))


def explain(list paths, BestpathConfig cfg):
    """Describe why each path lost to the winner.

    Selection itself only reports the one comparison that decided the
    winner. This runs the winner against every other path and reports each
    losing reason, which is what an operator debugging "why is my route not
    being used" needs -- the answer is usually about a specific rival, not
    about the field.

    Read-only in effect (B-9). :func:`select` marks the paths it is given
    -- ``best`` and ``multipath`` -- and these are the live paths of a
    destination, whose flags the advertisement pass and ``show`` read. The
    flags are put back as they were before returning, so asking why a path
    lost can never change which path the rest of the engine thinks won.

    :param paths: the candidate paths for one prefix.
    :param cfg: the knobs.
    :return: a dict with the winner and a list of per-path verdicts.
    """
    cdef BgpPath p
    cdef Py_ssize_t i
    cdef list saved = []
    for p in paths:
        saved.append((p.best, p.multipath))
    try:
        return _explain(paths, cfg)
    finally:
        for i in range(len(paths)):
            p = <BgpPath>paths[i]
            p.best = (<tuple>saved[i])[0]
            p.multipath = (<tuple>saved[i])[1]


cdef dict _explain(list paths, BestpathConfig cfg):
    cdef BestpathResult res = select(paths, cfg)
    cdef BgpPath p
    cdef int step = STEP_NONE
    cdef list rows = []

    if res.best is None:
        return {'best': None, 'reason': 'no resolvable path',
                'paths': [{'path': p.as_dict(), 'verdict': 'unresolved'}
                          for p in paths]}
    for p in paths:
        if p is res.best:
            rows.append({'path': p.as_dict(), 'verdict': 'best'})
            continue
        if not p.resolved:
            rows.append({'path': p.as_dict(), 'verdict': 'unresolved'})
            continue
        path_cmp(res.best, p, cfg, &step)
        rows.append({
            'path': p.as_dict(),
            'verdict': 'multipath' if p.multipath else 'not best',
            'lost-on': STEP_REASONS.get(step, 'unknown'),
            'step': step,
        })
    return {
        'best': res.best.as_dict(),
        'reason': res.reason_text,
        'multipath': len(res.multipath),
        'paths': rows,
    }
