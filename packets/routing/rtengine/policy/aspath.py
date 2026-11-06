# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""AS-path matching: regexes over the canonical AS path string.

An AS-path filter is a regular expression, and the only thing that makes it
meaningful is agreement about the *string* it is applied to. A pattern is
written against a rendering of the AS_PATH attribute, and if the renderer
and the pattern author disagree about how a set is spelled, the pattern does
not fail -- it silently never matches, and the filter that was supposed to
drop a route quietly permits it. So the rendering is a contract, and this is
it:

    ``AttrSet.as_path_str()`` in the BGP plugin. AS_SEQUENCE segments are
    rendered bare, as their ASNs joined by single spaces. An AS_SET is
    braced with its members comma-separated and no spaces: ``{65003,65004}``.
    A confederation sequence (RFC 5065) is parenthesised and
    space-separated: ``(65001 65002)``. A confederation set is bracketed and
    comma-separated: ``[65003,65004]``. Segments are joined by single
    spaces, and an empty AS_PATH renders as the empty string.

So ``'65001 65002 {65003,65004}'`` is a two-AS sequence followed by a set,
and a pattern looking for the set has to spell it with a brace and a comma.
This module does not know that ``AttrSet`` exists -- policy is core code and
imports nothing from a plugin -- but the string it matches against is
``AttrSet``'s, and any other producer of path attributes has to render the
same way to be filterable.

**Anchoring.** IOS AS-path regexes are substring matches, with ``^`` and
``$`` meaning the start and the end of the whole path string. That is
exactly Python's :func:`re.search` with the pattern written as-is, so
nothing here adds an anchor. Implicitly anchoring would break the single
most common idiom in production configurations -- ``_65001_`` style
"transits this AS" patterns and bare ``65001`` origin tests -- by turning
every one of them into a whole-string comparison.

**The underscore.** IOS gives ``_`` a special meaning: it matches a path
delimiter, which is the start or end of the string, a space, a brace, a
bracket, a parenthesis or a comma. Python's ``re`` treats it as a literal
underscore, and an underscore never appears in the canonical string, so an
IOS pattern used to match nothing at all -- and ``deny _65001_`` failed
*open* (P-1). It is now translated, the way FRR does, to
``(?:^|[ ,{}()\[\]]|$)`` -- the delimiters of the string above. Only a bare
``_`` is: ``\_`` is a literal underscore, and so is an underscore inside a
character class, where IOS gives it no meaning either. No other dialect
difference is translated, because there is no other one that matters: IOS'
remaining metacharacters mean what Python's do.

**The guard.** A pattern is operator input run on the engine thread
against a string a peer chose, and Python's ``re`` backtracks, so a
pattern is judged before it is accepted (P-2):

  * at most :data:`MAX_PATTERN_LENGTH` characters;
  * no backreference or group conditional -- nothing in IOS needs one, and
    they are what put a backtracking matcher beyond any bound;
  * a repeat whose body itself repeats is accepted only when every pass
    of the outer one begins or ends with a delimiter (``_``, a space, a
    comma, a brace) that nothing repeated inside can match. That keeps
    ``^[0-9]+(_[0-9]+)*$`` -- "any number of further ASNs" -- and rejects
    ``([0-9]+)+``, whose passes can split one run of digits in
    exponentially many ways;
  * a bounded *exponent*: how the worst case grows with the length of the
    path. Each *path-spanning* repeat -- an unbounded one that can run
    across a delimiter, like ``.*`` or ``(_[0-9]+)*`` -- multiplies it by
    the path length, and so does the search itself trying every start,
    unless the pattern begins with ``^``. A repeat that stays inside one
    ASN, like ``[0-9]+``, costs at most ten characters and does not count.
    An exponent above :data:`MAX_EXPONENT` (cubic) is refused outright. A
    quadratic one is accepted only while no path longer than
    :data:`QUADRATIC_MAX_ASNS` ASNs can reach it (:func:`check_length`),
    which is the BGP plugin's default ``maxas-limit``.

    Measured on the deployment target (S6-d, cnp02, 3.6.8), worst accepted
    patterns on the worst paths: linear ones stay under a millisecond at
    2,000 ASNs, the worst quadratic one takes 16 ms at 255 ASNs and 925 ms
    at 2,000, and a cubic one took 919 ms at 255 ASNs and over 30 s at
    1,000. The earlier rule, at most two path-spanning repeats whatever the
    anchoring and the path length, admitted that cubic one.

A leading ``.*`` (or ``^.*``) and a trailing ``.*`` (or ``.*$``) are dropped
before any of that, because a search already starts and ends anywhere:
``.*65001.*`` and ``65001`` accept exactly the same paths, and the first
one used to cost a full rescan per starting position. Stripping ``^.*``
also drops the anchor, so it is judged as the unanchored pattern it is.

**Caching.** Compiled patterns are cached module-level and keyed by the
pattern text, because the same handful of patterns are shared by every peer
and every reload of a configuration recompiles them all. The cache is
bounded and, on overflow, cleared entirely rather than evicted one entry at
a time: the working set is tens of patterns, an overflow means something
generated them programmatically, and a full clear costs one recompile per
live pattern with no ordering structure to maintain. ``re`` keeps its own
small cache as well, but it is keyed by ``(pattern, flags, type)`` and is
itself cleared wholesale when full, so relying on it would put the
compilation of a production filter set at the mercy of unrelated code doing
a few hundred ad-hoc regex calls.

A pattern with a path-spanning repeat also remembers its last
:data:`RESULT_CACHE_MAX` answers, keyed by the path string and shared by
every matcher built from the same text: a full table carries far fewer
distinct AS paths than prefixes, so most evaluations of an expensive pattern
become one dictionary lookup. A pattern without one is cheaper to run than
to look up, and is not cached.
"""

import re
from collections import OrderedDict

try:
    # 3.11 deprecated the public name; the parser itself did not change.
    from re import _parser as _sre_parse
except ImportError:  # Python < 3.11
    import sre_parse as _sre_parse

from packets.routing.rtengine.policy.prefixlist import (ACTION_DENY,
                                                        ACTION_NAMES,
                                                        ACTION_PERMIT,
                                                        NO_MATCH, action_id,
                                                        seq_number)

__all__ = ['ACTION_DENY', 'ACTION_PERMIT', 'ACTION_NAMES', 'NO_MATCH',
           'AsPathMatcher', 'AsPathList', 'compile_pattern',
           'AsPathListEntry', 'translate', 'strip_wildcards', 'check_length',
           'MAX_PATTERN_LENGTH', 'MAX_EXPONENT', 'QUADRATIC_MAX_ASNS',
           'UNDERSCORE']

# Tens of distinct patterns is a large production configuration. The bound is
# generous enough that no real configuration reaches it and small enough that
# a runaway caller cannot turn the cache into a leak.
_PATTERN_CACHE_MAX = 256

#: The longest pattern text accepted (P-2). The longest IOS AS-path regex in
#: real use is a few tens of characters.
MAX_PATTERN_LENGTH = 256

#: The highest growth exponent accepted (P-2, S6-d): quadratic in the path
#: length. See the module docstring.
MAX_EXPONENT = 2

#: The longest path, in ASNs, a quadratic pattern may be run over (S6-d).
#: The BGP plugin's default maxas-limit; a configuration that lets longer
#: paths through accepts only linear patterns.
QUADRATIC_MAX_ASNS = 255

#: Distinct path strings an expensive pattern remembers its answer for.
RESULT_CACHE_MAX = 4096

#: What IOS' ``_`` matches: a delimiter of the canonical path string, or its
#: start or end (P-1).
UNDERSCORE = r'(?:^|[ ,{}()\[\]]|$)'

# The characters UNDERSCORE consumes, for the guard's delimiter test.
_DELIMITERS = frozenset(' ,{}()[]')

_PATTERN_CACHE = {}


class _Program(object):
    """A judged, translated and compiled pattern, shared by its matchers.

    :ivar regex: the compiled :mod:`re` pattern.
    :ivar spanning: how many path-spanning repeats it holds.
    :ivar exponent: how its worst case grows with the path length: the
        spanning repeats, plus one for the search unless it starts with
        ``^``.
    :ivar results: path string -> bool, most recent last; None for a
        pattern too cheap to be worth it.
    """

    __slots__ = ('regex', 'spanning', 'exponent', 'results')

    def __init__(self, regex, spanning, exponent):
        self.regex = regex
        self.spanning = spanning
        self.exponent = exponent
        self.results = OrderedDict() if spanning else None


def translate(pattern):
    """Rewrite IOS' ``_`` into the delimiter class it means (P-1).

    :param pattern: the pattern as configured.
    :return: the pattern Python's ``re`` should compile. ``\_`` and an
        underscore inside ``[...]`` are left alone, as literal underscores.
    """
    if '_' not in pattern:
        return pattern
    out = []
    i = 0
    n = len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == '\\' and i + 1 < n:
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            if c == ']':
                in_class = False
            out.append(c)
        elif c == '[':
            in_class = True
            out.append(c)
            # A ']' first in a class (after an optional '^') is a member,
            # not the end of it.
            j = i + 1
            if j < n and pattern[j] == '^':
                out.append('^')
                j += 1
            if j < n and pattern[j] == ']':
                out.append(']')
                j += 1
            i = j
            continue
        elif c == '_':
            out.append(UNDERSCORE)
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def _escaped(text, index):
    """Whether the character at ``index`` follows an unpaired backslash."""
    count = 0
    while index - count - 1 >= 0 and text[index - count - 1] == '\\':
        count += 1
    return count % 2 == 1


def strip_wildcards(pattern):
    """Drop a leading and a trailing ``.*``, which a search makes redundant.

    ``re.search`` already tries every start and accepts any end, so a
    pattern that begins with ``.*`` or ``^.*``, or ends with ``.*`` or
    ``.*$``, accepts exactly the paths it would without them -- and a
    leading one used to cost a rescan from every start (P-2). Repeated
    until neither end has one; a lazy ``.*?`` counts, anything else
    (``.*+``, ``.*{2}``) is left for the compiler to judge.

    :param pattern: the configured pattern, before :func:`translate`.
    :return: the pattern that is actually run; possibly empty, which
        accepts every path, as ``.*`` did.
    """
    while True:
        before = pattern
        for head in ('^.*?', '^.*', '.*?', '.*'):
            if pattern.startswith(head):
                rest = pattern[len(head):]
                if rest[:1] not in ('*', '+', '?', '{'):
                    pattern = rest
                break
        for tail in ('.*?$', '.*$', '.*?', '.*'):
            if (pattern.endswith(tail) and
                    not _escaped(pattern, len(pattern) - len(tail))):
                pattern = pattern[:-len(tail)]
                break
        if pattern == before:
            return pattern


# --- the guard --------------------------------------------------------------

_OP = {name: getattr(_sre_parse, name, None) for name in (
    'LITERAL', 'NOT_LITERAL', 'ANY', 'IN', 'RANGE', 'NEGATE', 'CATEGORY',
    'AT', 'SUBPATTERN', 'BRANCH', 'MAX_REPEAT', 'MIN_REPEAT',
    'POSSESSIVE_REPEAT', 'ASSERT', 'ASSERT_NOT', 'ATOMIC_GROUP',
    'GROUPREF', 'GROUPREF_EXISTS', 'CATEGORY_DIGIT', 'CATEGORY_SPACE',
    'AT_BEGINNING', 'AT_BEGINNING_STRING', 'AT_END', 'AT_END_STRING')}
_REPEATS = frozenset(op for op in (_OP['MAX_REPEAT'], _OP['MIN_REPEAT'],
                                   _OP['POSSESSIVE_REPEAT']) if op is not None)
_EDGES = frozenset(op for op in (_OP['AT_BEGINNING'],
                                 _OP['AT_BEGINNING_STRING'], _OP['AT_END'],
                                 _OP['AT_END_STRING']) if op is not None)
_MAXREPEAT = _sre_parse.MAXREPEAT

# A bounded repeat this short multiplies the work by at most this much, not
# by the length of the path, so it is not counted as path-spanning.
_SHORT_REPEAT = 32

# "Any character": a set too wide to reason about.
_ANY = None


def _union(a, b):
    if a is _ANY or b is _ANY:
        return _ANY
    return a | b


def _items(sub):
    """A parsed sequence with every group spliced into it.

    3.6 keeps a non-capturing group as a SUBPATTERN node and 3.11 inlines
    it; a group never changes what a sequence consumes, so both become the
    same flat list.
    """
    out = []
    for op, av in sub:
        if op is _OP['SUBPATTERN']:
            out.extend(_items(av[-1]))
        else:
            out.append((op, av))
    return out


def _class_chars(items):
    chars = set()
    for op, av in items:
        if op is _OP['NEGATE']:
            return _ANY
        if op is _OP['LITERAL']:
            chars.add(chr(av))
        elif op is _OP['RANGE']:
            lo, hi = av
            if hi - lo > 512:
                return _ANY
            chars.update(chr(c) for c in range(lo, hi + 1))
        elif op is _OP['CATEGORY'] and av is _OP['CATEGORY_DIGIT']:
            chars.update('0123456789')
        elif op is _OP['CATEGORY'] and av is _OP['CATEGORY_SPACE']:
            chars.update(' \t\n\r\f\v')
        else:
            return _ANY
    return frozenset(chars)


def _chars(sub):
    """Every character a parsed sequence could consume, or :data:`_ANY`."""
    chars = frozenset()
    for op, av in _items(sub):
        if op is _OP['LITERAL']:
            got = frozenset((chr(av),))
        elif op is _OP['IN']:
            got = _class_chars(av)
        elif op is _OP['AT'] or op in (_OP['ASSERT'], _OP['ASSERT_NOT']):
            continue
        elif op is _OP['BRANCH']:
            got = frozenset()
            for alt in av[1]:
                got = _union(got, _chars(alt))
        elif op in _REPEATS:
            got = _chars(av[2])
        elif op is _OP['ATOMIC_GROUP']:
            got = _chars(av)
        else:
            return _ANY
        chars = _union(chars, got)
        if chars is _ANY:
            return _ANY
    return chars


def _delimiter_chars(item):
    """The characters a delimiter-like item consumes, or None if it is not.

    A delimiter here is something that consumes exactly one character from
    :data:`_DELIMITERS` -- or nothing, but only at the very start or end of
    the string, where it cannot be where one pass ends and the next begins
    more than once. ``_`` translates to exactly that.
    """
    op, av = item
    alts = av[1] if op is _OP['BRANCH'] else [[item]]
    chars = set()
    for alt in alts:
        alt = _items(alt)
        if len(alt) != 1:
            return None
        aop, aav = alt[0]
        if aop is _OP['AT'] and aav in _EDGES:
            continue
        if aop is _OP['LITERAL']:
            got = {chr(aav)}
        elif aop is _OP['IN']:
            got = _class_chars(aav)
            if got is _ANY:
                return None
        else:
            return None
        if not got or not got <= _DELIMITERS:
            return None
        chars |= got
    return frozenset(chars) if chars else None


def _repeats_within(sub):
    """Every repeat that can run more than once, anywhere in a sequence."""
    found = []
    for op, av in _items(sub):
        if op in _REPEATS:
            if av[1] > 1:
                found.append((op, av))
            found.extend(_repeats_within(av[2]))
        elif op is _OP['BRANCH']:
            for alt in av[1]:
                found.extend(_repeats_within(alt))
        elif op in (_OP['ASSERT'], _OP['ASSERT_NOT']):
            found.extend(_repeats_within(av[1]))
        elif op is _OP['ATOMIC_GROUP']:
            found.extend(_repeats_within(av))
    return found


def _fenced_edges(body, inside):
    """Which ends of a repeated body are fenced by a delimiter.

    :param body: the outer repeat's parsed body.
    :param inside: every character the repeats inside it can consume.
    :return: a set of ``'start'`` and ``'end'``. For an alternation, the
        ends fenced in *every* alternative: ``(_[0-9]+|[0-9]+_)+`` has a
        fence in each branch but none between one branch's pass and the
        next one's, so it is not fenced at all.
    """
    items = _items(body)
    if not items:
        return set()
    if len(items) == 1 and items[0][0] is _OP['BRANCH']:
        edges = set(('start', 'end'))
        for alt in items[0][1][1]:
            edges &= _fenced_edges(alt, inside)
        return edges
    edges = set()
    for name, edge in (('start', items[0]), ('end', items[-1])):
        fence = _delimiter_chars(edge)
        if fence is not None and inside is not _ANY and not fence & inside:
            edges.add(name)
    return edges


def _delimited(body, inner):
    """Whether every pass of a repeated body is fenced by a delimiter.

    :param body: the outer repeat's parsed body.
    :param inner: the repeats inside it.
    :return: True if the body begins (or ends) with a delimiter none of
        the inner repeats can consume -- so consecutive passes cannot trade
        characters, and there is one way to split a path into them.
    """
    inside = frozenset()
    for _op, av in inner:
        inside = _union(inside, _chars(av[2]))
    return bool(_fenced_edges(body, inside))


def _first(sub):
    """What a parsed sequence can begin with.

    :return: ``(chars, nullable)``: every character the first one consumed
        could be (or :data:`_ANY`), and whether it can consume nothing.
    """
    chars = frozenset()
    for op, av in _items(sub):
        if op is _OP['AT'] or op in (_OP['ASSERT'], _OP['ASSERT_NOT']):
            continue
        if op in _REPEATS:
            got, nullable = _first(av[2])
            chars = _union(chars, got)
            if av[0] > 0 and not nullable:
                return chars, False
            continue
        if op is _OP['BRANCH']:
            any_null = False
            for alt in av[1]:
                got, nullable = _first(alt)
                chars = _union(chars, got)
                any_null = any_null or nullable
            if not any_null:
                return chars, False
            continue
        if op is _OP['ATOMIC_GROUP']:
            got, nullable = _first(av)
            chars = _union(chars, got)
            if not nullable:
                return chars, False
            continue
        return _union(chars, _chars([(op, av)])), False
    return chars, True


def _edge_only(alt):
    """Whether an alternative is nothing but ``^`` or ``$``.

    Two of those cannot both match anywhere but the empty string, so they
    are never what makes an alternation ambiguous -- and ``_`` is one
    alternation of exactly that shape around a delimiter class.
    """
    items = _items(alt)
    return bool(items) and all(op is _OP['AT'] and av in _EDGES
                               for op, av in items)


def _distinct(a, b):
    """Whether two alternatives can never match the same text.

    Their common leading items -- compared structurally, and never past a
    repeat, which could consume different amounts in each -- are skipped;
    then what each remainder begins with must be disjoint, and neither may
    be able to consume nothing. Conservative: ``(a|ab)`` is refused, which
    is cheaper than proving it harmless.
    """
    a = _items(a)
    b = _items(b)
    i = 0
    while (i < len(a) and i < len(b) and a[i][0] not in _REPEATS and
           repr(a[i]) == repr(b[i])):
        i += 1
    first_a, null_a = _first(a[i:])
    first_b, null_b = _first(b[i:])
    if null_a or null_b or first_a is _ANY or first_b is _ANY:
        return False
    return not first_a & first_b


def _ambiguous(alts):
    """Whether two of an alternation's branches could match the same text."""
    alts = [alt for alt in alts if not _edge_only(alt)]
    for i in range(len(alts)):
        for j in range(i + 1, len(alts)):
            if not _distinct(alts[i], alts[j]):
                return True
    return False


def _judge(sub, pattern, repeated=False):
    """Walk a parsed pattern, refusing what could run away (P-2).

    :param sub: the parsed sequence.
    :param pattern: the configured text, for messages.
    :param repeated: ``sub`` is inside a repeat that can run more than
        once, where an ambiguous alternation multiplies per pass.
    :return: the number of path-spanning repeats found.
    :raises ValueError: a backreference, an undelimited nested repeat, or
        a repeated alternation whose branches can match the same text.
    """
    spanning = 0
    for op, av in _items(sub):
        if op in (_OP['GROUPREF'], _OP['GROUPREF_EXISTS']):
            raise ValueError(
                'as-path regex %r uses a backreference or a group '
                'conditional, which is not allowed' % (pattern,))
        if op in _REPEATS:
            body = av[2]
            many = av[1] > 1
            if many:
                inner = _repeats_within(body)
                if inner and not _delimited(body, inner):
                    raise ValueError(
                        'as-path regex %r repeats a group that itself '
                        'repeats, and nothing (such as _ or a space) '
                        'separates one pass from the next; that can take '
                        'exponential time on a long AS path' % (pattern,))
                if av[1] == _MAXREPEAT or av[1] > _SHORT_REPEAT:
                    chars = _chars(body)
                    if chars is _ANY or chars & _DELIMITERS:
                        spanning += 1
            spanning += _judge(body, pattern, repeated or many)
        elif op is _OP['BRANCH']:
            if repeated and _ambiguous(av[1]):
                raise ValueError(
                    'as-path regex %r repeats an alternation whose '
                    'branches can match the same text; that can take '
                    'exponential time on a long AS path' % (pattern,))
            for alt in av[1]:
                spanning += _judge(alt, pattern, repeated)
        elif op in (_OP['ASSERT'], _OP['ASSERT_NOT']):
            spanning += _judge(av[1], pattern, repeated)
        elif op is _OP['ATOMIC_GROUP']:
            spanning += _judge(av, pattern, repeated)
    return spanning


def _build(pattern):
    """Judge, translate and compile one configured pattern.

    :param pattern: the pattern text, already known to be a non-empty str.
    :return: a :class:`_Program`.
    :raises ValueError: see :func:`compile_pattern`.
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError('as-path regex is %d characters long; the limit is '
                         '%d' % (len(pattern), MAX_PATTERN_LENGTH))
    try:
        # The pattern as written must be valid, before stripping could
        # make an invalid one look valid.
        re.compile(translate(pattern))
        text = translate(strip_wildcards(pattern))
        parsed = _sre_parse.parse(text)
        regex = re.compile(text)
    except (re.error, RecursionError, OverflowError) as exc:
        raise ValueError('not a valid as-path regex %r: %s'
                         % (pattern, exc))
    spanning = _judge(parsed, pattern)
    anchored = _anchored(parsed)
    exponent = spanning + (0 if anchored else 1)
    if exponent > MAX_EXPONENT:
        raise ValueError(
            'as-path regex %r has %d path-spanning repeats (.* and the '
            'like)%s, so its work can grow with the cube of the path length '
            'or worse; at most one is allowed, or two when the pattern '
            'starts with ^' % (pattern, spanning,
                               '' if anchored else ' and does not start '
                                                   'with ^'))
    return _Program(regex, spanning, exponent)


def _anchored(parsed):
    """Whether a pattern can only match at the start of the path.

    Only a top-level ``^``: one inside an alternation, such as the one
    ``_`` becomes, still lets the search try every start.
    """
    items = _items(parsed)
    return bool(items) and items[0][0] is _OP['AT'] and \
        items[0][1] in (_OP['AT_BEGINNING'], _OP['AT_BEGINNING_STRING'])


def check_length(pattern, longest):
    """Refuse a quadratic pattern where a path may be too long for it (S6-d).

    :param pattern: an AS-path regex, as configured.
    :param longest: the longest AS path, in ASNs, a protocol will hand to
        policy: BGP's ``maxas-limit``. 0 means no limit.
    :raises ValueError: the pattern is invalid or refused outright (see
        :func:`compile_pattern`), or its work grows with the square of the
        path length and ``longest`` is 0 or above
        :data:`QUADRATIC_MAX_ASNS`.
    """
    program = _program(pattern)
    if program.exponent < 2:
        return
    if longest and longest <= QUADRATIC_MAX_ASNS:
        return
    raise ValueError(
        'as-path regex %r has %d path-spanning repeat%s (.* and the like)%s, '
        'so its work grows with the square of the path length; that is '
        'accepted only while no AS path longer than %d ASNs is accepted, and '
        'maxas-limit is %s. Start the pattern with ^, use one .* fewer, or '
        'lower maxas-limit' % (
            pattern, program.spanning, '' if program.spanning == 1 else 's',
            '' if program.spanning > 1 else ' and does not start with ^',
            QUADRATIC_MAX_ASNS,
            '%d' % longest if longest else '0 (no limit)'))


def _program(pattern):
    """Return the shared :class:`_Program` for a pattern, building it once.

    :raises ValueError: see :func:`compile_pattern`.
    """
    if not isinstance(pattern, str):
        raise ValueError('an as-path regex must be a string, not %s'
                         % type(pattern).__name__)
    if not pattern:
        raise ValueError('an as-path regex must not be empty')
    program = _PATTERN_CACHE.get(pattern)
    if program is not None:
        return program
    program = _build(pattern)
    if len(_PATTERN_CACHE) >= _PATTERN_CACHE_MAX:
        _PATTERN_CACHE.clear()
    _PATTERN_CACHE[pattern] = program
    return program


def compile_pattern(pattern):
    """Compile an AS-path regex, reusing an earlier compilation.

    :param pattern: the pattern text, exactly as configured. Not anchored
        here; ``_`` is translated and redundant ``.*`` dropped, see the
        module docstring.
    :return: the compiled :mod:`re` pattern object.
    :raises ValueError: the text is not a string, is empty, is too long, is
        not a valid regular expression, or is one the guard refuses.
        ``re.error`` is translated because everything wrong with a pattern
        is a configuration error and the callers above this one --
        ``PolicyStore.validate`` and the REST layer behind it -- key on
        ``ValueError`` for "the operator typed something wrong".
    """
    return _program(pattern).regex


def cache_stats():
    """Return the pattern cache's size and bound, for health output.

    :return: ``{'patterns': N, 'limit': N}``.
    """
    return {'patterns': len(_PATTERN_CACHE), 'limit': _PATTERN_CACHE_MAX}


class AsPathMatcher(object):
    """One compiled AS-path regex.

    Thin on purpose: it exists so that a route-map clause holds a *compiled*
    matcher rather than a string, which is what keeps the compilation out of
    the per-path hot path, and so that the pattern text survives for show
    output next to the thing that was made from it.

    :param pattern: the regex text, IOS-style, matched against the
        canonical AS path string.
    :raises ValueError: an empty, non-string, invalid or refused pattern.
    """

    __slots__ = ('pattern', '_regex', '_results')

    def __init__(self, pattern):
        program = _program(pattern)
        self._regex = program.regex
        self._results = program.results
        self.pattern = pattern

    def __repr__(self):
        return 'AsPathMatcher(%r)' % (self.pattern,)

    def matches(self, as_path_str):
        """Return whether the pattern occurs in a path string.

        :param as_path_str: the canonical AS path string, as produced by
            ``AttrSet.as_path_str()``. ``None`` is treated as an empty path
            rather than as an error, so a caller with no attributes at all
            -- a locally originated or non-BGP route -- can be filtered
            without a special case.
        :return: True if the pattern matches anywhere in the string.
        """
        if as_path_str is None:
            as_path_str = ''
        results = self._results
        if results is None:
            return self._regex.search(as_path_str) is not None
        hit = results.get(as_path_str)
        if hit is not None:
            results.move_to_end(as_path_str)
            return hit
        hit = self._regex.search(as_path_str) is not None
        results[as_path_str] = hit
        if len(results) > RESULT_CACHE_MAX:
            results.popitem(last=False)
        return hit


class AsPathListEntry(object):
    """One ``seq action regex`` line of an AS-path access-list.

    The matcher is compiled at construction, and the hit counter is here for
    the same reason it is on a prefix-list entry: "which line of my filter
    actually fired" is the first question asked when a filter behaves
    unexpectedly, and a list-level counter cannot answer it.

    :param seq: sequence number; ascending order is evaluation order.
    :param action: ``'permit'``, ``'deny'``, or the matching int.
    :param pattern: the regex text.
    :raises ValueError: a bad action, a bad seq, or a bad pattern.
    """

    __slots__ = ('seq', 'action', 'matcher', 'hits')

    def __init__(self, seq, action, pattern):
        self.seq = seq_number(seq)
        self.action = action_id(action)
        self.matcher = AsPathMatcher(pattern)
        self.hits = 0

    def __repr__(self):
        return '<AsPathListEntry %d %s %r>' % (
            self.seq, ACTION_NAMES[self.action], self.matcher.pattern)

    @property
    def pattern(self):
        """The regex text as configured."""
        return self.matcher.pattern

    def as_dict(self):
        """Render the entry for show output.

        :return: a dict of plain types.
        """
        return {
            'seq': self.seq,
            'action': ACTION_NAMES[self.action],
            'regex': self.matcher.pattern,
            'hits': self.hits,
        }


class AsPathList(object):
    """A named, ordered list of permit/deny AS-path regexes.

    IOS' ``ip as-path access-list``. The evaluation rule is the prefix-list
    rule and is deliberately identical: the first entry in ascending ``seq``
    order whose regex matches decides, and a path that matches nothing gets
    :data:`NO_MATCH`, which a caller treats as a deny. Sharing the rule and
    the action constants with :mod:`~..prefixlist` is not a coincidence --
    a route-map clause consults both kinds of list and must not have to
    remember which one spells "no opinion" differently.

    Ordering is kept by insertion rather than by sorting on read: the list is
    walked per path per peer, and a sort inside that walk would be the most
    expensive thing in it.

    :param name: the name configuration references it by.
    :raises ValueError: an empty name.
    """

    __slots__ = ('name', 'version', 'hits', 'matches', '_entries')

    def __init__(self, name):
        if not name:
            raise ValueError('an as-path access-list name is required')
        self.name = name
        # Bumped on every mutation. An update-group key cites it, so it must
        # move whenever the list's behaviour could have changed; see the
        # note on version numbers in store.py.
        self.version = 0
        self.hits = 0
        self.matches = 0
        self._entries = []

    def __len__(self):
        return len(self._entries)

    def __repr__(self):
        return '<AsPathList %s entries=%d version=%d>' % (
            self.name, len(self._entries), self.version)

    # --- mutation ----------------------------------------------------------

    def add(self, seq, action, pattern):
        """Add or replace one entry.

        A duplicate ``seq`` replaces the entry holding it, which is what
        re-issuing a line with the same sequence number does on a router.

        :param seq: sequence number.
        :param action: ``'permit'``, ``'deny'``, or the matching int.
        :param pattern: the regex text.
        :return: the :class:`AsPathListEntry` stored.
        :raises ValueError: a bad seq, action or pattern. Nothing is
            modified when this raises: the entry is built, and therefore
            the pattern compiled, before the list is touched.
        """
        entry = AsPathListEntry(seq, action, pattern)
        for index in range(len(self._entries)):
            existing = self._entries[index]
            if existing.seq == entry.seq:
                self._entries[index] = entry
                self.version += 1
                return entry
            if existing.seq > entry.seq:
                self._entries.insert(index, entry)
                self.version += 1
                return entry
        self._entries.append(entry)
        self.version += 1
        return entry

    def remove(self, seq):
        """Remove the entry with a sequence number.

        :param seq: the sequence number.
        :return: True if an entry was removed. Removing something absent is
            not an error: it is what applying a diff twice looks like.
        :raises ValueError: a seq that is not a non-negative integer.
        """
        wanted = seq_number(seq)
        for index in range(len(self._entries)):
            if self._entries[index].seq == wanted:
                del self._entries[index]
                self.version += 1
                return True
        return False

    def clear(self):
        """Drop every entry, keeping this object's identity and version line.

        How :class:`~..store.PolicyStore` reloads a list whose
        configuration changed; see :meth:`PrefixList.clear` for why the
        object is not simply replaced.

        :return: the number of entries removed.
        """
        removed = len(self._entries)
        self._entries = []
        if removed:
            self.version += 1
        return removed

    # --- evaluation --------------------------------------------------------

    def evaluate(self, as_path_str):
        """Decide what this list says about one AS path.

        :param as_path_str: the canonical AS path string; None is treated as
            an empty path.
        :return: :data:`ACTION_PERMIT`, :data:`ACTION_DENY`, or
            :data:`NO_MATCH` when no entry matched.
        :raises ValueError: ``as_path_str`` is neither a string nor None.
        """
        if as_path_str is None:
            as_path_str = ''
        elif not isinstance(as_path_str, str):
            raise ValueError('an AS path must be a string, not %s'
                             % type(as_path_str).__name__)
        self.hits += 1
        for entry in self._entries:
            if entry.matcher.matches(as_path_str):
                entry.hits += 1
                self.matches += 1
                return entry.action
        return NO_MATCH

    def permits(self, as_path_str):
        """Return whether this list permits an AS path.

        :param as_path_str: the canonical AS path string.
        :return: True only for an explicit permit; deny and no-match are
            both False.
        """
        return self.evaluate(as_path_str) == ACTION_PERMIT

    # --- views -------------------------------------------------------------

    def entries(self):
        """Return every entry in ascending ``seq`` order.

        :return: a new list of :class:`AsPathListEntry`; the entries are the
            live ones, so their hit counters keep moving.
        """
        return list(self._entries)

    def as_dict(self):
        """Render the list for show output.

        ``hits`` counts evaluations and ``matches`` the subset that found an
        entry, so ``hits - matches`` is how often the implicit deny fired.

        :return: a dict of plain types.
        """
        return {
            'name': self.name,
            'version': self.version,
            'entries': [e.as_dict() for e in self._entries],
            'hits': self.hits,
            'matches': self.matches,
        }
