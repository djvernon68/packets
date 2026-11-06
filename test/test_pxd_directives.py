"""Guard against compiler directives written as decorators in a ``.pxd``.

Cython parses ``@cython.boundscheck(False)`` on a ``cdef inline`` function in
a ``.pxd`` and then silently discards it. No warning, no error: the function
compiles with the directive still at its default, in every module that
``cimport``s it. This was not a theory -- ``rd_u16``/``rd_u32`` in
``packets/core/inetpkt.pxd`` carried both decorators from the day they were
written and had been compiling with full bounds and wraparound checks, a
RefNanny context and a ``WriteUnraisable`` error path the whole time, which is
the exact opposite of what their own comments and ``need_bytes``' docstring
said. Verified on Cython 0.28.1 and 0.29.37 by reading the generated C:
``__Pyx_RaiseBufferIndexError`` was present in ``rd_u16``'s body.

The form that *is* honoured is a ``with`` block inside the function::

    cdef inline uint16_t rd_u16(const unsigned char[:] b, Py_ssize_t off) nogil:
        with cython.boundscheck(False), cython.wraparound(False):
            return (<uint16_t>b[off] << 8) | b[off + 1]

so this module fails if a directive decorator reappears on anything in a
``.pxd``. It is deliberately pure Python over the source text: it needs no
build, runs in milliseconds, and catches the mistake at the point it is made
rather than after someone reads generated C.

Note the distinction the matcher draws. Decorators that configure *code
generation* for a function or block -- ``boundscheck``, ``wraparound``,
``cdivision`` and friends -- are the dropped ones. Decorators that are part of
a ``cdef class`` *declaration* -- ``@cython.final``, ``@cython.freelist(n)``,
``@cython.no_gc`` -- belong in a ``.pxd``, are honoured there, and must not be
flagged; ``inetpkt.pxd`` uses ``@cython.final`` legitimately.
"""

import os
import re
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories that hold generated or vendored copies of the sources. A stale
# .pxd under build/ is not something a developer edits, and flagging it would
# make the guard fail for a reason no source change can fix.
_SKIP_DIRS = frozenset(('build', 'dist', '.git', '.tox', '.eggs',
                        '__pycache__', '.venv', 'venv'))

# Compiler directives that Cython accepts as a decorator in a .pyx but drops
# in a .pxd. Taken from the directive list in the Cython compilation
# documentation, restricted to the ones that are meaningful per function or
# per block -- which is exactly the set someone reaches for when hand-tuning a
# shared inline reader.
_DROPPED_DIRECTIVES = (
    'boundscheck',
    'wraparound',
    'cdivision',
    'cdivision_warnings',
    'initializedcheck',
    'nonecheck',
    'overflowcheck',
    'always_allow_keywords',
    'infer_types',
    'linetrace',
    'profile',
    'embedsignature',
    'optimize.use_switch',
    'optimize.unpack_method_calls',
)

_DIRECTIVE_RE = re.compile(
    r'^\s*@\s*(?:cython\.)?(%s)\s*(?:\(|$)' %
    '|'.join(re.escape(d) for d in _DROPPED_DIRECTIVES))


def _pxd_files():
    """Every checked-in .pxd in the tree, as (repo-relative path, abs path)."""
    found = []
    for dirpath, dirnames, filenames in os.walk(_REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if name.endswith('.pxd'):
                abs_path = os.path.join(dirpath, name)
                found.append((os.path.relpath(abs_path, _REPO_ROOT),
                              abs_path))
    found.sort()
    return found


class PxdDirectiveDecoratorTestCase(unittest.TestCase):

    def test_tree_has_pxd_files_to_check(self):
        # A guard that silently checks nothing is worse than no guard: if the
        # walk stops finding the headers (moved, renamed, run from an
        # unexpected root) this fails rather than passing vacuously.
        names = [rel for rel, _ in _pxd_files()]
        self.assertTrue(names, 'no .pxd files found under %s' % _REPO_ROOT)
        self.assertIn('packets/core/inetpkt.pxd'.replace('/', os.sep), names)

    def test_no_directive_decorators_in_any_pxd(self):
        offenders = []
        for rel, abs_path in _pxd_files():
            with open(abs_path, 'r') as fh:
                for lineno, line in enumerate(fh, 1):
                    match = _DIRECTIVE_RE.match(line)
                    if match is not None:
                        offenders.append('%s:%d: %s' %
                                         (rel, lineno, line.strip()))
        self.assertEqual(
            offenders, [],
            'Cython silently drops a compiler-directive decorator in a .pxd. '
            'Put the directive in a "with cython.<directive>(False):" block '
            'inside the function body instead, which is honoured, or delete '
            'it and say in a comment that the check is deliberate:\n  ' +
            '\n  '.join(offenders))

    def test_the_shared_readers_keep_their_with_block(self):
        # C-4: the guard above only bans the decorator. Deleting it without
        # writing the `with` block would pass that test and leave rd_u16 and
        # rd_u32 silently bounds-checked again -- correct, but not what the
        # callers' guards and the benchmarks assume.
        path = os.path.join(_REPO_ROOT, 'packets', 'core', 'inetpkt.pxd')
        with open(path, 'r') as fh:
            source = fh.read()
        for name in ('rd_u16', 'rd_u32'):
            match = re.search(r'^cdef inline \S+ %s\(.*?(?=^\S)' % name,
                              source, re.S | re.M)
            self.assertIsNotNone(match, '%s not found in %s' % (name, path))
            self.assertIn('with cython.boundscheck(False), '
                          'cython.wraparound(False):', match.group(0),
                          '%s lost its directive block' % name)

    def test_matcher_flags_the_forms_it_must(self):
        # The matcher is the whole guard, so it gets its own coverage: a
        # false negative here would make the test above pass for the wrong
        # reason, which is the failure mode that let this defect live.
        for line in ('@cython.boundscheck(False)',
                     '@cython.wraparound(False)',
                     '  @cython.boundscheck(False)',
                     '@ cython.boundscheck(False)',
                     '@boundscheck(False)',
                     '@cython.cdivision(True)',
                     '@cython.initializedcheck(False)'):
            self.assertIsNotNone(_DIRECTIVE_RE.match(line),
                                 'missed %r' % line)

    def test_matcher_allows_class_declaration_decorators(self):
        # These are part of a cdef class declaration, are honoured in a .pxd,
        # and are in use: inetpkt.pxd declares @cython.final classes.
        for line in ('@cython.final',
                     '@cython.freelist(8)',
                     '@cython.no_gc_clear',
                     '@cython.internal',
                     '    # @cython.boundscheck(False) in a comment',
                     'with cython.boundscheck(False), cython.wraparound(False):'):
            self.assertIsNone(_DIRECTIVE_RE.match(line),
                              'wrongly flagged %r' % line)


if __name__ == '__main__':
    unittest.main()
