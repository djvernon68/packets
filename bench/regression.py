#!/usr/bin/env python3
"""Version-over-version regression driver for the packets library.

Builds a released baseline (a git ref, default tag ``2.1.5``) and the current
working tree, each in isolation, then measures both with the *current* harness
scripts and reports:

  * a per-row timing-delta table from ``bench/microbench.py --json``
    (median ns/pkt for baseline and current, plus percent change), and
  * a behavior diff of ``bench/correctness.py``'s golden JSON between the two
    builds (expected empty -- any entry is a behavior change).

Isolation model (never touches the system-installed packages):

  * The baseline is checked out into a throwaway ``git worktree`` and built
    with ``setup.py build_ext --inplace`` inside it.
  * The working tree is built in place the same way.
  * Each side is measured by running the *current* ``bench/microbench.py`` and
    ``bench/correctness.py`` with ``PYTHONPATH`` pointed at that build, so the
    harness is byte-for-byte identical for both sides and only the imported
    ``packets`` build differs. (Running each worktree's own harness would be
    apples-to-oranges: the baseline's microbench.py predates ``--json``.)
  * PYTHONPATH precedes site-packages, so the installed ``packets`` is never
    imported during a run.

Run on the Riverbed FlowGateway 10.32 (release 218) device, where the
Cython/gcc/libpcap toolchain lives:

    python3 bench/regression.py --baseline 2.1.5
    python3 bench/regression.py --baseline 2.1.5 --iterations 20000 --repeats 5

The created worktree is removed on exit, including on failure/interrupt.
"""
from __future__ import print_function
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MICROBENCH = os.path.join(HERE, 'microbench.py')
CORRECTNESS = os.path.join(HERE, 'correctness.py')


def _run(cmd, cwd=None, env=None, capture=True):
    """Run a command, returning (returncode, stdout, stderr) as text."""
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None)
    out, err = proc.communicate()
    if out is not None and not isinstance(out, str):
        out = out.decode('utf-8', 'replace')
    if err is not None and not isinstance(err, str):
        err = err.decode('utf-8', 'replace')
    return proc.returncode, out or '', err or ''


def _repo_root():
    rc, out, err = _run(['git', 'rev-parse', '--show-toplevel'], cwd=HERE)
    if rc != 0:
        raise SystemExit('not a git checkout: %s' % err.strip())
    return out.strip()


def _build_inplace(pkg_dir):
    """Compile the extensions of the checkout at pkg_dir, in place."""
    rc, out, err = _run([sys.executable, 'setup.py', 'build_ext', '--inplace'],
                        cwd=pkg_dir)
    if rc != 0:
        sys.stderr.write(out)
        sys.stderr.write(err)
        raise SystemExit('build_ext failed in %s' % pkg_dir)


def _env_with_pythonpath(pkg_dir):
    env = dict(os.environ)
    existing = env.get('PYTHONPATH', '')
    env['PYTHONPATH'] = pkg_dir + (os.pathsep + existing if existing else '')
    return env


def _measure(pkg_dir, iterations, repeats):
    """Run the current harness against the build at pkg_dir; return dicts."""
    env = _env_with_pythonpath(pkg_dir)
    rc, out, err = _run([sys.executable, MICROBENCH, '--json',
                         str(iterations), str(repeats)], cwd=HERE, env=env)
    if rc != 0:
        sys.stderr.write(err)
        raise SystemExit('microbench failed for %s' % pkg_dir)
    timings = json.loads(out)

    rc, out, err = _run([sys.executable, CORRECTNESS], cwd=HERE, env=env)
    if rc != 0:
        sys.stderr.write(err)
        raise SystemExit('correctness failed for %s' % pkg_dir)
    behavior = json.loads(out)
    return timings, behavior


def _print_timing_table(base, cur, base_label, cur_label):
    print('=' * 78)
    print('timing delta: %s -> %s (median ns/pkt; + means current is slower)'
          % (base_label, cur_label))
    print('-' * 78)
    print('%-24s %14s %14s %12s' % ('label', base_label, cur_label, 'delta %'))
    print('-' * 78)
    labels = sorted(set(base) & set(cur))
    for label in labels:
        b = base[label]['median_ns']
        c = cur[label]['median_ns']
        delta = ((c - b) / b * 100.0) if b else float('nan')
        print('%-24s %14.1f %14.1f %+11.1f%%' % (label, b, c, delta))
    only_base = sorted(set(base) - set(cur))
    only_cur = sorted(set(cur) - set(base))
    if only_base:
        print('labels only in %s: %s' % (base_label, ', '.join(only_base)))
    if only_cur:
        print('labels only in %s: %s' % (cur_label, ', '.join(only_cur)))
    print('-' * 78)


def _print_behavior_diff(base, cur, base_label, cur_label):
    print('=' * 78)
    print('behavior diff: %s vs %s (empty == no behavior change)'
          % (base_label, cur_label))
    print('-' * 78)
    keys = sorted(set(base) | set(cur))
    diffs = 0
    for key in keys:
        b = base.get(key)
        c = cur.get(key)
        if b != c:
            diffs += 1
            if key not in base:
                print('  + %s (only in %s)' % (key, cur_label))
            elif key not in cur:
                print('  - %s (only in %s)' % (key, base_label))
            else:
                print('  ~ %s differs' % key)
                _print_value_diff(b, c, base_label, cur_label)
    if diffs == 0:
        print('  (no differences)')
    print('-' * 78)
    return diffs


def _print_value_diff(b, c, base_label, cur_label):
    """Show the specific fields that differ for a changed correctness entry."""
    if isinstance(b, dict) and isinstance(c, dict):
        for field in sorted(set(b) | set(c)):
            if b.get(field) != c.get(field):
                print('      %s: %s=%r %s=%r'
                      % (field, base_label, b.get(field),
                         cur_label, c.get(field)))
    else:
        print('      %s=%r %s=%r' % (base_label, b, cur_label, c))


def _add_worktree(repo_root, ref):
    worktree = tempfile.mkdtemp(prefix='packets_regression_')
    rc, out, err = _run(['git', 'worktree', 'add', '--detach', worktree, ref],
                        cwd=repo_root)
    if rc != 0:
        shutil.rmtree(worktree, ignore_errors=True)
        raise SystemExit('git worktree add %s failed: %s' % (ref, err.strip()))
    return worktree


def _remove_worktree(repo_root, worktree):
    if not worktree:
        return
    _run(['git', 'worktree', 'remove', '--force', worktree], cwd=repo_root)
    shutil.rmtree(worktree, ignore_errors=True)
    _run(['git', 'worktree', 'prune'], cwd=repo_root)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--baseline', default='2.1.5',
                        help='git ref to compare against (default: %(default)s)')
    parser.add_argument('--iterations', type=int, default=20000,
                        help='microbench iterations per repeat '
                             '(default: %(default)s)')
    parser.add_argument('--repeats', type=int, default=5,
                        help='microbench repeats (default: %(default)s)')
    parser.add_argument('--keep', action='store_true',
                        help='keep the baseline git worktree for inspection')
    args = parser.parse_args()

    repo_root = _repo_root()
    cur_label = 'working-tree'
    base_label = args.baseline

    worktree = None
    try:
        print('building baseline %s in an isolated worktree...' % base_label,
              file=sys.stderr)
        worktree = _add_worktree(repo_root, args.baseline)
        _build_inplace(worktree)

        print('building working tree in place...', file=sys.stderr)
        _build_inplace(repo_root)

        print('measuring baseline...', file=sys.stderr)
        base_timings, base_behavior = _measure(worktree, args.iterations,
                                               args.repeats)
        print('measuring working tree...', file=sys.stderr)
        cur_timings, cur_behavior = _measure(repo_root, args.iterations,
                                             args.repeats)

        _print_timing_table(base_timings, cur_timings, base_label, cur_label)
        diffs = _print_behavior_diff(base_behavior, cur_behavior,
                                     base_label, cur_label)
        return 1 if diffs else 0
    finally:
        if worktree and not args.keep:
            _remove_worktree(repo_root, worktree)
        elif worktree:
            print('kept worktree at %s' % worktree, file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())
