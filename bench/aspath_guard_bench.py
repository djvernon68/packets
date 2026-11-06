#!/usr/bin/env python3
"""Worst-case cost of the AS-path regexes the P-2 guard accepts (S6-d).

The guard promises that no accepted regex can stall the engine thread on a
path a peer chose. This holds it to that promise on the host it runs on.
Rather than timing a fixed list, it asks the guard which candidates each
``maxas-limit`` regime accepts, then times every accepted one on the
slowest paths for that regime: all one-digit ASNs, which make every
``_1_`` match everywhere, and all ten-digit ones, which make every
``[0-9]+`` work hardest. A candidate the guard refuses is reported and not
timed, so a guard that starts admitting something slow fails here.

Each measurement runs in a child process with a time limit, because a
running ``re.search`` cannot be interrupted, and a slow candidate must cost
the run seconds, not the whole budget of the machine.

Regimes:

  * ``maxas-limit 255`` (the default): quadratic patterns are accepted;
    timed on 255-ASN paths.
  * ``maxas-limit 2000`` (the maximum): only linear ones; timed on
    2000-ASN paths. ``maxas-limit 0`` accepts the same set, and a 4096-byte
    UPDATE cannot carry a longer AS_PATH than this run uses.

Usage:
    PYTHONPATH=. python3 bench/aspath_guard_bench.py [budget_ms]

Exits 1 if any accepted pattern exceeds the budget (default 50 ms).
"""

from __future__ import print_function

import platform
import subprocess
import sys

from packets.routing.rtengine.policy import aspath

DEFAULT_BUDGET_MS = 50.0
TIMEOUT_S = 30

# Shapes found while fixing S6-d, accepted and refused, with the IOS idioms
# the guard must keep.
CANDIDATES = (
    # linear
    '_65001_', '^65001_', '_65001$', '^[0-9]+$', '^[0-9]+(_[0-9]+)*$',
    '^65001(_65001)*$', '^65000_([0-9]+_)*65001$', '^[0-9]+_.*X',
    '^[0-9]+(_[0-9]+)*X', '^([0-9]+_)*.*X',
    # quadratic
    '(_[0-9]+)*_65001$', '_65001_.*_65002_', '(_[0-9]+)*X',
    '(_[0-9]+)*_1_X', '_1_.*_1_X', '_1_.*X',
    '^[0-9]+(_[0-9]+)*(_[0-9]+)*X', '^[0-9]+_.*_1_.*X',
    '^65001_.*_65002_.*_65003_',
    # cubic and worse: the guard must refuse these
    '(_[0-9]+)*(_[0-9]+)*X', '_1_.*_1_.*_1_X', '.*_1_.*_1_.*X',
    '_1_.*_1_.*X', '(_[0-9]+)*_1_.*X', '_65001_.*_65002_.*_65003_',
    '^(_?[0-9]+)*X', '([0-9]+)+',
)

REGIMES = ((255, 255), (2000, 2000))

CHILD = r'''
import sys, time
from packets.routing.rtengine.policy.aspath import compile_pattern
regex = compile_pattern(sys.argv[1])
path = ' '.join([sys.argv[3]] * int(sys.argv[2]))
started = time.perf_counter()
regex.search(path)
print('%.3f' % ((time.perf_counter() - started) * 1000))
'''


def _accepted(pattern, maxas):
    try:
        aspath.check_length(pattern, maxas)
        return True
    except ValueError:
        return False


def _time(pattern, asns, asn):
    try:
        out = subprocess.run([sys.executable, '-c', CHILD, pattern, str(asns),
                              asn], stdout=subprocess.PIPE,
                             timeout=TIMEOUT_S, check=True)
    except subprocess.TimeoutExpired:
        return None
    return float(out.stdout.decode().strip())


def main(argv):
    budget = float(argv[1]) if len(argv) > 1 else DEFAULT_BUDGET_MS
    print('interpreter      : %s %s on %s' % (
        platform.python_implementation(), platform.python_version(),
        platform.machine()))
    print('budget           : %.1f ms per evaluation' % budget)
    failed = False
    for maxas, asns in REGIMES:
        accepted = [p for p in CANDIDATES if _accepted(p, maxas)]
        refused = [p for p in CANDIDATES if p not in accepted]
        print('\nmaxas-limit %d: %d accepted, %d refused; timed on %d ASNs'
              % (maxas, len(accepted), len(refused), asns))
        worst = (0.0, None)
        for pattern in accepted:
            times = [_time(pattern, asns, asn) for asn in ('1', '4294967295')]
            slowest = None if None in times else max(times)
            over = slowest is None or slowest > budget
            failed = failed or over
            if slowest is not None and slowest > worst[0]:
                worst = (slowest, pattern)
            print('  %-32s %10s ms%s' % (
                pattern, '>%d000' % TIMEOUT_S if slowest is None
                else '%.1f' % slowest, '  OVER BUDGET' if over else ''))
        print('  worst accepted: %.1f ms (%s)' % worst)
    print('\nguard: %s' % ('FAIL' if failed else 'PASS'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
