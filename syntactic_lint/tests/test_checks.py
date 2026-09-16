"""
Regression suite: run every check over every fixture and compare against
`expected.json`.

    python3 -m syntactic_lint.tests.test_checks          # run, exit 1 on failure
    python3 -m syntactic_lint.tests.test_checks --update # rewrite expected.json
    pytest syntactic_lint/tests/                         # same, under pytest

Comparison is on the whole finding set per fixture, at `--min-severity low`, so
a new finding fails as loudly as a lost one.  That is the point: the tool's
value is its silence, and a change that makes it noisier somewhere unrelated is
exactly the change that would otherwise go unnoticed.
"""

import argparse
import json
import sys
from pathlib import Path

from syntactic_lint.checks import CHECKS, scan_paths
from syntactic_lint.tests.cases import CASES

FIXTURE_DIR = Path(__file__).parent / 'fixtures'
EXPECTED = Path(__file__).parent / 'expected.json'

_SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def fixture_path(case):
    return FIXTURE_DIR / f'{case.name}.c'


def actual(case, max_bits=16):
    """The finding set for one fixture, as sorted (check, severity, fn, line)."""
    findings = scan_paths([fixture_path(case)], checks=CHECKS, max_bits=max_bits)
    return sorted(
        [f['check'], f['severity'], f['function'], f['line']] for f in findings)


def load_expected():
    if not EXPECTED.exists():
        return {}
    return {k: sorted(v) for k, v in json.loads(EXPECTED.read_text()).items()}


def _describe(rows):
    return [f"{c:12s} {s:6s} {fn}() line {ln}" for c, s, fn, ln in rows] or ['(none)']


def check_case(case, expected):
    """Return a list of failure lines, empty when the case passes."""
    path = fixture_path(case)
    if not path.exists():
        return [f"missing fixture {path.name} "
                f"(run: python3 -m syntactic_lint.tests.extract)"]
    if case.name not in expected:
        return [f"no entry in expected.json "
                f"(run: python3 -m syntactic_lint.tests.test_checks --update)"]

    got, want = actual(case), expected[case.name]
    if got == want:
        return []

    gained = [r for r in got if r not in want]
    lost = [r for r in want if r not in got]
    out = []
    if gained:
        out += ['  new findings:'] + [f"    + {d}" for d in _describe(gained)]
    if lost:
        out += ['  findings lost:'] + [f"    - {d}" for d in _describe(lost)]
    return out


def main(argv=None):
    p = argparse.ArgumentParser(prog='syntactic_lint.tests.test_checks')
    p.add_argument('--update', action='store_true',
                   help='rewrite expected.json from the current output')
    p.add_argument('--case', metavar='NAME', nargs='*',
                   help='run only these cases (default: all)')
    args = p.parse_args(argv)

    wanted = set(args.case or ())
    cases = [c for c in CASES if not wanted or c.name in wanted]

    if args.update:
        blob = load_expected() if wanted else {}
        for case in cases:
            blob[case.name] = actual(case)
        EXPECTED.write_text(json.dumps(blob, indent=2) + '\n')
        print(f"wrote {len(blob)} entries to {EXPECTED.name}")
        return 0

    expected = load_expected()
    failed = 0
    for case in cases:
        problems = check_case(case, expected)
        n = len(expected.get(case.name, ()))
        if problems:
            failed += 1
            print(f"FAIL  {case.name}")
            print('\n'.join(problems))
        else:
            print(f"ok    {case.name}  ({n} finding{'' if n == 1 else 's'}, "
                  f"{case.verdict})")

    print(f"\n{len(cases) - failed}/{len(cases)} cases pass")
    return 1 if failed else 0


# -- pytest entry point ----------------------------------------------------

def pytest_generate_tests(metafunc):
    if 'case' in metafunc.fixturenames:
        metafunc.parametrize('case', CASES, ids=[c.name for c in CASES])


def test_fixture(case):
    problems = check_case(case, load_expected())
    assert not problems, f"{case.name}:\n" + '\n'.join(problems)


if __name__ == '__main__':
    sys.exit(main())
