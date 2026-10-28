#!/usr/bin/env python3
"""
Stage 1.5 caller enumeration test harness.

Step A: tests find_call_sites() and is_static_fn() against probe_callers.c.

Exit code: 0 if all pass, 1 if any fail.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from kernel_analysis.parsers.c_parser import parse_file, find_functions
from bounds_checker.stages.stage1_5_callers import find_call_sites, is_static_fn

PROBE = Path(__file__).parent / 'probe_callers.c'

EXPECTED_SITES = {
    # caller_fn → arg[0] text
    'caller_guarded':   'h',
    'caller_unguarded': 'h',
}


def run():
    bad = 0

    def check(label, got, want):
        nonlocal bad
        if got == want:
            print(f'.  {label}')
        else:
            print(f'FAIL  {label}: expected {want!r}, got {got!r}')
            bad += 1

    # ── is_static_fn ────────────────────────────────────────────────────
    tree, source = parse_file(str(PROBE))
    fns = {f['name']: f for f in find_functions(tree, source)}

    check('static_helper is_static',
          is_static_fn(fns['static_helper']['node'], source), True)
    check('caller_guarded is_static',
          is_static_fn(fns['caller_guarded']['node'], source), False)
    check('non_static_helper is_static',
          is_static_fn(fns['non_static_helper']['node'], source), False)

    # ── find_call_sites ──────────────────────────────────────────────────
    sites = find_call_sites('static_helper', [PROBE])

    check('call_site_count', len(sites), 2)

    by_caller = {s['caller_fn']: s for s in sites}
    check('caller_fns', set(by_caller), set(EXPECTED_SITES))

    for caller, expected_arg0 in EXPECTED_SITES.items():
        s = by_caller.get(caller, {})
        check(f'{caller} arg[0]',    s.get('args', [''])[0], expected_arg0)
        check(f'{caller} snippet',   bool(s.get('snippet')), True)
        check(f'{caller} line > 0',  (s.get('line') or 0) > 0, True)

    # find_call_sites for a name that doesn't exist → empty
    check('missing_fn', find_call_sites('no_such_fn', [PROBE]), [])

    total = bad + sum(1 for _ in range(11 - bad))
    print(f'\n{11 - bad} pass, {bad} fail')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(run())
