#!/usr/bin/env python3
"""
Stage 1.5 caller enumeration test harness.

Step A: tests find_call_sites() and is_static_fn()
Step B: tests fn_param_names(), identify_taint_param(), annotate_with_guards()

Exit code: 0 if all pass, 1 if any fail.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from kernel_analysis.parsers.c_parser import parse_file, find_functions
from bounds_checker.parsers.taint_scanner import scan_files
from bounds_checker.stages.stage1_5_callers import (
    find_call_sites, is_static_fn,
    fn_param_names, identify_taint_param, annotate_with_guards,
)

PROBE = Path(__file__).parent / 'probe_callers.c'

EXPECTED_SITES = {
    # caller_fn → arg[0] text
    'caller_guarded':   'h',
    'caller_unguarded': 'h',
}


def run():
    bad = 0
    total = 0

    def check(label, got, want):
        nonlocal bad, total
        total += 1
        if got == want:
            print(f'.  {label}')
        else:
            print(f'FAIL  {label}: expected {want!r}, got {got!r}')
            bad += 1

    tree, source = parse_file(str(PROBE))
    fns = {f['name']: f for f in find_functions(tree, source)}

    # ── Step A: is_static_fn ────────────────────────────────────────────
    check('static_helper is_static',
          is_static_fn(fns['static_helper']['node'], source), True)
    check('caller_guarded is_static',
          is_static_fn(fns['caller_guarded']['node'], source), False)
    check('non_static_helper is_static',
          is_static_fn(fns['non_static_helper']['node'], source), False)

    # ── Step A: find_call_sites ──────────────────────────────────────────
    sites = find_call_sites('static_helper', [PROBE])
    check('call_site_count', len(sites), 2)

    by_caller = {s['caller_fn']: s for s in sites}
    check('caller_fns', set(by_caller), set(EXPECTED_SITES))

    for caller, expected_arg0 in EXPECTED_SITES.items():
        s = by_caller.get(caller, {})
        check(f'{caller} arg[0]',       s.get('args', [''])[0], expected_arg0)
        check(f'{caller} snippet',      bool(s.get('snippet')), True)
        check(f'{caller} line > 0',     (s.get('line') or 0) > 0, True)
        check(f'{caller} arg_names[0]', 'h' in s.get('arg_names', [{}])[0], True)

    check('missing_fn', find_call_sites('no_such_fn', [PROBE]), [])

    # ── Step B: fn_param_names ───────────────────────────────────────────
    helper_params = fn_param_names(fns['static_helper']['node'], source)
    check('static_helper params[0]', helper_params[0], 'h')
    check('static_helper params[1]', helper_params[1], 'extra')
    check('static_helper param_count', len(helper_params), 2)

    # ── Step B: identify_taint_param ────────────────────────────────────
    # Run Stage 1 to get a finding for static_helper.
    findings = scan_files([str(PROBE)])
    helper_findings = [f for f in findings if f['function'] == 'static_helper']
    if not helper_findings:
        print('FAIL  identify_taint_param: no findings for static_helper')
        bad += 1
        total += 1
    else:
        f = helper_findings[0]
        fn_body = fns['static_helper']['body']
        result = identify_taint_param(f, fn_body, source)
        check('taint_param_name',  result[0] if result else None, 'h')
        check('taint_param_index', result[1] if result else None, 0)

    # ── Step B: annotate_with_guards ────────────────────────────────────
    # param_idx=0 corresponds to `h`
    annotate_with_guards(sites, param_idx=0)

    guarded_site   = by_caller.get('caller_guarded', {})
    unguarded_site = by_caller.get('caller_unguarded', {})

    check('caller_guarded guarded',     guarded_site.get('guarded'),   True)
    check('caller_unguarded guarded',   unguarded_site.get('guarded'), False)
    check('caller_guarded guard_kind',  bool(guarded_site.get('guard_kind')), True)

    # annotate_with_guards when param_idx=None → all sites get guarded=None
    none_sites = [dict(s) for s in sites]
    annotate_with_guards(none_sites, param_idx=None)
    check('param_unknown guarded',      none_sites[0].get('guarded'),   None)
    check('param_unknown guard_kind',   none_sites[0].get('guard_kind'), 'param-unknown')

    print(f'\n{total - bad} pass, {bad} fail')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(run())
