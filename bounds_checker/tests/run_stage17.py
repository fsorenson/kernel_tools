#!/usr/bin/env python3
"""
Stage 1.7 SMT test harness.

Runs the taint scanner + SMT refinement over probe_smt.c (and optionally
cfg.c) and checks each finding's SMT verdict against an expected table.

Verdict codes:
  'safe'   — UNSAT; the obligation is provable
  'unsafe' — SAT witness exists
  '-'      — not-modelled; SMT cannot answer (expected for Cat E / buffer-size)

Exit code: 0 if all pass, 1 if any fail.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from kernel_analysis.parsers.c_parser import parse_file, find_functions
from bounds_checker.parsers.taint_scanner import scan_files
from bounds_checker.smt import check_finding

PROBE_SMT    = Path(__file__).parent / 'probe_smt.c'
PROBE_STAGE1 = Path(__file__).parent / 'probe_stage1.c'

# ---------------------------------------------------------------------------
# Expected SMT verdicts
#   'safe'   — solver must prove the obligation (UNSAT on the claim)
#   'unsafe' — solver must find a concrete witness (SAT)
#   (absent) — not checked (not-modelled or uncertain)
# ---------------------------------------------------------------------------
EXPECT = {
    # ── probe_smt.c (subscript / guard-kind cases) ───────────────────────
    'probe_mask':              'safe',     # & 0x0F pins both ends
    'probe_signed':            'unsafe',   # ceiling only, signed
    'probe_lookahead':         'unsafe',   # guard saw off, sink uses off+1
    'ctl_unsigned_upper':      'safe',
    'ctl_signed_both':         'safe',
    'ctl_unsigned_cast':       'safe',
    'ctl_guard_sees_offset':   'safe',
    'ctl_unlikely_wrapped':    'safe',
    'ctl_signed_narrow_src':   'safe',     # 16-bit source cannot be negative
    'ctl_signed_shifted':      'safe',     # >> of unsigned cannot be negative
    'ctl_signed_masked':       'safe',     # & 0x00FFFFFF non-negative
    'probe_signed_same_width': 'unsafe',   # 32-bit read keeps the sign bit
    'ctl_kill_branch_local':   'unsafe',
    'ctl_kill_compound':       'unsafe',
    'ctl_kill_retaint':        'unsafe',
    'ctl_redef_clamped':       'safe',
    'ctl_redef_unreachable':   'safe',
    'ctl_redef_reguarded':     'safe',
    'ctl_redef_transform':     'safe',     # floor guard, not a ceiling
    'ctl_call_arg_not_guard':  'safe',     # u16 cannot be negative
    'ctl_signed_div':          'safe',     # / 8 keeps it off the bottom
    'ctl_offset_shrinks':      'safe',     # len - 4 stays under the ceiling
    # ── cfg.c (control-flow cases) ──────────────────────────────────────
    'cfg_nondominating':       'safe',     # u16; real defect is unmodelled
    'cfg_killed_def':          'unsafe',   # len <= 64 then len += 8
    'cfg_goto_fallthrough':    'safe',     # label clears the env
    'cfg_ctl_ok':              'safe',
    'cfg_ctl_goto_below':      'safe',
    # ── Cat L (shift-bounds) cases from probe_stage1.c ──────────────────
    'bug_L_left_shift':        'unsafe',   # unbounded shift → witness at 0x20
    'bug_L_right_shift':       'unsafe',   # same for >>
    'guarded_L_bounded':       'safe',     # if (order >= 32) return 0
    'fp_L_masked':             'safe',     # & 0x1f → shift-bounds UNSAT, retires
}

# Whether the clean answer retires (suppresses) the finding.
SUPPRESS = {
    'ctl_signed_div':      True,
    'ctl_offset_shrinks':  True,
    'fp_L_masked':         True,          # mask proves shift safe; finding retires
}


def run(paths=None):
    if paths is None:
        paths = [str(PROBE_SMT), str(PROBE_STAGE1)]

    rows, bad = [], 0

    for p in paths:
        tree, source = parse_file(p)
        bodies = {f['name']: f['body'] for f in find_functions(tree, source)}
        for f in scan_files([p]):
            body = bodies.get(f['function'])
            if body is None:
                continue
            r = check_finding(f, body, source, c_path=p)
            exp = EXPECT.get(f['function'])
            got = {'safe': 'safe', 'witness': 'unsafe'}.get(r.verdict, r.verdict)
            mark = ' '
            if exp and got in ('safe', 'unsafe'):
                if got != exp:
                    mark, bad = 'X', bad + 1
                else:
                    mark = '.'
            elif exp:
                mark = '?'
            sup = SUPPRESS.get(f['function'])
            if sup is not None and r.suppresses != sup:
                mark, bad = 'S', bad + 1
            rows.append((mark, f['function'], f['category'],
                         f.get('guard_kind', '') or '-', r.verdict,
                         r.prop, exp or '', 'y' if r.suppresses else '-',
                         r.witness))

    if not rows:
        print("No findings.")
        return 0

    w = max(len(r[1]) for r in rows)
    print(f"{'':2}{'function':{w}}  {'cat':3} {'guard_kind':24} "
          f"{'smt':12} {'property':22} {'exp':7} {'sup':3} witness")
    for mark, fn, cat, kind, verdict, prop, exp, sup, wit in rows:
        ws = ' '.join(f'{k}={v}' for k, v in list(wit.items())[:3])
        print(f"{mark} {fn:{w}}  {cat:3} {kind:24} {verdict:12} "
              f"{prop:22} {exp:7} {sup:3} {ws}")

    agree    = sum(1 for r in rows if r[0] == '.')
    unchecked = sum(1 for r in rows if r[0] in (' ', '?'))
    print(f"\n{agree} agree, {bad} disagree, {unchecked} unchecked")
    return 1 if bad else 0


if __name__ == '__main__':
    paths = sys.argv[1:] or None
    sys.exit(run(paths))
