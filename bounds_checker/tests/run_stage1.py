#!/usr/bin/env python3
"""
Stage 1 scanner test harness.

Runs the taint scanner (and G1/G2 scanner) over probe_stage1.c and checks
findings against the expected table.

Outcome types:
  bug_*     — must produce Cat X, possibly_guarded=False
  guarded_* — must produce Cat X, possibly_guarded=True
  fp_*      — Stage 1 fires (possibly_guarded=True); only Stage 1.7 retires
              it.  These are conservatively flagged findings that are not real
              bugs in this specific case — Stage 2 would call them FP.

Exit code: 0 if all pass, 1 if any fail.
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bounds_checker.parsers.taint_scanner import scan_files, scan_copy_user_files

PROBE = Path(__file__).parent / 'probe_stage1.c'

# ---------------------------------------------------------------------------
# Expected findings table
#
# {'cat': 'X', 'guarded': bool}  — must produce that finding
# 'no_finding'                   — must produce NO finding for ANY category
# ---------------------------------------------------------------------------
EXPECTED = {
    # ── Category A ──────────────────────────────────────────────────────────
    'bug_A_memcpy_src_ptr':         {'cat': 'A', 'guarded': False},
    'bug_A_memcpy_dst_ptr':         {'cat': 'A', 'guarded': False},
    'guarded_A_bounded_ptr':        {'cat': 'A', 'guarded': True},

    # ── Category B ──────────────────────────────────────────────────────────
    'bug_B_kmalloc':                {'cat': 'B', 'guarded': False},
    'bug_B_overflow':               {'cat': 'B', 'guarded': False},
    'guarded_B_bounded':            {'cat': 'B', 'guarded': True},
    # Stage 1 fires on kmalloc_array(tainted_count, ...) — the count is
    # server-supplied and unvalidated even though the multiplication is safe.
    'fp_B_kmalloc_array':           {'cat': 'B', 'guarded': False},

    # ── Category C ──────────────────────────────────────────────────────────
    'bug_C_subscript':              {'cat': 'C', 'guarded': False},
    'guarded_C_bounded':            {'cat': 'C', 'guarded': True},
    # Stage 1 fires even with a bitmask; Stage 1.7 proves it safe.
    'fp_C_masked':                  {'cat': 'C', 'guarded': False},

    # ── Category D ──────────────────────────────────────────────────────────
    'bug_D_strlen':                 {'cat': 'D', 'guarded': False},
    # Discarded memchr is NOT a guard — finding survives with guarded=False.
    'bug_D_memchr_discarded':       {'cat': 'D', 'guarded': False},
    # Checked memchr/strnlen: Stage 1 fires with guarded=True; Stage 2 dismisses.
    'guarded_D_memchr_checked':     {'cat': 'D', 'guarded': True},
    'guarded_D_strnlen_checked':    {'cat': 'D', 'guarded': True},

    # ── Category E ──────────────────────────────────────────────────────────
    'bug_E_field_deref':            {'cat': 'E', 'guarded': False},
    'guarded_E_bounded':            {'cat': 'E', 'guarded': True},

    # ── Category F ──────────────────────────────────────────────────────────
    'bug_F_loop':                   {'cat': 'F', 'guarded': False},
    'guarded_F_bounded_loop':       {'cat': 'F', 'guarded': True},

    # ── Category G1 ─────────────────────────────────────────────────────────
    'bug_G1_discarded':             {'cat': 'G1', 'guarded': False},
    'bug_G1_unchecked_assign':      {'cat': 'G1', 'guarded': False},
    'fp_G1_checked':                'no_finding',

    # ── Category G2 ─────────────────────────────────────────────────────────
    'bug_G2_unvalidated_size':      {'cat': 'G2', 'guarded': False},
    'fp_G2_bounded':                'no_finding',

    # ── Category H ──────────────────────────────────────────────────────────
    'bug_H_u32_to_u16':             {'cat': 'H', 'guarded': False},
    'bug_H_u16_to_u8':              {'cat': 'H', 'guarded': False},
    'fp_H_same_width':              'no_finding',
    'fp_H_widening':                'no_finding',

    # ── Category L ──────────────────────────────────────────────────────────
    'bug_L_left_shift':             {'cat': 'L', 'guarded': False},
    'bug_L_right_shift':            {'cat': 'L', 'guarded': False},
    'guarded_L_bounded':            {'cat': 'L', 'guarded': True},
    # Stage 1 fires even with a bitmask; Stage 1.7 proves it safe.
    'fp_L_masked':                  {'cat': 'L', 'guarded': False},
}


def run():
    # Stage 1 taint scanner (A, B, C, D, E, F, H, L)
    findings = scan_files([str(PROBE)])
    # G1/G2 live in a separate scanner pass
    findings += scan_copy_user_files(
        [str(PROBE)], cats={'G1', 'G2'})

    # Group by (function, category)
    by_fn_cat = defaultdict(list)
    for f in findings:
        by_fn_cat[(f['function'], f['category'])].append(f)

    by_fn = defaultdict(list)
    for f in findings:
        by_fn[f['function']].append(f)

    rows = []
    passed = failed = 0

    for fn, exp in sorted(EXPECTED.items()):
        if exp == 'no_finding':
            if by_fn[fn]:
                cats = ', '.join(sorted({f['category'] for f in by_fn[fn]}))
                rows.append(('FAIL', fn, f'expected no finding, got Cat {cats}'))
                failed += 1
            else:
                rows.append(('.   ', fn, 'no finding (correct)'))
                passed += 1
        else:
            cat = exp['cat']
            want_guarded = exp['guarded']
            matches = by_fn_cat.get((fn, cat), [])
            if not matches:
                all_cats = sorted({f['category'] for f in by_fn[fn]})
                rows.append(('FAIL', fn,
                             f'expected Cat {cat} finding, got nothing '
                             f'(all: {all_cats})'))
                failed += 1
                continue
            hit = next(
                (f for f in matches if bool(f.get('possibly_guarded')) == want_guarded),
                matches[0],
            )
            got_guarded = bool(hit.get('possibly_guarded'))
            if got_guarded != want_guarded:
                rows.append(('FAIL', fn,
                             f'Cat {cat} found but guarded={got_guarded}, '
                             f'want guarded={want_guarded}'))
                failed += 1
            else:
                g = 'guarded' if got_guarded else 'unguarded'
                rows.append(('.   ', fn, f'Cat {cat} {g} (correct)'))
                passed += 1

    w = max(len(r[1]) for r in rows)
    for mark, fn, msg in rows:
        print(f"{mark} {fn:{w}}  {msg}")

    # Warn about unexpected findings from functions not in EXPECTED
    unexpected_fns = set(by_fn) - set(EXPECTED)
    if unexpected_fns:
        print()
        for fn in sorted(unexpected_fns):
            cats = ', '.join(sorted({f['category'] for f in by_fn[fn]}))
            print(f"WARN unlisted {fn:{w}}  Cat {cats}")

    print(f"\n{passed} pass, {failed} fail")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
