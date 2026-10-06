"""
Stage 1.7: SMT refinement of the taint scanner's verdicts.

Stage 1 decides whether a guard is sufficient with rules over the AST.  The
question those rules are really answering is about machine arithmetic — can
this be negative, can this product wrap, does a bound on `off` still hold for
`off + 1` — so each rule is an approximation.  This stage re-asks the same
question of Z3 over bitvectors with C's widths and conversions, and retires
the finding only when the obligation Stage 1's verdict rested on comes back
provable.

Everything the encoder could not resolve is an unconstrained bitvector, so a
proof holds for every value those could take; anything short of a proof leaves
the finding exactly where it was.  A counterexample is not a bug claim either,
only a concrete assignment Stage 2 can check against the real callers.

Cross-function findings are left alone: the sink is in the callee and the
guard is in the caller, and neither body answers the question on its own.
"""

import json
import sys
from collections import Counter, defaultdict
from multiprocessing import get_context
from pathlib import Path


def _check_file(job):
    """Refine every finding whose sink is in one file.  Runs in a worker."""
    path, indexed, timeout_ms = job
    from kernel_analysis.parsers.c_parser import parse_file, find_functions
    from bounds_checker.smt import check_finding

    try:
        tree, source = parse_file(path)
        bodies = {f['name']: f['body'] for f in find_functions(tree, source)}
    except Exception as e:
        return [(i, {'verdict': 'error', 'detail': f'{type(e).__name__}: {e}'})
                for i, _ in indexed]

    out = []
    for i, finding in indexed:
        body = bodies.get(finding['function'])
        if body is None:
            continue
        try:
            r = check_finding(finding, body, source, timeout_ms=timeout_ms,
                              c_path=path)
        except Exception as e:
            out.append((i, {'verdict': 'error',
                            'detail': f'{type(e).__name__}: {e}'}))
            continue
        if r.verdict == 'not-modelled':
            continue
        out.append((i, {
            'verdict':   r.verdict,
            'property':  r.prop,
            'detail':    r.detail,
            'witness':   r.witness,
            'retires':   bool(r.suppresses and r.verdict == 'safe'),
        }))
    return out


def _emit(run_dir, stage1_output):
    """
    Re-emit what Stage 1 deferred: its findings file and the static-only
    report, both of which this stage may have changed under them.
    """
    from bounds_checker.report import write_reports
    (Path(run_dir) / 'stage1_taint_scan.json').write_text(
        json.dumps(stage1_output, indent=2))
    write_reports(run_dir, stage1_output,
                  {'analyses': [], 'model': '—', 'functions_analyzed': 0})


def run(cfg, run_dir, stage1_output, verbose=False, n_workers=1):
    """
    Annotate Stage 1 findings with an `smt` verdict and move the retired ones
    aside.  `stage1_output` is modified in place so Stage 2 and the reports
    see the surviving set; the retired findings stay in the run under
    'findings_suppressed' so the decision is auditable.

    Stage 1 skips its own report when this stage is enabled, so every exit
    from here has to leave one behind.
    """
    try:
        import z3                                            # noqa: F401
    except ImportError:
        print("Stage 1.7 (SMT): z3-solver not installed — skipping")
        _emit(run_dir, stage1_output)
        return None

    findings = stage1_output.get('findings', [])
    if not findings:
        print("Stage 1.7 (SMT): no findings to refine.")
        _emit(run_dir, stage1_output)
        return None

    timeout_ms = int(cfg.get('smt', {}).get('timeout_ms', 200))

    by_file = defaultdict(list)
    skipped = 0
    for i, f in enumerate(findings):
        if f.get('propagation') == 'cross_function':
            skipped += 1
            continue
        by_file[f['file']].append((i, f))

    jobs = [(path, items, timeout_ms) for path, items in sorted(by_file.items())]
    print(f"Stage 1.7 (SMT): refining {sum(len(j[1]) for j in jobs)} finding(s) "
          f"in {len(jobs)} file(s)"
          + (f", {skipped} cross-function skipped" if skipped else '')
          + (f", {n_workers} workers" if n_workers > 1 else ''))

    results = []
    if n_workers > 1 and len(jobs) > 1:
        # fork, not the default: a worker inherits the parsed tree-sitter
        # grammar and the caller's module state instead of re-importing, and
        # the caller need not be a file on disk.
        with get_context('fork').Pool(min(n_workers, len(jobs))) as pool:
            for res in pool.imap_unordered(_check_file, jobs, chunksize=4):
                results.extend(res)
    else:
        for job in jobs:
            results.extend(_check_file(job))

    errors = 0
    for i, smt in results:
        if smt['verdict'] == 'error':
            errors += 1
            if verbose:
                f = findings[i]
                print(f"  !! {f['file']}:{f['sink_line']} {f['function']}(): "
                      f"{smt['detail']}", file=sys.stderr)
            continue
        findings[i]['smt'] = smt

    retired = [f for f in findings if f.get('smt', {}).get('retires')]
    kept    = [f for f in findings if not f.get('smt', {}).get('retires')]
    stage1_output['findings'] = kept
    stage1_output['findings_suppressed'] = retired
    stage1_output['findings_count'] = len(kept)

    _print_summary(retired, kept, errors, verbose)

    output = {
        'stage':      'smt_refinement',
        'timeout_ms': timeout_ms,
        'checked':    sum(len(j[1]) for j in jobs),
        'skipped_cross_function': skipped,
        'errors':     errors,
        'retired':    [_digest(f) for f in retired],
        'verdicts':   dict(Counter(f.get('smt', {}).get('verdict', 'not-modelled')
                                   for f in findings)),
    }
    out_path = Path(run_dir) / 'stage1_7_smt.json'
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Stage 1.7 output: {out_path}")

    _emit(run_dir, stage1_output)
    return output


def _digest(f):
    smt = f.get('smt', {})
    return {
        'file':     f['file'],
        'function': f['function'],
        'line':     f['sink_line'],
        'category': f['category'],
        'guard_kind': f.get('guard_kind', ''),
        'property': smt.get('property', ''),
        'detail':   smt.get('detail', ''),
    }


def _print_summary(retired, kept, errors, verbose):
    counts = Counter(f.get('smt', {}).get('verdict', 'not-modelled')
                     for f in kept + retired)
    witnessed = [f for f in kept if f.get('smt', {}).get('verdict') == 'witness']

    print(f"  Retired {len(retired)} finding(s); {len(kept)} remain"
          + (f"  ({errors} error(s))" if errors else ''))
    print("  " + "  ".join(f"{v}={n}" for v, n in counts.most_common()
                           if v != 'not-modelled'))

    if retired:
        by = Counter((f.get('guard_kind', '') or '—',
                      f['smt']['property']) for f in retired)
        print("  Retired by (guard_kind, property proved):")
        for (kind, prop), n in by.most_common():
            print(f"    {kind:24} {prop:24} {n}")
        if verbose:
            for f in retired:
                print(f"      {Path(f['file']).name}:{f['sink_line']} "
                      f"{f['function']}() — {f['smt']['detail']}")

    if witnessed:
        print(f"  {len(witnessed)} finding(s) carry a counterexample for Stage 2"
              f"; {sum(1 for f in witnessed if f.get('guard_kind') == 'bounded')} "
              f"of them Stage 1 had called bounded")
        if verbose:
            for f in witnessed:
                w = ' '.join(f'{k}={v}' for k, v in f['smt']['witness'].items())
                print(f"      {Path(f['file']).name}:{f['sink_line']} "
                      f"{f['function']}() {f['smt']['property']} — {w}")
    print()
