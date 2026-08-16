"""
Merge multiple bounds-checker run directories into a unified summary.

Usage (via CLI):
  bc merge bc_runs/dir1 bc_runs/dir2 ... [--output bc_runs/merged_TIMESTAMP]

Each run directory must contain stage1_taint_scan.json; stage2_llm_analysis.json
is optional.  Findings are deduplicated by stable content key across runs.
LLM finding_index values are re-mapped to the merged finding ordering so the
existing report renderer works without modification.
"""

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from bounds_checker.report import write_reports


_ASSESSMENT_SEVERITY = {
    'real_bug': 4, 'mixed': 3, 'needs_validation': 2, 'false_positive': 1, 'error': 0,
}
_CONFIDENCE_ORDER = {'high': 2, 'medium': 1, 'low': 0}


def _s1_key(f):
    """Stable dedup key for a Stage 1 finding — stable across identical scans."""
    return (
        f['file'], f['function'], f['category'],
        f['sink_line'], f['sink_fn'], f['tainted_var'],
    )


def _load_run(run_dir):
    """Load S1 and (optionally) S2 JSON from a run directory."""
    run_dir = Path(run_dir)
    s1_path = run_dir / 'stage1_taint_scan.json'
    s2_path = run_dir / 'stage2_llm_analysis.json'
    if not s1_path.exists():
        raise FileNotFoundError(f"stage1_taint_scan.json not found in {run_dir}")
    s1 = json.loads(s1_path.read_text())
    s2 = json.loads(s2_path.read_text()) if s2_path.exists() else {}
    return s1, s2


def _remap_llm_findings(run_fn_findings, merged_fn_findings, analysis):
    """
    Translate LLM finding_index values from positions in one run's per-function
    finding list to positions in the merged (deduplicated) finding list.

    run_fn_findings:    Stage 1 findings for this function from the source run.
    merged_fn_findings: Deduplicated merged list for the same function.
    analysis:           The Stage 2 analysis dict to remap.
    """
    merged_key_to_pos = {_s1_key(f): i for i, f in enumerate(merged_fn_findings, 1)}

    run_idx_to_merged = {}
    for i, f in enumerate(run_fn_findings, 1):
        merged_pos = merged_key_to_pos.get(_s1_key(f))
        if merged_pos is not None:
            run_idx_to_merged[i] = merged_pos

    new_llm_findings = []
    for lf in analysis.get('findings', []):
        orig = lf.get('finding_index', 0)
        new_lf = dict(lf)
        new_lf['finding_index'] = run_idx_to_merged.get(orig, orig)
        new_llm_findings.append(new_lf)

    return {**analysis, 'findings': new_llm_findings}


def _merge_fn_analyses(analyses):
    """
    Combine multiple remapped LLM analyses for the same function.

    Per-finding LLM data: first available assessment wins for each position
    (handles the case where different runs covered different LLM categories).
    Function-level: most-severe assessment, least-confident confidence, combined notes.
    """
    if len(analyses) == 1:
        return analyses[0]

    lkp = {}
    for a in analyses:
        for f in a.get('findings', []):
            idx = f.get('finding_index')
            if idx is not None and idx not in lkp:
                lkp[idx] = f

    assessment = max(
        (a.get('assessment', 'error') for a in analyses),
        key=lambda a: _ASSESSMENT_SEVERITY.get(a, 0),
    )
    confidence = min(
        (a.get('confidence', 'low') for a in analyses),
        key=lambda c: _CONFIDENCE_ORDER.get(c, 0),
    )
    notes_parts = [a['overall_notes'] for a in analyses if a.get('overall_notes')]

    first = analyses[0]
    return {
        'function':      first['function'],
        'file':          first['file'],
        'assessment':    assessment,
        'confidence':    confidence,
        'overall_notes': ' | '.join(notes_parts),
        'findings':      sorted(lkp.values(), key=lambda f: f.get('finding_index', 0)),
    }


def run(run_dirs, output_dir=None, verbose=False):
    """
    Merge run_dirs into a combined report written to output_dir.

    Returns the output Path, or None on failure.
    """
    if not run_dirs:
        print("merge: no run directories specified")
        return None

    print(f"Merging {len(run_dirs)} run(s):")

    # Load all runs, skip missing ones with a warning
    runs = []   # list of (Path, s1_dict, s2_dict)
    for rd in run_dirs:
        rd = Path(rd)
        try:
            s1, s2 = _load_run(rd)
            runs.append((rd, s1, s2))
            n_findings = s1.get('findings_count', len(s1.get('findings', [])))
            n_analyses = len(s2.get('analyses', []))
            llm_str = f", {n_analyses} LLM" if n_analyses else ''
            print(f"  {rd.name}: {n_findings} findings{llm_str}")
        except FileNotFoundError as e:
            print(f"  Warning: {e} — skipping")

    if not runs:
        print("merge: no valid runs found")
        return None

    # -----------------------------------------------------------------------
    # Build per-run finding groups {(fn, file) -> [findings]} — original order
    # -----------------------------------------------------------------------
    run_fn_groups = []
    for _, s1, _ in runs:
        groups = defaultdict(list)
        for f in s1.get('findings', []):
            groups[(f['function'], f['file'])].append(f)
        run_fn_groups.append(groups)

    # -----------------------------------------------------------------------
    # Merge Stage 1: deduplicate findings by stable key, first-seen wins
    # -----------------------------------------------------------------------
    seen_keys = set()
    merged_findings = []
    merged_fn_groups = defaultdict(list)   # (fn, file) -> deduplicated findings

    for groups in run_fn_groups:
        for fn_key, fn_findings in sorted(groups.items()):
            for f in fn_findings:
                sk = _s1_key(f)
                if sk not in seen_keys:
                    seen_keys.add(sk)
                    merged_findings.append(f)
                    merged_fn_groups[fn_key].append(f)

    total_raw = sum(len(s1.get('findings', [])) for _, s1, _ in runs)
    n_dupes = total_raw - len(merged_findings)

    # -----------------------------------------------------------------------
    # Merge Stage 2: remap per-finding indices, combine overlapping analyses
    # -----------------------------------------------------------------------
    fn_analyses = defaultdict(list)   # (fn, file) -> list of remapped analyses

    for (_, _, s2), fn_groups in zip(runs, run_fn_groups):
        # Build lookup for this run's analyses, keyed by both short_file and full path
        s2_by_fn = {}
        for a in s2.get('analyses', []):
            s2_by_fn[(a['function'], a['file'])] = a

        for fn_key, run_fn_findings in fn_groups.items():
            fn_name, filepath = fn_key
            short_file = Path(filepath).name
            # stage2 now stores filepath in 'file'; fall back to basename for old runs
            analysis = (s2_by_fn.get((fn_name, filepath))
                        or s2_by_fn.get((fn_name, short_file)))
            if analysis is None:
                continue
            remapped = _remap_llm_findings(
                run_fn_findings, merged_fn_groups[fn_key], analysis,
            )
            fn_analyses[fn_key].append(remapped)

    merged_analyses = []
    for fn_key in sorted(fn_analyses):
        merged_analyses.append(_merge_fn_analyses(fn_analyses[fn_key]))

    # -----------------------------------------------------------------------
    # Assemble merged stage1/stage2 dicts
    # -----------------------------------------------------------------------
    all_source_dirs = list(dict.fromkeys(
        d for _, s1, _ in runs for d in s1.get('source_dirs', [])
    ))
    kernel_git = next(
        (s1.get('kernel_git', {}) for _, s1, _ in runs if s1.get('kernel_git', {}).get('version')),
        {},
    )
    kernel_source = next(
        (s1.get('kernel_source', '') for _, s1, _ in runs if s1.get('kernel_source')),
        '',
    )
    all_models = list(dict.fromkeys(
        s2.get('model', '') for _, _, s2 in runs if s2.get('model')
    ))

    merged_s1 = {
        'stage':          'taint_scan',
        'source_dirs':    all_source_dirs,
        'kernel_source':  kernel_source,
        'files_scanned':  sum(s1.get('files_scanned', 0) for _, s1, _ in runs),
        'kernel_git':     kernel_git,
        'findings_count': len(merged_findings),
        'findings':       merged_findings,
    }
    merged_s2 = {
        'stage':              'llm_analysis',
        'model':              ', '.join(all_models) if all_models else '—',
        'source_dirs':        all_source_dirs,
        'functions_analyzed': len(merged_analyses),
        'analyses':           merged_analyses,
    }

    # -----------------------------------------------------------------------
    # Create output directory and write all outputs
    # -----------------------------------------------------------------------
    if output_dir is None:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = runs[0][0].parent / f"merged_{ts}"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dupe_str = f" ({n_dupes} duplicate(s) removed)" if n_dupes else ''
    print(f"\n  Total findings: {total_raw} → {len(merged_findings)} unique{dupe_str}")
    print(f"  LLM analyses:   {len(merged_analyses)} function(s)")
    print(f"  Output:         {output_dir}\n")

    (output_dir / 'merged_stage1.json').write_text(json.dumps(merged_s1, indent=2))
    (output_dir / 'merged_stage2.json').write_text(json.dumps(merged_s2, indent=2))

    write_reports(output_dir, merged_s1, merged_s2)
    return output_dir
