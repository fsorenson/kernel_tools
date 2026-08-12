"""Stage 1: Intra-procedural taint scanner + cross-function propagation (Cat A, B, C)."""

import json
from pathlib import Path

from bounds_checker.parsers.taint_scanner import scan_files, TAINT_SOURCES, DANGEROUS_SINKS
from bounds_checker.parsers.cross_function import build_param_sink_map, scan_cross_function_calls
from bounds_checker.report import write_reports


def run(cfg, run_dir, verbose=False):
    """
    Scan all .c files in cfg['target']['source_dirs'] for taint flows.
    Writes stage1_taint_scan.json to run_dir and returns the output dict.
    """
    kernel_src = Path(cfg['kernel_source'])
    source_dirs = cfg['target'].get('source_dirs', [])
    if not source_dirs:
        print("Stage 1: no source_dirs configured")
        return None

    # Collect candidate .c files
    c_paths = []
    for d in source_dirs:
        dpath = kernel_src / d
        if not dpath.exists():
            print(f"  Warning: source_dir not found: {dpath}")
            continue
        c_paths.extend(sorted(dpath.rglob('*.c')))

    if not c_paths:
        print("Stage 1: no .c files found")
        return None

    print(f"  Scanning {len(c_paths)} file(s) in {', '.join(source_dirs)} ...")

    # Intra-procedural scan
    findings_intra = scan_files(c_paths, verbose=verbose)
    for f in findings_intra:
        f['propagation'] = 'intra'

    # Cross-function taint propagation
    print(f"  Building parameter sink map ({len(c_paths)} file(s)) ...")
    param_sink_map = build_param_sink_map(c_paths, verbose=verbose)
    n_propagating = sum(len(v) for v in param_sink_map.values())
    print(f"  {len(param_sink_map)} function(s) with "
          f"{n_propagating} taint-propagating parameter(s)")

    print(f"  Scanning call sites for cross-function flows ...")
    findings_cross = scan_cross_function_calls(c_paths, param_sink_map, verbose=verbose)

    all_findings = findings_intra + findings_cross

    # Categorize counts
    by_category = {}
    for f in all_findings:
        cat = f['category']
        by_category.setdefault(cat, []).append(f)

    _print_summary(findings_intra, findings_cross, by_category, c_paths)

    output = {
        'stage':                'taint_scan',
        'files_scanned':        len(c_paths),
        'source_dirs':          source_dirs,
        'findings_count':       len(all_findings),
        'findings_intra':       len(findings_intra),
        'findings_cross':       len(findings_cross),
        'findings':             all_findings,
    }

    out_path = Path(run_dir) / 'stage1_taint_scan.json'
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\nStage 1 output: {out_path}")

    # Write static-analysis-only report (superseded if Stage 2 runs)
    write_reports(run_dir, output, {'analyses': [], 'model': '—', 'functions_analyzed': 0})
    return output


def _print_summary(findings_intra, findings_cross, by_category, c_paths):
    all_findings = findings_intra + findings_cross
    total    = len(all_findings)
    guarded  = sum(1 for f in all_findings if f['possibly_guarded'])
    overflow = sum(1 for f in all_findings if f.get('overflow'))

    print(f"\n{'─'*60}")
    print(f"  Taint scan: {total} finding(s) in {len(c_paths)} file(s)")
    print(f"  Intra-procedural: {len(findings_intra)}   "
          f"Cross-function: {len(findings_cross)}   "
          f"Integer-overflow: {overflow}")
    print(f"  Unguarded: {total - guarded}   Possibly guarded: {guarded}")
    print()

    for cat in sorted(by_category):
        label = {
            'A': 'Cat A — server offset → pointer → memory op',
            'B': 'Cat B — server value → size/alloc argument',
            'C': 'Cat C — server value → array subscript',
        }.get(cat, f'Cat {cat}')
        entries   = by_category[cat]
        intra_n   = sum(1 for f in entries if f.get('propagation') == 'intra')
        cross_n   = sum(1 for f in entries if f.get('propagation') == 'cross_function')
        ovf_n     = sum(1 for f in entries if f.get('overflow'))
        guarded_n = sum(1 for f in entries if f['possibly_guarded'])
        ovf_str   = f', overflow={ovf_n}' if ovf_n else ''
        print(f"  [{cat}] {label}: {len(entries)} finding(s)"
              f"  (intra={intra_n}, xfn={cross_n}{ovf_str}, {guarded_n} possibly guarded)")
        for f in entries[:8]:
            guard_tag  = ' [guarded?]' if f['possibly_guarded'] else ''
            xfn_tag    = f' → {f["callee_fn"]}()' if f.get('propagation') == 'cross_function' else ''
            short_file = Path(f['file']).name
            print(f"    {f['function']}(){xfn_tag}  {short_file}:{f.get('call_site_line', f['sink_line'])}"
                  f"  via {f['taint_source_fn']}() → {f['sink_fn']}"
                  f"{guard_tag}")
        if len(entries) > 8:
            print(f"    ... and {len(entries) - 8} more")
        print()
