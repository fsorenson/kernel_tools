"""Stage 1: Intra-procedural taint scanner (Categories A, B, C)."""

import json
from pathlib import Path

from bounds_checker.parsers.taint_scanner import scan_files, TAINT_SOURCES, DANGEROUS_SINKS


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

    print(f"  Scanning {len(c_paths)} file(s) in "
          f"{', '.join(source_dirs)}...")

    findings = scan_files(c_paths, verbose=verbose)

    # Categorize counts
    by_category = {}
    for f in findings:
        cat = f['category']
        by_category.setdefault(cat, []).append(f)

    _print_summary(findings, by_category, c_paths)

    output = {
        'stage':          'taint_scan',
        'files_scanned':  len(c_paths),
        'source_dirs':    source_dirs,
        'findings_count': len(findings),
        'findings':       findings,
    }

    out_path = Path(run_dir) / 'stage1_taint_scan.json'
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\nStage 1 output: {out_path}")
    return output


def _print_summary(findings, by_category, c_paths):
    total = len(findings)
    guarded = sum(1 for f in findings if f['possibly_guarded'])
    unguarded = total - guarded

    print(f"\n{'─'*60}")
    print(f"  Taint scan: {total} finding(s) in {len(c_paths)} file(s)")
    print(f"  Unguarded: {unguarded}   Possibly guarded: {guarded}")
    print()

    for cat in sorted(by_category):
        label = {
            'A': 'Cat A — server offset → pointer → memory op',
            'B': 'Cat B — server value → size/alloc argument',
            'C': 'Cat C — server value → array subscript',
        }.get(cat, f'Cat {cat}')
        entries = by_category[cat]
        guarded_n = sum(1 for f in entries if f['possibly_guarded'])
        print(f"  [{cat}] {label}: {len(entries)} finding(s)"
              f"  ({guarded_n} possibly guarded)")
        for f in entries[:8]:
            guard_tag = ' [guarded?]' if f['possibly_guarded'] else ''
            short_file = Path(f['file']).name
            print(f"    {f['function']}()  {short_file}:{f['sink_line']}"
                  f"  via {f['taint_source_fn']}() → {f['sink_fn']}"
                  f"{guard_tag}")
        if len(entries) > 8:
            print(f"    ... and {len(entries) - 8} more")
        print()
