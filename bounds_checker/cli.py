"""Bounds checker command-line entry point."""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from bounds_checker.config import build_arg_parser, load_config, KNOWN_MODELS
from bounds_checker.stages import (
    stage1_taint_scan, stage1_7_smt, stage2_llm_analysis,
)


def _main_merge(argv):
    """Handle: bc merge DIR [DIR ...] [--output DIR] [-v]"""
    from bounds_checker.stages import merge as merge_stage

    p = argparse.ArgumentParser(
        prog='bc merge',
        description='Merge multiple bounds-checker run directories into a unified report',
    )
    p.add_argument('run_dirs', metavar='DIR', nargs='+',
                   help='Run directories to merge (must contain stage1_taint_scan.json)')
    p.add_argument('--output', metavar='DIR',
                   help='Output directory (default: <first_run_parent>/merged_TIMESTAMP)')
    p.add_argument('--verbose', '-v', action='store_true')
    args = p.parse_args(argv)

    result = merge_stage.run(args.run_dirs, output_dir=args.output, verbose=args.verbose)
    return 0 if result else 1


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'merge':
        return _main_merge(sys.argv[2:])

    parser = build_arg_parser()
    args = parser.parse_args()

    if args.list_models:
        print("Known model IDs (pass to --model or set llm.model in config):\n")
        for model_id, desc in KNOWN_MODELS:
            print(f"  {model_id:<36}  {desc}")
        print("\nProvider is auto-detected from environment variables (first match wins):")
        print("  GOOGLE_CLOUD_PROJECT          → Gemini via Vertex AI (uses ADC)")
        print("  GEMINI_API_KEY                → Gemini via API key")
        print("  ANTHROPIC_VERTEX_PROJECT_ID   → Anthropic via Vertex AI")
        print("  ANTHROPIC_API_KEY             → Anthropic direct")
        print()
        sys.exit(0)

    cfg = load_config(args.config, args)

    if not cfg['target']['source_dirs'] and not cfg['target']['source_paths']:
        print("Error: specify at least one path to scan (positional PATH, or "
              "--source-dir DIR)", file=sys.stderr)
        sys.exit(1)

    # Create run directory, naming it after the first scan target.
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if cfg['target']['source_dirs']:
        label = cfg['target']['source_dirs'][0].replace('/', '_')
    else:
        first = cfg['target']['source_paths'][0]
        label = first.name  # file or dir basename
    run_dir = Path(cfg['output']['dir']) / f"{ts}_{label}"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Save config snapshot (source_paths contains Path objects; stringify them).
    snapshot = {
        'kernel_source': str(cfg['kernel_source']),
        'target': {
            'source_dirs':  cfg['target']['source_dirs'],
            'source_paths': [str(p) for p in cfg['target']['source_paths']],
        },
        'categories': cfg['categories'],
    }
    (run_dir / 'config_snapshot.json').write_text(json.dumps(snapshot, indent=2))

    print(f"\n{'='*60}")
    print(f"  Kernel Bounds / Data Validation Checker")
    print(f"{'='*60}")
    print(f"Run directory: {run_dir}")
    print(f"Kernel source: {cfg['kernel_source']}")
    all_targets = (cfg['target']['source_dirs'] +
                   [str(p) for p in cfg['target']['source_paths']])
    print(f"Scan targets:  {', '.join(all_targets)}")
    print(f"Categories:    {', '.join(cfg['categories'])}")

    # Stage 1: taint scan (Categories A, B, C)
    cats = set(cfg['categories'])
    _TAINT_CATS = {'A', 'B', 'C', 'D', 'E', 'F', 'G1', 'G2', 'H'}
    if cats & _TAINT_CATS:
        active = ', '.join(sorted(cats & _TAINT_CATS))
        print(f"\n--- Stage 1: Taint Scanner (Cat {active}) ---")
        s1 = stage1_taint_scan.run(cfg, run_dir, verbose=args.verbose,
                                   write_report=not cfg['smt']['enabled'])
    else:
        s1 = None

    # Stage 1.7: SMT refinement — retires what a solver can prove safe and
    # attaches a counterexample to the rest.
    if s1 and cfg['smt']['enabled']:
        print("\n--- Stage 1.7: SMT Refinement ---")
        stage1_7_smt.run(cfg, run_dir, s1, verbose=args.verbose,
                         n_workers=cfg['smt'].get('workers', 8))

    # Stage 2: LLM analysis
    if args.llm:
        print("\n--- Stage 2: LLM Analysis ---")
        if s1:
            cfg['llm']['enabled'] = True
            stage2_llm_analysis.run(
                cfg, run_dir, s1,
                verbose=args.verbose,
                debug=args.debug,
                thinking_budget=args.thinking,
                n_workers=cfg['llm'].get('workers', 4),
            )
        else:
            print("  Skipped — no Stage 1 findings.")

    print(f"\nDone. Artifacts in: {run_dir}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
