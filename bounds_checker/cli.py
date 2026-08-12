"""Bounds checker command-line entry point."""

import json
import sys
from datetime import datetime
from pathlib import Path

from bounds_checker.config import build_arg_parser, load_config, KNOWN_MODELS
from bounds_checker.stages import stage1_taint_scan, stage2_llm_analysis


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.list_models:
        print("Known Claude model IDs (pass to --model or set llm.model in config):\n")
        for model_id, desc in KNOWN_MODELS:
            print(f"  {model_id:<36}  {desc}")
        print()
        sys.exit(0)

    cfg = load_config(args.config, args)

    if not cfg['target']['source_dirs']:
        print("Error: specify --source-dir DIR (e.g. --source-dir fs/smb/client)",
              file=sys.stderr)
        sys.exit(1)

    # Create run directory
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    subsystem = cfg['target']['source_dirs'][0].replace('/', '_')
    run_dir = Path(cfg['output']['dir']) / f"{ts}_{subsystem}"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Save config snapshot
    snapshot = {
        'kernel_source': str(cfg['kernel_source']),
        'target': cfg['target'],
        'categories': cfg['categories'],
    }
    (run_dir / 'config_snapshot.json').write_text(json.dumps(snapshot, indent=2))

    print(f"\n{'='*60}")
    print(f"  Kernel Bounds / Data Validation Checker")
    print(f"{'='*60}")
    print(f"Run directory: {run_dir}")
    print(f"Kernel source: {cfg['kernel_source']}")
    print(f"Source dirs:   {', '.join(cfg['target']['source_dirs'])}")
    print(f"Categories:    {', '.join(cfg['categories'])}")

    # Stage 1: taint scan (Categories A, B, C)
    cats = set(cfg['categories'])
    _TAINT_CATS = {'A', 'B', 'C', 'E', 'F', 'H'}
    if cats & _TAINT_CATS:
        active = ', '.join(sorted(cats & _TAINT_CATS))
        print(f"\n--- Stage 1: Taint Scanner (Cat {active}) ---")
        s1 = stage1_taint_scan.run(cfg, run_dir, verbose=args.verbose)
    else:
        s1 = None

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
            )
        else:
            print("  Skipped — no Stage 1 findings.")

    print(f"\nDone. Artifacts in: {run_dir}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
