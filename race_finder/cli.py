"""Main CLI entry point."""

import sys
from datetime import datetime
from pathlib import Path

from .config import build_arg_parser, load_config
from .stages import (
    stage1_struct_map, stage2_lock_scan, stage3_async_tagger,
    stage4_toctou, stage6_llm_analysis, stage_report,
)


_ALL_STAGES = ['struct_map', 'lock_scan', 'async_tag', 'toctou', 'llm_analysis', 'report']


def _resolve_stages(raw):
    """Expand comma-separated values and 'all'; validate; return set or None."""
    if not raw:
        return None
    tokens = []
    for item in raw:
        tokens.extend(s.strip() for s in item.split(',') if s.strip())
    if 'all' in tokens:
        return set(_ALL_STAGES)
    valid = set(_ALL_STAGES)
    invalid = [t for t in tokens if t not in valid]
    if invalid:
        print(f"Error: unknown stage(s): {', '.join(invalid)}", file=sys.stderr)
        print(f"Valid stages: {', '.join(_ALL_STAGES)}, all", file=sys.stderr)
        sys.exit(1)
    return set(tokens)


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # Resolve config file relative to cwd or script location
    config_path = Path(args.config)
    if not config_path.exists():
        # Try next to this file
        config_path = Path(__file__).parent.parent / args.config
    cfg = load_config(config_path if config_path.exists() else None, args)

    # Determine which stages to run
    stages_requested = _resolve_stages(args.stages)

    def should_run(stage_name):
        if stages_requested:
            return stage_name in stages_requested
        return cfg['stages'].get(stage_name, False)

    # Create run directory
    target_name = cfg['target'].get('name') or 'unknown'
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_name = f"{timestamp}_{target_name}"

    output_base = Path(cfg['output']['dir'])
    if not output_base.is_absolute():
        output_base = config_path.parent / output_base if config_path.exists() else Path(cfg['output']['dir'])
    run_dir = output_base / run_name
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"Run directory: {run_dir}")
    print(f"Kernel source: {cfg['kernel_source']}")
    print(f"Target: {cfg['target']['type']} '{target_name}'\n")

    stage_results = {}

    if should_run('struct_map'):
        print("--- Stage 1: Structural Map ---")
        stage_results['struct_map'] = stage1_struct_map.run(cfg, run_dir, verbose=args.verbose)

    if should_run('async_tag'):
        print("\n--- Stage 3: Async/Callback Tagger ---")
        stage_results['async_tag'] = stage3_async_tagger.run(cfg, run_dir, verbose=args.verbose)

    if should_run('lock_scan'):
        print("\n--- Stage 2: Lock Usage Scan ---")
        s1 = stage_results.get('struct_map')
        s3 = stage_results.get('async_tag')
        if not s1:
            # Load from a prior run if stage 1 wasn't run this invocation
            import json, glob as _glob
            prior = sorted(_glob.glob(str(run_dir.parent / f'*_{target_name}' / 'stage1_struct_map.json')))
            if prior:
                with open(prior[-1]) as _f:
                    s1 = json.load(_f)
        if not s3:
            import json, glob as _glob
            prior = sorted(_glob.glob(str(run_dir.parent / f'*_{target_name}' / 'stage3_async_tags.json')))
            if prior:
                with open(prior[-1]) as _f:
                    s3 = json.load(_f)
        if not s1:
            print("  [skip] stage 1 output not available — run --stage struct_map first")
        else:
            stage_results['lock_scan'] = stage2_lock_scan.run(
                cfg, run_dir, s1, stage3_output=s3, verbose=args.verbose
            )

    if should_run('toctou'):
        print("\n--- Stage 4: TOCTOU Analysis ---")
        s1 = stage_results.get('struct_map')
        if not s1:
            import json, glob as _glob
            target_name = cfg['target'].get('name') or 'unknown'
            prior = sorted(_glob.glob(str(run_dir.parent / f'*_{target_name}' / 'stage1_struct_map.json')))
            if prior:
                with open(prior[-1]) as _f:
                    s1 = json.load(_f)
        if not s1:
            print("  [skip] stage 1 output not available — run --stage struct_map first")
        else:
            stage_results['toctou'] = stage4_toctou.run(cfg, run_dir, s1, verbose=args.verbose)

    if should_run('llm_analysis'):
        print("\n--- Stage 6: LLM Deep Analysis ---")
        import json, glob as _glob
        s1 = stage_results.get('struct_map')
        s2 = stage_results.get('lock_scan')
        if not s1:
            prior = sorted(_glob.glob(str(run_dir.parent / f'*_{target_name}' / 'stage1_struct_map.json')))
            if prior:
                with open(prior[-1]) as _f:
                    s1 = json.load(_f)
        if not s2:
            prior = sorted(_glob.glob(str(run_dir.parent / f'*_{target_name}' / 'stage2_lock_scan.json')))
            if prior:
                with open(prior[-1]) as _f:
                    s2 = json.load(_f)
        if not s1:
            print("  [skip] stage 1 output not available")
        elif not s2:
            print("  [skip] stage 2 output not available — run --stage lock_scan first")
        else:
            stage_results['llm_analysis'] = stage6_llm_analysis.run(
                cfg, run_dir, s1, s2, verbose=args.verbose,
                debug=cfg['llm'].get('debug', False),
                thinking_budget=cfg['llm'].get('thinking_budget', 0),
            )

    if should_run('report'):
        print("\n--- Report Generator ---")
        stage_results['report'] = stage_report.run(
            cfg, run_dir,
            stage1_output=stage_results.get('struct_map'),
            stage2_output=stage_results.get('lock_scan'),
            stage4_output=stage_results.get('toctou'),
            stage6_output=stage_results.get('llm_analysis'),
            verbose=args.verbose,
        )

    print(f"\nDone. Artifacts in: {run_dir}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
