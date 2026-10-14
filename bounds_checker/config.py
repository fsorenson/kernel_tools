"""Configuration loading for the bounds checker."""

import argparse
import re
import sys
from pathlib import Path

import yaml


KNOWN_MODELS = [
    ('claude-opus-5',               'Claude Opus 5      — highest capability, slowest, most expensive'),
    ('claude-sonnet-5',             'Claude Sonnet 5    — strong capability, balanced speed/cost'),
    ('claude-sonnet-4-6',           'Claude Sonnet 4.6  — default; good balance of quality and throughput'),
    ('claude-haiku-4-5-20251001',   'Claude Haiku 4.5   — fastest, lowest cost; lighter analysis'),
    ('gemini-2.5-pro',              'Gemini 2.5 Pro     — Google; strong reasoning, 1M context'),
    ('gemini-2.5-flash',            'Gemini 2.5 Flash   — Google; fast, cost-effective'),
]


# Ordered list used for range expansion in --categories / --llm-categories.
_VALID_CATS = ['A', 'B', 'C', 'D', 'E', 'F', 'G1', 'G2', 'H', 'L']
_CAT_INDEX  = {c: i for i, c in enumerate(_VALID_CATS)}


def parse_categories(s):
    """
    Parse a category specification into a deduplicated ordered list.

    Accepts comma-separated tokens, whitespace-separated tokens, and
    hyphen-separated ranges.  Examples:
        'A,B,C'   → ['A','B','C']
        'A-D'     → ['A','B','C','D']
        'A-C,G1'  → ['A','B','C','G1']
        'A B C'   → ['A','B','C']
    """
    tokens = re.split(r'[,\s]+', s.strip())
    result = []
    for tok in tokens:
        if not tok:
            continue
        if tok in _CAT_INDEX:
            result.append(tok)
        elif '-' in tok:
            # Hyphen separates two valid category names.
            # Split at the FIRST hyphen; multi-char names like G1, G2 never
            # contain hyphens, so this is unambiguous.
            lo, hi = tok.split('-', 1)
            if lo not in _CAT_INDEX or hi not in _CAT_INDEX:
                raise argparse.ArgumentTypeError(
                    f"Unknown category in range {tok!r} — "
                    f"valid: {', '.join(_VALID_CATS)}")
            si, ei = _CAT_INDEX[lo], _CAT_INDEX[hi]
            if si > ei:
                raise argparse.ArgumentTypeError(
                    f"Range {tok!r}: {lo!r} comes after {hi!r} in the "
                    f"category order ({', '.join(_VALID_CATS)})")
            result.extend(_VALID_CATS[si:ei + 1])
        else:
            raise argparse.ArgumentTypeError(
                f"Unknown category {tok!r} — valid: {', '.join(_VALID_CATS)}")
    # Deduplicate while preserving first-seen order.
    seen = set()
    return [c for c in result if not (c in seen or seen.add(c))]


DEFAULT_CONFIG = {
    'kernel_source': '/home/src/linux',
    'target': {
        'source_dirs':  [],   # relative to kernel_source; recursed for .c/.h
        'source_paths': [],   # absolute Path objects: files scanned directly,
                              # directories recursed — from positional CLI args
    },
    'categories': ['A', 'B', 'C', 'D', 'E', 'F', 'G1', 'G2', 'H', 'L'],   # which categories to scan
    'output': {
        'dir': 'bc_runs/',
    },
    'smt': {
        'enabled': True,
        # Per-query budget.  A proof that needs longer than this is rare enough
        # that waiting for it costs more than the finding it would retire.
        'timeout_ms': 200,
        'workers': 8,
    },
    'llm': {
        'enabled': False,
        'model': None,          # auto-detected from provider; override with --model
        'workers': 4,
    },
}


def _deep_merge(base, override):
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
    return base


def load_config(config_path=None, cli_args=None):
    cfg = {k: (dict(v) if isinstance(v, dict) else v)
           for k, v in DEFAULT_CONFIG.items()}

    if config_path:
        config_path = Path(config_path)
        if not config_path.exists():
            print(f"Error: config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
        with open(config_path) as f:
            file_cfg = yaml.safe_load(f) or {}
        _deep_merge(cfg, file_cfg)

    if cli_args:
        if getattr(cli_args, 'kernel_source', None):
            cfg['kernel_source'] = cli_args.kernel_source
        if getattr(cli_args, 'source_dir', None):
            cfg['target']['source_dirs'] = cli_args.source_dir
        if getattr(cli_args, 'output_dir', None):
            cfg['output']['dir'] = cli_args.output_dir
        if getattr(cli_args, 'categories', None):
            cfg['categories'] = cli_args.categories
        if getattr(cli_args, 'no_smt', False):
            cfg['smt']['enabled'] = False
        if getattr(cli_args, 'smt_timeout', None) is not None:
            cfg['smt']['timeout_ms'] = cli_args.smt_timeout
        if getattr(cli_args, 'smt_workers', None) is not None:
            cfg['smt']['workers'] = cli_args.smt_workers
        if getattr(cli_args, 'model', None):
            cfg['llm']['model'] = cli_args.model
        if getattr(cli_args, 'llm_workers', None) is not None:
            cfg['llm']['workers'] = cli_args.llm_workers
        if getattr(cli_args, 'llm_categories', None):
            cfg['llm']['categories'] = cli_args.llm_categories

        # Positional PATH arguments: resolve each against CWD; files are
        # scanned directly, directories are recursed for .c/.h files.
        for raw in getattr(cli_args, 'paths', None) or []:
            p = Path(raw).expanduser().resolve()
            if not p.exists():
                print(f"Error: path not found: {raw}", file=sys.stderr)
                sys.exit(1)
            cfg['target']['source_paths'].append(p)

    cfg['kernel_source'] = Path(cfg['kernel_source']).expanduser().resolve()
    if not cfg['kernel_source'].exists():
        print(f"Error: kernel_source not found: {cfg['kernel_source']}", file=sys.stderr)
        sys.exit(1)

    return cfg


def build_arg_parser():
    _cat_metavar = 'CAT[,CAT|-CAT]'
    _cat_help_suffix = (
        f'  Categories: {", ".join(_VALID_CATS)}.  '
        f'Accepts comma-separated values, hyphen ranges, or a mix: '
        f'"A-D", "A,B,G1", "A-C,G1-H".'
    )
    p = argparse.ArgumentParser(
        description='Kernel bounds / data validation checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s fs/smb/client
  %(prog)s fs/smb/client/reparse.c --llm
  %(prog)s --source-dir fs/xfs --categories A-D
  %(prog)s --config bc_config.yaml fs/smb/client
""",
    )
    p.add_argument('paths', metavar='PATH', nargs='*',
                   help='Files (.c/.h) or directories to scan (resolved from CWD; '
                        'directories are recursed for .c and .h files)')
    p.add_argument('--config', default=None,
                   help='Path to YAML config file')
    p.add_argument('--kernel-source', metavar='PATH',
                   help='Path to kernel source tree')
    p.add_argument('--source-dir', metavar='DIR', action='append',
                   help='Source directory to scan (relative to kernel_source); '
                        'may be repeated; superseded by positional PATH args '
                        'when both are given')
    p.add_argument('--categories', metavar=_cat_metavar, type=parse_categories,
                   help='Categories to scan (default: all).' + _cat_help_suffix)
    p.add_argument('--output-dir', metavar='DIR',
                   help='Output directory for run artifacts')
    p.add_argument('--no-smt', action='store_true',
                   help='Skip Stage 1.7 SMT refinement (keeps findings a solver '
                        'can prove safe)')
    p.add_argument('--smt-timeout', metavar='MS', type=int, default=None,
                   help='Per-query solver budget in ms (default: 200)')
    p.add_argument('--smt-workers', metavar='N', type=int, default=None,
                   help='Parallel SMT worker processes (default: 8; use 1 for serial)')
    p.add_argument('--llm', action='store_true',
                   help='Enable Stage 2 LLM deep analysis (requires API credentials)')
    p.add_argument('--model', metavar='MODEL',
                   help='LLM model for Stage 2 analysis (overrides config/auto-detect); '
                        'use --list-models to see known models')
    p.add_argument('--list-models', action='store_true',
                   help='List known model IDs and exit')
    p.add_argument('--thinking', metavar='TOKENS', type=int, default=0,
                   help='Extended thinking budget in tokens (0=disabled; min 1024)')
    p.add_argument('--llm-workers', metavar='N', type=int, default=None,
                   help='Number of parallel LLM API calls (default: 4; use 1 for serial)')
    p.add_argument('--llm-categories', metavar=_cat_metavar, type=parse_categories,
                   help='Limit LLM analysis to these categories (default: all scanned); '
                        'useful to skip noisy categories like H or G2.'
                        + _cat_help_suffix)
    p.add_argument('--debug', action='store_true',
                   help='Write full LLM prompts and responses to stage2_llm_analysis.debug')
    p.add_argument('--verbose', '-v', action='store_true')
    return p
