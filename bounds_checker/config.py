"""Configuration loading for the bounds checker."""

import argparse
import sys
from pathlib import Path

import yaml


# Known Claude models, most-capable-first.  IDs are the Anthropic/Vertex model strings.
KNOWN_MODELS = [
    ('claude-opus-5',               'Claude Opus 5      — highest capability, slowest, most expensive'),
    ('claude-sonnet-5',             'Claude Sonnet 5    — strong capability, balanced speed/cost'),
    ('claude-sonnet-4-6',           'Claude Sonnet 4.6  — default; good balance of quality and throughput'),
    ('claude-haiku-4-5-20251001',   'Claude Haiku 4.5   — fastest, lowest cost; lighter analysis'),
]

_DEFAULT_MODEL = 'claude-sonnet-4-6'


DEFAULT_CONFIG = {
    'kernel_source': '/home/src/linux',
    'target': {
        'source_dirs': [],
    },
    'categories': ['A', 'B', 'C', 'D', 'E', 'F', 'G1', 'G2', 'H'],   # which categories to scan
    'output': {
        'dir': 'bc_runs/',
    },
    'llm': {
        'enabled': False,
        'model': _DEFAULT_MODEL,
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
        if getattr(cli_args, 'model', None):
            cfg['llm']['model'] = cli_args.model
        if getattr(cli_args, 'llm_workers', None) is not None:
            cfg['llm']['workers'] = cli_args.llm_workers
        if getattr(cli_args, 'llm_categories', None):
            cfg['llm']['categories'] = cli_args.llm_categories

    cfg['kernel_source'] = Path(cfg['kernel_source']).expanduser().resolve()
    if not cfg['kernel_source'].exists():
        print(f"Error: kernel_source not found: {cfg['kernel_source']}", file=sys.stderr)
        sys.exit(1)

    return cfg


def build_arg_parser():
    p = argparse.ArgumentParser(
        description='Kernel bounds / data validation checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --source-dir fs/smb/client
  %(prog)s --source-dir fs/xfs --categories A B
  %(prog)s --config bc_config.yaml
""",
    )
    p.add_argument('--config', default=None,
                   help='Path to YAML config file')
    p.add_argument('--kernel-source', metavar='PATH',
                   help='Path to kernel source tree')
    p.add_argument('--source-dir', metavar='DIR', action='append',
                   help='Source directory to scan (relative to kernel_source); '
                        'may be repeated')
    p.add_argument('--categories', metavar='CAT', nargs='+',
                   choices=['A', 'B', 'C', 'D', 'E', 'F', 'G1', 'G2', 'H'],
                   help='Categories to scan (default: A B C D E F G1 G2 H)')
    p.add_argument('--output-dir', metavar='DIR',
                   help='Output directory for run artifacts')
    p.add_argument('--llm', action='store_true',
                   help='Enable Stage 2 LLM deep analysis (requires API credentials)')
    p.add_argument('--model', metavar='MODEL',
                   help='Claude model for LLM analysis (overrides config); '
                        'use --list-models to see known models')
    p.add_argument('--list-models', action='store_true',
                   help='List known Claude model IDs and exit')
    p.add_argument('--thinking', metavar='TOKENS', type=int, default=0,
                   help='Extended thinking budget in tokens (0=disabled; min 1024)')
    p.add_argument('--llm-workers', metavar='N', type=int, default=None,
                   help='Number of parallel LLM API calls (default: 4; use 1 for serial)')
    p.add_argument('--llm-categories', metavar='CAT', nargs='+',
                   choices=['A', 'B', 'C', 'D', 'E', 'F', 'G1', 'G2', 'H'],
                   help='Limit LLM analysis to these categories (default: all scanned); '
                        'useful to skip noisy categories like H or G2')
    p.add_argument('--debug', action='store_true',
                   help='Write full LLM prompts and responses to stage2_llm_analysis.debug')
    p.add_argument('--verbose', '-v', action='store_true')
    return p
