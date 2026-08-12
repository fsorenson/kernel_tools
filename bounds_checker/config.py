"""Configuration loading for the bounds checker."""

import argparse
import sys
from pathlib import Path

import yaml


DEFAULT_CONFIG = {
    'kernel_source': '/home/src/linux',
    'target': {
        'source_dirs': [],
    },
    'categories': ['A', 'B', 'C'],   # which categories to scan
    'output': {
        'dir': 'bc_runs/',
    },
    'llm': {
        'enabled': False,
        'model': 'claude-sonnet-4-6',
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
                   choices=['A', 'B', 'C', 'D', 'E', 'F', 'G'],
                   help='Categories to scan (default: A B C)')
    p.add_argument('--output-dir', metavar='DIR',
                   help='Output directory for run artifacts')
    p.add_argument('--llm', action='store_true',
                   help='Enable LLM deep analysis stage (not yet implemented)')
    p.add_argument('--verbose', '-v', action='store_true')
    return p
