"""Configuration loading: YAML file merged with command-line overrides."""

import argparse
import sys
from pathlib import Path

import yaml


DEFAULT_CONFIG = {
    'kernel_source': '/home/src/linux',
    'target': {
        'type': 'struct',
        'name': None,
        'headers': [],
        'source_dirs': [],
    },
    'stages': {
        'struct_map': True,
        'lock_scan': False,
        'toctou': False,
        'llm_analysis': False,
    },
    'output': {
        'dir': 'runs/',
        'format': 'json',
    },
    'llm': {
        'enabled': False,
        'model': 'claude-sonnet-4-6',
    },
}


def _deep_merge(base, override):
    """Recursively merge override into base (modifies base in-place)."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
    return base


def load_config(config_path=None, cli_args=None):
    """
    Load configuration from YAML file, then apply CLI overrides.
    Returns a config dict with all paths resolved to absolute Path objects.
    """
    cfg = dict(DEFAULT_CONFIG)
    for k, v in cfg.items():
        if isinstance(v, dict):
            cfg[k] = dict(v)

    if config_path:
        config_path = Path(config_path)
        if not config_path.exists():
            print(f"Error: config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
        with open(config_path) as f:
            file_cfg = yaml.safe_load(f) or {}
        _deep_merge(cfg, file_cfg)

    # Apply CLI overrides
    if cli_args:
        if getattr(cli_args, 'kernel_source', None):
            cfg['kernel_source'] = cli_args.kernel_source
        if getattr(cli_args, 'struct', None):
            cfg['target']['type'] = 'struct'
            cfg['target']['name'] = cli_args.struct
        if getattr(cli_args, 'file', None):
            cfg['target']['type'] = 'file'
            cfg['target']['name'] = cli_args.file
        if getattr(cli_args, 'llm', None):
            cfg['llm']['enabled'] = True
            cfg['stages']['llm_analysis'] = True
        thinking = getattr(cli_args, 'llm_thinking', 0) or 0
        if thinking:
            cfg['llm']['thinking_budget'] = thinking
            cfg['llm']['debug'] = True   # thinking implies debug output
        if getattr(cli_args, 'llm_debug', False):
            cfg['llm']['debug'] = True
        if getattr(cli_args, 'output_dir', None):
            cfg['output']['dir'] = cli_args.output_dir

    # Resolve kernel_source to absolute path
    cfg['kernel_source'] = Path(cfg['kernel_source']).expanduser().resolve()
    if not cfg['kernel_source'].exists():
        print(f"Error: kernel_source not found: {cfg['kernel_source']}", file=sys.stderr)
        sys.exit(1)

    return cfg


def build_arg_parser():
    p = argparse.ArgumentParser(
        description='Kernel race condition finder',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # use config.yaml defaults
  %(prog)s --struct cifs_tcon           # analyze a different struct
  %(prog)s --kernel-source /path/to/lk  # override kernel source path
  %(prog)s --stage struct_map           # run only stage 1
  %(prog)s --llm                        # enable LLM deep analysis
""",
    )
    p.add_argument('--config', default='config.yaml',
                   help='Path to YAML config file (default: config.yaml)')
    p.add_argument('--kernel-source', metavar='PATH',
                   help='Path to kernel source tree (overrides config)')
    p.add_argument('--struct', metavar='NAME',
                   help='Target struct name (overrides config)')
    p.add_argument('--file', metavar='PATH',
                   help='Target single C file (relative to kernel_source)')
    p.add_argument('--stage', metavar='STAGE', action='append', dest='stages',
                   help='Stage(s) to run: struct_map, lock_scan, toctou, llm_analysis, report, all'
                        ' — comma-separated or repeated (e.g. --stage struct_map,lock_scan)')
    p.add_argument('--llm', action='store_true',
                   help='Enable LLM deep analysis stage')
    p.add_argument('--llm-debug', action='store_true',
                   help='Log full LLM prompts and raw responses to stage6_llm_analysis.debug')
    p.add_argument('--llm-thinking', metavar='TOKENS', type=int, default=0,
                   help='Enable extended thinking with TOKENS budget (implies --llm-debug); '
                        'min 1024, e.g. --llm-thinking 8000')
    p.add_argument('--output-dir', metavar='DIR',
                   help='Output directory for run artifacts')
    p.add_argument('--verbose', '-v', action='store_true')
    return p
