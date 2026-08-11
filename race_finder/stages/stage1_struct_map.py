"""
Stage 1: Structural Map

Locates the target struct definition across configured header files,
extracts all fields with type/lock/state classifications, identifies
protected regions, and flags suspicious fields (unprotected refcounts,
unprotected state).

Output: JSON file written to the run directory.
"""

import json
import sys
from pathlib import Path

from ..parsers.c_parser import extract_struct_info


def run(cfg, run_dir, verbose=False):
    """
    Run Stage 1 for the configured target struct.
    Returns the result dict, or exits on fatal error.
    """
    target = cfg['target']
    if target['type'] != 'struct':
        print(f"Stage 1: target type '{target['type']}' not yet supported", file=sys.stderr)
        sys.exit(1)

    struct_name = target['name']
    if not struct_name:
        print("Stage 1: no target struct name specified", file=sys.stderr)
        sys.exit(1)

    kernel_source = cfg['kernel_source']
    headers = target.get('headers') or []

    # Build search path list: explicit headers first, then auto-discovered files.
    # Auto-discovery searches .h files first (most structs live there), then .c
    # files so that translation-unit-local structs (defined in a .c file) are
    # also found.
    if not headers:
        source_dirs = target.get('source_dirs') or []
        if not source_dirs:
            print("Stage 1: no headers or source_dirs specified", file=sys.stderr)
            sys.exit(1)
        h_files = []
        c_files = []
        for d in source_dirs:
            dir_path = kernel_source / d
            h_files.extend(sorted(dir_path.rglob('*.h')))
            c_files.extend(sorted(dir_path.rglob('*.c')))
        headers = [str(p.relative_to(kernel_source)) for p in h_files + c_files]

    result = None
    searched = []
    for rel_path in headers:
        src_path = kernel_source / rel_path
        if not src_path.exists():
            if verbose:
                print(f"  [skip] {rel_path} — not found")
            continue
        searched.append(str(rel_path))
        if verbose:
            print(f"  [searching] {rel_path}")
        info = extract_struct_info(src_path, struct_name)
        if info:
            result = info
            if verbose:
                print(f"  [found] struct {struct_name} at {rel_path}:{info['line']}")
            break

    if not result:
        n_h = sum(1 for p in searched if p.endswith('.h'))
        n_c = sum(1 for p in searched if p.endswith('.c'))
        print(
            f"Stage 1: struct '{struct_name}' not found "
            f"({n_h} .h files and {n_c} .c files searched in source_dirs)",
            file=sys.stderr,
        )
        sys.exit(1)

    output = {
        'stage': 'struct_map',
        'target': {'type': 'struct', 'name': struct_name},
        'kernel_source': str(kernel_source),
        'headers_searched': searched,
        'result': result,
    }

    out_path = run_dir / 'stage1_struct_map.json'
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Stage 1 output: {out_path}")

    _print_summary(result, verbose)
    return output


def _print_summary(result, verbose):
    """Print a human-readable summary to stdout."""
    sname = result['struct_name']
    nfields = len(result['fields'])
    locks = result['locks']
    regions = result['protected_regions']
    suspicious = result['suspicious_fields']

    print(f"\n=== struct {sname} ({result['file']}:{result['line']}) ===")
    print(f"  Fields:            {nfields}")
    print(f"  Embedded locks:    {len(locks)}: {', '.join(locks) or 'none'}")
    print(f"  Protected regions: {len(regions)}")
    for r in regions:
        print(f"    {r['lock']}: {', '.join(r['fields'])}")

    bf_groups = result.get('bitfield_groups', [])
    if bf_groups:
        print(f"\n  Bitfield co-location groups ({len(bf_groups)} groups with mixed/absent protection):")
        for g in bf_groups:
            prots = g.get('protections', [])
            if g.get('inner_type'):
                suffix = f"  (embedded {g['inner_type']} in '{g['embedded_in']}')"
            else:
                suffix = ''
            print(f"    [{', '.join(g['fields'])}]{suffix}  protections: {', '.join(prots)}")

    if suspicious:
        print(f"\n  SUSPICIOUS ({len(suspicious)} fields with no stated protection):")
        for s in suspicious:
            print(f"    [{s['reason']}]  {s['name']}")
    else:
        print("\n  No obvious unprotected state/refcount fields detected.")

    if verbose:
        print("\n  All fields:")
        for f in result['fields']:
            flags = []
            for k in ('is_lock', 'is_atomic', 'is_refcount', 'is_state'):
                if f.get(k):
                    flags.append(k.replace('is_', ''))
            prot = f"  ← {f['protection']}" if f.get('protection') else ''
            flag_str = f"  [{', '.join(flags)}]" if flags else ''
            comment = f"  // {f['comment']}" if f.get('comment') else ''
            print(f"    L{f['line']:4d}  {f['type']:30s} {f['name']}{flag_str}{prot}{comment}")
