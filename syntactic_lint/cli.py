"""
Standalone syntactic bounds linter — command-line entry point.

    python3 -m syntactic_lint.cli fs/smb/client [--kernel-source /home/src/linux]

Deliberately has no config file, no run directory, and no LLM stage: every
check is local and cheap, so the tool is meant to be run directly over a tree
and read in the terminal.
"""

import argparse
import json
import sys
from pathlib import Path

from syntactic_lint.checks import CHECKS, scan_paths

_SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def _collect_sources(targets, kernel_source):
    paths = []
    for t in targets:
        p = Path(t)
        if not p.is_absolute() and kernel_source:
            p = Path(kernel_source) / t
        if p.is_dir():
            paths += sorted(p.rglob('*.c'))
        elif p.exists():
            paths.append(p)
        else:
            print(f"error: no such file or directory: {p}", file=sys.stderr)
            sys.exit(1)
    return paths


def _rel(path, root):
    if not root:
        return str(path)
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return str(path)


def _print_text(findings, root, verbose):
    by_check = {}
    for f in findings:
        by_check.setdefault(f['check'], []).append(f)

    for check in CHECKS:
        group = by_check.get(check)
        if not group:
            continue
        group.sort(key=lambda f: (_SEVERITY_ORDER.get(f['severity'], 9),
                                  f['file'], f['line']))
        print(f"\n=== {check} ({len(group)}) " + "=" * (56 - len(check)))
        for f in group:
            loc = f"{_rel(f['file'], root)}:{f['line']}"
            print(f"\n[{f['severity']}] {loc}  in {f['function']}()")
            print(f"  {f['message']}")
            print(f"  | {f['snippet']}")
            if verbose:
                skip = {'check', 'severity', 'function', 'file', 'line',
                        'snippet', 'message'}
                extra = {k: v for k, v in f.items() if k not in skip}
                if extra:
                    print(f"  {extra}")

    print(f"\n{'-' * 64}")
    counts = {c: len(by_check.get(c, [])) for c in CHECKS}
    print("total: " + ", ".join(f"{c}={n}" for c, n in counts.items())
          + f"  (all: {len(findings)})")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog='syntactic_lint',
        description='Local syntactic bounds checks for kernel C '
                    '(pointer/length pairing, scan loops, fixed-width wrap)',
    )
    p.add_argument('targets', metavar='PATH', nargs='+',
                   help='C files or directories to scan (directories recurse over *.c)')
    p.add_argument('--kernel-source', metavar='PATH', default=None,
                   help='root to resolve relative targets against')
    p.add_argument('--check', metavar='NAME', nargs='+', choices=CHECKS,
                   default=list(CHECKS),
                   help=f"checks to run (default: all of {', '.join(CHECKS)})")
    p.add_argument('--min-severity', metavar='LEVEL', default='medium',
                   choices=('high', 'medium', 'low'),
                   help="drop findings below this severity (default medium; "
                        "'low' is mostly wrap that never reaches memory)")
    p.add_argument('--max-bits', metavar='N', type=int, default=16,
                   help='widest integer type the wrap checks consider '
                        '(default 16; 32 is real but much noisier)')
    p.add_argument('--json', metavar='FILE', nargs='?', const='-',
                   help='emit findings as JSON to FILE, or stdout if bare')
    p.add_argument('--verbose', '-v', action='store_true',
                   help='include the structured fields of each finding')
    args = p.parse_args(argv)

    paths = _collect_sources(args.targets, args.kernel_source)
    findings = scan_paths(paths, checks=tuple(args.check), max_bits=args.max_bits)
    floor = _SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings
                if _SEVERITY_ORDER.get(f['severity'], 9) <= floor]

    if args.json:
        blob = json.dumps(findings, indent=2)
        if args.json == '-':
            print(blob)
        else:
            Path(args.json).write_text(blob)
            print(f"wrote {len(findings)} findings to {args.json}", file=sys.stderr)
    else:
        _print_text(findings, args.kernel_source, args.verbose)

    return 0


if __name__ == '__main__':
    sys.exit(main())
