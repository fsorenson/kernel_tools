#!/usr/bin/env python3
"""
survey_taint_sources.py — identify candidate taint-source functions missing from
TAINT_SOURCES by scanning a kernel subtree for call-return patterns.

A "candidate" is a function called in a direct-assignment context whose name
matches one or more heuristics suggesting it reads from external data (network,
disk, flash, user, XDR stream, etc.) and returns the value directly.

Output is a ranked table of (count, function_name, example_file) sorted by
call frequency, filtered to functions NOT already in TAINT_SOURCES.

Usage:
    python3 bounds_checker/tools/survey_taint_sources.py [PATH ...]

    PATH may be a file or directory; directories are recursed for .c/.h files.
    Defaults to /home/src/linux/fs/ if no paths given.

Example:
    python3 bounds_checker/tools/survey_taint_sources.py /home/src/linux/fs/jffs2
    python3 bounds_checker/tools/survey_taint_sources.py /home/src/linux/fs /home/src/linux/net
    python3 bounds_checker/tools/survey_taint_sources.py --all-calls /home/src/linux/fs/btrfs
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bounds_checker.parsers.taint_scanner import TAINT_SOURCES

# ---------------------------------------------------------------------------
# Heuristics — name fragments that suggest "reads external data, returns value"
# ---------------------------------------------------------------------------

# Positive signals: name contains one of these substrings
_DECODE_FRAGS = {
    'decode', 'read', 'parse', 'get', 'fetch', 'load', 'recv',
    'extract', 'unpack', 'convert', 'translate',
}

# Suffix/prefix patterns that are strong signals
_STRONG_PATTERNS = [
    re.compile(r'_to_cpu'),          # le32_to_cpu, je32_to_cpu, etc.
    re.compile(r'^get_unaligned_'),  # get_unaligned_le32, etc.
    re.compile(r'_from_(be|le|net|wire|disk|flash|on_disk)'),
    re.compile(r'(read|decode|get)_(u8|u16|u32|u64|s8|s16|s32|s64|int|uint|byte|word|dword|qword)'),
    re.compile(r'(u8|u16|u32|u64|s8|s16|s32|s64)_(read|decode|get|from)'),
    re.compile(r'^xdr_(decode|stream_decode|read)'),
    re.compile(r'^ntohs?$'),
]

# Negative signals: exclude these — they are known non-taint helpers or
# too generic to be useful candidates
_EXCLUDE_EXACT = TAINT_SOURCES | {
    # Generic kernel helpers that don't read external data
    'get_user', 'copy_from_user', 'copy_to_user',
    'kmalloc', 'kzalloc', 'vmalloc',
    'get_seconds', 'get_cycles', 'get_jiffies',
    'get_random', 'get_order',
    'ktime_get', 'ktime_to',
    'printk', 'pr_err', 'pr_info',
    'BUG', 'WARN', 'BUG_ON', 'WARN_ON',
    'min', 'max', 'clamp',
    'likely', 'unlikely',
    'htonl', 'htons',   # host→network, not reading external data
}

_EXCLUDE_FRAGS = {
    'set', 'put', 'write', 'send', 'encode', 'pack',
    'lock', 'unlock', 'alloc', 'free', 'init', 'exit',
    'print', 'debug', 'trace', 'log', 'warn', 'err',
    'check', 'test', 'verify', 'validate',
    'list', 'hash', 'tree', 'rb_',
}

# ---------------------------------------------------------------------------

_ASSIGN_RE = re.compile(
    # Match: some_var = func_name(   OR   *ptr = func_name(
    # Capture the function name
    r'(?:^|[=,;\({\[])\s*'          # context before the call
    r'(?:\*\w+\s*=\s*)?'            # optional *ptr =
    r'(\w+)\s*\(',                   # capture: func_name (
    re.MULTILINE,
)


def _is_candidate(name: str) -> bool:
    if name in _EXCLUDE_EXACT:
        return False
    name_lower = name.lower()
    for frag in _EXCLUDE_FRAGS:
        if frag in name_lower:
            return False
    # Must have at least one positive signal
    for pat in _STRONG_PATTERNS:
        if pat.search(name_lower):
            return True
    for frag in _DECODE_FRAGS:
        if frag in name_lower:
            return True
    return False


def survey_file(path: Path, counts: Counter, examples: defaultdict):
    try:
        src = path.read_text(errors='replace')
    except OSError:
        return
    for m in _ASSIGN_RE.finditer(src):
        name = m.group(1)
        if _is_candidate(name):
            counts[name] += 1
            if name not in examples:
                examples[name] = str(path)


def collect_paths(roots):
    paths = []
    for root in roots:
        p = Path(root)
        if p.is_file():
            paths.append(p)
        elif p.is_dir():
            paths.extend(p.rglob('*.c'))
            paths.extend(p.rglob('*.h'))
    return paths


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('paths', metavar='PATH', nargs='*',
                    default=['/home/src/linux/fs'],
                    help='Files or directories to scan (default: /home/src/linux/fs)')
    ap.add_argument('--min-count', metavar='N', type=int, default=3,
                    help='Only show functions used at least N times (default: 3)')
    ap.add_argument('--top', metavar='N', type=int, default=50,
                    help='Show at most N candidates (default: 50)')
    ap.add_argument('--all-calls', action='store_true',
                    help='Disable heuristic filtering — show all call-return patterns')
    args = ap.parse_args()

    paths = collect_paths(args.paths)
    if not paths:
        print("No .c/.h files found.", file=sys.stderr)
        sys.exit(1)

    counts: Counter = Counter()
    examples: defaultdict = defaultdict(str)

    for p in paths:
        survey_file(p, counts, examples)

    if args.all_calls:
        candidates = [(n, c) for n, c in counts.items() if n not in TAINT_SOURCES]
    else:
        candidates = [(n, c) for n, c in counts.items()
                      if c >= args.min_count and n not in TAINT_SOURCES]

    candidates.sort(key=lambda x: -x[1])
    candidates = candidates[:args.top]

    if not candidates:
        print("No candidates found (try --min-count 1 or --all-calls).")
        return

    print(f"\nCandidate taint-source functions not in TAINT_SOURCES")
    print(f"Scanned {len(paths)} files in: {', '.join(args.paths)}")
    print(f"(functions used >= {args.min_count}x in assignment context, heuristically filtered)\n")
    print(f"{'count':>6}  {'function':<45}  example file")
    print('-' * 100)
    for name, count in candidates:
        ex = examples[name].replace('/home/src/linux/', '')
        print(f"{count:>6}  {name:<45}  {ex}")

    print(f"\n{len(candidates)} candidates shown.")
    print("\nTo add a candidate to TAINT_SOURCES, edit:")
    print("  bounds_checker/parsers/taint_scanner.py — TAINT_SOURCES and TAINT_SOURCE_WIDTHS")


if __name__ == '__main__':
    main()
