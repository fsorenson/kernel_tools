"""
Regenerate the fixture corpus from a kernel git tree.

    python3 -m syntactic_lint.tests.extract [--kernel-source /home/src/linux]

Each fixture is the verbatim text of the named functions at the named
revision, plus whatever comment block sits immediately above each one, under a
provenance header.  Extracting whole functions rather than whole files is safe
because every check in this tool is an invariant over one function body; it
keeps the corpus at a few hundred lines instead of a few hundred kilobytes of
GPL source in a repository that is not the kernel.

Regenerating shifts line numbers if a header or a comment changes, so follow
this with `test_checks.py --update` and read the resulting diff: an expectation
that moved by a constant is a reflow, an expectation that changed severity or
vanished is a regression.
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from kernel_analysis.parsers.c_parser import parse_file, find_functions

from syntactic_lint.tests.cases import CASES

FIXTURE_DIR = Path(__file__).parent / 'fixtures'


def _git(kernel_source, *args):
    out = subprocess.run(('git', '-C', str(kernel_source)) + args,
                         capture_output=True, check=True)
    return out.stdout


def _leading_comment(lines, start_idx):
    """Index of the first line of the comment block ending just above start_idx."""
    i = start_idx
    while i > 0 and lines[i - 1].strip().startswith(('*', '/*', '//')):
        i -= 1
        if lines[i].strip().startswith('/*'):
            break
    return i


def extract(case, kernel_source):
    blob = _git(kernel_source, 'show', f'{case.rev}:{case.path}')
    subject = _git(kernel_source, 'log', '-1', '--format=%h %s',
                   case.rev.rstrip('^')).decode().strip()

    with tempfile.NamedTemporaryFile(suffix='.c', delete=False) as tmp:
        tmp.write(blob)
        tmp_path = tmp.name
    try:
        tree, source = parse_file(tmp_path)
        found = {f['name']: f for f in find_functions(tree, source)}
    finally:
        Path(tmp_path).unlink()

    lines = blob.decode('utf-8', errors='replace').splitlines()
    chunks, provenance = [], []
    for name in case.functions:
        fn = found.get(name)
        if fn is None:
            raise SystemExit(
                f"{case.name}: no definition of {name}() in "
                f"{case.rev}:{case.path}")
        start = _leading_comment(lines, fn['start_line'] - 1)
        chunks.append('\n'.join(lines[start:fn['end_line']]))
        provenance.append(f" *   {name}()  lines {start + 1}-{fn['end_line']}")

    header = [
        '/*',
        ' * Test fixture for syntactic_lint -- generated, do not edit.',
        ' * Regenerate with: python3 -m syntactic_lint.tests.extract',
        ' *',
        f' * {case.path} at {case.rev}',
        f' * {case.rev.rstrip("^")} is {subject}',
        *provenance,
        ' */',
        '',
    ]
    return '\n'.join(header) + '\n\n'.join(chunks) + '\n'


def main(argv=None):
    p = argparse.ArgumentParser(prog='syntactic_lint.tests.extract')
    p.add_argument('--kernel-source', default='/home/src/linux')
    p.add_argument('--case', metavar='NAME', nargs='*',
                   help='regenerate only these cases (default: all)')
    args = p.parse_args(argv)

    FIXTURE_DIR.mkdir(exist_ok=True)
    wanted = set(args.case or ())
    for case in CASES:
        if wanted and case.name not in wanted:
            continue
        text = extract(case, args.kernel_source)
        path = FIXTURE_DIR / f'{case.name}.c'
        changed = not path.exists() or path.read_text() != text
        path.write_text(text)
        print(f"{'wrote  ' if changed else 'same   '} {path.name} "
              f"({text.count(chr(10))} lines)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
