# syntactic_lint

Fast local syntactic bounds linter. No taint table, no cross-function pass, no LLM.
Every check is decidable from one function body + declared types; runs over a whole tree in seconds at zero token cost.

Entry point: `syntactic_lint/cli.py`. Run: `python3 -m syntactic_lint.cli <path> [--kernel-source /home/src/linux]`

## Architecture

Single stage: `checks.py` runs all checks against each function body via the shared `kernel_analysis/parsers/c_parser.py`.

## Implemented checks

| Check | Description |
|---|---|
| `ptr-advance` | `mem*(dst, P + K, LEN)` where LEN was computed from un-advanced P (also interposed form) |
| `scan-loop` | `for (i = K; s[i]; i++)` with K > 0 — never tests positions 0..K-1 for the terminator |
| `narrow-sub` | Unsigned subtraction into a narrow fixed-width variable reaching a size/offset/subscript/wire field |
| `narrow-add` | Same for addition and `acc +=` accumulation in a loop |

## Key design decisions

- Intentionally has no config file, no run directory — output is terminal-only
- Checks fire on purely local defects (no server-supplied taint required); complements `bounds_checker` which needs endian-helper taint
- Wire-store targets (`cpu_to_le16` etc.) are suppressed — a truncated value shipped to a peer is not a local bounds bug

## Constraints

- Do NOT commit or push unless explicitly asked
- Stable; not the current focus of active development
