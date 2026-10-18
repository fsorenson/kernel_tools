# kernel_tools

Static analysis tools for Linux kernel C. All tools use tree-sitter (no compilation required).

## Project inventory

| Tool | Entry point | Status | Description |
|---|---|---|---|
| `bounds_checker` | `bounds_checker/cli.py` | **Active** | 3-stage bounds/data-validation checker: taint scanner → Z3 SMT → LLM |
| `syntactic_lint` | `syntactic_lint/cli.py` | Stable | Fast local linter for syntactic bounds patterns; no taint table, no LLM |
| `race_finder` | `main.py` → `race_finder/cli.py` | Prototype | Data race / TOCTOU finder: struct map → lock scan → async tag → TOCTOU → LLM |

## Shared code

- `kernel_analysis/parsers/c_parser.py` — shared tree-sitter C parser used by all three tools. Changes here affect all tools.

## Cross-cutting conventions

- **Kernel source**: `/home/src/linux` (configurable per tool)
- **Do NOT commit or push unless explicitly asked** — Frank commits each batch himself
- **Git commit attribution** — end every commit message with:
  ```
  Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
  ```
- **Scan scope**: both `.c` and `.h` files (not `.c` only)
- **No LLM calls in test harnesses** — Stage 2 excluded from automated tests due to API cost
- **Review brief**: `bounds_checker/bc_category_review_brief.md` is the external-review doc for `bounds_checker`; update it whenever categories, SMT properties, or Stage 2 prompt items change

## Active work

`bounds_checker` is the primary focus. `syntactic_lint` is stable. `race_finder` is parked.
