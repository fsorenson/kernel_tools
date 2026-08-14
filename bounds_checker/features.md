# Bounds / Data Validation Checker — Feature List

Companion tool to the race finder.  Detects missing or insufficient
validation of server-supplied (or user-supplied) values before use in
memory operations, allocations, or array indexing.

Shares generic parsing infrastructure from `kernel_analysis/parsers/`.

---

## P0 — Core Pipeline (MVP)

- [x] Shared parser infrastructure — `kernel_analysis/parsers/c_parser.py` provides
      `parse_file`, `find_functions`, `find_calls_to`, `extract_local_array_decls`,
      `find_alloc_vars`, and `build_var_type_map`; no duplication needed

- [x] Config and CLI — `bounds_checker/config.py` + `bounds_checker/cli.py`;
      YAML config with `source_dirs`, `taint_sources`, `dangerous_sinks`,
      `categories` (default: all)

- [x] Stage 1: Taint scanner — per-function intra-procedural taint flow analysis
      - [x] **Category A**: server-supplied value → pointer arithmetic → memory op
            (e.g., `DataOffset` field → `base + offset` → `memcpy(ptr, ...)`)
      - [x] **Category B**: server-supplied value → size/alloc argument
            (e.g., `kmalloc(le32_to_cpu(hdr->Size))`, direct size arg to memcpy)
      - [x] **Category C**: server-supplied value → array subscript without bounds check
            (e.g., `arr[le16_to_cpu(hdr->Index)]` without `if (idx >= ARRAY_SIZE(arr))`)

- [x] Stage 2: LLM deep analysis — feed taint findings to Claude API for
      false-positive filtering, severity assessment, and fix suggestions;
      analogous to race finder Stage 6

## P1 — Additional Categories

- [x] **Category D**: unterminated string / missing null-termination guarantee —
      `strlen()` / `strlcpy()` / `strcat()` / `strdup()` / `kstrdup()` on a
      server-supplied pointer (kind='pointer') without a prior `strnlen()` or
      `memchr()` call on the same variable.  strlcpy() is included because it
      limits the *destination* copy length but still calls strlen() internally on
      the source.  Guard check: `_find_string_guard()` looks for a `strnlen(ptr,n)`
      or `memchr(ptr,'\0',n)` call on the same variable between taint source and
      sink.  Detection runs before the DANGEROUS_SINKS early-exit so functions not
      in that table (strlen, strcat, strdup, kstrdup) are still checked.
      **Result in fs/smb/client: zero hits** — SMB2/3 wire protocol uses explicit
      length-counted fields (NameLength, FileNameLength, etc.) rather than
      null-terminated strings in responses, so the code correctly avoids strlen()
      on server-supplied buffers.  Cat D is more relevant for NFS or SMBv1 paths
      that do use C-string APIs on network data.

- [x] **Category E**: tainted pointer dereference — accessing `ptr->field` where
      `ptr` is derived from server-supplied offset arithmetic (i.e. `kind='pointer'`
      in the taint tracker) without first verifying `offset + sizeof(*ptr) <= pkt_end`;
      detected via `field_expression` nodes with `->` operator where the base argument
      traces to a tainted pointer variable.  Known limitation: inline cast expressions
      like `((struct Foo *)(base + le32_to_cpu(off)))->field` (no named intermediate
      pointer variable) are not yet flagged — a follow-up.

- [x] **Category F**: variable-length protocol array iterated without count validation —
      `for (i = 0; i < server_count; i++) use(&arr[i])` without checking
      `server_count * sizeof(entry) <= remaining_bytes`; detected via for/while/do
      loop conditions that carry a tainted relational bound; cross-function propagation
      extends this to callee loops whose count parameter traces back to a taint source
      in the caller

- [x] **Category G1**: `copy_from_user` / `copy_to_user` / `get_user` / `put_user` /
      `clear_user` return value unchecked — partial copy treated as success.
      Detects: (1) return value discarded as a void expression; (2) assigned to a
      variable that never appears in a conditional or return after the call; (3)
      declared as an initializer whose result is never subsequently tested.
      `_g1_retval_checked()` walks the function body for any conditional or
      return_statement containing the variable after the call line.  False positives
      where the variable is re-used for other purposes are filtered by the LLM stage.

- [x] **Category G2**: unvalidated size argument to `copy_from/to_user` — a
      variable in the size expression (arg 2) has no relational bounds check with
      early-exit terminal between the function start and the call site.
      `_g2_size_identifiers()` collects identifier names from the size argument,
      skipping `sizeof()` subexpressions and numeric literals.  The existing
      `_find_guards_between()` guard detector then checks for a bounds comparison
      before the call.  Higher false-positive rate than other categories because
      kernel-internal size variables may legitimately lack a range check; LLM
      assessment is especially important for G2 findings.

## P2 — Depth and Quality

- [x] Pointer kind tracking fix — `kind='pointer'` was incorrectly assigned to any
      taint assignment whose RHS text contained `-`, because `->` member access
      contains the `-` character.  Replaced the string-search heuristic
      (`'-' in rhs_text`) with an AST walk that checks for a `binary_expression`
      node whose operator child has type `'+'` or `'-'`.  Eliminated 8 Cat A and
      34 Cat E false positives in fs/smb/client.

- [x] Cross-function taint propagation — one-hop: Phase 1 builds a
      param_sink_map (which parameters of which functions reach a dangerous sink);
      Phase 2 scans call sites for tainted args matching param_sink_map entries.
      `propagation: 'cross_function'` distinguishes these from intra-procedural
      findings in the JSON, report, and LLM prompt.

- [x] Integer overflow detection — flag `a * b` or `a + b` in size/length
      arguments to allocators and memory ops where at least one operand is
      tainted; suppresses the plain Cat B for the same location in favor of
      the more specific `sink_arg_role: 'size_mul_overflow'` finding;
      safe wrappers (`array_size`, `size_mul`, `kmalloc_array`, etc.) are
      recognized and excluded

- [x] Guard detection improvement — upgraded from line-number heuristic to a
      two-requirement check: (1) condition must contain a relational comparison
      (`< <= > >= == !=`) referencing the tainted variable (eliminates bare
      zero-tests); (2) guard must actually gate the use via an early-exit terminal
      (`return`/`goto`/`break`/`continue`/`BUG`/`panic`) in the consequence or
      alternative, or the sink must be textually within the guarded branch.
      Reduces spurious "possibly guarded" rate from 66 % to 62 % on fs/smb/client;
      remaining flags correspond to genuine relational checks with early exits.

- [x] Type width narrowing (Category H) — server-supplied `u32` stored in `u16` or
      narrower intermediate; the narrowing silently caps the value, allowing a later
      bounds check on the narrowed copy to pass for values that would fail on the
      full-width original.  Detects both declaration and assignment forms; variables
      declared with different widths in different branches (if/else scope shadowing)
      are excluded to avoid false positives.  Common false positives: intentional
      shift-then-mask truncation (e.g. `u8 x = (u32_val >> 24) & 0xFF`) where the
      mask makes the narrowing safe — these require LLM assessment.

- [x] Parallel LLM calls — `ThreadPoolExecutor` with configurable worker count
      (`llm.workers` in YAML, `--llm-workers N` on CLI, default 4); each worker
      independently calls `_analyze_fn()` for one function; all debug file writes
      protected by a `threading.Lock`; `done_count` and `all_analyses` updated
      in the main thread via `as_completed()`; Anthropic SDK (`httpx.Client`) is
      thread-safe with connection pooling.  Output format: `[N/total] fn() [file]
      [K batches] [assessment, conf, N/M real]`.  Serial fallback: `--llm-workers 1`.
      Typical speedup: 4–6× on Vertex; throughput limited by API rate limits.

- [ ] Category filter for LLM — `--llm-categories A B C` to skip LLM analysis for
      noisy categories (e.g., H, G2) without re-running Stage 1; reduces call
      count when a full re-analysis is not warranted

- [ ] Merge/combine runs — `bc merge bc_runs/dir1 bc_runs/dir2 ...` to aggregate
      multiple run directories into a unified `summary.md` + `summary.html`; useful
      when scanning drivers/* in per-subdirectory batches and combining results

- [ ] Configurable taint sources and sinks — allow per-project YAML extension of
      the default `TAINT_SOURCES` and `DANGEROUS_SINKS` sets for non-CIFS subsystems
      (e.g., NFS uses `be32_to_cpu`, block drivers have their own idioms)

## P3 — Output and Integration

- [x] Markdown / HTML report formatter — per-file findings with source snippets,
      taint flow explanation, suggested fix; written after Stage 1 (static only)
      and overwritten after Stage 2 (with LLM assessment, impact badges, fix text)

- [ ] Integration with race finder run dirs — optionally consume race finder
      Stage 1 struct map to annotate which tainted fields belong to which struct

- [x] Multi-struct / cross-file summary — `write_summary()` aggregates all
      findings across the full subsystem into `summary.md` + `summary.html`,
      ranked by a composite score (category base + LLM impact bonus + guard
      bonus + overflow bonus).  Tier labels: Critical (LLM real bug, score ≥ 250),
      High (≥ 100), Medium (≥ 60), Low.  Auto-generated after every Stage 1 and
      Stage 2 run alongside `report.md`.  HTML version shows a score bar and
      color-coded tier/verdict columns.  A "Findings by File" table at the bottom
      identifies which source files have the highest finding density.

- [ ] Reproducer designer integration — pipe high-confidence bounds findings
      into `tools/reproducer_designer.py` for test case generation
