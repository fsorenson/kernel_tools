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

- [x] Guard direction and coverage — a candidate guard that is present can still
      fail to answer the question the sink asks, and two such cases now clear
      `possibly_guarded` while recording why in a new `guard_kind` field.
      `covers-base-not-offset`: the sink applies arithmetic to the variable and
      no guard does (`if (off > total) return;` then `data[off + 1]`).
      `upper-bound-only-signed`: the variable is signed and every guard pins only
      its ceiling, leaving the negative half that the subscript converts to
      `size_t`; a cast to an unsigned type inside the comparison supplies both
      ends, and a signed local fed only by `strlen`/`strnlen`/`ARRAY_SIZE`/
      `sizeof` needs no floor.  Direction is read off the falling-through path,
      so early-exit conditions are inverted before classification.  On
      fs/smb/client: 295 findings unchanged, guarded 159 → 156 — `CIFSPOSIXCreate`
      and `parse_posix_sids` (base-not-offset), `smb2_check_message`
      (`smb2_rsp_struct_sizes[command]`, signed — later reclassified, see the
      range rule below).  Without the nonneg-source
      carve-out it is 159 → 144, and all twelve of the difference are
      `int len = strnlen(...)` under `if (len >= bleft) return;`.

- [x] Guard operand vs. name mention — `_comparisons_on()` tested whether the
      variable appeared anywhere in the compared subtree, so a variable passed
      to a function counted as the thing being compared.  `if (memcmp(ea_name,
      temp_ptr, name_len) == 0)` in `CIFSSMBQAllEAs` and `if (compare_sids(
      &pntace->sid, pownersid) == 0)` in `set_chmod_dacl` were both credited as
      bounds checks on the pointer; each tests its call's *result*.  Operand
      matching now walks the side expression without descending into an
      `argument_list`, which leaves `unlikely()`/`WARN_ON()` wrappers working
      since the comparison itself is found by the enclosing walk.  fs/smb/client
      guarded 156 → 147, all nine in those two call chains.

      This also emptied the two control-flow gaps worth measuring here.  A
      standalone detector — guard whose conditional ancestors do not all enclose
      the sink, and variable redefined between guard and sink — found 0 and 2 of
      61 guarded findings before the fix, 0 and 0 of 58 after; the redefinition
      hits were symptoms of the operand defect, not of missing
      reaching-definitions.  For structured C, AST ancestry is dominance; only
      `goto` label resolution and loop back edges would need a real CFG.

- [x] `goto` label resolution — any `goto_statement` in a guard's branch counted
      as an early exit without asking where the label lands, so `if (cond) goto
      found;` was credited even when `found:` sits immediately above the sink.
      A goto now qualifies only if its label is past the use; an unresolvable
      label is still credited so a parse gap cannot produce a wave of findings.
      Zero change on fs/smb/client — the `goto out` idiom always lands below —
      and 18 findings tree-wide, e.g. `ldm_frag_add()` (block/partitions/ldm.c),
      where `goto found` skips the `kmalloc` and lands one line above the
      `memcpy(f->data + VBLK_SIZE_HEAD + rec * size, ...)`.

- [x] Guard reached only as a field base — `if (rsp->ByteCount < 8)` was credited
      as a bounds check on `rsp`, and `if (pctx->ContextType == SMB2_PREAUTH_
      INTEGRITY_CAPABILITIES)` in `smb311_decode_neg_context()` as one on `pctx`.
      A type discriminator is not a bound.  `_names_compared()` drops an
      identifier that appears only as the `argument` of a `field_expression`;
      it is kept separate from `_names_in_operand` so `_in_arithmetic` still
      reads `f->data + n` as an adjustment of `f`.  fs/smb/client guarded
      147 → 123, all 24 Category E; tree-wide 1,851 → 1,322.

      Worth being precise about what this buys: the real bound in
      `smb311_decode_neg_context()` is `if (clen > len_of_ctxts) break;`, on a
      derived length the scanner does not tie back to `pctx`, so these findings
      are not new bugs.  `possibly_guarded` is not a filter — it contributes +20
      to the ranking score and is handed to Stage 2 as context — so the gain is
      that Stage 2 is no longer told a guard exists when it does not.

- [x] Signed guard: non-negativity by range — a ceiling-only guard is a real gap
      only when the variable can reach the negative half, and the enumerated
      `strlen`/`strnlen`/`ARRAY_SIZE`/`sizeof` carve-out was too narrow to say so.
      `_max_bits()` bounds an initializer's width from the shapes parsers actually
      write — an unsigned local or cast (`_build_local_unsigned()` maps the
      declared width), a `le16_to_cpu`-class taint source, a mask, a right shift,
      `sizeof` — and a variable whose every assignment fits in width−1 bits keeps
      its guard.  Compound assignment and `++`/`--` still disqualify outright:
      `len -= hdr` reopens the negative half wherever len started.  `int command =
      le16_to_cpu(shdr->Command)` in `smb2_check_message()` was the only
      fs/smb/client hit and is one of these — 16 bits into 32 — so that earlier
      example was a false positive.  Tree-wide 126 → 98 against an unchanged
      11,074 findings and an unchanged 87 `covers-base-not-offset`; fs/smb/client
      guarded 130 → 131.  (fs/smb/client totals moved 295 → 300 across this work
      from kernel-tree drift, not from the rule; both counts above are from
      `/home/src/linux` at `e2f9a0adaae4`.)

      The surviving 98 are conservative by construction: 25 have a range that is
      known and genuinely too wide (`int fw_bin_count = le32_to_cpu(...)`), 70 have
      at least one assignment `_max_bits` returns None for, and 3 have no declared
      width.  The None bucket is mixed — `be32_to_cpu(x) - 1` really does reach -1,
      a driver mask hidden behind a macro really does not.

## Whole-tree guard measurement

65,645 files, ~3.5 min on 30 cores, intra-procedural only.  11,070 findings both
before and after the guard work (nothing here filters); `upper-bound-only-signed`
fires 126 times and `covers-base-not-offset` 87.  (The range rule later took the
signed count to 98; the table below predates it.)

Suppression shapes that do not hold up, measured with detectors carried on
positive *and* negative controls, over the guarded findings whose sink node and
candidate guard can be re-located from the finding record:

| shape | before | after | needs |
|---|---|---|---|
| variable reached only as a field base | 259 | **0** | operand test (done) |
| variable redefined between guard and sink | 128 | 104 | reaching definitions over a line range |
| guard does not dominate the sink | 51 | 21 | AST ancestor chain |
| `goto` label does not clear the sink | 18 | 17 | label map (done; detector counts verdict changes, not defects) |
| guarded findings | 1,851 | 1,322 | |
| of which examined | 1,160 | 868 | |

The field-base fix removed 529 suppressions tree-wide against a detector
estimate of 259, because the detector only examines findings it can re-locate —
treat every count here as a lower bound of roughly half.  It also halved gap1
and dented gap2, since those populations overlapped it.  Reaching definitions is
now the largest remaining shape; dominance at 21 does not justify CFG machinery.

- [x] Type width narrowing (Category H) — server-supplied `u32` stored in `u16` or
      narrower intermediate; the narrowing silently caps the value, allowing a later
      bounds check on the narrowed copy to pass for values that would fail on the
      full-width original.  Detects both declaration and assignment forms; variables
      declared with different widths in different branches (if/else scope shadowing)
      are excluded to avoid false positives.  Common false positives: intentional
      shift-then-mask truncation (e.g. `u8 x = (u32_val >> 24) & 0xFF`) where the
      mask makes the narrowing safe — these require LLM assessment.

- [x] Compound assignment taint propagation — `+= -= *= /= %= &= |= ^= <<= >>=`
      were skipped outright by the assignment handler, so a variable built up with
      `acc += le16_to_cpu(...)` never entered the taint table and no downstream sink
      on it was reachable.  Size accumulation in kernel protocol parsers is written
      this way almost exclusively.  Treated as a taint *merge* (LHS stays tainted if
      it already was, and additionally picks up the RHS), keeping the earliest taint
      line as the reported origin.  Width comes from the accumulator's own
      declaration rather than the source's, and Cat H is suppressed for the compound
      forms — an accumulation is not a truncating store, and treating it as one fires
      on every `u16 acc += le32_to_cpu(x)`.  Pointer-vs-value classification can't be
      read off the RHS here (`p += n` and `acc += n` are the same expression), so it
      comes from the scalar-locals table, then any prior classification, then a
      `+=`/`-=`-only guess.  Recovers the missed Cat B on `kzalloc(nsecdesclen)` in
      `id_mode_to_cifs_acl()` (Bjoern Doebel's `0ee150794c75`).  Net effect on
      fs/smb/client: +2 findings, none lost — of 775 compound assignments only 12
      have a taint source in the RHS, so the `|=` flag-accumulation bulk is inert.

- [x] Parallel LLM calls — `ThreadPoolExecutor` with configurable worker count
      (`llm.workers` in YAML, `--llm-workers N` on CLI, default 4); each worker
      independently calls `_analyze_fn()` for one function; all debug file writes
      protected by a `threading.Lock`; `done_count` and `all_analyses` updated
      in the main thread via `as_completed()`; Anthropic SDK (`httpx.Client`) is
      thread-safe with connection pooling.  Output format: `[N/total] fn() [file]
      [K batches] [assessment, conf, N/M real]`.  Serial fallback: `--llm-workers 1`.
      Typical speedup: 4–6× on Vertex; throughput limited by API rate limits.

- [x] Category filter for LLM — `--llm-categories A B C` (or `llm.categories` in
      YAML) to restrict LLM analysis to a subset of categories without re-running
      Stage 1; filter is applied per-finding before grouping by function, so a
      function with mixed Cat A + Cat H findings sends only its Cat A finding to
      the LLM when `--llm-categories A` is set.  Output JSON records
      `llm_categories` for traceability.  Default (omitted): analyze all findings.

- [x] Merge/combine runs — `bc merge bc_runs/dir1 bc_runs/dir2 ... [--output DIR]`
      aggregates multiple run directories into a unified report; deduplicates Stage 1
      findings by stable key `(file, function, category, sink_line, sink_fn, tainted_var)`;
      re-maps Stage 2 `finding_index` values from each run's per-function ordering to
      the merged ordering via `_remap_llm_findings()` so the existing renderer works
      without changes; for functions with LLM analyses from multiple runs (e.g., different
      `--llm-categories` passes), per-finding LLM data is combined (first-wins per position)
      and function-level assessment is most-severe across runs.  Writes
      `merged_stage1.json`, `merged_stage2.json`, `report.md/html`, `summary.md/html`
      to the output directory.

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
