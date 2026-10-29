# bounds_checker

Static bounds/data-validation checker for Linux kernel C. Four-stage pipeline:

- **Stage 1** (`parsers/taint_scanner.py`, `parsers/cross_function.py`): per-function taint scanner + one-hop cross-function pass
- **Stage 1.7** (`smt/`): Z3 SMT refinement using bitvector arithmetic
- **Stage 1.5** (`stages/stage1_5_callers.py`): caller enumeration — annotates findings in static functions with per-call-site guard detection
- **Stage 2** (`stages/stage2_llm_analysis.py`): LLM adjudication per function

Full category taxonomy, SMT properties, and Stage 2 prompt items: `bc_category_review_brief.md`

## Key design decisions

- **Bitvectors, not unbounded integers in SMT**: wraparound and truncation must be exact; unbounded integers would make `prop_overflow` unsound.
- **Retirement condition**: Stage 1.7 retires a finding only when the `safe` property matches what Stage 1's verdict rested on. A size that cannot be negative is still unbounded against the destination buffer — retiring on any `safe` result would be unsound.
- **Cross-function pass is one hop only**: extending to two hops raises false positives because intermediate functions often validate before passing further. Stage 1.5 (upward caller enumeration, now implemented) addresses the complementary direction: it looks UP from the callee to check whether every caller already validates before calling.
- **Cat H excludes error-code variable names**: `_ERROR_CODE_VARS` = {rc, ret, err, error, retval, result, status, r, rv, retcode}. Storing `le32_to_cpu(status)` into `int rc` is intentional kernel idiom; the sign change is by design.
- **NUL-term converters clear taint**: `_NUL_TERM_CONVERTERS` = {cifs_strndup_from_utf16, cifs_strndup_from_utf8}. Their return values are kernel-allocated NUL-terminated strings; taint on them would produce false positives on downstream `strlen`.
- **Cat L bitmask guard gap**: `le16_to_cpu(x) & 0x1f` → `1 << tag` shows `guarded=False` in Stage 1 (guard detection uses comparisons, not bitwise masks). Stage 1.7 `prop_shift_bounds` correctly retires these — `val & 0x1f` is provably < 32 in bitvectors.
- **SMT encoder ALL_CAPS treatment**: macro/enum constants are `opaque=True` with type `int`, never guessed widths. `sizeof` is typed as `size_t` (PTR_BITS, unsigned), never guessed.
- **`smt_witness_reachable`**: per-finding Stage 2 schema field (true/false/null) — LLM verifies whether the SMT witness is reachable on a real code path.
- **Merge upgrade**: when a duplicate finding appears in merge, if the newer copy has `smt` and the canonical doesn't, the canonical's `smt` field is upgraded.
- **Gap R/S (prop_underflow)**: Stage 1 correctly fires on unsigned subtraction underflow. Stage 1.7 misleadingly returns `safe` via `prop_negative` because the wrapped value IS unsigned-positive. Stage 2 prompt item 14 covers the reasoning gap in the meantime.

## Scope

**In scope**: values tainted through scalar endian helpers (`le16_to_cpu` etc.) OR direct field reads from known server-response struct types (`_SERVER_RESPONSE_STRUCTS`), reaching memory, allocation, loop, shift, or sign-conversion sinks within one function or one call hop.

**Deliberately out of scope** (design boundaries, not temporary gaps):
- Dual-use struct types (`smb2_hdr`, `smb2_pdu`) — type alone does not establish provenance (used for both requests and responses)
- Purely local overflow — covered by `syntactic_lint`
- Cross-function UAF / refcount / double-fetch — requires whole-program alias analysis
- Architecture-specific multiplication widths (32-bit intermediate wrap before `size_t` widening)
- DoS findings (zero-length TLV / infinite loop) — pending scope decision before implementing Cat K

## Deferred items

| Item | Prerequisite / blocker |
|---|---|
| **Gap R (remaining-length loop)** — `prop_underflow` covers Pattern 2 (straight-line subtraction) but NOT Pattern 1 (subtraction inside a loop body, where the path encoder clobbers loop-written variables so BVSUB is not visible at the post-loop sink). Stage 2 prompt item 14 covers the reasoning gap. | Path encoder limitation — would need loop-invariant recovery |
| **G3** — `kmalloc` (not `kzalloc`) of struct with padding → `copy_to_user` infoleak | Needs per-field write coverage |
| **Category I (multi-cast / Gap P)** — validation through one cast pointer, read through a different-type alias of the same buffer; scanner cannot connect them without alias analysis. | Alias analysis Step 5; Stage 2 prompt item 12 covers the gap |
| **Category J** — server-reported transfer count not validated against requested length | New sink type needed (value-out-of-bounds, no memory sink) |
| **Category K** — zero-length TLV / infinite loop (DoS) | Scope decision needed first |
| **Category M** — `%s` over-read via printk/cifs_dbg | Format string parser needed |
| **L3** — allocation-formula vs write-formula mismatch (buffer sized with formula A, written with larger formula B) | Two confirmed CIFS instances; needs cross-call-boundary analysis |

## Active next steps

1. **Run Cat I on fs/smb/client** — alias analysis Steps 1–3 are done; first real-world scan for OOB struct field reads. Use `--categories I` (and `cat_i_limit` in `scan_files` if needed) to cap LLM quota.

## Alias analysis progress

Six-step plan; steps 1–3 complete (not yet committed):

| Step | Status | Description |
|---|---|---|
| 1 | **Done** | `_SERVER_RESPONSE_STRUCTS` frozenset + `_ptr_is_server_response()` helper + `var_type_map` threaded through `scan_files()`/`scan_function()` |
| 2 | **Done** | Provenance taint sourcing: `u8 off = rsp->DataOffset` taints `off` via struct type (no endian helper needed); `_field_expr_ptr()` helper |
| 3 | **Done** | Category I scanner — single-cast: `_has_sizeof_guard()` + `scan_cat_i()` in taint_scanner; `cat_i_limit` parameter on `scan_files`; Stage 2 formatting branch added; 43/43 Stage 1 tests |
| 4 | Deferred | Intra-procedural alias root tracking (`_alias_roots()`): `smb2_hdr *hdr = buf; smb2_read_rsp *rsp = buf` → same root |
| 5 | Deferred | Category I multi-cast (Gap P): validation through one cast pointer, read through another alias |
| 6 | Deferred | G3 field-write coverage: which struct fields are initialized before `copy_to_user` |

**Key design decisions for alias analysis:**
- Dual-use types (`smb2_hdr`, `smb2_pdu`, `smb_hdr`) excluded from `_SERVER_RESPONSE_STRUCTS` — type alone does not establish provenance; initialization-based provenance deferred to Step 4
- `_field_expr_ptr` peels one cast level only (`(u8)rsp->field`) — deeper nesting returns None (conservative)
- provenance findings use struct type name as `taint_source_fn` (e.g., `'smb2_read_rsp'`) — the `()` suffix in Stage 2 display is a known cosmetic issue, acceptable for now

## Constraints

- Do NOT commit or push unless explicitly asked
- Git commits: `Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>`
- Update `bc_category_review_brief.md` whenever categories, SMT properties, or Stage 2 prompt items change
- Test suite: `python3 tests/run_all.py` — excludes Stage 2 (API cost)
- Config: `bc_config.yaml` in project root; output: `bc_runs/`

## Recently completed

- **Alias analysis Step 3** — Category I scanner (single-cast form): `_has_sizeof_guard()` checks for `sizeof(struct T)` or `sizeof(*ptr)` in an if_statement before the first field read; `scan_cat_i()` emits Cat I findings per server-response struct pointer; `cat_i_limit` param on `scan_files` caps tree-wide scan for LLM quota; Stage 2 formatting branch added; 43/43 Stage 1 tests.
- **Alias analysis Step 2** — provenance-based taint sourcing: `u8 off = rsp->DataOffset` now taints `off` when `rsp` is declared as a type in `_SERVER_RESPONSE_STRUCTS`; `_field_expr_ptr()` helper peels one cast; `fp_provenance_local_struct` test confirms non-server structs are not tainted. Tests: 39/39 Stage 1, 37/37 provenance.
- **Alias analysis Step 1** — `_SERVER_RESPONSE_STRUCTS` (21 SMBv2/SMB3 _rsp types + oplock/lease/transform), `_ptr_is_server_response()` helper, `build_var_type_map()` wired into `scan_files()`/`scan_function()` per function; `run_provenance.py` test harness.
- **Stage 1.5** (caller enumeration) — `stages/stage1_5_callers.py`: for static functions with findings, scans all source files once (via `build_call_site_index`), identifies the taint-originating parameter, checks each call site for guards via one-hop variable derivation + `_find_guards_between`. Attaches `caller_context` (determinable, all_callers_guarded, call_sites[{guarded, guard_kind, snippet}]) to each finding. Wired into cli.py between Stage 1.7 and Stage 2; rendered in all three report formats. Stage 2 prompt item 2d added: LLM dismisses findings where all callers guard.
- `prop_underflow` (Stage 1.7) — detects unsigned `A - B` subtraction (including under integer-promotion wrapping); `UGT(subtrahend, minuend)` produces a witness when no floor guard prevents wrap; UNSAT when a `total >= min` guard covers the path. Fixes misleading `safe: value is unsigned` from `prop_negative` for Gap S (subtraction-derived size at sink). Gap R (subtraction inside a loop body) remains not-modelled — loop clobber prevents BVSUB recovery at the post-loop sink.
- `min()`/`min_t()`/`clamp()` ceiling guard recognition in `_find_guards_between` — `V = min(V, LIMIT)` now credits `possibly_guarded=True`; non-dominating guards correctly rejected
- `flex_array_size` added to `_SAFE_SIZE_HELPERS` — false-positive fix for `kmalloc(flex_array_size(...))`
- Cat H extended to same-width unsigned→signed sign-conversion; `_ERROR_CODE_VARS` filter added
- Cat L added (tainted shift amount); `prop_shift_bounds` SMT property wired in
- Stage 2 prompt extended to 14 items: caps-vs-inflations, copy_to_user user-controlled size, struct cast before header check, kmalloc(0) ZERO_SIZE_PTR, unsigned subtraction underflow (both patterns)
- `smt_witness_reachable` field added to Stage 2 per-finding schema
- CLI reworked: positional PATH args, comma/hyphen category ranges (`A-D`, `A,B,G1`)
- Regression test suite added: `tests/probe_stage1.c`, `probe_smt.c`, `run_all.py`
- `prop_underflow` gap documented in review brief covering both Pattern 1 and Pattern 2
- SMT annotation upgrade on duplicate findings in merge
