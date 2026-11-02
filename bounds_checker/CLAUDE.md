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
| **G3 (per-field coverage)** — currently detects struct-level infoleak (kmalloc + copy_to_user without zeroing); true per-field coverage (which specific fields are written vs. uninitialized) not yet implemented | Needs field-definition parsing to know total field list |
| **Category I (multi-cast / Gap P)** — validation through one cast pointer, read through a different-type alias of the same buffer; scanner cannot connect them without alias analysis. | Alias analysis Step 5; Stage 2 prompt item 12 covers the gap |
| **Category J** — server-reported transfer count not validated against requested length | New sink type needed (value-out-of-bounds, no memory sink) |
| **Category K** — zero-length TLV / infinite loop (DoS) | Scope decision needed first |
| **Category M** — `%s` over-read via printk/cifs_dbg | Format string parser needed |
| **L3** — allocation-formula vs write-formula mismatch (buffer sized with formula A, written with larger formula B) | Two confirmed CIFS instances; needs cross-call-boundary analysis |

## Active next steps

1. **Expand `_SERVER_RESPONSE_STRUCTS` to other protocols** — Cat I currently fires only in fs/smb/ because the type table is SMB-specific. Add per-protocol data files under `bounds_checker/data/` (planned: Ceph, Bluetooth HCI). Tree-wide scan (`--categories I /home/src/linux`) found 133 findings in 65746 files — all in fs/smb/. Other protocols (Ceph, Bluetooth) have confirmed historical OOB bugs from the same pattern.
2. **Stage 2 LLM run on Cat I** — use `--categories I --llm` on fs/smb/client to triage the 62 findings (58 unguarded after while/for extension).
3. **Wider G3 scan** — G3 finds 0 in fs/smb (modern CIFS uses kzalloc); try `--categories G3` on older ioctl-heavy code (e.g., drivers/gpu/drm, net/).

## Known guard gaps (not yet implemented)

- **`_find_guards_between` (Cat B/C/E tainted values)**: currently only recognises `if_statement` guards. `while_statement` and `for_statement` conditions also guard their loop bodies, but extending `_find_guards_between` requires adjusting the dominance check and consequence/terminal logic (non-trivial). `_has_sizeof_guard` (Cat I) already supports while/for.
- **Named-constant guards (Bluetooth, older drivers)**: `if (skb->len < VENDOR_CAPA_BASE_SIZE)` where the constant equals `sizeof(struct T)` is not recognised; only `sizeof` expressions are checked.

## Alias analysis — COMPLETE

All 6 steps done (not yet committed as separate commits).

## Alias analysis progress

Six-step plan; steps 1–3 complete (not yet committed):

| Step | Status | Description |
|---|---|---|
| 1 | **Done** | `_SERVER_RESPONSE_STRUCTS` frozenset + `_ptr_is_server_response()` helper + `var_type_map` threaded through `scan_files()`/`scan_function()` |
| 2 | **Done** | Provenance taint sourcing: `u8 off = rsp->DataOffset` taints `off` via struct type (no endian helper needed); `_field_expr_ptr()` helper |
| 3 | **Done** | Category I scanner — single-cast: `_has_sizeof_guard()` + `scan_cat_i()` in taint_scanner; `cat_i_limit` parameter on `scan_files`; Stage 2 formatting branch added; 43/43 Stage 1 tests |
| 4 | **Done** | Alias root tracking: `_peel_casts()` + `_alias_roots()` build `{var: root_text}`; `_has_sizeof_guard` extended to credit same-root same-type aliases; 45/45 Stage 1 tests |
| 5 | **Done** | Cross-type alias guards: `_alias_roots` now returns `{var: frozenset_of_roots}` + tracks assignment expressions; `_SMB2_STRUCT_MIN_BYTES` size table; `_has_sizeof_guard` credits larger-type alias guards; 48/48 Stage 1 tests |
| 6 | **Done** | G3 scanner: `scan_g3()` + `scan_g3_files()` detect `kmalloc`-allocated structs (unzeroed) passed to `copy_to_user`; kzalloc and `memset(p, 0, ...)` suppress the finding; field-write heuristic avoids raw-buffer FPs; 52/52 Stage 1 tests. Zero findings in fs/smb/client (modern code uses kzalloc). |

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

- **Macro guard recognition** — `_SIZEOF_GUARD_CALLS` frozenset + second walk pass in `_has_sizeof_guard` for `call_expression` nodes (standalone guard macros like `ceph_decode_need` that are not inside an if/while/for condition). Sizeof helper extracted to inner `_sizeof_matches()`. Ceph types enabled in `ceph.yaml`; `process_message_header()` in `messenger_v2.c` now correctly shows as `[guarded?]` (the historical confirmed bug — fixed upstream by adding `ceph_decode_need`). 11 Ceph Cat I findings (1 guarded, 10 needing Stage 2 triage). 55/55 Stage 1 tests.
- **Stage 2 Cat I prompt** — added item 13 (dispatch-layer vs. direct-receiver pattern) and assessment step 2e (Cat I dispatch-layer check). Item 13 explains both the false-positive pattern (sub-handler with dispatcher-validated pointer) and the true-positive pattern (function casts raw buffer itself). Step 2e gives the LLM concrete signals: typed pointer parameter → likely FP; raw buffer + internal cast → likely real bug.
- **Wire-struct data files** — `_SERVER_RESPONSE_STRUCTS` and `_WIRE_STRUCT_MIN_BYTES` (was `_SMB2_STRUCT_MIN_BYTES`) now loaded from `bounds_checker/data/wire_structs/*.yaml`. `_load_wire_struct_tables()` reads `response_structs` (name→min_bytes) and `dual_use_sizes` (excluded from response table, included in size table for alias analysis). SMBv2/SMB3 content migrated to `smb2.yaml`; `ceph.yaml` is a stub (commented out — Ceph uses `ceph_decode_need` macro guards the scanner can't yet see). Adding a new protocol = add a YAML file, no code changes needed.
- **while/for sizeof guard extension** — `_has_sizeof_guard` extended to recognise `while_statement` and `for_statement` conditions (not only `if_statement`); `_GUARD_STMT_TYPES` frozenset; do-while excluded (condition runs after first body iteration). 2 new test cases (guarded_I_while_sizeof, guarded_I_for_sizeof); 54/54 Stage 1 tests. One previously-unguarded Cat I finding in fs/smb/client now correctly credited as guarded (62 total, 4 guarded was 3).
- **Alias analysis Step 6 (G3)** — `scan_g3()` + `scan_g3_files()` in `taint_scanner.py`: detects `kmalloc`/`kvmalloc`/`vmalloc`-allocated struct pointers passed to `copy_to_user` without prior zeroing (`kzalloc` or `memset(p, 0, ...)`); field-write heuristic (`p->field = value` must exist) avoids flagging raw buffer copies; wired into `stage1_taint_scan.py` (same pattern as G1/G2), `config.py`, `cli.py`, `report.py` (3 render formats); 4 test cases (bug, fp_kzalloc, fp_memset, fp_no_field_writes), 52/52 Stage 1 tests. Zero findings in fs/smb/client and fs/ tree (modern kernel code uses kzalloc for structs copied to userspace).
- **Alias analysis Step 5** — cross-type alias guards: `_alias_roots` refactored to return `{var: frozenset_of_roots}` and now also tracks `ptr = expr` assignment expressions (handles NULL-init-then-assign pattern); `_SMB2_STRUCT_MIN_BYTES` size table (22 SMBv2/SMB3 struct types, sizes verified from smb2pdu.h); `_has_sizeof_guard` extended to credit sizeof guards on larger-type aliases via set intersection + size comparison; 3 new test cases (cross-type larger guard, cross-type smaller guard, assignment alias); 48/48 Stage 1 tests. Real scan unchanged (no larger-type cross-type alias guards exist in fs/smb/client).
- **Alias analysis Step 4** — alias root tracking: `_peel_casts()` strips cast/paren wrappers; `_alias_roots(fn_body, source)` builds `{var_name: root_text}` from init_declarator nodes; `_has_sizeof_guard` extended to credit `sizeof(*alias_var)` guards when `alias_var` shares the same root buffer and same struct type as `ptr_var`. Real CIFS scan unchanged (no same-root same-type alias patterns exist in the codebase). 45/45 Stage 1 tests.
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
