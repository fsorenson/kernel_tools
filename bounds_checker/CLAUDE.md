# bounds_checker

Static bounds/data-validation checker for Linux kernel C. Four-stage pipeline:

- **Stage 1** (`parsers/taint_scanner.py`, `parsers/cross_function.py`): per-function taint scanner + one-hop cross-function pass
- **Stage 1.5** (`stages/stage1_5_callers.py`): caller enumeration — annotates findings in static functions with per-call-site guard detection; now includes Cat I-specific sizeof-guard check
- **Stage 1.7** (`smt/`): Z3 SMT refinement using bitvector arithmetic
- **Stage 2** (`stages/stage2_llm_analysis.py`): LLM adjudication per function (15 numbered prompt items + 2a–2e sub-checks)

Full category taxonomy, SMT properties, and Stage 2 prompt items: `bc_category_review_brief.md`

## Key design decisions

- **Bitvectors, not unbounded integers in SMT**: wraparound and truncation must be exact.
- **Retirement condition**: Stage 1.7 retires a finding only when the `safe` property matches what Stage 1's verdict rested on.
- **Cross-function pass is one hop only**: two hops raises FPs; Stage 1.5 looks UP from the callee to check caller-side guards.
- **Cat H excludes error-code variable names**: `_ERROR_CODE_VARS` = {rc, ret, err, error, retval, result, status, r, rv, retcode}.
- **NUL-term converters clear taint**: `_NUL_TERM_CONVERTERS` = {cifs_strndup_from_utf16, cifs_strndup_from_utf8}.
- **Cat I direct-receiver vs sub-handler**: `not-parameter` in caller_context means locally-cast (real bug); `not-static` or `all_callers_guarded` in caller_context informs Stage 2 via prompt 2e.
- **Gap R/S (prop_underflow)**: Stage 1.7 misleadingly returns `safe` for unsigned subtraction underflow; Stage 2 prompt item 15 covers the reasoning gap.
- **Wire-struct provenance**: `_SERVER_RESPONSE_STRUCTS` and `_WIRE_STRUCT_MIN_BYTES` loaded from `data/wire_structs/*.yaml`; dual-use types in `dual_use_sizes` contribute only to size table, not response table.

## Scope

**In scope**: values tainted through scalar endian helpers (`le16_to_cpu` etc.) OR direct field reads from known server-response struct types (`_SERVER_RESPONSE_STRUCTS`), reaching memory, allocation, loop, shift, or sign-conversion sinks within one function or one call hop.

**Deliberately out of scope** (design boundaries, not temporary gaps):
- Dual-use struct types (`smb2_hdr`, `smb2_pdu`) — type alone does not establish provenance
- Purely local overflow — covered by `syntactic_lint`
- Cross-function UAF / refcount / double-fetch — requires whole-program alias analysis
- DoS findings (zero-length TLV / infinite loop) — pending scope decision before Cat K

## Deferred items

| Item | Prerequisite / blocker |
|---|---|
| **Gap R (remaining-length loop)** — `prop_underflow` covers Pattern 2 only; loop-body subtraction not visible at post-loop sink | Path encoder limitation |
| **G3 (per-field coverage)** — currently struct-level infoleak only | Field-definition parsing needed |
| **Category I (multi-cast / Gap P)** — different-type alias of same buffer | Steps 1–5 done; alias Step 5 handles same-type; different-type needs struct-size confirmation |
| **Category J** — server-reported count not validated against requested length | New sink type (value-out-of-bounds) |
| **Category K** — zero-length TLV / infinite loop (DoS) | Scope decision first |
| **Category M** — `%s` over-read via printk/cifs_dbg | Format string parser |
| **L3** — allocation-formula vs write-formula mismatch | Cross-call-boundary analysis |

## Known guard gaps (not yet implemented)

- **`_find_guards_between` (Cat B/C/E taint values)**: now supports `while_statement` and `for_statement` as guards when the sink is inside the loop body; `do_statement` excluded (condition runs after body).
- **Named-constant guards**: `if (skb->len < VENDOR_CAPA_BASE_SIZE)` — constant value not checked against struct size; blocks Bluetooth HCI activation.
- **Macro-wrapped guards in taint path**: `_has_sizeof_guard` recognises `ceph_decode_need`; taint categories (`_find_guards_between`) do not.

## Active next steps

1. ~~**`_find_guards_between` while/for extension**~~ — **done**; 58/58 tests.
2. **Named-constant guard recognition** — prerequisite for Bluetooth HCI YAML activation; options: (a) constant propagation from `preproc_def` nodes, (b) heuristic `if (len_var < CONSTANT)` credited conservatively.
3. **Bluetooth HCI YAML** — audit which HCI event structs are receive-only (never sent); then add `bluetooth_hci.yaml`. Blocked on #2 or careful per-type audit.
4. **Wider G3 scan** — G3 finds 0 in fs/smb; try `--categories G3` on drivers/gpu/drm or net/.

## Constraints

- Do NOT commit or push unless explicitly asked
- Git commits: `Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>`
- Update `bc_category_review_brief.md` whenever categories, SMT properties, or Stage 2 prompt items change
- Test suite: `python3 tests/run_all.py` — excludes Stage 2 (API cost); 58/58 Stage 1 tests currently
- Config: `bc_config.yaml` in project root; output: `bc_runs/`

## Recently completed

- **`_find_guards_between` while/for** — `while_statement`/`for_statement` conditions now guard sinks inside the loop body (Cat B/C/E/F); do-while excluded; 3 new test cases; 58/58.
- **Cat I caller enumeration (Stage 1.5)** — `annotate_cat_i_findings()`: static functions with parameter-based Cat I findings get caller_context with sizeof-guard check at each call site; `not-parameter` labels direct receivers; 1 finding auto-dismissed in fs/smb/client (`cifs_fill_dirent_posix`).
- **Macro guard recognition** — `_SIZEOF_GUARD_CALLS` + second walk in `_has_sizeof_guard` for standalone macro calls (`ceph_decode_need`); Ceph types enabled in `ceph.yaml`; 55/55 tests.
- **Stage 2 Cat I prompt items 13 + 2e** — dispatch-layer vs. direct-receiver reasoning; typed-pointer parameter → FP; raw-buffer internal cast → real bug.
- **Wire-struct data files** — `data/wire_structs/*.yaml`; `smb2.yaml` (verified sizes), `ceph.yaml` (enabled, `ceph_decode_need` guards now recognised); `_load_wire_struct_tables()` loader.
- **while/for guard extension** — `_has_sizeof_guard` now checks `while_statement` and `for_statement` conditions; do-while excluded.
- **Alias analysis Steps 1–6** — provenance table, provenance taint, Cat I single-cast, alias roots, cross-type size guards, G3 scanner; all complete. Tree-wide Cat I scan: 133 findings (all in fs/smb/). Stage 2 LLM on fs/smb: 57 real bugs (OOB reads in SMBv2 command handlers), 76 FPs (request builders + sub-handlers).
- **`--categories` filtering** — `scan_files` category filter applied; each category only shows in summary when requested.
- **Ceph Cat I + macro guard** — `ceph_decode_need` now recognized; fs/ceph: 2 Cat I findings, both FPs (handle_reply has sizeof guard, mds_alloc_msg is sub-handler); net/ceph messenger not yet run through Stage 2.
