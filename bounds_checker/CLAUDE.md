# bounds_checker

Static bounds/data-validation checker for Linux kernel C. Three-stage pipeline:

- **Stage 1** (`parsers/taint_scanner.py`, `parsers/cross_function.py`): per-function taint scanner + one-hop cross-function pass
- **Stage 1.7** (`smt/`): Z3 SMT refinement using bitvector arithmetic
- **Stage 2** (`stages/stage2_llm_analysis.py`): LLM adjudication per function

Full category taxonomy, SMT properties, and Stage 2 prompt items: `bc_category_review_brief.md`

## Key design decisions

- **Bitvectors, not unbounded integers in SMT**: wraparound and truncation must be exact; unbounded integers would make `prop_overflow` unsound.
- **Retirement condition**: Stage 1.7 retires a finding only when the `safe` property matches what Stage 1's verdict rested on. A size that cannot be negative is still unbounded against the destination buffer — retiring on any `safe` result would be unsound.
- **Cross-function pass is one hop only**: extending to two hops raises false positives because intermediate functions often validate before passing further. The higher-value fix is Stage 1.5 (upward caller enumeration), not deeper callee following.
- **Cat H excludes error-code variable names**: `_ERROR_CODE_VARS` = {rc, ret, err, error, retval, result, status, r, rv, retcode}. Storing `le32_to_cpu(status)` into `int rc` is intentional kernel idiom; the sign change is by design.
- **NUL-term converters clear taint**: `_NUL_TERM_CONVERTERS` = {cifs_strndup_from_utf16, cifs_strndup_from_utf8}. Their return values are kernel-allocated NUL-terminated strings; taint on them would produce false positives on downstream `strlen`.
- **Cat L bitmask guard gap**: `le16_to_cpu(x) & 0x1f` → `1 << tag` shows `guarded=False` in Stage 1 (guard detection uses comparisons, not bitwise masks). Stage 1.7 `prop_shift_bounds` correctly retires these — `val & 0x1f` is provably < 32 in bitvectors.
- **SMT encoder ALL_CAPS treatment**: macro/enum constants are `opaque=True` with type `int`, never guessed widths. `sizeof` is typed as `size_t` (PTR_BITS, unsigned), never guessed.
- **`smt_witness_reachable`**: per-finding Stage 2 schema field (true/false/null) — LLM verifies whether the SMT witness is reachable on a real code path.
- **Merge upgrade**: when a duplicate finding appears in merge, if the newer copy has `smt` and the canonical doesn't, the canonical's `smt` field is upgraded.
- **Gap R/S (prop_underflow)**: Stage 1 correctly fires on unsigned subtraction underflow. Stage 1.7 misleadingly returns `safe` via `prop_negative` because the wrapped value IS unsigned-positive. Stage 2 prompt item 14 covers the reasoning gap in the meantime.

## Scope

**In scope**: values tainted through scalar endian helpers (`le16_to_cpu` etc.) reaching memory, allocation, loop, shift, or sign-conversion sinks within one function or one call hop.

**Deliberately out of scope** (design boundaries, not temporary gaps):
- Values never passing through an endian helper
- Purely local overflow — covered by `syntactic_lint`
- Cross-function UAF / refcount / double-fetch — requires whole-program alias analysis
- Architecture-specific multiplication widths (32-bit intermediate wrap before `size_t` widening)
- DoS findings (zero-length TLV / infinite loop) — pending scope decision before implementing Cat K

## Deferred items

| Item | Prerequisite / blocker |
|---|---|
| **`min()`/`min_t()`/`clamp()` ceiling guards** — `min(tainted, 256)` ≡ `if (t > 256) t = 256`; `_find_guards_between` only sees `if`-condition comparisons; fix: detect `var = min(tainted_var, const)` between source and sink | Moderate complexity; reduces false positives without new findings |
| **`prop_underflow`** (Stage 1.7) — Pattern 1: `remaining -= server_len` without guard; Pattern 2: `size = total_len - sizeof(header)` at Cat A/B sink. Fix: `UGT(subtrahend, minuend)`; must recover both operands from path condition | Moderate complexity; requires operand extraction from path condition |
| **Stage 1.5** — caller enumeration for `needs_validation` findings; check guards on tainted param at each call site | Highest-value precision improvement; moderate complexity |
| **G3** — `kmalloc` (not `kzalloc`) of struct with padding → `copy_to_user` infoleak | Needs per-field write coverage |
| **Category I** — struct cast from server buffer with field reads before header size check; confirmed instance: `cifs_to_posix_acl` (fixed `9b2b3cda`); multi-cast variant (Gap P) needs alias analysis | LLM quota (tree-wide scan too expensive); alias analysis for multi-cast |
| **Category J** — server-reported transfer count not validated against requested length | New sink type needed (value-out-of-bounds, no memory sink) |
| **Category K** — zero-length TLV / infinite loop (DoS) | Scope decision needed first |
| **Category M** — `%s` over-read via printk/cifs_dbg | Format string parser needed |
| **L3** — allocation-formula vs write-formula mismatch (buffer sized with formula A, written with larger formula B) | Two confirmed CIFS instances; needs cross-call-boundary analysis |

## Active next steps

1. `min()`/`min_t()`/`clamp()` ceiling guard recognition in `_find_guards_between` — moderate complexity, reduces false positives
2. `prop_underflow` Stage 1.7 property — covers Gap R (remaining-length loop) and Gap S (subtraction-derived size at sink)
3. Stage 1.5 caller enumeration — highest-value precision improvement, addresses `needs_validation` false positives

## Constraints

- Do NOT commit or push unless explicitly asked
- Git commits: `Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>`
- Update `bc_category_review_brief.md` whenever categories, SMT properties, or Stage 2 prompt items change
- Test suite: `python3 tests/run_all.py` — excludes Stage 2 (API cost)
- Config: `bc_config.yaml` in project root; output: `bc_runs/`

## Recently completed

- `flex_array_size` added to `_SAFE_SIZE_HELPERS` — false-positive fix for `kmalloc(flex_array_size(...))`
- `min()`/`min_t()` ceiling guard gap documented in `bc_category_review_brief.md`
- Cat H extended to same-width unsigned→signed sign-conversion; `_ERROR_CODE_VARS` filter added
- Cat L added (tainted shift amount); `prop_shift_bounds` SMT property wired in
- Stage 2 prompt extended to 14 items: caps-vs-inflations, copy_to_user user-controlled size, struct cast before header check, kmalloc(0) ZERO_SIZE_PTR, unsigned subtraction underflow (both patterns)
- `smt_witness_reachable` field added to Stage 2 per-finding schema
- CLI reworked: positional PATH args, comma/hyphen category ranges (`A-D`, `A,B,G1`)
- Regression test suite added: `tests/probe_stage1.c`, `probe_smt.c`, `run_all.py`
- `prop_underflow` gap documented in review brief covering both Pattern 1 and Pattern 2
- SMT annotation upgrade on duplicate findings in merge
