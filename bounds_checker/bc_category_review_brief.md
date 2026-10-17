# Bounds checker — category list for completeness review

A static analyzer for Linux kernel C (tree-sitter, no compilation).

**Stage 1** is a per-function taint/pattern scanner with a one-hop cross-function
pass.  **Stage 1.7** refines surviving findings with a Z3 SMT solver.  **Stage 2**
sends the refined set to an LLM for adjudication.

---

## Taint model

A value is tainted if it comes from a scalar endian helper —
`get_unaligned_{le,be}{8,16,32,64}()`, `{le,be}{16,32,64}_to_cpu()`, `ntohs/ntohl`
— or is derived from one by arithmetic.

Taint propagates through:
- Arithmetic on tainted values (`+`, `-`, `*`, `>>`, `|`, `&`)
- Assignment to a narrower type (also triggers Cat H `narrowed_value`)
- Assignment to a signed type of the same width (also triggers Cat H `sign_conversion`)
- Compound assignments (`|=`, `+=`, etc.)
- Field reads from a struct pointer that is itself derived via tainted offset
  arithmetic (pointer-kind taint)
- One call hop: a tainted argument flows through a callee into a dangerous sink
  in the callee body (cross-function pass, one level deep)

Taint does **not** propagate through:
- Buffers returned by allocators (`kmalloc` etc.) — the returned pointer is in
  bounds by construction regardless of the size argument
- Calls to NUL-terminating converter functions (`cifs_strndup_from_utf16`,
  `cifs_strndup_from_utf8`) — their return value is a kernel-allocated,
  NUL-terminated string safe for `strlen`, regardless of the server-supplied
  length argument
- Values never passing through an endian helper (e.g., a plain struct field read
  that is not endian-converted at this site)
- Transitive taint beyond one call hop

A finding carries a `possibly_guarded` flag when a comparison or a
`check_*_overflow()`/`size_{add,mul}()` call referencing the tainted variable
appears between the taint source and the sink.  A Cat D finding additionally
requires that the guard call's return value is actually used (a bare
`memchr(buf, 0, len);` with no result check is not a guard).

---

## Stage 1: implemented categories

| Cat | Sink | Description |
|---|---|---|
| A | `memcpy`/`memmove`/`memset`/`copy_{to,from}_user` etc. | Tainted value reaches a pointer or length argument of a memory operation |
| B | `kmalloc`/`kzalloc`/`kcalloc`/`kmalloc_array`/`vmalloc`/`devm_*` etc. | Tainted value reaches an allocation size argument |
| B (OVF) | Same allocators | Size argument is a `*` or `+` expression with a tainted operand and no safe-overflow wrapper; emitted as a separate finding with `overflow=True` |
| C | `arr[idx]` | Tainted value used as an array subscript |
| D | `strlen`/`strlcpy`/`strcat`/`kstrdup` | String function applied to a buffer derived via tainted offset arithmetic, with no prior `strnlen`/`memchr` *whose return value is checked* that establishes a terminator in bounds |
| E | `p->field` | Dereference of a pointer computed from a tainted offset, without first checking the resulting pointer against the packet end |
| F | `for (i = 0; i < n; i++)` | Tainted value used as a loop iteration bound |
| G1 | `copy_{to,from}_user` | Return value discarded or not compared against zero — a partial copy is treated as success |
| G2 | `copy_{to,from}_user` | Size argument is user-supplied and unvalidated at the call site |
| H (narrowing) | declaration / assignment | Tainted wide value stored into a narrower integer type; the truncated value is what later bounds checks see |
| H (sign-conv) | declaration / assignment | Tainted unsigned value stored into a signed local of the **same width**; values with the MSB set become negative, bypassing `if (local > MAX)` ceiling checks.  Not emitted for conventional error-code variable names (`rc`, `ret`, `err`, etc.). |
| L | `x << n` / `x >> n` | Tainted value used as the shift amount without a prior check that it is less than the type width — shifting by ≥ width is undefined behaviour in C |

### Cross-function pass

After the intra-procedural scan, a second pass enumerates call sites where a
tainted variable is passed as an argument, then scans the callee body for
dangerous sinks that use that parameter.  The resulting findings carry
`propagation: 'cross_function'` and a `callee_fn` label; Stage 1.7 skips them
(both bodies are needed to answer the arithmetic question, and neither alone
suffices).

### Notable suppressions in the taint model

- **Allocator returns** (Cat A/C/E): a pointer returned by `kmalloc` etc. is
  tracked as non-tainted even when its size argument was tainted — the allocation
  itself is in bounds by construction and the finding is already captured at the
  allocation call.
- **NUL-terminating converters**: `cifs_strndup_from_utf16` and
  `cifs_strndup_from_utf8` sanitize potentially-unterminated server data into a
  guaranteed NUL-terminated kernel string.  Taint is cleared from their return
  value so that downstream `strlen` calls on the result are not flagged.
- **`taint_indirect` flag**: when a tainted value is assigned from a field of a
  tainted pointer (`nlen = ea->ea_name_length`), the report marks the taint as
  indirect (`via le16_to_cpu()`) rather than a direct call, since the endian
  helper was not at the assignment line.
- **Cat H sign-conversion / error-code variables**: variable names conventionally
  used for return codes (`rc`, `ret`, `err`, `error`, `retval`, `result`, etc.)
  are excluded from sign-conversion findings.  Storing `le32_to_cpu(status)` in
  `int rc` is intentional kernel idiom; the sign change is by design.
- **Cat L / bitmask guard**: `tag = le16_to_cpu(x) & 0x1f` followed by
  `1 << tag` surfaces as Cat L with `guarded=False` because the scanner's guard
  detection looks for comparisons, not bitwise masks.  Stage 1.7's
  `prop_shift_bounds` retires these — the bitvector model proves `val & 0x1f`
  is always < 32.

---

## Stage 1.7: SMT refinement

Z3 (bitvector arithmetic, not integer) is run on each surviving finding in a
worker pool before Stage 2 sees it.  The five properties it can decide:

| Property | Claim checked | Retires on UNSAT? |
|---|---|---|
| `negative` | Can this signed value be negative where it reaches a `size_t` sink? | Yes, when Stage 1's verdict was `upper-bound-only-signed` |
| `overflow` | Can this `*` or `+` expression wrap before the allocator or copy sees it? | Yes, when role is `size_mul_overflow` |
| `truncation` | Can this value lose bits that matter when narrowed to the destination type? | Yes, when role is `narrowing_assignment` or `narrowed_value` |
| `guard-transfer` | Does the ceiling the guard established still cover the value reaching the sink? | Yes, when Stage 1's verdict was `covers-base-not-offset` or `stale-redefinition` |
| `shift-bounds` | Can the shift amount reach or exceed the bit-width of the left operand? | Yes, when role is `shift_amount` (Cat L) |

Properties that need a buffer size (how big is the destination of this `memcpy`,
how many entries does this table have) are absent — guessing would convert a
sound suppressor into an unsound one.

**Verdicts per finding:** `safe` (UNSAT — property holds for every value the
encoder could not resolve), `witness` (SAT with a concrete server-supplied
assignment that breaks the property), `unknown` (timeout or dependent
counterexample), `not-modelled` (finding type or expression shape not handled).

**Retirement:** a finding is retired (moved to `findings_suppressed`) only when
the property that came back `safe` is the one Stage 1's own verdict rested on.
A size that provably cannot be negative is still a size nobody bounded against
the destination buffer.

**Encoder guarantees:**
- Bitvectors, not unbounded integers — wraparound and truncation are exact.
- Struct field types resolved dynamically by parsing the file's `#include` chain
  (2-hop, LRU-cached); wire-typed fields (`__le32`, `__be16`) are marked as
  genuine server unknowns rather than model gaps.
- Function parameters are included in the declared-type map (not just locals).
- Macro and enum constants (`ALL_CAPS` names) are treated as fixed-but-unknown
  values (`opaque=True`) with type `int` — not guessed widths.
- `sizeof` expressions are typed as `size_t` (unsigned, PTR_BITS), not guessed.

---

## Stage 2: LLM adjudication

The surviving findings (after Stage 1.7) are sent function-by-function to an LLM
with the function source, callee source (one hop), known validator postconditions,
and the SMT verdict (PROVED or COUNTEREXAMPLE with witness, never `unknown`).

Per-finding schema fields: `taint_is_server_supplied`, `bounds_check_present`,
`bounds_check_sufficient`, `smt_witness_reachable` (true/false/null — whether the
LLM verified the SMT witness is reachable), `real_bug`, `impact`, `symptom`,
`suggested_fix`, `cve_pattern`, `notes`.

The analysis task prompt carries 13 numbered items covering the main classes of
reasoning error observed in practice:

1. Taint is genuinely server-supplied (vs. a locally-built request)
2. Bounds check present and sufficient (and callee postcondition analysis)
2a. Counterexample test (mandatory for every finding; includes `size=0` / ZERO_SIZE_PTR
    check for Cat B)
2b. SMT witness reachability
2c. Packet-relative bounds check — `count * sizeof(element) <= received_size`,
    not just `count <= MAX` (the SMT layer cannot see buffer sizes)
3–11. Real bug, impact, symptom, suggested fix, CVE pattern, validation notes
10. Caps vs. inflations — `if (x > limit) x = limit` reduces x, never inflates it
11. `copy_to_user` with user-controlled size cap is self-limiting
12. Struct cast from server buffer — field reads before the header size check
    (the scanner treats `le16_to_cpu(ptr->field)` as a taint source, not asking
    whether the READ ITSELF is in bounds if the buffer is too short for the struct)
13. `kmalloc(0)` returns ZERO_SIZE_PTR (non-null, non-dereferenceable); a `if (!p)`
    null check does not exclude this case

---

## Designed but not yet implemented

- **G3** — `kmalloc` (not `kzalloc`) of a struct with padding, then
  `copy_to_user`: uninitialized-byte infoleak. Needs per-field write coverage.

- **Category I** — struct cast from server buffer with field reads before the
  header size check.  Pattern: `(struct T *)src` followed by `le16_to_cpu(ptr->field)`
  reads before a `size_of_data_area >= sizeof(struct T)` check.  The scanner
  treats those `le16_to_cpu` calls as taint SOURCES, never asking whether the
  read itself is in bounds.  Confirmed instance: `cifs_to_posix_acl()` (fixed
  `9b2b3cda`).  Stage 2 prompt item 12 covers the reasoning gap; scanner
  detection requires a new category keyed on cast-from-response-buffer.
  Deferred: tree-wide scan would surface hundreds of instances needing Stage 2
  analysis against the monthly LLM quota.

  *Multi-cast variant (Gap P):* The same pattern appears when validation is done
  through one cast pointer (`smb2_hdr *hdr = buf`) and the field read is done
  through a different-type cast of the same buffer (`smb2_read_rsp *rsp = buf;
  rsp->DataLength`).  A length check via `hdr->Command` may or may not establish
  that `buf` is long enough to hold `smb2_read_rsp`; if not, reading `rsp->DataLength`
  is an OOB read, but the scanner has no way to connect the two pointer names to
  the same memory without alias analysis.  Stage 2 prompt item 12 applies here
  too; the alias aspect is out of scope for single-function-body analysis.

- **Category J** — server-reported transfer count not validated against the
  requested length.  The taint IS seeded (e.g., `written = le16_to_cpu(smb->Count)`)
  but never reaches a memory sink — the value goes to inode accounting, a warning,
  or a result out-param.  The sink model has no hook for "value returned to caller
  without an upper-bound check against the original request size."

- **Category K** — zero-length TLV / infinite loop.  Loop advancement
  `offset += tainted_len` where `tainted_len == 0` never advances, causing a
  soft lockup.  Missing guard: `if (tainted_len == 0) return -EINVAL` or
  `if (tainted_len < MIN_HEADER)`.  Not a memory-safety finding — a DoS
  finding — so a scope decision (does this tool want DoS findings?) is needed
  before implementing.  Intra-procedural, detectable with the current taint model.

- **Category M** — `%s` over-read via printk/cifs_dbg/seq_printf.  Passing a
  tainted, potentially non-NUL-terminated pointer to `%s` causes an OOB slab
  read.  Requires parsing format strings to match `%s` positions to their
  arguments.  Lower priority: many tainted `%s` pointers are from
  `cifs_strndup_from_utf16()` output (already suppressed as NUL-terminated), and
  most kernel debug logging (`cifs_dbg(FYI, ...)`) does not expose data to
  userspace.

- **Stage 1.5** — caller enumeration for `needs_validation` findings.  For
  findings where Stage 2 cannot determine safety from the function body alone,
  enumerate direct callers and extract any guards applied to the tainted parameter
  before the call.  Addresses cases like `__smb2_calc_size()` where every call
  site validates `shdr->Command` but Stage 2 only sees the callee.

- **L3 / allocation-formula vs write-formula mismatch** — caller sizes a buffer
  with formula A (e.g., POSIX xattr layout); callee writes it with formula B
  (CIFS wire layout, larger).  Neither formula is wrong internally; the defect is
  that A < B for large counts.  Two confirmed CIFS instances.

---

## What is deliberately out of scope

- Values that never pass through an endian helper (see taint model)
- Transitive taint beyond one call hop
- Guards established more than one frame up the call stack
- Purely local overflow with no server-supplied input — covered by the sibling
  `syntactic_lint` tool (narrow-integer wrap, pointer/length pairing, scan loops)
- Cross-function UAF and refcount accounting (whole-program alias analysis)
- Double-fetch / TOCTOU (requires alias analysis to detect two reads from the
  same expression across branches — out of scope for single-function-body analysis)
- **Integer promotion / architecture-specific multiplication widths**: The Cat B
  (OVF) finder and Stage 1.7 model `sizeof` as `size_t` (PTR_BITS, unsigned),
  which is correct for 64-bit Linux.  When a programmer explicitly intermediate-
  casts both operands to 32-bit (`(int)count * (int)stride`) before passing to
  a `size_t` parameter, the multiplication is done in 32-bit C arithmetic and can
  wrap before implicit widening to `size_t`.  The encoder cannot in general
  determine whether a local `int stride` variable holds a compile-time constant
  from `sizeof` or a narrower programmer-chosen value.  Findings involving such
  expressions are correctly flagged by Cat B (OVF); the SMT verdict on overflow
  depends on whether the encoder infers the right width for each operand.
  Architecture-specific behavior (e.g., whether `size_t` is 32 or 64 bits on the
  target) is not modelled.

---

## The review question

Which classes of kernel bounds, length, offset, or integer-range bug that occur
in real protocol-parsing and driver code are not covered by A–H (including sign-
conversion), L, and the gaps listed above?  For each gap: name the bug class,
give a concrete kernel or CVE example, state the sink and the guard whose absence
defines it, and say whether it is detectable from a single function body given
the taint model above (or whether it requires cross-function, caller-level, or
whole-program information).
