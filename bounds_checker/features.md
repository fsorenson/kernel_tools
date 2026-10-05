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

- [x] Stage 1.7: SMT refinement — `bounds_checker/smt/`, driven by
      `bounds_checker/stages/stage1_7_smt.py`.  Stage 1 decides whether a guard
      is sufficient with hand-written rules over the AST, but the question those
      rules are really answering is about machine arithmetic: can this value be
      negative, can this product wrap, does a bound established for `off` still
      hold for `off + 1`.  Each rule is therefore an approximation.  This stage
      re-asks the same question of Z3 over bitvectors with C's widths and
      conversions, which is the only model in which wraparound and truncation
      mean what they mean in the kernel.

      - **Direction.**  Everything the encoder cannot resolve — a call return,
        a global, a field whose type it could not read — becomes an
        unconstrained bitvector, so UNSAT is the only sound verdict: if the
        property holds with those free, it holds for every value they could
        take.  SAT is therefore only a witness, never a bug claim.  `unknown`,
        a solver timeout, and an exception in the worker all keep the finding
        exactly where it was — the layer fails open, and the only thing it can
        do to the finding set is remove entries it has proved unnecessary.

      - **Verdict and suppression are different things.**  `verdict` answers
        the properties that could be posed; `suppresses` (rendered as `retires`
        in the JSON) says whether those were the ones Stage 1's verdict
        actually rested on.  The two come apart constantly: a size that
        provably cannot be negative is still a size nobody bounded against the
        destination buffer.  `_BASIS_BY_KIND` maps `upper-bound-only-signed` →
        `negative` and `covers-base-not-offset` / `stale-redefinition` →
        `guard-transfer`; `_BASIS_BY_ROLE` maps `size_mul_overflow` →
        `overflow` and `narrowing_assignment` / `narrowed_value` →
        `truncation`.  A finding with no entry in either rests on something
        these properties do not express, so a clean answer is recorded and the
        finding survives.

      - **Encoder** (`smt/encoder.py`) — a C expression AST walks to a `Value
        (bv, width, signed, guessed)`, so the usual arithmetic conversions are
        applied at each operator rather than guessed once; the equal-width
        unsigned-wins rule is what turns `i < len` into an unsigned compare
        when `len` is `size_t` and lets a negative `i` through.  Shifts promote
        the left operand alone and keep its type.  `le32_to_cpu()`-class
        accessors yield the defining unknown — width fixed by the accessor,
        value entirely the far side's choice.  `likely`/`unlikely`/`WARN_ON`/
        `READ_ONCE` and friends are transparent, so
        `if (WARN_ON_ONCE(i >= size)) return;` contributes to the path
        condition instead of nothing.  `_LIMIT_CONSTS` supplies `U8_MAX`,
        `INT_MAX`, `SIZE_MAX` and the rest, without which `if (len > U8_MAX)`
        constrains `len` against a free variable and so constrains nothing;
        anything architecture- or config-dependent is deliberately left out,
        since a wrong constant is worse than an unknown one because it reaches
        the UNSAT direction.  An unevaluable `sizeof` is bounded to 1..0xFFFF
        rather than left free, which would make every product look like it can
        wrap.  Everything else — a subscript, a deref, an unrecognised shape —
        is a fresh constant.

      - **Path condition** (`smt/pathcond.py`) — nothing here searches for
        paths; the taint walk already chose one, and this reconstructs the
        facts that hold along it.  A structured walk descends into the arm the
        sink is in, inverts conditions whose other arm has an early-exit
        terminal, and `_merge()`s both arms when control rejoins below
        (pre-branch binding as the default, drop what neither arm resolves).
        Each guard is kept with a snapshot of the environment, because a bound
        constrains the term the variable held *then*, not the name.
        `_short_circuit()` picks up conjuncts that must have held for
        evaluation to reach the sink, as in `len > 0 && !strncmp(a, b, len)`.
        A loop is modelled as one arbitrary iteration: `_clobber()` unbinds
        everything the body writes, then the controlling test and the guards
        above the sink apply normally, and `_loop_floor()` restores the one
        fact a single iteration loses — `for (i = 0; ...; i++)` with no other
        write to `i` has `i` at or above its start, without which the counter
        runs negative and no amount of guarding inside the body can rule it
        out.  A `labeled_statement` clears the environment entirely, since a
        `goto` can land there from anywhere.  Every unmodelled write unbinds
        rather than guesses, including field accesses reached through the
        clobbered name, which costs precision but never soundness.

      - **Properties** (`smt/properties.py`) — four, each the negation of an
        obligation the finding implicitly claims is unmet.  `prop_negative`
        (`upper-bound-only-signed` decided rather than asserted — it absorbs
        the three shapes `_max_bits()` hand-models, since a widened 16-bit
        read, a mask and an unsigned right shift are each unsatisfiable here
        without a rule saying so), `prop_overflow` (`BVMulNoOverflow` /
        `BVAddNoOverflow`, plus the underflow side when signed),
        `prop_truncation`, and `prop_guard_transfer`, which substitutes what
        the sink computes for what the guard constrained and asks whether the
        ceiling survived — without needing to know what it meant.  Transfer
        declines to answer when the guard already applies arithmetic to the
        variable (pricing the adjustment in twice) or when the sink is not a
        constant shift of the guarded term (`num` bounded to 1..4, then
        `size * num` allocated — a ceiling on one is not a ceiling on the other).

      - **Counterexamples are tested for robustness.**  `_decide()` takes UNSAT
        as the clean answer, and on SAT asks a second question: the assignment
        may exist only because a term standing for a gap in the model was free
        to take whatever value it needed.  `ForAll(free, Implies(assumptions,
        claim))` over exactly those terms demands the counterexample hold for
        *every* value of them — the mirror of the UNSAT bargain.  Anything
        else, including a timeout on the quantified query, yields `unknown`.

      - **Two independent axes**, easy to conflate.  `opaque` says the *value*
        is a gap in the model — an unmodelled callee return, a macro the
        encoder could not expand, a name the walk lost — and it is these terms
        the ∀ test quantifies over.  `Value.guessed` says the *width and
        signedness* came from a default rather than from the source.  They are
        orthogonal: reasoning about the type (does this fit, can this be
        negative) cannot rest on a guessed type, so `prop_negative` and
        `prop_truncation` return `not-modelled` for one, while reasoning about
        the value still can, since the term is free either way.  An enum is the
        common case — nothing names its underlying type at the use site, and a
        guess of signed int would turn every wire value with the top bit set
        into a counterexample C would never produce.

      - **Struct field types are dynamic** (`smt/fields.py`) — nothing about
        any particular struct is recorded.  The index is built by parsing the
        definitions reachable through the file's `#include`s (two hops;
        `fs/smb/client/smb2misc.c` reaches `struct smb2_lease_break` via
        `smb2pdu.h`), cached per header since headers are shared heavily, so a
        field that gains a bit, changes width or moves to another header
        changes what the checker concludes with nothing here touched.  A tag
        two reachable headers define differently is dropped rather than decided
        by parse order — `struct node` is not a unique name in this tree and
        the wrong widths reach the UNSAT direction.  Bitfield widths become
        range facts.  The endianness annotation is worth as much as the width:
        a `__le32`/`__be16` field is wire or on-disk data *by declaration*,
        the same provenance `le32_to_cpu()` carries, so it is a genuine unknown
        rather than a gap — free in value, but not quantified over in the ∀
        test.  Only scalars take their declared type; `char *name` and
        `u8 buf[64]` both read as addresses.

      - **Wiring** — on by default between Stage 1 and Stage 2, one worker
        process per source file (`smt.workers`, default 8; `--smt-workers`),
        `smt.timeout_ms` per query (default 200; `--smt-timeout`), `--no-smt`
        to skip.  Retired findings move to `findings_suppressed` in the Stage 1
        output so the decision is auditable, and `stage1_7_smt.json` records
        the verdict histogram and a digest of each retirement.  Stage 1 defers
        its findings file and static-only report to this stage rather than
        writing a set that is about to change, so every exit from here —
        including no z3 and nothing to refine — emits them.  The reports carry
        the retirements per category (`Cat H: 5 (+5 retired)`) so a drop
        against an earlier run reads as a proof rather than as findings gone
        missing.  Surviving findings carry their `smt` block
        into the Stage 2 prompt as one line — a proof, or a counterexample with
        its `*_val` (wire) and `*_ret` (unmodelled return) assignments.  What
        the two verdicts are worth, and the asymmetry between them, is stated
        once in the preamble rather than per finding; `unknown` is not rendered
        at all, since it says nothing about the code and would only add weight
        to the prompt.

      - **Measured**, `/home/src/linux`, 37,372 `.c` files, 5,495 Stage 1
        findings, 85 s at 30 workers: 1,546 safe, 3,491 not-modelled, ~314
        unknown, ~144 witness.  The last two trade places by a couple across
        runs, since a query that lands near the 200 ms budget is decided by how
        loaded the box is.  374 findings retired by proof — i.e. of the 1,546
        proofs, 374 closed the property Stage 1's own verdict rested on; the
        remaining 1,172 answered a real question about a finding that rests on
        something else.  12 of the witnesses are findings Stage 1 had called
        `bounded`, which is the interesting direction: a counterexample against
        a guard the AST rules credited.  On the 57-file `fs/smb/client` subset,
        121 findings (92 refined, 29 cross-function skipped), 5 retired, 0
        counterexamples — the subsystem the rules were written against is where
        they are already right.  `fs/ntfs3` is the contrast: 305 findings, 11
        retired, 5 counterexamples.

      - **Known limitations.**  Buffer-size properties are out of scope
        entirely: how big is the destination of this `memcpy`, how many entries
        does this table have.  They need declaration data the scanner does not
        collect, and guessing would convert a sound suppressor into an unsound
        one.  Cross-function findings are skipped — the sink is in the callee
        and the guard in the caller, and neither body answers the question on
        its own.  A loop is one arbitrary iteration, so nothing that depends on
        the trip count is modelled.  And a guard whose comparison semantics
        rest on a guessed type is still asserted into the path condition: the
        `_grounded` test gates the properties, not the assumptions.

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

- [x] Reaching definitions — a guard was credited no matter what happened to the
      variable afterwards, so `old = READ_ONCE(server->fastest_cmd[smb_cmd]);`
      in `__release_mid()` kept the `if (prev == old)` from the iteration before
      it.  Staleness is now tested per candidate, since a write that discards an
      early guard may be covered by a later one, and three shapes do not count:

        - a write that reads the variable (`len -= sizeof(*rp)`, `++`/`--`,
          `min_t(u16, sense_len, SCSI_SENSE_BUFFERSIZE)`) is a transform the
          guard still describes.  `if (len < sizeof(*rp)) goto reject;` then
          `len -= sizeof(*rp)` is how every length-counted protocol loop in the
          tree is written, and the guard is what makes the subtraction safe;
        - a write in a branch that leaves (`w0 = ffdc_sz; break;` inside the
          guard's own arm, `__sbefifo_dump_ffdc`) never reaches the use;
        - a write gated on a comparison of the same variable, in a branch the
          use is not in, re-establishes the bound rather than discarding it —
          `if (w_length > USB_COMP_EP0_BUFSIZ) w_length = USB_COMP_EP0_BUFSIZ;`
          is how clamps are written.

      Tree-wide guarded 1,356 → 1,240 on an unchanged 11,074 findings; 129
      `stale-redefinition`, 13 of them reclassified from the two earlier kinds
      (`covers-base-not-offset` 87 → 80, `upper-bound-only-signed` 98 → 92).
      fs/smb/client 131 → 127: `__release_mid` above, and three in
      `cifs_query_reparse_point` where `buf = (struct reparse_data_buffer *)
      start;` post-dates the only guard naming `buf`.

      Known miss: `+=` after a ceiling guard does break it, while `-=` after a
      floor guard is what the guard protects — separating those needs the
      bound-direction machinery applied to intervening writes, and there are 10
      `+=` instances tree-wide.  `cfg_killed_def` in the probe corpus
      (`if (len > 64) return; len += 8; memcpy(...)`) still reads `bounded`.

- [x] Guard reached only through `sizeof` — found while reading the 170
      redefinition candidates above, a third of which the detector had scored as
      redefinitions when the guard never constrained the variable to begin with.
      A `sizeof` operand is evaluated for its type, so `if (partoffset +
      sizeof(*part) > datasize)` in `mac_partition()` bounds `partoffset` and
      `if (start >= end || (size_t)(end - start) < sizeof(*buf))` in
      `cifs_query_reparse_point()` bounds neither `start` nor `buf`.
      `_names_compared()` no longer descends into `sizeof_expression`, matching
      what `_g2_size_identifiers()` already did on the size-argument path;
      `_names_in_operand` keeps descending, so `covers-base-not-offset` is
      untouched at 80 tree-wide, which is the check that the change stayed
      inside the guard path.  Tree-wide guarded 1,240 → 1,151 on an unchanged
      11,074 findings, and `stale-redefinition` 129 → 94 as 35 of those guards
      stopped being candidates at all.  fs/smb/client 127 → 120, including the
      three `cifs_query_reparse_point` findings above — the right answer, since
      the only guard naming `buf` named it via `sizeof(*buf)`.

- [x] Guard does not dominate the sink — a credited guard was taken at face
      value however deeply it was nested, so a check reached on one path was
      credited for a use reachable on others.  `_dominates()` walks the guard's
      ancestors and requires every `if`/`switch`/`for`/`while` branch it sits
      inside to also contain the sink line; a `do` body is not a branch, since
      it always runs.  This is the last guard gap that structured-C ancestry
      answers — what remains (loop back edges) needs a real CFG.

      Tree-wide guarded 1,151 → 1,103 on an unchanged 11,074 findings, with 119
      `does-not-dominate`, 71 of them reclassified from the other kinds
      (`stale-redefinition` 94 → 38, `upper-bound-only-signed` 92 → 79,
      `covers-base-not-offset` 80 → 78).  fs/smb/client 120 → 118:
      `__release_mid` and `CIFSSMBQAllEAs`.

      119 is 7× what the standalone detector predicted, so it was checked
      rather than taken: the detector examined only the 756 findings whose sink
      node it could re-locate, compared ancestor sets by identity instead of
      line span, and ignored loops, which are half the population.  Of the 103
      that could be traced back to a construct, 52 were `if`/`switch` and 51 a
      loop.  Reading them turned up a real unchecked use:
      `kv_parse_power_table()` gates `clock_array_index` inside the
      `ucNumDPMLevels` loop, then reassigns it from `vce_states[i].clk_idx` in
      a second loop and indexes `clockInfo[clock_array_index *
      ucEntrySize]` with no check at all — `si_dpm.c` (amd and radeon) and
      `trinity_dpm.c` carry the same code.  In `altera_execute()` the guard
      sits under `if (version > 0)`, so the `version == 0` path reaches
      `charptr_tmp[long_idx >> 3L]` untested.

- [x] Reaching definitions on the taint map — the guard-level rule above was
      only half the story: `tainted` was append-only, so a plain assignment
      from a value derived from neither a source nor the old value left the
      taint in place.  `cifs_query_path_info()` has two WSL-EA blocks that each
      open `ea = (struct smb2_file_full_ea_info *)data->wsl.eas;`, and every
      dereference in the second block was attributed to the `le32_to_cpu()` in
      the first.  A kill is scoped by `_kill_extent()` to the branch arm the
      write sits in, since the other path still reaches the sink carrying the
      taint, and a retaint inside that arm supersedes the pending kill rather
      than being undone when the arm ends.  Compound assignment keeps what it
      accumulates onto, and `p->field = ...` yields no LHS variable, so neither
      kills.

      This does not subsume the guard-level rule: a fresh value taken from
      *another tainted variable* retaints rather than killing, which is the 34
      `stale-redefinition` that remain.  Tree-wide 11,074 → 10,864 findings
      (the first count in this section that moves), guarded 1,103 → 1,080,
      `does-not-dominate` 119 → 92, `stale-redefinition` 38 → 34.

- [x] Phase 1 attributed the callee's own taint to the parameter — the
      parameter simulation seeds one parameter and then recorded *every*
      finding the walk produced, including ones rooted in the callee's own
      `le32_to_cpu()`.  Passing an output buffer to `CIFSSMBQAllEAs()` was
      therefore credited with `list_len = le32_to_cpu(ea_response_data->
      list_len)`, read from the response and not reachable from the argument at
      all.  Phase 1 now keeps only findings whose `taint_source_fn` is the
      `<param:N>` tag it seeded.  A finding where the parameter is the
      destination and an unrelated callee value is the tainted size is
      correctly dropped too — it is a fact about the callee, not about the call
      site.

      fs/smb/client 300 → 277 findings with both fixes, cross-function 118 →
      94.  `cifs_query_path_info` alone goes 27 → 14, which is what prompted
      this: an adjudication returned all 27 as false positives.  Its own
      headline claim — that `data->wsl.eas` is a zero-length flexible array and
      any write into it overflows the stack — was wrong; the member is
      `__u8 eas[SMB2_WSL_MAX_QUERY_EA_RESP_SIZE]`, sized for all four WSL EAs.
      The 14 that remain are correctly anchored, and whether they are live
      depends on whether `data->wsl.eas` holds server bytes on entry, which is
      a caller fact Stage 1 does not have.

- [x] An allocator's return value inherited the taint of its size argument —
      so every store into a freshly allocated buffer read as a
      server-controlled dereference.  `id_mode_to_cifs_acl()` produced 15
      findings, nearly all of them writes into the `kzalloc(nsize, GFP_KERNEL)`
      result.  The size being server-chosen is already reported as Cat B at the
      allocation itself; propagating it past the call adds nothing and buries
      that one finding under the rest.  `_rhs_is_alloc()` now kills the taint on
      a plain assignment whose entire rhs, casts and parens aside, is a call to
      a `DANGEROUS_SINKS` entry marked `alloc`.  Requiring the whole expression
      matters — `kmalloc(n, GFP) + off` is an offset into an allocation, not
      one.  The kill uses the same `_kill_extent()` scoping, so an allocation in
      one arm of an `if` does not clear the taint below it.

      `id_mode_to_cifs_acl` 15 → 6.

- [x] Cat E emitted one finding per dereference rather than per statement.  A
      bounds check goes in front of a statement and covers every dereference
      in it, so the five `compare_sids()` calls in one `if` in
      `set_chmod_dacl()` are one check site, not five; `build_sec_desc()` was
      reporting 18 findings for roughly half that many places to look.
      `_enclosing_stmt()` walks to the nearest ancestor whose parent is a
      `compound_statement` and uses its node id, keyed with the tainted
      variable, as a dedup key; the surviving finding carries `deref_sites` so
      the count is not lost.  A controlling statement's own body stays separate,
      since the walk stops at the inner `compound_statement`.

      `build_sec_desc` 18 → 12.

      Both fixes together: fs/smb/client 277 → 241, and 306 → 241 against the
      run that prompted the review.  Tree-wide 10,864 → 10,129 findings, guarded
      1,080 → 1,038; no guard kind moves except in proportion
      (`does-not-dominate` 92 → 91, `covers-base-not-offset` 77 → 76).

- [x] One value reaching many sinks that ask the same question of it was
      reported once per sink.  `smb_cmd` in `__release_mid()` indexes twelve
      per-command stats arrays and produced twelve findings; `nlen` in
      `check_wsl_eas()` is the length argument to eight `strncmp()`s and
      produced eight.  Whoever answers "is it bounded here?" answers it for all
      of them at once, so Stage 2 was adjudicating the same question repeatedly
      and paying for the function's full source each time.  `_scan_body()` now
      ends with a collapse on `(tainted_var, taint_line, category, sink_fn,
      sink_arg_role, possibly_guarded, guard_kind)`, keeping the first and
      recording the rest in `sink_lines`.

      The key is what makes this safe.  The guard verdict is in it, so a use
      the guard reaches and a use it does not stay separate — `gap3_bare_too`
      in the probe corpus still reports both its unguarded 100 and its guarded
      102.  The role is in it, so a size argument never merges with a
      subscript.  Verified lossless on fs/smb/client: 94 distinct
      `(function, category, var, taint_line, sink_fn, role, guarded, kind)`
      tuples before and after, none lost, none gained.

      Phase 2 has the same shape one level up: the finding is anchored in the
      caller, and the caller has one place to put a check no matter how many
      sinks the argument reaches inside the callee.  Passing `offs` to
      `smb2_parse_native_symlink()` reached four and became four adjudications
      of one question.  Phase 2 now emits one finding per
      `(caller, var, callee, arg)` carrying a `callee_sinks` list, with the
      most severe sink as the headline and `possibly_guarded` requiring *all*
      callee sinks to be guarded — one unguarded use downstream still obliges
      the caller.  Phase 1's own collapse feeds this, so a callee sink list
      carries `sink_lines` too; verified that no callee sink disappears.

      Both lists are rendered into the Stage 2 prompt, so the adjudicator sees
      every site it would have seen before, in one place instead of scattered
      across a dozen findings.

      fs/smb/client 241 → 123 (306 → 123 against the run that prompted the
      review, 60 %); `check_wsl_eas` 16 → 3, `__release_mid` 12 → 3,
      `cifs_query_path_info` 14 → 4, cross-function 74 → 29.  Tree-wide
      10,129 → 5,518, guarded 1,038 → 751 — nearly half of every finding the
      tool has ever produced was a restatement.

- [x] A truncated Stage 2 response became a permanent `error` verdict for the
      function.  `CIFSFindFirst` failed this way with a reported 656 output
      tokens against a 16,384 cap, which looks impossible until you account for
      Gemini's dynamic thinking: `candidates_token_count` excludes
      `thoughts_token_count`, and the ~15,700 reasoning tokens are charged
      against `max_output_tokens` just the same.  Three parts, all needed to
      make the failure legible and survivable:

      `LLMResponse.output_tokens` now includes reasoning, with
      `thinking_tokens` broken out; `output_limit` reports the cap the backend
      actually applied, since `_gemini_generate()` scales our request by
      `max(n*3, 16384)` and the old message quoted our number rather than the
      real one.  And `_call_llm()` treats `stop_reason == 'max_tokens'` as a
      retry with a doubled budget instead of a hard raise — the loop already
      retried invalid JSON, and a truncation says even less about the code than
      malformed JSON does.  Three attempts, so an 8-finding function goes
      5,120 → 10,240 → 20,480 (Gemini sees 16,384 → 30,720 → 61,440); the retry
      note is only prepended for a JSON failure, not a truncation, since the
      model did nothing wrong in that case.

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

Both remaining shapes in that table have since been implemented, and the
detector undercounted both.  Dropping the requirement that the sink node be
re-locatable put reaching definitions at 170, not 104 — the earlier reading
that gap2 was mostly symptomatic was wrong.  Dominance came in at 119, not 21,
for the same reason plus two more: ancestor sets were compared by identity
rather than line span, and loops were not counted at all.  "Dominance does not
justify the machinery" was wrong on the number, though right that no CFG is
needed — AST ancestry suffices.  Treat these detector counts as lower bounds of
between a half and a seventh.

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
