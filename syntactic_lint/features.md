# Standalone Syntactic Linter — Feature List

Third tool alongside the bounds checker and the race finder, and deliberately
the least clever of the three: no taint engine, no LLM stage, no config file,
no run directory.  Every check is a local pattern over one function body, so
the tool runs over a whole subsystem in a couple of seconds and its output is
meant to be read straight out of the terminal.

The reason it exists separately: the bounds checker's taint categories all
start from a *server-supplied value*.  The bugs below are bounds bugs whose
inputs are entirely local — a `strlen()` of a buffer the kernel itself built, a
`u16` that overflows on the third addition — so no taint category will ever
reach them, however good the LLM stage gets.  They are also mechanical enough
that an LLM is the wrong instrument.

Shares parsing infrastructure with the other two tools
(`kernel_analysis/parsers/c_parser.py`).

    python3 -m syntactic_lint.cli fs/smb/client --kernel-source /home/src/linux

---

## P0 — Checks

- [x] **`ptr-advance`** — a length measured at a buffer's base, then used to copy
      from an advanced position inside it.  The buffer behind `strlen(P)` is
      valid over `[0, strlen(P)]`, so a copy of LEN bytes starting at `P + K`
      is in bounds exactly when `K + LEN <= strlen(P) + 1`.  With
      `LEN = strlen(P) + adj` that reduces to **`K + adj <= 1`**, which is the
      whole check — no heuristics and no tuning knob.  It separates
      `memcpy(d, p + 1, strlen(p) + 1)` (one byte past the terminator) from
      `memcpy(d, p + 1, strlen(p))` (exactly right) without guessing.

      Recognises the advance as an argument (`P + K`, `&P[K]`) or as an earlier
      `p++` / `p += K` interposed between the `strlen()` and the copy.  Offsets
      and adjustments must be integer literals: a symbolic advance such as
      `abs_path += sizeof("Global\\") - 1` is left alone rather than guessed
      at, which is what keeps this check quiet.  `strnlen()` is deliberately
      not accepted as a length source — its result is not pinned to the
      terminator, so the identity above does not hold.

- [x] **`scan-loop`** — a terminator scan entered at a nonzero index.
      `for (i = 1; s[i]; i++)` never tests `s[0]`, so on a string shorter than
      the start index the loop walks off the end unbounded.  Fires only when
      no prior `strlen`/`strnlen`/length comparison on the same buffer is
      visible in the function.

- [x] **`narrow-sub`** — a narrow unsigned local decremented with no
      lower-bound test, where the result then reaches memory.  One underflowing
      `-=` is enough to produce a near-`2^bits` length whatever fed it, so
      unlike `narrow-add` this check makes no demand on the operands.

- [x] **`narrow-add`** — a narrow unsigned local accumulated past its width,
      where the result then reaches memory.  Both `acc += n` and
      `acc = a + b` forms.

`--max-bits` (default 16) sets the widest type the two wrap checks consider.
32 is a real width for these bugs but much noisier, so it is opt-in.

## P0 — Precision machinery

The wrap checks are the ones that want restraint; these are what make them
usable rather than a 72-line wall.

- [x] Sink roles, ranked — a wrapped value is only interesting if it lands
      somewhere.  Roles are ranked by consequence (memory-op length,
      allocation size, array subscript, pointer offset, then wire field and
      return value) and the finding names the worst one the variable reaches,
      not the first.  A variable's own use outranks one a hop downstream: same
      wrap, more concrete story.

- [x] Memory-reaching requirement — only the first four roles are reported by
      default.  A wrap that reaches nothing but a request header corrupts the
      request, not the heap.  `--min-severity low` shows the rest.

- [x] Unbounded-input requirement for `narrow-add` — a sum can only wrap if
      something unbounded feeds it, so addition over locals the function
      computed itself, outside any loop, is demoted.  This is the SMB1
      request-header idiom (`offset = param_offset + params`), which appears
      fourteen times in `cifssmb.c` and is unreachable in every one.

- [x] One finding per accumulator — `populate_new_aces()` feeds `nsize` from
      seven statements; that is one bug, and reporting it seven times buried
      the two real DACL cases.  The finding cites the first statement and
      lists the rest.

- [x] Loop-carried sinks — a sink *above* the arithmetic still consumes it on
      the next trip.  `pnntace = (struct smb_ace *)(nacl_base + nsize)` sits
      one line above the `nsize +=` that feeds it, so requiring the sink to
      follow the arithmetic in source order lost the real story on both DACL
      walks.  Sinks anywhere in the enclosing loop count.

- [x] One-hop value flow — `plen` reaching `kzalloc()` via
      `len = sizeof(*buf) + plen + slen` is one assignment.  Deliberately not
      closed transitively: with no control flow or SSA to constrain it, the
      closure over a function body collapses into a single clique and every
      finding ends up citing an unrelated variable's sink.

- [x] Suppressions — `check_add_overflow()` / `size_add()` / `size_sub()` and
      friends around the arithmetic; a for-loop's own update expression, which
      its condition bounds (`for (i = 0; i < fh->size; i += 16)` was the only
      finding in all of `fs/nfs`); a relational guard on the variable against
      its own operands demotes to medium rather than dropping.

## Validation

Each check was developed against a known upstream bug, using the parent commit
as the fixture, and then measured over the whole subsystem.

| Check | Fixture | Line |
|---|---|---|
| `ptr-advance` | `cb26524ef4ac^` `smb2_parse_native_symlink()` | `memcpy(linux_target + levels*3, smb_target+1, smb_target_len)` |
| `scan-loop` | same function | `for (i = 1; full_path[i]; i++)` |
| `narrow-sub` | `23c240d9509e^` `create_native_symlink()` | `plen -= 2 * poff` |
| `narrow-add` | `d05045177a85^` `replace_sids_and_copy_aces()`, `set_chmod_dacl()` | `nsize += ace_size`, `nsize += cifs_copy_ace(...)` |

Each fires on exactly the intended line in its fixture, and the correct
sibling branch stays silent — in `smb2_parse_native_symlink()` the
`abs_path` copy, whose length *was* measured after the advance, is not
flagged alongside the `smb_target` one.

Whole-subsystem run over `fs/smb/client` (~80 kLOC, 5 s): **5 findings**, of
which 4 are real —

- `reparse.c` `smb2_parse_native_symlink()` — the scan loop, still unfixed in
  this checkout
- `reparse.c` `create_native_symlink()` — `plen -= 2 * poff`, still unfixed
- `cifsacl.c` ×2 — `size += le16_to_cpu(pntace->size)` in both DACL walks, the
  long-standing integer-wrap case
- `cifssmb.c` `CIFSSMBNegotiate()` — false positive; `count` accumulates
  `strlen()` over `CIFS_NUM_PROT` (2) short literal protocol names, and the
  comment immediately above the loop says so

`ptr-advance` reports nothing on the current tree, which is correct: that bug
is fixed in this checkout, and the fixture shows the check catches it.

Second tree, as a noise control: `fs/nfs` (~60 kLOC) reports **nothing**.

## P1 — Not yet

- [ ] `--min-severity` on the JSON path — the filter is applied in the CLI, so
      `--json` emits the filtered set; a `severity` field is present either
      way, but there is no way to get the full set as JSON without
      `--min-severity low`
- [ ] `sizeof()`-aware literal advances — `p += sizeof("prefix") - 1` is a
      constant the parser could fold, which would extend `ptr-advance` to the
      `abs_path` family without loosening the literal-only rule
- [ ] 32-bit wrap tuning — `--max-bits 32` is wired up but unmeasured; the
      unbounded-input rule probably needs to be stricter before it is usable
- [ ] Coverage beyond `fs/smb/client` and `fs/nfs` — the checks are
      subsystem-agnostic, but a tree with no findings at all only proves the
      floor is low, not that the checks generalise
- [ ] No test suite — the fixtures live in `/tmp` and the expected lines are
      recorded in the table above rather than in code
