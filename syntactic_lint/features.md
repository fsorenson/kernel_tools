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

- [x] Constant lower bound — against a literal subtrahend an earlier
      `if (len > 2)` or `if (!len) return` settles the question outright, so it
      suppresses rather than demotes. `_relational_guard` cannot: it wants an
      identifier on both sides, and `len -= 2` has none.

- [x] Overflow rollback — `if (check_add_overflow(size, n, &size)) size -= n;`.
      The helper already stored the wrapped sum, so the `-=` is an undo. The
      call is in the condition and the subtraction in the body, which is why
      looking for a `_SAFE_ARITH` call *around* the arithmetic misses it.

- [x] Single-expression sums — `x = a + b` truncates, it does not accumulate,
      and saying otherwise was simply false. `narrow-add` now demands that the
      variable appear on both sides (`x += n`, or `x = x + n`) before it will
      call anything an accumulation; a one-shot narrowing sum is reported at
      low with a message that says which question it actually raises. Seven of
      the nine `narrow-add` hits in a whole-`fs/` run were this
      (`log2_bits = sb->s_blocksize_bits + 3`).

- [x] Pointer differences — `max_non_overlap = dp_addr - dp_back_addr` is a
      distance between two pointers into one object, not a narrow quantity
      being spent down. Whoever ordered the two pointers ordered them; there is
      nothing here for a lower-bound test to say.

- [x] Post-hoc bounds — a comparison on the variable sitting *between* the
      arithmetic and the sink demotes to medium. `ulen = le16_to_cpu(
      rp->ReparseDataLength) - sizeof(struct REPARSE_POINT)` in
      `ntfs_readlink_hlp()` really does underflow, and
      `if (!ulen || uname + ulen > Add2Ptr(rp, size)) goto out` really does
      catch it. Demotion, not suppression: the check can still be the wrong
      one. Verified against the known-real `plen -= 2 * poff`, which has no
      comparison on `plen` anywhere between line 234 and the `memcpy` at 252.

- [x] Record-chain walks — `size += le16_to_cpu(pntace->size)` where
      `pntace = acl_base + size` is not a size accumulation, it is a cursor
      stepping through length-prefixed records, and the sum is bounded by the
      container's own size field. Whether it can run long is a question about
      whoever validated the chain, not about this loop, so it is reported at
      `low` with a message that says what it actually is. The test is narrow
      on purpose: the addend must be a *field read through* a pointer the
      accumulator positioned. Merely passing that pointer to a call —
      `nsize += cifs_copy_ace(pnntace, ...)`, which accumulates bytes written
      — is exactly the shape this check exists for, and stays at `high`.

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

### Regression suite

    python3 -m syntactic_lint.tests.test_checks     # or: pytest syntactic_lint/tests/

Twelve cases in `tests/`, running in about a fifth of a second. Three are the
pre-fix bugs above; the rest are functions that the whole-`fs/` run reported
and a hand triage cleared, so each suppression is pinned against the exact
code that motivated it rather than against an invented reproduction. Every
fixture is verbatim kernel source, extracted from a named revision by

    python3 -m syntactic_lint.tests.extract --kernel-source /home/src/linux

Whole functions rather than whole files, which is safe because every check is
an invariant over one function body, and which keeps the corpus at ~2 kLOC
instead of 130 KB of GPL source in a repository that is not the kernel.
`cases.py` carries the provenance and the hand-written verdict for each case;
`expected.json` carries the finding set and is machine-written by `--update`,
so an update diff can never quietly rewrite an argument a human made.

Two properties are worth stating because they are what make the suite useful
rather than decorative. It compares the **whole** finding set per fixture, so a
new finding fails as loudly as a lost one — the tool's value is its silence,
and a change that makes it noisier somewhere unrelated is exactly what would
otherwise go unnoticed. And expectations are recorded at `--min-severity low`,
so demotions are pinned: `narrow_add_dacl_accumulators` fails if the two `size`
cursors are ever promoted out of `low`, not only if they vanish.

Three cases have verdict `fp` — findings a human still has to clear
(`CIFSSMBNegotiate`, `set_mode_dacl`, `ocfs2_cp_xattr_block_to_bucket`). They
are pinned as-is so that a future precision lever shows up here as a diff.

Whole-subsystem run over `fs/smb/client` (~80 kLOC, 5 s) at `b4ea2789e060`:
**2 findings**, of which 1 is real —

- `reparse.c` `create_native_symlink()` — `plen -= 2 * poff`, still unfixed
- `cifssmb.c` `CIFSSMBNegotiate()` — false positive; `count` accumulates
  `strlen()` over `CIFS_NUM_PROT` (2) short literal protocol names, and the
  comment immediately above the loop says so

`ptr-advance` and `scan-loop` report nothing here, which is correct: both bugs
are fixed in this checkout (`cb26524ef4ac`, `46a3190c9264`), and the fixtures
show the checks catch them.

Second tree, as a noise control: `fs/nfs` (~60 kLOC) reports **nothing**.

**Read the 1-of-2 honestly.** It is not a 50% false-positive rate in any
useful sense — the sample is two, on a tree where every bug the tool was built
against has already been fixed. What it does say is that the floor is low
enough that each finding can be read by hand.

**Correction, 2026-09-15.** This section previously claimed 5 findings of
which 4 were real, counting the two `cifsacl.c` `size += le16_to_cpu(pntace->size)`
DACL walks as true positives. They are false positives, and the reasoning is
worth recording because it is the exact failure mode this tool is exposed to:
`validate_dacl()` (`cifsacl.c:852`) walks the identical chain and checks
`end_of_dacl - acl_base >= ace_size` before every advance, establishing
`sizeof(smb_acl) + Σ le16_to_cpu(pace->size) <= dacl_size <= U16_MAX`.
`build_sec_desc()` is the only caller of either function and calls it at
`:1456`, bailing before both call sites. So `size` cannot wrap. Worse, the
linter was pointing at the wrong accumulator in those loops: `nsize`, the one
that genuinely was dangerous, is already `u32` with `> U16_MAX` checks
(`0ee150794c75`, `d05045177a85`) — and locally it looks *more* suspicious than
`size`, not less.

The safety here is a non-local invariant, two frames up, which a per-function
syntactic check cannot see. The record-chain rule above recovers most of this
case without leaving the function, but the general problem does not have a
local answer, and any finding of this shape needs the caller checked by hand.

## Whole-`fs/` run

The real coverage test, run at `b4ea2789e060`: all of `fs/` (~1.5 MLOC) in 32 s.
The first pass gave **17 findings**, and three of them were checker defects
rather than kernel bugs — the constant lower bound, the overflow rollback and
the single-expression sum above. Fixing those and adding the two later
suppressions gives **7**, of which 3 are `high`:

| Finding | Verdict |
|---|---|
| `smb/client/reparse.c:234` `plen -= 2 * poff` | **real**, still unfixed |
| `ocfs2/xattr.c:4457` `size = blocksize - offset` | FP — `ocfs2_validate_xattr_entries_flat()` rejects `xe_name_offset > region_size` when the block is read, and `region_size` is `blocksize - off_change` |
| `smb/server/smbacl.c:839` `size += le16_to_cpu(pace->size)` | FP — five ACEs over fixed SIDs; the POSIX-ACL path `goto out`s before these and uses `check_add_overflow()` throughout |
| `ntfs/compress.c:426` `length -= max_non_overlap` | FP — the `else` arm of `if (length <= max_non_overlap)` |
| `ntfs3/inode.c:1742` `t16 = sbi->record_size - t16 - SIZEOF_NONRESIDENT` | FP — `t16` is `PtrOffset(rec, attr)`, an offset into the record it is subtracted from |
| `ntfs3/inode.c:2230` `ulen = ...ReparseDataLength - sizeof(...)` | FP — underflows for real, caught at the next line |
| `smb/client/cifssmb.c:466` `count += len` | FP — known; two short literal protocol names |

One real bug in 1.5 MLOC is not a yield to boast about, but the tree is one
where every bug the tool was built against is already fixed, and 7 findings is
an afternoon's reading. The three that remain `high` are the two whose safety
argument lives outside the function (`ocfs2`, `ksmbd`) plus the real one, which
is the shape the tool is for.

The one finding worth a second look regardless of verdict is
`ntfs3/inode.c:1742`: `t16`'s dangerous use is as the output-buffer size
argument to `run_pack()`, which the sink table has no name for, so the finding
cites a nonsense `pointer offset (via 'err')` instead. Callee-parameter roles
are the obvious next lever and are not implemented.

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
- [ ] Callee parameter roles — `run_pack(..., buf, t16, ...)` passes a
      wrapped value as an output-buffer size and the sink table cannot see it;
      a table of known length parameters, or a one-pass scan of callee
      signatures in the same file, would
- [ ] The suite pins per-function behaviour but nothing tree-wide; a change
      that leaves all twelve cases green and adds forty findings to `fs/` would
      pass. A recorded whole-`fs/` count, checked against a kernel tree when
      one is available, would close that
