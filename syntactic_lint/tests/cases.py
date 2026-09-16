"""
The fixture corpus: what each fixture is, where it came from, and what the
linter is expected to say about it.

Every fixture is verbatim kernel source, extracted from a named revision by
`extract.py`.  Nothing here is hand-written C, and that is deliberate — a
hand-written reproduction of a bug shape drifts away from the thing it was
meant to stand for, and these checks are entirely about the shapes real code
takes.  The positives are pre-fix revisions of known upstream bugs; the
negatives are functions that a whole-`fs/` run reported and a hand triage
cleared, so each one pins a suppression against the exact code that motivated
it.

The expected findings live in `expected.json`, not here, because that file is
machine-written by `test_checks.py --update` and this one is not: an `--update`
diff can then never quietly rewrite an argument a human made.  Expectations are
recorded at `--min-severity low`, so demotions are pinned too — a case that
expects `low` fails if it is ever promoted, not only if it disappears.

`verdict` records what the code actually does, which is a different question
from what the linter says about it.  `fp` cases are ones the tool still
reports and a human still has to clear; they are here so that a future
precision lever shows up as a test diff rather than going unnoticed.
"""

from collections import namedtuple

Case = namedtuple('Case', 'name rev path functions verdict note')

CASES = (

    # -- Positives: the bugs each check was built against ------------------

    Case(
        name='ptr_advance_smb2_parse_native_symlink',
        rev='cb26524ef4ac^',
        path='fs/smb/client/reparse.c',
        functions=('smb2_parse_native_symlink',),
        verdict='real',
        note="Fixed by cb26524ef4ac.  Two bugs in one function: `levels` is "
             "counted by a scan that starts at index 1, and the `smb_target` "
             "copy takes its length before the advance.  The `abs_path` copy "
             "just below measures after the advance and must stay silent — "
             "that sibling is the whole reason the check is an inequality and "
             "not a pattern match.",
    ),

    Case(
        name='narrow_sub_create_native_symlink',
        rev='23c240d9509e^',
        path='fs/smb/client/reparse.c',
        functions=('create_native_symlink',),
        verdict='real',
        note="`plen -= 2 * poff` with no lower bound on `plen`, reaching the "
             "`memcpy` into `buf->PathBuffer`.  23c240d9509e fixed one half of "
             "this; the decrement is still there in mainline at b4ea2789e060, "
             "which is the single real finding a whole-`fs/` run produces.",
    ),

    Case(
        name='narrow_add_dacl_accumulators',
        rev='d05045177a85^',
        path='fs/smb/client/cifsacl.c',
        functions=('populate_new_aces', 'replace_sids_and_copy_aces',
                   'set_chmod_dacl'),
        verdict='real',
        note="Fixed by 0ee150794c75 and d05045177a85, which widened `nsize` to "
             "u32 and added `> U16_MAX` checks.  The two `low` entries are the "
             "`size` cursors walking the source DACL: same loops, different "
             "variable, and bounded by `validate_dacl()` two frames up.  They "
             "are demoted by the record-chain rule, and getting that "
             "distinction right — `nsize` high, `size` low, in the same two "
             "loop bodies — is what this case exists to pin.",
    ),

    # -- Suppressions, each against the code that motivated it -------------

    Case(
        name='suppress_constant_floor',
        rev='b4ea2789e060',
        path='fs/isofs/joliet.c',
        functions=('get_joliet_filename',),
        verdict='clean',
        note="`if ((len > 2) && ...) len -= 2;`.  A literal subtrahend against "
             "an earlier literal floor is decidable, so it suppresses rather "
             "than demotes.  `_relational_guard` cannot see this one: it wants "
             "an identifier on both sides of the comparison.",
    ),

    Case(
        name='suppress_overflow_rollback',
        rev='b4ea2789e060',
        path='fs/smb/server/smbacl.c',
        functions=('set_ntacl_dacl',),
        verdict='clean',
        note="`if (check_add_overflow(size, nt_ace_size, &size)) size -= "
             "nt_ace_size;`.  The helper already stored the wrapped sum, so "
             "the subtraction is an undo.  The call is in the condition and "
             "the subtraction in the body, which is why looking for a safe "
             "arithmetic call *around* the statement misses it.",
    ),

    Case(
        name='suppress_pointer_difference',
        rev='b4ea2789e060',
        path='fs/ntfs/compress.c',
        functions=('ntfs_decompress',),
        verdict='clean',
        note="`max_non_overlap = dp_addr - dp_back_addr` is a distance between "
             "two pointers into one object, and `if (dp_back_addr < "
             "dp_sb_start) goto return_overflow` already ordered them.  The "
             "surviving `length -= max_non_overlap` is correctly demoted — it "
             "sits in the `else` arm of `if (length <= max_non_overlap)` — and "
             "the `length = (pt & (0xfff >> lg)) + 3` above it is a "
             "one-expression sum, not an accumulation.",
    ),

    Case(
        name='suppress_single_expression_sum',
        rev='b4ea2789e060',
        path='fs/ntfs3/bitmap.c',
        functions=('wnd_find',),
        verdict='clean',
        note="`log2_bits = sb->s_blocksize_bits + 3` truncates, it does not "
             "accumulate, and calling it an accumulation was simply false.  "
             "Seven of the nine `narrow-add` hits in the first whole-`fs/` run "
             "were this shape.",
    ),

    Case(
        name='suppress_for_loop_update',
        rev='b4ea2789e060',
        path='fs/nfs/inode.c',
        functions=('_nfs_display_fhandle',),
        verdict='clean',
        note="`for (i = 0; i < fh->size; i += 16)` — the update is bounded by "
             "the loop's own condition or the loop never ends.  This was the "
             "only finding in all of `fs/nfs`.",
    ),

    Case(
        name='suppress_macro_base_offset',
        rev='b4ea2789e060',
        path='fs/ntfs3/inode.c',
        functions=('ntfs_create_inode',),
        verdict='clean',
        note="`t16 = sbi->record_size - t16 - SIZEOF_NONRESIDENT` was reported "
             "as reaching a `pointer offset (via 'err')`, which is nonsense: "
             "the cited line is `asize = SIZEOF_NONRESIDENT + ALIGN(err, 8)`, "
             "and the sink test had only asked that the left operand of a `+` "
             "not be a known integer local.  A macro constant passes that.  It "
             "now has to be a declared pointer, so the finding loses its only "
             "memory-reaching sink and drops.  `t16`'s genuinely dangerous use "
             "is as the output-buffer size argument to `run_pack()`, which the "
             "sink table still has no name for.",
    ),

    Case(
        name='suppress_one_shot_difference',
        rev='b4ea2789e060',
        path='arch/powerpc/sysdev/xive/common.c',
        functions=('xive_scan_interrupts',),
        verdict='clean',
        note="`prio = ffs(xc->pending_prio) - 1` indexing `xc->queue[prio]`, "
             "inside `while (xc->pending_prio != 0)` — so `ffs()` is at least "
             "1.  The guard is on neither operand of the subtraction and no "
             "local rule will ever connect the two, which is the argument for "
             "demoting the whole `x = a - b` form: it asks whether one value "
             "can exceed another, and that is not a question about this "
             "statement.  185 of the 224 `narrow-sub` findings in a "
             "whole-kernel run were this shape.  The only non-`fs/` fixture, "
             "and deliberately so.",
    ),

    Case(
        name='suppress_reflected_subtrahend',
        rev='b4ea2789e060',
        path='arch/powerpc/kvm/book3s_32_mmu_host.c',
        functions=('create_sid_map',),
        verdict='clean',
        note="`sid_map_mask = SID_MAP_MASK - sid_map_mask` indexing "
             "`sid_map[sid_map_mask]`.  `kvmppc_sid_hash()` already returns a "
             "value masked to `SID_MAP_MASK`, so this reflects within a fixed "
             "range.  Subtraction is the one place where \"appears on both "
             "sides\" does not mean \"decrement\": the variable has to be the "
             "minuend.  This case pins that, and it is the reason "
             "`idx = idx + 1 - delta_ind` in `phy_n.c` is *not* demoted "
             "alongside it.",
    ),

    Case(
        name='demote_post_hoc_bound',
        rev='b4ea2789e060',
        path='fs/ntfs3/inode.c',
        functions=('ntfs_readlink_hlp',),
        verdict='fp',
        note="`ulen = le16_to_cpu(rp->ReparseDataLength) - sizeof(struct "
             "REPARSE_POINT)` really does underflow — the only preceding guard "
             "is on `size`, the attribute data size, which is independent.  "
             "`if (!ulen || uname + ulen > Add2Ptr(rp, size)) goto out` catches "
             "it two lines later.  It sat at `medium` on the post-hoc-bound "
             "rule until the one-shot-difference rule took it to `low` for a "
             "different reason; the post-hoc rule now has no fixture of its "
             "own, and this case pins the composite, not that rule.",
    ),

    # -- False positives the tool cannot yet clear -------------------------

    Case(
        name='fp_negotiate_protocol_names',
        rev='b4ea2789e060',
        path='fs/smb/client/cifssmb.c',
        functions=('CIFSSMBNegotiate',),
        verdict='fp',
        note="`count += len` over `CIFS_NUM_PROT` (2) short literal protocol "
             "names.  The bound is the length of a file-scope const array, "
             "which is outside the function body.  Pinned as-is so that a "
             "future const-array lever shows up here as a diff.",
    ),

    Case(
        name='fp_ksmbd_set_mode_dacl',
        rev='b4ea2789e060',
        path='fs/smb/server/smbacl.c',
        functions=('set_posix_acl_entries_dacl', 'set_mode_dacl'),
        verdict='fp',
        note="Five ACEs over fixed SIDs, so `size` tops out around 200 bytes.  "
             "The `fattr->cf_acls` path delegates to "
             "`set_posix_acl_entries_dacl()`, which uses `check_add_overflow()` "
             "on every add, and then `goto out`s past these lines — an "
             "argument that needs the callee, so the check cannot make it.",
    ),

    Case(
        name='fp_ocfs2_xattr_block_to_bucket',
        rev='b4ea2789e060',
        path='fs/ocfs2/xattr.c',
        functions=('ocfs2_cp_xattr_block_to_bucket',),
        verdict='fp',
        note="`offset = le16_to_cpu(xe->xe_name_offset) + off_change; size = "
             "blocksize - offset;` then `memcpy(target + offset, src + offset, "
             "size)`.  Cleared by `ocfs2_validate_xattr_entries_flat()`, which "
             "rejects `xe_name_offset > region_size` when the block is read, "
             "and `region_size` is exactly `blocksize - off_change`.  That "
             "validator is new (2cf82b46d5e4, 2026-07-05): on any older kernel "
             "this finding is live.",
    ),
)


def by_name(name):
    for c in CASES:
        if c.name == name:
            return c
    raise KeyError(name)
