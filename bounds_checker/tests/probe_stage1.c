/*
 * Stage 1 scanner probe: one positive and one or more negative/control cases
 * per category.  Run with run_stage1.py; see EXPECTED there for what each
 * function must produce.
 *
 * Naming convention:
 *   bug_X_*      — must produce a Cat X finding (possibly_guarded=False)
 *   guarded_X_*  — must produce a Cat X finding (possibly_guarded=True)
 *   fp_X_*       — Stage 1 fires (possibly_guarded=True); only Stage 1.7
 *                  retires it.  Labeled fp_ because the finding is not a real
 *                  bug — the scanner conservatively flags it and leaves the
 *                  decision to the solver or the LLM.
 *
 * No kernel headers needed.
 */

/* ── Type stubs ─────────────────────────────────────────────────────────── */

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef short              s16;
typedef int                s32;
typedef unsigned long      size_t;
typedef u16 __le16;
typedef u32 __le32;

#define GFP_KERNEL 0
#define NULL       ((void *)0)

struct pkt {
	__le16  count;
	__le16  offset;
	__le16  len;
	__le32  size32;
	__le16  shift_amt;
};

struct entry { u32 a; u32 b; };
struct inner { u16 val; u8 tag; };

extern u8   pkt_buf[4096];
extern u8   dst_buf[256];
extern void *dst;
extern int   cond;

/* endian helpers — treated as taint sources */
extern u16 le16_to_cpu(u16);
extern u32 le32_to_cpu(u32);

/* allocation sinks */
extern void *kmalloc(size_t size, int flags);
extern void *kzalloc(size_t size, int flags);
extern void *kmalloc_array(size_t n, size_t size, int flags);
extern void  kfree(void *);

/* memory operation sinks */
extern void *memcpy(void *dst, const void *src, size_t n);
extern void *memset(void *dst, int c, size_t n);

/* string sinks and guards */
extern size_t strlen(const char *);
extern void  *memchr(const void *, int, size_t);
extern size_t strnlen(const char *, size_t);

/* user-copy sinks */
extern long copy_to_user(void *dst, const void *src, size_t n);
extern long copy_from_user(void *dst, const void *src, size_t n);

/* ceiling-capping macros — kernel macros stubbed here for the probe file */
#define min(a, b)            ((a) < (b) ? (a) : (b))
#define min_t(t, a, b)       ((__typeof__(a))(a) < (__typeof__(a))(b) ? (a) : (b))
#define clamp(val, lo, hi)   ((val) < (lo) ? (lo) : (val) > (hi) ? (hi) : (val))
#define clamp_t(t, val, lo, hi) clamp(val, lo, hi)
#define clamp_val(val, lo, hi)  clamp(val, lo, hi)

/*
 * Server-response struct stubs for provenance and Cat I tests.
 * smb2_read_rsp and smb2_err_rsp are in _SERVER_RESPONSE_STRUCTS.
 * local_state is not.
 *
 * The real kernel structs are larger (both embed smb2_hdr at 64 bytes).
 * Scanner uses _SMB2_STRUCT_MIN_BYTES for size comparison, not C sizeof.
 * Per the size table: smb2_read_rsp(80) > smb2_err_rsp(72) > smb2_hdr(64).
 */
struct smb2_read_rsp { u8 DataOffset; u32 DataLength; };
struct smb2_err_rsp  { u16 StructureSize; u8 ErrorContextCount; u8 Reserved; u32 ByteCount; };
struct local_state   { u8 offset;    u32 length; };

/* ── Category A: tainted value → pointer arg of memory op ── */

/* tainted SOURCE pointer reaching memcpy */
void bug_A_memcpy_src_ptr(struct pkt *p, u8 *end)
{
	u16 off = le16_to_cpu(p->offset);
	u8 *src = pkt_buf + off;         /* pointer-kind taint */
	memcpy(dst_buf, src, 16);         /* tainted ptr as source */
}

/* tainted DESTINATION pointer reaching memcpy */
void bug_A_memcpy_dst_ptr(struct pkt *p, u8 *src_data)
{
	u16 off = le16_to_cpu(p->offset);
	u8 *d = dst_buf + off;           /* pointer-kind taint */
	memcpy(d, src_data, 16);          /* tainted ptr as destination */
}

/* guarded: pointer offset bounded before use */
void guarded_A_bounded_ptr(struct pkt *p, u8 *src_data, u8 *end)
{
	u16 off = le16_to_cpu(p->offset);
	u8 *src = pkt_buf + off;
	if (src + 16 > end)
		return;
	memcpy(dst_buf, src, 16);
}

/* ── Category B: tainted value → allocation size ── */

/* unbounded server size passed to kmalloc */
void *bug_B_kmalloc(struct pkt *p)
{
	u32 size = le32_to_cpu(p->size32);
	return kmalloc(size, GFP_KERNEL);
}

/* overflow: count * sizeof — can wrap before kmalloc sees it */
void *bug_B_overflow(struct pkt *p)
{
	u16 count = le16_to_cpu(p->count);
	return kmalloc(count * sizeof(struct entry), GFP_KERNEL);
}

/* guarded: size checked before allocation */
void *guarded_B_bounded(struct pkt *p)
{
	u16 count = le16_to_cpu(p->count);
	if (count > 64)
		return NULL;
	return kmalloc(count * sizeof(struct entry), GFP_KERNEL);
}

/*
 * Stage 1 fires on kmalloc_array(count, ...) even though kmalloc_array
 * handles the multiplication overflow internally.  The scanner correctly
 * flags an unvalidated server-supplied count; Stage 1.7 cannot retire it
 * (no buffer-size property), so Stage 2 evaluates whether the count is
 * bounded by protocol semantics.  Labeled fp_ because it's a false positive
 * only if the count is independently bounded by the received data length.
 */
void *fp_B_kmalloc_array(struct pkt *p)
{
	u16 count = le16_to_cpu(p->count);
	return kmalloc_array(count, sizeof(struct entry), GFP_KERNEL);
}

/* ── Category C: tainted value → array subscript ── */

static u8 table[16];

/* unbounded tainted subscript */
u8 bug_C_subscript(struct pkt *p)
{
	u16 i = le16_to_cpu(p->count);
	return table[i];
}

/* guarded: subscript bounded before use */
u8 guarded_C_bounded(struct pkt *p)
{
	u16 i = le16_to_cpu(p->count);
	if (i >= 16)
		return 0;
	return table[i];
}

/*
 * Stage 1 fires on a masked subscript (& 0x0f limits i to [0,15]).
 * Stage 1.7 proves it safe via the bitvector model.  Stage 1 cannot see
 * the mask as a ceiling guard (it looks for relational comparisons).
 */
u8 fp_C_masked(struct pkt *p)
{
	u16 i = le16_to_cpu(p->count) & 0x0f;
	return table[i];
}

/* ── Category D: strlen on tainted pointer without NUL guarantee ── */

/* strlen on pointer derived from tainted offset — no NUL guarantee */
int bug_D_strlen(struct pkt *p)
{
	u16 off = le16_to_cpu(p->offset);
	char *name = (char *)pkt_buf + off;
	return strlen(name);
}

/*
 * memchr called but return value discarded — the call does not establish
 * NUL termination; the finding survives with guarded=False.
 */
int bug_D_memchr_discarded(struct pkt *p)
{
	u16 off = le16_to_cpu(p->offset);
	char *name = (char *)pkt_buf + off;
	memchr(name, 0, 64);   /* result discarded — not a guard */
	return strlen(name);
}

/*
 * memchr return value IS checked.  Stage 1 still emits Cat D with
 * possibly_guarded=True; Stage 2 assesses whether the guard is sufficient.
 * A well-placed if(!memchr(...)) return is a genuine guard — Stage 2
 * should call this false_positive.
 */
int guarded_D_memchr_checked(struct pkt *p)
{
	u16 off = le16_to_cpu(p->offset);
	char *name = (char *)pkt_buf + off;
	if (!memchr(name, 0, 64))
		return -1;
	return strlen(name);
}

/* strnlen result stored and compared — another valid guard pattern */
int guarded_D_strnlen_checked(struct pkt *p)
{
	u16 off = le16_to_cpu(p->offset);
	char *name = (char *)pkt_buf + off;
	size_t slen = strnlen(name, 64);
	if (slen >= 64)
		return -1;
	return strlen(name);
}

/* ── Category E: dereference of pointer from tainted offset ── */

/* field access via pointer derived from tainted offset, no bounds check */
u16 bug_E_field_deref(struct pkt *p, u8 *end)
{
	u16 off = le16_to_cpu(p->offset);
	struct inner *q = (struct inner *)(pkt_buf + off);
	return q->val;
}

/* guarded: pointer validated against packet end before dereference */
u16 guarded_E_bounded(struct pkt *p, u8 *end)
{
	u16 off = le16_to_cpu(p->offset);
	struct inner *q = (struct inner *)(pkt_buf + off);
	if ((u8 *)q + sizeof(*q) > end)
		return 0;
	return q->val;
}

/* ── Category F: tainted loop iteration bound ── */

static struct entry entries[256];
extern void process(struct entry *);

/* tainted value drives loop count without bound check */
void bug_F_loop(struct pkt *p)
{
	u16 count = le16_to_cpu(p->count);
	for (int i = 0; i < count; i++)
		process(&entries[i]);
}

/* guarded: count bounded before loop */
void guarded_F_bounded_loop(struct pkt *p)
{
	u16 count = le16_to_cpu(p->count);
	if (count > 256)
		return;
	for (int i = 0; i < count; i++)
		process(&entries[i]);
}

/* ── Category G1: copy_to/from_user return value unchecked ── */

/* return value of copy_to_user discarded — partial copy treated as success */
void bug_G1_discarded(struct pkt *p, void *user_buf)
{
	copy_to_user(user_buf, p, sizeof(*p));
}

/* return value assigned but never tested against zero */
int bug_G1_unchecked_assign(struct pkt *p, void *user_buf)
{
	int rc;
	rc = copy_to_user(user_buf, p, sizeof(*p));
	return 0;   /* rc is never compared */
}

/* FP: return value properly checked */
int fp_G1_checked(struct pkt *p, void *user_buf)
{
	if (copy_to_user(user_buf, p, sizeof(*p)))
		return -1;
	return 0;
}

/* ── Category G2: unvalidated size argument to copy_to/from_user ── */

extern u8 kbuf[256];

/*
 * G2 fires when the size argument to copy_to_user is an identifier with no
 * prior guard — it does not require taint, only an unvalidated variable.
 */
long bug_G2_unvalidated_size(void *user_buf, u16 len)
{
	return copy_to_user(user_buf, kbuf, len);
}

/* FP: size checked before the copy */
long fp_G2_bounded(void *user_buf, u16 len)
{
	if (len > sizeof(kbuf))
		return -1;
	return copy_to_user(user_buf, kbuf, len);
}

/* ── Category G3: kmalloc'd struct with unzeroed padding → copy_to_user ── */

struct padded { u32 a; u8 b; /* 3 bytes compiler padding here */ u32 c; };

/*
 * Bug: kmalloc (not kzalloc) + field writes + copy_to_user.
 * Compiler padding bytes between 'b' and 'c' remain uninitialized.
 */
int bug_G3_kmalloc_struct(void *user_buf)
{
	struct padded *p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p) return -1;
	p->a = 1;
	p->b = 2;
	p->c = 3;
	return copy_to_user(user_buf, p, sizeof(*p));
}

/*
 * Safe: kzalloc zeroes the entire allocation including padding bytes.
 */
int fp_G3_kzalloc(void *user_buf)
{
	struct padded *p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) return -1;
	p->a = 1;
	p->c = 3;
	return copy_to_user(user_buf, p, sizeof(*p));
}

/*
 * Safe: explicit memset(p, 0, ...) before copy_to_user zeroes padding.
 */
int fp_G3_memset(void *user_buf)
{
	struct padded *p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p) return -1;
	memset(p, 0, sizeof(*p));
	p->a = 1;
	return copy_to_user(user_buf, p, sizeof(*p));
}

/*
 * No field writes — raw buffer copy, not a struct field pattern.
 * G3 must NOT fire (heuristic: field writes required).
 */
int fp_G3_no_field_writes(void *user_buf)
{
	u8 *buf = kmalloc(32, GFP_KERNEL);
	if (!buf) return -1;
	/* no buf->field writes — not a struct field usage */
	return copy_to_user(user_buf, buf, 32);
}

/* ── Category H: wide server value truncated to narrower LOCAL variable ── */

/* 32-bit server value stored into a declared 16-bit local variable */
u16 bug_H_u32_to_u16(struct pkt *p)
{
	u16 narrow = le32_to_cpu(p->size32);   /* truncates 32→16 */
	return narrow;
}

/* 16-bit server value stored into a declared u8 local variable */
u8 bug_H_u16_to_u8(struct pkt *p)
{
	u8 narrow = le16_to_cpu(p->len);       /* truncates 16→8 */
	return narrow;
}

/* FP: same width unsigned → unsigned — no sign change */
u16 fp_H_same_width(struct pkt *p)
{
	u16 v = le16_to_cpu(p->len);
	return v;
}

/* FP: narrower source — widening, not truncation */
u32 fp_H_widening(struct pkt *p)
{
	u32 v = le16_to_cpu(p->count);   /* 16 → 32: safe */
	return v;
}

/* ── Category H (sign-conversion): same-width unsigned→signed ── */

/*
 * u32 wire value stored into signed int — any value with MSB set becomes
 * negative, bypassing a subsequent `if (local > MAX)` ceiling check.
 */
s32 bug_H_u32_to_int(struct pkt *p)
{
	s32 local = le32_to_cpu(p->size32);   /* u32 → s32: sign reinterpret */
	if (local > 1000)
		return -1;
	return local;
}

/* FP: u16 → int is widening AND sign-safe (u16 always fits in int positive range) */
int fp_H_u16_to_int(struct pkt *p)
{
	int local = le16_to_cpu(p->count);    /* u16 (0-65535) → int: MSB never set */
	return local;
}

/* ── Category L: tainted shift amount ── */

/* server-supplied shift amount with no width bound — UB if >= 32 */
u32 bug_L_left_shift(struct pkt *p)
{
	u16 order = le16_to_cpu(p->shift_amt);
	return 1U << order;
}

/* right shift is the same problem */
u32 bug_L_right_shift(struct pkt *p, u32 val)
{
	u16 amount = le16_to_cpu(p->shift_amt);
	return val >> amount;
}

/* guarded: shift amount bounded below type width */
u32 guarded_L_bounded(struct pkt *p)
{
	u16 order = le16_to_cpu(p->shift_amt);
	if (order >= 32)
		return 0;
	return 1U << order;
}

/*
 * Stage 1 fires on a masked shift amount (& 0x1f limits to [0,31]).
 * Stage 1.7 proves it safe via the bitvector model; Stage 1 cannot see
 * the mask as a guard (same limitation as fp_C_masked above).
 */
u32 fp_L_masked(struct pkt *p)
{
	u16 order = le16_to_cpu(p->shift_amt) & 0x1f;
	return 1U << order;
}

/* ── min()/min_t()/clamp() ceiling guards ── */

/*
 * In-place min_t ceiling: size is capped before kmalloc.
 * The min_t assignment should be credited as an upper-bound guard.
 */
void *guarded_B_min_t(struct pkt *p)
{
	u16 size = le16_to_cpu(p->len);
	size = min_t(u16, size, 4096);
	return kmalloc(size, GFP_KERNEL);
}

/*
 * In-place min ceiling: size is capped before kmalloc.
 */
void *guarded_B_min(struct pkt *p)
{
	u16 size = le16_to_cpu(p->len);
	size = min(size, (u16)1024);
	return kmalloc(size, GFP_KERNEL);
}

/*
 * min inside a branch that does not dominate the sink — the cap only runs
 * on one path, so it is not a guard.
 */
void *bug_B_min_nondominant(struct pkt *p)
{
	u16 size = le16_to_cpu(p->len);
	if (cond)
		size = min(size, (u16)1024);
	return kmalloc(size, GFP_KERNEL);
}

/* ── Provenance-based taint: u8 field from server-response struct ── */

/*
 * u8 DataOffset is in smb2_read_rsp (in _SERVER_RESPONSE_STRUCTS).
 * No endian helper is needed — the provenance table makes this tainted.
 */
void *bug_B_provenance_u8(struct smb2_read_rsp *rsp)
{
	u8 off = rsp->DataOffset;
	return kmalloc(off, GFP_KERNEL);
}

/* guarded: off is bounded before kmalloc */
void *guarded_B_provenance_u8(struct smb2_read_rsp *rsp)
{
	u8 off = rsp->DataOffset;
	if (off > 64)
		return NULL;
	return kmalloc(off, GFP_KERNEL);
}

/*
 * local_state is NOT in _SERVER_RESPONSE_STRUCTS.
 * Stage 1 must NOT fire — the field read is not server-tainted.
 */
void *fp_provenance_local_struct(struct local_state *s)
{
	u8 off = s->offset;
	return kmalloc(off, GFP_KERNEL);
}

/* ── Category I: struct field read before sizeof header size check ── */

/*
 * Bug: first field access on smb2_read_rsp before any sizeof check.
 * The buffer may be shorter than the struct; reading DataOffset is an OOB read.
 * Value is returned (not used in a sink) so this is a pure Cat I finding.
 */
int bug_I_field_before_sizeof(struct smb2_read_rsp *rsp, u32 recv_len)
{
	u8 off = rsp->DataOffset;    /* OOB: no sizeof check before this read */
	if (recv_len < sizeof(struct smb2_read_rsp))
		return -1;
	return off;
}

/*
 * Guarded: sizeof(struct smb2_read_rsp) check appears before the first
 * field read — the buffer is guaranteed large enough.
 */
int guarded_I_sizeof_before_read(struct smb2_read_rsp *rsp, u32 recv_len)
{
	if (recv_len < sizeof(struct smb2_read_rsp))
		return -1;
	u8 off = rsp->DataOffset;
	return off;
}

/*
 * Guarded via sizeof(*rsp) — equivalent to sizeof(struct smb2_read_rsp).
 * The scanner must recognise both forms.
 */
int guarded_I_sizeof_star_ptr(struct smb2_read_rsp *rsp, u32 recv_len)
{
	if (recv_len < sizeof(*rsp))
		return -1;
	u8 off = rsp->DataOffset;
	return off;
}

/*
 * local_state is NOT in _SERVER_RESPONSE_STRUCTS.
 * Cat I must NOT fire — not a server-response struct.
 */
int fp_I_local_struct(struct local_state *s, u32 len)
{
	u8 off = s->offset;
	return off;
}

/* ── Category I: while/for loop sizeof guards ── */

/*
 * TLV-style parsing loop: while condition contains sizeof(*rsp), which runs
 * before the first field read in the body.  Must be credited as guarded.
 */
int guarded_I_while_sizeof(struct smb2_read_rsp *rsp, u32 recv_len)
{
	while (recv_len >= sizeof(*rsp)) {
		u8 off = rsp->DataOffset;   /* guarded: while condition runs first */
		recv_len -= sizeof(*rsp);
		break;
	}
	return 0;
}

/*
 * for loop with sizeof(struct T) in the condition — both the type-name and
 * the star-ptr forms must be recognised.
 */
int guarded_I_for_sizeof(struct smb2_read_rsp *rsp, u32 recv_len)
{
	for (; recv_len >= sizeof(struct smb2_read_rsp); recv_len--) {
		u8 off = rsp->DataOffset;   /* guarded by for condition */
		break;
	}
	return 0;
}

/* ── Category I: standalone guard macro (ceph_decode_need style) ── */

/*
 * Stub for ceph_decode_need — at source level this is a call_expression
 * statement, NOT an if_statement; the scanner must recognise sizeof(*p)
 * inside the arguments as a guard.
 */
#define ceph_decode_need(p, end, n, bad) \
	do { if ((u8 *)(*(p)) + (n) > (u8 *)(end)) goto bad; } while (0)

/*
 * Guarded via ceph_decode_need standalone macro call.
 * sizeof(*rsp) is in the 3rd argument — not in an if/while/for condition.
 */
int guarded_I_macro_guard(struct smb2_read_rsp *rsp, u8 *end)
{
	u8 *p = (u8 *)rsp;
	ceph_decode_need(&p, end, sizeof(*rsp), bad);
	return rsp->DataOffset;   /* guarded by macro */
bad:
	return -1;
}

/* ── Category I: alias root tracking (Step 4) ── */

/*
 * Two same-type pointers cast from the same buffer.
 * sizeof guard references the alias variable, not rsp directly.
 * Step 4 must credit the guard via alias root matching.
 */
int guarded_I_sizeof_via_alias(char *buf, u32 recv_len)
{
	struct smb2_read_rsp *alias = (struct smb2_read_rsp *)buf;
	struct smb2_read_rsp *rsp   = (struct smb2_read_rsp *)buf;
	if (recv_len < sizeof(*alias))   /* guard references alias, not rsp */
		return -1;
	return rsp->DataOffset;           /* guarded via same-root alias */
}

/*
 * Two pointers cast from DIFFERENT buffers — alias guard does not apply.
 * sizeof(*alias) guards buf2, not buf; rsp->DataOffset is still unguarded.
 */
int bug_I_alias_different_root(char *buf, char *buf2, u32 recv_len)
{
	struct smb2_read_rsp *alias = (struct smb2_read_rsp *)buf2;
	struct smb2_read_rsp *rsp   = (struct smb2_read_rsp *)buf;
	if (recv_len < sizeof(*alias))   /* guards buf2, not buf */
		return -1;
	return rsp->DataOffset;           /* unguarded — different root */
}

/* ── Category I: cross-type alias guards (alias Step 5) ── */

/*
 * sizeof guard via a LARGER struct (smb2_read_rsp, 80 bytes) protects a
 * SMALLER struct read (smb2_err_rsp, 72 bytes) from the same buffer.
 * _SMB2_STRUCT_MIN_BYTES: 80 >= 72 → credit the guard.
 */
int guarded_I_cross_type_larger_guard(char *buf, u32 recv_len)
{
	struct smb2_read_rsp *read = (struct smb2_read_rsp *)buf;
	struct smb2_err_rsp  *err  = (struct smb2_err_rsp  *)buf;
	if (recv_len < sizeof(*read))   /* guard for larger struct (80 bytes) */
		return -1;
	return err->ErrorContextCount;   /* guarded: 80 >= 72 */
}

/*
 * Bug: sizeof guard via SMALLER struct (smb2_err_rsp, 72 bytes) does NOT
 * protect a LARGER struct read (smb2_read_rsp, 80 bytes) from the same buf.
 * _SMB2_STRUCT_MIN_BYTES: 72 < 80 → guard insufficient.
 */
int bug_I_cross_type_smaller_guard(char *buf, u32 recv_len)
{
	struct smb2_err_rsp  *err  = (struct smb2_err_rsp  *)buf;
	struct smb2_read_rsp *read = (struct smb2_read_rsp *)buf;
	if (recv_len < sizeof(*err))    /* guard for smaller struct (72 bytes) */
		return -1;
	return read->DataOffset;         /* unguarded: 72 < 80 */
}

/*
 * Step 5 assignment-expression tracking: NULL-init then assign from same buf.
 * The alias root is established via assignment, not init_declarator.
 * sizeof(*read) guard (80 bytes) covers err->field (72 bytes) via alias.
 */
int guarded_I_alias_via_assignment(char *buf, u32 recv_len)
{
	struct smb2_read_rsp *read = NULL;
	struct smb2_err_rsp  *err  = NULL;
	read = (struct smb2_read_rsp *)buf;
	err  = (struct smb2_err_rsp  *)buf;
	if (recv_len < sizeof(*read))
		return -1;
	return err->ErrorContextCount;   /* guarded via assignment-tracked alias */
}
