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

/* FP: same width — no truncation */
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
