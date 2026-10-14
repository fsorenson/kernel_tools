struct hdr { __le16 idx; __le16 off; __le16 len; __le32 big; };
static u8 table[8];
static u8 buf[256];

/* Gap 1: bitmask-truncated index, no relational guard */
int probe_mask(void *p, u8 *data)
{
	struct hdr *h = p;
	u16 i = le16_to_cpu(h->idx) & 0x0F;
	return table[i];
}

/* Gap 4: signed index, upper bound checked, no lower bound */
int probe_signed(void *p)
{
	struct hdr *h = p;
	s16 v = le16_to_cpu(h->idx);
	int i = v >> 2;
	if (i > 7)
		return -1;
	return table[i];
}

/* Gap 2: lookahead past a validated base offset */
int probe_lookahead(void *p, u8 *data, u32 total)
{
	struct hdr *h = p;
	u32 off = le32_to_cpu(h->off);
	if (off > total)
		return -1;
	return data[off + 1];
}

/* Controls: each of these is genuinely guarded and must stay silent */
int ctl_unsigned_upper(void *p)          /* unsigned + upper bound = complete */
{
	struct hdr *h = p;
	u16 i = le16_to_cpu(h->idx);
	if (i >= 8)
		return -1;
	return table[i];
}

int ctl_signed_both(void *p)             /* signed, both ends pinned */
{
	struct hdr *h = p;
	int i = le16_to_cpu(h->idx);
	if (i < 0 || i >= 8)
		return -1;
	return table[i];
}

int ctl_unsigned_cast(void *p)           /* (unsigned) cast pins both at once */
{
	struct hdr *h = p;
	int i = le16_to_cpu(h->idx);
	if ((unsigned int)i >= 8)
		return -1;
	return table[i];
}

int ctl_guard_sees_offset(void *p, u8 *data, u32 total)
{
	struct hdr *h = p;
	u32 off = le32_to_cpu(h->off);
	if (off + 1 > total)
		return -1;
	return data[off + 1];
}

/* operand-vs-name-mention: the variable is a call argument, so the comparison
   tests the call's result, not the variable */
void ctl_call_arg_not_guard(struct hdr *h, const void *key)
{
	u16 idx = le16_to_cpu(h->len);

	if (memcmp(key, tbl_names[0], idx) == 0)
		return;
	total += tbl[idx];
}

/* the comparison is wrapped in unlikely(): still a real guard */
void ctl_unlikely_wrapped(struct hdr *h)
{
	u16 idx = le16_to_cpu(h->len);

	if (unlikely(idx >= 8))
		return;
	total += tbl[idx];
}

/* signed rule, non-negative by width: a 16-bit field widened into an int
   cannot reach the negative half */
void ctl_signed_narrow_src(struct hdr *h)
{
	int idx = le16_to_cpu(h->idx);

	if (idx >= 8)
		return;
	total += tbl[idx];
}

/* non-negative by shift of an unsigned */
void ctl_signed_shifted(struct hdr *h)
{
	u32 type_len = le32_to_cpu(h->big);
	int len = type_len >> 8;

	if (len > 8)
		return;
	total += tbl[len];
}

/* non-negative by mask */
void ctl_signed_masked(struct hdr *h)
{
	int idx = le32_to_cpu(h->big) & 0x00FFFFFF;

	if (idx >= 8)
		return;
	total += tbl[idx];
}

/* still dangerous: a 32-bit field into an int keeps the sign bit */
void probe_signed_same_width(struct hdr *h)
{
	int idx = le32_to_cpu(h->big);

	if (idx >= 8)
		return;
	total += tbl[idx];
}

/* reaching definitions on the taint map: the sink consumes a value that never
   came from the server, so there is no finding here at all.  The guard-level
   stale-redefinition rule is what remains once the kill is scoped away. */
void probe_stale_redef(struct hdr *h, struct lst *l)
{
	int idx = le32_to_cpu(h->big);

	if (idx >= 8 || idx < 0)
		return;
	idx = lookup_slot(l);
	total += tbl[idx];
}

/* the other arm still reaches the sink carrying the server value */
void ctl_kill_branch_local(struct hdr *h, int err)
{
	int idx = le32_to_cpu(h->big);

	if (err)
		idx = 0;
	total += tbl[idx];
}

/* a compound assignment keeps what it accumulates onto */
void ctl_kill_compound(struct hdr *h)
{
	int idx = le32_to_cpu(h->big);

	idx |= 4;
	total += tbl[idx];
}

/* the retaint, not the value the kill replaced, is what survives the branch:
   the reported taint line must be the h2 read, not the h read */
void ctl_kill_retaint(struct hdr *h, struct hdr *h2, int err)
{
	int idx = le32_to_cpu(h->big);

	if (err) {
		idx = 0;
		idx = le32_to_cpu(h2->big);
	}
	total += tbl[idx];
}

/* storing through a tainted pointer does not retarget the pointer */
void ctl_kill_field_write(struct hdr *h, u8 *base)
{
	struct hdr *p = (struct hdr *)(base + le32_to_cpu(h->big));

	p->idx = 0;
	total += le16_to_cpu(p->len);
}

/* transform, not a fresh value: the guard is what makes the subtraction safe */
void ctl_redef_transform(struct hdr *h)
{
	int len = le32_to_cpu(h->big);

	if (len < 4)
		return;
	len -= 4;
	memcpy(dst, h, len);
}

/* clamp gated on a comparison of the same variable re-establishes the bound */
void ctl_redef_clamped(struct hdr *h)
{
	int idx = le32_to_cpu(h->big);

	if (idx < 0)
		return;
	if (idx >= 8)
		idx = 7;
	total += tbl[idx];
}

/* write in a branch that leaves never reaches the sink */
void ctl_redef_unreachable(struct hdr *h, int err)
{
	int idx = le32_to_cpu(h->big);

	if (idx >= 8 || idx < 0)
		return;
	if (err) {
		idx = 99;
		return;
	}
	total += tbl[idx];
}

/* a later guard covers what an earlier one lost */
void ctl_redef_reguarded(struct hdr *h, struct hdr *h2)
{
	int idx = le32_to_cpu(h->big);

	if (idx >= 8 || idx < 0)
		return;
	idx = le32_to_cpu(h2->big);
	if (idx >= 8 || idx < 0)
		return;
	total += tbl[idx];
}

/* a sizeof operand is evaluated for its type, so it bounds nothing */
void probe_sizeof_operand(struct hdr *h, u8 *base, u8 *end)
{
	u32 off = le32_to_cpu(h->big);
	struct hdr *buf = (struct hdr *)(base + off);

	if ((size_t)(end - base) < sizeof(*buf))
		return;
	total += le16_to_cpu(buf->idx);
}

/* same guard, but the variable also appears outside the sizeof */
void ctl_sizeof_and_bare(struct hdr *h, u8 *base, u8 *end)
{
	u32 off = le32_to_cpu(h->big);
	struct hdr *buf = (struct hdr *)(base + off);

	if ((u8 *)buf + sizeof(*buf) > end)
		return;
	total += le16_to_cpu(buf->idx);
}

/* FP control: division keeps the value off the bottom, so the missing floor
   costs nothing — _max_bits() does not model /, so Stage 1 flags it */
int ctl_signed_div(void *p)
{
	struct hdr *h = p;
	int i = le16_to_cpu(h->idx) / 8;
	if (i > 7)
		return -1;
	return table[i];
}

/* FP control: the sink's adjustment moves away from the ceiling the guard
   established, and the floor keeps it from going through zero */
void ctl_offset_shrinks(struct hdr *h, void *src)
{
	int len = le16_to_cpu(h->len);

	if (len < 4 || len > 64)
		return;
	memcpy(dst, src, len - 4);
}
#include <linux/kernel.h>

struct hdr { __le16 len; };
extern char buf[64];
extern void *dst;
extern int cond;

/* 1. guard exists in range but is nested under an unrelated condition, so it
      does not dominate the sink */
void cfg_nondominating(struct hdr *h, void *src)
{
	u16 len = le16_to_cpu(h->len);

	if (cond) {
		if (len > 64)
			return;
	}
	memcpy(dst, src, len);
}

/* 2. guard dominates, but the value is redefined after it */
void cfg_killed_def(struct hdr *h, void *src)
{
	u16 len = le16_to_cpu(h->len);

	if (len > 64)
		return;
	len += 8;
	memcpy(dst, src, len);
}

/* 3. sink precedes the taint assignment in text; the back edge makes it
      reachable with the previous iteration's value */
void cfg_back_edge(struct hdr *h, void *src)
{
	u16 len = 0;

	while (cond) {
		memcpy(dst, src, len);
		len = le16_to_cpu(h->len);
		h++;
	}
}

/* 4. guard's terminal is a goto whose label falls through to the sink */
void cfg_goto_fallthrough(struct hdr *h, void *src)
{
	u16 len = le16_to_cpu(h->len);

	if (len > 64)
		goto out;
	return;
out:
	memcpy(dst, src, len);
}

/* control: guard dominates, value untouched */
void cfg_ctl_ok(struct hdr *h, void *src)
{
	u16 len = le16_to_cpu(h->len);

	if (len > 64)
		return;
	memcpy(dst, src, len);
}

/* control: the guard's goto lands below the sink, the normal cifs shape */
void cfg_ctl_goto_below(struct hdr *h, void *src)
{
	u16 len = le16_to_cpu(h->len);

	if (len > 64)
		goto out;
	memcpy(dst, src, len);
out:
	return;
}

struct rsp_hdr { __le16 ByteCount; u8 data[]; };
extern int total;

/* gap3 control: the guard reaches the tainted pointer only as a field base,
   so it bounds rsp->ByteCount, not rsp */
void gap3_field_base(void *base, struct hdr *h)
{
	u16 off = le16_to_cpu(h->off);
	struct rsp_hdr *rsp = (struct rsp_hdr *)((char *)base + off);

	if (rsp->ByteCount < 8)
		return;
	total += rsp->data[0];
}

/* negative control: the same variable also compared bare */
void gap3_bare_too(void *base, struct hdr *h)
{
	u16 off = le16_to_cpu(h->off);
	struct rsp_hdr *rsp = (struct rsp_hdr *)((char *)base + off);

	if (rsp->ByteCount < 8 || (char *)rsp > (char *)base + 512)
		return;
	total += rsp->data[0];
}
