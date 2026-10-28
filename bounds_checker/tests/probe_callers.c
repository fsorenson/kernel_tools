/*
 * Stage 1.5 caller enumeration probe.
 *
 * Contains one static function (static_helper) with exactly two callers:
 * one that guards the argument before the call and one that does not.
 * A non-static function (non_static_helper) is present to verify that
 * is_static_fn() correctly distinguishes static from non-static.
 */

typedef unsigned short u16;
typedef unsigned int   u32;
typedef u16 __le16;

struct hdr { __le16 len; __le16 cmd; };

extern u16   le16_to_cpu(u16);
extern void *kmalloc(unsigned long, int);
#define GFP_KERNEL 0

/* ── The function under enumeration ── */

static void *static_helper(struct hdr *h, u32 extra)
{
	u16 len = le16_to_cpu(h->len);
	return kmalloc(len + extra, GFP_KERNEL);
}

/* ── Caller 1: guarded ── */

void caller_guarded(struct hdr *h)
{
	u16 len = le16_to_cpu(h->len);
	if (len > 256)
		return;
	static_helper(h, 0);
}

/* ── Caller 2: unguarded ── */

void caller_unguarded(struct hdr *h)
{
	static_helper(h, 8);
}

/* ── Non-static function: should NOT be considered a closed call set ── */

void non_static_helper(struct hdr *h, u32 extra)
{
	u16 len = le16_to_cpu(h->len);
	(void)kmalloc(len + extra, GFP_KERNEL);
}
