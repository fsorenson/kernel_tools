/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * arch/powerpc/sysdev/xive/common.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   xive_scan_interrupts()  lines 130-213
 */
/*
 * Scans all the queue that may have interrupts in them
 * (based on "pending_prio") in priority order until an
 * interrupt is found or all the queues are empty.
 *
 * Then updates the CPPR (Current Processor Priority
 * Register) based on the most favored interrupt found
 * (0xff if none) and return what was found (0 if none).
 *
 * If just_peek is set, return the most favored pending
 * interrupt if any but don't update the queue pointers.
 *
 * Note: This function can operate generically on any number
 * of queues (up to 8). The current implementation of the XIVE
 * driver only uses a single queue however.
 *
 * Note2: This will also "flush" "the pending_count" of a queue
 * into the "count" when that queue is observed to be empty.
 * This is used to keep track of the amount of interrupts
 * targetting a queue. When an interrupt is moved away from
 * a queue, we only decrement that queue count once the queue
 * has been observed empty to avoid races.
 */
static u32 xive_scan_interrupts(struct xive_cpu *xc, bool just_peek)
{
	u32 irq = 0;
	u8 prio = 0;

	/* Find highest pending priority */
	while (xc->pending_prio != 0) {
		struct xive_q *q;

		prio = ffs(xc->pending_prio) - 1;
		DBG_VERBOSE("scan_irq: trying prio %d\n", prio);

		/* Try to fetch */
		irq = xive_read_eq(&xc->queue[prio], just_peek);

		/* Found something ? That's it */
		if (irq) {
			if (just_peek || irq_to_desc(irq))
				break;
			/*
			 * We should never get here; if we do then we must
			 * have failed to synchronize the interrupt properly
			 * when shutting it down.
			 */
			pr_crit("xive: got interrupt %d without descriptor, dropping\n",
				irq);
			WARN_ON(1);
			continue;
		}

		/* Clear pending bits */
		xc->pending_prio &= ~(1 << prio);

		/*
		 * Check if the queue count needs adjusting due to
		 * interrupts being moved away. See description of
		 * xive_dec_target_count()
		 */
		q = &xc->queue[prio];
		if (atomic_read(&q->pending_count)) {
			int p = atomic_xchg(&q->pending_count, 0);
			if (p) {
				WARN_ON(p > atomic_read(&q->count));
				atomic_sub(p, &q->count);
			}
		}
	}

	/* If nothing was found, set CPPR to 0xff */
	if (irq == 0)
		prio = 0xff;

	/* Update HW CPPR to match if necessary */
	if (prio != xc->cppr) {
		DBG_VERBOSE("scan_irq: adjusting CPPR to %d\n", prio);
		xc->cppr = prio;
		out_8(xive_tima + xive_tima_offset + TM_CPPR, prio);
	}

	return irq;
}
