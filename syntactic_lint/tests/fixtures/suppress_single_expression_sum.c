/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/ntfs3/bitmap.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   wnd_find()  lines 969-1318
 */
/*
 * wnd_find - Look for free space.
 *
 * - flags - BITMAP_FIND_XXX flags
 *
 * Return: 0 if not found.
 */
size_t wnd_find(struct wnd_bitmap *wnd, size_t to_alloc, size_t hint,
		size_t flags, size_t *allocated)
{
	struct super_block *sb;
	u32 wbits, wpos, wzbit, wzend;
	size_t fnd, max_alloc, b_len, b_pos;
	size_t iw, prev_tail, nwnd, wbit, ebit, zbit, zend;
	size_t to_alloc0 = to_alloc;
	const struct e_node *e;
	const struct rb_node *pr, *cr;
	u8 log2_bits;
	bool fbits_valid;
	struct buffer_head *bh;

	/* Fast checking for available free space. */
	if (flags & BITMAP_FIND_FULL) {
		size_t zeroes = wnd_zeroes(wnd);

		zeroes -= wnd->zone_end - wnd->zone_bit;
		if (zeroes < to_alloc0)
			goto no_space;

		if (to_alloc0 > wnd->extent_max)
			goto no_space;
	} else {
		if (to_alloc > wnd->extent_max)
			to_alloc = wnd->extent_max;
	}

	if (wnd->zone_bit <= hint && hint < wnd->zone_end)
		hint = wnd->zone_end;

	max_alloc = wnd->nbits;
	b_len = b_pos = 0;

	if (hint >= max_alloc)
		hint = 0;

	if (RB_EMPTY_ROOT(&wnd->start_tree)) {
		if (wnd->uptodated == 1) {
			/* Extents tree is updated -> No free space. */
			goto no_space;
		}
		goto scan_bitmap;
	}

	e = NULL;
	if (!hint)
		goto allocate_biggest;

	/* Use hint: Enumerate extents by start >= hint. */
	pr = NULL;
	cr = wnd->start_tree.rb_node;

	for (;;) {
		e = rb_entry(cr, struct e_node, start.node);

		if (e->start.key == hint)
			break;

		if (e->start.key < hint) {
			pr = cr;
			cr = cr->rb_right;
			if (!cr)
				break;
			continue;
		}

		cr = cr->rb_left;
		if (!cr) {
			e = pr ? rb_entry(pr, struct e_node, start.node) : NULL;
			break;
		}
	}

	if (!e)
		goto allocate_biggest;

	if (e->start.key + e->count.key > hint) {
		/* We have found extension with 'hint' inside. */
		size_t len = e->start.key + e->count.key - hint;

		if (len >= to_alloc && hint + to_alloc <= max_alloc) {
			fnd = hint;
			goto found;
		}

		if (!(flags & BITMAP_FIND_FULL)) {
			if (len > to_alloc)
				len = to_alloc;

			if (hint + len <= max_alloc) {
				fnd = hint;
				to_alloc = len;
				goto found;
			}
		}
	}

allocate_biggest:
	/* Allocate from biggest free extent. */
	e = rb_entry(rb_first(&wnd->count_tree), struct e_node, count.node);
	if (e->count.key != wnd->extent_max)
		wnd->extent_max = e->count.key;

	if (e->count.key < max_alloc) {
		if (e->count.key >= to_alloc) {
			;
		} else if (flags & BITMAP_FIND_FULL) {
			if (e->count.key < to_alloc0) {
				/* Biggest free block is less then requested. */
				goto no_space;
			}
			to_alloc = e->count.key;
		} else if (-1 != wnd->uptodated) {
			to_alloc = e->count.key;
		} else {
			/* Check if we can use more bits. */
			size_t op, max_check;
			struct rb_root start_tree;

			memcpy(&start_tree, &wnd->start_tree,
			       sizeof(struct rb_root));
			memset(&wnd->start_tree, 0, sizeof(struct rb_root));

			max_check = e->start.key + to_alloc;
			if (max_check > max_alloc)
				max_check = max_alloc;
			for (op = e->start.key + e->count.key; op < max_check;
			     op++) {
				if (!wnd_is_free(wnd, op, 1))
					break;
			}
			memcpy(&wnd->start_tree, &start_tree,
			       sizeof(struct rb_root));
			to_alloc = op - e->start.key;
		}

		/* Prepare to return. */
		fnd = e->start.key;
		if (e->start.key + to_alloc > max_alloc)
			to_alloc = max_alloc - e->start.key;
		goto found;
	}

	if (wnd->uptodated == 1) {
		/* Extents tree is updated -> no free space. */
		goto no_space;
	}

	b_len = e->count.key;
	b_pos = e->start.key;

scan_bitmap:
	sb = wnd->sb;
	log2_bits = sb->s_blocksize_bits + 3;

	/* At most two ranges [hint, max_alloc) + [0, hint). */
Again:

	/* TODO: Optimize request for case nbits > wbits. */
	iw = hint >> log2_bits;
	wbits = sb->s_blocksize * 8;
	wpos = hint & (wbits - 1);
	prev_tail = 0;
	fbits_valid = true;

	if (max_alloc == wnd->nbits) {
		nwnd = wnd->nwnd;
	} else {
		size_t t = max_alloc + wbits - 1;

		nwnd = likely(t > max_alloc) ? (t >> log2_bits) : wnd->nwnd;
	}

	/* Enumerate all windows. */
	for (; iw < nwnd; iw++) {
		wbit = iw << log2_bits;

		if (!wnd->free_bits[iw]) {
			if (prev_tail > b_len) {
				b_pos = wbit - prev_tail;
				b_len = prev_tail;
			}

			/* Skip full used window. */
			prev_tail = 0;
			wpos = 0;
			continue;
		}

		if (unlikely(iw + 1 == nwnd)) {
			if (max_alloc == wnd->nbits) {
				wbits = wnd->bits_last;
			} else {
				size_t t = max_alloc & (wbits - 1);

				if (t) {
					wbits = t;
					fbits_valid = false;
				}
			}
		}

		if (wnd->zone_end > wnd->zone_bit) {
			ebit = wbit + wbits;
			zbit = max(wnd->zone_bit, wbit);
			zend = min(wnd->zone_end, ebit);

			/* Here we have a window [wbit, ebit) and zone [zbit, zend). */
			if (zend <= zbit) {
				/* Zone does not overlap window. */
			} else {
				wzbit = zbit - wbit;
				wzend = zend - wbit;

				/* Zone overlaps window. */
				if (wnd->free_bits[iw] == wzend - wzbit) {
					prev_tail = 0;
					wpos = 0;
					continue;
				}

				/* Scan two ranges window: [wbit, zbit) and [zend, ebit). */
				bh = wnd_map(wnd, iw);

				if (IS_ERR(bh)) {
					/* TODO: Error */
					prev_tail = 0;
					wpos = 0;
					continue;
				}

				/* Scan range [wbit, zbit). */
				if (wpos < wzbit) {
					/* Scan range [wpos, zbit). */
					fnd = wnd_scan(bh->b_data, wbit, wpos,
						       wzbit, to_alloc,
						       &prev_tail, &b_pos,
						       &b_len);
					if (fnd != MINUS_ONE_T) {
						put_bh(bh);
						goto found;
					}
				}

				prev_tail = 0;

				/* Scan range [zend, ebit). */
				if (wzend < wbits) {
					fnd = wnd_scan(bh->b_data, wbit,
						       max(wzend, wpos), wbits,
						       to_alloc, &prev_tail,
						       &b_pos, &b_len);
					if (fnd != MINUS_ONE_T) {
						put_bh(bh);
						goto found;
					}
				}

				wpos = 0;
				put_bh(bh);
				continue;
			}
		}

		/* Current window does not overlap zone. */
		if (!wpos && fbits_valid && wnd->free_bits[iw] == wbits) {
			/* Window is empty. */
			if (prev_tail + wbits >= to_alloc) {
				fnd = wbit + wpos - prev_tail;
				goto found;
			}

			/* Increase 'prev_tail' and process next window. */
			prev_tail += wbits;
			wpos = 0;
			continue;
		}

		/* Read window. */
		bh = wnd_map(wnd, iw);
		if (IS_ERR(bh)) {
			// TODO: Error.
			prev_tail = 0;
			wpos = 0;
			continue;
		}

		/* Scan range [wpos, eBits). */
		fnd = wnd_scan(bh->b_data, wbit, wpos, wbits, to_alloc,
			       &prev_tail, &b_pos, &b_len);
		put_bh(bh);
		if (fnd != MINUS_ONE_T)
			goto found;
	}

	if (b_len < prev_tail) {
		/* The last fragment. */
		b_len = prev_tail;
		b_pos = max_alloc - prev_tail;
	}

	if (hint) {
		/*
		 * We have scanned range [hint max_alloc).
		 * Prepare to scan range [0 hint + to_alloc).
		 */
		size_t nextmax = hint + to_alloc;

		if (likely(nextmax >= hint) && nextmax < max_alloc)
			max_alloc = nextmax;
		hint = 0;
		goto Again;
	}

	if (!b_len)
		goto no_space;

	wnd->extent_max = b_len;

	if (flags & BITMAP_FIND_FULL)
		goto no_space;

	fnd = b_pos;
	to_alloc = b_len;

found:
	if (flags & BITMAP_FIND_MARK_AS_USED) {
		/* TODO: Optimize remove extent (pass 'e'?). */
		if (wnd_set_used(wnd, fnd, to_alloc))
			goto no_space;
	} else if (wnd->extent_max != MINUS_ONE_T &&
		   to_alloc > wnd->extent_max) {
		wnd->extent_max = to_alloc;
	}

	*allocated = fnd;
	return to_alloc;

no_space:
	return 0;
}
