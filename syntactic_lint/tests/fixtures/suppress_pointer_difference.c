/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/ntfs/compress.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   ntfs_decompress()  lines 126-443
 */
/*
 * ntfs_decompress - decompress a compression block into an array of pages
 * @dest_pages:		destination array of pages
 * @completed_pages:	scratch space to track completed pages
 * @dest_index:		current index into @dest_pages (IN/OUT)
 * @dest_ofs:		current offset within @dest_pages[@dest_index] (IN/OUT)
 * @dest_max_index:	maximum index into @dest_pages (IN)
 * @dest_max_ofs:	maximum offset within @dest_pages[@dest_max_index] (IN)
 * @xpage:		the target page (-1 if none) (IN)
 * @xpage_done:		set to 1 if xpage was completed successfully (IN/OUT)
 * @cb_start:		compression block to decompress (IN)
 * @cb_size:		size of compression block @cb_start in bytes (IN)
 * @i_size:		file size when we started the read (IN)
 * @initialized_size:	initialized file size when we started the read (IN)
 *
 * The caller must have disabled preemption. ntfs_decompress() reenables it when
 * the critical section is finished.
 *
 * This decompresses the compression block @cb_start into the array of
 * destination pages @dest_pages starting at index @dest_index into @dest_pages
 * and at offset @dest_pos into the page @dest_pages[@dest_index].
 *
 * When the page @dest_pages[@xpage] is completed, @xpage_done is set to 1.
 * If xpage is -1 or @xpage has not been completed, @xpage_done is not modified.
 *
 * @cb_start is a pointer to the compression block which needs decompressing
 * and @cb_size is the size of @cb_start in bytes (8-64kiB).
 *
 * Return 0 if success or -EOVERFLOW on error in the compressed stream.
 * @xpage_done indicates whether the target page (@dest_pages[@xpage]) was
 * completed during the decompression of the compression block (@cb_start).
 *
 * Warning: This function *REQUIRES* PAGE_SIZE >= 4096 or it will blow up
 * unpredicatbly! You have been warned!
 *
 * Note to hackers: This function may not sleep until it has finished accessing
 * the compression block @cb_start as it is a per-CPU buffer.
 */
static int ntfs_decompress(struct page *dest_pages[], int completed_pages[],
		int *dest_index, int *dest_ofs, const int dest_max_index,
		const int dest_max_ofs, const int xpage, char *xpage_done,
		u8 *const cb_start, const u32 cb_size, const loff_t i_size,
		const s64 initialized_size)
{
	/*
	 * Pointers into the compressed data, i.e. the compression block (cb),
	 * and the therein contained sub-blocks (sb).
	 */
	u8 *cb_end = cb_start + cb_size; /* End of cb. */
	u8 *cb = cb_start;	/* Current position in cb. */
	u8 *cb_sb_start = cb;	/* Beginning of the current sb in the cb. */
	u8 *cb_sb_end;		/* End of current sb / beginning of next sb. */

	/* Variables for uncompressed data / destination. */
	struct page *dp;	/* Current destination page being worked on. */
	u8 *dp_kaddr;		/* Local kmap for the current destination page. */
	u8 *dp_addr;		/* Current pointer into dp. */
	u8 *dp_sb_start;	/* Start of current sub-block in dp. */
	u8 *dp_sb_end;		/* End of current sb in dp (dp_sb_start + NTFS_SB_SIZE). */
	u16 do_sb_start;	/* @dest_ofs when starting this sub-block. */
	u16 do_sb_end;		/* @dest_ofs of end of this sb (do_sb_start + NTFS_SB_SIZE). */

	/* Variables for tag and token parsing. */
	u8 tag;			/* Current tag. */
	int token;		/* Loop counter for the eight tokens in tag. */
	int nr_completed_pages = 0;

	/* Default error code. */
	int err = -EOVERFLOW;

	dp_kaddr = NULL;
	ntfs_debug("Entering, cb_size = 0x%x.", cb_size);
do_next_sb:
	ntfs_debug("Beginning sub-block at offset = 0x%zx in the cb.",
			cb - cb_start);
	/*
	 * Have we reached the end of the compression block or the end of the
	 * decompressed data?  The latter can happen for example if the current
	 * position in the compression block is one byte before its end so the
	 * first two checks do not detect it.
	 */
	if (cb == cb_end || !le16_to_cpup((__le16 *)cb) ||
			(*dest_index == dest_max_index &&
			*dest_ofs == dest_max_ofs)) {
		int i;

		ntfs_debug("Completed. Returning success (0).");
		err = 0;
return_error:
		/* We can sleep from now on, so we drop lock. */
		mutex_unlock(&ntfs_cb_lock);
		/* Second stage: finalize completed pages. */
		if (nr_completed_pages > 0) {
			for (i = 0; i < nr_completed_pages; i++) {
				int di = completed_pages[i];

				dp = dest_pages[di];
				/*
				 * If we are outside the initialized size, zero
				 * the out of bounds page range.
				 */
				handle_bounds_compressed_page(dp, i_size,
						initialized_size);
				SetPageUptodate(dp);
				unlock_page(dp);
				if (di == xpage)
					*xpage_done = 1;
				else
					put_page(dp);
				dest_pages[di] = NULL;
			}
		}
		return err;
	}

	/* Setup offsets for the current sub-block destination. */
	do_sb_start = *dest_ofs;
	do_sb_end = do_sb_start + NTFS_SB_SIZE;

	/* Check that we are still within allowed boundaries. */
	if (*dest_index == dest_max_index && do_sb_end > dest_max_ofs)
		goto return_overflow;

	/* Does the minimum size of a compressed sb overflow valid range? */
	if (cb + 6 > cb_end)
		goto return_overflow;

	/* Setup the current sub-block source pointers and validate range. */
	cb_sb_start = cb;
	cb_sb_end = cb_sb_start + (le16_to_cpup((__le16 *)cb) & NTFS_SB_SIZE_MASK)
			+ 3;
	if (cb_sb_end > cb_end)
		goto return_overflow;

	/* Get the current destination page. */
	dp = dest_pages[*dest_index];
	if (!dp) {
		/* No page present. Skip decompression of this sub-block. */
		cb = cb_sb_end;

		/* Advance destination position to next sub-block. */
		*dest_ofs = (*dest_ofs + NTFS_SB_SIZE) & ~PAGE_MASK;
		if (!*dest_ofs && (++*dest_index > dest_max_index))
			goto return_overflow;
		goto do_next_sb;
	}

	/* We have a valid destination page. Setup the destination pointers. */
	dp_kaddr = kmap_local_page(dp);
	dp_addr = dp_kaddr + do_sb_start;

	/* Now, we are ready to process the current sub-block (sb). */
	if (!(le16_to_cpup((__le16 *)cb) & NTFS_SB_IS_COMPRESSED)) {
		ntfs_debug("Found uncompressed sub-block.");
		/* This sb is not compressed, just copy it into destination. */

		/* Advance source position to first data byte. */
		cb += 2;

		/* An uncompressed sb must be full size. */
		if (cb_sb_end - cb != NTFS_SB_SIZE)
			goto return_overflow;

		/* Copy the block and advance the source position. */
		memcpy(dp_addr, cb, NTFS_SB_SIZE);
		cb += NTFS_SB_SIZE;

		/* Advance destination position to next sub-block. */
		*dest_ofs += NTFS_SB_SIZE;
		*dest_ofs &= ~PAGE_MASK;
		kunmap_local(dp_kaddr);
		dp_kaddr = NULL;
		if (!(*dest_ofs)) {
finalize_page:
			/*
			 * First stage: add current page index to array of
			 * completed pages.
			 */
			completed_pages[nr_completed_pages++] = *dest_index;
			if (++*dest_index > dest_max_index)
				goto return_overflow;
		}
		goto do_next_sb;
	}
	ntfs_debug("Found compressed sub-block.");
	/* This sb is compressed, decompress it into destination. */

	/* Setup destination pointers. */
	dp_sb_start = dp_addr;
	dp_sb_end = dp_sb_start + NTFS_SB_SIZE;

	/* Forward to the first tag in the sub-block. */
	cb += 2;
do_next_tag:
	if (cb == cb_sb_end) {
		/* Check if the decompressed sub-block was not full-length. */
		if (dp_addr < dp_sb_end) {
			int nr_bytes = do_sb_end - *dest_ofs;

			ntfs_debug("Filling incomplete sub-block with zeroes.");
			/* Zero remainder and update destination position. */
			memset(dp_addr, 0, nr_bytes);
			*dest_ofs += nr_bytes;
		}
		/* We have finished the current sub-block. */
		*dest_ofs &= ~PAGE_MASK;
		kunmap_local(dp_kaddr);
		dp_kaddr = NULL;
		if (!(*dest_ofs))
			goto finalize_page;
		goto do_next_sb;
	}

	/* Check we are still in range. */
	if (cb > cb_sb_end || dp_addr > dp_sb_end)
		goto return_overflow;

	/* Get the next tag and advance to first token. */
	tag = *cb++;

	/* Parse the eight tokens described by the tag. */
	for (token = 0; token < 8; token++, tag >>= 1) {
		register u16 i;
		u16 lg, pt, length, max_non_overlap;
		u8 *dp_back_addr;

		/* Check if we are done / still in range. */
		if (cb >= cb_sb_end || dp_addr >= dp_sb_end)
			break;

		/* Determine token type and parse appropriately.*/
		if ((tag & NTFS_TOKEN_MASK) == NTFS_SYMBOL_TOKEN) {
			/*
			 * We have a symbol token, copy the symbol across, and
			 * advance the source and destination positions.
			 */
			*dp_addr++ = *cb++;
			++*dest_ofs;

			/* Continue with the next token. */
			continue;
		}

		/*
		 * We have a phrase token. Make sure it is not the first tag in
		 * the sb as this is illegal and would confuse the code below.
		 */
		if (dp_addr == dp_sb_start)
			goto return_overflow;

		/*
		 * Determine the number of bytes to go back (p) and the number
		 * of bytes to copy (l). We use an optimized algorithm in which
		 * we first calculate log2(current destination position in sb),
		 * which allows determination of l and p in O(1) rather than
		 * O(n). We just need an arch-optimized log2() function now.
		 */
		lg = 0;
		for (i = *dest_ofs - do_sb_start - 1; i >= 0x10; i >>= 1)
			lg++;

		/* Get the phrase token into i. */
		pt = le16_to_cpup((__le16 *)cb);

		/*
		 * Calculate starting position of the byte sequence in
		 * the destination using the fact that p = (pt >> (12 - lg)) + 1
		 * and make sure we don't go too far back.
		 */
		dp_back_addr = dp_addr - (pt >> (12 - lg)) - 1;
		if (dp_back_addr < dp_sb_start)
			goto return_overflow;

		/* Now calculate the length of the byte sequence. */
		length = (pt & (0xfff >> lg)) + 3;

		/* Advance destination position and verify it is in range. */
		*dest_ofs += length;
		if (*dest_ofs > do_sb_end)
			goto return_overflow;

		/* The number of non-overlapping bytes. */
		max_non_overlap = dp_addr - dp_back_addr;

		if (length <= max_non_overlap) {
			/* The byte sequence doesn't overlap, just copy it. */
			memcpy(dp_addr, dp_back_addr, length);

			/* Advance destination pointer. */
			dp_addr += length;
		} else {
			/*
			 * The byte sequence does overlap, copy non-overlapping
			 * part and then do a slow byte by byte copy for the
			 * overlapping part. Also, advance the destination
			 * pointer.
			 */
			memcpy(dp_addr, dp_back_addr, max_non_overlap);
			dp_addr += max_non_overlap;
			dp_back_addr += max_non_overlap;
			length -= max_non_overlap;
			while (length--)
				*dp_addr++ = *dp_back_addr++;
		}

		/* Advance source position and continue with the next token. */
		cb += 2;
	}

	/* No tokens left in the current tag. Continue with the next tag. */
	goto do_next_tag;

return_overflow:
	if (dp_kaddr)
		kunmap_local(dp_kaddr);
	ntfs_error(NULL, "Failed. Returning -EOVERFLOW.");
	goto return_error;
}
