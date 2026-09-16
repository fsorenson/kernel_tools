/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/ocfs2/xattr.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   ocfs2_cp_xattr_block_to_bucket()  lines 4418-4484
 */
/*
 * When the ocfs2_xattr_block is filled up, new bucket will be created
 * and all the xattr entries will be moved to the new bucket.
 * The header goes at the start of the bucket, and the names+values are
 * filled from the end.  This is why *target starts as the last buffer.
 * Note: we need to sort the entries since they are not saved in order
 * in the ocfs2_xattr_block.
 */
static void ocfs2_cp_xattr_block_to_bucket(struct inode *inode,
					   struct buffer_head *xb_bh,
					   struct ocfs2_xattr_bucket *bucket)
{
	int i, blocksize = inode->i_sb->s_blocksize;
	int blks = ocfs2_blocks_per_xattr_bucket(inode->i_sb);
	u16 offset, size, off_change;
	struct ocfs2_xattr_entry *xe;
	struct ocfs2_xattr_block *xb =
				(struct ocfs2_xattr_block *)xb_bh->b_data;
	struct ocfs2_xattr_header *xb_xh = &xb->xb_attrs.xb_header;
	struct ocfs2_xattr_header *xh = bucket_xh(bucket);
	u16 count = le16_to_cpu(xb_xh->xh_count);
	char *src = xb_bh->b_data;
	char *target = bucket_block(bucket, blks - 1);

	trace_ocfs2_cp_xattr_block_to_bucket_begin(
				(unsigned long long)xb_bh->b_blocknr,
				(unsigned long long)bucket_blkno(bucket));

	for (i = 0; i < blks; i++)
		memset(bucket_block(bucket, i), 0, blocksize);

	/*
	 * Since the xe_name_offset is based on ocfs2_xattr_header,
	 * there is a offset change corresponding to the change of
	 * ocfs2_xattr_header's position.
	 */
	off_change = offsetof(struct ocfs2_xattr_block, xb_attrs.xb_header);
	xe = &xb_xh->xh_entries[count - 1];
	offset = le16_to_cpu(xe->xe_name_offset) + off_change;
	size = blocksize - offset;

	/* copy all the names and values. */
	memcpy(target + offset, src + offset, size);

	/* Init new header now. */
	xh->xh_count = xb_xh->xh_count;
	xh->xh_num_buckets = cpu_to_le16(1);
	xh->xh_name_value_len = cpu_to_le16(size);
	xh->xh_free_start = cpu_to_le16(OCFS2_XATTR_BUCKET_SIZE - size);

	/* copy all the entries. */
	target = bucket_block(bucket, 0);
	offset = offsetof(struct ocfs2_xattr_header, xh_entries);
	size = count * sizeof(struct ocfs2_xattr_entry);
	memcpy(target + offset, (char *)xb_xh + offset, size);

	/* Change the xe offset for all the xe because of the move. */
	off_change = OCFS2_XATTR_BUCKET_SIZE - blocksize +
		 offsetof(struct ocfs2_xattr_block, xb_attrs.xb_header);
	for (i = 0; i < count; i++)
		le16_add_cpu(&xh->xh_entries[i].xe_name_offset, off_change);

	trace_ocfs2_cp_xattr_block_to_bucket_end(offset, size, off_change);

	sort(target + offset, count, sizeof(struct ocfs2_xattr_entry),
	     cmp_xe, NULL);
}
