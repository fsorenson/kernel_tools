/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/ntfs3/inode.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   ntfs_readlink_hlp()  lines 2114-2266
 */
static noinline int ntfs_readlink_hlp(const struct dentry *link_de,
				      struct inode *inode, char *buffer,
				      int buflen)
{
	int i, err = -EINVAL;
	struct ntfs_inode *ni = ntfs_i(inode);
	struct super_block *sb = inode->i_sb;
	struct ntfs_sb_info *sbi = sb->s_fs_info;
	u64 size;
	u16 ulen = 0;
	void *to_free = NULL;
	struct REPARSE_DATA_BUFFER *rp;
	const __le16 *uname;
	struct ATTRIB *attr;

	/* Reparse data present. Try to parse it. */
	static_assert(!offsetof(struct REPARSE_DATA_BUFFER, ReparseTag));
	static_assert(sizeof(u32) == sizeof(rp->ReparseTag));

	*buffer = 0;

	attr = ni_find_attr(ni, NULL, NULL, ATTR_REPARSE, NULL, 0, NULL, NULL);
	if (!attr)
		goto out;

	if (!attr->non_res) {
		rp = resident_data_ex(attr, sizeof(struct REPARSE_DATA_BUFFER));
		if (!rp)
			goto out;
		size = le32_to_cpu(attr->res.data_size);
	} else {
		size = le64_to_cpu(attr->nres.data_size);
		rp = NULL;
	}

	if (size > sbi->reparse.max_size || size <= sizeof(u32))
		goto out;

	if (!rp) {
		rp = kmalloc(size, GFP_NOFS);
		if (!rp) {
			err = -ENOMEM;
			goto out;
		}
		to_free = rp;
		/* Read into temporal buffer. */
		err = ntfs_read_run_nb(sbi, &ni->file.run, 0, rp, size, NULL);
		if (err)
			goto out;
	}

	/* Microsoft Tag. */
	switch (rp->ReparseTag) {
	case IO_REPARSE_TAG_MOUNT_POINT:
		/* Mount points and junctions. */
		/* Can we use 'Rp->MountPointReparseBuffer.PrintNameLength'? */
		if (size <= offsetof(struct REPARSE_DATA_BUFFER,
				     MountPointReparseBuffer.PathBuffer))
			goto out;
		uname = Add2Ptr(rp,
				offsetof(struct REPARSE_DATA_BUFFER,
					 MountPointReparseBuffer.PathBuffer) +
					le16_to_cpu(rp->MountPointReparseBuffer
							    .PrintNameOffset));
		ulen = le16_to_cpu(rp->MountPointReparseBuffer.PrintNameLength);
		break;

	case IO_REPARSE_TAG_SYMLINK:
		/* FolderSymbolicLink */
		/* Can we use 'Rp->SymbolicLinkReparseBuffer.PrintNameLength'? */
		if (size <= offsetof(struct REPARSE_DATA_BUFFER,
				     SymbolicLinkReparseBuffer.PathBuffer))
			goto out;
		uname = Add2Ptr(
			rp, offsetof(struct REPARSE_DATA_BUFFER,
				     SymbolicLinkReparseBuffer.PathBuffer) +
				    le16_to_cpu(rp->SymbolicLinkReparseBuffer
							.PrintNameOffset));
		ulen = le16_to_cpu(
			rp->SymbolicLinkReparseBuffer.PrintNameLength);
		break;

	case IO_REPARSE_TAG_CLOUD:
	case IO_REPARSE_TAG_CLOUD_1:
	case IO_REPARSE_TAG_CLOUD_2:
	case IO_REPARSE_TAG_CLOUD_3:
	case IO_REPARSE_TAG_CLOUD_4:
	case IO_REPARSE_TAG_CLOUD_5:
	case IO_REPARSE_TAG_CLOUD_6:
	case IO_REPARSE_TAG_CLOUD_7:
	case IO_REPARSE_TAG_CLOUD_8:
	case IO_REPARSE_TAG_CLOUD_9:
	case IO_REPARSE_TAG_CLOUD_A:
	case IO_REPARSE_TAG_CLOUD_B:
	case IO_REPARSE_TAG_CLOUD_C:
	case IO_REPARSE_TAG_CLOUD_D:
	case IO_REPARSE_TAG_CLOUD_E:
	case IO_REPARSE_TAG_CLOUD_F:
		err = sizeof("OneDrive") - 1;
		if (err > buflen)
			err = buflen;
		memcpy(buffer, "OneDrive", err);
		goto out;

	default:
		if (IsReparseTagMicrosoft(rp->ReparseTag)) {
			/* Unknown Microsoft Tag. */
			goto out;
		}
		if (!IsReparseTagNameSurrogate(rp->ReparseTag) ||
		    size <= sizeof(struct REPARSE_POINT)) {
			goto out;
		}

		/* Users tag. */
		uname = Add2Ptr(rp, sizeof(struct REPARSE_POINT));
		ulen = le16_to_cpu(rp->ReparseDataLength) -
		       sizeof(struct REPARSE_POINT);
	}

	/* Convert nlen from bytes to UNICODE chars. */
	ulen >>= 1;

	/* Check that name is available. */
	if (!ulen || uname + ulen > (__le16 *)Add2Ptr(rp, size))
		goto out;

	/* If name is already zero terminated then truncate it now. */
	if (!uname[ulen - 1])
		ulen -= 1;

	err = ntfs_utf16_to_nls(sbi, uname, ulen, buffer, buflen);

	if (err < 0)
		goto out;

	/* Translate Windows '\' into Linux '/'. */
	for (i = 0; i < err; i++) {
		if (buffer[i] == '\\')
			buffer[i] = '/';
	}

	/* Always set last zero. */
	buffer[err] = 0;

	/* If this is a junction, translate the link target. */
	if (rp->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT)
		err = ntfs_translate_junction(sb, link_de, buffer, err, buflen);

out:
	kfree(to_free);
	return err;
}
