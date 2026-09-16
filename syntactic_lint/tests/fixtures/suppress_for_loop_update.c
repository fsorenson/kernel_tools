/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/nfs/inode.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   _nfs_display_fhandle()  lines 1822-1864
 */
/*
 * _nfs_display_fhandle - display an NFS file handle on the console
 *
 * @fh: file handle to display
 * @caption: display caption
 *
 * For debugging only.
 */
void _nfs_display_fhandle(const struct nfs_fh *fh, const char *caption)
{
	unsigned short i;

	if (fh == NULL || fh->size == 0) {
		printk(KERN_DEFAULT "%s at %p is empty\n", caption, fh);
		return;
	}

	printk(KERN_DEFAULT "%s at %p is %u bytes, crc: 0x%08x:\n",
	       caption, fh, fh->size, _nfs_display_fhandle_hash(fh));
	for (i = 0; i < fh->size; i += 16) {
		__be32 *pos = (__be32 *)&fh->data[i];

		switch ((fh->size - i - 1) >> 2) {
		case 0:
			printk(KERN_DEFAULT " %08x\n",
				be32_to_cpup(pos));
			break;
		case 1:
			printk(KERN_DEFAULT " %08x %08x\n",
				be32_to_cpup(pos), be32_to_cpup(pos + 1));
			break;
		case 2:
			printk(KERN_DEFAULT " %08x %08x %08x\n",
				be32_to_cpup(pos), be32_to_cpup(pos + 1),
				be32_to_cpup(pos + 2));
			break;
		default:
			printk(KERN_DEFAULT " %08x %08x %08x %08x\n",
				be32_to_cpup(pos), be32_to_cpup(pos + 1),
				be32_to_cpup(pos + 2), be32_to_cpup(pos + 3));
		}
	}
}
