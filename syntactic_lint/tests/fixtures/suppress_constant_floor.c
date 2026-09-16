/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/isofs/joliet.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   get_joliet_filename()  lines 41-68
 */
int
get_joliet_filename(struct iso_directory_record * de, unsigned char *outname, struct inode * inode)
{
	struct nls_table *nls;
	unsigned char len = 0;

	nls = ISOFS_SB(inode->i_sb)->s_nls_iocharset;

	if (!nls) {
		len = utf16s_to_utf8s((const wchar_t *) de->name,
				de->name_len[0] >> 1, UTF16_BIG_ENDIAN,
				outname, PAGE_SIZE);
	} else {
		len = uni16_to_x8(outname, (__be16 *) de->name,
				de->name_len[0] >> 1, nls);
	}
	if ((len > 2) && (outname[len-2] == ';') && (outname[len-1] == '1'))
		len -= 2;

	/*
	 * Windows doesn't like periods at the end of a name,
	 * so neither do we
	 */
	while (len >= 2 && (outname[len-1] == '.'))
		len--;

	return len;
}
