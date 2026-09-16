/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/smb/client/reparse.c at 23c240d9509e^
 * 23c240d9509e is 23c240d9509e smb: client: validate absolute native symlink targets before NT fixups
 *   create_native_symlink()  lines 53-260
 */
static int create_native_symlink(const unsigned int xid, struct inode *inode,
				 struct dentry *dentry, struct cifs_tcon *tcon,
				 const char *full_path, const char *symname)
{
	struct reparse_symlink_data_buffer *buf = NULL;
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode);
	const char *symroot = cifs_sb->ctx->symlinkroot;
	struct cifs_open_info_data data = {};
	char sep = CIFS_DIR_SEP(cifs_sb);
	char *symlink_target = NULL;
	u16 len, plen, poff, slen;
	unsigned int sbflags;
	__le16 *path = NULL;
	struct inode *new;
	char *sym = NULL;
	struct kvec iov;
	bool directory;
	int path_len;
	int rc = 0;

	if (strlen(symname) > REPARSE_SYM_PATH_MAX)
		return -ENAMETOOLONG;

	symlink_target = kstrdup(symname, GFP_KERNEL);
	if (!symlink_target) {
		rc = -ENOMEM;
		goto out;
	}

	data = (struct cifs_open_info_data) {
		.reparse_point = true,
		.reparse = { .tag = IO_REPARSE_TAG_SYMLINK, },
		.symlink_target = symlink_target,
	};

	sbflags = cifs_sb_flags(cifs_sb);
	if (!(sbflags & CIFS_MOUNT_POSIX_PATHS) && symroot && symname[0] == '/') {
		/*
		 * This is a request to create an absolute symlink on the server
		 * which does not support POSIX paths, and expects symlink in
		 * NT-style path. So convert absolute Linux symlink target path
		 * to the absolute NT-style path. Root of the NT-style path for
		 * symlinks is specified in "symlinkroot" mount option. This will
		 * ensure compatibility of this symlink stored in absolute form
		 * on the SMB server.
		 */
		if (!strstarts(symname, symroot)) {
			/*
			 * If the absolute Linux symlink target path is not
			 * inside "symlinkroot" location then there is no way
			 * to convert such Linux symlink to NT-style path.
			 */
			cifs_dbg(VFS,
				 "absolute symlink '%s' cannot be converted to NT format "
				 "because it is outside of symlinkroot='%s'\n",
				 symname, symroot);
			rc = -EINVAL;
			goto out;
		}
		len = strlen(symroot);
		if (symroot[len - 1] != '/')
			len++;
		if (symname[len] >= 'a' && symname[len] <= 'z' &&
		    (symname[len+1] == '/' || symname[len+1] == '\0')) {
			/*
			 * Symlink points to Linux target /symlinkroot/x/path/...
			 * where 'x' is the lowercase local Windows drive.
			 * NT-style path for 'x' has common form \??\X:\path\...
			 * with uppercase local Windows drive.
			 */
			int common_path_len = strlen(symname+len+1)+1;
			sym = kzalloc(6+common_path_len, GFP_KERNEL);
			if (!sym) {
				rc = -ENOMEM;
				goto out;
			}
			memcpy(sym, "\\??\\", 4);
			sym[4] = symname[len] - ('a'-'A');
			sym[5] = ':';
			memcpy(sym+6, symname+len+1, common_path_len);
		} else {
			/* Unhandled absolute symlink. Report an error. */
			cifs_dbg(
				 VFS,
				 "absolute symlink '%s' cannot be converted to NT format "
				 "because it points to unknown target\n",
				 symname);
			rc = -EINVAL;
			goto out;
		}
	} else {
		/*
		 * This is request to either create an absolute symlink on
		 * server which expects POSIX paths or it is an request to
		 * create a relative symlink from the current directory.
		 * These paths have same format as relative SMB symlinks,
		 * so no conversion is needed. So just take symname as-is.
		 */
		sym = kstrdup(symname, GFP_KERNEL);
		if (!sym) {
			rc = -ENOMEM;
			goto out;
		}
	}

	if (sep == '\\')
		convert_delimiter(sym, sep);

	/*
	 * For absolute NT symlinks it is required to pass also leading
	 * backslash and to not mangle NT object prefix "\\??\\" and not to
	 * mangle colon in drive letter. But cifs_convert_path_to_utf16()
	 * removes leading backslash and replaces '?' and ':'. So temporary
	 * mask these characters in NT object prefix by '_' and then change
	 * them back.
	 */
	if (!(sbflags & CIFS_MOUNT_POSIX_PATHS) && symname[0] == '/')
		sym[0] = sym[1] = sym[2] = sym[5] = '_';

	/*
	 * On a POSIX paths mount the symlink target is stored verbatim, so
	 * convert it with cifs_strndup_to_utf16().  cifs_convert_path_to_utf16()
	 * must not be used here: it strips a leading path separator (it is
	 * meant for share-relative SMB paths), which would corrupt an absolute
	 * POSIX symlink target such as "/foo/bar".  Using NO_MAP_UNI_RSVD also
	 * matches the readback path in smb2_parse_native_symlink().
	 */
	if (sbflags & CIFS_MOUNT_POSIX_PATHS)
		path = cifs_strndup_to_utf16(sym, strlen(sym), &path_len,
					     cifs_sb->local_nls,
					     NO_MAP_UNI_RSVD);
	else
		path = cifs_convert_path_to_utf16(sym, cifs_sb);

	if (!path) {
		rc = -ENOMEM;
		goto out;
	}

	if (!(sbflags & CIFS_MOUNT_POSIX_PATHS) && symname[0] == '/') {
		sym[0] = '\\';
		sym[1] = sym[2] = '?';
		sym[5] = ':';
		path[0] = cpu_to_le16('\\');
		path[1] = path[2] = cpu_to_le16('?');
		path[5] = cpu_to_le16(':');
	}

	/*
	 * SMB distinguish between symlink to directory and symlink to file.
	 * They cannot be exchanged (symlink of file type which points to
	 * directory cannot be resolved and vice-versa). Try to detect if
	 * the symlink target could be a directory or not. When detection
	 * fails then treat symlink as a file (non-directory) symlink.
	 */
	directory = false;
	rc = detect_directory_symlink_target(cifs_sb, xid, full_path, symname, &directory);
	if (rc < 0)
		goto out;

	slen = 2 * UniStrnlen((wchar_t *)path, REPARSE_SYM_PATH_MAX);
	poff = 0;
	plen = slen;
	if (!(sbflags & CIFS_MOUNT_POSIX_PATHS) && symname[0] == '/') {
		/*
		 * For absolute NT symlinks skip leading "\\??\\" in PrintName as
		 * PrintName is user visible location in DOS/Win32 format (not in NT format).
		 */
		poff = 4;
		plen -= 2 * poff;
	}
	len = sizeof(*buf) + plen + slen;
	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	buf->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
	buf->ReparseDataLength = cpu_to_le16(len - sizeof(struct reparse_data_buffer));

	buf->SubstituteNameOffset = cpu_to_le16(plen);
	buf->SubstituteNameLength = cpu_to_le16(slen);
	memcpy(&buf->PathBuffer[plen], path, slen);

	buf->PrintNameOffset = 0;
	buf->PrintNameLength = cpu_to_le16(plen);
	memcpy(buf->PathBuffer, path+poff, plen);

	buf->Flags = cpu_to_le32(*symname != '/' ? SYMLINK_FLAG_RELATIVE : 0);

	iov.iov_base = buf;
	iov.iov_len = len;
	new = tcon->ses->server->ops->create_reparse_inode(
				     &data, inode->i_sb, xid,
				     tcon, full_path, directory,
				     &iov, NULL);
	if (!IS_ERR(new))
		d_instantiate(dentry, new);
	else
		rc = PTR_ERR(new);
out:
	kfree(sym);
	kfree(path);
	cifs_free_open_info(&data);
	kfree(buf);
	return rc;
}
