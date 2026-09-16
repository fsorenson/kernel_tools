/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/ntfs3/inode.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   ntfs_create_inode()  lines 1372-1924
 */
/*
 * ntfs_create_inode
 *
 * Helper function for:
 * - ntfs_create
 * - ntfs_mknod
 * - ntfs_symlink
 * - ntfs_mkdir
 * - ntfs_atomic_open
 *
 * NOTE: if fnd != NULL (ntfs_atomic_open) then @dir is locked
 */
int ntfs_create_inode(struct mnt_idmap *idmap, struct inode *dir,
		      struct dentry *dentry, const struct cpu_str *uni,
		      umode_t mode, dev_t dev, const char *symname, u32 size,
		      struct ntfs_fnd *fnd)
{
	int err;
	struct super_block *sb = dir->i_sb;
	struct ntfs_sb_info *sbi = sb->s_fs_info;
	const struct qstr *name = &dentry->d_name;
	CLST ino = 0;
	struct ntfs_inode *dir_ni = ntfs_i(dir);
	struct ntfs_inode *ni = NULL;
	struct inode *inode = NULL;
	struct ATTRIB *attr;
	struct ATTR_STD_INFO5 *std5;
	struct ATTR_FILE_NAME *fname;
	struct MFT_REC *rec;
	u32 asize, dsize, sd_size;
	enum FILE_ATTRIBUTE fa;
	__le32 security_id = SECURITY_ID_INVALID;
	CLST vcn;
	const void *sd;
	u16 t16, nsize = 0, aid = 0;
	struct INDEX_ROOT *root, *dir_root;
	struct NTFS_DE *e, *new_de = NULL;
	struct REPARSE_DATA_BUFFER *rp = NULL;
	bool rp_inserted = false;

	/* New file will be resident or non resident. */
	const bool new_file_resident = 1;

	if (!fnd)
		ni_lock_dir(dir_ni);

	if (sbi->options->ads) {
		const char *ads = strchr(name->name + 1, ':');
		if (ads && ads[1]) {
			ntfs_warn(sb, "failed to create ads");
			err = -EINVAL;
			goto out1;
		}
	}

	dir_root = indx_get_root(&dir_ni->dir, dir_ni, NULL, NULL);
	if (!dir_root) {
		err = -EINVAL;
		goto out1;
	}

	if (S_ISDIR(mode)) {
		/* Use parent's directory attributes. */
		fa = dir_ni->std_fa | FILE_ATTRIBUTE_DIRECTORY |
		     FILE_ATTRIBUTE_ARCHIVE;
		/*
		 * By default child directory inherits parent attributes.
		 * Root directory is hidden + system.
		 * Make an exception for children in root.
		 */
		if (dir->i_ino == MFT_REC_ROOT)
			fa &= ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
	} else if (S_ISLNK(mode)) {
		/* It is good idea that link should be the same type (file/dir) as target */
		fa = FILE_ATTRIBUTE_REPARSE_POINT;

		/*
		 * Linux: there are dir/file/symlink and so on.
		 * NTFS: symlinks are "dir + reparse" or "file + reparse"
		 * It is good idea to create:
		 * dir + reparse if 'symname' points to directory
		 * or
		 * file + reparse if 'symname' points to file
		 * Unfortunately kern_path hangs if symname contains 'dir'.
		 */

		/*
		 *	struct path path;
		 *
		 *	if (!kern_path(symname, LOOKUP_FOLLOW, &path)){
		 *		struct inode *target = d_inode(path.dentry);
		 *
		 *		if (S_ISDIR(target->i_mode))
		 *			fa |= FILE_ATTRIBUTE_DIRECTORY;
		 *		// if ( target->i_sb == sb ){
		 *		//	use relative path?
		 *		// }
		 *		path_put(&path);
		 *	}
		 */
	} else if (S_ISREG(mode)) {
		if (sbi->options->sparse) {
			/* Sparsed regular file, cause option 'sparse'. */
			fa = FILE_ATTRIBUTE_SPARSE_FILE |
			     FILE_ATTRIBUTE_ARCHIVE;
		} else if (dir_ni->std_fa & FILE_ATTRIBUTE_COMPRESSED) {
			/* Compressed regular file, if parent is compressed. */
			fa = FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ARCHIVE;
		} else {
			/* Regular file, default attributes. */
			fa = FILE_ATTRIBUTE_ARCHIVE;
		}
	} else {
		fa = FILE_ATTRIBUTE_ARCHIVE;
	}

	/* If option "hide_dot_files" then set hidden attribute for dot files. */
	if (sbi->options->hide_dot_files && name->name[0] == '.')
		fa |= FILE_ATTRIBUTE_HIDDEN;

	if (!(mode & 0222))
		fa |= FILE_ATTRIBUTE_READONLY;

	new_de = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!new_de) {
		err = -ENOMEM;
		goto out1;
	}

	/* Avoid any operation if inode is bad. */
	if (unlikely(is_bad_ni(dir_ni))) {
		err = -EINVAL;
		goto out2;
	}

	if (unlikely(ntfs3_forced_shutdown(sb))) {
		err = -EIO;
		goto out2;
	}

	/* Mark rw ntfs as dirty. it will be cleared at umount. */
	ntfs_set_state(sbi, NTFS_DIRTY_DIRTY);

	/* Step 1: allocate and fill new mft record. */
	err = ntfs_look_free_mft(sbi, &ino, false, NULL, NULL);
	if (err)
		goto out2;

	ni = ntfs_new_inode(sbi, ino, S_ISDIR(mode) ? RECORD_FLAG_DIR : 0);
	if (IS_ERR(ni)) {
		err = PTR_ERR(ni);
		ni = NULL;
		goto out3;
	}
	inode = &ni->vfs_inode;
	inode_init_owner(idmap, inode, dir, mode);
	mode = inode->i_mode;

	ni->i_crtime = current_time(inode);

	rec = ni->mi.mrec;
	rec->hard_links = cpu_to_le16(1);
	attr = Add2Ptr(rec, le16_to_cpu(rec->attr_off));

	/* Get default security id. */
	sd = s_default_security;
	sd_size = sizeof(s_default_security);

	if (is_ntfs3(sbi)) {
		security_id = dir_ni->std_security_id;
		if (le32_to_cpu(security_id) < SECURITY_ID_FIRST) {
			security_id = sbi->security.def_security_id;

			if (security_id == SECURITY_ID_INVALID &&
			    !ntfs_insert_security(sbi, sd, sd_size,
						  &security_id, NULL))
				sbi->security.def_security_id = security_id;
		}
	}

	/* Insert standard info. */
	std5 = Add2Ptr(attr, SIZEOF_RESIDENT);

	if (security_id == SECURITY_ID_INVALID) {
		dsize = sizeof(struct ATTR_STD_INFO);
	} else {
		dsize = sizeof(struct ATTR_STD_INFO5);
		std5->security_id = security_id;
		ni->std_security_id = security_id;
	}
	asize = SIZEOF_RESIDENT + dsize;

	attr->type = ATTR_STD;
	attr->size = cpu_to_le32(asize);
	attr->id = cpu_to_le16(aid++);
	attr->res.data_off = SIZEOF_RESIDENT_LE;
	attr->res.data_size = cpu_to_le32(dsize);

	std5->cr_time = std5->m_time = std5->c_time = std5->a_time =
		kernel2nt(&ni->i_crtime);

	std5->fa = ni->std_fa = fa;

	attr = Add2Ptr(attr, asize);

	/* Insert file name. */
	err = fill_name_de(sbi, new_de, name, uni);
	if (err)
		goto out4;

	mi_get_ref(&ni->mi, &new_de->ref);

	fname = (struct ATTR_FILE_NAME *)(new_de + 1);

	if (sbi->options->windows_names &&
	    !valid_windows_name(sbi, (struct le_str *)&fname->name_len)) {
		err = -EINVAL;
		goto out4;
	}

	mi_get_ref(&dir_ni->mi, &fname->home);
	fname->dup.cr_time = fname->dup.m_time = fname->dup.c_time =
		fname->dup.a_time = std5->cr_time;
	fname->dup.alloc_size = fname->dup.data_size = 0;
	fname->dup.fa = std5->fa;
	fname->dup.extend_data = S_ISLNK(mode) ? IO_REPARSE_TAG_SYMLINK : 0;

	dsize = le16_to_cpu(new_de->key_size);
	asize = ALIGN(SIZEOF_RESIDENT + dsize, 8);

	attr->type = ATTR_NAME;
	attr->size = cpu_to_le32(asize);
	attr->res.data_off = SIZEOF_RESIDENT_LE;
	attr->res.flags = RESIDENT_FLAG_INDEXED;
	attr->id = cpu_to_le16(aid++);
	attr->res.data_size = cpu_to_le32(dsize);
	memcpy(Add2Ptr(attr, SIZEOF_RESIDENT), fname, dsize);

	attr = Add2Ptr(attr, asize);

	if (security_id == SECURITY_ID_INVALID) {
		/* Insert security attribute. */
		asize = SIZEOF_RESIDENT + ALIGN(sd_size, 8);

		attr->type = ATTR_SECURE;
		attr->size = cpu_to_le32(asize);
		attr->id = cpu_to_le16(aid++);
		attr->res.data_off = SIZEOF_RESIDENT_LE;
		attr->res.data_size = cpu_to_le32(sd_size);
		memcpy(Add2Ptr(attr, SIZEOF_RESIDENT), sd, sd_size);

		attr = Add2Ptr(attr, asize);
	}

	attr->id = cpu_to_le16(aid++);
	if (fa & FILE_ATTRIBUTE_DIRECTORY) {
		/*
		 * Regular directory or symlink to directory.
		 * Create root attribute.
		 */
		dsize = sizeof(struct INDEX_ROOT) + sizeof(struct NTFS_DE);
		asize = sizeof(I30_NAME) + SIZEOF_RESIDENT + dsize;

		attr->type = ATTR_ROOT;
		attr->size = cpu_to_le32(asize);

		attr->name_len = ARRAY_SIZE(I30_NAME);
		attr->name_off = SIZEOF_RESIDENT_LE;
		attr->res.data_off =
			cpu_to_le16(sizeof(I30_NAME) + SIZEOF_RESIDENT);
		attr->res.data_size = cpu_to_le32(dsize);
		memcpy(Add2Ptr(attr, SIZEOF_RESIDENT), I30_NAME,
		       sizeof(I30_NAME));

		root = Add2Ptr(attr, sizeof(I30_NAME) + SIZEOF_RESIDENT);
		memcpy(root, dir_root, offsetof(struct INDEX_ROOT, ihdr));
		root->ihdr.de_off = cpu_to_le32(sizeof(struct INDEX_HDR));
		root->ihdr.used = cpu_to_le32(sizeof(struct INDEX_HDR) +
					      sizeof(struct NTFS_DE));
		root->ihdr.total = root->ihdr.used;

		e = Add2Ptr(root, sizeof(struct INDEX_ROOT));
		e->size = cpu_to_le16(sizeof(struct NTFS_DE));
		e->flags = NTFS_IE_LAST;
	} else if (S_ISLNK(mode)) {
		/*
		 * Symlink to file.
		 * Create empty resident data attribute.
		 */
		asize = SIZEOF_RESIDENT;

		/* Insert empty ATTR_DATA */
		attr->type = ATTR_DATA;
		attr->size = cpu_to_le32(SIZEOF_RESIDENT);
		attr->name_off = SIZEOF_RESIDENT_LE;
		attr->res.data_off = SIZEOF_RESIDENT_LE;
	} else if (!new_file_resident && S_ISREG(mode)) {
		/*
		 * Regular file. Create empty non resident data attribute.
		 */
		attr->type = ATTR_DATA;
		attr->non_res = 1;
		attr->nres.evcn = cpu_to_le64(-1ll);
		if (fa & FILE_ATTRIBUTE_SPARSE_FILE) {
			attr->size = cpu_to_le32(SIZEOF_NONRESIDENT_EX + 8);
			attr->name_off = SIZEOF_NONRESIDENT_EX_LE;
			attr->flags = ATTR_FLAG_SPARSED;
			asize = SIZEOF_NONRESIDENT_EX + 8;
		} else if (fa & FILE_ATTRIBUTE_COMPRESSED) {
			attr->size = cpu_to_le32(SIZEOF_NONRESIDENT_EX + 8);
			attr->name_off = SIZEOF_NONRESIDENT_EX_LE;
			attr->flags = ATTR_FLAG_COMPRESSED;
			attr->nres.c_unit = NTFS_LZNT_CUNIT;
			asize = SIZEOF_NONRESIDENT_EX + 8;
		} else {
			attr->size = cpu_to_le32(SIZEOF_NONRESIDENT + 8);
			attr->name_off = SIZEOF_NONRESIDENT_LE;
			asize = SIZEOF_NONRESIDENT + 8;
		}
		attr->nres.run_off = attr->name_off;
	} else {
		/*
		 * Node. Create empty resident data attribute.
		 */
		attr->type = ATTR_DATA;
		attr->size = cpu_to_le32(SIZEOF_RESIDENT);
		attr->name_off = SIZEOF_RESIDENT_LE;
		if (fa & FILE_ATTRIBUTE_SPARSE_FILE)
			attr->flags = ATTR_FLAG_SPARSED;
		else if (fa & FILE_ATTRIBUTE_COMPRESSED)
			attr->flags = ATTR_FLAG_COMPRESSED;
		attr->res.data_off = SIZEOF_RESIDENT_LE;
		asize = SIZEOF_RESIDENT;
		ni->ni_flags |= NI_FLAG_RESIDENT;
	}

	if (S_ISDIR(mode)) {
		ni->ni_flags |= NI_FLAG_DIR;
		err = indx_init(&ni->dir, sbi, attr, INDEX_MUTEX_I30);
		if (err)
			goto out4;
	} else if (S_ISLNK(mode)) {
		rp = ntfs_create_reparse_buffer(sbi, symname, size, &nsize);

		if (IS_ERR(rp)) {
			err = PTR_ERR(rp);
			rp = NULL;
			goto out4;
		}

		/*
		 * Insert ATTR_REPARSE.
		 */
		attr = Add2Ptr(attr, asize);
		attr->type = ATTR_REPARSE;
		attr->id = cpu_to_le16(aid++);

		/* Resident or non resident? */
		asize = ALIGN(SIZEOF_RESIDENT + nsize, 8);
		t16 = PtrOffset(rec, attr);

		/*
		 * Below function 'ntfs_save_wsl_perm' requires 0x78 bytes.
		 * It is good idea to keep extended attributes resident.
		 */
		if (asize + t16 + 0x78 + 8 > sbi->record_size) {
			CLST alen;
			CLST clst = bytes_to_cluster(sbi, nsize);

			/* Bytes per runs. */
			t16 = sbi->record_size - t16 - SIZEOF_NONRESIDENT;

			attr->non_res = 1;
			attr->nres.evcn = cpu_to_le64(clst - 1);
			attr->name_off = SIZEOF_NONRESIDENT_LE;
			attr->nres.run_off = attr->name_off;
			attr->nres.data_size = cpu_to_le64(nsize);
			attr->nres.valid_size = attr->nres.data_size;
			attr->nres.alloc_size =
				cpu_to_le64(ntfs_up_cluster(sbi, nsize));

			err = attr_allocate_clusters(sbi, &ni->file.run, NULL,
						     0, 0, clst, NULL,
						     ALLOCATE_DEF, &alen, 0,
						     NULL, NULL);
			if (err)
				goto out5;

			err = run_pack(&ni->file.run, 0, clst,
				       Add2Ptr(attr, SIZEOF_NONRESIDENT), t16,
				       &vcn);
			if (err < 0)
				goto out5;

			if (vcn != clst) {
				err = -EINVAL;
				goto out5;
			}

			asize = SIZEOF_NONRESIDENT + ALIGN(err, 8);
			/* Write non resident data. */
			err = ntfs_sb_write_run(sbi, &ni->file.run, 0, rp,
						nsize, 0);
			if (err)
				goto out5;
		} else {
			attr->res.data_off = SIZEOF_RESIDENT_LE;
			attr->res.data_size = cpu_to_le32(nsize);
			memcpy(Add2Ptr(attr, SIZEOF_RESIDENT), rp, nsize);
		}
		/* Size of symlink equals the length of input string. */
		inode->i_size = size;

		attr->size = cpu_to_le32(asize);

		err = ntfs_insert_reparse(sbi, IO_REPARSE_TAG_SYMLINK,
					  &new_de->ref);
		if (err)
			goto out5;

		rp_inserted = true;
	}

	attr = Add2Ptr(attr, asize);
	attr->type = ATTR_END;

	rec->used = cpu_to_le32(PtrOffset(rec, attr) + 8);
	rec->next_attr_id = cpu_to_le16(aid);

	inode->i_generation = le16_to_cpu(rec->seq);

	if (S_ISDIR(mode)) {
		inode->i_op = &ntfs_dir_inode_operations;
		inode->i_fop = &ntfs_dir_operations;
	} else if (S_ISLNK(mode)) {
		inode->i_op = &ntfs_link_inode_operations;
		inode->i_fop = NULL;
		inode->i_mapping->a_ops = &ntfs_aops;
		inode->i_size = size;
		inode_nohighmem(inode);
	} else if (S_ISREG(mode)) {
		inode->i_op = &ntfs_file_inode_operations;
		inode->i_fop = &ntfs_file_operations;
		inode->i_mapping->a_ops = is_compressed(ni) ? &ntfs_aops_cmpr :
							      &ntfs_aops;
		init_rwsem(&ni->file.run_lock);
	} else {
		inode->i_op = &ntfs_special_inode_operations;
		init_special_inode(inode, mode, dev);
	}

#ifdef CONFIG_NTFS3_FS_POSIX_ACL
	if (!S_ISLNK(mode) && (sb->s_flags & SB_POSIXACL)) {
		err = ntfs_init_acl(idmap, inode, dir);
		if (err)
			goto out5;
	} else
#endif
	{
		inode->i_flags |= S_NOSEC;
	}

	if (!S_ISLNK(mode)) {
		/*
		 * ntfs_init_acl and ntfs_save_wsl_perm update extended attribute.
		 * The packed size of extended attribute is stored in direntry too.
		 * 'fname' here points to inside new_de.
		 */
		err = ntfs_save_wsl_perm(inode, &fname->dup.extend_data);
		if (err)
			goto out6;

		/*
		 * update ea_size in file_name attribute too.
		 * Use ni_find_attr cause layout of MFT record may be changed
		 * in ntfs_init_acl and ntfs_save_wsl_perm.
		 */
		attr = ni_find_attr(ni, NULL, NULL, ATTR_NAME, NULL, 0, NULL,
				    NULL);
		if (attr) {
			struct ATTR_FILE_NAME *fn;

			fn = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
			if (fn)
				fn->dup.extend_data = fname->dup.extend_data;
		}
	}

	/* We do not need to update parent directory later */
	ni->ni_flags &= ~NI_FLAG_UPDATE_PARENT;

	/* Step 2: Add new name in index. */
	err = indx_insert_entry(&dir_ni->dir, dir_ni, new_de, sbi, fnd, 0);
	if (err)
		goto out6;

	/*
	 * Call 'd_instantiate' after inode->i_op is set
	 * but before finish_open.
	 */
	d_instantiate(dentry, inode);

	/* Set original time. inode times (i_ctime) may be changed in ntfs_init_acl. */
	inode_set_atime_to_ts(inode, ni->i_crtime);
	inode_set_ctime_to_ts(inode, ni->i_crtime);
	inode_set_mtime_to_ts(inode, ni->i_crtime);
	inode_set_mtime_to_ts(dir, ni->i_crtime);
	inode_set_ctime_to_ts(dir, ni->i_crtime);

	mark_inode_dirty(dir);
	mark_inode_dirty(inode);

	/* Normal exit. */
	goto out2;

out6:
	attr = ni_find_attr(ni, NULL, NULL, ATTR_EA, NULL, 0, NULL, NULL);
	if (attr && attr->non_res) {
		/* Delete ATTR_EA, if non-resident. */
		struct runs_tree run;
		run_init(&run);
		attr_set_size(ni, ATTR_EA, NULL, 0, &run, 0, NULL, false);
		run_close(&run);
	}

	if (rp_inserted)
		ntfs_remove_reparse(sbi, IO_REPARSE_TAG_SYMLINK, &new_de->ref);

out5:
	if (!S_ISDIR(mode))
		run_deallocate(sbi, &ni->file.run, false);

out4:
	clear_rec_inuse(rec);
	clear_nlink(inode);
	ni->mi.dirty = false;
	discard_new_inode(inode);
out3:
	ntfs_mark_rec_free(sbi, ino, false);

out2:
	kfree(new_de);
	kfree(rp);

out1:
	if (!fnd)
		ni_unlock(dir_ni);

	if (!err)
		unlock_new_inode(inode);

	return err;
}
