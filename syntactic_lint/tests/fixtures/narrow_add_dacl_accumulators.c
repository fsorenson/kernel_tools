/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/smb/client/cifsacl.c at d05045177a85^
 * d05045177a85 is d05045177a85 smb: client: fail DACL rewrite when the new DACL exceeds 64K
 *   populate_new_aces()  lines 1096-1202
 *   replace_sids_and_copy_aces()  lines 1204-1246
 *   set_chmod_dacl()  lines 1248-1328
 */
static void populate_new_aces(char *nacl_base,
		struct smb_sid *pownersid,
		struct smb_sid *pgrpsid,
		__u64 *pnmode, u16 *pnum_aces, u16 *pnsize,
		bool modefromsid,
		bool posix)
{
	__u64 nmode;
	u16 num_aces = 0;
	u16 nsize = 0;
	__u64 user_mode;
	__u64 group_mode;
	__u64 other_mode;
	__u64 deny_user_mode = 0;
	__u64 deny_group_mode = 0;
	bool sticky_set = false;
	struct smb_ace *pnntace = NULL;

	nmode = *pnmode;
	num_aces = *pnum_aces;
	nsize = *pnsize;

	if (modefromsid || posix) {
		pnntace = (struct smb_ace *) (nacl_base + nsize);
		nsize += setup_special_mode_ACE(pnntace, posix, nmode);
		num_aces++;
		if (modefromsid) {
			pnntace = (struct smb_ace *) (nacl_base + nsize);
			nsize += setup_authusers_ACE(pnntace);
			num_aces++;
		}
		goto set_size;
	}

	/*
	 * We'll try to keep the mode as requested by the user.
	 * But in cases where we cannot meaningfully convert that
	 * into ACL, return back the updated mode, so that it is
	 * updated in the inode.
	 */

	if (!memcmp(pownersid, pgrpsid, sizeof(struct smb_sid))) {
		/*
		 * Case when owner and group SIDs are the same.
		 * Set the more restrictive of the two modes.
		 */
		user_mode = nmode & (nmode << 3) & 0700;
		group_mode = nmode & (nmode >> 3) & 0070;
	} else {
		user_mode = nmode & 0700;
		group_mode = nmode & 0070;
	}

	other_mode = nmode & 0007;

	/* We need DENY ACE when the perm is more restrictive than the next sets. */
	deny_user_mode = ~(user_mode) & ((group_mode << 3) | (other_mode << 6)) & 0700;
	deny_group_mode = ~(group_mode) & (other_mode << 3) & 0070;

	*pnmode = user_mode | group_mode | other_mode | (nmode & ~0777);

	/* This tells if we should allow delete child for group and everyone. */
	if (nmode & 01000)
		sticky_set = true;

	if (deny_user_mode) {
		pnntace = (struct smb_ace *) (nacl_base + nsize);
		nsize += fill_ace_for_sid(pnntace, pownersid, deny_user_mode,
				0700, ACCESS_DENIED, false);
		num_aces++;
	}

	/* Group DENY ACE does not conflict with owner ALLOW ACE. Keep in preferred order*/
	if (deny_group_mode && !(deny_group_mode & (user_mode >> 3))) {
		pnntace = (struct smb_ace *) (nacl_base + nsize);
		nsize += fill_ace_for_sid(pnntace, pgrpsid, deny_group_mode,
				0070, ACCESS_DENIED, false);
		num_aces++;
	}

	pnntace = (struct smb_ace *) (nacl_base + nsize);
	nsize += fill_ace_for_sid(pnntace, pownersid, user_mode,
			0700, ACCESS_ALLOWED, true);
	num_aces++;

	/* Group DENY ACE conflicts with owner ALLOW ACE. So keep it after. */
	if (deny_group_mode && (deny_group_mode & (user_mode >> 3))) {
		pnntace = (struct smb_ace *) (nacl_base + nsize);
		nsize += fill_ace_for_sid(pnntace, pgrpsid, deny_group_mode,
				0070, ACCESS_DENIED, false);
		num_aces++;
	}

	pnntace = (struct smb_ace *) (nacl_base + nsize);
	nsize += fill_ace_for_sid(pnntace, pgrpsid, group_mode,
			0070, ACCESS_ALLOWED, !sticky_set);
	num_aces++;

	pnntace = (struct smb_ace *) (nacl_base + nsize);
	nsize += fill_ace_for_sid(pnntace, &sid_everyone, other_mode,
			0007, ACCESS_ALLOWED, !sticky_set);
	num_aces++;

set_size:
	*pnum_aces = num_aces;
	*pnsize = nsize;
}

static __u16 replace_sids_and_copy_aces(struct smb_acl *pdacl, struct smb_acl *pndacl,
		struct smb_sid *pownersid, struct smb_sid *pgrpsid,
		struct smb_sid *pnownersid, struct smb_sid *pngrpsid,
		int *aclflag)
{
	int i;
	u16 size = 0;
	struct smb_ace *pntace = NULL;
	char *acl_base = NULL;
	u16 src_num_aces = 0;
	u16 nsize = 0;
	struct smb_ace *pnntace = NULL;
	char *nacl_base = NULL;
	u16 ace_size = 0;

	acl_base = (char *)pdacl;
	size = sizeof(struct smb_acl);
	src_num_aces = le16_to_cpu(pdacl->num_aces);

	nacl_base = (char *)pndacl;
	nsize = sizeof(struct smb_acl);

	/* Go through all the ACEs */
	for (i = 0; i < src_num_aces; ++i) {
		pntace = (struct smb_ace *) (acl_base + size);
		pnntace = (struct smb_ace *) (nacl_base + nsize);

		if (pnownersid && compare_sids(&pntace->sid, pownersid) == 0) {
			ace_size = cifs_copy_ace(pnntace, pntace, pnownersid);
			*aclflag |= CIFS_ACL_DACL;
		} else if (pngrpsid && compare_sids(&pntace->sid, pgrpsid) == 0) {
			ace_size = cifs_copy_ace(pnntace, pntace, pngrpsid);
			*aclflag |= CIFS_ACL_DACL;
		} else {
			ace_size = cifs_copy_ace(pnntace, pntace, NULL);
		}

		size += le16_to_cpu(pntace->size);
		nsize += ace_size;
	}

	return nsize;
}

static int set_chmod_dacl(struct smb_acl *pdacl, struct smb_acl *pndacl,
		struct smb_sid *pownersid,	struct smb_sid *pgrpsid,
		__u64 *pnmode, bool mode_from_sid, bool posix)
{
	int i;
	u16 size = 0;
	struct smb_ace *pntace = NULL;
	char *acl_base = NULL;
	u16 src_num_aces = 0;
	u16 nsize = 0;
	struct smb_ace *pnntace = NULL;
	char *nacl_base = NULL;
	u16 num_aces = 0;
	bool new_aces_set = false;

	/* Assuming that pndacl and pnmode are never NULL */
	nacl_base = (char *)pndacl;
	nsize = sizeof(struct smb_acl);

	/* If pdacl is NULL, we don't have a src. Simply populate new ACL. */
	if (!pdacl || posix) {
		populate_new_aces(nacl_base,
				pownersid, pgrpsid,
				pnmode, &num_aces, &nsize,
				mode_from_sid, posix);
		goto finalize_dacl;
	}

	acl_base = (char *)pdacl;
	size = sizeof(struct smb_acl);
	src_num_aces = le16_to_cpu(pdacl->num_aces);

	/* Retain old ACEs which we can retain */
	for (i = 0; i < src_num_aces; ++i) {
		pntace = (struct smb_ace *) (acl_base + size);

		if (!new_aces_set && (pntace->flags & INHERITED_ACE)) {
			/* Place the new ACEs in between existing explicit and inherited */
			populate_new_aces(nacl_base,
					pownersid, pgrpsid,
					pnmode, &num_aces, &nsize,
					mode_from_sid, posix);

			new_aces_set = true;
		}

		/* If it's any one of the ACE we're replacing, skip! */
		if (((compare_sids(&pntace->sid, &sid_unix_NFS_mode) == 0) ||
				(compare_sids(&pntace->sid, pownersid) == 0) ||
				(compare_sids(&pntace->sid, pgrpsid) == 0) ||
				(compare_sids(&pntace->sid, &sid_everyone) == 0) ||
				(compare_sids(&pntace->sid, &sid_authusers) == 0))) {
			goto next_ace;
		}

		/* update the pointer to the next ACE to populate*/
		pnntace = (struct smb_ace *) (nacl_base + nsize);

		nsize += cifs_copy_ace(pnntace, pntace, NULL);
		num_aces++;

next_ace:
		size += le16_to_cpu(pntace->size);
	}

	/* If inherited ACEs are not present, place the new ones at the tail */
	if (!new_aces_set) {
		populate_new_aces(nacl_base,
				pownersid, pgrpsid,
				pnmode, &num_aces, &nsize,
				mode_from_sid, posix);

		new_aces_set = true;
	}

finalize_dacl:
	pndacl->num_aces = cpu_to_le16(num_aces);
	pndacl->size = cpu_to_le16(nsize);

	return 0;
}
