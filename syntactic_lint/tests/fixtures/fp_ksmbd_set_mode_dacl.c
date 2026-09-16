/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/smb/server/smbacl.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   set_posix_acl_entries_dacl()  lines 622-751
 *   set_mode_dacl()  lines 812-874
 */
static void set_posix_acl_entries_dacl(struct mnt_idmap *idmap,
				       struct smb_ace *pndace,
				       struct smb_fattr *fattr, u16 *num_aces,
				       u16 *size, u16 existing_nt_aces,
				       bool had_nt_aces)
{
	struct posix_acl_entry *pace;
	struct smb_sid *sid;
	struct smb_ace *ntace;
	int i, j;
	u16 ace_sz;

	if (!fattr->cf_acls)
		goto posix_default_acl;

	pace = fattr->cf_acls->a_entries;
	for (i = 0; i < fattr->cf_acls->a_count; i++, pace++) {
		int flags = 0;

		sid = kmalloc_obj(struct smb_sid, KSMBD_DEFAULT_GFP);
		if (!sid)
			break;

		if (pace->e_tag == ACL_USER) {
			uid_t uid;
			unsigned int sid_type = SIDOWNER;

			uid = posix_acl_uid_translate(idmap, pace);
			if (!uid)
				sid_type = SIDUNIX_USER;
			id_to_sid(uid, sid_type, sid);
		} else if (pace->e_tag == ACL_GROUP) {
			gid_t gid;

			gid = posix_acl_gid_translate(idmap, pace);
			id_to_sid(gid, SIDUNIX_GROUP, sid);
		} else if (pace->e_tag == ACL_OTHER && !had_nt_aces) {
			smb_copy_sid(sid, &sid_everyone);
		} else {
			kfree(sid);
			continue;
		}
		ntace = pndace;
		for (j = 0; j < existing_nt_aces; j++) {
			if (ntace->sid.sub_auth[ntace->sid.num_subauth - 1] ==
					sid->sub_auth[sid->num_subauth - 1])
				goto pass_same_sid;
			ntace = (struct smb_ace *)((char *)ntace +
					le16_to_cpu(ntace->size));
		}

		if (S_ISDIR(fattr->cf_mode) && pace->e_tag == ACL_OTHER)
			flags = 0x03;

		ntace = (struct smb_ace *)((char *)pndace + *size);
		ace_sz = fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED, flags,
				pace->e_perm, 0777);
		if (check_add_overflow(*size, ace_sz, size)) {
			*size -= ace_sz;
			kfree(sid);
			break;
		}
		(*num_aces)++;
		if (pace->e_tag == ACL_USER)
			ntace->access_req |=
				FILE_DELETE_LE | FILE_DELETE_CHILD_LE;

		if (S_ISDIR(fattr->cf_mode) &&
		    (pace->e_tag == ACL_USER || pace->e_tag == ACL_GROUP)) {
			ntace = (struct smb_ace *)((char *)pndace + *size);
			ace_sz = fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED,
					0x03, pace->e_perm, 0777);
			if (check_add_overflow(*size, ace_sz, size)) {
				*size -= ace_sz;
				kfree(sid);
				break;
			}
			(*num_aces)++;
			if (pace->e_tag == ACL_USER)
				ntace->access_req |=
					FILE_DELETE_LE | FILE_DELETE_CHILD_LE;
		}

pass_same_sid:
		kfree(sid);
	}

	if (had_nt_aces)
		return;

posix_default_acl:
	if (!fattr->cf_dacls)
		return;

	pace = fattr->cf_dacls->a_entries;
	for (i = 0; i < fattr->cf_dacls->a_count; i++, pace++) {
		sid = kmalloc_obj(struct smb_sid, KSMBD_DEFAULT_GFP);
		if (!sid)
			break;

		if (pace->e_tag == ACL_USER) {
			uid_t uid;

			uid = posix_acl_uid_translate(idmap, pace);
			id_to_sid(uid, SIDCREATOR_OWNER, sid);
		} else if (pace->e_tag == ACL_GROUP) {
			gid_t gid;

			gid = posix_acl_gid_translate(idmap, pace);
			id_to_sid(gid, SIDCREATOR_GROUP, sid);
		} else {
			kfree(sid);
			continue;
		}

		ntace = (struct smb_ace *)((char *)pndace + *size);
		ace_sz = fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED, 0x0b,
				pace->e_perm, 0777);
		if (check_add_overflow(*size, ace_sz, size)) {
			*size -= ace_sz;
			kfree(sid);
			break;
		}
		(*num_aces)++;
		if (pace->e_tag == ACL_USER)
			ntace->access_req |=
				FILE_DELETE_LE | FILE_DELETE_CHILD_LE;
		kfree(sid);
	}
}

static void set_mode_dacl(struct mnt_idmap *idmap,
			  struct smb_acl *pndacl, struct smb_fattr *fattr)
{
	struct smb_ace *pace, *pndace;
	u16 num_aces = 0;
	u16 size = 0, ace_size = 0;
	uid_t uid;
	const struct smb_sid *sid;

	pace = pndace = (struct smb_ace *)((char *)pndacl + sizeof(struct smb_acl));

	if (fattr->cf_acls) {
		set_posix_acl_entries_dacl(idmap, pndace, fattr,
					   &num_aces, &size, num_aces, false);
		goto out;
	}

	/* owner RID */
	uid = from_kuid(&init_user_ns, fattr->cf_uid);
	if (uid)
		sid = &server_conf.domain_sid;
	else
		sid = &sid_unix_users;
	ace_size = fill_ace_for_sid(pace, sid, ACCESS_ALLOWED, 0,
				    fattr->cf_mode, 0700);
	pace->sid.sub_auth[pace->sid.num_subauth++] = cpu_to_le32(uid);
	pace->size = cpu_to_le16(ace_size + 4);
	size += le16_to_cpu(pace->size);
	pace = (struct smb_ace *)((char *)pndace + size);

	/* Group RID */
	ace_size = fill_ace_for_sid(pace, &sid_unix_groups,
				    ACCESS_ALLOWED, 0, fattr->cf_mode, 0070);
	pace->sid.sub_auth[pace->sid.num_subauth++] =
		cpu_to_le32(from_kgid(&init_user_ns, fattr->cf_gid));
	pace->size = cpu_to_le16(ace_size + 4);
	size += le16_to_cpu(pace->size);
	pace = (struct smb_ace *)((char *)pndace + size);
	num_aces = 3;

	if (S_ISDIR(fattr->cf_mode)) {
		pace = (struct smb_ace *)((char *)pndace + size);

		/* creator owner */
		size += fill_ace_for_sid(pace, &creator_owner, ACCESS_ALLOWED,
					 0x0b, fattr->cf_mode, 0700);
		pace = (struct smb_ace *)((char *)pndace + size);

		/* creator group */
		size += fill_ace_for_sid(pace, &creator_group, ACCESS_ALLOWED,
					 0x0b, fattr->cf_mode, 0070);
		pace = (struct smb_ace *)((char *)pndace + size);
		num_aces = 5;
	}

	/* other */
	size += fill_ace_for_sid(pace, &sid_everyone, ACCESS_ALLOWED, 0,
				 fattr->cf_mode, 0007);

out:
	pndacl->num_aces = cpu_to_le16(num_aces);
	pndacl->size = cpu_to_le16(le16_to_cpu(pndacl->size) + size);
}
