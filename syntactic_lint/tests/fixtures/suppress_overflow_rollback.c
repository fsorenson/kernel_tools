/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/smb/server/smbacl.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   set_ntacl_dacl()  lines 753-810
 */
static void set_ntacl_dacl(struct mnt_idmap *idmap,
			   struct smb_acl *pndacl,
			   struct smb_acl *nt_dacl,
			   unsigned int aces_size,
			   const struct smb_sid *pownersid,
			   const struct smb_sid *pgrpsid,
			   struct smb_fattr *fattr)
{
	struct smb_ace *ntace, *pndace;
	u16 nt_num_aces = le16_to_cpu(nt_dacl->num_aces), num_aces = 0;
	u16 copied_nt_aces;
	unsigned short size = 0;
	int i;

	pndace = (struct smb_ace *)((char *)pndacl + sizeof(struct smb_acl));
	if (nt_num_aces) {
		ntace = (struct smb_ace *)((char *)nt_dacl + sizeof(struct smb_acl));
		for (i = 0; i < nt_num_aces; i++) {
			unsigned short nt_ace_size;

			if (aces_size < offsetof(struct smb_ace, sid) +
					CIFS_SID_BASE_SIZE)
				break;

			nt_ace_size = le16_to_cpu(ntace->size);
			if (nt_ace_size > aces_size ||
			    nt_ace_size < offsetof(struct smb_ace, sid) +
					  CIFS_SID_BASE_SIZE)
				break;

			if (ntace->sid.num_subauth == 0 ||
			    ntace->sid.num_subauth > SID_MAX_SUB_AUTHORITIES ||
			    nt_ace_size < offsetof(struct smb_ace, sid) +
					  CIFS_SID_BASE_SIZE +
					  sizeof(__le32) *
					  ntace->sid.num_subauth)
				goto next_ace;

			memcpy((char *)pndace + size, ntace, nt_ace_size);
			if (check_add_overflow(size, nt_ace_size, &size)) {
				size -= nt_ace_size;
				break;
			}
			num_aces++;

next_ace:
			aces_size -= nt_ace_size;
			ntace = (struct smb_ace *)((char *)ntace + nt_ace_size);
		}
	}

	copied_nt_aces = num_aces;
	set_posix_acl_entries_dacl(idmap, pndace, fattr,
				   &num_aces, &size, copied_nt_aces,
				   nt_num_aces != 0);
	pndacl->num_aces = cpu_to_le16(num_aces);
	pndacl->size = cpu_to_le16(le16_to_cpu(pndacl->size) + size);
}
