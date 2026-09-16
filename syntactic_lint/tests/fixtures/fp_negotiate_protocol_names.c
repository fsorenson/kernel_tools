/*
 * Test fixture for syntactic_lint -- generated, do not edit.
 * Regenerate with: python3 -m syntactic_lint.tests.extract
 *
 * fs/smb/client/cifssmb.c at b4ea2789e060
 * b4ea2789e060 is b4ea2789e060 smb: client: don't count UNC prefix separators as symlink path levels
 *   CIFSSMBNegotiate()  lines 422-535
 */
int
CIFSSMBNegotiate(const unsigned int xid,
		 struct cifs_ses *ses,
		 struct TCP_Server_Info *server)
{
	SMB_NEGOTIATE_REQ *pSMB;
	SMB_NEGOTIATE_RSP *pSMBr;
	unsigned int in_len;
	int rc = 0;
	int bytes_returned;
	int i;
	u16 count;

	if (!server) {
		WARN(1, "%s: server is NULL!\n", __func__);
		return smb_EIO(smb_eio_trace_null_pointers);
	}

	rc = smb_init(SMB_COM_NEGOTIATE, 0, NULL /* no tcon yet */ ,
		      (void **) &pSMB, (void **) &pSMBr);
	if (rc < 0)
		return rc;
	in_len = rc;

	pSMB->hdr.Mid = get_next_mid(server);
	pSMB->hdr.Flags2 |= SMBFLG2_ERR_STATUS;

	if (ses->unicode != 0)
		pSMB->hdr.Flags2 |= SMBFLG2_UNICODE;

	if (should_set_ext_sec_flag(ses->sectype)) {
		cifs_dbg(FYI, "Requesting extended security\n");
		pSMB->hdr.Flags2 |= SMBFLG2_EXT_SEC;
	}

	count = 0;
	/*
	 * We know that all the name entries in the protocols array
	 * are short (< 16 bytes anyway) and are NUL terminated.
	 */
	for (i = 0; i < CIFS_NUM_PROT; i++) {
		size_t len = strlen(protocols[i].name) + 1;

		memcpy(&pSMB->DialectsArray[count], protocols[i].name, len);
		count += len;
	}
	in_len += count;
	pSMB->ByteCount = cpu_to_le16(count);

	rc = SendReceive(xid, ses, (struct smb_hdr *) pSMB, in_len,
			 (struct smb_hdr *) pSMBr, &bytes_returned, 0);
	if (rc != 0)
		goto neg_err_exit;

	server->dialect = le16_to_cpu(pSMBr->DialectIndex);
	cifs_dbg(FYI, "Dialect: %d\n", server->dialect);
	/* Check wct = 1 error case */
	if ((pSMBr->hdr.WordCount <= 13) || (server->dialect == BAD_PROT)) {
		/* core returns wct = 1, but we do not ask for core - otherwise
		small wct just comes when dialect index is -1 indicating we
		could not negotiate a common dialect */
		rc = -EOPNOTSUPP;
		goto neg_err_exit;
	} else if (pSMBr->hdr.WordCount != 17) {
		/* unknown wct */
		rc = -EOPNOTSUPP;
		goto neg_err_exit;
	}
	/* else wct == 17, NTLM or better */

	server->sec_mode = pSMBr->SecurityMode;
	if ((server->sec_mode & SECMODE_USER) == 0)
		cifs_dbg(FYI, "share mode security\n");

	/* one byte, so no need to convert this or EncryptionKeyLen from
	   little endian */
	server->maxReq = min_t(unsigned int, le16_to_cpu(pSMBr->MaxMpxCount),
			       cifs_max_pending);
	set_credits(server, server->maxReq);
	/* probably no need to store and check maxvcs */
	server->maxBuf = le32_to_cpu(pSMBr->MaxBufferSize);
	/* set up max_read for readahead check */
	server->max_read = server->maxBuf;
	server->max_rw = le32_to_cpu(pSMBr->MaxRawSize);
	cifs_dbg(NOISY, "Max buf = %d\n", ses->server->maxBuf);
	server->capabilities = le32_to_cpu(pSMBr->Capabilities);
	server->session_key_id = pSMBr->SessionKey;
	server->timeAdj = (int)(__s16)le16_to_cpu(pSMBr->ServerTimeZone);
	server->timeAdj *= 60;

	if (pSMBr->EncryptionKeyLength == CIFS_CRYPTO_KEY_SIZE) {
		server->negflavor = CIFS_NEGFLAVOR_UNENCAP;
		memcpy(ses->server->cryptkey, pSMBr->u.EncryptionKey,
		       CIFS_CRYPTO_KEY_SIZE);
	} else if (pSMBr->hdr.Flags2 & SMBFLG2_EXT_SEC ||
			server->capabilities & CAP_EXTENDED_SECURITY) {
		server->negflavor = CIFS_NEGFLAVOR_EXTENDED;
		rc = decode_ext_sec_blob(ses, pSMBr);
	} else if (server->sec_mode & SECMODE_PW_ENCRYPT) {
		/* no crypt key only if plain text pwd */
		rc = smb_EIO(smb_eio_trace_neg_no_crypt_key);
	} else {
		server->negflavor = CIFS_NEGFLAVOR_UNENCAP;
		server->capabilities &= ~CAP_EXTENDED_SECURITY;
	}

	if (!rc)
		rc = cifs_enable_signing(server, ses->sign);
neg_err_exit:
	cifs_buf_release(pSMB);

	cifs_dbg(FYI, "negprot rc %d\n", rc);
	return rc;
}
