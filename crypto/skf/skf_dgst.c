/* crypto/skf/skf_dgst.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/skf.h>
#include <openssl/skf_ex.h>
#include "skf_lcl.h"


ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phHash)
{
	ULONG ret = SAR_FAIL;
	const EVP_MD *md;
	EVP_MD_CTX *mdctx = NULL;
	EC_KEY *ec_key = NULL;
	SKF_HANDLE *hHash;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen = 0;

	switch (ulAlgID) {
	case SGD_SM3:
		md = EVP_sm3();
		break;
	case SGD_SHA1:
		md = EVP_sha1();
		break;
	case SGD_SHA256:
		md = EVP_sha256();
		break;
	default:
		SKFerr(SKF_F_SKF_DIGESTINIT, SKF_R_INVALID_ALGID);
		return SAR_INVALIDPARAMERR;
	}

	if (!(mdctx = EVP_MD_CTX_create())) {
		SKFerr(SKF_F_SKF_DIGESTINIT, SKF_R_MALLOC_FAILED);
		return SAR_FAIL;
	}

	if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
		SKFerr(SKF_F_SKF_DIGESTINIT, ERR_R_EVP_LIB);
		goto end;
	}

	if (pPubKey) {

		if (!(ec_key = EC_KEY_new_from_ECCPUBLICKEYBLOB(pPubKey))) {
			SKFerr(SKF_F_SKF_DIGESTINIT, SKF_R_INVALID_BLOB);
			ret = SAR_INVALIDPARAMERR;
			goto end;
		}

		if (pbID) {
			if (ulIDLen <= 0 || ulIDLen > SM2_MAX_ID_LENGTH) {
				SKFerr(SKF_F_SKF_DIGESTINIT, SKF_R_INVALID_ID_LENGTH);
				ret = SAR_INVALIDPARAMERR;
				goto end;
			}

			OPENSSL_assert(strlen((char *)pbID) == ulIDLen);
			if (!SM2_set_id(ec_key, (char *)pbID)) {
				SKFerr(SKF_F_SKF_DIGESTINIT, ERR_R_SM2_LIB);
				ret = SAR_FAIL;
				goto end;
			}
		}

		dgstlen = sizeof(dgst);
		if (!SM2_compute_id_digest(md, dgst, &dgstlen, ec_key)) {
			SKFerr(SKF_F_SKF_DIGESTINIT, ERR_R_SM2_LIB);
			goto end;
		}

		if (!EVP_DigestUpdate(mdctx, dgst, dgstlen)) {
			goto end;
		}

	} else {
		if (pbID) {
			SKFerr(SKF_F_SKF_DIGESTINIT, SKF_R_NO_PUBLIC_KEY);
			ret = SAR_INVALIDPARAMERR;
			goto end;
		}
	}


	if (!(hHash = OPENSSL_malloc(sizeof(*hHash)))) {
		SKFerr(SKF_F_SKF_DIGESTINIT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	memset(hHash, 0, sizeof(*hHash));
	hHash->magic = SKF_HANDLE_MAGIC;
	hHash->type = SKF_HASH_HANDLE;
	hHash->u.md_ctx = mdctx;
	mdctx = NULL;

	*phHash = hHash;
	ret = SAR_OK;
end:
	EVP_MD_CTX_destroy(mdctx);
	EC_KEY_free(ec_key);
	return ret;
}


ULONG DEVAPI SKF_DigestUpdate(HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen)
{
	EVP_MD_CTX *md_ctx;

	if (!(md_ctx = SKF_HANDLE_get_md_ctx(hHash))) {
		SKFerr(SKF_F_SKF_DIGESTUPDATE, SKF_R_INVALID_HASH_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	if (!pbData) {
		SKFerr(SKF_F_SKF_DIGESTUPDATE, SKF_R_INVALID_ARGUMENTS);
		return SAR_INVALIDPARAMERR;
	}

	if (ulDataLen == 0) {
		return SAR_OK;
	}

	if (!EVP_DigestUpdate(md_ctx, pbData, ulDataLen)) {
		SKFerr(SKF_F_SKF_DIGESTUPDATE, ERR_R_EVP_LIB);
		return SAR_FAIL;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DigestFinal(HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen)
{
	EVP_MD_CTX *mdctx;

	if (!(mdctx = SKF_HANDLE_get_md_ctx(hHash))) {
		SKFerr(SKF_F_SKF_DIGESTFINAL, SKF_R_INVALID_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	if (!pulHashLen) {
		SKFerr(SKF_F_SKF_DIGESTFINAL, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	if (!EVP_DigestFinal_ex(mdctx, pHashData, pulHashLen)) {
		SKFerr(SKF_F_SKF_DIGESTFINAL, ERR_R_EVP_LIB);
		return SAR_FAIL;
	}

	EVP_MD_CTX_destroy(mdctx);
	((SKF_HANDLE *)hHash)->u.md_ctx = NULL;
	return SAR_OK;
}

ULONG DEVAPI SKF_Digest(HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen)
{
	ULONG rv;

	if ((rv = SKF_DigestUpdate(hHash, pbData, ulDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DIGEST, ERR_R_SKF_LIB);
		return rv;
	}

	if ((rv = SKF_DigestFinal(hHash, pbHashData, pulHashLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DIGEST, ERR_R_SKF_LIB);
		return rv;
	}

	return SAR_OK;
}

