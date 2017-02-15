/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES
 * LOSS OF USE, DATA, OR PROFITS OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/gmsdf.h>
#include "sdf_lcl.h"

int SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	int ret = SDR_UNKNOWERR;
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	EVP_MD_CTX *md_ctx = NULL;
	const EVP_MD *md;

	/* check arguments */
	if (!hSessionHandle) {
		SDFerr(SDF_F_SDF_HASHINIT, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_INARGERR;
	}
	if (pucID && (uiIDLength <= 0 || uiIDLength > INT_MAX)) {
		SDFerr(SDF_F_SDF_HASHINIT, SDF_R_INVALID_LENGTH);
		return SDR_INARGERR;
	}
	if (session->md_ctx) {
		SDFerr(SDF_F_SDF_HASHINIT, SDF_R_INVALID_OPERATION_STATE);
		return SDR_INARGERR;
	}
	if (!(md = EVP_get_digestbysgd(uiAlgID))) {
		SDFerr(SDF_F_SDF_HASHINIT, SDF_R_INVALID_ALGOR);
		return SDR_INARGERR;
	}

	/* malloc and init */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		SDFerr(SDF_F_SDF_HASHINIT, ERR_R_MALLOC_FAILURE);
		ret = SDR_NOBUFFER;
		goto end;
	}
	if (!EVP_DigestInit_ex(md_ctx, md, session->engine)) {
		SDFerr(SDF_F_SDF_HASHINIT, ERR_R_EVP_LIB);
		ret = SDR_UNKNOWERR;
		goto end;
	}

	/* compute ZA and update */
	if (pucPublicKey) {
		EC_KEY *ec_key = NULL;
		unsigned char za[EVP_MAX_MD_SIZE];
		size_t zalen = sizeof(za);
		char *id;
		size_t idlen;

		if (pucID) {
			id = (char *)pucID;
			idlen = uiIDLength;
		} else {
			id = SM2_DEFAULT_ID;
			idlen = strlen(SM2_DEFAULT_ID);
		}

		if (!(ec_key = EC_KEY_new_from_ECCrefPublicKey(pucPublicKey))) {
			SDFerr(SDF_F_SDF_HASHINIT, ERR_R_GMAPI_LIB);
			ret = SDR_INARGERR;
			goto end;
		}

		if (!SM2_compute_id_digest(md, id, idlen, za, &zalen, ec_key)) {
			SDFerr(SDF_F_SDF_HASHINIT,
				SDF_R_COMPUTE_SM2_ID_FAILURE);
			ret = SDR_UNKNOWERR;
			EC_KEY_free(ec_key);
			goto end;
		}

		EC_KEY_free(ec_key);

		if (!EVP_DigestUpdate(md_ctx, za, zalen)) {
			SDFerr(SDF_F_SDF_HASHINIT, ERR_R_EVP_LIB);
			ret = SDR_UNKNOWERR;
			goto end;
		}
	}

	session->md_ctx = md_ctx;
	md_ctx = NULL;
	ret = SDR_OK;

end:
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

int SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;

	/* check arguments */
	if (!hSessionHandle || !pucData) {
		SDFerr(SDF_F_SDF_HASHUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_INARGERR;
	}
	if (session->magic != SDF_SESSION_MAGIC) {
		SDFerr(SDF_F_SDF_HASHUPDATE, SDF_R_INVALID_SESSION);
		return SDR_INARGERR;
	}
	if (!session->md_ctx) {
		SDFerr(SDF_F_SDF_HASHUPDATE, SDF_R_INVALID_OPERATION_STATE);
		return SDR_INARGERR;
	}

	/* update */
	if (!EVP_DigestUpdate(session->md_ctx, pucData, (size_t)uiDataLength)) {
		SDFerr(SDF_F_SDF_HASHUPDATE, ERR_R_EVP_LIB);
		return SDR_UNKNOWERR;
	}

	return SDR_OK;
}

int SDF_HashFinal(
	void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength)
{
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;

	/* check arguments */
	if (!hSessionHandle || !pucHash || !puiHashLength) {
		SDFerr(SDF_F_SDF_HASHFINAL, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_INARGERR;
	}
	if (session->magic != SDF_SESSION_MAGIC) {
		SDFerr(SDF_F_SDF_HASHFINAL, SDF_R_INVALID_SESSION);
		return SDR_INARGERR;
	}
	if (!session->md_ctx) {
		SDFerr(SDF_F_SDF_HASHFINAL,
			SDF_R_INVALID_OPERATION_STATE);
		return SDR_INARGERR;
	}
	if (*puiHashLength < EVP_MD_CTX_size(session->md_ctx)) {
		SDFerr(SDF_F_SDF_HASHFINAL, SDF_R_BUFFER_TOO_SMALL);
		return SDR_INARGERR;
	}

	/* digest final */
	if (!EVP_DigestFinal_ex(session->md_ctx, pucHash, puiHashLength)) {
		SDFerr(SDF_F_SDF_HASHFINAL, ERR_R_EVP_LIB);
		return SDR_UNKNOWERR;
	}

	/* note: only success, the md_ctx can be free-ed */
	EVP_MD_CTX_free(session->md_ctx);
	session->md_ctx = NULL;

	return SDR_OK;
}

