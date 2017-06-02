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
#include <openssl/evp.h>
#include <openssl/gmsaf.h>
#include <openssl/gmapi.h>
#include "saf_lcl.h"

/* 7.3.12 */
int SAF_CreateHashObj(void **phHashObj,
	unsigned int uiAlgoType,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucID,
	unsigned int uiIDLen)
{
	int ret = SAR_UnknownErr;
	const EVP_MD *md;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;

	if (!phHashObj) {
		SAFerr(SAF_F_SAF_CREATEHASHOBJ, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!(md = EVP_get_digestbysgd(uiAlgoType))) {
		SAFerr(SAF_F_SAF_CREATEHASHOBJ, SAF_R_INVALID_ALGOR);
		return SAR_AlgoTypeErr;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		SAFerr(SAF_F_SAF_CREATEHASHOBJ, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* limitation of the SAF hashing:
	 * can not specify an engine, only use the default implementation
	 */
	if (!EVP_DigestInit_ex(ctx, md, NULL)) {
		SAFerr(SAF_F_SAF_CREATEHASHOBJ, ERR_R_EVP_LIB);
		goto end;
	}

	if (pucPublicKey) {
		unsigned char dgst[EVP_MAX_MD_SIZE];
		size_t dgstlen = sizeof(dgst);

		if (!pucID) {
			SAFerr(SAF_F_SAF_CREATEHASHOBJ, ERR_R_PASSED_NULL_PARAMETER);
			ret = SAR_IndataErr;
			goto end;
		}

		if (uiIDLen <= 0 || uiIDLen > SM2_MAX_ID_LENGTH
			|| strlen((char *)pucID) != uiIDLen
			|| uiPublicKeyLen <= 0 || uiPublicKeyLen > INT_MAX) {
			SAFerr(SAF_F_SAF_CREATEHASHOBJ, SAF_R_INVALID_INPUT_LENGTH);
			ret = SAR_IndataLenErr;
			goto end;
		}

		if (!(pkey = d2i_PUBKEY(NULL, (const unsigned char **)&pucPublicKey, (long)uiPublicKeyLen))
			|| EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
			SAFerr(SAF_F_SAF_CREATEHASHOBJ, SAF_R_INVALID_PUBLIC_KEY);
			ret = SAR_IndataErr;
			goto end;
		}

		if (!SM2_compute_id_digest(md, (char *)pucID, uiIDLen, dgst, &dgstlen,
			EVP_PKEY_get0_EC_KEY(pkey))) {
			SAFerr(SAF_F_SAF_CREATEHASHOBJ, ERR_R_EC_LIB);
			goto end;
		}

		if (!EVP_DigestUpdate(ctx, dgst, dgstlen)) {
			SAFerr(SAF_F_SAF_CREATEHASHOBJ, ERR_R_EVP_LIB);
			goto end;
		}
	}

	*phHashObj = ctx;
	ctx = NULL;

	ret = SAR_Ok;

end:
	if (ret != SAR_Ok) {
		*phHashObj = NULL;
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return ret;
}

/* 7.3.13 */
int SAF_DestroyHashObj(
	void *phHashObj)
{
	if (!phHashObj) {
		SAFerr(SAF_F_SAF_DESTROYHASHOBJ, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	EVP_MD_CTX_free((EVP_MD_CTX *)phHashObj);
	return SAR_Ok;
}

/* 7.3.14 */
int SAF_HashUpdate(
	void *phHashObj,
	const unsigned char *pucInData,
	unsigned int uiInDataLen)
{
	if (!phHashObj || pucInData) {
		SAFerr(SAF_F_SAF_HASHUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiInDataLen <= 0 || uiInDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_HASHUPDATE, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!EVP_DigestUpdate((EVP_MD_CTX *)phHashObj, pucInData, uiInDataLen)) {
		SAFerr(SAF_F_SAF_HASHUPDATE, ERR_R_EVP_LIB);
		return SAR_HashErr;
	}

	return SAR_Ok;
}

/* 7.3.15 */
int SAF_HashFinal(void *phHashObj,
	unsigned char *pucOutData,
	unsigned int *uiOutDataLen)
{
	if (!phHashObj || !pucOutData || !uiOutDataLen) {
		SAFerr(SAF_F_SAF_HASHFINAL, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (*uiOutDataLen < EVP_MAX_MD_SIZE) {
		SAFerr(SAF_F_SAF_HASHFINAL, SAF_R_BUFFER_TOO_SMALL);
		return SAR_IndataLenErr;
	}

	if (!EVP_DigestFinal_ex((EVP_MD_CTX *)phHashObj, pucOutData, uiOutDataLen)) {
		SAFerr(SAF_F_SAF_HASHFINAL, ERR_R_EVP_LIB);
		return SAR_HashErr;
	}

	return SAR_Ok;
}

/* 7.3.11 */
int SAF_Hash(
	unsigned int uiAlgoType,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pubID,
	unsigned int uiIDLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret;
	void *hHashObj = NULL;

	if ((ret = SAF_CreateHashObj(
		&hHashObj,
		uiAlgoType,
		pucPublicKey,
		uiPublicKeyLen,
		pubID,
		uiIDLen)) != SAR_Ok) {
		SAFerr(SAF_F_SAF_HASH, ERR_R_SAF_LIB);
		return ret;
	}

	if ((ret = SAF_HashUpdate(
		hHashObj,
		pucInData,
		uiInDataLen)) != SAR_Ok) {
		SAFerr(SAF_F_SAF_HASH, ERR_R_SAF_LIB);
		goto err;
	}

	if ((ret = SAF_HashFinal(
		hHashObj,
		pucOutData,
		puiOutDataLen)) != SAR_Ok) {
		SAFerr(SAF_F_SAF_HASH, ERR_R_SAF_LIB);
		goto err;
	}

	if ((ret = SAF_DestroyHashObj(
		hHashObj)) != SAR_Ok) {
		SAFerr(SAF_F_SAF_HASH, ERR_R_SAF_LIB);
		return ret;
	}

	return SAR_Ok;

err:
	/* keep the first error */
	(void)SAF_DestroyHashObj(hHashObj);
	return ret;
}
