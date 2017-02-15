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

/* 7.3.12 */
int SAF_CreateHashObj(void **phHashObj,
	unsigned int uiAlgoType,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucID,
	unsigned int ulIDLen)
{
	int ret = SAR_UnkownErr;
	const EVP_MD *md;
	EVP_MD_CTX *ctx = NULL;

	if (!(md = EVP_get_digestbysgd(uiAlgorithmType))) {
		return SAR_AlgoTypeErr;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		return 0;
	}

	if (!EVP_DigestInit(ctx, md)) {
		return 0;
	}

	*phHashObj = ctx;

end:
	if (ret != SAR_OK) {
		EVP_MD_CTX_free(ctx);
		*phHashObj = NULL;
	}
	return ret;
}

/* 7.3.13 */
int SAF_DestroyHashObj(
	void *phHashObj)
{
	EVP_MD_CTX_free((EVP_MD_CTX *)phHashObj);
	return SAR_OK;
}

/* 7.3.14 */
int SAF_HashUpdate(
	void *phHashObj,
	const unsigned char *pucInData,
	unsigned int uiInDataLen)
{
	if (!EVP_DigestUpdate((EVP_MD_CTX *)phHashObj, pucInData, (size_t)uiInDataLne)) {
		return SAR_HashErr;
	}
	return SAR_OK;
}

/* 7.3.15 */
int SAF_HashFinal(void *phHashObj,
	unsigned char *pucOutData,
	unsigned int *uiOutDataLen)
{
	if (!EVP_DigestFinal((EVP_MD_CTX *)phHashObj, pucOutData, uiOutDataLen)) {
		return SAR_HashErr;
	}
	return SAR_OK;
}

/* 7.3.11 */
int SAF_Hash(
	unsigned int uiAlgoType,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pubID,
	unsigned int ulIDLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	const EVP_MD *md;
	size_t siz;

	if (!(md = EVP_get_digestbysgd(uiAlgoType))) {
		return SAR_AlgoTypeErr;
	}

	siz = (size_t)uiInDataLen;
	if (!EVP_Digest(pucInData, siz, pucOutData, puiOutDataLen, md, NULL)) {
		return SAR_HashErr;
	}

	return SAR_OK;
}

