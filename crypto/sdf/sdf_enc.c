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
#include <openssl/rand.h>
#include <openssl/gmapi.h>
#include <openssl/gmsdf.h>
#include "sdf_lcl.h"

/* TODO: current max input length is INT_MAX
 * we will return error when the input is longer than INT_MAX.
 * do not fixed this in GmSSL 2.x, fixed it in the future.
 * we can seperate the input to multiple of INT_MAX with multiple upadtes.
 */
/*
 * Implement with ENGINE
 * as some of the ciphers such as SM1/SSF33 can not be supported by
 * software, we can use ENGINEs hoping that such ciphers can be supported.
 */
int SDF_Encrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)
{
	int ret = SDR_UNKNOWERR;
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	SDF_KEY *key = (SDF_KEY *)hKeyHandle;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher;
	unsigned char *p;
	int len;

	/* check arguments */
	if (!hSessionHandle || !hKeyHandle || !pucIV || !pucData || !pucEncData
		|| !puiEncDataLength) {
		SDFerr(SDF_F_SDF_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (uiDataLength <= 0 || uiDataLength > INT_MAX) {
		SDFerr(SDF_F_SDF_ENCRYPT, SDF_R_INVALID_INPUT_LENGTH);
		return SDR_UNKNOWERR;
	}
	if (*puiEncDataLength < uiDataLength + EVP_MAX_BLOCK_LENGTH * 2) {
		SDFerr(SDF_F_SDF_ENCRYPT, SDF_R_BUFFER_TOO_SMALL);
		return SDR_UNKNOWERR;
	}

	/* parse arguments */
	if (!(cipher = sdf_get_cipher(hSessionHandle, uiAlgID))) {
		SDFerr(SDF_F_SDF_ENCRYPT, SDF_R_INVALID_ALGOR);
		goto end;
	}
	if (key->keylen != EVP_CIPHER_key_length(cipher)) {
		SDFerr(SDF_F_SDF_ENCRYPT, SDF_R_INVALID_KEY_HANDLE);
		goto end;
	}

	/* encrypt */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		SDFerr(SDF_F_SDF_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EVP_EncryptInit_ex(ctx, cipher, session->engine, key->key, pucIV)) {
		SDFerr(SDF_F_SDF_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	p = pucEncData;
	if (!EVP_EncryptUpdate(ctx, p, &len, pucData, (int)uiDataLength)) {
		SDFerr(SDF_F_SDF_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	p += len;
	if (!EVP_EncryptFinal_ex(ctx, p, &len)) {
		SDFerr(SDF_F_SDF_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	p += len;

	/* set return value */
	*puiEncDataLength = p - pucEncData;
	ret = SDR_OK;

end:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int SDF_Decrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	int ret = SDR_UNKNOWERR;
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	SDF_KEY *key = (SDF_KEY *)hKeyHandle;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *p;
	int len;

	/* check arguments */
	if (!hSessionHandle || !hKeyHandle || !pucIV || !pucEncData ||
		!pucData || !puiDataLength) {
		SDFerr(SDF_F_SDF_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (uiEncDataLength <= 0 || uiEncDataLength > INT_MAX) {
		SDFerr(SDF_F_SDF_DECRYPT, SDF_R_INVALID_INPUT_LENGTH);
		return SDR_UNKNOWERR;
	}
	if (*puiDataLength < uiEncDataLength) {
		SDFerr(SDF_F_SDF_DECRYPT, SDF_R_BUFFER_TOO_SMALL);
		return SDR_UNKNOWERR;
	}

	/* parse arguments */
	if (!(cipher = sdf_get_cipher(hSessionHandle, uiAlgID))) {
		SDFerr(SDF_F_SDF_DECRYPT, SDF_R_INVALID_ALGOR);
		goto end;
	}
	if (key->keylen != EVP_CIPHER_key_length(cipher)) {
		SDFerr(SDF_F_SDF_DECRYPT, SDF_R_INVALID_KEY_HANDLE);
		goto end;
	}

	/* decrypt */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		SDFerr(SDF_F_SDF_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EVP_DecryptInit_ex(ctx, cipher, session->engine, key->key, pucIV)) {
		SDFerr(SDF_F_SDF_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	p = pucData;
	if (!EVP_DecryptUpdate(ctx, p, &len, pucEncData,
		(int)uiEncDataLength)) {
		SDFerr(SDF_F_SDF_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	p += len;
	if (!EVP_DecryptFinal_ex(ctx, p, &len)) {
		SDFerr(SDF_F_SDF_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	p += len;

	/* set return value */
	*puiDataLength = p - pucEncData;
	ret =SDR_OK;

end:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

