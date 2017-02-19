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

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/gmsaf.h>
#include <openssl/gmapi.h>

/* 7.3.39 */
int SAF_SymmEncryptUpdate(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = SAR_UnknownErr;
	SAF_KEY_HANDLE *hkey = (SAF_KEY_HANDLE *)hKeyHandle;
	unsigned char *out = pucOutData;
	int inlen, outlen;

	if (!hKeyHandle || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiInDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, SAF_R_INVALID_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!hkey->cipher_ctx) {
		unsigned char iv[32];
		int ivlen;

		if (!(hkey->cipher_ctx = EVP_CIPHER_CTX_new())) {
			SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, ERR_R_MALLOC_FAILURE);
			ret = SAR_MemoryErr;
			goto end;
		}

		/* generate random iv and output */
		ivlen = EVP_CIPHER_block_size(hkey->cipher);
		if (ivlen <= 0 || ivlen > sizeof(iv)) {
			SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, SAF_R_INVALID_CONTEXT);
			ret = SAR_ObjErr;
			goto end;
		}
		if (!RAND_bytes(iv, ivlen)) {
			SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, SAF_R_GEN_RANDOM);
			ret = SAR_GenRandErr;
			goto end;
		}

		/* output iv, update out pointer */
		memcpy(out, iv, ivlen);
		out += ivlen;

		if (!EVP_EncryptInit(hkey->cipher_ctx, hkey->cipher, hkey->key, iv)) {
			SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, ERR_R_EVP_LIB);
			goto end;
		}
	}

	inlen = (int)uiInDataLen;
	if (!EVP_EncryptUpdate(hkey->cipher_ctx, out, &outlen, pucInData, inlen)) {
		SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, ERR_R_EVP_LIB);
		goto end;
	}

	*puiOutDataLen = (unsigned int)outlen;
	ret = SAR_OK;

end:
	if (ret != SAR_OK && hkey->cipher_ctx) {
		EVP_CIPHER_CTX_free(hkey->cipher_ctx);
		hkey->cipher_ctx = NULL;
	}
	return ret;
}

/* 7.3.40 */
int SAF_SymmEncryptFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	return 0;
}

/* 7.3.42 */
int SAF_SymmDecryptUpdate(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = SAR_UnknownErr;
	SAF_KEY_HANDLE *hkey = (SAF_KEY_HANDLE *)hKeyHandle;
	unsigned char *in = pucInData;
	int inlen, outlen;

	if (!hKeyHandle || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiInDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, SAF_R_INVALID_LENGTH);
		return SAR_IndataLenErr;
	}

	inlen = (int)uiInDataLen;

	if (!hkey->cipher_ctx) {
		unsigned char iv[32];
		int ivlen;

		if (!(hkey->cipher_ctx = EVP_CIPHER_CTX_new())) {
			SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, ERR_R_MALLOC_FAILURE);
			ret = SAR_MemoryErr;
			goto end;
		}

		/* get iv from input */
		ivlen = EVP_CIPHER_block_size(hkey->cipher);
		if (ivlen <= 0 || ivlen > sizeof(iv)) {
			SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, SAF_R_INVALID_CONTEXT);
			ret = SAR_ObjErr;
			goto end;
		}

		memcpy(iv, in, ivlen);
		in += ivlen;
		inlen -= ivlen;

		if (!EVP_DecryptInit(hkey->cipher_ctx, hkey->cipher, hkey->key, iv)) {
			SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, ERR_R_EVP_LIB);
			goto end;
		}
	}

	if (!EVP_DecryptUpdate(hkey->cipher_ctx, pucOutData, &outlen, in, inlen)) {
		SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, ERR_R_EVP_LIB);
		goto end;
	}

	*puiOutDataLen = (unsigned int)outlen;
	ret = SAR_OK;

end:
	if (ret != SAR_OK && hkey->cipher_ctx) {
		EVP_CIPHER_CTX_free(hkey->cipher_ctx);
		hkey->cipher_ctx = NULL;
	}
	return ret;
}

/* 7.3.43 */
int SAF_SymmDecryptFinal(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	return 0;
}

/* 7.3.38 */
int SAF_SymmEncrypt(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret;
	unsigned char *out;
	unsigned int outlen;

	out = pucOutData;
	outlen = *puiOutDataLen;

	if ((ret = SAF_SymmEncryptUpdate(hKeyHandle, pucInData, uiInDataLen,
		out, &outlen)) != SAR_OK) {
		return ret;
	}
	out += outlen;
	if ((ret = SAF_SymmEncryptFinal(hKeyHandle, out, &outlen)) != SAR_OK) {
		return ret;
	}
	out += outlen;

	*puiOutDataLen = out - pucOutData;
	return SAR_OK;
}

/* 7.3.41 */
int SAF_SymmDecrypt(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret;
	unsigned char *out;
	unsigned int outlen;

	out = pucOutData;
	outlen = *puiOutDataLen;

	if ((ret = SAF_SymmDecryptUpdate(hKeyHandle, pucInData, uiInDataLen,
		out, &outlen)) != SAR_OK) {
		return ret;
	}
	out += outlen;
	if ((ret = SAF_SymmDecryptFinal(hKeyHandle, out, &outlen)) != SAR_OK) {
		return ret;
	}
	out += outlen;

	*puiOutDataLen = out - pucOutData;
	return SAR_OK;
}
