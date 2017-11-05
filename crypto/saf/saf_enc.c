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
#include "saf_lcl.h"

/* 7.3.39 */
int SAF_SymmEncryptUpdate(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = SAR_UnknownErr;
	SAF_KEY *hkey = (SAF_KEY *)hKeyHandle;
	int outlen;

	if (!hKeyHandle || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiInDataLen <= 0 || uiInDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, SAF_R_INVALID_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!hkey->cipher_ctx) {
		const EVP_CIPHER *cipher;

				
		// FIXME: get ulFeedBitLen from key handle
		if (!(cipher = EVP_get_cipherbysgd(hkey->hSymmKeyObj->uiCryptoAlgID, 0))) {
			SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, SAF_R_INVALID_KEY_HANDLE);
			ret = SAR_IndataErr;
			goto end;
		}

		if (!(hkey->cipher_ctx = EVP_CIPHER_CTX_new())) {
			SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, ERR_R_MALLOC_FAILURE);
			ret = SAR_MemoryErr;
			goto end;
		}

		if (!EVP_EncryptInit_ex(hkey->cipher_ctx, cipher,
			hkey->hSymmKeyObj->app->engine,
			hkey->key, hkey->hSymmKeyObj->pucIV)) {
			SAFerr(SAF_F_SAF_SYMMENCRYPTUPDATE, ERR_R_EVP_LIB);
			goto end;
		}
	}

	if (!EVP_EncryptUpdate(hkey->cipher_ctx, pucOutData, &outlen,
		pucInData, (int)uiInDataLen)) {
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
	int ret = SAR_UnknownErr;
	SAF_KEY *hkey = (SAF_KEY *)hKeyHandle;
	int outlen;

	if (!hKeyHandle || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_SYMMENCRYPTFINAL, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!hkey->cipher_ctx) {
		SAFerr(SAF_F_SAF_SYMMENCRYPTFINAL, SAF_R_ENCRYPT_NOT_INITIALIED);
		return SAR_NotInitializeErr;
	}

	if (!EVP_EncryptFinal_ex(hkey->cipher_ctx, pucOutData, &outlen)) {
		SAFerr(SAF_F_SAF_SYMMENCRYPTFINAL, ERR_R_EVP_LIB);
		goto end;
	}
	*puiOutDataLen = (unsigned int)outlen;

	ret = SAR_OK;
end:
	EVP_CIPHER_CTX_free(hkey->cipher_ctx);
	hkey->cipher_ctx = NULL;
	return ret;
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
	SAF_KEY *hkey = (SAF_KEY *)hKeyHandle;
	int outlen;

	if (!hKeyHandle || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiInDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, SAF_R_INVALID_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!hkey->cipher_ctx) {
		const EVP_CIPHER *cipher;

		//Get feedbitlen from keyhandle 			
		if (!(cipher = EVP_get_cipherbysgd(hkey->hSymmKeyObj->uiCryptoAlgID, 0))) {
			SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, SAF_R_INVALID_KEY_HANDLE);
			ret = SAR_IndataErr;
			goto end;
		}

		if (!(hkey->cipher_ctx = EVP_CIPHER_CTX_new())) {
			SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, ERR_R_MALLOC_FAILURE);
			ret = SAR_MemoryErr;
			goto end;
		}

		if (!EVP_DecryptInit_ex(hkey->cipher_ctx, cipher,
			hkey->hSymmKeyObj->app->engine,
			hkey->key, hkey->hSymmKeyObj->pucIV)) {
			SAFerr(SAF_F_SAF_SYMMDECRYPTUPDATE, ERR_R_EVP_LIB);
			goto end;
		}
	}

	if (!EVP_DecryptUpdate(hkey->cipher_ctx, pucOutData, &outlen,
		pucInData, (int)uiInDataLen)) {
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
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = SAR_UnknownErr;
	SAF_KEY *hkey = (SAF_KEY *)hKeyHandle;
	int outlen;

	if (!hKeyHandle || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_SYMMDECRYPTFINAL, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!hkey->cipher_ctx) {
		SAFerr(SAF_F_SAF_SYMMDECRYPTFINAL, SAF_R_DECRYPT_NOT_INITIALIZED);
		return SAR_NotInitializeErr;
	}

	if (!EVP_DecryptFinal_ex(hkey->cipher_ctx, pucOutData, &outlen)) {
		SAFerr(SAF_F_SAF_SYMMDECRYPTFINAL, ERR_R_EVP_LIB);
		goto end;
	}
	*puiOutDataLen = (unsigned int)outlen;

	ret = SAR_OK;

end:
	EVP_CIPHER_CTX_free(hkey->cipher_ctx);
	hkey->cipher_ctx = NULL;
	return ret;
}

/* 7.3.38 */
int SAF_SymmEncrypt(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = SAR_UnknownErr;
	unsigned int len;

	if ((ret = SAF_SymmEncryptUpdate(hKeyHandle, pucInData, uiInDataLen,
		pucOutData, puiOutDataLen)) != SAR_OK) {
		return ret;
	}

	if ((ret = SAF_SymmEncryptFinal(hKeyHandle,
		pucOutData + *puiOutDataLen, &len)) != SAR_OK) {
		return ret;
	}
	*puiOutDataLen += len;

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
	int ret = SAR_UnknownErr;
	unsigned int len;

	if ((ret = SAF_SymmDecryptUpdate(hKeyHandle, pucInData, uiInDataLen,
		pucOutData, puiOutDataLen)) != SAR_OK) {
		return ret;
	}

	if ((ret = SAF_SymmDecryptFinal(hKeyHandle,
		pucOutData + *puiOutDataLen, &len)) != SAR_OK) {
		return ret;
	}
	*puiOutDataLen += len;

	return SAR_OK;
}
