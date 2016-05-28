/* crypto/skf/skf_enc.c */
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
#include <openssl/sms4.h>
#include <openssl/skf.h>
#include <openssl/skf_ex.h>
#include "skf_lcl.h"

#define PADDING_TYPE_NO_PADDING		0
#define PADDING_TYPE_PKCS5		1


ULONG DEVAPI SKF_EncryptInit(HANDLE hKey,
	BLOCKCIPHERPARAM encryptParam)
{
	ULONG ret = SAR_FAIL;
	BLOCKCIPHERPARAM *encparam = &encryptParam;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher;
	unsigned char *key;
	unsigned char *iv;

	//FIXME: CFB bits!

	if (!(key = SKF_HANDLE_get_key(hKey))) {
		SKFerr(SKF_F_SKF_ENCRYPTINIT, SKF_R_INVALID_KEY_HANDLE);
		ret = SAR_INVALIDPARAMERR;
		goto end;
	}

	if (encparam->IVLen != SMS4_IV_LENGTH) {
		SKFerr(SKF_F_SKF_ENCRYPTINIT, SKF_R_INVALID_IV_LENGTH);
		ret = SAR_INVALIDPARAMERR;
		goto end;
	}

	iv = encparam->IV;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		SKFerr(SKF_F_SKF_ENCRYPTINIT, ERR_R_EVP_LIB);
		goto end;
	}

	if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
		SKFerr(SKF_F_SKF_ENCRYPTINIT, ERR_R_EVP_LIB);
		goto end;
	}

	if (!SKF_HANDLE_set1_cipher_ctx(hKey, ctx)) {
		SKFerr(SKF_F_SKF_ENCRYPTINIT, SKF_R_SET_CIPHER_CTX_FAILED);
		goto end;
	}
	ctx = NULL;

	ret = SAR_OK;
end:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	EVP_CIPHER_CTX *ctx;
	int inlen, outlen;

	if (!(ctx = SKF_HANDLE_get_cipher_ctx(hKey))) {
		SKFerr(SKF_F_SKF_ENCRYPTUPDATE, SKF_R_INVALID_CIPHER_CTX_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	//FIXME: check INT_MAX
	inlen = ulDataLen;
	outlen = *pulEncryptedLen;
	if (!EVP_EncryptUpdate(ctx, pbEncryptedData, &outlen, pbData, inlen)) {
		SKFerr(SKF_F_SKF_ENCRYPTUPDATE, ERR_R_EVP_LIB);
		return SAR_FAIL;
	}

	*pulEncryptedLen = outlen;
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptFinal(HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen)
{
	EVP_CIPHER_CTX *ctx;
	int outlen;

	if (!(ctx = SKF_HANDLE_get_cipher_ctx(hKey))) {
		SKFerr(SKF_F_SKF_ENCRYPTFINAL, SKF_R_INVALID_CIPHER_CTX_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	outlen = *pulEncryptedDataLen;
	if (!EVP_EncryptFinal(ctx, pbEncryptedData, &outlen)) {
		SKFerr(SKF_F_SKF_ENCRYPTFINAL, ERR_R_EVP_LIB);
		return SAR_FAIL;
	}

	*pulEncryptedDataLen = outlen;
	SKF_HANDLE_free_cipher_ctx(hKey);
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptInit(HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam)
{
	ULONG ret = SAR_FAIL;
	BLOCKCIPHERPARAM *param = &DecryptParam;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher;
	unsigned char *key;
	unsigned char *iv;

	if (!(key = SKF_HANDLE_get_key(hKey))) {
		SKFerr(SKF_F_SKF_DECRYPTINIT, SKF_R_INVALID_KEY_HANDLE);
		ret = SAR_INVALIDPARAMERR;
		goto end;
	}

	if (param->IVLen != SMS4_IV_LENGTH) {
		SKFerr(SKF_F_SKF_DECRYPTINIT, SKF_R_INVALID_IV_LENGTH);
		ret = SAR_INVALIDPARAMERR;
		goto end;
	}

	iv = param->IV;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		SKFerr(SKF_F_SKF_DECRYPTINIT, ERR_R_EVP_LIB);
		goto end;
	}

	if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
		SKFerr(SKF_F_SKF_DECRYPTINIT, ERR_R_EVP_LIB);
		goto end;
	}

	if (!SKF_HANDLE_set1_cipher_ctx(hKey, ctx)) {
		SKFerr(SKF_F_SKF_DECRYPTINIT, SKF_R_SET_CIPHER_CTX_FAILED);
		goto end;
	}
	ctx = NULL;

	ret = SAR_OK;
end:
	EVP_CIPHER_CTX_free(ctx);
	return ret;

	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	EVP_CIPHER_CTX *ctx;
	int inlen, outlen;

	if (!(ctx = SKF_HANDLE_get_cipher_ctx(hKey))) {
		SKFerr(SKF_F_SKF_DECRYPTUPDATE, SKF_R_INVALID_CIPHER_CTX_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	//FIXME: check INT_MAX
	inlen = ulEncryptedLen;
	outlen = *pulDataLen;
	if (!EVP_DecryptUpdate(ctx, pbData, &outlen, pbEncryptedData, inlen)) {
		SKFerr(SKF_F_SKF_DECRYPTUPDATE, ERR_R_EVP_LIB);
		return SAR_FAIL;
	}

	*pulDataLen = outlen;
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptFinal(HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen)
{
	EVP_CIPHER_CTX *ctx;
	int len;

	if (!(ctx = SKF_HANDLE_get_cipher_ctx(hKey))) {
		SKFerr(SKF_F_SKF_DECRYPTFINAL, SKF_R_INVALID_KEY_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	if (!EVP_DecryptFinal(ctx, pbDecryptedData, &len)) {
		return SAR_FAIL;
	}

	*pulDecryptedDataLen = len;
	SKF_HANDLE_free_cipher_ctx(hKey);
	return SAR_OK;
}

ULONG DEVAPI SKF_Encrypt(HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	ULONG rv;
	BYTE *p;
	ULONG len;

	p = pbEncryptedData;
	len = *pulEncryptedLen;
	if ((rv = SKF_EncryptUpdate(hKey, pbData, ulDataLen, p, &len)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENCRYPT, ERR_R_SKF_LIB);
		return rv;
	}

	p += len;
	len = *pulEncryptedLen - len;
	if ((rv = SKF_EncryptFinal(hKey, p, &len)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENCRYPT, ERR_R_SKF_LIB);
		return rv;
	}

	*pulEncryptedLen = p + len - pbEncryptedData;
	return SAR_OK;
}

ULONG DEVAPI SKF_Decrypt(HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	ULONG rv;
	BYTE *p;
	ULONG len;

	p = pbData;
	len = *pulDataLen;
	if ((rv = SKF_DecryptUpdate(hKey, pbEncryptedData, ulEncryptedLen, p, &len)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DECRYPT, ERR_R_SKF_LIB);
		return rv;
	}

	p += len;
	len = *pulDataLen - len;
	if ((rv = SKF_DecryptFinal(hKey, p, &len)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DECRYPT, ERR_R_SKF_LIB);
		return rv;
	}

	*pulDataLen = p + len - pbData;
	return SAR_OK;
}

