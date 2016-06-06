/* crypto/skf/skf_handle.c */
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
#include <openssl/skf.h>
#include <openssl/skf_ex.h>
#include "skf_lcl.h"

unsigned char *SKF_HANDLE_get_key(HANDLE hKey)
{
	SKF_HANDLE *handle;

	if (!(handle = (SKF_HANDLE *)hKey)) {
		SKFerr(SKF_F_SKF_HANDLE_GET_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (handle->magic != SKF_HANDLE_MAGIC) {
		SKFerr(SKF_F_SKF_HANDLE_GET_KEY, SKF_R_INVALID_HANDLE_MAGIC);
		return NULL;
	}
	if (handle->type < SKF_KEY_HANDLE) {
		SKFerr(SKF_F_SKF_HANDLE_GET_KEY, SKF_R_INVALID_HANDLE_TYPE);
		return NULL;
	}

	switch (handle->algid) {
	case SGD_SM4_ECB:
	case SGD_SM4_CBC:
	case SGD_SM4_CFB:
	case SGD_SM4_OFB:
	case SGD_SM4_MAC:
		break;
	default:
		SKFerr(SKF_F_SKF_HANDLE_GET_KEY, SKF_R_INVALID_ALGOR);
		return NULL;
	}

	if (!handle->keylen) {
		SKFerr(SKF_F_SKF_HANDLE_GET_KEY, SKF_R_INVALID_KEY_HANDLE);
		return NULL;
	}
	return handle->key;
}

const EVP_CIPHER *SKF_HANDLE_get_cipher(HANDLE hKey, BLOCKCIPHERPARAM *param)
{
	SKF_HANDLE *handle = (SKF_HANDLE *)hKey;
	if (!SKF_HANDLE_get_key(hKey)) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CIPHER, SKF_R_INVALID_KEY_HANDLE);
		return NULL;
	}

	switch (handle->algid) {
	case SGD_SM4_ECB:
		return EVP_sms4_ecb();
	case SGD_SM4_CBC:
		return EVP_sms4_cbc();
	case SGD_SM4_OFB:
		return EVP_sms4_ofb();
	case SGD_SM4_CFB:
		switch (param->FeedBitLen) {
		case   1: return EVP_sms4_cfb1();
		case   8: return EVP_sms4_cfb8();
		case 128: return EVP_sms4_cfb128();
		}
		SKFerr(SKF_F_SKF_HANDLE_GET_CIPHER, SKF_R_INVALID_FEED_BIT_LENGTH);
		return NULL;
	}

	SKFerr(SKF_F_SKF_HANDLE_GET_CIPHER, SKF_R_INVALID_HANDLE_ALGOR);
	return NULL;
}

EVP_MD_CTX *SKF_HANDLE_get_md_ctx(HANDLE hHash)
{
	EVP_MD_CTX *ret;
	SKF_HANDLE *handle;

	if (!(handle = (SKF_HANDLE *)hHash)) {
		SKFerr(SKF_F_SKF_HANDLE_GET_MD_CTX, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (handle->magic != SKF_HANDLE_MAGIC) {
		SKFerr(SKF_F_SKF_HANDLE_GET_MD_CTX, SKF_R_INVALID_HANDLE_MAGIC);
		return NULL;
	}
	if (handle->type != SKF_HASH_HANDLE) {
		SKFerr(SKF_F_SKF_HANDLE_GET_MD_CTX, SKF_R_INVALID_HANDLE_TYPE);
		return NULL;
	}

	if (!(ret = handle->u.md_ctx)) {
		SKFerr(SKF_F_SKF_HANDLE_GET_MD_CTX, SKF_R_CTX_NOT_CREATED);
		return NULL;
	}
	return ret;
}

CBCMAC_CTX *SKF_HANDLE_get_cbcmac_ctx(HANDLE hMac)
{
	CBCMAC_CTX *ret;
	SKF_HANDLE *handle;

	if (!(handle = (SKF_HANDLE *)hMac)) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CBCMAC_CTX, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (handle->magic != SKF_HANDLE_MAGIC) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CBCMAC_CTX, SKF_R_INVALID_HANDLE_MAGIC);
		return NULL;
	}
	if (handle->type != SKF_MAC_HANDLE) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CBCMAC_CTX, SKF_R_INVALID_HANDLE_TYPE);
		return NULL;
	}

	if (!(ret = handle->u.cbcmac_ctx)) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CBCMAC_CTX, SKF_R_CTX_NOT_CREATED);
		return NULL;
	}
	return ret;
}

EVP_CIPHER_CTX *SKF_HANDLE_get_cipher_ctx(HANDLE hKey)
{
	EVP_CIPHER_CTX *ret;
	SKF_HANDLE *handle;

	if (!(handle = (SKF_HANDLE *)hKey)) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CIPHER_CTX, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (handle->magic != SKF_HANDLE_MAGIC) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CIPHER_CTX, SKF_R_INVALID_HANDLE_MAGIC);
		return NULL;
	}
	if (handle->type != SKF_CIPHER_HANDLE) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CIPHER_CTX, SKF_R_INVALID_HANDLE_TYPE);
		return NULL;
	}

	if (!(ret = handle->u.cipher_ctx)) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CIPHER_CTX, SKF_R_CTX_NOT_CREATED);
		return NULL;
	}
	return ret;
}

int SKF_HANDLE_free(HANDLE handle)
{
	return 0;
}


HANDLE SKF_HANDLE_new(int type)
{

	return NULL;
}

ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle)
{
	SKF_HANDLE *handle;
	return SAR_OK; //FIXME:

	if (!(handle = (SKF_HANDLE *)hHandle)) {
		return SAR_OK;
	}

	if (handle->magic != SKF_HANDLE_MAGIC) {
		SKFerr(SKF_F_SKF_CLOSEHANDLE, SKF_R_INVALID_HANDLE_MAGIC);
		return SAR_INVALIDPARAMERR;
	}

	switch (handle->type) {
	case SKF_KEY_HANDLE:
		OPENSSL_cleanse(handle->key, EVP_MAX_KEY_LENGTH);
		// FIXME: we need to make sure there are no pending operation
		if (handle->u.cipher_ctx) {
			EVP_CIPHER_CTX_cleanup(handle->u.cipher_ctx);
		}
		break;

	case SKF_MAC_HANDLE:
		CBCMAC_CTX_cleanup(handle->u.cbcmac_ctx);
		break;

	case SKF_HASH_HANDLE:
		EVP_MD_CTX_cleanup(handle->u.md_ctx);
		break;

	default:
		SKFerr(SKF_F_SKF_CLOSEHANDLE, SKF_R_INVALID_HANDLE_TYPE);
		return SAR_INVALIDPARAMERR;
	}

	/* now we remove this handle from list */

	return SAR_OK;
}

