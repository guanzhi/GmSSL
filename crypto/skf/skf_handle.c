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


EVP_MD_CTX *SKF_HANDLE_get_md_ctx(SKF_HANDLE *handle)
{
	EVP_MD_CTX *ret;

	if (!handle) {
		SKFerr(SKF_F_SKF_HANDLE_GET_MD_CTX, SKF_R_NULL_ARGUMENT);
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

CBCMAC_CTX *SKF_HANDLE_get_cbcmac_ctx(SKF_HANDLE *handle)
{
	CBCMAC_CTX *ret;

	if (!handle) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CBCMAC_CTX, SKF_R_NULL_ARGUMENT);
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

EVP_CIPHER_CTX *SKF_HANDLE_get_cipher_ctx(SKF_HANDLE *handle)
{
	EVP_CIPHER_CTX *ret;

	if (!handle) {
		SKFerr(SKF_F_SKF_HANDLE_GET_CIPHER_CTX, SKF_R_NULL_ARGUMENT);
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

int SKF_HANDLE_free_cipher_ctx(SKF_HANDLE *handle)
{
	return 0;
}

int SKF_HANDLE_free(SKF_HANDLE *handle)
{
	return 0;
}

unsigned char *SKF_HANDLE_get_key(SKF_HANDLE *handle)
{
	return NULL;
}

SKF_HANDLE *SKF_HANDLE_new(int type)
{
	return NULL;
}

int SKF_HANDLE_set1_cipher_ctx(SKF_HANDLE *handle, EVP_CIPHER_CTX *ctx)
{
	return 0;
}



ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle)
{
	SKF_HANDLE *handle;

	if (!(handle = (SKF_HANDLE *)hHandle)) {
		SKFerr(SKF_F_SKF_CLOSEHANDLE, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
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

