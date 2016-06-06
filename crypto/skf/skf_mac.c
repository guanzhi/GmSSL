/* crypto/skf/skf_mac.c */
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
#include <openssl/sms4.h>
#include <openssl/cbcmac.h>
#include <openssl/skf.h>
#include <openssl/skf_ex.h>
#include "skf_lcl.h"


ULONG DEVAPI SKF_MacInit(HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac)
{
	SKF_HANDLE *key;
	SKF_HANDLE *hMac = NULL;
	const EVP_CIPHER *cipher;

	if (!(key = (SKF_HANDLE *)hKey)) {
		SKFerr(SKF_F_SKF_MACINIT, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	//TODO: check pMacParam

	if (key->magic != SKF_HANDLE_MAGIC) {
		SKFerr(SKF_F_SKF_MACINIT, SKF_R_INVALID_HANDLE_MAGIC);
		return SAR_INVALIDPARAMERR;
	}

	if (key->type < SKF_KEY_HANDLE) {
		SKFerr(SKF_F_SKF_MACINIT, SKF_R_INVALID_KEY_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	if (key->algid != SGD_SM4_MAC) {
		SKFerr(SKF_F_SKF_MACINIT, SKF_R_INVALID_ALGOR);
		return SAR_INVALIDPARAMERR;
	}
	cipher = EVP_sms4_ecb();

	if (key->keylen < SMS4_KEY_LENGTH) {
		SKFerr(SKF_F_SKF_MACINIT, SKF_R_INVALID_KEY_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (!(hMac = OPENSSL_malloc(sizeof(*hMac)))) {
		SKFerr(SKF_F_SKF_MACINIT, SKF_R_FAIL);
		return SAR_FAIL;
	}

	hMac->magic = SKF_HANDLE_MAGIC;
	hMac->type = SKF_MAC_HANDLE;
	hMac->algid = key->algid;

	if (!(hMac->u.cbcmac_ctx = CBCMAC_CTX_new())) {
		SKFerr(SKF_F_SKF_MACINIT, ERR_R_CBCMAC_LIB);
		goto end;
	}

	if (!CBCMAC_Init(hMac->u.cbcmac_ctx, key->key, key->keylen, cipher, NULL)) {
		SKFerr(SKF_F_SKF_MACINIT, ERR_R_CBCMAC_LIB);
		return SAR_FAIL;
	}

	*phMac = hMac;
end:
	return SAR_OK;
}

ULONG DEVAPI SKF_MacUpdate(HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen)
{
	CBCMAC_CTX *ctx;

	if (!(ctx = SKF_HANDLE_get_cbcmac_ctx(hMac))) {
		SKFerr(SKF_F_SKF_MACUPDATE, SKF_R_INVALID_MAC_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	if (!CBCMAC_Update(ctx, pbData, ulDataLen)) {
		SKFerr(SKF_F_SKF_MACUPDATE, ERR_R_CBCMAC_LIB);
		return SAR_FAIL;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_MacFinal(HANDLE hMac,
	BYTE *pbMacData,
	ULONG *pulMacDataLen)
{
	CBCMAC_CTX *ctx;
	size_t size;

	if (!(ctx = SKF_HANDLE_get_cbcmac_ctx(hMac))) {
		SKFerr(SKF_F_SKF_MACFINAL, SKF_R_INVALID_MAC_HANDLE);
		return SAR_INVALIDPARAMERR;
	}

	size = *pulMacDataLen;
	if (!CBCMAC_Final(ctx, pbMacData, &size)) {
		SKFerr(SKF_F_SKF_MACFINAL, ERR_R_CBCMAC_LIB);
		return SAR_FAIL;
	}

	*pulMacDataLen = (ULONG)size;
	return SAR_OK;
}

ULONG DEVAPI SKF_Mac(HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMacData,
	ULONG *pulMacLen)
{
	ULONG rv;

	if ((rv = SKF_MacUpdate(hMac, pbData, ulDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_MAC, ERR_R_SKF_LIB);
		return rv;
	}

	if ((rv = SKF_MacFinal(hMac, pbMacData, pulMacLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_MAC, ERR_R_SKF_LIB);
		return rv;
	}

	return SAR_OK;
}

