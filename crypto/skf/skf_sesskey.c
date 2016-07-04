/* crypto/skf/skf_sesskey.c */
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
#include <string.h>
#include <openssl/sms4.h>
#include <openssl/evp.h>
#include <openssl/skf.h>
#include <openssl/skf_ex.h>
#include "skf_lcl.h"

#define PADDING_TYPE_NO_PADDING		0
#define PADDING_TYPE_PKCS5		1


ULONG DEVAPI SKF_SetSymmKey(DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey)
{
	SKF_HANDLE *hKey = NULL;

	if (!(hKey = OPENSSL_malloc(sizeof(*hKey)))) {
		SKFerr(SKF_F_SKF_SETSYMMKEY, SKF_R_MALLOC_FAILED);
		return SAR_FAIL;
	}
	memset(hKey, 0, sizeof(*hKey));

	hKey->magic = SKF_HANDLE_MAGIC;
	hKey->type = SKF_KEY_HANDLE;

	switch (ulAlgID) {
	case SGD_SM4_ECB:
	case SGD_SM4_CBC:
	case SGD_SM4_CFB:
	case SGD_SM4_OFB:
	case SGD_SM4_MAC:
		hKey->algid = ulAlgID;
		hKey->keylen = SMS4_KEY_LENGTH;
		break;
	default:
		SKFerr(SKF_F_SKF_SETSYMMKEY, SKF_R_INVALID_ALGOR);
		return SAR_INVALIDPARAMERR;
	}
	memcpy(hKey->key, pbKey, hKey->keylen);

	*phKey = hKey;
	return SAR_OK;
}

