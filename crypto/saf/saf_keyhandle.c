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

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/gmsaf.h>
#include <openssl/gmapi.h>
#include "saf_lcl.h"

/* 7.3.31 */
int SAF_GenerateKeyWithEPK(
	void *hSymmKeyObj,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucSymmKey,
	unsigned int *puiSymmKeyLen,
	void **phKeyHandle)
{
	int ret = SAR_UnknownErr;
	SAF_KEY *hkey = NULL;
	SAF_SYMMKEYOBJ *obj = (SAF_SYMMKEYOBJ *)hSymmKeyObj;
	const EVP_CIPHER *cipher;
	unsigned char keybuf[32];
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
	size_t outlen;

	if (!hSymmKeyObj || !pucPublicKey || !pucSymmKey
		|| !puiSymmKeyLen || !phKeyHandle) {
		SAFerr(SAF_F_SAF_GENERATEKEYWITHEPK, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiPublicKeyLen <= 0 || uiPublicKeyLen > INT_MAX) {
		SAFerr(SAF_F_SAF_GENERATEKEYWITHEPK, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	outlen = (size_t)*puiSymmKeyLen;
	if (!(cipher = EVP_get_cipherbysgd(obj->algor))
		|| !RAND_bytes(keybuf, EVP_CIPHER_key_length(cipher))
		|| !(pkey = d2i_PUBKEY(NULL, &pucPublicKey, (long)uiPublicKeyLen))
		|| !(pkctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| !EVP_PKEY_encrypt_init(pkctx)
		|| !EVP_PKEY_encrypt(pkctx, pucSymmKey, &outlen, keybuf, (size_t)EVP_CIPHER_key_length(cipher))) {
		SAFerr(SAF_F_SAF_GENERATEKEYWITHEPK, SAF_R_ENCRYPT_KEY_FAILURE);
		goto end;
	}

	// init EVP_CIPHER_CTX
	if (!(hkey = OPENSSL_zalloc(sizeof(*hkey)))) {
		SAFerr(SAF_F_SAF_GENERATEKEYWITHEPK, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	*puiSymmKeyLen = (unsigned int)outlen;
	ret = SAR_Ok;

end:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

/* 7.3.32 */
int SAF_ImportEncedKey(
	void *hSymmKeyObj,
	unsigned char *pucSymmKey,
	unsigned int uiSymmKeyLen,
	void **phKeyHandle)
{
	SAFerr(SAF_F_SAF_IMPORTENCEDKEY, SAF_R_NOT_SUPPORTED);
	return SAR_NotSupportYetErr;
}

/* 7.3.37 */
int SAF_DestroyKeyHandle(
	void *hKeyHandle)
{
	SAF_KEY *hkey = (SAF_KEY *)hKeyHandle;
	OPENSSL_clear_free(hkey, hkey->keylen);
	return SAR_OK;
}
