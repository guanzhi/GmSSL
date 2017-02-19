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
#include <openssl/cmac.h>
#include <openssl/gmsaf.h>
#include <openssl/gmapi.h>

/* 7.3.45 */
int SAF_MacUpdate(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen)
{
	int ret = SAR_UnknownErr;
	SAF_KEY *hkey = (SAF_KEY *)hKeyHandle;

	if (!hKeyHandle || !pucInData) {
		SAFerr(SAF_F_SAF_MACUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!hkey->cmac_ctx) {
		if (!(hkey->cmac_ctx = CMAC_CTX_new())) {
			SAFerr(SAF_F_SAF_MACUPDATE, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(hkey->cmac_ctx, hkey->key, hkey->keylen, hkey->cipher, NULL)) {
			SAFerr(SAF_F_SAF_MACUPDATE, SAF_R_CMAC_FAILURE);
			goto end;
		}
	}

	if (!CMAC_Update(hkey->cmac_ctx, pucInData, (size_t)uiInDataLen)) {
		SAFerr(SAF_F_SAF_MACUPDATE, SAF_R_CMAC_FAILURE);
		return SAR_UnknownErr;
	}

	ret = SAR_OK;

end:
	if (ret != SAR_OK && hkey->cmac_ctx) {
		CMAC_CTX_free(hkey->cmac_ctx);
		hkey->cmac_ctx = NULL;
	}
	return ret;
}

/* 7.3.46 */
int SAF_MacFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	SAF_KEY *hkey = (SAF_KEY *)hKeyHandle;
	size_t siz;

	if (!hKeyHandle || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_MACFINAL, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (*puiOutDataLen < EVP_CIPHER_block_size(hkey->cipher)) {
		SAFerr(SAF_F_SAF_MACFINAL, SAF_R_BUFFER_TOO_SMALL);
		return SAR_IndataLenErr;
	}

	if (!hkey->cmac_ctx) {
		SAFerr(SAF_F_SAF_MACFINAL, SAF_R_OPERATION_NOT_INITIALIZED);
		return SAR_UnknownErr;
	}

	siz = EVP_CIPHER_block_size(hkey->cipher);
	if (!CBCMAC_Final(hkey->cbcmac_ctx, pucOutData, &siz)) {
		SAFerr(SAF_F_SAF_MACFINAL, SAF_R_MAC_FAILURE);
		return SAR_UnknownErr;
	}

	*puiOutDataLen = (unsigned int)siz;
	return SAR_OK;
}

/* 7.4.44 */
int SAF_Mac(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret;
	if ((ret = SAF_MacUpdate(hKeyHandle, pucInData, uiInDataLen)) != SAR_OK) {
		return ret;
	}
	if ((ret = SAF_MacFinal(hKeyHandle, pucOutData, puiOutDataLen)) != SAR_OK) {
		return ret;
	}
	return SAR_OK;
}

