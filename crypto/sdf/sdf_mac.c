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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/gmsdf.h>
#include "sdf_lcl.h"

int SDF_CalculateMAC(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucMAC,
	unsigned int *puiMACLength)
{
	int ret = SDR_UNKNOWERR;
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	SDF_KEY *key = (SDF_KEY *)hKeyHandle;
	CMAC_CTX *ctx = NULL;
	const EVP_CIPHER *cipher;
	size_t siz;

	/* check arguments, omit the useless pucIV in CBC-MAC */
	if (!hSessionHandle || !hKeyHandle || !pucData ||
		!pucMAC || !puiMACLength) {
		SDFerr(SDF_F_SDF_CALCULATEMAC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	/* the CBC-MAC API accept size_t input length, but we don't
	 * know whether future MAC implementation will change this */
	if (uiDataLength <= 0 || uiDataLength > INT_MAX) {
		SDFerr(SDF_F_SDF_CALCULATEMAC,
			SDF_R_INVALID_INPUT_LENGTH);
		return SDR_UNKNOWERR;
	}

	/* parse arguments */
	if (!(cipher = sdf_get_cipher(hSessionHandle, uiAlgID))) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, SDF_R_INVALID_ALGOR);
		goto end;
	}
	if (key->keylen != EVP_CIPHER_key_length(cipher)) {
		SDFerr(SDF_F_SDF_CALCULATEMAC,
			SDF_R_INVALID_KEY_HANDLE);
		goto end;
	}
	if (*puiMACLength < EVP_CIPHER_block_size(cipher)) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, SDF_R_BUUTER_TOO_SMALL);
		goto end;
	}

	/* generate mac */
	if (!(ctx = CMAC_CTX_new())) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!CMAC_Init(ctx, key->key, key->keylen, cipher, session->engine)) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, SDF_R_CMAC_FAILURE);
		goto end;
	}
	if (!CMAC_Update(ctx, pucData, (size_t)uiDataLength)) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, SDF_R_CMAC_FAILURE);
		goto end;
	}
	if (!CMAC_Final(ctx, pucMAC, &siz)) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, SDF_R_CMAC_FAILURE);
		goto end;
	}

	*puiMACLength = (unsigned int)siz;
	ret = SDR_OK;

end:
	CMAC_CTX_free(ctx);
	return ret;
}

