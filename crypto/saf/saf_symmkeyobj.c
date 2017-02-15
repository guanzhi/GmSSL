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


/* 7.3.30
 * All symmetric keys in GMAPI are session objects.
 * The `SymmKeyObj` is a EVP_CIPHER_CTX
 */
int SAF_CreateSymmKeyObj(
	void *hAppHandle,
	void **phSymmKeyObj,
	unsigned char *pucContainerName,
	unsigned int uiContainerLen,
	unsigned char *pucIV,
	unsigned int uiIVLen,
	unsigned int uiEncOrDec,
	unsigned int uiCryptoAlgID)
{
	int ret = SAR_UnknownErr;
	SAF_SymmKeyObj *obj = NULL;

	/* check arguments */
	if (!hAppHandle || !phSymmKeyObj || !pucContainerName || !pucIV) {
		SAFerr(SAF_F_SAF_CREATESYMMKEYOBJ,
			ERR_R_PASSED_NULL_PARAMETER);
		return -1;
	}
	if (uiContainerLen > INT_MAX) {
		SAFerr(SAF_F_SAF_CREATESYMMKEYOBJ,
			SAF_R_INVALID_INPUT_LENGTH);
		return -1;
	}
	if (uiIVLen > EVP_MAX_IV_LENGTH) {
		SAFerr(SAF_F_SAF_CREATESYMMKEYOBJ,
			SAF_R_INVALID_INPUT_LENGTH);
		return -1;
	}

	/* init object */
	if (!(obj = OPENSSL_zalloc(sizeof(*obj)))) {
		SAFerr(SAF_F_SAF_CREATESYMMKEYOBJ,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	obj->hAppHandle = hAppHandle;
	if (!(obj->pucContainerName = OPENSSL_memdup(pucContainerName,
		(size_t)uiContainerLen))) {
		SAFerr(SAF_F_SAF_CREATESYMMKEYOBJ,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(obj->pucIV = OPENSSL_memdup(pucIV, (size_t)uiIVLen))) {
		SAFerr(SAF_F_SAF_CREATESYMMKEYOBJ,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	obj->uiEncOrDec = uiEncOrDec;

	if (!EVP_get_cipherbysgd(uiCryptoAlgID)) {
		SAFerr(SAF_F_SAF_CREATESYMMKEYOBJ,
			SAF_R_INVALID_ALGOR);
		goto end;
	}
	obj->uiCryptoAlgID = uiCryptoAlgID;

	/* set output */
	*phSymmKeyObj = obj;
	obj = NULL;

	ret = SAR_OK;

end:
	(void)SAF_DestroySymmAlgoObj(obj);
	return ret;
}

/* 7.3.36 */
int SAF_DestroySymmAlgoObj(
	void *hSymmKeyObj)
{
	SAF_SymmKeyObj *obj = (SAF_SymmKeyObj *)hSymmKeyObj;

	if (!hSymmKeyObj) {
		return SAR_OK;
	}

	OPENSSL_free(obj->pucContainerName);
	OPENSSL_free(obj->pucIV);
	memset(obj, 0, sizeof(*obj));
	return SAR_OK;
}
