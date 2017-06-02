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
#include <openssl/gmsaf.h>
#include <openssl/crypto.h>
#include "saf_lcl.h"

/* 7.1.2 */
int SAF_Initialize(
	void **phAppHandle,
	char *pubCfgFilePath)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = NULL;
	char *engine_id = pubCfgFilePath;

	if (!phAppHandle || !pubCfgFilePath) {
		SAFerr(SAF_F_SAF_INITIALIZE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!(app = OPENSSL_zalloc(sizeof(*app)))) {
		SAFerr(SAF_F_SAF_INITIALIZE, ERR_R_MALLOC_FAILURE);
		return SAR_MemoryErr;
	}

	if (!(app->engine = ENGINE_by_id(engine_id))
		|| !ENGINE_init(app->engine)) {
		SAFerr(SAF_F_SAF_INITIALIZE, ERR_R_ENGINE_LIB);
		goto end;
	}

	*phAppHandle = app;
	app = NULL;
	ret = SAR_Ok;

end:
	SAF_Finalize(app);
	return ret;
}

/* 7.1.3 */
int SAF_Finalize(
	void *hAppHandle)
{
	SAF_APP *app = (SAF_APP *)hAppHandle;

	if (app->engine) {
		ENGINE_finish(app->engine);
		ENGINE_free(app->engine);
	}

	OPENSSL_free(app);
	return SAR_Ok;
}

/* 7.1.4 */
int SAF_GetVersion(
	unsigned int *puiVersion)
{
	if (!puiVersion) {
		SAFerr(SAF_F_SAF_GETVERSION, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	*puiVersion = (unsigned int)OpenSSL_version_num();
	return SAR_Ok;
}

/* 7.1.5 */
int SAF_Login(
	void *hAppHandle,
	unsigned int uiUsrType,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned char *pucPin,
	unsigned int uiPinLen,
	unsigned int *puiRemainCount)
{
	SAFerr(SAF_F_SAF_LOGIN, SAF_R_NOT_SUPPORTED);
	return SAR_NotSupportYetErr;
}

/* 7.1.6 */
int SAF_ChangePin(
	void *hAppHandle,
	unsigned int uiUsrType,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned char *pucOldPin,
	unsigned int uiOldPinLen,
	unsigned char *pucNewPin,
	unsigned int uiNewPinLen,
	unsigned int *puiRemainCount)
{
	SAFerr(SAF_F_SAF_CHANGEPIN, SAF_R_NOT_SUPPORTED);
	return SAR_NotSupportYetErr;
}

/* 7.1.7 */
int SAF_Logout(
	void *hAppHandle,
	unsigned int uiUsrType)
{
	SAFerr(SAF_F_SAF_LOGOUT, SAF_R_NOT_SUPPORTED);
	return SAR_NotSupportYetErr;
}
