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
#include <openssl/rand.h>
#include <openssl/gmsdf.h>
#include <openssl/engine.h>
#include "sdf_lcl.h"

/*
 * Unlike the `SDF_OpenDevice`, we always assume that the `SDF_OpenSession` can
 * be called multiple times, and the implementation will always return a new
 * session handle on success. But noramlly the hardware and the software can
 * only support limited sessions, so this function can also failed.
 *
 * For portability, the application should assume that only one cryptographic
 * operation can be processed over one session. For example, do not mix
 * symmetric encryption and hash functions over the same session. The
 * implementation might support multiple operations, check the vendor's manual.
 */

/*
 * there are two purpose for session:
 * (1) hold session information
 * (2) a reference to ENGINE
 */
/*
typedef struct {
	uint32_t magic;
	char *app;
	ENGINE *engine;
	char *passwords[SDF_MAX_KEY_INDEX];
	EVP_MD_CTX *md_ctx;
} SDF_SESSION;
*/

int SDF_OpenSession(
	void *hDeviceHandle,
	void **phSessionHandle)
{
	int ret = SDR_UNKNOWERR;
	SDF_SESSION *session = NULL;

	if (!hDeviceHandle || !phSessionHandle) {
		SDFerr(SDF_F_SDF_OPENSESSION, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_INARGERR;
	}
	if (hDeviceHandle != deviceHandle) {
		SDFerr(SDF_F_SDF_OPENSESSION, SDF_R_INVALID_DEVICE_HANDLE);
		return SDR_INARGERR;
	}

	if (!(session = OPENSSL_zalloc(sizeof(*session)))) {
		SDFerr(SDF_F_SDF_OPENSESSION, ERR_R_MALLOC_FAILURE);
		ret = SDR_NOBUFFER;
		goto end;
	}

	session->magic = SDF_SESSION_MAGIC;

#ifndef OPENSSL_NO_ENGINE
	if (!(session->engine = ENGINE_by_id(SDF_ENGINE_ID))) {
		SDFerr(SDF_F_SDF_OPENSESSION, SDF_R_LOAD_ENGINE_FAILURE);
		ret = SDR_HARDFAIL;
		goto end;
	}
#endif

	*phSessionHandle = session;
	session = NULL;
	ret = SDR_OK;

end:
	OPENSSL_free(session);
	return ret;
}

int SDF_CloseSession(
	void *hSessionHandle)
{
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	int i;

	if (!hSessionHandle) {
		return SDR_OK;
	}

	if (session->magic != SDF_SESSION_MAGIC) {
		SDFerr(SDF_F_SDF_CLOSESESSION, SDF_R_INVALID_SESSION);
		return SDR_INARGERR;
	}

#ifndef OPENSSL_NO_ENGINE
	if (session->engine) {
		ENGINE_finish(session->engine);
		ENGINE_free(session->engine);
		session->engine = NULL;
	}
#endif

	for (i = 0; i <= SDF_MAX_KEY_INDEX; i++) {
		OPENSSL_clear_free(session->password[i],
			strlen(session->password[i]));
		session->password[i] = NULL;
	}

	OPENSSL_free(session);
	return SDR_OK;
}

/* we try that the password is correct by `ENGINE_load_private_key`, then we
 * destory the returned `EVP_PKEY` and keep the verified password in the
 * session. We can use `UI_set_result` to pass the password to the ENGINE
 */
int SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength)
{
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	EVP_PKEY *pkey = NULL;
	char *key_id = NULL;
	UI_METHOD *ui_meth = NULL;
	void *cb_data = NULL;

	if (!hSessionHandle || !pucPassword) {
		SDFerr(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_INARGERR;
	}
	if (session->magic != SDF_SESSION_MAGIC) {
		SDFerr(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT,
			SDF_R_INVALID_SESSION_HANDLE);
		return SDR_INARGERR;
	}
	if (uiKeyIndex <= 0 || uiKeyIndex > SDF_MAX_KEY_INDEX) {
		SDFerr(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT,
			SDF_R_INVALID_KEY_INDEX);
		return -1;
	}
	if (uiPwdLength <= 0 || uiPwdLength > INT_MAX) {
		SDFerr(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT,
			SDF_R_INVALID_PASSWORD_LENGTH);
		return SDR_INARGERR;
	}

	if (!(pkey = ENGINE_load_private_key(session->engine, key_id,
		ui_meth, cb_data))) {
		SDFerr(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT, ERR_R_ENGINE_LIB);
		return 0;
	}

	return SDR_OK;
}

int SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex)
{
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;

	if (!hSessionHandle) {
		SDFerr(SDF_F_SDF_RELEASEPRIVATEKEYACCESSRIGHT,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_INARGERR;
	}
	if (session->magic != SDF_SESSION_MAGIC) {
		SDFerr(SDF_F_SDF_RELEASEPRIVATEKEYACCESSRIGHT,
			SDF_R_INVALID_SESSION_HANDLE);
		return SDR_INARGERR;
	}
	if (uiKeyIndex <= 0 || uiKeyIndex > SDF_MAX_KEY_INDEX) {
		SDFerr(SDF_F_SDF_RELEASEPRIVATEKEYACCESSRIGHT,
			SDF_R_INVALID_KEY_INDEX);
		return -1;
	}

	if (session->password[uiKeyIndex]) {
		OPENSSL_clear_free(session->password[uiKeyIndex],
			strlen(session->password[uiKeyIndex]));
		session->password[uiKeyIndex] = NULL;
	}

	return SDR_OK;
}

