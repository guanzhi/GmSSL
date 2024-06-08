/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sdf.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>
#include "sdf.h"
#include "sdf_ext.h"


void *globalDeviceHandle = NULL;


typedef struct {
	void *hSession;
} SDF_SM3_CTX;


int sm3_digest_init(SM3_DIGEST_CTX *ctx, const uint8_t *key, size_t keylen)
{
	SDF_SM3_CTX *sdf_sm3_ctx = (SDF_SM3_CTX *)&ctx->sm3_ctx;
	void *hSession = NULL;
	int ret;

	if (globalDeviceHandle == NULL) {
		if ((ret = SDF_OpenDevice(&globalDeviceHandle)) != SDR_OK) {
			error_print_msg("SDFerror: 0x%08X\n", ret);
			return -1;
		}
		if (globalDeviceHandle == NULL) {
			error_print();
			return -1;
		}
	}

	if ((ret = SDF_OpenSession(globalDeviceHandle, &hSession)) != SDR_OK) {
		error_print_msg("SDFerror: 0x%08X\n", ret);
		return -1;
	}

	if ((ret = SDF_HashInit(hSession, SGD_SM3, NULL, NULL, 0)) != SDR_OK) {
		error_print_msg("SDFerror: 0x%08X\n", ret);
		return -1;
	}

	sdf_sm3_ctx->hSession = hSession;
	return 1;
}

int sm3_digest_update(SM3_DIGEST_CTX *ctx, const uint8_t *data, size_t datalen)
{
	SDF_SM3_CTX *sdf_sm3_ctx = (SDF_SM3_CTX *)&ctx->sm3_ctx;
	int ret;

	if ((ret = SDF_HashUpdate(sdf_sm3_ctx->hSession, (uint8_t *)data, (unsigned int)datalen)) != SDR_OK) {
		error_print_msg("SDFerror: 0x%08X\n", ret);
		return -1;
	}
	return 1;
}

int sm3_digest_finish(SM3_DIGEST_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE])
{
	SDF_SM3_CTX *sdf_sm3_ctx = (SDF_SM3_CTX *)&ctx->sm3_ctx;
	unsigned int dgstlen;
	int ret;

	if ((ret = SDF_HashFinal(sdf_sm3_ctx->hSession, dgst, &dgstlen)) != SDR_OK) {
		error_print_msg("SDFerror: 0x%08X\n", ret);
		return -1;
	}
	return 1;
}

int sm3_digest_reset(SM3_DIGEST_CTX *ctx)
{
	SDF_SM3_CTX *sdf_sm3_ctx = (SDF_SM3_CTX *)&ctx->sm3_ctx;
	int ret;

	if ((ret = SDF_HashInit(sdf_sm3_ctx->hSession, SGD_SM3, NULL, NULL, 0)) != SDR_OK) {
		error_print_msg("SDFerror: 0x%08X\n", ret);
		return -1;
	}
	return 1;
}

void sm3_digest_cleanup(SM3_DIGEST_CTX *ctx)
{
	SDF_SM3_CTX *sdf_sm3_ctx = (SDF_SM3_CTX *)&ctx->sm3_ctx;
	int ret;

	if ((ret = SDF_CloseSession(sdf_sm3_ctx->hSession)) != SDR_OK) {
		error_print_msg("SDFerror: 0x%08X\n", ret);
	}
	memset(ctx, 0, sizeof(*ctx));
}
