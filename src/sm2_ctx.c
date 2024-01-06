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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	ctx->key = *key;
	sm3_init(&ctx->sm3_ctx);

	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];
		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}
	return 1;
}

int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if (sm2_sign(&ctx->key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_sign_finish_fixlen(SM2_SIGN_CTX *ctx, size_t siglen, uint8_t *sig)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if (sm2_sign_fixlen(&ctx->key, dgst, siglen, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->key.public_key = key->public_key;
	sm3_init(&ctx->sm3_ctx);

	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];
		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}
	return 1;
}

int sm2_verify_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sm2_verify_finish(SM2_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if (sm2_verify(&ctx->key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

