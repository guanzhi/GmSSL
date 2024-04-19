/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/error.h>


int sm3_digest_init(SM3_DIGEST_CTX *ctx, const uint8_t *key, size_t keylen)
{
	if (!ctx) {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));

	if (!key) {
		sm3_init(&ctx->sm3_ctx);
		ctx->state = 1;
	} else {
		if (keylen < 12 || keylen > 64) {
			error_print();
			return -1;
		}
		sm3_hmac_init(&ctx->hmac_ctx, key, keylen);
		ctx->state = 2;
	}

	return 1;
}

int sm3_digest_update(SM3_DIGEST_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (!data || !datalen) {
		error_print();
		return -1;
	}

	if (ctx->state == 1) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	} else if (ctx->state == 2) {
		sm3_hmac_update(&ctx->hmac_ctx, data, datalen);
	} else {
		error_print();
		return -1;
	}
	return 1;
}

int sm3_digest_finish(SM3_DIGEST_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE])
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}

	if (ctx->state == 1) {
		sm3_finish(&ctx->sm3_ctx, dgst);
	} else if (ctx->state == 2) {
		sm3_hmac_finish(&ctx->hmac_ctx, dgst);
	} else {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	return 1;
}
