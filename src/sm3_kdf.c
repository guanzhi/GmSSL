/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/endian.h>
#include <gmssl/error.h>


void sm3_kdf_init(SM3_KDF_CTX *ctx, size_t outlen)
{
	sm3_init(&ctx->sm3_ctx);
	ctx->outlen = outlen;
}

void sm3_kdf_update(SM3_KDF_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
}

void sm3_kdf_finish(SM3_KDF_CTX *ctx, uint8_t *out)
{
	SM3_CTX sm3_ctx;
	size_t outlen = ctx->outlen;
	uint8_t counter_be[4];
	uint8_t dgst[SM3_DIGEST_SIZE];
	uint32_t counter = 1;
	size_t len;

	while (outlen) {
		PUTU32(counter_be, counter);
		counter++;

		sm3_ctx = ctx->sm3_ctx;
		sm3_update(&sm3_ctx, counter_be, sizeof(counter_be));
		sm3_finish(&sm3_ctx, dgst);

		len = outlen < SM3_DIGEST_SIZE ? outlen : SM3_DIGEST_SIZE;
		memcpy(out, dgst, len);
		out += len;
		outlen -= len;
	}

	memset(&sm3_ctx, 0, sizeof(SM3_CTX));
	memset(dgst, 0, sizeof(dgst));
}
