/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include <gmssl/mem.h>
#include <gmssl/hmac.h>
#include <gmssl/error.h>


#define IPAD	0x36
#define OPAD	0x5C


int hmac_init(HMAC_CTX *ctx, const DIGEST *digest, const uint8_t *key, size_t keylen)
{
	uint8_t i_key[DIGEST_MAX_BLOCK_SIZE] = {0};
	uint8_t o_key[sizeof(i_key)] = {0};
	size_t blocksize;
	size_t i;

	if (!ctx || !digest) {
		error_print();
		return -1;
	}
	if (digest->block_size > sizeof(i_key)
		|| digest->digest_size > HMAC_MAX_SIZE
		|| !digest->digest_size
		|| !digest->block_size) {
		error_print();
		return -1;
	}
	if (!key && keylen) {
		error_print();
		return -1;
	}

	ctx->digest = digest;
	blocksize = digest->block_size;

	if (key) {
		if (keylen > blocksize) {
			if (digest_init(&ctx->digest_ctx, digest) != 1
				|| digest_update(&ctx->digest_ctx, key, keylen) != 1
				|| digest_finish(&ctx->digest_ctx, i_key, &keylen) != 1) {
				error_print();
				return -1;
			}
			memcpy(o_key, i_key, keylen);
		} else if (keylen) {
			memcpy(i_key, key, keylen);
			memcpy(o_key, key, keylen);
		}
	}

	for (i = 0; i < blocksize; i++) {
		i_key[i] ^= IPAD;
		o_key[i] ^= OPAD;
	}

	if (digest_init(&ctx->i_ctx, digest) != 1
		|| digest_update(&ctx->i_ctx, i_key, blocksize) != 1
		|| digest_init(&ctx->o_ctx, digest) != 1
		|| digest_update(&ctx->o_ctx, o_key, blocksize) != 1) {
		error_print();
		return -1;
	}
	memcpy(&ctx->digest_ctx, &ctx->i_ctx, sizeof(DIGEST_CTX));

	gmssl_secure_clear(i_key, sizeof(i_key));
	gmssl_secure_clear(o_key, sizeof(o_key));
	return 1;
}

int hmac_update(HMAC_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (!data && datalen) {
		error_print();
		return -1;
	}
	if (!data || datalen == 0) {
		return 1;
	}
	if (digest_update(&ctx->digest_ctx, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hmac_finish(HMAC_CTX *ctx, uint8_t *mac, size_t *maclen)
{
	if (!ctx || !mac || !maclen) {
		error_print();
		return -1;
	}
	if (digest_finish(&ctx->digest_ctx, mac, maclen) != 1) {
		error_print();
		return -1;
	}
	memcpy(&ctx->digest_ctx, &ctx->o_ctx, sizeof(DIGEST_CTX));
	if (digest_update(&ctx->digest_ctx, mac, ctx->digest->digest_size) != 1
		|| digest_finish(&ctx->digest_ctx, mac, maclen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hmac(const DIGEST *digest, const uint8_t *key, size_t keylen,
	const uint8_t *data, size_t datalen,
	uint8_t *mac, size_t *maclen)
{
	HMAC_CTX ctx;
	if (hmac_init(&ctx, digest, key, keylen) != 1
		|| hmac_update(&ctx, data, datalen) != 1
		|| hmac_finish(&ctx, mac, maclen) != 1) {
		gmssl_secure_clear(&ctx, sizeof(ctx));
		return -1;
	}
	gmssl_secure_clear(&ctx, sizeof(ctx));
	return 1;
}
