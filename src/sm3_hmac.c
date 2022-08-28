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
#include <gmssl/error.h>

/**
 * HMAC_k(m) = H((k ^ opad) || H((k ^ ipad) || m))
 * pseudo-code:
 * function hmac(key, message)
 *	opad = [0x5c * blocksize]
 *	ipad = [0x36 * blocksize]
 *	if (length(key) > blocksize) then
 *		key = hash(key)
 *	end if
 *	for i from 0 to length(key) - 1 step 1
 *		ipad[i] = ipad[i] XOR key[i]
 *		opad[i] = opad[i] XOR key[i]
 *	end for
 *	return hash(opad || hash(ipad || message))
 * end function
 */


#define IPAD	0x36
#define OPAD	0x5C

void sm3_hmac_init(SM3_HMAC_CTX *ctx, const uint8_t *key, size_t key_len)
{
	int i;

	if (key_len <= SM3_BLOCK_SIZE) {
		memcpy(ctx->key, key, key_len);
		memset(ctx->key + key_len, 0, SM3_BLOCK_SIZE - key_len);
	} else {
		sm3_init(&ctx->sm3_ctx);
		sm3_update(&ctx->sm3_ctx, key, key_len);
		sm3_finish(&ctx->sm3_ctx, ctx->key);
		memset(ctx->key + SM3_DIGEST_SIZE, 0,
			SM3_BLOCK_SIZE - SM3_DIGEST_SIZE);
	}
	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx->key[i] ^= IPAD;
	}

	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
}

void sm3_hmac_update(SM3_HMAC_CTX *ctx, const uint8_t *data, size_t data_len)
{
	sm3_update(&ctx->sm3_ctx, data, data_len);
}

void sm3_hmac_finish(SM3_HMAC_CTX *ctx, uint8_t mac[SM3_HMAC_SIZE])
{
	int i;
	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx->key[i] ^= (IPAD ^ OPAD);
	}
	sm3_finish(&ctx->sm3_ctx, mac);
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
	sm3_update(&ctx->sm3_ctx, mac, SM3_DIGEST_SIZE);
	sm3_finish(&ctx->sm3_ctx, mac);
	memset(ctx, 0, sizeof(*ctx));
}

void sm3_hmac(const uint8_t *key, size_t key_len,
	const uint8_t *data, size_t data_len,
	uint8_t mac[SM3_HMAC_SIZE])
{
	SM3_HMAC_CTX ctx;
	sm3_hmac_init(&ctx, key, key_len);
	sm3_hmac_update(&ctx, data, data_len);
	sm3_hmac_finish(&ctx, mac);
}
