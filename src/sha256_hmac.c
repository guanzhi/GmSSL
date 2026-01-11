/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include <gmssl/sha2.h>
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

void sha256_hmac_init(SHA256_HMAC_CTX *ctx, const uint8_t *key, size_t key_len)
{
	int i;

	if (key_len <= SHA256_BLOCK_SIZE) {
		memcpy(ctx->key, key, key_len);
		memset(ctx->key + key_len, 0, SHA256_BLOCK_SIZE - key_len);
	} else {
		sha256_init(&ctx->sha256_ctx);
		sha256_update(&ctx->sha256_ctx, key, key_len);
		sha256_finish(&ctx->sha256_ctx, ctx->key);
		memset(ctx->key + SHA256_DIGEST_SIZE, 0,
			SHA256_BLOCK_SIZE - SHA256_DIGEST_SIZE);
	}
	for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
		ctx->key[i] ^= IPAD;
	}

	sha256_init(&ctx->sha256_ctx);
	sha256_update(&ctx->sha256_ctx, ctx->key, SHA256_BLOCK_SIZE);
}

void sha256_hmac_update(SHA256_HMAC_CTX *ctx, const uint8_t *data, size_t data_len)
{
	sha256_update(&ctx->sha256_ctx, data, data_len);
}

void sha256_hmac_finish(SHA256_HMAC_CTX *ctx, uint8_t mac[SHA256_HMAC_SIZE])
{
	int i;
	for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
		ctx->key[i] ^= (IPAD ^ OPAD);
	}
	sha256_finish(&ctx->sha256_ctx, mac);
	sha256_init(&ctx->sha256_ctx);
	sha256_update(&ctx->sha256_ctx, ctx->key, SHA256_BLOCK_SIZE);
	sha256_update(&ctx->sha256_ctx, mac, SHA256_DIGEST_SIZE);
	sha256_finish(&ctx->sha256_ctx, mac);
}
