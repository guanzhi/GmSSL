/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>


// sm4_ofb_encrypt iv type is not compatible with sm4_cbc_encrypt, careful if inlen % 16 != 0
void sm4_ofb_encrypt(const SM4_KEY *key, uint8_t iv[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		sm4_encrypt(key, iv, iv);
		gmssl_memxor(out, in, iv, len);
		in += len;
		out += len;
		inlen -= len;
	}
}

int sm4_ofb_encrypt_init(SM4_OFB_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE])
{
	if (!ctx || !key || !iv) {
		error_print();
		return -1;
	}
	sm4_set_encrypt_key(&ctx->sm4_key, key);
	memcpy(ctx->iv, iv, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_ofb_encrypt_update(SM4_OFB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t left;
	size_t nblocks;
	size_t len;

	if (!ctx || !in || !outlen) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = 16 * ((inlen + 15)/16);
		return 1;
	}
	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (ctx->block_nbytes) {
		left = SM4_BLOCK_SIZE - ctx->block_nbytes;
		if (inlen < left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		sm4_ofb_encrypt(&ctx->sm4_key, ctx->iv, ctx->block, SM4_BLOCK_SIZE, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_ofb_encrypt(&ctx->sm4_key, ctx->iv, in, len, out);
		in += len;
		inlen -= len;
		*outlen += len;
	}
	if (inlen) {
		memcpy(ctx->block, in, inlen);
	}
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_ofb_encrypt_finish(SM4_OFB_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (!ctx || !outlen) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = SM4_BLOCK_SIZE;
		return 1;
	}
	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	sm4_ofb_encrypt(&ctx->sm4_key, ctx->iv, ctx->block, ctx->block_nbytes, out);
	*outlen = ctx->block_nbytes;
	return 1;
}

