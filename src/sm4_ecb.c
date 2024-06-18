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


int sm4_ecb_encrypt_init(SM4_ECB_CTX *ctx, const uint8_t key[SM4_BLOCK_SIZE])
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	sm4_set_encrypt_key(&ctx->sm4_key, key);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_ecb_encrypt_update(SM4_ECB_CTX *ctx,
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
		sm4_encrypt_blocks(&ctx->sm4_key, ctx->block, 1, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_encrypt_blocks(&ctx->sm4_key, in, nblocks, out);
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

int sm4_ecb_encrypt_finish(SM4_ECB_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (!ctx || !outlen) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = SM4_BLOCK_SIZE; // anyway, caller should prepare a block buffer to support any length input
		return 1;
	}
	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (ctx->block_nbytes) {
		error_puts("invalid total input length");
		return -1;
	}
	*outlen = 0;
	return 1;
}

int sm4_ecb_decrypt_init(SM4_ECB_CTX *ctx, const uint8_t key[SM4_BLOCK_SIZE])
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	sm4_set_decrypt_key(&ctx->sm4_key, key);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_ecb_decrypt_update(SM4_ECB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (sm4_ecb_encrypt_update(ctx, in, inlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm4_ecb_decrypt_finish(SM4_ECB_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (sm4_ecb_encrypt_finish(ctx, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
