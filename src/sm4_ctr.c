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


void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	if (inlen >= 16) {
		size_t nblocks = inlen / 16;
		size_t len = nblocks * 16;
		sm4_ctr_encrypt_blocks(key, ctr, in, nblocks, out);
		in += len;
		out += len;
		inlen -= len;
	}
	if (inlen) {
		uint8_t block[16] = {0};
		memcpy(block, in, inlen);
		sm4_ctr_encrypt_blocks(key, ctr, block, 1, block);
		memcpy(out, block, inlen);
	}
}

void sm4_ctr32_encrypt(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	if (inlen >= 16) {
		size_t nblocks = inlen / 16;
		size_t len = nblocks * 16;
		sm4_ctr32_encrypt_blocks(key, ctr, in, nblocks, out);
		in += len;
		out += len;
		inlen -= len;
	}
	if (inlen) {
		uint8_t block[16] = {0};
		memcpy(block, in, inlen);
		sm4_ctr32_encrypt_blocks(key, ctr, block, 1, block);
		memcpy(out, block, inlen);
	}
}

int sm4_ctr_encrypt_init(SM4_CTR_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t ctr[SM4_BLOCK_SIZE])
{
	if (!ctx || !key || !ctr) {
		error_print();
		return -1;
	}
	sm4_set_encrypt_key(&ctx->sm4_key, key);
	memcpy(ctx->ctr, ctr, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_ctr_encrypt_update(SM4_CTR_CTX *ctx,
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
		sm4_ctr_encrypt_blocks(&ctx->sm4_key, ctx->ctr, ctx->block, 1, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_ctr_encrypt_blocks(&ctx->sm4_key, ctx->ctr, in, nblocks, out);
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

int sm4_ctr_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen)
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
	sm4_ctr_encrypt_blocks(&ctx->sm4_key, ctx->ctr, ctx->block, 1, ctx->block);
	memcpy(out, ctx->block, ctx->block_nbytes);
	*outlen = ctx->block_nbytes;
	return 1;
}

int sm4_ctr32_encrypt_init(SM4_CTR_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t ctr[SM4_BLOCK_SIZE])
{
	if (!ctx || !key || !ctr) {
		error_print();
		return -1;
	}
	sm4_set_encrypt_key(&ctx->sm4_key, key);
	memcpy(ctx->ctr, ctr, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_ctr32_encrypt_update(SM4_CTR_CTX *ctx,
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
		sm4_ctr32_encrypt_blocks(&ctx->sm4_key, ctx->ctr, ctx->block, 1, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_ctr32_encrypt_blocks(&ctx->sm4_key, ctx->ctr, in, nblocks, out);
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

int sm4_ctr32_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen)
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
	sm4_ctr32_encrypt_blocks(&ctx->sm4_key, ctx->ctr, ctx->block, 1, ctx->block);
	memcpy(out, ctx->block, ctx->block_nbytes);
	*outlen = ctx->block_nbytes;
	return 1;
}
