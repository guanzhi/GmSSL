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


int sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t piv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t iv[16];
	uint8_t block[16];
	size_t rem = inlen % 16;
	int padding = 16 - inlen % 16;

	memcpy(iv, piv, 16);

	if (in) {
		memcpy(block, in + inlen - rem, rem);
	}
	memset(block + rem, padding, padding);

	if (inlen/16) {
		sm4_cbc_encrypt_blocks(key, iv, in, inlen/16, out);
		out += inlen - rem;
	}
	sm4_cbc_encrypt_blocks(key, iv, block, 1, out);
	*outlen = inlen - rem + 16;
	return 1;
}

int sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t piv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t iv[16];
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;

	memcpy(iv, piv, 16);

	if (inlen == 0) {
		error_puts("warning: input lenght = 0");
		return 0;
	}
	if (inlen%16 != 0 || inlen < 16) {
		error_puts("invalid cbc ciphertext length");
		return -1;
	}
	if (inlen > 16) {
		sm4_cbc_decrypt_blocks(key, iv, in, inlen/16 - 1, out);
	}

	sm4_cbc_decrypt_blocks(key, iv, in + inlen - 16, 1, block);

	padding = block[15];
	if (padding < 1 || padding > 16) {
		error_print();
		return -1;
	}
	len -= padding;
	memcpy(out + inlen - 16, block, len);
	*outlen = inlen - padding;
	return 1;
}

int sm4_cbc_encrypt_init(SM4_CBC_CTX *ctx,
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

int sm4_cbc_encrypt_update(SM4_CBC_CTX *ctx,
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
		sm4_cbc_encrypt_blocks(&ctx->sm4_key, ctx->iv, ctx->block, 1, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_cbc_encrypt_blocks(&ctx->sm4_key, ctx->iv, in, nblocks, out);
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

int sm4_cbc_encrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen)
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
	if (sm4_cbc_padding_encrypt(&ctx->sm4_key, ctx->iv, ctx->block, ctx->block_nbytes, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm4_cbc_decrypt_init(SM4_CBC_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE])
{
	if (!ctx || !key || !iv) {
		error_print();
		return -1;
	}
	sm4_set_decrypt_key(&ctx->sm4_key, key);
	memcpy(ctx->iv, iv, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_cbc_decrypt_update(SM4_CBC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t left, len, nblocks;

	if (!ctx || !in || !outlen) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = 16 * ((inlen + 15)/16);
		return 1;
	}
	if (ctx->block_nbytes > SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}

	*outlen = 0;
	if (ctx->block_nbytes) {
		left = SM4_BLOCK_SIZE - ctx->block_nbytes;
		if (inlen <= left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		sm4_cbc_decrypt_blocks(&ctx->sm4_key, ctx->iv, ctx->block, 1, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen > SM4_BLOCK_SIZE) {
		nblocks = (inlen-1) / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_cbc_decrypt_blocks(&ctx->sm4_key, ctx->iv, in, nblocks, out);
		in += len;
		inlen -= len;
		*outlen += len;
	}
	memcpy(ctx->block, in, inlen);
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_cbc_decrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (!ctx || !outlen) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = SM4_BLOCK_SIZE;
		return 1;
	}
	if (ctx->block_nbytes != SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (sm4_cbc_padding_decrypt(&ctx->sm4_key, ctx->iv, ctx->block, SM4_BLOCK_SIZE, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
