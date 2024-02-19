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


void sm4_cfb_encrypt(const SM4_KEY *key, size_t sbytes, uint8_t iv[16],
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len, i;

	// assert(1 <= sbytes && sbytes <= 16);

	while (inlen) {
		len = inlen < sbytes ? inlen : sbytes;
		sm4_encrypt(key, iv, block);
		gmssl_memxor(out, in, block, len);

		// iv = (iv << sbytes) | out
		for (i = 0; i < 16 - sbytes; i++) {
			iv[i] = iv[sbytes + i];
		}
		memcpy(iv + i, out, len);

		in += len;
		out += len;
		inlen -= len;
	}
}

void sm4_cfb_decrypt(const SM4_KEY *key, size_t sbytes, uint8_t iv[16],
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len, i;

	// assert(1 <= sbytes && sbytes <= 16);

	while (inlen) {
		len = inlen < sbytes ? inlen : sbytes;
		sm4_encrypt(key, iv, block);
		gmssl_memxor(out, in, block, len);

		// iv = (iv << sbytes) | in
		for (i = 0; i < 16 - sbytes; i++) {
			iv[i] = iv[sbytes + i];
		}
		memcpy(iv + i, in, len);

		in += len;
		out += len;
		inlen -= len;
	}
}

int sm4_cfb_encrypt_init(SM4_CFB_CTX *ctx, size_t sbytes,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE])
{
	if (sbytes < 1 || sbytes > 16) {
		error_print();
		return -1;
	}
	sm4_set_encrypt_key(&ctx->sm4_key, key);
	memcpy(ctx->iv, iv, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	ctx->sbytes = sbytes;
	return 1;
}

int sm4_cfb_encrypt_update(SM4_CFB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t left;
	size_t nblocks;
	size_t len;

	if (ctx->block_nbytes >= ctx->sbytes) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (ctx->block_nbytes) {
		left = ctx->sbytes - ctx->block_nbytes;
		if (inlen < left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		sm4_cfb_encrypt(&ctx->sm4_key, ctx->sbytes, ctx->iv, ctx->block, ctx->sbytes, out);
		in += left;
		inlen -= left;
		out += ctx->sbytes;
		*outlen += ctx->sbytes;
	}
	if (inlen >= ctx->sbytes) {
		nblocks = inlen / ctx->sbytes;
		len = nblocks * ctx->sbytes;
		sm4_cfb_encrypt(&ctx->sm4_key, ctx->sbytes, ctx->iv, in, len, out);
		in += len;
		inlen -= len;
		out += len;
		*outlen += len;
	}
	if (inlen) {
		memcpy(ctx->block, in, inlen);
	}
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_cfb_encrypt_finish(SM4_CFB_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (ctx->block_nbytes >= ctx->sbytes) {
		error_print();
		return -1;
	}
	sm4_cfb_encrypt(&ctx->sm4_key, ctx->sbytes, ctx->iv, ctx->block, ctx->block_nbytes, out);
	*outlen = ctx->block_nbytes;
	return 1;
}

int sm4_cfb_decrypt_init(SM4_CFB_CTX *ctx, size_t sbytes,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE])
{
	if (sbytes < 1 || sbytes > 16) {
		error_print();
		return -1;
	}
	sm4_set_encrypt_key(&ctx->sm4_key, key);
	memcpy(ctx->iv, iv, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	ctx->sbytes = sbytes;
	return 1;
}

int sm4_cfb_decrypt_update(SM4_CFB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t left;
	size_t nblocks;
	size_t len;

	if (ctx->block_nbytes >= ctx->sbytes) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (ctx->block_nbytes) {
		left = ctx->sbytes - ctx->block_nbytes;
		if (inlen < left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		sm4_cfb_decrypt(&ctx->sm4_key, ctx->sbytes, ctx->iv, ctx->block, ctx->sbytes, out);
		in += left;
		inlen -= left;
		out += ctx->sbytes;
		*outlen += ctx->sbytes;
	}
	if (inlen >= ctx->sbytes) {
		nblocks = inlen / ctx->sbytes;
		len = nblocks * ctx->sbytes;
		sm4_cfb_decrypt(&ctx->sm4_key, ctx->sbytes, ctx->iv, in, len, out);
		in += len;
		inlen -= len;
		out += len;
		*outlen += len;
	}
	if (inlen) {
		memcpy(ctx->block, in, inlen);
	}
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_cfb_decrypt_finish(SM4_CFB_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (ctx->block_nbytes >= ctx->sbytes) {
		error_print();
		return -1;
	}
	sm4_cfb_decrypt(&ctx->sm4_key, ctx->sbytes, ctx->iv, ctx->block, ctx->block_nbytes, out);
	*outlen = ctx->block_nbytes;
	return 1;
}

