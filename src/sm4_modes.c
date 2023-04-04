/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/gcm.h>
#include <gmssl/error.h>

void sm4_cbc_encrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		gmssl_memxor(out, in, iv, 16);
		sm4_encrypt(key, out, out);
		iv = out;
		in += 16;
		out += 16;
	}
}

void sm4_cbc_decrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		sm4_encrypt(key, in, out);
		memxor(out, iv, 16);
		iv = in;
		in += 16;
		out += 16;
	}
}

int sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t rem = inlen % 16;
	int padding = 16 - inlen % 16;

	if (in) {
		memcpy(block, in + inlen - rem, rem);
	}
	memset(block + rem, padding, padding);
	if (inlen/16) {
		sm4_cbc_encrypt(key, iv, in, inlen/16, out);
		out += inlen - rem;
		iv = out - 16;
	}
	sm4_cbc_encrypt(key, iv, block, 1, out);
	*outlen = inlen - rem + 16;
	return 1;
}

int sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;

	if (inlen == 0) {
		error_puts("warning: input lenght = 0");
		return 0;
	}
	if (inlen%16 != 0 || inlen < 16) {
		error_puts("invalid cbc ciphertext length");
		return -1;
	}
	if (inlen > 16) {
		sm4_cbc_decrypt(key, iv, in, inlen/16 - 1, out);
		iv = in + inlen - 32;
	}
	sm4_cbc_decrypt(key, iv, in + inlen - 16, 1, block);

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

static void ctr_incr(uint8_t a[16])
{
	int i;
	for (i = 15; i >= 0; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

#ifndef SM4_AESNI_AVX
void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		sm4_encrypt(key, ctr, block);
		gmssl_memxor(out, in, block, len);
		ctr_incr(ctr);
		in += len;
		out += len;
		inlen -= len;
	}
}
#endif

int sm4_gcm_encrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	const uint8_t *pin = in;
	uint8_t *pout = out;
	size_t left = inlen;
	uint8_t H[16] = {0};
	uint8_t Y[16];
	uint8_t T[16];

	if (taglen > SM4_GCM_MAX_TAG_SIZE) {
		error_print();
		return -1;
	}

	sm4_encrypt(key, H, H);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	sm4_encrypt(key, Y, T);

	while (left) {
		uint8_t block[16];
		size_t len = left < 16 ? left : 16;
		ctr_incr(Y);
		sm4_encrypt(key, Y, block);
		gmssl_memxor(pout, pin, block, len);
		pin += len;
		pout += len;
		left -= len;
	}

	ghash(H, aad, aadlen, out, inlen, H);
	gmssl_memxor(tag, T, H, taglen);
	return 1;
}

int sm4_gcm_decrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	const uint8_t *pin = in;
	uint8_t *pout = out;
	size_t left = inlen;
	uint8_t H[16] = {0};
	uint8_t Y[16];
	uint8_t T[16];

	sm4_encrypt(key, H, H);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	ghash(H, aad, aadlen, in, inlen, H);
	sm4_encrypt(key, Y, T);
	gmssl_memxor(T, T, H, taglen);
	if (memcmp(T, tag, taglen) != 0) {
		error_print();
		return -1;
	}

	while (left) {
		uint8_t block[16];
		size_t len = left < 16 ? left : 16;
		ctr_incr(Y);
		sm4_encrypt(key, Y, block);
		gmssl_memxor(pout, pin, block, len);
		pin += len;
		pout += len;
		left -= len;
	}
	return 1;
}

int sm4_cbc_encrypt_init(SM4_CBC_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE])
{
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
		sm4_cbc_encrypt(&ctx->sm4_key, ctx->iv, ctx->block, 1, out);
		memcpy(ctx->iv, out, SM4_BLOCK_SIZE);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_cbc_encrypt(&ctx->sm4_key, ctx->iv, in, nblocks, out);
		memcpy(ctx->iv, out + len - SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
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

int sm4_cbc_encrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen)
{
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
		sm4_cbc_decrypt(&ctx->sm4_key, ctx->iv, ctx->block, 1, out);
		memcpy(ctx->iv, ctx->block, SM4_BLOCK_SIZE);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen > SM4_BLOCK_SIZE) {
		nblocks = (inlen-1) / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_cbc_decrypt(&ctx->sm4_key, ctx->iv, in, nblocks, out);
		memcpy(ctx->iv, in + len - SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
		in += len;
		inlen -= len;
		out += len;
		*outlen += len;
	}
	memcpy(ctx->block, in, inlen);
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_cbc_decrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen)
{
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

int sm4_ctr_encrypt_init(SM4_CTR_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t ctr[SM4_BLOCK_SIZE])
{
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
		sm4_ctr_encrypt(&ctx->sm4_key, ctx->ctr, ctx->block, SM4_BLOCK_SIZE, out);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		sm4_ctr_encrypt(&ctx->sm4_key, ctx->ctr, in, len, out);
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

int sm4_ctr_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	sm4_ctr_encrypt(&ctx->sm4_key, ctx->ctr, ctx->block, ctx->block_nbytes, out);
	*outlen = ctx->block_nbytes;
	return 1;
}
