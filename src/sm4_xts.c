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
#include <gmssl/gf128.h>
#include <gmssl/error.h>


int sm4_xts_encrypt(const SM4_KEY *key1, const SM4_KEY *key2, const uint8_t tweak[16],
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t T[16];
	uint8_t block[16];
	size_t nblocks, i;
	gf128_t a;

	if (inlen < 16) {
		error_print();
		return -1;
	}
	nblocks = inlen / 16 + 1;

	memcpy(T, tweak, 16);
	sm4_encrypt(key2, T, T);

	for (i = 0; i < nblocks - 2; i++) {
		gmssl_memxor(block, in, T, 16);
		sm4_encrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);

		gf128_from_bytes(a, T);
		gf128_mul_by_2(a, a);
		gf128_to_bytes(a, T);

		in += 16;
		inlen -= 16;
		out += 16;
	}

	if (inlen % 16 == 0) {
		gmssl_memxor(block, in, T, 16);
		sm4_encrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);

	} else {
		gmssl_memxor(out, in, T, 16);
		sm4_encrypt(key1, out, out);
		gmssl_memxor(out, out, T, 16);

		gf128_from_bytes(a, T);
		gf128_mul_by_2(a, a);
		gf128_to_bytes(a, T);

		in += 16;
		inlen -= 16;

		memcpy(block, out, inlen); // backup last part of ciphertext

		memcpy(out, in, inlen);
		gmssl_memxor(out, out, T, 16);
		sm4_encrypt(key1, out, out);
		gmssl_memxor(out, out, T, 16);

		memcpy(out + 16, block, inlen);
	}

	return 1;
}

int sm4_xts_decrypt(const SM4_KEY *key1, const SM4_KEY *key2, const uint8_t tweak[16],
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t T[16];
	uint8_t block[16];
	size_t nblocks, i;
	gf128_t a;

	if (inlen < 16) {
		error_print();
		return -1;
	}
	nblocks = inlen / 16 + 1;

	memcpy(T, tweak, 16);
	sm4_encrypt(key2, T, T);

	for (i = 0; i < nblocks - 2; i++) {
		gmssl_memxor(block, in, T, 16);
		sm4_encrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);

		gf128_from_bytes(a, T);
		gf128_mul_by_2(a, a);
		gf128_to_bytes(a, T);

		in += 16;
		inlen -= 16;
		out += 16;
	}

	if (inlen % 16 == 0) {
		gmssl_memxor(block, in, T, 16);
		sm4_encrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);

	} else  {
		uint8_t T1[16];

		gf128_from_bytes(a, T);
		gf128_mul_by_2(a, a);
		gf128_to_bytes(a, T1);

		gmssl_memxor(out, in, T1, 16);
		sm4_encrypt(key1, out, out);
		gmssl_memxor(out, out, T1, 16);

		in += 16;
		inlen -= 16;

		memcpy(block, out, inlen); // backup last part of plaintext

		memcpy(out, in, inlen);
		gmssl_memxor(out, out, T, 16);
		sm4_encrypt(key1, out, out);
		gmssl_memxor(out, out, T, 16);

		memcpy(out + 16, block, inlen);
	}

	return 1;
}

static void tweak_incr(uint8_t a[16])
{
	int i;
	for (i = 0; i < 16; i++) {
		a[i]++;
		if (a[i]) break;
	}
}

int sm4_xts_encrypt_init(SM4_XTS_CTX *ctx, const uint8_t key[32], const uint8_t iv[16], size_t data_unit_size)
{
	if (data_unit_size < SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	sm4_set_encrypt_key(&ctx->key1, key);
	sm4_set_encrypt_key(&ctx->key2, key + 16);
	memcpy(ctx->tweak, iv, 16);
	ctx->data_unit_size = data_unit_size;
	if (!(ctx->block = (uint8_t *)malloc(data_unit_size))) {
		error_print();
		return -1;
	}
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_xts_encrypt_update(SM4_XTS_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t DATA_UNIT_SIZE = ctx->data_unit_size;
	size_t left;

	if (ctx->block_nbytes >= DATA_UNIT_SIZE) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (ctx->block_nbytes) {
		left = DATA_UNIT_SIZE - ctx->block_nbytes;
		if (inlen < left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		if (sm4_xts_encrypt(&ctx->key1, &ctx->key2, ctx->tweak, ctx->block, DATA_UNIT_SIZE, out) != 1) {
			error_print();
			return -1;
		}
		tweak_incr(ctx->tweak);
		in += left;
		inlen -= left;
		out += DATA_UNIT_SIZE;
		*outlen += DATA_UNIT_SIZE;
	}
	while (inlen >= DATA_UNIT_SIZE) {
		if (sm4_xts_encrypt(&ctx->key1, &ctx->key2, ctx->tweak, in, DATA_UNIT_SIZE, out) != 1) {
			error_print();
			return -1;
		}
		tweak_incr(ctx->tweak);
		in += DATA_UNIT_SIZE;
		inlen -= DATA_UNIT_SIZE;
		out += DATA_UNIT_SIZE;
		*outlen += DATA_UNIT_SIZE;
	}
	if (inlen) {
		memcpy(ctx->block, in, inlen);
	}
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_xts_encrypt_finish(SM4_XTS_CTX *ctx, uint8_t *out, size_t *outlen)
{
	size_t DATA_UNIT_SIZE = ctx->data_unit_size;
	if (ctx->block_nbytes >= DATA_UNIT_SIZE) {
		error_print();
		return -1;
	}
	if (ctx->block) {
		free(ctx->block);
		ctx->block = NULL;
	}
	if (ctx->block_nbytes) {
		error_puts("invalid total input length");
		return -1;
	}
	*outlen = 0;
	return 1;
}


int sm4_xts_decrypt_init(SM4_XTS_CTX *ctx, const uint8_t key[32], const uint8_t iv[16], size_t data_unit_size)
{
	if (data_unit_size < SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	sm4_set_decrypt_key(&ctx->key1, key);
	sm4_set_encrypt_key(&ctx->key2, key + 16);
	memcpy(ctx->tweak, iv, 16);
	ctx->data_unit_size = data_unit_size;
	if (!(ctx->block = (uint8_t *)malloc(data_unit_size))) {
		error_print();
		return -1;
	}
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_xts_decrypt_update(SM4_XTS_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t DATA_UNIT_SIZE = ctx->data_unit_size;
	size_t left;

	if (ctx->block_nbytes >= DATA_UNIT_SIZE) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (ctx->block_nbytes) {
		error_print();
		left = DATA_UNIT_SIZE - ctx->block_nbytes;
		if (inlen < left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		if (sm4_xts_decrypt(&ctx->key1, &ctx->key2, ctx->tweak, ctx->block, DATA_UNIT_SIZE, out) != 1) {
			error_print();
			return -1;
		}
		tweak_incr(ctx->tweak);
		in += left;
		inlen -= left;
		out += DATA_UNIT_SIZE;
		*outlen += DATA_UNIT_SIZE;
	}
	while (inlen >= DATA_UNIT_SIZE) {
		if (sm4_xts_decrypt(&ctx->key1, &ctx->key2, ctx->tweak, in, DATA_UNIT_SIZE, out) != 1) {
			error_print();
			return -1;
		}
		tweak_incr(ctx->tweak);
		in += DATA_UNIT_SIZE;
		inlen -= DATA_UNIT_SIZE;
		out += DATA_UNIT_SIZE;
		*outlen += DATA_UNIT_SIZE;
	}
	if (inlen) {
		memcpy(ctx->block, in, inlen);
	}
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_xts_decrypt_finish(SM4_XTS_CTX *ctx, uint8_t *out, size_t *outlen)
{
	size_t DATA_UNIT_SIZE = ctx->data_unit_size;
	if (ctx->block_nbytes >= DATA_UNIT_SIZE) {
		error_print();
		return -1;
	}
	if (ctx->block) {
		free(ctx->block);
		ctx->block = NULL;
	}
	if (ctx->block_nbytes) {
		error_puts("invalid total input length");
		return -1;
	}
	*outlen = 0;
	return 1;
}
