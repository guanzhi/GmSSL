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


int sm4_xts_encrypt(const SM4_KEY *key1, const SM4_KEY *key2, size_t tweak,
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t T[16] = {0};
	uint8_t block[16];
	size_t nblocks, i;
	gf128_t a;

	if (inlen < 16) {
		error_print();
		return -1;
	}
	nblocks = inlen / 16 + 1;

	for (i = 0; i < 8; i++) {
		T[i] = tweak & 0xff;
		tweak >>= 8;
	}
	sm4_encrypt(key2, T, T);

	for (i = 0; i < nblocks - 2; i++) {
		gmssl_memxor(block, in, T, 16);
		sm4_encrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);

		a = gf128_from_bytes(T);
		a = gf128_mul2(a);
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
		gmssl_memxor(block, in, T, 16);
		sm4_encrypt(key1, block, block);
		gmssl_memxor(block, block, T, 16);

		a = gf128_from_bytes(T);
		a = gf128_mul2(a);
		gf128_to_bytes(a, T);

		in += 16;
		inlen -= 16;

		memcpy(out + 16, block, inlen);
		memcpy(block, in, inlen);

		gmssl_memxor(block, block, T, 16);
		sm4_encrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);
	}

	return 1;
}

int sm4_xts_decrypt(const SM4_KEY *key1, const SM4_KEY *key2, size_t tweak,
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t T[16] = {0};
	uint8_t block[16];
	size_t nblocks, i;
	gf128_t a;

	if (inlen < 16) {
		error_print();
		return -1;
	}
	nblocks = inlen / 16 + 1;

	for (i = 0; i < 8; i++) {
		T[i] = tweak & 0xff;
		tweak >>= 8;
	}
	sm4_encrypt(key2, T, T);

	for (i = 0; i < nblocks - 2; i++) {
		gmssl_memxor(block, in, T, 16);
		sm4_decrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);

		a = gf128_from_bytes(T);
		a = gf128_mul2(a);
		gf128_to_bytes(a, T);

		in += 16;
		inlen -= 16;
		out += 16;
	}

	if (inlen % 16 == 0) {
		gmssl_memxor(block, in, T, 16);
		sm4_decrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);

	} else  {
		uint8_t T1[16];

		a = gf128_from_bytes(T);
		a = gf128_mul2(a);
		gf128_to_bytes(a, T1);

		gmssl_memxor(block, in, T1, 16);
		sm4_decrypt(key1, block, block);
		gmssl_memxor(block, block, T1, 16);

		in += 16;
		inlen -= 16;

		memcpy(out + 16, block, inlen);
		memcpy(block, in, inlen);

		gmssl_memxor(block, block, T, 16);
		sm4_decrypt(key1, block, block);
		gmssl_memxor(out, block, T, 16);
	}

	return 1;
}

