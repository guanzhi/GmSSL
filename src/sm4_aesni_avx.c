/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
// modify from https://github.com/mjosaarinen/sm4ni
// 2018-04-20  Markku-Juhani O. Saarinen <mjos@iki.fi>
/*
MIT License

Copyright (c) 2018 Markku-Juhani O. Saarinen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/mem.h>
#include <gmssl/sm4.h>
#include <x86intrin.h>


void sm4_aesni_avx_encrypt(const uint32_t rk[32], const uint8_t in[16 * 4], uint8_t out[16 * 4])
{
	// nibble mask
	const __m128i c0f __attribute__((aligned(0x10))) = {
		0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F };

	// flip all bytes in all 32-bit words
	const __m128i flp __attribute__((aligned(0x10))) = {
		0x0405060700010203, 0x0C0D0E0F08090A0B };

	// inverse shift rows
	const __m128i shr __attribute__((aligned(0x10))) = {
		0x0B0E0104070A0D00, 0x0306090C0F020508 };

	// Affine transform 1 (low and high hibbles)
	const __m128i m1l __attribute__((aligned(0x10))) = {
		0x9197E2E474720701, 0xC7C1B4B222245157 };
	const __m128i m1h __attribute__((aligned(0x10))) = {
		0xE240AB09EB49A200, 0xF052B91BF95BB012 };

	// Affine transform 2 (low and high hibbles)
	const __m128i m2l __attribute__((aligned(0x10))) = {
		0x5B67F2CEA19D0834, 0xEDD14478172BBE82 };
	const __m128i m2h __attribute__((aligned(0x10))) = {
		0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF };

	// left rotations of 32-bit words by 8-bit increments
	const __m128i r08 __attribute__((aligned(0x10))) = {
		0x0605040702010003, 0x0E0D0C0F0A09080B };
	const __m128i r16 __attribute__((aligned(0x10))) = {
		0x0504070601000302, 0x0D0C0F0E09080B0A };
	const __m128i r24 __attribute__((aligned(0x10))) = {
		0x0407060500030201, 0x0C0F0E0D080B0A09 };

	const uint32_t *cp32;
	__m128i x, y, t0, t1, t2, t3;
	uint32_t k, *p32, v[4] __attribute__((aligned(0x10)));
	int i;

	cp32 = (const uint32_t *)in;
	t0 = _mm_set_epi32(cp32[12], cp32[ 8], cp32[ 4], cp32[ 0]);
	t0 = _mm_shuffle_epi8(t0, flp);
	t1 = _mm_set_epi32(cp32[13], cp32[ 9], cp32[ 5], cp32[ 1]);
	t1 = _mm_shuffle_epi8(t1, flp);
	t2 = _mm_set_epi32(cp32[14], cp32[10], cp32[ 6], cp32[ 2]);
	t2 = _mm_shuffle_epi8(t2, flp);
	t3 = _mm_set_epi32(cp32[15], cp32[11], cp32[ 7], cp32[ 3]);
	t3 = _mm_shuffle_epi8(t3, flp);

	for (i = 0; i < 32; i++) {

		k = rk[i];
		x = t1 ^ t2 ^ t3 ^ _mm_set_epi32(k, k, k, k);

		y = _mm_and_si128(x, c0f); // inner affine
		y = _mm_shuffle_epi8(m1l, y);
		x = _mm_srli_epi64(x, 4);
		x = _mm_and_si128(x, c0f);
		x = _mm_shuffle_epi8(m1h, x) ^ y;

		x = _mm_shuffle_epi8(x, shr); // inverse MixColumns
		x = _mm_aesenclast_si128(x, c0f); // AESNI instruction

		y = _mm_andnot_si128(x, c0f); // outer affine
		y = _mm_shuffle_epi8(m2l, y);
		x = _mm_srli_epi64(x, 4);
		x = _mm_and_si128(x, c0f);
		x = _mm_shuffle_epi8(m2h, x) ^ y;

		// 4 parallel L1 linear transforms
		y = x ^ _mm_shuffle_epi8(x, r08) ^ _mm_shuffle_epi8(x, r16);
		y = _mm_slli_epi32(y, 2) ^ _mm_srli_epi32(y, 30);
		x = x ^ y ^ _mm_shuffle_epi8(x, r24);

		// rotate registers
		x ^= t0;
		t0 = t1;
		t1 = t2;
		t2 = t3;
		t3 = x;
	}

	p32 = (uint32_t *)out;

	_mm_store_si128((__m128i *) v, _mm_shuffle_epi8(t3, flp));
	p32[ 0] = v[0];
	p32[ 4] = v[1];
	p32[ 8] = v[2];
	p32[12] = v[3];

	_mm_store_si128((__m128i *) v, _mm_shuffle_epi8(t2, flp));
	p32[ 1] = v[0];
	p32[ 5] = v[1];
	p32[ 9] = v[2];
	p32[13] = v[3];

	_mm_store_si128((__m128i *) v, _mm_shuffle_epi8(t1, flp));
	p32[ 2] = v[0];
	p32[ 6] = v[1];
	p32[10] = v[2];
	p32[14] = v[3];

	_mm_store_si128((__m128i *) v, _mm_shuffle_epi8(t0, flp));
	p32[ 3] = v[0];
	p32[ 7] = v[1];
	p32[11] = v[2];
	p32[15] = v[3];
}

static void ctr_incr(uint8_t a[16])
{
	int i;
	for (i = 15; i >= 0; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t blocks[64];
	size_t len, i;

	while (inlen) {
		len = inlen < 64 ? inlen : 64;
		memcpy(blocks, ctr, 16); ctr_incr(ctr);
		memcpy(blocks + 16, ctr, 16); ctr_incr(ctr);
		memcpy(blocks + 32, ctr, 16); ctr_incr(ctr);
		memcpy(blocks + 48, ctr, 16); ctr_incr(ctr);
		sm4_aesni_avx_encrypt(key->rk, blocks, blocks);
		for (i = 0; i < len; i++) {
			out[i] = in[i] ^ blocks[i];
		}
		in += len;
		out += len;
		inlen -= len;
	}

	memset(blocks, 0, sizeof(blocks));
}

/*
static int test_sm4_aesni_avx(void)
{
	const uint32_t rk[32] = {
		0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077,
		0x367360f4, 0x776a0c61, 0xb6bb89b3, 0x24763151,
		0xa520307c, 0xb7584dbd, 0xc30753ed, 0x7ee55b57,
		0x6988608c, 0x30d895b7, 0x44ba14af, 0x104495a1,
		0xd120b428, 0x73b55fa3, 0xcc874966, 0x92244439,
		0xe89e641f, 0x98ca015a, 0xc7159060, 0x99e1fd2e,
		0xb79bd80c, 0x1d2115b0, 0x0e228aeb, 0xf1780c81,
		0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012,
	};
	const uint8_t plaintext[16 * 4] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	const uint8_t ciphertext[16 * 4] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	};
	const uint8_t ciphertext1m[16 * 4] = {
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
	};

	uint8_t buf[16 * 4];
	int i;

	// test encrypt once
	sm4_aesni_avx_encrypt(rk, plaintext, buf);

	if (memcmp(buf, ciphertext, sizeof(ciphertext)) != 0) {
		fprintf(stderr, "%s %d: %s error\n", __FILE__, __LINE__, __FUNCTION__);
		return -1;
	}

	// test encrypt 1000000 times
	memcpy(buf, plaintext, sizeof(plaintext));
	for (i = 0; i < 1000000; i++) {
		sm4_aesni_avx_encrypt(rk, buf, buf);
	}
	if (memcmp(buf, ciphertext1m, sizeof(ciphertext1m)) != 0) {
		fprintf(stderr, "%s %d: %s 1 million times error\n", __FILE__, __LINE__, __FUNCTION__);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	test_sm4_aesni_avx();
	return 0;
}
*/
