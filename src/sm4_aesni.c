/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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

#include <x86intrin.h>
#include <gmssl/mem.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


static uint32_t FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static uint32_t CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

const uint8_t S[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

#define L32(X)					\
	((X) ^					\
	ROL32((X),  2) ^			\
	ROL32((X), 10) ^			\
	ROL32((X), 18) ^			\
	ROL32((X), 24))

#define L32_(X)					\
	((X) ^ 					\
	ROL32((X), 13) ^			\
	ROL32((X), 23))

#define S32(A)					\
	((S[((A) >> 24)       ] << 24) |	\
	 (S[((A) >> 16) & 0xff] << 16) |	\
	 (S[((A) >>  8) & 0xff] <<  8) |	\
	 (S[((A))       & 0xff]))


void sm4_set_encrypt_key(SM4_KEY *key, const uint8_t user_key[16])
{
	uint32_t X0, X1, X2, X3, X4;
	int i;

	X0 = GETU32(user_key     ) ^ FK[0];
	X1 = GETU32(user_key  + 4) ^ FK[1];
	X2 = GETU32(user_key  + 8) ^ FK[2];
	X3 = GETU32(user_key + 12) ^ FK[3];

	for (i = 0; i < 32; i++) {

		X4 = X1 ^ X2 ^ X3 ^ CK[i];
		X4 = S32(X4);
		X4 = X0 ^ L32_(X4);

		key->rk[i] = X4;

		X0 = X1;
		X1 = X2;
		X2 = X3;
		X3 = X4;
	}
}

void sm4_set_decrypt_key(SM4_KEY *key, const uint8_t user_key[16])
{
	uint32_t X0, X1, X2, X3, X4;
	int i;

	X0 = GETU32(user_key     ) ^ FK[0];
	X1 = GETU32(user_key  + 4) ^ FK[1];
	X2 = GETU32(user_key  + 8) ^ FK[2];
	X3 = GETU32(user_key + 12) ^ FK[3];

	for (i = 0; i < 32; i++) {

		X4 = X1 ^ X2 ^ X3 ^ CK[i];
		X4 = S32(X4);
		X4 = X0 ^ L32_(X4);

		key->rk[31 - i] = X4;

		X0 = X1;
		X1 = X2;
		X2 = X3;
		X3 = X4;
	}
}

void sm4_encrypt(const SM4_KEY *key, const uint8_t in[16], uint8_t out[16])
{
	uint32_t X0, X1, X2, X3, X4;
	int i;

	X0 = GETU32(in     );
	X1 = GETU32(in +  4);
	X2 = GETU32(in +  8);
	X3 = GETU32(in + 12);

	for (i = 0; i < 32; i++) {

		X4 = X1 ^ X2 ^ X3 ^ key->rk[i];
		X4 = S32(X4);
		X4 = X0 ^ L32(X4);

		X0 = X1;
		X1 = X2;
		X2 = X3;
		X3 = X4;
	}

	PUTU32(out     , X3);
	PUTU32(out +  4, X2);
	PUTU32(out +  8, X1);
	PUTU32(out + 12, X0);
}

void sm4_encrypt_blocks(const SM4_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out)
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


	while (nblocks >= 4) {

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

			k = key->rk[i];
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

		in += 16 * 4;
		out += 16 * 4;
		nblocks -= 4;
	}

	while (nblocks--) {
		sm4_encrypt(key, in, out);
		in += 16;
		out += 16;
	}
}

void sm4_cbc_encrypt_blocks(const SM4_KEY *key, uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	const uint8_t *piv = iv;

	while (nblocks--) {
		size_t i;
		for (i = 0; i < 16; i++) {
			out[i] = in[i] ^ piv[i];
		}
		sm4_encrypt(key, out, out);
		piv = out;
		in += 16;
		out += 16;
	}

	memcpy(iv, piv, 16);
}

void sm4_cbc_decrypt_blocks(const SM4_KEY *key, uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	const uint8_t *piv = iv;

	while (nblocks--) {
		size_t i;
		sm4_encrypt(key, in, out);
		for (i = 0; i < 16; i++) {
			out[i] ^= piv[i];
		}
		piv = in;
		in += 16;
		out += 16;
	}

	memcpy(iv, piv, 16);
}

static void ctr_incr(uint8_t a[16]) {
	int i;
	for (i = 15; i >= 0; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

void sm4_ctr_encrypt_blocks(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t nblocks, uint8_t *out)
{
	uint8_t block[16];
	int i;

	while (nblocks--) {
		sm4_encrypt(key, ctr, block);
		ctr_incr(ctr);
		for (i = 0; i < 16; i++) {
			out[i] = in[i] ^ block[i];
		}
		in += 16;
		out += 16;
	}
}

// inc32() in nist-sp800-38d
static void ctr32_incr(uint8_t a[16]) {
	int i;
	for (i = 15; i >= 12; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

void sm4_ctr32_encrypt_blocks(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t nblocks, uint8_t *out)
{
	uint8_t block[16];
	int i;

	while (nblocks--) {
		sm4_encrypt(key, ctr, block);
		ctr32_incr(ctr);
		for (i = 0; i < 16; i++) {
			out[i] = in[i] ^ block[i];
		}
		in += 16;
		out += 16;
	}
}

/*
int main(void)
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

	unsigned char buf[16 * 4];
	int i;

	sm4_aesni_avx_encrypt(rk, plaintext, buf);

	if (memcmp(buf, ciphertext, 16 * 4) != 0) {
		fprintf(stderr, "error\n");
		return -1;
	}
	printf("ok\n");

	return 0;
}
*/

