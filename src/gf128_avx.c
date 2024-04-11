/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/gf128.h>
#include <gmssl/endian.h>
#include <gmssl/error.h>
#include <immintrin.h>


static uint64_t reverse_bits(uint64_t a)
{
	uint64_t r = 0;
	int i;

	for (i = 0; i < 63; i++) {
		r |= a & 1;
		r <<= 1;
		a >>= 1;
	}
	r |= a & 1;
	return r;
}

void gf128_set_zero(gf128_t r)
{
	r[0] = 0;
	r[1] = 0;
}

void gf128_set_one(gf128_t r)
{
	r[0] = 1;
	r[1] = 0;
}

/*
void gf128_print_bits(gf128_t a)
{
	int i;

	a.hi = reverse_bits(a.hi);
	a.lo = reverse_bits(a.lo);

	for (i = 0; i < 64; i++) {
		printf("%d", (int)(a.hi % 2));
		a.hi >>= 1;
	}
	for (i = 0; i < 64; i++) {
		printf("%d", (int)(a.lo % 2));
		a.lo >>= 1;
	}
	printf("\n");
}
*/

int gf128_print(FILE *fp, int fmt, int ind, const char *label, const gf128_t a)
{
	uint8_t be[16];
	int i;

	printf("%s: ", label);
	gf128_to_bytes(a, be);
	for (i = 0; i < 16; i++) {
		printf("%02x", be[i]);
	}
	printf("\n");
	return 1;
}

void gf128_from_bytes(gf128_t r, const uint8_t p[16])
{
	r[0] = reverse_bits(GETU64(p));
	r[1] = reverse_bits(GETU64(p + 8));
}

void gf128_to_bytes(const gf128_t a, uint8_t p[16])
{
	PUTU64(p, reverse_bits(a[0]));
	PUTU64(p + 8, reverse_bits(a[1]));
}

void gf128_add(gf128_t r, const gf128_t a, const gf128_t b)
{
	r[0] = a[0] ^ b[0];
	r[1] = a[1] ^ b[1];
}

void gf128_mul(gf128_t gr, const gf128_t ga, const gf128_t gb)
{
	const __m128i MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	__m128i a1, b1;
	__m128i T0, T1, T2, T3, T4, T5;
	uint8_t r[16], a[16], b[16];

	// FIXME: directly load a, b
	gf128_to_bytes(ga, a);
	gf128_to_bytes(gb, b);

	a1 = _mm_loadu_si128((const __m128i*)a);
	b1 = _mm_loadu_si128((const __m128i*)b);

	a1 = _mm_shuffle_epi8(a1, MASK);
	b1 = _mm_shuffle_epi8(b1, MASK);

	T0 = _mm_clmulepi64_si128(a1, b1, 0x00);
	T1 = _mm_clmulepi64_si128(a1, b1, 0x01);
	T2 = _mm_clmulepi64_si128(a1, b1, 0x10);
	T3 = _mm_clmulepi64_si128(a1, b1, 0x11);

	T1 = _mm_xor_si128(T1, T2);
	T2 = _mm_slli_si128(T1, 8);
	T1 = _mm_srli_si128(T1, 8);
	T0 = _mm_xor_si128(T0, T2);
	T3 = _mm_xor_si128(T3, T1);

	T4 = _mm_srli_epi32(T0, 31);
	T0 = _mm_slli_epi32(T0, 1);

	T5 = _mm_srli_epi32(T3, 31);
	T3 = _mm_slli_epi32(T3, 1);

	T2 = _mm_srli_si128(T4, 12);
	T5 = _mm_slli_si128(T5, 4);
	T4 = _mm_slli_si128(T4, 4);
	T0 = _mm_or_si128(T0, T4);
	T3 = _mm_or_si128(T3, T5);
	T3 = _mm_or_si128(T3, T2);

	T4 = _mm_slli_epi32(T0, 31);
	T5 = _mm_slli_epi32(T0, 30);
	T2 = _mm_slli_epi32(T0, 25);

	T4 = _mm_xor_si128(T4, T5);
	T4 = _mm_xor_si128(T4, T2);
	T5 = _mm_srli_si128(T4, 4);
	T3 = _mm_xor_si128(T3, T5);
	T4 = _mm_slli_si128(T4, 12);
	T0 = _mm_xor_si128(T0, T4);
	T3 = _mm_xor_si128(T3, T0);

	T4 = _mm_srli_epi32(T0, 1);
	T1 = _mm_srli_epi32(T0, 2);
	T2 = _mm_srli_epi32(T0, 7);
	T3 = _mm_xor_si128(T3, T1);
	T3 = _mm_xor_si128(T3, T2);
	T3 = _mm_xor_si128(T3, T4);

	T3 = _mm_shuffle_epi8(T3, MASK);
	_mm_storeu_si128((__m128i*)r, T3);
	gf128_from_bytes(gr, r);
}

void gf128_mul_by_2(gf128_t gr, const gf128_t ga)
{
	const __m128i MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	__m128i MASK1 = _mm_set_epi8(0xe1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
	__m128i MASK2 = _mm_set_epi8(0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
	__m128i a1;
	__m128i T0, T1, T2, T3, T4, T5;
	uint8_t r[16], a[16];

	gf128_to_bytes(ga, a);
	a1 = _mm_loadu_si128((const __m128i*)a);
	a1 = _mm_shuffle_epi8(a1, MASK);

	T0 = _mm_srli_epi64(a1,1);

	T1 = _mm_slli_epi64(a1,63);
	T2 = _mm_shuffle_epi32(T1,0x0C);

	T3 = _mm_shuffle_epi32(T1,0x40);
	T4 = _mm_cmpeq_epi8(T3,MASK2);
	T3 = _mm_and_si128(T4,MASK1);

	T5 = _mm_xor_si128(T0,T2);
	T5 = _mm_xor_si128(T5,T3);

	T5 = _mm_shuffle_epi8(T5, MASK);
	_mm_storeu_si128((__m128i*)r, T5);
	gf128_from_bytes(gr, r);
}
