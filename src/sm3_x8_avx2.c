/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <x86intrin.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>
#include <gmssl/mem.h>
#include <gmssl/sm3.h>
#include <gmssl/sm3_x8_avx2.h>


#define ROLT(x,n)  _mm256_or_si256(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), (32-(n))))
#define P0(x)	_mm256_xor_si256((x), _mm256_xor_si256(ROLT((x),  9), ROLT((x), 17)))
#define P1(x)  _mm256_xor_si256((x), _mm256_xor_si256(ROLT((x), 15), ROLT((x), 23)))

#define FF00(x,y,z)  _mm256_xor_si256((x), _mm256_xor_si256((y), (z)))
#define FF16(x,y,z)  _mm256_or_si256(_mm256_and_si256((x), (y)), _mm256_or_si256(_mm256_and_si256((x), (z)), _mm256_and_si256((y), (z))))
#define GG00(x,y,z)  _mm256_xor_si256((x), _mm256_xor_si256((y), (z)))
#define GG16(x,y,z)  _mm256_xor_si256(_mm256_and_si256(_mm256_xor_si256((y), (z)), (x)), (z))


static uint32_t K[64] = {
	0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
	0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
	0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
	0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
	0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
	0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
	0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
	0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

static int _mm256_print(FILE *fp, int fmt, int ind, const char *label, __m256i a)
{
	uint32_t arr[8];
	int i;

	_mm256_storeu_si256((__m256i *)arr, a);

	format_print(fp, fmt, ind, "%s: ", label);
	for (i = 0; i < 7; i++) {
		fprintf(fp, "%08X ", arr[i]);
	}
	fprintf(fp, "%08X\n", arr[i]);
	return 1;
}

void sm3_x8_init(SM3_X8_CTX *ctx)
{
	ctx->digest[0] = _mm256_set1_epi32(0x7380166F);
	ctx->digest[1] = _mm256_set1_epi32(0x4914B2B9);
	ctx->digest[2] = _mm256_set1_epi32(0x172442D7);
	ctx->digest[3] = _mm256_set1_epi32(0xDA8A0600);
	ctx->digest[4] = _mm256_set1_epi32(0xA96F30BC);
	ctx->digest[5] = _mm256_set1_epi32(0x163138AA);
	ctx->digest[6] = _mm256_set1_epi32(0xE38DEE4D);
	ctx->digest[7] = _mm256_set1_epi32(0xB0FB0E4E);
}

void sm3_x8_compress_blocks(__m256i digest[8], const uint8_t *data, size_t datalen)
{
	__m256i A;
	__m256i B;
	__m256i C;
	__m256i D;
	__m256i E;
	__m256i F;
	__m256i G;
	__m256i H;
	__m256i SS1, SS2, TT1, TT2;
	uint32_t W[68][8];
	size_t nblocks = datalen/SM3_BLOCK_SIZE;
	int j;

	memset(W, 0, sizeof(W));

	A = digest[0];
	B = digest[1];
	C = digest[2];
	D = digest[3];
	E = digest[4];
	F = digest[5];
	G = digest[6];
	H = digest[7];

	/*
	format_print(stderr, 0, 0, "state %d\n", 0);
	_mm256_print(stderr, 0, 4, "A", A);
	_mm256_print(stderr, 0, 4, "B", B);
	_mm256_print(stderr, 0, 4, "C", C);
	_mm256_print(stderr, 0, 4, "D", D);
	_mm256_print(stderr, 0, 4, "E", E);
	_mm256_print(stderr, 0, 4, "F", F);
	_mm256_print(stderr, 0, 4, "G", G);
	_mm256_print(stderr, 0, 4, "H", H);
	*/

	while (nblocks--) {

		TT1 = _mm256_setr_epi32(
			datalen*0, datalen*1, datalen*2, datalen*3,
			datalen*4, datalen*5, datalen*6, datalen*7);
		TT2 = _mm256_setr_epi8(
			3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
			3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12);

		for (j = 0; j < 16; j++) {
			SS1 = _mm256_i32gather_epi32(data + 4*j, TT1, 1);
			SS1 = _mm256_shuffle_epi8(SS1, TT2);
			_mm256_storeu_si256((__m256i *)W[j], SS1);
		}

		for (; j < 68; j++) {
			// SS1 = ROLT((ROLT(A, 12) + E + K(j)), 7);
			SS1 = _mm256_loadu_si256((__m256i *)W[j - 16]);
			SS2 = _mm256_loadu_si256((__m256i *)W[j -  9]);
			SS1 = _mm256_xor_si256(SS1, SS2);
			SS2 = _mm256_loadu_si256((__m256i *)W[j -  3]);
			SS2 = ROLT(SS2, 15);
			SS1 = _mm256_xor_si256(SS1, SS2);

			// P1(x) = (x) ^ ROLT((x),15) ^ ROLT((x),23)
			TT1 = ROLT(SS1, 15);
			TT2 = ROLT(SS1, 23);
			SS1 = _mm256_xor_si256(SS1, TT1);
			SS1 = _mm256_xor_si256(SS1, TT2);

			// ^ (W[j - 13] >>> 7) ^ W[j - 6]
			SS2 = _mm256_loadu_si256((__m256i *)W[j - 13]);
			SS2 = ROLT(SS2, 7);
			SS1 = _mm256_xor_si256(SS1, SS2);
			SS2 = _mm256_loadu_si256((__m256i *)W[j -  6]);
			SS1 = _mm256_xor_si256(SS1, SS2);

			_mm256_storeu_si256((__m256i *)&W[j], SS1);
		}


		for (j = 0; j < 16; j++) {
			//SS1 = ROLT((ROLT(A, 12) + E + K(j)), 7);
			SS2 = ROLT(A, 12);
			SS1 = _mm256_add_epi32(SS2, E);
			SS1 = _mm256_add_epi32(SS1, _mm256_set1_epi32(K[j]));
			SS1 = ROLT(SS1, 7);

			//SS2 = SS1 ^ ROLT(A, 12);
			SS2 = _mm256_xor_si256(SS2, SS1);

			//TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
			TT2 = _mm256_loadu_si256((__m256i *)W[j]);
			TT1 = _mm256_xor_si256(TT2, _mm256_loadu_si256((__m256i *)W[j + 4]));
			TT1 = _mm256_add_epi32(TT1, FF00(A, B, C));
			TT1 = _mm256_add_epi32(TT1, D);
			TT1 = _mm256_add_epi32(TT1, SS2);

			//TT2 = GG00(E, F, G) + H + SS1 + W[j];
			TT2 = _mm256_add_epi32(TT2, GG00(E, F, G));
			TT2 = _mm256_add_epi32(TT2, H);
			TT2 = _mm256_add_epi32(TT2, SS1);

			D = C;
			C = ROLT(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = ROLT(F, 19);
			F = E;
			E = P0(TT2);

			/*
			format_print(stderr, 0, 0, "state %d\n", j+1);
			_mm256_print(stderr, 0, 4, "A", A);
			_mm256_print(stderr, 0, 4, "B", B);
			_mm256_print(stderr, 0, 4, "C", C);
			_mm256_print(stderr, 0, 4, "D", D);
			_mm256_print(stderr, 0, 4, "E", E);
			_mm256_print(stderr, 0, 4, "F", F);
			_mm256_print(stderr, 0, 4, "G", G);
			_mm256_print(stderr, 0, 4, "H", H);
			*/
		}


		for (; j < 64; j++) {
			//SS1 = ROLT((ROLT(A, 12) + E + K(j)), 7);
			SS2 = ROLT(A, 12);
			SS1 = _mm256_add_epi32(SS2, E);
			SS1 = _mm256_add_epi32(SS1, _mm256_set1_epi32(K[j]));
			SS1 = ROLT(SS1, 7);

			//SS2 = SS1 ^ ROLT(A, 12);
			SS2 = _mm256_xor_si256(SS2, SS1);

			//TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
			TT2 = _mm256_loadu_si256((__m256i *)W[j]);
			TT1 = _mm256_xor_si256(TT2, _mm256_loadu_si256((__m256i *)W[j + 4]));
			TT1 = _mm256_add_epi32(TT1, FF16(A, B, C));
			TT1 = _mm256_add_epi32(TT1, D);
			TT1 = _mm256_add_epi32(TT1, SS2);

			// TT2 = GG16(E, F, G) + H + SS1 + W[j];
			TT2 = _mm256_add_epi32(TT2, GG16(E, F, G));
			TT2 = _mm256_add_epi32(TT2, H);
			TT2 = _mm256_add_epi32(TT2, SS1);

			D = C;
			C = ROLT(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = ROLT(F, 19);
			F = E;
			E = P0(TT2);

			/*
			format_print(stderr, 0, 0, "state %d\n", j+1);
			_mm256_print(stderr, 0, 4, "A", A);
			_mm256_print(stderr, 0, 4, "B", B);
			_mm256_print(stderr, 0, 4, "C", C);
			_mm256_print(stderr, 0, 4, "D", D);
			_mm256_print(stderr, 0, 4, "E", E);
			_mm256_print(stderr, 0, 4, "F", F);
			_mm256_print(stderr, 0, 4, "G", G);
			_mm256_print(stderr, 0, 4, "H", H);
			*/
		}

		_mm256_storeu_si256((__m256i *)&digest[0], _mm256_xor_si256(A, _mm256_loadu_si256((__m256i *)&digest[0])));
		_mm256_storeu_si256((__m256i *)&digest[1], _mm256_xor_si256(B, _mm256_loadu_si256((__m256i *)&digest[1])));
		_mm256_storeu_si256((__m256i *)&digest[2], _mm256_xor_si256(C, _mm256_loadu_si256((__m256i *)&digest[2])));
		_mm256_storeu_si256((__m256i *)&digest[3], _mm256_xor_si256(D, _mm256_loadu_si256((__m256i *)&digest[3])));
		_mm256_storeu_si256((__m256i *)&digest[4], _mm256_xor_si256(E, _mm256_loadu_si256((__m256i *)&digest[4])));
		_mm256_storeu_si256((__m256i *)&digest[5], _mm256_xor_si256(F, _mm256_loadu_si256((__m256i *)&digest[5])));
		_mm256_storeu_si256((__m256i *)&digest[6], _mm256_xor_si256(G, _mm256_loadu_si256((__m256i *)&digest[6])));
		_mm256_storeu_si256((__m256i *)&digest[7], _mm256_xor_si256(H, _mm256_loadu_si256((__m256i *)&digest[7])));

		data += SM3_BLOCK_SIZE;
	}
}

void sm3_x8_digest(const uint8_t *data, size_t datalen, uint8_t dgst[8][32])
{
	SM3_X8_CTX ctx;
	__m256i vindex, a, b;
	uint8_t block[8][SM3_BLOCK_SIZE];
	size_t nblocks = datalen/SM3_BLOCK_SIZE;
	size_t rem = datalen % 64;
	int i;


	sm3_x8_init(&ctx);

	sm3_x8_compress_blocks(ctx.digest, data, datalen);
	data += SM3_BLOCK_SIZE * nblocks;

	memset(block, 0, sizeof(block));
	for (i = 0; i < 8; i++) {
		memcpy(block[i], data, rem);
		block[i][rem] = 0x80;
		data += datalen;
	}
	if (SM3_BLOCK_SIZE - rem < 9) {
		sm3_x8_compress_blocks(ctx.digest, &block[0][0], SM3_BLOCK_SIZE);
		memset(block, 0, sizeof(block));
	}

	for (i = 0; i < 8; i++) {
		*((uint64_t *)(block[i] + 56)) = _bswap64(datalen << 3);
	}
	sm3_x8_compress_blocks(ctx.digest, &block[0][0], SM3_BLOCK_SIZE);

	vindex = _mm256_setr_epi32(0,1*32,2*32,3*32,4*32,5*32,6*32,7*32);
	b = _mm256_setr_epi8(
			3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
			3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12);
	for (i = 0; i < 8; i++) {
		a = _mm256_i32gather_epi32((uint8_t *)&ctx + 4*i, vindex, 1);
		a = _mm256_shuffle_epi8(a, b);
		_mm256_storeu_si256((__m256i *)dgst[i], a);
	}

	gmssl_secure_clear(&ctx, sizeof(ctx));
	gmssl_secure_clear(block, sizeof(block));
}

static int test_sm3_x8_avx2(void)
{
	uint8_t data[8][96] = {0};
	uint8_t dgst[8][32];
	uint8_t dgst2[8][32] = {{0}};
	int i;

	rand_bytes(data[0], sizeof(data));
	for (i = 0; i < 8; i++) {
		sm3_digest(data[i], sizeof(data)/8, dgst[i]);
	}
	sm3_x8_digest(&data[0][0], sizeof(data)/8, dgst2);

	if (memcmp(dgst2, dgst, sizeof(dgst)) != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
