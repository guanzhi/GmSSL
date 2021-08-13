/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <string.h>
#include <openssl/sm3.h>
#include "internal/rotate.h"
#include "internal/byteorder.h"
#include "modes_lcl.h"

#ifdef SM3_SSE3
# include <x86intrin.h>
# include <immintrin.h>

# define _mm_rotl_epi32(X,i) \
	_mm_xor_si128(_mm_slli_epi32((X),(i)), _mm_srli_epi32((X),32-(i)))
#endif

static void sm3_compress_blocks(uint32_t digest[8],
	const unsigned char *data, size_t blocks);


void sm3_init(sm3_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;
}

void sm3_compute_id_digest(unsigned char z[32], const char *id,
	const unsigned char x[32], const unsigned char y[32])
{
	unsigned char zin[] = {
		0x00, 0x80,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
		0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
		0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
		0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
		0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
       		0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
		0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
		0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
		0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
		0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
		0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
		0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        	0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x06, 0x90,
	};

	if (!id || (strcmp(id, "1234567812345678") == 0)) {
		unsigned int digest[8] = {
			0xadadedb5U, 0x0446043fU, 0x08a87aceU, 0xe86d2243U,
			0x8e232383U, 0xbfc81fe2U, 0xcf9117c8U, 0x4707011dU,
		};
		memcpy(&zin[128], x, 32);
		memcpy(&zin[160], y, 32);
		sm3_compress_blocks(digest, zin, 2);
		PUTU32(z     , digest[0]);
		PUTU32(z +  4, digest[1]);
		PUTU32(z +  8, digest[2]);
		PUTU32(z + 12, digest[3]);
		PUTU32(z + 16, digest[4]);
		PUTU32(z + 20, digest[5]);
		PUTU32(z + 24, digest[6]);
		PUTU32(z + 28, digest[7]);

	} else {
		sm3_ctx_t ctx;
		unsigned char idbits[2];
		size_t len;

		len = strlen(id);
		idbits[0] = (unsigned char)(len >> 5);
		idbits[1] = (unsigned char)(len << 3);

		sm3_init(&ctx);
		sm3_update(&ctx, idbits, 2);
		sm3_update(&ctx, (unsigned char *)id, len);
		sm3_update(&ctx, zin + 18, 128);
		sm3_update(&ctx, x, 32);
		sm3_update(&ctx, y, 32);
		sm3_final(&ctx, z);
	}
}

int sm3_sm2_init(sm3_ctx_t *ctx, const char *id,
	const unsigned char *x, const unsigned char *y)
{
	unsigned char z[32];
	if ((id && strlen(id) > 65535/8) || !x || !y) {
		return 0;
	}
	sm3_compute_id_digest(z, id, x, y);
	sm3_init(ctx);
	sm3_update(ctx, z, 32);
	return 1;
}

void sm3_update(sm3_ctx_t *ctx, const unsigned char *data, size_t data_len)
{
	size_t blocks;

	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress_blocks(ctx->digest, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}

	blocks = data_len / SM3_BLOCK_SIZE;
	sm3_compress_blocks(ctx->digest, data, blocks);
	ctx->nblocks += blocks;
	data += SM3_BLOCK_SIZE * blocks;
	data_len -= SM3_BLOCK_SIZE * blocks;

	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_final(sm3_ctx_t *ctx, unsigned char *digest)
{
	int i;

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}
	PUTU32(ctx->block + 56, ctx->nblocks >> 23);
	PUTU32(ctx->block + 60, (ctx->nblocks << 9) + (ctx->num << 3));

	sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < 8; i++) {
		PUTU32(digest + i*4, ctx->digest[i]);
	}
}

#define ROTL(x,n)  (((x)<<(n)) | ((x)>>(32-(n))))
#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x),17))
#define P1(x) ((x) ^ ROL32((x),15) ^ ROL32((x),23))

#define FF00(x,y,z)  ((x) ^ (y) ^ (z))
#define FF16(x,y,z)  (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z)  ((x) ^ (y) ^ (z))
#define GG16(x,y,z)  ((((y)^(z)) & (x)) ^ (z))

#define R(A, B, C, D, E, F, G, H, xx)				\
	SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);		\
	SS2 = SS1 ^ ROL32(A, 12);				\
	TT1 = FF##xx(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);	\
	TT2 = GG##xx(E, F, G) + H + SS1 + W[j];			\
	B = ROL32(B, 9);					\
	H = TT1;						\
	F = ROL32(F, 19);					\
	D = P0(TT2);						\
	j++

#define R8(A, B, C, D, E, F, G, H, xx)				\
	R(A, B, C, D, E, F, G, H, xx);				\
	R(H, A, B, C, D, E, F, G, xx);				\
	R(G, H, A, B, C, D, E, F, xx);				\
	R(F, G, H, A, B, C, D, E, xx);				\
	R(E, F, G, H, A, B, C, D, xx);				\
	R(D, E, F, G, H, A, B, C, xx);				\
	R(C, D, E, F, G, H, A, B, xx);				\
	R(B, C, D, E, F, G, H, A, xx)



#define T00 0x79cc4519U
#define T16 0x7a879d8aU

#define K0	0x79cc4519U
#define K1	0xf3988a32U
#define K2	0xe7311465U
#define K3	0xce6228cbU
#define K4	0x9cc45197U
#define K5	0x3988a32fU
#define K6	0x7311465eU
#define K7	0xe6228cbcU
#define K8	0xcc451979U
#define K9	0x988a32f3U
#define K10	0x311465e7U
#define K11	0x6228cbceU
#define K12	0xc451979cU
#define K13	0x88a32f39U
#define K14	0x11465e73U
#define K15	0x228cbce6U
#define K16	0x9d8a7a87U
#define K17	0x3b14f50fU
#define K18	0x7629ea1eU
#define K19	0xec53d43cU
#define K20	0xd8a7a879U
#define K21	0xb14f50f3U
#define K22	0x629ea1e7U
#define K23	0xc53d43ceU
#define K24	0x8a7a879dU
#define K25	0x14f50f3bU
#define K26	0x29ea1e76U
#define K27	0x53d43cecU
#define K28	0xa7a879d8U
#define K29	0x4f50f3b1U
#define K30	0x9ea1e762U
#define K31	0x3d43cec5U
#define K32	0x7a879d8aU
#define K33	0xf50f3b14U
#define K34	0xea1e7629U
#define K35	0xd43cec53U
#define K36	0xa879d8a7U
#define K37	0x50f3b14fU
#define K38	0xa1e7629eU
#define K39	0x43cec53dU
#define K40	0x879d8a7aU
#define K41	0x0f3b14f5U
#define K42	0x1e7629eaU
#define K43	0x3cec53d4U
#define K44	0x79d8a7a8U
#define K45	0xf3b14f50U
#define K46	0xe7629ea1U
#define K47	0xcec53d43U
#define K48	0x9d8a7a87U
#define K49	0x3b14f50fU
#define K50	0x7629ea1eU
#define K51	0xec53d43cU
#define K52	0xd8a7a879U
#define K53	0xb14f50f3U
#define K54	0x629ea1e7U
#define K55	0xc53d43ceU
#define K56	0x8a7a879dU
#define K57	0x14f50f3bU
#define K58	0x29ea1e76U
#define K59	0x53d43cecU
#define K60	0xa7a879d8U
#define K61	0x4f50f3b1U
#define K62	0x9ea1e762U
#define K63	0x3d43cec5U

uint32_t K[64] = {
	K0,  K1,  K2,  K3,  K4,  K5,  K6,  K7,
	K8,  K9,  K10, K11, K12, K13, K14, K15,
	K16, K17, K18, K19, K20, K21, K22, K23,
	K24, K25, K26, K27, K28, K29, K30, K31,
	K32, K33, K34, K35, K36, K37, K38, K39,
	K40, K41, K42, K43, K44, K45, K46, K47,
	K48, K49, K50, K51, K52, K53, K54, K55,
	K56, K57, K58, K59, K60, K61, K62, K63,
	/*
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
	*/
};

static void sm3_compress_blocks(uint32_t digest[8],
	const unsigned char *data, size_t blocks)
{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t E;
	uint32_t F;
	uint32_t G;
	uint32_t H;
	uint32_t W[68];
	uint32_t SS1, SS2, TT1, TT2;
	int j;

#ifdef SM3_SSE3
	__m128i X, T, R;
	__m128i M = _mm_setr_epi32(0, 0, 0, 0xffffffff);
	__m128i V = _mm_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12);
#endif

	while (blocks--) {

		A = digest[0];
		B = digest[1];
		C = digest[2];
		D = digest[3];
		E = digest[4];
		F = digest[5];
		G = digest[6];
		H = digest[7];


#ifdef SM3_SSE3

		for (j = 0; j < 16; j += 4) {
			X = _mm_loadu_si128((__m128i *)(data + j * 4));
			X = _mm_shuffle_epi8(X, V);
			_mm_storeu_si128((__m128i *)(W + j), X);
		}

		for (j = 16; j < 68; j += 4) {
			/* X = (W[j - 3], W[j - 2], W[j - 1], 0) */
			X = _mm_loadu_si128((__m128i *)(W + j - 3));
			X = _mm_andnot_si128(M, X);

			X = _mm_rotl_epi32(X, 15);
			T = _mm_loadu_si128((__m128i *)(W + j - 9));
			X = _mm_xor_si128(X, T);
			T = _mm_loadu_si128((__m128i *)(W + j - 16));
			X = _mm_xor_si128(X, T);

			/* P1() */
			T = _mm_rotl_epi32(X, (23 - 15));
			T = _mm_xor_si128(T, X);
			T = _mm_rotl_epi32(T, 15);
			X = _mm_xor_si128(X, T);

			T = _mm_loadu_si128((__m128i *)(W + j - 13));
			T = _mm_rotl_epi32(T, 7);
			X = _mm_xor_si128(X, T);
			T = _mm_loadu_si128((__m128i *)(W + j - 6));
			X = _mm_xor_si128(X, T);

			/* W[j + 3] ^= P1(ROL32(W[j + 1], 15)) */
			R = _mm_shuffle_epi32(X, 0);
			R = _mm_and_si128(R, M);
			T = _mm_rotl_epi32(R, 15);
			T = _mm_xor_si128(T, R);
			T = _mm_rotl_epi32(T, 9);
			R = _mm_xor_si128(R, T);
			R = _mm_rotl_epi32(R, 6);
			X = _mm_xor_si128(X, R);

			_mm_storeu_si128((__m128i *)(W + j), X);
		}
#else
		for (j = 0; j < 16; j++)
			W[j] = GETU32(data + j*4);

		for (; j < 68; j++)
			W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15))
				^ ROL32(W[j - 13], 7) ^ W[j - 6];
#endif


		j = 0;

#define FULL_UNROLL
#ifdef FULL_UNROLL
		R8(A, B, C, D, E, F, G, H, 00);
		R8(A, B, C, D, E, F, G, H, 00);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
		R8(A, B, C, D, E, F, G, H, 16);
#else
		for (; j < 16; j++) {
			SS1 = ROL32((ROL32(A, 12) + E + K(j)), 7);
			SS2 = SS1 ^ ROL32(A, 12);
			TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
			TT2 = GG00(E, F, G) + H + SS1 + W[j];
			D = C;
			C = ROL32(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = ROL32(F, 19);
			F = E;
			E = P0(TT2);
		}

		for (; j < 64; j++) {
			SS1 = ROL32((ROL32(A, 12) + E + K(j)), 7);
			SS2 = SS1 ^ ROL32(A, 12);
			TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
			TT2 = GG16(E, F, G) + H + SS1 + W[j];
			D = C;
			C = ROL32(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = ROL32(F, 19);
			F = E;
			E = P0(TT2);
		}
#endif

		digest[0] ^= A;
		digest[1] ^= B;
		digest[2] ^= C;
		digest[3] ^= D;
		digest[4] ^= E;
		digest[5] ^= F;
		digest[6] ^= G;
		digest[7] ^= H;

		data += 64;
	}
}

void sm3_compress(uint32_t digest[8], const unsigned char block[64])
{
	return sm3_compress_blocks(digest, block, 1);
}

void sm3(const unsigned char *msg, size_t msglen,
	unsigned char dgst[SM3_DIGEST_LENGTH])
{
	sm3_ctx_t ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, msg, msglen);
	sm3_final(&ctx, dgst);

	memset(&ctx, 0, sizeof(sm3_ctx_t));
}
