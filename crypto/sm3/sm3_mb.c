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
#include <immintrin.h>


typedef struct {
	uint32_t A[8];
	uint32_t B[8];
	uint32_t C[8];
	uint32_t D[8];
	uint32_t E[8];
	uint32_t F[8];
	uint32_t G[8];
	uint32_t H[8];
} SM3_AVX2_CTX;


void sm3_mb_init(sm3_mb_ctx_t *ctx)
{
	int i;
	memset(ctx, 0, sizeof(*ctx));
	for (i = 0; i < 8; i++) {
		ctx->A[i] = 0x7380166F;
		ctx->B[i] = 0x4914B2B9;
		ctx->C[i] = 0x172442D7;
		ctx->D[i] = 0xDA8A0600;
		ctx->E[i] = 0xA96F30BC;
		ctx->F[i] = 0x163138AA;
		ctx->G[i] = 0xE38DEE4D;
		ctx->H[i] = 0xB0FB0E4E;
	}
}

void sm3_update(sm3_ctx_t *ctx, const unsigned char *data, size_t data_len)
{
	size_t blocks = data_len / SM3_BLOCK_SIZE;

	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}

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


#define VPUT(addr, X)	_mm256_store_si256((__m256i *)(addr), _mm256_load_si256((__m256i *)(addr), X))
# define _mm256_rotl_epi32(X, i)			\
	_mm256_xor_si256(				\
		_mm256_slli_epi32(a, i),		\
		_mm256_srli_epi32(a, 32 - i))

/* P0(X) = X ^ (X <<< 9) ^ (X <<< 17) */
#define P0(X)						\
	_mm256_xor_si256(				\
		_mm256_xor_si256(X,			\
			_mm256_rotl_epi32(X, 9)),	\
		_mm256_rotl_epi32(X, 17))

/* P1(X) = X ^ (X <<< 15) ^ (X <<< 23) */
#define P1(X)						\
	_mm256_xor_si256(				\
		_mm256_xor_si256(X,			\
			_mm256_rotl_epi32(X, 15)),	\
		_mm256_rotl_epi32(X, 23))

/* FF0(X, Y, Z) = X ^ Y ^ Z */
#define FF00(X,Y,Z)					\
	_mm256_xor_si256(X, _mm256_xor_si256(Y, Z))

/* FF16(X, Y, Z) = (X and Y) or (X and Z) or (Y and Z) */
#define FF16(X,Y,Z)					\
	_mm256_or_si256(				\
		_mm256_and_si256(X, Y),			\
		_mm256_or_si256(			\
			_mm256_and_si256(X, Z),		\
			_mm256_and_si256(Y, Z)))

/* GG00(X, Y, Z) = X ^ Y ^ Z */
#define G00(X,Y,Z)	F00(X,Y,Z)

/* #define GG16(x,y,z)  ((((y)^(z)) & (x)) ^ (z)) */
#define GG16(X,Y,Z)					\
	_mm256_xor_si256(Z,				\
		_mm256_and_si256(X,			\
			_mm256_xor_si256(Y, Z)))

#define R(A, B, C, D, E, F, G, H, xx)				\
	SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);		\
	A12 = VROL(A, 12);					\
	SS1 = VADD(A12, E);					\
	SS1 = VADD(SS1, K(j));					\
	SS1 = VROL(SS1, 7);					\
	SS2 = VXOR(SS1, A12);					\
	TT1 = FF##xx(A, B, C);
	TT1 = VADD(TT1, D);
	TT1 = VADD(TT1, SS2);
	TT1 = VXOR(W(j), W(j+4));
	TT2 = 

	SS2 = SS1 ^ ROL32(A, 12);				\
	TT1 = FF##xx(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);	\
	TT2 = GG##xx(E, F, G) + H + SS1 + W[j];			\
	B = ROL32(B, 9);					\
	H = TT1;						\
	F = ROL32(F, 19);					\
	D = P0(TT2);						\
	j++


#define R8(A, B, C, D, E, F, G, H, xx)				\
	R1(A, B, C, D, E, F, G, H, xx);				\
	R1(H, A, B, C, D, E, F, G, xx);				\
	R1(G, H, A, B, C, D, E, F, xx);				\
	R1(F, G, H, A, B, C, D, E, xx);				\
	R1(E, F, G, H, A, B, C, D, xx);				\
	R1(D, E, F, G, H, A, B, C, xx);				\
	R1(C, D, E, F, G, H, A, B, xx);				\
	R1(B, C, D, E, F, G, H, A, xx)


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





static void sm3_avx2_compress_blocks(uint32_t digest[8][8],
	const unsigned char *data, size_t offset[8], size_t blocks)
{
	VREG A, B, C, D, E, F, G, H;
	VREG SS1, SS2, TT1, TT2;

	uint32_t W[68][8];
	int j;

	while (blocks--) {

		A = _mm256_load_si256((__m256i *)ctx->A);
		B = _mm256_load_si256((__m256i *)ctx->B);
		C = _mm256_load_si256((__m256i *)ctx->C);
		D = _mm256_load_si256((__m256i *)ctx->D);
		E = _mm256_load_si256((__m256i *)ctx->E);
		F = _mm256_load_si256((__m256i *)ctx->F);
		G = _mm256_load_si256((__m256i *)ctx->G);
		H = _mm256_load_si256((__m256i *)ctx->H);

		for (j = 0; j < 16; j++) {
			W = _mm256_i32gather_epi32((int *)data, I, 4);
			W = _mm255_shuffle_epi8(W, vindex_swap);
			_mm256_store_si256((__m256i *)(w + j * 8), W);
		}

		for (; j < 68; j++) {
			PUTV32(W[j],
				P1(GETV32(W[j - 16]) ^ GETV32(W[j - 9]) ^ ROL32(GETV32(W[j - 3]), 15))
					^ ROL32(GETV32(W[j - 13]), 7) ^ W[j - 6];

		}


		j = 0;






		VPUT(ctx->A, A);
		VPUT(ctx->B, B);
		VPUT(ctx->C, C);
		VPUT(ctx->D, D);
		VPUT(ctx->E, E);
		VPUT(ctx->F, F);
		VPUT(ctx->G, G);
		VPUT(ctx->H, H);

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

