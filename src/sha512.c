/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/sha2.h>
#include <gmssl/endian.h>


static void sha512_compress_blocks(uint64_t state[8],
	const unsigned char *data, size_t blocks);

void sha512_init(SHA512_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0x6a09e667f3bcc908;
	ctx->state[1] = 0xbb67ae8584caa73b;
	ctx->state[2] = 0x3c6ef372fe94f82b;
	ctx->state[3] = 0xa54ff53a5f1d36f1;
	ctx->state[4] = 0x510e527fade682d1;
	ctx->state[5] = 0x9b05688c2b3e6c1f;
	ctx->state[6] = 0x1f83d9abfb41bd6b;
	ctx->state[7] = 0x5be0cd19137e2179;
}

void sha512_update(SHA512_CTX *ctx, const unsigned char *data, size_t datalen)
{
	size_t blocks;

	if (ctx->num) {
		size_t left = SHA512_BLOCK_SIZE - ctx->num;
		if (datalen < left) {
			memcpy(ctx->block + ctx->num, data, datalen);
			ctx->num += datalen;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sha512_compress_blocks(ctx->state, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			datalen -= left;
		}
	}

	blocks = datalen / SHA512_BLOCK_SIZE;
	if (blocks) {
		sha512_compress_blocks(ctx->state, data, blocks);
		ctx->nblocks += blocks;
		data += SHA512_BLOCK_SIZE * blocks;
		datalen -= SHA512_BLOCK_SIZE * blocks;
	}

	ctx->num = datalen;
	if (datalen) {
		memcpy(ctx->block, data, datalen);
	}
}

void sha512_finish(SHA512_CTX *ctx, unsigned char dgst[SHA512_DIGEST_SIZE])
{
	int i;

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 17 <= SHA512_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SHA512_BLOCK_SIZE - ctx->num - 17);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SHA512_BLOCK_SIZE - ctx->num - 1);
		sha512_compress_blocks(ctx->state, ctx->block, 1);
		memset(ctx->block, 0, SHA512_BLOCK_SIZE - 16);
	}
	PUTU64(ctx->block + 112, ctx->nblocks >> 54);
	PUTU64(ctx->block + 120, (ctx->nblocks << 10) + (ctx->num << 3));

	sha512_compress_blocks(ctx->state, ctx->block, 1);
	for (i = 0; i < 8; i++) {
		PUTU64(dgst, ctx->state[i]);
		dgst += sizeof(uint64_t);
	}
}

#define Ch(X, Y, Z)	(((X) & (Y)) ^ ((~(X)) & (Z)))
#define Maj(X, Y, Z)	(((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define Sigma0(X)	(ROR64((X), 28) ^ ROR64((X), 34) ^ ROR64((X), 39))
#define Sigma1(X)	(ROR64((X), 14) ^ ROR64((X), 18) ^ ROR64((X), 41))
#define sigma0(X)	(ROR64((X),  1) ^ ROR64((X),  8) ^ ((X) >> 7))
#define sigma1(X)	(ROR64((X), 19) ^ ROR64((X), 61) ^ ((X) >> 6))

static const uint64_t K[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

static void sha512_compress_blocks(uint64_t state[8],
	const unsigned char *data, size_t blocks)
{
	uint64_t A;
	uint64_t B;
	uint64_t C;
	uint64_t D;
	uint64_t E;
	uint64_t F;
	uint64_t G;
	uint64_t H;
	uint64_t W[80];
	uint64_t T1, T2;
	int i;

	while (blocks--) {

		A = state[0];
		B = state[1];
		C = state[2];
		D = state[3];
		E = state[4];
		F = state[5];
		G = state[6];
		H = state[7];

		for (i = 0; i < 16; i++) {
			W[i] = GETU64(data);
			data += sizeof(uint64_t);
		}
		for (; i < 80; i++) {
			W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
		}

		for (i = 0; i < 80; i++) {
			T1 = H + Sigma1(E) + Ch(E, F, G) + K[i] + W[i];
			T2 = Sigma0(A) + Maj(A, B, C);
			H = G;
			G = F;
			F = E;
			E = D + T1;
			D = C;
			C = B;
			B = A;
			A = T1 + T2;
		}

		state[0] += A;
		state[1] += B;
		state[2] += C;
		state[3] += D;
		state[4] += E;
		state[5] += F;
		state[6] += G;
		state[7] += H;
	}
}

void sha512_compress(uint64_t state[8], const unsigned char block[64])
{
	sha512_compress_blocks(state, block, 1);
}

void sha512_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA512_DIGEST_SIZE])
{
	SHA512_CTX ctx;
	sha512_init(&ctx);
	sha512_update(&ctx, data, datalen);
	sha512_finish(&ctx, dgst);
	memset(&ctx, 0, sizeof(ctx));
}


void sha384_init(SHA384_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0xcbbb9d5dc1059ed8;
	ctx->state[1] = 0x629a292a367cd507;
	ctx->state[2] = 0x9159015a3070dd17;
	ctx->state[3] = 0x152fecd8f70e5939;
	ctx->state[4] = 0x67332667ffc00b31;
	ctx->state[5] = 0x8eb44a8768581511;
	ctx->state[6] = 0xdb0c2e0d64f98fa7;
	ctx->state[7] = 0x47b5481dbefa4fa4;
}

void sha384_update(SHA384_CTX *ctx, const unsigned char *data, size_t datalen)
{
	sha512_update((SHA512_CTX *)ctx, data, datalen);
}

void sha384_finish(SHA384_CTX *ctx, unsigned char dgst[SHA384_DIGEST_SIZE])
{
	unsigned char buf[SHA512_DIGEST_SIZE];
	sha512_finish((SHA512_CTX *)ctx, buf);
	memcpy(dgst, buf, SHA384_DIGEST_SIZE);
	memset(buf, 0, sizeof(buf));
}

void sha384_compress(uint64_t state[8], const unsigned char block[64])
{
	sha512_compress_blocks(state, block, 1);
}

void sha384_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA384_DIGEST_SIZE])
{
	SHA384_CTX ctx;
	sha384_init(&ctx);
	sha384_update(&ctx, data, datalen);
	sha384_finish(&ctx, dgst);
	memset(&ctx, 0, sizeof(ctx));
}

