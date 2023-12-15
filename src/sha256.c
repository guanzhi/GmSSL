/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include <gmssl/sha2.h>
#include <gmssl/endian.h>


#define Ch(X, Y, Z)	(((X) & (Y)) ^ ((~(X)) & (Z)))
#define Maj(X, Y, Z)	(((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define Sigma0(X)	(ROR32((X),  2) ^ ROR32((X), 13) ^ ROR32((X), 22))
#define Sigma1(X)	(ROR32((X),  6) ^ ROR32((X), 11) ^ ROR32((X), 25))
#define sigma0(X)	(ROR32((X),  7) ^ ROR32((X), 18) ^ ((X) >>  3))
#define sigma1(X)	(ROR32((X), 17) ^ ROR32((X), 19) ^ ((X) >> 10))

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_compress_blocks(uint32_t state[8],
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
	uint32_t W[64];
	uint32_t T1, T2;
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
			W[i] = GETU32(data);
			data += 4;
		}
		for (; i < 64; i++) {
			W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
		}

		for (i = 0; i < 64; i++) {
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


void sha256_init(SHA256_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const unsigned char *data, size_t datalen)
{
	size_t blocks;

	ctx->num &= 0x3f;
	if (ctx->num) {
		size_t left = SHA256_BLOCK_SIZE - ctx->num;
		if (datalen < left) {
			memcpy(ctx->block + ctx->num, data, datalen);
			ctx->num += datalen;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sha256_compress_blocks(ctx->state, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			datalen -= left;
		}
	}

	blocks = datalen / SHA256_BLOCK_SIZE;
	if (blocks) {
		sha256_compress_blocks(ctx->state, data, blocks);
		ctx->nblocks += blocks;
		data += SHA256_BLOCK_SIZE * blocks;
		datalen -= SHA256_BLOCK_SIZE * blocks;
	}

	ctx->num = datalen;
	if (datalen) {
		memcpy(ctx->block, data, datalen);
	}
}

void sha256_finish(SHA256_CTX *ctx, unsigned char dgst[SHA256_DIGEST_SIZE])
{
	int i;

	ctx->num &= 0x3f;
	ctx->block[ctx->num] = 0x80;

	if (ctx->num <= SHA256_BLOCK_SIZE - 9) {
		memset(ctx->block + ctx->num + 1, 0, SHA256_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SHA256_BLOCK_SIZE - ctx->num - 1);
		sha256_compress_blocks(ctx->state, ctx->block, 1);
		memset(ctx->block, 0, SHA256_BLOCK_SIZE - 8);
	}
	PUTU32(ctx->block + 56, ctx->nblocks >> 23);
	PUTU32(ctx->block + 60, (ctx->nblocks << 9) + (ctx->num << 3));

	sha256_compress_blocks(ctx->state, ctx->block, 1);
	for (i = 0; i < 8; i++) {
		PUTU32(dgst, ctx->state[i]);
		dgst += sizeof(uint32_t);
	}
}

void sha256_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA256_DIGEST_SIZE])
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, datalen);
	sha256_finish(&ctx, dgst);
	memset(&ctx, 0, sizeof(ctx));
}


void sha224_init(SHA224_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0xc1059ed8;
	ctx->state[1] = 0x367cd507;
	ctx->state[2] = 0x3070dd17;
	ctx->state[3] = 0xf70e5939;
	ctx->state[4] = 0xffc00b31;
	ctx->state[5] = 0x68581511;
	ctx->state[6] = 0x64f98fa7;
	ctx->state[7] = 0xbefa4fa4;
}

void sha224_update(SHA224_CTX *ctx, const unsigned char *data, size_t datalen)
{
	sha256_update((SHA256_CTX *)ctx, data, datalen);
}

void sha224_finish(SHA224_CTX *ctx, unsigned char dgst[SHA224_DIGEST_SIZE])
{
	uint8_t buf[SHA256_DIGEST_SIZE];
	sha256_finish((SHA256_CTX *)ctx, buf);
	memcpy(dgst, buf, SHA224_DIGEST_SIZE);
	memset(buf, 0, sizeof(buf));
}

void sha224_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA224_DIGEST_SIZE])
{
	SHA224_CTX ctx;
	sha224_init(&ctx);
	sha224_update(&ctx, data, datalen);
	sha224_finish(&ctx, dgst);
	memset(&ctx, 0, sizeof(ctx));
}
