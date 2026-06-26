/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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


#define Ch512(X, Y, Z)		(((X) & (Y)) ^ ((~(X)) & (Z)))
#define Maj512(X, Y, Z)		(((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define Sigma512_0(X)		(ROR64((X), 28) ^ ROR64((X), 34) ^ ROR64((X), 39))
#define Sigma512_1(X)		(ROR64((X), 14) ^ ROR64((X), 18) ^ ROR64((X), 41))
#define sigma512_0(X)		(ROR64((X),  1) ^ ROR64((X),  8) ^ ((X) >> 7))
#define sigma512_1(X)		(ROR64((X), 19) ^ ROR64((X), 61) ^ ((X) >> 6))

static const uint64_t K512[80] = {
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
			W[i] = sigma512_1(W[i-2]) + W[i-7] + sigma512_0(W[i-15]) + W[i-16];
		}

		for (i = 0; i < 80; i++) {
			T1 = H + Sigma512_1(E) + Ch512(E, F, G) + K512[i] + W[i];
			T2 = Sigma512_0(A) + Maj512(A, B, C);
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


void sha512_256_init(SHA512_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0x22312194fc2bf72c;
	ctx->state[1] = 0x9f555fa3c84c64c2;
	ctx->state[2] = 0x2393b86b6f53b151;
	ctx->state[3] = 0x963877195940eabd;
	ctx->state[4] = 0x96283ee2a88effe3;
	ctx->state[5] = 0xbe5e1e2553863992;
	ctx->state[6] = 0x2b0199fc2c85b8aa;
	ctx->state[7] = 0x0eb72ddc81c52ca2;
}

void sha512_256_finish(SHA512_CTX *ctx, unsigned char dgst[SHA256_DIGEST_SIZE])
{
	unsigned char buf[SHA512_DIGEST_SIZE];
	sha512_finish(ctx, buf);
	memcpy(dgst, buf, SHA256_DIGEST_SIZE);
	memset(buf, 0, sizeof(buf));
}

void sha512_224_init(SHA512_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0x8c3d37c819544da2;
	ctx->state[1] = 0x73e1996689dcd4d6;
	ctx->state[2] = 0x1dfab7ae32ff9c82;
	ctx->state[3] = 0x679dd514582f9fcf;
	ctx->state[4] = 0x0f6d2b697bd44da8;
	ctx->state[5] = 0x77e36f7304c48942;
	ctx->state[6] = 0x3f9d85a86a1d36c8;
	ctx->state[7] = 0x1112e6ad91d692a1;
}

void sha512_224_finish(SHA512_CTX *ctx, unsigned char dgst[SHA224_DIGEST_SIZE])
{
	unsigned char buf[SHA512_DIGEST_SIZE];
	sha512_finish(ctx, buf);
	memcpy(dgst, buf, SHA224_DIGEST_SIZE);
	memset(buf, 0, sizeof(buf));
}
