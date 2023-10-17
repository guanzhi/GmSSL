/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <string.h>
#include <gmssl/md5.h>
#include <gmssl/endian.h>


#define F(B, C, D)	(((B) & (C)) | ((~(B)) & (D)))
#define G(B, C, D)	(((B) & (D)) | ((C) & (~(D))))
#define H(B, C, D)	((B) ^ (C) ^ (D))
#define I(B, C, D)	((C) ^ ((B) | (~(D))))

static const uint32_t K[] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const int S[] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static void md5_compress_blocks(uint32_t state[4],
	const unsigned char *data, size_t blocks)
{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t T;
	uint32_t W[16];
	int g, i;

	while (blocks--) {

		A = state[0];
		B = state[1];
		C = state[2];
		D = state[3];

		for (i = 0; i < 16; i++) {
			W[i] = GETU32_LE(data);
			data += sizeof(uint32_t);
		}

		for (i = 0; i < 16; i++) {
			T = ROL32(A + F(B, C, D) + W[i] + K[i], S[i]) + B;
			A = D;
			D = C;
			C = B;
			B = T;
		}
		for (; i < 32; i++) {
			g = (5 * i + 1) % 16;
			T = ROL32(A + G(B, C, D) + W[g] + K[i], S[i]) + B;
			A = D;
			D = C;
			C = B;
			B = T;
		}
		for (; i < 48; i++) {
			g = (3 * i + 5) % 16;
			T = ROL32(A + H(B, C, D) + W[g] + K[i], S[i]) + B;
			A = D;
			D = C;
			C = B;
			B = T;
		}
		for (; i < 64; i++) {
			g = (7 * i) % 16;
			T = ROL32(A + I(B, C, D) + W[g] + K[i], S[i]) + B;
			A = D;
			D = C;
			C = B;
			B = T;
		}

		state[0] += A;
		state[1] += B;
		state[2] += C;
		state[3] += D;
	}
}

void md5_init(MD5_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

void md5_update(MD5_CTX *ctx, const unsigned char *data, size_t datalen)
{
	size_t blocks;

	ctx->num &= 0x3f;
	if (ctx->num) {
		size_t left = MD5_BLOCK_SIZE - ctx->num;
		if (datalen < left) {
			memcpy(ctx->block + ctx->num, data, datalen);
			ctx->num += datalen;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			md5_compress_blocks(ctx->state, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			datalen -= left;
		}
	}

	blocks = datalen / MD5_BLOCK_SIZE;
	md5_compress_blocks(ctx->state, data, blocks);
	ctx->nblocks += blocks;
	data += MD5_BLOCK_SIZE * blocks;
	datalen -= MD5_BLOCK_SIZE * blocks;

	ctx->num = datalen;
	if (datalen) {
		memcpy(ctx->block, data, datalen);
	}
}

void md5_finish(MD5_CTX *ctx, unsigned char *dgst)
{
	int i;

	ctx->num &= 0x3f;
	ctx->block[ctx->num] = 0x80;

	if (ctx->num <= MD5_BLOCK_SIZE - 9) {
		memset(ctx->block + ctx->num + 1, 0, MD5_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, MD5_BLOCK_SIZE - ctx->num - 1);
		md5_compress_blocks(ctx->state, ctx->block, 1);
		memset(ctx->block, 0, MD5_BLOCK_SIZE - 8);
	}
	PUTU64_LE(ctx->block + 56, (ctx->nblocks << 9) + (ctx->num << 3));
	md5_compress_blocks(ctx->state, ctx->block, 1);
	for (i = 0; i < 4; i++) {
		PUTU32_LE(dgst, ctx->state[i]);
		dgst += sizeof(uint32_t);
	}
}

void md5_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[MD5_DIGEST_SIZE])
{
	MD5_CTX ctx;
	md5_init(&ctx);
	md5_update(&ctx, data, datalen);
	md5_finish(&ctx, dgst);
	memset(&ctx, 0, sizeof(ctx));
}
