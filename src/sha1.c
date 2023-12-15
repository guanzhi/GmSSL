/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include <gmssl/sha1.h>
#include <gmssl/endian.h>


#define F0(B, C, D)	(((B) & (C)) | ((~(B)) & (D)))
#define F1(B, C, D)	((B) ^ (C) ^ (D))
#define F2(B, C, D)	(((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define F3(B, C, D)	((B) ^ (C) ^ (D))

#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

static void sha1_compress_blocks(uint32_t state[5],
	const unsigned char *data, size_t blocks)
{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t E;
	uint32_t T;
	uint32_t W[80];
	int i;

	while (blocks--) {

		A = state[0];
		B = state[1];
		C = state[2];
		D = state[3];
		E = state[4];

		for (i = 0; i < 16; i++) {
			W[i] = GETU32(data);
			data += 4;
		}
		for (; i < 80; i++) {
			W[i] = ROL32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
		}

		/* see https://en.wikipedia.org/wiki/SHA-1#/media/File:SHA-1.svg */
		for (i = 0; i < 20; i++) {
			T = E + F0(B, C, D) + ROL32(A, 5) + W[i] + K0;
			E = D;
			D = C;
			C = ROL32(B, 30);
			B = A;
			A = T;
		}
		for (; i < 40; i++) {
			T = E + F1(B, C, D) + ROL32(A, 5) + W[i] + K1;
			E = D;
			D = C;
			C = ROL32(B, 30);
			B = A;
			A = T;
		}
		for (; i < 60; i++) {
			T = E + F2(B, C, D) + ROL32(A, 5) + W[i] + K2;
			E = D;
			D = C;
			C = ROL32(B, 30);
			B = A;
			A = T;
		}
		for (; i < 80; i++) {
			T = E + F3(B, C, D) + ROL32(A, 5) + W[i] + K3;
			E = D;
			D = C;
			C = ROL32(B, 30);
			B = A;
			A = T;
		}

		state[0] += A;
		state[1] += B;
		state[2] += C;
		state[3] += D;
		state[4] += E;
	}
}

void sha1_init(SHA1_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
}

void sha1_update(SHA1_CTX *ctx, const unsigned char *data, size_t datalen)
{
	size_t blocks;

	ctx->num &= 0x3f;
	if (ctx->num) {
		size_t left = SHA1_BLOCK_SIZE - ctx->num;
		if (datalen < left) {
			memcpy(ctx->block + ctx->num, data, datalen);
			ctx->num += datalen;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sha1_compress_blocks(ctx->state, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			datalen -= left;
		}
	}

	blocks = datalen / SHA1_BLOCK_SIZE;
	if (blocks) {
		sha1_compress_blocks(ctx->state, data, blocks);
		ctx->nblocks += blocks;
		data += SHA1_BLOCK_SIZE * blocks;
		datalen -= SHA1_BLOCK_SIZE * blocks;
	}

	ctx->num = datalen;
	if (datalen) {
		memcpy(ctx->block, data, datalen);
	}
}

void sha1_finish(SHA1_CTX *ctx, unsigned char *dgst)
{
	int i;

	ctx->num &= 0x3f;
	ctx->block[ctx->num] = 0x80;

	if (ctx->num <= SHA1_BLOCK_SIZE - 9) {
		memset(ctx->block + ctx->num + 1, 0, SHA1_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SHA1_BLOCK_SIZE - ctx->num - 1);
		sha1_compress_blocks(ctx->state, ctx->block, 1);
		memset(ctx->block, 0, SHA1_BLOCK_SIZE - 8);
	}
	PUTU32(ctx->block + 56, ctx->nblocks >> 23);
	PUTU32(ctx->block + 60, (ctx->nblocks << 9) + (ctx->num << 3));

	sha1_compress_blocks(ctx->state, ctx->block, 1);
	for (i = 0; i < 5; i++) {
		PUTU32(dgst + i*4, ctx->state[i]);
	}
}

void sha1_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA1_DIGEST_SIZE])
{
	SHA1_CTX ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, data, datalen);
	sha1_finish(&ctx, dgst);
	memset(&ctx, 0, sizeof(ctx));
}
