/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <string.h>
#include <gmssl/mem.h>
#include <gmssl/sha3.h>


static uint64_t load64_le(const uint8_t in[8])
{
	return ((uint64_t)in[0])
		| ((uint64_t)in[1] << 8)
		| ((uint64_t)in[2] << 16)
		| ((uint64_t)in[3] << 24)
		| ((uint64_t)in[4] << 32)
		| ((uint64_t)in[5] << 40)
		| ((uint64_t)in[6] << 48)
		| ((uint64_t)in[7] << 56);
}

static void store64_le(uint8_t out[8], uint64_t a)
{
	out[0] = (uint8_t)a;
	out[1] = (uint8_t)(a >> 8);
	out[2] = (uint8_t)(a >> 16);
	out[3] = (uint8_t)(a >> 24);
	out[4] = (uint8_t)(a >> 32);
	out[5] = (uint8_t)(a >> 40);
	out[6] = (uint8_t)(a >> 48);
	out[7] = (uint8_t)(a >> 56);
}

static uint64_t rol64(uint64_t a, int n)
{
	return n ? ((a << n) | (a >> (64 - n))) : a;
}

static void keccak_f1600(uint64_t a[25])
{
	static const uint64_t rc[24] = {
		0x0000000000000001ULL, 0x0000000000008082ULL,
		0x800000000000808aULL, 0x8000000080008000ULL,
		0x000000000000808bULL, 0x0000000080000001ULL,
		0x8000000080008081ULL, 0x8000000000008009ULL,
		0x000000000000008aULL, 0x0000000000000088ULL,
		0x0000000080008009ULL, 0x000000008000000aULL,
		0x000000008000808bULL, 0x800000000000008bULL,
		0x8000000000008089ULL, 0x8000000000008003ULL,
		0x8000000000008002ULL, 0x8000000000000080ULL,
		0x000000000000800aULL, 0x800000008000000aULL,
		0x8000000080008081ULL, 0x8000000000008080ULL,
		0x0000000080000001ULL, 0x8000000080008008ULL,
	};
	static const int rho[25] = {
		 0,  1, 62, 28, 27,
		36, 44,  6, 55, 20,
		 3, 10, 43, 25, 39,
		41, 45, 15, 21,  8,
		18,  2, 61, 56, 14,
	};
	uint64_t b[25];
	uint64_t c[5];
	uint64_t d;
	int round;
	int x;
	int y;

	for (round = 0; round < 24; round++) {
		for (x = 0; x < 5; x++) {
			c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		}
		for (x = 0; x < 5; x++) {
			d = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1);
			for (y = 0; y < 5; y++) {
				a[x + 5 * y] ^= d;
			}
		}
		for (x = 0; x < 5; x++) {
			for (y = 0; y < 5; y++) {
				b[y + 5 * ((2 * x + 3 * y) % 5)] =
					rol64(a[x + 5 * y], rho[x + 5 * y]);
			}
		}
		for (x = 0; x < 5; x++) {
			for (y = 0; y < 5; y++) {
				a[x + 5 * y] = b[x + 5 * y]
					^ ((~b[((x + 1) % 5) + 5 * y])
					& b[((x + 2) % 5) + 5 * y]);
			}
		}
		a[0] ^= rc[round];
	}

	gmssl_secure_clear(b, sizeof(b));
	gmssl_secure_clear(c, sizeof(c));
	gmssl_secure_clear(&d, sizeof(d));
}

static void keccak_xor_block(uint64_t state[25], const uint8_t *block, size_t rate)
{
	size_t i;

	for (i = 0; i < rate / 8; i++) {
		state[i] ^= load64_le(block + 8 * i);
	}
}

static void keccak_store_block(uint8_t *block, const uint64_t state[25], size_t rate)
{
	size_t i;

	for (i = 0; i < rate / 8; i++) {
		store64_le(block + 8 * i, state[i]);
	}
}

static void keccak_init(SHAKE_CTX *ctx, size_t rate)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->rate = rate;
}

static void keccak_update(SHAKE_CTX *ctx, const uint8_t *in, size_t inlen)
{
	size_t len;

	while (inlen) {
		len = ctx->rate - ctx->num;
		if (len > inlen) {
			len = inlen;
		}
		memcpy(ctx->block + ctx->num, in, len);
		ctx->num += len;
		in += len;
		inlen -= len;

		if (ctx->num == ctx->rate) {
			keccak_xor_block(ctx->state, ctx->block, ctx->rate);
			keccak_f1600(ctx->state);
			gmssl_secure_clear(ctx->block, ctx->rate);
			ctx->num = 0;
		}
	}
}

static void keccak_finish(SHAKE_CTX *ctx, uint8_t suffix)
{
	memset(ctx->block + ctx->num, 0, ctx->rate - ctx->num);
	ctx->block[ctx->num] ^= suffix;
	ctx->block[ctx->rate - 1] ^= 0x80;
	keccak_xor_block(ctx->state, ctx->block, ctx->rate);
	keccak_f1600(ctx->state);
	keccak_store_block(ctx->block, ctx->state, ctx->rate);
	ctx->num = 0;
	ctx->squeezing = 1;
}

static void keccak_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t outlen)
{
	size_t len;

	while (outlen) {
		if (ctx->num == ctx->rate) {
			keccak_f1600(ctx->state);
			keccak_store_block(ctx->block, ctx->state, ctx->rate);
			ctx->num = 0;
		}
		len = ctx->rate - ctx->num;
		if (len > outlen) {
			len = outlen;
		}
		memcpy(out, ctx->block + ctx->num, len);
		ctx->num += len;
		out += len;
		outlen -= len;
	}
}

static void keccak_digest(size_t rate, uint8_t suffix,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
	SHAKE_CTX ctx;

	keccak_init(&ctx, rate);
	keccak_update(&ctx, in, inlen);
	keccak_finish(&ctx, suffix);
	keccak_squeeze(&ctx, out, outlen);
	gmssl_secure_clear(&ctx, sizeof(ctx));
}

void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[SHA3_256_DIGEST_SIZE])
{
	keccak_digest(136, 0x06, in, inlen, out, SHA3_256_DIGEST_SIZE);
}

void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[SHA3_512_DIGEST_SIZE])
{
	keccak_digest(72, 0x06, in, inlen, out, SHA3_512_DIGEST_SIZE);
}

void shake128_init(SHAKE_CTX *ctx)
{
	keccak_init(ctx, 168);
}

void shake256_init(SHAKE_CTX *ctx)
{
	keccak_init(ctx, 136);
}

void shake_update(SHAKE_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx->squeezing) {
		keccak_update(ctx, in, inlen);
	}
}

void shake_finish(SHAKE_CTX *ctx)
{
	if (!ctx->squeezing) {
		keccak_finish(ctx, 0x1f);
	}
}

void shake_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t outlen)
{
	if (!ctx->squeezing) {
		keccak_finish(ctx, 0x1f);
	}
	keccak_squeeze(ctx, out, outlen);
}

void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
	keccak_digest(168, 0x1f, in, inlen, out, outlen);
}

void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
	keccak_digest(136, 0x1f, in, inlen, out, outlen);
}
