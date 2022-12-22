/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
// see GM/T 0105-2021 Design Guide for Software-based Random Number Generators

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sm3_rng.h>


static const uint8_t num[4] = { 0, 1, 2, 3 };

typedef struct {
	SM3_CTX sm3_ctx[2];
} SM3_DF_CTX;

// sm3_df(in) := ( sm3(be32(1) || be32(440) || in) ||
//		   sm3(b332(2) || be32(440) || in) )[0:55]
static void sm3_df_init(SM3_DF_CTX *df_ctx)
{
	uint8_t counter[4] = {0, 0, 0, 1};
	uint8_t seedlen[4] = {0, 0, 440/256, 440%256};

	sm3_init(&df_ctx->sm3_ctx[0]);
	sm3_update(&df_ctx->sm3_ctx[0], counter, 4);
	sm3_update(&df_ctx->sm3_ctx[0], seedlen, 4);
	counter[3] = 2;
	sm3_init(&df_ctx->sm3_ctx[1]);
	sm3_update(&df_ctx->sm3_ctx[1], counter, 4);
	sm3_update(&df_ctx->sm3_ctx[1], seedlen, 4);
}

static void sm3_df_update(SM3_DF_CTX *df_ctx, const uint8_t *data, size_t datalen)
{
	if (data && datalen) {
		sm3_update(&df_ctx->sm3_ctx[0], data, datalen);
		sm3_update(&df_ctx->sm3_ctx[1], data, datalen);
	}
}

static void sm3_df_finish(SM3_DF_CTX *df_ctx, uint8_t out[55])
{
	uint8_t buf[32];
	sm3_finish(&df_ctx->sm3_ctx[0], out);
	sm3_finish(&df_ctx->sm3_ctx[1], buf);
	memcpy(out + 32, buf, 55 - 32);
}

int sm3_rng_init(SM3_RNG *rng, const uint8_t *nonce, size_t nonce_len,
	const uint8_t *label, size_t label_len)
{
	SM3_DF_CTX df_ctx;
	uint8_t entropy[512];

	// get_entropy, 512-byte might be too long for some system RNGs
	if (rand_bytes(entropy, 256) != 1
		|| rand_bytes(entropy + 256, 256) != 1) {
		error_print();
		return -1;
	}

	// V = sm3_df(entropy || nonce || label)
	sm3_df_init(&df_ctx);
	sm3_df_update(&df_ctx, entropy, sizeof(entropy));
	sm3_df_update(&df_ctx, nonce, nonce_len);
	sm3_df_update(&df_ctx, label, label_len);
	sm3_df_finish(&df_ctx, rng->V);

	// C = sm3_df(0x00 || V)
	sm3_df_init(&df_ctx);
	sm3_df_update(&df_ctx, &num[0], 1);
	sm3_df_update(&df_ctx, rng->V, 55);
	sm3_df_finish(&df_ctx, rng->C);

	// reseed_counter = 1, last_ressed_time = now()
	rng->reseed_counter = 1;
	rng->last_reseed_time = time(NULL);

	gmssl_secure_clear(&df_ctx, sizeof(df_ctx));
	gmssl_secure_clear(entropy, sizeof(entropy));
	return 1;
}

int sm3_rng_reseed(SM3_RNG *rng, const uint8_t *addin, size_t addin_len)
{
	SM3_DF_CTX df_ctx;
	uint8_t entropy[512];

	// get_entropy, 512-byte might be too long for some system RNGs
	if (rand_bytes(entropy, 256) != 1
		|| rand_bytes(entropy + 256, 256) != 1) {
		error_print();
		return -1;
	}

	// V = sm3_df(0x01 || entropy || V || appin)
	sm3_df_init(&df_ctx);
	sm3_df_update(&df_ctx, &num[1], 1);
	sm3_df_update(&df_ctx, entropy, sizeof(entropy));
	sm3_df_update(&df_ctx, rng->V, 55);
	sm3_df_update(&df_ctx, addin, addin_len);
	sm3_df_finish(&df_ctx, rng->V);

	// C = sm3_df(0x00 || V)
	sm3_df_init(&df_ctx);
	sm3_df_update(&df_ctx, &num[0], 1);
	sm3_df_update(&df_ctx, rng->V, 55);
	sm3_df_finish(&df_ctx, rng->C);

	// reseed_counter = 1, last_ressed_time = now()
	rng->reseed_counter = 1;
	rng->last_reseed_time = time(NULL);

	gmssl_secure_clear(&df_ctx, sizeof(df_ctx));
	gmssl_secure_clear(entropy, sizeof(entropy));
	return 1;
}

static void be_add(uint8_t r[55], const uint8_t *a, size_t alen)
{
	int i, j, carry = 0;

	for (i = 54, j = (int)(alen - 1); j >= 0; i--, j--) {
		carry += r[i] + a[j];
		r[i] = carry & 0xff;
		carry >>= 8;
	}
	for (; i >= 0; i--) {
		carry += r[i];
		r[i] = carry & 0xff;
		carry >>= 8;
	}
}

int sm3_rng_generate(SM3_RNG *rng, const uint8_t *addin, size_t addin_len,
	uint8_t *out, size_t outlen)
{
	SM3_CTX sm3_ctx;
	uint8_t H[32];
	uint8_t counter[4];

	if (!outlen || outlen > 32) {
		error_print();
		return -1;
	}

	if (rng->reseed_counter > SM3_RNG_MAX_RESEED_COUNTER
		|| time(NULL) - rng->last_reseed_time > SM3_RNG_MAX_RESEED_SECONDS) {
		if (sm3_rng_reseed(rng, addin, addin_len) != 1) {
			error_print();
			return -1;
		}
		if (addin) {
			addin = NULL;
		}
	}

	if (addin && addin_len) {
		uint8_t W[32];

		// W = sm3(0x02 || V || addin)
		sm3_init(&sm3_ctx);
		sm3_update(&sm3_ctx, &num[2], 1);
		sm3_update(&sm3_ctx, rng->V, 55);
		sm3_update(&sm3_ctx, addin, addin_len);
		sm3_finish(&sm3_ctx, W);

		// V = (V + W) mod 2^440
		be_add(rng->V, W, 32);

		gmssl_secure_clear(W, sizeof(W));
	}

	// output sm3(V)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, rng->V, 55);
	if (outlen < 32) {
		uint8_t buf[32];
		sm3_finish(&sm3_ctx, buf);
		memcpy(out, buf, outlen);
	} else {
		sm3_finish(&sm3_ctx, out);
	}

	// H = sm3(0x03 || V)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, &num[3], 1);
	sm3_update(&sm3_ctx, rng->V, 55);
	sm3_finish(&sm3_ctx, H);

	// V = (V + H + C + reseed_counter) mod 2^440
	be_add(rng->V, H, 32);
	be_add(rng->V, rng->C, 55);
	counter[0] = (rng->reseed_counter >> 24) & 0xff;
	counter[1] = (rng->reseed_counter >> 16) & 0xff;
	counter[2] = (rng->reseed_counter >>  8) & 0xff;
	counter[3] = (rng->reseed_counter      ) & 0xff;
	be_add(rng->V, counter, 4);

	(rng->reseed_counter)++;

	gmssl_secure_clear(&sm3_ctx, sizeof(sm3_ctx));
	gmssl_secure_clear(H, sizeof(H));
	return 1;
}
