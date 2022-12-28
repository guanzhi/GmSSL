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
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sm4_cbc_mac.h>
#include <gmssl/sm4_rng.h>


/*
u8[16] R0, R1

(R0,R1) = sm4_df(in):

	L = nbytes(in)
	N = 32 -- nbytes(R0||R1)
	S = be32(L) || be32(N) || in || 0x80 || 0x00^*,  nbytes(S) = 0 (mod 16)
	K = 0x000102030405060708090a0b0c0d0e0f

	T = CBC_MAC(K, be32(0) || 0x00^12 || S) = CBC_MAC(K, be32(0) || 0x00^12 || be32(L) || be32(N) || in || 0x80)
	X = CBC_MAC(K, be32(1) || 0x00^12 || S) = CBC_MAC(K, be32(1) || 0x00^12 || be32(L) || be32(N) || in || 0x80)
	K = T

	R0 = sm4(K, X)
	R1 = sm4(K, R0)
*/

typedef struct {
	SM4_CBC_MAC_CTX cbc_mac_ctx[2];
	uint32_t len;
	uint32_t len_check;
} SM4_DF_CTX;

static void sm4_df_init(SM4_DF_CTX *df_ctx, size_t len)
{
	const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	uint8_t prefix[16] = {0};
	uint8_t Lbuf[4] = {0};
	uint8_t Nbuf[4] = {0};

	Lbuf[0] = (len >> 24) & 0xff;
	Lbuf[1] = (len >> 16) & 0xff;
	Lbuf[2] = (len >> 8) & 0xff;
	Lbuf[3] = len & 0xff;

	Nbuf[3] = 32;

	sm4_cbc_mac_init(&df_ctx->cbc_mac_ctx[0], key);
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[0], prefix, 16);
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[0], Lbuf, 4);
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[0], Nbuf, 4);

	prefix[3] = 1;
	sm4_cbc_mac_init(&df_ctx->cbc_mac_ctx[1], key);
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[1], prefix, 16);
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[1], Lbuf, 4);
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[1], Nbuf, 4);

	df_ctx->len = (uint32_t)len;
	df_ctx->len_check = 0;
}

static void sm4_df_update(SM4_DF_CTX *df_ctx, const uint8_t *data, size_t datalen)
{
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[0], data, datalen);
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[1], data, datalen);
	df_ctx->len_check += datalen;
}

static void sm4_df_finish(SM4_DF_CTX *df_ctx, uint8_t out[32])
{
	const uint8_t suffix[1] = {0x80};
	uint8_t K[16];
	uint8_t X[16];
	SM4_KEY sm4_key;

	assert(df_ctx->len == df_ctx->len_check);

	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[0], suffix, 1);
	sm4_cbc_mac_finish(&df_ctx->cbc_mac_ctx[0], K);
	sm4_cbc_mac_update(&df_ctx->cbc_mac_ctx[1], suffix, 1);
	sm4_cbc_mac_finish(&df_ctx->cbc_mac_ctx[1], X);

	sm4_set_encrypt_key(&sm4_key, K);
	sm4_encrypt(&sm4_key, X, out);
	sm4_encrypt(&sm4_key, out, out + 16);

	gmssl_secure_clear(K, sizeof(K));
	gmssl_secure_clear(X, sizeof(X));
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
}

static void be_incr(uint8_t a[16])
{
	int i;
	for (i = 15; i >= 0; i--) {
		a[i]++;
		if (a[i]) break;
	}
}


int sm4_rng_update(SM4_RNG *rng, const uint8_t seed[32])
{
	SM4_KEY sm4_key;

	sm4_set_encrypt_key(&sm4_key, rng->K);
	be_incr(rng->V);
	sm4_encrypt(&sm4_key, rng->V, rng->K);
	be_incr(rng->V);
	sm4_encrypt(&sm4_key, rng->V, rng->V);
    
    memxor(rng->K, seed, 16);
    memxor(rng->V, seed + 16, 16);

	return 1;
}

int sm4_rng_init(SM4_RNG *rng, const uint8_t *nonce, size_t nonce_len,
	const uint8_t *label, size_t label_len)
{
	SM4_DF_CTX df_ctx;
	uint8_t entropy[512];
	uint8_t seed[32];

	// get_entropy, 512-byte might be too long for some system RNGs
	if (rand_bytes(entropy, 256) != 1
		|| rand_bytes(entropy + 256, 256) != 1) {
		error_print();
		return -1;
	}

	// seed = sm4_df(entropy || nonce || label)
	sm4_df_init(&df_ctx, sizeof(entropy) + nonce_len + label_len);
	sm4_df_update(&df_ctx, entropy, sizeof(entropy));
	sm4_df_update(&df_ctx, nonce, nonce_len);
	sm4_df_update(&df_ctx, label, label_len);
	sm4_df_finish(&df_ctx, seed);

	memset(rng->K, 0, 16);
	memset(rng->V, 0, 16);

	// (K, V) = sm3_rng_update(seed, K, V)
	sm4_rng_update(rng, seed);

	// reseed_counter = 1, last_ressed_time = now()
	rng->reseed_counter = 1;
	rng->last_reseed_time = time(NULL);

	gmssl_secure_clear(&df_ctx, sizeof(df_ctx));
	gmssl_secure_clear(entropy, sizeof(entropy));
	gmssl_secure_clear(seed, sizeof(seed));
	return 1;
}

int sm4_rng_reseed(SM4_RNG *rng, const uint8_t *addin, size_t addin_len)
{
	SM4_DF_CTX df_ctx;
	uint8_t entropy[512];
	uint8_t seed[32];

	// get_entropy, 512-byte might be too long for some system RNGs
	if (rand_bytes(entropy, 256) != 1
		|| rand_bytes(entropy + 256, 256) != 1) {
		error_print();
		return -1;
	}

	// seed = sm4_df(entropy || addin)
	sm4_df_init(&df_ctx, sizeof(entropy) + addin_len);
	sm4_df_update(&df_ctx, entropy, sizeof(entropy));
	sm4_df_update(&df_ctx, addin, addin_len);
	sm4_df_finish(&df_ctx, seed);

	sm4_rng_update(rng, seed);
    
	rng->reseed_counter = 1;
	rng->last_reseed_time = time(NULL);

	gmssl_secure_clear(&df_ctx, sizeof(df_ctx));
	gmssl_secure_clear(entropy, sizeof(entropy));
	return 1;
}


#define SM4_RNG_MAX_RESEED_COUNTER (1<<20)
#define SM4_RNG_MAX_RESEED_SECONDS 600

int sm4_rng_generate(SM4_RNG *rng, const uint8_t *addin, size_t addin_len,
	uint8_t *out, size_t outlen)
{
	uint8_t seed[32] = {0};
	SM4_KEY sm4_key;

	if (!outlen || outlen > 16) {
		error_print();
		return -1;
	}

	if (rng->reseed_counter > SM4_RNG_MAX_RESEED_COUNTER
		|| time(NULL) - rng->last_reseed_time > SM4_RNG_MAX_RESEED_SECONDS) {
		if (sm4_rng_reseed(rng, addin, addin_len) != 1) {
			error_print();
			return -1;
		}
		if (addin) {
			addin = NULL;
		}
	}

	if (addin && addin_len) {
		// seed = sm4_df(addin)
		SM4_DF_CTX df_ctx;
		sm4_df_init(&df_ctx, addin_len);
		sm4_df_update(&df_ctx, addin, addin_len);
		sm4_df_finish(&df_ctx, seed);
		gmssl_secure_clear(&df_ctx, sizeof(df_ctx));

		// rng_update(seed)
		sm4_rng_update(rng, seed);
	}

	// V = (V + 1) mod 2^128
	be_incr(rng->V);

	// output sm4(K, V)[0:outlen]
	sm4_set_encrypt_key(&sm4_key, rng->K);
	if (outlen < 16) {
		uint8_t buf[16];
		sm4_encrypt(&sm4_key, rng->V, buf);
		memcpy(out, buf, outlen);
	} else {
		sm4_encrypt(&sm4_key, rng->V, out);
	}

	// (K, V) = update(seed, (K, V))
	sm4_rng_update(rng, seed);

	// reseed_counter++
	(rng->reseed_counter)++;


	gmssl_secure_clear(seed, sizeof(seed));
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	return 1;
}
