/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>
#include <gmssl/sm3_xmss.h>


// copy this static function from src/sm3_xmss.c
static void hash256_prf_init(HASH256_CTX *hash256_ctx, const uint8_t key[32])
{
	uint8_t hash_id[32] = {0};
	hash_id[31] = 3;

	hash256_init(hash256_ctx);
	hash256_update(hash256_ctx, hash_id, 32);
	hash256_update(hash256_ctx, key, 32);
}

static int test_sm3_wots_derive_sk(void)
{
	uint8_t wots_secret[32] = {0};
	uint8_t seed[32] = {0};
	uint8_t adrs[32] = {0};
	hash256_bytes_t wots_sk[67];
	hash256_bytes_t test_sk[67];
	size_t len;

	// sha256 test 1
	memset(wots_secret, 0, 32);
	memset(seed, 0, 32);
	memset(adrs, 0, 32);
	hex_to_bytes("0cb52ea67abd5da0328099db02de310e4ab01ac39d0bbeb71e97eb7e83c467b5", 64, test_sk[0], &len);
	hex_to_bytes("382c16f94b77905d4a6f78e1f38faf5ef914ac42324e356aeede056d356a5eeb", 64, test_sk[1], &len);
	hex_to_bytes("ab08e768529903e533c9bf8b3ea8c69d36aedcee5ac78801f92d23ef758cfe03", 64, test_sk[66], &len);

	sm3_wots_derive_sk(wots_secret, seed, adrs, wots_sk);
	if (memcmp(wots_sk[0], test_sk[0], 32)
		|| memcmp(wots_sk[1], test_sk[1], 32)
		|| memcmp(wots_sk[66], test_sk[66], 32)) {
		error_print();
		return -1;
	}

	// sha256 test 2
	memset(wots_secret, 0x12, 32);
	memset(seed, 0xab, 32);
	memset(adrs, 0, 32);
	hex_to_bytes("1a50a39a53e6ef2480db612cef9456d0f33222f934c58bcba9d04fa91108faf6", 64, test_sk[0], &len);
	hex_to_bytes("e45dad76c1b23975e898a365b8c73d13695a887ba2ba2377f840d3a3b7bf806c", 64, test_sk[1], &len);
	hex_to_bytes("aaad735aa51662b8a48258561fb857b3f2b12a5802593522145b3b68355abf3b", 64, test_sk[66], &len);

	sm3_wots_derive_sk(wots_secret, seed, adrs, wots_sk);
	if (memcmp(wots_sk[0], test_sk[0], 32)
		|| memcmp(wots_sk[1], test_sk[1], 32)
		|| memcmp(wots_sk[66], test_sk[66], 32)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm3_wots_derive_pk(void)
{
	uint8_t wots_secret[32] = {0};
	uint8_t seed[32] = {0};
	uint8_t adrs[32] = {0};
	hash256_bytes_t wots_sk[67];
	hash256_bytes_t wots_pk[67];
	hash256_bytes_t test_pk[67];
	HASH256_CTX prf_seed_ctx;
	size_t len;

	// sha256 test 2
	memset(wots_secret, 0x12, 32);
	memset(seed, 0xab, 32);
	memset(adrs, 0, 32);
	hex_to_bytes("0c74a626695831994961641c487b70da83cd2aba2ba5c63c38ce72479b8a0ab9", 64, test_pk[0], &len);
	hex_to_bytes("acf6be724d4b074d67330559ec24b3d42c9b9d87fa103e7f6be402ec3a2d41c1", 64, test_pk[1], &len);
	hex_to_bytes("98691d83a657840d4b6f410e25fcd9a6480670ac9c090d3b79bc904ba7e131aa", 64, test_pk[66], &len);

	sm3_wots_derive_sk(wots_secret, seed, adrs, wots_sk);
	hash256_prf_init(&prf_seed_ctx, seed);
	sm3_wots_derive_pk(wots_sk, &prf_seed_ctx, adrs, wots_pk);

	if (memcmp(wots_pk[0], test_pk[0], 32)
		|| memcmp(wots_pk[1], test_pk[1], 32)
		|| memcmp(wots_pk[66], test_pk[66], 32)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm3_wots_do_sign(void)
{
	uint8_t wots_secret[32] = {0};
	uint8_t seed[32] = {0};
	uint8_t adrs[32] = {0};
	uint8_t dgst[32] = {0};
	hash256_bytes_t wots_sk[67];
	hash256_bytes_t wots_pk[67];
	hash256_bytes_t wots_sig[67];
	hash256_bytes_t test_sig[67];
	hash256_bytes_t sig_pk[67];
	HASH256_CTX prf_seed_ctx;
	size_t len;
	int i;

	memset(wots_secret, 0x12, 32);
	memset(seed, 0xab, 32);
	memset(adrs, 0, 32);
	for (i = 0; i < 32; i++) {
		dgst[i] = i; // try different dgst, check base_w and checksum
	}
	hex_to_bytes("1a50a39a53e6ef2480db612cef9456d0f33222f934c58bcba9d04fa91108faf6", 64, test_sig[0], &len);
	hex_to_bytes("e45dad76c1b23975e898a365b8c73d13695a887ba2ba2377f840d3a3b7bf806c", 64, test_sig[1], &len);
	hex_to_bytes("75d2cfddd6ca9773fb9d0d17efe5c731c1a44f4b31352e26767623abf52911f9", 64, test_sig[15], &len);
	hex_to_bytes("aaad735aa51662b8a48258561fb857b3f2b12a5802593522145b3b68355abf3b", 64, test_sig[66], &len);

	sm3_wots_derive_sk(wots_secret, seed, adrs, wots_sk);
	hash256_prf_init(&prf_seed_ctx, seed);
	sm3_wots_derive_pk(wots_sk, &prf_seed_ctx, adrs, wots_pk);
	sm3_wots_do_sign(wots_sk, &prf_seed_ctx, adrs, dgst, wots_sig);

	if (memcmp(wots_sig[0], test_sig[0], 32)
		|| memcmp(wots_sig[1], test_sig[1], 32)
		|| memcmp(wots_sig[15], test_sig[15], 32)
		|| memcmp(wots_sig[66], test_sig[66], 32)) {
		error_print();
		return -1;
	}

	sm3_wots_sig_to_pk(wots_sig, dgst, &prf_seed_ctx, adrs, sig_pk);
	if (memcmp(sig_pk ,wots_pk, 32 * 67)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm3_xmss_derive_root(void)
{
	uint8_t xmss_secret[32];
	uint8_t seed[32];
	int height = 10;
	hash256_bytes_t *tree = malloc(32 * (1<<height) * 2);
	uint8_t xmss_root[32];
	uint8_t test_root[32];
	size_t len;

	memset(xmss_secret, 0x12, 32);
	memset(seed, 0xab, 32);
	hex_to_bytes("f0415ed807c8f8c2ee8ca3a00178bff37e1ccb2836e02607d06131c9341e52ca", 64, test_root, &len);

	sm3_xmss_derive_root(xmss_secret, height, seed, tree, xmss_root);

	if (memcmp(xmss_root, test_root, 32)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm3_xmss_do_sign(void)
{
	uint8_t xmss_secret[32];
	uint8_t xmss_root[32];
	int h = 4;
	uint8_t dgst[32];
	uint8_t seed[32];
	uint8_t adrs[32] = {0};
	hash256_bytes_t wots_sig[67];
	hash256_bytes_t *auth_path = malloc(32 * h);
	hash256_bytes_t *tree = malloc(32 * (1<<h) * 2);
	uint32_t index = 0;
	uint8_t i;

	memset(xmss_secret, 0x12, 32);
	memset(seed, 0xab, 32);
	for (i = 0; i < 32; i++) {
		dgst[i] = i;
	}

	sm3_xmss_derive_root(xmss_secret, h, seed, tree, xmss_root);

	for (index = 0; index < (1<<h); index++) {
		uint8_t root_from_sig[32];
		sm3_xmss_do_sign(xmss_secret, index, seed, adrs, h, tree, dgst, wots_sig, auth_path);
		sm3_xmss_sig_to_root(wots_sig, index, auth_path, seed, adrs, h, dgst, root_from_sig);
		if (memcmp(xmss_root, root_from_sig, 32) != 0) {
			printf("xmss_sig_to_root failed\n");
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm3_xmss_sign(void)
{
#if defined(ENABLE_SHA2) && defined(ENABLE_SM3_XMSS_CROSSCHECK)
	uint32_t oid = XMSS_SHA256_10;
#else
	uint32_t oid = XMSS_SM3_10;
#endif
	SM3_XMSS_KEY key;
	SM3_XMSS_SIGN_CTX sign_ctx;
	uint8_t sig[sizeof(SM3_XMSS_SIGNATURE)];
	size_t siglen;
	uint8_t msg[100] = {0};
	int i;

	sm3_xmss_key_generate(&key, oid);
	sm3_xmss_key_print(stderr, 0, 0, "XMSS Key", &key);

	for (i = 0; i < 3; i++) {
		sm3_xmss_sign_init(&sign_ctx, &key);
		sm3_xmss_sign_update(&sign_ctx, msg, sizeof(msg));
		sm3_xmss_sign_finish(&sign_ctx, &key, sig, &siglen);

		(key.index)++;

		sm3_xmss_signature_print(stderr, 0, 0, "XMSS Signature", sig, siglen);

		sm3_xmss_verify_init(&sign_ctx, &key, sig, siglen);
		sm3_xmss_verify_update(&sign_ctx, msg, sizeof(msg));
		if (sm3_xmss_verify_finish(&sign_ctx, &key, sig, siglen) != 1) {
			error_print();
			return -1;
		}
	}
	sm3_xmss_key_cleanup(&key);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm3_wots_derive_sk() != 1) goto err;
	if (test_sm3_wots_derive_pk() != 1) goto err;
	if (test_sm3_wots_do_sign() != 1) goto err;
	if (test_sm3_xmss_derive_root() != 1) goto err;
	if (test_sm3_xmss_do_sign() != 1) goto err;
	if (test_sm3_xmss_sign() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
