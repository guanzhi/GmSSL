/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <gmssl/xmss.h>



static int test_xmss_adrs(void)
{
	xmss_adrs_t adrs;


	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 1);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, 0);
	adrs_set_chain_address(adrs, 1);
	adrs_set_hash_address(adrs, 12);
	adrs_set_key_and_mask(adrs, 0);

	xmss_adrs_print(stderr, 0, 4, "ADRS", adrs);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


#if defined(ENABLE_XMSS_CROSSCHECK) && defined(ENABLE_SHA2)
static int test_wots_derive_sk(void)
{
	hash256_t secret = {0};
	hash256_t seed = {0};
	xmss_adrs_t adrs = {0};
	wots_key_t wots_sk;
	wots_key_t test_sk;
	size_t len;

	// sha256 test 1
	memset(secret, 0, sizeof(secret));
	memset(seed, 0, sizeof(seed));
	memset(adrs, 0, sizeof(adrs));
	hex_to_bytes("0cb52ea67abd5da0328099db02de310e4ab01ac39d0bbeb71e97eb7e83c467b5", 64, test_sk[0], &len);
	hex_to_bytes("382c16f94b77905d4a6f78e1f38faf5ef914ac42324e356aeede056d356a5eeb", 64, test_sk[1], &len);
	hex_to_bytes("ab08e768529903e533c9bf8b3ea8c69d36aedcee5ac78801f92d23ef758cfe03", 64, test_sk[66], &len);

	wots_derive_sk(secret, seed, adrs, wots_sk);

	if (memcmp(wots_sk[0], test_sk[0], 32)
		|| memcmp(wots_sk[1], test_sk[1], 32)
		|| memcmp(wots_sk[66], test_sk[66], 32)) {
		error_print();
		return -1;
	}

	// sha256 test 2
	memset(secret, 0x12, sizeof(secret));
	memset(seed, 0xab, sizeof(seed));
	memset(adrs, 0, sizeof(adrs));
	hex_to_bytes("1a50a39a53e6ef2480db612cef9456d0f33222f934c58bcba9d04fa91108faf6", 64, test_sk[0], &len);
	hex_to_bytes("e45dad76c1b23975e898a365b8c73d13695a887ba2ba2377f840d3a3b7bf806c", 64, test_sk[1], &len);
	hex_to_bytes("aaad735aa51662b8a48258561fb857b3f2b12a5802593522145b3b68355abf3b", 64, test_sk[66], &len);

	wots_derive_sk(secret, seed, adrs, wots_sk);

	if (memcmp(wots_sk[0], test_sk[0], 32)
		|| memcmp(wots_sk[1], test_sk[1], 32)
		|| memcmp(wots_sk[66], test_sk[66], 32)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_wots_sk_to_pk(void)
{
	hash256_t secret = {0};
	hash256_t seed = {0};
	xmss_adrs_t adrs = {0};
	wots_key_t wots_sk;
	wots_key_t wots_pk;
	wots_key_t test_pk;
	size_t len;

	// sha256 test 2
	memset(secret, 0x12, sizeof(secret));
	memset(seed, 0xab, sizeof(seed));
	memset(adrs, 0, sizeof(adrs));
	hex_to_bytes("0c74a626695831994961641c487b70da83cd2aba2ba5c63c38ce72479b8a0ab9", 64, test_pk[0], &len);
	hex_to_bytes("acf6be724d4b074d67330559ec24b3d42c9b9d87fa103e7f6be402ec3a2d41c1", 64, test_pk[1], &len);
	hex_to_bytes("98691d83a657840d4b6f410e25fcd9a6480670ac9c090d3b79bc904ba7e131aa", 64, test_pk[66], &len);

	wots_derive_sk(secret, seed, adrs, wots_sk);

	wots_sk_to_pk(wots_sk, seed, adrs, wots_pk);

	if (memcmp(wots_pk[0], test_pk[0], 32)
		|| memcmp(wots_pk[1], test_pk[1], 32)
		|| memcmp(wots_pk[66], test_pk[66], 32)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_wots_sign(void)
{
	hash256_t secret = {0};
	hash256_t seed = {0};
	xmss_adrs_t adrs = {0};
	hash256_t dgst = {0};
	wots_key_t wots_sk;
	wots_key_t wots_pk;
	wots_sig_t wots_sig;
	wots_sig_t test_sig;
	wots_key_t sig_pk;
	size_t len;
	int i;

	memset(secret, 0x12, sizeof(secret));
	memset(seed, 0xab, sizeof(seed));
	memset(adrs, 0, sizeof(adrs));
	for (i = 0; i < 32; i++) {
		dgst[i] = i; // try different dgst, check base_w and checksum
	}
	hex_to_bytes("1a50a39a53e6ef2480db612cef9456d0f33222f934c58bcba9d04fa91108faf6", 64, test_sig[0], &len);
	hex_to_bytes("e45dad76c1b23975e898a365b8c73d13695a887ba2ba2377f840d3a3b7bf806c", 64, test_sig[1], &len);
	hex_to_bytes("75d2cfddd6ca9773fb9d0d17efe5c731c1a44f4b31352e26767623abf52911f9", 64, test_sig[15], &len);
	hex_to_bytes("aaad735aa51662b8a48258561fb857b3f2b12a5802593522145b3b68355abf3b", 64, test_sig[66], &len);

	wots_derive_sk(secret, seed, adrs, wots_sk);

	wots_sk_to_pk(wots_sk, seed, adrs, wots_pk);

	wots_sign(wots_sk, seed, adrs, dgst, wots_sig);

	if (memcmp(wots_sig[0], test_sig[0], sizeof(hash256_t))
		|| memcmp(wots_sig[1], test_sig[1], sizeof(hash256_t))
		|| memcmp(wots_sig[15], test_sig[15], sizeof(hash256_t))
		|| memcmp(wots_sig[66], test_sig[66], sizeof(hash256_t))) {
		error_print();
		return -1;
	}

	wots_sig_to_pk(wots_sig, seed, adrs, dgst, sig_pk);

	if (memcmp(sig_pk ,wots_pk, sizeof(wots_key_t))) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_wots_derive_root(void)
{
	hash256_t secret;
	hash256_t seed;
	xmss_adrs_t adrs;
	hash256_t root;
	hash256_t wots_0_root;
	hash256_t wots_1023_root;
	size_t len;

	memset(secret, 0x12, sizeof(hash256_t));
	memset(seed, 0xab, sizeof(hash256_t));
	hex_to_bytes("7A968C5F9AE4D2B781872B4E6EE851D55CC02F0AB9196701580D6F503D35DB68", 64, wots_0_root, &len);
	hex_to_bytes("939E10CD44769D4D9853F7CF5612D6D83B3AA140A8867CCF34A1DBCC66FC4333", 64, wots_1023_root, &len);

	// wots index is 0
	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	adrs_set_ots_address(adrs, 0);

	wots_derive_root(secret, seed, adrs, root);

	if (memcmp(root, wots_0_root, sizeof(hash256_t)) != 0) {
		error_print();
		return -1;
	}

	// wots index is 1023
	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	adrs_set_ots_address(adrs, 1023);

	wots_derive_root(secret, seed, adrs, root);

	if (memcmp(root, wots_1023_root, sizeof(hash256_t)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_wots_verify(void)
{
	uint32_t index = 0;
	hash256_t secret;
	hash256_t seed;
	xmss_adrs_t adrs;
	wots_key_t sk;
	hash256_t dgst;
	wots_sig_t sig;
	hash256_t root;


	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, index);

	wots_derive_sk(secret, seed, adrs, sk);
	wots_sign(sk, seed, adrs, dgst, sig);
	wots_derive_root(secret, seed, adrs, root);

	if (wots_verify(root, seed, adrs, dgst, sig) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif



static int test_xmss_build_tree(void)
{
	hash256_t xmss_secret;
	hash256_t seed;
	xmss_adrs_t adrs;
	int height = 10;
	hash256_t *tree = malloc(32 * (1<<height) * 2);
	hash256_t xmss_root;
	hash256_t test_root;
	size_t len;

	memset(xmss_secret, 0x12, sizeof(hash256_t));
	memset(seed, 0xab, sizeof(hash256_t));
	hex_to_bytes("f0415ed807c8f8c2ee8ca3a00178bff37e1ccb2836e02607d06131c9341e52ca", 64, test_root, &len);

	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	xmss_build_tree(xmss_secret, seed, adrs, height, tree);

	memcpy(xmss_root, tree[(1 << (height + 1)) - 2], sizeof(hash256_t));
	/*
	if (memcmp(xmss_root, test_root, sizeof(hash256_t))) {
		error_print();
		return -1;
	}
	*/

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmss_build_root(void)
{
	hash256_t secret;
	hash256_t seed;
	xmss_adrs_t adrs;
	size_t height = 4;
	hash256_t tree[(1 << (4+1)) - 1];
	hash256_t auth_path[4];
	hash256_t root;
	uint32_t index;

	rand_bytes(secret, sizeof(secret));
	rand_bytes(seed, sizeof(seed));
	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	xmss_build_tree(secret, seed, adrs, height, tree);

	for (index = 0; index < (1 << height); index++) {
		xmss_build_auth_path(tree, height, index, auth_path);
		xmss_build_root(tree[index], index, seed, adrs, auth_path, height, root);
		if (memcmp(root, tree[sizeof(tree)/sizeof(tree[0]) - 1], sizeof(hash256_t)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmss_private_key_size(void)
{
	struct {
		uint32_t xmss_type;
		size_t keylen;
	} tests[] = {
		{ XMSS_HASH256_10_256, 65640 },
		{ XMSS_HASH256_16_256, 4194408 },
		{ XMSS_HASH256_20_256, 67108968 },
	};
	size_t keylen;
	size_t i;

	format_print(stderr, 0, 4, "xmss_private_key_size\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (xmss_private_key_size(tests[i].xmss_type, &keylen) != 1) {
			error_print();
			return -1;
		}
		if (keylen != tests[i].keylen) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 8, "%s: %zu\n", xmss_type_name(tests[i].xmss_type), keylen);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmss_key_generate(void)
{
	uint32_t xmss_type = XMSS_HASH256_10_256;
	XMSS_KEY key;
	size_t count;
	size_t i;

	if (xmss_key_generate(&key, xmss_type) != 1) {
		error_print();
		return -1;
	}
	xmss_public_key_print(stderr, 0, 4, "xmss_public_key", &key);
	xmss_private_key_print(stderr, 0, 4, "xmss_private_key", &key);

	if (xmss_key_remaining_signs(&key, &count) != 1) {
		error_print();
		return -1;
	}
	if (count != 1024) {
		error_print();
		return -1;
	}
	key.index += 4;
	if (xmss_key_remaining_signs(&key, &count) != 1) {
		error_print();
		return -1;
	}
	if (count != 1020) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmss_public_key_to_bytes(void)
{
	uint32_t xmss_type = XMSS_HASH256_10_256;
	XMSS_KEY key;
	XMSS_KEY pub;
	uint8_t buf[XMSS_PUBLIC_KEY_SIZE];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (xmss_key_generate(&key, xmss_type) != 1) {
		error_print();
		return -1;
	}

	if (xmss_public_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != XMSS_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}
	if (xmss_public_key_from_bytes(&pub, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(&key, &pub, sizeof(XMSS_PUBLIC_KEY)) != 0) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// XMSS_SM3_10_256	2500 bytes
// XMSS_SM3_16_256	2692 bytes
// XMSS_SM3_20_256	2820 bytes

struct {
	uint32_t xmss_type;
	size_t siglen;
} xmss_siglens[] = {
	{ XMSS_HASH256_10_256, 2500 },
	{ XMSS_HASH256_16_256, 2692 },
	{ XMSS_HASH256_20_256, 2820 },
};

static int test_xmss_signature_size(void)
{
	size_t siglen;
	size_t i;

	for (i = 0; i < sizeof(xmss_siglens)/sizeof(xmss_siglens[0]); i++) {
		if (xmss_signature_size(xmss_siglens[i].xmss_type, &siglen) != 1) {
			error_print();
			return -1;
		}
		if (siglen != xmss_siglens[i].siglen) {
			error_print();
			return -1;
		}
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmss_sign(void)
{
	static const uint8_t hash256_two[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	};
	uint8_t msg[100] = {0};
	uint32_t xmss_type = XMSS_HASH256_10_256;
	size_t height = 10;
	uint32_t index = 1011;
	hash256_t hash256_index = {0};
	XMSS_KEY key;
	XMSS_SIGNATURE sig;
	xmss_adrs_t adrs;
	hash256_t root;
	HASH256_CTX ctx;
	hash256_t dgst;
	size_t h;


	if (xmss_key_generate(&key, xmss_type) != 1) {
		error_print();
		return -1;
	}

	// xmss_sig.index
	// xmss_sig.random
	// xmss_sig.wots_sig
	// xmss_sig.auth_path

	sig.index = index;

	memset(sig.random, 0, 32);

	// wots_sk => sig.wots_sig
	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, index);
	wots_derive_sk(key.secret, key.public_key.seed, adrs, sig.wots_sig);

	// check wots_root
	wots_derive_root(key.secret, key.public_key.seed, adrs, root);
	if (memcmp(root, key.tree[index], sizeof(hash256_t)) != 0) {
		xmss_key_cleanup(&key);
		error_print();
		return -1;
	}

	xmss_build_auth_path(key.tree, height, index, sig.auth_path);



	PUTU32(hash256_index + 28, index);
	hash256_init(&ctx);
	hash256_update(&ctx, hash256_two, sizeof(hash256_t));
	hash256_update(&ctx, sig.random, sizeof(hash256_t));
	hash256_update(&ctx, key.public_key.root, sizeof(hash256_t));
	hash256_update(&ctx, hash256_index, sizeof(hash256_t));
	hash256_update(&ctx, msg, sizeof(msg));
	hash256_finish(&ctx, dgst);

	wots_sign(sig.wots_sig, key.public_key.seed, adrs, dgst, sig.wots_sig);

	// verify

	// wots_sig => wots_root
	wots_sig_to_pk(sig.wots_sig, key.public_key.seed, adrs, dgst, sig.wots_sig);

	adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
	adrs_set_ltree_address(adrs, index);
	wots_pk_to_root(sig.wots_sig, key.public_key.seed, adrs, root);



	// wots_root, index, auth_path => xmss_root
	/*
	adrs_set_type(adrs, XMSS_ADRS_TYPE_HASHTREE);
	adrs_set_padding(adrs, 0);
	adrs_set_key_and_mask(adrs, 0);
	for (h = 0; h < height; h++) {
		int right = index & 1;
		index >>= 1;
		adrs_set_tree_height(adrs, h + 1);
		adrs_set_tree_index(adrs, index);
		if (right)
			randomized_tree_hash(sig.auth_path[h], root, key.public_key.seed, adrs, root);
		else	randomized_tree_hash(root, sig.auth_path[h], key.public_key.seed, adrs, root);
	}
	*/

	xmss_build_root(root, index, key.public_key.seed, adrs, sig.auth_path, height, root);

	if (memcmp(root, key.public_key.root, sizeof(hash256_t)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_xmss_sign_init(void)
{
	uint32_t xmss_type = XMSS_HASH256_10_256;
	XMSS_KEY key;
	XMSS_SIGN_CTX sign_ctx;
	uint8_t sig[XMSS_SIGNATURE_MAX_SIZE];
	size_t siglen;
	uint8_t msg[100] = {0};
	int i;

	if (xmss_key_generate(&key, xmss_type) != 1) {
		error_print();
		return -1;
	}

	if (xmss_sign_init(&sign_ctx, &key) != 1) {
		error_print();
		return -1;
	}
	if (xmss_sign_update(&sign_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (xmss_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	if (xmss_verify_init(&sign_ctx, &key, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (xmss_verify_update(&sign_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (xmss_verify_finish(&sign_ctx) != 1) {
		error_print();
		return -1;
	}
	xmss_key_cleanup(&key);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



struct {
	uint32_t xmssmt_type;
	size_t indexlen;
	size_t siglen;
} xmssmt_consts[] = {
	{ XMSSMT_HASH256_20_2_256, 3, 4963 },
	{ XMSSMT_HASH256_20_4_256, 3, 9251 },
	{ XMSSMT_HASH256_40_2_256, 5, 5605 },
	{ XMSSMT_HASH256_40_4_256, 5, 9893 },
	{ XMSSMT_HASH256_40_8_256, 5, 18469 },
	{ XMSSMT_HASH256_60_3_256, 8, 8392 },
	{ XMSSMT_HASH256_60_6_256, 8, 14824 },
	{ XMSSMT_HASH256_60_12_256, 8, 27688 },
};

static int test_xmssmt_index_to_bytes(void)
{
	uint64_t index = 0;
	size_t indexlen;
	size_t i;

	for (i = 0; i < sizeof(xmssmt_consts)/sizeof(xmssmt_consts[0]); i++) {
		indexlen = 0;
		if (xmssmt_index_to_bytes(index, xmssmt_consts[i].xmssmt_type, NULL, &indexlen) != 1) {
			error_print();
			return -1;
		}
		if (indexlen != xmssmt_consts[i].indexlen) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmssmt_key_generate(void)
{
	uint32_t xmssmt_index = XMSSMT_HASH256_20_4_256;
	XMSSMT_KEY key;

	if (xmssmt_key_generate(&key, xmssmt_index) != 1) {
		error_print();
		return -1;
	}

	xmssmt_public_key_print(stderr, 0, 4, "xmssmt_public_key", &key);
	xmssmt_private_key_print(stderr, 0, 4, "xmssmt_private_key", &key);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_xmssmt_signature_size(void)
{
	size_t siglen;
	size_t i;

	for (i = 0; i < sizeof(xmssmt_consts)/sizeof(xmssmt_consts[0]); i++) {
		if (xmssmt_signature_size(xmssmt_consts[i].xmssmt_type, &siglen) != 1) {
			error_print();
			return -1;
		}
		if (siglen != xmssmt_consts[i].siglen) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmssmt_signature_print(void)
{
	XMSSMT_SIGNATURE xmssmt_sig;
	size_t layer, i;

	// set xmssmt_sig
	memset(&xmssmt_sig, 0, sizeof(xmssmt_sig));
	xmssmt_sig.index = 1;
	rand_bytes(xmssmt_sig.random, 32);

	for (layer = 0; layer < XMSSMT_MAX_LAYERS; layer++) {
		for (i = 0; i < 67; i++) {
			xmssmt_sig.wots_sigs[layer][i][0] = 0x0a;
			xmssmt_sig.wots_sigs[layer][i][1] = 0xff & layer;
			xmssmt_sig.wots_sigs[layer][i][2] = 0xff & i;
		}
	}
	for (i = 0; i < XMSSMT_MAX_HEIGHT; i++) {
		xmssmt_sig.auth_path[i][0] = 0x0b;
		xmssmt_sig.auth_path[i][1] = 0xff & i;
	}

	// print
	for (i = 0; i < sizeof(xmssmt_consts)/sizeof(xmssmt_consts[0]); i++) {
		xmssmt_signature_print_ex(stderr, 0, 4, "xmssmt_signature", &xmssmt_sig, xmssmt_consts[i].xmssmt_type);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmssmt_signature_to_bytes(void)
{
	uint32_t xmssmt_type = XMSSMT_HASH256_20_2_256;
	XMSSMT_SIGNATURE xmssmt_sig;
	uint8_t buf[XMSSMT_SIGNATURE_MAX_SIZE];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	memset(&xmssmt_sig, 0, sizeof(xmssmt_sig));

	if (xmssmt_signature_to_bytes(&xmssmt_sig, xmssmt_type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	xmssmt_signature_print(stderr, 0, 4, "xmssmt_signature", buf, len, xmssmt_type);

	if (xmssmt_signature_from_bytes(&xmssmt_sig, xmssmt_type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		fprintf(stderr, "xmssmt_signature_len: %zu\n", len);
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

/*
XMSSMT_SHA2_20_2_256: 133287		133KB
XMSSMT_SHA2_20_4_256: 14631		 14KB
XMSSMT_SHA2_40_2_256: 134219945		134MB
XMSSMT_SHA2_40_4_256: 268585		268KB
XMSSMT_SHA2_40_8_256: 31273		 31KB
XMSSMT_SHA2_60_3_256: 201330924		201MB
XMSSMT_SHA2_60_6_256: 403884		403KB
XMSSMT_SHA2_60_12_256: 47916		 47KB
*/
static int test_xmssmt_private_key_size(void)
{
	uint32_t xmssmt_types[] = {
		XMSSMT_HASH256_20_2_256,
		XMSSMT_HASH256_20_4_256,
		XMSSMT_HASH256_40_2_256,
		XMSSMT_HASH256_40_4_256,
		XMSSMT_HASH256_40_8_256,
		XMSSMT_HASH256_60_3_256,
		XMSSMT_HASH256_60_6_256,
		XMSSMT_HASH256_60_12_256,
	};
	size_t len;
	size_t i;

	fprintf(stderr, "xmssmt_private_key_size()\n");
	for (i = 0; i < sizeof(xmssmt_types)/sizeof(xmssmt_types[0]); i++) {
		if (xmssmt_private_key_size(xmssmt_types[i], &len) != 1) {
			error_print();
			return -1;
		}
		fprintf(stderr, "    %s: %zu\n", xmssmt_type_name(xmssmt_types[i]), len);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmssmt_public_key_to_bytes(void)
{
	uint32_t xmssmt_types[] = {
		XMSSMT_HASH256_20_2_256,
		XMSSMT_HASH256_20_4_256,
		XMSSMT_HASH256_40_2_256,
		XMSSMT_HASH256_40_4_256,
		XMSSMT_HASH256_40_8_256,
		XMSSMT_HASH256_60_3_256,
		XMSSMT_HASH256_60_6_256,
		XMSSMT_HASH256_60_12_256,
	};
	XMSSMT_KEY key;
	uint8_t buf[XMSSMT_PUBLIC_KEY_SIZE];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;




	memset(&key, 0, sizeof(key));

	key.public_key.xmssmt_type = XMSSMT_HASH256_20_2_256;




	if (xmssmt_public_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != XMSSMT_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}
	if (xmssmt_public_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmssmt_private_key_to_bytes(void)
{
	uint32_t xmssmt_type = XMSSMT_HASH256_20_4_256;
	XMSSMT_KEY key;
	size_t buflen;
	uint8_t *buf = NULL;
	uint8_t *p;
	const uint8_t *cp;
	size_t len = 0;

	memset(&key, 0, sizeof(key));

	if (xmssmt_private_key_size(xmssmt_type, &buflen) != 1) {
		error_print();
		return -1;
	}
	if (!(buf = malloc(buflen))) {
		error_print();
		return -1;
	}
	cp = p = buf;

	if (xmssmt_key_generate(&key, xmssmt_type) != 1) {
		error_print();
		return -1;
	}

	if (xmssmt_private_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != buflen) {
		error_print();
		return -1;
	}
	if (xmssmt_private_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		fprintf(stderr, "len = %zu\n", len);
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmssmt_index(void)
{

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// copy from xmss.c
static uint64_t xmssmt_tree_address(uint64_t index, size_t height, size_t layers, size_t layer) {
	return (index >> (height/layers) * (layer + 1));
}

// copy from xmss.c
static uint64_t xmssmt_tree_index(uint64_t index, size_t height, size_t layers, size_t layer) {
	return (index >> (height/layers) * layer) % (1 << (height/layers));
}

// reference implementation of xmss^mt sign/verify
static int test_xmssmt_sign(void)
{
	static const uint8_t hash256_two[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	};
	static const uint8_t hash256_three[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	};

	uint32_t xmssmt_type = XMSSMT_HASH256_20_4_256;
	size_t height = 0;
	size_t layers = 0;

	uint8_t msg[100] = {0};
	XMSSMT_SIGNATURE xmssmt_sig;
	XMSSMT_SIGNATURE *sig = &xmssmt_sig;
	XMSSMT_KEY xmssmt_key;
	XMSSMT_KEY *key = &xmssmt_key;
	XMSSMT_SIGN_CTX xmssmt_ctx;
	XMSSMT_SIGN_CTX *ctx = &xmssmt_ctx;
	hash256_t dgst;

	hash256_t hash256_index;
	xmss_adrs_t adrs;

	uint64_t tree_address;
	uint32_t tree_index;
	uint32_t layer;


	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}


	// generate key
	if (xmssmt_key_generate(key, xmssmt_type) != 1) {
		error_print();
		return -1;
	}
	xmssmt_private_key_print(stderr, 0, 4, "xmssmt_private_key", key);


	// init sign ctx
	memset(ctx, 0, sizeof(XMSSMT_SIGN_CTX));

	// set ctx->xmssmt_public_key
	ctx->xmssmt_public_key = key->public_key;

	// set ctx->xmssmt_sig

	// XMSSMT_SIGNATURE:
	//	uint64_t	index
	//	hash256_t	random
	//	wots_sig_t	wots_sigs[layers];
	//	hash256_t	auth_path[height/layers]

	// copy index
	ctx->xmssmt_sig.index = key->index;

	// copy wots_sigs[1] to wots_sig[layers - 1] from key
	for (layer = 1; layer < layers; layer++) {
		memcpy(ctx->xmssmt_sig.wots_sigs[layer], key->wots_sigs[layer - 1], sizeof(wots_sig_t));
	}

	// build auth_path
	for (layer = 0; layer < layers; layer++) {
		uint32_t tree_index = xmssmt_tree_index(ctx->xmssmt_sig.index, height, layers, layer);
		hash256_t *tree = key->trees + xmss_num_tree_nodes(height/layers) * layer;
		hash256_t *auth_path = ctx->xmssmt_sig.auth_path + (height/layers) * layer;
		xmss_build_auth_path(tree, height/layers, tree_index, auth_path);
	}

	// derive ctx->xmssmt_sig.random
	memset(hash256_index, 0, 24);
	PUTU64(hash256_index + 24, ctx->xmssmt_sig.index);
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_three, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, key->sk_prf, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, hash256_index, sizeof(hash256_t));
	hash256_finish(&ctx->hash256_ctx, ctx->xmssmt_sig.random);

	// derive wots_sk and save to wots_sigs[0]
	layer = 0;
	tree_address = xmssmt_tree_address(ctx->xmssmt_sig.index, height, layers, layer);
	tree_index = xmssmt_tree_index(ctx->xmssmt_sig.index, height, layers, layer);
	adrs_set_layer_address(adrs, layer);
	adrs_set_tree_address(adrs, tree_address);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, tree_index);
	wots_derive_sk(key->secret, key->public_key.seed, adrs, ctx->xmssmt_sig.wots_sigs[0]);

	// H_msg(M) := HASH256(toByte(2, 32) || r || XMSS_ROOT || toByte(idx_sig, 32) || M)
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_two, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, ctx->xmssmt_sig.random, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, key->public_key.root, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, hash256_index, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, msg, sizeof(msg));
	hash256_finish(&ctx->hash256_ctx, dgst);

	// generate message wots_sig as wots_sigs[0]
	layer = 0;
	tree_address = xmssmt_tree_address(ctx->xmssmt_sig.index, height, layers, layer);
	tree_index = xmssmt_tree_index(ctx->xmssmt_sig.index, height, layers, layer);
	adrs_set_layer_address(adrs, layer);
	adrs_set_tree_address(adrs, tree_address);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, tree_index);
	wots_sign(ctx->xmssmt_sig.wots_sigs[0], ctx->xmssmt_public_key.seed, adrs, dgst,
		ctx->xmssmt_sig.wots_sigs[0]);

	xmssmt_signature_print_ex(stderr, 0, 4, "xmssmt_signature", &ctx->xmssmt_sig, xmssmt_type);


	// verify
	for (layer = 0; layer < layers; layer++) {
		uint64_t tree_address = xmssmt_tree_address(ctx->xmssmt_sig.index, height, layers, layer);
		uint32_t tree_index = xmssmt_tree_index(ctx->xmssmt_sig.index, height, layers, layer);
		wots_key_t wots_pk;

		// wots_sig, dgst => wots_pk
		adrs_set_layer_address(adrs, layer);
		adrs_set_tree_address(adrs, tree_address);
		adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
		adrs_set_ots_address(adrs, tree_index);
		wots_sig_to_pk(ctx->xmssmt_sig.wots_sigs[layer], ctx->xmssmt_public_key.seed, adrs, dgst, wots_pk);

		// wots_pk => wots_root
		adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
		adrs_set_ltree_address(adrs, tree_index);
		wots_pk_to_root(wots_pk, ctx->xmssmt_public_key.seed, adrs, dgst);

		// wots_root, auth_path => xmss_root (as dgst)
		adrs_set_type(adrs, XMSS_ADRS_TYPE_HASHTREE);
		adrs_set_padding(adrs, 0);
		xmss_build_root(dgst, tree_index,
			ctx->xmssmt_public_key.seed, adrs,
			ctx->xmssmt_sig.auth_path + (height/layers) * layer, height/layers,
			dgst);
	}

	// verify xmssmt_root (save in dgst)
	if (memcmp(dgst, ctx->xmssmt_public_key.root, sizeof(hash256_t)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_xmssmt_sign_update(void)
{
	uint32_t xmssmt_type = XMSSMT_HASH256_20_4_256;
	XMSSMT_KEY key;
	XMSSMT_SIGN_CTX ctx;
	XMSSMT_SIGNATURE sig;
	uint8_t msg[100] = {0};


	if (xmssmt_key_generate(&key, xmssmt_type) != 1) {
		error_print();
		return -1;
	}


	if (xmssmt_sign_init(&ctx, &key) != 1) {
		error_print();
		return -1;
	}
	if (xmssmt_sign_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (xmssmt_sign_finish_ex(&ctx, &sig) != 1) {
		error_print();
		return -1;
	}

	memset(&ctx, 0, sizeof(ctx));
	if (xmssmt_verify_init_ex(&ctx, &key, &sig) != 1) {
		error_print();
		return -1;
	}
	if (xmssmt_verify_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (xmssmt_verify_finish(&ctx) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
	if (test_wots_derive_sk() != 1) goto err;
	if (test_wots_sk_to_pk() != 1) goto err;
	if (test_wots_sign() != 1) goto err;
	if (test_wots_derive_root() != 1) goto err;
	if (test_wots_verify() != 1) goto err;
#endif
	if (test_xmss_adrs() != 1) goto err;
	if (test_xmss_build_tree() != 1) goto err;
	if (test_xmss_build_root() != 1) goto err;
	if (test_xmss_key_generate() != 1) goto err;
	if (test_xmss_public_key_to_bytes() != 1) goto err;
	if (test_xmss_private_key_size() != 1) goto err;
	//if (test_xmss_private_key_to_bytes() != 1) goto err;
	if (test_xmss_signature_size() != 1) goto err;
	if (test_xmss_sign() != 1) goto err;
	if (test_xmss_sign_init() != 1) goto err;
	if (test_xmssmt_key_generate() != 1) goto err;
	if (test_xmssmt_index_to_bytes() != 1) goto err;
	if (test_xmssmt_signature_to_bytes() != 1) goto err;
	if (test_xmssmt_signature_size() != 1) goto err;
	if (test_xmssmt_signature_print() != 1) goto err;
	if (test_xmssmt_private_key_size() != 1) goto err;
	if (test_xmssmt_public_key_to_bytes() != 1) goto err;
	if (test_xmssmt_private_key_to_bytes() != 1) goto err;
	if (test_xmssmt_sign() != 1) goto err;
	if (test_xmssmt_sign_update() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
