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
#include <gmssl/sphincs.h>


typedef struct {
	char *name;
	size_t secret_size;
	size_t hypertree_height;
	size_t hypertree_layers;
	size_t fors_tree_height;
	size_t fors_num_trees;
	int winternitz_w;
	int bitsec;
	int sec_level;
	size_t siglen;
} SPHINCS_PARAMS;

static const SPHINCS_PARAMS sphincs_params[] = {
	//                  n   h  d  lg(t) k   w         siglen
	{ "SPHINCS+_128s", 16, 63,  7, 12, 14, 16, 133, 1,  7856 },
	{ "SPHINCS+_128f", 16, 66, 22,  6, 33, 16, 128, 1, 17088 },
	{ "SPHINCS+_192s", 24, 64,  7, 14, 17, 16, 193, 3, 16244 },
	{ "SPHINCS+_192f", 24, 66, 22,  8, 33, 16, 194, 3, 35644 },
	{ "SPHINCS+_256s", 32, 64,  8, 14, 22, 16, 255, 5, 29792 },
	{ "SPHINCS+_256f", 32, 68, 17,  9, 35, 16, 255, 5, 49856 },
};

static int test_sphincs_print_params(void)
{
	size_t i;

	for (i = 0; i < sizeof(sphincs_params)/sizeof(sphincs_params[0]); i++) {
		format_print(stderr, 0, 4, "%s\n", sphincs_params[i].name);
		format_print(stderr, 0, 8, "secret_size: %zu\n", sphincs_params[i].secret_size);
		format_print(stderr, 0, 8, "hypertree_height: %zu\n", sphincs_params[i].hypertree_height);
		format_print(stderr, 0, 8, "fors_tree_height: %zu\n", sphincs_params[i].fors_tree_height);
		format_print(stderr, 0, 8, "fors_num_trees: %zu\n", sphincs_params[i].fors_num_trees);
		format_print(stderr, 0, 8, "winternitz_w: %d\n", sphincs_params[i].winternitz_w);
		format_print(stderr, 0, 8, "bitsec: %d\n", sphincs_params[i].bitsec);
		format_print(stderr, 0, 8, "sec_level: %d\n", sphincs_params[i].sec_level);
		format_print(stderr, 0, 8, "siglen: %zu\n", sphincs_params[i].siglen);
	}

	format_print(stderr, 0, 4, "const\n");
	format_print(stderr, 0, 8, "SPHINCS_WOTS_NUM_CHAINS: %d\n", SPHINCS_WOTS_NUM_CHAINS);
	format_print(stderr, 0, 8, "SPHINCS_HYPERTREE_HEIGHT: %d\n", SPHINCS_HYPERTREE_HEIGHT);
	format_print(stderr, 0, 8, "SPHINCS_HYPERTREE_LAYERS: %d\n", SPHINCS_HYPERTREE_LAYERS);
	format_print(stderr, 0, 8, "SPHINCS_FORS_TREE_HEIGHT: %d\n", SPHINCS_FORS_TREE_HEIGHT);
	format_print(stderr, 0, 8, "SPHINCS_FORS_NUM_TREES: %d\n", SPHINCS_FORS_NUM_TREES);
	format_print(stderr, 0, 8, "SPHINCS_XMSS_HEIGHT: %d\n", SPHINCS_XMSS_HEIGHT);
	format_print(stderr, 0, 8, "SPHINCS_XMSS_NUM_NODES: %d\n", SPHINCS_XMSS_NUM_NODES);
	format_print(stderr, 0, 8, "SPHINCS_FORS_TREE_NUM_NODES: %d\n", SPHINCS_FORS_TREE_NUM_NODES);
	format_print(stderr, 0, 8, "SPHINCS_TBS_FORS_SIZE: %d\n", SPHINCS_TBS_FORS_SIZE);
	format_print(stderr, 0, 8, "SPHINCS_TBS_TREE_ADDRESS_SIZE: %d\n", SPHINCS_TBS_TREE_ADDRESS_SIZE);
	format_print(stderr, 0, 8, "SPHINCS_TBS_KEYPAIR_ADDRESS_SIZE: %d\n", SPHINCS_TBS_KEYPAIR_ADDRESS_SIZE);
	format_print(stderr, 0, 8, "SPHINCS_TBS_SIZE: %d\n", SPHINCS_TBS_SIZE);
	format_print(stderr, 0, 8, "SPHINCS_FORS_SIGNATURE_SIZE: %d\n", SPHINCS_FORS_SIGNATURE_SIZE);
	format_print(stderr, 0, 8, "SPHINCS_PUBLIC_KEY_SIZE: %d\n", SPHINCS_PUBLIC_KEY_SIZE);
	format_print(stderr, 0, 8, "SPHINCS_PRIVATE_KEY_SIZE: %d\n", SPHINCS_PRIVATE_KEY_SIZE);
	format_print(stderr, 0, 8, "SPHINCS_SIGNATURE_SIZE: %d\n", SPHINCS_SIGNATURE_SIZE);


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_derive_sk(void)
{
	sphincs_hash128_t secret;
	sphincs_hash128_t seed;
	sphincs_adrs_t adrs = {0};
	sphincs_wots_key_t wots_sk;

	memset(secret, 0, sizeof(secret));
	memset(seed, 0, sizeof(seed));
	sphincs_adrs_set_layer_address(adrs, 0);
	sphincs_adrs_set_tree_address(adrs, 0);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_PRF);
	sphincs_adrs_set_keypair_address(adrs, 0);

	format_bytes(stderr, 0, 4, "secret", secret, sizeof(secret));
	format_bytes(stderr, 0, 4, "seed", seed, sizeof(seed));
	sphincs_adrs_print(stderr, 0, 4, "adrs", adrs);

	memset(wots_sk, 0, sizeof(wots_sk));
	sphincs_wots_derive_sk(secret, seed, adrs, wots_sk);
	sphincs_wots_key_print(stderr, 0, 4, "wots_sk", wots_sk);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_chain(void)
{
	sphincs_hash128_t seed = {0};
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t x = {0};
	sphincs_hash128_t y = {0};
	int start = 0;
	int steps = 15;

	format_bytes(stderr, 0, 4, "seed", seed, sizeof(seed));

	sphincs_wots_chain(x, seed, adrs, start, steps, y);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_sk_to_pk(void)
{
	sphincs_wots_key_t wots_sk;
	sphincs_hash128_t seed;
	sphincs_adrs_t adrs;
	sphincs_wots_key_t wots_pk;

	sphincs_wots_sk_to_pk(wots_sk, seed, adrs, wots_pk);

	sphincs_wots_key_print(stderr, 0, 4, "wots_pk", wots_pk);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_pk_to_root(void)
{
	sphincs_wots_key_t wots_pk;
	sphincs_hash128_t seed;
	sphincs_adrs_t adrs;
	sphincs_hash128_t wots_root;

	sphincs_wots_pk_to_root(wots_pk, seed, adrs, wots_root);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_sign(void)
{
	sphincs_wots_key_t wots_sk;
	sphincs_hash128_t seed;
	sphincs_adrs_t adrs;
	sphincs_hash128_t dgst;
	sphincs_wots_sig_t wots_sig;

	sphincs_wots_sign(wots_sk, seed, adrs, dgst, wots_sig);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_sig_to_pk(void)
{
	sphincs_wots_sig_t wots_sig;
	sphincs_hash128_t seed;
	sphincs_adrs_t adrs;
	sphincs_hash128_t dgst;
	sphincs_wots_key_t wots_pk;

	sphincs_wots_sig_to_pk(wots_sig, seed, adrs, dgst, wots_pk);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_sign_verify(void)
{
	sphincs_hash128_t secret = {0};
	sphincs_hash128_t seed = {0};
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t dgst = {0};

	sphincs_wots_key_t wots_sk;
	sphincs_wots_key_t wots_pk;
	sphincs_wots_sig_t wots_sig;
	sphincs_wots_key_t wots_pk2;
	sphincs_hash128_t wots_root;
	int i;

	sphincs_adrs_set_layer_address(adrs, 0);
	sphincs_adrs_set_tree_address(adrs, 0);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_PRF);
	sphincs_adrs_set_keypair_address(adrs, 0);

	sphincs_wots_derive_sk(secret, seed, adrs, wots_sk);

	format_print(stderr, 0, 4, "wots_sk\n");
	for (i = 0; i < 35; i++) {
		format_print(stderr, 0, 8, "%d", i);
		format_bytes(stderr, 0, 0, "", wots_sk[i], 16);
	}

	sphincs_wots_sk_to_pk(wots_sk, seed, adrs, wots_pk);

	format_print(stderr, 0, 4, "wots_pk\n");
	for (i = 0; i < 35; i++) {
		format_print(stderr, 0, 8, "%d", i);
		format_bytes(stderr, 0, 0, "", wots_pk[i], 16);
	}


	sphincs_wots_pk_to_root(wots_pk, seed, adrs, wots_root);
	format_bytes(stderr, 0, 4, "wots_root (from pk)", wots_root, 16);



	sphincs_wots_sign(wots_sk, seed, adrs, dgst, wots_sig);

	sphincs_wots_sig_to_pk(wots_sig, seed, adrs, dgst, wots_pk2);
	format_print(stderr, 0, 4, "wots_pk\n");
	for (i = 0; i < 35; i++) {
//		format_print(stderr, 0, 8, "%d", i);
//		format_bytes(stderr, 0, 0, "", wots_pk[i], 16);
	}

	sphincs_wots_pk_to_root(wots_pk2, seed, adrs, wots_root);
	format_bytes(stderr, 0, 4, "wots_root (from sig)", wots_root, 16);



	if (memcmp(wots_pk2, wots_pk, sizeof(sphincs_wots_key_t)) != 0) {
		error_print();
		return -1;
	}




	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_sphincs_xmss_build_tree(void)
{
	sphincs_hash128_t secret = {0};
	sphincs_hash128_t seed = {0};
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES] = {0};
	int i;

	sphincs_xmss_build_tree(secret, seed, adrs, tree);

	// for sphincs+_128s, height==9, num_nodes==1023
	format_print(stderr, 0, 4, "xmss_tree\n");
	for (i = 0; i < SPHINCS_XMSS_NUM_NODES; i++) {
		format_print(stderr, 0, 8, "%d", i);
		format_bytes(stderr, 0, 0, "", tree[i], sizeof(sphincs_hash128_t));
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_xmss_build_auth_path(void)
{
	sphincs_hash128_t secret = {0};
	sphincs_hash128_t seed = {0};
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES] = {0};
	uint32_t tree_index = 0;
	sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT];
	int i;

	sphincs_xmss_build_tree(secret, seed, adrs, tree);

	sphincs_xmss_build_auth_path(tree, tree_index, auth_path);

	format_print(stderr, 0, 4, "auth_path\n");
	for (i = 0; i < SPHINCS_XMSS_HEIGHT; i++) {
		format_print(stderr, 0, 8, "%d", i);
		format_bytes(stderr, 0, 0, "", auth_path[i], sizeof(sphincs_hash128_t));
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_xmss_build_root(void)
{
	sphincs_hash128_t secret = {0};
	sphincs_hash128_t seed = {0};
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES] = {0};
	uint32_t tree_index = 0;
	sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT];
	sphincs_hash128_t root;

	sphincs_xmss_build_tree(secret, seed, adrs, tree);

	sphincs_xmss_build_auth_path(tree, tree_index, auth_path);

	sphincs_xmss_build_root(tree[tree_index], tree_index, seed, adrs, auth_path, root);

	if (memcmp(root, tree[SPHINCS_XMSS_NUM_NODES - 1], sizeof(root)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_xmss_sign(void)
{
	sphincs_hash128_t secret = {0};
	sphincs_hash128_t seed = {0};
	sphincs_adrs_t adrs = {0};
	uint32_t keypair_address = 0;

	sphincs_hash128_t xmss_tree[SPHINCS_XMSS_NUM_NODES];
	sphincs_hash128_t dgst = {0};
	SPHINCS_XMSS_SIGNATURE sig;
	sphincs_hash128_t xmss_root;
	sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT];


	sphincs_xmss_build_tree(secret, seed, adrs, xmss_tree);

	sphincs_xmss_build_auth_path(xmss_tree, keypair_address, auth_path);

	sphincs_xmss_build_root(xmss_tree[keypair_address], keypair_address, seed, adrs, auth_path, xmss_root);


	format_bytes(stderr, 0, 4, "tree[0]", xmss_tree[0], 16);
	format_bytes(stderr, 0, 4, "tree_root", xmss_tree[SPHINCS_XMSS_NUM_NODES-1], 16);


	sphincs_xmss_sign(secret, seed, adrs, keypair_address, dgst, &sig);

	sphincs_xmss_sig_to_root(&sig, seed, adrs, keypair_address, dgst, xmss_root);

	if (memcmp(xmss_root, xmss_tree[SPHINCS_XMSS_NUM_NODES - 1], sizeof(sphincs_hash128_t)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_xmss_sig_to_root(void)
{
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_hypertree(void)
{
	sphincs_hash128_t secret = {0};
	sphincs_hash128_t seed = {0};
	uint64_t tree_address = 0;
	uint32_t keypair_address = 0;
	sphincs_hash128_t forest_root = {0};
	int i;

	sphincs_adrs_t adrs = {0};

	sphincs_hash128_t trees[SPHINCS_XMSS_NUM_NODES * SPHINCS_HYPERTREE_LAYERS];
	sphincs_hash128_t *tree = trees;



	for (i = 0; i < SPHINCS_HYPERTREE_LAYERS; i++) {
		sphincs_adrs_set_layer_address(adrs, i);
		sphincs_adrs_set_tree_address(adrs, 0);

		sphincs_xmss_build_tree(secret, seed, adrs, tree);

		char label[64];
		snprintf(label, sizeof(label), "leaf[%d]", i);

		format_bytes(stderr, 0, 4, label, tree[0], 16);

		snprintf(label, sizeof(label), "root[%d]", i);
		format_bytes(stderr, 0, 4, label, tree[1022], 16);


		tree += SPHINCS_XMSS_NUM_NODES;
	}

	SPHINCS_XMSS_SIGNATURE sig[SPHINCS_HYPERTREE_LAYERS];

	sphincs_adrs_set_layer_address(adrs, 0);
	sphincs_adrs_set_tree_address(adrs, keypair_address);
	sphincs_xmss_sign(secret, seed, adrs, keypair_address, forest_root, &sig[0]);

	sphincs_hash128_t xmss_root;
	sphincs_xmss_sig_to_root(&sig[0], seed, adrs, keypair_address, forest_root, xmss_root);

	format_bytes(stderr, 0, 4, "xmss_root[0]", xmss_root, 16);

	for (i = 1; i < SPHINCS_HYPERTREE_LAYERS; i++) {
		// layer +1 keypair_address is the lowest xmss_height bits of tree_address
		keypair_address = tree_address & ((1 << SPHINCS_XMSS_HEIGHT) - 1);
		tree_address >>= SPHINCS_XMSS_HEIGHT;

		sphincs_adrs_set_layer_address(adrs, i);
		sphincs_adrs_set_tree_address(adrs, tree_address);
		// sign xmss_root with layer +1 xmss_keypair
		sphincs_xmss_sign(secret, seed, adrs, keypair_address, xmss_root, &sig[i]);
		// xmss_sig => xmss_root, to be signed by next layer +1
		sphincs_xmss_sig_to_root(&sig[i], seed, adrs, keypair_address, xmss_root, xmss_root);



		format_print(stderr, 0, 4, "xmss_root[%d]", i);
		format_bytes(stderr, 0, 0, "", xmss_root, 16);
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sphincs_hypertree_sign(void)
{
	sphincs_hash128_t secret = {0};
	sphincs_hash128_t seed = {0};
	uint64_t tree_address = 0;
	uint32_t keypair_address = 0;
	sphincs_hash128_t forest_root = {0};

	sphincs_hash128_t ht_root;
	SPHINCS_XMSS_SIGNATURE ht_sig[SPHINCS_HYPERTREE_LAYERS];

	sphincs_hypertree_derive_root(secret, seed, ht_root);
	format_bytes(stderr, 0, 4, "hypertree_root", ht_root, 16);


	sphincs_hypertree_sign(secret, seed, tree_address, keypair_address, forest_root, ht_sig);


	if (sphincs_hypertree_verify(ht_root, seed, tree_address, keypair_address, forest_root, ht_sig) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;

}

static int test_sphincs_fors_sign(void)
{
	sphincs_hash128_t secret = {0};
	sphincs_hash128_t seed = {0};
	sphincs_adrs_t adrs = {0};
	const uint8_t dgst[21] = {0};

	sphincs_hash128_t root;
	sphincs_hash128_t sig_to_root;
	SPHINCS_FORS_SIGNATURE sig;



	sphincs_fors_derive_root(secret, seed, adrs, root);

	sphincs_fors_sign(secret, seed, adrs, dgst, &sig);

	sphincs_fors_sig_to_root(&sig, seed, adrs, dgst, sig_to_root);

	if (memcmp(sig_to_root, root, 16) != 0) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sphincs_sign(void)
{
	SPHINCS_KEY _key;
	SPHINCS_KEY *key = &_key;
	uint8_t msg[100] = {1, 2, 3, 0};
	SPHINCS_SIGNATURE _sig;
	SPHINCS_SIGNATURE *sig = &_sig;
	SPHINCS_HASH256_CTX hash_ctx;
	SPHINCS_HMAC256_CTX hmac_ctx;
	sphincs_hash256_t dgst;


	sphincs_hash128_t opt_rand;


	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t fors_forest_root;

	uint8_t tree_address_buf[8] = {0};
	uint8_t keypair_address_buf[4] = {0};

	uint64_t tree_address;
	uint32_t keypair_address;

	int randomize = 0;
	uint32_t i;

	uint8_t tbs[SPHINCS_TBS_SIZE];

	if (sphincs_key_generate(key) != 1) {
		error_print();
		return -1;
	}


	// set opt_rand
	memcpy(opt_rand, key->public_key.seed, sizeof(sphincs_hash128_t));
	if (randomize) {
		if (rand_bytes(opt_rand, sizeof(opt_rand)) != 1) {
			error_print();
			return -1;
		}
	}

	// 如果R是用M生成的，这意味着M要读取2遍，这就没办法用init/update范式了

	// R = PRF_msg(sk_prf, optrand, M) = HMAC(sk_prf, opt_rand|M)
	sphincs_hmac256_init(&hmac_ctx, key->sk_prf, sizeof(sphincs_hash128_t));
	sphincs_hmac256_update(&hmac_ctx, opt_rand, sizeof(sphincs_hash128_t));
	sphincs_hmac256_update(&hmac_ctx, msg, sizeof(msg));
	sphincs_hmac256_finish(&hmac_ctx, dgst);
	memcpy(sig->random, dgst, sizeof(sphincs_hash128_t));

	// dgst = HASH256(R|seed|root|M)
	sphincs_hash256_init(&hash_ctx);
	sphincs_hash256_update(&hash_ctx, sig->random, sizeof(sphincs_hash128_t));
	sphincs_hash256_update(&hash_ctx, key->public_key.seed, sizeof(sphincs_hash128_t));
	sphincs_hash256_update(&hash_ctx, key->public_key.root, sizeof(sphincs_hash128_t));
	sphincs_hash256_update(&hash_ctx, msg, sizeof(msg));
	sphincs_hash256_finish(&hash_ctx, dgst);

	// tbs = H_msg(R, seed, root, M) = MGF1(R|seed|dgst, tbs_len)
	for (i = 0; i < (SPHINCS_TBS_SIZE + 31)/32; i++) {
		uint8_t count[4];
		PUTU32(count, i);
		sphincs_hash256_init(&hash_ctx);
		sphincs_hash256_update(&hash_ctx, sig->random, sizeof(sphincs_hash128_t));
		sphincs_hash256_update(&hash_ctx, key->public_key.seed, sizeof(sphincs_hash128_t));
		sphincs_hash256_update(&hash_ctx, dgst, sizeof(dgst));
		sphincs_hash256_update(&hash_ctx, count, sizeof(count));
		sphincs_hash256_finish(&hash_ctx, tbs + sizeof(dgst) * i);
	}


	// get tree_address from tbs
	memcpy(tree_address_buf + 8 - 7, tbs + 21, 7);
	tree_address = GETU64(tree_address_buf); // 54 bits
	tree_address >>= 10;

	// get keypair_address from tbs
	memcpy(keypair_address_buf + 4 - 2, tbs + 21 + 7, 2);
	keypair_address = GETU32(keypair_address_buf);
	keypair_address >>= (16 - 9);



	format_bytes(stderr, 0, 4, "tree_address", tree_address_buf, 8);
	format_bytes(stderr, 0, 4, "keypair_address", keypair_address_buf, 4);


	fprintf(stderr, "tree_address %zu\n", (size_t)tree_address);
	fprintf(stderr, "keypair_address %zu\n", (size_t)keypair_address);






	// fors_sign
	sphincs_adrs_set_layer_address(adrs, 0);
	sphincs_adrs_set_tree_address(adrs, tree_address);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_FORS_TREE);
	sphincs_adrs_set_keypair_address(adrs, keypair_address);
	sphincs_fors_sign(key->secret, key->public_key.seed, adrs, tbs, &sig->fors_sig);

	// fors_sig => fors_forest_root
	sphincs_fors_sig_to_root(&sig->fors_sig, key->public_key.seed, adrs, tbs, fors_forest_root);





	// hypertree_sign fors_forest_root
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_TREE);
	sphincs_hypertree_sign(key->secret, key->public_key.seed, tree_address, keypair_address,
		fors_forest_root, sig->xmss_sigs);


	// sphincs_verify
	// --------------


	// fors_sig => fors_forest_root
	sphincs_adrs_set_layer_address(adrs, 0);
	sphincs_adrs_set_tree_address(adrs, tree_address);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_FORS_TREE);
	sphincs_adrs_set_keypair_address(adrs, keypair_address);

	sphincs_fors_sig_to_root(&sig->fors_sig, key->public_key.seed, adrs, tbs, fors_forest_root);

	// hypertree_verify
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_TREE);

	if (sphincs_hypertree_verify(key->public_key.root, key->public_key.seed,
		tree_address, keypair_address, fors_forest_root, sig->xmss_sigs) != 1) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sphincs_sign_update(void)
{
	SPHINCS_KEY key;
	SPHINCS_SIGN_CTX ctx;
	SPHINCS_SIGNATURE sig;
	uint8_t msg[100] = { 1,2,3 };

	if (sphincs_key_generate(&key) != 1) {
		error_print();
		return -1;
	}

	if (sphincs_sign_init(&ctx, &key) != 1) {
		error_print();
		return -1;
	}
	if (sphincs_sign_prepare(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sphincs_sign_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sphincs_sign_finish_ex(&ctx, &sig) != 1) {
		error_print();
		return -1;
	}

	// verify

	if (sphincs_verify_init_ex(&ctx, &key, &sig) != 1) {
		error_print();
		return -1;
	}
	if (sphincs_verify_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sphincs_verify_finish(&ctx) != 1) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


int main(void)
{
	if (test_sphincs_print_params() != 1) goto err;

	if (test_sphincs_wots_sign_verify() != 1) goto err;
	if (test_sphincs_wots_derive_sk() != 1) goto err;
	if (test_sphincs_wots_chain() != 1) goto err;
	if (test_sphincs_wots_sk_to_pk() != 1) goto err;
	if (test_sphincs_wots_pk_to_root() != 1) goto err;
	if (test_sphincs_wots_sign() != 1) goto err;
	if (test_sphincs_wots_sig_to_pk() != 1) goto err;

	if (test_sphincs_xmss_build_tree() != 1) goto err;
	if (test_sphincs_xmss_build_auth_path() != 1) goto err;
	if (test_sphincs_xmss_build_root() != 1) goto err;
	if (test_sphincs_xmss_sign() != 1) goto err;

	if (test_sphincs_hypertree() != 1) goto err;
	if (test_sphincs_hypertree_sign() != 1) goto err;

	if (test_sphincs_fors_sign() != 1) goto err;

	if (test_sphincs_sign() != 1) goto err;
	if (test_sphincs_sign_update() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
