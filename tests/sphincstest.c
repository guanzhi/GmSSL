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
	SPHINCS_KEY key;
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t random;


	uint32_t tree_index;
	uint32_t leaf_index;

	sphincs_adrs_set_layer_address(adrs, 0);
	sphincs_adrs_set_tree_address(adrs, tree_index);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_FORS_TREE);
	sphincs_adrs_set_keypair_address(adrs, leaf_index);


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sphincs_fors_sign() != 1) goto err;
	//if (test_sphincs_xmss_build_tree() != 1) goto err;
	//if (test_sphincs_hypertree() != 1) goto err;
//	if (test_sphincs_hypertree_sign() != 1) goto err;
	//if (test_sphincs_wots_sign_verify() != 1) goto err;
	/*
	if (test_sphincs_wots_derive_sk() != 1) goto err;
	if (test_sphincs_wots_chain() != 1) goto err;
	if (test_sphincs_wots_sk_to_pk() != 1) goto err;
	if (test_sphincs_wots_pk_to_root() != 1) goto err;
	if (test_sphincs_wots_sign() != 1) goto err;
	if (test_sphincs_wots_sig_to_pk() != 1) goto err;

	if (test_sphincs_xmss_build_auth_path() != 1) goto err;
	*/

	//if (test_sphincs_xmss_build_root() != 1) goto err;
	//if (test_sphincs_xmss_sign() != 1) goto err;


	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
