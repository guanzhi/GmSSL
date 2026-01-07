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
#include <stdint.h>
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sha2.h>
#include <gmssl/sm3.h>
#include <gmssl/endian.h>
#include <gmssl/sphincs.h>




static const SPHINCS_PARAMS sphincs_params[] = {
	//                  n   h  d  lg(t) k   w         siglen
	{ "SPHINCS+_128s", 16, 63,  7, 12, 14, 16, 133, 1,  7856 },
	{ "SPHINCS+_128f", 16, 66, 22,  6, 33, 16, 128, 1, 17088 },
	{ "SPHINCS+_192s", 24, 64,  7, 14, 17, 16, 193, 3, 16244 },
	{ "SPHINCS+_192f", 24, 66, 22,  8, 33, 16, 194, 3, 35644 },
	{ "SPHINCS+_256s", 32, 64,  8, 14, 22, 16, 255, 5, 29792 },
	{ "SPHINCS+_256f", 32, 68, 17,  9, 35, 16, 255, 5, 49856 },
};



void sphincs_adrs_copy_layer_address(sphincs_adrs_t dst, const sphincs_adrs_t src) {
	memcpy(dst, src, 4);
}

void sphincs_adrs_copy_tree_address(sphincs_adrs_t dst, const sphincs_adrs_t src) {
	memcpy(dst + 4, src + 4, 12);
}

void sphincs_adrs_copy_type(sphincs_adrs_t dst, const sphincs_adrs_t src) {
	memcpy(dst + 16, src + 16, 4);
}

void sphincs_adrs_copy_keypair_address(sphincs_adrs_t dst, const sphincs_adrs_t src) {
	memcpy(dst + 20, src + 20, 4);
}

void sphincs_adrs_copy_chain_address(sphincs_adrs_t dst, const sphincs_adrs_t src) {
	memcpy(dst + 24, src + 24, 4);
}

void sphincs_adrs_copy_hash_address(sphincs_adrs_t dst, const sphincs_adrs_t src) {
	memcpy(dst + 28, src + 28, 4);
}

void sphincs_adrs_set_layer_address(sphincs_adrs_t adrs, const uint32_t address) {
	PUTU32(adrs, address);
}

void sphincs_adrs_set_tree_address(sphincs_adrs_t adrs, const uint64_t address) {
	PUTU32(adrs + 4, 0);
	PUTU64(adrs + 8, address);
}

void sphincs_adrs_set_type(sphincs_adrs_t adrs, const uint32_t type) {
	PUTU32(adrs + 16, type);
}

void sphincs_adrs_set_keypair_address(sphincs_adrs_t adrs, const uint32_t address) {
	PUTU32(adrs + 20, address);
}

void sphincs_adrs_set_chain_address(sphincs_adrs_t adrs, const uint32_t address) {
	PUTU32(adrs + 24, address);
}

void sphincs_adrs_set_hash_address(sphincs_adrs_t adrs, const uint32_t address) {
	PUTU32(adrs + 28, address);
}

void sphincs_adrs_copy_tree_height(sphincs_adrs_t dst, const sphincs_adrs_t src) {
	memcpy(dst + 24, src + 24, 4);
}

void sphincs_adrs_copy_tree_index(sphincs_adrs_t dst, const sphincs_adrs_t src) {
	memcpy(dst + 28, src + 28, 4);
}

void sphincs_adrs_set_tree_height(sphincs_adrs_t adrs, uint32_t height) {
	PUTU32(adrs + 24, height);
}

void sphincs_adrs_set_tree_index(sphincs_adrs_t adrs, uint32_t index) {
	PUTU32(adrs + 28, index);
}


void sphincs_adrs_compress(const sphincs_adrs_t adrs, sphincs_adrsc_t adrsc)
{
	memcpy(adrsc, adrs, 22);
}


void sphincs_wots_chain(const sphincs_secret_t x,
	const sphincs_secret_t seed, const sphincs_adrs_t ots_adrs,
	int start, int steps, sphincs_secret_t y)
{
	const uint8_t uint32_zero[4] = {0};
	uint8_t block[HASH256_BLOCK_SIZE] = {0};
	sphincs_adrs_t adrs;
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;
	int i;

	memcpy(block, seed, sizeof(sphincs_secret_t));

	sphincs_adrs_copy_layer_address(adrs, ots_adrs);
	sphincs_adrs_copy_tree_address(adrs, ots_adrs);
	sphincs_adrs_copy_type(adrs, ots_adrs);
	sphincs_adrs_copy_keypair_address(adrs, ots_adrs);
	sphincs_adrs_copy_chain_address(adrs, ots_adrs);

	memcpy(y, x, sizeof(sphincs_secret_t));

	for (i = 0; i < steps; i++) {
		sphincs_adrs_set_hash_address(adrs, start + i);
		sphincs_adrs_compress(adrs, adrsc);

		// tmp = tmp xor mgf1(seed||ardsc)
		hash256_init(&ctx);
		hash256_update(&ctx, seed, sizeof(sphincs_secret_t));
		hash256_update(&ctx, adrsc, sizeof(sphincs_adrsc_t));
		hash256_update(&ctx, uint32_zero, sizeof(uint32_zero));
		hash256_finish(&ctx, dgst);

		gmssl_memxor(y, y, dgst, sizeof(sphincs_secret_t));

		// y = hash256(blockpad(seed) || adrsc || y)
		hash256_init(&ctx);
		hash256_update(&ctx, block, sizeof(block));
		hash256_update(&ctx, adrsc, sizeof(sphincs_adrsc_t));
		hash256_update(&ctx, y, sizeof(sphincs_secret_t));
		hash256_finish(&ctx, dgst);

		memcpy(y, dgst, sizeof(sphincs_secret_t));
	}
}

void sphincs_wots_derive_sk(const sphincs_secret_t secret,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	sphincs_wots_key_t sk)
{
	uint8_t block[HASH256_BLOCK_SIZE] = {0};
	sphincs_adrs_t adrs;
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;
	int i;

	memcpy(block, seed, sizeof(sphincs_secret_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_PRF);

	for (i = 0; i < 35; i++) {
		sphincs_adrs_set_chain_address(adrs, i);
		sphincs_adrs_set_hash_address(adrs, 0);
		sphincs_adrs_compress(adrs, adrsc);

		// sk[i]
		hash256_init(&ctx);
		hash256_update(&ctx, block, sizeof(block));
		hash256_update(&ctx, adrsc, sizeof(adrsc));
		hash256_update(&ctx, secret, sizeof(sphincs_secret_t));
		hash256_finish(&ctx, dgst);
		memcpy(sk, dgst, sizeof(sphincs_secret_t));
	}
}

void sphincs_wots_sk_to_pk(const sphincs_wots_key_t sk,
	const sphincs_secret_t seed, const sphincs_adrs_t ots_adrs,
	sphincs_wots_key_t pk)
{
	const int start = 0;
	const int steps = 16 - 1;
	sphincs_adrs_t adrs;
	int chain;

	sphincs_adrs_copy_layer_address(adrs, ots_adrs);
	sphincs_adrs_copy_tree_address(adrs, ots_adrs);
	sphincs_adrs_copy_type(adrs, ots_adrs);
	sphincs_adrs_copy_keypair_address(adrs, ots_adrs);

	for (chain = 0; chain < 35; chain++) {
		sphincs_adrs_set_chain_address(adrs, chain);
		sphincs_adrs_set_hash_address(adrs, 0);
		sphincs_wots_chain(sk[chain], seed, adrs, start, steps, pk[chain]);
	}
}

void sphincs_wots_pk_to_root(const sphincs_wots_key_t pk,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	sphincs_secret_t root)
{
	uint8_t block[HASH256_BLOCK_SIZE] = {0};
	sphincs_adrs_t adrs;
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;
	int i;

	memcpy(block, seed, sizeof(sphincs_secret_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_PK);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);
	sphincs_adrs_compress(adrs, adrsc);

	hash256_init(&ctx);
	hash256_update(&ctx, block, sizeof(block));
	hash256_update(&ctx, adrsc, sizeof(adrsc));
	for (i = 0; i < 35; i++) {
		hash256_update(&ctx, pk[i], sizeof(sphincs_secret_t));
	}
	hash256_finish(&ctx, dgst);

	memcpy(root, dgst, sizeof(sphincs_secret_t));
}

void sphincs_base_w_and_checksum(const sphincs_secret_t dgst, int steps[35])
{
	int csum = 0;
	int sbits;
	int i;

	for (i = 0; i < 16; i++) {
		steps[2 * i]     = dgst[i] >> 4;
		steps[2 * i + 1] = dgst[i] & 0xf;
	}
	for (i = 0; i < 32; i++) {
		csum += 15 - steps[i];
	}
	// csum = csum << (8 - ((len_2 * lg(w)) %8)) = (8 - (3*4)%8) = 8 - 4 = 4
	sbits = (8 - ((3 * 4) % 8));
	csum <<= sbits;

	// len_2_bytes = ceil((len_2 * lg(w)) / 8) = ceil(12/8) = 2
	uint8_t csum_bytes[2];
	csum_bytes[0] = (csum >> 8) & 0xff;
	csum_bytes[1] = csum & 0xff;

	steps[32] = csum_bytes[0] >> 4;
	steps[33] = csum_bytes[0] & 0xf;
	steps[34] = csum_bytes[1] >> 4;
}

void sphincs_wots_sign(const sphincs_wots_key_t sk,
	const sphincs_secret_t seed, const sphincs_adrs_t ots_adrs,
	const sphincs_secret_t dgst, sphincs_wots_sig_t sig)
{
	sphincs_adrs_t adrs;
	const int start = 0;
	int steps[35];
	uint32_t i;

	sphincs_adrs_copy_layer_address(adrs, ots_adrs);
	sphincs_adrs_copy_tree_address(adrs, ots_adrs);
	sphincs_adrs_copy_type(adrs, ots_adrs);
	sphincs_adrs_copy_keypair_address(adrs, ots_adrs);

	sphincs_base_w_and_checksum(dgst, steps);

	for (i = 0; i < 35; i++) {
		sphincs_adrs_set_chain_address(adrs, i);
		sphincs_adrs_set_hash_address(adrs, 0);
		sphincs_wots_chain(sk[i], seed, adrs, start, steps[i], sig[i]);
	}
}

void sphincs_wots_sig_to_pk(const sphincs_wots_sig_t sig,
	const sphincs_secret_t seed, const sphincs_adrs_t ots_adrs,
	const sphincs_secret_t dgst, sphincs_wots_key_t pk)
{
	sphincs_adrs_t adrs;
	int steps[35];
	int i;

	sphincs_adrs_copy_layer_address(adrs, ots_adrs);
	sphincs_adrs_copy_tree_address(adrs, ots_adrs);
	sphincs_adrs_copy_type(adrs, ots_adrs);
	sphincs_adrs_copy_keypair_address(adrs, ots_adrs);

	sphincs_base_w_and_checksum(dgst, steps);

	for (i = 0; i < 35; i++) {
		sphincs_adrs_set_chain_address(adrs, i);
		sphincs_wots_chain(sig[i], seed, adrs, steps[i], 15 - steps[i], pk[i]);
	}
}

void sphincs_xmss_tree_hash(const sphincs_secret_t left_child, const sphincs_secret_t right_child,
	const sphincs_secret_t seed, const sphincs_adrs_t adrs,
	hash256_t parent)
{
	HASH256_CTX ctx;
	hash256_t dgst;

	hash256_init(&ctx);
	hash256_update(&ctx, seed, sizeof(sphincs_secret_t));
	hash256_update(&ctx, adrs, sizeof(sphincs_adrs_t));
	hash256_update(&ctx, left_child, sizeof(sphincs_secret_t));
	hash256_update(&ctx, right_child, sizeof(sphincs_secret_t));
	hash256_finish(&ctx, dgst);

	memcpy(parent, dgst, sizeof(sphincs_secret_t));
}

void sphincs_xmss_build_tree(const sphincs_secret_t secret,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	size_t height, sphincs_secret_t *tree)
{
	sphincs_adrs_t adrs;
	sphincs_secret_t *children;
	sphincs_secret_t *parents;
	size_t n = 1 << height;
	uint32_t h; // as tree_height
	uint32_t i; // as tree_index

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);

	// derive 2^h wots+ roots as leaves of xmss tree
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_PRF);
	for (i = 0; i < n; i++) {
		sphincs_adrs_set_keypair_address(adrs, i);
		//sphincs_wots_derive_root(secret, seed, adrs, tree[i]);
	}

	// build xmss tree
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_HASHTREE);
	//sphincs_adrs_set_padding(adrs, 0);

	children = tree;
	parents = tree + n;
	for (h = 0; h < height; h++) {
		sphincs_adrs_set_tree_height(adrs, h + 1);
		n >>= 1;
		for (i = 0; i < n; i++) {
			sphincs_adrs_set_tree_index(adrs, i);
			sphincs_xmss_tree_hash(children[2*i], children[2*i + 1], seed, adrs, parents[i]);
		}
		children = parents;
		parents += n;
	}
}

// auth_path[height]
void sphincs_xmss_build_auth_path(const sphincs_secret_t *tree, size_t height,
	uint32_t tree_index, sphincs_secret_t *auth_path)
{
	size_t h;
	for (h = 0; h < height; h++) {
		memcpy(auth_path[h], tree[tree_index ^ 1], sizeof(sphincs_secret_t));
		tree += (1 << (height - h));
		tree_index >>= 1;
	}
}

void sphincs_xmss_build_root(const sphincs_secret_t wots_root, uint32_t tree_index,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	const sphincs_secret_t *auth_path, size_t height,
	hash256_t root)
{
	sphincs_adrs_t adrs;
	uint32_t h;

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_HASHTREE);
	//sphincs_adrs_set_padding(adrs, 0);

	memcpy(root, wots_root, sizeof(sphincs_secret_t));


	for (h = 0; h < height; h++) {
		int right_child = tree_index & 1;
		tree_index >>= 1;
		sphincs_adrs_set_tree_height(adrs, h + 1);
		sphincs_adrs_set_tree_index(adrs, tree_index);

		if (right_child)
			sphincs_xmss_tree_hash(auth_path[h], root, seed, adrs, root);
		else	sphincs_xmss_tree_hash(root, auth_path[h], seed, adrs, root);
	}
}

// TODO: index or tree_index?
void sphincs_xmss_sign(const sphincs_secret_t secret, uint32_t index,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	const sphincs_secret_t dgst, SPHINCS_XMSS_SIGNATURE *sig)
{
	size_t height = SPHINCS_XMSS_HEIGHT;
	sphincs_adrs_t adrs;
	sphincs_wots_key_t wots_sk;
	sphincs_secret_t tree[(1 << (SPHINCS_XMSS_HEIGHT + 1)) - 1];

	// generate wots_sig
	sphincs_wots_derive_sk(secret, seed, adrs, wots_sk);
	sphincs_wots_sign(wots_sk, seed, adrs, dgst, sig->wots_sig);

	// build xmss_tree, then build auth_path
	sphincs_xmss_build_tree(secret, seed, adrs, height, tree);
	sphincs_xmss_build_auth_path(tree, height, index, sig->auth_path);
}

void sphincs_xmss_sig_to_root(const SPHINCS_XMSS_SIGNATURE *sig,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	const sphincs_secret_t dgst, sphincs_secret_t xmss_root)
{
	sphincs_adrs_t adrs;
	sphincs_wots_key_t wots_pk;
	sphincs_secret_t wots_root;
	size_t height = SPHINCS_XMSS_HEIGHT;


	sphincs_wots_sig_to_pk(sig->wots_sig, seed, adrs, dgst, wots_pk);
	sphincs_wots_pk_to_root(wots_pk, seed, adrs, wots_root);


	sphincs_xmss_build_root(wots_root, sig->index, seed, adrs,
		sig->auth_path, height,
		xmss_root);
}

// generate the highest layer xmss_tree root
void sphincs_hypertree_derive_root(const sphincs_secret_t secret, const sphincs_secret_t seed,
	sphincs_secret_t root)
{
	sphincs_adrs_t adrs;
	sphincs_secret_t tree[(1 << (SPHINCS_XMSS_HEIGHT + 1)) - 1];
	sphincs_adrs_set_layer_address(adrs, SPHINCS_HYPERTREE_LAYERS - 1);
	sphincs_adrs_set_tree_address(adrs, 0);
	sphincs_xmss_build_tree(secret, seed, adrs, SPHINCS_XMSS_HEIGHT, tree);
	root = tree[(1 << (SPHINCS_XMSS_HEIGHT + 1)) - 2];
}

// FIXME: uint64_t for leaf_index?
void sphincs_hypertree_sign(const sphincs_secret_t secret, const sphincs_secret_t seed,
	uint32_t tree_index, uint32_t leaf_index,
	SPHINCS_XMSS_SIGNATURE sig[SPHINCS_HYPERTREE_LAYERS])
{
	sphincs_adrs_t adrs = {0};

}



void sphincs_fors_derive_sk(const sphincs_secret_t secret,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	uint32_t fors_index, sphincs_secret_t sk)
{
	uint8_t block[HASH256_BLOCK_SIZE] = {0};
	sphincs_adrs_t adrs;
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;

	// blockpad(seed)
	memcpy(block, seed, sizeof(sphincs_secret_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_FORS_KEYGEN);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);
	sphincs_adrs_set_tree_height(adrs, 0);
	sphincs_adrs_set_tree_index(adrs, fors_index);

	// compress adrs
	sphincs_adrs_compress(adrs, adrsc);

	// sk = prf(seed, secret, adrs) = hash256(blockpad(seed)||adrsc||secret)
	hash256_init(&ctx);
	hash256_update(&ctx, block, sizeof(block));
	hash256_update(&ctx, adrsc, sizeof(adrsc));
	hash256_update(&ctx, secret, sizeof(sphincs_secret_t));
	hash256_finish(&ctx, dgst);

	memcpy(sk, dgst, sizeof(sphincs_secret_t));
	gmssl_secure_clear(dgst, sizeof(dgst));
}

void sphincs_fors_derive_root_ex(const sphincs_secret_t secret,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	size_t fors_height, size_t fors_trees,
	sphincs_secret_t root)
{
}

void sphincs_fors_derive_root(const sphincs_secret_t secret,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	sphincs_secret_t root)
{
	size_t fors_height = SPHINCS_FORS_HEIGHT;
	size_t fors_trees = SPHINCS_FORS_NUM_TREES;

	sphincs_fors_derive_root_ex(secret, seed, in_adrs, fors_height, fors_trees, root);
}


void sphincs_fors_sign(const sphincs_secret_t secret,
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	const uint8_t dgst[SPHINCS_FORS_DIGEST_SIZE],
	SPHINCS_FORS_SIGNATURE *sig)
{
	sphincs_adrs_t adrs;
	sphincs_secret_t fors_sk;
	size_t i;

	for (i = 0; i < SPHINCS_FORS_NUM_TREES; i++) {


		//sphincs_fors_derive_sk(secret, seed, adrs, fors_index, fors_sk);



	}

}

