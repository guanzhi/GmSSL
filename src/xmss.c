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
#include <gmssl/endian.h>
#include <gmssl/xmss.h>


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


static void uint32_to_bytes(uint32_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		PUTU32(*out, a);
		*out += 4;
	}
	*outlen += 4;
}

static void uint32_from_bytes(uint32_t *a, const uint8_t **in, size_t *inlen)
{
	*a = GETU32(*in);
	*in += 4;
	*inlen -= 4;
}

static void hash256_to_bytes(const hash256_t hash, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		memcpy(*out, hash, 32);
		*out += 32;
	}
	*outlen += 32;
}

static void hash256_from_bytes(hash256_t hash, const uint8_t **in, size_t *inlen)
{
	memcpy(hash, *in, 32);
	*in += 32;
	*inlen -= 32;
}


void adrs_copy_layer_address(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst, src, 4);
}

void adrs_copy_tree_address(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 4, src + 4, 8);
}

void adrs_copy_type(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 12, src + 12, 4);
}

void adrs_copy_ots_address(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 16, src + 16, 4);
}

void adrs_copy_chain_address(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 20, src + 20, 4);
}

void adrs_copy_hash_address(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 24, src + 24, 4);
}

void adrs_copy_key_and_mask(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 28, src + 28, 4);
}

void adrs_copy_ltree_address(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 16, src + 16, 4);
}

void adrs_copy_tree_height(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 20, src + 20, 4);
}

void adrs_copy_tree_index(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 24, src + 24, 4);
}

void adrs_copy_padding(xmss_adrs_t dst, const xmss_adrs_t src) {
	memcpy(dst + 16, src + 16, 4);
}

void adrs_set_layer_address(uint8_t adrs[32], uint32_t layer) {
	PUTU32(adrs, layer);
}

void adrs_set_tree_address(uint8_t adrs[32], uint64_t tree_addr) {
	PUTU64(adrs + 4, tree_addr);
}

void adrs_set_type(uint8_t adrs[32], uint32_t type) {
	PUTU32(adrs + 4*3, type);
	memset(adrs + 16, 0, 16);
}

void adrs_set_ots_address(uint8_t adrs[32], uint32_t address) {
	PUTU32(adrs + 4*4, address);
}

void adrs_set_chain_address(uint8_t adrs[32], uint32_t address) {
	PUTU32(adrs + 4*5, address);
}

void adrs_set_hash_address(uint8_t adrs[32], uint32_t address) {
	PUTU32(adrs + 4*6, address);
}

void adrs_set_ltree_address(uint8_t adrs[32], uint32_t address) {
	PUTU32(adrs + 4*4, address);
}

void adrs_set_padding(uint8_t adrs[32], uint32_t padding) {
	PUTU32(adrs + 4*4, padding);
}

void adrs_set_tree_height(uint8_t adrs[32], uint32_t height) {
	PUTU32(adrs + 4*5, height);
}

void adrs_set_tree_index(uint8_t adrs[32], uint32_t index) {
	PUTU32(adrs + 4*6, index);
}

void adrs_set_key_and_mask(uint8_t adrs[32], uint32_t key_and_mask) {
	PUTU32(adrs + 4*7, key_and_mask);
}

int xmss_adrs_print(FILE *fp, int fmt, int ind, const char *label, const hash256_t adrs)
{
	uint32_t layer_address;
	uint64_t tree_address;
	uint32_t type;
	uint32_t key_and_mask;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	layer_address = GETU32(adrs);
	adrs += 4;
	format_print(fp, fmt, ind, "layer_address: %"PRIu32"\n", layer_address);

	tree_address = GETU64(adrs);
	adrs += 8;
	format_print(fp, fmt, ind, "tree_address : %"PRIu64"\n", tree_address);

	type = GETU32(adrs);
	adrs += 4;
	format_print(fp, fmt, ind, "type         : %"PRIu32"\n", type);

	if (type == XMSS_ADRS_TYPE_OTS) {
		uint32_t ots_address;
		uint32_t chain_address;
		uint32_t hash_address;

		ots_address = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "ots_address  : %"PRIu32"\n", ots_address);
		chain_address = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "chain_address: %"PRIu32"\n", chain_address);
		hash_address = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "hash_address : %"PRIu32"\n", hash_address);
	} else if (type == XMSS_ADRS_TYPE_LTREE) {
		uint32_t ltree_address;
		uint32_t tree_height;
		uint32_t tree_index;

		ltree_address = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "ltree_address: %"PRIu32"\n", ltree_address);
		tree_height = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "tree_height  : %"PRIu32"\n", tree_height);
		tree_index = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "tree_index   : %"PRIu32"\n", tree_index);
	} else if (type == XMSS_ADRS_TYPE_HASHTREE) {
		uint32_t padding;
		uint32_t tree_height;
		uint32_t tree_index;

		padding = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "padding      : %"PRIu32"\n", padding);
		tree_height = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "tree_height  : %"PRIu32"\n", tree_height);
		tree_index = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "tree_index   : %"PRIu32"\n", tree_index);
	} else {
		error_print();
	}

	key_and_mask = GETU32(adrs);
	adrs += 4;
	format_print(fp, fmt, ind, "key_and_mask : %"PRIu32"\n", key_and_mask);

	return 1;
}

void wots_derive_sk(const hash256_t secret,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	wots_key_t sk)
{
	static const uint8_t hash256_four[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	};
	HASH256_CTX ctx;
	xmss_adrs_t adrs;
	int chain;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);

	for (chain = 0; chain < WOTS_NUM_CHAINS; chain++) {
		adrs_set_chain_address(adrs, chain);
		adrs_set_hash_address(adrs, 0);
		adrs_set_key_and_mask(adrs, XMSS_ADRS_GENERATE_KEY);

		hash256_init(&ctx);
		hash256_update(&ctx, hash256_four, sizeof(hash256_t));
		hash256_update(&ctx, secret, sizeof(hash256_t));
		hash256_update(&ctx, seed, sizeof(hash256_t));
		hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
		hash256_finish(&ctx, sk[chain]);
	}
}

void wots_chain(const hash256_t x,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	int start, int steps, hash256_t y)
{
	const hash256_t hash256_zero = {0};
	HASH256_CTX ctx;
	xmss_adrs_t adrs;
	hash256_t key;
	hash256_t bitmask;
	int i;

	// tmp = x
	memcpy(y, x, sizeof(hash256_t));

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);
	adrs_copy_chain_address(adrs, ots_adrs);

	for (i = 0; i < steps; i++) {
		adrs_set_hash_address(adrs, start + i);

		// key = prf(seed, adrs)
		adrs_set_key_and_mask(adrs, XMSS_ADRS_GENERATE_KEY);
		hash256_init(&ctx);
		hash256_update(&ctx, hash256_three, sizeof(hash256_t));
		hash256_update(&ctx, seed, sizeof(hash256_t));
		hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
		hash256_finish(&ctx, key);

		// bitmask = prf(seed, adrs)
		adrs_set_key_and_mask(adrs, XMSS_ADRS_GENERATE_BITMASK);
		hash256_init(&ctx);
		hash256_update(&ctx, hash256_three, sizeof(hash256_t));
		hash256_update(&ctx, seed, sizeof(hash256_t));
		hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
		hash256_finish(&ctx, bitmask);

		// tmp = f(key, tmp xor bitmask)
		gmssl_memxor(y, y, bitmask, sizeof(hash256_t));
		hash256_init(&ctx);
		hash256_update(&ctx, hash256_zero, sizeof(hash256_t));
		hash256_update(&ctx, key, sizeof(hash256_t));
		hash256_update(&ctx, y, sizeof(hash256_t));
		hash256_finish(&ctx, y);
	}

}

void wots_sk_to_pk(const wots_key_t sk,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	wots_key_t pk)
{
	const int start = 0;
	const int steps = WOTS_WINTERNITZ_W - 1;
	xmss_adrs_t adrs;
	int chain;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);

	for (chain = 0; chain < WOTS_NUM_CHAINS; chain++) {
		adrs_set_chain_address(adrs, chain);
		wots_chain(sk[chain], seed, adrs, start, steps, pk[chain]);
	}
}

// seperate 256 bit digest into 256/4 = 64 step values, generate 3 checksum step values
// output steps[i] in [0, w-1] = [0, 16-1]
// this implementation is for hash256 and w=16 only!
static void base_w_and_checksum(const hash256_t dgst, int steps[67])
{
	int csum = 0;
	int sbits;
	int i;

	for (i = 0; i < 32; i++) {
		steps[2 * i]     = dgst[i] >> 4;
		steps[2 * i + 1] = dgst[i] & 0xf;
	}
	for (i = 0; i < 64; i++) {
		csum += 15 - steps[i];
	}
	// csum = csum << (8 - ((len_2 * lg(w)) %8)) = (8 - (3*4)%8) = 8 - 4 = 4
	sbits = (8 - ((3 * 4) % 8));
	csum <<= sbits;

	// len_2_bytes = ceil((len_2 * lg(w)) / 8) = ceil(12/8) = 2
	uint8_t csum_bytes[2];
	csum_bytes[0] = (csum >> 8) & 0xff;
	csum_bytes[1] = csum & 0xff;

	steps[64] = csum_bytes[0] >> 4;
	steps[65] = csum_bytes[0] & 0xf;
	steps[66] = csum_bytes[1] >> 4;
}

void wots_sign(const wots_key_t sk,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	const hash256_t dgst, wots_key_t sig)
{
	xmss_adrs_t adrs;
	const int start = 0;
	int steps[WOTS_NUM_CHAINS];
	int chain;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);

	base_w_and_checksum(dgst, steps);

	for (chain = 0; chain < WOTS_NUM_CHAINS; chain++) {
		adrs_set_chain_address(adrs, chain);
		wots_chain(sk[chain], seed, adrs, start, steps[chain], sig[chain]);
	}
}

void wots_sig_to_pk(const wots_sig_t sig,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	const hash256_t dgst, wots_key_t pk)
{
	hash256_t adrs;
	int steps[67];
	int chain;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);

	base_w_and_checksum(dgst, steps);

	for (chain = 0; chain < WOTS_NUM_CHAINS; chain++) {
		adrs_set_chain_address(adrs, chain);
		wots_chain(sig[chain], seed, adrs, steps[chain], 15 - steps[chain], pk[chain]);
	}
}

// TODO: need test and test vector
static void randomized_tree_hash(const hash256_t left_child, const hash256_t right_child,
	const hash256_t seed, const xmss_adrs_t tree_adrs,
	hash256_t parent)
{
	static const uint8_t hash256_one[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	};
	HASH256_CTX ctx;
	xmss_adrs_t adrs;
	hash256_t key;
	hash256_t bm0;
	hash256_t bm1;

	// copy adrs (and set the last key_and_mask)
	adrs_copy_layer_address(adrs, tree_adrs);
	adrs_copy_tree_address(adrs, tree_adrs);
	adrs_copy_type(adrs, tree_adrs);
	adrs_copy_ltree_address(adrs, tree_adrs);
	adrs_copy_tree_height(adrs, tree_adrs);
	adrs_copy_tree_index(adrs, tree_adrs);

	// key = prf(seed, adrs)
	adrs_set_key_and_mask(adrs, 0);
	hash256_init(&ctx);
	hash256_update(&ctx, hash256_three, sizeof(hash256_t));
	hash256_update(&ctx, seed, sizeof(hash256_t));
	hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
	hash256_finish(&ctx, key);

	// bm_0 = prf(seed, adrs)
	adrs_set_key_and_mask(adrs, 1);
	hash256_init(&ctx);
	hash256_update(&ctx, hash256_three, sizeof(hash256_t));
	hash256_update(&ctx, seed, sizeof(hash256_t));
	hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
	hash256_finish(&ctx, bm0);

	// bm_1 = prf(seed, adrs)
	adrs_set_key_and_mask(adrs, 2);
	hash256_init(&ctx);
	hash256_update(&ctx, hash256_three, sizeof(hash256_t));
	hash256_update(&ctx, seed, sizeof(hash256_t));
	hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
	hash256_finish(&ctx, bm1);

	// parent = Hash( tobyte(1, 32) || key || (left xor bm_0) || (right xor bm_1) )
	gmssl_memxor(bm0, bm0, left_child, sizeof(hash256_t));
	gmssl_memxor(bm1, bm1, right_child, sizeof(hash256_t));
	hash256_init(&ctx);
	hash256_update(&ctx, hash256_one, sizeof(hash256_t));
	hash256_update(&ctx, key, sizeof(hash256_t));
	hash256_update(&ctx, bm0, sizeof(hash256_t));
	hash256_update(&ctx, bm1, sizeof(hash256_t));
	hash256_finish(&ctx, parent);
}

// ltree is wots+ leaf tree, (un-balanced) merkle tree from the 67 wots+ hashs
void wots_pk_to_root(const wots_key_t in_pk,
	const hash256_t seed, const xmss_adrs_t in_adrs,
	hash256_t wots_root)
{
	wots_key_t pk;
	xmss_adrs_t adrs;
	uint32_t tree_height = 0;
	int len = WOTS_NUM_CHAINS;

	uint32_t i;

	memcpy(pk, in_pk, sizeof(wots_key_t));

	adrs_copy_layer_address(adrs, in_adrs);
	adrs_copy_tree_address(adrs, in_adrs);
	adrs_copy_type(adrs, in_adrs);
	adrs_copy_ltree_address(adrs, in_adrs);

	adrs_set_tree_height(adrs, tree_height++);

	while (len > 1) {
		for (i = 0; i < len/2; i++) {
			adrs_set_tree_index(adrs, i);
			randomized_tree_hash(pk[2 * i], pk[2 * i + 1], seed, adrs, pk[i]);
		}
		if (len % 2) {
			memcpy(pk[len/2], pk[len-1], 32); //pk[len/2] = pk[len - 1];
		}

		len = (len + 1)/2;
		adrs_set_tree_height(adrs, tree_height++);
	}

	memcpy(wots_root, pk[0], 32);
}

int wots_verify(const hash256_t wots_root,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	const hash256_t dgst, const wots_sig_t sig)
{
	xmss_adrs_t adrs;
	wots_key_t pk;
	hash256_t root;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);
	wots_sig_to_pk(sig, seed, adrs, dgst, pk);

	adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
	adrs_copy_ltree_address(adrs, ots_adrs); // ltree_address offset is same as ots_address
	wots_pk_to_root(pk, seed, adrs, root);

	if (memcmp(root, wots_root, sizeof(hash256_t)) != 0) {
		//error_print();
		return 0;
	}
	return 1;
}

void wots_derive_root(const hash256_t secret,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	hash256_t wots_root)
{
	xmss_adrs_t adrs;
	wots_key_t wots_key;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);
	wots_derive_sk(secret, seed, adrs, wots_key);
	wots_sk_to_pk(wots_key, seed, adrs, wots_key);

	adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
	adrs_copy_ltree_address(adrs, ots_adrs); // ltree_address offset is same as ots_address
	wots_pk_to_root(wots_key, seed, adrs, wots_root);
}



static size_t xmss_tree_root_offset(size_t height) {
	return (1 << (height + 1)) - 2;
}

size_t xmss_num_tree_nodes(size_t height) {
	return (1 << (height + 1)) - 1;
}

void xmss_build_tree(const hash256_t secret,
	const hash256_t seed, const xmss_adrs_t xmss_adrs,
	size_t height, hash256_t *tree)
{
	xmss_adrs_t adrs;
	hash256_t *children;
	hash256_t *parents;
	size_t n = 1 << height;
	uint32_t h; // as tree_height
	uint32_t i; // as tree_index

	adrs_copy_layer_address(adrs, xmss_adrs);
	adrs_copy_tree_address(adrs, xmss_adrs);

	// derive 2^h wots+ roots as leaves of xmss tree
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	for (i = 0; i < n; i++) {
		adrs_set_ots_address(adrs, i);
		wots_derive_root(secret, seed, adrs, tree[i]);
	}

	// build xmss tree
	adrs_set_type(adrs, XMSS_ADRS_TYPE_HASHTREE);
	adrs_set_padding(adrs, 0);

	children = tree;
	parents = tree + n;
	for (h = 0; h < height; h++) {
		adrs_set_tree_height(adrs, h + 1);
		n >>= 1;
		for (i = 0; i < n; i++) {
			adrs_set_tree_index(adrs, i);
			randomized_tree_hash(children[2*i], children[2*i + 1], seed, adrs, parents[i]);
		}
		children = parents;
		parents += n;
	}
}

void xmss_build_auth_path(const hash256_t *tree, size_t height, uint32_t tree_index, hash256_t *auth_path)
{
	size_t h;
	for (h = 0; h < height; h++) {
		memcpy(auth_path[h], tree[tree_index ^ 1], sizeof(hash256_t));
		tree += (1 << (height - h));
		tree_index >>= 1;
	}
}

void xmss_build_root(const hash256_t wots_root, uint32_t tree_index,
	const hash256_t seed, const xmss_adrs_t xmss_adrs,
	const hash256_t *auth_path, size_t height,
	hash256_t root)
{
	xmss_adrs_t adrs;
	uint32_t h;

	adrs_copy_layer_address(adrs, xmss_adrs);
	adrs_copy_tree_address(adrs, xmss_adrs);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_HASHTREE);
	adrs_set_padding(adrs, 0);

	memcpy(root, wots_root, sizeof(hash256_t));

	for (h = 0; h < height; h++) {
		int right_child = tree_index & 1;
		tree_index >>= 1;
		adrs_set_tree_height(adrs, h + 1);
		adrs_set_tree_index(adrs, tree_index);

		if (right_child)
			randomized_tree_hash(auth_path[h], root, seed, adrs, root);
		else	randomized_tree_hash(root, auth_path[h], seed, adrs, root);
	}
}

int xmss_type_to_height(uint32_t xmss_type, size_t *height)
{
	switch (xmss_type) {
	case XMSS_HASH256_10_256: *height = 10; break;
	case XMSS_HASH256_16_256: *height = 16; break;
	case XMSS_HASH256_20_256: *height = 20; break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

char *xmss_type_name(uint32_t type)
{
	switch (type) {
	case XMSS_HASH256_10_256: return XMSS_HASH256_10_256_NAME;
	case XMSS_HASH256_16_256: return XMSS_HASH256_16_256_NAME;
	case XMSS_HASH256_20_256: return XMSS_HASH256_20_256_NAME;
	}
	return NULL;
}

uint32_t xmss_type_from_name(const char *name)
{
	if (!strcmp(name, XMSS_HASH256_10_256_NAME)) {
		return XMSS_HASH256_10_256;
	} else if (!strcmp(name, XMSS_HASH256_16_256_NAME)) {
		return XMSS_HASH256_16_256;
	} else if (!strcmp(name, XMSS_HASH256_20_256_NAME)) {
		return XMSS_HASH256_20_256;
	}
	return 0;
}

int xmss_private_key_size(uint32_t xmss_type, size_t *keysize)
{
	size_t height;

	if (!keysize) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	*keysize = XMSS_PUBLIC_KEY_SIZE
		+ sizeof(hash256_t)
		+ sizeof(hash256_t)
		+ sizeof(uint32_t)
		+ sizeof(hash256_t) * xmss_num_tree_nodes(height);
	return 1;
}

int xmss_key_generate_ex(XMSS_KEY *key, uint32_t xmss_type,
	const hash256_t seed, const hash256_t secret, const hash256_t sk_prf)
{
	size_t height;
	xmss_adrs_t adrs;

	if (!key || !seed || !secret || !sk_prf) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));
	if (!(key->tree = malloc(sizeof(hash256_t) * xmss_num_tree_nodes(height)))) {
		error_print();
		return -1;
	}

	key->public_key.xmss_type = xmss_type;
	memcpy(key->public_key.seed, seed, sizeof(hash256_t));
	memcpy(key->secret, secret, sizeof(hash256_t));
	memcpy(key->sk_prf, sk_prf, sizeof(hash256_t));

	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	xmss_build_tree(key->secret, key->public_key.seed, adrs, height, key->tree);
	memcpy(key->public_key.root, key->tree[xmss_tree_root_offset(height)], sizeof(hash256_t));
	key->index = 0;
	return 1;
}

int xmss_key_generate(XMSS_KEY *key, uint32_t xmss_type)
{
	int ret = -1;
	hash256_t seed;
	hash256_t secret;
	hash256_t sk_prf;

	if (!key) {
		error_print();
		return -1;
	}
	if (rand_bytes(seed, sizeof(hash256_t)) != 1
		|| rand_bytes(secret, sizeof(hash256_t)) != 1
		|| rand_bytes(sk_prf, sizeof(hash256_t)) != 1) {
		error_print();
		goto end;
	}
	if (xmss_key_generate_ex(key, xmss_type, seed, secret, sk_prf) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(seed, sizeof(seed)); // clear all RNG outputs
	gmssl_secure_clear(secret, sizeof(secret));
	gmssl_secure_clear(sk_prf, sizeof(sk_prf));
	return ret;
}

int xmss_key_update(XMSS_KEY *key)
{
	size_t height;

	if (!key) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(key->public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	if (key->index > (1 << height)) {
		error_print();
		return -1;
	}
	if (key->index == (1 << height)) {
		return 0;
	}
	key->index++;
	return 1;
}

int xmss_key_remaining_signs(const XMSS_KEY *key, size_t *count)
{
	size_t height;
	size_t n;

	if (!key || !count) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(key->public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	n = 1 << height;
	if (key->index > n) {
		error_print();
		return -1;
	}
	*count = n - key->index;
	return 1;
}

void xmss_key_cleanup(XMSS_KEY *key)
{
	if (key) {
		gmssl_secure_clear(key->public_key.seed, sizeof(hash256_t)); // clear all RNG outputs
		gmssl_secure_clear(key->secret, sizeof(hash256_t));
		gmssl_secure_clear(key->sk_prf, sizeof(hash256_t));
		if (key->tree) {
			free(key->tree);
			key->tree = NULL;
		}
	}
}

int xmss_public_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	uint32_to_bytes(key->public_key.xmss_type, out, outlen);
	hash256_to_bytes(key->public_key.root, out, outlen);
	hash256_to_bytes(key->public_key.seed, out, outlen);
	return 1;
}

int xmss_public_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < XMSS_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));

	uint32_from_bytes(&key->public_key.xmss_type, in, inlen);
	if (!xmss_type_name(key->public_key.xmss_type)) {
		error_print();
		return -1;
	}
	hash256_from_bytes(key->public_key.root, in, inlen);
	hash256_from_bytes(key->public_key.seed, in, inlen);
	return 1;
}

int xmss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "type: %s\n", xmss_type_name(key->public_key.xmss_type));
	format_bytes(fp, fmt, ind, "seed", key->public_key.seed, sizeof(hash256_t));
	format_bytes(fp, fmt, ind, "root", key->public_key.root, sizeof(hash256_t));
	return 1;
}

int xmss_private_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen)
{
	size_t height;
	size_t tree_size;

	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (xmss_public_key_to_bytes(key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	uint32_to_bytes(key->index, out, outlen);
	hash256_to_bytes(key->secret, out, outlen);
	hash256_to_bytes(key->sk_prf, out, outlen);

	if (key->tree == NULL) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(key->public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	tree_size = sizeof(hash256_t) * xmss_num_tree_nodes(height);
	if (out && *out) {
		memcpy(*out, key->tree, tree_size);
		*out += tree_size;
	}
	*outlen += tree_size;
	return 1;
}

int xmss_private_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen)
{
	size_t height;
	size_t tree_size;
	xmss_adrs_t adrs;

	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (xmss_public_key_from_bytes(key, in, inlen) != 1) {
		error_print();
		return -1;
	}
	// check inlen without tree
	if (*inlen < sizeof(uint32_t) + sizeof(hash256_t)*2) {
		error_print();
		return -1;
	}

	if (xmss_type_to_height(key->public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	tree_size = sizeof(hash256_t) * xmss_num_tree_nodes(height);

	// prepare buffer (might failure ops) before load secrets
	if (!(key->tree = malloc(tree_size))) {
		error_print();
		return -1;
	}

	// index, allow index == 2^h, which means out-of-keys
	uint32_from_bytes(&key->index, in, inlen);
	if (key->index > (1 << height)) {
		error_print();
		return -1;
	}
	hash256_from_bytes(key->secret, in, inlen);
	hash256_from_bytes(key->sk_prf, in, inlen);

	if (*inlen) {
		// load tree
		if (*inlen < tree_size) {
			error_print();
			return -1;
		}
		memcpy(key->tree, *in, tree_size);
		*in += tree_size;
		*inlen -= tree_size;
	} else {
		// build_tree
		adrs_set_layer_address(adrs, 0);
		adrs_set_tree_address(adrs, 0);
		xmss_build_tree(key->secret, key->public_key.seed, adrs, height, key->tree);
	}

	// check
	if (memcmp(key->tree[xmss_tree_root_offset(height)],
		key->public_key.root, sizeof(hash256_t)) != 0) {
		xmss_key_cleanup(key);
		error_print();
		return -1;
	}
	return 1;
}

int xmss_private_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	xmss_public_key_print(fp, fmt, ind, "public_key", key);
	format_bytes(fp, fmt, ind, "secret", key->secret, sizeof(hash256_t));
	format_bytes(fp, fmt, ind, "sk_prf", key->sk_prf, sizeof(hash256_t));
	format_print(fp, fmt, ind, "index: %"PRIu32"\n", key->index);
	return 1;
}

int xmss_signature_size(uint32_t xmss_type, size_t *siglen)
{
	XMSS_SIGNATURE sig;
	size_t height;

	if (!siglen) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	*siglen = sizeof(sig.index)
		+ sizeof(sig.random)
		+ sizeof(sig.wots_sig)
		+ sizeof(hash256_t) * height;
	return 1;
}

int xmss_signature_from_bytes(XMSS_SIGNATURE *sig, uint32_t xmss_type, const uint8_t **in, size_t *inlen)
{
	size_t height;
	size_t siglen;
	size_t i;

	if (xmss_type_to_height(xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	if (xmss_signature_size(xmss_type, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (*inlen < siglen) {
		error_print();
		return -1;
	}

	uint32_from_bytes(&sig->index, in, inlen);
	hash256_from_bytes(sig->random, in, inlen);
	for (i = 0; i < WOTS_NUM_CHAINS; i++) {
		hash256_from_bytes(sig->wots_sig[i], in, inlen);
	}
	for (i = 0; i < height; i++) {
		hash256_from_bytes(sig->auth_path[i], in, inlen);
	}
	return 1;
}

int xmss_signature_to_bytes(const XMSS_SIGNATURE *sig, uint32_t xmss_type, uint8_t **out, size_t *outlen)
{
	size_t height;
	size_t i;

	if (!sig || !outlen) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	uint32_to_bytes(sig->index, out, outlen);
	hash256_to_bytes(sig->random, out, outlen);
	for (i = 0; i < WOTS_NUM_CHAINS; i++) {
		hash256_to_bytes(sig->wots_sig[i], out, outlen);
	}
	for (i = 0; i < height; i++) {
		hash256_to_bytes(sig->auth_path[i], out, outlen);
	}
	return 1;
}

int xmss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const XMSS_SIGNATURE *sig)
{
	uint32_t xmss_type;
	size_t height;
	size_t i;

	xmss_type = (uint32_t)fmt;
	if (xmss_type_to_height(xmss_type, &height) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "index: %u\n", sig->index);
	format_bytes(fp, fmt, ind, "random", sig->random, 32);
	format_print(fp, fmt, ind, "wots_sig\n");
	for (i = 0; i < 67; i++) {
		format_print(fp, fmt, ind+4, "%d", i);
		format_bytes(fp, fmt, 0, "", sig->wots_sig[i], 32);
	}
	format_print(fp, fmt, ind, "auth_path\n");
	for (i = 0; i < height; i++) {
		format_print(fp, fmt, ind+4, "%d", i);
		format_bytes(fp, fmt, 0, "", sig->auth_path[i], 32);
	}
	return 1;
}

int xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen)
{
	uint32_t index;
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (siglen < 4) {
		error_print();
		return -1;
	}
	index = GETU32(sig);
	format_print(fp, fmt, ind, "index: %u\n", index);
	sig += 4;
	siglen -= 4;


	if (siglen < 32) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "random", sig, 32);
	sig += 32;
	siglen -= 32;

	format_print(fp, fmt, ind, "wots_sig\n");
	for (i = 0; i < 67; i++) {
		if (siglen < 32) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind+4, "%d", i);
		format_bytes(fp, fmt, 0, "", sig, 32);
		sig += 32;
		siglen -= 32;
	}

	format_print(fp, fmt, ind, "auth_path\n");
	for (i = 0; i < XMSS_MAX_HEIGHT && siglen >= 32; i++) {
		format_print(fp, fmt, ind+4, "%d", i);
		format_bytes(fp, fmt, 0, "", sig, 32);
		sig += 32;
		siglen -= 32;
	}

	format_print(fp, fmt, ind, "[%zu bytes left]\n", siglen);

	return 1;
}

void xmss_sign_ctx_cleanup(XMSS_SIGN_CTX *ctx)
{
	if (ctx) {
		gmssl_secure_clear(ctx->xmss_sig.random, sizeof(hash256_t));
		gmssl_secure_clear(ctx->xmss_sig.wots_sig, sizeof(wots_sig_t)); // might cache wots_sk
	}
}

int xmss_sign_init(XMSS_SIGN_CTX *ctx, XMSS_KEY *key)
{
	hash256_t hash256_index = {0};
	xmss_adrs_t adrs;
	size_t height;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(key->public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	// check if out of keys
	if (key->index >= (1 << height)) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));

	// cache public key
	ctx->xmss_public_key = key->public_key;

	// key->index => xmss_sig.index
	ctx->xmss_sig.index = key->index;

	// derive ctx->xmss_sig.random
	PUTU32(hash256_index + 28, key->index);
	// r = PRF(SK_PRF, toByte(idx_sig, 32));
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_three, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, key->sk_prf, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, hash256_index, sizeof(hash256_t));
	hash256_finish(&ctx->hash256_ctx, ctx->xmss_sig.random);

	// wots_sk => ctx->xmss_sig.wots_sig
	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, key->index);
	wots_derive_sk(key->secret, key->public_key.seed, adrs, ctx->xmss_sig.wots_sig);

	// xmss_sig.auth_path
	xmss_build_auth_path(key->tree, height, key->index, ctx->xmss_sig.auth_path);

	// update key->index
	key->index++;

	// H_msg(M) := HASH256(toByte(2, 32) || r || XMSS_ROOT || toByte(idx_sig, 32) || M)
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_two, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, ctx->xmss_sig.random, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, key->public_key.root, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, hash256_index, sizeof(hash256_t));

	return 1;
}

int xmss_sign_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

// TODO: support output *siglen only
int xmss_sign_finish(XMSS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	xmss_adrs_t adrs;
	hash256_t dgst;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	hash256_finish(&ctx->hash256_ctx, dgst);

	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, ctx->xmss_sig.index);

	wots_sign(ctx->xmss_sig.wots_sig, ctx->xmss_public_key.seed, adrs, dgst,
		ctx->xmss_sig.wots_sig);

	*siglen = 0;
	if (xmss_signature_to_bytes(&ctx->xmss_sig, ctx->xmss_public_key.xmss_type, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int xmss_verify_init_ex(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const XMSS_SIGNATURE *sig)
{
	hash256_t hash256_index = {0};

	if (!ctx || !key || !sig) {
		error_print();
		return -1;
	}
	// cache xmss_public_key
	ctx->xmss_public_key = key->public_key;

	// cache xmss_sig
	ctx->xmss_sig = *sig;

	// hash256_init
	PUTU32(hash256_index + 28, ctx->xmss_sig.index);
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_two, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, ctx->xmss_sig.random, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, key->public_key.root, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, hash256_index, sizeof(hash256_t));
	return 1;
}

int xmss_verify_init(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const uint8_t *sig, size_t siglen)
{
	hash256_t hash256_index = {0};

	if (!ctx || !key || !sig || !siglen) {
		error_print();
		return -1;
	}
	// cache xmss_public_key
	ctx->xmss_public_key = key->public_key;

	// parse signature
	if (xmss_signature_from_bytes(&ctx->xmss_sig, key->public_key.xmss_type, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	// hash256_init
	PUTU32(hash256_index + 28, ctx->xmss_sig.index);
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_two, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, ctx->xmss_sig.random, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, key->public_key.root, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, hash256_index, sizeof(hash256_t));
	return 1;
}

int xmss_verify_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

int xmss_verify_finish(XMSS_SIGN_CTX *ctx)
{
	size_t height, h;
	uint32_t index;
	hash256_t dgst;
	xmss_adrs_t adrs;
	hash256_t root;

	if (!ctx) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(ctx->xmss_public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	if (ctx->xmss_sig.index >= (1 << height)) {
		error_print();
		return -1;
	}
	index = ctx->xmss_sig.index;

	// dgst
	hash256_finish(&ctx->hash256_ctx, dgst);

	// wots_sig => wots_pk
	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, ctx->xmss_sig.index);
	wots_sig_to_pk(ctx->xmss_sig.wots_sig, ctx->xmss_public_key.seed, adrs, dgst, ctx->xmss_sig.wots_sig);

	// wots_pk => wots_root
	adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
	adrs_set_ltree_address(adrs, ctx->xmss_sig.index);
	wots_pk_to_root(ctx->xmss_sig.wots_sig, ctx->xmss_public_key.seed, adrs, root);

	// wots_root (index), auth_path => xmss_root
	adrs_set_type(adrs, XMSS_ADRS_TYPE_HASHTREE);
	adrs_set_padding(adrs, 0);
	for (h = 0; h < height; h++) {
		int right_child = index & 1;
		index >>= 1;
		adrs_set_tree_height(adrs, h + 1);
		adrs_set_tree_index(adrs, index);
		if (right_child)
			randomized_tree_hash(ctx->xmss_sig.auth_path[h], root, ctx->xmss_public_key.seed, adrs, root);
		else	randomized_tree_hash(root, ctx->xmss_sig.auth_path[h], ctx->xmss_public_key.seed, adrs, root);
	}

	if (memcmp(root, ctx->xmss_public_key.root, 32) != 0) {
		error_print();
		return 0;
	}
	return 1;
}

char *xmssmt_type_name(uint32_t xmssmt_type)
{
	switch (xmssmt_type) {
	case XMSSMT_HASH256_20_2_256: return XMSSMT_HASH256_20_2_256_NAME;
	case XMSSMT_HASH256_20_4_256: return XMSSMT_HASH256_20_4_256_NAME;
	case XMSSMT_HASH256_40_2_256: return XMSSMT_HASH256_40_2_256_NAME;
	case XMSSMT_HASH256_40_4_256: return XMSSMT_HASH256_40_4_256_NAME;
	case XMSSMT_HASH256_40_8_256: return XMSSMT_HASH256_40_8_256_NAME;
	case XMSSMT_HASH256_60_3_256: return XMSSMT_HASH256_60_3_256_NAME;
	case XMSSMT_HASH256_60_6_256: return XMSSMT_HASH256_60_6_256_NAME;
	case XMSSMT_HASH256_60_12_256: return XMSSMT_HASH256_60_12_256_NAME;
	}
	return NULL;
}

uint32_t xmssmt_type_from_name(const char *name)
{
	if (!strcmp(name, XMSSMT_HASH256_20_2_256_NAME)) {
		return XMSSMT_HASH256_20_2_256;
	} else if (!strcmp(name, XMSSMT_HASH256_20_4_256_NAME)) {
		return XMSSMT_HASH256_20_4_256;
	} else if (!strcmp(name, XMSSMT_HASH256_40_2_256_NAME)) {
		return XMSSMT_HASH256_40_2_256;
	} else if (!strcmp(name, XMSSMT_HASH256_40_4_256_NAME)) {
		return XMSSMT_HASH256_40_4_256;
	} else if (!strcmp(name, XMSSMT_HASH256_40_8_256_NAME)) {
		return XMSSMT_HASH256_40_8_256;
	} else if (!strcmp(name, XMSSMT_HASH256_60_3_256_NAME)) {
		return XMSSMT_HASH256_60_3_256;
	} else if (!strcmp(name, XMSSMT_HASH256_60_6_256_NAME)) {
		return XMSSMT_HASH256_60_6_256;
	} else if (!strcmp(name, XMSSMT_HASH256_60_12_256_NAME)) {
		return XMSSMT_HASH256_60_12_256;
	}
	return 0;
}

int xmssmt_type_to_height_and_layers(uint32_t xmssmt_type, size_t *height, size_t *layers)
{
	if (!height || !layers) {
		error_print();
		return -1;
	}
	switch (xmssmt_type) {
	case XMSSMT_HASH256_20_2_256: *height = 20; *layers = 2; break;
	case XMSSMT_HASH256_20_4_256: *height = 20; *layers = 4; break;
	case XMSSMT_HASH256_40_2_256: *height = 40; *layers = 2; break;
	case XMSSMT_HASH256_40_4_256: *height = 40; *layers = 4; break;
	case XMSSMT_HASH256_40_8_256: *height = 40; *layers = 8; break;
	case XMSSMT_HASH256_60_3_256: *height = 60; *layers = 3; break;
	case XMSSMT_HASH256_60_6_256: *height = 60; *layers = 6; break;
	case XMSSMT_HASH256_60_12_256: *height = 60; *layers = 12; break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

static uint64_t xmssmt_tree_address(uint64_t index, size_t height, size_t layers, size_t layer) {
	return (index >> (height/layers) * (layer + 1));
}

static uint64_t xmssmt_tree_index(uint64_t index, size_t height, size_t layers, size_t layer) {
	return (index >> (height/layers) * layer) % (1 << (height/layers));
}

size_t xmssmt_num_trees_nodes(size_t height, size_t layers)
{
	return xmss_num_tree_nodes(height/layers) * layers;
}

int xmssmt_public_key_to_bytes(const XMSSMT_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	uint32_to_bytes(key->public_key.xmssmt_type, out, outlen);
	hash256_to_bytes(key->public_key.root, out, outlen);
	hash256_to_bytes(key->public_key.seed, out, outlen);
	return 1;
}

int xmssmt_public_key_from_bytes(XMSSMT_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < XMSSMT_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));

	uint32_from_bytes(&key->public_key.xmssmt_type, in, inlen);
	if (!xmssmt_type_name(key->public_key.xmssmt_type)) {
		error_print();
		return -1;
	}
	hash256_from_bytes(key->public_key.root, in, inlen);
	hash256_from_bytes(key->public_key.seed, in, inlen);
	return 1;
}

int xmssmt_private_key_size(uint32_t xmssmt_type, size_t *len)
{
	uint64_t index = 0;
	size_t height;
	size_t layers;

	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	*len = XMSSMT_PUBLIC_KEY_SIZE;
	*len += sizeof(hash256_t);
	*len += sizeof(hash256_t);
	xmssmt_index_to_bytes(index, xmssmt_type, NULL, len);
	*len += sizeof(hash256_t) * xmssmt_num_trees_nodes(height, layers);
	*len += sizeof(wots_sig_t) * (layers - 1);
	return 1;
}

int xmssmt_private_key_to_bytes(const XMSSMT_KEY *key, uint8_t **out, size_t *outlen)
{
	size_t height;
	size_t layers;
	size_t treeslen;

	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}

	if (xmssmt_public_key_to_bytes(key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	xmssmt_index_to_bytes(key->index, key->public_key.xmssmt_type, out, outlen);
	hash256_to_bytes(key->secret, out, outlen);
	hash256_to_bytes(key->sk_prf, out, outlen);

	treeslen = sizeof(hash256_t) * xmssmt_num_trees_nodes(height, layers);
	if (out && *out) {
		memcpy(*out, key->trees, treeslen);
		*out += treeslen;
		memcpy(*out, key->wots_sigs, sizeof(wots_sig_t) * (layers - 1));
		*out += sizeof(wots_sig_t) * (layers - 1);
	}
	*outlen += treeslen;
	*outlen += sizeof(wots_sig_t) * (layers - 1);
	return 1;
}

int xmssmt_private_key_from_bytes(XMSSMT_KEY *key, const uint8_t **in, size_t *inlen)
{
	size_t height;
	size_t layers;
	size_t keylen;
	size_t treeslen;

	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));

	if (xmssmt_public_key_from_bytes(key, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (xmssmt_private_key_size(key->public_key.xmssmt_type, &keylen) != 1) {
		error_print();
		return -1;
	}
	if (*inlen < keylen - XMSSMT_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}

	if (xmssmt_index_from_bytes(&key->index, key->public_key.xmssmt_type, in, inlen) != 1) {
		error_print();
		return -1;
	}
	hash256_from_bytes(key->secret, in, inlen);
	hash256_from_bytes(key->sk_prf, in, inlen);

	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	treeslen = sizeof(hash256_t) * xmssmt_num_trees_nodes(height, layers);
	if (!(key->trees = malloc(treeslen))) {
		error_print();
		return -1;
	}
	memcpy(key->trees, *in, treeslen);
	*in += treeslen;
	*inlen -= treeslen;
	memcpy(key->wots_sigs, *in, sizeof(wots_sig_t) * (layers - 1));
	*in += sizeof(wots_sig_t) * (layers - 1);
	*inlen -= sizeof(wots_sig_t) * (layers - 1);

	return 1;
}

int xmssmt_key_update(XMSSMT_KEY *key)
{
	size_t height;
	size_t layers;
	size_t layer;
	hash256_t *tree;
	uint64_t next_index;
	xmss_adrs_t adrs;
	uint8_t *xmss_root; // FIXME: use hash256_t*

	if (!key) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	if (key->index >= (1 << height)) {
		if (key->index == (1 << height)) {
			return 0;
		}
		error_print();
		return -1;
	}

	next_index = key->index + 1;
	tree = key->trees;

	for (layer = 0; layer < layers - 1; layer++) {
		if (xmssmt_tree_address(next_index, height, layers, layer) ==
			xmssmt_tree_address(key->index, height, layers, layer)) {
			break;
		}

		// generate tree of the layer
		adrs_set_layer_address(adrs, layer);
		adrs_set_tree_address(adrs, xmssmt_tree_address(next_index, height, layers, layer));
		xmss_build_tree(key->secret, key->public_key.seed, adrs, height/layers, tree);

		// sign the new xmss_root
		adrs_set_layer_address(adrs, layer + 1);
		adrs_set_tree_address(adrs, xmssmt_tree_address(next_index, height, layers, layer + 1));
		adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
		adrs_set_ots_address(adrs, xmssmt_tree_index(next_index, height, layers, layer + 1));
		wots_derive_sk(key->secret, key->public_key.seed, adrs, key->wots_sigs[layer]);
		xmss_root = tree[xmss_tree_root_offset(height/layers)];
		wots_sign(key->wots_sigs[layer], key->public_key.seed, adrs, xmss_root, key->wots_sigs[layer]);
		tree += xmss_num_tree_nodes(height/layers);
	}

	key->index++;

	return 1;
}

void xmssmt_key_cleanup(XMSSMT_KEY *key)
{
	if (key) {
		gmssl_secure_clear(key->public_key.seed, sizeof(hash256_t)); // clear all RNG outputs
		gmssl_secure_clear(key->secret, sizeof(hash256_t));
		gmssl_secure_clear(key->sk_prf, sizeof(hash256_t));
		if (key->trees) {
			free(key->trees);
		}
		memset(key, 0, sizeof(XMSSMT_KEY));
	}
}

int xmssmt_key_generate_ex(XMSSMT_KEY *key, uint32_t xmssmt_type,
	const hash256_t seed, const hash256_t secret, const hash256_t sk_prf)
{
	size_t height;
	size_t layers;
	uint32_t layer;
	xmss_adrs_t adrs;
	hash256_t *tree;
	uint8_t *xmss_root;


	uint64_t index = 0;


	uint64_t tree_address;
	uint32_t tree_index;


	if (!key) {
		error_print();
		return -1;
	}
	if (!xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers)) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));

	key->public_key.xmssmt_type = xmssmt_type;


	memcpy(key->public_key.seed, seed, sizeof(hash256_t));
	memcpy(key->secret, secret, sizeof(hash256_t));
	memcpy(key->sk_prf, sk_prf, sizeof(hash256_t));




	key->index = 0;

	// malloc tress
	if (!(key->trees = malloc(xmssmt_num_trees_nodes(height, layers) * sizeof(hash256_t)))) {
		error_print();
		return -1;
	}


	tree = key->trees;

	for (layer = 0; layer < layers; layer++) {

		// generate tree of the layer
		adrs_set_layer_address(adrs, layer);
		adrs_set_tree_address(adrs, xmssmt_tree_address(index, height, layers, layer));
		xmss_build_tree(key->secret, key->public_key.seed, adrs, height/layers, tree);


			xmss_root = tree[xmss_tree_root_offset(height/layers)];
			tree += xmss_num_tree_nodes(height/layers);

		// sign xmss_root with higher layer
		if (layer < layers - 1) {
			adrs_set_layer_address(adrs, layer + 1);
			adrs_set_tree_address(adrs, xmssmt_tree_address(index, height, layers, layer + 1));
			adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
			adrs_set_ots_address(adrs, xmssmt_tree_index(index, height, layers, layer + 1));
			wots_derive_sk(key->secret, key->public_key.seed, adrs, key->wots_sigs[layer]);


			/*
			hash256_t *tree2 = key->trees + xmss_num_tree_nodes(height/layers) * layer;
			hash256_t xmss_root2 = tree2[xmss_tree_root_offset(height/layers)];


			fprintf(stderr, "%p %p\n", tree, tree2);
			fprintf(stderr, "%p %p\n", xmss_root, xmss_root2);
			*/


			wots_sign(key->wots_sigs[layer], key->public_key.seed, adrs, xmss_root, key->wots_sigs[layer]);
		}
	}

	// copy the top-level root
	memcpy(key->public_key.root, xmss_root, sizeof(hash256_t));

	tree = key->trees;


	hash256_t root;

	wots_key_t wots_pk;

	// extra check

	for (layer = 0; layer < layers - 1; layer++) {
		uint8_t *dgst = tree[xmss_tree_root_offset(height/layers)];

		tree_address = xmssmt_tree_address(index, height, layers, layer + 1);
		tree_index = xmssmt_tree_index(index, height, layers, layer + 1);

		adrs_set_layer_address(adrs, layer + 1);
		adrs_set_tree_address(adrs, tree_address);
		adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
		adrs_set_ots_address(adrs, tree_index);

		wots_sig_to_pk(key->wots_sigs[layer], key->public_key.seed, adrs, dgst, wots_pk);


		adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
		adrs_set_tree_index(adrs, tree_index);
		wots_pk_to_root(wots_pk, key->public_key.seed, adrs, root);

		tree += xmss_num_tree_nodes(height/layers);

		if (memcmp(root, tree[0], 32) != 0) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int xmssmt_key_generate(XMSSMT_KEY *key, uint32_t xmssmt_type)
{

	hash256_t seed;
	hash256_t secret;
	hash256_t sk_prf;


	if (rand_bytes(seed, sizeof(hash256_t)) != 1) {
		error_print();
		return -1;
	}

	if (rand_bytes(secret, sizeof(hash256_t)) != 1) {
		error_print();
		return -1;
	}
	if (rand_bytes(sk_prf, sizeof(hash256_t)) != 1) {
		error_print();
		return -1;
	}

	if (xmssmt_key_generate_ex(key, xmssmt_type, seed, secret, sk_prf) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

// not checked
int xmssmt_build_auth_path(const hash256_t *tree, size_t height, size_t layers, uint64_t index, hash256_t *auth_path)
{
	size_t i;

	if (!tree || !auth_path) {
		error_print();
		return -1;
	}

	for (i = 0; i < layers; i++) {
		uint64_t local_index = index & ((1 << (height/layers)) - 1);
		xmss_build_auth_path(tree, height/layers, local_index, auth_path);
		auth_path += height/layers;
		index >>= height/layers;
		tree += xmss_num_tree_nodes(height/layers);
	}

	return 1;
}

int xmssmt_public_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "type: %s\n", xmssmt_type_name(key->public_key.xmssmt_type));
	format_bytes(fp, fmt, ind, "seed", key->public_key.seed, 32);
	format_bytes(fp, fmt, ind, "root", key->public_key.root, 32);
	return 1;
}

int xmssmt_private_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_KEY *key)
{
	size_t height;
	size_t layers;
	hash256_t *tree;
	size_t i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	xmssmt_public_key_print(fp, fmt, ind, "public_key", key);
	format_bytes(fp, fmt, ind, "secret", key->secret, 32);
	format_bytes(fp, fmt, ind, "sk_prf", key->sk_prf, 32);
	format_print(fp, fmt, ind, "index: %u\n", key->index);

	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	/*
	for (i = 0; i < layers - 1; i++) {
		size_t j;
		format_print(fp, fmt, ind, "wots_sig\n");
		for (j = 0; j < 67; j++) {
			format_bytes(stderr, 0, ind+4, "", key->wots_sigs[i][j], sizeof(hash256_t));
		}
	}
	*/

	tree = key->trees;
	for (i = 0; i < layers; i++) {
		char label[64];
		snprintf(label, sizeof(label), "xmss_root[%zu]", i);
		format_bytes(fp, fmt, ind, label, tree[xmss_tree_root_offset(height/layers)], 32);
		tree += xmss_num_tree_nodes(height/layers);
	}

	return 1;
}

int xmssmt_index_to_bytes(uint64_t index, uint32_t xmssmt_type, uint8_t **out, size_t *outlen)
{
	size_t height;
	size_t layers;
	uint8_t bytes[8];
	size_t nbytes;

	if (!outlen) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	if (index >= ((uint64_t)1 << height)) {
		error_print();
		return -1;
	}

	nbytes = (height + 7)/8;
	if (out && *out) {
		PUTU64(bytes, index);
		memcpy(*out, bytes + 8 - nbytes, nbytes);
		*out += nbytes;
	}
	*outlen += nbytes;
	return 1;
}

int xmssmt_index_from_bytes(uint64_t *index, uint32_t xmssmt_type, const uint8_t **in, size_t *inlen)
{
	size_t height;
	size_t layers;
	uint8_t bytes[8] = {0};
	size_t nbytes;

	if (!index || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	nbytes = (height + 7)/8;
	if (*inlen < nbytes) {
		error_print();
		return -1;
	}

	memcpy(bytes + 8 - nbytes, *in, nbytes);
	*in += nbytes;
	*inlen -= nbytes;

	*index = GETU64(bytes);

	// check value in [0, 2^height], 2^height means out of keys
	if (*index > (1 << height)) {
		error_print();
		return -1;
	}
	return 1;
}

int xmssmt_signature_size(uint32_t xmssmt_type, size_t *siglen)
{
	size_t height;
	size_t layers;

	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	if (!siglen) {
		error_print();
		return -1;
	}
	*siglen = 0;

	if (xmssmt_index_to_bytes(0, xmssmt_type, NULL, siglen) != 1) {
		error_print();
		return -1;
	}
	*siglen += sizeof(hash256_t);
	*siglen += sizeof(wots_sig_t) * layers;
	*siglen += sizeof(hash256_t) * height;
	return 1;
}

int xmssmt_signature_to_bytes(const XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type, uint8_t **out, size_t *outlen)
{
	size_t height;
	size_t layers;
	size_t i;

	if (!sig) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}

	if (out && *out) {
		if (xmssmt_index_to_bytes(sig->index, xmssmt_type, out, outlen) != 1) {
			error_print();
			return -1;
		}
		hash256_to_bytes(sig->random, out, outlen);
		size_t layer;

		for (layer = 0; layer < layers; layer++) {
			for (i = 0; i < 67; i++) {
				hash256_to_bytes(sig->wots_sigs[layer][i], out, outlen);
			}
			for (i = 0; i < height/layers; i++) {
				hash256_to_bytes(sig->auth_path[(height/layers) * layer + i], out, outlen);
			}
		}
	}

	return 1;
}

int xmssmt_signature_from_bytes(XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type, const uint8_t **in, size_t *inlen)
{
	size_t height;
	size_t layers;
	size_t siglen;
	size_t layer;
	size_t i;

	if (!sig || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	if (xmssmt_signature_size(xmssmt_type, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (*inlen < siglen) {
		error_print();
		return -1;
	}


	// index
	if (xmssmt_index_from_bytes(&sig->index, xmssmt_type, in, inlen) != 1) {
		error_print();
		return -1;
	}

	// random
	hash256_from_bytes(sig->random, in, inlen);

	for (layer = 0; layer < layers; layer++) {
		int i;
		// wots_sig
		for (i = 0; i < 67; i++) {
			hash256_from_bytes(sig->wots_sigs[layer][i], in, inlen);
		}
		// auth_path
		for (i = 0; i < height/layers; i++) {
			hash256_from_bytes(sig->auth_path[(height/layers) * layer + i], in, inlen);
		}
	}

	return 1;
}

int xmssmt_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type)
{
	size_t height;
	size_t layers;
	size_t layer;
	size_t i;

	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	format_print(fp, fmt, ind, "index: %"PRIu64"\n", sig->index);
	format_bytes(fp, fmt, ind, "random", sig->random, 32);

	for (layer = 0; layer < layers; layer++) {
		format_print(fp, fmt, ind, "redurced_xmss_signature[%zu]\n", layer);
		format_print(fp, fmt, ind+4, "wots_sig\n");
		for (i = 0; i < 67; i++) {
			format_print(fp, fmt, ind+8, "%d", i);
			format_bytes(fp, fmt, 0, "", sig->wots_sigs[layer][i], 32);
		}

		format_print(fp, fmt, ind+4, "auth_path\n");
		for (i = 0; i < height/layers; i++) {
			format_print(fp, fmt, ind+8, "%d", i);
			format_bytes(fp, fmt, 0, "", sig->auth_path[(height/layers) * layer + i], 32);
		}
	}
	return 1;
}

int xmssmt_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen, uint32_t xmssmt_type)
{
	size_t height;
	size_t layers;
	uint64_t index;
	size_t layer;
	size_t i;

	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (xmssmt_index_from_bytes(&index, xmssmt_type, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	//format_print(fp, fmt, ind, "index: %u"PRIu64"\n", index);
	format_print(fp, fmt, ind, "index: %llu\n", (unsigned long long)index);

	if (siglen < sizeof(hash256_t)) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "random", sig, sizeof(hash256_t));
	sig += sizeof(hash256_t);
	siglen -= sizeof(hash256_t);

	for (layer = 0; layer < layers; layer++) {
		format_print(fp, fmt, ind, "redurced_xmss_signature[%zu]\n", layer);
		format_print(fp, fmt, ind+4, "wots_sig\n");
		for (i = 0; i < 67; i++) {
			format_print(fp, fmt, ind+4, "%d ", i);
			if (siglen < sizeof(hash256_t)) {
				error_print();
				return -1;
			}
			format_bytes(fp, fmt, 0, "", sig, sizeof(hash256_t));
			sig += sizeof(hash256_t);
			siglen -= sizeof(hash256_t);
		}
		format_print(fp, fmt, ind+4, "auth_path\n");
		for (i = 0; i < height/layers; i++) {
			format_print(fp, fmt, ind+8, "%d ", i);
			if (siglen < sizeof(hash256_t)) {
				error_print();
				return -1;
			}
			format_bytes(fp, fmt, 0, "", sig, sizeof(hash256_t));
			sig += sizeof(hash256_t);
			siglen -= sizeof(hash256_t);
		}
	}
	if (siglen) {
		error_print();
		return -1;
	}
	return 1;
}

void xmssmt_sign_ctx_cleanup(XMSSMT_SIGN_CTX *ctx)
{
	if (ctx) {
		gmssl_secure_clear(ctx->xmssmt_sig.random, sizeof(hash256_t));
		gmssl_secure_clear(ctx->xmssmt_sig.wots_sigs[0], sizeof(wots_sig_t));
	}
}

int xmssmt_sign_init(XMSSMT_SIGN_CTX *ctx, XMSSMT_KEY *key)
{
	size_t height;
	size_t layers;
	size_t layer;
	uint64_t tree_address;
	uint32_t tree_index;
	hash256_t hash256_index;
	xmss_adrs_t adrs;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}

	if (key->index >= (1 << height)) {
		error_print();
		return -1;
	}

	// init sign ctx
	memset(ctx, 0, sizeof(XMSSMT_SIGN_CTX));

	// set ctx->xmssmt_public_key
	ctx->xmssmt_public_key = key->public_key;

	// copy index
	ctx->xmssmt_sig.index = key->index;

	// copy wots_sigs[1] to wots_sig[layers - 1] from key
	for (layer = 1; layer < layers; layer++) {
		memcpy(ctx->xmssmt_sig.wots_sigs[layer], key->wots_sigs[layer - 1], sizeof(wots_sig_t));
	}

	// build auth_path
	for (layer = 0; layer < layers; layer++) {
		hash256_t *tree;
		hash256_t *auth_path;
		tree = key->trees + xmss_num_tree_nodes(height/layers) * layer;
		tree_index = xmssmt_tree_index(ctx->xmssmt_sig.index, height, layers, layer);
		auth_path = ctx->xmssmt_sig.auth_path + (height/layers) * layer;
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


	xmssmt_key_update(key);

	return 1;
}

int xmssmt_sign_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

int xmssmt_sign_finish_ex(XMSSMT_SIGN_CTX *ctx, XMSSMT_SIGNATURE *sig)
{
	// generate message wots_sig as wots_sigs[0]
	size_t height;
	size_t layers;
	size_t layer = 0;
	uint64_t tree_address;
	uint32_t tree_index;
	xmss_adrs_t adrs;
	hash256_t dgst;

	if (!ctx || !sig) {
		error_print();
		return -1;
	}

	hash256_finish(&ctx->hash256_ctx, dgst);

	if (xmssmt_type_to_height_and_layers(ctx->xmssmt_public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	tree_address = xmssmt_tree_address(ctx->xmssmt_sig.index, height, layers, layer);
	tree_index = xmssmt_tree_index(ctx->xmssmt_sig.index, height, layers, layer);

	adrs_set_layer_address(adrs, layer);
	adrs_set_tree_address(adrs, tree_address);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, tree_index);
	wots_sign(ctx->xmssmt_sig.wots_sigs[0], ctx->xmssmt_public_key.seed, adrs, dgst,
		ctx->xmssmt_sig.wots_sigs[0]);


	*sig = ctx->xmssmt_sig;
	return 1;
}

int xmssmt_sign_finish(XMSSMT_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	XMSSMT_SIGNATURE signature;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (xmssmt_sign_finish_ex(ctx, &signature) != 1) {
		error_print();
		return -1;
	}

	*siglen = 0;
	if (xmssmt_signature_to_bytes(&ctx->xmssmt_sig, ctx->xmssmt_public_key.xmssmt_type, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int xmssmt_verify_init_ex(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const XMSSMT_SIGNATURE *sig)
{
	hash256_t hash256_index;
	xmss_adrs_t adrs;

	if (!ctx || !key || !sig) {
		error_print();
		return -1;
	}

	// init sign ctx
	memset(ctx, 0, sizeof(XMSSMT_SIGN_CTX));

	// set ctx->xmssmt_public_key
	ctx->xmssmt_public_key = key->public_key;

	// copy ctx->xmssmt_sig
	ctx->xmssmt_sig = *sig;

	memset(hash256_index, 0, 24);
	PUTU64(hash256_index + 24, ctx->xmssmt_sig.index);

	// H_msg(M) := HASH256(toByte(2, 32) || r || XMSS_ROOT || toByte(idx_sig, 32) || M)
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_two, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, ctx->xmssmt_sig.random, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, key->public_key.root, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, hash256_index, sizeof(hash256_t));

	return 1;
}

// check compatible publickey and sig				
int xmssmt_verify_init(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const uint8_t *sig, size_t siglen)
{
	hash256_t hash256_index;
	xmss_adrs_t adrs;
	if (!ctx || !key || !sig) {
		error_print();
		return -1;
	}

	// init sign ctx
	memset(ctx, 0, sizeof(XMSSMT_SIGN_CTX));

	// set ctx->xmssmt_public_key
	ctx->xmssmt_public_key = key->public_key;


	if (xmssmt_signature_from_bytes(&ctx->xmssmt_sig, key->public_key.xmssmt_type, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}


	memset(hash256_index, 0, 24);
	PUTU64(hash256_index + 24, ctx->xmssmt_sig.index);

	// H_msg(M) := HASH256(toByte(2, 32) || r || XMSS_ROOT || toByte(idx_sig, 32) || M)
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_two, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, ctx->xmssmt_sig.random, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, key->public_key.root, sizeof(hash256_t));
	hash256_update(&ctx->hash256_ctx, hash256_index, sizeof(hash256_t));

	return 1;
}

int xmssmt_verify_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

int xmssmt_verify_finish(XMSSMT_SIGN_CTX *ctx)
{
	size_t height;
	size_t layers;
	size_t layer;
	xmss_adrs_t adrs;
	hash256_t dgst;

	hash256_finish(&ctx->hash256_ctx, dgst);

	if (xmssmt_type_to_height_and_layers(ctx->xmssmt_public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}

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

	return 1;
}
