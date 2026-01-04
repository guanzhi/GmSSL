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


// TODO: not here
static uint8_t bn256_zero[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t bn256_one[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

static const uint8_t bn256_two[] = {
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
	format_print(fp, fmt, ind, "tree_address: %"PRIu64"\n", tree_address);

	type = GETU32(adrs);
	adrs += 4;
	format_print(fp, fmt, ind, "type: %"PRIu32"\n", type);

	if (type == XMSS_ADRS_TYPE_OTS) {
		uint32_t ots_address;
		uint32_t chain_address;
		uint32_t hash_address;

		ots_address = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "ots_address: %"PRIu32"\n", ots_address);
		chain_address = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "chain_address: %"PRIu32"\n", chain_address);
		hash_address = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "hash_address: %"PRIu32"\n", hash_address);
	} else if (type == XMSS_ADRS_TYPE_LTREE) {
		uint32_t ltree_address;
		uint32_t tree_height;
		uint32_t tree_index;

		ltree_address = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "ltree_address: %"PRIu32"\n", ltree_address);
		tree_height = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "tree_height: %"PRIu32"\n", tree_height);
		tree_index = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "tree_index: %"PRIu32"\n", tree_index);
	} else if (type == XMSS_ADRS_TYPE_HASHTREE) {
		uint32_t padding;
		uint32_t tree_height;
		uint32_t tree_index;

		padding = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "padding: %"PRIu32"\n", padding);
		tree_height = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "tree_height: %"PRIu32"\n", tree_height);
		tree_index = GETU32(adrs);
		adrs += 4;
		format_print(fp, fmt, ind, "tree_index: %"PRIu32"\n", tree_index);
	} else {
		error_print();
	}

	key_and_mask = GETU32(adrs);
	adrs += 4;
	format_print(fp, fmt, ind, "key_and_mask: %"PRIu32"\n", key_and_mask);

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
	int i;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);

	for (i = 0; i < 67; i++) {
		adrs_set_chain_address(adrs, i);
		adrs_set_hash_address(adrs, 0);
		adrs_set_key_and_mask(adrs, 0);

		hash256_init(&ctx);
		hash256_update(&ctx, hash256_four, sizeof(hash256_t));
		hash256_update(&ctx, secret, sizeof(hash256_t));
		hash256_update(&ctx, seed, sizeof(hash256_t));
		hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
		hash256_finish(&ctx, sk[i]);
	}
}

void wots_chain(const hash256_t x,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	int start, int steps, hash256_t pk)
{
	HASH256_CTX ctx;
	uint8_t adrs[32];
	int i;

	//assert(start >= 0 && start <= 15);
	//assert(steps >= 0 && steps <= 15);
	//assert(start + steps <= 15);

	memcpy(pk, x, 32);

	// 4 * 6 = 24, copy 24 bytes
	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);
	adrs_copy_chain_address(adrs, ots_adrs);

	for (i = start; i < start + steps; i++) {
		uint8_t key[32];
		uint8_t bitmask[32];

		adrs_set_hash_address(adrs, i);

		// key = prf(seed, adrs)
		adrs_set_key_and_mask(adrs, XMSS_ADRS_GENERATE_KEY);
		hash256_init(&ctx);
		hash256_update(&ctx, hash256_three, 32);
		hash256_update(&ctx, seed, 32);
		hash256_update(&ctx, adrs, 32);
		hash256_finish(&ctx, key);

		// bitmask = prf(seed, adrs)
		adrs_set_key_and_mask(adrs, XMSS_ADRS_GENERATE_BITMASK);
		hash256_init(&ctx);
		hash256_update(&ctx, hash256_three, 32);
		hash256_update(&ctx, seed, 32);
		hash256_update(&ctx, adrs, 32);
		hash256_finish(&ctx, bitmask);

		// tmp = f(key, tmp xor bitmask)
		gmssl_memxor(pk, pk, bitmask, 32);
		hash256_init(&ctx);
		hash256_update(&ctx, bn256_zero, 32);
		hash256_update(&ctx, key, 32);
		hash256_update(&ctx, pk, 32);
		hash256_finish(&ctx, pk);
	}

}

void wots_sk_to_pk(const wots_key_t sk,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	wots_key_t pk)
{
	xmss_adrs_t adrs;
	int i;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);

	for (i = 0; i < 67; i++) {
		adrs_set_chain_address(adrs, i);
		wots_chain(sk[i], seed, adrs, 0, 15, pk[i]);
	}
}

// seperate 256 bit digest into 256/4 = 64 step values, generate 3 checksum step values
// output steps[i] in [0, w-1] = [0, 16-1]
static void base_w_and_checksum(const hash256_t dgst, uint8_t steps[67])
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
	const hash256_t seed, const xmss_adrs_t wots_adrs,
	const hash256_t dgst, wots_key_t sig)
{
	hash256_t adrs;
	uint8_t steps[WOTS_NUM_CHAINS];
	int i;

	adrs_copy_layer_address(adrs, wots_adrs);
	adrs_copy_tree_address(adrs, wots_adrs);
	adrs_copy_type(adrs, wots_adrs);
	adrs_copy_ots_address(adrs, wots_adrs);

	base_w_and_checksum(dgst, steps);

	for (i = 0; i < WOTS_NUM_CHAINS; i++) {
		adrs_set_chain_address(adrs, i);
		wots_chain(sk[i], seed, adrs, 0, steps[i], sig[i]);
	}
}

void wots_sig_to_pk(const wots_sig_t sig,
	const hash256_t seed, const xmss_adrs_t ots_adrs,
	const hash256_t dgst, wots_key_t pk)
{
	hash256_t adrs;
	uint8_t steps[67];
	int i;

	adrs_copy_layer_address(adrs, ots_adrs);
	adrs_copy_tree_address(adrs, ots_adrs);
	adrs_copy_type(adrs, ots_adrs);
	adrs_copy_ots_address(adrs, ots_adrs);

	base_w_and_checksum(dgst, steps);

	for (i = 0; i < 67; i++) {
		adrs_set_chain_address(adrs, i);
		wots_chain(sig[i], seed, adrs, steps[i], 15 - steps[i], pk[i]);
	}
}

// TODO: need test and test vector
static void randomized_tree_hash(const hash256_t left_child, const hash256_t right_child,
	const hash256_t seed, const xmss_adrs_t tree_adrs,
	hash256_t parent)
{
	HASH256_CTX ctx;
	xmss_adrs_t adrs;
	hash256_t key;
	hash256_t bm_0;
	hash256_t bm_1;

	// copy adrs (and set the last key_and_mask)
	adrs_copy_layer_address(adrs, tree_adrs);
	adrs_copy_tree_address(adrs, tree_adrs);
	adrs_copy_type(adrs, tree_adrs);
	adrs_copy_ltree_address(adrs, tree_adrs);
	adrs_copy_tree_height(adrs, tree_adrs);
	adrs_copy_tree_index(adrs, tree_adrs);

	adrs_set_key_and_mask(adrs, 0);
	// key = prf(seed, adrs)
	hash256_init(&ctx);
	hash256_update(&ctx, hash256_three, sizeof(hash256_t));
	hash256_update(&ctx, seed, sizeof(hash256_t));
	hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
	hash256_finish(&ctx, key);

	adrs_set_key_and_mask(adrs, 1);
	// bm_0 = prf(seed, adrs)
	hash256_init(&ctx);
	hash256_update(&ctx, hash256_three, sizeof(hash256_t));
	hash256_update(&ctx, seed, sizeof(hash256_t));
	hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
	hash256_finish(&ctx, bm_0);

	adrs_set_key_and_mask(adrs, 2);
	// bm_1 = prf(seed, adrs)
	hash256_init(&ctx);
	hash256_update(&ctx, hash256_three, sizeof(hash256_t));
	hash256_update(&ctx, seed, sizeof(hash256_t));
	hash256_update(&ctx, adrs, sizeof(xmss_adrs_t));
	hash256_finish(&ctx, bm_1);

	// parent = Hash( tobyte(1, 32) || key || (left xor bm_0) || (right xor bm_1) )
	gmssl_memxor(bm_0, bm_0, left_child, sizeof(hash256_t));
	gmssl_memxor(bm_1, bm_1, right_child, sizeof(hash256_t));
	hash256_init(&ctx);
	hash256_update(&ctx, bn256_one, sizeof(hash256_t));
	hash256_update(&ctx, key, sizeof(hash256_t));
	hash256_update(&ctx, bm_0, sizeof(hash256_t));
	hash256_update(&ctx, bm_1, sizeof(hash256_t));
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
	adrs_copy_type(adrs, in_adrs); // type must be LTREE			
	adrs_copy_ltree_address(adrs, in_adrs);

	adrs_set_tree_height(adrs, tree_height++);

	while (len > 1) {
		for (i = 0; i < (uint32_t)len/2; i++) {
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
	const hash256_t seed, const xmss_adrs_t in_adrs,
	const hash256_t dgst, const wots_sig_t sig)
{
	xmss_adrs_t adrs;
	wots_key_t pk;
	hash256_t root;

	adrs_copy_layer_address(adrs, in_adrs);
	adrs_copy_tree_address(adrs, in_adrs);

	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_copy_ots_address(adrs, in_adrs);
	wots_sig_to_pk(sig, seed, adrs, dgst, pk);

	adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
	adrs_copy_ltree_address(adrs, in_adrs);
	wots_pk_to_root(pk, seed, adrs, root);

	if (memcmp(root, wots_root, sizeof(hash256_t)) == 0) {
		return 1;
	} else {
		return 0;
	}
}

// adrs: layer_address, tree_address, ots_address or ltree_address should be set
void wots_derive_root(const hash256_t secret,
	const hash256_t seed, const xmss_adrs_t adrs,
	hash256_t wots_root)
{
	wots_key_t wots_key;
	xmss_adrs_t wots_adrs;
	xmss_adrs_t ltree_adrs;

	adrs_copy_layer_address(wots_adrs, adrs);
	adrs_copy_tree_address(wots_adrs, adrs);
	adrs_set_type(wots_adrs, XMSS_ADRS_TYPE_OTS);
	adrs_copy_ots_address(wots_adrs, adrs);

	wots_derive_sk(secret, seed, wots_adrs, wots_key);
	wots_sk_to_pk(wots_key, seed, wots_adrs, wots_key);

	adrs_copy_layer_address(ltree_adrs, adrs);
	adrs_copy_tree_address(ltree_adrs, adrs);
	adrs_set_type(ltree_adrs, XMSS_ADRS_TYPE_LTREE);
	adrs_copy_ltree_address(ltree_adrs, adrs); // ltree_address == ots_address

	wots_pk_to_root(wots_key, seed, ltree_adrs, wots_root);
}

static size_t tree_root_offset(size_t height) {
	return (1 << (height + 1)) - 2;
}

// 2^(height + 1) - 1
void xmss_build_tree(const hash256_t secret,
	const hash256_t seed, const xmss_adrs_t tree_adrs,
	size_t height, hash256_t *tree)
{
	xmss_adrs_t adrs;
	hash256_t *children;
	hash256_t *parents;
	size_t n = 1 << height;
	size_t h;
	size_t i;

	adrs_copy_layer_address(adrs, tree_adrs);
	adrs_copy_tree_address(adrs, tree_adrs);

	// derive 2^h wots+ roots as leaves of xmss tree
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	//fprintf(stderr, "xmss_build_tree() progress\n");
	for (i = 0; i < n; i++) {
		adrs_set_ots_address(adrs, i);
		wots_derive_root(secret, seed, adrs, tree[i]);
		/*
		if (i % (n/100) == 0 && i/(n/100) <= 100) {
			fprintf(stderr, " %zu%%\n", i/(n/100)       );
		}
		*/
	}

	// build xmss tree
	adrs_set_type(adrs, XMSS_ADRS_TYPE_HASHTREE);
	adrs_set_padding(adrs, 0);
	adrs_set_key_and_mask(adrs, 0);

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

void xmss_do_sign(const hash256_t secret, uint32_t index,
	const hash256_t seed, const xmss_adrs_t in_adrs,
	const hash256_t dgst, wots_sig_t wots_sig)
{
	xmss_adrs_t adrs;

	adrs_copy_layer_address(adrs, in_adrs);
	adrs_copy_tree_address(adrs, in_adrs);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, index);

	wots_derive_sk(secret, seed, adrs, wots_sig);
	wots_sign(wots_sig, seed, adrs, dgst, wots_sig);
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

static uint64_t xmssmt_tree_address(uint64_t index, size_t height, size_t layers, size_t layer) {
	return (index >> (height/layers) * (layer + 1));
}

static uint64_t xmssmt_tree_index(uint64_t index, size_t height, size_t layers, size_t layer) {
	return (index >> (height/layers) * layer) % (1 << (height/layers));
}



void xmss_build_root(const hash256_t wots_root, uint32_t tree_index,
	const hash256_t seed, const xmss_adrs_t in_adrs,
	const hash256_t *auth_path, size_t height,
	hash256_t root)
{
	xmss_adrs_t adrs;
	size_t h;

	adrs_copy_layer_address(adrs, in_adrs);
	adrs_copy_tree_address(adrs, in_adrs);

	adrs_set_type(adrs, XMSS_ADRS_TYPE_HASHTREE);
	adrs_set_padding(adrs, 0);
	adrs_set_key_and_mask(adrs, 0);

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

// remove this function
void xmss_sig_to_root(const hash256_t wots_sig[67],
	const uint8_t seed[32], const uint8_t in_adrs[32],
	const uint8_t dgst[32],
	const hash256_t *auth_path, int height,
	uint8_t xmss_root[32])
{
	xmss_adrs_t adrs;
	wots_key_t wots_pk;
	uint8_t *node = xmss_root;
	int h;
	uint32_t index;

	// wots_sig to wots_pk
	adrs_copy_layer_address(adrs, in_adrs);
	adrs_copy_tree_address(adrs, in_adrs);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_copy_ots_address(adrs, in_adrs);
	wots_sig_to_pk(wots_sig, seed, adrs, dgst, wots_pk);

	// wots_pk to wots_root
	adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
	adrs_copy_ltree_address(adrs, in_adrs);
	wots_pk_to_root(wots_pk, seed, adrs, xmss_root);

	index = GETU32(in_adrs + 16);

	// wots_root, auth_path => xmss_root
	adrs_set_type(adrs, XMSS_ADRS_TYPE_HASHTREE);
	adrs_set_padding(adrs, 0);
	adrs_set_key_and_mask(adrs, 0);

	for (h = 0; h < height; h++) {
		int right = index & 1;
		index >>= 1;
		adrs_set_tree_height(adrs, h);
		adrs_set_tree_index(adrs, index);
		if (right)
			randomized_tree_hash(auth_path[h], node, seed, adrs, node);
		else	randomized_tree_hash(node, auth_path[h], seed, adrs, node);
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

int xmss_key_generate(XMSS_KEY *key, uint32_t xmss_type)
{
	size_t height;
	size_t tree_nodes; // = 2^(h + 1) - 1
	xmss_adrs_t adrs;

	if (!key) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));

	key->public_key.xmss_type = xmss_type;

	if (rand_bytes(key->public_key.seed, 32) != 1
		|| rand_bytes(key->secret, 32) != 1
		|| rand_bytes(key->sk_prf, 32) != 1) {
		error_print();
		return -1;
	}
	tree_nodes = (1 << height) * 2 - 1;
	if (!(key->tree = malloc(sizeof(hash256_t) * tree_nodes))) {
		error_print();
		return -1;
	}

	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	xmss_build_tree(key->secret, key->public_key.seed, adrs, height, key->tree);
	memcpy(key->public_key.root, key->tree[tree_root_offset(height)], sizeof(hash256_t));
	key->index = 0;
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
		gmssl_secure_clear(key->secret, sizeof(hash256_t));
		gmssl_secure_clear(key->sk_prf, sizeof(hash256_t));
		if (key->tree) {
			free(key->tree);
		}
		memset(key, 0, sizeof(*key));
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
	format_bytes(fp, fmt, ind, "seed", key->public_key.seed, 32);
	format_bytes(fp, fmt, ind, "root", key->public_key.root, 32);
	return 1;
}


int xmss_private_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	uint32_to_bytes(key->public_key.xmss_type, out, outlen);
	hash256_to_bytes(key->public_key.root, out, outlen);
	hash256_to_bytes(key->public_key.seed, out, outlen);
	uint32_to_bytes(key->index, out, outlen);
	hash256_to_bytes(key->secret, out, outlen);
	hash256_to_bytes(key->sk_prf, out, outlen);
	return 1;
}

int xmss_private_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen)
{
	size_t height;
	size_t tree_nodes;
	xmss_adrs_t adrs;

	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < XMSS_PRIVATE_KEY_SIZE) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));

	// xmss_type
	uint32_from_bytes(&key->public_key.xmss_type, in, inlen);
	if (xmss_type_to_height(key->public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	// root
	hash256_from_bytes(key->public_key.root, in, inlen);
	// seed
	hash256_from_bytes(key->public_key.seed, in, inlen);

	// index, allow index == 2^h, which means out-of-keys
	uint32_from_bytes(&key->index, in, inlen);
	if (key->index > (1 << height)) {
		error_print();
		return -1;
	}
	// prepare buffer (might failure ops) before load secrets
	tree_nodes = (1 << (height + 1)) - 1;
	if (!(key->tree = malloc(sizeof(hash256_t) * tree_nodes))) {
		error_print();
		return -1;
	}

	// secret
	hash256_from_bytes(key->secret, in, inlen);
	// sk_prf
	hash256_from_bytes(key->sk_prf, in, inlen);

	// build_tree
	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	xmss_build_tree(key->secret, key->public_key.seed, adrs, height, key->tree);
	// check
	if (memcmp(key->tree[tree_root_offset(height)],
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
	format_print(fp, fmt, ind, "type: %s\n", xmss_type_name(key->public_key.xmss_type));
	format_bytes(fp, fmt, ind, "seed", key->public_key.seed, 32);
	format_bytes(fp, fmt, ind, "root", key->public_key.root, 32);
	format_bytes(fp, fmt, ind, "secret", key->secret, 32);
	format_bytes(fp, fmt, ind, "sk_prf", key->sk_prf, 32);
	format_print(fp, fmt, ind, "index: %u\n", key->index);
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

int xmss_signature_from_bytes(uint32_t xmss_type, XMSS_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
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
	for (i = 0; i < 67; i++)
		hash256_from_bytes(sig->wots_sig[i], in, inlen);
	for (i = 0; i < height; i++)
		hash256_from_bytes(sig->auth_path[i], in, inlen);

	return 1;
}

int xmss_signature_to_bytes(uint32_t xmss_type, const XMSS_SIGNATURE *sig, uint8_t **out, size_t *outlen)
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
	for (i = 0; i < 67; i++) {
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
		format_print(fp, fmt, ind+4, "%d ", i);
		format_bytes(fp, fmt, 0, "", sig->wots_sig[i], 32);
	}
	format_print(fp, fmt, ind, "auth_path\n");
	for (i = 0; i < height; i++) {
		format_print(fp, fmt, ind+4, "%d ", i);
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
		format_print(fp, fmt, ind+4, "%d ", i);
		format_bytes(fp, fmt, 0, "", sig, 32);
		sig += 32;
		siglen -= 32;
	}

	format_print(fp, fmt, ind, "auth_path\n");
	for (i = 0; i < XMSS_MAX_HEIGHT && siglen >= 32; i++) {
		format_print(fp, fmt, ind+4, "%d ", i);
		format_bytes(fp, fmt, 0, "", sig, 32);
		sig += 32;
		siglen -= 32;
	}

	format_print(fp, fmt, ind, "[left %zu bytes]\n", siglen);

	return 1;
}

int xmss_sign_init(XMSS_SIGN_CTX *ctx, XMSS_KEY *key)
{
	uint8_t index_buf[32] = {0};
	uint8_t adrs[32];
	size_t height;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(key->public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));

	// cache public key
	ctx->xmss_public_key = key->public_key;

	// key->index => xmss_sig.index
	ctx->xmss_sig.index = key->index;

	// derive ctx->xmss_sig.random
	PUTU32(index_buf + 28, key->index);
	// r = PRF(SK_PRF, toByte(idx_sig, 32));
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_three, 32);
	hash256_update(&ctx->hash256_ctx, key->sk_prf, 32);
	hash256_update(&ctx->hash256_ctx, index_buf, 32);
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
	hash256_update(&ctx->hash256_ctx, bn256_two, 32);
	hash256_update(&ctx->hash256_ctx, ctx->xmss_sig.random, 32);
	hash256_update(&ctx->hash256_ctx, key->public_key.root, 32);
	hash256_update(&ctx->hash256_ctx, index_buf, 32);

	return 1;
}




int xmss_sign_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (data && datalen) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

int xmss_sign_finish(XMSS_SIGN_CTX *ctx, uint8_t *sigbuf, size_t *siglen)
{
	xmss_adrs_t adrs;
	uint8_t dgst[32];

	hash256_finish(&ctx->hash256_ctx, dgst);

	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, ctx->xmss_sig.index);

	wots_sign(ctx->xmss_sig.wots_sig, ctx->xmss_public_key.seed, adrs, dgst,
		ctx->xmss_sig.wots_sig);

	*siglen = 0;
	if (xmss_signature_to_bytes(ctx->xmss_public_key.xmss_type, &ctx->xmss_sig, &sigbuf, siglen) != 1) {
		error_print();
		return -1;
	}


	return 1;
}

int xmss_verify_init(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const uint8_t *sig, size_t siglen)
{
	uint8_t sig_index[32];

	if (!ctx || !key || !sig || !siglen) {
		error_print();
		return -1;
	}

	// cache xmss_public_key
	ctx->xmss_public_key = key->public_key;

	// parse signature
	if (xmss_signature_from_bytes(key->public_key.xmss_type, &ctx->xmss_sig, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	memset(sig_index, 0, 28);
	PUTU32(sig_index + 28, ctx->xmss_sig.index);

	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, bn256_two, 32);
	hash256_update(&ctx->hash256_ctx, ctx->xmss_sig.random, 32);
	hash256_update(&ctx->hash256_ctx, key->public_key.root, 32);
	hash256_update(&ctx->hash256_ctx, sig_index, 32);

	return 1;
}

int xmss_verify_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
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
	int right;

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
	adrs_set_key_and_mask(adrs, 0);
	for (h = 0; h < height; h++) {
		right = index & 1;
		index >>= 1;
		adrs_set_tree_height(adrs, h + 1);
		adrs_set_tree_index(adrs, index);
		if (right)
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

size_t xmss_tree_num_nodes(size_t height)
{
	return (1 << (height + 1)) - 1;
}

size_t xmssmt_trees_num_nodes(size_t height, size_t layers)
{
	return xmss_tree_num_nodes(height/layers) * layers;
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
	*len += sizeof(hash256_t) * ((1 << (height/layers + 1)) - 1) * layers;
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

	treeslen = sizeof(hash256_t) * xmssmt_trees_num_nodes(height, layers);
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
	treeslen = sizeof(hash256_t) * xmssmt_trees_num_nodes(height, layers);
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

int xmssmt_key_generate(XMSSMT_KEY *key, uint32_t xmssmt_type)
{
	size_t height;
	size_t layers;
	uint32_t layer;
	xmss_adrs_t adrs;
	hash256_t *tree;
	uint8_t *xmss_root;

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

#if 0
	memset(key->public_key.seed, 0, 32);
	memset(key->secret, 0, 32);
	memset(key->sk_prf, 0, 32);
#else
	if (rand_bytes(key->public_key.seed, sizeof(hash256_t)) != 1) {
		error_print();
		return -1;
	}

	if (rand_bytes(key->secret, sizeof(hash256_t)) != 1) {
		error_print();
		return -1;
	}
	if (rand_bytes(key->sk_prf, sizeof(hash256_t)) != 1) {
		error_print();
		return -1;
	}
#endif
	key->index = 0;

	// malloc tress
	if (!(key->trees = malloc(xmssmt_trees_num_nodes(height, layers) * sizeof(hash256_t)))) {
		error_print();
		return -1;
	}
	tree = key->trees;

	for (layer = 0; layer < layers - 1; layer++) {
		// generate the leftmost tree of the level
		adrs_set_layer_address(adrs, layer);
		adrs_set_tree_address(adrs, 0);
		xmss_build_tree(key->secret, key->public_key.seed, adrs, height/layers, tree);
		xmss_root = tree[tree_root_offset(height/layers)];

		adrs_set_layer_address(adrs, layer + 1);
		adrs_set_tree_address(adrs, 0);
		adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
		adrs_set_ots_address(adrs, 0); // 具体值由index决定！

		wots_derive_sk(key->secret, key->public_key.seed, adrs, key->wots_sigs[layer]);
		wots_sign(key->wots_sigs[layer], key->public_key.seed, adrs, xmss_root, key->wots_sigs[layer]);
		tree += tree_root_offset(height/layers) + 1;
	}

	// highest layer (without signatures)
	adrs_set_layer_address(adrs, layer);
	adrs_set_tree_address(adrs, 0);
	xmss_build_tree(key->secret, key->public_key.seed, adrs, height/layers, tree);
	xmss_root = tree[tree_root_offset(height/layers)];

	// copy the top-level root
	memcpy(key->public_key.root, xmss_root, sizeof(hash256_t));




	tree = key->trees;


	hash256_t root;

	size_t i;
	wots_key_t wots_pk;

	for (i = 0; i < layers - 1; i++) {

		adrs_set_layer_address(adrs, i + 1);
		adrs_set_tree_address(adrs, 0); //				
		adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
		adrs_set_ots_address(adrs, 0);  // FIXME: value from index			

		uint8_t *dgst = tree[tree_root_offset(height/layers)];

		wots_sig_to_pk(key->wots_sigs[i], key->public_key.seed, adrs, dgst, wots_pk);


		adrs_set_type(adrs, XMSS_ADRS_TYPE_LTREE);
		adrs_set_tree_index(adrs, 0); // 				
		wots_pk_to_root(wots_pk, key->public_key.seed, adrs, root);

		tree += xmss_tree_num_nodes(height/layers);

		if (memcmp(root, tree[0], 32) != 0) {
			error_print();
			return -1;
		}
	}

	return 1;
}

// change API as xmss_build_auth_path
int xmssmt_key_build_auth_path(const XMSSMT_KEY *key, hash256_t *auth_path)
{
	size_t height;
	size_t layers;
	uint64_t index;
	const hash256_t *tree;
	size_t i;

	if (!key || !auth_path) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	index = key->index;
	tree = key->trees;

	for (i = 0; i < layers; i++) {
		uint64_t local_index = index & ((1 << (height/layers)) - 1);
		xmss_build_auth_path(tree, height/layers, local_index, auth_path);
		auth_path += height/layers;
		index >>= height/layers;
		tree += xmss_tree_num_nodes(height/layers);
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
		snprintf(label, sizeof(label), "layer %zu root", i);
		format_bytes(stderr, 0, 0, label, tree[tree_root_offset(height/layers)], 32);
		tree += xmss_tree_num_nodes(height/layers);

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
	*siglen += XMSS_WOTS_SIGNATURE_SIZE * layers;
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
			format_print(fp, fmt, ind+4, "%d ", i);
			format_bytes(fp, fmt, 0, "", sig->wots_sigs[layer][i], 32);
		}

		format_print(fp, fmt, ind+4, "auth_path\n");
		for (i = 0; i < height/layers; i++) {
			format_print(fp, fmt, ind+8, "%d ", i);
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
	format_print(fp, fmt, ind, "index: %u"PRIu64"\n", index);

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

int xmssmt_sign_init(XMSSMT_SIGN_CTX *ctx, XMSSMT_KEY *key)
{
	hash256_t hash256_index = {0};
	xmss_adrs_t adrs;
	size_t height;
	size_t layers;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));

	// cache public key
	ctx->xmssmt_public_key = key->public_key;

	// key->index => xmssmt_sig.index
	ctx->xmssmt_sig.index = key->index;

	// derive ctx->xmssmt_sig.random
	PUTU64(hash256_index + 24, key->index);
	// r = PRF(SK_PRF, toByte(idx_sig, 32));
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, hash256_three, 32);
	hash256_update(&ctx->hash256_ctx, key->sk_prf, 32);
	hash256_update(&ctx->hash256_ctx, hash256_index, 32);
	hash256_finish(&ctx->hash256_ctx, ctx->xmssmt_sig.random);

	// wots_sk => ctx->xmss_sig.wots_sig
	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, 0); // 				
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, key->index); // 				
	wots_derive_sk(key->secret, key->public_key.seed, adrs, ctx->xmssmt_sig.wots_sigs[0]);

	// 				
	// xmss_sig.auth_path
	xmss_build_auth_path(key->trees, height, key->index, ctx->xmssmt_sig.auth_path);


	// update key->index
	key->index++;

	// H_msg(M) := HASH256(toByte(2, 32) || r || XMSS_ROOT || toByte(idx_sig, 32) || M)
	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, bn256_two, 32);
	hash256_update(&ctx->hash256_ctx, ctx->xmssmt_sig.random, 32);
	hash256_update(&ctx->hash256_ctx, key->public_key.root, 32);
	hash256_update(&ctx->hash256_ctx, hash256_index, 32);


	size_t i;

	for (i = 0; i < layers; i++) {


	}


	return -1;

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
	xmss_adrs_t adrs;
	size_t height;
	size_t layers;

	uint64_t tree_address;

	uint8_t dgst[32];

	if (!ctx || !sig) {
		error_print();
		return -1;
	}


	if (xmssmt_type_to_height_and_layers(ctx->xmssmt_public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}

	tree_address = sig->index / layers;


	hash256_finish(&ctx->hash256_ctx, dgst);

	adrs_set_layer_address(adrs, 0);
	adrs_set_tree_address(adrs, tree_address);
	adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	adrs_set_ots_address(adrs, ctx->xmssmt_sig.index);

	wots_sign(ctx->xmssmt_sig.wots_sigs[0], ctx->xmssmt_public_key.seed, adrs, dgst,
		ctx->xmssmt_sig.wots_sigs[0]);

	return 1;
}

int xmssmt_sign_finish(XMSSMT_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	*siglen = 0;
	if (xmssmt_signature_to_bytes(&ctx->xmssmt_sig, ctx->xmssmt_public_key.xmssmt_type, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return -1;
}

int xmssmt_verify_init_ex(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const XMSSMT_SIGNATURE *sig)
{
	if (!ctx || !key || !sig) {
		error_print();
		return -1;
	}

	return -1;
}

int xmssmt_verify_init(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const uint8_t *sig, size_t siglen)
{
	return -1;
}

int xmssmt_verify_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	return -1;
}

int xmssmt_verify_finish(XMSSMT_SIGN_CTX *ctx)
{
	return -1;
}
