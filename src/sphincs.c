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


int sphincs_adrs_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_adrs_t adrs)
{
	uint32_t layer_address;
	uint32_t tree_address_hi32;
	uint64_t tree_address_lo64;
	uint32_t type;
	uint32_t keypair_address;
	uint32_t chain_address;
	uint32_t hash_address;
	uint32_t tree_height;
	uint32_t tree_index;
	uint32_t padding;


	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	layer_address = GETU32(adrs);
	format_print(fp, fmt, ind, "layer_address  : %"PRIu32"\n", layer_address);
	adrs += 4;
	tree_address_hi32 = GETU32(adrs);
	format_print(fp, fmt, ind, "tree_address   : %"PRIu32"\n", tree_address_hi32);
	adrs += 4;
	tree_address_lo64 = GETU64(adrs);
	format_print(fp, fmt, ind, "tree_address   : %"PRIu64"\n", tree_address_lo64);
	adrs += 8;
	type = GETU32(adrs);
	format_print(fp, fmt, ind, "type           : %"PRIu32"\n", type);
	adrs += 4;


	switch (type) {
	case SPHINCS_ADRS_TYPE_WOTS_HASH:
		keypair_address = GETU32(adrs);
		format_print(fp, fmt, ind, "keypair_address: %"PRIu32"\n", keypair_address);
		adrs += 4;
		chain_address = GETU32(adrs);
		format_print(fp, fmt, ind, "chain_address  : %"PRIu32"\n", chain_address);
		adrs += 4;
		hash_address = GETU32(adrs);
		format_print(fp, fmt, ind, "hash_address   : %"PRIu32"\n", hash_address);
		adrs += 4;
		break;
	case SPHINCS_ADRS_TYPE_WOTS_PK:
		keypair_address = GETU32(adrs);
		format_print(fp, fmt, ind, "keypair_address: %"PRIu32"\n", keypair_address);
		adrs += 4;
		padding = GETU32(adrs);
		format_print(fp, fmt, ind, "padding        : %"PRIu32"\n", padding);
		adrs += 4;
		padding = GETU32(adrs);
		format_print(fp, fmt, ind, "padding        : %"PRIu32"\n", padding);
		adrs += 4;
		break;
	case SPHINCS_ADRS_TYPE_TREE:
		padding = GETU32(adrs);
		format_print(fp, fmt, ind, "padding        : %"PRIu32"\n", padding);
		adrs += 4;
		tree_height = GETU32(adrs);
		format_print(fp, fmt, ind, "tree_height    : %"PRIu32"\n", tree_height);
		adrs += 4;
		tree_index = GETU32(adrs);
		format_print(fp, fmt, ind, "tree_index     : %"PRIu32"\n", tree_index);
		adrs += 4;
		break;
	case SPHINCS_ADRS_TYPE_FORS_TREE:
		keypair_address = GETU32(adrs);
		format_print(fp, fmt, ind, "keypair_address: %"PRIu32"\n", keypair_address);
		adrs += 4;
		tree_height = GETU32(adrs);
		format_print(fp, fmt, ind, "tree_height    : %"PRIu32"\n", tree_height);
		adrs += 4;
		tree_index = GETU32(adrs);
		format_print(fp, fmt, ind, "tree_index     : %"PRIu32"\n", tree_index);
		adrs += 4;
		break;
		break;
	case SPHINCS_ADRS_TYPE_FORS_ROOTS:
		keypair_address = GETU32(adrs);
		format_print(fp, fmt, ind, "keypair_address: %"PRIu32"\n", keypair_address);
		adrs += 4;
		padding = GETU32(adrs);
		format_print(fp, fmt, ind, "padding        : %"PRIu32"\n", padding);
		adrs += 4;
		padding = GETU32(adrs);
		format_print(fp, fmt, ind, "padding        : %"PRIu32"\n", padding);
		adrs += 4;
		break;
	case SPHINCS_ADRS_TYPE_WOTS_PRF:
		keypair_address = GETU32(adrs);
		format_print(fp, fmt, ind, "keypair_address: %"PRIu32"\n", keypair_address);
		adrs += 4;
		chain_address = GETU32(adrs);
		format_print(fp, fmt, ind, "chain_address  : %"PRIu32"\n", chain_address);
		adrs += 4;
		hash_address = GETU32(adrs);
		format_print(fp, fmt, ind, "hash_address   : %"PRIu32"\n", hash_address);
		adrs += 4;
		break;
	case SPHINCS_ADRS_TYPE_FORS_PRF:
		keypair_address = GETU32(adrs);
		format_print(fp, fmt, ind, "keypair_address: %"PRIu32"\n", keypair_address);
		adrs += 4;
		tree_height = GETU32(adrs);
		format_print(fp, fmt, ind, "tree_height    : %"PRIu32"\n", tree_height);
		adrs += 4;
		tree_index = GETU32(adrs);
		format_print(fp, fmt, ind, "tree_index     : %"PRIu32"\n", tree_index);
		adrs += 4;
		break;
	default:
		error_print();
		return -1;
	}

	return 1;
}

void sphincs_adrs_compress(const sphincs_adrs_t adrs, sphincs_adrsc_t adrsc)
{
	// copy layer_address
	memcpy(adrsc, adrs + 3, 1);
	adrsc += 1;
	adrs += 4;

	// copy tree_address
	memcpy(adrsc, adrs + 4, 8);
	adrsc += 8;
	adrs += 12;

	// copy type
	memcpy(adrsc, adrs + 3, 1);
	adrsc += 1;
	adrs += 4;

	// copy others
	memcpy(adrsc, adrs, 12);
}

int sphincs_wots_key_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_wots_key_t key)
{
	int i;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	for (i = 0; i < 35; i++) {
		format_print(fp, fmt, ind, "%d", i);
		format_bytes(fp, fmt, 0, "", key[i], sizeof(sphincs_hash128_t));
	}
	return 1;
}

int sphincs_wots_sig_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_wots_sig_t sig)
{
	int i;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	for (i = 0; i < 35; i++) {
		format_print(fp, fmt, ind, "%d", i);
		format_bytes(fp, fmt, 0, "", sig[i], sizeof(sphincs_hash128_t));
	}
	return 1;
}

void sphincs_wots_derive_sk(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_wots_key_t sk)
{
	uint8_t block[HASH256_BLOCK_SIZE] = {0};
	sphincs_adrs_t adrs;
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;
	int i;

	memcpy(block, seed, sizeof(sphincs_hash128_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_PRF);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);

	for (i = 0; i < 35; i++) {
		sphincs_adrs_set_chain_address(adrs, i);
		sphincs_adrs_set_hash_address(adrs, 0);
		sphincs_adrs_compress(adrs, adrsc);

		// sk[i] = prf(secret, adrs)
		hash256_init(&ctx);
		hash256_update(&ctx, block, sizeof(block));
		hash256_update(&ctx, adrsc, sizeof(adrsc));
		hash256_update(&ctx, secret, sizeof(sphincs_hash128_t));
		hash256_finish(&ctx, dgst);

		memcpy(sk[i], dgst, sizeof(sphincs_hash128_t));
	}
}

// from fips 205 section 11.2.1, not sphincs+ r3.1 spec
void sphincs_wots_chain(const sphincs_hash128_t x,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	int start, int steps, sphincs_hash128_t y)
{
	const uint8_t uint32_zero[4] = {0};
	uint8_t block[HASH256_BLOCK_SIZE] = {0};
	sphincs_adrs_t adrs;
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;
	int i;

	memcpy(block, seed, sizeof(sphincs_hash128_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_copy_type(adrs, in_adrs);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);
	sphincs_adrs_copy_chain_address(adrs, in_adrs);

	memcpy(y, x, sizeof(sphincs_hash128_t));

	for (i = 0; i < steps; i++) {
		sphincs_adrs_set_hash_address(adrs, start + i);
		sphincs_adrs_compress(adrs, adrsc);

		// y = hash256(blockpad(seed) || adrsc || y)
		hash256_init(&ctx);
		hash256_update(&ctx, block, sizeof(block));
		hash256_update(&ctx, adrsc, sizeof(sphincs_adrsc_t));
		hash256_update(&ctx, y, sizeof(sphincs_hash128_t));
		hash256_finish(&ctx, dgst);

		memcpy(y, dgst, sizeof(sphincs_hash128_t));
	}
}

void sphincs_wots_sk_to_pk(const sphincs_wots_key_t sk,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_wots_key_t pk)
{
	const int start = 0;
	const int steps = 16 - 1;
	sphincs_adrs_t adrs;
	uint32_t i;

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_HASH);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);

	for (i = 0; i < 35; i++) {
		sphincs_adrs_set_chain_address(adrs, i);
		sphincs_wots_chain(sk[i], seed, adrs, start, steps, pk[i]);
	}
}

static void sphincs_base_w_and_checksum(const sphincs_hash128_t dgst, int steps[35])
{
	int csum = 0;
	int sbits;
	int i;

	// seperate 128-bit dgst into 32 4-bit base_w numbers
	for (i = 0; i < 16; i++) {
		steps[2 * i]     = dgst[i] >> 4;
		steps[2 * i + 1] = dgst[i] & 0xf;
	}

	// compute checksum, maxium is (16 - 1) * 32 = 480, which is 9-bit and 3 base_w number
	for (i = 0; i < 32; i++) {
		csum += 15 - steps[i];
	}

#if 0
	uint8_t csum_bytes[2];

	// encode checksum (3 base_w) into 2-byte array
	sbits = (8 - ((3 * 4) % 8));
	csum <<= sbits;
	csum_bytes[0] = (csum >> 8) & 0xff;
	csum_bytes[1] = csum & 0xff;

	// convert 2-byte array to 3 base_w number
	steps[32] = csum_bytes[0] >> 4;
	steps[33] = csum_bytes[0] & 0xf;
	steps[34] = csum_bytes[1] >> 4;
#else
	steps[32] = (csum >> 8) & 0x0f;
	steps[33] = (csum >> 4) & 0x0f;
	steps[34] = (csum >> 0) & 0x0f;
#endif
}

void sphincs_wots_sign(const sphincs_wots_key_t sk,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	const sphincs_hash128_t dgst, sphincs_wots_sig_t sig)
{
	sphincs_adrs_t adrs;
	const int start = 0;
	int steps[35];
	uint32_t i;

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_HASH);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);

	sphincs_base_w_and_checksum(dgst, steps);

	for (i = 0; i < 35; i++) {
		sphincs_adrs_set_chain_address(adrs, i);
		sphincs_wots_chain(sk[i], seed, adrs, start, steps[i], sig[i]);
	}
}

void sphincs_wots_sig_to_pk(const sphincs_wots_sig_t sig,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	const sphincs_hash128_t dgst, sphincs_wots_key_t pk)
{
	sphincs_adrs_t adrs;
	int steps[35];
	int i;

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_HASH);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);

	sphincs_base_w_and_checksum(dgst, steps);

	for (i = 0; i < 35; i++) {
		sphincs_adrs_set_chain_address(adrs, i);
		sphincs_wots_chain(sig[i], seed, adrs, steps[i], 15 - steps[i], pk[i]);
	}
}

void sphincs_wots_pk_to_root(const sphincs_wots_key_t pk,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_hash128_t root)
{
	uint8_t block[HASH256_BLOCK_SIZE] = {0};
	sphincs_adrs_t adrs = {0};
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;
	int i;

	memcpy(block, seed, sizeof(sphincs_hash128_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_WOTS_PK);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);
	sphincs_adrs_compress(adrs, adrsc);

	hash256_init(&ctx);
	hash256_update(&ctx, block, sizeof(block));
	hash256_update(&ctx, adrsc, sizeof(adrsc));
	hash256_update(&ctx, pk[0], sizeof(sphincs_wots_key_t));
	hash256_finish(&ctx, dgst);

	memcpy(root, dgst, sizeof(sphincs_hash128_t));
}






void sphincs_tree_hash(const sphincs_hash128_t left_child, const sphincs_hash128_t right_child,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	hash256_t parent)
{
	HASH256_CTX ctx;
	hash256_t dgst;

	hash256_init(&ctx);
	hash256_update(&ctx, seed, sizeof(sphincs_hash128_t));
	hash256_update(&ctx, adrs, sizeof(sphincs_adrs_t));
	hash256_update(&ctx, left_child, sizeof(sphincs_hash128_t));
	hash256_update(&ctx, right_child, sizeof(sphincs_hash128_t));
	hash256_finish(&ctx, dgst);

	memcpy(parent, dgst, sizeof(sphincs_hash128_t));
}







void sphincs_xmss_build_tree(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES])
{
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t *children;
	sphincs_hash128_t *parents;
	size_t n = 1 << SPHINCS_XMSS_HEIGHT;
	uint32_t h; // as tree_height
	uint32_t i; // as tree_index

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);

	// derive 2^h wots+ roots as leaves of xmss tree
	for (i = 0; i < n; i++) {
		sphincs_wots_key_t wots_key;

		sphincs_adrs_set_keypair_address(adrs, i);

		// type = SPHINCS_ADRS_TYPE_WOTS_PRF
		sphincs_wots_derive_sk(secret, seed, adrs, wots_key);
		// type = SPHINCS_ADRS_TYPE_WOTS_HASH
		sphincs_wots_sk_to_pk(wots_key, seed, adrs, wots_key);
		// type = SPHINCS_ADRS_TYPE_WOTS_PK
		sphincs_wots_pk_to_root(wots_key, seed, adrs, tree[i]);
	}

	// keypair_address == TREE.padding, so reset adrs
	memset(adrs, 0, sizeof(adrs));
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_TREE);
	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);

	// build xmss tree
	children = tree;
	parents = tree + n;
	for (h = 0; h < SPHINCS_XMSS_HEIGHT; h++) {
		sphincs_adrs_set_tree_height(adrs, h + 1);
		n >>= 1;
		for (i = 0; i < n; i++) {
			sphincs_adrs_set_tree_index(adrs, i);
			sphincs_tree_hash(children[2*i], children[2*i + 1], seed, adrs, parents[i]);
		}
		children = parents;
		parents += n;
	}
}

void sphincs_xmss_build_auth_path(const sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES],
	uint32_t tree_index, sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT])
{
	size_t h;
	for (h = 0; h < SPHINCS_XMSS_HEIGHT; h++) {
		memcpy(auth_path[h], tree[tree_index ^ 1], sizeof(sphincs_hash128_t));
		tree += (1 << (SPHINCS_XMSS_HEIGHT - h));
		tree_index >>= 1;
	}
}

void sphincs_xmss_build_root(const sphincs_hash128_t wots_root, uint32_t tree_index,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	const sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT],
	hash256_t root)
{
	sphincs_adrs_t adrs = {0};
	uint32_t h;

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_TREE);

	memcpy(root, wots_root, sizeof(sphincs_hash128_t));

	for (h = 0; h < SPHINCS_XMSS_HEIGHT; h++) {
		int right_child = tree_index & 1;
		tree_index >>= 1;
		sphincs_adrs_set_tree_height(adrs, h + 1);
		sphincs_adrs_set_tree_index(adrs, tree_index);

		if (right_child)
			sphincs_tree_hash(auth_path[h], root, seed, adrs, root);
		else	sphincs_tree_hash(root, auth_path[h], seed, adrs, root);

		//format_bytes(stderr, 0, 4, "build_root", root, 16);
	}
}

// in sphincs+, xmss sign the lower layer xmss_root or the fors_forest_root
// TODO: tree_index or keypair_address?

void sphincs_xmss_sign(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs, uint32_t keypair_address,
	const sphincs_hash128_t tbs_root, SPHINCS_XMSS_SIGNATURE *sig)
{
	sphincs_adrs_t adrs = {0};
	sphincs_wots_key_t wots_sk;
	sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES];


	//fprintf(stderr, "    sphincs_xmss_sign: keypair = %d\n", (int)keypair_address);

	// generate wots_sig
	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_keypair_address(adrs, keypair_address);



	sphincs_wots_derive_sk(secret, seed, adrs, wots_sk);

		sphincs_wots_key_t wots_pk;
		sphincs_hash128_t wots_root;
		sphincs_wots_sk_to_pk(wots_sk, seed, adrs, wots_pk);
		sphincs_wots_pk_to_root(wots_pk, seed, adrs, wots_root);
	//	format_bytes(stderr, 0, 4, "sphincs_xmss_sign: wots_root", wots_root, 16);


	sphincs_wots_sign(wots_sk, seed, adrs, tbs_root, sig->wots_sig);


		sphincs_wots_sig_to_pk(sig->wots_sig, seed, adrs, tbs_root, wots_pk);
		sphincs_wots_pk_to_root(wots_pk, seed, adrs, wots_root);

	//	format_bytes(stderr, 0, 4, "sphincs_xmss_sign: wots_root", wots_root, 16);


	// build xmss_tree, then build auth_path
	// note: build_tree use the original in_adrs (without keypair_address set)
	sphincs_xmss_build_tree(secret, seed, in_adrs, tree);

	//	format_bytes(stderr, 0, 4, "sphincs_xmss_sign: tree[0]", tree[0], 16);
	//	format_bytes(stderr, 0, 4, "sphincs_xmss_sign: tree[1022]", tree[1022], 16);


	sphincs_xmss_build_auth_path(tree, keypair_address, sig->auth_path);



	//	sphincs_xmss_build_root(wots_root, keypair_address, seed, adrs, sig->auth_path, wots_root);
	//	format_bytes(stderr, 0, 4, "sphincs_xmss_sign: xmss_root", wots_root, 16);


}

void sphincs_xmss_sig_to_root(const SPHINCS_XMSS_SIGNATURE *sig,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs, uint32_t keypair_address,
	const sphincs_hash128_t tbs_root, sphincs_hash128_t xmss_root)
{
	sphincs_adrs_t adrs;
	sphincs_wots_key_t wots_pk;
	sphincs_hash128_t wots_root;

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_keypair_address(adrs, keypair_address);

	fprintf(stderr, "sphincs_xmss_sig_to_root\n");

	// type == SPHINCS_ADRS_TYPE_WOTS_HASH
	sphincs_wots_sig_to_pk(sig->wots_sig, seed, adrs, tbs_root, wots_pk);
	// type == SPHINCS_ADRS_TYPE_WOTS_PK
	sphincs_wots_pk_to_root(wots_pk, seed, adrs, wots_root);

	//format_bytes(stderr, 0, 4, "sphincs_xmss_sig_to_root: wots_root", wots_root, 16);


	// type == SPHINCS_ADRS_TYPE_TREE
	sphincs_xmss_build_root(wots_root, keypair_address, seed, adrs, sig->auth_path, xmss_root);

	fprintf(stderr, "\n");
}






// generate the highest layer xmss_tree root, which is the hypertree_root, and the sphincs_root
void sphincs_hypertree_derive_root(const sphincs_hash128_t secret, const sphincs_hash128_t seed,
	sphincs_hash128_t root)
{
	sphincs_adrs_t adrs;
	sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES];

	sphincs_adrs_set_layer_address(adrs, SPHINCS_HYPERTREE_LAYERS - 1);
	sphincs_adrs_set_tree_address(adrs, 0);

	sphincs_xmss_build_tree(secret, seed, adrs, tree);

	memcpy(root, tree[SPHINCS_XMSS_NUM_NODES - 1], sizeof(sphincs_hash128_t));
}

// hypertree sign the fors_forest_root, generate layers xmss_sig


void sphincs_hypertree_sign(const sphincs_hash128_t secret, const sphincs_hash128_t seed,
	uint64_t tree_address, uint32_t keypair_address,
	const sphincs_hash128_t fors_forest_root,
	SPHINCS_XMSS_SIGNATURE sig[SPHINCS_HYPERTREE_LAYERS])
{
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t xmss_root;
	int i;

	sphincs_adrs_set_layer_address(adrs, 0);
	sphincs_adrs_set_tree_address(adrs, tree_address);

	// sign fors_forest_root with layer 0 xmss keypair
	sphincs_xmss_sign(secret, seed, adrs, keypair_address, fors_forest_root, &sig[0]);


	// sig0 => layer 0 xmss_root
	sphincs_xmss_sig_to_root(&sig[0], seed, adrs, keypair_address, fors_forest_root, xmss_root);


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
	}
}


// test pass!
int sphincs_hypertree_verify(const sphincs_hash128_t top_xmss_root, const sphincs_hash128_t seed,
	uint64_t tree_address, uint32_t keypair_address,
	const sphincs_hash128_t tbs_fors_forest_root,
	const SPHINCS_XMSS_SIGNATURE sig[SPHINCS_HYPERTREE_LAYERS])
{
	sphincs_adrs_t adrs = {0};
	sphincs_hash128_t xmss_root;
	int i;

	sphincs_adrs_set_layer_address(adrs, 0);
	sphincs_adrs_set_tree_address(adrs, tree_address);

	sphincs_xmss_sig_to_root(&sig[0], seed, adrs, keypair_address, tbs_fors_forest_root, xmss_root);


	for (i = 1; i < SPHINCS_HYPERTREE_LAYERS; i++) {
		keypair_address = tree_address & ((1 << SPHINCS_XMSS_HEIGHT) - 1);
		tree_address >>= SPHINCS_XMSS_HEIGHT;

		sphincs_adrs_set_layer_address(adrs, i);
		sphincs_adrs_set_tree_address(adrs, tree_address);

		// xmss_sig => xmss_root, to be signed by next layer +1
		sphincs_xmss_sig_to_root(&sig[i], seed, adrs, keypair_address, xmss_root, xmss_root);
	}

	if (memcmp(xmss_root, top_xmss_root, sizeof(sphincs_hash128_t)) != 0) {
		error_print();
		return 0;
	}
	return 1;
}

void sphincs_fors_derive_sk(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	uint32_t fors_index, sphincs_hash128_t sk)
{
	uint8_t block[HASH256_BLOCK_SIZE] = {0};
	sphincs_adrs_t adrs;
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;

	// blockpad(seed)
	memcpy(block, seed, sizeof(sphincs_hash128_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_FORS_PRF);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);
	sphincs_adrs_set_tree_height(adrs, 0);
	sphincs_adrs_set_tree_index(adrs, fors_index);

	// compress adrs
	sphincs_adrs_compress(adrs, adrsc);

	// sk = prf(seed, secret, adrs) = hash256(blockpad(seed)||adrsc||secret)
	hash256_init(&ctx);
	hash256_update(&ctx, block, sizeof(block));
	hash256_update(&ctx, adrsc, sizeof(adrsc));
	hash256_update(&ctx, secret, sizeof(sphincs_hash128_t));
	hash256_finish(&ctx, dgst);

	memcpy(sk, dgst, sizeof(sphincs_hash128_t));
	gmssl_secure_clear(dgst, sizeof(dgst));
}

void sphincs_fors_build_tree(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs, int tree_addr,
	sphincs_hash128_t tree[SPHINCS_FORS_TREE_NUM_NODES])
{
	uint8_t block[64] = {0};
	sphincs_adrs_t adrs = {0};
	sphincs_adrsc_t adrsc;
	uint32_t n = 1 << SPHINCS_FORS_TREE_HEIGHT;
	uint32_t tree_index;
	HASH256_CTX ctx;
	hash256_t dgst;
	sphincs_hash128_t *children;
	sphincs_hash128_t *parents;
	uint32_t h;
	uint32_t i;


	memcpy(block, seed, sizeof(sphincs_hash128_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_TREE);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);
	sphincs_adrs_set_tree_height(adrs, 0);

	for (i = 0; i < n; i++) {
		tree_index = n * tree_addr + i;
		sphincs_fors_derive_sk(secret, seed, adrs, tree_index, tree[i]);

		sphincs_adrs_set_tree_index(adrs, tree_index);
		sphincs_adrs_compress(adrs, adrsc);


		hash256_init(&ctx);
		hash256_update(&ctx, block, sizeof(block));
		hash256_update(&ctx, adrsc, sizeof(adrsc));
		hash256_update(&ctx, tree[i], sizeof(sphincs_hash128_t));
		hash256_finish(&ctx, dgst);

		memcpy(tree[i], dgst, sizeof(sphincs_hash128_t));
	}

	children = tree;
	parents = tree + n;
	for (h = 0; h < SPHINCS_FORS_TREE_HEIGHT; h++) {
		sphincs_adrs_set_tree_height(adrs, h + 1);
		n >>= 1;
		for (i = 0; i < n; i++) {
			tree_index = n * tree_addr + i;
			sphincs_adrs_set_tree_index(adrs, tree_index);
			sphincs_tree_hash(children[2*i], children[2*i + 1], seed, adrs, parents[i]);
		}
		children = parents;
		parents += n;
	}
}


void sphincs_fors_derive_root(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_hash128_t root)
{
	uint8_t block[64] = {0};
	sphincs_adrs_t adrs = {0};
	sphincs_adrsc_t adrsc;
	sphincs_hash128_t tree[SPHINCS_FORS_TREE_NUM_NODES];
	sphincs_hash128_t roots[SPHINCS_FORS_NUM_TREES];
	HASH256_CTX ctx;
	hash256_t dgst;
	int i;

	memcpy(block, seed, sizeof(sphincs_hash128_t));

	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_FORS_ROOTS);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);

	// FORS_ROOTS has padding[2] = {0,0}, which will be modified by fors_build_tree
	sphincs_adrs_compress(adrs, adrsc);

	for (i = 0; i < SPHINCS_FORS_NUM_TREES; i++) {
		sphincs_fors_build_tree(secret, seed, adrs, i, tree);
		memcpy(roots[i], tree[SPHINCS_FORS_TREE_NUM_NODES - 1], sizeof(sphincs_hash128_t));
	}

	hash256_init(&ctx);
	hash256_update(&ctx, block, sizeof(block));
	hash256_update(&ctx, adrsc, sizeof(adrsc));
	hash256_update(&ctx, roots[0], sizeof(roots));
	hash256_finish(&ctx, dgst);

	memcpy(root, dgst, sizeof(sphincs_hash128_t));
}


void split_bits(const uint8_t dgst[21], uint32_t index[14])
{
	int i;
	for (i = 0; i < 7; i++) {
		index[0] = ((uint32_t)dgst[0] << 4) | (dgst[1] >> 4);
		index[1] = ((uint32_t)(dgst[1] & 0x0f) << 8) | dgst[2];
		index += 2;
		dgst += 3;
	}
	/*
	for (i = 0; i < 14; i++) {
		index[i] += (1 << SPHINCS_FORS_TREE_HEIGHT) * i;
	}
	*/
}




void sphincs_fors_sign(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	const uint8_t dgst[21],
	SPHINCS_FORS_SIGNATURE *sig)
{
	uint32_t index[14];
	uint32_t tree_index;
	uint32_t i, h;
	sphincs_hash128_t fors_tree[SPHINCS_FORS_TREE_NUM_NODES];


	sphincs_hash128_t fors_root;


	sphincs_fors_derive_root(secret, seed, in_adrs, fors_root);

	format_bytes(stderr, 0, 4, "--------fors_root", fors_root, 16);



	memset(sig, 0, sizeof(SPHINCS_FORS_SIGNATURE));


	split_bits(dgst, index);

	for (i = 0; i < 14; i++) {
		tree_index = (1 << SPHINCS_FORS_TREE_HEIGHT) * i + index[i];

		sphincs_fors_derive_sk(secret, seed, in_adrs, tree_index, sig->fors_sk[i]);
	}


	for (i = 0; i < 14; i++) {

		sphincs_hash128_t *tree = fors_tree;

		sphincs_fors_build_tree(secret, seed, in_adrs, i, tree);


		format_bytes(stderr, 0, 4, "tree[0]", tree[0], 16);
		format_bytes(stderr, 0, 4, "root", tree[SPHINCS_FORS_TREE_NUM_NODES - 1], 16);

		int k;
		for (k = 0; k < SPHINCS_FORS_TREE_NUM_NODES; k++) {
//			format_print(stderr, 0, 4, "tree[%d]", k);
//			format_bytes(stderr, 0, 0, "", tree[k], 16);
		}



		tree_index = index[i];

		for (h = 0; h < SPHINCS_FORS_TREE_HEIGHT; h++) {

			memcpy(sig->auth_path[i][h], tree[tree_index ^ 1], sizeof(sphincs_hash128_t));
			tree += (1 << (SPHINCS_FORS_TREE_HEIGHT - h));
			tree_index >>= 1;
		}
	}




	// sig->fors_sk[0], sig->auth_path[0] ==> fors_root[0]


	if (0) {
		uint8_t block[64] = {0};
		sphincs_adrs_t adrs;
		sphincs_adrsc_t adrsc;
		HASH256_CTX ctx;
		hash256_t root;

		tree_index = index[0];

		sphincs_adrs_copy_layer_address(adrs, in_adrs);
		sphincs_adrs_copy_tree_address(adrs, in_adrs);
		sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_TREE);
		sphincs_adrs_copy_keypair_address(adrs, in_adrs);
		sphincs_adrs_set_tree_height(adrs, 0);
		sphincs_adrs_set_tree_index(adrs, tree_index);

		sphincs_adrs_compress(adrs, adrsc);

		hash256_init(&ctx);
		hash256_update(&ctx, block, sizeof(block));
		hash256_update(&ctx, adrsc, sizeof(adrsc));
		hash256_update(&ctx, sig->fors_sk[0], sizeof(sphincs_hash128_t));
		hash256_finish(&ctx, root);

		format_bytes(stderr, 0, 4, "fors_tree[0]", root, 16);


		uint32_t n = 1 << SPHINCS_FORS_TREE_HEIGHT;


		for (h = 0; h < SPHINCS_FORS_TREE_HEIGHT; h++) {
			int right_child = tree_index & 1;
			tree_index >>= 1;
			n >>= 1;

			sphincs_adrs_set_tree_height(adrs, h + 1);
			sphincs_adrs_set_tree_index(adrs, tree_index);

			if (right_child)
				sphincs_tree_hash(sig->auth_path[0][h], root, seed, adrs, root);
			else	sphincs_tree_hash(root, sig->auth_path[0][h], seed, adrs, root);
		}

		format_bytes(stderr, 0, 4, "fors_root", root, 16);
	}


	memset(fors_root, 0, 16);

	sphincs_fors_sig_to_root(sig, seed, in_adrs, dgst, fors_root);
	format_bytes(stderr, 0, 4, ">>>>>>fors_root", fors_root, 16);


}

void sphincs_fors_sig_to_root(const SPHINCS_FORS_SIGNATURE *sig,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	const uint8_t tbs[21], sphincs_hash128_t root)
{

	uint8_t block[64] = {0};
	sphincs_adrs_t adrs;
	sphincs_adrsc_t adrsc;
	HASH256_CTX ctx;
	hash256_t dgst;

	uint32_t index[14];
	uint32_t tree_index;
	uint32_t i, h;

	sphincs_hash128_t fors_roots[14];


	memcpy(block, seed, sizeof(sphincs_hash128_t));

	split_bits(tbs, index);


	fprintf(stderr, "sphincs_fors_sig_to_root\n");

	for (i = 0; i < 14; i++) {

		tree_index = (1 << SPHINCS_FORS_TREE_HEIGHT) * i + index[i];

		sphincs_adrs_copy_layer_address(adrs, in_adrs);
		sphincs_adrs_copy_tree_address(adrs, in_adrs);
		sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_TREE);
		sphincs_adrs_copy_keypair_address(adrs, in_adrs);
		sphincs_adrs_set_tree_height(adrs, 0);
		sphincs_adrs_set_tree_index(adrs, tree_index);

		sphincs_adrs_compress(adrs, adrsc);


		hash256_init(&ctx);
		hash256_update(&ctx, block, sizeof(block));
		hash256_update(&ctx, adrsc, sizeof(adrsc));
		hash256_update(&ctx, sig->fors_sk[i], sizeof(sphincs_hash128_t));
		hash256_finish(&ctx, dgst);

		memcpy(root, dgst, 16);


		uint32_t n = 1 << SPHINCS_FORS_TREE_HEIGHT;


		tree_index = index[i];

		for (h = 0; h < SPHINCS_FORS_TREE_HEIGHT; h++) {
			int right_child = tree_index & 1;
			tree_index >>= 1;
			n >>= 1;

			sphincs_adrs_set_tree_height(adrs, h + 1);
			sphincs_adrs_set_tree_index(adrs, n * i + tree_index);

			if (right_child)
				sphincs_tree_hash(sig->auth_path[i][h], root, seed, adrs, root);
			else	sphincs_tree_hash(root, sig->auth_path[i][h], seed, adrs, root);
		}

		memcpy(fors_roots[i], root, 16);


		format_print(stderr, 0, 4, "fors_roots[%d]", i);
		format_bytes(stderr, 0, 0, "", fors_roots[i], 16);

	}


	memset(adrs, 0, sizeof(adrs));
	sphincs_adrs_copy_layer_address(adrs, in_adrs);
	sphincs_adrs_copy_tree_address(adrs, in_adrs);
	sphincs_adrs_set_type(adrs, SPHINCS_ADRS_TYPE_FORS_ROOTS);
	sphincs_adrs_copy_keypair_address(adrs, in_adrs);

	sphincs_adrs_compress(adrs, adrsc);


	hash256_init(&ctx);
	hash256_update(&ctx, block, sizeof(block));
	hash256_update(&ctx, adrsc, sizeof(adrsc));
	hash256_update(&ctx, fors_roots[0], sizeof(fors_roots));
	hash256_finish(&ctx, dgst);

	memcpy(root, dgst, 16);

	format_bytes(stderr, 0, 4, "fors_root", root, 16);


}


















int sphincs_fors_signature_to_bytes(const SPHINCS_FORS_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	if (!sig || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, sig->fors_sk, sizeof(sphincs_hash128_t) * SPHINCS_FORS_NUM_TREES);
		*out += sizeof(sphincs_hash128_t) * SPHINCS_FORS_NUM_TREES;
		memcpy(*out, sig->auth_path, sizeof(sphincs_hash128_t) * SPHINCS_FORS_HEIGHT * SPHINCS_FORS_NUM_TREES);
		*out += sizeof(sphincs_hash128_t) * SPHINCS_FORS_HEIGHT * SPHINCS_FORS_NUM_TREES;
	}
	*outlen += sizeof(sphincs_hash128_t) * SPHINCS_FORS_NUM_TREES;
	*outlen += sizeof(sphincs_hash128_t) * SPHINCS_FORS_HEIGHT * SPHINCS_FORS_NUM_TREES;
	return 1;
}

int sphincs_fors_signature_from_bytes(SPHINCS_FORS_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	if (!sig || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < SPHINCS_FORS_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	memcpy(sig->fors_sk, *in, sizeof(sphincs_hash128_t) * SPHINCS_FORS_NUM_TREES);
	*in += sizeof(sphincs_hash128_t) * SPHINCS_FORS_NUM_TREES;
	*inlen += sizeof(sphincs_hash128_t) * SPHINCS_FORS_NUM_TREES;
	memcpy(sig->auth_path, *in, sizeof(sphincs_hash128_t) * SPHINCS_FORS_HEIGHT * SPHINCS_FORS_NUM_TREES);
	*in += sizeof(sphincs_hash128_t) * SPHINCS_FORS_HEIGHT * SPHINCS_FORS_NUM_TREES;
	*inlen += sizeof(sphincs_hash128_t) * SPHINCS_FORS_HEIGHT * SPHINCS_FORS_NUM_TREES;
	return 1;
}

int sphincs_fors_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_FORS_SIGNATURE *sig)
{
	int i, j;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	for (i = 0; i < SPHINCS_FORS_HEIGHT; i++) {
		format_bytes(fp, fmt, 0, "fork_sk", sig->fors_sk[i], sizeof(sphincs_hash128_t));
		format_print(fp, fmt, ind, "auth_path\n");
		for (j = 0; i < SPHINCS_FORS_NUM_TREES; i++) {
		}
	}
	return 1;
}

int sphincs_fors_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen)
{
	return -1;
}

int sphincs_public_key_to_bytes(const SPHINCS_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, key->public_key.seed, sizeof(sphincs_hash128_t));
		*out += sizeof(sphincs_hash128_t);
		memcpy(*out, key->public_key.root, sizeof(sphincs_hash128_t));
		*out += sizeof(sphincs_hash128_t);
	}
	*outlen += sizeof(sphincs_hash128_t) * 2;
	return 1;
}

int sphincs_public_key_from_bytes(SPHINCS_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < sizeof(sphincs_hash128_t) * 2) {
		error_print();
		return -1;
	}
	memcpy(key->public_key.seed, *in, sizeof(sphincs_hash128_t));
	*in += sizeof(sphincs_hash128_t);
	*inlen -= sizeof(sphincs_hash128_t);
	memcpy(key->public_key.root, *in, sizeof(sphincs_hash128_t));
	*in += sizeof(sphincs_hash128_t);
	*inlen -= sizeof(sphincs_hash128_t);
	return 1;
}

int sphincs_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_bytes(fp, fmt, ind, "seed", key->public_key.seed, sizeof(sphincs_hash128_t));
	format_bytes(fp, fmt, ind, "root", key->public_key.root, sizeof(sphincs_hash128_t));
	return 1;
}

int sphincs_private_key_to_bytes(const SPHINCS_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (sphincs_public_key_to_bytes(key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, key->secret, sizeof(sphincs_hash128_t));
		*out += sizeof(sphincs_hash128_t);
		memcpy(*out, key->sk_prf, sizeof(sphincs_hash128_t));
		*out += sizeof(sphincs_hash128_t);
	}
	*outlen += sizeof(sphincs_hash128_t) * 2;
	return 1;
}

int sphincs_private_key_from_bytes(SPHINCS_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < SPHINCS_PRIVATE_KEY_SIZE) {
		error_print();
		return -1;
	}
	if (sphincs_public_key_from_bytes(key, in, inlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sphincs_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	sphincs_public_key_print(fp, fmt, ind, "public_key", key);
	format_bytes(fp, fmt, ind, "secret", key->secret, sizeof(sphincs_hash128_t));
	format_bytes(fp, fmt, ind, "sk_prf", key->sk_prf, sizeof(sphincs_hash128_t));
	return 1;
}

void sphincs_key_cleanup(SPHINCS_KEY *key)
{
	if (key) {
		gmssl_secure_clear(key->secret, sizeof(sphincs_hash128_t));
		gmssl_secure_clear(key->sk_prf, sizeof(sphincs_hash128_t));
	}
}


