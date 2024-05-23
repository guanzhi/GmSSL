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
#include <stdint.h>
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sm3_xmss.h>


#define uint32_from_bytes(ptr) \
	((uint32_t)(ptr)[0] << 24 | \
	 (uint32_t)(ptr)[1] << 16 | \
	 (uint32_t)(ptr)[2] <<  8 | \
	 (uint32_t)(ptr)[3])

#define uint32_to_bytes(a,ptr) \
	((ptr)[0] = (uint8_t)((a) >> 24), \
	 (ptr)[1] = (uint8_t)((a) >> 16), \
	 (ptr)[2] = (uint8_t)((a) >>  8), \
	 (ptr)[3] = (uint8_t)(a))

static void adrs_set_type(uint8_t adrs[32], uint32_t type) {
	uint32_to_bytes(type, adrs + 4*3);
	memset(adrs + 16, 0, 16);
}

static void adrs_set_ots_address(uint8_t adrs[32], uint32_t address) {
	uint32_to_bytes(address, adrs + 4*4);
}

static void adrs_set_chain_address(uint8_t adrs[32], uint32_t address) {
	uint32_to_bytes(address, adrs + 4*5);
}

static void adrs_set_hash_address(uint8_t adrs[32], uint32_t address) {
	uint32_to_bytes(address, adrs + 4*6);
}

static void adrs_set_ltree_address(uint8_t adrs[32], uint32_t address) {
	uint32_to_bytes(address, adrs + 4*4);
}

static void adrs_set_tree_height(uint8_t adrs[32], uint32_t height) {
	uint32_to_bytes(height, adrs + 4*5);
}

static void adrs_set_tree_index(uint8_t adrs[32], uint32_t index) {
	uint32_to_bytes(index, adrs + 4*6);
}

static void adrs_set_key_and_mask(uint8_t adrs[32], uint8_t key_and_mask) {
	uint32_to_bytes((uint32_t)key_and_mask, adrs + 4*7);
}

/*
static void adrs_print(const uint8_t adrs[32])
{
	const uint32_t *p = (uint32_t *)adrs;
	int i;
	for (i = 0; i < 8; i++) {
		fprintf(stderr, "%08x ", p[i]);
	}
	fprintf(stderr, "\n");
}
*/


// F: HASH256(toByte(0, 32) || KEY || M)
static void hash256_f_init(HASH256_CTX *hash256_ctx, const uint8_t key[32])
{
	uint8_t hash_id[32] = {0};

	hash256_init(hash256_ctx);
	hash256_update(hash256_ctx, hash_id, 32);
	hash256_update(hash256_ctx, key, 32);
}

// H: HASH256(toByte(1, 32) || KEY || M), M = (LEFT XOR BM_0) || (RIGHT XOR BM_1)
static void hash256_h_init(HASH256_CTX *hash256_ctx, const uint8_t key[32])
{
	uint8_t hash_id[32] = {0};
	hash_id[31] = 1;

	hash256_init(hash256_ctx);
	hash256_update(hash256_ctx, hash_id, 32);
	hash256_update(hash256_ctx, key, 32);
}

// H_msg: HASH256(toByte(2, 32) || KEY || M), u[64] KEY = r[32] || XMSS_ROOT[32] || toByte(idx_sig, 32)
static void hash256_h_msg_init(HASH256_CTX *hash256_ctx, const uint8_t key[96])
{
	uint8_t hash_id[32] = {0};
	hash_id[31] = 2;

	hash256_init(hash256_ctx);
	hash256_update(hash256_ctx, hash_id, 32);
	hash256_update(hash256_ctx, key, 96);
}

// PRF: HASH256(toByte(3, 32) || KEY[32] || M)
static void hash256_prf_init(HASH256_CTX *hash256_ctx, const uint8_t key[32])
{
	uint8_t hash_id[32] = {0};
	hash_id[31] = 3;

	hash256_init(hash256_ctx);
	hash256_update(hash256_ctx, hash_id, 32);
	hash256_update(hash256_ctx, key, 32);
}

// PRF_keygen: HASH256(toByte(4, 32) || KEY[32] || M)
// 	follow github.com/XMSS/xmss-reference
static void hash256_prf_keygen_init(HASH256_CTX *hash256_ctx, const uint8_t key[32])
{
	uint8_t hash_id[32] = {0};
	hash_id[31] = 4;

	hash256_init(hash256_ctx);
	hash256_update(hash256_ctx, hash_id, 32);
	hash256_update(hash256_ctx, key, 32);
}

static void wots_chain(const uint8_t x[32], int start, int steps,
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32], uint8_t pk[32])
{
	HASH256_CTX hash256_ctx;
	uint8_t state[32];
	uint8_t adrs[32];
	uint8_t key[32];
	uint8_t bitmask[32];
	int i;

	memcpy(adrs, in_adrs, 32);
	memcpy(state, x, 32);
	assert(start + steps <= 15);

	for (i = start; i < start + steps; i++) {
		adrs_set_hash_address(adrs, i);

		// key = prf(seed, adrs)
		hash256_ctx = *prf_seed_ctx;
		adrs_set_key_and_mask(adrs, 0);
		hash256_update(&hash256_ctx, adrs, sizeof(adrs));
		hash256_finish(&hash256_ctx, key);

		// bitmask = prf(seed, adrs)
		hash256_ctx = *prf_seed_ctx;
		adrs_set_key_and_mask(adrs, 1);
		hash256_update(&hash256_ctx, adrs, sizeof(adrs));
		hash256_finish(&hash256_ctx, bitmask);

		// state = f(key, state xor bitmask)
		gmssl_memxor(state, state, bitmask, 32);
		hash256_f_init(&hash256_ctx, key);
		hash256_update(&hash256_ctx, state, 32);
		hash256_finish(&hash256_ctx, state);
	}

	memcpy(pk, state, 32);
}

void sm3_wots_derive_sk(const uint8_t secret[32], const uint8_t seed[32], const uint8_t in_adrs[32], hash256_bytes_t sk[67])
{
	HASH256_CTX prf_keygen_ctx;
	HASH256_CTX prf_ctx;
	uint8_t adrs[32];
	int i;

	hash256_prf_keygen_init(&prf_keygen_ctx, secret);

	memcpy(adrs, in_adrs, 32);
	adrs_set_hash_address(adrs, 0);
	adrs_set_key_and_mask(adrs, 0);

	for (i = 0; i < 67; i++) {
		// sk[i] = prf(secret, toBytes(i,32))
		prf_ctx = prf_keygen_ctx;
		adrs_set_chain_address(adrs, i);
		hash256_update(&prf_ctx, seed, 32);
		hash256_update(&prf_ctx, adrs, 32);
		hash256_finish(&prf_ctx, sk[i]);
	}
}

void sm3_wots_derive_pk(const hash256_bytes_t sk[67],
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	hash256_bytes_t pk[67])
{
	uint8_t adrs[32];
	int i;

	memcpy(adrs, in_adrs, 32);

	for (i = 0; i < 67; i++) {
		adrs_set_chain_address(adrs, i);
		wots_chain(sk[i], 0, 15, prf_seed_ctx, adrs, pk[i]);
	}
}

static void base_w_and_checksum(const uint8_t dgst[32], uint8_t msg[67])
{
	int csum = 0;
	int sbits;
	int i;

	for (i = 0; i < 32; i++) {
		msg[2 * i]     = dgst[i] >> 4;
		msg[2 * i + 1] = dgst[i] & 0xf;
	}
	for (i = 0; i < 64; i++) {
		csum += 15 - msg[i];
	}
	// csum = csum << (8 - ((len_2 * lg(w)) %8)) = (8 - (3*4)%8) = 8 - 4 = 4
	sbits = (8 - ((3 * 4) % 8));
	csum <<= sbits;

	// len_2_bytes = ceil((len_2 * lg(w)) / 8) = ceil(12/8) = 2
	uint8_t csum_bytes[2];
	csum_bytes[0] = (csum >> 8) & 0xff;
	csum_bytes[1] = csum & 0xff;

	msg[64] = csum_bytes[0] >> 4;
	msg[65] = csum_bytes[0] & 0xf;
	msg[66] = csum_bytes[1] >> 4;
}

void sm3_wots_do_sign(const hash256_bytes_t sk[67],
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	const uint8_t dgst[32], hash256_bytes_t sig[67])
{
	uint8_t adrs[32];
	uint8_t msg[67];
	uint32_t i;

	memcpy(adrs, in_adrs, 32);

	base_w_and_checksum(dgst, msg);

	for (i = 0; i < 67; i++) {
		adrs_set_chain_address(adrs, i);
		wots_chain(sk[i], 0, msg[i], prf_seed_ctx, adrs, sig[i]);
	}
}

void sm3_wots_sig_to_pk(const hash256_bytes_t sig[67], const uint8_t dgst[32],
	const  HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	hash256_bytes_t pk[67])
{
	uint8_t adrs[32];
	uint8_t msg[67];
	int i;

	memcpy(adrs, in_adrs, 32);

	base_w_and_checksum(dgst, msg);

	for (i = 0; i < 67; i++) {
		adrs_set_chain_address(adrs, i);
		wots_chain(sig[i], msg[i], 15 - msg[i], prf_seed_ctx, adrs, pk[i]);
	}
}

static void randomized_hash(const uint8_t left[32], const uint8_t right[32],
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	uint8_t out[32])
{
	HASH256_CTX hash256_ctx;
	uint8_t adrs[32];
	uint8_t key[32];
	uint8_t bitmask[64];

	memcpy(adrs, in_adrs, 32);

	// key = prf(seed, adrs)
	hash256_ctx = *prf_seed_ctx;
	adrs_set_key_and_mask(adrs, 0);
	hash256_update(&hash256_ctx, adrs, 32);
	hash256_finish(&hash256_ctx, key);

	// bm_0 = prf(seed, adrs)
	hash256_ctx = *prf_seed_ctx;
	adrs_set_key_and_mask(adrs, 1);
	hash256_update(&hash256_ctx, adrs, 32);
	hash256_finish(&hash256_ctx, bitmask);

	// bm_1 = prf(seed, adrs)
	hash256_ctx = *prf_seed_ctx;
	adrs_set_key_and_mask(adrs, 2);
	hash256_update(&hash256_ctx, adrs, 32);
	hash256_finish(&hash256_ctx, bitmask + 32);

	// return h(key, (left xor bm_0) || (right xor bm_1))
	hash256_h_init(&hash256_ctx, key);
	gmssl_memxor(bitmask, bitmask, left, 32);
	gmssl_memxor(bitmask + 32, bitmask + 32, right, 32);
	hash256_update(&hash256_ctx, bitmask, 64);
	hash256_finish(&hash256_ctx, out);
}

static void build_ltree(const hash256_bytes_t in_pk[67],
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	uint8_t wots_root[32])
{
	hash256_bytes_t pk[67];
	uint8_t adrs[32];
	uint32_t tree_height = 0;
	int len = 67;
	uint32_t i;

	memcpy(pk, in_pk, sizeof(pk));
	memcpy(adrs, in_adrs, 32);

	adrs_set_tree_height(adrs, tree_height++);

	while (len > 1) {
		for (i = 0; i < (uint32_t)len/2; i++) {
			adrs_set_tree_index(adrs, i);
			randomized_hash(pk[2 * i], pk[2 * i + 1], prf_seed_ctx, adrs, pk[i]);
		}
		if (len % 2) {
			memcpy(pk[len/2], pk[len-1], 32); //pk[len/2] = pk[len - 1];
		}

		len = (len + 1)/2;
		adrs_set_tree_height(adrs, tree_height++);
	}

	memcpy(wots_root, pk[0], 32);
}

// len(tree) = 2^h - 1
// root = tree[len(tree) - 1] = tree[2^h - 2]
static void build_hash_tree(const hash256_bytes_t *leaves, int height,
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	hash256_bytes_t *tree)
{
	uint8_t adrs[32];
	int n = 1 << height;
	int h, i;

	memcpy(adrs, in_adrs, 32);
	adrs_set_type(adrs, 2);

	for (h = 0; h < height; h++) {
		adrs_set_tree_height(adrs, h);

		n >>= 1;
		for (i = 0; i < n; i++) {
			adrs_set_tree_index(adrs, i);
			randomized_hash(leaves[2*i], leaves[2*i + 1], prf_seed_ctx, adrs, tree[i]);
		}
		leaves = tree;
		tree += n;
	}
}

void sm3_xmss_derive_root(const uint8_t xmss_secret[32], int height,
	const uint8_t seed[32],
	hash256_bytes_t *tree, uint8_t xmss_root[32])
{
	HASH256_CTX prf_keygen_ctx;
	HASH256_CTX prf_seed_ctx;
	uint8_t adrs[32] = {0};
	uint32_t i;

	hash256_prf_keygen_init(&prf_keygen_ctx, xmss_secret);
	hash256_prf_init(&prf_seed_ctx, seed);

	// generate all the wots pk[]
	for (i = 0; i < (uint32_t)(1<<height); i++) {
		//HASH256_CTX prf_ctx = prf_keygen_ctx;
		hash256_bytes_t wots_sk[67];
		hash256_bytes_t wots_pk[67];

		// xmss_secret => wots_sk[0..67] => wots_pk[0..67]
		//	follow github.com/XMSS/xmss-reference
		adrs_set_type(adrs, 0);
		adrs_set_ots_address(adrs, i);
		sm3_wots_derive_sk(xmss_secret, seed, adrs, wots_sk);
		sm3_wots_derive_pk(wots_sk, &prf_seed_ctx, adrs, wots_pk);

		// wots_pk[0..67] => wots_root
		adrs_set_type(adrs, 1);
		adrs_set_ltree_address(adrs, i);
		build_ltree(wots_pk, &prf_seed_ctx, adrs, tree[i]);
	}

	// build full hash_tree
	memset(adrs, 0, sizeof(adrs));
	build_hash_tree(tree, height, &prf_seed_ctx, adrs, tree + (1<<height));
	memcpy(xmss_root, tree + (1 << (height + 1)) - 2, 32);
}

static void build_auth_path(const hash256_bytes_t *tree, int height, int index, hash256_bytes_t *path)
{
	int h;
	for (h = 0; h < height; h++) {
		memcpy(path[h], tree[index ^ 1], 32);
		tree += (1 << (height - h));
		index >>= 1;
	}
}

void sm3_xmss_do_sign(const uint8_t xmss_secret[32], int index,
	const uint8_t seed[32], const uint8_t in_adrs[32], int height,
	const hash256_bytes_t *tree,
	const uint8_t dgst[32],
	hash256_bytes_t wots_sig[67],
	hash256_bytes_t *auth_path)
{
	HASH256_CTX prf_seed_ctx;
	uint8_t adrs[32];
	hash256_bytes_t wots_sk[67];

	hash256_prf_init(&prf_seed_ctx, seed);
	memcpy(adrs, in_adrs, 32);

	// xmss_secret => wots_sk[0..67] => wots_pk[0..67]
	adrs_set_type(adrs, 0);
	adrs_set_ots_address(adrs, index);
	sm3_wots_derive_sk(xmss_secret, seed, adrs, wots_sk);

	sm3_wots_do_sign(wots_sk, &prf_seed_ctx, adrs, dgst, wots_sig);

	build_auth_path(tree, height, index, auth_path);
}

void sm3_xmss_sig_to_root(const hash256_bytes_t wots_sig[67], int index, const hash256_bytes_t *auth_path,
	const uint8_t seed[32], const uint8_t in_adrs[32], int height,
	const uint8_t dgst[32],
	uint8_t xmss_root[32])
{
	HASH256_CTX prf_seed_ctx;
	uint8_t adrs[32];
	hash256_bytes_t wots_pk[67];
	uint8_t *node = xmss_root;
	int h;

	hash256_prf_init(&prf_seed_ctx, seed);

	memcpy(adrs, in_adrs, 32);

	adrs_set_type(adrs, 0);
	adrs_set_ots_address(adrs, index);
	sm3_wots_sig_to_pk(wots_sig, dgst, &prf_seed_ctx, adrs, wots_pk);

	adrs_set_type(adrs, 1);
	adrs_set_ltree_address(adrs, index);
	build_ltree(wots_pk, &prf_seed_ctx, adrs, node);

	adrs_set_type(adrs, 2);
	adrs_set_tree_index(adrs, index);
	for (h = 0; h < height; h++) {
		int right = index & 1;
		index >>= 1;
		adrs_set_tree_height(adrs, h);
		adrs_set_tree_index(adrs, index);
		if (right)
			randomized_hash(auth_path[h], node, &prf_seed_ctx, adrs, node);
		else	randomized_hash(node, auth_path[h], &prf_seed_ctx, adrs, node);
	}
}

int sm3_xmss_height_from_oid(uint32_t *height, uint32_t id)
{
	switch (id) {
	case XMSS_SM3_10: *height = 10; break;
	case XMSS_SM3_16: *height = 16; break;
	case XMSS_SM3_20: *height = 20; break;
	case XMSS_SHA256_10: *height = 10; break;
	case XMSS_SHA256_16: *height = 16; break;
	case XMSS_SHA256_20: *height = 20; break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int sm3_xmss_key_generate(SM3_XMSS_KEY *key, uint32_t oid)
{
	uint32_t height;

	if (sm3_xmss_height_from_oid(&height, oid) != 1) {
		error_print();
		return -1;
	}

	key->oid = oid;
	key->index = 0;
	if (rand_bytes(key->seed, 32) != 1
		|| rand_bytes(key->secret, 32) != 1
		|| rand_bytes(key->prf_key, 32) != 1
		|| !(key->tree = malloc(32 * (1 << height) * 2 - 1))) {
		error_print();
		return -1;
	}
	sm3_xmss_derive_root(key->secret, height, key->seed, key->tree, key->root);

	return 1;
}

void sm3_xmss_key_cleanup(SM3_XMSS_KEY *key)
{
	if (key->tree) {
		free(key->tree);
	}
	gmssl_secure_clear(key, sizeof(*key));
}

int sm3_xmss_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_XMSS_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "oid: 0x%08X\n", key->oid);
	format_bytes(fp, fmt, ind, "seed", key->seed, 32);
	format_bytes(fp, fmt, ind, "root", key->root, 32);
	format_bytes(fp, fmt, ind, "secret", key->secret, 32);
	format_bytes(fp, fmt, ind, "prf_key", key->prf_key, 32);
	format_print(fp, fmt, ind, "index: %u\n", key->index);
	return 1;
}

int sm3_xmss_key_get_height(const SM3_XMSS_KEY *key, uint32_t *height)
{
	if (sm3_xmss_height_from_oid(height, key->oid) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm3_xmss_key_to_bytes(const SM3_XMSS_KEY *key, uint8_t *out, size_t *outlen)
{
	uint32_t height;
	size_t tree_size;
	uint8_t *p;

	if (!outlen) {
		error_print();
		return -1;
	}

	if (sm3_xmss_height_from_oid(&height, key->oid) != 1) {
		error_print();
		return -1;
	}
	tree_size = 32 * ((1 << (height + 1)) - 1);
	if (!key->tree) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = 4 + 32*4 + 4 + tree_size;
		return 1;
	}

	p = out;
	uint32_to_bytes(key->oid, p); p += 4;
	memcpy(p, key->seed, 32); p += 32;
	memcpy(p, key->root, 32); p += 32;
	memcpy(p, key->secret, 32); p += 32;
	memcpy(p, key->prf_key, 32); p += 32;
	uint32_to_bytes(key->index, p); p += 4;
	memcpy(p, key->tree, tree_size); p += tree_size;
	*outlen = p - out;

	return 1;
}

int sm3_xmss_key_from_bytes(SM3_XMSS_KEY *key, const uint8_t *in, size_t inlen)
{
	uint32_t height;
	size_t tree_size;
	const uint8_t *p;

	if (inlen < 4) {
		error_print();
		return -1;
	}
	p = in;
	key->oid = uint32_from_bytes(p); p += 4;

	if (sm3_xmss_height_from_oid(&height, key->oid) != 1) {
		error_print();
		return -1;
	}
	tree_size = 32 * ((1 << (height + 1)) - 1);
	if (inlen != (4 + 32 * 4 + 4 + tree_size)) {
		error_print();
		return -1;
	}
	memcpy(key->seed, p, 32); p += 32;
	memcpy(key->root, p, 32); p += 32;
	memcpy(key->secret, p, 32); p += 32;
	memcpy(key->prf_key, p, 32); p += 32;

	key->index = uint32_from_bytes(p); p += 4;
	if (key->index >= (uint32_t)(1 << height)) {
		error_print();
		return -1;
	}

	if (!(key->tree = malloc(tree_size))) {
		error_print();
		return -1;
	}
	memcpy(key->tree, p, tree_size);
	return 1;
}

int sm3_xmss_public_key_to_bytes(const SM3_XMSS_KEY *key, uint8_t *out, size_t *outlen)
{
	uint32_t height;
	uint8_t *p;

	if (!outlen) {
		error_print();
		return -1;
	}

	if (sm3_xmss_height_from_oid(&height, key->oid) != 1) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = 4 + 32 + 32;
		return 1;
	}

	p = out;
	uint32_to_bytes(key->oid, p); p += 4;
	memcpy(p, key->seed, 32); p += 32;
	memcpy(p, key->root, 32); p += 32;
	*outlen = p - out;

	return 1;
}

// FIXME: check input length
int sm3_xmss_public_key_from_bytes(SM3_XMSS_KEY *key, const uint8_t *in, size_t inlen)
{
	uint32_t height;
	const uint8_t *p;

	if (inlen != 4 + 32 * 2) {
		error_print();
		return -1;
	}
	p = in;
	key->oid = uint32_from_bytes(p); p += 4;
	if (sm3_xmss_height_from_oid(&height, key->oid) != 1) {
		error_print();
		return -1;
	}
	memcpy(key->seed, p, 32); p += 32;
	memcpy(key->root, p, 32); p += 32;
	return 1;
}

int sm3_xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *in, size_t inlen)
{
	uint32_t index;
	SM3_XMSS_SIGNATURE *sig = (SM3_XMSS_SIGNATURE *)in;
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	index = uint32_from_bytes(sig->index);
	format_print(fp, fmt, ind, "index: %u\n", index);
	format_bytes(fp, fmt, ind, "random", sig->random, 32);
	format_print(fp, fmt, ind, "wots_sig\n");
	for (i = 0; i < 67; i++) {
		format_print(fp, fmt, ind+4, "%d ", i);
		format_bytes(fp, fmt, 0, "", sig->wots_sig[i], 32);
	}
	format_print(fp, fmt, ind, "auth_path\n");

	assert(sizeof(SM3_XMSS_SIGNATURE) == 4 + 32 * (68 + 20));
	inlen -= 4 + 32 * 68;
	for (i = 0; i < 20 && inlen >= 32; i++) {
		format_print(fp, fmt, ind+4, "%d ", i);
		format_bytes(fp, fmt, 0, "", sig->auth_path[i], 32);
		inlen -= 32;
	}

	return 1;
}

int sm3_xmss_sign_init(SM3_XMSS_SIGN_CTX *ctx, const SM3_XMSS_KEY *key)
{
	HASH256_CTX prf_ctx;
	uint8_t hash_id[32] = {0};
	uint8_t index_buf[32] = {0};

	// r = PRF(SK_PRF, toByte(idx_sig, 32));
	hash256_prf_init(&prf_ctx, key->prf_key);
	uint32_to_bytes(key->index, index_buf + 28);
	hash256_update(&prf_ctx, index_buf, 32);
	hash256_finish(&prf_ctx, ctx->random);

	// H_msg(M) := HASH256(toByte(2, 32) || r || XMSS_ROOT || toByte(idx_sig, 32) || M)
	hash256_init(&ctx->hash256_ctx);
	hash_id[31] = 2;
	hash256_update(&ctx->hash256_ctx, hash_id, 32);
	hash256_update(&ctx->hash256_ctx, ctx->random, 32);
	hash256_update(&ctx->hash256_ctx, key->root, 32);
	hash256_update(&ctx->hash256_ctx, index_buf, 32);

	return 1;
}

int sm3_xmss_sign_update(SM3_XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (data && datalen) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

int sm3_xmss_sign_finish(SM3_XMSS_SIGN_CTX *ctx, const SM3_XMSS_KEY *key, uint8_t *sigbuf, size_t *siglen)
{
	SM3_XMSS_SIGNATURE *sig = (SM3_XMSS_SIGNATURE *)sigbuf;
	uint8_t adrs[32] = {0};
	uint8_t dgst[32];
	uint32_t height;

	hash256_finish(&ctx->hash256_ctx, dgst);

	sm3_xmss_key_get_height(key, &height);
	sm3_xmss_do_sign(key->secret, key->index, key->seed, adrs, height, key->tree, dgst,
		sig->wots_sig, sig->auth_path);

	uint32_to_bytes(key->index, sig->index);
	memcpy(sig->random, ctx->random, 32);

	*siglen = 4 + 32 * (68 + height);
	return 1;
}

int sm3_xmss_verify_init(SM3_XMSS_SIGN_CTX *ctx, const SM3_XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen)
{
	SM3_XMSS_SIGNATURE *sig = (SM3_XMSS_SIGNATURE *)sigbuf;
	uint8_t hash_id[32] = {0};
	uint8_t index_buf[32] = {0};

	memcpy(index_buf + 28, sig->index, 4);

	hash256_init(&ctx->hash256_ctx);
	hash_id[31] = 2;
	hash256_update(&ctx->hash256_ctx, hash_id, 32);
	hash256_update(&ctx->hash256_ctx, sig->random, 32);
	hash256_update(&ctx->hash256_ctx, key->root, 32);
	hash256_update(&ctx->hash256_ctx, index_buf, 32);

	return 1;
}

int sm3_xmss_verify_update(SM3_XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (data && datalen) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

int sm3_xmss_verify_finish(SM3_XMSS_SIGN_CTX *ctx, const SM3_XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen)
{

	const SM3_XMSS_SIGNATURE *sig = (const SM3_XMSS_SIGNATURE *)sigbuf;
	uint8_t adrs[32] = {0};
	uint8_t dgst[32];
	uint32_t index, height;
	uint8_t xmss_root[32];

	hash256_finish(&ctx->hash256_ctx, dgst);

	sm3_xmss_key_get_height(key, &height);
	index = uint32_from_bytes(sig->index);

	sm3_xmss_sig_to_root(sig->wots_sig, index, sig->auth_path, key->seed, adrs, height, dgst, xmss_root);

	if (memcmp(xmss_root, key->root, 32) != 0) {
		error_print();
		return 0;
	}
	return 1;
}
