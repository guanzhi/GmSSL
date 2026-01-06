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
	const sphincs_secret_t seed, const sphincs_adrs_t in_adrs,
	hash256_t parent)
{
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



void fors_tree_hash(const sphincs_secret_t seed, const sphincs_secret_t secret,
	int start, int height, const sphincs_adrs_t adrs)
{
}




void fors_derive_secret(const sphincs_secret_t seed, const sphincs_secret_t secret,
	const sphincs_adrs_t in_adrs, uint32_t fors_index, sphincs_secret_t sk)
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






/*
int fors_derive_merkle_tree(const sphincs_hash_t sk_seed, const sphincs_adrs_t adrs, sphincs_hash_t *tree)
{
	int r;

	int a = 12;
	int t = (1 << a);


	uint8_t rbytes[4];
	HASH256_CTX ctx;
	hash256_t x[34];
	hash256_t pub;
	hash256_t *T = tree - 1;

	for (r = 2*t - 1; r >= 1; r--) {

		PUTU32(rbytes, r);

		if (r >= t) {
			int q = r - n;


			sm3_lmots_derive_secrets(seed, I, q, x);
			sm3_lmots_secrets_to_public_hash(I, q, x, pub);



			// H(I||u32str(r)||u16str(D_LEAF)||OTS_PUB_HASH[r-2^h])
			hash256_init(&ctx);
			hash256_update(&ctx, I, 16);
			hash256_update(&ctx, rbytes, 4);
			hash256_update(&ctx, D_LEAF, 2);
			hash256_update(&ctx, pub, 32);
			hash256_finish(&ctx, T[r]);

		} else {
			// H(I||u32str(r)||u16str(D_INTR)||T[2*r]||T[2*r+1])
			hash256_init(&ctx);
			hash256_update(&ctx, I, 16);
			hash256_update(&ctx, rbytes, 4);
			hash256_update(&ctx, D_INTR, 2);
			hash256_update(&ctx, T[2*r], 32);
			hash256_update(&ctx, T[2*r + 1], 32);
			hash256_finish(&ctx, T[r]);
		}
	}
}



int fors_derive_secrets(const sphincs_hash_t sk_seed, const sphincs_adrs_t adrs, uint32_t index, sphincs_hash_t sk[14 * 4096])
{
	sphincs_adrs_t sk_adrs;
	uint32_t i;

	memcpy(sk_adrs, adrs, sizeof(sphincs_adrs_t));
	sphincs_adrs_set_type(sk_adrs, SPHINCSX_ADRS_TYPE_FORS_KEYGEN);
	sphincs_adrs_set_tree_height(sk_adrs, 0);
	sphincs_adrs_set_tree_index(sk_adrs, index);

	for (i = 0; i < SPHINCSX_FORS_NUM_SK; i++) {
		sphincs_adrs_set_keypair_addrss(sk_adrs, i);
		sphincs_prf(sk_seed, sk_adrs, sk[i]);
	}

	return 1;
}


void fors_treehash(const sphincs_hash_t sk_seed, const sphincs_hash_t pk_seed)
{
}

void fors_secrets_to_public_root(const sphincs_hash_t sk[SPHINCSX_FORS_NUM_SK],
	const sphincs_adrs_t pk_seed, const sphincs_adrs_t adrs,
	sphincs_hash_t pub)
{

}

int fors_treehash(const sphincs_adrs_t sk_seed, cosnt sphincs_adrs_t pk_seed,
	unsigned int s, unsigned int z, const sphincs_adrs_t fors_adrs,
	uint8_t out[16])
{
}
*/

