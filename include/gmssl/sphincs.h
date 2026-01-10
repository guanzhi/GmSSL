/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SPHINCS_H
#define GMSSL_SPHINCS_H


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/hash256.h>
#ifdef ENABLE_SHA2
#include <gmssl/sha2.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif


#if defined(ENABLE_SPHINCS_CROSSCHECK) && defined(ENABLE_SHA2)
# define HASH256_CTX		SHA256_CTX
# define hash256_init		sha256_init
# define hash256_update		sha256_update
# define hash256_finish		sha256_finish
# define HASH256_BLOCK_SIZE	SHA256_BLOCK_SIZE
#else
# define HASH256_CTX		SM3_CTX
# define hash256_init		sm3_init
# define hash256_update		sm3_update
# define hash256_finish		sm3_finish
# define HASH256_BLOCK_SIZE	SM3_BLOCK_SIZE
#endif



enum {
	SPHINCS_ADRS_TYPE_WOTS_HASH	= 0,
	SPHINCS_ADRS_TYPE_WOTS_PK	= 1,
	SPHINCS_ADRS_TYPE_TREE		= 2,
	SPHINCS_ADRS_TYPE_FORS_TREE	= 3,
	SPHINCS_ADRS_TYPE_FORS_ROOTS	= 4,
	SPHINCS_ADRS_TYPE_WOTS_PRF	= 5,
	SPHINCS_ADRS_TYPE_FORS_PRF	= 6,
};

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 0
	uint32_t keypair_address;
	uint32_t chain_address;
	uint32_t hash_address;
} SPHINCS_ADRS_WOTS_HASH;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 1
	uint32_t keypair_address;
	uint32_t padding[2];
} SPHINCS_ADRS_WOTS_PK;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 2
	uint32_t padding; // = 0
	uint32_t tree_height;
	uint32_t tree_index;
} SPHINCS_ADRS_TREE;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 3
	uint32_t keypair_address;
	uint32_t tree_height;
	uint32_t tree_index;
} SPHINCS_ADRS_FORS_TREE;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 4
	uint32_t keypair_address;
	uint32_t padding[2];
} SPHINCS_ADRS_FORS_ROOTS;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 5
	uint32_t keypair_address;
	uint32_t chain_address;
	uint32_t hash_address; // = 0
} SPHINCS_ADRS_WOTS_PRF;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 6
	uint32_t keypair_address;
	uint32_t tree_height; // = 0
	uint32_t tree_index;
} SPHINCS_ADRS_FORS_PRF;

typedef uint8_t sphincs_adrs_t[32];

void sphincs_adrs_copy_layer_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_tree_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_type(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_keypair_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_chain_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_hash_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_tree_height(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_tree_index(sphincs_adrs_t dst, const sphincs_adrs_t src);

void sphincs_adrs_set_layer_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_tree_address(sphincs_adrs_t adrs, const uint64_t address);
void sphincs_adrs_set_type(sphincs_adrs_t adrs, const uint32_t type);
void sphincs_adrs_set_keypair_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_chain_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_hash_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_tree_height(sphincs_adrs_t adrs, uint32_t height);
void sphincs_adrs_set_tree_index(sphincs_adrs_t adrs, uint32_t index);

int sphincs_adrs_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_adrs_t adrs);

typedef struct {
	uint8_t layer_address;
	uint64_t tree_address;
	uint8_t type;
	uint32_t others[3];
} SPHINCS_ADRSC;

#define SPHINCS_ADRSC_SIZE 22

typedef uint8_t sphincs_adrsc_t[22];

void sphincs_adrs_compress(const sphincs_adrs_t adrs, sphincs_adrsc_t adrsc);

// TODO: remove this!
typedef struct {
	char *name;
	size_t secret_size;
	size_t height;
	size_t layers;
	size_t fors_height;
	size_t fors_trees;
	int winternitz_w;
	int bitsec;
	int sec_level;
	size_t siglen;
} SPHINCS_PARAMS;

// sizeof(sphincs_hash128_t) == n, when sm3/sha256, n == 16
typedef uint8_t sphincs_hash128_t[16];



#define SPHINCS_WOTS_NUM_CHAINS 35

typedef sphincs_hash128_t sphincs_wots_key_t[35];
typedef sphincs_hash128_t sphincs_wots_sig_t[35];

int sphincs_wots_key_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_wots_key_t key);
int sphincs_wots_sig_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_wots_sig_t sig);

void sphincs_wots_derive_sk(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_wots_key_t sk);
void sphincs_wots_chain(const sphincs_hash128_t x,
	const sphincs_hash128_t seed, const sphincs_adrs_t ots_adrs,
	int start, int steps, sphincs_hash128_t y);
void sphincs_wots_sk_to_pk(const sphincs_wots_key_t sk,
	const sphincs_hash128_t seed, const sphincs_adrs_t ots_adrs,
	sphincs_wots_key_t pk);
void sphincs_wots_sign(const sphincs_wots_key_t sk,
	const sphincs_hash128_t seed, const sphincs_adrs_t ots_adrs,
	const sphincs_hash128_t dgst, sphincs_wots_sig_t sig);
void sphincs_wots_sig_to_pk(const sphincs_wots_sig_t sig,
	const sphincs_hash128_t seed, const sphincs_adrs_t ots_adrs,
	const sphincs_hash128_t dgst, sphincs_wots_key_t pk);
void sphincs_wots_pk_to_root(const sphincs_wots_key_t pk,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_hash128_t root);


#if 1 // SPHINCS+_128s
# define SPHINCS_HYPERTREE_HEIGHT 63
# define SPHINCS_HYPERTREE_LAYERS 7
# define SPHINCS_FORS_HEIGHT 12
# define SPHINCS_FORS_NUM_TREES 14
# define SPHINCS_FORS_DIGEST_SIZE 21
#else
# define SPHINCS_HYPERTREE_HEIGHT 66
# define SPHINCS_HYPERTREE_LAYERS 22
# define SPHINCS_FORS_HEIGHT 6
# define SPHINCS_FORS_NUM_TREES 33
#endif



#define SPHINCS_FORS_TREE_HEIGHT 12
#define SPHINCS_FORS_TREE_NUM_NODES ((1 << (SPHINCS_FORS_TREE_HEIGHT + 1)) - 1)


#define SPHINCS_FORS_NUM_NODES (SPHINCS_FORS_TREE_NUM_NODES * SPHINCS_FORS_NUM_TRESS + 1)





// FORS (Forest Of Random Subsets)

// fors_tree
// fors_tree_height
// fors_tree_root
// fors_forest
// fors_num_trees
// fors_root

#define SPHINCS_XMSS_HEIGHT (SPHINCS_HYPERTREE_HEIGHT/SPHINCS_HYPERTREE_LAYERS)
#define SPHINCS_XMSS_NUM_NODES	((1 << (SPHINCS_XMSS_HEIGHT + 1)) - 1)







/*

  SPHINCS+_128s/SM3


	H_msg(R, PK.seed, PK.root, M)
		= MGF1-SM3(R
			||PK.seed
			||SM3(R||PK.seed||PK.root||M),
			m),


	1. fors_index: 12 * 14 = 168 bits = 21 bytes
	2. tree_index: 63 - 63/7 = 54 bits = 7 bytes
	3. leaf_index: 9 bits = 2 bytes
	total: 30 bytes, 1 MGF1-SM3 output



  SPHINCS+_128f/SM3

	1. fors_index: 6 * 33 = 198 bits = 25 bytes
	2. tree_address: 66 - 66/22 = 63 bits = 8 bytes
	3. keypair_address (leaf_index): 3 bits = 1 byte
	total: 34 bytes, so need 2 MGF1-SM3 output

*/



void sphincs_xmss_tree_hash(
	const sphincs_hash128_t left_child, const sphincs_hash128_t right_child,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	hash256_t parent);
void sphincs_xmss_build_tree(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES]);
void sphincs_xmss_build_auth_path(const sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES],
	uint32_t tree_index, sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT]);
void sphincs_xmss_build_root(const sphincs_hash128_t wots_root, uint32_t tree_index,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	const sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT],
	hash256_t root);


typedef struct {
	sphincs_wots_sig_t wots_sig;
	sphincs_hash128_t auth_path[22]; // sphincs+_128f height = 22
} SPHINCS_XMSS_SIGNATURE;

void sphincs_xmss_sign(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs, uint32_t keypair_address,
	const sphincs_hash128_t tbs_root, // to be signed xmss_root or fors_forest_root
	SPHINCS_XMSS_SIGNATURE *sig);
void sphincs_xmss_sig_to_root(const SPHINCS_XMSS_SIGNATURE *sig,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs, uint32_t keypair_address,
	const sphincs_hash128_t tbs_root, // to be signed xmss_root or fors_forest_root
	sphincs_hash128_t xmss_root);


void sphincs_hypertree_derive_root(const sphincs_hash128_t secret, const sphincs_hash128_t seed,
	sphincs_hash128_t root);
void sphincs_hypertree_sign(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, uint64_t tree_address, uint32_t keypair_address,
	const sphincs_hash128_t tbs_fors_forest_root,
	SPHINCS_XMSS_SIGNATURE sig[SPHINCS_HYPERTREE_LAYERS]);
int sphincs_hypertree_verify(const sphincs_hash128_t top_xmss_root,
	const sphincs_hash128_t seed, uint64_t tree_address, uint32_t keypair_address,
	const sphincs_hash128_t tbs_fors_forest_root,
	const SPHINCS_XMSS_SIGNATURE sig[SPHINCS_HYPERTREE_LAYERS]);



typedef uint8_t sphincs_fors_digest_t[21];


void sphincs_fors_derive_sk(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	uint32_t fors_index, sphincs_hash128_t sk);

void sphincs_fors_build_tree(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs, int tree_addr,
	sphincs_hash128_t tree[SPHINCS_FORS_TREE_NUM_NODES]);;
void sphincs_fors_derive_root(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_hash128_t root);


typedef struct {
	sphincs_hash128_t fors_sk[SPHINCS_FORS_NUM_TREES];
	sphincs_hash128_t auth_path[SPHINCS_FORS_NUM_TREES][SPHINCS_FORS_HEIGHT];
} SPHINCS_FORS_SIGNATURE;

void sphincs_fors_sign(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	const uint8_t dgst[21],
	SPHINCS_FORS_SIGNATURE *sig);
void sphincs_fors_sig_to_root(const SPHINCS_FORS_SIGNATURE *sig,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	const uint8_t dgst[21], sphincs_hash128_t root);


#define SPHINCS_FORS_SIGNATURE_SIZE sizeof(SPHINCS_FORS_SIGNATURE)
int sphincs_fors_signature_to_bytes(const SPHINCS_FORS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sphincs_fors_signature_from_bytes(SPHINCS_FORS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sphincs_fors_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_FORS_SIGNATURE *sig);
int sphincs_fors_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);


typedef struct {
	sphincs_hash128_t seed;
	sphincs_hash128_t root;
} SPHINCS_PUBLIC_KEY;

typedef struct {
	SPHINCS_PUBLIC_KEY public_key;
	sphincs_hash128_t secret;
	sphincs_hash128_t sk_prf;
} SPHINCS_KEY;

#define SPHINCS_PUBLIC_KEY_SIZE sizeof(SPHINCS_PUBLIC_KEY)
#define SPHINCS_PRIVATE_KEY_SIZE sizeof(SPHINCS_KEY)

int sphincs_public_key_to_bytes(const SPHINCS_KEY *key, uint8_t **out, size_t *outlen);
int sphincs_public_key_from_bytes(SPHINCS_KEY *key, const uint8_t **in, size_t *inlen);
int sphincs_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_KEY *key);
int sphincs_private_key_to_bytes(const SPHINCS_KEY *key, uint8_t **out, size_t *outlen);
int sphincs_private_key_from_bytes(SPHINCS_KEY *key, const uint8_t **in, size_t *inlen);
int sphincs_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_KEY *key);
void sphincs_key_cleanup(SPHINCS_KEY *key);


typedef struct {
	sphincs_hash128_t random;
	SPHINCS_FORS_SIGNATURE fors_sig;
	SPHINCS_XMSS_SIGNATURE xmss_sigs[SPHINCS_HYPERTREE_LAYERS];
} SPHINCS_SIGNATURE;

int sphincs_signature_to_bytes(const SPHINCS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sphincs_signature_from_bytes(SPHINCS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sphincs_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_SIGNATURE *sig);
int sphincs_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);



#ifdef __cplusplus
}
#endif
#endif

