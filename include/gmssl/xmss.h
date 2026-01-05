/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_XMSS_H
#define GMSSL_XMSS_H


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


// Crosscheck with data from xmss-reference (SHA-256), except the XMSS signature.
#if defined(ENABLE_XMSS_CROSSCHECK) && defined(ENABLE_SHA2)
# define HASH256_CTX		SHA256_CTX
# define hash256_init		sha256_init
# define hash256_update		sha256_update
# define hash256_finish		sha256_finish
#else
# define HASH256_CTX		SM3_CTX
# define hash256_init		sm3_init
# define hash256_update		sm3_update
# define hash256_finish		sm3_finish
#endif


// ADRS scheme

enum {
	XMSS_ADRS_TYPE_OTS	= 0,
	XMSS_ADRS_TYPE_LTREE	= 1,
	XMSS_ADRS_TYPE_HASHTREE	= 2,
};

enum {
	XMSS_ADRS_GENERATE_KEY = 0,
	XMSS_ADRS_GENERATE_BITMASK = 1,
};

typedef struct {
	uint32_t layer_address; // layer index of multi-tree, 0 for lowest layer (and xmss, and OTS ADRS)
	uint64_t tree_address; // tree index of a layer, 0 for the left most (and xmss), in [0, 2^(h*(layers-1))-1]
	uint32_t type; // = XMSS_ADRS_TYPE_OTS
	uint32_t ots_address; // index of a leaf (wots+ public key) of a layer-0 xmss tree, in [0, 2^h-1]
	uint32_t chain_address; // index of wots+ chain, in [0, 67)  when w = 16
	uint32_t hash_address; // index of hash calls in a wots+ chain, in [0, w-1]
	uint32_t key_and_mask; // in { XMSS_ADRS_GENERATE_KEY, XMSS_ADRS_GENERATE_BITMASK }
} XMSS_ADRS_OTS;

typedef struct {
	uint32_t layer_address;
	uint64_t tree_address;
	uint32_t type; // = XMSS_ADRS_TYPE_LTREE
	uint32_t ltree_address;
	uint32_t tree_height;
	uint32_t tree_index;
	uint32_t key_and_mask;
} XMSS_ADRS_LTREE;

typedef struct {
	uint32_t layer_address;
	uint64_t tree_address;
	uint32_t type; // = XMSS_ADRS_TYPE_HASHTREE
	uint32_t padding; // = 0
	uint32_t tree_height;
	uint32_t tree_index;
	uint32_t key_and_mask;
} XMSS_ADRS_HASHTREE;

typedef uint8_t xmss_adrs_t[32];

void adrs_copy_layer_address(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_tree_address(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_type(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_ots_address(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_ltree_address(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_padding(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_chain_address(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_tree_height(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_hash_address(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_tree_index(xmss_adrs_t dst, const xmss_adrs_t src);
void adrs_copy_key_and_mask(xmss_adrs_t dst, const xmss_adrs_t src);

void adrs_set_layer_address(xmss_adrs_t adrs, uint32_t layer);
void adrs_set_tree_address(xmss_adrs_t adrs, uint64_t tree_addr);
void adrs_set_type(xmss_adrs_t adrs, uint32_t type);
void adrs_set_ots_address(xmss_adrs_t adrs, uint32_t address);
void adrs_set_ltree_address(xmss_adrs_t adrs, uint32_t address);
void adrs_set_padding(xmss_adrs_t adrs, uint32_t padding);
void adrs_set_chain_address(xmss_adrs_t adrs, uint32_t address);
void adrs_set_tree_height(xmss_adrs_t adrs, uint32_t height);
void adrs_set_hash_address(xmss_adrs_t adrs, uint32_t address);
void adrs_set_tree_index(xmss_adrs_t adrs, uint32_t index);
void adrs_set_key_and_mask(xmss_adrs_t adrs, uint32_t key_and_mask);

int xmss_adrs_print(FILE *fp, int fmt, int ind, const char *label, const hash256_t adrs);

// WOTS+ with SM3/SHA256

#define WOTS_WINTERNITZ_W 16 // rfc 8391 named algors only support w = 2^4 = 16
#define WOTS_NUM_CHAINS	67

typedef hash256_t wots_key_t[WOTS_NUM_CHAINS];
typedef hash256_t wots_sig_t[WOTS_NUM_CHAINS];


void wots_derive_sk(const hash256_t secret,
	const hash256_t seed, const xmss_adrs_t adrs,
	wots_key_t sk);
void wots_chain(const hash256_t x,
	const hash256_t seed, const xmss_adrs_t adrs,
	int start, int steps, hash256_t y);
void wots_sk_to_pk(const wots_key_t sk,
	const hash256_t seed, const xmss_adrs_t adrs,
	wots_key_t pk);
void wots_sign(const wots_key_t sk,
	const hash256_t seed, const xmss_adrs_t adrs,
	const hash256_t dgst, wots_sig_t sig);
void wots_sig_to_pk(const wots_sig_t sig,
	const hash256_t seed, const xmss_adrs_t adrs,
	const hash256_t dgst, wots_key_t pk);
void wots_pk_to_root(const wots_key_t pk,
	const hash256_t seed, const xmss_adrs_t adrs,
	hash256_t wots_root);
void wots_derive_root(const hash256_t secret,
	const hash256_t seed, const xmss_adrs_t adrs,
	hash256_t wots_root);
int  wots_verify(const hash256_t wots_root,
	const hash256_t seed, const xmss_adrs_t adrs,
	const hash256_t dgst, const wots_sig_t sig);



// from RFC 8391 table 7
enum {
	XMSS_SHA2_10_256	= 0x00000001,
	XMSS_SHA2_16_256	= 0x00000002,
	XMSS_SHA2_20_256	= 0x00000003,
};

enum {
	XMSS_SM3_10_256		= 0x10000001, // height = 10, sigs = 2^10
	XMSS_SM3_16_256		= 0x10000002, // height = 16, sigs = 2^16
	XMSS_SM3_20_256		= 0x10000003, // height = 20, sigs = 2^20
};

#define XMSS_MAX_HEIGHT	20

// Crosscheck with data from xmss-reference (SHA-256), except the XMSS signature.
#if defined(ENABLE_XMSS_CROSSCHECK) && defined(ENABLE_SHA2)
# define XMSS_HASH256_10_256		XMSS_SHA2_10_256
# define XMSS_HASH256_16_256		XMSS_SHA2_16_256
# define XMSS_HASH256_20_256		XMSS_SHA2_20_256
# define XMSS_HASH256_10_256_NAME	"XMSS_SHA2_10_256"
# define XMSS_HASH256_16_256_NAME	"XMSS_SHA2_16_256"
# define XMSS_HASH256_20_256_NAME	"XMSS_SHA2_20_256"
#else
# define XMSS_HASH256_10_256		XMSS_SM3_10_256
# define XMSS_HASH256_16_256		XMSS_SM3_16_256
# define XMSS_HASH256_20_256		XMSS_SM3_20_256
# define XMSS_HASH256_10_256_NAME	"XMSS_SM3_10_256"
# define XMSS_HASH256_16_256_NAME	"XMSS_SM3_16_256"
# define XMSS_HASH256_20_256_NAME	"XMSS_SM3_20_256"
#endif

char *xmss_type_name(uint32_t xmss_type);
uint32_t xmss_type_from_name(const char *name);

int xmss_type_to_height(uint32_t xmss_type, size_t *height);

size_t xmss_num_tree_nodes(size_t height);
void xmss_build_tree(const hash256_t secret,
	const hash256_t seed, const xmss_adrs_t adrs,
	size_t height, hash256_t *tree); // tree[xmss_num_tree_nodes(height)]
void xmss_build_auth_path(const hash256_t *tree, size_t height,
	uint32_t index, hash256_t *auth_path); // auth_path[height]
void xmss_build_root(const hash256_t wots_root, uint32_t index,
	const hash256_t seed, const xmss_adrs_t adrs,
	const hash256_t *auth_path, size_t height,
	hash256_t xmss_root);


typedef struct {
	uint32_t xmss_type;
	hash256_t seed;
	hash256_t root;
} XMSS_PUBLIC_KEY;

#define XMSS_PUBLIC_KEY_SIZE	(4 + 32 + 32) // = 68

typedef struct {
	XMSS_PUBLIC_KEY public_key;
	uint32_t index;
	hash256_t secret;
	hash256_t sk_prf;
	hash256_t *tree; // hash256_t[2^(h + 1) - 1]
} XMSS_KEY;

// XMSS_SHA2_10_256:     65,640
// XMSS_SHA2_16_256:  4,194,408
// XMSS_SHA2_20_256: 67,108,968
int xmss_private_key_size(uint32_t xmss_type, size_t *keysize);

//#define XMSS_PRIVATE_KEY_SIZE	(XMSS_PUBLIC_KEY_SIZE + 32 + 32 + 4) // = 136

int xmss_key_generate(XMSS_KEY *key, uint32_t xmss_type);
int xmss_key_remaining_signs(const XMSS_KEY *key, size_t *count);
int xmss_public_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen);
int xmss_public_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen);
int xmss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key);
int xmss_private_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen);
int xmss_private_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen);
int xmss_private_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key);
void xmss_key_cleanup(XMSS_KEY *key);


typedef struct {
	uint32_t index; // < 2^(XMSS_MAX_HEIGHT) = 2^20, always encode to 4 bytes
	hash256_t random;
	wots_sig_t wots_sig;
	hash256_t auth_path[XMSS_MAX_HEIGHT];
} XMSS_SIGNATURE;

// XMSS_SM3_10_256	2500 bytes
// XMSS_SM3_16_256	2692 bytes
// XMSS_SM3_20_256	2820 bytes
#define XMSS_SIGNATURE_MIN_SIZE	(4 + 32 + 32*67 + 32 * XMSS_MIN_HEIGHT) // = 2500 bytes
#define XMSS_SIGNATURE_MAX_SIZE	(4 + 32 + 32*67 + 32 * XMSS_MAX_HEIGHT) // = 2820 bytes
int xmss_signature_size(uint32_t xmss_type, size_t *siglen);
int xmss_signature_to_bytes(const XMSS_SIGNATURE *sig, uint32_t xmss_type, uint8_t **out, size_t *outlen);
int xmss_signature_from_bytes(XMSS_SIGNATURE *sig, uint32_t xmss_type, const uint8_t **in, size_t *inlen);
int xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *in, size_t inlen);
int xmss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const XMSS_SIGNATURE *sig);

typedef struct {
	XMSS_PUBLIC_KEY xmss_public_key;
	XMSS_SIGNATURE xmss_sig;
	HASH256_CTX hash256_ctx;
} XMSS_SIGN_CTX;

int xmss_sign_init(XMSS_SIGN_CTX *ctx, XMSS_KEY *key);
int xmss_sign_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmss_sign_finish(XMSS_SIGN_CTX *ctx, uint8_t *sigbuf, size_t *siglen);
int xmss_verify_init(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int xmss_verify_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmss_verify_finish(XMSS_SIGN_CTX *ctx);
void xmss_sign_ctx_cleanup(XMSS_SIGN_CTX *ctx);


enum {
	XMSSMT_SM3_20_2_256	= 0x00000001,
	XMSSMT_SM3_20_4_256	= 0x00000002,
	XMSSMT_SM3_40_2_256	= 0x00000003,
	XMSSMT_SM3_40_4_256	= 0x00000004,
	XMSSMT_SM3_40_8_256	= 0x00000005,
	XMSSMT_SM3_60_3_256	= 0x00000006,
	XMSSMT_SM3_60_6_256	= 0x00000007,
	XMSSMT_SM3_60_12_256	= 0x00000008,
};

// from rfc 8391 table 8
enum {
	XMSSMT_RESERVED		= 0x00000000,
	XMSSMT_SHA2_20_2_256	= 0x00000001,
	XMSSMT_SHA2_20_4_256	= 0x00000002,
	XMSSMT_SHA2_40_2_256	= 0x00000003,
	XMSSMT_SHA2_40_4_256	= 0x00000004,
	XMSSMT_SHA2_40_8_256	= 0x00000005,
	XMSSMT_SHA2_60_3_256	= 0x00000006,
	XMSSMT_SHA2_60_6_256	= 0x00000007,
	XMSSMT_SHA2_60_12_256	= 0x00000008,
};


#if defined(ENABLE_XMSS_CROSSCHECK) && defined(ENABLE_SHA2)
# define XMSSMT_HASH256_20_2_256	XMSSMT_SHA2_20_2_256
# define XMSSMT_HASH256_20_4_256	XMSSMT_SHA2_20_4_256
# define XMSSMT_HASH256_40_2_256	XMSSMT_SHA2_40_2_256
# define XMSSMT_HASH256_40_4_256	XMSSMT_SHA2_40_4_256
# define XMSSMT_HASH256_40_8_256	XMSSMT_SHA2_40_8_256
# define XMSSMT_HASH256_60_3_256	XMSSMT_SHA2_60_3_256
# define XMSSMT_HASH256_60_6_256	XMSSMT_SHA2_60_6_256
# define XMSSMT_HASH256_60_12_256	XMSSMT_SHA2_60_12_256
# define XMSSMT_HASH256_20_2_256_NAME	"XMSSMT_SHA2_20_2_256"
# define XMSSMT_HASH256_20_4_256_NAME	"XMSSMT_SHA2_20_4_256"
# define XMSSMT_HASH256_40_2_256_NAME	"XMSSMT_SHA2_40_2_256"
# define XMSSMT_HASH256_40_4_256_NAME	"XMSSMT_SHA2_40_4_256"
# define XMSSMT_HASH256_40_8_256_NAME	"XMSSMT_SHA2_40_8_256"
# define XMSSMT_HASH256_60_3_256_NAME	"XMSSMT_SHA2_60_3_256"
# define XMSSMT_HASH256_60_6_256_NAME	"XMSSMT_SHA2_60_6_256"
# define XMSSMT_HASH256_60_12_256_NAME	"XMSSMT_SHA2_60_12_256"
#else
# define XMSSMT_HASH256_20_2_256	XMSSMT_SM3_20_2_256
# define XMSSMT_HASH256_20_4_256	XMSSMT_SM3_20_4_256
# define XMSSMT_HASH256_40_2_256	XMSSMT_SM3_40_2_256
# define XMSSMT_HASH256_40_4_256	XMSSMT_SM3_40_4_256
# define XMSSMT_HASH256_40_8_256	XMSSMT_SM3_40_8_256
# define XMSSMT_HASH256_60_3_256	XMSSMT_SM3_60_3_256
# define XMSSMT_HASH256_60_6_256	XMSSMT_SM3_60_6_256
# define XMSSMT_HASH256_60_12_256	XMSSMT_SM3_60_12_256
# define XMSSMT_HASH256_20_2_256_NAME	"XMSSMT_SM3_20_2_256"
# define XMSSMT_HASH256_20_4_256_NAME	"XMSSMT_SM3_20_4_256"
# define XMSSMT_HASH256_40_2_256_NAME	"XMSSMT_SM3_40_2_256"
# define XMSSMT_HASH256_40_4_256_NAME	"XMSSMT_SM3_40_4_256"
# define XMSSMT_HASH256_40_8_256_NAME	"XMSSMT_SM3_40_8_256"
# define XMSSMT_HASH256_60_3_256_NAME	"XMSSMT_SM3_60_3_256"
# define XMSSMT_HASH256_60_6_256_NAME	"XMSSMT_SM3_60_6_256"
# define XMSSMT_HASH256_60_12_256_NAME	"XMSSMT_SM3_60_12_256"
#endif

char *xmssmt_type_name(uint32_t xmssmt_type);
uint32_t xmssmt_type_from_name(const char *name);

#define XMSSMT_MAX_HEIGHT 60
#define XMSSMT_MAX_LAYERS 12
int xmssmt_type_to_height_and_layers(uint32_t xmssmt_type, size_t *height, size_t *layers);

size_t xmssmt_num_trees_nodes(size_t height, size_t layers);

typedef struct {
	uint32_t xmssmt_type;
	hash256_t seed;
	hash256_t root;
} XMSSMT_PUBLIC_KEY;

#define XMSSMT_PUBLIC_KEY_SIZE (4 + sizeof(hash256_t) + sizeof(hash256_t)) // = 68 bytes

typedef struct {
	XMSSMT_PUBLIC_KEY public_key;
	uint64_t index; // in [0, 2^60 - 1]
	hash256_t secret;
	hash256_t sk_prf;
	hash256_t *trees;
	wots_sig_t wots_sigs[XMSSMT_MAX_LAYERS - 1];
} XMSSMT_KEY;

/*
    XMSSMT_SM3_20_2_256:     133,287 bytes
    XMSSMT_SM3_20_4_256:      14,631 bytes
    XMSSMT_SM3_40_2_256: 134,219,945 bytes
    XMSSMT_SM3_40_4_256:     268,585 bytes
    XMSSMT_SM3_40_8_256:      31,273 bytes
    XMSSMT_SM3_60_3_256: 201,330,924 bytes
    XMSSMT_SM3_60_6_256:     403,884 bytes
    XMSSMT_SM3_60_12_256:     47,916 bytes
*/
int xmssmt_private_key_size(uint32_t xmssmt_type, size_t *len);
int xmssmt_build_auth_path(const hash256_t *tree, size_t height, size_t layers, uint64_t index, hash256_t *auth_path);

int xmssmt_key_generate(XMSSMT_KEY *key, uint32_t xmssmt_type);
int xmssmt_key_update(XMSSMT_KEY *key);
int xmssmt_public_key_to_bytes(const XMSSMT_KEY *key, uint8_t **out, size_t *outlen);
int xmssmt_public_key_from_bytes(XMSSMT_KEY *key, const uint8_t **in, size_t *inlen);
int xmssmt_public_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_KEY *key);
int xmssmt_private_key_to_bytes(const XMSSMT_KEY *key, uint8_t **out, size_t *outlen);
int xmssmt_private_key_from_bytes(XMSSMT_KEY *key, const uint8_t **in, size_t *inlen);
int xmssmt_private_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_KEY *key);
void xmssmt_key_cleanup(XMSSMT_KEY *key);


typedef struct {
	uint64_t index;
	hash256_t random;
	wots_sig_t wots_sigs[XMSSMT_MAX_LAYERS];
	hash256_t auth_path[XMSSMT_MAX_HEIGHT];
} XMSSMT_SIGNATURE;

int xmssmt_index_to_bytes(uint64_t index, uint32_t xmssmt_type, uint8_t **out, size_t *outlen);
int xmssmt_index_from_bytes(uint64_t *index, uint32_t xmssmt_type, const uint8_t **in, size_t *inlen);

#define XMSSMT_SIGNATURE_MAX_SIZE \
	(sizeof(uint64_t) + sizeof(hash256_t) + sizeof(wots_sig_t)*XMSSMT_MAX_LAYERS + sizeof(hash256_t)*XMSSMT_MAX_HEIGHT) // = 27688 bytes

int xmssmt_signature_size(uint32_t xmssmt_type, size_t *siglen);
int xmssmt_signature_to_bytes(const XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type, uint8_t **out, size_t *outlen);
int xmssmt_signature_from_bytes(XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type, const uint8_t **in, size_t *inlen);
int xmssmt_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type);
int xmssmt_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen, uint32_t xmssmt_type);


typedef struct {
	XMSSMT_PUBLIC_KEY xmssmt_public_key;
	XMSSMT_SIGNATURE xmssmt_sig;
	HASH256_CTX hash256_ctx;
} XMSSMT_SIGN_CTX;

int xmssmt_sign_init(XMSSMT_SIGN_CTX *ctx, XMSSMT_KEY *key);
int xmssmt_sign_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmssmt_sign_finish(XMSSMT_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int xmssmt_sign_finish_ex(XMSSMT_SIGN_CTX *ctx, XMSSMT_SIGNATURE *sig);
int xmssmt_verify_init_ex(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const XMSSMT_SIGNATURE *sig);
int xmssmt_verify_init(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const uint8_t *sig, size_t siglen);
int xmssmt_verify_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmssmt_verify_finish(XMSSMT_SIGN_CTX *ctx);
void xmssmt_sign_ctx_cleanup(XMSSMT_SIGN_CTX *ctx);

#ifdef __cplusplus
}
#endif
#endif
