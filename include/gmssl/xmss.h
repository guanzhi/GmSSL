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


#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t xmss_sm3_digest_t[32];

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

void xmss_adrs_copy_layer_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_tree_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_type(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_ots_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_ltree_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_padding(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_chain_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_tree_height(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_hash_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_tree_index(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_key_and_mask(xmss_adrs_t dst, const xmss_adrs_t src);

void xmss_adrs_set_layer_address(xmss_adrs_t adrs, uint32_t layer);
void xmss_adrs_set_tree_address(xmss_adrs_t adrs, uint64_t tree_addr);
void xmss_adrs_set_type(xmss_adrs_t adrs, uint32_t type);
void xmss_adrs_set_ots_address(xmss_adrs_t adrs, uint32_t address);
void xmss_adrs_set_ltree_address(xmss_adrs_t adrs, uint32_t address);
void xmss_adrs_set_padding(xmss_adrs_t adrs, uint32_t padding);
void xmss_adrs_set_chain_address(xmss_adrs_t adrs, uint32_t address);
void xmss_adrs_set_tree_height(xmss_adrs_t adrs, uint32_t height);
void xmss_adrs_set_hash_address(xmss_adrs_t adrs, uint32_t address);
void xmss_adrs_set_tree_index(xmss_adrs_t adrs, uint32_t index);
void xmss_adrs_set_key_and_mask(xmss_adrs_t adrs, uint32_t key_and_mask);

int xmss_adrs_print(FILE *fp, int fmt, int ind, const char *label, const xmss_sm3_digest_t adrs);

// WOTS+ with SM3

#define XMSS_WOTS_WINTERNITZ_W 16 // rfc 8391 named algors only support w = 2^4 = 16
#define XMSS_WOTS_NUM_CHAINS	67

typedef xmss_sm3_digest_t xmss_wots_key_t[XMSS_WOTS_NUM_CHAINS];
typedef xmss_sm3_digest_t xmss_wots_sig_t[XMSS_WOTS_NUM_CHAINS];


void xmss_wots_derive_sk(const xmss_sm3_digest_t secret,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	xmss_wots_key_t sk);
void xmss_wots_chain(const xmss_sm3_digest_t x,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	int start, int steps, xmss_sm3_digest_t y);
void xmss_wots_sk_to_pk(const xmss_wots_key_t sk,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	xmss_wots_key_t pk);
void xmss_wots_sign(const xmss_wots_key_t sk,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	const xmss_sm3_digest_t dgst, xmss_wots_sig_t sig);
void xmss_wots_sig_to_pk(const xmss_wots_sig_t sig,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	const xmss_sm3_digest_t dgst, xmss_wots_key_t pk);
void xmss_wots_pk_to_root(const xmss_wots_key_t pk,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	xmss_sm3_digest_t wots_root);
void xmss_wots_derive_root(const xmss_sm3_digest_t secret,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	xmss_sm3_digest_t wots_root);
int  xmss_wots_verify(const xmss_sm3_digest_t wots_root,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	const xmss_sm3_digest_t dgst, const xmss_wots_sig_t sig);

enum {
	XMSS_SM3_10_256		= 0x10000001, // height = 10, sigs = 2^10
	XMSS_SM3_16_256		= 0x10000002, // height = 16, sigs = 2^16
	XMSS_SM3_20_256		= 0x10000003, // height = 20, sigs = 2^20
};

#define XMSS_MAX_HEIGHT	20

#define XMSS_SM3_10_256_NAME	"XMSS_SM3_10_256"
#define XMSS_SM3_16_256_NAME	"XMSS_SM3_16_256"
#define XMSS_SM3_20_256_NAME	"XMSS_SM3_20_256"

char *xmss_type_name(uint32_t xmss_type);
uint32_t xmss_type_from_name(const char *name);

int xmss_type_to_height(uint32_t xmss_type, size_t *height);

size_t xmss_num_tree_nodes(size_t height);
void xmss_build_tree(const xmss_sm3_digest_t secret,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	size_t height, xmss_sm3_digest_t *tree); // tree[xmss_num_tree_nodes(height)]
void xmss_build_auth_path(const xmss_sm3_digest_t *tree, size_t height,
	uint32_t index, xmss_sm3_digest_t *auth_path); // auth_path[height]
void xmss_build_root(const xmss_sm3_digest_t wots_root, uint32_t index,
	const xmss_sm3_digest_t seed, const xmss_adrs_t adrs,
	const xmss_sm3_digest_t *auth_path, size_t height,
	xmss_sm3_digest_t xmss_root);


typedef struct {
	uint32_t xmss_type;
	xmss_sm3_digest_t seed;
	xmss_sm3_digest_t root;
} XMSS_PUBLIC_KEY;

#define XMSS_PUBLIC_KEY_SIZE	(4 + 32 + 32) // = 68

typedef struct XMSS_KEY_st XMSS_KEY;

typedef int (*xmss_key_update_callback)(XMSS_KEY *key);

typedef struct XMSS_KEY_st {
	XMSS_PUBLIC_KEY public_key;
	uint32_t index;
	xmss_sm3_digest_t secret;
	xmss_sm3_digest_t sk_prf;
	xmss_sm3_digest_t *tree; // xmss_sm3_digest_t[2^(h + 1) - 1]
	xmss_key_update_callback update_callback;
	void *update_param;
} XMSS_KEY;

// XMSS_SM3_10_256:     65,640
// XMSS_SM3_16_256:  4,194,408
// XMSS_SM3_20_256: 67,108,968
int xmss_private_key_size(uint32_t xmss_type, size_t *keysize);

//#define XMSS_PRIVATE_KEY_SIZE	(XMSS_PUBLIC_KEY_SIZE + 32 + 32 + 4) // = 136

int xmss_key_generate(XMSS_KEY *key, uint32_t xmss_type);
int xmss_key_remaining_signs(const XMSS_KEY *key, size_t *count);
int xmss_key_set_update_callback(XMSS_KEY *key, xmss_key_update_callback update_cb, void *param);
int xmss_key_update(XMSS_KEY *key);
void xmss_key_cleanup(XMSS_KEY *key);

int xmss_public_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen);
int xmss_public_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen);
int xmss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key);
int xmss_private_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen);
int xmss_private_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen);
int xmss_private_key_from_file(XMSS_KEY *key, FILE *fp);
int xmss_private_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key);


typedef struct {
	uint32_t index; // < 2^(XMSS_MAX_HEIGHT) = 2^20, always encode to 4 bytes
	xmss_sm3_digest_t random;
	xmss_wots_sig_t wots_sig;
	xmss_sm3_digest_t auth_path[XMSS_MAX_HEIGHT];
} XMSS_SIGNATURE;

// XMSS_SM3_10_256	2500 bytes
// XMSS_SM3_16_256	2692 bytes
// XMSS_SM3_20_256	2820 bytes
#define XMSS_SIGNATURE_MIN_SIZE	(4 + 32 + 32*67 + 32 * XMSS_MIN_HEIGHT) // = 2500 bytes
#define XMSS_SIGNATURE_MAX_SIZE	(4 + 32 + 32*67 + 32 * XMSS_MAX_HEIGHT) // = 2820 bytes
int xmss_signature_size(uint32_t xmss_type, size_t *siglen);
int xmss_key_get_signature_size(const XMSS_KEY *key, size_t *siglen);
int xmss_signature_to_bytes(const XMSS_SIGNATURE *sig, uint32_t xmss_type, uint8_t **out, size_t *outlen);
int xmss_signature_from_bytes(XMSS_SIGNATURE *sig, uint32_t xmss_type, const uint8_t **in, size_t *inlen);
int xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *in, size_t inlen);
int xmss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const XMSS_SIGNATURE *sig);

typedef struct {
	XMSS_PUBLIC_KEY xmss_public_key;
	XMSS_SIGNATURE xmss_sig;
	SM3_CTX sm3_ctx;
} XMSS_SIGN_CTX;

int xmss_sign_init(XMSS_SIGN_CTX *ctx, XMSS_KEY *key);
int xmss_sign_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmss_sign_finish_ex(XMSS_SIGN_CTX *ctx, XMSS_SIGNATURE *sig);
int xmss_sign_finish(XMSS_SIGN_CTX *ctx, uint8_t *sigbuf, size_t *siglen);
int xmss_verify_init_ex(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const XMSS_SIGNATURE *sig);
int xmss_verify_init(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int xmss_verify_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmss_verify_finish(XMSS_SIGN_CTX *ctx);


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

#define XMSSMT_SM3_20_2_256_NAME	"XMSSMT_SM3_20_2_256"
#define XMSSMT_SM3_20_4_256_NAME	"XMSSMT_SM3_20_4_256"
#define XMSSMT_SM3_40_2_256_NAME	"XMSSMT_SM3_40_2_256"
#define XMSSMT_SM3_40_4_256_NAME	"XMSSMT_SM3_40_4_256"
#define XMSSMT_SM3_40_8_256_NAME	"XMSSMT_SM3_40_8_256"
#define XMSSMT_SM3_60_3_256_NAME	"XMSSMT_SM3_60_3_256"
#define XMSSMT_SM3_60_6_256_NAME	"XMSSMT_SM3_60_6_256"
#define XMSSMT_SM3_60_12_256_NAME	"XMSSMT_SM3_60_12_256"

char *xmssmt_type_name(uint32_t xmssmt_type);
uint32_t xmssmt_type_from_name(const char *name);

#define XMSSMT_MAX_HEIGHT 60
#define XMSSMT_MAX_LAYERS 12
int xmssmt_type_to_height_and_layers(uint32_t xmssmt_type, size_t *height, size_t *layers);

size_t xmssmt_num_trees_nodes(size_t height, size_t layers);

typedef struct {
	uint32_t xmssmt_type;
	xmss_sm3_digest_t seed;
	xmss_sm3_digest_t root;
} XMSSMT_PUBLIC_KEY;

#define XMSSMT_PUBLIC_KEY_SIZE (4 + sizeof(xmss_sm3_digest_t) + sizeof(xmss_sm3_digest_t)) // = 68 bytes

typedef struct XMSSMT_KEY_st XMSSMT_KEY;

typedef int (*xmssmt_key_update_callback)(XMSSMT_KEY *key);

typedef struct XMSSMT_KEY_st {
	XMSSMT_PUBLIC_KEY public_key;
	uint64_t index; // in [0, 2^60 - 1]
	xmss_sm3_digest_t secret;
	xmss_sm3_digest_t sk_prf;
	xmss_sm3_digest_t *trees;
	xmss_wots_sig_t wots_sigs[XMSSMT_MAX_LAYERS - 1];
	xmssmt_key_update_callback update_callback;
	void *update_param;
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
int xmssmt_build_auth_path(const xmss_sm3_digest_t *tree, size_t height, size_t layers, uint64_t index, xmss_sm3_digest_t *auth_path);

int xmssmt_key_generate(XMSSMT_KEY *key, uint32_t xmssmt_type);
int xmssmt_key_set_update_callback(XMSSMT_KEY *key, xmssmt_key_update_callback update_cb, void *param);
int xmssmt_key_update(XMSSMT_KEY *key);
int xmssmt_public_key_to_bytes(const XMSSMT_KEY *key, uint8_t **out, size_t *outlen);
int xmssmt_public_key_from_bytes(XMSSMT_KEY *key, const uint8_t **in, size_t *inlen);
int xmssmt_public_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_KEY *key);
int xmssmt_private_key_to_bytes(const XMSSMT_KEY *key, uint8_t **out, size_t *outlen);
int xmssmt_private_key_from_bytes(XMSSMT_KEY *key, const uint8_t **in, size_t *inlen);
int xmssmt_private_key_from_file(XMSSMT_KEY *key, FILE *fp);
int xmssmt_private_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_KEY *key);
void xmssmt_key_cleanup(XMSSMT_KEY *key);


typedef struct {
	uint64_t index;
	xmss_sm3_digest_t random;
	xmss_wots_sig_t wots_sigs[XMSSMT_MAX_LAYERS];
	xmss_sm3_digest_t auth_path[XMSSMT_MAX_HEIGHT];
} XMSSMT_SIGNATURE;

int xmssmt_index_to_bytes(uint64_t index, uint32_t xmssmt_type, uint8_t **out, size_t *outlen);
int xmssmt_index_from_bytes(uint64_t *index, uint32_t xmssmt_type, const uint8_t **in, size_t *inlen);

#define XMSSMT_SIGNATURE_MAX_SIZE sizeof(XMSSMT_SIGNATURE) // >= 27688 bytes

int xmssmt_key_get_signature_size(const XMSSMT_KEY *key, size_t *siglen);
int xmssmt_signature_size(uint32_t xmssmt_type, size_t *siglen);
int xmssmt_signature_to_bytes(const XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type, uint8_t **out, size_t *outlen);
int xmssmt_signature_from_bytes(XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type, const uint8_t **in, size_t *inlen);
int xmssmt_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type);
int xmssmt_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen, uint32_t xmssmt_type);


typedef struct {
	XMSSMT_PUBLIC_KEY xmssmt_public_key;
	XMSSMT_SIGNATURE xmssmt_sig;
	SM3_CTX sm3_ctx;
} XMSSMT_SIGN_CTX;

int xmssmt_sign_init(XMSSMT_SIGN_CTX *ctx, XMSSMT_KEY *key);
int xmssmt_sign_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmssmt_sign_finish(XMSSMT_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int xmssmt_sign_finish_ex(XMSSMT_SIGN_CTX *ctx, XMSSMT_SIGNATURE *sig);
int xmssmt_verify_init_ex(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const XMSSMT_SIGNATURE *sig);
int xmssmt_verify_init(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const uint8_t *sig, size_t siglen);
int xmssmt_verify_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmssmt_verify_finish(XMSSMT_SIGN_CTX *ctx);

#ifdef __cplusplus
}
#endif
#endif
