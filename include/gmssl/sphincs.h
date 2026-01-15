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
#ifdef ENABLE_SHA2
#include <gmssl/sha2.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif



#if 1 // SPHINCS+_128s
# define SPHINCS_HYPERTREE_HEIGHT 63
# define SPHINCS_HYPERTREE_LAYERS 7
# define SPHINCS_FORS_TREE_HEIGHT 12
# define SPHINCS_FORS_NUM_TREES 14
#else
# define SPHINCS_HYPERTREE_HEIGHT 66
# define SPHINCS_HYPERTREE_LAYERS 22
# define SPHINCS_FORS_TREE_HEIGHT 6
# define SPHINCS_FORS_NUM_TREES 33
#endif

#define SPHINCS_XMSS_HEIGHT  (SPHINCS_HYPERTREE_HEIGHT/SPHINCS_HYPERTREE_LAYERS) // = 9
#define SPHINCS_XMSS_NUM_NODES  ((1 << (SPHINCS_XMSS_HEIGHT + 1)) - 1) // 1023
#define SPHINCS_FORS_TREE_NUM_NODES  ((1 << (SPHINCS_FORS_TREE_HEIGHT + 1)) - 1) // = 8191
#define SPHINCS_TBS_FORS_SIZE  ((SPHINCS_FORS_TREE_HEIGHT * SPHINCS_FORS_NUM_TREES + 7)/8) // = 21
#define SPHINCS_TBS_TREE_ADDRESS_SIZE  ((SPHINCS_HYPERTREE_HEIGHT - SPHINCS_XMSS_HEIGHT + 7)/8) // = 7
#define SPHINCS_TBS_KEYPAIR_ADDRESS_SIZE  ((SPHINCS_XMSS_HEIGHT + 7)/8) // = 2
#define SPHINCS_TBS_SIZE  (SPHINCS_TBS_FORS_SIZE + SPHINCS_TBS_TREE_ADDRESS_SIZE + SPHINCS_TBS_KEYPAIR_ADDRESS_SIZE) // = 30


// sizeof(sphincs_hash128_t) == n, when sm3/sha256, n == 16
#define SPHINCS_DIGEST_SIZE  16

// only support w = 16, w_bits = 4
#define SPHINCS_WOTS_W 16

// for sphincs+_128s and 128f, digest_bits = 128, encoded into 32 4-bit base_w numbers
// max checksum = (w - 1) * 32 = 15 * 32 = 480, need 9 bits, 3 4-bit base_w numbers
// so the total wots+ chinas is 32 + 3 = 35
#define SPHINCS_WOTS_NUM_CHAINS 35

typedef uint8_t sphincs_hash128_t[16];

typedef uint8_t sphincs_hash256_t[32];

#if defined(ENABLE_SPHINCS_CROSSCHECK) && defined(ENABLE_SHA2) && !defined(SPHINCS_HASH256_CTX)
# define SPHINCS_HASH256_CTX		SHA256_CTX
# define sphincs_hash256_init		sha256_init
# define sphincs_hash256_update		sha256_update
# define sphincs_hash256_finish		sha256_finish
# define SPHINCS_HASH256_BLOCK_SIZE	SHA256_BLOCK_SIZE
# define SPHINCS_HMAC256_CTX	SHA256_HMAC_CTX
# define sphincs_hmac256_init	sha256_hmac_init
# define sphincs_hmac256_update	sha256_hmac_update
# define sphincs_hmac256_finish	sha256_hmac_finish
#else
# define SPHINCS_HASH256_CTX		SM3_CTX
# define sphincs_hash256_init		sm3_init
# define sphincs_hash256_update		sm3_update
# define sphincs_hash256_finish		sm3_finish
# define SPHINCS_HASH256_BLOCK_SIZE	SM3_BLOCK_SIZE
# define SPHINCS_HMAC256_CTX	SM3_HMAC_CTX
# define sphincs_hmac256_init	sm3_hmac_init
# define sphincs_hmac256_update	sm3_hmac_update
# define sphincs_hmac256_finish	sm3_hmac_finish
#endif


// ADRS scheme

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
	uint32_t padding2;
	uint32_t padding3;
} SPHINCS_ADRS_WOTS_PK;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 2
	uint32_t padding1;
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
	uint32_t padding2;
	uint32_t padding3;
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
void sphincs_adrs_init_padding1(sphincs_adrs_t adrs);
void sphincs_adrs_init_padding2(sphincs_adrs_t adrs);
void sphincs_adrs_init_padding3(sphincs_adrs_t adrs);
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


// WOTS+

typedef sphincs_hash128_t sphincs_wots_key_t[SPHINCS_WOTS_NUM_CHAINS];
typedef sphincs_hash128_t sphincs_wots_sig_t[SPHINCS_WOTS_NUM_CHAINS];

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


// XMSS

void sphincs_xmss_tree_hash(
	const sphincs_hash128_t left_child, const sphincs_hash128_t right_child,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	sphincs_hash256_t parent);
void sphincs_xmss_build_tree(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES]);
void sphincs_xmss_build_auth_path(const sphincs_hash128_t tree[SPHINCS_XMSS_NUM_NODES],
	uint32_t tree_index, sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT]);
void sphincs_xmss_build_root(const sphincs_hash128_t wots_root, uint32_t tree_index,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	const sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT],
	sphincs_hash256_t root);

typedef struct {
	sphincs_wots_sig_t wots_sig;
	sphincs_hash128_t auth_path[SPHINCS_XMSS_HEIGHT];
} SPHINCS_XMSS_SIGNATURE;

int sphincs_xmss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_XMSS_SIGNATURE *sig);
int sphincs_xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);
int sphincs_xmss_signature_to_bytes(const SPHINCS_XMSS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sphincs_xmss_signature_from_bytes(SPHINCS_XMSS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);

void sphincs_xmss_sign(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs, uint32_t keypair_address,
	const sphincs_hash128_t tbs_root, // to be signed xmss_root or fors_root
	SPHINCS_XMSS_SIGNATURE *sig);
void sphincs_xmss_sig_to_root(const SPHINCS_XMSS_SIGNATURE *sig,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs, uint32_t keypair_address,
	const sphincs_hash128_t tbs_root, // to be signed xmss_root or fors_root
	sphincs_hash128_t xmss_root);

// Hypertree

void sphincs_hypertree_derive_root(const sphincs_hash128_t secret, const sphincs_hash128_t seed,
	sphincs_hash128_t root);
void sphincs_hypertree_sign(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, uint64_t tree_address, uint32_t keypair_address,
	const sphincs_hash128_t tbs_fors_root,
	SPHINCS_XMSS_SIGNATURE sig[SPHINCS_HYPERTREE_LAYERS]);
int sphincs_hypertree_verify(const sphincs_hash128_t top_xmss_root,
	const sphincs_hash128_t seed, uint64_t tree_address, uint32_t keypair_address,
	const sphincs_hash128_t tbs_fors_root,
	const SPHINCS_XMSS_SIGNATURE sig[SPHINCS_HYPERTREE_LAYERS]);


// FORS

void sphincs_fors_derive_sk(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	uint32_t fors_index, sphincs_hash128_t sk);
void sphincs_fors_build_tree(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs, int tree_addr,
	sphincs_hash128_t tree[SPHINCS_FORS_TREE_NUM_NODES]);;
void sphincs_fors_derive_root(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	sphincs_hash128_t fors_root);

typedef struct {
	sphincs_hash128_t fors_sk[SPHINCS_FORS_NUM_TREES];
	sphincs_hash128_t auth_path[SPHINCS_FORS_NUM_TREES][SPHINCS_FORS_TREE_HEIGHT];
} SPHINCS_FORS_SIGNATURE;

#define SPHINCS_FORS_SIGNATURE_SIZE sizeof(SPHINCS_FORS_SIGNATURE)

int sphincs_fors_signature_to_bytes(const SPHINCS_FORS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sphincs_fors_signature_from_bytes(SPHINCS_FORS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sphincs_fors_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_FORS_SIGNATURE *sig);
int sphincs_fors_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

void sphincs_fors_sign(const sphincs_hash128_t secret,
	const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
	const uint8_t dgst[SPHINCS_TBS_FORS_SIZE],
	SPHINCS_FORS_SIGNATURE *sig);
void sphincs_fors_sig_to_root(const SPHINCS_FORS_SIGNATURE *sig,
	const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
	const uint8_t dgst[SPHINCS_TBS_FORS_SIZE], sphincs_hash128_t fors_root);


// SPHINCS+

typedef struct {
	sphincs_hash128_t seed;
	sphincs_hash128_t root;
} SPHINCS_PUBLIC_KEY;

#define SPHINCS_PUBLIC_KEY_SIZE sizeof(SPHINCS_PUBLIC_KEY)

typedef struct {
	SPHINCS_PUBLIC_KEY public_key;
	sphincs_hash128_t secret;
	sphincs_hash128_t sk_prf;
} SPHINCS_KEY;

#define SPHINCS_PRIVATE_KEY_SIZE sizeof(SPHINCS_KEY)

int sphincs_key_generate(SPHINCS_KEY *key);
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

#define SPHINCS_SIGNATURE_SIZE sizeof(SPHINCS_SIGNATURE)

int sphincs_signature_to_bytes(const SPHINCS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sphincs_signature_from_bytes(SPHINCS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sphincs_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_SIGNATURE *sig);
int sphincs_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

typedef struct {
	SPHINCS_HMAC256_CTX hmac_ctx;
	SPHINCS_HASH256_CTX hash_ctx;
	SPHINCS_SIGNATURE sig;
	int state; // after init 0, after prepare 1, after update 2
	size_t round1_msglen;
	size_t round2_msglen;
	SPHINCS_KEY key;
} SPHINCS_SIGN_CTX;

int sphincs_sign_init_ex(SPHINCS_SIGN_CTX *ctx, const SPHINCS_KEY *key, int randomize);
int sphincs_sign_init(SPHINCS_SIGN_CTX *ctx, const SPHINCS_KEY *key);
int sphincs_sign_prepare(SPHINCS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sphincs_sign_update(SPHINCS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sphincs_sign_finish_ex(SPHINCS_SIGN_CTX *ctx, SPHINCS_SIGNATURE *sig);
int sphincs_sign_finish(SPHINCS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sphincs_verify_init_ex(SPHINCS_SIGN_CTX *ctx, const SPHINCS_KEY *key, const SPHINCS_SIGNATURE *sig);
int sphincs_verify_init(SPHINCS_SIGN_CTX *ctx, const SPHINCS_KEY *key, const uint8_t *sig, size_t siglen);
int sphincs_verify_update(SPHINCS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sphincs_verify_finish(SPHINCS_SIGN_CTX *ctx);
void sphincs_sign_ctx_cleanup(SPHINCS_SIGN_CTX *ctx);


#ifdef __cplusplus
}
#endif
#endif

