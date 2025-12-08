/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
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
# define HASH256_CTX	SHA256_CTX
# define hash256_init	sha256_init
# define hash256_update	sha256_update
# define hash256_finish	sha256_finish
# define hash256_digest	sha256_digest
# define LMS_HASH256_10		XMSS_SHA256_10
# define LMS_HASH256_16		XMSS_SHA256_16
# define LMS_HASH256_20		XMSS_SHA256_20
#else
# define HASH256_CTX	SM3_CTX
# define hash256_init	sm3_init
# define hash256_update	sm3_update
# define hash256_finish	sm3_finish
# define hash256_digest	sm3_digest
# define LMS_HASH256_10		XMSS_SM3_10
# define LMS_HASH256_16		XMSS_SM3_16
# define LMS_HASH256_20		XMSS_SM3_20
#endif



#define XMSS_MIX_HEIGHT	16
#define XMSS_MAX_HEIGHT	20


// TODO:
// 	* change uint8[32] to hash256_t
//	* key_to_bytes, from_bytes, use **out, *outlen style
//	* support private key/ public key functions



// Derive wots+ sk from a secret seed use the spec of xmss-reference.
void sm3_wots_derive_sk(const uint8_t secret[32],
	const uint8_t seed[32], const uint8_t in_adrs[32],
	hash256_t sk[67]); // change number 67 to a DEFINE
void sm3_wots_derive_pk(const hash256_t sk[67],
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	hash256_t pk[67]);
void sm3_wots_do_sign(const hash256_t sk[67],
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	const uint8_t dgst[32], hash256_t sig[67]);
void sm3_wots_sig_to_pk(const hash256_t sig[67], const uint8_t dgst[32],
	const  HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	hash256_t pk[67]);

void xmss_derive_root(const uint8_t xmss_secret[32], int height,
	const uint8_t seed[32],
	hash256_t *tree, uint8_t xmss_root[32]);
void xmss_do_sign(const uint8_t xmss_secret[32], int index,
	const uint8_t seed[32], const uint8_t in_adrs[32], int height,
	const hash256_t *tree,
	const uint8_t dgst[32],
	hash256_t wots_sig[67],
	hash256_t *auth_path);

void xmss_sig_to_root(const hash256_t wots_sig[67], int index, const hash256_t *auth_path,
	const uint8_t seed[32], const uint8_t in_adrs[32], int height,
	const uint8_t dgst[32],
	uint8_t xmss_root[32]);

enum {
	XMSS_SM3_10	= 0x10000001,
	XMSS_SM3_16	= 0x10000002,
	XMSS_SM3_20	= 0x10000003,
	XMSS_SHA256_10	= 0x00000001,
	XMSS_SHA256_16	= 0x00000002,
	XMSS_SHA256_20	= 0x00000003,
};

// delete this func
int xmss_height_from_oid(uint32_t *height, uint32_t id);


// PK = OID || root || SEED
// SK = idx || wots_sk || SK_PRF || root || SEED;

typedef struct {
	uint32_t oid;
	uint8_t seed[32];
	uint8_t root[32];

	uint8_t secret[32];
	uint8_t prf_key[32];
	uint32_t index; // change this to int, update every signing
	hash256_t *tree;
} XMSS_KEY;


#define XMSS_PUBLIC_KEY_SIZE	(4 + 32 + 32) // = 68
#define XMSS_PRIVATE_KEY_SIZE	(XMSS_PUBLIC_KEY_SIZE + 32 + 32 + 4) // = 136


// TODO: add public_key, private_key funcs
// TODO: key_update func
// TODO: build tree in private_key_from_bytes
int xmss_key_generate(XMSS_KEY *key, uint32_t oid);
int xmss_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key);
int xmss_key_get_height(const XMSS_KEY *key, uint32_t *height);
int xmss_key_to_bytes(const XMSS_KEY *key, uint8_t *out, size_t *outlen);
int xmss_key_from_bytes(XMSS_KEY *key, const uint8_t *in, size_t inlen);
int xmss_public_key_to_bytes(const XMSS_KEY *key, uint8_t *out, size_t *outlen);
int xmss_public_key_from_bytes(XMSS_KEY *key, const uint8_t *in, size_t inlen);
void xmss_key_cleanup(XMSS_KEY *key);




typedef struct {
	uint8_t index[4];
	uint8_t random[32];
	hash256_t wots_sig[67];
	hash256_t auth_path[XMSS_MAX_HEIGHT];
} XMSS_SIGNATURE;



// XMSS_SM3_10_256	2500 bytes
// XMSS_SM3_16_256	2692 bytes
// XMSS_SM3_20_256	2820 bytes
#define XMSS_SIGNATURE_MIN_SIZE	(4 + 32 + 32*67 + 32 * XMSS_MIN_HEIGHT) // = 2500 bytes
#define XMSS_SIGNATURE_MAX_SIZE	(4 + 32 + 32*67 + 32 * XMSS_MAX_HEIGHT) // = 2820 bytes

int xmss_signature_size(uint32_t oid, size_t *siglen);

// TODO: impl this
int xmss_key_get_signature_size(const XMSS_KEY *key, size_t siglen);

int xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *in, size_t inlen);

typedef struct {
	uint8_t random[32];
	HASH256_CTX hash256_ctx;
	// TODO: cache signing key
} XMSS_SIGN_CTX;


// TODO: change the API to LMS/HSS style
// TODO: remove const before XMSS_KEY in sign_init
int xmss_sign_init(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key);
int xmss_sign_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmss_sign_finish(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, uint8_t *sigbuf, size_t *siglen);
int xmss_verify_init(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int xmss_verify_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmss_verify_finish(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen);


#ifdef __cplusplus
}
#endif
#endif
