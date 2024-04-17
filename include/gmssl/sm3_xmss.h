/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM3_XMSS_H
#define GMSSL_SM3_XMSS_H

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


// Crosscheck with data from xmss-reference (SHA-256), except the XMSS signature.
#if defined(ENABLE_SM3_XMSS_CROSSCHECK) && defined(ENABLE_SHA2)
# define HASH256_CTX	SHA256_CTX
# define hash256_init	sha256_init
# define hash256_update	sha256_update
# define hash256_finish	sha256_finish
# define hash256_digest	sha256_digest
#else
# define HASH256_CTX	SM3_CTX
# define hash256_init	sm3_init
# define hash256_update	sm3_update
# define hash256_finish	sm3_finish
# define hash256_digest	sm3_digest
#endif

typedef uint8_t hash256_bytes_t[32];

// Derive wots+ sk from a secret seed use the spec of xmss-reference.
void sm3_wots_derive_sk(const uint8_t secret[32],
	const uint8_t seed[32], const uint8_t in_adrs[32],
	hash256_bytes_t sk[67]);
void sm3_wots_derive_pk(const hash256_bytes_t sk[67],
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	hash256_bytes_t pk[67]);
void sm3_wots_do_sign(const hash256_bytes_t sk[67],
	const HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	const uint8_t dgst[32], hash256_bytes_t sig[67]);
void sm3_wots_sig_to_pk(const hash256_bytes_t sig[67], const uint8_t dgst[32],
	const  HASH256_CTX *prf_seed_ctx, const uint8_t in_adrs[32],
	hash256_bytes_t pk[67]);

void sm3_xmss_derive_root(const uint8_t xmss_secret[32], int height,
	const uint8_t seed[32],
	hash256_bytes_t *tree, uint8_t xmss_root[32]);
void sm3_xmss_do_sign(const uint8_t xmss_secret[32], int index,
	const uint8_t seed[32], const uint8_t in_adrs[32], int height,
	const hash256_bytes_t *tree,
	const uint8_t dgst[32],
	hash256_bytes_t wots_sig[67],
	hash256_bytes_t *auth_path);

void sm3_xmss_sig_to_root(const hash256_bytes_t wots_sig[67], int index, const hash256_bytes_t *auth_path,
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

int sm3_xmss_height_from_oid(uint32_t *height, uint32_t id);

typedef struct {
	uint32_t oid;
	uint8_t seed[32];
	uint8_t root[32];
	uint8_t secret[32];
	uint8_t prf_key[32];
	uint32_t index;
	hash256_bytes_t *tree;
} SM3_XMSS_KEY;

int sm3_xmss_key_generate(SM3_XMSS_KEY *key, uint32_t oid);
int sm3_xmss_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_XMSS_KEY *key);
int sm3_xmss_key_get_height(const SM3_XMSS_KEY *key, uint32_t *height);
int sm3_xmss_key_to_bytes(const SM3_XMSS_KEY *key, uint8_t *out, size_t *outlen);
int sm3_xmss_key_from_bytes(SM3_XMSS_KEY *key, const uint8_t *in, size_t inlen);
int sm3_xmss_public_key_to_bytes(const SM3_XMSS_KEY *key, uint8_t *out, size_t *outlen);
int sm3_xmss_public_key_from_bytes(SM3_XMSS_KEY *key, const uint8_t *in, size_t inlen);
void sm3_xmss_key_cleanup(SM3_XMSS_KEY *key);

typedef struct {
	uint8_t index[4];
	uint8_t random[32];
	hash256_bytes_t wots_sig[67];
	hash256_bytes_t auth_path[20];
} SM3_XMSS_SIGNATURE;

int sm3_xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *in, size_t inlen);

typedef struct {
	uint8_t random[32];
	HASH256_CTX hash256_ctx;
} SM3_XMSS_SIGN_CTX;

int sm3_xmss_sign_init(SM3_XMSS_SIGN_CTX *ctx, const SM3_XMSS_KEY *key);
int sm3_xmss_sign_update(SM3_XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm3_xmss_sign_finish(SM3_XMSS_SIGN_CTX *ctx, const SM3_XMSS_KEY *key, uint8_t *sigbuf, size_t *siglen);
int sm3_xmss_verify_init(SM3_XMSS_SIGN_CTX *ctx, const SM3_XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int sm3_xmss_verify_update(SM3_XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm3_xmss_verify_finish(SM3_XMSS_SIGN_CTX *ctx, const SM3_XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen);


#ifdef __cplusplus
}
#endif
#endif
