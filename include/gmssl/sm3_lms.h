/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM3_LMS_H
#define GMSSL_SM3_LMS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


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


typedef uint8_t hash256_t[32];


#define SM3_HSS_MAX_LEVELS 5
#define SM3_LMS_MAX_HEIGHT 25


// Crosscheck with data from LMS-reference (SHA-256), except the LMS signature.
#if defined(ENABLE_SM3_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
# define HASH256_CTX	SHA256_CTX
# define hash256_init	sha256_init
# define hash256_update	sha256_update
# define hash256_finish	sha256_finish
# define hash256_digest	sha256_digest
# define LMOTS_HASH256_N32_W8		LMOTS_SHA256_N32_W8
# define LMOTS_HASH256_N32_W8_NAME	"LMOTS_SHA256_N32_W8"
# define LMS_HASH256_M32_H5		LMS_SHA256_M32_H5
# define LMS_HASH256_M32_H10		LMS_SHA256_M32_H10
# define LMS_HASH256_M32_H15		LMS_SHA256_M32_H15
# define LMS_HASH256_M32_H20		LMS_SHA256_M32_H20
# define LMS_HASH256_M32_H25		LMS_SHA256_M32_H25
# define LMS_HASH256_M32_H5_NAME	"LMS_SHA256_M32_H5"
# define LMS_HASH256_M32_H10_NAME	"LMS_SHA256_M32_H10"
# define LMS_HASH256_M32_H15_NAME	"LMS_SHA256_M32_H15"
# define LMS_HASH256_M32_H20_NAME	"LMS_SHA256_M32_H20"
# define LMS_HASH256_M32_H25_NAME	"LMS_SHA256_M32_H25"
#else
# define HASH256_CTX	SM3_CTX
# define hash256_init	sm3_init
# define hash256_update	sm3_update
# define hash256_finish	sm3_finish
# define hash256_digest	sm3_digest
# define LMOTS_HASH256_N32_W8		LMOTS_SM3_N32_W8
# define LMOTS_HASH256_N32_W8_NAME	"LMOTS_SM3_N32_W8"
# define LMS_HASH256_M32_H5		LMS_SM3_M32_H5
# define LMS_HASH256_M32_H10		LMS_SM3_M32_H10
# define LMS_HASH256_M32_H15		LMS_SM3_M32_H15
# define LMS_HASH256_M32_H20		LMS_SM3_M32_H20
# define LMS_HASH256_M32_H25		LMS_SM3_M32_H25
# define LMS_HASH256_M32_H5_NAME	"LMS_SM3_M32_H5"
# define LMS_HASH256_M32_H10_NAME	"LMS_SM3_M32_H10"
# define LMS_HASH256_M32_H15_NAME	"LMS_SM3_M32_H15"
# define LMS_HASH256_M32_H20_NAME	"LMS_SM3_M32_H20"
# define LMS_HASH256_M32_H25_NAME	"LMS_SM3_M32_H25"
#endif

enum {
	LMOTS_RESERVED		= 0,
	LMOTS_SHA256_N32_W1	= 1,
	LMOTS_SHA256_N32_W2	= 2,
	LMOTS_SHA256_N32_W4	= 3,
	LMOTS_SHA256_N32_W8	= 4,
	LMOTS_SM3_N32_W1	= 11,
	LMOTS_SM3_N32_W2	= 12,
	LMOTS_SM3_N32_W4	= 13,
	LMOTS_SM3_N32_W8	= 14,
};

enum {
#if defined(ENABLE_SM3_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
	LMS_SHA256_M32_H5	= 5,
	LMS_SHA256_M32_H10	= 6,
	LMS_SHA256_M32_H15	= 7,
	LMS_SHA256_M32_H20	= 8,
	LMS_SHA256_M32_H25	= 9,
#else
	// TODO: submit to IETF
	LMS_SM3_M32_H5		= 5,
	LMS_SM3_M32_H10		= 6,
	LMS_SM3_M32_H15		= 7,
	LMS_SM3_M32_H20		= 8,
	LMS_SM3_M32_H25		= 9,
#endif
};


char *sm3_lmots_type_name(int lmots_type);
void sm3_lmots_derive_secrets(const hash256_t seed, const uint8_t I[16], int q, hash256_t x[34]);
void sm3_lmots_secrets_to_public_hash(const uint8_t I[16], int q, const hash256_t x[34], hash256_t pub);
void sm3_lmots_compute_signature(const uint8_t I[16], int q, const hash256_t dgst, const hash256_t x[34], hash256_t y[34]);
void sm3_lmots_signature_to_public_hash(const uint8_t I[16], int q, const hash256_t y[34], const hash256_t dgst, hash256_t pub);


char *sm3_lms_type_name(int lms_type);
int sm3_lms_type_from_name(const char *name);
int sm3_lms_type_to_height(int type, size_t *height);
void sm3_lms_derive_merkle_tree(const hash256_t seed, const uint8_t I[16], int height, hash256_t *tree);
void sm3_lms_derive_merkle_root(const hash256_t seed, const uint8_t I[16], int height, hash256_t root);


typedef struct {
	int lms_type;
	int lmots_type;
	uint8_t I[16]; // lms key identifier
	hash256_t root; // merkle tree root
} SM3_LMS_PUBLIC_KEY;

#define SM3_LMS_PUBLIC_KEY_SIZE (4 + 4 + 16 + 32) // = 56 bytes

typedef struct {
	SM3_LMS_PUBLIC_KEY public_key;
	hash256_t *tree;
	hash256_t seed;
	uint32_t q; // in [0, 2^h - 1], q++ after every sign
} SM3_LMS_KEY;

#define SM3_LMS_PRIVATE_KEY_SIZE (SM3_LMS_PUBLIC_KEY_SIZE + 32 + 4) // = 92 bytes

// FIXME: do we need a function to update lms_key->q ?

int sm3_lms_key_generate_ex(SM3_LMS_KEY *key, int lms_type, const hash256_t seed, const uint8_t I[16], int cache_tree);
int sm3_lms_key_generate(SM3_LMS_KEY *key, int lms_type);
int sm3_lms_key_check(const SM3_LMS_KEY *key, const SM3_LMS_PUBLIC_KEY *pub);
int sm3_lms_key_remaining_signs(const SM3_LMS_KEY *key, size_t *count);
int sm3_lms_public_key_to_bytes(const SM3_LMS_KEY *key, uint8_t **out, size_t *outlen);
int sm3_lms_public_key_from_bytes_ex(const SM3_LMS_PUBLIC_KEY **key, const uint8_t **in, size_t *inlen);
int sm3_lms_public_key_from_bytes(SM3_LMS_KEY *key, const uint8_t **in, size_t *inlen);
int sm3_lms_private_key_to_bytes(const SM3_LMS_KEY *key, uint8_t **out, size_t *outlen);
int sm3_lms_private_key_from_bytes(SM3_LMS_KEY *key, const uint8_t **in, size_t *inlen);
int sm3_lms_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_LMS_PUBLIC_KEY *pub);
int sm3_lms_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_LMS_KEY *key);
void sm3_lms_key_cleanup(SM3_LMS_KEY *key);



typedef struct {
	int q; // index of LMS tree leaf, in [0, 2^h - 1]
	struct {
		int lmots_type; // LMOTS_SM3_N32_W8 or LMOTS_SHA256_N32_W8 in compile time
		hash256_t C; // randomness of every LMOTS signature
		hash256_t y[34]; // for w = 8 and hash256, 34 winternitz chains
	} lmots_sig;
	int lms_type;
	hash256_t path[25]; // max tree height = 25 when LMS_SM3_M32_H25
} SM3_LMS_SIGNATURE;

// encoded size, SHOULD be changed when supporting text/der encoding
#define SM3_LMS_SIGNATURE_MIN_SIZE	(4 + 4 + 32 + 32*34 + 4 + 32*5) // = 1292 bytes
#define SM3_LMS_SIGNATURE_MAX_SIZE	(4 + 4 + 32 + 32*34 + 4 + 32*25) // = 1932 bytes


int sm3_lms_signature_to_merkle_root(const uint8_t I[16], size_t h, int q,
	const hash256_t y[34], const hash256_t *path,
	const hash256_t dgst, hash256_t root);

int sm3_lms_key_get_signature_size(const SM3_LMS_KEY *key, size_t *siglen);
int sm3_lms_signature_size(int lms_type, size_t *siglen);

int sm3_lms_signature_to_bytes(const SM3_LMS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sm3_lms_signature_from_bytes_ex(const SM3_LMS_SIGNATURE **sig, size_t *siglen, const uint8_t **in, size_t *inlen);
int sm3_lms_signature_from_bytes(SM3_LMS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sm3_lms_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SM3_LMS_SIGNATURE *sig);
int sm3_lms_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);


typedef struct {
	HASH256_CTX hash256_ctx;
	SM3_LMS_PUBLIC_KEY lms_public_key; // FIXME: or use LMS_PUBLIC_KEY to re-use tree?
	SM3_LMS_SIGNATURE lms_sig;
} SM3_LMS_SIGN_CTX;

int sm3_lms_sign_init(SM3_LMS_SIGN_CTX *ctx, SM3_LMS_KEY *key);
int sm3_lms_sign_update(SM3_LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm3_lms_sign_finish(SM3_LMS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sm3_lms_sign_finish_ex(SM3_LMS_SIGN_CTX *ctx, SM3_LMS_SIGNATURE *sig);
int sm3_lms_verify_init_ex(SM3_LMS_SIGN_CTX *ctx, const SM3_LMS_KEY *key, const SM3_LMS_SIGNATURE *sig);
int sm3_lms_verify_init(SM3_LMS_SIGN_CTX *ctx, const SM3_LMS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int sm3_lms_verify_update(SM3_LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm3_lms_verify_finish(SM3_LMS_SIGN_CTX *ctx);

// `sm3_lms_sign_init` copy lmots private to ctx->lms_sig.y
// call `sm3_lms_sign_ctx_cleanup` incase `sm3_lms_sign_finish` not called nor finished
void sm3_lms_sign_ctx_cleanup(SM3_LMS_SIGN_CTX *ctx);


/*
// just for reference, HSS_PUBLIC_KEY memory layout might not compatible with HSS_KEY
typedef struct {
	uint32_t levels;
	SM3_LMS_PUBLIC_KEY lms_public_key;
} SM3_HSS_PUBLIC_KEY;
*/

// SM3_HSS_PUBLIC_KEY: { level, lms_key[0].public_key }
#define SM3_HSS_PUBLIC_KEY_SIZE (4 + SM3_LMS_PUBLIC_KEY_SIZE)


// TODO: LMS_KEY should be a tree other than a vector
// when updated, low level lms keys will lost, maybe a good feature
typedef struct {
	uint32_t levels; // should be checked to prevent memory error
	SM3_LMS_KEY lms_key[5];
	SM3_LMS_SIGNATURE lms_sig[4];
} SM3_HSS_KEY;


#define SM3_HSS_PRIVATE_KEY_MAX_SIZE sizeof(SM3_HSS_KEY)
int sm3_hss_private_key_size(const int *lms_types, size_t levels, size_t *len);

int sm3_hss_key_generate(SM3_HSS_KEY *key, const int *lms_types, size_t levels);
int sm3_hss_key_update(SM3_HSS_KEY *key);

int sm3_hss_public_key_to_bytes(const SM3_HSS_KEY *key, uint8_t **out, size_t *outlen);
int sm3_hss_private_key_to_bytes(const SM3_HSS_KEY *key, uint8_t **out, size_t *outlen);
int sm3_hss_public_key_from_bytes(SM3_HSS_KEY *key, const uint8_t **in, size_t *inlen);
int sm3_hss_private_key_from_bytes(SM3_HSS_KEY *key, const uint8_t **in, size_t *inlen);
int sm3_hss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_HSS_KEY *key);
int sm3_hss_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_HSS_KEY *key);
void sm3_hss_key_cleanup(SM3_HSS_KEY *key);



typedef struct {
	uint32_t num_signed_public_keys; // = hss_key->levels - 1
	struct {
		SM3_LMS_SIGNATURE lms_sig; // lms_sig[i] = sign(hss_key->lms_key[i], lms_public_key[i])
		SM3_LMS_PUBLIC_KEY lms_public_key; // signed_public_keys[i] = hss_key->lms_key[i+1].public_key
	} signed_public_keys[SM3_HSS_MAX_LEVELS - 1];
	SM3_LMS_SIGNATURE msg_lms_sig; // = sign(hss->lms_key[levels-1], msg)
} SM3_HSS_SIGNATURE;


#define SM3_HSS_SIGNATURE_MAX_SIZE sizeof(SM3_HSS_SIGNATURE)
int sm3_hss_signature_size(const int *lms_types, size_t levels, size_t *len);
int sm3_hss_key_get_signature_size(const SM3_HSS_KEY *key, size_t *siglen);

int sm3_hss_signature_to_bytes(const SM3_HSS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sm3_hss_signature_from_bytes(SM3_HSS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sm3_hss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SM3_HSS_SIGNATURE *sig);
int sm3_hss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);


typedef struct {
	SM3_LMS_SIGN_CTX lms_ctx;
	uint32_t levels;
	SM3_LMS_SIGNATURE lms_sigs[SM3_HSS_MAX_LEVELS - 1];
	SM3_LMS_PUBLIC_KEY lms_public_keys[SM3_HSS_MAX_LEVELS - 1];
} SM3_HSS_SIGN_CTX;


int sm3_hss_sign_init(SM3_HSS_SIGN_CTX *ctx, SM3_HSS_KEY *key);
int sm3_hss_sign_update(SM3_HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm3_hss_sign_finish(SM3_HSS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sm3_hss_sign_finish_ex(SM3_HSS_SIGN_CTX *ctx, SM3_HSS_SIGNATURE *sig);
int sm3_hss_verify_init_ex(SM3_HSS_SIGN_CTX *ctx, const SM3_HSS_KEY *key, const SM3_HSS_SIGNATURE *sig);
int sm3_hss_verify_init(SM3_HSS_SIGN_CTX *ctx, const SM3_HSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int sm3_hss_verify_update(SM3_HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm3_hss_verify_finish(SM3_HSS_SIGN_CTX *ctx);


/*
from RFC 9708

id-alg-hss-lms-hashsig OBJECT IDENTIFIER ::= {
	iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
	pkcs-9(9) smime(16) alg(3) 17
}
*/
#include <gmssl/oid.h>

#define oid_hss_lms_hashsig	oid_pkcs,9,16,3,17



#ifdef __cplusplus
}
#endif
#endif
