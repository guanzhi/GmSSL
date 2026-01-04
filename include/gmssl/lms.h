/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_LMS_H
#define GMSSL_LMS_H


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


#define HSS_MAX_LEVELS 5
#define LMS_MAX_HEIGHT 25


// Crosscheck with data from LMS-reference (SHA-256), except the LMS signature.
#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
# define HASH256_CTX	SHA256_CTX
# define hash256_init	sha256_init
# define hash256_update	sha256_update
# define hash256_finish	sha256_finish
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
#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
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


char *lmots_type_name(int lmots_type);
void lmots_derive_secrets(const hash256_t seed, const uint8_t I[16], int q, hash256_t x[34]);
void lmots_secrets_to_public_hash(const uint8_t I[16], int q, const hash256_t x[34], hash256_t pub);
void lmots_compute_signature(const uint8_t I[16], int q, const hash256_t dgst, const hash256_t x[34], hash256_t y[34]);
void lmots_signature_to_public_hash(const uint8_t I[16], int q, const hash256_t y[34], const hash256_t dgst, hash256_t pub);


char *lms_type_name(int lms_type);
int lms_type_from_name(const char *name);
int lms_type_to_height(int type, size_t *height);
void lms_derive_merkle_tree(const hash256_t seed, const uint8_t I[16], int height, hash256_t *tree);
void lms_derive_merkle_root(const hash256_t seed, const uint8_t I[16], int height, hash256_t root);


typedef struct {
	int lms_type;
	int lmots_type;
	uint8_t I[16]; // lms key identifier
	hash256_t root; // merkle tree root
} LMS_PUBLIC_KEY;

#define LMS_PUBLIC_KEY_SIZE (4 + 4 + 16 + 32) // = 56 bytes

typedef struct {
	LMS_PUBLIC_KEY public_key;
	hash256_t *tree;
	hash256_t seed;
	uint32_t q; // in [0, 2^h - 1], q++ after every sign
} LMS_KEY;

#define LMS_PRIVATE_KEY_SIZE (LMS_PUBLIC_KEY_SIZE + 32 + 4) // = 92 bytes

// FIXME: do we need a function to update lms_key->q ?

int lms_key_generate_ex(LMS_KEY *key, int lms_type, const hash256_t seed, const uint8_t I[16], int cache_tree);
int lms_key_generate(LMS_KEY *key, int lms_type);
int lms_key_check(const LMS_KEY *key, const LMS_PUBLIC_KEY *pub);
int lms_key_remaining_signs(const LMS_KEY *key, size_t *count);
int lms_public_key_to_bytes(const LMS_KEY *key, uint8_t **out, size_t *outlen);
int lms_public_key_from_bytes_ex(const LMS_PUBLIC_KEY **key, const uint8_t **in, size_t *inlen);
int lms_public_key_from_bytes(LMS_KEY *key, const uint8_t **in, size_t *inlen);
int lms_private_key_to_bytes(const LMS_KEY *key, uint8_t **out, size_t *outlen);
int lms_private_key_from_bytes(LMS_KEY *key, const uint8_t **in, size_t *inlen);
int lms_public_key_print(FILE *fp, int fmt, int ind, const char *label, const LMS_PUBLIC_KEY *pub);
int lms_key_print(FILE *fp, int fmt, int ind, const char *label, const LMS_KEY *key);
void lms_key_cleanup(LMS_KEY *key);



typedef struct {
	int q; // index of LMS tree leaf, in [0, 2^h - 1]
	struct {
		int lmots_type; // LMOTS_SM3_N32_W8 or LMOTS_SHA256_N32_W8 in compile time
		hash256_t C; // randomness of every LMOTS signature
		hash256_t y[34]; // for w = 8 and hash256, 34 winternitz chains
	} lmots_sig;
	int lms_type;
	hash256_t path[25]; // max tree height = 25 when LMS_SM3_M32_H25
} LMS_SIGNATURE;

// encoded size, SHOULD be changed when supporting text/der encoding
#define LMS_SIGNATURE_MIN_SIZE	(4 + 4 + 32 + 32*34 + 4 + 32*5) // = 1292 bytes
#define LMS_SIGNATURE_MAX_SIZE	(4 + 4 + 32 + 32*34 + 4 + 32*25) // = 1932 bytes


int lms_signature_to_merkle_root(const uint8_t I[16], size_t h, int q,
	const hash256_t y[34], const hash256_t *path,
	const hash256_t dgst, hash256_t root);


/*
 * LMS_HASH256_M32_H5	1292
 * LMS_HASH256_M32_H10	1452
 * LMS_HASH256_M32_H15	1612
 * LMS_HASH256_M32_H20	1772
 * LMS_HASH256_M32_H25	1932
 */
int lms_signature_size(int lms_type, size_t *siglen);
int lms_key_get_signature_size(const LMS_KEY *key, size_t *siglen);

int lms_signature_to_bytes(const LMS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int lms_signature_from_bytes_ex(const LMS_SIGNATURE **sig, size_t *siglen, const uint8_t **in, size_t *inlen);
int lms_signature_from_bytes(LMS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int lms_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const LMS_SIGNATURE *sig);
int lms_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);


typedef struct {
	HASH256_CTX hash256_ctx;
	LMS_PUBLIC_KEY lms_public_key; // FIXME: or use LMS_PUBLIC_KEY to re-use tree?
	LMS_SIGNATURE lms_sig;
} LMS_SIGN_CTX;

int lms_sign_init(LMS_SIGN_CTX *ctx, LMS_KEY *key);
int lms_sign_update(LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int lms_sign_finish(LMS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int lms_sign_finish_ex(LMS_SIGN_CTX *ctx, LMS_SIGNATURE *sig);
int lms_verify_init_ex(LMS_SIGN_CTX *ctx, const LMS_KEY *key, const LMS_SIGNATURE *sig);
int lms_verify_init(LMS_SIGN_CTX *ctx, const LMS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int lms_verify_update(LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int lms_verify_finish(LMS_SIGN_CTX *ctx);

// `lms_sign_init` copy lmots private to ctx->lms_sig.y
// call `lms_sign_ctx_cleanup` incase `lms_sign_finish` not called nor finished
void lms_sign_ctx_cleanup(LMS_SIGN_CTX *ctx);


/*
// just for reference, HSS_PUBLIC_KEY memory layout might not compatible with HSS_KEY
typedef struct {
	uint32_t levels;
	LMS_PUBLIC_KEY lms_public_key;
} HSS_PUBLIC_KEY;
*/

// HSS_PUBLIC_KEY: { level, lms_key[0].public_key }
#define HSS_PUBLIC_KEY_SIZE (4 + LMS_PUBLIC_KEY_SIZE)


// TODO: LMS_KEY should be a tree other than a vector
// when updated, low level lms keys will lost, maybe a good feature
typedef struct {
	uint32_t levels; // should be checked to prevent memory error
	LMS_KEY lms_key[5];
	LMS_SIGNATURE lms_sig[4];
} HSS_KEY;


#define HSS_PRIVATE_KEY_MAX_SIZE sizeof(HSS_KEY)
int hss_private_key_size(const int *lms_types, size_t levels, size_t *len);

int hss_key_generate(HSS_KEY *key, const int *lms_types, size_t levels);
int hss_key_update(HSS_KEY *key);

int hss_public_key_digest(const HSS_KEY *key, uint8_t dgst[32]);
int hss_public_key_to_bytes(const HSS_KEY *key, uint8_t **out, size_t *outlen);
int hss_private_key_to_bytes(const HSS_KEY *key, uint8_t **out, size_t *outlen);
int hss_public_key_from_bytes(HSS_KEY *key, const uint8_t **in, size_t *inlen);
int hss_private_key_from_bytes(HSS_KEY *key, const uint8_t **in, size_t *inlen);
int hss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const HSS_KEY *key);
int hss_key_print(FILE *fp, int fmt, int ind, const char *label, const HSS_KEY *key);
void hss_key_cleanup(HSS_KEY *key);


typedef struct {
	uint32_t num_signed_public_keys; // = hss_key->levels - 1
	struct {
		LMS_SIGNATURE lms_sig; // lms_sig[i] = sign(hss_key->lms_key[i], lms_public_key[i])
		LMS_PUBLIC_KEY lms_public_key; // signed_public_keys[i] = hss_key->lms_key[i+1].public_key
	} signed_public_keys[HSS_MAX_LEVELS - 1];
	LMS_SIGNATURE msg_lms_sig; // = sign(hss->lms_key[levels-1], msg)
} HSS_SIGNATURE;


#define HSS_SIGNATURE_MAX_SIZE sizeof(HSS_SIGNATURE)
int hss_signature_size(const int *lms_types, size_t levels, size_t *len);
int hss_key_get_signature_size(const HSS_KEY *key, size_t *siglen);

int hss_signature_to_bytes(const HSS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int hss_signature_from_bytes(HSS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int hss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const HSS_SIGNATURE *sig);
int hss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);


typedef struct {
	LMS_SIGN_CTX lms_ctx;
	uint32_t levels;
	LMS_SIGNATURE lms_sigs[HSS_MAX_LEVELS - 1];
	LMS_PUBLIC_KEY lms_public_keys[HSS_MAX_LEVELS - 1];
} HSS_SIGN_CTX;


int hss_sign_init(HSS_SIGN_CTX *ctx, HSS_KEY *key);
int hss_sign_update(HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int hss_sign_finish(HSS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int hss_sign_finish_ex(HSS_SIGN_CTX *ctx, HSS_SIGNATURE *sig);
int hss_verify_init_ex(HSS_SIGN_CTX *ctx, const HSS_KEY *key, const HSS_SIGNATURE *sig);
int hss_verify_init(HSS_SIGN_CTX *ctx, const HSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int hss_verify_update(HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int hss_verify_finish(HSS_SIGN_CTX *ctx);


// X.509 related
#define HSS_PUBLIC_KEY_DER_SIZE	63
#define HSS_PUBLIC_KEY_INFO_SIZE	82

int hss_public_key_to_der(const HSS_KEY *key, uint8_t **out, size_t *outlen);
int hss_public_key_from_der(HSS_KEY *key, const uint8_t **in, size_t *inlen);
int hss_public_key_algor_to_der(uint8_t **out, size_t *outlen);
int hss_public_key_algor_from_der(const uint8_t **in, size_t *inlen);
int hss_public_key_info_to_der(const HSS_KEY *key, uint8_t **out, size_t *outlen);
int hss_public_key_info_from_der(HSS_KEY *key, const uint8_t **in, size_t *inlen);


#ifdef __cplusplus
}
#endif
#endif
