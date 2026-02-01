/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#ifdef ENABLE_SHA2
#include <gmssl/sha2.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif


#define HSS_MAX_LEVELS 5
#define LMS_MAX_HEIGHT 25


typedef uint8_t lms_hash256_t[32];

// Crosscheck with data from LMS-reference (SHA-256), except the LMS signature.
#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
#define LMS_HASH256_CTX		SHA256_CTX
#define lms_hash256_init	sha256_init
#define lms_hash256_update	sha256_update
#define lms_hash256_finish	sha256_finish
#else
#define LMS_HASH256_CTX	SM3_CTX
#define lms_hash256_init	sm3_init
#define lms_hash256_update	sm3_update
#define lms_hash256_finish	sm3_finish
#endif


#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
enum {
	//LMOTS_SHA256_N32_W1	= 1,
	//LMOTS_SHA256_N32_W2	= 2,
	//LMOTS_SHA256_N32_W4	= 3,
	LMOTS_SHA256_N32_W8	= 4,
};
#define LMOTS_HASH256_N32_W8		 LMOTS_SHA256_N32_W8
#define LMOTS_HASH256_N32_W8_NAME	"LMOTS_SHA256_N32_W8"
#else
enum {
	//LMOTS_SM3_N32_W1	= 11,
	//LMOTS_SM3_N32_W2	= 12,
	//LMOTS_SM3_N32_W4	= 13,
	LMOTS_SM3_N32_W8	= 14,
};
#define LMOTS_HASH256_N32_W8		 LMOTS_SM3_N32_W8
#define LMOTS_HASH256_N32_W8_NAME	"LMOTS_SM3_N32_W8"
#endif

// in LMS, we use Winternitz w = 2^8 = 256
// represent 256-bit hash as 256/8 = 32 base_w numbers
// max checksum is 255 * 32 = 8160 < 2^13 = 8192, so checksum need two 8-bit base_w number
// so total hash chains is 32 + 2 = 34
#define LMOTS_NUM_CHAINS  34

typedef lms_hash256_t lmots_key_t[34];
typedef lms_hash256_t lmots_sig_t[34];

char *lmots_type_name(int lmots_type);
void lmots_derive_secrets(const lms_hash256_t seed, const uint8_t I[16], int q, lms_hash256_t x[34]);
void lmots_secrets_to_public_hash(const uint8_t I[16], int q, const lms_hash256_t x[34], lms_hash256_t pub);
void lmots_compute_signature(const uint8_t I[16], int q, const lms_hash256_t dgst, const lms_hash256_t x[34], lms_hash256_t y[34]);
void lmots_signature_to_public_hash(const uint8_t I[16], int q, const lms_hash256_t y[34], const lms_hash256_t dgst, lms_hash256_t pub);


#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
enum {
	LMS_SHA256_M32_H5	= 5,
	LMS_SHA256_M32_H10	= 6,
	LMS_SHA256_M32_H15	= 7,
	LMS_SHA256_M32_H20	= 8,
	LMS_SHA256_M32_H25	= 9,
};
#else
// TODO: submit to IETF
enum {
	LMS_SM3_M32_H5		= 5,
	LMS_SM3_M32_H10		= 6,
	LMS_SM3_M32_H15		= 7,
	LMS_SM3_M32_H20		= 8,
	LMS_SM3_M32_H25		= 9,
};
#endif

#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
# define LMS_HASH256_M32_H5		 LMS_SHA256_M32_H5
# define LMS_HASH256_M32_H5_NAME	"LMS_SHA256_M32_H5"
# define LMS_HASH256_M32_H10		 LMS_SHA256_M32_H10
# define LMS_HASH256_M32_H10_NAME	"LMS_SHA256_M32_H10"
# define LMS_HASH256_M32_H15		 LMS_SHA256_M32_H15
# define LMS_HASH256_M32_H15_NAME	"LMS_SHA256_M32_H15"
# define LMS_HASH256_M32_H20		 LMS_SHA256_M32_H20
# define LMS_HASH256_M32_H20_NAME	"LMS_SHA256_M32_H20"
# define LMS_HASH256_M32_H25		 LMS_SHA256_M32_H25
# define LMS_HASH256_M32_H25_NAME	"LMS_SHA256_M32_H25"
#else
# define LMS_HASH256_M32_H5		 LMS_SM3_M32_H5
# define LMS_HASH256_M32_H5_NAME	"LMS_SM3_M32_H5"
# define LMS_HASH256_M32_H10		 LMS_SM3_M32_H10
# define LMS_HASH256_M32_H10_NAME	"LMS_SM3_M32_H10"
# define LMS_HASH256_M32_H15		 LMS_SM3_M32_H15
# define LMS_HASH256_M32_H15_NAME	"LMS_SM3_M32_H15"
# define LMS_HASH256_M32_H20		 LMS_SM3_M32_H20
# define LMS_HASH256_M32_H20_NAME	"LMS_SM3_M32_H20"
# define LMS_HASH256_M32_H25		 LMS_SM3_M32_H25
# define LMS_HASH256_M32_H25_NAME	"LMS_SM3_M32_H25"
#endif

char *lms_type_name(int lms_type);
int   lms_type_from_name(const char *name);
int   lms_type_to_height(int type, size_t *height);
void  lms_derive_merkle_tree(const lms_hash256_t seed, const uint8_t I[16], int height, lms_hash256_t *tree);
void  lms_derive_merkle_root(const lms_hash256_t seed, const uint8_t I[16], int height, lms_hash256_t root);

typedef struct {
	int lms_type;
	int lmots_type;
	uint8_t I[16]; // lms key identifier
	lms_hash256_t root; // merkle tree root
} LMS_PUBLIC_KEY;

#define LMS_PUBLIC_KEY_SIZE (4 + 4 + 16 + 32) // = 56 bytes

typedef struct LMS_KEY_st LMS_KEY;

typedef int (*lms_key_update_callback)(LMS_KEY *key);

typedef struct LMS_KEY_st {
	LMS_PUBLIC_KEY public_key;
	lms_hash256_t seed; // secret seed
	uint32_t q; // key index

	lms_hash256_t *tree;
	lms_key_update_callback update_callback;
	void *update_param;
} LMS_KEY;

#define LMS_PRIVATE_KEY_SIZE (LMS_PUBLIC_KEY_SIZE + 32 + 4) // = 92 bytes

int lms_key_generate_ex(LMS_KEY *key, int lms_type, const lms_hash256_t seed, const uint8_t I[16], int cache_tree);
int lms_key_generate(LMS_KEY *key, int lms_type);
int lms_key_set_update_callback(LMS_KEY *key, lms_key_update_callback update_cb, void *param);
int lms_key_update(LMS_KEY *key);
int lms_key_remaining_signs(const LMS_KEY *key, size_t *count);
int lms_key_get_signature_size(const LMS_KEY *key, size_t *siglen);
void lms_key_cleanup(LMS_KEY *key);

int lms_public_key_to_bytes_ex(const LMS_PUBLIC_KEY *public_key, uint8_t **out, size_t *outlen); // called by signature_to_bytes
int lms_public_key_from_bytes_ex(LMS_PUBLIC_KEY *public_key, const uint8_t **in, size_t *inlen); // called by signature_from_bytes
int lms_public_key_to_bytes(const LMS_KEY *key, uint8_t **out, size_t *outlen);
int lms_public_key_from_bytes(LMS_KEY *key, const uint8_t **in, size_t *inlen);
int lms_public_key_print(FILE *fp, int fmt, int ind, const char *label, const LMS_KEY *pub);
int lms_private_key_to_bytes(const LMS_KEY *key, uint8_t **out, size_t *outlen);
int lms_private_key_from_bytes(LMS_KEY *key, const uint8_t **in, size_t *inlen);
int lms_private_key_print(FILE *fp, int fmt, int ind, const char *label, const LMS_KEY *key);


typedef struct {
	uint32_t q; // key index
	struct {
		int lmots_type;
		lms_hash256_t C; // signature random
		lms_hash256_t y[34];
	} lmots_sig;
	int lms_type;
	lms_hash256_t path[LMS_MAX_HEIGHT];
} LMS_SIGNATURE;

int lms_signature_to_merkle_root(const uint8_t I[16], size_t h, int q,
	const lms_hash256_t y[34], const lms_hash256_t *path,
	const lms_hash256_t dgst, lms_hash256_t root);

#define LMS_HASH256_M32_H5_SIGNATURE_SIZE 1292
#define LMS_HASH256_M32_H10_SIGNATURE_SIZE 1452
#define LMS_HASH256_M32_H15_SIGNATURE_SIZE 1612
#define LMS_HASH256_M32_H20_SIGNATURE_SIZE 1772
#define LMS_HASH256_M32_H25_SIGNATURE_SIZE 1932
#define LMS_SIGNATURE_MIN_SIZE LMS_HASH256_M32_H5_SIGNATURE_SIZE // = 4 + 4 + 32 + 32*34 + 4 + 32*5 = 1292 bytes
#define LMS_SIGNATURE_MAX_SIZE LMS_HASH256_M32_H25_SIGNATURE_SIZE // = 4 + 4 + 32 + 32*34 + 4 + 32*25 = 1932 bytes

int lms_signature_size(int lms_type, size_t *siglen);
int lms_signature_to_bytes(const LMS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int lms_signature_from_bytes(LMS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int lms_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const LMS_SIGNATURE *sig);
int lms_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

typedef struct {
	LMS_HASH256_CTX lms_hash256_ctx;
	LMS_PUBLIC_KEY lms_public_key;
	LMS_SIGNATURE lms_sig; // cache lmots x[34]
} LMS_SIGN_CTX;

int lms_sign_init(LMS_SIGN_CTX *ctx, LMS_KEY *key);
int lms_sign_update(LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int lms_sign_finish_ex(LMS_SIGN_CTX *ctx, LMS_SIGNATURE *sig);
int lms_sign_finish(LMS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int lms_verify_init_ex(LMS_SIGN_CTX *ctx, const LMS_KEY *key, const LMS_SIGNATURE *sig);
int lms_verify_init(LMS_SIGN_CTX *ctx, const LMS_KEY *key, const uint8_t *sig, size_t siglen);
int lms_verify_update(LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int lms_verify_finish(LMS_SIGN_CTX *ctx);
void lms_sign_ctx_cleanup(LMS_SIGN_CTX *ctx);



// just for reference, HSS_PUBLIC_KEY memory layout might not compatible with HSS_KEY
typedef struct {
	uint32_t levels;
	LMS_PUBLIC_KEY lms_public_key;
} HSS_PUBLIC_KEY;

#define HSS_PUBLIC_KEY_SIZE (4 + LMS_PUBLIC_KEY_SIZE) // = 60 bytes

typedef struct HSS_KEY_st HSS_KEY;

typedef int (*hss_key_update_callback)(HSS_KEY *key);

typedef struct HSS_KEY_st {
	uint32_t levels;
	LMS_KEY lms_key[5];
	LMS_SIGNATURE lms_sig[4];
	hss_key_update_callback update_callback;
	void *update_param;
} HSS_KEY;

#define HSS_PRIVATE_KEY_MAX_SIZE sizeof(HSS_KEY)
int hss_private_key_size(const int *lms_types, size_t levels, size_t *len);

int hss_key_generate(HSS_KEY *key, const int *lms_types, size_t levels);
int hss_key_set_update_callback(HSS_KEY *key, hss_key_update_callback update_cb, void *param);
int hss_key_update(HSS_KEY *key);
int hss_key_get_signature_size(const HSS_KEY *key, size_t *siglen);
void hss_key_cleanup(HSS_KEY *key);

int hss_public_key_equ(const HSS_KEY *key, const HSS_KEY *pub);
int hss_public_key_to_bytes(const HSS_KEY *key, uint8_t **out, size_t *outlen);
int hss_private_key_to_bytes(const HSS_KEY *key, uint8_t **out, size_t *outlen);
int hss_public_key_from_bytes(HSS_KEY *key, const uint8_t **in, size_t *inlen);
int hss_private_key_from_bytes(HSS_KEY *key, const uint8_t **in, size_t *inlen);
int hss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const HSS_KEY *key);
int hss_private_key_print(FILE *fp, int fmt, int ind, const char *label, const HSS_KEY *key);

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
int hss_signature_to_bytes(const HSS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int hss_signature_from_bytes(HSS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int hss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const HSS_SIGNATURE *sig);
int hss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

typedef struct {
	LMS_SIGN_CTX lms_sign_ctx;
	uint32_t levels;
	LMS_SIGNATURE lms_sigs[HSS_MAX_LEVELS - 1];
	LMS_PUBLIC_KEY lms_public_keys[HSS_MAX_LEVELS - 1];
} HSS_SIGN_CTX;

int hss_sign_init(HSS_SIGN_CTX *ctx, HSS_KEY *key);
int hss_sign_update(HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int hss_sign_finish_ex(HSS_SIGN_CTX *ctx, HSS_SIGNATURE *sig);
int hss_sign_finish(HSS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int hss_verify_init_ex(HSS_SIGN_CTX *ctx, const HSS_KEY *key, const HSS_SIGNATURE *sig);
int hss_verify_init(HSS_SIGN_CTX *ctx, const HSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int hss_verify_update(HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int hss_verify_finish(HSS_SIGN_CTX *ctx);
void hss_sign_ctx_cleanup(HSS_SIGN_CTX *ctx);


#ifdef __cplusplus
}
#endif
#endif
