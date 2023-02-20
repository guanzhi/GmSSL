/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_SM2_H
#define GMSSL_SM2_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <gmssl/api.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
SM2 Public API

	SM2_DEFAULT_ID
	SM2_MAX_ID_LENGTH
	SM2_MAX_SIGNATURE_SIZE
	SM2_MAX_PLAINTEXT_SIZE
	SM2_MAX_CIPHERTEXT_SIZE

	SM2_KEY
	sm2_key_generate
	sm2_private_key_info_encrypt_to_der
	sm2_private_key_info_decrypt_from_der
	sm2_private_key_info_encrypt_to_pem
	sm2_private_key_info_decrypt_from_pem
	sm2_public_key_info_to_der
	sm2_public_key_info_from_der
	sm2_public_key_info_to_pem
	sm2_public_key_info_from_pem

	sm2_sign
	sm2_verify
	sm2_encrypt
	sm2_decrypt
	sm2_ecdh

	SM2_SIGN_CTX
	sm2_sign_init
	sm2_sign_update
	sm2_sign_finish
	sm2_verify_init
	sm2_verify_update
	sm2_verify_finish
*/

typedef uint64_t SM2_BN[8];

int sm2_bn_is_zero(const SM2_BN a);
int sm2_bn_is_one(const SM2_BN a);
int sm2_bn_is_odd(const SM2_BN a);
int sm2_bn_cmp(const SM2_BN a, const SM2_BN b);
int sm2_bn_from_hex(SM2_BN r, const char hex[64]);
int sm2_bn_from_asn1_integer(SM2_BN r, const uint8_t *d, size_t dlen);
int sm2_bn_equ_hex(const SM2_BN a, const char *hex);
int sm2_bn_print(FILE *fp, int fmt, int ind, const char *label, const SM2_BN a);
int sm2_bn_rshift(SM2_BN ret, const SM2_BN a, unsigned int nbits);

void sm2_bn_to_bytes(const SM2_BN a, uint8_t out[32]);
void sm2_bn_from_bytes(SM2_BN r, const uint8_t in[32]);
void sm2_bn_to_hex(const SM2_BN a, char hex[64]);
void sm2_bn_to_bits(const SM2_BN a, char bits[256]);
void sm2_bn_set_word(SM2_BN r, uint32_t a);
void sm2_bn_add(SM2_BN r, const SM2_BN a, const SM2_BN b);
void sm2_bn_sub(SM2_BN ret, const SM2_BN a, const SM2_BN b);
int  sm2_bn_rand_range(SM2_BN r, const SM2_BN range);

#define sm2_bn_init(r) memset((r),0,sizeof(SM2_BN))
#define sm2_bn_set_zero(r) memset((r),0,sizeof(SM2_BN))
#define sm2_bn_set_one(r) sm2_bn_set_word((r),1)
#define sm2_bn_copy(r,a) memcpy((r),(a),sizeof(SM2_BN))
#define sm2_bn_clean(r) memset((r),0,sizeof(SM2_BN))


// GF(p)
typedef SM2_BN SM2_Fp;

void sm2_fp_add(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_sub(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_mul(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_exp(SM2_Fp r, const SM2_Fp a, const SM2_Fp e);
void sm2_fp_dbl(SM2_Fp r, const SM2_Fp a);
void sm2_fp_tri(SM2_Fp r, const SM2_Fp a);
void sm2_fp_div2(SM2_Fp r, const SM2_Fp a);
void sm2_fp_neg(SM2_Fp r, const SM2_Fp a);
void sm2_fp_sqr(SM2_Fp r, const SM2_Fp a);
void sm2_fp_inv(SM2_Fp r, const SM2_Fp a);
int  sm2_fp_rand(SM2_Fp r);

int sm2_fp_sqrt(SM2_Fp r, const SM2_Fp a);

#define sm2_fp_init(r)		sm2_bn_init(r)
#define sm2_fp_set_zero(r)	sm2_bn_set_zero(r)
#define sm2_fp_set_one(r)	sm2_bn_set_one(r)
#define sm2_fp_copy(r,a)	sm2_bn_copy(r,a)
#define sm2_fp_clean(r)		sm2_bn_clean(r)

// GF(n)
typedef SM2_BN SM2_Fn;

void sm2_fn_add(SM2_Fn r, const SM2_Fn a, const SM2_Fn b);
void sm2_fn_sub(SM2_Fn r, const SM2_Fn a, const SM2_Fn b);
void sm2_fn_mul(SM2_Fn r, const SM2_Fn a, const SM2_Fn b);
void sm2_fn_mul_word(SM2_Fn r, const SM2_Fn a, uint32_t b);
void sm2_fn_exp(SM2_Fn r, const SM2_Fn a, const SM2_Fn e);
void sm2_fn_neg(SM2_Fn r, const SM2_Fn a);
void sm2_fn_sqr(SM2_Fn r, const SM2_Fn a);
void sm2_fn_inv(SM2_Fn r, const SM2_Fn a);
int  sm2_fn_rand(SM2_Fn r);

#define sm2_fn_init(r)		sm2_bn_init(r)
#define sm2_fn_set_zero(r)	sm2_bn_set_zero(r)
#define sm2_fn_set_one(r)	sm2_bn_set_one(r)
#define sm2_fn_copy(r,a)	sm2_bn_copy(r,a)
#define sm2_fn_clean(r)		sm2_bn_clean(r)


typedef struct {
	SM2_BN X;
	SM2_BN Y;
	SM2_BN Z;
} SM2_JACOBIAN_POINT;

void sm2_jacobian_point_init(SM2_JACOBIAN_POINT *R);
void sm2_jacobian_point_set_xy(SM2_JACOBIAN_POINT *R, const SM2_BN x, const SM2_BN y);
void sm2_jacobian_point_get_xy(const SM2_JACOBIAN_POINT *P, SM2_BN x, SM2_BN y);
void sm2_jacobian_point_neg(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_dbl(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_add(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q);
void sm2_jacobian_point_sub(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q);
void sm2_jacobian_point_mul(SM2_JACOBIAN_POINT *R, const SM2_BN k, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_to_bytes(const SM2_JACOBIAN_POINT *P, uint8_t out[64]);
void sm2_jacobian_point_from_bytes(SM2_JACOBIAN_POINT *P, const uint8_t in[64]);
void sm2_jacobian_point_mul_generator(SM2_JACOBIAN_POINT *R, const SM2_BN k);
void sm2_jacobian_point_mul_sum(SM2_JACOBIAN_POINT *R, const SM2_BN t, const SM2_JACOBIAN_POINT *P, const SM2_BN s);
void sm2_jacobian_point_from_hex(SM2_JACOBIAN_POINT *P, const char hex[64 * 2]); // for testing only

int sm2_jacobian_point_is_at_infinity(const SM2_JACOBIAN_POINT *P);
int sm2_jacobian_point_is_on_curve(const SM2_JACOBIAN_POINT *P);
int sm2_jacobian_point_equ_hex(const SM2_JACOBIAN_POINT *P, const char hex[128]); // for testing only
int sm2_jacobian_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_JACOBIAN_POINT *P);

#define sm2_jacobian_point_set_infinity(R) sm2_jacobian_point_init(R)
#define sm2_jacobian_point_copy(R, P) memcpy((R), (P), sizeof(SM2_JACOBIAN_POINT))

typedef uint8_t sm2_bn_t[32];

typedef struct {
	uint8_t x[32];
	uint8_t y[32];
} SM2_POINT;

#define sm2_point_init(P) memset((P),0,sizeof(SM2_POINT))
#define sm2_point_set_infinity(P) sm2_point_init(P)
int sm2_point_from_octets(SM2_POINT *P, const uint8_t *in, size_t inlen);
void sm2_point_to_compressed_octets(const SM2_POINT *P, uint8_t out[33]);
void sm2_point_to_uncompressed_octets(const SM2_POINT *P, uint8_t out[65]);

int sm2_point_from_x(SM2_POINT *P, const uint8_t x[32], int y);
int sm2_point_from_xy(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32]);
int sm2_point_is_on_curve(const SM2_POINT *P);
int sm2_point_is_at_infinity(const SM2_POINT *P);
int sm2_point_add(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q);
int sm2_point_sub(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q);
int sm2_point_neg(SM2_POINT *R, const SM2_POINT *P);
int sm2_point_dbl(SM2_POINT *R, const SM2_POINT *P);
int sm2_point_mul(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P);
int sm2_point_mul_generator(SM2_POINT *R, const uint8_t k[32]);
int sm2_point_mul_sum(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P, const uint8_t s[32]); // R = k * P + s * G

/*
RFC 5480 Elliptic Curve Cryptography Subject Public Key Information
ECPoint ::= OCTET STRING
*/
#define SM2_POINT_MAX_SIZE (2 + 65)
int sm2_point_to_der(const SM2_POINT *P, uint8_t **out, size_t *outlen);
int sm2_point_from_der(SM2_POINT *P, const uint8_t **in, size_t *inlen);
int sm2_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_POINT *P);
int sm2_point_from_hash(SM2_POINT *R, const uint8_t *data, size_t datalen);


typedef struct {
	SM2_POINT public_key;
	uint8_t private_key[32];
} SM2_KEY;


_gmssl_export int sm2_key_generate(SM2_KEY *key);
int sm2_key_set_private_key(SM2_KEY *key, const uint8_t private_key[32]); // key->public_key will be replaced
int sm2_key_set_public_key(SM2_KEY *key, const SM2_POINT *public_key); // key->private_key will be cleared // FIXME: support octets as input?
int sm2_key_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY *key);

int sm2_public_key_equ(const SM2_KEY *sm2_key, const SM2_KEY *pub_key);
//int sm2_public_key_copy(SM2_KEY *sm2_key, const SM2_KEY *pub_key); // do we need this?
int sm2_public_key_digest(const SM2_KEY *key, uint8_t dgst[32]);
int sm2_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY *pub_key);

/*
from RFC 5915

ECPrivateKey ::= SEQUENCE {
	version		INTEGER,	-- value MUST be (1)
	privateKey	OCTET STRING,	-- big endian encoding of integer 这里不是以INTEGER编码的，因此长度固定
	parameters	[0] EXPLICIT ECParameters OPTIONAL,
					-- ONLY namedCurve OID is permitted, by RFC 5480
					-- MUST always include this field, by RFC 5915
	publicKey	[1] EXPLICIT BIT STRING OPTIONAL -- compressed_point
					-- SHOULD always include this field, by RFC 5915 }

ECParameters ::= CHOICE { namedCurve OBJECT IDENTIFIER }
*/
#define SM2_PRIVATE_KEY_DEFAULT_SIZE 120 // generated
#define SM2_PRIVATE_KEY_BUF_SIZE 512 // MUST >= SM2_PRIVATE_KEY_DEFAULT_SIZE

int sm2_private_key_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen);
int sm2_private_key_from_der(SM2_KEY *key, const uint8_t **in, size_t *inlen);
int sm2_private_key_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
int sm2_private_key_to_pem(const SM2_KEY *key, FILE *fp);
int sm2_private_key_from_pem(SM2_KEY *key, FILE *fp);

/*
AlgorithmIdentifier ::= {
	algorithm	OBJECT IDENTIFIER { id-ecPublicKey },
	parameters	OBJECT IDENTIFIER { id-sm2 } }
*/
int sm2_public_key_algor_to_der(uint8_t **out, size_t *outlen);
int sm2_public_key_algor_from_der(const uint8_t **in, size_t *inlen);

/*
SubjectPublicKeyInfo from RFC 5280

SubjectPublicKeyInfo  ::=  SEQUENCE  {
	algorithm            AlgorithmIdentifier,
	subjectPublicKey     BIT STRING  -- uncompressed octets of ECPoint }
*/
_gmssl_export int sm2_public_key_info_to_der(const SM2_KEY *a, uint8_t **out, size_t *outlen);
_gmssl_export int sm2_public_key_info_from_der(SM2_KEY *a, const uint8_t **in, size_t *inlen);
_gmssl_export int sm2_public_key_info_to_pem(const SM2_KEY *a, FILE *fp);
_gmssl_export int sm2_public_key_info_from_pem(SM2_KEY *a, FILE *fp);

/*
PKCS #8 PrivateKeyInfo from RFC 5208

PrivateKeyInfo ::= SEQUENCE {
	version			Version { v1(0) },
	privateKeyAlgorithm	AlgorithmIdentifier,
	privateKey		OCTET STRING, -- DER-encoding of ECPrivateKey
	attributes		[0] IMPLICIT SET OF Attribute OPTIONAL }
*/
enum {
	PKCS8_private_key_info_version = 0,
};


int sm2_private_key_info_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen);
int sm2_private_key_info_from_der(SM2_KEY *key, const uint8_t **attrs, size_t *attrslen, const uint8_t **in, size_t *inlen);
int sm2_private_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
int sm2_private_key_info_to_pem(const SM2_KEY *key, FILE *fp);
// FIXME: #define default buffer size for sm2_private_key_info_from_pem
int sm2_private_key_info_from_pem(SM2_KEY *key, FILE *fp);

/*
EncryptedPrivateKeyInfo ::= SEQUENCE {
	encryptionAlgorithm	EncryptionAlgorithmIdentifier, -- id-PBES2
	encryptedData		OCTET STRING }
*/
_gmssl_export int sm2_private_key_info_encrypt_to_der(const SM2_KEY *key,
	const char *pass, uint8_t **out, size_t *outlen);
_gmssl_export int sm2_private_key_info_decrypt_from_der(SM2_KEY *key, const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen);
_gmssl_export int sm2_private_key_info_encrypt_to_pem(const SM2_KEY *key, const char *pass, FILE *fp);
// FIXME: #define default buffer size
_gmssl_export int sm2_private_key_info_decrypt_from_pem(SM2_KEY *key, const char *pass, FILE *fp);


typedef struct {
	uint8_t r[32];
	uint8_t s[32];
} SM2_SIGNATURE;

int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig);
int sm2_do_sign_fast(const SM2_Fn d, const uint8_t dgst[32], SM2_SIGNATURE *sig);
int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig);


#define SM2_MIN_SIGNATURE_SIZE 8
#define SM2_MAX_SIGNATURE_SIZE 72
int sm2_signature_to_der(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sm2_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);
_gmssl_export int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
_gmssl_export int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen);

enum {
	SM2_signature_compact_size = 70,
	SM2_signature_typical_size = 71,
	SM2_signature_max_size = 72,
};
int sm2_sign_fixlen(const SM2_KEY *key, const uint8_t dgst[32], size_t siglen, uint8_t *sig);

#define SM2_DEFAULT_ID		"1234567812345678"
#define SM2_DEFAULT_ID_LENGTH	(sizeof(SM2_DEFAULT_ID) - 1)  // LENGTH for string and SIZE for bytes
#define SM2_DEFAULT_ID_BITS	(SM2_DEFAULT_ID_LENGTH * 8)
#define SM2_MAX_ID_BITS		65535
#define SM2_MAX_ID_LENGTH	(SM2_MAX_ID_BITS/8)

int sm2_compute_z(uint8_t z[32], const SM2_POINT *pub, const char *id, size_t idlen);


typedef struct {
	SM3_CTX sm3_ctx;
	SM2_KEY key;
} SM2_SIGN_CTX;

_gmssl_export int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
_gmssl_export int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
_gmssl_export int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sm2_sign_finish_fixlen(SM2_SIGN_CTX *ctx, size_t siglen, uint8_t *sig);

_gmssl_export int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
_gmssl_export int sm2_verify_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
_gmssl_export int sm2_verify_finish(SM2_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen);

/*
SM2Cipher ::= SEQUENCE {
	XCoordinate	INTEGER,
	YCoordinate	INTEGER,
	HASH		OCTET STRING SIZE(32),
	CipherText	OCTET STRING }
*/
#define SM2_MIN_PLAINTEXT_SIZE	1 // re-compute SM2_MIN_CIPHERTEXT_SIZE when modify
#define SM2_MAX_PLAINTEXT_SIZE	255 // re-compute SM2_MAX_CIPHERTEXT_SIZE when modify

typedef struct {
	SM2_POINT point;
	uint8_t hash[32];
	uint8_t ciphertext_size;
	uint8_t ciphertext[SM2_MAX_PLAINTEXT_SIZE];
} SM2_CIPHERTEXT;

int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out);
int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen);

#define SM2_MIN_CIPHERTEXT_SIZE	 45 // depends on SM2_MIN_PLAINTEXT_SIZE
#define SM2_MAX_CIPHERTEXT_SIZE	366 // depends on SM2_MAX_PLAINTEXT_SIZE
int sm2_ciphertext_to_der(const SM2_CIPHERTEXT *c, uint8_t **out, size_t *outlen);
int sm2_ciphertext_from_der(SM2_CIPHERTEXT *c, const uint8_t **in, size_t *inlen);
int sm2_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);
_gmssl_export int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
_gmssl_export int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);

enum {
	SM2_ciphertext_compact_point_size = 68,
	SM2_ciphertext_typical_point_size = 69,
	SM2_ciphertext_max_point_size = 70,
};
int sm2_do_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, SM2_CIPHERTEXT *out);
int sm2_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, uint8_t *out, size_t *outlen);


int sm2_do_ecdh(const SM2_KEY *key, const SM2_POINT *peer_public, SM2_POINT *out);
_gmssl_export int sm2_ecdh(const SM2_KEY *key, const uint8_t *peer_public, size_t peer_public_len, SM2_POINT *out);


#ifdef __cplusplus
}
#endif
#endif
