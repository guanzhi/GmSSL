/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/sm2_z256.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	SM2_Z256_POINT public_key;
	sm2_z256_t private_key;
} SM2_KEY;

int sm2_key_generate(SM2_KEY *key);
int sm2_key_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY *key);
int sm2_key_set_private_key(SM2_KEY *key, const sm2_z256_t private_key);
int sm2_key_set_public_key(SM2_KEY *key, const SM2_Z256_POINT *public_key);

int sm2_public_key_equ(const SM2_KEY *sm2_key, const SM2_KEY *pub_key);
int sm2_public_key_digest(const SM2_KEY *key, uint8_t dgst[32]);
int sm2_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY *pub_key);


/*
from RFC 5915

ECPrivateKey ::= SEQUENCE {
	version		INTEGER,	-- value MUST be (1)
	privateKey	OCTET STRING,	-- big endian encoding of integer, fixed length
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
int sm2_public_key_info_to_der(const SM2_KEY *a, uint8_t **out, size_t *outlen);
int sm2_public_key_info_from_der(SM2_KEY *a, const uint8_t **in, size_t *inlen);
int sm2_public_key_info_to_pem(const SM2_KEY *a, FILE *fp);
int sm2_public_key_info_from_pem(SM2_KEY *a, FILE *fp);

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
int sm2_private_key_info_encrypt_to_der(const SM2_KEY *key,
	const char *pass, uint8_t **out, size_t *outlen);
int sm2_private_key_info_decrypt_from_der(SM2_KEY *key, const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen);
int sm2_private_key_info_encrypt_to_pem(const SM2_KEY *key, const char *pass, FILE *fp);
// FIXME: #define default buffer size
int sm2_private_key_info_decrypt_from_pem(SM2_KEY *key, const char *pass, FILE *fp);



typedef struct {
	uint8_t r[32];
	uint8_t s[32];
} SM2_SIGNATURE;

int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig);
int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig);

int sm2_fast_sign_compute_key(const SM2_KEY *key, sm2_z256_t fast_private);

typedef struct {
	sm2_z256_t k;
	sm2_z256_t x1_modn;
} SM2_SIGN_PRE_COMP;

#define SM2_SIGN_PRE_COMP_COUNT 32

int sm2_fast_sign_pre_compute(SM2_SIGN_PRE_COMP pre_comp[32]);
int sm2_fast_sign(const sm2_z256_t fast_private, SM2_SIGN_PRE_COMP *pre_comp,
	const uint8_t dgst[32], SM2_SIGNATURE *sig);
int sm2_fast_verify(const SM2_Z256_POINT point_table[16],
	const uint8_t dgst[32], const SM2_SIGNATURE *sig);


#define SM2_MIN_SIGNATURE_SIZE 8
#define SM2_MAX_SIGNATURE_SIZE 72
int sm2_signature_to_der(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sm2_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);
int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen);

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

int sm2_compute_z(uint8_t z[32], const SM2_Z256_POINT *pub, const char *id, size_t idlen);



typedef struct {
	SM3_CTX sm3_ctx;
	SM3_CTX saved_sm3_ctx;
	SM2_KEY key;
	sm2_z256_t fast_sign_private;
	SM2_SIGN_PRE_COMP pre_comp[SM2_SIGN_PRE_COMP_COUNT];
	unsigned int num_pre_comp;

	// verify public point table, P, 2P, ..., 16P
	SM2_Z256_POINT public_point_table[16];
} SM2_SIGN_CTX;

int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sm2_sign_reset(SM2_SIGN_CTX *ctx);
int sm2_sign_finish_fixlen(SM2_SIGN_CTX *ctx, size_t siglen, uint8_t *sig);

typedef struct {
	SM3_CTX sm3_ctx;
	SM3_CTX saved_sm3_ctx;
	SM2_KEY key;
	SM2_Z256_POINT public_point_table[16];
} SM2_VERIFY_CTX;

int sm2_verify_init(SM2_VERIFY_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
int sm2_verify_update(SM2_VERIFY_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_verify_finish(SM2_VERIFY_CTX *ctx, const uint8_t *sig, size_t siglen);
int sm2_verify_reset(SM2_VERIFY_CTX *ctx);


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
	uint8_t x[32];
	uint8_t y[32];
} SM2_POINT;

typedef struct {
	SM2_POINT point;
	uint8_t hash[32];
	uint8_t ciphertext_size;
	uint8_t ciphertext[SM2_MAX_PLAINTEXT_SIZE];
} SM2_CIPHERTEXT;


int sm2_kdf(const uint8_t *in, size_t inlen, size_t outlen, uint8_t *out);

int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out);
int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen);

#define SM2_MIN_CIPHERTEXT_SIZE	 45 // depends on SM2_MIN_PLAINTEXT_SIZE
#define SM2_MAX_CIPHERTEXT_SIZE	366 // depends on SM2_MAX_PLAINTEXT_SIZE
int sm2_ciphertext_to_der(const SM2_CIPHERTEXT *c, uint8_t **out, size_t *outlen);
int sm2_ciphertext_from_der(SM2_CIPHERTEXT *c, const uint8_t **in, size_t *inlen);
int sm2_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);
int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);

enum {
	SM2_ciphertext_compact_point_size = 68,
	SM2_ciphertext_typical_point_size = 69,
	SM2_ciphertext_max_point_size = 70,
};
int sm2_do_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, SM2_CIPHERTEXT *out);
int sm2_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, uint8_t *out, size_t *outlen);


int sm2_do_ecdh(const SM2_KEY *key, const SM2_Z256_POINT *peer_public, SM2_Z256_POINT *out);
int sm2_ecdh(const SM2_KEY *key, const uint8_t *peer_public, size_t peer_public_len, uint8_t out[64]);


typedef struct {
	sm2_z256_t k;
	SM2_POINT C1;
} SM2_ENC_PRE_COMP;

#define SM2_ENC_PRE_COMP_NUM 8
int sm2_encrypt_pre_compute(SM2_ENC_PRE_COMP pre_comp[SM2_ENC_PRE_COMP_NUM]);
int sm2_do_encrypt_ex(const SM2_KEY *key, const SM2_ENC_PRE_COMP *pre_comp,
	const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out);

typedef struct {
	SM2_ENC_PRE_COMP pre_comp[SM2_ENC_PRE_COMP_NUM];
	size_t pre_comp_num;
	uint8_t buf[SM2_MAX_PLAINTEXT_SIZE];
	size_t buf_size;
} SM2_ENC_CTX;

int sm2_encrypt_init(SM2_ENC_CTX *ctx);
int sm2_encrypt_update(SM2_ENC_CTX *ctx, const uint8_t *in, size_t inlen);
int sm2_encrypt_finish(SM2_ENC_CTX *ctx, const SM2_KEY *public_key, uint8_t *out, size_t *outlen);
int sm2_encrypt_reset(SM2_ENC_CTX *ctx);

typedef struct {
	uint8_t buf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t buf_size;
} SM2_DEC_CTX;

int sm2_decrypt_init(SM2_DEC_CTX *ctx);
int sm2_decrypt_update(SM2_DEC_CTX *ctx, const uint8_t *in, size_t inlen);
int sm2_decrypt_finish(SM2_DEC_CTX *ctx, const SM2_KEY *key, uint8_t *out, size_t *outlen);
int sm2_decrypt_reset(SM2_DEC_CTX *ctx);


#ifdef __cplusplus
}
#endif
#endif
