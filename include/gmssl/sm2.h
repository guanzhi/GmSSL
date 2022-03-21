/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef GMSSL_SM2_H
#define GMSSL_SM2_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint8_t x[32];
	uint8_t y[32];
} SM2_POINT;

void sm2_point_to_compressed_octets(const SM2_POINT *P, uint8_t out[33]);
void sm2_point_to_uncompressed_octets(const SM2_POINT *P, uint8_t out[65]);
int sm2_point_from_octets(SM2_POINT *P, const uint8_t *in, size_t inlen);

/*
RFC 5480 Elliptic Curve Cryptography Subject Public Key Information
ECPoint ::= OCTET STRING
*/
int sm2_point_to_der(const SM2_POINT *P, uint8_t **out, size_t *outlen);
int sm2_point_from_der(SM2_POINT *P, const uint8_t **in, size_t *inlen);


int sm2_point_from_x(SM2_POINT *P, const uint8_t x[32], int y);
int sm2_point_from_xy(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32]);
int sm2_point_is_on_curve(const SM2_POINT *P);
int sm2_point_mul(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P);
int sm2_point_mul_generator(SM2_POINT *R, const uint8_t k[32]);
int sm2_point_mul_sum(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P, const uint8_t s[32]); // R = k * P + s * G
int sm2_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_POINT *P);

typedef struct {
	SM2_POINT public_key;
	uint8_t private_key[32];
} SM2_KEY;

int sm2_key_generate(SM2_KEY *key);
int sm2_key_set_private_key(SM2_KEY *key, const uint8_t private_key[32]); // 自动生成公钥
int sm2_key_set_public_key(SM2_KEY *key, const SM2_POINT *public_key); // 自动清空私钥，不要和set_private_key同时用
int sm2_key_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY *key);

int sm2_public_key_equ(const SM2_KEY *sm2_key, const SM2_KEY *pub_key);
int sm2_public_key_copy(SM2_KEY *sm2_key, const SM2_KEY *pub_key);
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
X.509 SubjectPublicKeyInfo from RFC 5280

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
int sm2_private_key_info_from_pem(SM2_KEY *key, const uint8_t **attrs, size_t *attrslen, FILE *fp);

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
int sm2_private_key_info_decrypt_from_pem(SM2_KEY *key, const char *pass, FILE *fp);


typedef struct {
	uint8_t r[32];
	uint8_t s[32];
} SM2_SIGNATURE;

int sm2_signature_to_der(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sm2_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);
int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig);
int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig);

#define SM2_MIN_SIGNATURE_SIZE 8
#define SM2_MAX_SIGNATURE_SIZE 72

int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen);


#define SM2_DEFAULT_ID				"1234567812345678"
#define SM2_DEFAULT_ID_LENGTH			(sizeof(SM2_DEFAULT_ID) - 1)  // LENGTH for string and SIZE for bytes
#define SM2_DEFAULT_ID_BITS			(SM2_DEFAULT_ID_LENGTH * 8)
#define SM2_MAX_ID_BITS				65535
#define SM2_MAX_ID_LENGTH			(SM2_MAX_ID_BITS/8)

int sm2_compute_z(uint8_t z[32], const SM2_POINT *pub, const char *id, size_t idlen);


typedef struct {
	SM2_KEY key;
	SM3_CTX sm3_ctx;
} SM2_SIGN_CTX;

int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);

int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
int sm2_verify_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_verify_finish(SM2_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen);

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

int sm2_ciphertext_to_der(const SM2_CIPHERTEXT *c, uint8_t **out, size_t *outlen);
int sm2_ciphertext_from_der(SM2_CIPHERTEXT *c, const uint8_t **in, size_t *inlen);
int sm2_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);
int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out);
int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen);

#define SM2_MIN_CIPHERTEXT_SIZE	45 // dependes on SM2_MIN_PLAINTEXT_SIZE
#define SM2_MAX_CIPHERTEXT_SIZE	366 // depends on SM2_MAX_PLAINTEXT_SIZE

int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);


int sm2_ecdh(const SM2_KEY *key, const SM2_POINT *peer_public, SM2_POINT *out);

int sm2_selftest(void);

#ifdef __cplusplus
extern "C" {
#endif
#endif
