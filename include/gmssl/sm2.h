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
int sm2_point_to_der(const SM2_POINT *a, uint8_t **out, size_t *outlen);
int sm2_point_from_der(SM2_POINT *a, const uint8_t **in, size_t *inlen);
int sm2_point_from_x(SM2_POINT *P, const uint8_t x[32], int y);
int sm2_point_from_xy(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32]);
int sm2_point_is_on_curve(const SM2_POINT *P);
int sm2_point_mul(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P);
int sm2_point_mul_generator(SM2_POINT *R, const uint8_t k[32]);
int sm2_point_mul_sum(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P, const uint8_t s[32]);
int sm2_point_print(FILE *fp, const SM2_POINT *P, int format, int indent);

int sm2_compute_z(uint8_t z[32], const SM2_POINT *pub, const char *id);


typedef struct {
	SM2_POINT public_key;
	uint8_t private_key[32];
	uint8_t key_usage[4];
} SM2_KEY;

int sm2_keygen(SM2_KEY *key);
int sm2_set_private_key(SM2_KEY *key, const uint8_t private_key[32]);
int sm2_set_public_key(SM2_KEY *key, const uint8_t public_key[64]); // FIXME: 这里是否应该用octets呢？这算是椭圆曲线点的一个公开格式了
int sm2_key_print(FILE *fp, const SM2_KEY *key, int format, int indent);
int sm2_public_key_digest(const SM2_KEY *key, uint8_t dgst[32]);

// ECPrivateKey
int sm2_private_key_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen);
int sm2_private_key_to_pem(const SM2_KEY *key, FILE *fp);
int sm2_private_key_from_der(SM2_KEY *key, const uint8_t **in, size_t *inlen);
int sm2_private_key_from_pem(SM2_KEY *key, FILE *fp);


// AlgorithmIdentifier
int sm2_public_key_algor_to_der(uint8_t **out, size_t *outlen);
int sm2_public_key_algor_from_der(const uint8_t **in, size_t *inlen);

// X.509 SubjectPublicKeyInfo
int sm2_public_key_info_to_der(const SM2_KEY *a, uint8_t **out, size_t *outlen);
int sm2_public_key_info_to_pem(const SM2_KEY *a, FILE *fp);
int sm2_public_key_info_from_der(SM2_KEY *a, const uint8_t **in, size_t *inlen);
int sm2_public_key_info_from_pem(SM2_KEY *a, FILE *fp);

// PKCS #8 PrivateKeyInfo
int sm2_private_key_info_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen);
int sm2_private_key_info_from_der(SM2_KEY *key, const uint8_t **attrs, size_t *attrslen, const uint8_t **in, size_t *inlen);
int sm2_private_key_info_to_pem(const SM2_KEY *key, FILE *fp);
int sm2_private_key_info_from_pem(SM2_KEY *key, const uint8_t **attrs, size_t *attrslen, FILE *fp);


typedef struct {
	uint8_t r[32];
	uint8_t s[32];
} SM2_SIGNATURE;

int sm2_signature_to_der(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig);
int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig);
int sm2_print_signature(FILE *fp, const uint8_t *sig, size_t siglen, int format, int indent);

#define SM2_MAX_SIGNATURE_SIZE 72

int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen);

#define SM2_MAX_ID_BITS				65535
#define SM2_MAX_ID_LENGTH			(SM2_MAX_ID_BITS/8)
#define SM2_MAX_ID_SIZE				(SM2_MAX_ID_BITS/8)
#define SM2_DEFAULT_ID_GMT09			"1234567812345678"
#define SM2_DEFAULT_ID_GMSSL			"anonym@gmssl.org"
#define SM2_DEFAULT_ID				SM2_DEFAULT_ID_GMT09
#define SM2_DEFAULT_ID_LENGTH			(sizeof(SM2_DEFAULT_ID) - 1)
#define SM2_DEFAULT_ID_BITS			(SM2_DEFAULT_ID_LENGTH * 8)
#define SM2_DEFAULT_ID_DIGEST_LENGTH		SM3_DIGEST_LENGTH


typedef struct {
	SM2_KEY key;
	SM3_CTX sm3_ctx;
	int flags;
} SM2_SIGN_CTX;

int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id);
int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id);
int sm2_verify_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_verify_finish(SM2_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen);


typedef struct {
	SM2_POINT point;
	uint8_t hash[32];
	uint32_t ciphertext_size;
	uint8_t ciphertext[1];
} SM2_CIPHERTEXT;

#define SM2_MAX_PLAINTEXT	256
#define SM2_MAX_PLAINTEXT_SIZE	256

#define SM2_CIPHERTEXT_SIZE(inlen)  (sizeof(SM2_CIPHERTEXT)-1+inlen)

#define SM2_MAX_CIPHERTEXT_SIZE	512



int sm2_ciphertext_to_der(const SM2_CIPHERTEXT *c, uint8_t **out, size_t *outlen);
int sm2_ciphertext_from_der(SM2_CIPHERTEXT *c, const uint8_t **in, size_t *inlen);
int sm2_ciphertext_print(FILE *fp, const SM2_CIPHERTEXT *c, int format, int indent);
int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out);
int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen);

int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm2_print_ciphertext(FILE *fp, const uint8_t *c, size_t clen, int format, int indent);

int sm2_ecdh(const SM2_KEY *key, const SM2_POINT *peer_public, SM2_POINT *out);


int sm2_algo_selftest(void);


#ifdef __cplusplus
extern "C" {
#endif
#endif
