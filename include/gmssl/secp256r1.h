/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_SECP256R1_H
#define GMSSL_SECP256R1_H


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/digest.h>


#ifdef __cplusplus
extern "C" {
#endif


// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//   = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
// a = -3
// b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
// x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
// y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
// h = 1


typedef uint32_t secp256r1_t[8];

#define SECP256R1_K (sizeof(secp256r1_t)/sizeof(uint32_t))

extern const secp256r1_t SECP256R1_P;
extern const secp256r1_t SECP256R1_B;
extern const secp256r1_t SECP256R1_N;
extern const uint32_t SECP256R1_U_P[9];
extern const uint32_t SECP256R1_U_N[9];

int  secp256r1_is_zero(const secp256r1_t a);
int  secp256r1_is_one(const secp256r1_t a);
int  secp256r1_cmp(const secp256r1_t a, const secp256r1_t b);
int  secp256r1_set_zero(secp256r1_t r);
int  secp256r1_set_one(secp256r1_t r);
int  secp256r1_copy(secp256r1_t r, const secp256r1_t a);
int  secp256r1_to_32bytes(const secp256r1_t a, uint8_t out[32]);
int  secp256r1_from_32bytes(secp256r1_t r, const uint8_t in[32]);
int  secp256r1_print(FILE *fp, int fmt, int ind, const char *label, const secp256r1_t a);

int  secp256r1_modp_add(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
int  secp256r1_modp_dbl(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modp_tri(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modp_sub(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
int  secp256r1_modp_neg(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modp_haf(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modp_mul(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
int  secp256r1_modp_sqr(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modp_exp(secp256r1_t r, const secp256r1_t a, const secp256r1_t e);
int  secp256r1_modp_inv(secp256r1_t r, const secp256r1_t a);

int  secp256r1_modn(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modn_add(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
int  secp256r1_modn_dbl(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modn_tri(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modn_sub(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
int  secp256r1_modn_neg(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modn_mul(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
int  secp256r1_modn_sqr(secp256r1_t r, const secp256r1_t a);
int  secp256r1_modn_exp(secp256r1_t r, const secp256r1_t a, const secp256r1_t e);
int  secp256r1_modn_inv(secp256r1_t r, const secp256r1_t a);


typedef struct {
	secp256r1_t X;
	secp256r1_t Y;
	secp256r1_t Z;
} SECP256R1_POINT;

const SECP256R1_POINT *secp256r1_generator(void);
#define SECP256R1_POINT_G (*secp256r1_generator())

int  secp256r1_point_set_infinity(SECP256R1_POINT *R);
int  secp256r1_point_is_at_infinity(const SECP256R1_POINT *P);
int  secp256r1_point_is_on_curve(const SECP256R1_POINT *P);
int  secp256r1_point_equ(const SECP256R1_POINT *P, const SECP256R1_POINT *Q);
int  secp256r1_point_set_xy(SECP256R1_POINT *R, const secp256r1_t x, const secp256r1_t y);
int  secp256r1_point_get_xy(const SECP256R1_POINT *P, secp256r1_t x, secp256r1_t y);
int  secp256r1_point_copy(SECP256R1_POINT *R, const SECP256R1_POINT *P);
int  secp256r1_point_dbl(SECP256R1_POINT *R, const SECP256R1_POINT *P);
int  secp256r1_point_add(SECP256R1_POINT *R, const SECP256R1_POINT *P, const SECP256R1_POINT *Q);
int  secp256r1_point_neg(SECP256R1_POINT *R, const SECP256R1_POINT *P);
int  secp256r1_point_sub(SECP256R1_POINT *R, const SECP256R1_POINT *P, const SECP256R1_POINT *Q);
int  secp256r1_point_mul(SECP256R1_POINT *R, const secp256r1_t k, const SECP256R1_POINT *P);
int  secp256r1_point_mul_generator(SECP256R1_POINT *R, const secp256r1_t k);
int  secp256r1_point_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_POINT *P);
int  secp256r1_point_to_uncompressed_octets(const SECP256R1_POINT *P, uint8_t octets[65]);
int  secp256r1_point_from_uncompressed_octets(SECP256R1_POINT *P, const uint8_t octets[65]);


typedef struct {
	SECP256R1_POINT public_key;
	secp256r1_t private_key;
} SECP256R1_KEY;

int secp256r1_key_generate(SECP256R1_KEY *key);
int secp256r1_key_set_private_key(SECP256R1_KEY *key, const secp256r1_t private_key);
int secp256r1_public_key_equ(const SECP256R1_KEY *key, const SECP256R1_KEY *pub);

int secp256r1_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key);
int secp256r1_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key);

int secp256r1_public_key_to_bytes(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_public_key_from_bytes(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_private_key_to_bytes(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_private_key_from_bytes(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_public_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_public_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_private_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_private_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_private_key_info_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_private_key_info_from_der(SECP256R1_KEY *key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen);
int secp256r1_private_key_info_encrypt_to_der(const SECP256R1_KEY *ec_key, const char *pass,
	uint8_t **out, size_t *outlen);
int secp256r1_private_key_info_decrypt_from_der(SECP256R1_KEY *ec_key,
	const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen);

int secp256r1_private_key_to_pem(const SECP256R1_KEY *key, FILE *fp);
int secp256r1_private_key_from_pem(SECP256R1_KEY *key, FILE *fp);
int secp256r1_private_key_info_encrypt_to_pem(const SECP256R1_KEY *key, const char *pass, FILE *fp);
int secp256r1_private_key_info_decrypt_from_pem(SECP256R1_KEY *key, const char *pass, FILE *fp);

int secp256r1_do_ecdh(const SECP256R1_KEY *key, const SECP256R1_KEY *pub, uint8_t out[32]);
int secp256r1_ecdh(const SECP256R1_KEY *key, const uint8_t uncompressed_point[65], uint8_t out[32]);


typedef struct {
	secp256r1_t r;
	secp256r1_t s;
} SECP256R1_ECDSA_SIGNATURE;

#define SECP256R1_ECDSA_SIGNATURE_COMPACT_SIZE	70
#define SECP256R1_ECDSA_SIGNATURE_TYPICAL_SIZE	71
#define SECP256R1_ECDSA_SIGNATURE_MAX_SIZE	72

int secp256r1_ecdsa_signature_to_der(const SECP256R1_ECDSA_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int secp256r1_ecdsa_signature_from_der(SECP256R1_ECDSA_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int secp256r1_ecdsa_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_ECDSA_SIGNATURE *sig);
int secp256r1_ecdsa_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

int secp256r1_ecdsa_do_sign_ex(const SECP256R1_KEY *key, const secp256r1_t k,
	const uint8_t *dgst, size_t dgstlen, SECP256R1_ECDSA_SIGNATURE *sig);
int secp256r1_ecdsa_do_sign(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, SECP256R1_ECDSA_SIGNATURE *sig);
int secp256r1_ecdsa_do_verify(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, const SECP256R1_ECDSA_SIGNATURE *sig);

int secp256r1_ecdsa_sign(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, uint8_t *sig, size_t *siglen);
int secp256r1_ecdsa_sign_fixlen(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, size_t siglen, uint8_t *sig);
int secp256r1_ecdsa_verify(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, const uint8_t *sig, size_t siglen);

typedef struct {
	DIGEST_CTX digest_ctx;
	SECP256R1_KEY key;
	SECP256R1_ECDSA_SIGNATURE sig;
} SECP256R1_ECDSA_SIGN_CTX;

int secp256r1_ecdsa_sign_init(SECP256R1_ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const DIGEST *digest);
int secp256r1_ecdsa_sign_update(SECP256R1_ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int secp256r1_ecdsa_sign_finish(SECP256R1_ECDSA_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int secp256r1_ecdsa_sign_finish_fixlen(SECP256R1_ECDSA_SIGN_CTX *ctx, size_t siglen, uint8_t *sig);
int secp256r1_ecdsa_verify_init(SECP256R1_ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const DIGEST *digest,
	const uint8_t *sig, size_t siglen);
int secp256r1_ecdsa_verify_update(SECP256R1_ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int secp256r1_ecdsa_verify_finish(SECP256R1_ECDSA_SIGN_CTX *ctx);


#ifdef __cplusplus
}
#endif
#endif
