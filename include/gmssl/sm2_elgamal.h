/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM2_ELGAMAL_H
#define GMSSL_SM2_ELGAMAL_H


#include <string.h>
#include <stdint.h>
#include <gmssl/sm2.h>


#ifdef __cplusplus
extern "C" {
#endif


#define SM2_PRE_COMPUTE_MAX_OFFSETS	6

typedef struct {
	uint16_t offset[SM2_PRE_COMPUTE_MAX_OFFSETS];
	uint8_t offset_count;
	uint8_t x_coordinate[32];
} SM2_PRE_COMPUTE;

int sm2_elgamal_decrypt_pre_compute(SM2_PRE_COMPUTE table[1<<16]);
int sm2_elgamal_solve_ecdlp(const SM2_PRE_COMPUTE table[1<<16], const SM2_POINT *point, uint32_t *private);


typedef struct {
	SM2_POINT C1;
	SM2_POINT C2;
} SM2_ELGAMAL_CIPHERTEXT;

int sm2_elgamal_do_encrypt(const SM2_KEY *pub_key, uint32_t in, SM2_ELGAMAL_CIPHERTEXT *out);
int sm2_elgamal_do_decrypt(const SM2_KEY *key, const SM2_ELGAMAL_CIPHERTEXT *in, uint32_t *out);

int sm2_elgamal_ciphertext_add(SM2_ELGAMAL_CIPHERTEXT *r,
	const SM2_ELGAMAL_CIPHERTEXT *a,
	const SM2_ELGAMAL_CIPHERTEXT *b,
	const SM2_KEY *pub_key);
int sm2_elgamal_cipehrtext_sub(SM2_ELGAMAL_CIPHERTEXT *r,
	const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_ELGAMAL_CIPHERTEXT *b,
	const SM2_KEY *pub_key);
int sm2_elgamal_cipehrtext_neg(SM2_ELGAMAL_CIPHERTEXT *r,
	const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_KEY *pub_key);
int sm2_elgamal_ciphertext_scalar_mul(SM2_ELGAMAL_CIPHERTEXT *R,
	const uint8_t scalar[32], const SM2_ELGAMAL_CIPHERTEXT *A,
	const SM2_KEY *pub_key);

int sm2_elgamal_ciphertext_to_der(const SM2_ELGAMAL_CIPHERTEXT *c, uint8_t **out, size_t *outlen);
int sm2_elgamal_ciphertext_from_der(SM2_ELGAMAL_CIPHERTEXT *c, const uint8_t **in, size_t *inlen);

int sm2_elgamal_encrypt(const SM2_KEY *pub_key, uint32_t in, uint8_t *out, size_t *outlen);
int sm2_elgamal_decrypt(SM2_KEY *key, const uint8_t *in, size_t inlen, uint32_t *out);


#ifdef __cplusplus
}
#endif
#endif
