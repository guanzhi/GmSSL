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


typedef uint32_t sm2_elgamal_plaintext_t;

typedef struct {
	SM2_POINT C1;
	SM2_POINT C2;
} SM2_ELGAMAL_CIPHERTEXT;


int sm2_elgamal_encrypt(const SM2_KEY *pub_key, sm2_elgamal_plaintext_t in, SM2_ELGAMAL_CIPHERTEXT *out);
int sm2_elgamal_decrypt(const SM2_KEY *key, const SM2_ELGAMAL_CIPHERTEXT *in, sm2_elgamal_plaintext_t *out);
int sm2_elgamal_ciphertext_add(SM2_ELGAMAL_CIPHERTEXT *r, const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_ELGAMAL_CIPHERTEXT *b, const SM2_KEY *pub_key);
int sm2_elgamal_cipehrtext_sub(SM2_ELGAMAL_CIPHERTEXT *r, const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_ELGAMAL_CIPHERTEXT *b, const SM2_KEY *pub_key);
int sm2_elgamal_cipehrtext_neg(SM2_ELGAMAL_CIPHERTEXT *r, const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_KEY *pub_key);
int sm2_elgamal_ciphertext_scalar_mul(SM2_ELGAMAL_CIPHERTEXT *r, uint32_t scalar, const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_KEY *pub_key);
int sm2_elgamal_ciphertext_to_der(const SM2_ELGAMAL_CIPHERTEXT *c, uint8_t **out, size_t *outlen);
int sm2_elgamal_ciphertext_from_der(SM2_ELGAMAL_CIPHERTEXT *c, const uint8_t **in, size_t *inlen);


#ifdef __cplusplus
}
#endif
#endif
