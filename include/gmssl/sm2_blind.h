/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef GMSSL_SM2_BLIND_H
#define GMSSL_SM2_BLIND_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	SM3_CTX sm3_ctx;
	SM2_KEY public_key;
	uint8_t blind_factor_a[32];
	uint8_t blind_factor_b[32];
	uint8_t sig_r[32];
} SM2_BLIND_SIGN_CTX;


#define SM2_BLIND_SIGN_MAX_COMMITLEN	65

int sm2_blind_sign_commit(SM2_Fn k, uint8_t *commit, size_t *commitlen);
int sm2_blind_sign_init(SM2_BLIND_SIGN_CTX *ctx, const SM2_KEY *public_key, const char *id, size_t idlen);
int sm2_blind_sign_update(SM2_BLIND_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_blind_sign_finish(SM2_BLIND_SIGN_CTX *ctx, const uint8_t *commit, size_t commitlen, uint8_t blinded_sig_r[32]);
int sm2_blind_sign(const SM2_KEY *key, const SM2_Fn k, const uint8_t blinded_sig_r[32], uint8_t blinded_sig_s[32]);
int sm2_blind_sign_unblind(SM2_BLIND_SIGN_CTX *ctx, const uint8_t blinded_sig_s[32], uint8_t *sig, size_t *siglen);


#ifdef __cplusplus
}
#endif
#endif
