/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_SM2_RING_H
#define GMSSL_SM2_RING_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm2.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef uint8_t sm2_bn_t[32];

int sm2_ring_do_sign(const SM2_KEY *sign_key, const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], uint8_t r[32], sm2_bn_t *s);
int sm2_ring_do_verify(const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], const uint8_t r[32], const sm2_bn_t *s);
int sm2_ring_signature_to_der(const sm2_bn_t r, const sm2_bn_t *s, size_t s_cnt, uint8_t **out, size_t *outlen);
int sm2_ring_signature_from_der(sm2_bn_t r, sm2_bn_t *s, size_t *s_cnt, const uint8_t **in, size_t *inlen);
int sm2_ring_sign(const SM2_KEY *sign_key, const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int sm2_ring_verify(const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], const uint8_t *sig, size_t siglen);


#define SM2_RING_SIGN_MAX_SIGNERS  32
typedef struct {
	int state;
	SM3_CTX sm3_ctx;
	SM2_KEY sign_key;
	SM2_POINT public_keys[SM2_RING_SIGN_MAX_SIGNERS];
	size_t public_keys_count;
	char *id;
	size_t idlen;
} SM2_RING_SIGN_CTX;

int sm2_ring_sign_init(SM2_RING_SIGN_CTX *ctx, const SM2_KEY *sign_key, const char *id, size_t idlen);
int sm2_ring_sign_add_signer(SM2_RING_SIGN_CTX *ctx, const SM2_KEY *public_key);
int sm2_ring_sign_update(SM2_RING_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_ring_sign_finish(SM2_RING_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sm2_ring_verify_init(SM2_RING_SIGN_CTX *ctx, const char *id, size_t idlen);
int sm2_ring_verify_add_signer(SM2_RING_SIGN_CTX *ctx, const SM2_KEY *public_key);
int sm2_ring_verify_update(SM2_RING_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_ring_verify_finish(SM2_RING_SIGN_CTX *ctx, uint8_t *sig, size_t siglen);


#ifdef __cplusplus
}
#endif
#endif
