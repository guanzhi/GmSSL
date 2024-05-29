/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM4_CBC_SM3_HMAC_H
#define GMSSL_SM4_CBC_SM3_HMAC_H

#include <string.h>
#include <stdint.h>
#include <gmssl/sm4.h>
#include <gmssl/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	SM4_CBC_CTX enc_ctx;
	SM3_HMAC_CTX mac_ctx;
	uint8_t mac[SM3_HMAC_SIZE];
	size_t maclen;
} SM4_CBC_SM3_HMAC_CTX;

#define SM4_CBC_SM3_HMAC_KEY_SIZE 48
#define SM4_CBC_SM3_HMAC_IV_SIZE  16

int sm4_cbc_sm3_hmac_encrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t key[48], const uint8_t iv[16],
	const uint8_t *aad, size_t aadlen);
int sm4_cbc_sm3_hmac_encrypt_update(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_sm3_hmac_encrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx,
	uint8_t *out, size_t *outlen);
int sm4_cbc_sm3_hmac_decrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t key[48], const uint8_t iv[16],
	const uint8_t *aad, size_t aadlen);
int sm4_cbc_sm3_hmac_decrypt_update(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_sm3_hmac_decrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx,
	uint8_t *out, size_t *outlen);


#ifdef __cplusplus
}
#endif
#endif
