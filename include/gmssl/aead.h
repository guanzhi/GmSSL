/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_AEAD_H
#define GMSSL_AEAD_H

#include <string.h>
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/gcm.h>
#include <gmssl/api.h>

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

_gmssl_export int sm4_cbc_sm3_hmac_encrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen);
_gmssl_export int sm4_cbc_sm3_hmac_encrypt_update(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
_gmssl_export int sm4_cbc_sm3_hmac_encrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx,
	uint8_t *out, size_t *outlen);
_gmssl_export int sm4_cbc_sm3_hmac_decrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen);
_gmssl_export int sm4_cbc_sm3_hmac_decrypt_update(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
_gmssl_export int sm4_cbc_sm3_hmac_decrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx,
	uint8_t *out, size_t *outlen);


typedef struct {
	SM4_CTR_CTX enc_ctx;
	SM3_HMAC_CTX mac_ctx;
	uint8_t mac[SM3_HMAC_SIZE];
	size_t maclen;
} SM4_CTR_SM3_HMAC_CTX;

#define SM4_CTR_SM3_HMAC_KEY_SIZE 48
#define SM4_CTR_SM3_HMAC_IV_SIZE  16

_gmssl_export int sm4_ctr_sm3_hmac_encrypt_init(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen);
_gmssl_export int sm4_ctr_sm3_hmac_encrypt_update(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
_gmssl_export int sm4_ctr_sm3_hmac_encrypt_finish(SM4_CTR_SM3_HMAC_CTX *ctx,
	uint8_t *out, size_t *outlen);
_gmssl_export int sm4_ctr_sm3_hmac_decrypt_init(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen);
_gmssl_export int sm4_ctr_sm3_hmac_decrypt_update(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
_gmssl_export int sm4_ctr_sm3_hmac_decrypt_finish(SM4_CTR_SM3_HMAC_CTX *ctx,
	uint8_t *out, size_t *outlen);


typedef struct {
	SM4_CTR_CTX enc_ctx;
	GHASH_CTX mac_ctx;
	uint8_t Y[16]; // E(K, Y_0)
	size_t taglen;
	uint8_t mac[16];
	size_t maclen;
} SM4_GCM_CTX;

#define SM4_GCM_KEY_SIZE 16
#define SM4_GCM_DEFAULT_TAG_SIZE 16

_gmssl_export int sm4_gcm_encrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, size_t taglen);
_gmssl_export int sm4_gcm_encrypt_update(SM4_GCM_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
_gmssl_export int sm4_gcm_encrypt_finish(SM4_GCM_CTX *ctx,
	uint8_t *out, size_t *outlen);
_gmssl_export int sm4_gcm_decrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, size_t taglen);
_gmssl_export int sm4_gcm_decrypt_update(SM4_GCM_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
_gmssl_export int sm4_gcm_decrypt_finish(SM4_GCM_CTX *ctx,
	uint8_t *out, size_t *outlen);


#ifdef __cplusplus
}
#endif
#endif
