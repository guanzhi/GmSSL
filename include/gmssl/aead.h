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

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	SM4_CBC_CTX cbc_ctx;
	SM3_HMAC_CTX hmac_ctx;
} SM4_CBC_SM3_HMAC_CTX;

int sm4_cbc_sm3_hmac_encrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE + SM3_HMAC_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen);
int sm4_cbc_sm3_hmac_encrypt_update(SM4_CBC_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_sm3_hmac_encrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen);
int sm4_cbc_sm3_hmac_decrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE + SM3_HMAC_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen);
int sm4_cbc_sm3_hmac_decrypt_update(SM4_CBC_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_sm3_hmac_decrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen);


typedef struct {
	SM4_CTR_CTX ctr_ctx;
	SM3_HMAC_CTX hmac_ctx;
} SM4_CTR_SM3_HMAC_CTX;

int sm4_ctr_sm3_hmac_encrypt_init(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE + SM3_HMAC_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen);
int sm4_ctr_sm3_hmac_encrypt_update(SM4_CTR_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ctr_sm3_hmac_encrypt_finish(SM4_CTR_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen);
int sm4_ctr_sm3_hmac_decrypt_init(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE + SM3_HMAC_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen);
int sm4_ctr_sm3_hmac_decrypt_update(SM4_CTR_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ctr_sm3_hmac_decrypt_finish(SM4_CTR_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen);


typedef struct {
} SM4_GCM_CTX;

int sm4_gcm_encrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE], const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen);
int sm4_gcm_encrypt_update(SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_gcm_encrypt_finish(SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen);
int sm4_gcm_decrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE], const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen);
int sm4_gcm_decrypt_update(SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_gcm_decrypt_finish(SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen);


#define ZUC_KEY_SIZE	16
#define ZUC_IV_SIZE	16
#define ZUC_MAC_KEY_SIZE	16

typedef struct {
} ZUC_WITH_MAC_CTX;

int zuc_encrypt_init(ZUC_CTX *ctx, const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE]);
int zuc_encrypt_update(ZUC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int zuc_encrypt_finish(ZUC_CTX *ctx, uint8_t *out, size_t *outlen);

int zuc_with_mac_encrypt_init(ZUC_WITH_MAC_CTX *ctx,
	const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE],
	const uint8_t *aad, size_t aadlen);
int zuc_with_mac_encrypt_update(ZUC_WITH_MAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int zuc_with_mac_encrypt_finish(ZUC_WITH_MAC_CTX *ctx, uint8_t *out, size_t *outlen);

int zuc_with_mac_decrypt_init(ZUC_WITH_MAC_CTX *ctx,
	const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE],
	const uint8_t *aad, size_t aadlen);
int zuc_with_mac_decrypt_update(ZUC_WITH_MAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int zuc_with_mac_decrypt_finish(ZUC_WITH_MAC_CTX *ctx, uint8_t *out, size_t *outlen);


#ifdef __cplusplus
}
#endif
#endif
