/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_API_H
#define GMSSL_API_H

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


enum {
	GMSSL_SUCCESS = 1,
	GMSSL_ERR_NULL_PARAMETER = -1,
	GMSSL_ERR_TOO_LONG = -2,
	GMSSL_ERR_CTX_NOT_INITIALIZED = -3,
	GMSSL_ERR_NOT_INITIALIZED = -3,
	GMSSL_ERR_LENGTH_IS_ZERO = -4,
	GMSSL_ERR_INTERNAL_ERROR,
	GMSSL_ERR_INVALID_KEY,
	GMSSL_ERR_INVALID_KEY_LENGTH,
	GMSSL_ERR_VERIFY_FAILURE,
};


#ifdef WIN32
#define GMSSL_PUBLIC __declspec(dllexport)

#else
// use -fvisibility=hidden to change the "default" behavior
#define GMSSL_PUBLIC __attribute__((visibility("default")))
#endif

int gmssl_version(int *ver);

int gmssl_rand(uint8_t *buf, size_t len);



#define GMSSL_SM3_DIGEST_SIZE 32

// SM2

typedef struct GMSSL_SM2_KEY GMSSL_SM2_KEY;

GMSSL_PUBLIC GMSSL_SM2_KEY *gmssl_sm2_key_new(void);
GMSSL_PUBLIC void gmssl_sm2_key_free(GMSSL_SM2_KEY *key);
GMSSL_PUBLIC int gmssl_sm2_key_generate(GMSSL_SM2_KEY *key);
GMSSL_PUBLIC int gmssl_sm2_key_set(GMSSL_SM2_KEY *key, const uint8_t private_key[32], const uint8_t *public_key, size_t public_key_len);
GMSSL_PUBLIC int gmssl_sm2_key_get(const GMSSL_SM2_KEY *key, uint8_t private_key[32], uint8_t *public_key, size_t *public_key_len);
GMSSL_PUBLIC int gmssl_sm2_private_key_encrypt_to_file(const GMSSL_SM2_KEY *key, const char *pass, const char *path);
GMSSL_PUBLIC int gmssl_sm2_private_key_decrypt_from_file(GMSSL_SM2_KEY *key, const char *pass, const char *path);
GMSSL_PUBLIC int gmssl_sm2_public_key_to_file(const GMSSL_SM2_KEY *key, const char *path);
GMSSL_PUBLIC int gmssl_sm2_public_key_from_file(GMSSL_SM2_KEY *key, const char *path);
GMSSL_PUBLIC int gmssl_sm2_compute_z(const GMSSL_SM2_KEY *key, const char *id, size_t idlen, uint8_t z[GMSSL_SM3_DIGEST_SIZE]);
GMSSL_PUBLIC int gmssl_sm2_sign_digest(const GMSSL_SM2_KEY *key, const uint8_t dgst[GMSSL_SM3_DIGEST_SIZE], uint8_t *sig, size_t *siglen);
GMSSL_PUBLIC int gmssl_sm2_verify_digest(const GMSSL_SM2_KEY *key, const uint8_t dgst[GMSSL_SM3_DIGEST_SIZE], const uint8_t *sig, size_t siglen);
GMSSL_PUBLIC int gmssl_sm2_encrypt(const GMSSL_SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm2_decrypt(const GMSSL_SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);


typedef struct GMSSL_SM2_SIGN_CTX GMSSL_SM2_SIGN_CTX;

GMSSL_PUBLIC GMSSL_SM2_SIGN_CTX *gmssl_sm2_sign_ctx_new(void);
GMSSL_PUBLIC void gmssl_sm2_sign_ctx_free(GMSSL_SM2_SIGN_CTX *ctx);
GMSSL_PUBLIC int gmssl_sm2_sign_init(GMSSL_SM2_SIGN_CTX *ctx, const GMSSL_SM2_KEY *key, const char *id, size_t idlen);
GMSSL_PUBLIC int gmssl_sm2_sign_update(GMSSL_SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
GMSSL_PUBLIC int gmssl_sm2_sign_finish(GMSSL_SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
GMSSL_PUBLIC int gmssl_sm2_verify_init(GMSSL_SM2_SIGN_CTX *ctx, const GMSSL_SM2_KEY *key, const char *id, size_t idlen);
GMSSL_PUBLIC int gmssl_sm2_verify_update(GMSSL_SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
GMSSL_PUBLIC int gmssl_sm2_verify_finish(GMSSL_SM2_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen);


// SM3


typedef struct GMSSL_SM3_CTX GMSSL_SM3_CTX;

GMSSL_PUBLIC GMSSL_SM3_CTX *gmssl_sm3_ctx_new(void);
GMSSL_PUBLIC void gmssl_sm3_ctx_free(GMSSL_SM3_CTX *ctx);

GMSSL_PUBLIC int gmssl_sm3_init(GMSSL_SM3_CTX *ctx);
GMSSL_PUBLIC int gmssl_sm3_update(GMSSL_SM3_CTX *ctx, const uint8_t *data, size_t datalen);
GMSSL_PUBLIC int gmssl_sm3_finish(GMSSL_SM3_CTX *ctx, uint8_t dgst[GMSSL_SM3_DIGEST_SIZE]);
GMSSL_PUBLIC int gmssl_sm3_digest(const uint8_t *data, size_t datalen, uint8_t dgst[GMSSL_SM3_DIGEST_SIZE]);

typedef struct GMSSL_SM3_HMAC_CTX GMSSL_SM3_HMAC_CTX;

#define GMSSL_SM3_HMAC_SIZE 32

GMSSL_PUBLIC GMSSL_SM3_HMAC_CTX *gmssl_sm3_hmac_ctx_new(void);
GMSSL_PUBLIC void gmssl_sm3_hmac_ctx_free(GMSSL_SM3_HMAC_CTX *ctx);

GMSSL_PUBLIC int gmssl_sm3_hmac_init(GMSSL_SM3_HMAC_CTX *ctx, const uint8_t *key, size_t keylen);
GMSSL_PUBLIC int gmssl_sm3_hmac_update(GMSSL_SM3_HMAC_CTX *ctx, const uint8_t *data, size_t datalen);
GMSSL_PUBLIC int gmssl_sm3_hmac_finish(GMSSL_SM3_HMAC_CTX *ctx, uint8_t mac[GMSSL_SM3_HMAC_SIZE]);

GMSSL_PUBLIC int gmssl_sm3_hmac(const uint8_t *key, size_t keylen,
	const uint8_t *data, size_t datalen,
	uint8_t mac[GMSSL_SM3_HMAC_SIZE]);

#define GMSSL_SM4_KEY_SIZE	16
#define GMSSL_SM4_BLOCK_SIZE	16

// SM4-CBC

typedef struct GMSSL_SM4_CBC_CTX GMSSL_SM4_CBC_CTX;

GMSSL_PUBLIC GMSSL_SM4_CBC_CTX *gmssl_sm4_cbc_ctx_new(void);
GMSSL_PUBLIC void gmssl_sm4_cbc_ctx_free(GMSSL_SM4_CBC_CTX *ctx);
GMSSL_PUBLIC int gmssl_sm4_cbc_encrypt_init(GMSSL_SM4_CBC_CTX *ctx, const uint8_t key[GMSSL_SM4_KEY_SIZE], const uint8_t iv[GMSSL_SM4_BLOCK_SIZE]);
GMSSL_PUBLIC int gmssl_sm4_cbc_encrypt_update(GMSSL_SM4_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_cbc_encrypt_finish(GMSSL_SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_cbc_decrypt_init(GMSSL_SM4_CBC_CTX *ctx, const uint8_t key[GMSSL_SM4_KEY_SIZE], const uint8_t iv[GMSSL_SM4_BLOCK_SIZE]);
GMSSL_PUBLIC int gmssl_sm4_cbc_decrypt_update(GMSSL_SM4_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_cbc_decrypt_finish(GMSSL_SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen);

// SM4-CTR

typedef struct GMSSL_SM4_CTR_CTX GMSSL_SM4_CTR_CTX;

GMSSL_PUBLIC GMSSL_SM4_CTR_CTX *gmssl_sm4_ctr_ctx_new(void);
GMSSL_PUBLIC void gmssl_sm4_ctr_ctx_free(GMSSL_SM4_CTR_CTX *ctx);
GMSSL_PUBLIC int gmssl_sm4_ctr_encrypt_init(GMSSL_SM4_CTR_CTX *ctx, const uint8_t key[GMSSL_SM4_KEY_SIZE], const uint8_t ctr[GMSSL_SM4_BLOCK_SIZE]);
GMSSL_PUBLIC int gmssl_sm4_ctr_encrypt_update(GMSSL_SM4_CTR_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_ctr_encrypt_finish(GMSSL_SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen); // FIXME: change final output behavior?		


// AEAD: decryption will buffer the final mac-tag

// SM4-CBC + HMAC-SM3

typedef struct GMSSL_SM4_CBC_SM3_HMAC_CTX GMSSL_SM4_CBC_SM3_HMAC_CTX;

GMSSL_PUBLIC GMSSL_SM4_CBC_SM3_HMAC_CTX *gmssl_sm4_cbc_sm3_hmac_ctx_new(void);
GMSSL_PUBLIC void gmssl_sm4_cbc_sm3_hmac_ctx_free(GMSSL_SM4_CBC_SM3_HMAC_CTX *ctx);
GMSSL_PUBLIC int gmssl_sm4_cbc_sm3_hmac_encrypt_init(GMSSL_SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t key[GMSSL_SM4_KEY_SIZE + GMSSL_SM3_HMAC_SIZE], const uint8_t iv[GMSSL_SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen);
GMSSL_PUBLIC int gmssl_sm4_cbc_sm3_hmac_encrypt_update(GMSSL_SM4_CBC_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_cbc_sm3_hmac_encrypt_finish(GMSSL_SM4_CBC_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_cbc_sm3_hmac_decrypt_init(GMSSL_SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t key[GMSSL_SM4_KEY_SIZE + GMSSL_SM3_HMAC_SIZE], const uint8_t iv[GMSSL_SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen);
GMSSL_PUBLIC int gmssl_sm4_cbc_sm3_hmac_decrypt_update(GMSSL_SM4_CBC_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_cbc_sm3_hmac_decrypt_finish(GMSSL_SM4_CBC_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen);

// SM4-CTR + SM3-HMAC

typedef struct GMSSL_SM4_CTR_SM3_HMAC_CTX GMSSL_SM4_CTR_SM3_HMAC_CTX;

GMSSL_PUBLIC GMSSL_SM4_CTR_SM3_HMAC_CTX *gmssl_sm4_ctr_sm3_hmac_ctx_new(void);
GMSSL_PUBLIC void gmssl_sm4_ctr_sm3_hmac_ctx_free(GMSSL_SM4_CTR_SM3_HMAC_CTX *ctx);
GMSSL_PUBLIC int gmssl_sm4_ctr_sm3_hmac_encrypt_init(GMSSL_SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t key[GMSSL_SM4_KEY_SIZE + GMSSL_SM3_HMAC_SIZE], const uint8_t iv[GMSSL_SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen);
GMSSL_PUBLIC int gmssl_sm4_ctr_sm3_hmac_encrypt_update(GMSSL_SM4_CTR_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_ctr_sm3_hmac_encrypt_finish(GMSSL_SM4_CTR_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_ctr_sm3_hmac_decrypt_init(GMSSL_SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t key[GMSSL_SM4_KEY_SIZE + GMSSL_SM3_HMAC_SIZE], const uint8_t iv[GMSSL_SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen);
GMSSL_PUBLIC int gmssl_sm4_ctr_sm3_hmac_decrypt_update(GMSSL_SM4_CTR_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_ctr_sm3_hmac_decrypt_finish(GMSSL_SM4_CTR_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen);

// SM4-GCM

typedef struct GMSSL_SM4_GCM_CTX GMSSL_SM4_GCM_CTX;

GMSSL_PUBLIC GMSSL_SM4_GCM_CTX *gmssl_sm4_gcm_ctx_new(void);
GMSSL_PUBLIC void gmssl_sm4_gcm_ctx_free(GMSSL_SM4_GCM_CTX *ctx);
GMSSL_PUBLIC int gmssl_sm4_gcm_encrypt_init(GMSSL_SM4_GCM_CTX *ctx,
	const uint8_t key[GMSSL_SM4_KEY_SIZE], const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen);
GMSSL_PUBLIC int gmssl_sm4_gcm_encrypt_update(GMSSL_SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_gcm_encrypt_finish(GMSSL_SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_gcm_decrypt_init(GMSSL_SM4_GCM_CTX *ctx,
	const uint8_t key[GMSSL_SM4_KEY_SIZE], const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen);
GMSSL_PUBLIC int gmssl_sm4_gcm_decrypt_update(GMSSL_SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_sm4_gcm_decrypt_finish(GMSSL_SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen);


// ZUC

#define GMSSL_ZUC_KEY_SIZE	16
#define GMSSL_ZUC_IV_SIZE	16
#define GMSSL_ZUC_MAC_KEY_SIZE	16

typedef struct GMSSL_ZUC_CTX GMSSL_ZUC_CTX;

GMSSL_PUBLIC GMSSL_ZUC_CTX *gmssl_zuc_ctx_new(void);
GMSSL_PUBLIC void gmssl_zuc_ctx_free(GMSSL_ZUC_CTX *ctx);
GMSSL_PUBLIC int gmssl_zuc_encrypt_init(GMSSL_ZUC_CTX *ctx, const uint8_t key[GMSSL_ZUC_KEY_SIZE], const uint8_t iv[GMSSL_ZUC_IV_SIZE]);
GMSSL_PUBLIC int gmssl_zuc_encrypt_update(GMSSL_ZUC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_zuc_encrypt_finish(GMSSL_ZUC_CTX *ctx, uint8_t *out, size_t *outlen);


typedef struct GMSSL_ZUC_WITH_MAC_CTX GMSSL_ZUC_WITH_MAC_CTX;

GMSSL_PUBLIC GMSSL_ZUC_WITH_MAC_CTX *gmssl_zuc_with_macctx_new(void);
GMSSL_PUBLIC void gmssl_zuc_with_mac_ctx_free(GMSSL_ZUC_WITH_MAC_CTX *ctx);
GMSSL_PUBLIC int gmssl_zuc_with_mac_encrypt_init(GMSSL_ZUC_WITH_MAC_CTX *ctx,
	const uint8_t key[GMSSL_ZUC_KEY_SIZE], const uint8_t iv[GMSSL_ZUC_IV_SIZE],
	const uint8_t *aad, size_t aadlen);
GMSSL_PUBLIC int gmssl_zuc_with_mac_encrypt_update(GMSSL_ZUC_WITH_MAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_zuc_with_mac_encrypt_finish(GMSSL_ZUC_WITH_MAC_CTX *ctx, uint8_t *out, size_t *outlen);

GMSSL_PUBLIC int gmssl_zuc_with_mac_decrypt_init(GMSSL_ZUC_WITH_MAC_CTX *ctx,
	const uint8_t key[GMSSL_ZUC_KEY_SIZE], const uint8_t iv[GMSSL_ZUC_IV_SIZE],
	const uint8_t *aad, size_t aadlen);
GMSSL_PUBLIC int gmssl_zuc_with_mac_decrypt_update(GMSSL_ZUC_WITH_MAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
GMSSL_PUBLIC int gmssl_zuc_with_mac_decrypt_finish(GMSSL_ZUC_WITH_MAC_CTX *ctx, uint8_t *out, size_t *outlen);



#ifdef __cplusplus
}
#endif
#endif
