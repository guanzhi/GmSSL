/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SM4_H
#define GMSSL_SM4_H

#include <stdint.h>
#include <string.h>
#include <gmssl/ghash.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SM4_KEY_SIZE		(16)
#define SM4_BLOCK_SIZE		(16)
#define SM4_NUM_ROUNDS		(32)


typedef struct {
	uint32_t rk[SM4_NUM_ROUNDS];
} SM4_KEY;

void sm4_set_encrypt_key(SM4_KEY *key, const uint8_t raw_key[SM4_KEY_SIZE]);
void sm4_set_decrypt_key(SM4_KEY *key, const uint8_t raw_key[SM4_KEY_SIZE]);
void sm4_encrypt(const SM4_KEY *key, const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE]);

void sm4_encrypt_blocks(const SM4_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_cbc_encrypt_blocks(const SM4_KEY *key, uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_cbc_decrypt_blocks(const SM4_KEY *key, uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_ctr_encrypt_blocks(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_ctr32_encrypt_blocks(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t nblocks, uint8_t *out);

int  sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int  sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out);
void sm4_ctr32_encrypt(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out);


typedef struct {
	SM4_KEY sm4_key;
	uint8_t iv[SM4_BLOCK_SIZE];
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
} SM4_CBC_CTX;

int sm4_cbc_encrypt_init(SM4_CBC_CTX *ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE]);
int sm4_cbc_encrypt_update(SM4_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_encrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen);
int sm4_cbc_decrypt_init(SM4_CBC_CTX *ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE]);
int sm4_cbc_decrypt_update(SM4_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_decrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen);


void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out);
void sm4_ctr32_encrypt(const SM4_KEY *key, uint8_t ctr[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out);

typedef struct {
	SM4_KEY sm4_key;
	uint8_t ctr[SM4_BLOCK_SIZE];
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
} SM4_CTR_CTX;

int sm4_ctr_encrypt_init(SM4_CTR_CTX *ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t ctr[SM4_BLOCK_SIZE]);
int sm4_ctr_encrypt_update(SM4_CTR_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ctr_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen);
int sm4_ctr32_encrypt_init(SM4_CTR_CTX *ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t ctr[SM4_BLOCK_SIZE]);
int sm4_ctr32_encrypt_update(SM4_CTR_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ctr32_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen);


#define NIST_SP800_GCM_MAX_IV_SIZE	(((uint64_t)1 << (64-3)) - 1) // 2305843009213693951
#define SM4_GCM_MAX_IV_SIZE		64
#define SM4_GCM_MIN_IV_SIZE		1
#define SM4_GCM_DEFAULT_IV_SIZE		12

#define NIST_SP800_GCM_MAX_AAD_SIZE	(((uint64_t)1 << (64-3)) - 1) // 2305843009213693951
#define SM4_GCM_MIN_AAD_SIZE		0
#define SM4_GCM_MAX_AAD_SIZE		(1<<24) // 16MiB

#define SM4_GCM_MIN_PLAINTEXT_SIZE	0
#define SM4_GCM_MAX_PLAINTEXT_NBLOCKS	(((uint64_t)1 << 32) - 2)
#define SM4_GCM_MAX_PLAINTEXT_SIZE	(SM4_GCM_MAX_PLAINTEXT_NBLOCKS * 16) // 68719476704

#define SM4_GCM_MAX_TAG_SIZE		16
#define SM4_GCM_MIN_TAG_SIZE		12
#define SM4_GCM_DEFAULT_TAG_SIZE	16
// For certain applications (voice or video), tag may be 64 or 32 bits
// see NIST Special Publication 800-38D, Appendix C for more details

int sm4_gcm_encrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag);
int sm4_gcm_decrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);


typedef struct {
	SM4_CTR_CTX enc_ctx;
	GHASH_CTX mac_ctx;
	uint8_t Y[16]; // E(K, Y_0)
	size_t taglen;
	uint8_t mac[16];
	size_t maclen;
	uint64_t encedlen;
} SM4_GCM_CTX;

int sm4_gcm_encrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, size_t taglen);
int sm4_gcm_encrypt_update(SM4_GCM_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_gcm_encrypt_finish(SM4_GCM_CTX *ctx,
	uint8_t *out, size_t *outlen);
int sm4_gcm_decrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, size_t taglen);
int sm4_gcm_decrypt_update(SM4_GCM_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_gcm_decrypt_finish(SM4_GCM_CTX *ctx,
	uint8_t *out, size_t *outlen);


#ifdef ENABLE_SM4_ECB
// call `sm4_set_decrypt_key` before decrypt

typedef struct {
	SM4_KEY sm4_key;
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
} SM4_ECB_CTX;

int sm4_ecb_encrypt_init(SM4_ECB_CTX *ctx, const uint8_t key[SM4_BLOCK_SIZE]);
int sm4_ecb_encrypt_update(SM4_ECB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ecb_encrypt_finish(SM4_ECB_CTX *ctx, uint8_t *out, size_t *outlen);

int sm4_ecb_decrypt_init(SM4_ECB_CTX *ctx, const uint8_t key[SM4_BLOCK_SIZE]);
int sm4_ecb_decrypt_update(SM4_ECB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ecb_decrypt_finish(SM4_ECB_CTX *ctx, uint8_t *out, size_t *outlen);
#endif // ENABLE_SM4_ECB


#ifdef ENABLE_SM4_OFB
// always call `sm4_set_encrypt_key` before encrypt/decrypt
// `sm4_ofb_encrypt` will change the param `iv`
void sm4_ofb_encrypt(const SM4_KEY *key, uint8_t iv[16], const uint8_t *in, size_t inlen, uint8_t *out);

typedef struct {
	SM4_KEY sm4_key;
	uint8_t iv[SM4_BLOCK_SIZE];
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
} SM4_OFB_CTX;

int sm4_ofb_encrypt_init(SM4_OFB_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE]);
int sm4_ofb_encrypt_update(SM4_OFB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ofb_encrypt_finish(SM4_OFB_CTX *ctx, uint8_t *out, size_t *outlen);
#endif // ENABLE_SM4_OFB


#ifdef ENABLE_SM4_CFB
#define SM4_CFB_MIN_SBYTES 	1
#define SM4_CFB_MAX_SBYTES	16

// pre-defined values for `sbytes`
#define SM4_CFB_8		1
#define SM4_CFB_64		8
#define SM4_CFB_128		16

// always call `sm4_set_encrypt_key` before encrypt/decrypt
// `sm4_cfb_encrypt/decrypt` will change the param `iv`
void sm4_cfb_encrypt(const SM4_KEY *key, size_t sbytes, uint8_t iv[16],
	const uint8_t *in, size_t inlen, uint8_t *out);
void sm4_cfb_decrypt(const SM4_KEY *key, size_t sbytes, uint8_t iv[16],
	const uint8_t *in, size_t inlen, uint8_t *out);

typedef struct {
	SM4_KEY sm4_key;
	uint8_t iv[SM4_BLOCK_SIZE];
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
	size_t sbytes;
} SM4_CFB_CTX;

int sm4_cfb_encrypt_init(SM4_CFB_CTX *ctx, size_t sbytes,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE]);
int sm4_cfb_encrypt_update(SM4_CFB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cfb_encrypt_finish(SM4_CFB_CTX *ctx, uint8_t *out, size_t *outlen);

int sm4_cfb_decrypt_init(SM4_CFB_CTX *ctx, size_t sbytes,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE]);
int sm4_cfb_decrypt_update(SM4_CFB_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cfb_decrypt_finish(SM4_CFB_CTX *ctx, uint8_t *out, size_t *outlen);
#endif // ENABLE_SM4_CFB


#ifdef ENABLE_SM4_CCM
#define SM4_CCM_MIN_IV_SIZE 7
#define SM4_CCM_MAX_IV_SIZE 13
#define SM4_CCM_MIN_TAG_SIZE 4
#define SM4_CCM_MAX_TAG_SIZE 16
#define SM4_CCM_DEFAULT_TAG_SIZE 16

// make sure inlen < 2^((15 - ivlen) * 8)
int sm4_ccm_encrypt(const SM4_KEY *sm4_key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag);
int sm4_ccm_decrypt(const SM4_KEY *sm4_key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);
#endif // ENABLE_SM4_CCM


#ifdef ENABLE_SM4_XTS
// call `sm4_set_encrypt_key` to set both `key1` and `key2`
int sm4_xts_encrypt(const SM4_KEY *key1, const SM4_KEY *key2, const uint8_t tweak[16],
	const uint8_t *in, size_t inlen, uint8_t *out);
// call `sm4_set_decrypt_key(key1)` and `sm4_set_encrypt_key(key2)`
int sm4_xts_decrypt(const SM4_KEY *key1, const SM4_KEY *key2, const uint8_t tweak[16],
	const uint8_t *in, size_t inlen, uint8_t *out);

typedef struct {
	SM4_KEY key1;
	SM4_KEY key2;
	uint8_t tweak[16];
	size_t data_unit_size;
	uint8_t *block;
	size_t block_nbytes;
} SM4_XTS_CTX;

int sm4_xts_encrypt_init(SM4_XTS_CTX *ctx, const uint8_t key[32], const uint8_t iv[16], size_t data_unit_size);
int sm4_xts_encrypt_update(SM4_XTS_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_xts_encrypt_finish(SM4_XTS_CTX *ctx, uint8_t *out, size_t *outlen);
int sm4_xts_decrypt_init(SM4_XTS_CTX *ctx, const uint8_t key[32], const uint8_t iv[16], size_t data_unit_size);
int sm4_xts_decrypt_update(SM4_XTS_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_xts_decrypt_finish(SM4_XTS_CTX *ctx, uint8_t *out, size_t *outlen);
#endif // ENABLE_SM4_XTS


#ifdef __cplusplus
}
#endif
#endif
