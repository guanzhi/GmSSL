/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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

#ifdef __cplusplus
extern "C" {
#endif


/*
SM4 Public API

	SM4_KEY_SIZE
	SM4_BLOCK_SIZE

	SM4_CBC_CTX
	sm4_cbc_encrypt_init
	sm4_cbc_encrypt_update
	sm4_cbc_encrypt_finish
	sm4_cbc_decrypt_init
	sm4_cbc_decrypt_update
	sm4_cbc_decrypt_finish

	SM4_CTR_CTX
	sm4_ctr_encrypt_init
	sm4_ctr_encrypt_update
	sm4_ctr_encrypt_finish
	sm4_ctr_decrypt_init
	sm4_ctr_decrypt_update
	sm4_ctr_decrypt_finish
*/

#define SM4_KEY_SIZE		(16)
#define SM4_BLOCK_SIZE		(16)
#define SM4_NUM_ROUNDS		(32)


typedef struct {
	uint32_t rk[SM4_NUM_ROUNDS];
} SM4_KEY;

void sm4_set_encrypt_key(SM4_KEY *key, const uint8_t raw_key[SM4_KEY_SIZE]);
void sm4_set_decrypt_key(SM4_KEY *key, const uint8_t raw_key[SM4_KEY_SIZE]);
void sm4_encrypt(const SM4_KEY *key, const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE]);
#define sm4_decrypt(key,in,out) sm4_encrypt(key,in,out)


void sm4_cbc_encrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_cbc_decrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
int sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);


void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out);
#define sm4_ctr_decrypt(key,ctr,in,inlen,out) sm4_ctr_encrypt(key,ctr,in,inlen,out)


#define SM4_GCM_IV_MIN_SIZE		1
#define SM4_GCM_IV_MAX_SIZE		(((uint64_t)1 << (64-3)) - 1) // 2305843009213693951

#define SM4_GCM_IV_DEFAULT_BITS		96
#define SM4_GCM_IV_DEFAULT_SIZE		12

//#define NIST_SP800_GCM_MAX_IV_SIZE	(((uint64_t)1 << (64-3)) - 1) // 2305843009213693951

#define SM4_GCM_MAX_IV_SIZE		64
#define SM4_GCM_MIN_IV_SIZE		1
#define SM4_GCM_DEFAULT_IV_SIZE		12

#define SM4_GCM_MIN_AAD_SIZE		0
#define SM4_GCM_MAX_AAD_SIZE		(((uint64_t)1 << (64-3)) - 1) // 2305843009213693951

#define SM4_GCM_MIN_PLAINTEXT_SIZE	0
#define SM4_GCM_MAX_PLAINTEXT_SIZE	((((uint64_t)1 << 39) - 256) >> 3) // 68719476704

#define SM4_GCM_MAX_TAG_SIZE		16
#define SM4_GCM_MIN_TAG_SIZE		12
// For certain applications (voice or video), tag may be 64 or 32 bits
// see NIST Special Publication 800-38D, Appendix C for more details


int sm4_gcm_encrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag);
int sm4_gcm_decrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);


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


typedef struct {
	SM4_KEY sm4_key;
	uint8_t ctr[SM4_BLOCK_SIZE];
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
} SM4_CTR_CTX;

int sm4_ctr_encrypt_init(SM4_CTR_CTX *ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t ctr[SM4_BLOCK_SIZE]);
int sm4_ctr_encrypt_update(SM4_CTR_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ctr_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen);

#define sm4_ctr_decrypt_init(ctx,key,ctr) sm4_ctr_encrypt_init(ctx,key,ctr)
#define sm4_ctr_decrypt_update(ctx,in,inlen,out,outlen) sm4_ctr_encrypt_update(ctx,in,inlen,out,outlen)
#define sm4_ctr_decrypt_finish(ctx,out,outlen) sm4_ctr_encrypt_finish(ctx,out,outlen)


#ifdef __cplusplus
}
#endif
#endif
