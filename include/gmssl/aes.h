/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_AES_H
#define GMSSL_AES_H

#include <stdint.h>
#include <stdlib.h>

#ifdef  __cplusplus
extern "C" {
#endif


#define AES128_KEY_BITS		128
#define AES192_KEY_BITS		192
#define AES256_KEY_BITS		256

#define AES128_KEY_SIZE		(AES128_KEY_BITS/8)
#define AES192_KEY_SIZE		(AES192_KEY_BITS/8)
#define AES256_KEY_SIZE		(AES256_KEY_BITS/8)

#define AES_BLOCK_SIZE		16

#define AES128_ROUNDS		10
#define AES192_ROUNDS		12
#define AES256_ROUNDS		14
#define AES_MAX_ROUNDS		AES256_ROUNDS


typedef struct {
	uint32_t rk[4 * (AES_MAX_ROUNDS + 1)];
	size_t rounds;
} AES_KEY;

int aes_set_encrypt_key(AES_KEY *key, const uint8_t *raw_key, size_t raw_key_len);
int aes_set_decrypt_key(AES_KEY *key, const uint8_t *raw_key, size_t raw_key_len);
void aes_encrypt(const AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);
void aes_decrypt(const AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);


void aes_cbc_encrypt(const AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
void aes_cbc_decrypt(const AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
int aes_cbc_padding_encrypt(const AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);
int aes_cbc_padding_decrypt(const AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

void aes_ctr_encrypt(const AES_KEY *key, uint8_t ctr[AES_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out);
#define aes_ctr_decrypt(key,ctr,in,inlen,out) aes_ctr_encrypt(key,ctr,in,inlen,out)


#define AES_GCM_IV_MIN_SIZE		1
#define AES_GCM_IV_MAX_SIZE		((uint64_t)(1 << (64-3)))
#define AES_GCM_IV_DEFAULT_BITS		96
#define AES_GCM_IV_DEFAULT_SIZE		12

#define AES_GCM_MIN_AAD_SIZE		0
#define AES_GCM_MAX_AAD_SIZE		((uint64_t)(1 << (64-3)))

#define AES_GCM_MIN_PLAINTEXT_SIZE	0
#define AES_GCM_MAX_PLAINTEXT_SIZE	((((uint64_t)1 << 39) - 256) >> 3)

#define AES_GCM_MAX_TAG_SIZE		16

int aes_gcm_encrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag);
int aes_gcm_decrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);


#ifdef  __cplusplus
}
#endif
#endif
