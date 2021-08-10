/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */


#ifndef GMSSL_AES_H
#define GMSSL_AES_H

#include <stdint.h>
#include <stdlib.h>

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


#ifdef  __cplusplus
extern "C" {
#endif


typedef struct {
	uint32_t rk[4 * (AES_MAX_ROUNDS + 1)];
	size_t rounds;
} AES_KEY;

int aes_set_encrypt_key(AES_KEY *aes_key, const uint8_t *key, size_t keylen);
int aes_set_decrypt_key(AES_KEY *aes_key, const uint8_t *key, size_t keylen);
void aes_encrypt(const AES_KEY *aes_key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

void aes_decrypt(const AES_KEY *aes_key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

void aes_cbc_encrypt(const AES_KEY *key, const uint8_t iv[16], const uint8_t *in, size_t nblocks, uint8_t *out);
void aes_cbc_decrypt(const AES_KEY *key, const uint8_t iv[16], const uint8_t *in, size_t nblocks, uint8_t *out);

int aes_cbc_padding_encrypt(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int aes_cbc_padding_decrypt(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

void aes_ctr_encrypt(const AES_KEY *key, uint8_t ctr[16],
	const uint8_t *in, size_t inlen, uint8_t *out);

int aes_gcm_encrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, const size_t taglen, uint8_t *tag);

int aes_gcm_decrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);


#ifdef  __cplusplus
}
#endif
#endif
