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

#ifndef GMSSL_SM4_H
#define GMSSL_SM4_H


#include <sys/types.h>
#include <stdint.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif


#define SM4_KEY_SIZE		(16)
#define SM4_BLOCK_SIZE		(16)
#define SM4_NUM_ROUNDS		(32)

// TODO: 增加一个flag标注用于加密还是解密，使用时用assert检查这个flag
typedef struct {
	uint32_t rk[SM4_NUM_ROUNDS];
} SM4_KEY;


void sm4_set_encrypt_key(SM4_KEY *sm4_key, const uint8_t key[16]);
void sm4_set_decrypt_key(SM4_KEY *sm4_key, const uint8_t key[16]);
void sm4_encrypt(const SM4_KEY *sm4_key, const uint8_t in[16], uint8_t out[16]);


void sm4_cbc_encrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out);

void sm4_cbc_decrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out);

int sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[16],
	const uint8_t *in, size_t inlen, uint8_t *out);

int sm4_gcm_encrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, const size_t taglen, uint8_t *tag);

int sm4_gcm_decrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
