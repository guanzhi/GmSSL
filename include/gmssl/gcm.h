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

#ifndef GMSSL_GCM_H
#define GMSSL_GCM_H


#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/gf128.h>
#include <gmssl/block_cipher.h>


#ifdef __cplusplus
extern "C" {
#endif



#define GCM_IV_MIN_SIZE		1
#define GCM_IV_MAX_SIZE		((uint64_t)(1 << (64-3)))
#define GCM_IV_DEFAULT_BITS	96
#define GCM_IV_DEFAULT_SIZE	12

#define GCM_MIN_AAD_SIZE	0
#define GCM_MAX_AAD_SIZE	((uint64_t)(1 << (64-3)))

#define GCM_MIN_PLAINTEXT_SIZE	0
#define GCM_MAX_PLAINTEXT_SIZE	((((uint64_t)1 << 39) - 256) >> 3)


#define GHASH_SIZE		(16)


#define GCM_IS_LITTLE_ENDIAN 1


void ghash(const uint8_t h[16], const uint8_t *aad, size_t aadlen,
	const uint8_t *c, size_t clen, uint8_t out[16]);


int gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag);

int gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);




#ifdef __cplusplus
}
#endif
#endif
