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



#ifndef GMSSL_BLOCK_CIPHER_H
#define GMSSL_BLOCK_CIPHER_H


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/aes.h>
#include <gmssl/sm4.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct BLOCK_CIPHER BLOCK_CIPHER;
typedef struct BLOCK_CIPHER_KEY BLOCK_CIPHER_KEY;

struct BLOCK_CIPHER_KEY {
	union {
		SM4_KEY sm4_key;
		AES_KEY aes_key;
	} u;
	const BLOCK_CIPHER *cipher;
};

typedef void (*block_cipher_set_encrypt_key_func)(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key);
typedef void (*block_cipher_set_decrypt_key_func)(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key);
typedef void (*block_cipher_encrypt_func)(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);
typedef void (*block_cipher_decrypt_func)(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);

struct BLOCK_CIPHER {
	size_t key_size;
	size_t block_size;
	block_cipher_set_encrypt_key_func set_encrypt_key;
	block_cipher_set_decrypt_key_func set_decrypt_key;
	block_cipher_encrypt_func encrypt;
	block_cipher_decrypt_func decrypt;
};

int block_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key);
int block_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key);
int block_cipher_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);
int block_cipher_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);

const BLOCK_CIPHER *BLOCK_CIPHER_sm4(void);
const BLOCK_CIPHER *BLOCK_CIPHER_aes128(void);



#ifdef __cplusplus
}
#endif
#endif
