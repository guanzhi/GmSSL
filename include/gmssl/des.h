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

/* FIPS PUB 46-3 "Data Encryption Standard (DES)" */

#ifndef GMSSL_DES_H
#define GMSSL_DES_H


#include <stdint.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif


#define DES_KEY_BITS	56
#define DES_BLOCK_BITS	64
#define DES_KEY_SIZE	(DES_KEY_BITS/8)
#define DES_BLOCK_SIZE	(DES_BLOCK_BITS/8)

#define DES_RK_BITS	48
#define DES_RK_SIZE	(DES_RK_BITS/8)
#define DES_ROUNDS	16


typedef struct {
	uint64_t rk[DES_ROUNDS];
} DES_KEY;

void des_set_encrypt_key(DES_KEY *key, const unsigned char user_key[8]);
void des_set_decrypt_key(DES_KEY *key, const unsigned char user_key[8]);
void des_encrypt(DES_KEY *key, const unsigned char in[8], unsigned char out[8]);


typedef struct {
	DES_KEY K[3];
} DES_EDE_KEY;

void des_ede_set_encrypt_key(DES_EDE_KEY *key, const unsigned char user_key[24]);
void des_ede_set_decrypt_key(DES_EDE_KEY *key, const unsigned char user_key[24]);
void des_ede_encrypt(DES_EDE_KEY *key, const unsigned char in[8], unsigned char out[8]);


#ifdef __cplusplus
}
#endif
#endif
