/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
#define DES_KEY_SIZE	((DES_KEY_BITS)/7)
#define DES_BLOCK_SIZE	(DES_BLOCK_BITS/8)

#define DES_RK_BITS	48
#define DES_RK_SIZE	(DES_RK_BITS/8)
#define DES_ROUNDS	16

#define DES_EDE_KEY_SIZE	(DES_KEY_SIZE * 3)

typedef struct {
	uint64_t rk[DES_ROUNDS];
} DES_KEY;

void des_set_encrypt_key(DES_KEY *key, const uint8_t raw_key[DES_KEY_SIZE]);
void des_set_decrypt_key(DES_KEY *key, const uint8_t raw_key[DES_KEY_SIZE]);
void des_encrypt(DES_KEY *key, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);


typedef struct {
	DES_KEY K[3];
} DES_EDE_KEY;

void des_ede_set_encrypt_key(DES_EDE_KEY *key, const uint8_t raw_key[DES_EDE_KEY_SIZE]);
void des_ede_set_decrypt_key(DES_EDE_KEY *key, const uint8_t raw_key[DES_EDE_KEY_SIZE]);
void des_ede_encrypt(DES_EDE_KEY *key, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
