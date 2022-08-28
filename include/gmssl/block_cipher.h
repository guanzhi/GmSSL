/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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


#define BLOCK_CIPHER_BLOCK_SIZE		16
#define BLOCK_CIPHER_MIN_KEY_SIZE	16
#define BLOCK_CIPHER_MAX_KEY_SIZE	32


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
	int oid;
	size_t key_size;
	size_t block_size;
	block_cipher_set_encrypt_key_func set_encrypt_key;
	block_cipher_set_decrypt_key_func set_decrypt_key;
	block_cipher_encrypt_func encrypt;
	block_cipher_decrypt_func decrypt;
};

const BLOCK_CIPHER *BLOCK_CIPHER_sm4(void);
const BLOCK_CIPHER *BLOCK_CIPHER_aes128(void);

const BLOCK_CIPHER *block_cipher_from_name(const char *name);
const char *block_cipher_name(const BLOCK_CIPHER *cipher);
int block_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key);
int block_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key);
int block_cipher_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);
int block_cipher_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
