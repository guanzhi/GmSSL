/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_FF1_H
#define GMSSL_FF1_H


#include <stdint.h>
#include <stddef.h>
#include <gmssl/block_cipher.h>


#ifdef __cplusplus
extern "C" {
#endif


#define FF1_MIN_DIGITS		8
#define FF1_MAX_DIGITS		18
#define FF1_MIN_TWEAK_SIZE	0
#define FF1_MAX_TWEAK_SIZE	11
#define FF1_NUM_ROUNDS		10


int ff1_init(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key);
int ff1_encrypt(const BLOCK_CIPHER_KEY *key, const char *in, size_t inlen,
	const uint8_t *tweak, size_t tweaklen, char *out);
int ff1_decrypt(const BLOCK_CIPHER_KEY *key, const char *in, size_t inlen,
	const uint8_t *tweak, size_t tweaklen, char *out);


#ifdef __cplusplus
}
#endif
#endif
