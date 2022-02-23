/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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
