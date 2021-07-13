/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/block_cipher.h>
#include "internal/endian.h"


int block_cipher_encrypt_init(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher,
	const uint8_t *user_key, size_t keylen)
{
	memset(key, 0, sizeof(BLOCK_CIPHER_KEY));
	key->cipher = cipher;
	return key->cipher->set_encrypt_key(key, user_key, keylen);
}

int block_cipher_decrypt_init(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher,
	const uint8_t *user_key, size_t keylen)
{
	memset(key, 0, sizeof(BLOCK_CIPHER_KEY));
	key->cipher = cipher;
	return key->cipher->set_decrypt_key(key, user_key, keylen);
}

void block_cipher_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out)
{
	key->cipher->encrypt(key, in, out);
}

void block_cipher_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out)
{
	key->cipher->decrypt(key, in, out);
}

void block_cipher_ecb_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		key->cipher->encrypt(key, in, out);
		in += key->cipher->block_size;
		out += key->cipher->block_size;
	}
}

void block_cipher_ecb_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		key->cipher->decrypt(key, in, out);
		in += key->cipher->block_size;
		out += key->cipher->block_size;
	}
}

void block_cipher_cbc_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv,
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		gmssl_memxor(out, in, iv, key->cipher->block_size);
		key->cipher->encrypt(key, out, out);
		iv = out;
		in += key->cipher->block_size;
		out += key->cipher->block_size;
	}
}

void block_cipher_cbc_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv,
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		key->cipher->decrypt(key, in, out);
		gmssl_memxor(out, out, iv, key->cipher->block_size);
		iv = in;
		in += key->cipher->block_size;
		out += key->cipher->block_size;
	}
}

void block_cipher_ctr_encrypt(const BLOCK_CIPHER_KEY *key, uint8_t *counter,
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	size_t block_size = key->cipher->block_size;
	uint8_t block[block_size];
	uint64_t ctr = GETU64(counter + block_size - sizeof(uint64_t));

	while (nblocks--) {
		key->cipher->encrypt(key, counter, block);
		gmssl_memxor(out, in, block, block_size);
		in += block_size;
		out += block_size;
		ctr++;
		PUTU64(counter + block_size - sizeof(uint64_t), ctr);
	}
}


static const BLOCK_CIPHER aes_block_cipher_object = {
	OID_aes,
	AES128_KEY_SIZE,
	AES256_KEY_SIZE,
	AES_BLOCK_SIZE,
	(block_cipher_set_encrypt_key_func)aes_set_encrypt_key,
	(block_cipher_set_decrypt_key_func)aes_set_decrypt_key,
	(block_cipher_encrypt_func)aes_encrypt,
	(block_cipher_decrypt_func)aes_encrypt,
};

const BLOCK_CIPHER *BLOCK_CIPHER_aes(void)
{
	return &aes_block_cipher_object;
}


static int set_encrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *user_key, size_t keylen)
{
	if (keylen != SM4_KEY_SIZE) {
		return -1;
	}
	sm4_set_encrypt_key(&key->u.sm4_key, user_key);
	return 1;
}

static int set_decrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *user_key, size_t keylen)
{
	if (keylen != SM4_KEY_SIZE) {
		return -1;
	}
	sm4_set_decrypt_key(&key->u.sm4_key, user_key);
	return 1;
}

static const BLOCK_CIPHER sm4_block_cipher_object = {
	OID_sm4,
	SM4_KEY_SIZE,
	SM4_KEY_SIZE,
	SM4_BLOCK_SIZE,
	set_encrypt_key,
	set_decrypt_key,
	(block_cipher_encrypt_func)sm4_encrypt,
	(block_cipher_decrypt_func)sm4_encrypt,
};

const BLOCK_CIPHER *BLOCK_CIPHER_sm4(void)
{
	return &sm4_block_cipher_object;
}

const BLOKC_CIPHER *block_cipher_from_name(const char *name)
{
	if (strcmp(name, "aes") == 0) {
		return BLOCK_CIPHER_aes();
	} else if (strcmp(name, "sm4") == 0) {
		return BLOCK_CIPHER_sm4();
	}
	return NULL;
}
