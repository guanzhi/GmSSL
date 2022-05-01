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
#include <gmssl/endian.h>


int block_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key)
{
	memset(key, 0, sizeof(BLOCK_CIPHER_KEY));
	cipher->set_encrypt_key(key, raw_key);
	key->cipher = cipher;
	return 1;
}

int block_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key)
{
	memset(key, 0, sizeof(BLOCK_CIPHER_KEY));
	cipher->set_decrypt_key(key, raw_key);
	key->cipher = cipher;
	return 1;
}

int block_cipher_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out)
{
	key->cipher->encrypt(key, in, out);
	return 1;
}

int block_cipher_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out)
{
	key->cipher->decrypt(key, in, out);
	return 1;
}

static const BLOCK_CIPHER sm4_block_cipher_object = {
	OID_sm4,
	SM4_KEY_SIZE,
	SM4_BLOCK_SIZE,
	(block_cipher_set_encrypt_key_func)sm4_set_encrypt_key,
	(block_cipher_set_decrypt_key_func)sm4_set_decrypt_key,
	(block_cipher_encrypt_func)sm4_encrypt,
	(block_cipher_decrypt_func)sm4_encrypt,
};

const BLOCK_CIPHER *BLOCK_CIPHER_sm4(void) {
	return &sm4_block_cipher_object;
}

static int aes128_set_encrypt_key(AES_KEY *aes_key, const uint8_t key[16]) {
	return aes_set_encrypt_key(aes_key, key, 16);
}

static int aes128_set_decrypt_key(AES_KEY *aes_key, const uint8_t key[16]) {
	return aes_set_decrypt_key(aes_key, key, 16);
}

static const BLOCK_CIPHER aes128_block_cipher_object = {
	OID_aes128,
	AES128_KEY_SIZE,
	AES_BLOCK_SIZE,
	(block_cipher_set_encrypt_key_func)aes128_set_encrypt_key,
	(block_cipher_set_decrypt_key_func)aes128_set_decrypt_key,
	(block_cipher_encrypt_func)aes_encrypt,
	(block_cipher_decrypt_func)aes_encrypt,
};

const BLOCK_CIPHER *BLOCK_CIPHER_aes128(void) {
	return &aes128_block_cipher_object;
}
