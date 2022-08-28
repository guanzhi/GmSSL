/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
