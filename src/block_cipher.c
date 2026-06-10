/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <gmssl/block_cipher.h>


const BLOCK_CIPHER *block_cipher_from_name(const char *name)
{
	if (!name) {
		error_print();
		return NULL;
	}
	if (!strcmp(name, "sm4")) {
		return BLOCK_CIPHER_sm4();
#ifdef ENABLE_AES
	} else if (!strcmp(name, "aes128")) {
		return BLOCK_CIPHER_aes128();
	} else if (!strcmp(name, "aes192")) {
		return BLOCK_CIPHER_aes192();
	} else if (!strcmp(name, "aes256")) {
		return BLOCK_CIPHER_aes256();
#endif
	}
	error_print();
	return NULL;
}

const char *block_cipher_name(const BLOCK_CIPHER *cipher)
{
	if (!cipher) {
		error_print();
		return NULL;
	}
	switch (cipher->oid) {
	case OID_sm4: return "sm4";
#ifdef ENABLE_AES
	case OID_aes128: return "aes128";
	case OID_aes192: return "aes192";
	case OID_aes256: return "aes256";
#endif
	}
	error_print();
	return NULL;
}

int block_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key)
{
	if (!key || !cipher || !cipher->set_encrypt_key || !cipher->encrypt || !cipher->decrypt || !raw_key) {
		error_print();
		return -1;
	}
	if (cipher->key_size < BLOCK_CIPHER_MIN_KEY_SIZE
		|| cipher->key_size > BLOCK_CIPHER_MAX_KEY_SIZE
		|| cipher->block_size != BLOCK_CIPHER_BLOCK_SIZE
		|| cipher->ctx_size > sizeof(key->u)) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(BLOCK_CIPHER_KEY));
	if (cipher->set_encrypt_key(key, raw_key) != 1) {
		error_print();
		memset(key, 0, sizeof(BLOCK_CIPHER_KEY));
		return -1;
	}
	key->cipher = cipher;
	return 1;
}

int block_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key)
{
	if (!key || !cipher || !cipher->set_decrypt_key || !cipher->encrypt || !cipher->decrypt || !raw_key) {
		error_print();
		return -1;
	}
	if (cipher->key_size < BLOCK_CIPHER_MIN_KEY_SIZE
		|| cipher->key_size > BLOCK_CIPHER_MAX_KEY_SIZE
		|| cipher->block_size != BLOCK_CIPHER_BLOCK_SIZE
		|| cipher->ctx_size > sizeof(key->u)) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(BLOCK_CIPHER_KEY));
	if (cipher->set_decrypt_key(key, raw_key) != 1) {
		error_print();
		memset(key, 0, sizeof(BLOCK_CIPHER_KEY));
		return -1;
	}
	key->cipher = cipher;
	return 1;
}

int block_cipher_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out)
{
	if (!key || !key->cipher || !key->cipher->encrypt || !in || !out) {
		error_print();
		return -1;
	}
	if (key->cipher->encrypt(key, in, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int block_cipher_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out)
{
	if (!key || !key->cipher || !key->cipher->decrypt || !in || !out) {
		error_print();
		return -1;
	}
	if (key->cipher->decrypt(key, in, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


static int sm4_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key) {
	sm4_set_encrypt_key(&key->u.sm4_key, raw_key);
	return 1;
}

static int sm4_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key) {
	sm4_set_decrypt_key(&key->u.sm4_key, raw_key);
	return 1;
}

static int sm4_cipher_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out) {
	sm4_encrypt(&key->u.sm4_key, in, out);
	return 1;
}

static const BLOCK_CIPHER sm4_block_cipher_object = {
	OID_sm4,
	SM4_KEY_SIZE,
	SM4_BLOCK_SIZE,
	sizeof(SM4_KEY),
	sm4_cipher_set_encrypt_key,
	sm4_cipher_set_decrypt_key,
	sm4_cipher_encrypt,
	sm4_cipher_encrypt,
};

const BLOCK_CIPHER *BLOCK_CIPHER_sm4(void) {
	return &sm4_block_cipher_object;
}


#ifdef ENABLE_AES
static int aes128_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key) {
	return aes_set_encrypt_key(&key->u.aes_key, raw_key, AES128_KEY_SIZE);
}

static int aes128_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key) {
	return aes_set_decrypt_key(&key->u.aes_key, raw_key, AES128_KEY_SIZE);
}

static int aes192_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key) {
	return aes_set_encrypt_key(&key->u.aes_key, raw_key, AES192_KEY_SIZE);
}

static int aes192_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key) {
	return aes_set_decrypt_key(&key->u.aes_key, raw_key, AES192_KEY_SIZE);
}

static int aes256_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key) {
	return aes_set_encrypt_key(&key->u.aes_key, raw_key, AES256_KEY_SIZE);
}

static int aes256_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key) {
	return aes_set_decrypt_key(&key->u.aes_key, raw_key, AES256_KEY_SIZE);
}

static int aes_cipher_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out) {
	aes_encrypt(&key->u.aes_key, in, out);
	return 1;
}

static int aes_cipher_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out) {
	aes_decrypt(&key->u.aes_key, in, out);
	return 1;
}

static const BLOCK_CIPHER aes128_block_cipher_object = {
	OID_aes128,
	AES128_KEY_SIZE,
	AES_BLOCK_SIZE,
	sizeof(AES_KEY),
	aes128_cipher_set_encrypt_key,
	aes128_cipher_set_decrypt_key,
	aes_cipher_encrypt,
	aes_cipher_decrypt,
};

const BLOCK_CIPHER *BLOCK_CIPHER_aes128(void) {
	return &aes128_block_cipher_object;
}

static const BLOCK_CIPHER aes192_block_cipher_object = {
	OID_aes192,
	AES192_KEY_SIZE,
	AES_BLOCK_SIZE,
	sizeof(AES_KEY),
	aes192_cipher_set_encrypt_key,
	aes192_cipher_set_decrypt_key,
	aes_cipher_encrypt,
	aes_cipher_decrypt,
};

const BLOCK_CIPHER *BLOCK_CIPHER_aes192(void) {
	return &aes192_block_cipher_object;
}

static const BLOCK_CIPHER aes256_block_cipher_object = {
	OID_aes256,
	AES256_KEY_SIZE,
	AES_BLOCK_SIZE,
	sizeof(AES_KEY),
	aes256_cipher_set_encrypt_key,
	aes256_cipher_set_decrypt_key,
	aes_cipher_encrypt,
	aes_cipher_decrypt,
};

const BLOCK_CIPHER *BLOCK_CIPHER_aes256(void) {
	return &aes256_block_cipher_object;
}
#endif // ENABLE_AES
