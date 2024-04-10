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
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/gcm.h>
#include <gmssl/oid.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


int gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	if (key->cipher == BLOCK_CIPHER_sm4()) {
		if (sm4_gcm_encrypt(&(key->u.sm4_key), iv, ivlen, aad, aadlen,  in, inlen, out, taglen, tag) != 1) {
			error_print();
			return -1;
		}
#ifdef ENABLE_AES
	} else if (key->cipher == BLOCK_CIPHER_aes128()) {
		if (aes_gcm_encrypt(&(key->u.aes_key), iv, ivlen, aad, aadlen,  in, inlen, out, taglen, tag) != 1) {
			error_print();
			return -1;
		}
#endif
	} else {
		error_print();
		return -1;
	}
	return 1;
}

int gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	if (key->cipher == BLOCK_CIPHER_sm4()) {
		if (sm4_gcm_decrypt(&(key->u.sm4_key), iv, ivlen, aad, aadlen,  in, inlen, tag, taglen, out) != 1) {
			error_print();
			return -1;
		}
#ifdef ENABLE_AES
	} else if (key->cipher == BLOCK_CIPHER_aes128()) {
		if (aes_gcm_decrypt(&(key->u.aes_key), iv, ivlen, aad, aadlen,  in, inlen, tag, taglen, out) != 1) {
			error_print();
			return -1;
		}
#endif
	} else {
		error_print();
		return -1;
	}
	return 1;
}
