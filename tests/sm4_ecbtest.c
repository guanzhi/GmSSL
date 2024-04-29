/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/sm4.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_sm4_ecb(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t plaintext[16 * 4];
	uint8_t encrypted[16 * 4];
	uint8_t decrypted[16 * 4];
	int i;

	for (i = 0; i < 3; i++) {
		rand_bytes(key, sizeof(key));
		rand_bytes(plaintext, sizeof(plaintext));

		sm4_set_encrypt_key(&sm4_key, key);
		sm4_encrypt_blocks(&sm4_key, plaintext, sizeof(plaintext)/16, encrypted);

		sm4_set_decrypt_key(&sm4_key, key);
		sm4_encrypt_blocks(&sm4_key, encrypted, sizeof(encrypted)/16, decrypted);

		if (memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ecb_test_vectors(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16] = {
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
	};
	uint8_t plaintext[16 * 4] = {
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
	};
	uint8_t ciphertext[sizeof(plaintext)] = {
		0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46,
		0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46,
		0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46,
		0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46,
	};
	uint8_t encrypted[sizeof(plaintext)] = {0};
	uint8_t decrypted[sizeof(plaintext)] = {0};

	sm4_set_encrypt_key(&sm4_key, key);
	sm4_encrypt_blocks(&sm4_key, plaintext, sizeof(plaintext)/16, encrypted);

	format_bytes(stderr, 0, 0, "", encrypted, sizeof(encrypted));

	if (memcmp(encrypted, ciphertext, sizeof(ciphertext)) != 0) {
		error_print();
		return -1;
	}

	sm4_set_decrypt_key(&sm4_key, key);
	sm4_encrypt_blocks(&sm4_key, encrypted, sizeof(encrypted)/16, decrypted);

	if (memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ecb_ctx(void)
{
	SM4_ECB_CTX ctx;
	uint8_t key[16];
	size_t inlen[] = { 2, 14, 32, 4, 12 };
	uint8_t plaintext[2 + 14 + 32 + 4 + 12];
	uint8_t encrypted[sizeof(plaintext) + 16];
	uint8_t decrypted[sizeof(plaintext) + 16];
	size_t plaintext_len = 0;
	size_t encrypted_len = 0;
	size_t decrypted_len = 0;
	uint8_t *in, *out;
	size_t len;
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(plaintext, sizeof(plaintext));


	// encrypt

	if (sm4_ecb_encrypt_init(&ctx, key) != 1) {
		error_print();
		return -1;
	}

	in = plaintext;
	out = encrypted;

	for (i = 0; i < sizeof(inlen)/sizeof(inlen[0]); i++) {
		if (sm4_ecb_encrypt_update(&ctx, in, inlen[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += inlen[i];
		out += len;
		plaintext_len += inlen[i];
		encrypted_len += len;
	}

	if (sm4_ecb_encrypt_finish(&ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	encrypted_len += len;

	if (encrypted_len != plaintext_len) {
		error_print();
		return -1;
	}

	// decrypt

	if (sm4_ecb_decrypt_init(&ctx, key) != 1) {
		error_print();
		return -1;
	}

	in = encrypted;
	out = decrypted;

	for (i = 0; i < sizeof(inlen)/sizeof(inlen[0]); i++) {
		if (sm4_ecb_decrypt_update(&ctx, in, inlen[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += inlen[i];
		out += len;
		decrypted_len += len;
	}

	if (sm4_ecb_decrypt_finish(&ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	decrypted_len += len;

	if (decrypted_len != plaintext_len) {
		error_print();
		return -1;
	}
	if (memcmp(decrypted, plaintext, plaintext_len) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm4_ecb() != 1) goto err;
	if (test_sm4_ecb_test_vectors() != 1) goto err;
	if (test_sm4_ecb_ctx() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
