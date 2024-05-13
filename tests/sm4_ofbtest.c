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


static int test_sm4_ofb(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t iv[16];

	size_t len[] = { 4, 16, 16+2, 32, 48+8 };
	uint8_t plaintext[48+8];
	uint8_t encrypted[sizeof(plaintext)];
	uint8_t decrypted[sizeof(plaintext)];
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(plaintext, sizeof(plaintext));

	sm4_set_encrypt_key(&sm4_key, key);

	for (i = 0; i < sizeof(len)/sizeof(len[0]); i++) {
		uint8_t state_iv[16];

		memcpy(state_iv, iv, sizeof(iv));
		sm4_ofb_encrypt(&sm4_key, state_iv, plaintext, len[i], encrypted);

		memcpy(state_iv, iv, sizeof(iv));
		sm4_ofb_encrypt(&sm4_key, state_iv, encrypted, len[i], decrypted);

		if (memcmp(decrypted, plaintext, len[i]) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ofb_test_vectors(void)
{
	struct {
		char *label;
		char *key;
		char *iv;
		char *plaintext;
		char *ciphertext;
	} tests[] = {
		{
		"sm4-ofb from openssl",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
		"693d9a535bad5bb1786f53d7253a7056f2075d28b5235f58d50027e4177d2bce",
		},
		{
		"sm4-ofb-example-1 from draft-ribose-cfrg-sm4-10",
		"0123456789abcdeffedcba9876543210",
		"000102030405060708090a0b0c0d0e0f",
		"aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb",
		"ac3236cb861dd316e6413b4e3c7524b71d01aca2487ca582cbf5463e6698539b",
		},
		{
		"sm4-ofb-example-2 from draft-ribose-cfrg-sm4-10",
		"fedcba98765432100123456789abcdef",
		"000102030405060708090a0b0c0d0e0f",
		"aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb",
		"5dcccd25a84ba16560d7f2658870684933fa16bd5cd9c856cacaa1e101897a97",
		},
	};

	uint8_t key[16];
	size_t key_len;
	uint8_t iv[16];
	size_t iv_len;
	uint8_t *plaintext;
	size_t plaintext_len;
	uint8_t *ciphertext;
	size_t ciphertext_len;

	SM4_KEY sm4_key;
	uint8_t *encrypted;
	uint8_t *decrypted;
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {


		if ((plaintext = (uint8_t *)malloc(strlen(tests[i].plaintext)/2)) == NULL) {
			error_print();
			return -1;
		}
		if ((ciphertext = (uint8_t *)malloc(strlen(tests[i].ciphertext)/2)) == NULL) {
			error_print();
			return -1;
		}

		hex_to_bytes(tests[i].key, strlen(tests[i].key), key, &key_len);
		hex_to_bytes(tests[i].iv, strlen(tests[i].iv), iv, &iv_len);
		hex_to_bytes(tests[i].plaintext, strlen(tests[i].plaintext), plaintext, &plaintext_len);
		hex_to_bytes(tests[i].ciphertext, strlen(tests[i].ciphertext), ciphertext, &ciphertext_len);

		if ((encrypted = (uint8_t *)malloc(ciphertext_len)) == NULL) {
			error_print();
			return -1;
		}
		if ((decrypted = (uint8_t *)malloc(plaintext_len)) == NULL) {
			error_print();
			return -1;
		}

		sm4_set_encrypt_key(&sm4_key, key);
		sm4_ofb_encrypt(&sm4_key, iv, plaintext, plaintext_len, encrypted);

		if (memcmp(encrypted, ciphertext, ciphertext_len) != 0) {
			error_print();
			return -1;
		}

		sm4_set_encrypt_key(&sm4_key, key);
		hex_to_bytes(tests[i].iv, strlen(tests[i].iv), iv, &iv_len);
		sm4_ofb_encrypt(&sm4_key, iv, ciphertext, ciphertext_len, decrypted);

		if (memcmp(decrypted, plaintext, plaintext_len) != 0) {
			error_print();
			return -1;
		}

		free(plaintext);
		free(ciphertext);
		free(encrypted);
		free(decrypted);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ofb_ctx(void)
{
	SM4_OFB_CTX ctx;
	uint8_t key[16];
	uint8_t iv[16];
	size_t inlen[] = { 2, 14, 32, 4, 18 };
	uint8_t plaintext[2 + 14 + 32 + 4 + 18];
	uint8_t encrypted[sizeof(plaintext) + 16];
	uint8_t decrypted[sizeof(plaintext) + 16];
	size_t plaintext_len = 0;
	size_t encrypted_len = 0;
	size_t decrypted_len = 0;
	uint8_t *in, *out;
	size_t len;
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(plaintext, sizeof(plaintext));


	// encrypt

	if (sm4_ofb_encrypt_init(&ctx, key, iv) != 1) {
		error_print();
		return -1;
	}

	in = plaintext;
	out = encrypted;

	for (i = 0; i < sizeof(inlen)/sizeof(inlen[0]); i++) {
		if (sm4_ofb_encrypt_update(&ctx, in, inlen[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += inlen[i];
		out += len;
		plaintext_len += inlen[i];
		encrypted_len += len;
	}

	if (sm4_ofb_encrypt_finish(&ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	encrypted_len += len;

	if (encrypted_len != plaintext_len) {
		error_print();
		return -1;
	}

	// decrypt

	if (sm4_ofb_encrypt_init(&ctx, key, iv) != 1) {
		error_print();
		return -1;
	}

	in = encrypted;
	out = decrypted;

	for (i = 0; i < sizeof(inlen)/sizeof(inlen[0]); i++) {
		if (sm4_ofb_encrypt_update(&ctx, in, inlen[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += inlen[i];
		out += len;
		decrypted_len += len;
	}

	if (sm4_ofb_encrypt_finish(&ctx, out, &len) != 1) {
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
	if (test_sm4_ofb() != 1) goto err;
	if (test_sm4_ofb_test_vectors() != 1) goto err;
	if (test_sm4_ofb_ctx() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
