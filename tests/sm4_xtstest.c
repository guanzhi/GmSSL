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


static int test_sm4_xts(void)
{
	SM4_KEY sm4_key1;
	SM4_KEY sm4_key2;
	uint8_t key[32];
	size_t len[] = { 16, 16+2, 25, 32, 48+8, 64 };
	uint8_t plaintext[16 * 4];
	uint8_t encrypted[sizeof(plaintext)];
	uint8_t decrypted[sizeof(plaintext)];
	uint8_t tweak[16];
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(tweak, sizeof(tweak));
	rand_bytes(plaintext, sizeof(plaintext));

	for (i = 0; i < sizeof(len)/sizeof(len[0]); i++) {

		sm4_set_encrypt_key(&sm4_key1, key);
		sm4_set_encrypt_key(&sm4_key2, key + 16);
		sm4_xts_encrypt(&sm4_key1, &sm4_key2, tweak, plaintext, len[i], encrypted);

		sm4_set_decrypt_key(&sm4_key1, key);
		sm4_set_encrypt_key(&sm4_key2, key + 16);
		sm4_xts_decrypt(&sm4_key1, &sm4_key2, tweak, encrypted, len[i], decrypted);

		if (memcmp(decrypted, plaintext, len[i]) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_xts_test_vectors(void)
{
	struct {
		char *label;
		char *key;
		char *iv;
		char *plaintext;
		char *ciphertext;
	} tests[] = {
		{
		"https://github.com/mewmix/sm4-xts-openssl",
		"68d90424687cc2043595091a78a44ec2c639c3ecc6b14d7ac42ce74e582fa3dc",
		"601cd97ddeb1c75bbe5865072f3dc7a8",
		"686579667269656e64736c657473676574656e6372797074656421",
		"34143fbf6cb3a97feb84f866d85e01f8d15ed03905552cb12cd567",
		},
		{
		"openssl-1 (openssl/test/recipes/30-test_evp_data/evpciph_sm4.txt)",
		"2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17",
		"e9538251c71d7b80bbe4483fef497bd12c5c581bd6242fc51e08964fb4f60fdb0ba42f63499279213d318d2c11f6886e903be7f93a1b3479",
		},
		/*
		{
		"openssl-2",
		"2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17",
		"e9538251c71d7b80bbe4483fef497bd12c5c581bd6242fc51e08964fb4f60fdb0ba42f63499279213d318d2c11f6886e903be7f93a1b3479",
		},
		*/
	};

	SM4_KEY sm4_key1;
	SM4_KEY sm4_key2;

	uint8_t key[32];
	size_t key_len;
	uint8_t iv[16];
	size_t iv_len;
	uint8_t *plaintext;
	size_t plaintext_len;
	uint8_t *ciphertext;
	size_t ciphertext_len;

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

		sm4_set_encrypt_key(&sm4_key1, key);
		sm4_set_encrypt_key(&sm4_key2, key + 16);

		if (sm4_xts_encrypt(&sm4_key1, &sm4_key2, iv, plaintext, plaintext_len, encrypted) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(encrypted, ciphertext, ciphertext_len) != 0) {
			error_print();
			return -1;
		}

		sm4_set_decrypt_key(&sm4_key1, key);
		sm4_set_encrypt_key(&sm4_key2, key + 16);
		if (sm4_xts_decrypt(&sm4_key1, &sm4_key2, iv, ciphertext, ciphertext_len, decrypted) != 1) {
			error_print();
			return -1;
		}

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

int main(void)
{
	if (test_sm4_xts() != 1) goto err;
	if (test_sm4_xts_test_vectors() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
