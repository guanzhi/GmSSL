/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>


typedef struct {
	const uint8_t key[16];
	const char *plaintext;
	const uint8_t *tweak;
	size_t tweaklen;
	const char *ciphertext;
} SM4_FF1_TEST;

static const uint8_t sm4_ff1_sm4_tweak1[] = {
	0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32,
	0x31, 0x30,
};

static const uint8_t sm4_ff1_sm4_tweak2[] = {
	0x37, 0x38, 0x39, 0x36, 0x70, 0x71, 0x72, 0x73,
	0x74, 0x75, 0x76,
};

static const SM4_FF1_TEST sm4_ff1_sm4_tests[] = {
	{
		{
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
		},
		"6226090102675688",
		sm4_ff1_sm4_tweak1,
		sizeof(sm4_ff1_sm4_tweak1),
		"2326982895499381",
	},
	{
		{
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
		},
		"110107197203192876",
		sm4_ff1_sm4_tweak2,
		sizeof(sm4_ff1_sm4_tweak2),
		"755842115213533405",
	},
	{
		{
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
		},
		"13687260594",
		NULL,
		0,
		"37914960556",
	},
};

static int test_sm4_ff1(void)
{
	const char *plaintext = "99999999999999999";
	size_t plaintext_len = strlen(plaintext);
	const char sentinel = '#';
	const uint8_t key[16] = {0};
	const uint8_t tweak[8] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	};
	SM4_KEY sm4_key;
	char ciphertext[SM4_FF1_MAX_DIGITS + 1];
	char decrypted[SM4_FF1_MAX_DIGITS + 1];

	if (sm4_ff1_init(&sm4_key, key) != 1) {
		error_print();
		return -1;
	}
	ciphertext[plaintext_len] = sentinel;
	if (sm4_ff1_encrypt(&sm4_key, plaintext, plaintext_len,
		tweak, sizeof(tweak), ciphertext) != 1) {
		error_print();
		return -1;
	}
	if (ciphertext[plaintext_len] != sentinel) {
		error_print();
		return -1;
	}
	ciphertext[plaintext_len] = '\0';
	decrypted[plaintext_len] = sentinel;
	if (sm4_ff1_decrypt(&sm4_key, ciphertext, plaintext_len,
		tweak, sizeof(tweak), decrypted) != 1) {
		error_print();
		return -1;
	}
	if (decrypted[plaintext_len] != sentinel) {
		error_print();
		return -1;
	}
	decrypted[plaintext_len] = '\0';
	if (strcmp(plaintext, decrypted) != 0) {
		error_print();
		return -1;
	}

	printf("sm4_ff1_encrypt(\"%s\") = \"%s\"\n", plaintext, ciphertext);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ff1_vectors(void)
{
	SM4_KEY sm4_key;
	char ciphertext[SM4_FF1_MAX_DIGITS + 1];
	char decrypted[SM4_FF1_MAX_DIGITS + 1];
	size_t i;
	int err = 0;

	for (i = 0; i < sizeof(sm4_ff1_sm4_tests)/sizeof(sm4_ff1_sm4_tests[0]); i++) {
		const SM4_FF1_TEST *test = &sm4_ff1_sm4_tests[i];

		if (sm4_ff1_init(&sm4_key, test->key) != 1) {
			error_print();
			return -1;
		}
		if (sm4_ff1_encrypt(&sm4_key, test->plaintext, strlen(test->plaintext),
			test->tweak, test->tweaklen, ciphertext) != 1) {
			error_print();
			return -1;
		}
		ciphertext[strlen(test->plaintext)] = '\0';
		if (strcmp(ciphertext, test->ciphertext) != 0) {
			fprintf(stderr, "test %zu: got %s, expected %s\n",
				i + 1, ciphertext, test->ciphertext);
			error_print();
			err++;
			continue;
		}
		if (sm4_ff1_decrypt(&sm4_key, test->ciphertext, strlen(test->ciphertext),
			test->tweak, test->tweaklen, decrypted) != 1) {
			error_print();
			return -1;
		}
		decrypted[strlen(test->ciphertext)] = '\0';
		if (strcmp(decrypted, test->plaintext) != 0) {
			error_print();
			return -1;
		}
	}
	if (err) {
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	int err = 0;

	if (test_sm4_ff1() != 1) {
		err++;
	}
	if (test_sm4_ff1_vectors() != 1) {
		err++;
	}

	return err;
}
