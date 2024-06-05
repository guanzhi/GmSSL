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
#include <time.h>
#include <gmssl/rand.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/pkcs8.h>


// TODO: prepare POINT with different length		

static int test_sm2_ciphertext(void)
{
	struct {
		char *label;
		size_t ciphertext_size;
	} tests[] = {
		{ "null ciphertext", 0 },
		{ "min ciphertext size", SM2_MIN_PLAINTEXT_SIZE },
		{ "max ciphertext size", SM2_MAX_PLAINTEXT_SIZE },
	};

	SM2_CIPHERTEXT C;
	SM2_KEY sm2_key;
	uint8_t buf[1024];
	size_t i;

	rand_bytes(C.hash, 32);
	rand_bytes(C.ciphertext, SM2_MAX_PLAINTEXT_SIZE);

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		if (sm2_key_generate(&sm2_key) != 1) {
			error_print();
			return -1;
		}

		sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&(C.point));
		C.ciphertext_size = (uint8_t)tests[i].ciphertext_size;

		if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
			error_print();
			return -1;
		}

		printf("Plaintext size = %zu, SM2Ciphertext DER size %zu\n", tests[i].ciphertext_size, len);

		if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}

	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#define TEST_COUNT 20

static int test_sm2_do_encrypt(void)
{
	SM2_KEY sm2_key;
	uint8_t plaintext[] = "Hello World!";
	SM2_CIPHERTEXT ciphertext;

	uint8_t plainbuf[SM2_MAX_PLAINTEXT_SIZE] = {0};
	size_t plainlen = 0;
	int r = 0;

	size_t i = 0;

	for (i = 0; i < TEST_COUNT; i++) {

		if (sm2_key_generate(&sm2_key) != 1) {
			error_print();
			return -1;
		}

		if (sm2_do_encrypt(&sm2_key, plaintext, sizeof(plaintext), &ciphertext) != 1) {
			error_print();
			return -1;
		}

		if (sm2_do_decrypt(&sm2_key, &ciphertext, plainbuf, &plainlen) != 1) {
			error_print();
			return -1;
		}
		if (plainlen != sizeof(plaintext)
			|| memcmp(plainbuf, plaintext, sizeof(plaintext)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_do_encrypt_fixlen(void)
{
	struct {
		int point_size;
		size_t plaintext_len;
	} tests[] = {
		{ SM2_ciphertext_compact_point_size, 10 },
		{ SM2_ciphertext_typical_point_size, 10 },
		{ SM2_ciphertext_max_point_size, 10 },
	};

	SM2_KEY sm2_key;
	uint8_t plaintext[SM2_MAX_PLAINTEXT_SIZE];
	SM2_CIPHERTEXT ciphertext;
	uint8_t decrypted[SM2_MAX_PLAINTEXT_SIZE];
	size_t decrypted_len;

	size_t i;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	rand_bytes(plaintext, sizeof(plaintext));

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		if (sm2_do_encrypt_fixlen(&sm2_key, plaintext, tests[i].plaintext_len, tests[i].point_size, &ciphertext) != 1) {
			error_print();
			return -1;
		}

		if (sm2_do_decrypt(&sm2_key, &ciphertext, decrypted, &decrypted_len) != 1) {
			error_print();
			return -1;
		}

		if (decrypted_len != tests[i].plaintext_len) {
			error_print();
			return -1;
		}
		if (memcmp(decrypted, plaintext, decrypted_len) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm2_encrypt_fixlen(void)
{
	struct {
		int point_size;
		size_t plaintext_len;
	} tests[] = {
		{ SM2_ciphertext_compact_point_size, 1 },
		{ SM2_ciphertext_typical_point_size, 64 },
		{ SM2_ciphertext_max_point_size, SM2_MAX_PLAINTEXT_SIZE },
	};

	SM2_KEY sm2_key;
	uint8_t plaintext[SM2_MAX_PLAINTEXT_SIZE];
	uint8_t encrypted[SM2_MAX_CIPHERTEXT_SIZE];
	uint8_t decrypted[SM2_MAX_PLAINTEXT_SIZE];
	size_t encrypted_len, encrypted_fixlen, decrypted_len;
	size_t i, j;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	rand_bytes(plaintext, sizeof(plaintext));

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		if (sm2_encrypt_fixlen(&sm2_key, plaintext, tests[i].plaintext_len, tests[i].point_size,
			encrypted, &encrypted_len) != 1) {
			error_print();
			return -1;
		}

		if (sm2_decrypt(&sm2_key, encrypted, encrypted_len, decrypted, &decrypted_len) != 1) {
			error_print();
			return -1;
		}
		if (decrypted_len != tests[i].plaintext_len) {
			error_print();
			return -1;
		}
		if (memcmp(decrypted, plaintext, tests[i].plaintext_len) != 0) {
			error_print();
			return -1;
		}

		// check if sm2_encrypt_fixlen always output fixed length ciphertext
		encrypted_fixlen = encrypted_len;
		for (j = 0; j < 10; j++) {
			if (sm2_encrypt_fixlen(&sm2_key, plaintext, tests[i].plaintext_len, tests[i].point_size,
				encrypted, &encrypted_len) != 1) {
				error_print();
				return -1;
			}
			if (encrypted_len != encrypted_fixlen) {
				error_print();
				return -1;
			}
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm2_encrypt(void)
{
	SM2_KEY sm2_key;
	uint8_t msg[SM2_MAX_PLAINTEXT_SIZE];
	uint8_t cbuf[SM2_MAX_CIPHERTEXT_SIZE+100];
	uint8_t mbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t lens[] = {
//		0,
		1,
		16,
		SM2_MAX_PLAINTEXT_SIZE,
	};
	size_t clen, mlen;
	int i;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	for (i = 0; i < sizeof(msg); i++) {
		msg[i] = (uint8_t)i;
	}

	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		format_print(stderr, 0, 0, "test %d\n", i + 1);
		format_bytes(stderr, 0, 4, "plaintext", msg, lens[i]);
		if (sm2_encrypt(&sm2_key, msg, lens[i], cbuf, &clen) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "ciphertext", cbuf, clen);
		sm2_ciphertext_print(stderr, 0, 4, "Ciphertext", cbuf, clen);
		format_print(stderr, 0, 0, "\n");

		if (sm2_decrypt(&sm2_key, cbuf, clen, mbuf, &mlen) != 1) {
			error_print();
			return -1;
		}
		if (mlen != lens[i]
			|| memcmp(mbuf, msg, lens[i]) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int speed_sm2_encrypt_ctx(void)
{
	SM2_KEY sm2_key;
	SM2_ENC_CTX enc_ctx;
	uint8_t plaintext[32];
	uint8_t ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
	size_t ciphertext_len;
	clock_t begin, end;
	double seconds;
	int i;

	sm2_key_generate(&sm2_key);

	if (sm2_encrypt_init(&enc_ctx) != 1) {
		error_print();
		return -1;
	}

	begin = clock();
	for (i = 0; i < 4096; i++) {
		if (sm2_encrypt_update(&enc_ctx, plaintext, sizeof(plaintext)) != 1) {
			error_print();
			return -1;
		}
		if (sm2_encrypt_finish(&enc_ctx, &sm2_key, ciphertext, &ciphertext_len) != 1) {
			error_print();
			return -1;
		}
		sm2_encrypt_reset(&enc_ctx);
	}
	end = clock();
	seconds = (double)(end - begin)/CLOCKS_PER_SEC;

	printf("%s: %f encryptions per second\n", __FUNCTION__, 4096/seconds);
	return 1;
}


int main(void)
{
	if (test_sm2_ciphertext() != 1) goto err;
	if (test_sm2_do_encrypt() != 1) goto err;
	if (test_sm2_do_encrypt_fixlen() != 1) goto err;
	if (test_sm2_encrypt() != 1) goto err;
	if (test_sm2_encrypt_fixlen() != 1) goto err;
#if ENABLE_TEST_SPEED
	if (speed_sm2_encrypt_ctx() != 1) goto err;
#endif
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}

