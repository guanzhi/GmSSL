/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License);
 *  you may not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/digest.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/error.h>

#define TEST_PBKDF2_MAX_PASSWORD_SIZE 257
#define TEST_PBKDF2_MAX_SALT_SIZE 36
#define TEST_PBKDF2_MAX_DK_SIZE 65

#ifndef ENABLE_LONG_TEST
#define TEST_PBKDF2_MAX_ITERATION_COUNT 1000000
#endif

enum {
	TEST_RESULT_VALID,
	TEST_RESULT_INVALID,
	TEST_RESULT_ACCEPTABLE,
};

typedef struct {
	int tc_id;
	const char *comment;
	const char *flags;
	const char *password;
	const char *salt;
	size_t iteration_count;
	size_t dk_len;
	const char *dk;
	int result;
} TEST_PBKDF2_VECTOR;

#ifdef ENABLE_SHA1
#include "pbkdf2test_sha1.h"
#endif
#ifdef ENABLE_SHA2
#include "pbkdf2test_sha224.h"
#include "pbkdf2test_sha256.h"
#include "pbkdf2test_sha384.h"
#include "pbkdf2test_sha512.h"
#endif

static int test_pbkdf2_hmac_wycheproof(const char *name, const DIGEST *digest,
	const TEST_PBKDF2_VECTOR *tests, size_t tests_count)
{
	size_t i;
	size_t skipped = 0;

	for (i = 0; i < tests_count; i++) {
		const TEST_PBKDF2_VECTOR *tv = &tests[i];
		uint8_t password[TEST_PBKDF2_MAX_PASSWORD_SIZE];
		uint8_t salt[TEST_PBKDF2_MAX_SALT_SIZE];
		uint8_t dk[TEST_PBKDF2_MAX_DK_SIZE];
		uint8_t expected[TEST_PBKDF2_MAX_DK_SIZE];
		size_t password_len;
		size_t salt_len;
		size_t expected_len;
		int ret;

#ifndef ENABLE_LONG_TEST
		if (tv->iteration_count > TEST_PBKDF2_MAX_ITERATION_COUNT) {
			fprintf(stderr, "%s tcId %d skipped: iteration_count = %zu\n",
				name, tv->tc_id, tv->iteration_count);
			skipped++;
			continue;
		}
#endif

		if (strlen(tv->password)/2 > sizeof(password)
			|| strlen(tv->salt)/2 > sizeof(salt)
			|| strlen(tv->dk)/2 > sizeof(expected)
			|| tv->dk_len > sizeof(dk)) {
			error_print();
			return -1;
		}
		if (hex_to_bytes(tv->password, strlen(tv->password), password, &password_len) != 1
			|| hex_to_bytes(tv->salt, strlen(tv->salt), salt, &salt_len) != 1
			|| hex_to_bytes(tv->dk, strlen(tv->dk), expected, &expected_len) != 1) {
			error_print();
			return -1;
		}
		if (tv->result == TEST_RESULT_VALID && expected_len != tv->dk_len) {
			error_print();
			return -1;
		}

		ret = pbkdf2_hmac_genkey(digest,
			password_len ? (const char *)password : NULL, password_len,
			salt_len ? salt : NULL, salt_len,
			tv->iteration_count, tv->dk_len, dk);

		if (tv->result == TEST_RESULT_VALID) {
			if (ret != 1 || memcmp(dk, expected, expected_len) != 0) {
				fprintf(stderr, "%s tcId %d failed: %s %s\n",
					name, tv->tc_id, tv->comment, tv->flags);
				error_print();
				return -1;
			}
		} else if (tv->result == TEST_RESULT_INVALID) {
			if (ret == 1) {
				error_print();
				return -1;
			}
		} else {
			if (ret != 1 && ret != -1) {
				error_print();
				return -1;
			}
		}
	}

	if (skipped) {
		fprintf(stderr, "%s skipped %zu long-iteration test vector(s)\n", name, skipped);
	}
	printf("%s() ok\n", name);
	return 1;
}

#ifdef ENABLE_SHA1
static int test_pbkdf2_hmac_sha1_wycheproof(void)
{
	return test_pbkdf2_hmac_wycheproof(__FUNCTION__, DIGEST_sha1(),
		pbkdf2_hmac_sha1_tests,
		sizeof(pbkdf2_hmac_sha1_tests)/sizeof(pbkdf2_hmac_sha1_tests[0]));
}
#endif

#ifdef ENABLE_SHA2
static int test_pbkdf2_hmac_sha224_wycheproof(void)
{
	return test_pbkdf2_hmac_wycheproof(__FUNCTION__, DIGEST_sha224(),
		pbkdf2_hmac_sha224_tests,
		sizeof(pbkdf2_hmac_sha224_tests)/sizeof(pbkdf2_hmac_sha224_tests[0]));
}

static int test_pbkdf2_hmac_sha256_wycheproof(void)
{
	return test_pbkdf2_hmac_wycheproof(__FUNCTION__, DIGEST_sha256(),
		pbkdf2_hmac_sha256_tests,
		sizeof(pbkdf2_hmac_sha256_tests)/sizeof(pbkdf2_hmac_sha256_tests[0]));
}

static int test_pbkdf2_hmac_sha384_wycheproof(void)
{
	return test_pbkdf2_hmac_wycheproof(__FUNCTION__, DIGEST_sha384(),
		pbkdf2_hmac_sha384_tests,
		sizeof(pbkdf2_hmac_sha384_tests)/sizeof(pbkdf2_hmac_sha384_tests[0]));
}

static int test_pbkdf2_hmac_sha512_wycheproof(void)
{
	return test_pbkdf2_hmac_wycheproof(__FUNCTION__, DIGEST_sha512(),
		pbkdf2_hmac_sha512_tests,
		sizeof(pbkdf2_hmac_sha512_tests)/sizeof(pbkdf2_hmac_sha512_tests[0]));
}
#endif

int main(void)
{

#ifdef ENABLE_SHA1
	if (test_pbkdf2_hmac_sha1_wycheproof() != 1) goto err;
#endif
#ifdef ENABLE_SHA2
	if (test_pbkdf2_hmac_sha224_wycheproof() != 1) goto err;
	if (test_pbkdf2_hmac_sha256_wycheproof() != 1) goto err;
	if (test_pbkdf2_hmac_sha384_wycheproof() != 1) goto err;
	if (test_pbkdf2_hmac_sha512_wycheproof() != 1) goto err;
#endif

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
