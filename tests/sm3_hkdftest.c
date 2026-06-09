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
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/hkdf.h>
#include <gmssl/error.h>
#include "sm3_hkdftest.h"

static int test_sm3_hkdf_wycheproof(void)
{
	size_t i;

	for (i = 0; i < sizeof(test_sm3_hkdf_vectors)/sizeof(test_sm3_hkdf_vectors[0]); i++) {
		const TEST_SM3_HKDF_VECTOR *tv = &test_sm3_hkdf_vectors[i];
		uint8_t ikm[80];
		uint8_t salt[80];
		uint8_t info[80];
		uint8_t prk[32];
		uint8_t okm[32 * 255]; // = 8160
		uint8_t expected[32 * 255]; // = 8160
		size_t ikmlen, saltlen, infolen, expected_len;
		int ret;

		if (strlen(tv->ikm)/2 > sizeof(ikm)
			|| strlen(tv->salt)/2 > sizeof(salt)
			|| strlen(tv->info)/2 > sizeof(info)
			|| strlen(tv->okm)/2 > sizeof(expected)) {
			error_print();
			return -1;
		}
		if (hex_to_bytes(tv->ikm, strlen(tv->ikm), ikm, &ikmlen) != 1
			|| hex_to_bytes(tv->salt, strlen(tv->salt), salt, &saltlen) != 1
			|| hex_to_bytes(tv->info, strlen(tv->info), info, &infolen) != 1
			|| hex_to_bytes(tv->okm, strlen(tv->okm), expected, &expected_len) != 1) {
			error_print();
			return -1;
		}
		if (tv->result == TEST_RESULT_VALID) {
			if (expected_len != tv->size) {
				error_print();
				return -1;
			}
		}

		if (sm3_hkdf_extract(salt, saltlen, ikm, ikmlen, prk) != 1) {
			error_print();
			return -1;
		}
		ret = sm3_hkdf_expand(prk, info, infolen, tv->size, okm);

		if (tv->result == TEST_RESULT_VALID) {
			if (ret != 1 || memcmp(okm, expected, expected_len) != 0) {
				error_print();
				return -1;
			}
		} else if (tv->result == TEST_RESULT_INVALID) {
			if (ret == 1) {
				error_print();
				return -1;
			}
			fprintf(stderr, "tcId %d expected HKDF-SM3 failure for %s\n", tv->tc_id, tv->flags);
		} else {
			if (ret != 1 && ret != -1) {
				error_print();
				return -1;
			}
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm3_hkdf_wycheproof() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
