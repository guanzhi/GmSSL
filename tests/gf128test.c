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
#include <assert.h>
#include <gmssl/hex.h>
#include <gmssl/gf128.h>
#include <gmssl/error.h>


int test_gf128_from_hex(void)
{
	char *tests[] = {
		"00000000000000000000000000000000",
		"00000000000000000000000000000001",
		"10000000000000000000000000000000",
		"de300f9301a499a965f8bf677e99e80d",
		"14b267838ec9ef1bb7b5ce8c19e34bc6",
	};
	gf128_t a;
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		a = gf128_from_hex(tests[i]);
		if (gf128_equ_hex(a, tests[i]) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_gf128_mul2(void)
{
	char *tests[] = {
		"00000000000000000000000000000001",
		"de300f9301a499a965f8bf677e99e80d",
	};
	char *results[] = {
		"e1000000000000000000000000000000",
		"8e1807c980d24cd4b2fc5fb3bf4cf406",
	};
	gf128_t a;
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		a = gf128_from_hex(tests[i]);
		a = gf128_mul2(a);
		if (gf128_equ_hex(a, results[i]) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_gf128_mul(void)
{
	char *hex_a = "de300f9301a499a965f8bf677e99e80d";
	char *hex_b = "14b267838ec9ef1bb7b5ce8c19e34bc6";
	char *hex_add_a_b = "ca8268108f6d76b2d24d71eb677aa3cb";
	char *hex_mul_a_b = "7d87dda57a20b0c51d9743071ab14010";
	gf128_t a, b, r;

	a = gf128_from_hex(hex_a);
	b = gf128_from_hex(hex_b);

	r = gf128_add(a, b);
	if (gf128_equ_hex(r, hex_add_a_b) != 1) {
		error_print();
		return -1;
	}

	r = gf128_mul(a, b);
	if (gf128_equ_hex(r, hex_mul_a_b) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_gf128_from_hex() != 1) goto err;
	if (test_gf128_mul2() != 1) goto err;
	if (test_gf128_mul() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;

}
