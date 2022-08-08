/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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
