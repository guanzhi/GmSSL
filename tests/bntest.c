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
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/bn.h>


static int test_print_consts(void)
{
	// secp256r1 parameters
	char *p = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
	char *b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
	char *x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
	char *y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
	char *n = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
	char *u_p = "0000000100000000fffffffffffffffefffffffefffffffeffffffff0000000000000003"; // floor(2^512/p)
	char *u_n = "0000000100000000fffffffffffffffeffffffff43190552df1a6c21012ffd85eedf9bfe"; // floor(2^512/n)

	int k = 8;
	uint32_t bn[9];
	uint8_t buf[36];
	size_t len;

	hex_to_bytes(p, 64, buf, &len);
	bn_from_bytes(bn, k, buf);
	bn_print(stderr, 0, 4, "p", bn, k);

	hex_to_bytes(b, 64, buf, &len);
	bn_from_bytes(bn, k, buf);
	bn_print(stderr, 0, 4, "a", bn, k);

	hex_to_bytes(x, 64, buf, &len);
	bn_from_bytes(bn, k, buf);
	bn_print(stderr, 0, 4, "x", bn, k);

	hex_to_bytes(y, 64, buf, &len);
	bn_from_bytes(bn, k, buf);
	bn_print(stderr, 0, 4, "y", bn, k);

	hex_to_bytes(n, 64, buf, &len);
	bn_from_bytes(bn, k, buf);
	bn_print(stderr, 0, 4, "n", bn, k);

	hex_to_bytes(u_p, 72, buf, &len);
	bn_from_bytes(bn, k + 1, buf);
	bn_print(stderr, 0, 4, "u_p = 2^512//p", bn, k + 1);

	hex_to_bytes(u_n, 72, buf, &len);
	bn_from_bytes(bn, k + 1, buf);
	bn_print(stderr, 0, 4, "u_n = 2^512//n", bn, k + 1);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1(void)
{
	char *x_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
	char *p_hex = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";

	int c;

	uint32_t a[8];
	uint32_t r[8];
	uint8_t buf[32];
	size_t len;

	hex_to_bytes(x_hex, 64, buf, &len);

	bn_from_bytes(a, 8, buf);





	bn_add(r, a, a, 8);
	bn_add(r, r, a, 8);

	bn_print(stderr, 0, 4, "3*x", a, 8);

	uint32_t p[8];

	hex_to_bytes(p_hex, 64, buf, &len);
	bn_from_bytes(p, 8, buf);


	c = bn_sub(r, a, p, 8);
	printf("carray = %d\n", c);


	// 我知道了，这里有一个进位被忽略了
	if (bn_cmp(a, p, 8) >= 0) {
		error_print();
	} else {
		error_print();
	}




	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_print_consts() != 1) goto err;
	if (test_secp256r1() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
