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
#include <gmssl/bn.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/ecdsa.h>

/*
d  0x5
xP 0x51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed
yP 0xe0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4
x1 0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c
r  0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c
s  0x48a928086a55111cf99d39f886293cff41a8dda957c43b0851846697f76199ef
x1 0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c
v  0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c
*/

// 这个签名是没有问题的，看来验证签名是有问题的
static int test_ecdsa(void)
{
	SECP256R1_KEY key;
	ECDSA_SIGNATURE sig;
	uint8_t dgst[32];
	secp256r1_t d;
	secp256r1_t k;

	// d = 5
	bn_set_word(d, 5, 8);
	secp256r1_key_set_private_key(&key, d);

	secp256r1_key_generate(&key);

	secp256r1_private_key_print(stderr, 0, 0, "private_key", &key);

	// k = 3
	bn_set_word(k, 3, 8);

	// e = 2
	memset(dgst, 0, 31);
	dgst[31] = 2;

	/*
	if (ecdsa_do_sign_ex(&key, k, dgst, &sig) != 1) {
		error_print();
		return -1;
	}
	*/

	if (ecdsa_do_sign(&key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}



	secp256r1_print(stderr, 0, 0, "r", sig.r);
	secp256r1_print(stderr, 0, 0, "s", sig.s);


	if (ecdsa_do_verify(&key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_ecdsa() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
