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
#include <gmssl/secp256r1_ecdsa.h>

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
	SECP256R1_ECDSA_SIGNATURE sig;
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
	if (secp256r1_ecdsa_do_sign_ex(&key, k, dgst, sizeof(dgst), &sig) != 1) {
		error_print();
		return -1;
	}
	*/

	if (secp256r1_ecdsa_do_sign(&key, dgst, sizeof(dgst), &sig) != 1) {
		error_print();
		return -1;
	}



	secp256r1_print(stderr, 0, 0, "r", sig.r);
	secp256r1_print(stderr, 0, 0, "s", sig.s);


	if (secp256r1_ecdsa_do_verify(&key, dgst, sizeof(dgst), &sig) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_ecdsa_verify_infinity(void)
{
	SECP256R1_KEY key;
	SECP256R1_ECDSA_SIGNATURE sig;
	secp256r1_t d;
	uint8_t dgst[32];
	size_t dgstlen;

	if (secp256r1_set_one(d) != 1
		|| secp256r1_key_set_private_key(&key, d) != 1
		|| secp256r1_set_one(sig.r) != 1
		|| secp256r1_set_one(sig.s) != 1) {
		error_print();
		return -1;
	}

	// e = n - 1, so u1 * G + u2 * Q = (n - 1)G + G = O for Q = G
	if (hex_to_bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550",
			64, dgst, &dgstlen) != 1
		|| dgstlen != sizeof(dgst)) {
		error_print();
		return -1;
	}
	if (secp256r1_ecdsa_do_verify(&key, dgst, sizeof(dgst), &sig) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_ecdsa_digest_lengths(void)
{
	SECP256R1_KEY key;
	uint8_t dgst32[32];
	uint8_t dgst48[48];
	uint8_t dgst31[31];
	uint8_t sig[SECP256R1_ECDSA_SIGNATURE_MAX_SIZE];
	size_t siglen;

	if (secp256r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	memset(dgst32, 0x32, sizeof(dgst32));
	memset(dgst48, 0x48, sizeof(dgst48));
	memset(dgst31, 0x31, sizeof(dgst31));

	if (secp256r1_ecdsa_sign(&key, dgst32, sizeof(dgst32), sig, &siglen) != 1
		|| siglen > sizeof(sig)
		|| secp256r1_ecdsa_verify(&key, dgst32, sizeof(dgst32), sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_ecdsa_sign(&key, dgst48, sizeof(dgst48), sig, &siglen) != 1
		|| siglen > sizeof(sig)
		|| secp256r1_ecdsa_verify(&key, dgst48, sizeof(dgst48), sig, siglen) != 1
		|| secp256r1_ecdsa_sign_fixlen(&key, dgst48, sizeof(dgst48), siglen, sig) != 1
		|| secp256r1_ecdsa_verify(&key, dgst48, sizeof(dgst48), sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_ecdsa_sign(&key, dgst31, sizeof(dgst31), sig, &siglen) >= 0
		|| secp256r1_ecdsa_verify(&key, dgst31, sizeof(dgst31), sig, siglen) >= 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_ecdsa_generic(void)
{
	EC_KEY key;
	uint8_t dgst32[32];
	uint8_t dgst48[48];
	uint8_t sig[SECP256R1_ECDSA_SIGNATURE_MAX_SIZE];
	size_t siglen;

	key.oid = OID_secp256r1;
	if (secp256r1_key_generate(&key.u.secp256r1_key) != 1) {
		error_print();
		return -1;
	}
	memset(dgst32, 0x11, sizeof(dgst32));
	memset(dgst48, 0x22, sizeof(dgst48));

	if (ecdsa_sign(&key, dgst32, sizeof(dgst32), sig, &siglen) != 1
		|| siglen > sizeof(sig)
		|| ecdsa_verify(&key, dgst32, sizeof(dgst32), sig, siglen) != 1) {
		error_print();
		return -1;
	}
	dgst32[0] ^= 0x01;
	if (ecdsa_verify(&key, dgst32, sizeof(dgst32), sig, siglen) != 0) {
		error_print();
		return -1;
	}

	if (ecdsa_sign(&key, dgst48, sizeof(dgst48), sig, &siglen) != 1
		|| siglen > sizeof(sig)
		|| ecdsa_verify(&key, dgst48, sizeof(dgst48), sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (ecdsa_sign_fixed_len(&key, dgst48, sizeof(dgst48), siglen, sig) != 1
		|| ecdsa_verify(&key, dgst48, sizeof(dgst48), sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (ecdsa_sign(&key, dgst32, 31, sig, &siglen) >= 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_ecdsa() != 1) goto err;
	if (test_ecdsa_verify_infinity() != 1) goto err;
	if (test_ecdsa_digest_lengths() != 1) goto err;
	if (test_ecdsa_generic() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
