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
#include <gmssl/secp384r1.h>

static int test_secp384r1_ecdsa_do_sign(void)
{
	SECP384R1_KEY key;
	SECP384R1_ECDSA_SIGNATURE sig;
	uint8_t dgst[48];
	secp384r1_t d;
	secp384r1_t k;

	// d = 5
	bn_set_word(d, 5, 8);
	secp384r1_key_set_private_key(&key, d);

	secp384r1_private_key_print(stderr, 0, 0, "private_key", &key);

	// k = 3
	bn_set_word(k, 3, 8);

	// e = 2
	memset(dgst, 0, sizeof(dgst));
	dgst[47] = 2;

	if (secp384r1_ecdsa_do_sign_ex(&key, k, dgst, sizeof(dgst), &sig) != 1) {
		error_print();
		return -1;
	}

	secp384r1_print(stderr, 0, 0, "r", sig.r);
	secp384r1_print(stderr, 0, 0, "s", sig.s);


	if (secp384r1_ecdsa_do_verify(&key, dgst, sizeof(dgst), &sig) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp384r1_ecdsa_sign(void)
{
	SECP384R1_KEY key;
	uint8_t dgst32[32];
	uint8_t dgst48[48];
	uint8_t dgst31[31];
	uint8_t sig[SECP384R1_ECDSA_SIGNATURE_MAX_SIZE];
	size_t siglen;

	if (secp384r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	memset(dgst32, 0x32, sizeof(dgst32));
	memset(dgst48, 0x48, sizeof(dgst48));
	memset(dgst31, 0x31, sizeof(dgst31));

	if (secp384r1_ecdsa_sign(&key, dgst48, sizeof(dgst48), sig, &siglen) != 1
		|| siglen > sizeof(sig)) {
		error_print();
		return -1;
	}
	if (secp384r1_ecdsa_verify(&key, dgst48, sizeof(dgst48), sig, siglen) != 1) {
		error_print();
		return -1;
	}
	dgst48[0] ^= 0x01;
	if (secp384r1_ecdsa_verify(&key, dgst48, sizeof(dgst48), sig, siglen) != 0) {
		error_print();
		return -1;
	}
	if (secp384r1_ecdsa_sign(&key, dgst32, sizeof(dgst32), sig, &siglen) != 1
		|| siglen > sizeof(sig)
		|| secp384r1_ecdsa_verify(&key, dgst32, sizeof(dgst32), sig, siglen) != 1
		|| secp384r1_ecdsa_sign_fixlen(&key, dgst32, sizeof(dgst32), siglen, sig) != 1
		|| secp384r1_ecdsa_verify(&key, dgst32, sizeof(dgst32), sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (secp384r1_ecdsa_sign(&key, dgst31, sizeof(dgst31), sig, &siglen) >= 0
		|| secp384r1_ecdsa_verify(&key, dgst31, sizeof(dgst31), sig, siglen) >= 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp384r1_ecdsa_ctx(void)
{
	SECP384R1_KEY key;
	SECP384R1_ECDSA_SIGN_CTX sign_ctx;
	SECP384R1_ECDSA_SIGN_CTX verify_ctx;
	uint8_t sig[SECP384R1_ECDSA_SIGNATURE_MAX_SIZE];
	size_t siglen;
	uint8_t msg[] = "message";

	if (secp384r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (secp384r1_ecdsa_sign_init(&sign_ctx, &key, NULL) != 1
		|| secp384r1_ecdsa_sign_update(&sign_ctx, msg, sizeof(msg) - 1) != 1
		|| secp384r1_ecdsa_sign_finish(&sign_ctx, sig, &siglen) != 1
		|| siglen > sizeof(sig)) {
		error_print();
		return -1;
	}
	if (secp384r1_ecdsa_verify_init(&verify_ctx, &key, NULL, sig, siglen) != 1
		|| secp384r1_ecdsa_verify_update(&verify_ctx, msg, sizeof(msg) - 1) != 1
		|| secp384r1_ecdsa_verify_finish(&verify_ctx) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp384r1_ecdsa_verify_infinity(void)
{
	SECP384R1_KEY key;
	SECP384R1_ECDSA_SIGNATURE sig;
	secp384r1_t d;
	uint8_t dgst[48];
	size_t dgstlen;

	if (secp384r1_set_one(d) != 1
		|| secp384r1_key_set_private_key(&key, d) != 1
		|| secp384r1_set_one(sig.r) != 1
		|| secp384r1_set_one(sig.s) != 1) {
		error_print();
		return -1;
	}

	// e = n - 1, so u1 * G + u2 * Q = (n - 1)G + G = O for Q = G
	if (hex_to_bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52972",
			96, dgst, &dgstlen) != 1
		|| dgstlen != sizeof(dgst)) {
		error_print();
		return -1;
	}
	if (secp384r1_ecdsa_do_verify(&key, dgst, sizeof(dgst), &sig) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_secp384r1_ecdsa_do_sign() != 1) goto err;
	if (test_secp384r1_ecdsa_sign() != 1) goto err;
	if (test_secp384r1_ecdsa_ctx() != 1) goto err;
	if (test_secp384r1_ecdsa_verify_infinity() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
