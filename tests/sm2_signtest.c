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
#include <gmssl/asn1.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm2_z256.h>
#include <gmssl/pkcs8.h>


static int test_sm2_signature(void)
{
	SM2_SIGNATURE sig;
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	// MinLen
	memset(&sig, 0x00, sizeof(sig));
	cp = p = buf; len = 0;
	if (sm2_signature_to_der(&sig, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MIN_SIGNATURE_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	sm2_signature_print(stderr, 0, 4, "signature", buf, len);
	if (len != SM2_MIN_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_signature_from_der(&sig, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}


	// MaxLen
	memset(&sig, 0x80, sizeof(sig));
	cp = p = buf; len = 0;
	if (sm2_signature_to_der(&sig, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MAX_SIGNATURE_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	sm2_signature_print(stderr, 0, 4, "signature", buf, len);
	if (len != SM2_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_signature_from_der(&sig, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#define TEST_COUNT 20

static int test_sm2_do_sign(void)
{
	SM2_KEY sm2_key;
	uint8_t dgst[32];
	SM2_SIGNATURE sig;
	size_t i;

	for (i = 0; i < TEST_COUNT; i++) {

		if (sm2_key_generate(&sm2_key) != 1) {
			error_print();
			return -1;
		}
		rand_bytes(dgst, 32);

		if (sm2_do_sign(&sm2_key, dgst, &sig) != 1) {
			error_print();
			return -1;
		}
		if (sm2_do_verify(&sm2_key, dgst, &sig) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_fast_sign(void)
{
	SM2_KEY sm2_key;
	sm2_z256_t fast_private;
	uint8_t dgst[32];
	SM2_SIGNATURE sig;
	size_t i;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	if (sm2_fast_sign_compute_key(&sm2_key, fast_private) != 1) {
		error_print();
		return -1;
	}
	rand_bytes(dgst, sizeof(dgst));

	for (i = 0; i < TEST_COUNT; i++) {
		sm2_z256_t k;
		sm2_z256_t x1_modn;

		if (sm2_fast_sign_pre_compute(k, x1_modn) != 1) {
			error_print();
			return -1;
		}
		if (sm2_fast_sign(fast_private, k, x1_modn, dgst, &sig) != 1) {
			error_print();
			return -1;
		}

		if (sm2_do_verify(&sm2_key, dgst, &sig) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_do_sign_pre_compute(void)
{
	SM2_KEY sm2_key;
	uint64_t d[4];

	uint64_t k[4];
	uint64_t x1[4];
	uint8_t dgst[32];
	SM2_SIGNATURE sig;


	sm2_key_generate(&sm2_key);

		const uint64_t *one = sm2_z256_one();
		sm2_z256_copy(d, sm2_key.private_key);
		sm2_z256_modn_add(d, d, one);
		sm2_z256_modn_inv(d, d);

	if (sm2_fast_sign_pre_compute(k, x1) != 1) {
		error_print();
		return -1;
	}

	rand_bytes(dgst, sizeof(dgst));

	if (sm2_fast_sign(d, k, x1, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	if (sm2_do_verify(&sm2_key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_sign(void)
{
	SM2_KEY sm2_key;
	uint8_t dgst[32];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	size_t i;

	for (i = 0; i < TEST_COUNT; i++) {

		if (sm2_key_generate(&sm2_key) != 1) {
			error_print();
			return -1;
		}
		rand_bytes(dgst, 32);

		if (sm2_sign(&sm2_key, dgst, sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		if (sm2_verify(&sm2_key, dgst, sig, siglen) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_sign_ctx(void)
{
	int ret;
	SM2_KEY sm2_key;
	SM2_SIGN_CTX sign_ctx;
	uint8_t msg[] = "Hello World!";
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE] = {0};
	size_t siglen;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "signature", sig, siglen);
	sm2_signature_print(stderr, 0, 4, "signature", sig, siglen);

	if (sm2_verify_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_verify_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| (ret = sm2_verify_finish(&sign_ctx, sig, siglen)) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "verification: %s\n", ret ? "success" : "failed");

	// FIXME: 还应该增加验证不通过的测试
	// 还应该增加底层的参数
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_sign_ctx_reset(void)
{
	SM2_KEY sm2_key;
	SM2_SIGN_CTX sign_ctx;
	SM2_SIGN_CTX vrfy_ctx;
	uint8_t msg[64];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	// init sign_ctx and sign a message
	rand_bytes(msg, sizeof(msg));

	if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
		error_print();
		return -1;
	}
	if (sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	// reset sign_ctx and sign another message
	rand_bytes(msg, sizeof(msg));

	if (sm2_sign_ctx_reset(&sign_ctx) != 1) {
		error_print();
		return -1;
	}
	if (sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	// verify, check whether reset works
	if (sm2_verify_init(&vrfy_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
		error_print();
		return -1;
	}
	if (sm2_verify_update(&vrfy_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_verify_finish(&vrfy_ctx, sig, siglen) != 1) {
		format_bytes(stderr, 0, 4, "signature", sig, siglen);
		error_print();
		return -1;
	}

	// reset ctx and verify again
	if (sm2_sign_ctx_reset(&vrfy_ctx) != 1) {
		error_print();
		return -1;
	}
	if (sm2_verify_update(&vrfy_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_verify_finish(&vrfy_ctx, sig, siglen) != 1) {
		format_bytes(stderr, 0, 4, "signature", sig, siglen);
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm2_signature() != 1) goto err;
	if (test_sm2_do_sign() != 1) goto err;
	if (test_sm2_do_sign_pre_compute() != 1) goto err;
	if (test_sm2_fast_sign() != 1) goto err;
	if (test_sm2_sign() != 1) goto err;
	if (test_sm2_sign_ctx() != 1) goto err;
	if (test_sm2_sign_ctx_reset() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}

