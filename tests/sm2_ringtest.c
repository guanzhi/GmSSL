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
#include <gmssl/sm2.h>
#include <gmssl/sm2_ring.h>
#include <gmssl/error.h>


static int test_sm2_ring_do_sign(void)
{
	SM2_KEY sign_key;
	SM2_POINT public_keys[5];
	size_t public_keys_count = sizeof(public_keys)/sizeof(public_keys[0]);
	size_t sign_index, i;
	uint8_t dgst[32];
	uint8_t r[32];
	uint8_t s[sizeof(public_keys)/sizeof(public_keys[0])][32];

	for (sign_index = 0; sign_index < 5; sign_index++) {

		for (i = 0; i < public_keys_count; i++) {
			SM2_KEY key;
			sm2_key_generate(&key);
			memcpy(&public_keys[i], &(key.public_key), sizeof(SM2_POINT));

			if (i == sign_index) {
				memcpy(&sign_key, &key, sizeof(SM2_KEY));
			}
		}
		if (sm2_ring_do_sign(&sign_key, public_keys, public_keys_count, dgst, r, s) != 1) {
			error_print();
			return -1;
		}
		if (sm2_ring_do_verify(public_keys, public_keys_count, dgst, r, s) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_ring_sign(void)
{
	SM2_KEY sign_key;
	SM2_POINT public_keys[5];
	size_t public_keys_count = sizeof(public_keys)/sizeof(public_keys[0]);
	size_t sign_index = 2, i;
	uint8_t dgst[32];
	uint8_t sig[9 + (2 + 33) * (1 + sizeof(public_keys)/sizeof(public_keys[0]))];
	size_t siglen = 0;

	for (i = 0; i < public_keys_count; i++) {
		SM2_KEY key;
		sm2_key_generate(&key);
		memcpy(&public_keys[i], &(key.public_key), sizeof(SM2_POINT));

		if (i == sign_index) {
			memcpy(&sign_key, &key, sizeof(SM2_KEY));
		}
	}
	if (sm2_ring_sign(&sign_key, public_keys, public_keys_count, dgst, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_ring_verify(public_keys, 5, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_ring_sign_crosscheck(void)
{
	SM2_KEY sign_key;
	SM2_POINT public_key;
	uint8_t dgst[32];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen = 0;

	sm2_key_generate(&sign_key);
	public_key = sign_key.public_key;

	if (sm2_ring_sign(&sign_key, &public_key, 1, dgst, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_ring_verify(&public_key, 1, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_ring_sign_update(void)
{
	SM2_KEY keys[5];
	SM2_RING_SIGN_CTX sign_ctx;
	SM2_RING_SIGN_CTX verify_ctx;
	size_t public_keys_count = sizeof(keys)/sizeof(keys[0]);
	char *id = "Alice";
	uint8_t msg[128] = {0};
	uint8_t sig[9 + (2 + 33) * (1 + sizeof(keys)/sizeof(keys[0]))];
	size_t siglen = 0;
	size_t i;

	for (i = 0; i < public_keys_count; i++) {
		sm2_key_generate(&keys[i]);
	}

	if (sm2_ring_sign_init(&sign_ctx, &keys[0], id, strlen(id)) != 1) {
		error_print();
		return -1;
	}
	for (i = 1; i < public_keys_count; i++) {
		if (sm2_ring_sign_add_signer(&sign_ctx, &keys[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if (sm2_ring_sign_update(&sign_ctx, msg, 32) != 1
		|| sm2_ring_sign_update(&sign_ctx, msg + 32, 32) != 1
		|| sm2_ring_sign_update(&sign_ctx, msg + 64, 64) != 1
		|| sm2_ring_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	if (sm2_ring_verify_init(&verify_ctx, id, strlen(id)) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < public_keys_count; i++) {
		if (sm2_ring_verify_add_signer(&verify_ctx, &keys[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if (sm2_ring_verify_update(&verify_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_ring_verify_finish(&verify_ctx, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm2_ring_do_sign() != 1) { error_print(); return -1; }
	if (test_sm2_ring_sign() != 1) { error_print(); return -1; }
	if (test_sm2_ring_sign_crosscheck() != 1) { error_print(); return -1; }
	if (test_sm2_ring_sign_update() != 1) { error_print(); return -1; }
	return 0;
}
