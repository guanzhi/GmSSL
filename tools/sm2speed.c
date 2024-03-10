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
#include <gmssl/sm2.h>
#include <gmssl/error.h>

int sm2sign_speed(void)
{
	SM2_KEY sm2_key;
	SM2_SIGN_CTX sign_ctx;
	uint8_t msg[32];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	size_t i;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
		error_print();
		return -1;
	}

	for (i = 0; i < 10000; i++) {
		/*
		if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
			error_print();
			return -1;
		}
		*/
		if (sm2_sign_ctx_reset(&sign_ctx) != 1
			|| sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1
			|| sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
			error_print();
			return -1;
		}
	}

	return 0;
}

int main(void)
{
	sm2sign_speed();
	return 0;
}

