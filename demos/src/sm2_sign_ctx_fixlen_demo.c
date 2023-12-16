/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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


int main(void)
{
	SM2_KEY sm2_key;
	SM2_SIGN_CTX sign_ctx;
	unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;


	sm2_key_generate(&sm2_key);


	siglen = SM2_signature_compact_size;
	memset(sig, 0, sizeof(sig));
	if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| sm2_sign_update(&sign_ctx, (uint8_t *)"hello ", strlen("hello ")) != 1
		|| sm2_sign_update(&sign_ctx, (uint8_t *)"world", strlen("world")) != 1
		|| sm2_sign_finish_fixlen(&sign_ctx, siglen, sig) != 1) {
		fprintf(stderr, "error\n");
		goto err;
	}
	format_bytes(stdout, 0, 0, "sig", sig, sizeof(sig));


	siglen = SM2_signature_typical_size;
	memset(sig, 0, sizeof(sig));
	if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| sm2_sign_update(&sign_ctx, (uint8_t *)"hello ", strlen("hello ")) != 1
		|| sm2_sign_update(&sign_ctx, (uint8_t *)"world", strlen("world")) != 1
		|| sm2_sign_finish_fixlen(&sign_ctx, siglen, sig) != 1) {
		fprintf(stderr, "error\n");
		goto err;
	}
	format_bytes(stdout, 0, 0, "sig", sig, sizeof(sig));


	siglen = SM2_signature_max_size;
	memset(sig, 0, sizeof(sig));
	if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| sm2_sign_update(&sign_ctx, (uint8_t *)"hello ", strlen("hello ")) != 1
		|| sm2_sign_update(&sign_ctx, (uint8_t *)"world", strlen("world")) != 1
		|| sm2_sign_finish_fixlen(&sign_ctx, siglen, sig) != 1) {
		fprintf(stderr, "error\n");
		goto err;
	}
	format_bytes(stdout, 0, 0, "sig", sig, sizeof(sig));

err:
	return 0;
}
