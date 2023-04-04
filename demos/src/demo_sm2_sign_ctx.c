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
#include <gmssl/sm2.h>
#include <gmssl/error.h>


int main(void)
{
	SM2_KEY sm2_key;
	SM2_KEY pub_key;
	SM2_SIGN_CTX sign_ctx;
	unsigned char dgst[32];
	unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	int ret;

	sm2_key_generate(&sm2_key);

	memcpy(&pub_key, &sm2_key, sizeof(SM2_POINT));

	// sign without signer ID (and Z value)
	sm2_sign_init(&sign_ctx, &sm2_key, NULL, 0);
	sm2_sign_update(&sign_ctx, (unsigned char *)"hello ", strlen("hello "));
	sm2_sign_update(&sign_ctx, (unsigned char *)"world", strlen("world"));
	sm2_sign_finish(&sign_ctx, sig, &siglen);
	format_bytes(stdout, 0, 0, "signature", sig, siglen);

	// digest and verify
	sm3_digest((unsigned char *)"hello world", strlen("hello world"), dgst);
	ret = sm2_verify(&pub_key, dgst, sig, siglen);
	printf("verify result: %s\n", ret == 1 ? "success" : "failure");

	// use verify update API
	sm2_verify_init(&sign_ctx, &pub_key, NULL, 0);
	sm2_verify_update(&sign_ctx, (unsigned char *)"hello world", strlen("hello world"));
	ret = sm2_verify_finish(&sign_ctx, sig, siglen);
	printf("verify result: %s\n", ret == 1 ? "success" : "failure");

	// sign use default signer ID
	sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	sm2_sign_update(&sign_ctx, (unsigned char *)"hello ", strlen("hello "));
	sm2_sign_update(&sign_ctx, (unsigned char *)"world", strlen("world"));
	sm2_sign_finish(&sign_ctx, sig, &siglen);
	format_bytes(stdout, 0, 0, "signature", sig, siglen);

	sm2_verify_init(&sign_ctx, &pub_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	sm2_verify_update(&sign_ctx, (unsigned char *)"hello world", strlen("hello world"));
	ret = sm2_verify_finish(&sign_ctx, sig, siglen);
	printf("verify result: %s\n", ret == 1 ? "success" : "failure");

	return 0;
}
