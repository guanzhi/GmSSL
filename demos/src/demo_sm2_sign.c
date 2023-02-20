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
	unsigned char dgst[32];
	unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	int ret;

	sm3_digest((unsigned char *)"hello world", strlen("hello world"), dgst);
	format_bytes(stdout, 0, 0, "to be signed digest", dgst, sizeof(dgst));

	sm2_key_generate(&sm2_key);

	sm2_sign(&sm2_key, dgst, sig, &siglen);
	format_bytes(stdout, 0, 0, "signature", sig, siglen);

	memcpy(&pub_key, &sm2_key, sizeof(SM2_POINT));

	if ((ret = sm2_verify(&pub_key, dgst, sig, siglen)) != 1) {
		fprintf(stderr, "verify failed\n");
	} else {
		printf("verify success\n");
	}

	return 0;
}
