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
#include <gmssl/sm3.h>


int main(void)
{
	SM3_CTX sm3_ctx;
	uint8_t dgst[SM3_DIGEST_SIZE];
	size_t i;

	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, (uint8_t *)"a", 1);
	sm3_update(&sm3_ctx, (uint8_t *)"bc", 2);
	sm3_finish(&sm3_ctx, dgst);

	printf("sm3('abc') = ");
	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");

	return 0;
}
