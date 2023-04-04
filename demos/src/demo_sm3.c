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
#include <gmssl/sm3.h>


int main(int argc, char **argv)
{
	SM3_CTX sm3_ctx;
	uint8_t buf[4096];
	size_t len;
	uint8_t dgst[32];
	int i;

	sm3_init(&sm3_ctx);
	while ((len = fread(buf, 1, sizeof(buf), stdin)) > 0) {
		sm3_update(&sm3_ctx, buf, len);
	}
	sm3_finish(&sm3_ctx, dgst);

	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");
	return 0;
}
