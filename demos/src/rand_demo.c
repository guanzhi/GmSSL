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
#include <gmssl/rand.h>


int main(int argc, char **argv)
{
	uint8_t buf[1024];
	size_t i;

	if (rand_bytes(buf, 32) != 1) {
		fprintf(stderr, "rand_bytes() failure\n");
		return 1;
	}
	printf("rand_bytes() output: ");
	for (i = 0; i < 32; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");

	if (rand_bytes(buf, sizeof(buf)) != 1) {
		fprintf(stderr, "rand_bytes() failure, maybe %zu is too long\n", sizeof(buf));
		return 1;
	}

	return 0;
}
