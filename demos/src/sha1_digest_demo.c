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
#include <gmssl/sha1.h>


int main(int argc, char **argv)
{
	uint8_t dgst[SHA1_DIGEST_SIZE];
	size_t i;

	sha1_digest((uint8_t *)"abc", 3, dgst);

	printf("sha1('abc') = ");
	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");

	return 0;
}
