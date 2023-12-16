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
#include <gmssl/pbkdf2.h>


int main(int argc, char **argv)
{
	char *pass = "P@ssw0rd";
	uint8_t salt[8];
	size_t iter = 8000;
	uint8_t key[16];
	size_t i;

	if (rand_bytes(salt, sizeof(salt)) != 1) {
		fprintf(stderr, "rand_bytes() error\n");
		return -1;
	}

	if (pbkdf2_hmac_sm3_genkey(pass, strlen(pass), salt, sizeof(salt), iter, sizeof(key), key) != 1) {
		fprintf(stderr, "pbkdf2 error\n");
		return -1;
	}

	printf("pbkdf2('%s') = ", pass);
	for (i = 0; i < sizeof(key); i++) {
		printf("%02x", key[i]);
	}
	printf("\n");

	return 0;
}
