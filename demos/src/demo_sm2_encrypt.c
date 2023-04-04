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
	unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
	unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
	size_t len;

	sm2_key_generate(&sm2_key);
	memcpy(&pub_key, &sm2_key, sizeof(SM2_POINT));

	sm2_encrypt(&pub_key, (uint8_t *)"hello world", strlen("hello world"), ciphertext, &len);
	format_bytes(stdout, 0, 0, "ciphertext", ciphertext, len);

	if (sm2_decrypt(&sm2_key, ciphertext, len, plaintext, &len) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}
	plaintext[len] = 0;
	printf("plaintext: %s\n", plaintext);

	return 0;
}
