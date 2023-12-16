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
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


int main(void)
{
	SM4_KEY sm4_key;
	uint8_t key[SM4_KEY_SIZE];
	int i;

	rand_bytes(key, sizeof(key));

	format_bytes(stdout, 0, 0, "SM4 Raw Key", key, sizeof(key));
	printf("\n");

	sm4_set_encrypt_key(&sm4_key, key);

	printf("SM4 Round Keys for Encryption\n");
	for (i = 0; i < SM4_NUM_ROUNDS; i++) {
		printf("    %08x\n", sm4_key.rk[i]);
	}
	printf("\n");

	sm4_set_decrypt_key(&sm4_key, key);

	printf("SM4 Round Keys for Decryption\n");
	for (i = 0; i < SM4_NUM_ROUNDS; i++) {
		printf("    %08x\n", sm4_key.rk[i]);
	}
	printf("\n");

	return 0;
}
