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


int main(void)
{
	SM3_KDF_CTX kdf_ctx;
	unsigned char key[16] = {0};
	unsigned char raw[32] = {
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
	};
	int i;

	sm3_kdf_init(&kdf_ctx, sizeof(key));
	sm3_kdf_update(&kdf_ctx, raw, sizeof(raw));
	sm3_kdf_finish(&kdf_ctx, key);

	printf("key: ");
	for (i = 0; i < sizeof(key); i++) {
		printf("%02X", key[i]);
	}
	printf("\n");

	return 0;
}
