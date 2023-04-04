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
	SM3_HMAC_CTX hmac_ctx;
	unsigned char key[16] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x01,0xf2,0x03,0x04,0x05,0x06,0x07,0x08,
	};
	unsigned char mbuf[16] = {
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
	};
	unsigned char hmac[32] = {0};
	int i;


	sm3_hmac_init(&hmac_ctx, key, sizeof(key));
	sm3_hmac_update(&hmac_ctx, mbuf, sizeof(mbuf));
	sm3_hmac_finish(&hmac_ctx, hmac);

	printf("hmac: ");
	for (i = 0; i < sizeof(hmac); i++) {
		printf("%02X", hmac[i]);
	}
	printf("\n");

	memset(hmac, 0, sizeof(hmac));
	sm3_hmac(key, sizeof(key), mbuf, sizeof(mbuf), hmac);

	printf("hmac: ");
	for (i = 0; i < sizeof(hmac); i++) {
		printf("%02X", hmac[i]);
	}
	printf("\n");

	return 0;
}
