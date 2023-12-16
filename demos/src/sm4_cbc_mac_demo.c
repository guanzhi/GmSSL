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
#include <gmssl/sm4_cbc_mac.h>


int main(int argc, char **argv)
{
	SM4_CBC_MAC_CTX ctx;
	uint8_t key[16] = {0};
	uint8_t data[16 * 3] = {0};
	uint8_t mac[16] = {0};
	size_t i;

	if (sizeof(data) % SM4_BLOCK_SIZE != 0) {
		fprintf(stderr, "CBC_MAC data length error\n");
		goto err;
	}

	sm4_cbc_mac_init(&ctx, key);
	sm4_cbc_mac_update(&ctx, data, sizeof(data));
	sm4_cbc_mac_finish(&ctx, mac);

	printf("cbc_mac = ");
	for (i = 0; i < sizeof(mac); i++) {
		printf("%02x", mac[i]);
	}
	printf("\n");

err:
	return 0;
}
