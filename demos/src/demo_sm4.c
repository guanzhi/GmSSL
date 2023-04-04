/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

// sm4 demo1: encrypt and decrypt a block of message (16 bytes)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm4.h>


int main(void)
{
	SM4_KEY sm4_key;
	unsigned char key[16] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x01,0xf2,0x03,0x04,0x05,0x06,0x07,0x08,
	};
	unsigned char mbuf[16] = {
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
	};
	unsigned char cbuf[16];
	unsigned char pbuf[16];
	int i;

	printf("key: ");
	for (i = 0; i < sizeof(key); i++) {
		printf("%02X", key[i]);
	}
	printf("\n");

	printf("plaintext: ");
	for (i = 0; i < sizeof(mbuf); i++) {
		printf("%02X", mbuf[i]);
	}
	printf("\n");

	sm4_set_encrypt_key(&sm4_key, key);
	sm4_encrypt(&sm4_key, mbuf, cbuf);

	printf("ciphertext: ");
	for (i = 0; i < sizeof(cbuf); i++) {
		printf("%02X", cbuf[i]);
	}
	printf("\n");

	sm4_set_decrypt_key(&sm4_key, key);
	sm4_decrypt(&sm4_key, cbuf, pbuf);

	printf("decrypted: ");
	for (i = 0; i < sizeof(pbuf); i++) {
		printf("%02X", pbuf[i]);
	}
	printf("\n");

	return 0;
}
