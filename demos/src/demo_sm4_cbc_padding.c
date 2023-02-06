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
#include <gmssl/sm4.h>
#include <gmssl/rand.h>


int main(void)
{
	SM4_KEY sm4_key;
	unsigned char key[16];
	unsigned char iv[16];
	unsigned char mbuf[32] = {
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
	};
	unsigned char cbuf[32] = {0};
	unsigned char pbuf[32] = {0};
	size_t mlen1 = 20, mlen2 = 16;
	size_t clen1, clen2;
	size_t plen1, plen2;
	int i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));

	printf("key: ");
	for (i = 0; i < sizeof(key); i++) {
		printf("%02X", key[i]);
	}
	printf("\n");

	printf("iv: ");
	for (i = 0; i < sizeof(iv); i++) {
		printf("%02X", iv[i]);
	}
	printf("\n");


	printf("sm4_cbc_pading encrypt %zu bytes\n", mlen1);

	printf("plaintext: ");
	for (i = 0; i < mlen1; i++) {
		printf("%02X", mbuf[i]);
	}
	printf("\n");

	sm4_set_encrypt_key(&sm4_key, key);
	sm4_cbc_padding_encrypt(&sm4_key, iv, mbuf, mlen1, cbuf, &clen1);

	printf("ciphertext: ");
	for (i = 0; i < clen1; i++) {
		printf("%02X", cbuf[i]);
	}
	printf("\n");

	sm4_set_decrypt_key(&sm4_key, key);
	sm4_cbc_padding_decrypt(&sm4_key, iv, cbuf, clen1, pbuf, &plen1);

	printf("decrypted: ");
	for (i = 0; i < plen1; i++) {
		printf("%02X", pbuf[i]);
	}
	printf("\n");

	printf("sm4_cbc_pading encrypt %zu bytes\n", mlen2);

	printf("plaintext: ");
	for (i = 0; i < mlen2; i++) {
		printf("%02X", mbuf[i]);
	}
	printf("\n");

	sm4_set_encrypt_key(&sm4_key, key);
	sm4_cbc_padding_encrypt(&sm4_key, iv, mbuf, mlen2, cbuf, &clen2);

	printf("ciphertext: ");
	for (i = 0; i < clen2; i++) {
		printf("%02X", cbuf[i]);
	}
	printf("\n");

	sm4_set_decrypt_key(&sm4_key, key);
	sm4_cbc_padding_decrypt(&sm4_key, iv, cbuf, clen2, pbuf, &plen2);

	printf("decrypted: ");
	for (i = 0; i < plen2; i++) {
		printf("%02X", pbuf[i]);
	}
	printf("\n");


	return 0;
}
