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
	unsigned char key[SM4_KEY_SIZE];
	uint8_t data[SM4_BLOCK_SIZE * 3];
	uint8_t *p;
	size_t i;

	rand_bytes(key, sizeof(key));

	// Plaintext block #1 and #3 are the same
	rand_bytes(data, SM4_BLOCK_SIZE * 2);
	memcpy(data + SM4_BLOCK_SIZE * 2, data, SM4_BLOCK_SIZE);

	format_bytes(stdout, 0, 0, "key", key, sizeof(key));
	format_bytes(stdout, 0, 0, "ECB Plaintext ", data, sizeof(data));

	// SM4-ECB encrypt
	sm4_set_encrypt_key(&sm4_key, key);

	p = data;
	for (i = 0; i < sizeof(data)/SM4_BLOCK_SIZE; i++) {
		sm4_encrypt(&sm4_key, p, p);
		p += SM4_BLOCK_SIZE;
	}
	format_bytes(stdout, 0, 0, "ECB Ciphertext", data, sizeof(data));

	// SM4-ECB decrypt
	sm4_set_decrypt_key(&sm4_key, key);

	p = data;
	for (i = 0; i < sizeof(data)/SM4_BLOCK_SIZE; i++) {
		sm4_decrypt(&sm4_key, p, p);
		p += SM4_BLOCK_SIZE;
	}
	format_bytes(stdout, 0, 0, "ECB Plaintext ", data, sizeof(data));

	return 0;
}
