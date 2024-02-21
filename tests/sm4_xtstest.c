/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/sm4.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_sm4_xts(void)
{
	SM4_KEY sm4_key1;
	SM4_KEY sm4_key2;
	uint8_t key[32];
	size_t len[] = { 16, 16+2, 32, 48+8, 64 };
	uint8_t plaintext[16 * 4];
	uint8_t encrypted[sizeof(plaintext)];
	uint8_t decrypted[sizeof(plaintext)];
	uint8_t tweak[16];
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(tweak, sizeof(tweak));
	rand_bytes(plaintext, sizeof(plaintext));

	for (i = 0; i < sizeof(len)/sizeof(len[0]); i++) {

		sm4_set_encrypt_key(&sm4_key1, key);
		sm4_set_encrypt_key(&sm4_key2, key + 16);
		sm4_xts_encrypt(&sm4_key1, &sm4_key2, tweak, plaintext, len[i], encrypted);

		sm4_set_decrypt_key(&sm4_key1, key);
		sm4_set_encrypt_key(&sm4_key2, key + 16);
		sm4_xts_decrypt(&sm4_key1, &sm4_key2, tweak, encrypted, len[i], decrypted);

		if (memcmp(decrypted, plaintext, len[i]) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm4_xts() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
