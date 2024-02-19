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


static int test_sm4_ccm(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t iv[SM4_CCM_MAX_IV_SIZE];
	size_t ivlen[] = { SM4_CCM_MIN_IV_SIZE, SM4_CCM_MIN_IV_SIZE + 1, SM4_CCM_MAX_IV_SIZE };
	uint8_t aad[32];
	size_t aadlen[] = {0, 8, 16, 20, 32 };
	uint8_t plaintext[64];
	size_t len[] = { 4, 16, 36, 64 };
	uint8_t encrypted[sizeof(plaintext)];
	uint8_t decrypted[sizeof(plaintext)];
	uint8_t mac[SM4_CCM_MAX_MAC_SIZE];
	size_t maclen[] = { SM4_CCM_MIN_MAC_SIZE, SM4_CCM_MAX_MAC_SIZE };
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(aad, sizeof(aad));
	rand_bytes(plaintext, sizeof(plaintext));

	sm4_set_encrypt_key(&sm4_key, key);

	for (i = 0; i < sizeof(ivlen)/sizeof(ivlen[0]); i++) {

		if (sm4_ccm_encrypt(&sm4_key, iv, ivlen[i],  aad, sizeof(aad),
			plaintext, sizeof(plaintext), encrypted, sizeof(mac), mac) != 1) {
			error_print();
			return -1;
		}

		if (sm4_ccm_decrypt(&sm4_key, iv, ivlen[i], aad, sizeof(aad),
			encrypted, sizeof(encrypted), mac, sizeof(mac), decrypted) != 1) {
			error_print();
			return -1;
		}

		if (memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm4_ccm() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
