/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <time.h>
#include <gmssl/sm3.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>
#include "sm3_hmactest.h"


static int test_sm3_hmac(void)
{
	size_t i;
	int failed = 0;

	for (i = 0; i < sizeof(test_sm3_hmac_vectors)/sizeof(test_sm3_hmac_vectors[0]); i++) {
		const TEST_SM3_HMAC_VECTOR *tv = &test_sm3_hmac_vectors[i];
		uint8_t key[256];
		uint8_t msg[256];
		uint8_t expected[32];
		uint8_t mac[32];
		size_t keylen, msglen, taglen;
		SM3_HMAC_CTX ctx;
		int match;
		int ok;

		if (hex_to_bytes(tv->key, strlen(tv->key), key, &keylen) != 1
			|| hex_to_bytes(tv->msg, strlen(tv->msg), msg, &msglen) != 1
			|| hex_to_bytes(tv->tag, strlen(tv->tag), expected, &taglen) != 1) {
			return -1;
		}
		// allow truncated tags
		if (taglen > SM3_HMAC_SIZE) {
			error_print();
			return -1;
		}

		sm3_hmac_init(&ctx, key, keylen);
		sm3_hmac_update(&ctx, msg, msglen);
		sm3_hmac_finish(&ctx, mac);

		match = memcmp(mac, expected, taglen) == 0;
		ok = tv->result == TEST_RESULT_VALID ? match : !match;

		if (!ok) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm3_hmac() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
