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
#include <gmssl/hex.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/error.h>


struct {
	char *pass;
	char *salt;
	int iter;
	int dklen;
	char *dk;
} pbkdf2_hmac_sha1_tests[] = {

	// rfc 6070 test vectors for pbkdf2-hmac-sha1
	{
		"password",
		"salt",
		1,
		20,
		"0c60c80f961f0e71f3a9b524af6012062fe037a6",
	},
	{
		"password",
		"salt",
		2,
		20,
		"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
	},
	{
		"password",
		"salt",
		4096,
		20,
		"4b007901b765489abead49d926f721d065a429c1",
	},
	/*
	{
		"password",
		"salt",
		16777216, // very slow
		20,
		"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984",
	},
	*/
	{
		"passwordPASSWORDpassword",
		"saltSALTsaltSALTsaltSALTsaltSALTsalt",
		4096,
		25,
		"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
	},
};

/*
void test(void)
{
	HMAC_CTX ctx;
	uint8_t iter[4] = {0, 0, 0, 1};
	uint8_t mac[20];
	size_t len;
	int i;

	hmac_init(&ctx, DIGEST_sha1(), (uint8_t *)"password", 8);
	hmac_update(&ctx, (uint8_t *)"salt", 4);
	hmac_update(&ctx, iter, 4);
	hmac_finish(&ctx, mac, &len);

	for (i = 1; i < 4096; i++) {
		uint8_t buf[20];
		memset(&ctx, 0, sizeof(HMAC_CTX));
		hmac_init(&ctx, DIGEST_sha1(), (uint8_t *)"password", 8);
		hmac_update(&ctx, mac, len);
		hmac_finish(&ctx, buf, &len);
		int j;
		for (j = 0; j < len; j++) {
			mac[j] ^= buf[j];
		}
	}


	for (i = 0; i < len; i++) {
		printf("%02x", mac[i]);
	}
	printf("\n");
}
*/

static int test_pbkdf2_genkey(void)
{
// FIXME: currently we only has SHA-1 tests, replace with SHA-256
#ifdef ENABLE_BROKEN_CRYPTO
	int i;
	uint8_t key[64];
	uint8_t buf[64];
	size_t len;

	for (i = 0; i < sizeof(pbkdf2_hmac_sha1_tests)/sizeof(pbkdf2_hmac_sha1_tests[0]); i++) {
		hex_to_bytes(pbkdf2_hmac_sha1_tests[i].dk, strlen(pbkdf2_hmac_sha1_tests[i].dk), buf, &len);

		if (pbkdf2_genkey(DIGEST_sha1(),
			pbkdf2_hmac_sha1_tests[i].pass, strlen(pbkdf2_hmac_sha1_tests[i].pass),
			(uint8_t *)pbkdf2_hmac_sha1_tests[i].salt, strlen(pbkdf2_hmac_sha1_tests[i].salt),
			pbkdf2_hmac_sha1_tests[i].iter, pbkdf2_hmac_sha1_tests[i].dklen, key) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(key, buf, pbkdf2_hmac_sha1_tests[i].dklen) != 0) {
			fprintf(stderr, "test_pbkdf2_genkey test %d failed\n", i);
			return -1;
		} else {
			fprintf(stderr, "test_pbkdf2_genkey test %d ok\n", i);
		}
	}
#endif
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

int main(int argc, char **argv)
{
	int err = 0;
	err += test_pbkdf2_genkey();
	return err;
}
