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
#include <gmssl/hmac.h>


// FIXME: md5, sha1, sm3 test vectors


struct {
	char *key;
	char *data;
	char *hmac_sha224;
	char *hmac_sha256;
	char *hmac_sha384;
	char *hmac_sha512;
} hmac_tests[] = {

	// rfc 4231 test vectors
	{
		"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
		"0b0b0b0b",
		"4869205468657265",
		"896fb1128abbdf196832107cd49df33f"
		"47b4b1169912ba4f53684b22",
		"b0344c61d8db38535ca8afceaf0bf12b"
		"881dc200c9833da726e9376c2e32cff7",
		"afd03944d84895626b0825f4ab46907f"
		"15f9dadbe4101ec682aa034c7cebc59c"
		"faea9ea9076ede7f4af152e8b2fa9cb6",
		"87aa7cdea5ef619d4ff0b4241a1d6cb0"
		"2379f4e2ce4ec2787ad0b30545e17cde"
		"daa833b7d6b8a702038b274eaea3f4e4"
		"be9d914eeb61f1702e696c203a126854",
	},
	{
		"4a656665",
		"7768617420646f2079612077616e7420"
		"666f72206e6f7468696e673f",
		"a30e01098bc6dbbf45690f3a7e9e6d0f"
		"8bbea2a39e6148008fd05e44",
		"5bdcc146bf60754e6a042426089575c7"
		"5a003f089d2739839dec58b964ec3843",
		"af45d2e376484031617f78d2b58a6b1b"
		"9c7ef464f5a01b47e42ec3736322445e"
		"8e2240ca5e69e2c78b3239ecfab21649",
		"164b7a7bfcf819e2e395fbe73b56e0a3"
		"87bd64222e831fd610270cd7ea250554"
		"9758bf75c05a994a6d034f65f8f0e6fd"
		"caeab1a34d4a6b4b636e070a38bce737",
	},
	{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaa",
		"dddddddddddddddddddddddddddddddd"
		"dddddddddddddddddddddddddddddddd"
		"dddddddddddddddddddddddddddddddd"
		"dddd",
		"7fb3cb3588c6c1f6ffa9694d7d6ad264"
		"9365b0c1f65d69d1ec8333ea",
		"773ea91e36800e46854db8ebd09181a7"
		"2959098b3ef8c122d9635514ced565fe",
		"88062608d3e6ad8a0aa2ace014c8a86f"
		"0aa635d947ac9febe83ef4e55966144b"
		"2a5ab39dc13814b94e3ab6e101a34f27",
		"fa73b0089d56a284efb0f0756c890be9"
		"b1b5dbdd8ee81a3655f83e33b2279d39"
		"bf3e848279a722c806b485a47e67c807"
		"b946a337bee8942674278859e13292fb",
	},
};

int test_hmac(const DIGEST *digest, const char *key_hex, const char *data_hex, const char *hmac_hex)
{
	HMAC_CTX ctx;
	uint8_t *key = (uint8_t *)malloc(strlen(key_hex)/2);
	uint8_t *data = (uint8_t *)malloc(strlen(data_hex)/2);
	uint8_t *hmac = (uint8_t *)malloc(strlen(hmac_hex) / 2);
	size_t keylen, datalen, hmaclen;
	uint8_t buf[64];
	size_t buflen;

	hex_to_bytes(key_hex, strlen(key_hex), key, &keylen);
	hex_to_bytes(data_hex, strlen(data_hex), data, &datalen);
	hex_to_bytes(hmac_hex, strlen(hmac_hex), hmac, &hmaclen);

	hmac_init(&ctx, digest, key, keylen);
	hmac_update(&ctx, data, datalen);
	hmac_finish(&ctx, buf, &buflen);

	if (buflen !=  hmaclen || memcmp(buf, hmac, hmaclen) != 0) {
		printf("failed\n");
		return 0;
	}
	printf("ok\n");

	if (key) free(key);
	if (data) free(data);
	if (hmac) free(hmac);
	return 1;
}

int main(void)
{
	int i;
	for (i = 0; i < sizeof(hmac_tests)/sizeof(hmac_tests[0]); i++) {
		test_hmac(DIGEST_sha224(), hmac_tests[i].key, hmac_tests[i].data, hmac_tests[i].hmac_sha224);
		test_hmac(DIGEST_sha256(), hmac_tests[i].key, hmac_tests[i].data, hmac_tests[i].hmac_sha256);
		test_hmac(DIGEST_sha384(), hmac_tests[i].key, hmac_tests[i].data, hmac_tests[i].hmac_sha384);
		test_hmac(DIGEST_sha512(), hmac_tests[i].key, hmac_tests[i].data, hmac_tests[i].hmac_sha512);
	};

	return 0;
};
