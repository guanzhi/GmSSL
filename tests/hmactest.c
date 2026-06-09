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
#include <gmssl/hex.h>
#include <gmssl/hmac.h>
#include <gmssl/error.h>


static int hmac_test_one(const DIGEST *digest, const char *key_hex, const char *data_hex, const char *hmac_hex)
{
	HMAC_CTX ctx;
	uint8_t key[256];
	uint8_t data[256];
	uint8_t expected[64];
	uint8_t mac[64];
	size_t keylen, datalen, expected_len, maclen;

	if (hex_to_bytes(key_hex, strlen(key_hex), key, &keylen) != 1
		|| hex_to_bytes(data_hex, strlen(data_hex), data, &datalen) != 1
		|| hex_to_bytes(hmac_hex, strlen(hmac_hex), expected, &expected_len) != 1) {
		error_print();
		return -1;
	}
	if (hmac_init(&ctx, digest, key, keylen) != 1
		|| hmac_update(&ctx, data, datalen) != 1
		|| hmac_finish(&ctx, mac, &maclen) != 1) {
		error_print();
		return -1;
	}
	if (maclen != expected_len || memcmp(mac, expected, expected_len) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int test_hmac_sm3(void)
{
	// Wycheproof hmac_sm3_test.json tcId 1
	if (hmac_test_one(DIGEST_sm3(),
		"1e225cafb90339bba1b24076d4206c3e"
		"79c355805d851682bc818baa4f5a7779",
		"",
		"f9938b1b2515117f25dcd636c9a6a0e7"
		"f00bccaf5347e0e0df435cfca736cfc1") != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#ifdef ENABLE_SHA1
static int test_hmac_sha1(void)
{
	// Wycheproof hmac_sha1_test.json tcId 1
	if (hmac_test_one(DIGEST_sha1(),
		"06c0dcdc16ff81dce92807fa2c82b44d"
		"28ac178a",
		"",
		"7d91d1b4748077b28911b4509762b6df"
		"24365810") != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

#ifdef ENABLE_SHA2
static struct {
	const char *key;
	const char *data;
	const char *hmac_sha224;
	const char *hmac_sha256;
	const char *hmac_sha384;
	const char *hmac_sha512;
} hmac_sha2_tests[] = {

	// RFC 4231 test vectors
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

static int test_hmac_sha2(void)
{
	size_t i;

	for (i = 0; i < sizeof(hmac_sha2_tests)/sizeof(hmac_sha2_tests[0]); i++) {
		if (hmac_test_one(DIGEST_sha224(),
				hmac_sha2_tests[i].key,
				hmac_sha2_tests[i].data,
				hmac_sha2_tests[i].hmac_sha224) != 1
			|| hmac_test_one(DIGEST_sha256(),
				hmac_sha2_tests[i].key,
				hmac_sha2_tests[i].data,
				hmac_sha2_tests[i].hmac_sha256) != 1
			|| hmac_test_one(DIGEST_sha384(),
				hmac_sha2_tests[i].key,
				hmac_sha2_tests[i].data,
				hmac_sha2_tests[i].hmac_sha384) != 1
			|| hmac_test_one(DIGEST_sha512(),
				hmac_sha2_tests[i].key,
				hmac_sha2_tests[i].data,
				hmac_sha2_tests[i].hmac_sha512) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

int main(void)
{
	if (test_hmac_sm3() != 1) goto err;
#ifdef ENABLE_SHA1
	if (test_hmac_sha1() != 1) goto err;
#endif
#ifdef ENABLE_SHA2
	if (test_hmac_sha2() != 1) goto err;
#endif
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
