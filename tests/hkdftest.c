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
#include <gmssl/hkdf.h>
#include <gmssl/error.h>

static struct {
	char *algor;
	char *ikm;
	char *salt;
	char *info;
	int L;
	char *prk;
	char *okm;
} hkdf_tests[] = {
	{
		// test 1
		"sha256",
		"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		"000102030405060708090a0b0c",
		"f0f1f2f3f4f5f6f7f8f9",
		42,
		"077709362c2e32df0ddc3f0dc47bba63"
		"90b6c73bb50f9c3122ec844ad7c2b3e5",
		"3cb25f25faacd57a90434f64d0362f2a"
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
		"34007208d5b887185865",
	},
	{
		// test 2
		"sha256",
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f"
		"303132333435363738393a3b3c3d3e3f"
		"404142434445464748494a4b4c4d4e4f",
		"606162636465666768696a6b6c6d6e6f"
		"707172737475767778797a7b7c7d7e7f"
		"808182838485868788898a8b8c8d8e8f"
		"909192939495969798999a9b9c9d9e9f"
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		82,
		"06a6b88c5853361a06104c9ceb35b45c"
		"ef760014904671014a193f40c15fc244",
		"b11e398dc80327a1c8e7f78c596a4934"
		"4f012eda2d4efad8a050cc4c19afa97c"
		"59045a99cac7827271cb41c65e590e09"
		"da3275600c2f09b8367793a9aca3db71"
		"cc30c58179ec3e87c14c01d5c1f3434f"
		"1d87",
	},
	{
		// test 3
		"sha256",
		"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		"",
		"",
		42,
		"19ef24a32c717b167f33a91d6f648bdf"
		"96596776afdb6377ac434c1c293ccb04",
		"8da4e775a563c18f715f802a063c5a31"
		"b8a11f5c5ee1879ec3454e5f3c738d2d"
		"9d201395faa4b61a96c8",
	},
#ifdef ENABLE_BROKEN_CRYPTO
	{
		// test 4
		"sha1",
		"0b0b0b0b0b0b0b0b0b0b0b",
		"000102030405060708090a0b0c",
		"f0f1f2f3f4f5f6f7f8f9",
		42,
		"9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
		"085a01ea1b10f36933068b56efa5ad81"
		"a4f14b822f5b091568a9cdd4f155fda2"
		"c22e422478d305f3f896",
	},
	{
		// test 5
		"sha1",
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f"
		"303132333435363738393a3b3c3d3e3f"
		"404142434445464748494a4b4c4d4e4f",
		"606162636465666768696a6b6c6d6e6f"
		"707172737475767778797a7b7c7d7e7f"
		"808182838485868788898a8b8c8d8e8f"
		"909192939495969798999a9b9c9d9e9f"
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		82,
		"8adae09a2a307059478d309b26c4115a224cfaf6",
		"0bd770a74d1160f7c9f12cd5912a06eb"
		"ff6adcae899d92191fe4305673ba2ffe"
		"8fa3f1a4e5ad79f3f334b3b202b2173c"
		"486ea37ce3d397ed034c7f9dfeb15c5e"
		"927336d0441f4c4300e2cff0d0900b52"
		"d3b4",
	},
	{
		// test 6
		"sha1",
		"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		"",
		"",
		42,
		"da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
		"0ac1af7002b3d761d1e55298da9d0506"
		"b9ae52057220a306e07b6b87e8df21d0"
		"ea00033de03984d34918"
	},
	{
		// test 7
		"sha1",
		"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
		"",
		"",
		42,
		"2adccada18779e7c2077ad2eb19d3f3e731385dd",
		"2c91117204d745f3500d636a62f64f0a"
		"b3bae548aa53d423b0d1f27ebba6f5e5"
		"673a081d70cce7acfc48",
	},
#endif
};

int test_hkdf(void)
{
	int i;
	const DIGEST *digest;
	uint8_t ikm[512];
	uint8_t salt[512];
	uint8_t info[512];
	uint8_t prk[512];
	uint8_t okm[512];
	size_t ikmlen, saltlen, infolen, prklen, okmlen;
	size_t L;
	uint8_t buf[512];
	size_t buflen;
	size_t len;

	for (i = 0; i < sizeof(hkdf_tests)/sizeof(hkdf_tests[0]); i++) {

		digest = digest_from_name(hkdf_tests[i].algor);
		hex_to_bytes(hkdf_tests[i].ikm, strlen(hkdf_tests[i].ikm), ikm, &len);
		hex_to_bytes(hkdf_tests[i].salt, strlen(hkdf_tests[i].salt), salt, &len);
		hex_to_bytes(hkdf_tests[i].info, strlen(hkdf_tests[i].info), info, &len);
		hex_to_bytes(hkdf_tests[i].prk, strlen(hkdf_tests[i].prk), prk, &len);
		hex_to_bytes(hkdf_tests[i].okm, strlen(hkdf_tests[i].okm), okm, &len);
		ikmlen = strlen(hkdf_tests[i].ikm)/2;
		saltlen = strlen(hkdf_tests[i].salt)/2;
		infolen = strlen(hkdf_tests[i].info)/2;
		prklen = strlen(hkdf_tests[i].prk)/2;
		okmlen = strlen(hkdf_tests[i].okm)/2;
		L = hkdf_tests[i].L;

		printf("test %d\n", i + 1);
		format_print(stdout, 0, 0, "Hash = %s\n", digest_name(digest));
		format_bytes(stdout, 0, 0, "IKM  = ", ikm, ikmlen);
		format_bytes(stdout, 0, 0, "salt = ", salt, saltlen);
		format_bytes(stdout, 0, 0, "info = ", info, infolen);
		format_print(stdout, 0, 0, "L    = %zu\n", L);

		if (hkdf_extract(digest, salt, saltlen, ikm, ikmlen, buf, &buflen) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stdout, 0, 0, "PRK  = ", buf, buflen);
		format_bytes(stdout, 0, 0, "     = ", prk, prklen);
		if (buflen != prklen || memcmp(buf, prk, prklen) != 0) {
			error_print();
			return -1;
		}

		if (hkdf_expand(digest, prk, prklen, info, infolen, L, buf) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stdout, 0, 0, "OKM  = ", buf, L);
		format_bytes(stdout, 0, 0, "     = ", okm, okmlen);
		if (L != okmlen || memcmp(buf, okm, okmlen) != 0) {
			error_print();
			return -1;
		}

		printf("\n");

	}
	return 0;
}

int main(void)
{
	int err = 0;
	err += test_hkdf();
	return err;
}
