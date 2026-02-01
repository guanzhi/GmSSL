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
#include <gmssl/oid.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/x509_key.h>



static int test_x509_algor_param_from_lms_types(void)
{
	int lms_types1[] = {
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H10,
		LMS_HASH256_M32_H15,
		LMS_HASH256_M32_H20,
		LMS_HASH256_M32_H25,
	};
	int hss_algor_param1 = 624485;

	int lms_types2[] = {
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H5,
	};
	int hss_algor_param2 = 1365;

	int algor_param1;
	int algor_param2;
	int lms_types[5];
	size_t num;

	if (x509_algor_param_from_lms_types(&algor_param1, lms_types1, sizeof(lms_types1)/sizeof(lms_types1[0])) != 1) {
		error_print();
		return -1;
	}
	if (algor_param1 != hss_algor_param1) {
		format_print(stderr, 0, 4, "hss_algor_param: %d\n", algor_param1);
		error_print();
		return -1;
	}
	if (x509_algor_param_to_lms_types(algor_param1, lms_types, &num) != 1) {
		error_print();
		return -1;
	}
	if (num != sizeof(lms_types1)/sizeof(lms_types1[0])) {
		error_print();
		return -1;
	}
	if (memcmp(lms_types, lms_types1, sizeof(lms_types1)) != 0) {
		error_print();
		return -1;
	}


	if (x509_algor_param_from_lms_types(&algor_param2, lms_types2, sizeof(lms_types2)/sizeof(lms_types2[0])) != 1) {
		error_print();
		return -1;
	}
	if (algor_param2 != hss_algor_param2) {
		format_print(stderr, 0, 4, "hss_algor_param: %d\n", algor_param2);
		error_print();
		return -1;
	}
	if (x509_algor_param_to_lms_types(algor_param2, lms_types, &num) != 1) {
		error_print();
		return -1;
	}
	if (num != sizeof(lms_types2)/sizeof(lms_types2[0])) {
		error_print();
		return -1;
	}
	if (memcmp(lms_types, lms_types2, sizeof(lms_types2)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

X509_KEY x509_keys[7];


	// 这个也要挪到外面，才能判断某个x509_key的类型
	struct {
		int algor;
		int algor_param;
	} tests[] = {
		{ OID_ec_public_key, OID_sm2 },
		{ OID_ec_public_key, OID_secp256r1 },
		{ OID_lms_hashsig, LMS_HASH256_M32_H5 },
		{ OID_hss_lms_hashsig, 1365 },
		{ OID_xmss_hashsig, XMSS_HASH256_10_256 },
		{ OID_xmssmt_hashsig, XMSSMT_HASH256_20_4_256 },
		{ OID_sphincs_hashsig, OID_undef },
	};



static int test_x509_key_generate(void)
{
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_key_generate(&x509_keys[i], tests[i].algor, tests[i].algor_param) != 1) {
			error_print();
			return -1;
		}

	// 这个也没有实现啊！
	//	x509_private_key_print(stderr, 0, 4, "private_key", &x509_keys[i]);
		x509_public_key_print(stderr, 0, 4, "private_key", &x509_keys[i]);

	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_to_bytes(void)
{
	int i;
	uint8_t buf[128];
	uint8_t *p;
	size_t len;

	uint8_t dgst[32];

	X509_KEY key;

	for (i = 0; i < 7; i++) {
		p = buf;
		len = 0;
		if (x509_public_key_to_bytes(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "public_key_bytes: %zu\n", len);

		if (x509_public_key_digest(&x509_keys[i], dgst) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "dgst", dgst, 32);

		// 居然没有public_key_from_bytes
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_info_to_der(void)
{
	X509_KEY key;
	uint8_t buf[50240];
	int i;

	for (i = 0; i < sizeof(x509_keys)/sizeof(x509_keys[0]); i++) {
		const uint8_t *cp = buf;
		uint8_t *p = buf;
		size_t len = 0;

		fprintf(stderr, "%d: algor = %d param = %d\n", i, x509_keys[i].algor, x509_keys[i].algor_param);

		if (x509_public_key_info_to_der(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "public_key_der_size: %zu\n", len);

		if (x509_public_key_info_from_der(&key, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			error_print();
			return -1;
		}

		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_ec_private_key_to_der(void)
{
	X509_KEY key;
	uint8_t buf[1024];
	int i;

	for (i = 0; i < 2; i++) {
		const uint8_t *cp = buf;
		uint8_t *p = buf;
		size_t len = 0;
		// 目前底层的asn1功能不支持这两个不编码，需要仔细看看是怎么回事，explicit的编码是如何实现的
		int encode_params = 1; // X509_ENCODE_EC_PRIVATE_KEY_PARAMS;
		int encode_pubkey = 1; //X509_ENCODE_EC_PRIVATE_KEY_PUBKEY;

		if (ec_private_key_to_der(&x509_keys[i], encode_params, encode_pubkey, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (ec_private_key_from_der(&key, tests[i].algor_param, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_private_key_info_to_der(void)
{
	X509_KEY key;
	uint8_t buf[1024];
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (tests[i].algor == OID_ec_public_key) {
			const uint8_t *cp = buf;
			uint8_t *p = buf;
			size_t len = 0;
			const uint8_t *attrs;
			size_t attrslen;

			if (x509_private_key_info_to_der(&x509_keys[i], &p, &len) != 1) {
				error_print();
				return -1;
			}
			if (x509_private_key_info_from_der(&key, &attrs, &attrslen, &cp, &len) != 1) {
				error_print();
				return -1;
			}
			if (len) {
				error_print();
				return -1;
			}
			if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
				error_print();
				return -1;
			}
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;





}

static int test_x509_private_key_info_encrypt_to_der(void)
{
	const char *pass = "P@ssw0rd";
	X509_KEY key;
	uint8_t buf[1024];
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (tests[i].algor == OID_ec_public_key) {
			const uint8_t *cp = buf;
			uint8_t *p = buf;
			size_t len = 0;
			const uint8_t *attrs;
			size_t attrslen;

			if (x509_private_key_info_encrypt_to_der(&x509_keys[i], pass, &p, &len) != 1) {
				error_print();
				return -1;
			}
			if (x509_private_key_info_decrypt_from_der(&key, &attrs, &attrslen, pass, &cp, &len) != 1) {
				error_print();
				return -1;
			}
			if (len) {
				error_print();
				return -1;
			}
			if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
				error_print();
				return -1;
			}
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_x509_private_key_info_encrypt_to_pem(void)
{
	const char *pass = "P@ssw0rd";
	X509_KEY key;
	uint8_t buf[1024];
	FILE *fp;
	int i;


	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (tests[i].algor == OID_ec_public_key) {
			const uint8_t *cp = buf;
			uint8_t *p = buf;
			size_t len = 0;
			const uint8_t *attrs;
			size_t attrslen;

			if (!(fp = fopen("test_x509_private_key_info_encrypt_to_pem.pem", "w"))) {
				error_print();
				return -1;
			}
			if (x509_private_key_info_encrypt_to_pem(&x509_keys[i], pass, fp) != 1) {
				error_print();
				return -1;
			}
			fclose(fp);

			if (!(fp = fopen("test_x509_private_key_info_encrypt_to_pem.pem", "r"))) {
				error_print();
				return -1;
			}
			if (x509_private_key_info_decrypt_from_pem(&key, &attrs, &attrslen, pass, fp) != 1) {
				error_print();
				return -1;
			}
			fclose(fp);
			if (len) {
				error_print();
				return -1;
			}
			if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
				error_print();
				return -1;
			}
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}














// 首先某些头文件中的函数并没有实现，很奇怪！

// 然后是某些数据长度（公钥、签名之类）还没有计算具体的值，因此没有办法准备最大的缓冲去

// 应该把密钥生成放到最外面，这样只需要生成一次就可以了

// X509_KEY还不支持Kyber







int main(void)
{
	if (test_x509_key_generate() != 1) goto err;
	if (test_x509_algor_param_from_lms_types() != 1) goto err;
	if (test_x509_public_key_to_bytes() != 1) goto err;
	if (test_x509_public_key_info_to_der() != 1) goto err;
	if (test_ec_private_key_to_der() != 1) goto err;
	if (test_x509_private_key_info_to_der() != 1) goto err;
	if (test_x509_private_key_info_encrypt_to_der() != 1) goto err;
	if (test_x509_private_key_info_encrypt_to_pem() != 1) goto err;

	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
