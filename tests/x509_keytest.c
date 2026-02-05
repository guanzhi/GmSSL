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
#include <gmssl/x509_alg.h>
#include <gmssl/x509_key.h>


int lms_types[] = {
	LMS_HASH256_M32_H5,
	LMS_HASH256_M32_H5,
	LMS_HASH256_M32_H5,
};

struct {
	int algor;
	int algor_param;
} tests[] = {
	{ OID_ec_public_key, OID_sm2 },
	{ OID_ec_public_key, OID_secp256r1 },
	{ OID_lms_hashsig, LMS_HASH256_M32_H5 },
	{ OID_hss_lms_hashsig, OID_undef }, // use lms_types[]
	{ OID_xmss_hashsig, XMSS_HASH256_10_256 },
	{ OID_xmssmt_hashsig, XMSSMT_HASH256_20_4_256 },
	{ OID_sphincs_hashsig, OID_undef },
	{ OID_kyber_kem, OID_undef },
};

X509_KEY x509_keys[sizeof(tests)/sizeof(tests[0])];


static int test_x509_key_generate(void)
{
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		void *param = NULL;
		size_t paramlen = 0;

		switch (tests[i].algor) {
		case OID_hss_lms_hashsig:
			param = lms_types;
			paramlen = sizeof(lms_types);
			break;
		case OID_sphincs_hashsig:
		case OID_kyber_kem:
			param = NULL;
			paramlen = 0;
			break;
		default:
			param = &tests[i].algor_param;
			paramlen = sizeof(tests[i].algor_param);
		}
		if (x509_key_generate(&x509_keys[i], tests[i].algor, param, paramlen) != 1) {
			error_print();
			return -1;
		}
		//x509_private_key_print(stderr, 0, 4, "private_key", &x509_keys[i]);
		//x509_public_key_print(stderr, 0, 4, "private_key", &x509_keys[i]);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_to_bytes(void)
{
	X509_KEY key;
	uint8_t buf[1568]; // kyber-1024
	uint8_t *p;
	size_t len;
	uint8_t dgst[32];
	int i;

	//format_print(stderr, 0, 4, "public_key_to_bytes size\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		p = buf;
		len = 0;
		if (x509_public_key_to_bytes(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		//format_print(stderr, 0, 4, "%s: %zu\n", x509_public_key_algor_name(tests[i].algor), len);
		if (x509_public_key_digest(&x509_keys[i], dgst) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_info_to_der(void)
{
	X509_KEY key;
	uint8_t buf[2048];
	int i;

	//format_print(stderr, 0, 4, "public_key_info_to_bytes size\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		const uint8_t *cp = buf;
		uint8_t *p = buf;
		size_t len = 0;

		if (x509_public_key_info_to_der(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		//format_print(stderr, 0, 8, "%s: %zu\n", x509_public_key_algor_name(tests[i].algor), len);

		if (x509_public_key_info_from_der(&key, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			fprintf(stderr, "len = %zu\n", len);
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
	uint8_t buf[512];
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
		const uint8_t *cp = buf;
		uint8_t *p = buf;
		size_t len = 0;
		int encode_params;
		int encode_pubkey;

		// test 1
		encode_params = 0;
		encode_pubkey = 0;
		if (ec_private_key_to_der(&x509_keys[i], encode_params, encode_pubkey, &p, &len) != 1) {
			error_print();
			return -1;
		}
		//format_print(stderr, 0, 0, "ECPrivateKey encode_params = %d, encode_pubkey = %d\n", encode_params, encode_pubkey);
		//format_bytes(stderr, 0, 0, "ECPrivateKey", buf, len);
		if (ec_private_key_from_der(&key, tests[i].algor_param, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}

		// test 2
		encode_params = 0;
		encode_pubkey = 1;
		if (ec_private_key_to_der(&x509_keys[i], encode_params, encode_pubkey, &p, &len) != 1) {
			error_print();
			return -1;
		}
		//format_print(stderr, 0, 0, "ECPrivateKey encode_params = %d, encode_pubkey = %d\n", encode_params, encode_pubkey);
		//format_bytes(stderr, 0, 0, "ECPrivateKey", buf, len);
		if (ec_private_key_from_der(&key, tests[i].algor_param, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}

		// test 3
		encode_params = 1;
		encode_pubkey = 0;
		if (ec_private_key_to_der(&x509_keys[i], encode_params, encode_pubkey, &p, &len) != 1) {
			error_print();
			return -1;
		}
		//format_print(stderr, 0, 0, "ECPrivateKey encode_params = %d, encode_pubkey = %d\n", encode_params, encode_pubkey);
		//format_bytes(stderr, 0, 0, "ECPrivateKey", buf, len);
		if (ec_private_key_from_der(&key, tests[i].algor_param, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}

		// test 4
		encode_params = 1;
		encode_pubkey = 1;
		if (ec_private_key_to_der(&x509_keys[i], encode_params, encode_pubkey, &p, &len) != 1) {
			error_print();
			return -1;
		}
		//format_print(stderr, 0, 0, "ECPrivateKey encode_params = %d, encode_pubkey = %d\n", encode_params, encode_pubkey);
		//format_bytes(stderr, 0, 0, "ECPrivateKey", buf, len);
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
	uint8_t buf[512];
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
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

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_private_key_info_encrypt_to_der(void)
{
	const char *pass = "P@ssw0rd";
	X509_KEY key;
	uint8_t buf[1024];
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
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


	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
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

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_sign(void)
{
	size_t i;
	X509_SIGN_CTX sign_ctx;
	void *args = NULL;
	size_t argslen = 0;
	uint8_t msg[66];
	uint8_t sig[40969];
	size_t siglen;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (tests[i].algor == OID_kyber_kem) {
			continue;
		}
		//format_print(stderr, 0, 4, "%s\n", x509_public_key_algor_name(tests[i].algor));
		if (x509_sign_init(&sign_ctx, &x509_keys[i], args, argslen) != 1) {
			error_print();
			return -1;
		}
		if (x509_sign(&sign_ctx, msg, sizeof(msg), sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		if (x509_verify_init(&sign_ctx, &x509_keys[i], args, argslen, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		if (x509_verify(&sign_ctx, msg, sizeof(msg)) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_key_exchange(void)
{
	X509_KEY key;
	uint8_t point1[65];
	uint8_t point2[65];
	uint8_t share1[32];
	uint8_t share2[32];
	uint8_t *p;
	size_t len;
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (tests[i].algor != OID_ec_public_key) {
			continue;
		}
		if (x509_key_generate(&key, tests[i].algor, &tests[i].algor_param, sizeof(tests[i].algor_param)) != 1) {
			error_print();
			return -1;
		}

		// export public key 1
		p = point1;
		len = 0;
		if (x509_public_key_to_bytes(&key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(point1)) {
			error_print();
			return -1;
		}

		// export public key 2
		p = point2;
		len = 0;
		if (x509_public_key_to_bytes(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(point2)) {
			error_print();
			return -1;
		}

		// key exchange 1
		if (x509_key_exchange(&key, point2, sizeof(point2), share1, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(share1)) {
			error_print();
			return -1;
		}

		// key exchange 2
		if (x509_key_exchange(&x509_keys[i], point1, sizeof(point1), share2, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(share2)) {
			error_print();
			return -1;
		}

		// share secrets equal
		if (memcmp(share1, share2, sizeof(share1)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_kem(void)
{
	uint8_t ciphertext[sizeof(KYBER_CIPHERTEXT)];
	size_t ciphertext_len;
	uint8_t secret1[32];
	uint8_t secret2[32];
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (tests[i].algor != OID_kyber_kem) {
			continue;
		}

		if (x509_key_encapsulate(&x509_keys[i], ciphertext, &ciphertext_len, secret1) != 1) {
			error_print();
			return -1;
		}
		if (ciphertext_len != sizeof(ciphertext)) {
			error_print();
			return -1;
		}
		if (x509_key_decapsulate(&x509_keys[i], ciphertext, ciphertext_len, secret2) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(secret1, secret2, 32) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


int main(void)
{
	if (test_x509_key_generate() != 1) goto err;
	if (test_x509_public_key_to_bytes() != 1) goto err;
	if (test_x509_public_key_info_to_der() != 1) goto err;
	if (test_ec_private_key_to_der() != 1) goto err;
	if (test_x509_private_key_info_to_der() != 1) goto err;
	if (test_x509_private_key_info_encrypt_to_der() != 1) goto err;
	if (test_x509_private_key_info_encrypt_to_pem() != 1) goto err;
	if (test_x509_sign() != 1) goto err;
	if (test_x509_key_exchange() != 1) goto err;
	if (test_x509_kem() != 1) goto err;

	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
