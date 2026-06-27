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


#ifdef ENABLE_LMS
static int lms_types[] = {
	LMS_SM3_M32_H5,
	LMS_SM3_M32_H5,
	LMS_SM3_M32_H5,
};
#endif

struct {
	int algor;
	int algor_param;
} tests[] = {
	{ OID_ec_public_key, OID_sm2 },
#ifdef ENABLE_SECP256R1
	{ OID_ec_public_key, OID_secp256r1 },
#endif
#ifdef ENABLE_SECP384R1
	{ OID_ec_public_key, OID_secp384r1 },
#endif
#ifdef ENABLE_LMS
	{ OID_lms_hashsig, LMS_SM3_M32_H5 },
	{ OID_hss_lms_hashsig, OID_undef }, // use lms_types[]
#endif
#ifdef ENABLE_XMSS
	{ OID_xmss_hashsig, XMSS_SM3_10_256 },
	{ OID_xmssmt_hashsig, XMSSMT_SM3_20_4_256 },
#endif
#ifdef ENABLE_SPHINCS
	{ OID_sphincs_hashsig, OID_undef },
#endif
#ifdef ENABLE_KYBER
	{ OID_kyber_kem, OID_undef },
#endif
};

X509_KEY x509_keys[sizeof(tests)/sizeof(tests[0])];


static int test_sign_algor(const X509_KEY *key)
{
	switch (key->algor) {
	case OID_ec_public_key:
		switch (key->algor_param) {
		case OID_sm2:
			return OID_sm2sign_with_sm3;
#ifdef ENABLE_SECP256R1
		case OID_secp256r1:
			return OID_ecdsa_with_sha256;
#endif
		default:
			return OID_undef;
		}
#ifdef ENABLE_LMS
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
		return key->algor;
#endif
#ifdef ENABLE_XMSS
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
		return key->algor;
#endif
#ifdef ENABLE_SPHINCS
	case OID_sphincs_hashsig:
		return key->algor;
#endif
	default:
		return OID_undef;
	}
}


static int test_x509_key_generate(void)
{
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		void *param = NULL;
		size_t paramlen = 0;

		switch (tests[i].algor) {
#ifdef ENABLE_LMS
		case OID_hss_lms_hashsig:
			param = lms_types;
			paramlen = sizeof(lms_types);
			break;
#endif
#ifdef ENABLE_SPHINCS
		case OID_sphincs_hashsig:
#endif
#ifdef ENABLE_KYBER
		case OID_kyber_kem:
#endif
#if defined(ENABLE_SPHINCS) || defined(ENABLE_KYBER)
			param = NULL;
			paramlen = 0;
			break;
#endif
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

		if (!(fp = tmpfile())) {
			error_print();
			return -1;
		}
		if (x509_private_key_info_encrypt_to_pem(&x509_keys[i], pass, fp) != 1) {
			error_print();
			fclose(fp);
			return -1;
		}
		rewind(fp);

		if (x509_private_key_info_decrypt_from_pem(&key, &attrs, &attrslen, pass, fp) != 1) {
			error_print();
			fclose(fp);
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

static int test_x509_private_key_info_decrypt_from_pem(void)
{
	const char *pass = "P@ssw0rd";
	FILE *fp;
	int i;

	if (!(fp = tmpfile())) {
		error_print();
		return -1;
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
		if (x509_private_key_info_encrypt_to_pem(&x509_keys[i], pass, fp) != 1) {
			error_print();
			fclose(fp);
			return -1;
		}

	}
	rewind(fp);
	while (1) {
		int ret;
		X509_KEY key;
		const uint8_t *attrs;
		size_t attrslen;

		if ((ret = x509_private_key_info_decrypt_from_pem(&key, &attrs, &attrslen, pass, fp)) < 0) {
			error_print();
			fclose(fp);
			return -1;
		} else if (ret == 0) {
			break;
		}
	}
	fclose(fp);

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

	memset(msg, 0xa5, sizeof(msg));

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		int sign_algor;

		if (tests[i].algor == OID_kyber_kem) {
			continue;
		}
		sign_algor = test_sign_algor(&x509_keys[i]);
		if (sign_algor == OID_undef) {
			continue;
		}
		//format_print(stderr, 0, 4, "%s\n", x509_public_key_algor_name(tests[i].algor));
		if (x509_sign_init(&sign_ctx, &x509_keys[i], sign_algor, args, argslen) != 1) {
			error_print();
			return -1;
		}
		if (x509_sign(&sign_ctx, msg, sizeof(msg), sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s: %zu\n", x509_public_key_algor_name(tests[i].algor), siglen);
		if (x509_verify_init(&sign_ctx, &x509_keys[i], sign_algor, args, argslen, sig, siglen) != 1) {
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

#ifdef ENABLE_SM9
static int test_x509_sign_sm9(void)
{
	SM9_SIGN_MASTER_KEY sm9_sign_master_key;
	SM9_SIGN_KEY sm9_sign_key;
	char *id = "guan@pku.edu.cn";
	size_t idlen = strlen(id);
	X509_KEY x509_key;
	X509_SIGN_CTX sign_ctx;
	uint8_t msg[66];
	uint8_t sig[128]; // sm9 signature size = 104
	size_t siglen;

	if (sm9_sign_master_key_generate(&sm9_sign_master_key) != 1) {
		error_print();
		return -1;
	}
	if (sm9_sign_master_key_extract_key(&sm9_sign_master_key, id, idlen, &sm9_sign_key) != 1) {
		error_print();
		return -1;
	}

	if (x509_key_set_sm9_sign_key(&x509_key, &sm9_sign_key) != 1) {
		error_print();
		return -1;
	}
	if (x509_sign_init(&sign_ctx, &x509_key, OID_sm9sign, NULL, 0) != 1) {
		error_print();
		return -1;
	}
	if (x509_sign_update(&sign_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (x509_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	if (x509_key_set_sm9_sign_master_key(&x509_key, &sm9_sign_master_key) != 1) {
		error_print();
		return -1;
	}
	if (x509_verify_init(&sign_ctx, &x509_key, OID_sm9sign, id, idlen, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (x509_verify_update(&sign_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (x509_verify_finish(&sign_ctx) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

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
		if (tests[i].algor_param == OID_secp384r1) {
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

#ifdef ENABLE_KYBER
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
#endif

int main(void)
{
	if (test_x509_key_generate() != 1) goto err;
	if (test_x509_public_key_to_bytes() != 1) goto err;
	if (test_x509_public_key_info_to_der() != 1) goto err;
	if (test_x509_private_key_info_to_der() != 1) goto err;
	if (test_x509_private_key_info_encrypt_to_der() != 1) goto err;
	if (test_x509_private_key_info_encrypt_to_pem() != 1) goto err;
	if (test_x509_private_key_info_decrypt_from_pem() != 1) goto err;
	if (test_x509_sign() != 1) goto err;
#ifdef ENABLE_SM9
	if (test_x509_sign_sm9() != 1) goto err;
#endif
	if (test_x509_key_exchange() != 1) goto err;
#ifdef ENABLE_KYBER
	if (test_x509_kem() != 1) goto err;
#endif

	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
