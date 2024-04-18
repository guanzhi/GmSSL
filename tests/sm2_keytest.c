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
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/pkcs8.h>


static int test_sm2_private_key(void)
{
	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	uint8_t buf[SM2_PRIVATE_KEY_BUF_SIZE];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "ECPrivateKey", buf, len);
	format_print(stderr, 0, 4, "#define SM2_PRIVATE_KEY_DEFAULT_SIZE %zu\n", len);
	if (sm2_private_key_from_der(&tmp_key, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	if (memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {

		sm2_key_print(stderr, 0, 0, "sm2_key", &sm2_key);
		sm2_key_print(stderr, 0, 0, "tmp_key", &tmp_key);


		error_print();
		return -1;
	}

	cp = p = buf; len = 0;
	memset(&tmp_key, 0, sizeof(tmp_key));
	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	sm2_private_key_print(stderr, 0, 4, "ECPrivateKey", d, dlen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_private_key_info(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	const uint8_t *attrs;
	size_t attrs_len;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_info_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "PrivateKeyInfo", buf, len);
	format_print(stderr, 0, 4, "sizeof(PrivateKeyInfo): %zu\n", len);
	if (asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	sm2_private_key_info_print(stderr, 0, 4, "PrivateKeyInfo", d, dlen);

	cp = p = buf; len = 0;
	if (sm2_private_key_info_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_from_der(&tmp_key, &attrs, &attrs_len, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_enced_private_key_info(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	const uint8_t *attrs;
	size_t attrs_len;
	const char *pass = "Password";

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_info_encrypt_to_der(&sm2_key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "EncryptedPrivateKeyInfo", buf, len);
	format_print(stderr, 0, 4, "sizeof(EncryptedPrivateKeyInfo): %zu\n", len);
	if (asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pkcs8_enced_private_key_info_print(stderr, 0, 4, "EncryptedPrivateKeyInfo", d, dlen);


	cp = p = buf; len = 0;
	if (sm2_private_key_info_encrypt_to_der(&sm2_key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_decrypt_from_der(&tmp_key, &attrs, &attrs_len, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


int main(void)
{
	if (test_sm2_private_key() != 1) goto err;
	if (test_sm2_private_key_info() != 1) goto err;
	if (test_sm2_enced_private_key_info() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
