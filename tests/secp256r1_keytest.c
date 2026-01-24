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
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/secp256r1_key.h>


static int test_secp256r1_key_generate(void)
{
	SECP256R1_KEY key;

	if (secp256r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	secp256r1_public_key_print(stderr, 0, 4, "public_key", &key);
	secp256r1_private_key_print(stderr, 0, 4, "private_key", &key);
	secp256r1_key_cleanup(&key);
	secp256r1_private_key_print(stderr, 0, 4, "private_key", &key);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_key_set_private_key(void)
{
	SECP256R1_KEY key;
	secp256r1_t private_key;
	uint8_t bytes[32];
	size_t len;

	// key = 1
	memset(bytes, 0, sizeof(bytes));
	bytes[31] = 1;
	secp256r1_from_32bytes(private_key, bytes);
	if (secp256r1_key_set_private_key(&key, private_key) != 1) {
		error_print();
		return -1;
	}
	secp256r1_private_key_print(stderr, 0, 4, "private_key = 1", &key);


	// key = n-1
	hex_to_bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550", 64, bytes, &len);
	secp256r1_from_32bytes(private_key, bytes);
	if (secp256r1_key_set_private_key(&key, private_key) != 1) {
		error_print();
		return -1;
	}


	// key = 0, should fail
	memset(bytes, 0, sizeof(bytes));
	secp256r1_from_32bytes(private_key, bytes);
	if (secp256r1_key_set_private_key(&key, private_key) >= 0) {
		error_print();
		return -1;
	}

	// key = n, should fail
	hex_to_bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 64, bytes, &len);
	secp256r1_from_32bytes(private_key, bytes);
	if (secp256r1_key_set_private_key(&key, private_key) >= 0) {
		error_print();
		return -1;
	}

	// key = 0xff..f, should fail
	memset(bytes, 0xff, sizeof(bytes));
	secp256r1_from_32bytes(private_key, bytes);
	if (secp256r1_key_set_private_key(&key, private_key) >= 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_public_key_to_bytes(void)
{
	SECP256R1_KEY key;
	SECP256R1_KEY key1;
	uint8_t bytes[512];
	uint8_t *p = bytes;
	const uint8_t *cp = bytes;
	size_t len = 0;

	if (secp256r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_from_bytes(&key1, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_equ(&key, &key1) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_public_key_to_der(void)
{
	SECP256R1_KEY key;
	SECP256R1_KEY key1;
	uint8_t bytes[512];
	uint8_t *p = bytes;
	const uint8_t *cp = bytes;
	size_t len = 0;

	if (secp256r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_to_der(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_from_der(&key1, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_equ(&key, &key1) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_private_key_to_der(void)
{
	SECP256R1_KEY key;
	SECP256R1_KEY key1;
	uint8_t bytes[512];
	uint8_t *p = bytes;
	const uint8_t *cp = bytes;
	size_t len = 0;

	if (secp256r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_private_key_to_der(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_private_key_from_der(&key1, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_equ(&key, &key1) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_private_key_info_to_der(void)
{
	SECP256R1_KEY key;
	SECP256R1_KEY key1;
	uint8_t bytes[512];
	uint8_t *p = bytes;
	const uint8_t *cp = bytes;
	size_t len = 0;
	const uint8_t *attrs;
	size_t attrslen;

	if (secp256r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_private_key_info_to_der(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_private_key_info_from_der(&key1, &attrs, &attrslen, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_equ(&key, &key1) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_private_key_info_encrypt_to_der(void)
{
	SECP256R1_KEY key;
	SECP256R1_KEY key1;
	uint8_t bytes[512];
	uint8_t *p = bytes;
	const uint8_t *cp = bytes;
	size_t len = 0;
	char *pass = "password";
	const uint8_t *attrs;
	size_t attrslen;

	if (secp256r1_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_private_key_info_encrypt_to_der(&key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_private_key_info_decrypt_from_der(&key1, &attrs, &attrslen, pass, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_equ(&key, &key1) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}









int main(void)
{
	if (test_secp256r1_key_generate() != 1) goto err;
//	if (test_secp256r1_key_set_private_key() != 1) goto err;
	if (test_secp256r1_public_key_to_bytes() != 1) goto err;
	if (test_secp256r1_public_key_to_der() != 1) goto err;
	if (test_secp256r1_private_key_to_der() != 1) goto err;
	if (test_secp256r1_private_key_info_to_der() != 1) goto err;
	if (test_secp256r1_private_key_info_encrypt_to_der() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}

