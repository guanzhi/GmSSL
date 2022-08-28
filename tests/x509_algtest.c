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
#include <gmssl/oid.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_x509_digest_algor(void)
{
	char *names[] = {
		"sm3",
		"md5",
		"sha1",
		"sha224",
		"sha256",
		"sha384",
		"sha512",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int oid;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_digest_algor_from_name(names[i]);
		if (x509_digest_algor_to_der(oid, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}

	format_print(stderr, 0, 0, "OID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_digest_algor_from_der(&oid, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (oid != x509_digest_algor_from_name(names[i])) {
			error_print();
			return 1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_digest_algor_name(oid));
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_encryption_algor(void)
{
	char *names[] = {
		"sm4-cbc",
		"aes128-cbc",
		"aes192-cbc",
		"aes256-cbc",
	};
	uint8_t iv[16] = {0};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int oid;
	const uint8_t *params;
	size_t paramslen;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_encryption_algor_from_name(names[i]);
		if (x509_encryption_algor_to_der(oid, iv, sizeof(iv), &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	format_print(stderr, 0, 0, "OID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_encryption_algor_from_der(&oid, &params, &paramslen, &cp, &len) != 1
			|| asn1_check(params != NULL) != 1
			|| asn1_check(paramslen == sizeof(iv)) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_encryption_algor_name(oid));
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_signature_algor(void)
{
	char *names[] = {
		"sm2sign-with-sm3",
		"rsasign-with-sm3",
		"ecdsa-with-sha1",
		"ecdsa-with-sha224",
		"ecdsa-with-sha256",
		"ecdsa-with-sha384",
		"ecdsa-with-sha512",
		"sha1WithRSAEncryption",
		"sha224WithRSAEncryption",
		"sha256WithRSAEncryption",
		"sha384WithRSAEncryption",
		"sha512WithRSAEncryption",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int oid;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_signature_algor_from_name(names[i]);
		if (x509_signature_algor_to_der(oid, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	format_print(stderr, 0, 0, "OID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_signature_algor_from_der(&oid, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_signature_algor_name(oid));
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_encryption_algor(void)
{
	char *names[] = {
		"sm2encrypt",
	//	"rsaesOAEP",
	//	"rsaEncryption",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int oid;
	const uint8_t *params;
	size_t paramslen;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_public_key_encryption_algor_from_name(names[i]);
		if (x509_public_key_encryption_algor_to_der(oid, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	format_print(stderr, 0, 0, "OID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_public_key_encryption_algor_from_der(&oid, &params, &paramslen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_public_key_encryption_algor_name(oid));
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_x509_digest_algor() != 1) goto err;
	if (test_x509_encryption_algor() != 1) goto err;
	if (test_x509_signature_algor() != 1) goto err;
	if (test_x509_public_key_encryption_algor() != 1) goto err;
	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
