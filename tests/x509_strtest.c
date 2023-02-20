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
#include <gmssl/x509_ext.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>

static int test_x509_directory_name(void)
{
	uint8_t str[] = { 'a', 'b', 'c', 0 };
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int tag;
	const uint8_t *d;
	size_t dlen;

	if (x509_directory_name_check_ex(ASN1_TAG_UTF8String, str, 3, 1, 10) != 1  // str,4 will fail
		|| x509_directory_name_to_der(ASN1_TAG_UTF8String, str, 3, &p, &len) != 1
		|| x509_directory_name_from_der(&tag, &d, &dlen, &cp, &len) != 1
		|| asn1_check(tag == ASN1_TAG_UTF8String) != 1
		|| asn1_check(dlen == 3) != 1
		|| asn1_check(memcmp(str, d, dlen) == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_display_text(void)
{
	uint8_t str[] = { 'a', 'b', 'c', 0 };
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int tag;
	const uint8_t *d;
	size_t dlen;

	if (x509_display_text_check(ASN1_TAG_UTF8String, str, 3) != 1  // str,4 will fail
		|| x509_display_text_to_der(ASN1_TAG_UTF8String, str, 3, &p, &len) != 1
		|| x509_display_text_from_der(&tag, &d, &dlen, &cp, &len) != 1
		|| asn1_check(tag == ASN1_TAG_UTF8String) != 1
		|| asn1_check(dlen == 3) != 1
		|| asn1_check(memcmp(str, d, dlen) == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_x509_directory_name() != 1) goto err;
	if (test_x509_display_text() != 1) goto err;
	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
