/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>

static void print_buf(const uint8_t *a, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		printf("%02x ", a[i]);
	}
	printf("\n");
}

static void print_integer(const uint8_t *a, size_t alen)
{
	size_t i;
	printf("integer = ");
	for (i = 0; i < alen; i++) {
		printf("%02x", a[i]);
	}
	printf("\n");
}

static void print_bits(const uint8_t *bits, size_t nbits)
{
	size_t i;
	printf("bits (%zu) = ", nbits);
	for (i = 0; i < (nbits + 7)/8; i++) {
		printf("%02x", bits[i]);
	}
	printf("\n");
}

static void print_octets(const uint8_t *o, size_t olen)
{
	size_t i;
	printf("octets (%zu) = ", olen);
	for (i = 0; i < olen; i++) {
		printf("%02x", o[i]);
	}
	printf("\n");
}

static int test_asn1_tag(void)
{
	int i;
	format_print(stderr, 0, 0, "Tags:\n");
	for (i = 1; i <= 13; i++) {
		format_print(stderr, 0, 4, "%s (0x%02x)\n", asn1_tag_name(i), i);
	}
	for (i = 18; i <= 30; i++) {
		format_print(stderr, 0, 4, "%s (0x%02x)\n", asn1_tag_name(i), i);
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_length(void)
{
	size_t tests[] = {
		0,
		5,
		127,
		128,
		256,
		344,
		65537,
		1<<23,
		(size_t)1<<31,
	};
	size_t length;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "Length:\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_length_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		int ret;
		ret = asn1_length_from_der(&length, &cp, &len);
		if (ret != 1 && ret != -2) {
			error_print();
			return -1;
		}
		if (length != tests[i]) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%zd\n", length);
	}
	if (len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_boolean(void)
{
	int tests[] = {0, 1};
	int val;
	uint8_t buf[128] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_BOOLEAN));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_boolean_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_boolean_from_der(&val, &cp, &len) != 1
			|| asn1_check(val == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", val ? "true" : "false");
	}
	if (len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_int(void)
{
	int tests[] = {
		0,
		1,
		127,
		128,
		65535,
		65537,
		1<<23,
		1<<30,
	};
	int val;
	uint8_t buf[256] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;
	int rv;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_INTEGER));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_int_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	// 测试 -1 表示默认不编码
	if (asn1_int_to_der(-1, &p, &len) != 0) {
		error_print();
		return -1;
	}

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_int_from_der(&val, &cp, &len) != 1
			|| asn1_check(val == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%d\n", val);
	}
	if (len != 0) {
		error_print();
		return -1;
	}

	// 测试返回0时是否对val值做初始化
	if (asn1_int_from_der(&val, &cp, &len) != 0) {
		error_print();
		return -1;
	}
	if (val != -1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_bits(void)
{
	int tests[] = {
		0x01,
		0x02,
		0x03,
		0x7f,
		0xfe,
		0xff,
		0xffff,
		0xfffff,
	};
	uint8_t der[] = {
		0x03,0x02,0x07,0x80,
		0x03,0x02,0x06,0x40,
		0x03,0x02,0x06,0xC0,
		0x03,0x02,0x01,0xFE,
		0x03,0x02,0x00,0x7F,
		0x03,0x02,0x00,0xFF,
		0x03,0x03,0x00,0xFF,0xFF,
		0x03,0x04,0x04,0xFF,0xFF,0xF0,
	};
	int bits;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_BIT_STRING));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_bits_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	if (sizeof(der) != len
		|| memcmp(der, buf, len) != 0) {
		error_print();
		return -1;
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_bits_from_der(&bits, &cp, &len) != 1
			|| asn1_check(bits == tests[i]) != 1) {
			error_print();
			return 1;
		}
		format_print(stderr, 0, 4, "%x\n", bits);
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_null(void)
{
	uint8_t buf[256] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "NULL\n");
	for (i = 0; i < 3; i++) {
		if (asn1_null_to_der(&p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < 3; i++) {
		if (asn1_null_from_der(&cp, &len) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", asn1_tag_name(ASN1_TAG_NULL));
	}
	if (asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_object_identifier(void)
{
	int err = 0;
	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_OBJECT_IDENTIFIER));

	if (1) {
		char *name = "sm2";
		uint32_t oid[] = { 1,2,156,10197,1,301 };
		uint8_t der[] = { 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D };
		uint32_t nodes[32];
		size_t nodes_cnt;
		uint8_t buf[128];
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		format_print(stderr, 0 ,4, "%s ", name);
		if (asn1_object_identifier_to_der(oid, sizeof(oid)/sizeof(int), &p, &len) != 1
			|| asn1_check(len == sizeof(der)) != 1
			|| asn1_check(memcmp(buf, der, sizeof(der)) == 0) != 1
			|| asn1_object_identifier_from_der(nodes, &nodes_cnt, &cp, &len) != 1
			|| asn1_length_is_zero(len) != 1
			|| asn1_object_identifier_equ(nodes, nodes_cnt, oid, sizeof(oid)/sizeof(int)) != 1) {
			printf("failed\n");
			error_print();
			err++;
		} else {
			printf("ok\n");
		}
	}

	if (2) {
		char *name = "x9.62-ecPublicKey";
		uint32_t oid[] = { 1,2,840,10045,2,1 };
		uint8_t der[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
		uint8_t buf[128];
		uint32_t nodes[32];
		size_t nodes_cnt;
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		format_print(stderr, 0 ,4, "%s ", name);
		if (asn1_object_identifier_to_der(oid, sizeof(oid)/sizeof(int), &p, &len) != 1
			|| asn1_check(len == sizeof(der)) != 1
			|| asn1_check(memcmp(buf, der, sizeof(der)) == 0) != 1
			|| asn1_object_identifier_from_der(nodes, &nodes_cnt, &cp, &len) != 1
			|| asn1_length_is_zero(len) != 1
			|| asn1_object_identifier_equ(nodes, nodes_cnt, oid, sizeof(oid)/sizeof(int)) != 1) {
			printf("failed\n");
			error_print();
			err++;
		} else {
			printf("ok\n");
		}
	}

	if (!err) printf("%s() ok\n", __FUNCTION__);
	return err;
}

static int test_asn1_printable_string(void)
{
	char *tests[] = {
		"hello",
		"world",
		"Just do it!",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_PrintableString));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_printable_string_to_der(tests[i], strlen(tests[i]), &p, &len) != 1) {
			error_print();
			return 1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		const char *d;
		size_t dlen;
		if (asn1_printable_string_from_der(&d, &dlen, &cp, &len) != 1
			|| strlen(tests[i]) != dlen
			|| memcmp(tests[i], d, dlen) != 0) {
			error_print();
			return 1;
		}
		format_string(stderr, 0, 4, "", (uint8_t *)d, dlen);
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_utf8_string(void)
{
	char *tests[] = {
		"hello",
		"world",
		"Just do it!",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_UTF8String));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_utf8_string_to_der(tests[i], strlen(tests[i]), &p, &len) != 1) {
			error_print();
			return 1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		const char *d;
		size_t dlen;
		if (asn1_utf8_string_from_der(&d, &dlen, &cp, &len) != 1
			|| strlen(tests[i]) != dlen
			|| memcmp(tests[i], d, dlen) != 0) {
			error_print();
			return 1;
		}
		format_string(stderr, 0, 4, "", (uint8_t *)d, dlen);
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_ia5_string(void)
{
	char *tests[] = {
		"hello",
		"world",
		"Just do it!",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_IA5String));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_ia5_string_to_der(tests[i], strlen(tests[i]), &p, &len) != 1) {
			error_print();
			return 1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		const char *d;
		size_t dlen;
		if (asn1_ia5_string_from_der(&d, &dlen, &cp, &len) != 1
			|| strlen(tests[i]) != dlen
			|| memcmp(tests[i], d, dlen) != 0) {
			error_print();
			return 1;
		}
		format_string(stderr, 0, 4, "", (uint8_t *)d, dlen);
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_time(void)
{
	time_t tval = 0;
	printf("%s", ctime(&tval));
	time(&tval);
	printf("%s", ctime(&tval));

	printf("%08x%08x\n", (uint32_t)(tval >> 32), (uint32_t)tval);

	return 0;
}

static int test_asn1_utc_time(void)
{
	time_t tests[] = {
		0,
		0,
		1<<30,
	};
	time_t tv;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	time(&tests[1]);

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_UTCTime));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_utc_time_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_utc_time_from_der(&tv, &cp, &len) != 1
			|| asn1_check(tv == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s", ctime(&tv));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_asn1_generalized_time(void)
{
	time_t tests[] = {
		0,
		1<<30,
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	time(&tests[0]);

	format_print(stderr, 0, 0, "%s\n", asn1_tag_name(ASN1_TAG_GeneralizedTime));
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (asn1_generalized_time_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return 1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		time_t tv;
		if (asn1_generalized_time_from_der(&tv, &cp, &len) != 1
			|| asn1_check(tv == tests[i]) != 1) {
			error_print();
			return 1;
		}
		format_print(stderr, 0, 4, "%s", ctime(&tv));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}


int main(void)
{
	int err = 0;
	err += test_asn1_tag();
	err += test_asn1_length();
	err += test_asn1_boolean();
	err += test_asn1_int();
	err += test_asn1_bits();
	err += test_asn1_null();
	err += test_asn1_object_identifier();
	err += test_asn1_printable_string();
	err += test_asn1_utf8_string();
	err += test_asn1_ia5_string();
	err += test_asn1_utc_time();
	err += test_asn1_generalized_time();
	return err;
}
