/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>

#define BOOL_1	0
#define BOOL_2	1

#define INT_1	"\x00"
#define INT_2	"\x7f"
#define INT_3	"\x80"
#define INT_4	"\xff\xf0"

#define BITS_1		"\xff\xf0"
#define BITS_1_LEN	12

#define OCTETS_1	"\x12\x34\x45\x56"

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
	int i = 0;
	for (i = 0; i < 32; i++) {
		printf("%s\n", asn1_tag_name(i));
	}
	return 0;
}

static int test_asn1_length(void)
{
	int err = 0;
	size_t tests[] = {5, 127, 128, 256, 65537, 1<<23, (size_t)1<<31, };
	size_t val;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = ((size_t)1 << 32);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%zu ", tests[i]);
	}
	printf("\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_length_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		rv = asn1_length_from_der(&val, &cp, &left);
		assert(rv > 0);
		if (val != tests[i]) {
			error_print_msg("error decoding %zu-th length: get %zu, should be %zu", i, val, tests[i]);
			err++;
		}
	}

	printf("\n");
	return err;
}

static int test_asn1_boolean(void)
{
	int err = 0;
	int tests[] = {0, 1};
	int val;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%d ", tests[i]);
	}
	printf("\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_boolean_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		rv = asn1_boolean_from_der(&val, &cp, &left);
		assert(rv > 0);
		if (val != tests[i]) {
			error_print_msg("error decoding %zu-th: get %d, should be %d", i, val, tests[i]);
			err++;
		}
	}

	printf("\n");
	return err;
}

static int test_asn1_integer(void)
{
	int err = 0;
	int tests[] = {1, 127, 128, 65535, 65537, 1<<23, 1<<30, /* 0, -1 */ };
	int val;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%d ", tests[i]);
	}
	printf("\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_int_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		rv = asn1_int_from_der(&val, &cp, &left);
		assert(rv > 0);
		if (val != tests[i]) {
			error_print_msg("error decoding %zu-th: get %d, should be %d", i, val, tests[i]);
			err++;
		}
	}

	printf("\n");
	return err;
}

static int test_asn1_bit_string(void)
{
	int err = 0;
	int tests[] = {1, 0xfe, 0xff, 0xffff, 0xfffff };
	int val;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%d ", tests[i]);
	}
	printf("\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_bits_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		rv = asn1_bits_from_der(&val, &cp, &left);
		assert(rv > 0);
		if (val != tests[i]) {
			error_print_msg("error decoding %zu-th: get %d, should be %d", i, val, tests[i]);
			err++;
		}
	}

	printf("\n");
	return err;
}

static int test_asn1_null(void)
{
	int err = 0;
	int tests[6];
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("null ");
	}
	printf("\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_null_to_der(&p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		rv = asn1_null_from_der(&cp, &left);
		assert(rv > 0);
	}

	printf("\n");
	return err;
}

static int test_asn1_object_identifier(void)
{
	int err = 0;
	int tests[] = {1, 2, 3, 4, 5, 6};
	int val;
	uint32_t nodes[32];
	size_t nodes_count;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%d ", tests[i]);
	}
	printf("\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_object_identifier_to_der(tests[i], NULL, 0, &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		rv = asn1_object_identifier_from_der(&val, nodes, &nodes_count, &cp, &left);
		assert(rv > 0);
		if (val != tests[i]) {
			error_print_msg("error decoding %zu-th: get %d, should be %d", i, val, tests[i]);
			err++;
		}
		printf("%s\n", asn1_object_identifier_name(val));
	}

	printf("\n");
	return err;
}

static int test_asn1_printable_string(void)
{
	int err = 0;
	char *tests[] = {"hello", "world", "Just do it!"};
	const char *val;
	size_t vallen;
	uint32_t nodes[32];
	size_t nodes_count;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%s\n", tests[i]);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_printable_string_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		char str[256] = {0};
		rv = asn1_printable_string_from_der(&val, &vallen, &cp, &left);
		assert(rv > 0);
		memcpy(str, val, vallen);

		if (strcmp(str, tests[i]) != 0) {
			error_print_msg("error decoding %zu-th: get %s, should be %s", i, str, tests[i]);
			err++;
		}
		printf("%s\n", str);
	}

	printf("\n");
	return err;
}

static int test_asn1_utf8_string(void)
{
	int err = 0;
	char *tests[] = {"hello", "world", "Just do it!"};
	const char *val;
	size_t vallen;
	uint32_t nodes[32];
	size_t nodes_count;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%s\n", tests[i]);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_utf8_string_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		char str[256] = {0};
		rv = asn1_utf8_string_from_der(&val, &vallen, &cp, &left);
		assert(rv > 0);
		memcpy(str, val, vallen);

		if (strcmp(str, tests[i]) != 0) {
			error_print_msg("error decoding %zu-th: get %s, should be %s", i, str, tests[i]);
			err++;
		}
		printf("%s\n", str);
	}

	printf("\n");
	return err;
}

static int test_asn1_ia5_string(void)
{
	int err = 0;
	char *tests[] = {"hello", "world", "Just do it!"};
	const char *val;
	size_t vallen;
	uint32_t nodes[32];
	size_t nodes_count;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%s\n", tests[i]);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_ia5_string_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		char str[256] = {0};
		rv = asn1_ia5_string_from_der(&val, &vallen, &cp, &left);
		assert(rv > 0);
		memcpy(str, val, vallen);

		if (strcmp(str, tests[i]) != 0) {
			error_print_msg("error decoding %zu-th: get %s, should be %s", i, str, tests[i]);
			err++;
		}
		printf("%s\n", str);
	}

	printf("\n");
	return err;
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
	int err = 0;
	time_t tests[] = {0, 0, 1<<30 };
	time_t val;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	time(&tests[0]);

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%s", ctime(&tests[i]));
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_utc_time_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		rv = asn1_utc_time_from_der(&val, &cp, &left);
		assert(rv > 0);
		if (val != tests[i]) {
			error_print_msg("error decoding %zu-th: get %zu, should be %zu", i, val, tests[i]);
			err++;
		}
		printf("%s", ctime(&val));
	}

	printf("\n");
	return err;
}

static int test_asn1_generalized_time(void)
{
	int err = 0;
	time_t tests[] = {0, 1<<30};
	time_t val;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t left = sizeof(buf);
	size_t i;
	int rv;

	time(&tests[0]);

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%s", ctime(&tests[i]));
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		asn1_generalized_time_to_der(tests[i], &p, &len);
		print_buf(buf, len);
	}


	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		rv = asn1_generalized_time_from_der(&val, &cp, &left);
		assert(rv > 0);
		if (val != tests[i]) {
			error_print_msg("error decoding %zu-th: get %zu, should be %zu", i, val, tests[i]);
			err++;
		}
		printf("%s", ctime(&val));
	}

	printf("\n");
	return err;
}
















int main(void)
{
	int err = 0;
	err += test_asn1_tag();
	err += test_asn1_length();
	err += test_asn1_boolean();
	err += test_asn1_integer();
	//err += test_asn1_bit_string();
	err += test_asn1_null();
	err += test_asn1_object_identifier();
	err += test_asn1_printable_string();
	err += test_asn1_utf8_string();
	err += test_asn1_ia5_string();
	err += test_asn1_utc_time();
	err += test_asn1_generalized_time();

	return err;
}
