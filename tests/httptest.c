/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/http.h>
#include <gmssl/x509_crl.h>
#include <gmssl/error.h>


static int test_http_parse_uri(void)
{
	char *tests[] = {
		"http://www.example.com:8080/ca/ca2023.crl",
		"http://www.example.com:80/ca/ca2023.crl",
		"http://www.example.com/ca/ca2023.crl",
		"http://www.example.com/ca2023.crl",
		"http://www.example.com:8080/",
		"http://www.example.com:8080",
		"http://www.example.com/",
		"http://www.example.com",
	};
	size_t i;

	char host[128];
	int port;
	char path[256];

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (http_parse_uri(tests[i], host, &port, path) != 1) {
			fprintf(stderr, "error: tests[%zu]: %s\n", i, tests[i]);
			error_print();
			return -1;
		}
		printf("%s: host = %s, port = %d, path = %s\n", tests[i], host, port, path);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_http_parse_uri_bad(void)
{
	char *tests[] = {
		"ldap://www.example.com:8080/ca/ca2023.crl",
		"http://www.example.com::8080/ca/ca2023.crl",
		"http://www.example.com:8080:/ca/ca2023.crl",
		"http://www.example.com:-100/ca/ca2023.crl",
		"http://www.example.com:/ca/ca2023.crl",
		"http:///ca2023.crl",
		"http:///",
		"http://",
	};
	size_t i;

	char host[128];
	int port;
	char path[256];

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (http_parse_uri(tests[i], host, &port, path) != -1) {
			fprintf(stderr, "error: tests[%zu]: %s\n", i, tests[i]);
			printf("%s: host = %s, port = %d, path = %s\n", tests[i], host, port, path);
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_http_get_crl(void)
{
	char *tests[] = {
		"http://crl.pki.goog/gsr1/gsr1.crl",
	};
	uint8_t buf[65536];
	size_t contentlen;
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (http_get(tests[i], buf, &contentlen, sizeof(buf)) != 1) {
			fprintf(stderr, "%s() tests[%zu] <%s> failure\n", __FUNCTION__, i, tests[i]);
			error_print();
			return -1;
		}
		x509_crl_print(stderr, 0, 0, "CRL", buf, contentlen);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_http_parse_uri() != 1) { error_print(); return -1; }
	if (test_http_parse_uri_bad() != 1) { error_print(); return -1; }
	if (test_http_get_crl() != 1) { error_print(); return -1; }
	printf("%s all tests passed\n", __FILE__);
	return 0;
}
