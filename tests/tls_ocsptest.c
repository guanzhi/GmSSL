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
#include <gmssl/tls.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>

static int test_tls_ocsp_status_request(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *responder_id_list = NULL;
	size_t responder_id_list_len = 0;
	const uint8_t *request_exts = NULL;
	size_t request_exts_len = 0;


	if (tls_ocsp_status_request_to_bytes(responder_id_list, responder_id_list_len,
		request_exts, request_exts_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "ocsp_status_request_len = %zu\n", len);
	len = 0;

	if (tls_ocsp_status_request_to_bytes(responder_id_list, responder_id_list_len,
		request_exts, request_exts_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "ocsp_status_request", buf, len);

	tls_ocsp_status_request_print(stderr, 0, 0, "ocsp_status_request", buf, len);

	if (tls_ocsp_status_request_from_bytes(&responder_id_list, &responder_id_list_len,
		&request_exts, &request_exts_len, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	//format_bytes(stderr, 0, 4, "responder_id_list", responder_id_list, responder_id_list_len);
	//format_bytes(stderr, 0, 4, "request_exts", request_exts, request_exts_len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_client_status_request_ext(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	int ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;

	int status_type = 0;
	const uint8_t *responder_id_list = NULL;
	size_t responder_id_list_len = 0;
	const uint8_t *request_exts = NULL;
	size_t request_exts_len = 0;

	if (tls_client_status_request_ext_to_bytes(TLS_certificate_status_type_ocsp,
		responder_id_list, responder_id_list_len,
		request_exts, request_exts_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "tls_client_status_request_ext_len = %zu\n", len);
	len = 0;

	if (tls_client_status_request_ext_to_bytes(TLS_certificate_status_type_ocsp,
		responder_id_list, responder_id_list_len,
		request_exts, request_exts_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 0, "status_request_ext", buf, len);

	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (ext_type != TLS_extension_status_request) {
		error_print();
		return -1;
	}
	tls_client_status_request_print(stderr, 0, 4, ext_data, ext_datalen);

	if (tls_client_status_request_from_bytes(&status_type,
		&responder_id_list, &responder_id_list_len,
		&request_exts, &request_exts_len, ext_data, ext_datalen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_tls_ocsp_status_request() != 1) goto err;
	if (test_tls_client_status_request_ext() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
