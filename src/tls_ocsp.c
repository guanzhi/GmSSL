/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/mem.h>
#include <gmssl/tls.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>



/*
status_request(5)

ClientHello.status_request
	ext_data := CertificateStatusRequest;
	struct {
		uint8 status_type = ocsp(1);
		opaque request<0..2^16-1>;
	} CertificateStatusRequest;

	request.data := OCSPStatusRequest;
	struct {
		ResponderID responder_id_list<0..2^16-1>;
		Extensions request_extensions;
	} OCSPStatusRequest;
*/

// 如果两个参数都为空的话，我们应该提供一个空的request			
int tls_ocsp_status_request_to_bytes(
	const uint8_t *responder_id_list, size_t responder_id_list_len, // optional
	const uint8_t *request_exts, size_t request_exts_len, // optinoal
	uint8_t **out, size_t *outlen)
{
	uint8_t **pp = out;
	size_t request_len = 0;
	size_t len;

	if (!outlen) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes(0, out, &len);
	tls_uint16array_to_bytes(responder_id_list, responder_id_list_len, out, &request_len);
	tls_uint16array_to_bytes(request_exts, request_exts_len, out, &request_len);
	tls_uint16array_to_bytes(NULL, request_len, pp, outlen);
	return 1;
}

int tls_ocsp_status_request_from_bytes(
	const uint8_t **responder_id_list, size_t *responder_id_list_len,
	const uint8_t **request_exts, size_t *request_exts_len,
	const uint8_t **in, size_t *inlen)
{
	const uint8_t *request;
	size_t request_len;

	if (!responder_id_list || !responder_id_list_len || !request_exts || !request_exts_len
		|| !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&request, &request_len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!request) {
		*responder_id_list = NULL;
		*responder_id_list_len = 0;
		*request_exts = NULL;
		*request_exts_len = 0;
		return 1;
	}
	if (tls_uint16array_from_bytes(responder_id_list, responder_id_list_len, &request, &request_len) != 1
		|| tls_uint16array_from_bytes(request_exts, request_exts_len, &request, &request_len) != 1
		|| tls_length_is_zero(request_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_ocsp_status_request_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *request;
	size_t request_len;
	const uint8_t *responder_id_list;
	size_t responder_id_list_len;
	const uint8_t *request_exts;
	size_t request_exts_len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (tls_uint16array_from_bytes(&request, &request_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!request) {
		format_print(fp, fmt, ind, "(null)\n");
		if (ext_datalen) {
			format_print(fp, fmt, ind, "error: left %zu bytes\n", ext_datalen);
			return -1;
		}
		return 1;
	}

	if (tls_uint16array_from_bytes(&responder_id_list, &responder_id_list_len, &request, &request_len) != 1
		|| tls_uint16array_from_bytes(&request_exts, &request_exts_len, &request, &request_len) != 1) {
		error_print();
		return -1;
	}
	while (responder_id_list_len) {
		const uint8_t *responder_id;
		size_t responder_id_len;

		if (tls_uint16array_from_bytes(&responder_id, &responder_id_len,
			&responder_id_list, &responder_id_list_len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(fp, fmt, ind + 4, "ResponderID", responder_id, responder_id_len);
	}
	while (request_exts_len) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &request_exts, &request_exts_len) != 1) {
			error_print();
			return -1;
		}
		// print
	}
	return 1;
}

int tls_client_status_request_ext_to_bytes(int status_type,
	const uint8_t *responder_id_list, size_t responder_id_list_len,
	const uint8_t *request_exts, size_t request_exts_len,
	uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_status_request;
	size_t ext_datalen = 0;
	uint8_t **pp = out;
	size_t len;

	if (!outlen) {
		error_print();
		return -1;
	}
	if (status_type != TLS_certificate_status_type_ocsp) {
		error_print();
		return -1;
	}
	tls_ext_to_bytes(ext_type, NULL, 0, out, &len);
	tls_uint8_to_bytes(status_type, out, &ext_datalen);
	tls_ocsp_status_request_to_bytes(responder_id_list, responder_id_list_len,
		request_exts, request_exts_len, out, &ext_datalen);
	tls_ext_to_bytes(ext_type, NULL, ext_datalen, pp, outlen);
	return 1;
}

int tls_client_status_request_from_bytes(int *status_type,
	const uint8_t **responder_id_list, size_t *responder_id_list_len,
	const uint8_t **request_exts, size_t *request_exts_len,
	const uint8_t *ext_data, size_t ext_datalen)
{
	uint8_t status;

	if (!status_type || !responder_id_list || !responder_id_list_len
		|| !request_exts || !request_exts_len || !ext_data || !ext_datalen) {
		error_print();
		return -1;
	}
	if (tls_uint8_from_bytes(&status, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (status != TLS_certificate_status_type_ocsp) {
		error_print();
		return -1;
	}
	*status_type = status;
	if (tls_ocsp_status_request_from_bytes(responder_id_list, responder_id_list_len,
		request_exts, request_exts_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_client_status_request_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	uint8_t status_type;
	const uint8_t *request;
	size_t request_len;

	if (tls_uint8_from_bytes(&status_type, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(&request, &request_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "status_type: %s (%d)\n", status_type == TLS_certificate_status_type_ocsp ? "ocsp" : NULL, status_type);

	request -= tls_uint16_size();
	request_len += tls_uint16_size();
	tls_ocsp_status_request_print(fp, fmt, ind, "request", request, request_len);

	return 1;
}

/*
Certificate.certificate_list.CertificateEntry.status_request
	ext_data := CertificateStatus;
	struct {
		CertificateStatusType status_type;
		opaque response<1..2^24-1>;
	} CertificateStatus;
*/

int tls_server_status_request_ext_to_bytes(const uint8_t *ocsp_response, size_t ocsp_response_len,
	uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_status_request;
	size_t ext_datalen = 0;
	uint8_t **pp = out;
	size_t len;

	if (!ocsp_response || !ocsp_response_len || !outlen) {
		error_print();
		return -1;
	}
	tls_ext_to_bytes(ext_type, NULL, 0, out, &len);
	tls_uint24array_to_bytes(ocsp_response, ocsp_response_len, out, &ext_datalen);
	tls_ext_to_bytes(ext_type, NULL, ext_datalen, pp, outlen);
	return 1;
}

int tls_server_status_request_from_bytes(const uint8_t **ocsp_response, size_t *ocsp_response_len,
	const uint8_t *ext_data, size_t ext_datalen)
{
	if (!ocsp_response || !ocsp_response_len || !ext_data || !ext_datalen) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(ocsp_response, ocsp_response_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_server_status_request_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *ocsp_response;
	size_t ocsp_response_len;

	if (tls_uint24array_from_bytes(&ocsp_response, &ocsp_response_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "ocsp_response", ocsp_response, ocsp_response_len);
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_set_client_status_request(TLS_CONNECT *conn,
	const uint8_t *status_request_responder_id_list, size_t status_request_responder_id_list_len, // optional
	const uint8_t *status_request_exts, size_t status_request_exts_len) // optional
{
	if (!conn) {
		error_print();
		return -1;
	}
	if (!conn->is_client) {
		error_print();
		return -1;
	}
	conn->status_request = 1;
	conn->status_request_responder_id_list = status_request_responder_id_list;
	conn->status_request_responder_id_list_len = status_request_responder_id_list_len;
	conn->status_request_exts = status_request_exts;
	conn->status_request_exts_len = status_request_exts_len;
	return 1;
}

int ocsp_response_verify(const uint8_t *ocsp_response, size_t ocsp_response_len,
	const uint8_t *ca_certs, size_t ca_certs_len)
{
	return 1;
}

int tls_ocsp_response_match_status_request(
	const uint8_t *status_request_ocsp_response, size_t status_request_ocsp_response_len,
	const uint8_t *responder_id_list, size_t responder_id_list_len,
	const uint8_t *request_exts, size_t request_exts_len)
{
	return 1;
}


