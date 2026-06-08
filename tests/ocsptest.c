/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License);
 *  you may not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/x509_crl.h>
#include <gmssl/ocsp.h>


static uint8_t issuer_name_hash[32] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
	0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
};

static uint8_t issuer_key_hash[32] = {
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
};

static uint8_t serial_number[] = { 0x05 };

static int test_ocsp_request_item(void)
{
	uint8_t buf[128];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int hash_algor;
	const uint8_t *name_hash;
	size_t name_hash_len;
	const uint8_t *key_hash;
	size_t key_hash_len;
	const uint8_t *serial;
	size_t serial_len;
	const uint8_t *single_request_exts;
	size_t single_request_exts_len;

	if (ocsp_request_item_to_der(OID_sm3,
			issuer_name_hash, sizeof(issuer_name_hash),
			issuer_key_hash, sizeof(issuer_key_hash),
			serial_number, sizeof(serial_number), NULL, 0, &p, &len) != 1) {
		error_print();
		return -1;
	}
	ocsp_request_item_print(stderr, 0, 0, "Request", buf, len);

	if (ocsp_request_item_from_der(&hash_algor,
			&name_hash, &name_hash_len,
			&key_hash, &key_hash_len,
			&serial, &serial_len,
			&single_request_exts, &single_request_exts_len, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| hash_algor != OID_sm3
		|| name_hash_len != sizeof(issuer_name_hash)
		|| memcmp(name_hash, issuer_name_hash, sizeof(issuer_name_hash)) != 0
		|| key_hash_len != sizeof(issuer_key_hash)
		|| memcmp(key_hash, issuer_key_hash, sizeof(issuer_key_hash)) != 0
		|| serial_len != sizeof(serial_number)
		|| memcmp(serial, serial_number, sizeof(serial_number)) != 0
		|| single_request_exts != NULL
		|| single_request_exts_len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_ocsp_request(void)
{
	uint8_t request_item[128];
	uint8_t *p = request_item;
	size_t request_item_len = 0;
	uint8_t req[256];
	const uint8_t *cp = req;
	size_t reqlen = 0;
	int version;
	const uint8_t *requestor_name;
	size_t requestor_name_len;
	const uint8_t *request_list;
	size_t request_list_len;
	const uint8_t *request_exts;
	size_t request_exts_len;
	const uint8_t *optional_signature;
	size_t optional_signature_len;
	const uint8_t *request;
	size_t request_len;
	int hash_algor;
	const uint8_t *name_hash;
	size_t name_hash_len;
	const uint8_t *key_hash;
	size_t key_hash_len;
	const uint8_t *serial;
	size_t serial_len;
	const uint8_t *single_request_exts;
	size_t single_request_exts_len;

	if (ocsp_request_item_to_der(OID_sm3,
			issuer_name_hash, sizeof(issuer_name_hash),
			issuer_key_hash, sizeof(issuer_key_hash),
			serial_number, sizeof(serial_number), NULL, 0,
			&p, &request_item_len) != 1) {
		error_print();
		return -1;
	}
	p = req;
	if (ocsp_request_to_der(-1, NULL, 0, request_item, request_item_len,
			NULL, 0, NULL, 0, &p, &reqlen) != 1) {
		error_print();
		return -1;
	}
	ocsp_request_print(stderr, 0, 0, "OCSPRequest", req, reqlen);

	if (ocsp_request_from_der(&version,
			&requestor_name, &requestor_name_len,
			&request_list, &request_list_len,
			&request_exts, &request_exts_len,
			&optional_signature, &optional_signature_len,
			&cp, &reqlen) != 1
		|| asn1_length_is_zero(reqlen) != 1
		|| version != X509_version_v1
		|| requestor_name != NULL
		|| requestor_name_len != 0
		|| request_exts != NULL
		|| request_exts_len != 0
		|| optional_signature != NULL
		|| optional_signature_len != 0) {
		error_print();
		return -1;
	}
	cp = request_list;
	reqlen = request_list_len;
	if (asn1_any_from_der(&request, &request_len, &cp, &reqlen) != 1
		|| asn1_length_is_zero(reqlen) != 1) {
		error_print();
		return -1;
	}
	cp = request;
	reqlen = request_len;
	if (ocsp_request_item_from_der(&hash_algor,
			&name_hash, &name_hash_len,
			&key_hash, &key_hash_len,
			&serial, &serial_len,
			&single_request_exts, &single_request_exts_len, &cp, &reqlen) != 1
		|| asn1_length_is_zero(reqlen) != 1
		|| hash_algor != OID_sm3
		|| name_hash_len != sizeof(issuer_name_hash)
		|| memcmp(name_hash, issuer_name_hash, sizeof(issuer_name_hash)) != 0
		|| key_hash_len != sizeof(issuer_key_hash)
		|| memcmp(key_hash, issuer_key_hash, sizeof(issuer_key_hash)) != 0
		|| serial_len != sizeof(serial_number)
		|| memcmp(serial, serial_number, sizeof(serial_number)) != 0
		|| single_request_exts != NULL
		|| single_request_exts_len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#ifdef ENABLE_SHA1
/*
 * Extracted from BoringSSL pki/testdata/ocsp_unittest/good_response_sha256.pem,
 * the embedded "OCSP REQUEST" block.
 */
static uint8_t ocsp_request_der[] = {
	0x30, 0x42, 0x30, 0x40, 0x30, 0x3e, 0x30, 0x3c,
	0x30, 0x3a, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x44,
	0x9b, 0x1c, 0x5b, 0x31, 0xc6, 0xe9, 0x99, 0x09,
	0x66, 0x52, 0x3e, 0x49, 0xc3, 0xf7, 0x73, 0xc0,
	0x24, 0x19, 0x0a, 0x04, 0x14, 0x34, 0x5c, 0xb2,
	0x8b, 0x1d, 0x8c, 0xdd, 0x6c, 0xbf, 0xf8, 0xf5,
	0xcc, 0xf4, 0x65, 0x21, 0xe8, 0x7a, 0x8d, 0xf3,
	0x91, 0x02, 0x01, 0x05,
};

static int test_ocsp_request_vector(void)
{
	const uint8_t *cp = ocsp_request_der;
	size_t len = sizeof(ocsp_request_der);
	int version;
	const uint8_t *requestor_name;
	size_t requestor_name_len;
	const uint8_t *request_list;
	size_t request_list_len;
	const uint8_t *request_exts;
	size_t request_exts_len;
	const uint8_t *optional_signature;
	size_t optional_signature_len;

	ocsp_request_print(stderr, 0, 0, "OCSPRequest", ocsp_request_der, sizeof(ocsp_request_der));

	if (ocsp_request_from_der(&version,
			&requestor_name, &requestor_name_len,
			&request_list, &request_list_len,
			&request_exts, &request_exts_len,
			&optional_signature, &optional_signature_len,
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| version != X509_version_v1
		|| requestor_name != NULL
		|| requestor_name_len != 0
		|| request_list == NULL
		|| request_list_len == 0
		|| request_exts != NULL
		|| request_exts_len != 0
		|| optional_signature != NULL
		|| optional_signature_len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

static int test_ocsp_single_response(void)
{
	uint8_t exts[128];
	uint8_t *p = exts;
	size_t extslen = 0;
	uint8_t buf[256];
	const uint8_t *cp;
	size_t len;
	int hash_algor;
	const uint8_t *name_hash;
	size_t name_hash_len;
	const uint8_t *key_hash;
	size_t key_hash_len;
	const uint8_t *serial;
	size_t serial_len;
	int cert_status;
	time_t revocation_time;
	int revocation_reason;
	time_t this_update;
	time_t next_update;
	const uint8_t *single_response_exts;
	size_t single_response_exts_len;

	/*
	if (ocsp_crl_id_print(stderr, 0, 0, "CrlID", NULL, 0) != 1) {
		error_print();
		return -1;
	}
	{
		uint8_t crl_url[64];
		uint8_t *crl_url_p = crl_url;
		size_t crl_url_len = 0;
		uint8_t crl_id[128];
		uint8_t *crl_id_p = crl_id;
		size_t crl_id_len = 0;
		const char *uri = "http://example.com/root.crl";

		if (asn1_ia5_string_to_der(uri, strlen(uri), &crl_url_p, &crl_url_len) != 1
			|| asn1_explicit_to_der(0, crl_url, crl_url_len, &crl_id_p, &crl_id_len) != 1
			|| ocsp_crl_id_print(stderr, 0, 0, "CrlID", crl_id, crl_id_len) != 1) {
			error_print();
			return -1;
		}
	}
	*/

	if (x509_crl_reason_ext_to_der(-1, X509_cr_key_compromise, &p, &extslen) != 1) {
		error_print();
		return -1;
	}

	p = buf;
	len = 0;
	if (ocsp_single_response_to_der(OID_sm3,
			issuer_name_hash, sizeof(issuer_name_hash),
			issuer_key_hash, sizeof(issuer_key_hash),
			serial_number, sizeof(serial_number),
			OCSP_cert_status_revoked, 1700000000, X509_cr_key_compromise,
			1700003600, 1700007200, exts, extslen, &p, &len) != 1) {
		error_print();
		return -1;
	}
	ocsp_single_response_print(stderr, 0, 0, "SingleResponse", buf, len);

	cp = buf;
	if (ocsp_single_response_from_der(&hash_algor,
			&name_hash, &name_hash_len,
			&key_hash, &key_hash_len,
			&serial, &serial_len,
			&cert_status, &revocation_time, &revocation_reason,
			&this_update, &next_update,
			&single_response_exts, &single_response_exts_len, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| hash_algor != OID_sm3
		|| name_hash_len != sizeof(issuer_name_hash)
		|| memcmp(name_hash, issuer_name_hash, sizeof(issuer_name_hash)) != 0
		|| key_hash_len != sizeof(issuer_key_hash)
		|| memcmp(key_hash, issuer_key_hash, sizeof(issuer_key_hash)) != 0
		|| serial_len != sizeof(serial_number)
		|| memcmp(serial, serial_number, sizeof(serial_number)) != 0
		|| cert_status != OCSP_cert_status_revoked
		|| revocation_time != 1700000000
		|| revocation_reason != X509_cr_key_compromise
		|| this_update != 1700003600
		|| next_update != 1700007200
		|| single_response_exts_len != extslen
		|| memcmp(single_response_exts, exts, extslen) != 0) {
		error_print();
		return -1;
	}

	p = buf;
	len = 0;
	if (ocsp_single_response_to_der(OID_sm3,
			issuer_name_hash, sizeof(issuer_name_hash),
			issuer_key_hash, sizeof(issuer_key_hash),
			serial_number, sizeof(serial_number),
			OCSP_cert_status_good, -1, -1,
			1700003600, -1, NULL, 0, &p, &len) != 1) {
		error_print();
		return -1;
	}
	ocsp_single_response_print(stderr, 0, 0, "SingleResponse", buf, len);

	cp = buf;
	if (ocsp_single_response_from_der(&hash_algor,
			&name_hash, &name_hash_len,
			&key_hash, &key_hash_len,
			&serial, &serial_len,
			&cert_status, &revocation_time, &revocation_reason,
			&this_update, &next_update,
			&single_response_exts, &single_response_exts_len, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| hash_algor != OID_sm3
		|| cert_status != OCSP_cert_status_good
		|| revocation_time != (time_t)-1
		|| revocation_reason != -1
		|| this_update != 1700003600
		|| next_update != (time_t)-1
		|| single_response_exts != NULL
		|| single_response_exts_len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_ocsp_single_response() != 1) goto err;
	if (test_ocsp_request_item() != 1) goto err;
	if (test_ocsp_request() != 1) goto err;
#ifdef ENABLE_SHA1
	if (test_ocsp_request_vector() != 1) goto err;
#endif
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
