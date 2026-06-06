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
#include <stdint.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/ocsp.h>


int ocsp_request_item_to_der(int hash_algor,
	const uint8_t *issuer_name_hash, size_t issuer_name_hash_len,
	const uint8_t *issuer_key_hash, size_t issuer_key_hash_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *single_request_exts, size_t single_request_exts_len,
	uint8_t **out, size_t *outlen)
{
	size_t cert_id_len = 0;
	size_t len = 0;

	if (!issuer_name_hash || !issuer_name_hash_len
		|| !issuer_key_hash || !issuer_key_hash_len
		|| !serial_number || !serial_number_len) {
		error_print();
		return -1;
	}
	if (x509_digest_algor_to_der(hash_algor, NULL, &cert_id_len) != 1
		|| asn1_octet_string_to_der(issuer_name_hash, issuer_name_hash_len, NULL, &cert_id_len) != 1
		|| asn1_octet_string_to_der(issuer_key_hash, issuer_key_hash_len, NULL, &cert_id_len) != 1
		|| asn1_integer_to_der(serial_number, serial_number_len, NULL, &cert_id_len) != 1) {
		error_print();
		return -1;
	}
	len = cert_id_len;
	if (asn1_sequence_header_to_der(cert_id_len, NULL, &len) != 1
		|| x509_explicit_exts_to_der(0, single_request_exts, single_request_exts_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_sequence_header_to_der(cert_id_len, out, outlen) != 1
		|| x509_digest_algor_to_der(hash_algor, out, outlen) != 1
		|| asn1_octet_string_to_der(issuer_name_hash, issuer_name_hash_len, out, outlen) != 1
		|| asn1_octet_string_to_der(issuer_key_hash, issuer_key_hash_len, out, outlen) != 1
		|| asn1_integer_to_der(serial_number, serial_number_len, out, outlen) != 1
		|| x509_explicit_exts_to_der(0, single_request_exts, single_request_exts_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int ocsp_request_item_from_der(int *hash_algor,
	const uint8_t **issuer_name_hash, size_t *issuer_name_hash_len,
	const uint8_t **issuer_key_hash, size_t *issuer_key_hash_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **single_request_exts, size_t *single_request_exts_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *cert_id;
	size_t cert_id_len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_sequence_from_der(&cert_id, &cert_id_len, &d, &dlen) != 1
		|| x509_digest_algor_from_der(hash_algor, &cert_id, &cert_id_len) != 1
		|| asn1_octet_string_from_der(issuer_name_hash, issuer_name_hash_len, &cert_id, &cert_id_len) != 1
		|| asn1_octet_string_from_der(issuer_key_hash, issuer_key_hash_len, &cert_id, &cert_id_len) != 1
		|| asn1_integer_from_der(serial_number, serial_number_len, &cert_id, &cert_id_len) != 1
		|| asn1_length_is_zero(cert_id_len) != 1
		|| x509_explicit_exts_from_der(0, single_request_exts, single_request_exts_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int ocsp_request_item_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen)
{
	const uint8_t *seq;
	size_t seq_len;
	const uint8_t *p;
	size_t len;
	const uint8_t *cert_id;
	size_t cert_id_len;
	int hash_algor;
	const uint8_t *issuer_name_hash;
	size_t issuer_name_hash_len;
	const uint8_t *issuer_key_hash;
	size_t issuer_key_hash_len;
	const uint8_t *serial;
	size_t serial_len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&seq, &seq_len, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "reqCert\n");
	if (asn1_sequence_from_der(&cert_id, &cert_id_len, &seq, &seq_len) != 1) goto err;
	if (x509_digest_algor_from_der(&hash_algor, &cert_id, &cert_id_len) != 1) goto err;
	if (asn1_octet_string_from_der(&issuer_name_hash, &issuer_name_hash_len, &cert_id, &cert_id_len) != 1) goto err;
	if (asn1_octet_string_from_der(&issuer_key_hash, &issuer_key_hash_len, &cert_id, &cert_id_len) != 1) goto err;
	if (asn1_integer_from_der(&serial, &serial_len, &cert_id, &cert_id_len) != 1) goto err;
	format_print(fp, fmt, ind + 4, "hashAlgorithm: %s\n", x509_digest_algor_name(hash_algor));
	format_bytes(fp, fmt, ind + 4, "issuerNameHash", issuer_name_hash, issuer_name_hash_len);
	format_bytes(fp, fmt, ind + 4, "issuerKeyHash", issuer_key_hash, issuer_key_hash_len);
	format_bytes(fp, fmt, ind + 4, "serialNumber", serial, serial_len);
	if (asn1_length_is_zero(cert_id_len) != 1) goto err;
	if (x509_explicit_exts_from_der(0, &p, &len, &seq, &seq_len) < 0) goto err;
	if (p) x509_exts_print(fp, fmt, ind, "singleRequestExtensions", p, len);
	if (asn1_length_is_zero(seq_len) != 1) goto err;
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int ocsp_request_to_der(int version,
	const uint8_t *requestor_name, size_t requestor_name_len,
	const uint8_t *request_list, size_t request_list_len,
	const uint8_t *request_exts, size_t request_exts_len,
	const uint8_t *optional_signature, size_t optional_signature_len,
	uint8_t **out, size_t *outlen)
{
	size_t tbs_request_len = 0;
	size_t len = 0;

	if (!request_list || !request_list_len) {
		error_print();
		return -1;
	}
	if ((version >= 0 && x509_explicit_version_to_der(0, version, NULL, &tbs_request_len) != 1)
		|| asn1_explicit_to_der(1, requestor_name, requestor_name_len, NULL, &tbs_request_len) < 0
		|| asn1_sequence_to_der(request_list, request_list_len, NULL, &tbs_request_len) != 1
		|| x509_explicit_exts_to_der(2, request_exts, request_exts_len, NULL, &tbs_request_len) < 0) {
		error_print();
		return -1;
	}
	len = tbs_request_len;
	if (asn1_sequence_header_to_der(tbs_request_len, NULL, &len) != 1
		|| asn1_explicit_to_der(0, optional_signature, optional_signature_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_sequence_header_to_der(tbs_request_len, out, outlen) != 1
		|| (version >= 0 && x509_explicit_version_to_der(0, version, out, outlen) != 1)
		|| asn1_explicit_to_der(1, requestor_name, requestor_name_len, out, outlen) < 0
		|| asn1_sequence_to_der(request_list, request_list_len, out, outlen) != 1
		|| x509_explicit_exts_to_der(2, request_exts, request_exts_len, out, outlen) < 0
		|| asn1_explicit_to_der(0, optional_signature, optional_signature_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int ocsp_request_from_der(int *version,
	const uint8_t **requestor_name, size_t *requestor_name_len,
	const uint8_t **request_list, size_t *request_list_len,
	const uint8_t **request_exts, size_t *request_exts_len,
	const uint8_t **optional_signature, size_t *optional_signature_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *tbs_request;
	size_t tbs_request_len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	*version = X509_version_v1;
	if (asn1_sequence_from_der(&tbs_request, &tbs_request_len, &d, &dlen) != 1
		|| x509_explicit_version_from_der(0, version, &tbs_request, &tbs_request_len) < 0
		|| asn1_explicit_from_der(1, requestor_name, requestor_name_len, &tbs_request, &tbs_request_len) < 0
		|| asn1_sequence_from_der(request_list, request_list_len, &tbs_request, &tbs_request_len) != 1
		|| x509_explicit_exts_from_der(2, request_exts, request_exts_len, &tbs_request, &tbs_request_len) < 0
		|| asn1_length_is_zero(tbs_request_len) != 1
		|| asn1_explicit_from_der(0, optional_signature, optional_signature_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version == -1) {
		*version = X509_version_v1;
	}
	if (*version != X509_version_v1) {
		error_print();
		return -1;
	}
	return 1;
}

int ocsp_request_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen)
{
	const uint8_t *seq;
	size_t seq_len;
	const uint8_t *p;
	size_t len;
	const uint8_t *tbs_request;
	size_t tbs_request_len;
	const uint8_t *request_list;
	size_t request_list_len;
	int ret;
	int version = X509_version_v1;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&seq, &seq_len, &d, &dlen) != 1) goto err;
	if (asn1_sequence_from_der(&tbs_request, &tbs_request_len, &seq, &seq_len) != 1) goto err;
	format_print(fp, fmt, ind, "tbsRequest\n");
	ind += 4;
	if ((ret = x509_explicit_version_from_der(0, &version, &tbs_request, &tbs_request_len)) < 0) goto err;
	if (version == -1) version = X509_version_v1;
	if (ret) format_print(fp, fmt, ind, "version: v1 (%d)\n", version);
	if (version != X509_version_v1) goto err;
	if ((ret = asn1_explicit_from_der(1, &p, &len, &tbs_request, &tbs_request_len)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "requestorName", p, len);
	if (asn1_sequence_from_der(&request_list, &request_list_len, &tbs_request, &tbs_request_len) != 1) goto err;
	format_print(fp, fmt, ind, "requestList\n");
	while (request_list_len) {
		const uint8_t *request;
		size_t request_len;
		if (asn1_any_from_der(&request, &request_len, &request_list, &request_list_len) != 1) goto err;
		if (ocsp_request_item_print(fp, fmt, ind + 4, "Request", request, request_len) != 1) goto err;
	}
	if (x509_explicit_exts_from_der(2, &p, &len, &tbs_request, &tbs_request_len) < 0) goto err;
	if (p) x509_exts_print(fp, fmt, ind, "requestExtensions", p, len);
	if (asn1_length_is_zero(tbs_request_len) != 1) goto err;
	ind -= 4;
	if (asn1_explicit_from_der(0, &p, &len, &seq, &seq_len) < 0) goto err;
	if (p) format_bytes(fp, fmt, ind, "optionalSignature", p, len);
	if (asn1_length_is_zero(seq_len) != 1) goto err;
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int ocsp_request_generate(uint8_t *req, size_t *reqlen, size_t maxlen,
	const uint8_t *cert, size_t certlen,
	const uint8_t *issuer_cert, size_t issuer_certlen,
	const DIGEST *digest_algor)
{
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *issuer_subject;
	size_t issuer_subject_len;
	const uint8_t *serial;
	size_t serial_len;
	X509_KEY issuer_public_key;
	uint8_t issuer_name[512];
	uint8_t *issuer_name_ptr = issuer_name;
	size_t issuer_name_len = 0;
	uint8_t issuer_name_hash[DIGEST_MAX_SIZE];
	size_t issuer_name_hash_len;
	uint8_t issuer_key_hash[DIGEST_MAX_SIZE];
	size_t issuer_key_hash_len;
	uint8_t request_list[256];
	uint8_t *request_list_ptr = request_list;
	size_t request_list_len = 0;
	uint8_t *out;
	size_t outlen = 0;
	size_t len = 0;

	if (!req || !reqlen || !digest_algor
		|| !cert || !certlen || !issuer_cert || !issuer_certlen) {
		error_print();
		return -1;
	}
	out = req;

	if (x509_cert_get_issuer_and_serial_number(cert, certlen, &issuer, &issuer_len, &serial, &serial_len) != 1
		|| x509_cert_get_subject(issuer_cert, issuer_certlen, &issuer_subject, &issuer_subject_len) != 1
		|| x509_cert_get_subject_public_key(issuer_cert, issuer_certlen, &issuer_public_key) != 1
		|| x509_name_equ(issuer, issuer_len, issuer_subject, issuer_subject_len) != 1) {
		error_print();
		return -1;
	}

	// issuer_name_hash
	if (asn1_sequence_to_der(issuer_subject, issuer_subject_len, NULL, &len) != 1
		|| asn1_length_le(len, sizeof(issuer_name)) != 1
		|| asn1_sequence_to_der(issuer_subject, issuer_subject_len, &issuer_name_ptr, &issuer_name_len) != 1
		|| digest(digest_algor, issuer_name, issuer_name_len, issuer_name_hash, &issuer_name_hash_len) != 1) {
		error_print();
		return -1;
	}
	len = 0;

	// issuer_key_hash
	if (x509_public_key_digest_ex(&issuer_public_key, digest_algor, issuer_key_hash, &issuer_key_hash_len) != 1) {
		error_print();
		return -1;
	}

	// request_list
	if (ocsp_request_item_to_der(digest_algor->oid,
			issuer_name_hash, issuer_name_hash_len,
			issuer_key_hash, issuer_key_hash_len,
			serial, serial_len, NULL, 0, NULL, &len) != 1
		|| asn1_length_le(len, sizeof(request_list)) != 1
		|| ocsp_request_item_to_der(digest_algor->oid,
			issuer_name_hash, issuer_name_hash_len,
			issuer_key_hash, issuer_key_hash_len,
			serial, serial_len, NULL, 0, &request_list_ptr, &request_list_len) != 1) {
		error_print();
		return -1;
	}
	len = 0;

	if (ocsp_request_to_der(-1, NULL, 0, request_list, request_list_len, NULL, 0, NULL, 0, NULL, &len) != 1
		|| asn1_length_le(len, maxlen) != 1
		|| ocsp_request_to_der(-1, NULL, 0, request_list, request_list_len, NULL, 0, NULL, 0, &out, &outlen) != 1) {
		error_print();
		return -1;
	}

	*reqlen = outlen;
	return 1;
}
