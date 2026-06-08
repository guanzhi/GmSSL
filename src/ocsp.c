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
#include <gmssl/x509_crl.h>
#include <gmssl/ocsp.h>


static const char *ocsp_cert_status_name(int status)
{
	switch (status) {
	case OCSP_cert_status_good:
		return "good";
	case OCSP_cert_status_revoked:
		return "revoked";
	case OCSP_cert_status_unknown:
		return "unknown";
	default:
		return NULL;
	}
}



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

	if (asn1_sequence_from_der(&seq, &seq_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "reqCert\n");
	if (asn1_sequence_from_der(&cert_id, &cert_id_len, &seq, &seq_len) != 1
		|| x509_digest_algor_from_der(&hash_algor, &cert_id, &cert_id_len) != 1
		|| asn1_octet_string_from_der(&issuer_name_hash, &issuer_name_hash_len, &cert_id, &cert_id_len) != 1
		|| asn1_octet_string_from_der(&issuer_key_hash, &issuer_key_hash_len, &cert_id, &cert_id_len) != 1
		|| asn1_integer_from_der(&serial, &serial_len, &cert_id, &cert_id_len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind + 4, "hashAlgorithm: %s\n", x509_digest_algor_name(hash_algor));
	format_bytes(fp, fmt, ind + 4, "issuerNameHash", issuer_name_hash, issuer_name_hash_len);
	format_bytes(fp, fmt, ind + 4, "issuerKeyHash", issuer_key_hash, issuer_key_hash_len);
	format_bytes(fp, fmt, ind + 4, "serialNumber", serial, serial_len);
	if (asn1_length_is_zero(cert_id_len) != 1
		|| x509_explicit_exts_from_der(0, &p, &len, &seq, &seq_len) < 0) {
		error_print();
		return -1;
	}
	if (p && x509_exts_print(fp, fmt, ind, "singleRequestExtensions", p, len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_length_is_zero(seq_len) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
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

	if (asn1_sequence_from_der(&seq, &seq_len, &d, &dlen) != 1
		|| asn1_sequence_from_der(&tbs_request, &tbs_request_len, &seq, &seq_len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "tbsRequest\n");
	ind += 4;
	if ((ret = x509_explicit_version_from_der(0, &version, &tbs_request, &tbs_request_len)) < 0) {
		error_print();
		return -1;
	}
	if (version == -1) version = X509_version_v1;
	if (ret) format_print(fp, fmt, ind, "version: v1 (%d)\n", version);
	if (version != X509_version_v1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_explicit_from_der(1, &p, &len, &tbs_request, &tbs_request_len)) < 0) {
		error_print();
		return -1;
	}
	if (ret) format_bytes(fp, fmt, ind, "requestorName", p, len);
	if (asn1_sequence_from_der(&request_list, &request_list_len, &tbs_request, &tbs_request_len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "requestList\n");
	while (request_list_len) {
		const uint8_t *request;
		size_t request_len;
		if (asn1_any_from_der(&request, &request_len, &request_list, &request_list_len) != 1
			|| ocsp_request_item_print(fp, fmt, ind + 4, "Request", request, request_len) != 1) {
			error_print();
			return -1;
		}
	}
	if (x509_explicit_exts_from_der(2, &p, &len, &tbs_request, &tbs_request_len) < 0) {
		error_print();
		return -1;
	}
	if (p && x509_exts_print(fp, fmt, ind, "requestExtensions", p, len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_length_is_zero(tbs_request_len) != 1) {
		error_print();
		return -1;
	}
	ind -= 4;
	if (asn1_explicit_from_der(0, &p, &len, &seq, &seq_len) < 0) {
		error_print();
		return -1;
	}
	if (p) format_bytes(fp, fmt, ind, "optionalSignature", p, len);
	if (asn1_length_is_zero(seq_len) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
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

/*
CrlID ::= SEQUENCE {
	crlUrl				[0] EXPLICIT IA5String OPTIONAL,
	crlNum				[1] EXPLICIT INTEGER OPTIONAL,
	crlTime				[2] EXPLICIT GeneralizedTime OPTIONAL }
*/
static int ocsp_crl_id_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;
	const char *crl_url;
	size_t crl_url_len;
	const uint8_t *crl_num;
	size_t crl_num_len;
	time_t crl_time;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (!d) {
		if (dlen) {
			error_print();
			return -1;
		}
		return 1;
	}
	if (asn1_explicit_from_der(0, &p, &len, &d, &dlen) < 0) {
		error_print();
		return -1;
	}
	if (p) {
		if (asn1_ia5_string_from_der(&crl_url, &crl_url_len, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "crlUrl: %.*s\n", (int)crl_url_len, crl_url);
	}
	if (asn1_explicit_from_der(1, &p, &len, &d, &dlen) < 0) {
		error_print();
		return -1;
	}
	if (p) {
		if (asn1_integer_from_der(&crl_num, &crl_num_len, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(fp, fmt, ind, "crlNum", crl_num, crl_num_len);
	}
	if (asn1_explicit_from_der(2, &p, &len, &d, &dlen) < 0) {
		error_print();
		return -1;
	}
	if (p) {
		if (asn1_generalized_time_from_der(&crl_time, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "crlTime: %s", ctime(&crl_time));
	}
	if (asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
ArchiveCutoff ::= GeneralizedTime
*/
static int ocsp_archive_cutoff_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen)
{
	time_t archive_cutoff;

	if (asn1_generalized_time_from_der(&archive_cutoff, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "%s: %s", label, ctime(&archive_cutoff));
	return 1;
}

int ocsp_single_response_to_der(int hash_algor,
	const uint8_t *issuer_name_hash, size_t issuer_name_hash_len,
	const uint8_t *issuer_key_hash, size_t issuer_key_hash_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int cert_status, time_t revocation_time, int revocation_reason,
	time_t this_update, time_t next_update,
	const uint8_t *exts, size_t extslen,
	uint8_t **out, size_t *outlen)
{
	size_t cert_id_len = 0;
	size_t revoked_info_len = 0;
	size_t revocation_reason_len = 0;
	size_t next_update_len = 0;
	size_t len = 0;

	if (!issuer_name_hash || !issuer_name_hash_len
		|| !issuer_key_hash || !issuer_key_hash_len
		|| !serial_number || !serial_number_len
		|| !ocsp_cert_status_name(cert_status)
		|| this_update == (time_t)-1) {
		error_print();
		return -1;
	}
	if (cert_status == OCSP_cert_status_revoked) {
		if (revocation_time == (time_t)-1) {
			error_print();
			return -1;
		}
	} else if (revocation_time != (time_t)-1 || revocation_reason != -1) {
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
	if (cert_status == OCSP_cert_status_revoked) {
		if (asn1_generalized_time_to_der(revocation_time, NULL, &revoked_info_len) != 1
			|| (revocation_reason >= 0
				&& x509_crl_reason_to_der(revocation_reason, NULL, &revocation_reason_len) != 1)) {
			error_print();
			return -1;
		}
		if (revocation_reason >= 0) {
			revoked_info_len += revocation_reason_len;
			if (asn1_explicit_header_to_der(0, revocation_reason_len, NULL, &revoked_info_len) != 1) {
				error_print();
				return -1;
			}
		}
	}
	if (next_update != (time_t)-1) {
		if (asn1_generalized_time_to_der(next_update, NULL, &next_update_len) != 1) {
			error_print();
			return -1;
		}
	}

	len = cert_id_len;
	if (asn1_sequence_header_to_der(cert_id_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	switch (cert_status) {
	case OCSP_cert_status_good:
		if (asn1_header_to_der(ASN1_TAG_IMPLICIT(0), 0, NULL, &len) != 1) {
			error_print();
			return -1;
		}
		break;
	case OCSP_cert_status_revoked:
		len += revoked_info_len;
		if (asn1_header_to_der(ASN1_TAG_EXPLICIT(1), revoked_info_len, NULL, &len) != 1) {
			error_print();
			return -1;
		}
		break;
	case OCSP_cert_status_unknown:
		if (asn1_header_to_der(ASN1_TAG_IMPLICIT(2), 0, NULL, &len) != 1) {
			error_print();
			return -1;
		}
		break;
	}
	if (asn1_generalized_time_to_der(this_update, NULL, &len) != 1
		|| (next_update != (time_t)-1 && asn1_explicit_header_to_der(0, next_update_len, NULL, &len) != 1)) {
		error_print();
		return -1;
	}
	if (next_update != (time_t)-1) {
		len += next_update_len;
	}
	if (x509_explicit_exts_to_der(1, exts, extslen, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_sequence_header_to_der(cert_id_len, out, outlen) != 1
		|| x509_digest_algor_to_der(hash_algor, out, outlen) != 1
		|| asn1_octet_string_to_der(issuer_name_hash, issuer_name_hash_len, out, outlen) != 1
		|| asn1_octet_string_to_der(issuer_key_hash, issuer_key_hash_len, out, outlen) != 1
		|| asn1_integer_to_der(serial_number, serial_number_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	switch (cert_status) {
	case OCSP_cert_status_good:
		if (asn1_header_to_der(ASN1_TAG_IMPLICIT(0), 0, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OCSP_cert_status_revoked:
		if (asn1_header_to_der(ASN1_TAG_EXPLICIT(1), revoked_info_len, out, outlen) != 1
			|| asn1_generalized_time_to_der(revocation_time, out, outlen) != 1) {
			error_print();
			return -1;
		}
		if (revocation_reason >= 0) {
			size_t reason_len = 0;
			if (x509_crl_reason_to_der(revocation_reason, NULL, &reason_len) != 1
				|| asn1_explicit_header_to_der(0, reason_len, out, outlen) != 1
				|| x509_crl_reason_to_der(revocation_reason, out, outlen) != 1) {
				error_print();
				return -1;
			}
		}
		break;
	case OCSP_cert_status_unknown:
		if (asn1_header_to_der(ASN1_TAG_IMPLICIT(2), 0, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	}
	if (asn1_generalized_time_to_der(this_update, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (next_update != (time_t)-1) {
		if (asn1_explicit_header_to_der(0, next_update_len, out, outlen) != 1
			|| asn1_generalized_time_to_der(next_update, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (x509_explicit_exts_to_der(1, exts, extslen, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int ocsp_single_response_from_der(int *hash_algor,
	const uint8_t **issuer_name_hash, size_t *issuer_name_hash_len,
	const uint8_t **issuer_key_hash, size_t *issuer_key_hash_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *cert_status, time_t *revocation_time, int *revocation_reason,
	time_t *this_update, time_t *next_update,
	const uint8_t **exts, size_t *extslen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	int tag;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *cert_id;
	size_t cert_id_len;
	const uint8_t *p;
	size_t len;
	const uint8_t *q;
	size_t qlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_sequence_from_der(&cert_id, &cert_id_len, &d, &dlen) != 1
		|| x509_digest_algor_from_der(hash_algor, &cert_id, &cert_id_len) != 1
		|| asn1_octet_string_from_der(issuer_name_hash, issuer_name_hash_len, &cert_id, &cert_id_len) != 1
		|| asn1_octet_string_from_der(issuer_key_hash, issuer_key_hash_len, &cert_id, &cert_id_len) != 1
		|| asn1_integer_from_der(serial_number, serial_number_len, &cert_id, &cert_id_len) != 1
		|| asn1_length_is_zero(cert_id_len) != 1) {
		error_print();
		return -1;
	}
	*revocation_time = (time_t)-1;
	*revocation_reason = -1;
	if (asn1_tag_from_der_readonly(&tag, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	switch (tag) {
	case ASN1_TAG_IMPLICIT(0):
		if (asn1_implicit_from_der(0, &p, &len, &d, &dlen) != 1
			|| len != 0) {
			error_print();
			return -1;
		}
		*cert_status = OCSP_cert_status_good;
		break;
	case ASN1_TAG_EXPLICIT(1):
		if (asn1_type_from_der(ASN1_TAG_EXPLICIT(1), &p, &len, &d, &dlen) != 1
			|| asn1_generalized_time_from_der(revocation_time, &p, &len) != 1
			|| asn1_explicit_from_der(0, &q, &qlen, &p, &len) < 0) {
			error_print();
			return -1;
		}
		if (q) {
			if (x509_crl_reason_from_der(revocation_reason, &q, &qlen) != 1
				|| asn1_length_is_zero(qlen) != 1) {
				error_print();
				return -1;
			}
		}
		if (asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		*cert_status = OCSP_cert_status_revoked;
		break;
	case ASN1_TAG_IMPLICIT(2):
		if (asn1_implicit_from_der(2, &p, &len, &d, &dlen) != 1
			|| len != 0) {
			error_print();
			return -1;
		}
		*cert_status = OCSP_cert_status_unknown;
		break;
	default:
		error_print();
		return -1;
	}
	if (asn1_generalized_time_from_der(this_update, &d, &dlen) != 1
		|| asn1_explicit_from_der(0, &p, &len, &d, &dlen) < 0) {
		error_print();
		return -1;
	}
	if (p) {
		if (asn1_generalized_time_from_der(next_update, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
	} else {
		*next_update = (time_t)-1;
	}
	if (x509_explicit_exts_from_der(1, exts, extslen, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int ocsp_revoked_info_print(FILE *fp, int fmt, int ind,
	const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;
	time_t tv;
	int reason;

	if (!d || !dlen) {
		error_print();
		return -1;
	}
	if (asn1_generalized_time_from_der(&tv, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "revocationTime: %s", ctime(&tv));
	if (asn1_explicit_from_der(0, &p, &len, &d, &dlen) < 0) {
		error_print();
		return -1;
	}
	if (p) {
		if (x509_crl_reason_from_der(&reason, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "revocationReason: %s\n", x509_crl_reason_name(reason));
	}
	if (asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static const uint32_t oid_pkix_ocsp_crl[] = { 1,3,6,1,5,5,7,48,1,3 };
static const uint32_t oid_pkix_ocsp_archive_cutoff[] = { 1,3,6,1,5,5,7,48,1,6 };

static int ocsp_single_response_ext_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen)
{
	int oid;
	int critical = -1;
	uint32_t nodes[32];
	size_t nodes_cnt = 0;
	const char *ext_name = NULL;
	const uint8_t *val;
	size_t vlen;
	const uint8_t *p;
	size_t len;
	time_t tv;
	int reason;

	if (!d || !dlen) {
		error_print();
		return -1;
	}
	if (x509_ext_id_from_der(&oid, nodes, &nodes_cnt, &d, &dlen) != 1
		|| asn1_boolean_from_der(&critical, &d, &dlen) < 0
		|| asn1_octet_string_from_der(&val, &vlen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "%s\n", label);

	// extnID
	if (asn1_object_identifier_equ(nodes, nodes_cnt,
		oid_pkix_ocsp_crl, oid_cnt(oid_pkix_ocsp_crl))) {
		oid = OID_pkix_ocsp_crl;
		ext_name = "CrlID";
	} else if (asn1_object_identifier_equ(nodes, nodes_cnt,
		oid_pkix_ocsp_archive_cutoff, oid_cnt(oid_pkix_ocsp_archive_cutoff))) {
		oid = OID_pkix_ocsp_archive_cutoff;
		ext_name = "ArchiveCutoff";
	}
	switch (oid) {
	case OID_ce_crl_reasons:
	case OID_ce_invalidity_date:
	case OID_ce_certificate_issuer:
		ext_name = x509_crl_entry_ext_id_name(oid);
		break;
	default:
		ext_name = x509_ext_id_name(oid);
	}
	asn1_object_identifier_print(fp, fmt, ind + 4, "extnID", ext_name, nodes, nodes_cnt);

	// critical
	if (critical != -1) {
		format_print(fp, fmt, ind + 4, "critical: %s\n", asn1_boolean_name(critical));
	}

	switch (oid) {
	case OID_pkix_ocsp_crl:
		if (asn1_sequence_from_der(&p, &len, &val, &vlen) != 1
			|| asn1_length_is_zero(vlen) != 1
			|| ocsp_crl_id_print(fp, fmt, ind + 4, "crlID", p, len) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_pkix_ocsp_archive_cutoff:
		if (ocsp_archive_cutoff_print(fp, fmt, ind + 4, "archiveCutoff", val, vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ce_crl_reasons:
		if (x509_crl_reason_from_der(&reason, &val, &vlen) != 1
			|| asn1_length_is_zero(vlen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind + 4, "reasonCode: %s\n", x509_crl_reason_name(reason));
		break;
	case OID_ce_invalidity_date:
		if (asn1_generalized_time_from_der(&tv, &val, &vlen) != 1
			|| asn1_length_is_zero(vlen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind + 4, "invalidityDate: %s", ctime(&tv));
		break;
	case OID_ce_certificate_issuer:
		if (asn1_sequence_from_der(&p, &len, &val, &vlen) != 1
			|| asn1_length_is_zero(vlen) != 1
			|| x509_general_names_print(fp, fmt, ind + 4, "certificateIssuer", p, len) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		format_bytes(fp, fmt, ind + 4, "extnValue", val, vlen);
		break;
	}
	return 1;
}

int ocsp_single_response_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen)
{
	const uint8_t *seq;
	size_t seq_len;
	const uint8_t *cert_id;
	size_t cert_id_len;
	const uint8_t *p;
	size_t len;
	const uint8_t *issuer_name_hash;
	size_t issuer_name_hash_len;
	const uint8_t *issuer_key_hash;
	size_t issuer_key_hash_len;
	const uint8_t *serial_number;
	size_t serial_number_len;
	int hash_algor;
	int cert_status;
	time_t tv;
	int tag;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&seq, &seq_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}

	// certID
	format_print(fp, fmt, ind, "certID\n");
	if (asn1_sequence_from_der(&cert_id, &cert_id_len, &seq, &seq_len) != 1
		|| x509_digest_algor_from_der(&hash_algor, &cert_id, &cert_id_len) != 1
		|| asn1_octet_string_from_der(&issuer_name_hash, &issuer_name_hash_len, &cert_id, &cert_id_len) != 1
		|| asn1_octet_string_from_der(&issuer_key_hash, &issuer_key_hash_len, &cert_id, &cert_id_len) != 1
		|| asn1_integer_from_der(&serial_number, &serial_number_len, &cert_id, &cert_id_len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind + 4, "hashAlgorithm: %s\n", x509_digest_algor_name(hash_algor));
	format_bytes(fp, fmt, ind + 4, "issuerNameHash", issuer_name_hash, issuer_name_hash_len);
	format_bytes(fp, fmt, ind + 4, "issuerKeyHash", issuer_key_hash, issuer_key_hash_len);
	format_bytes(fp, fmt, ind + 4, "serialNumber", serial_number, serial_number_len);
	if (asn1_length_is_zero(cert_id_len) != 1) {
		error_print();
		return -1;
	}

	// certStatus
	if (asn1_tag_from_der_readonly(&tag, &seq, &seq_len) != 1) {
		error_print();
		return -1;
	}
	switch (tag) {
	case ASN1_TAG_IMPLICIT(0):
		if (asn1_implicit_from_der(0, &p, &len, &seq, &seq_len) != 1 || len != 0) {
			error_print();
			return -1;
		}
		cert_status = OCSP_cert_status_good;
		format_print(fp, fmt, ind, "certStatus: %s\n", ocsp_cert_status_name(cert_status));
		break;
	case ASN1_TAG_EXPLICIT(1):
		if (asn1_type_from_der(ASN1_TAG_EXPLICIT(1), &p, &len, &seq, &seq_len) != 1) {
			error_print();
			return -1;
		}
		cert_status = OCSP_cert_status_revoked;
		format_print(fp, fmt, ind, "certStatus: %s\n", ocsp_cert_status_name(cert_status));
		if (ocsp_revoked_info_print(fp, fmt, ind + 4, p, len) != 1) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_IMPLICIT(2):
		if (asn1_implicit_from_der(2, &p, &len, &seq, &seq_len) != 1 || len != 0) {
			error_print();
			return -1;
		}
		cert_status = OCSP_cert_status_unknown;
		format_print(fp, fmt, ind, "certStatus: %s\n", ocsp_cert_status_name(cert_status));
		break;
	default:
		error_print();
		return -1;
	}

	// thisUpdate
	if (asn1_generalized_time_from_der(&tv, &seq, &seq_len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "thisUpdate: %s", ctime(&tv));

	// nextUpdate [0]
	if (asn1_explicit_from_der(0, &p, &len, &seq, &seq_len) < 0) {
		error_print();
		return -1;
	}
	if (p) {
		if (asn1_generalized_time_from_der(&tv, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "nextUpdate: %s", ctime(&tv));
	}

	// singleExtensions [1]
	if (x509_explicit_exts_from_der(1, &p, &len, &seq, &seq_len) < 0) {
		error_print();
		return -1;
	}
	if (p) {
		format_print(fp, fmt, ind, "singleExtensions\n");
	}
	while (len) {
		const uint8_t *ext;
		size_t ext_len;

		if (asn1_sequence_from_der(&ext, &ext_len, &p, &len) != 1
			|| ocsp_single_response_ext_print(fp, fmt, ind + 4, "Extension", ext, ext_len) != 1) {
			error_print();
			return -1;
		}
	}

	if (asn1_length_is_zero(seq_len) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
