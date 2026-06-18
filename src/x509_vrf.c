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
#include <stdint.h>
#include <gmssl/asn1.h>
#include <gmssl/oid.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_cer.h>
#include <gmssl/error.h>


static int x509_general_name_check(int choice, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;
	const uint8_t *q;
	size_t qlen;
	uint32_t nodes[32];
	size_t nodes_cnt;
	int tag;
	int ret;

	if (!d || !dlen) {
		error_print();
		return -1;
	}

	switch (choice) {
	case X509_gn_other_name:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1
			|| asn1_object_identifier_from_der(nodes, &nodes_cnt, &p, &len) != 1
			|| asn1_explicit_from_der(0, &q, &qlen, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		if (!qlen) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_rfc822_name:
	case X509_gn_dns_name:
	case X509_gn_uniform_resource_identifier:
		if (asn1_string_is_ia5_string((const char *)d, dlen) != 1) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_x400_address:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1
			|| !len) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_directory_name:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1
			|| x509_name_check(p, len) != 1) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_edi_party_name:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_explicit_directory_name_from_der(0, &tag, &q, &qlen, &p, &len)) < 0) {
			error_print();
			return -1;
		}
		if (ret && x509_directory_name_check(tag, q, qlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_explicit_directory_name_from_der(1, &tag, &q, &qlen, &p, &len) != 1
			|| x509_directory_name_check(tag, q, qlen) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_ip_address:
		if (dlen != 4 && dlen != 16) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_registered_id:
		if (asn1_object_identifier_from_octets(nodes, &nodes_cnt, d, dlen) != 1) {
			error_print();
			return -1;
		}
		break;

	default:
		error_print();
		return -1;
	}

	return 1;
}

static int x509_general_names_check(const uint8_t *d, size_t dlen)
{
	int choice;
	const uint8_t *name;
	size_t namelen;

	if (!d || !dlen) {
		error_print();
		return -1;
	}

	while (dlen) {
		if (x509_general_name_from_der(&choice, &name, &namelen, &d, &dlen) != 1
			|| x509_general_name_check(choice, name, namelen) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int x509_cert_check_subject(const uint8_t *cert, size_t certlen, int cert_type)
{
	int ret;
	int is_cacert;
	const uint8_t *subject;
	size_t subject_len;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *val;
	size_t vlen;
	const uint8_t *gns;
	size_t gnslen;
	int critical;

	if (!cert || !certlen) {
		error_print();
		return -1;
	}

	switch (cert_type) {
	case X509_cert_server_auth:
	case X509_cert_client_auth:
	case X509_cert_server_key_encipher:
	case X509_cert_client_key_encipher:
		is_cacert = 0;
		break;
	case X509_cert_ca:
	case X509_cert_root_ca:
	case X509_cert_crl_sign:
		is_cacert = 1;
		break;
	default:
		error_print();
		return -1;
	}

	if (x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_name_check(subject, subject_len)) < 0) {
		error_print();
		return -1;
	}

	if (ret == 0) {
		if (is_cacert) {
			error_print();
			return -1;
		}

		if (x509_cert_get_exts(cert, certlen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		if (x509_exts_get_ext_by_oid(exts, extslen, OID_ce_subject_alt_name, &critical, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		if (critical != X509_critical) {
			error_print();
			return -1;
		}
		if (asn1_sequence_from_der(&gns, &gnslen, &val, &vlen) != 1
			|| asn1_length_is_zero(vlen) != 1
			|| x509_general_names_check(gns, gnslen) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}
