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



static int x509_cert_get_authority_key_identifier_keyid(const uint8_t *cert, size_t certlen,
	const uint8_t **keyid, size_t *keyid_len,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial, size_t *serial_len)
{
	int ret;
	int critical;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *val;
	size_t vlen;

	if (!cert || !certlen || !keyid || !keyid_len
		|| !issuer || !issuer_len || !serial || !serial_len) {
		error_print();
		return -1;
	}

	*keyid = NULL;
	*keyid_len = 0;
	*issuer = NULL;
	*issuer_len = 0;
	*serial = NULL;
	*serial_len = 0;

	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_authority_key_identifier,
		&critical, &val, &vlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if (x509_authority_key_identifier_from_der(keyid, keyid_len,
		issuer, issuer_len, serial, serial_len, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int x509_cert_get_subject_key_identifier(const uint8_t *cert, size_t certlen,
	const uint8_t **keyid, size_t *keyid_len)
{
	int ret;
	int critical;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *val;
	size_t vlen;

	if (!cert || !certlen || !keyid || !keyid_len) {
		error_print();
		return -1;
	}

	*keyid = NULL;
	*keyid_len = 0;

	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_subject_key_identifier,
		&critical, &val, &vlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(keyid, keyid_len, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int x509_signed_is_verified_by_key(const uint8_t *a, size_t alen,
	const X509_KEY *key, const char *signer_id, size_t signer_id_len)
{
	const uint8_t *tbs;
	size_t tbslen;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	int key_sig_alg;
	void *sign_args = NULL;
	size_t sign_argslen = 0;
	X509_SIGN_CTX verify_ctx;

	if (!a || !alen || !key) {
		error_print();
		return -1;
	}
	if (x509_key_get_sign_algor(key, &key_sig_alg) != 1) {
		error_print();
		return -1;
	}
	if (x509_signed_from_der(&tbs, &tbslen, &sig_alg, &sig, &siglen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	if (sig_alg != key_sig_alg) {
		return 0;
	}

	if (key->algor == OID_ec_public_key && key->algor_param == OID_sm2) {
		sign_args = (uint8_t *)signer_id;
		sign_argslen = signer_id_len;
	}
	if (x509_verify_init(&verify_ctx, key, sign_args, sign_argslen, sig, siglen) != 1
		|| x509_verify_update(&verify_ctx, tbs, tbslen) != 1
		|| x509_verify_finish(&verify_ctx) != 1) {
		return 0;
	}
	return 1;
}

int x509_cert_is_signed_by_root_ca_cert(const uint8_t *cert, size_t certlen,
	const uint8_t *rootcacert, size_t rootcacertlen,
	const char *signer_id, size_t signer_id_len)
{
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;

	const uint8_t *aki;
	size_t aki_len;
	const uint8_t *aki_issuer;
	size_t aki_issuer_len;
	const uint8_t *aki_serial;
	size_t aki_serial_len;
	const uint8_t *ski;
	size_t ski_len;
	const uint8_t *root_serial;
	size_t root_serial_len;
	const uint8_t *directory_name;
	size_t directory_name_len;
	int issuer_match;
	X509_KEY public_key;
	int ret;

	if (!cert || !certlen || !rootcacert || !rootcacertlen) {
		error_print();
		return -1;
	}

	// check issuer == subject
	if (x509_cert_get_issuer(cert, certlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject(rootcacert, rootcacertlen, &subject, &subject_len) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_name_equ(issuer, issuer_len, subject, subject_len)) != 1) {
		if (ret) error_print();
		return ret;
	}

	// if AKI not exist
	if ((ret = x509_cert_get_authority_key_identifier_keyid(cert, certlen,
		&aki, &aki_len, &aki_issuer, &aki_issuer_len, &aki_serial, &aki_serial_len)) < 0) {
		error_print();
		return -1;
	} else if (ret) {
		// AKI exist

		// SKI not exist => not_match
		if ((ret = x509_cert_get_subject_key_identifier(rootcacert, rootcacertlen, &ski, &ski_len)) < 0) {
			if (ret) error_print();
			return ret;
		}

		if (aki_len) {
			if (aki_len != ski_len || memcmp(aki, ski, ski_len) != 0) {
				return 0;
			}
		}

		if (aki_issuer_len || aki_serial_len) {
			if (!aki_issuer_len || !aki_serial_len) {
				error_print();
				return -1;
			}
			if (x509_cert_get_issuer_and_serial_number(rootcacert, rootcacertlen,
				NULL, NULL, &root_serial, &root_serial_len) != 1) {
				error_print();
				return -1;
			}

			// aki_issuer AKI 中的Issuer 是一个GeneralNames.directoryName == ROOTCACERT.subject

			if ((ret = x509_general_names_get_first(aki_issuer, aki_issuer_len, NULL,
				X509_gn_directory_name, &directory_name, &directory_name_len)) < 0) {
				if (ret) error_print();
				return ret;
			}
			if (ret == 0) {
				return 0;
			}
			if ((issuer_match = x509_name_equ(directory_name, directory_name_len,
				subject, subject_len)) != 1) {
				if (issuer_match) error_print();
				return issuer_match;
			}

			if (aki_serial_len != root_serial_len
				|| memcmp(aki_serial, root_serial, root_serial_len) != 0) {
				return 0;
			}
		}

	}


	if (x509_cert_get_subject_public_key(rootcacert, rootcacertlen, &public_key) != 1) {
		error_print();
		return -1;
	}
	return x509_signed_is_verified_by_key(cert, certlen, &public_key, signer_id, signer_id_len);
}

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
