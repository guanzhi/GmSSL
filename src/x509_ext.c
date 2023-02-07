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
#include <stdint.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <gmssl/error.h>



static uint32_t oid_ce_subject_directory_attributes[] = { oid_ce,9 };
static uint32_t oid_ce_subject_key_identifier[] = { oid_ce,14 };
static uint32_t oid_ce_key_usage[] = { oid_ce,15 };
static uint32_t oid_ce_subject_alt_name[] = { oid_ce,17 };
static uint32_t oid_ce_issuer_alt_name[] = { oid_ce,18 };
static uint32_t oid_ce_basic_constraints[] = { oid_ce,19 };
static uint32_t oid_ce_name_constraints[] = { oid_ce,30 };
static uint32_t oid_ce_crl_distribution_points[] = { oid_ce,31 };
static uint32_t oid_ce_certificate_policies[] = { oid_ce,32 };
static uint32_t oid_ce_policy_mappings[] = { oid_ce,33 };
static uint32_t oid_ce_authority_key_identifier[] = { oid_ce,35 };
static uint32_t oid_ce_policy_constraints[] = { oid_ce,36 };
static uint32_t oid_ce_ext_key_usage[] = { oid_ce,37 };
static uint32_t oid_ce_freshest_crl[] = { oid_ce,46 };
static uint32_t oid_ce_inhibit_any_policy[] = { oid_ce,54 };
static uint32_t oid_ce_crl_reasons[] = { oid_ce,21 }; // crl_entry_ext
static uint32_t oid_ce_invalidity_date[] = { oid_ce,24 }; // crl_entry_ext
static uint32_t oid_ce_certificate_issuer[] = { oid_ce,29 }; // crl_entry_ext
#define OID_CE_CNT sizeof(oid_ce_subject_directory_attributes)/sizeof(int)
static uint32_t oid_netscape_cert_type[] = { 2,16,840,1,113730,1,1 };
static uint32_t oid_netscape_cert_comment[] = { 2,16,840,1,113730,1,13 };
static uint32_t oid_pe_authority_info_access[] = { 1,3,6,1,5,5,7,1,1 };
static uint32_t oid_ct_precertificate_scts[] = { 1,3,6,1,4,1,11129,2,4,2 };

static const ASN1_OID_INFO x509_ext_ids[] = {
	{ OID_ce_authority_key_identifier, "AuthorityKeyIdentifier", oid_ce_authority_key_identifier, OID_CE_CNT },
	{ OID_ce_subject_key_identifier, "SubjectKeyIdentifier", oid_ce_subject_key_identifier, OID_CE_CNT },
	{ OID_ce_key_usage, "KeyUsage", oid_ce_key_usage, OID_CE_CNT },
	{ OID_ce_certificate_policies, "CertificatePolicies", oid_ce_certificate_policies, OID_CE_CNT },
	{ OID_ce_policy_mappings, "PolicyMappings", oid_ce_policy_mappings, OID_CE_CNT },
	{ OID_ce_subject_alt_name, "SubjectAltName", oid_ce_subject_alt_name, OID_CE_CNT },
	{ OID_ce_issuer_alt_name, "IssuerAltName", oid_ce_issuer_alt_name, OID_CE_CNT },
	{ OID_ce_subject_directory_attributes, "SubjectDirectoryAttributes", oid_ce_subject_directory_attributes, OID_CE_CNT },
	{ OID_ce_basic_constraints, "BasicConstraints", oid_ce_basic_constraints, OID_CE_CNT },
	{ OID_ce_name_constraints, "NameConstraints", oid_ce_name_constraints, OID_CE_CNT },
	{ OID_ce_policy_constraints, "PolicyConstraints", oid_ce_policy_constraints, OID_CE_CNT },
	{ OID_ce_ext_key_usage, "ExtKeyUsage", oid_ce_ext_key_usage, OID_CE_CNT },
	{ OID_ce_crl_distribution_points, "CRLDistributionPoints", oid_ce_crl_distribution_points, OID_CE_CNT },
	{ OID_ce_inhibit_any_policy, "InhibitAnyPolicy", oid_ce_inhibit_any_policy, OID_CE_CNT },
	{ OID_ce_freshest_crl, "FreshestCRL", oid_ce_freshest_crl, OID_CE_CNT },
	{ OID_ce_crl_reasons, "CRLReasons", oid_ce_crl_reasons, OID_CE_CNT },
	{ OID_ce_invalidity_date, "InvalidityDate", oid_ce_invalidity_date, OID_CE_CNT },
	{ OID_ce_certificate_issuer, "CertificateIssuer", oid_ce_certificate_issuer, OID_CE_CNT },
	{ OID_netscape_cert_type, "NetscapeCertType", oid_netscape_cert_type, sizeof(oid_netscape_cert_type)/sizeof(int) },
	{ OID_netscape_cert_comment, "NetscapeCertComment", oid_netscape_cert_comment, sizeof(oid_netscape_cert_comment)/sizeof(int) },
	{ OID_pe_authority_info_access, "AuthorityInformationAccess", oid_pe_authority_info_access, sizeof(oid_pe_authority_info_access)/sizeof(int) },
	{ OID_ct_precertificate_scts, "CT-PrecertificateSCTs", oid_ct_precertificate_scts, sizeof(oid_ct_precertificate_scts)/sizeof(int) },
};

static const int x509_ext_ids_count =
	sizeof(x509_ext_ids)/sizeof(x509_ext_ids[0]);

const char *x509_ext_id_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (oid == 0) {
		return NULL;
	}
	if (!(info = asn1_oid_info_from_oid(x509_ext_ids, x509_ext_ids_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_ext_id_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_ext_ids, x509_ext_ids_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_ext_id_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_ext_ids, x509_ext_ids_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

// 如果要支持未知的ext_id，应该提供一个callback
int x509_ext_id_from_der(int *oid, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;

	if ((ret = asn1_oid_info_from_der_ex(&info, nodes, nodes_cnt, x509_ext_ids, x509_ext_ids_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info ? info->oid : 0;
	return 1;
}

int x509_ext_to_der(int oid, int critical, const uint8_t *val, size_t vlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (vlen == 0) {
		return 0;
	}
	if (x509_ext_id_to_der(oid, NULL, &len) != 1
		|| asn1_boolean_to_der(critical, NULL, &len) < 0
		|| asn1_octet_string_to_der(val, vlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_ext_id_to_der(oid, out, outlen) != 1
		|| asn1_boolean_to_der(critical, out, outlen) < 0
		|| asn1_octet_string_to_der(val, vlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_ext_to_der_ex(int oid, int critical, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	size_t vlen = 0;
	size_t len = 0;

	if (dlen == 0) {
		return 0;
	}
	if (asn1_sequence_to_der(d, dlen, NULL, &vlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_ext_id_to_der(oid, NULL, &len) != 1
		|| asn1_boolean_to_der(critical, NULL, &len) < 0
		|| asn1_tag_to_der(ASN1_TAG_OCTET_STRING, NULL, &len) != 1
		|| asn1_length_to_der(vlen, NULL, &len) != 1
		|| asn1_sequence_to_der(d, dlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_ext_id_to_der(oid, out, outlen) != 1
		|| asn1_boolean_to_der(critical, out, outlen) < 0
		|| asn1_tag_to_der(ASN1_TAG_OCTET_STRING, out, outlen) != 1
		|| asn1_length_to_der(vlen, out, outlen) != 1
		|| asn1_sequence_to_der(d, dlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_ext_from_der(int *oid, uint32_t *nodes, size_t *nodes_cnt,
	int *critical, const uint8_t **val, size_t *vlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_ext_id_from_der(oid, nodes, nodes_cnt, &d, &dlen) != 1
		|| asn1_boolean_from_der(critical, &d, &dlen) < 0
		|| asn1_octet_string_from_der(val, vlen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_ext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, oid, critical;
	uint32_t nodes[32];
	size_t nodes_cnt;
	const uint8_t *val;
	size_t vlen;

	const uint8_t *p;
	size_t len;
	int ival;
	const char *name;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	if (x509_ext_id_from_der(&oid, nodes, &nodes_cnt, &d, &dlen) != 1) goto err;
	asn1_object_identifier_print(fp, fmt, ind, "extnID", x509_ext_id_name(oid), nodes, nodes_cnt);
	if ((ret = asn1_boolean_from_der(&critical, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "critical: %s\n", asn1_boolean_name(critical));
	if (asn1_octet_string_from_der(&val, &vlen, &d, &dlen) != 1) goto err;

	switch (oid) {
	case OID_ce_subject_key_identifier:
		if (asn1_octet_string_from_der(&p, &len, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ce_key_usage:
	case OID_netscape_cert_type:
		if (asn1_bits_from_der(&ival, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ce_inhibit_any_policy:
		if (asn1_int_from_der(&ival, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_netscape_cert_comment:
		if (asn1_ia5_string_from_der((const char **)&p, &len, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ct_precertificate_scts:
	case OID_undef:
		p = val;
		len = vlen;
		vlen = 0;
		break;
	default:
		if (asn1_sequence_from_der(&p, &len, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}

	name = x509_ext_id_name(oid);

	switch (oid) {
	case OID_ce_authority_key_identifier: return x509_authority_key_identifier_print(fp, fmt, ind, name, p, len);
	case OID_ce_subject_key_identifier: return format_bytes(fp, fmt, ind, name, p, len);
	case OID_ce_key_usage: return x509_key_usage_print(fp, fmt, ind, name, ival);
	case OID_ce_certificate_policies: return x509_certificate_policies_print(fp, fmt, ind, name, p, len);
	case OID_ce_policy_mappings: return x509_policy_mappings_print(fp, fmt, ind, name, p, len);
	case OID_ce_subject_alt_name: return x509_general_names_print(fp, fmt, ind, name, p, len);
	case OID_ce_issuer_alt_name: return x509_general_names_print(fp, fmt, ind, name, p, len);
	case OID_ce_subject_directory_attributes: return x509_attributes_print(fp, fmt, ind, name, p, len);
	case OID_ce_basic_constraints: return x509_basic_constraints_print(fp, fmt, ind, name, p, len);
	case OID_ce_name_constraints: return x509_name_constraints_print(fp, fmt, ind, name, p, len);
	case OID_ce_policy_constraints: return x509_policy_constraints_print(fp, fmt, ind, name, p, len);
	case OID_ce_ext_key_usage: return x509_ext_key_usage_print(fp, fmt, ind, name, p, len);
	case OID_ce_crl_distribution_points: return x509_crl_distribution_points_print(fp, fmt, ind, name, p, len);
	case OID_ce_inhibit_any_policy: format_print(fp, fmt, ind, "%s: %d\n", name, ival);
	case OID_ce_freshest_crl: return x509_freshest_crl_print(fp, fmt, ind, name, p, len);
	case OID_netscape_cert_type: return x509_netscape_cert_type_print(fp, fmt, ind, name, ival);
	case OID_netscape_cert_comment: return format_string(fp, fmt, ind, name, p, len);
	case OID_pe_authority_info_access: return x509_authority_info_access_print(fp, fmt, ind, name, p, len);
	default: format_bytes(fp, fmt, ind, "extnValue", p, len);
	}
	return 1;
err:
	error_print();
	return -1;
}

int x509_exts_add_sequence(uint8_t *exts, size_t *extslen, size_t maxlen,
	int oid, int critical, const uint8_t *d, size_t dlen)
{
	size_t curlen = *extslen;

	if (dlen == 0) {
		return 0;
	}
	exts += *extslen;
	if (x509_ext_to_der_ex(oid, critical, d, dlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der_ex(oid, critical, d, dlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_authority_key_identifier(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len)
{
	int oid = OID_ce_authority_key_identifier;
	size_t curlen = *extslen;
	uint8_t val[512];
	uint8_t *p = val;
	size_t vlen = 0;
	size_t len = 0;

	if (keyid_len == 0 && issuer_len == 0 && serial_len == 0) {
		return 0;
	}
	exts += *extslen;
	if (x509_authority_key_identifier_to_der(
			keyid, keyid_len,
			issuer, issuer_len,
			serial, serial_len,
			NULL, &len) != 1
		|| asn1_length_le(len, sizeof(val)) != 1
		|| x509_authority_key_identifier_to_der(
			keyid, keyid_len,
			issuer, issuer_len,
			serial, serial_len,
			&p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_default_authority_key_identifier(uint8_t *exts, size_t *extslen, size_t maxlen,
	const SM2_KEY *public_key)
{
	uint8_t buf[65];
	uint8_t id[32];
	int critical = -1;

	if (!public_key) {
		return 0;
	}
	sm2_point_to_uncompressed_octets(&public_key->public_key, buf);
	sm3_digest(buf, sizeof(buf), id);

	if (x509_exts_add_authority_key_identifier(exts, extslen, maxlen, critical,
		id, sizeof(id), NULL, 0, NULL, 0) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_subject_key_identifier(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_subject_key_identifier;
	size_t curlen = *extslen;
	uint8_t val[32 + X509_SUBJECT_KEY_IDENTIFIER_MAX_LEN];
	uint8_t *p = val;
	size_t vlen = 0;

	if (dlen == 0) {
		return 0;
	}
	if (dlen < X509_SUBJECT_KEY_IDENTIFIER_MIN_LEN
		|| dlen > X509_SUBJECT_KEY_IDENTIFIER_MAX_LEN) {
		error_print();
		return -1;
	}

	exts += *extslen;
	if (asn1_octet_string_to_der(d, dlen, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_subject_key_identifier_ex(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const SM2_KEY *subject_key)
{
	uint8_t buf[65];
	uint8_t id[32];

	if (!subject_key) {
		return 0;
	}
	sm2_point_to_uncompressed_octets(&subject_key->public_key, buf);
	sm3_digest(buf, sizeof(buf), id);

	if (x509_exts_add_subject_key_identifier(exts, extslen, maxlen, critical, id, 32) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_key_usage(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, int bits)
{
	int oid = OID_ce_key_usage;
	size_t curlen = *extslen;
	uint8_t val[16];
	uint8_t *p = val;
	size_t vlen = 0;

	if (bits == -1) {
		return 0;
	}
	if (!bits) {
		if (x509_key_usage_check(bits, -1) != 1) {
			error_print();
			return -1;
		}
	}

	exts += *extslen;
	if (asn1_bits_to_der(bits, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_certificate_policies(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_certificate_policies;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_exts_add_policy_mappings(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_policy_mappings;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_exts_add_subject_alt_name(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_subject_alt_name;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_exts_add_issuer_alt_name(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_issuer_alt_name;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_exts_add_subject_directory_attributes(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_subject_directory_attributes;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_exts_add_name_constraints(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *permitted_subtrees, size_t permitted_subtrees_len,
	const uint8_t *excluded_subtrees, size_t excluded_subtrees_len)
{
	int oid = OID_ce_name_constraints;
	size_t curlen = *extslen;
	uint8_t val[512];
	uint8_t *p = val;
	size_t vlen = 0;
	size_t len = 0;

	if (permitted_subtrees_len == 0 && excluded_subtrees_len == 0) {
		return 0;
	}
	exts += *extslen;
	if (x509_name_constraints_to_der(
			permitted_subtrees, permitted_subtrees_len,
			excluded_subtrees, excluded_subtrees_len,
			NULL, &len) != 1
		|| asn1_length_le(len, sizeof(val)) != 1
		|| x509_name_constraints_to_der(
			permitted_subtrees, permitted_subtrees_len,
			excluded_subtrees, excluded_subtrees_len,
			&p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_policy_constraints(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, int require_explicit_policy, int inhibit_policy_mapping)
{
	int oid = OID_ce_policy_constraints;
	size_t curlen = *extslen;
	uint8_t val[32];
	uint8_t *p = val;
	size_t vlen = 0;

	if (require_explicit_policy == -1 && inhibit_policy_mapping == -1) {
		return 0;
	}
	exts += *extslen;
	if (x509_policy_constraints_to_der(
			require_explicit_policy,
			inhibit_policy_mapping,
			&p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_basic_constraints(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, int ca, int path_len_constraint)
{
	int oid = OID_ce_basic_constraints;
	size_t curlen = *extslen;
	uint8_t val[32];
	uint8_t *p = val;
	size_t vlen = 0;

	if (ca == -1 && path_len_constraint == -1) {
		return 0;
	}
	exts += *extslen;
	if (x509_basic_constraints_to_der(ca, path_len_constraint, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_ext_key_usage(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const int *key_purposes, size_t key_purposes_cnt)
{
	int oid = OID_ce_ext_key_usage;
	size_t curlen = *extslen;
	uint8_t val[256];
	uint8_t *p = val;
	size_t vlen = 0;
	size_t len = 0;

	if (key_purposes_cnt == 0) {
		return 0;
	}
	exts += *extslen;
	if (x509_ext_key_usage_to_der(key_purposes, key_purposes_cnt, NULL, &len) != 1
		|| asn1_length_le(len, sizeof(val)) != 1
		|| x509_ext_key_usage_to_der(key_purposes, key_purposes_cnt, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_crl_distribution_points_ex(uint8_t *exts, size_t *extslen, size_t maxlen,
	int oid, int critical, const char *uri, size_t urilen, const char *ldap_uri, size_t ldap_urilen)
{
	size_t curlen = *extslen;
	uint8_t val[256];
	uint8_t *p = val;
	size_t vlen = 0;
	size_t len = 0;

	if (urilen == 0 && ldap_urilen == 0) {
		return 0;
	}
	if (x509_uri_as_distribution_points_to_der(uri, urilen, -1, NULL, 0, NULL, &len) != 1
		|| asn1_length_le(len, sizeof(val)) != 1
		|| x509_uri_as_distribution_points_to_der(uri, urilen, -1, NULL, 0, &p, &vlen) != 1) {
		error_print();
		return -1;
	}
	exts += *extslen;
	if (x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_crl_distribution_points(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const char *http_uri, size_t http_urilen, const char *ldap_uri, size_t ldap_urilen)
{
	int oid = OID_ce_crl_distribution_points;
	if (x509_exts_add_crl_distribution_points_ex(exts, extslen, maxlen,
		oid, critical, http_uri, http_urilen, ldap_uri, ldap_urilen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_inhibit_any_policy(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, int skip_certs)
{
	int oid = OID_ce_inhibit_any_policy;
	size_t curlen = *extslen;
	uint8_t val[16];
	uint8_t *p = val;
	size_t vlen = 0;

	if (skip_certs == -1) {
		return 0;
	}
	exts += *extslen;
	if (x509_inhibit_any_policy_to_der(skip_certs, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_add_freshest_crl(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_freshest_crl;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_exts_get_ext_by_oid(const uint8_t *d, size_t dlen, int oid,
	int *critical, const uint8_t **val, size_t *vlen)
{
	int ext_id;
	uint32_t nodes[32];
	size_t nodes_cnt;

	while (dlen) {
		if (x509_ext_from_der(&ext_id, nodes, &nodes_cnt, critical, val, vlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (ext_id == oid) {
			return 1;
		}
	}
	*critical = -1;
	*val = NULL;
	*vlen = 0;
	return 0;
}

int x509_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_ext_print(fp, fmt, ind, "Extension", p, len);
	}
	return 1;
}

// GeneralName

int x509_other_name_to_der(
	const uint32_t *type_nodes, size_t type_nodes_cnt,
	const uint8_t *value_a, size_t value_alen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (type_nodes_cnt == 0 && value_alen == 0) {
		return 0;
	}
	if (asn1_object_identifier_to_der(type_nodes, type_nodes_cnt, NULL, &len) != 1
		|| asn1_explicit_to_der(0, value_a, value_alen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(type_nodes, type_nodes_cnt, out, outlen) != 1
		|| asn1_explicit_to_der(0, value_a, value_alen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_other_name_from_der(
	uint32_t *type_nodes, size_t *type_nodes_cnt,
	const uint8_t **value, size_t *value_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(type_nodes, type_nodes_cnt, &p, &len) != 1
		|| asn1_explicit_from_der(0, value, value_len, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_other_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	uint32_t nodes[32];
	size_t nodes_cnt;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &d, &dlen) != 1) goto err;
	asn1_object_identifier_print(fp, fmt, ind, "type-id", NULL, nodes, nodes_cnt);
	if (asn1_explicit_from_der(0, &p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "value", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_edi_party_name_to_der(
	int assigner_choice, const uint8_t *assigner, size_t assigner_len,
	int party_name_choice, const uint8_t *party_name, size_t party_name_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (assigner_len == 0 && party_name_len == 0) {
		return 0;
	}
	if (x509_explicit_directory_name_to_der(0, assigner_choice, assigner, assigner_len, NULL, &len) < 0
		|| x509_explicit_directory_name_to_der(1, party_name_choice, party_name, party_name_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_explicit_directory_name_to_der(0, assigner_choice, assigner, assigner_len, out, outlen) < 0
		|| x509_explicit_directory_name_to_der(1, party_name_choice, party_name, party_name_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_edi_party_name_from_der(
	int *assigner_choice, const uint8_t **assigner, size_t *assigner_len,
	int *party_name_choice, const uint8_t **party_name, size_t *party_name_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_explicit_directory_name_from_der(0, assigner_choice, assigner, assigner_len, &p, &len) < 0
		|| x509_explicit_directory_name_from_der(1, party_name_choice, party_name, party_name_len, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_edi_party_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	int tag;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = x509_explicit_directory_name_from_der(0, &tag, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_directory_name_print(fp, fmt, ind, "nameAssigner", tag, p, len);
	if (x509_explicit_directory_name_from_der(1, &tag, &p, &len, &d, &dlen) != 1) goto err;
	x509_directory_name_print(fp, fmt, ind, "partyName", tag, p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_general_name_to_der(int choice, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;

	if (dlen == 0) {
		return 0;
	}
	switch (choice) {
	case X509_gn_other_name:
	case X509_gn_rfc822_name:
	case X509_gn_dns_name:
	case X509_gn_x400_address:
	case X509_gn_directory_name:
	case X509_gn_edi_party_name:
	case X509_gn_uniform_resource_identifier:
	case X509_gn_ip_address:
	case X509_gn_registered_id:
		if ((ret = asn1_implicit_to_der(choice, d, dlen, out, outlen)) != 1) {
			if (ret < 0) error_print();
			return ret;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_name_from_der(int *choice, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	int tag;
	if ((ret = asn1_any_type_from_der(&tag, d, dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	switch (tag) {
	case ASN1_TAG_EXPLICIT(0): *choice = 0; break;
	case ASN1_TAG_IMPLICIT(1): *choice = 1; break;
	case ASN1_TAG_IMPLICIT(2): *choice = 2; break;
	case ASN1_TAG_EXPLICIT(3): *choice = 3; break;
	case ASN1_TAG_EXPLICIT(4): *choice = 4; break;
	case ASN1_TAG_EXPLICIT(5): *choice = 5; break;
	case ASN1_TAG_IMPLICIT(6): *choice = 6; break;
	case ASN1_TAG_IMPLICIT(7): *choice = 7; break;
	case ASN1_TAG_IMPLICIT(8): *choice = 8; break;
	default:
		fprintf(stderr, "%s %d: tag = %x\n", __FILE__, __LINE__, tag);
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_name_print(FILE *fp, int fmt, int ind, const char *label, int choice, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	switch (choice) {
	case 0:
	case 3:
	case 4:
	case 5:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		d = p;
		dlen = len;
	}
	switch (choice) {
	case 0: return x509_other_name_print(fp, fmt, ind, "otherName", d, dlen);
	case 1: return asn1_string_print(fp, fmt, ind, "rfc822Name", ASN1_TAG_IA5String, d, dlen);
	case 2: return asn1_string_print(fp, fmt, ind, "DNSName", ASN1_TAG_IA5String, d, dlen);
	case 3: return format_bytes(fp, fmt, ind, "x400Address", d, dlen);
	case 4: return x509_name_print(fp, fmt, ind, "directoryName", d, dlen);
	case 5: return x509_edi_party_name_print(fp, fmt, ind, "ediPartyName", d, dlen);
	case 6: return asn1_string_print(fp, fmt, ind, "URI", ASN1_TAG_IA5String, d, dlen);
	case 7: return format_bytes(fp, fmt, ind, "IPAddress", d, dlen);
	case 8:
	{
		uint32_t nodes[32];
		size_t nodes_cnt;
		if (asn1_object_identifier_from_octets(nodes, &nodes_cnt, d, dlen) != 1) {
			error_print();
			return -1;
		}
		return asn1_object_identifier_print(fp, fmt, ind, "registeredID", NULL, nodes, nodes_cnt);
	}
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_names_add_general_name(uint8_t *gns, size_t *gnslen, size_t maxlen,
	int choice, const uint8_t *d, size_t dlen)
{
	size_t len = 0;
	uint8_t *p = gns + *gnslen;

	switch (choice) {
	case X509_gn_rfc822_name:
	case X509_gn_dns_name:
	case X509_gn_uniform_resource_identifier:
		if (asn1_string_is_ia5_string((char *)d, dlen) != 1) {
			error_print();
			return -1;
		}
		break;
	}
	if (x509_general_name_to_der(choice, d, dlen, NULL, &len) != 1
		|| asn1_length_le(*gnslen + len, maxlen) != 1
		|| x509_general_name_to_der(choice, d, dlen, &p, gnslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_names_add_other_name(uint8_t *gns, size_t *gnslen, size_t maxlen,
	const uint32_t *nodes, size_t nodes_cnt,
	const uint8_t *value, size_t value_len)
{
	int choice = X509_gn_other_name;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	if (x509_other_name_to_der(nodes, nodes_cnt, value, value_len, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| x509_general_names_add_general_name(gns, gnslen, maxlen, choice, d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_names_add_edi_party_name(uint8_t *gns, size_t *gnslen, size_t maxlen,
	int assigner_tag, const uint8_t *assigner, size_t assigner_len,
	int party_name_tag, const uint8_t *party_name, size_t party_name_len)
{
	int choice = X509_gn_edi_party_name;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	if (x509_edi_party_name_to_der(
			assigner_tag, assigner, assigner_len,
			party_name_tag, party_name, party_name_len,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| x509_general_names_add_general_name(gns, gnslen, maxlen, choice, d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_names_add_registered_id(uint8_t *gns, size_t *gnslen, size_t maxlen,
	const uint32_t *nodes, size_t nodes_cnt)
{
	int choice = X509_gn_registered_id;
	uint8_t d[64];
	size_t dlen;

	if (asn1_object_identifier_to_octets(nodes, nodes_cnt, d, &dlen) != 1
		|| x509_general_names_add_general_name(gns, gnslen, maxlen, choice, d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_names_get_next(const uint8_t *gns, size_t gns_len, const uint8_t **ptr, int choice, const uint8_t **d, size_t *dlen)
{
	if (!gns || !gns_len) {
		error_print();
		return -1;
	}
	if (!ptr || !d || !dlen) {
		error_print();
		return -1;
	}

	if (*ptr > gns + gns_len) {
		error_print();
		return -1;
	}
	gns_len -= (*ptr - gns);

	while (gns_len) {
		int tag;
		if (x509_general_name_from_der(&tag, d, dlen, ptr, &gns_len) != 1) {
			error_print();
			return -1;
		}
		if (tag == choice) {
			return 1;
		}
	}

	*d = NULL;
	*dlen = 0;
	return 0;
}

int x509_general_names_get_first(const uint8_t *gns, size_t gns_len, const uint8_t **ptr, int choice, const uint8_t **d, size_t *dlen)
{
	int ret;
	const uint8_t *p;
	p = gns;

	if ((ret = x509_general_names_get_next(gns, gns_len, &p, choice, d, dlen)) < 0) {
		error_print();
		return - 1;
	}

	if (ptr) {
		*ptr = p;
	}

	return ret;
}

int x509_uri_as_general_names_to_der_ex(int tag, const char *uri, size_t urilen,
	uint8_t **out, size_t *outlen)
{
	int choice = X509_gn_uniform_resource_identifier;
	size_t len = 0;

	if (!urilen) {
		return 0;
	}
	if (x509_general_name_to_der(choice, (uint8_t *)uri, urilen, NULL, &len) != 1
		|| asn1_sequence_header_to_der_ex(tag, len, out, outlen) != 1
		|| x509_general_name_to_der(choice, (uint8_t *)uri, urilen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_uri_as_general_names_from_der_ex(int tag, const uint8_t **uri, size_t *urilen,
	const uint8_t **in, size_t *inlen)
{
	int choice = X509_gn_uniform_resource_identifier;
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_type_from_der(tag, &d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*uri = NULL;
			*urilen = 0;
		}
		return ret;
	}
	if (x509_general_names_get_first(d, dlen, NULL, choice, uri, urilen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_names_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int choice;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (x509_general_name_from_der(&choice, &p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_general_name_print(fp, fmt, ind, "GeneralName", choice, p, len);
	}
	return 1;
}

int x509_authority_key_identifier_to_der(
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (keyid_len == 0 && issuer_len == 0 && serial_len == 0) {
		return 0;
	}
	if (asn1_implicit_octet_string_to_der(0, keyid, keyid_len, NULL, &len) < 0
		|| asn1_implicit_sequence_to_der(1, issuer, issuer_len, NULL, &len) < 0
		|| asn1_implicit_integer_to_der(2, serial, serial_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_implicit_octet_string_to_der(0, keyid, keyid_len, out, outlen) < 0
		|| asn1_implicit_sequence_to_der(1, issuer, issuer_len, out, outlen) < 0
		|| asn1_implicit_integer_to_der(2, serial, serial_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_authority_key_identifier_from_der(
	const uint8_t **keyid, size_t *keyid_len,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial, size_t *serial_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_implicit_octet_string_from_der(0, keyid, keyid_len, &d, &dlen) < 0
		|| asn1_implicit_sequence_from_der(1, issuer, issuer_len, &d, &dlen) < 0
		|| asn1_implicit_integer_from_der(2, serial, serial_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_authority_key_identifier_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = asn1_implicit_octet_string_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "keyIdentifier", p, len);
	if ((ret = asn1_implicit_sequence_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_general_names_print(fp, fmt, ind, "authorityCertIssuer", p, len);
	if ((ret = asn1_implicit_integer_from_der(2, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "authorityCertSerialNumber", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

static const char *x509_key_usages[] = {
	"digitalSignature",
	"nonRepudiation",
	"keyEncipherment",
	"dataEncipherment",
	"keyAgreement",
	"keyCertSign",
	"cRLSign",
	"encipherOnly",
	"decipherOnly",
};

static size_t x509_key_usages_count =
	sizeof(x509_key_usages)/sizeof(x509_key_usages[0]);

const char *x509_key_usage_name(int flag)
{
	int i;
	for (i = 0; i < x509_key_usages_count; i++) {
		if (flag & 1) {
			if (flag >> 1) {
				error_print();
				return NULL;
			}
			return x509_key_usages[i];
		}
		flag >>= 1;
	}
	error_print();
	return NULL;
}

int x509_key_usage_from_name(int *flag, const char *name)
{
	int i;
	for (i = 0; i < x509_key_usages_count; i++) {
		if (strcmp(name, x509_key_usages[i]) == 0) {
			*flag = 1 << i;
			return 1;
		}
	}
	*flag = 0;
	error_print();
	return -1;
}

int x509_key_usage_check(int bits, int cert_type)
{
	if (bits == -1) {
		return 0;
	}
	if (!bits) {
		error_print();
		return -1;
	}

	switch (cert_type) {
	case -1:
		break;
	case X509_cert_server_auth:
	case X509_cert_client_auth:
		if (!(bits & X509_KU_DIGITAL_SIGNATURE)
			//&& !(bits & X509_KU_NON_REPUDIATION) // un-comment for compatibility
			) {
			error_print();
			return -1;
		}
		if ((bits & X509_KU_KEY_CERT_SIGN)
			|| (bits & X509_KU_CRL_SIGN)) {
			error_print();
			return -1;
		}
		break;

	case X509_cert_server_key_encipher:
	case X509_cert_client_key_encipher:
		if (!(bits & X509_KU_KEY_ENCIPHERMENT)
			//&& !(bits & X509_KU_KEY_AGREEMENT) // un-comment for compatibility
			) {
			error_print();
			return -1;
		}
		if ((bits & X509_KU_KEY_CERT_SIGN)
			|| (bits & X509_KU_CRL_SIGN)) {
			error_print();
			return -1;
		}
		break;

	case X509_cert_ca:
		if (!(bits & X509_KU_KEY_CERT_SIGN)) {
			error_print();
			return -1;
		}
		if ((bits & X509_KU_DIGITAL_SIGNATURE)
			|| (bits & X509_KU_NON_REPUDIATION)) {
			error_print();
			//return -1; // comment to print warning
		}
		break;
	case X509_cert_crl_sign:
		if (!(bits & X509_KU_CRL_SIGN)) {
			error_print();
			return -1;
		}
		if ((bits & X509_KU_DIGITAL_SIGNATURE)
			|| (bits & X509_KU_NON_REPUDIATION)) {
			error_print();
			//return -1; // comment to print warning
		}
		break;
	default:
		error_print();
		return -1;
	}

	return 1;
}

int x509_key_usage_print(FILE *fp, int fmt, int ind, const char *label, int bits)
{
	(void)asn1_bits_print(fp, fmt, ind, label, x509_key_usages, x509_key_usages_count, bits);
	return 1;
}

int x509_display_text_check(int tag, const uint8_t *d, size_t dlen)
{
	switch (tag) {
	case ASN1_TAG_IA5String:
	case ASN1_TAG_VisibleString:
	case ASN1_TAG_UTF8String:
		if (d && strnlen((char *)d, dlen) != dlen) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_BMPString:
		if (d && dlen % 2) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	if (dlen < X509_DISPLAY_TEXT_MIN_LEN || dlen > X509_DISPLAY_TEXT_MAX_LEN) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_display_text_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;
	if (x509_display_text_check(tag, d, dlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_type_to_der(tag, d, dlen, out, outlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_display_text_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_tag_from_der_readonly(tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	switch (*tag) {
	case ASN1_TAG_IA5String:
	case ASN1_TAG_VisibleString:
	case ASN1_TAG_UTF8String:
	case ASN1_TAG_BMPString:
		break;
	default:
		return 0;
	}

	if ((ret = asn1_any_type_from_der(tag, d, dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_display_text_check(*tag, *d, *dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_display_text_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen)
{
	return asn1_string_print(fp, fmt, ind, label, tag, d, dlen);
}

int x509_notice_reference_to_der(
	int org_tag, const uint8_t *org, size_t org_len,
	const int *notice_numbers, size_t notice_numbers_cnt,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (org_len == 0 && notice_numbers_cnt == 0) {
		return 0;
	}
	if (x509_display_text_to_der(org_tag, org, org_len, NULL, &len) != 1
		|| asn1_sequence_of_int_to_der(notice_numbers, notice_numbers_cnt, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_display_text_to_der(org_tag, org, org_len, out, outlen) != 1
		|| asn1_sequence_of_int_to_der(notice_numbers, notice_numbers_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_notice_reference_from_der(
	int *org_tag, const uint8_t **org, size_t *org_len,
	int *notice_numbers, size_t *notice_numbers_cnt, size_t max_notice_numbers,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return ret;
	}
	if (x509_display_text_from_der(org_tag, org, org_len, &d, &dlen) != 1
		|| asn1_sequence_of_int_from_der(notice_numbers, notice_numbers_cnt, max_notice_numbers, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_notice_reference_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int tag;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind,  "%s\n", label);
	ind += 4;

	if (x509_display_text_from_der(&tag, &p, &len, &d, &dlen) != 1) goto err;
	x509_display_text_print(fp, fmt, ind, "organization", tag, p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	asn1_sequence_of_int_print(fp, fmt, ind, "noticeNumbers", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_user_notice_to_der(
	int notice_ref_org_tag, const uint8_t *notice_ref_org, size_t notice_ref_org_len,
	const int *notice_ref_notice_numbers, size_t notice_ref_notice_numbers_cnt,
	int explicit_text_tag, const uint8_t *explicit_text, size_t explicit_text_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (notice_ref_org_len == 0
		&& notice_ref_notice_numbers_cnt == 0
		&& explicit_text_len == 0) {
		return 0;
	}
	if (x509_notice_reference_to_der(
			notice_ref_org_tag, notice_ref_org, notice_ref_org_len,
			notice_ref_notice_numbers, notice_ref_notice_numbers_cnt,
			NULL, &len) < 0
		|| x509_display_text_to_der(explicit_text_tag, explicit_text, explicit_text_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_notice_reference_to_der(
			notice_ref_org_tag, notice_ref_org, notice_ref_org_len,
			notice_ref_notice_numbers, notice_ref_notice_numbers_cnt,
			out, outlen) < 0
		|| x509_display_text_to_der(explicit_text_tag, explicit_text, explicit_text_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_user_notice_from_der(
	int *notice_ref_org_tag, const uint8_t **notice_ref_org, size_t *notice_ref_org_len,
	int *notice_ref_notice_numbers, size_t *notice_ref_notice_numbers_cnt, size_t max_notice_ref_notice_numbers,
	int *explicit_text_tag, const uint8_t **explicit_text, size_t *explicit_text_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_notice_reference_from_der(notice_ref_org_tag, notice_ref_org, notice_ref_org_len,
			notice_ref_notice_numbers, notice_ref_notice_numbers_cnt, max_notice_ref_notice_numbers, &d, &dlen) < 0
		|| x509_display_text_from_der(explicit_text_tag, explicit_text, explicit_text_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_user_notice_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	int tag;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = asn1_sequence_from_der(&p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_notice_reference_print(fp, fmt, ind, "noticeRef", p, len);
	if ((ret = x509_display_text_from_der(&tag, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_display_text_print(fp, fmt, ind, "explicitText", tag, p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}




static uint32_t oid_qt_cps[] = { oid_qt,1 };
static uint32_t oid_qt_unotice[] = {oid_qt,2 };

static const ASN1_OID_INFO x509_qt_ids[] = {
	{ OID_qt_cps, "CPS", oid_qt_cps, sizeof(oid_qt_cps)/sizeof(int) },
	{ OID_qt_unotice, "userNotice", oid_qt_unotice, sizeof(oid_qt_unotice)/sizeof(int) }
};

static const int x509_qt_ids_count =
	sizeof(x509_qt_ids)/sizeof(x509_qt_ids[0]);

int x509_qualifier_id_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_qt_ids, x509_qt_ids_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

const char *x509_qualifier_id_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_qt_ids, x509_qt_ids_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_qualifier_id_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_qt_ids, x509_qt_ids_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_qualifier_id_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;
	if ((ret = asn1_oid_info_from_der(&info, x509_qt_ids, x509_qt_ids_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}


int x509_policy_qualifier_info_to_der(
	int oid,
	const uint8_t *qualifier, size_t qualifier_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (qualifier_len == 0) {
		return 0;
	}
	if (x509_qualifier_id_to_der(oid, NULL, &len) != 1
		|| asn1_any_to_der(qualifier, qualifier_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_qualifier_id_to_der(oid, out, outlen) != 1
		|| asn1_any_to_der(qualifier, qualifier_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_qualifier_info_from_der(int *oid, const uint8_t **qualifier, size_t *qualifier_len, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_qualifier_id_from_der(oid, &p, &len) != 1
		|| asn1_any_from_der(qualifier, qualifier_len, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_qualifier_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int oid;
	const uint8_t *p;
	size_t len;

	if (x509_qualifier_id_from_der(&oid, &d, &dlen) != 1) goto err;
	switch (oid) {
	case OID_qt_cps:
		if (asn1_ia5_string_from_der((const char **)&p, &len, &d, &dlen) != 1) goto err;
		format_string(fp, fmt, ind, "cPSuri", p, len);
		break;
	case OID_qt_unotice:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
		x509_user_notice_print(fp, fmt, ind, "userNotice", p, len);
		break;
	}
	return 1;
err:
	error_print();
	return -1;
}

int x509_policy_qualifier_infos_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_policy_qualifier_info_print(fp, fmt, ind, "PolicyQualifierInfo", p, len);
	}
	return 1;
}


int x509_cert_policy_id_from_name(const char *name)
{
	if (strcmp(name, "anyPolicy") == 0) {
		return OID_any_policy;
	}
	return OID_undef;
}

char *x509_cert_policy_id_name(int oid)
{
	switch (oid) {
	case OID_any_policy: return "anyPolicy";
	}
	return NULL;
}

static uint32_t oid_any_policy[] = { oid_ce,32,0 };

int x509_cert_policy_id_to_der(int oid, const uint32_t *nodes, size_t nodes_cnt, uint8_t **out, size_t *outlen)
{
	switch (oid) {
	case OID_any_policy:
		if (asn1_object_identifier_to_der(oid_any_policy, sizeof(oid_any_policy)/sizeof(int), out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_undef:
		if (asn1_object_identifier_to_der(nodes, nodes_cnt, out, outlen) != 1) {
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

int x509_cert_policy_id_from_der(int *oid, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_object_identifier_from_der(nodes, nodes_cnt, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	if (asn1_object_identifier_equ(nodes, *nodes_cnt, oid_any_policy, oid_cnt(oid_any_policy)))
		*oid = OID_any_policy;
	else	*oid = 0;
	return 1;
}

int x509_policy_information_to_der(
	int oid, const uint32_t *nodes, size_t nodes_cnt,
	const uint8_t *qualifiers, size_t qualifiers_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_cert_policy_id_to_der(oid, nodes, nodes_cnt, NULL, &len) != 1
		|| asn1_sequence_to_der(qualifiers, qualifiers_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_cert_policy_id_to_der(oid, nodes, nodes_cnt, out, outlen) != 1
		|| asn1_sequence_to_der(qualifiers, qualifiers_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_information_from_der(
	int *oid, uint32_t *nodes, size_t *nodes_cnt,
	const uint8_t **qualifiers, size_t *qualifiers_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_cert_policy_id_from_der(oid, nodes, nodes_cnt, &d, &dlen) != 1
		|| asn1_sequence_from_der(qualifiers, qualifiers_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_information_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, oid;
	uint32_t nodes[32];
	size_t nodes_cnt;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_cert_policy_id_from_der(&oid, nodes, &nodes_cnt, &d, &dlen) != 1) goto err;
	asn1_object_identifier_print(fp, fmt, ind, "policyIdentifier", x509_cert_policy_id_name(oid), nodes, nodes_cnt);
	if ((ret = asn1_sequence_from_der(&p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_policy_qualifier_infos_print(fp, fmt, ind, "policyQualifiers", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_certificate_policies_add_policy_information(uint8_t *d, size_t *dlen, size_t maxlen,
	int policy_oid, const uint32_t *policy_nodes, size_t policy_nodes_cnt,
	const uint8_t *qualifiers, size_t qualifiers_len)
{
	error_print();
	return -1;
}

int x509_certificate_polices_check(const uint8_t *d, size_t dlen)
{
	error_print();
	return -1;
}

int x509_certificate_policies_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_policy_information_print(fp, fmt, ind, label, p, len);
	}
	return 1;
}

int x509_policy_mapping_to_der(
	int issuer_policy_oid, const uint32_t *issuer_policy_nodes, size_t issuer_policy_nodes_cnt,
	int subject_policy_oid, const uint32_t *subject_policy_nodes, size_t subject_policy_nodes_cnt,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (issuer_policy_oid == -1 && subject_policy_oid == -1) {
		return 0;
	}
	if (x509_cert_policy_id_to_der(issuer_policy_oid,
			issuer_policy_nodes, issuer_policy_nodes_cnt, NULL, &len) != 1
		|| x509_cert_policy_id_to_der(subject_policy_oid,
			subject_policy_nodes, subject_policy_nodes_cnt, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_cert_policy_id_to_der(issuer_policy_oid,
			issuer_policy_nodes, issuer_policy_nodes_cnt, out, outlen) != 1
		|| x509_cert_policy_id_to_der(subject_policy_oid,
			subject_policy_nodes, subject_policy_nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_mapping_from_der(
	int *issuer_policy_oid, uint32_t *issuer_policy_nodes, size_t *issuer_policy_nodes_cnt,
	int *subject_policy_oid, uint32_t *subject_policy_nodes, size_t *subject_policy_nodes_cnt,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_cert_policy_id_from_der(issuer_policy_oid,
			issuer_policy_nodes, issuer_policy_nodes_cnt, &d, &dlen) != 1
		|| x509_cert_policy_id_from_der(subject_policy_oid,
			subject_policy_nodes, subject_policy_nodes_cnt, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_mapping_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int oid;
	uint32_t nodes[32];
	size_t nodes_cnt;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_cert_policy_id_from_der(&oid, nodes, &nodes_cnt, &d, &dlen) != 1) goto err;
	asn1_object_identifier_print(fp, fmt, ind, "issuerDomainPolicy", x509_cert_policy_id_name(oid), nodes, nodes_cnt);
	if (x509_cert_policy_id_from_der(&oid, nodes, &nodes_cnt, &d, &dlen) != 1) goto err;
	asn1_object_identifier_print(fp, fmt, ind, "subjectDomainPolicy", x509_cert_policy_id_name(oid), nodes, nodes_cnt);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_policy_mappings_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_policy_mapping_print(fp, fmt, ind, label, p, len);
	}
	return 1;
}

int x509_attribute_to_der(
	const uint32_t *nodes, size_t nodes_cnt,
	const uint8_t *values, size_t values_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_object_identifier_to_der(nodes, nodes_cnt, NULL, &len) != 1
		|| asn1_set_to_der(values, values_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(nodes, nodes_cnt, out, outlen) != 1
		|| asn1_set_to_der(values, values_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_attribute_from_der(
	int *oid, uint32_t *nodes, size_t *nodes_cnt,
	const uint8_t **values, size_t *values_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	*oid = OID_undef;
	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(nodes, nodes_cnt, &p, &len) != 1
		|| asn1_set_from_der(values, values_len, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_attribute_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	uint32_t nodes[32];
	size_t nodes_cnt;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &d, &dlen) != 1) goto err;
	asn1_object_identifier_print(fp, fmt, ind, "type", NULL, nodes, nodes_cnt);
	if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "values", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_attributes_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	if (!dlen) {
		format_print(fp, fmt, ind, "(null)\n");
	}
	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_attribute_print(fp, fmt, ind, "Attribute", p, len);
	}
	return 1;
}

int x509_basic_constraints_to_der(int ca, int path_len_cons, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (ca == -1 && path_len_cons == -1) {
		error_print();
		return -1;
	}
	if (asn1_boolean_to_der(ca, NULL, &len) < 0
		|| asn1_int_to_der(path_len_cons, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_boolean_to_der(ca, out, outlen) < 0
		|| asn1_int_to_der(path_len_cons, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_basic_constraints_from_der(int *ca, int *path_len_cons, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *ca = *path_len_cons = -1;
		return ret;
	}
	if (dlen == 0) {
		error_print();
		return -1;
	}
	if (asn1_boolean_from_der(ca, &d, &dlen) < 0
		|| asn1_int_from_der(path_len_cons, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_basic_constraints_check(int ca, int path_len_constraint, int cert_type)
{
	/*
	entity_cert:
		ca = -1 or 0
		path_len_constraint = -1
	first_ca_cert:
		ca = 1
		path_len_constraint = 0
	middle_ca_cert:
		ca = 1
		path_len_constraint = -1 or > 0
	root_ca_cert:
		ca = 1
		path_len_constraint = -1 or > 0 (=0 might be ok?)
	*/
	switch (cert_type) {
	case X509_cert_server_auth:
	case X509_cert_client_auth:
	case X509_cert_server_key_encipher:
	case X509_cert_client_key_encipher:
		if (ca > 0 || path_len_constraint != -1) {
			error_print();
			return -1;
		}
		break;
	// FIXME: add more cert types and check path_len_constraint		
	case X509_cert_ca:
	case X509_cert_crl_sign:
	case X509_cert_root_ca:
		if (ca != 1) {
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

int x509_basic_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	// BasicConstraints might be an empty sequence in entity certificates
	if (!d || !dlen) {
		return 1;
	}

	if ((ret = asn1_boolean_from_der(&val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "cA: %s\n", asn1_boolean_name(val));
	if ((ret = asn1_int_from_der(&val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "pathLenConstraint: %d\n", val);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_general_subtree_to_der(
	int base_choice, const uint8_t *base, size_t base_len,
	int minimum,
	int maximum,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_general_name_to_der(base_choice, base, base_len, NULL, &len) != 1
		|| asn1_implicit_int_to_der(0, minimum, NULL, &len) < 0
		|| asn1_implicit_int_to_der(1, maximum, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_general_name_to_der(base_choice, base, base_len, out, outlen) != 1
		|| asn1_implicit_int_to_der(0, minimum, out, outlen) < 0
		|| asn1_implicit_int_to_der(1, maximum, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_subtree_from_der(
	int *base_choice, const uint8_t **base, size_t *base_len,
	int *minimum,
	int *maximum,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_general_name_from_der(base_choice, base, base_len, &d, &dlen) != 1
		|| asn1_implicit_int_from_der(0, minimum, &d, &dlen) < 0
		|| asn1_implicit_int_from_der(1, maximum, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*minimum < 0) *minimum = 0;
	return 1;
}

int x509_general_subtree_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, choice, val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_general_name_from_der(&choice, &p, &len, &d, &dlen) != 1) goto err;
	x509_general_name_print(fp, fmt, ind, "base", choice, p, len);
	if ((ret = asn1_implicit_int_from_der(0, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "minimum: %d\n", val);
	if ((ret = asn1_implicit_int_from_der(1, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "maximum: %d\n", val);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_general_subtrees_add_general_subtree(uint8_t *d, size_t *dlen, size_t maxlen,
	int base_choice, const uint8_t *base, size_t base_len,
	int minimum, int maximum)
{
	error_print();
	return -1;
}

int x509_general_subtrees_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_general_subtree_print(fp, fmt, ind, "GeneralSubtree", p, len);
	}
	return 1;
}

int x509_name_constraints_to_der(
	const uint8_t *permitted_subtrees, size_t permitted_subtrees_len,
	const uint8_t *excluded_subtrees, size_t excluded_subtrees_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_implicit_sequence_to_der(0, permitted_subtrees, permitted_subtrees_len, NULL, &len) < 0
		|| asn1_implicit_sequence_to_der(1, excluded_subtrees, excluded_subtrees_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_implicit_sequence_to_der(0, permitted_subtrees, permitted_subtrees_len, out, outlen) < 0
		|| asn1_implicit_sequence_to_der(1, excluded_subtrees, excluded_subtrees_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_name_constraints_from_der(
	const uint8_t **permitted_subtrees, size_t *permitted_subtrees_len,
	const uint8_t **excluded_subtrees, size_t *excluded_subtrees_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	*permitted_subtrees = NULL;
	*permitted_subtrees_len = 0;
	*excluded_subtrees = NULL;
	*excluded_subtrees_len = 0;
	if (asn1_implicit_sequence_from_der(0, permitted_subtrees, permitted_subtrees_len, &d, &dlen) < 0
		|| asn1_implicit_sequence_from_der(1, excluded_subtrees, excluded_subtrees_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_name_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = asn1_implicit_sequence_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_general_subtrees_print(fp, fmt, ind, "permittedSubtrees", p, len);
	if ((ret = asn1_implicit_sequence_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_general_subtrees_print(fp, fmt, ind, "excludedSubtrees", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_policy_constraints_to_der(
	int require_explicit_policy,
	int inhibit_policy_mapping,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (require_explicit_policy == -1 && inhibit_policy_mapping == -1) {
		error_print();
		return -1;
	}
	if (asn1_implicit_int_to_der(0, require_explicit_policy, NULL, &len) < 0
		|| asn1_implicit_int_to_der(1, inhibit_policy_mapping, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_implicit_int_to_der(0, require_explicit_policy, out, outlen) < 0
		|| asn1_implicit_int_to_der(1, inhibit_policy_mapping, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_constraints_from_der(
	int *require_explicit_policy,
	int *inhibit_policy_mapping,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *require_explicit_policy = *inhibit_policy_mapping = -1;
		return ret;
	}
	if (dlen == 0) {
		error_print();
		return -1;
	}
	if (asn1_implicit_int_from_der(0, require_explicit_policy, &d, &dlen) < 0
		|| asn1_implicit_int_from_der(1, inhibit_policy_mapping, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_constraints_check(const uint8_t *a, size_t alen)
{
	error_print();
	return -1;
}

int x509_policy_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = asn1_implicit_int_from_der(0, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "requireExplicitPolicy: %d\n", val);
	if ((ret = asn1_implicit_int_from_der(1, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "inhibitPolicyMapping: %d\n", val);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}


static uint32_t oid_any_extended_key_usage[] = { oid_ce,37,0 };

#define oid_kp oid_pkix,3

static uint32_t oid_kp_server_auth[] = { oid_kp,1 };
static uint32_t oid_kp_client_auth[] = { oid_kp,2 };
static uint32_t oid_kp_code_signing[] = { oid_kp,3 };
static uint32_t oid_kp_email_protection[] = { oid_kp,4 };
static uint32_t oid_kp_time_stamping[] = { oid_kp,8 };
static uint32_t oid_kp_ocsp_signing[] = { oid_kp,9 };
#define OID_KP_CNT sizeof(oid_kp_server_auth)/sizeof(int)

static const ASN1_OID_INFO x509_key_purposes[] = {
	{ OID_any_extended_key_usage, "anyExtendedKeyUsage", oid_any_extended_key_usage, sizeof(oid_any_extended_key_usage)/sizeof(uint32_t), 0, "Any Extended Key Usage" },
	{ OID_kp_server_auth, "serverAuth", oid_kp_server_auth, OID_KP_CNT, 0, "TLS WWW server authentication" },
	{ OID_kp_client_auth, "clientAuth", oid_kp_client_auth, OID_KP_CNT, 0, "TLS WWW client authentication" },
	{ OID_kp_code_signing, "codeSigning", oid_kp_code_signing, OID_KP_CNT, 0, "Signing of downloadable executable code" },
	{ OID_kp_email_protection, "emailProtection", oid_kp_email_protection, OID_KP_CNT, 0, "Email protection" },
	{ OID_kp_time_stamping, "timeStamping", oid_kp_time_stamping, OID_KP_CNT, 0, "Binding the hash of an object to a time" },
	{ OID_kp_ocsp_signing, "OCSPSigning", oid_kp_ocsp_signing, OID_KP_CNT, 0, "Signing OCSP responses" },
};

static const int x509_key_purposes_count =
	sizeof(x509_key_purposes)/sizeof(x509_key_purposes[0]);

int x509_key_purpose_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_key_purposes, x509_key_purposes_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

const char *x509_key_purpose_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_key_purposes, x509_key_purposes_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

const char *x509_key_purpose_text(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_key_purposes, x509_key_purposes_count, oid))) {
		error_print();
		return NULL;
	}
	return info->description;
}

int x509_key_purpose_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_key_purposes, x509_key_purposes_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_key_purpose_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;
	if ((ret = asn1_oid_info_from_der(&info, x509_key_purposes, x509_key_purposes_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}


int x509_ext_key_usage_to_der(const int *oids, size_t oids_cnt, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t i;

	if (oids_cnt > X509_MAX_KEY_PURPOSES) {
		error_print();
		return -1;
	}
	for (i = 0; i < oids_cnt; i++) {
		if (x509_key_purpose_to_der(oids[i], NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < oids_cnt; i++) {
		if (x509_key_purpose_to_der(oids[i], out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_ext_key_usage_from_der(int *oids, size_t *oids_cnt, size_t max_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	*oids_cnt = 0;
	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	while (len && (*oids_cnt < max_cnt)) {
		if (x509_key_purpose_from_der(oids, &p, &len) != 1) {
			error_print();
			return -1;
		}
		oids++;
		(*oids_cnt)++;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_ext_key_usage_check(const int *oids, size_t oids_cnt, int cert_type)
{
	int ret = -1;
	size_t i;

	for (i = 0; i < oids_cnt; i++) {
		// anyExtendedKeyUsage might not acceptable for strict validation
		if (oids[i] == OID_any_extended_key_usage) {
			ret = 0;
		}

		switch (cert_type) {
		case X509_cert_server_auth:
		case X509_cert_server_key_encipher:
			if (oids[i] == OID_kp_server_auth) {
				return 1;
			}
			break;

		case X509_cert_client_auth:
		case X509_cert_client_key_encipher:
			if (oids[i] == OID_kp_client_auth) {
				return 1;
			}
			break;

		default:
			error_print();
			return -1;
		}
	}
	return ret;
}

int x509_ext_key_usage_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int oid;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (x509_key_purpose_from_der(&oid, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s\n", x509_key_purpose_name(oid));
	}
	return 1;
}

static const char *x509_revoke_reason_flags[] = {
	"unused",
	"keyCompromise",
	"cACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
	"privilegeWithdrawn",
	"aACompromise",
};

static size_t x509_revoke_reason_flags_count =
	sizeof(x509_revoke_reason_flags)/sizeof(x509_revoke_reason_flags[0]);

const char *x509_revoke_reason_flag_name(int flag)
{
	int i;
	for (i = 0; i < x509_revoke_reason_flags_count; i++) {
		if (flag & 1) {
			if (flag >> 1) {
				error_print();
				return NULL;
			}
			return x509_revoke_reason_flags[i];
		}
		flag >>= 1;
	}
	return NULL;
}

int x509_revoke_reason_flag_from_name(int *flag, const char *name)
{
	int i;
	for (i = 0; i < x509_revoke_reason_flags_count; i++) {
		if (strcmp(name, x509_revoke_reason_flags[i]) == 0) {
			*flag = 1 << i;
			return 1;
		}
	}
	*flag = 0;
	error_print();
	return -1;
}

int x509_revoke_reason_flags_print(FILE *fp, int fmt, int ind, const char *label, int bits)
{
	return asn1_bits_print(fp, fmt, ind, label, x509_revoke_reason_flags, x509_revoke_reason_flags_count, bits);
}

int x509_uri_as_distribution_point_name_to_der(const char *uri, size_t urilen,
	uint8_t **out, size_t *outlen)
{
	int tag = ASN1_TAG_EXPLICIT(X509_full_name);

	if (urilen == 0) {
		return 0;
	}
	if (x509_uri_as_general_names_to_der_ex(tag, uri, urilen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_distribution_point_name_from_der(int *choice, const uint8_t **d, size_t *dlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	int tag;

	if ((ret = asn1_any_type_from_der(&tag, d, dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	switch (tag) {
	case ASN1_TAG_EXPLICIT(X509_full_name):
		*choice = X509_full_name;
		break;
	case ASN1_TAG_EXPLICIT(X509_name_relative_to_crl_issuer):
		*choice = X509_name_relative_to_crl_issuer;
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_uri_as_distribution_point_name_from_der(const char **uri, size_t *urilen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	int choice;
	const uint8_t *d;
	size_t dlen;

	if ((ret = x509_distribution_point_name_from_der(&choice, &d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (choice == X509_full_name) {
		if (x509_general_names_get_first(d, dlen, NULL, X509_gn_uniform_resource_identifier, (const uint8_t **)uri, urilen) < 0) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_distribution_point_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	int tag;
	const uint8_t *d;
	size_t dlen;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_any_type_from_der(&tag, &d, &dlen, &a, &alen) != 1) {
		error_print();
		return -1;
	}
	switch (tag) {
	case ASN1_TAG_EXPLICIT(0): return x509_general_names_print(fp, fmt, ind, "fullName", d, dlen);
	case ASN1_TAG_IMPLICIT(1): return x509_rdn_print(fp, fmt, ind, "nameRelativeToCRLIssuer", d, dlen);
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_uri_as_explicit_distribution_point_name_to_der(int index,
	const char *uri, size_t urilen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (!urilen) {
		return 0;
	}
	if (x509_uri_as_distribution_point_name_to_der(uri, urilen, NULL, &len) != 1
		|| asn1_explicit_header_to_der(index, len, out, outlen) != 1
		|| x509_uri_as_distribution_point_name_to_der(uri, urilen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_uri_as_explicit_distribution_point_name_from_der(int index,
	const char **uri, size_t *urilen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *a;
	size_t alen;

	if ((ret = asn1_explicit_from_der(index, &a, &alen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_uri_as_distribution_point_name_from_der(uri, urilen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_uri_as_distribution_point_to_der(const char *uri, size_t urilen,
	int reasons, const uint8_t *crl_issuer, size_t crl_issuer_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_uri_as_explicit_distribution_point_name_to_der(0, uri, urilen, NULL, &len) != 1
		|| x509_revoke_reason_flags_to_der(reasons, NULL, &len) < 0
		|| x509_general_names_to_der(crl_issuer, crl_issuer_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_uri_as_explicit_distribution_point_name_to_der(0, uri, urilen, out, outlen) != 1
		|| x509_revoke_reason_flags_to_der(reasons, out, outlen) < 0
		|| x509_general_names_to_der(crl_issuer, crl_issuer_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_uri_as_distribution_point_from_der(const char **uri, size_t *urilen,
	int *reasons, const uint8_t **crl_issuer, size_t *crl_issuer_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_uri_as_explicit_distribution_point_name_from_der(0, uri, urilen, &d, &dlen) < 0
		|| x509_revoke_reason_flags_from_der(reasons, &d, &dlen) < 0
		|| x509_general_names_from_der(crl_issuer, crl_issuer_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_distribution_point_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	int bits;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = asn1_explicit_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_distribution_point_name_print(fp, fmt, ind, "distributionPoint", p, len);

	if ((ret = asn1_implicit_bits_from_der(1, &bits, &d, &dlen)) < 0) goto err;
	if (ret) x509_revoke_reason_flags_print(fp, fmt, ind, "reasons", bits);

	if ((ret = asn1_implicit_sequence_from_der(2, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_general_names_print(fp, fmt, ind, "cRLIssuer", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_uri_as_distribution_points_to_der(const char *uri, size_t urilen,
	int reasons, const uint8_t *crl_issuer, size_t crl_issuer_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_uri_as_distribution_point_to_der(uri, urilen, reasons, crl_issuer, crl_issuer_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_uri_as_distribution_point_to_der(uri, urilen, reasons, crl_issuer, crl_issuer_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_uri_as_distribution_points_from_der(const char **uri, size_t *urilen,
	int *reasons, const uint8_t **crl_issuer, size_t *crl_issuer_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	while (dlen) {
		if (x509_uri_as_distribution_point_from_der(uri, urilen, reasons, crl_issuer, crl_issuer_len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (*uri != NULL) {
			return 1;
		}
	}
	*uri = NULL;
	*urilen = 0;
	*reasons = -1;
	*crl_issuer = NULL;
	*crl_issuer_len = 0;
	return 1;
}

int x509_distribution_points_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_distribution_point_print(fp, fmt, ind, "DistributionPoint", p, len);
	}
	return 1;
}

static const char *netscape_cert_types[] = {
	"SSL Client certificate",
	"SSL Server certificate",
	"S/MIME certificate",
	"Object-signing certificate",
	"Reserved for future use",
	"SSL CA certificate",
	"S/MIME CA certificate",
	"Object-signing CA certificate",
};

int x509_netscape_cert_type_print(FILE *fp, int fmt, int ind, const char *label, int bits)
{
	return asn1_bits_print(fp, fmt, ind, label, netscape_cert_types,
		sizeof(netscape_cert_types)/sizeof(netscape_cert_types[0]), bits);
}

int x509_exts_check(const uint8_t *exts, size_t extslen, int cert_type,
	int *path_len_constraint)
{
	int oid;
	uint32_t nodes[32];
	size_t nodes_cnt;
	int critical;
	const uint8_t *val;
	size_t vlen;

	int ca = -1;
	int path_len = -1;
	int key_usage;
	int ext_key_usages[X509_MAX_KEY_PURPOSES];
	size_t ext_key_usages_cnt;

	*path_len_constraint = -1;

	while (extslen) {
		if (x509_ext_from_der(&oid, nodes, &nodes_cnt, &critical, &val, &vlen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}

		switch (oid) {
		case OID_ce_authority_key_identifier:
			if (critical == X509_critical) {
				error_print();
				return -1;
			}
			/*
			if (x509_authority_key_identifier(val, vlen) != 1) {
				error_print();
				return -1;
			}
			*/
			break;
		case OID_ce_subject_key_identifier:
			if (critical == X509_critical) {
				error_print();
				return -1;
			}
			const uint8_t *p;
			size_t len;
			if (asn1_octet_string_from_der(&p, &len, &val, &vlen) != 1
				|| asn1_length_is_zero(vlen) != 1) {
				error_print();
				return -1;
			}
			if (!p || !len) {
				error_print();
				return -1;
			}
			break;
		case OID_ce_key_usage:
			if (critical != X509_critical) {
				error_print();
				// conforming CAs SHOULD mark this extension as critical.
			}
			if (asn1_bits_from_der(&key_usage, &val, &vlen) != 1
				|| x509_key_usage_check(key_usage, cert_type) != 1) {
				error_print();
				return -1;
			}
			break;
		case OID_ce_certificate_policies:
			break;
		case OID_ce_policy_mappings:
			if (critical != X509_critical) {
				error_print();
				return -1;
			}
			break;
		case OID_ce_subject_alt_name:
			break;
		case OID_ce_issuer_alt_name:
			if (critical == X509_critical) {
				error_print();
				return -1;
			}
			break;
		case OID_ce_subject_directory_attributes:
			if (critical == X509_critical) {
				error_print();
				return -1;
			}
			break;

		case OID_ce_basic_constraints:
			if (x509_basic_constraints_from_der(&ca, &path_len, &val, &vlen) != 1
				|| x509_basic_constraints_check(ca, path_len, cert_type) != 1) {
				error_print();
				return -1;
			}
			*path_len_constraint = path_len;
			break;

		case OID_ce_ext_key_usage:
			if (x509_ext_key_usage_from_der(ext_key_usages, &ext_key_usages_cnt,
					sizeof(ext_key_usages)/sizeof(ext_key_usages[0]), &val, &vlen) != 1
				|| x509_ext_key_usage_check(ext_key_usages, ext_key_usages_cnt, cert_type) != 1) {
				error_print();
				return -1;
			}
			break;

		case OID_ce_name_constraints:
		case OID_ce_policy_constraints:
		case OID_ce_crl_distribution_points:
		case OID_ce_inhibit_any_policy:
		case OID_ce_freshest_crl:

			break;
		default:
			if (critical == X509_critical) {
				error_print();
				return -1;
			}
		}
	}

	return 1;
}

// AuthorityInfoAccess Extension

static uint32_t oid_ad_ocsp[] =  { oid_ad,1 };
static uint32_t oid_ad_ca_issuers[] = { oid_ad,2 };

#define cnt(oid)	(sizeof(oid)/sizeof((oid)[0]))

static const ASN1_OID_INFO access_methods[] = {
	{ OID_ad_ocsp, "OCSP", oid_ad_ocsp, oid_cnt(oid_ad_ocsp) },
	{ OID_ad_ca_issuers, "CAIssuers", oid_ad_ca_issuers, oid_cnt(oid_ad_ca_issuers) },
};

const char *x509_access_method_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(access_methods, cnt(access_methods), oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_access_method_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(access_methods, cnt(access_methods), name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_access_method_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(access_methods, cnt(access_methods), oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_access_method_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;
	uint32_t nodes[32];
	size_t nodes_cnt;

	if ((ret = asn1_oid_info_from_der_ex(&info, nodes, &nodes_cnt, access_methods, cnt(access_methods), in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}

// currently AccessDescription not support values of SubjectInfoAccess extension
int x509_access_description_to_der(int oid, const char *uri, size_t urilen, uint8_t **out, size_t *outlen)
{
	const int uri_choice = X509_gn_uniform_resource_identifier;
	size_t len = 0;

	if (oid != OID_ad_ocsp && oid != OID_ad_ca_issuers) {
		error_print();
		return -1;
	}
	if (!uri || !urilen) {
		error_print();
		return -1;
	}
	if (x509_access_method_to_der(oid, NULL, &len) != 1
		|| x509_general_name_to_der(uri_choice, (const uint8_t *)uri, urilen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_access_method_to_der(oid, out, outlen) != 1
		|| x509_general_name_to_der(uri_choice, (const uint8_t *)uri, urilen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_access_description_from_der(int *oid, const char **uri, size_t *urilen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int uri_choice;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*oid = -1;
			*uri = NULL;
			*urilen = 0;
		}
		return ret;
	}
	if (x509_access_method_from_der(oid, &d, &dlen) != 1
		|| x509_general_name_from_der(&uri_choice, (const uint8_t **)uri, urilen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (uri_choice != X509_gn_uniform_resource_identifier) {
		error_print();
		return -1;
	}
	if (*uri == NULL || *urilen == 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_access_description_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int oid;
	int choice;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_access_method_from_der(&oid, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "accessMethod: %s\n", x509_access_method_name(oid));

	if (x509_general_name_from_der(&choice, &p, &len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	x509_general_name_print(fp, fmt, ind, "GeneralName", choice, p, len);

	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_authority_info_access_to_der(
	const char *ca_issuers_uri, size_t ca_issuers_urilen,
	const char *ocsp_uri, size_t ocsp_urilen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (ca_issuers_uri && ca_issuers_urilen) {
		if (x509_access_description_to_der(OID_ad_ca_issuers, ca_issuers_uri, ca_issuers_urilen, NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (ocsp_uri && ocsp_urilen) {
		if (x509_access_description_to_der(OID_ad_ocsp, ocsp_uri, ocsp_urilen, NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (!len) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (ca_issuers_uri && ca_issuers_urilen) {
		if (x509_access_description_to_der(OID_ad_ca_issuers, ca_issuers_uri, ca_issuers_urilen, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (ocsp_uri && ocsp_urilen) {
		if (x509_access_description_to_der(OID_ad_ocsp, ocsp_uri, ocsp_urilen, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_authority_info_access_from_der(
	const char **ca_issuers_uri, size_t *ca_issuers_urilen,
	const char **ocsp_uri, size_t *ocsp_urilen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if (!ca_issuers_uri || !ca_issuers_urilen  || !ocsp_uri || !ocsp_urilen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	*ca_issuers_uri = NULL;
	*ca_issuers_urilen = 0;
	*ocsp_uri = NULL;
	*ocsp_urilen = 0;

	if ((ret = asn1_sequence_of_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	while (dlen) {
		int oid;
		const char *uri;
		size_t urilen;

		if (x509_access_description_from_der(&oid, &uri, &urilen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		switch (oid) {
		case OID_ad_ca_issuers:
			if (*ca_issuers_uri) {
				error_print();
				return -1;
			}
			*ca_issuers_uri = uri;
			*ca_issuers_urilen = urilen;
			break;
		case OID_ad_ocsp:
			if (*ocsp_uri) {
				error_print();
				return -1;
			}
			*ocsp_uri = uri;
			*ocsp_urilen = urilen;
			break;
		default:
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_authority_info_access_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_access_description_print(fp, fmt, ind, "AccessDescription", p, len);
	}
	return 1;
}

int x509_exts_add_authority_info_access(uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const char *ca_issuers_uri, size_t ca_issuers_urilen, const char *ocsp_uri, size_t ocsp_urilen)
{
	int oid = OID_pe_authority_info_access;
	size_t curlen = *extslen;
	uint8_t val[256];
	uint8_t *p = val;
	size_t vlen = 0;
	size_t len = 0;

	if (x509_authority_info_access_to_der(ca_issuers_uri, ca_issuers_urilen, ocsp_uri, ocsp_urilen, NULL, &len) != 1
		|| asn1_length_le(len, sizeof(val)) != 1
		|| x509_authority_info_access_to_der(ca_issuers_uri, ca_issuers_urilen, ocsp_uri, ocsp_urilen, &p, &vlen) != 1) {
		error_print();
		return -1;
	}
	exts += *extslen;
	if (x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
