/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/x509_str.h>
#include <gmssl/x509_oid.h>
#include <gmssl/x509_ext.h>
#include <gmssl/error.h>



int x509_exts_add_sequence(uint8_t *exts, size_t *extslen, size_t maxlen,
	int oid, int critical, const uint8_t *d, size_t dlen)
{
	uint8_t val[32 + dlen];
	uint8_t *p = val;
	size_t curlen = *extslen;
	size_t vlen = 0;

	exts += *extslen;
	if (asn1_sequence_to_der(d, dlen, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
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

int x509_exts_add_key_usage(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, int bits)
{
	int oid = OID_ce_key_usage;
	size_t curlen = *extslen;
	uint8_t val[16];
	uint8_t *p = val;
	size_t vlen = 0;

	if (!bits) {
		// TODO: 检查是否在合法范围内
		error_print();
		return -1;
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

int x509_exts_add_crl_distribution_points(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_crl_distribution_points;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_exts_add_inhibit_any_policy(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, int skip_certs)
{
	int oid = OID_ce_inhibit_any_policy;
	size_t curlen = *extslen;
	uint8_t val[16];
	uint8_t *p = val;
	size_t vlen = 0;

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

int x509_other_name_to_der(
	const uint32_t *type_nodes, size_t type_nodes_cnt,
	const uint8_t *value, size_t value_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_object_identifier_to_der(type_nodes, type_nodes_cnt, NULL, &len) != 1
		|| asn1_explicit_to_der(0, value, value_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(type_nodes, type_nodes_cnt, out, outlen) != 1
		|| asn1_explicit_to_der(0, value, value_len, out, outlen) != 1) {
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

// GeneralName CHOICE 中有的是基本类型，有的是SEQUENCE，在设置标签时是否有区别？			
// 这里是否支持OPTIONAL??		
int x509_general_name_to_der(int choice, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	return asn1_implicit_to_der(choice, d, dlen, out, outlen);
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
		if (asn1_ia5_string_check((char *)d, dlen) != 1) {
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
	uint8_t buf[128];		
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
	uint8_t buf[128];		
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
	uint8_t d[128];		
	size_t dlen;

	if (asn1_object_identifier_to_octets(nodes, nodes_cnt, d, &dlen) != 1
		|| x509_general_names_add_general_name(gns, gnslen, maxlen, choice, d, dlen) != 1) {
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

int x509_key_usage_print(FILE *fp, int fmt, int ind, const char *label, int bits)
{
	return asn1_bits_print(fp, fmt, ind, label, x509_key_usages, x509_key_usages_count, bits);
}

int x509_notice_reference_to_der(
	int org_tag, const uint8_t *org, size_t org_len,
	const int *notice_numbers, size_t notice_numbers_cnt,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
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
	int notice_numbers[X509_MAX_NOTICE_NUMBERS], size_t *notice_numbers_cnt, size_t max_notice_numbers, //FIXME: max_notice_numbers 还没检查	
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
		|| asn1_sequence_of_int_from_der(notice_numbers, notice_numbers_cnt, &d, &dlen) != 1
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
	int *notice_ref_notice_numbers, size_t *notice_ref_notice_numbers_cnt, size_t max_notice_ref_notice_numbers, // FIXME: max_notice_ref_notice_numbers	
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

// 是否要针对oid = cps的IA5String做一个方便的接口呢？毕竟oid 只有两个可选项		
int x509_policy_qualifier_info_to_der(
	int oid,
	const uint8_t *qualifier, size_t qualifier_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
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
		return ret;
	}
	if (asn1_boolean_from_der(ca, &d, &dlen) < 0
		|| asn1_int_from_der(path_len_cons, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*ca < 0 && *path_len_cons < 0) {
		error_print();
		return -1;
	}
	if (*ca < 0) *ca = 0;
	return 1;
}

int x509_basic_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = asn1_boolean_from_der(&val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "cA: %s\n", asn1_boolean_name(val));
	else format_print(fp, fmt, ind, "cA: %s\n", asn1_boolean_name(0)); // 特殊对待，无论cA值是否编码均输出结果
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
		return ret;
	}
	*require_explicit_policy = -1;
	*inhibit_policy_mapping = -1;
	if (asn1_implicit_int_from_der(0, require_explicit_policy, &d, &dlen) < 0
		|| asn1_implicit_int_from_der(1, inhibit_policy_mapping, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
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

static const char *x509_revoke_reasons[] = {
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

static size_t x509_revoke_reasons_count =
	sizeof(x509_revoke_reasons)/sizeof(x509_revoke_reasons[0]);

const char *x509_revoke_reason_name(int flag)
{
	int i;
	for (i = 0; i < x509_revoke_reasons_count; i++) {
		if (flag & 1) {
			if (flag >> 1) {
				error_print();
				return NULL;
			}
			return x509_revoke_reasons[i];
		}
		flag >>= 1;
	}
	return NULL;
}

int x509_revoke_reason_from_name(int *flag, const char *name)
{
	int i;
	for (i = 0; i < x509_revoke_reasons_count; i++) {
		if (strcmp(name, x509_revoke_reasons[i]) == 0) {
			*flag = 1 << i;
			return 1;
		}
	}
	*flag = 0;
	error_print();
	return -1;
}

int x509_revoke_reasons_print(FILE *fp, int fmt, int ind, const char *label, int bits)
{
	return asn1_bits_print(fp, fmt, ind, label, x509_revoke_reasons, x509_revoke_reasons_count, bits);
}

int x509_distribution_point_name_to_der(int choice, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	switch (choice) {
	case 0:
	case 1:
		if (asn1_implicit_to_der(choice, d, dlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		return 1;
	default:
		error_print();
		return -1;
	}
}

int x509_distribution_point_name_from_der(int *choice, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_implicit_from_der(*choice, d, dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return -1;
	}
	switch (*choice) {
	case 0:
	case 1:
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_explicit_distribution_point_name_to_der(int index, int choice, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	// 注意：要能够解决d == NULL的情况
	error_print();
	return -1;
}

int x509_explicit_distribution_point_name_from_der(int index, int *choice, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	// 注意：要能够解决d == NULL的情况
	error_print();
	return -1;
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

int x509_distribution_point_to_der(
	int dist_point_choice, const uint8_t *dist_point, size_t dist_point_len,
	int reasons, const uint8_t *crl_issuer, size_t crl_issuer_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_explicit_distribution_point_name_to_der(0, dist_point_choice, dist_point, dist_point_len, NULL, &len) < 0
		|| asn1_implicit_bits_to_der(1, reasons, NULL, &len) < 0
		|| asn1_implicit_sequence_to_der(2, crl_issuer, crl_issuer_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_explicit_distribution_point_name_to_der(0, dist_point_choice, dist_point, dist_point_len, out, outlen) < 0
		|| asn1_implicit_bits_to_der(1, reasons, out, outlen) < 0
		|| asn1_implicit_sequence_to_der(2, crl_issuer, crl_issuer_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_distribution_point_from_der(
	int *dist_point_choice, const uint8_t **dist_point, size_t *dist_point_len,
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
	if (x509_explicit_distribution_point_name_from_der(0, dist_point_choice, dist_point, dist_point_len, &d, &dlen) < 0
		|| asn1_implicit_bits_from_der(1, reasons, &d, &dlen) < 0
		|| asn1_implicit_sequence_from_der(2, crl_issuer, crl_issuer_len, &d, &dlen) < 0
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
	if (ret) x509_revoke_reasons_print(fp, fmt, ind, "reasons", bits);

	if ((ret = asn1_implicit_sequence_from_der(2, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_general_names_print(fp, fmt, ind, "cRLIssuer", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

/*
                extnID: CRLDistributionPoints (2.5.29.31)
                    DistributionPoint
                        distributionPoint
                            fullName
                                GeneralName
                                    URI: http://www.rootca.gov.cn/Civil_Servant_arl/Civil_Servant_ARL.crl
                    DistributionPoint
                        distributionPoint
                            fullName
                                GeneralName
                                    URI: ldap://ldap.rootca.gov.cn:390/CN=Civil_Servant_ARL,OU=ARL,O=NRCAC,C=CN

*/

int x509_distribution_points_add_url(uint8_t *d, size_t *dlen, size_t maxlen, const char *url)
{
	return 0;
}

int x509_distribution_points_add_distribution_point(uint8_t *d, size_t *dlen, size_t maxlen,
	int dist_point_choice, const uint8_t *dist_point, size_t dist_point_len,
	int reasons, const uint8_t *crl_issuer, size_t crl_issuer_len)
{
	error_print();
	return -1;
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

