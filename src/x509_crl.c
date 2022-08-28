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
#include <gmssl/asn1.h>
#include <gmssl/oid.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>

static const char *x509_crl_reason_names[] = {
	"unspecified",
	"keyCompromise",
	"cACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
	"notAssigned",
	"removeFromCRL",
	"privilegeWithdrawn",
	"aACompromise",
};

static const size_t x509_crl_reason_names_count =
	sizeof(x509_crl_reason_names)/sizeof(x509_crl_reason_names[0]);

const char *x509_crl_reason_name(int reason)
{
	if (reason < 0 || reason >= x509_crl_reason_names_count) {
		error_print();
		return NULL;
	}
	return x509_crl_reason_names[reason];
}

int x509_crl_reason_from_name(int *reason, const char *name)
{
	int i;
	for (i = 0; i < x509_crl_reason_names_count; i++) {
		if (strcmp(name, x509_crl_reason_names[i]) == 0) {
			*reason = i;
			return 1;
		}
	}
	return 0;
}

int x509_crl_reason_to_der(int reason, uint8_t **out, size_t *outlen)
{
	if (reason >= 0 && !x509_crl_reason_name(reason)) {
		error_print();
		return -1;
	}
	return asn1_enumerated_to_der(reason, out, outlen);
}

int x509_crl_reason_from_der(int *reason, const uint8_t **in, size_t *inlen)
{
	return asn1_enumerated_from_der(reason, in, inlen);
}

int x509_implicit_crl_reason_from_der(int index, int *reason, const uint8_t **in, size_t *inlen)
{
	return asn1_implicit_enumerated_from_der(index, reason, in, inlen);
}


static uint32_t oid_ce_crl_reasons[] = { oid_ce,21 };
static uint32_t oid_ce_invalidity_date[] = { oid_ce,24 };
static uint32_t oid_ce_certificate_issuer[] = { oid_ce,29 };

static const ASN1_OID_INFO x509_crl_entry_exts[] = {
	{ OID_ce_crl_reasons, "CRLReasons", oid_ce_crl_reasons, sizeof(oid_ce_crl_reasons)/sizeof(int) },
	{ OID_ce_invalidity_date, "InvalidityDate", oid_ce_invalidity_date, sizeof(oid_ce_invalidity_date)/sizeof(int) },
	{ OID_ce_certificate_issuer, "CertificateIssuer", oid_ce_certificate_issuer, sizeof(oid_ce_certificate_issuer)/sizeof(int) },
};

static const int x509_crl_entry_exts_count =
	sizeof(x509_crl_entry_exts)/sizeof(x509_crl_entry_exts[0]);

const char *x509_crl_entry_ext_id_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_crl_entry_exts, x509_crl_entry_exts_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_crl_entry_ext_id_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_crl_entry_exts, x509_crl_entry_exts_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_crl_entry_ext_id_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_crl_entry_exts, x509_crl_entry_exts_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out,  outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_ext_id_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;

	if ((ret = asn1_oid_info_from_der(&info, x509_crl_entry_exts, x509_crl_entry_exts_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}

int x509_crl_entry_exts_add_reason(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, int reason)
{
	int oid = OID_ce_crl_reasons;
	size_t curlen = *extslen;
	uint8_t val[16];
	uint8_t *p = val;
	size_t vlen = 0;

	exts += *extslen;
	if (x509_crl_reason_to_der(reason, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_exts_add_invalidity_date(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, time_t tv)
{
	int oid = OID_ce_invalidity_date;
	size_t curlen = *extslen;
	uint8_t val[16];
	uint8_t *p = val;
	size_t vlen = 0;

	exts += *extslen;
	if (asn1_generalized_time_to_der(tv, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_exts_add_certificate_issuer(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_certificate_issuer;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_crl_entry_ext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, oid, critical;
	const uint8_t *v;
	size_t vlen;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_crl_entry_ext_id_from_der(&oid, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "extnID: %s\n", x509_crl_entry_ext_id_name(oid));
	if ((ret = asn1_boolean_from_der(&critical, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "critical: %s\n", asn1_boolean_name(critical));
	if (asn1_octet_string_from_der(&v, &vlen, &d, &dlen) != 1) goto err;

	if (oid == OID_ce_crl_reasons) {
		int reason;
		if (x509_crl_reason_from_der(&reason, &v, &vlen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "reasonCode: %s\n", x509_crl_reason_name(reason));

	} else if (oid == OID_ce_invalidity_date) {
		time_t invalidity_date;
		if (asn1_generalized_time_from_der(&invalidity_date, &v, &vlen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "invalidityDate: %s", ctime(&invalidity_date));

	} else if (oid == OID_ce_certificate_issuer) {
		const uint8_t *gns;
		size_t gnslen;
		if (asn1_sequence_from_der(&gns, &gnslen, &v, &vlen) != 1) {
			error_print();
			return -1;
		}
		x509_general_names_print(fp, fmt, ind, "certificateIssuer", gns, gnslen);

	} else {
err:
		error_print();
		return -1;
	}

	return 1;
}

int x509_crl_entry_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
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
		x509_crl_entry_ext_print(fp, fmt, ind, "Extension", p, len);
	}
	return 1;
}

int x509_revoked_cert_to_der(
	const uint8_t *serial, size_t serial_len,
	time_t revoke_date,
	const uint8_t *entry_exts, size_t entry_exts_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_integer_to_der(serial, serial_len, NULL, &len) != 1
		|| x509_time_to_der(revoke_date, NULL, &len) != 1
		|| asn1_sequence_to_der(entry_exts, entry_exts_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(serial, serial_len, out, outlen) != 1
		|| x509_time_to_der(revoke_date, out, outlen) != 1
		|| asn1_sequence_to_der(entry_exts, entry_exts_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_revoked_cert_from_der(
	const uint8_t **serial, size_t *serial_len,
	time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(serial, serial_len, &d, &dlen) != 1
		|| x509_time_from_der(revoke_date, &d, &dlen) != 1
		|| asn1_sequence_from_der(entry_exts, entry_exts_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_revoked_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	time_t tv;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_integer_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "userCertificate", p, len);
	if (x509_time_from_der(&tv, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "revocationDate: %s", ctime(&tv));
	if ((ret = asn1_sequence_from_der(&p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_crl_entry_exts_print(fp, fmt, ind, "crlEntryExtensions", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_revoked_certs_add_revoked_cert(uint8_t *d, size_t *dlen, size_t maxlen,
	const uint8_t *serial, size_t serial_len,
	time_t revoke_date,
	const uint8_t *entry_exts, size_t entry_exts_len)
{
	error_print();
	return -1;
}

int x509_revoked_certs_get_revoked_cert_by_serial_number(const uint8_t *d, size_t dlen,
	const uint8_t *serial, size_t serial_len,
	time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len)
{
	error_print();
	return -1;
}

int x509_revoked_certs_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
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
		x509_revoked_cert_print(fp, fmt, ind, "RevokedCertificate", p, len);
	}
	return 1;
}


static uint32_t oid_ce_authority_key_identifier[] = { oid_ce,35 };
static uint32_t oid_ce_issuer_alt_name[] = { oid_ce,18 };
static uint32_t oid_ce_crl_number[] = { oid_ce,20 };
static uint32_t oid_ce_delta_crl_indicator[] = { oid_ce,27 };
static uint32_t oid_ce_issuing_distribution_point[] = { oid_ce,28 };
static uint32_t oid_ce_freshest_crl[] = { oid_ce,46 };
static uint32_t oid_pe_authority_info_access[] = { oid_pe,1 };


static const ASN1_OID_INFO x509_crl_exts[] = {
	{ OID_ce_authority_key_identifier, "AuthorityKeyIdentifier", oid_ce_authority_key_identifier, sizeof(oid_ce_authority_key_identifier)/sizeof(int) },
	{ OID_ce_issuer_alt_name, "IssuerAltName", oid_ce_issuer_alt_name, sizeof(oid_ce_issuer_alt_name)/sizeof(int) },
	{ OID_ce_crl_number, "CRLNumber", oid_ce_crl_number, sizeof(oid_ce_crl_number)/sizeof(int) },
	{ OID_ce_delta_crl_indicator, "DeltaCRLIndicator", oid_ce_delta_crl_indicator, sizeof(oid_ce_delta_crl_indicator)/sizeof(int) },
	{ OID_ce_issuing_distribution_point, "IssuingDistributionPoint", oid_ce_issuing_distribution_point, sizeof(oid_ce_issuing_distribution_point)/sizeof(int) },
	{ OID_ce_freshest_crl, "FreshestCRL", oid_ce_freshest_crl, sizeof(oid_ce_freshest_crl)/sizeof(int) },
	{ OID_pe_authority_info_access, "AuthorityInfoAccess", oid_pe_authority_info_access, sizeof(oid_pe_authority_info_access)/sizeof(int) },
};

static const int x509_crl_exts_count =
	sizeof(x509_crl_exts)/sizeof(x509_crl_exts[0]);

const char *x509_crl_ext_id_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_crl_exts, x509_crl_exts_count, oid))) {
		return NULL;
	}
	return info->name;
}

int x509_crl_ext_id_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_crl_exts, x509_crl_exts_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_crl_ext_id_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	size_t len = 0;
	if (!(info = asn1_oid_info_from_oid(x509_crl_exts, x509_crl_exts_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out,  outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_ext_id_from_der_ex(int *oid, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	const ASN1_OID_INFO *info;

	*oid = 0;
	if ((ret = asn1_oid_info_from_der_ex(&info, nodes, nodes_cnt, x509_crl_exts, x509_crl_exts_count, in, inlen)) != 1) {
		error_print();
		return -1;
	}
	if (info) {
		*oid = info->oid;
	}
	return ret;
}

int x509_crl_exts_add_authority_key_identifier(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len)
{
	if (x509_exts_add_authority_key_identifier(exts, extslen, maxlen, critical,
		keyid, keyid_len, issuer, issuer_len, serial, serial_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_exts_add_issuer_alt_name(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *d, size_t dlen)
{
	if (x509_exts_add_issuer_alt_name(exts, extslen, maxlen, critical, d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_exts_add_crl_number(
 	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	int num)
{
	int oid = OID_ce_crl_number;
	size_t curlen = *extslen;
	uint8_t val[32];
	uint8_t *p = val;
	size_t vlen = 0;

	exts += *extslen;
	if (asn1_int_to_der(num, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_exts_add_delta_crl_indicator(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	int num)
{
	int oid = OID_ce_delta_crl_indicator;
	size_t curlen = *extslen;
	uint8_t val[32];
	uint8_t *p = val;
	size_t vlen = 0;

	exts += *extslen;
	if (asn1_int_to_der(num, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_exts_add_issuing_distribution_point(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *dist_point, size_t dist_point_len,
	int only_contains_user_certs,
	int only_contains_ca_certs,
	int only_some_reasons,
	int indirect_crl,
	int only_contains_attr_certs)
{
	error_print();
	return -1;
}

int x509_issuing_distribution_point_to_der(
	int dist_point_choice, const uint8_t *dist_point, size_t dist_point_len,
	int only_contains_user_certs,
	int only_contains_ca_certs,
	int only_some_reasons,
	int indirect_crl,
	int only_contains_attr_certs,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_explicit_distribution_point_name_to_der(0, dist_point_choice, dist_point, dist_point_len, NULL, &len) < 0
		|| asn1_implicit_boolean_to_der(1, only_contains_user_certs, NULL, &len) < 0
		|| asn1_implicit_boolean_to_der(2, only_contains_ca_certs, NULL, &len) < 0
		|| asn1_implicit_bits_to_der(3, only_some_reasons, NULL, &len) < 0 // 是否有特化的类型
		|| asn1_implicit_boolean_to_der(4, indirect_crl, NULL, &len) < 0
		|| asn1_implicit_boolean_to_der(5, only_contains_attr_certs, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_explicit_distribution_point_name_to_der(0, dist_point_choice, dist_point, dist_point_len, out, outlen) < 0
		|| asn1_implicit_boolean_to_der(1, only_contains_user_certs, out, outlen) < 0
		|| asn1_implicit_boolean_to_der(2, only_contains_ca_certs, out, outlen) < 0
		|| asn1_implicit_bits_to_der(3, only_some_reasons, out, outlen) < 0 // 是否有特化的类型
		|| asn1_implicit_boolean_to_der(4, indirect_crl, out, outlen) < 0
		|| asn1_implicit_boolean_to_der(5, only_contains_attr_certs, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_issuing_distribution_point_from_der(
	int *dist_point_choice, const uint8_t **dist_point, size_t *dist_point_len,
	int *only_contains_user_certs,
	int *only_contains_ca_certs,
	int *only_some_reasons,
	int *indirect_crl,
	int *only_contains_attr_certs,
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
		|| asn1_implicit_boolean_from_der(1, only_contains_user_certs, &d, &dlen) < 0
		|| asn1_implicit_boolean_from_der(2, only_contains_ca_certs, &d, &dlen) < 0
		|| asn1_implicit_bits_from_der(3, only_some_reasons, &d, &dlen) < 0
		|| asn1_implicit_boolean_from_der(4, indirect_crl, &d, &dlen) < 0
		|| asn1_implicit_boolean_from_der(5, only_contains_attr_certs, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_issuing_distribution_point_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = asn1_explicit_from_der(0, &p, &len, &d, &dlen)) < 0) goto end;
	if (ret) x509_distribution_point_name_print(fp, fmt, ind, "distributionPoint", p, len);
	if ((ret = asn1_implicit_boolean_from_der(1, &val, &d, &dlen)) < 0) goto end;
	if (!ret) val = 0;
	format_print(fp, fmt, ind, "onlyContainsUserCerts: %s\n", asn1_boolean_name(val));
	if ((ret = asn1_implicit_boolean_from_der(2, &val, &d, &dlen)) < 0) goto end;
	if (!ret) val = 0;
	format_print(fp, fmt, ind, "onlyContainsCACerts: %s\n", asn1_boolean_name(val));
	if ((ret = x509_implicit_crl_reason_from_der(3, &val, &d, &dlen)) < 0) goto end;
	if (ret) format_print(fp, fmt, ind, "onlySomeReasons: %s\n", x509_crl_reason_name(val));
	if ((ret = asn1_implicit_boolean_from_der(4, &val, &d, &dlen)) < 0) goto end;
	if (!ret) val = 0;
	format_print(fp, fmt, ind, "indirectCRL: %s\n", asn1_boolean_name(val));
	if ((ret = asn1_implicit_boolean_from_der(5, &val, &d, &dlen)) < 0) goto end;
	if (!ret) val = 0;
	format_print(fp, fmt, ind, "onlyContainsAttributeCerts: %s\n", asn1_boolean_name(val));
	if (asn1_length_is_zero(dlen) != 1) goto end;
	return 1;
end:
	error_print();
	return -1;
}

int x509_access_descriptions_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	error_print();
	return -1;
}

int x509_crl_ext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, oid, critical;
	const char *name;
	const uint8_t *v;
	size_t vlen;
	const uint8_t *p;
	size_t len;
	uint32_t nodes[32];
	size_t nodes_cnt;
	int num;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_crl_ext_id_from_der_ex(&oid, nodes, &nodes_cnt, &d, &dlen) != 1) goto err;
	asn1_object_identifier_print(fp, fmt, ind, "extnID", x509_crl_ext_id_name(oid), nodes, nodes_cnt);
	if ((ret = asn1_boolean_from_der(&critical, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "critical: %s\n", asn1_boolean_name(critical));
	if (asn1_octet_string_from_der(&v, &vlen, &d, &dlen) != 1) goto err;

	switch (oid) {
	case OID_ce_authority_key_identifier:
	case OID_ce_issuer_alt_name:
	case OID_ce_issuing_distribution_point:
	case OID_ce_freshest_crl:
	case OID_pe_authority_info_access:
		if (asn1_sequence_from_der(&p, &len, &v, &vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ce_crl_number:
	case OID_ce_delta_crl_indicator:
		if (asn1_int_from_der(&num, &v, &vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		if (asn1_any_from_der(&p, &len, &v, &vlen) != 1) {
			error_print();
			return -1;
		}
	}

	name = x509_crl_ext_id_name(oid);

	switch (oid) {
	case OID_ce_authority_key_identifier: x509_authority_key_identifier_print(fp, fmt, ind, name, p, len); break;
	case OID_ce_issuer_alt_name: x509_general_names_print(fp, fmt, ind, name, p, len); break;
	case OID_ce_crl_number: format_print(fp, fmt, ind, "%s: %d\n", name, num); break;
	case OID_ce_delta_crl_indicator: format_print(fp, fmt, ind, "%s: %d\n", name, num); break;
	case OID_ce_issuing_distribution_point: x509_issuing_distribution_point_print(fp, fmt, ind, name, p, len); break;
	case OID_ce_freshest_crl: x509_crl_distribution_points_print(fp, fmt, ind, name, p, len); break;
	case OID_pe_authority_info_access: x509_access_descriptions_print(fp, fmt, ind, name, p, len); break;
	default: format_bytes(fp, fmt, ind, "value", p, len);
	}
	if (asn1_length_is_zero(vlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_crl_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
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
		x509_crl_ext_print(fp, fmt, ind, "Extension", p, len);
	}
	return 1;
}

int x509_tbs_crl_to_der(
	int version,
	int signature_algor,
	const uint8_t *issuer, size_t issuer_len,
	time_t this_update, time_t next_update,
	const uint8_t *revoked_certs, size_t revoked_certs_len,
	const uint8_t *exts, size_t exts_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(version, NULL, &len) < 0
		|| x509_signature_algor_to_der(signature_algor, NULL, &len) != 1
		|| x509_name_to_der(issuer, issuer_len, NULL, &len) != 1
		|| x509_time_to_der(this_update, NULL, &len) != 1
		|| x509_time_to_der(next_update, NULL, &len) < 0
		|| asn1_sequence_to_der(revoked_certs, revoked_certs_len, NULL, &len) < 0
		|| asn1_sequence_to_der(exts, exts_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) < 0
		|| x509_signature_algor_to_der(signature_algor, out, outlen) != 1
		|| x509_name_to_der(issuer, issuer_len, out, outlen) != 1
		|| x509_time_to_der(this_update, out, outlen) != 1
		|| x509_time_to_der(next_update, out, outlen) < 0
		|| asn1_sequence_to_der(revoked_certs, revoked_certs_len, out, outlen) < 0
		|| asn1_sequence_to_der(exts, exts_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_tbs_crl_from_der(
	int *version,
	int *signature_algor,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update,
	time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	const uint8_t **exts, size_t *exts_len,
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
	if (asn1_int_from_der(version, &d, &dlen) < 0
		|| x509_signature_algor_from_der(signature_algor, &d, &dlen) != 1
		|| x509_name_from_der(issuer, issuer_len, &d, &dlen) != 1
		|| x509_time_from_der(this_update, &d, &dlen) != 1
		|| x509_time_from_der(next_update, &d, &dlen) < 0
		|| asn1_sequence_from_der(revoked_certs, revoked_certs_len, &d, &dlen) < 0
		|| x509_explicit_exts_from_der(0, exts, exts_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version >= 0 && *version != X509_version_v2) {
		error_print();
		return -1;
	}
	if (*revoked_certs && *version != X509_version_v2) {
		error_print();
		return -1;
	}
	if (*exts && *version != X509_version_v2) {
		error_print();
		return -1;
	}

	return 1;
}

int x509_tbs_crl_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;
	const uint8_t *p;
	size_t len;
	time_t tv;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = asn1_int_from_der(&val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "version: %s (%d)\n", x509_version_name(val), val);
	if (x509_signature_algor_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "signature: %s\n", x509_signature_algor_name(val));
	if (x509_name_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_name_print(fp, fmt, ind, "issuer", p, len);
	if (x509_time_from_der(&tv, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "thisUpdate: %s", ctime(&tv));
	if ((ret = x509_time_from_der(&tv, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "nextUpdate: %s", ctime(&tv));
	if ((ret = asn1_sequence_from_der(&p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_revoked_certs_print(fp, fmt, ind, "revokedCertificates", p, len);
	if ((ret = x509_explicit_exts_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) {
		x509_crl_exts_print(fp, fmt, ind, "crlExtensions", p, len);
	}
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_cert_list_to_der(const uint8_t *tbs_crl, size_t tbs_crl_len,
	int signature_algor, const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_sequence_to_der(tbs_crl, tbs_crl_len, NULL, &len) != 1
		|| x509_signature_algor_to_der(signature_algor, NULL, &len) != 1
		|| asn1_bit_octets_to_der(sig, siglen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_sequence_to_der(tbs_crl, tbs_crl_len, out, outlen) != 1
		|| x509_signature_algor_to_der(signature_algor, out, outlen) != 1
		|| asn1_bit_octets_to_der(sig, siglen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_list_from_der(const uint8_t **tbs_crl, size_t *tbs_crl_len,
	int *signature_algor, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_sequence_from_der(tbs_crl, tbs_crl_len, &d, &dlen) != 1
		|| x509_signature_algor_from_der(signature_algor, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(sig, siglen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_list_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int val;
	const uint8_t *p;
	size_t len;

	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_tbs_crl_print(fp, fmt, ind, "tbsCertList", p, len);
	if (x509_signature_algor_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "signatureAlgorithm: %s\n", x509_signature_algor_name(val));
	if (asn1_bit_octets_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "signatureValue", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

// FIXME: 这两个函数应该检查CRL格式是否正确
int x509_crl_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	int ret;
	if ((ret = asn1_any_to_der(a, alen, out, outlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_any_from_der(a, alen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_to_pem(const uint8_t *a, size_t alen, FILE *fp)
{
	if (pem_write(fp, "X509 CRL", a, alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_from_pem(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp)
{
	int ret;
	if ((ret = pem_read(fp, "X509 CRL", a, alen, maxlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_to_fp(const uint8_t *a, size_t alen, FILE *fp)
{
	if (fwrite(a, 1, alen, fp) != alen) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_from_fp(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp)
{
	size_t len;
	const uint8_t *d = a;
	size_t dlen;
	const uint8_t *crl;
	size_t crl_len;

	if (!(len = fread(a, 1, maxlen, fp))) {
		if (feof(fp)) {
			return 0;
		} else {
			error_print();
			return -1;
		}
	}

	dlen = len;
	if (x509_crl_from_der(&crl, &crl_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}

	*alen = len;
	return 1;
}


int x509_crl_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *d;
	size_t dlen;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&d, &dlen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	x509_cert_list_print(fp, fmt, ind, label, d, dlen);
	return 1;
}

int x509_tbs_crl_sign(
	int version,
	int signature_algor,
	const uint8_t *issuer, size_t issuer_len,
	time_t this_update, time_t next_update,
	const uint8_t *revoked_certs, size_t revoked_certs_len,
	const uint8_t *exts, size_t exts_len,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len,
	uint8_t *crl, size_t *crl_len)
{
	uint8_t tbs[512];
	size_t tbslen;
	SM2_SIGN_CTX sign_ctx;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	uint8_t *p = tbs;
	size_t len = 0;
	uint8_t *out = crl;
	size_t outlen = 0;

	if (x509_tbs_crl_to_der(version, signature_algor, issuer, issuer_len,
		this_update, next_update, revoked_certs, revoked_certs_len,
		exts, exts_len, &p, &tbslen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_sign_init(&sign_ctx, sign_key, signer_id, signer_id_len) != 1
		|| sm2_sign_update(&sign_ctx, tbs, tbslen) != 1
		|| sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (asn1_data_to_der(tbs, tbslen, NULL, &len) != 1
		|| x509_signature_algor_to_der(signature_algor, NULL, &len) != 1
		|| asn1_bit_octets_to_der(sig, siglen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, &out, &outlen) != 1
		|| asn1_data_to_der(tbs, tbslen, &out, &outlen) != 1
		|| x509_signature_algor_to_der(signature_algor, &out, &outlen) != 1
		|| asn1_bit_octets_to_der(sig, siglen, &out, &outlen) != 1) {
		error_print();
		return -1;
	}
	*crl_len = outlen;
	return 1;
}

int x509_crl_verify(const uint8_t *a, size_t alen,
	const SM2_KEY *pub_key, const char *signer_id, size_t signer_id_len)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *tbs;
	size_t tbslen;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	SM2_SIGN_CTX verify_ctx;

	if ((ret = asn1_sequence_from_der(&d, &dlen, &a, &alen)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return -1;
	}
	if (asn1_any_from_der(&tbs, &tbslen, &d, &dlen) != 1
		|| x509_signature_algor_from_der(&sig_alg, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&sig, &siglen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (sig_alg != OID_sm2sign_with_sm3) {
		error_print();
		return -1;
	}
	if (sm2_verify_init(&verify_ctx, pub_key, signer_id, signer_id_len) != 1
		|| sm2_verify_update(&verify_ctx, tbs, tbslen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = sm2_verify_finish(&verify_ctx, sig, siglen)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return -1;
	}
	return 1;
}

int x509_crl_verify_by_ca_cert(const uint8_t *a, size_t alen, const uint8_t *cacert, size_t cacertlen,
	const char *signer_id, size_t signer_id_len)
{
	int ret;
	SM2_KEY public_key;

	if (x509_cert_get_subject_public_key(cacert, cacertlen, &public_key) != 1
		|| (ret = x509_crl_verify(a, alen, &public_key, signer_id, signer_id_len)) < 0) {
		error_print();
		return -1;
	}
	if (!ret) error_print();
	return ret;
}

int x509_crl_get_details(const uint8_t *a, size_t alen,
	int *opt_version,
	const uint8_t **opt_issuer, size_t *opt_issuer_len,
	time_t *opt_this_update,
	time_t *opt_next_update,
	const uint8_t **opt_revoked_certs, size_t *opt_revoked_certs_len,
	const uint8_t **opt_exts, size_t *opt_exts_len,
	int *opt_signature_algor,
	const uint8_t **opt_sig, size_t *opt_siglen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *tbs;
	size_t tbs_len;
	int signature_algor;
	const uint8_t *sig;
	size_t siglen;

	int version;
	int sig_alg;
	const uint8_t *issuer;
	size_t issuer_len;
	time_t this_update;
	time_t next_update;
	const uint8_t *revoked_certs;
	size_t revoked_certs_len;
	const uint8_t *exts;
	size_t exts_len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, &a, &alen)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return -1;
	}
	if (asn1_any_from_der(&tbs, &tbs_len, &d, &dlen) != 1
		|| x509_signature_algor_from_der(&sig_alg, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&sig, &siglen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (opt_signature_algor) *opt_signature_algor = signature_algor;
	if (opt_sig) *opt_sig = sig;
	if (opt_siglen) *opt_siglen = siglen;

	if (x509_tbs_crl_from_der(&version, &sig_alg, &issuer, &issuer_len,
		&this_update, &next_update, &revoked_certs, &revoked_certs_len,
		&exts, &exts_len, &tbs, &tbs_len) != 1
		|| asn1_length_is_zero(tbs_len) != 1) {
		error_print();
		return -1;
	}

	if (opt_version) *opt_version = version;
	if (opt_issuer) *opt_issuer = issuer;
	if (opt_issuer_len) *opt_issuer_len = issuer_len;
	if (opt_this_update) *opt_this_update = this_update;
	if (opt_next_update) *opt_next_update = next_update;
	if (opt_revoked_certs) *opt_revoked_certs = revoked_certs;
	if (opt_revoked_certs_len) *opt_revoked_certs_len = revoked_certs_len;
	if (opt_exts) *opt_exts = exts;
	if (opt_exts_len) *opt_exts_len = exts_len;
	return 1;
}

int x509_crl_get_issuer(const uint8_t *crl, size_t crl_len,
	const uint8_t **issuer, size_t *issuer_len)
{
	if (x509_crl_get_details(crl, crl_len,
		NULL, // version
		issuer, issuer_len,
		NULL, NULL, // this_udpate, next_update
		NULL, NULL, // revoked_certs, revoked_certs_len
		NULL, NULL, // exts, exts_len,
		NULL, // signature_algor
		NULL, NULL // sig, siglen
		) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_find_revoked_cert_by_serial_number(const uint8_t *a, size_t alen,
	const uint8_t *serial, size_t serial_len,
	time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len)
{
	const uint8_t *certs;
	size_t certslen;

	if (x509_crl_get_details(a, alen,
		NULL, NULL, NULL, NULL, NULL,
		&certs, &certslen,
		NULL, NULL, NULL, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	while (certslen) {
		const uint8_t *serial_number;
		size_t serial_number_len;

		if (x509_revoked_cert_from_der(
			&serial_number, &serial_number_len,
			revoke_date,
			entry_exts, entry_exts_len,
			&certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		if (serial_number_len == serial_len
			&& memcmp(serial_number, serial, serial_len) == 0) {
			return 1;
		}
	}

	return 0;
}

int x509_crls_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
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
		x509_cert_list_print(fp, fmt, ind, "CertificateRevocationList", p, len);
	}
	return 1;
}
