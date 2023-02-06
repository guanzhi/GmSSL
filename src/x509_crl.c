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
#include <gmssl/asn1.h>
#include <gmssl/oid.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/pem.h>
#include <gmssl/mem.h>
#include <gmssl/http.h>
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
	error_print();
	return -1;
}

int x509_crl_reason_to_der(int reason, uint8_t **out, size_t *outlen)
{
	if (reason == -1) {
		return 0;
	}
	if (!x509_crl_reason_name(reason)) {
		error_print();
		return -1;
	}
	if (asn1_enumerated_to_der(reason, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_reason_from_der(int *reason, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_enumerated_from_der(reason, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_crl_reason_name(*reason) == NULL) {
		error_print();
		return -1;
	}
	return 1;
}

/*
int x509_implicit_crl_reason_from_der(int index, int *reason, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_implicit_enumerated_from_der(index, reason, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (!x509_crl_reason_name(*reason)) {
		error_print();
		return -1;
	}
	return 1;
}
*/

static uint32_t oid_ce_crl_reasons[] = { oid_ce,21 };
static uint32_t oid_ce_invalidity_date[] = { oid_ce,24 };
static uint32_t oid_ce_certificate_issuer[] = { oid_ce,29 };

static const ASN1_OID_INFO x509_crl_entry_exts[] = {
	{ OID_ce_crl_reasons, "CRLReasons", oid_ce_crl_reasons, oid_cnt(oid_ce_crl_reasons) },
	{ OID_ce_invalidity_date, "InvalidityDate", oid_ce_invalidity_date, oid_cnt(oid_ce_invalidity_date) },
	{ OID_ce_certificate_issuer, "CertificateIssuer", oid_ce_certificate_issuer, oid_cnt(oid_ce_certificate_issuer) },
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

int x509_crl_entry_ext_critical_check(int oid, int critical)
{
	switch (oid) {
	case OID_ce_crl_reasons:
	case OID_ce_invalidity_date:
		if (critical == X509_critical) {
			error_print();
			return -1;
		}
		break;
	case OID_ce_certificate_issuer:
		if (critical != X509_critical) {
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

int x509_crl_entry_ext_to_der(int oid, int critical, const uint8_t *val, size_t vlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (vlen == 0) {
		return 0;
	}
	if (x509_crl_entry_ext_id_to_der(oid, NULL, &len) != 1
		|| asn1_boolean_to_der(critical, NULL, &len) < 0
		|| asn1_octet_string_to_der(val, vlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_crl_entry_ext_id_to_der(oid, out, outlen) != 1
		|| asn1_boolean_to_der(critical, out, outlen) < 0
		|| asn1_octet_string_to_der(val, vlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_ext_from_der(int *oid, int *critical, const uint8_t **val, size_t *vlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_crl_entry_ext_id_from_der(oid, &d, &dlen) != 1
		|| asn1_boolean_from_der(critical, &d, &dlen) < 0
		|| asn1_octet_string_from_der(val, vlen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_reason_ext_to_der(int critical, int reason, uint8_t **out, size_t *outlen)
{
	int oid = OID_ce_crl_reasons;
	uint8_t val[3];
	uint8_t *p = val;
	size_t vlen = 0;

	if (reason == -1) {
		return 0;
	}
	if (x509_crl_reason_to_der(reason, &p, &vlen) != 1
		|| asn1_length_le(vlen, sizeof(val)) != 1
		|| x509_crl_entry_ext_to_der(oid, critical, val, vlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_invalidity_date_ext_to_der(int critical, time_t date, uint8_t **out, size_t *outlen)
{
	int oid = OID_ce_invalidity_date;
	uint8_t val[ASN1_GENERALIZED_TIME_MAX_SIZE];
	uint8_t *p = val;
	size_t vlen = 0;

	if (date == -1) {
		return 0;
	}
	if (asn1_generalized_time_to_der(date, &p, &vlen) != 1
		|| asn1_length_le(vlen, sizeof(val)) != 1
		|| x509_crl_entry_ext_to_der(oid, critical, val, vlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_issuer_ext_to_der(int critical, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int oid = OID_ce_certificate_issuer;
	uint8_t val[256];
	uint8_t *p = val;
	size_t vlen = 0;

	if (dlen == 0) {
		return 0;
	}
	if (asn1_sequence_to_der(d, dlen, NULL, &vlen) != 1
		|| asn1_length_le(vlen, sizeof(val)) != 1) {
		error_print();
		return -1;
	}
	vlen = 0;
	if (asn1_sequence_to_der(d, dlen, &p, &vlen) != 1
		|| x509_crl_entry_ext_to_der(oid, critical, val, vlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_ext_from_der_ex(int *oid, int *critical,
	int *reason, time_t *invalid_date, const uint8_t **cert_issuer, size_t *cert_issuer_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *val;
	size_t vlen;

	if ((ret = x509_crl_entry_ext_from_der(oid, critical, &val, &vlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*reason = -1;
			*invalid_date = -1;
			*cert_issuer = NULL;
			*cert_issuer_len = 0;
		}
		return ret;
	}
	switch (*oid) {
	case OID_ce_crl_reasons:
		if (*reason != -1) {
			error_print();
			return -1;
		}
		if (x509_crl_reason_from_der(reason, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ce_invalidity_date:
		if (*invalid_date != -1) {
			error_print();
			return -1;
		}
		if (asn1_generalized_time_from_der(invalid_date, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ce_certificate_issuer:
		if (*cert_issuer != NULL) {
			error_print();
			return -1;
		}
		if (asn1_sequence_from_der(cert_issuer, cert_issuer_len, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		if (!cert_issuer) {
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

int x509_crl_entry_exts_to_der(
	int reason, time_t invalid_date, const uint8_t *cert_issuer, size_t cert_issuer_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (reason == -1 && invalid_date == -1 && cert_issuer_len == 0) {
		return 0;
	}
	if (x509_crl_reason_ext_to_der(-1, reason, NULL, &len) < 0
		|| x509_invalidity_date_ext_to_der(-1, invalid_date, NULL, &len) < 0
		|| x509_cert_issuer_ext_to_der(X509_critical, cert_issuer, cert_issuer_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_crl_reason_ext_to_der(-1, reason, out, outlen) < 0
		|| x509_invalidity_date_ext_to_der(-1, invalid_date, out, outlen) < 0
		|| x509_cert_issuer_ext_to_der(X509_critical, cert_issuer, cert_issuer_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_exts_get(const uint8_t *d, size_t dlen,
	int *reason, time_t *invalid_date, const uint8_t **cert_issuer, size_t *cert_issuer_len)
{
	int oid;
	int critical;
	*reason = -1;
	*invalid_date = -1;
	*cert_issuer = NULL;
	*cert_issuer_len = 0;

	while (dlen) {
		if (x509_crl_entry_ext_from_der_ex(&oid, &critical, reason, invalid_date, cert_issuer, cert_issuer_len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_crl_entry_ext_critical_check(oid, critical) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_crl_entry_exts_from_der(
	int *reason, time_t *invalid_date, const uint8_t **cert_issuer, size_t *cert_issuer_len,
	const uint8_t **in, size_t *inlen)
{
	int ret = 0;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (!d || !dlen) {
		error_print();
		return -1;
	}
	if (x509_crl_entry_exts_get(d, dlen, reason, invalid_date, cert_issuer, cert_issuer_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_exts_check(const uint8_t *d, size_t dlen)
{
	int oid;
	int critical;
	int reason = -1;
	time_t invalid_date = -1;
	const uint8_t *cert_issuer = NULL;
	size_t cert_issuer_len = 0;

	while (dlen) {
		if (x509_crl_entry_ext_from_der_ex(&oid, &critical,
			&reason, &invalid_date, &cert_issuer, &cert_issuer_len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_crl_entry_ext_critical_check(oid, critical) != 1) {
			error_print();
			return -1;
		}
		if (cert_issuer) {
			error_print();
			//return -1; // currently cert_issuer can not be processed
		}
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
	const uint8_t *serial, size_t serial_len, time_t revoke_date,
	const uint8_t *crl_entry_exts, size_t crl_entry_exts_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (serial_len == 0 && revoke_date == -1 && crl_entry_exts_len == 0) {
		return 0;
	}
	if (asn1_integer_to_der(serial, serial_len, NULL, &len) != 1
		|| asn1_generalized_time_to_der(revoke_date, NULL, &len) != 1
		|| asn1_sequence_to_der(crl_entry_exts, crl_entry_exts_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(serial, serial_len, out, outlen) != 1
		|| asn1_generalized_time_to_der(revoke_date, out, outlen) != 1
		|| asn1_sequence_to_der(crl_entry_exts, crl_entry_exts_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_revoked_cert_to_der_ex(
	const uint8_t *serial, size_t serial_len, time_t revoke_date,
	int reason, time_t invalid_date, const uint8_t *cert_issuer, size_t cert_issuer_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (serial_len ==0 && revoke_date == -1
		&& reason == -1 && invalid_date == -1 && cert_issuer_len == 0) {
		return 0;
	}
	if (asn1_integer_to_der(serial, serial_len, NULL, &len) != 1
		|| asn1_generalized_time_to_der(revoke_date, NULL, &len) != 1
		|| x509_crl_entry_exts_to_der(reason, invalid_date, cert_issuer, cert_issuer_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(serial, serial_len, out, outlen) != 1
		|| asn1_generalized_time_to_der(revoke_date, out, outlen) != 1
		|| x509_crl_entry_exts_to_der(reason, invalid_date, cert_issuer, cert_issuer_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_revoked_cert_from_der(
	const uint8_t **serial, size_t *serial_len, time_t *revoke_date,
	const uint8_t **crl_entry_exts, size_t *crl_entry_exts_len,
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
		|| asn1_sequence_from_der(crl_entry_exts, crl_entry_exts_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_revoked_cert_from_der_ex(
	const uint8_t **serial, size_t *serial_len, time_t *revoke_date,
	int *reason, time_t *invalid_date, const uint8_t **cert_issuer, size_t *cert_issuer_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *crl_entry_exts;
	size_t crl_entry_exts_len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(serial, serial_len, &d, &dlen) != 1
		|| x509_time_from_der(revoke_date, &d, &dlen) != 1
		|| asn1_sequence_from_der(&crl_entry_exts, &crl_entry_exts_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_crl_entry_exts_get(crl_entry_exts, crl_entry_exts_len,
		reason, invalid_date, cert_issuer, cert_issuer_len) != 1) {
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

int x509_cert_revoke_to_der(const uint8_t *cert, size_t certlen,
	time_t revoke_date, int reason, time_t invalid_date, const uint8_t *cert_issuer, size_t cert_issuer_len,
	uint8_t **out, size_t *outlen)
{
	const uint8_t *serial;
	size_t serial_len;

	if (x509_cert_get_issuer_and_serial_number(cert, certlen, NULL, 0, &serial, &serial_len) != 1
		|| x509_revoked_cert_to_der_ex(serial, serial_len, revoke_date,
			reason, invalid_date, cert_issuer, cert_issuer_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_revoked_certs_find_revoked_cert_by_serial_number(const uint8_t *d, size_t dlen,
	const uint8_t *serial, size_t serial_len,
	time_t *revoke_date, const uint8_t **crl_entry_exts, size_t *crl_entry_exts_len)
{
	const uint8_t *sn;
	size_t sn_len;

	while (dlen) {
		if (x509_revoked_cert_from_der(&sn, &sn_len, revoke_date,
			crl_entry_exts, crl_entry_exts_len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (sn_len == serial_len && memcmp(sn, serial, serial_len) == 0) {
			return 1;
		}
	}
	*revoke_date = -1;
	*crl_entry_exts = NULL;
	*crl_entry_exts_len = 0;
	return 0;
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


// CRL Extensions
static uint32_t oid_ce_authority_key_identifier[] = { oid_ce,35 };
static uint32_t oid_ce_issuer_alt_name[] = { oid_ce,18 };
static uint32_t oid_ce_crl_number[] = { oid_ce,20 };
static uint32_t oid_ce_delta_crl_indicator[] = { oid_ce,27 };
static uint32_t oid_ce_issuing_distribution_point[] = { oid_ce,28 };
static uint32_t oid_ce_freshest_crl[] = { oid_ce,46 };
static uint32_t oid_pe_authority_info_access[] = { oid_pe,1 };

static const ASN1_OID_INFO x509_crl_exts[] = {
	{ OID_ce_authority_key_identifier, "AuthorityKeyIdentifier", oid_ce_authority_key_identifier, oid_cnt(oid_ce_authority_key_identifier) },
	{ OID_ce_issuer_alt_name, "IssuerAltName", oid_ce_issuer_alt_name, oid_cnt(oid_ce_issuer_alt_name) },
	{ OID_ce_crl_number, "CRLNumber", oid_ce_crl_number, oid_cnt(oid_ce_crl_number) },
	{ OID_ce_delta_crl_indicator, "DeltaCRLIndicator", oid_ce_delta_crl_indicator, oid_cnt(oid_ce_delta_crl_indicator) },
	{ OID_ce_issuing_distribution_point, "IssuingDistributionPoint", oid_ce_issuing_distribution_point, oid_cnt(oid_ce_issuing_distribution_point) },
	{ OID_ce_freshest_crl, "FreshestCRL", oid_ce_freshest_crl, oid_cnt(oid_ce_freshest_crl) },
	{ OID_pe_authority_info_access, "AuthorityInfoAccess", oid_pe_authority_info_access, oid_cnt(oid_pe_authority_info_access) },
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
	if (!(info = asn1_oid_info_from_oid(x509_crl_exts, x509_crl_exts_count, oid))
		|| asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out,  outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_ext_id_from_der_ex(int *oid, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;

	*oid = 0;
	if ((ret = asn1_oid_info_from_der_ex(&info, nodes, nodes_cnt, x509_crl_exts, x509_crl_exts_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (info) {
		*oid = info->oid;
	}
	return ret;
}

int x509_crl_ext_id_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	uint32_t nodes[32];
	size_t nodes_cnt;

	if ((ret = x509_crl_ext_id_from_der_ex(oid, nodes, &nodes_cnt, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*oid == OID_undef) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_issuing_distribution_point_to_der(
	const char *dist_point_uri, size_t dist_point_uri_len,
	int only_contains_user_certs,
	int only_contains_ca_certs,
	int only_some_reasons,
	int indirect_crl,
	int only_contains_attr_certs,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (dist_point_uri_len == 0
		&& only_contains_user_certs == -1
		&& only_contains_ca_certs == -1
		&& only_some_reasons == -1
		&& indirect_crl == -1
		&& only_contains_attr_certs == -1) {
		return 0;
	}
	if (x509_uri_as_explicit_distribution_point_name_to_der(0, dist_point_uri, dist_point_uri_len, NULL, &len) < 0
		|| asn1_implicit_boolean_to_der(1, only_contains_user_certs, NULL, &len) < 0
		|| asn1_implicit_boolean_to_der(2, only_contains_ca_certs, NULL, &len) < 0
		|| asn1_implicit_bits_to_der(3, only_some_reasons, NULL, &len) < 0 // TODO: 特化的类型
		|| asn1_implicit_boolean_to_der(4, indirect_crl, NULL, &len) < 0
		|| asn1_implicit_boolean_to_der(5, only_contains_attr_certs, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_uri_as_explicit_distribution_point_name_to_der(0, dist_point_uri, dist_point_uri_len, out, outlen) < 0
		|| asn1_implicit_boolean_to_der(1, only_contains_user_certs, out, outlen) < 0
		|| asn1_implicit_boolean_to_der(2, only_contains_ca_certs, out, outlen) < 0
		|| asn1_implicit_bits_to_der(3, only_some_reasons, out, outlen) < 0 // TODO: 特化的类型
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
	const uint8_t *a;
	size_t alen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_explicit_from_der(0, &a, &alen, &d, &dlen) < 0
		|| asn1_implicit_boolean_from_der(1, only_contains_user_certs, &d, &dlen) < 0
		|| asn1_implicit_boolean_from_der(2, only_contains_ca_certs, &d, &dlen) < 0
		|| asn1_implicit_bits_from_der(3, only_some_reasons, &d, &dlen) < 0
		|| asn1_implicit_boolean_from_der(4, indirect_crl, &d, &dlen) < 0
		|| asn1_implicit_boolean_from_der(5, only_contains_attr_certs, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_distribution_point_name_from_der(dist_point_choice, dist_point, dist_point_len, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
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
	if ((ret = asn1_implicit_bits_from_der(3, &val, &d, &dlen)) < 0) goto end;
	if (ret) x509_revoke_reason_flags_print(fp, fmt, ind, "onlySomeReasons", val);
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

int x509_crl_ext_critical_check(int oid, int critical)
{
	switch (oid) {
	// MUST be critical
	case OID_ce_delta_crl_indicator:
	case OID_ce_issuing_distribution_point:
		if (critical != X509_critical) {
			error_print();
			return -1;
		}
		break;
	// critical or non-critical
	case OID_ce_authority_key_identifier:
		break;
	// SHOULD be non-critical
	case OID_ce_issuer_alt_name:
		if (critical == X509_critical) {
			error_print();
			return 0;
		}
		break;
	// MUST be non-critical
	case OID_ce_crl_number:
	case OID_ce_freshest_crl:
	case OID_pe_authority_info_access:
	default:
		if (critical == X509_critical) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_crl_ext_to_der(int oid, int critical, const uint8_t *val, size_t vlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (vlen == 0) {
		return 0;
	}
	if (x509_crl_ext_id_to_der(oid, NULL, &len) != 1
		|| asn1_boolean_to_der(critical, NULL, &len) < 0
		|| asn1_octet_string_to_der(val, vlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_crl_ext_id_to_der(oid, out, outlen) != 1
		|| asn1_boolean_to_der(critical, out, outlen) < 0
		|| asn1_octet_string_to_der(val, vlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_ext_from_der_ex(int *oid, uint32_t *nodes, size_t *nodes_cnt,
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
	if (x509_crl_ext_id_from_der_ex(oid, nodes, nodes_cnt, &d, &dlen) != 1
		|| asn1_boolean_from_der(critical, &d, &dlen) < 0
		|| asn1_octet_string_from_der(val, vlen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
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
	case OID_pe_authority_info_access: x509_authority_info_access_print(fp, fmt, ind, name, p, len); break;
	default: format_bytes(fp, fmt, ind, "value", p, len);
	}
	if (asn1_length_is_zero(vlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_crl_exts_add_authority_key_identifier(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len)
{
	int ret;
	if ((ret = x509_exts_add_authority_key_identifier(exts, extslen, maxlen, critical,
		keyid, keyid_len, issuer, issuer_len, serial, serial_len)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_exts_add_default_authority_key_identifier(uint8_t *exts, size_t *extslen, size_t maxlen,
	const SM2_KEY *public_key)
{
	int ret;
	if ((ret = x509_exts_add_default_authority_key_identifier(exts, extslen, maxlen, public_key)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_exts_add_issuer_alt_name(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *d, size_t dlen)
{
	int ret;
	if ((ret = x509_exts_add_issuer_alt_name(exts, extslen, maxlen, critical, d, dlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_exts_add_crl_number_ex(
 	uint8_t *exts, size_t *extslen, size_t maxlen,
	int oid, int critical, int num)
{
	size_t curlen = *extslen;
	uint8_t val[32];
	uint8_t *p = val;
	size_t vlen = 0;

	if (num < 0) {
		return 0;
	}

	exts += *extslen;
	if (asn1_int_to_der(num, &p, &vlen) != 1
		|| x509_crl_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_crl_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_exts_add_crl_number(
 	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, int num)
{
	int oid = OID_ce_crl_number;
	int ret;

	if ((ret = x509_crl_exts_add_crl_number_ex(exts, extslen, maxlen, oid, critical, num)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_exts_add_delta_crl_indicator(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	int num)
{
	int oid = OID_ce_delta_crl_indicator;
	int ret;

	if ((ret = x509_crl_exts_add_crl_number_ex(exts, extslen, maxlen, oid, critical, num)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_exts_add_issuing_distribution_point(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const char *dist_point_uri, size_t dist_point_uri_len,
	int only_contains_user_certs,
	int only_contains_ca_certs,
	int only_some_reasons,
	int indirect_crl,
	int only_contains_attr_certs)
{
	int oid = OID_ce_issuing_distribution_point;
	int ret;
	size_t curlen = *extslen;
	uint8_t val[512];
	size_t vlen = 0;
	uint8_t *p = val;
	size_t len = 0;

	if ((ret = x509_issuing_distribution_point_to_der(
		dist_point_uri, dist_point_uri_len,
		only_contains_user_certs,
		only_contains_ca_certs,
		only_some_reasons,
		indirect_crl,
		only_contains_attr_certs, NULL, &len)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (len > sizeof(val)) {
		error_print();
		return -1;
	}
	if (x509_issuing_distribution_point_to_der(
		dist_point_uri, dist_point_uri_len,
		only_contains_user_certs,
		only_contains_ca_certs,
		only_some_reasons,
		indirect_crl,
		only_contains_attr_certs, &p, &vlen) != 1) {
		error_print();
		return -1;
	}
	exts += *extslen;
	if (x509_crl_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_crl_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_exts_add_freshest_crl(
	uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const char *http_uri, size_t http_urilen, const char *ldap_uri, size_t ldap_urilen)
{
	int oid = OID_ce_freshest_crl;
	int ret;
	if ((ret = x509_exts_add_crl_distribution_points_ex(exts, extslen, maxlen,
		oid, critical, http_uri, http_urilen, ldap_uri, ldap_urilen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_exts_add_authority_info_acess(
	uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const char *ca_issuers_uri, size_t ca_issuers_urilen, const char *ocsp_uri, size_t ocsp_urilen)
{
	int ret;
	if ((ret = x509_exts_add_authority_info_access(exts, extslen, maxlen, critical,
		ca_issuers_uri, ca_issuers_urilen, ocsp_uri, ocsp_urilen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_crl_exts_check(const uint8_t *d, size_t dlen)
{
	int oid;
	uint32_t nodes[32];
	size_t nodes_cnt;
	int critical;
	const uint8_t *val;
	size_t vlen;

	while (dlen) {
		if (x509_crl_ext_from_der_ex(&oid, nodes, &nodes_cnt, &critical, &val, &vlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_crl_ext_critical_check(oid, critical) != 1) {
			error_print();
			return -1;
		}
		if (critical == X509_critical) {
			error_print();
			return -1;
		}
	}
	return 1;
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
		|| x509_explicit_exts_to_der(0, exts, exts_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) < 0
		|| x509_signature_algor_to_der(signature_algor, out, outlen) != 1
		|| x509_name_to_der(issuer, issuer_len, out, outlen) != 1
		|| x509_time_to_der(this_update, out, outlen) != 1
		|| x509_time_to_der(next_update, out, outlen) < 0
		|| asn1_sequence_to_der(revoked_certs, revoked_certs_len, out, outlen) < 0
		|| x509_explicit_exts_to_der(0, exts, exts_len, out, outlen) < 0) {
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
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_signature_algor_print(fp, fmt, ind, "signature", p, len);
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

static int x509_cert_list_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_tbs_crl_print(fp, fmt, ind, "tbsCertList", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_signature_algor_print(fp, fmt, ind, "signatureAlgorithm", p, len);
	if (asn1_bit_octets_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "signatureValue", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_crl_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	if (x509_crl_get_issuer(a, alen, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	if (asn1_any_to_der(a, alen, out, outlen) != 1) {
		error_print();
		return -1;
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
	if (x509_crl_get_issuer(*a, *alen, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
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

int x509_crl_sign_to_der(
	int version, int sig_alg,
	const uint8_t *issuer, size_t issuer_len,
	time_t this_update, time_t next_update,
	const uint8_t *revoked_certs, size_t revoked_certs_len,
	const uint8_t *crl_exts, size_t crl_exts_len,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t *tbs;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen = SM2_signature_typical_size;

	if (sig_alg != OID_sm2sign_with_sm3) {
		error_print();
		return -1;
	}

	if (x509_tbs_crl_to_der(version, sig_alg, issuer, issuer_len,
			this_update, next_update, revoked_certs, revoked_certs_len,
			crl_exts, crl_exts_len, NULL, &len) != 1
		|| x509_signature_algor_to_der(sig_alg, NULL, &len) != 1
		|| asn1_bit_octets_to_der(sig, siglen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		tbs = *out;
	}
	if (x509_tbs_crl_to_der(version, sig_alg, issuer, issuer_len,
			this_update, next_update, revoked_certs, revoked_certs_len,
			crl_exts, crl_exts_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		SM2_SIGN_CTX sign_ctx;
		if (sm2_sign_init(&sign_ctx, sign_key, signer_id, signer_id_len) != 1
			|| sm2_sign_update(&sign_ctx, tbs, *out - tbs) != 1
			|| sm2_sign_finish_fixlen(&sign_ctx, siglen, sig) != 1) {
			gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
			error_print();
			return -1;
		}
		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	}
	if (x509_signature_algor_to_der(sig_alg, out, outlen) != 1
		|| asn1_bit_octets_to_der(sig, siglen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_from_der_ex(
	int *version,
	int *inner_sig_alg,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update, time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	const uint8_t **exts, size_t *exts_len,
	int *sig_alg, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *tbs;
	size_t tbs_len;

	if ((ret = x509_signed_from_der(&tbs, &tbs_len, sig_alg, sig, siglen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_tbs_crl_from_der(version, inner_sig_alg, issuer, issuer_len,
		this_update, next_update, revoked_certs, revoked_certs_len,
		exts, exts_len, &tbs, &tbs_len) != 1
		|| asn1_length_is_zero(tbs_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_verify_by_ca_cert(const uint8_t *a, size_t alen,
	const uint8_t *cert, size_t certlen, const char *signer_id, size_t signer_id_len)
{
	const uint8_t *crl_issuer;
	size_t crl_issuer_len;
	const uint8_t *ca_subject;
	size_t ca_subject_len;

	if (x509_crl_get_issuer(a, alen, &crl_issuer, &crl_issuer_len) != 1
		|| x509_cert_get_subject(cert, certlen, &ca_subject, &ca_subject_len) != 1) {
		error_print();
		return -1;
	}
	if (x509_name_equ(crl_issuer, crl_issuer_len, ca_subject, ca_subject_len) != 1) {
		error_print();
		return -1;
	}
	if (x509_signed_verify_by_ca_cert(a, alen, cert, certlen, signer_id, signer_id_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_get_details(const uint8_t *a, size_t alen,
	int *version, int *inner_sig_alg,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update, time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	const uint8_t **exts, size_t *exts_len,
	int *sig_alg, const uint8_t **sig, size_t *siglen)
{
	const uint8_t *crl_tbs;
	size_t crl_tbslen;
	int crl_sig_alg;
	const uint8_t *crl_sig;
	size_t crl_siglen;

	struct {
		int version;
		int sig_alg;
		const uint8_t *issuer; size_t issuer_len;
		time_t this_update; time_t next_update;
		const uint8_t *revoked_certs; size_t revoked_certs_len;
		const uint8_t *exts; size_t exts_len;
	} tbs;

	if (x509_signed_from_der(&crl_tbs, &crl_tbslen, &crl_sig_alg, &crl_sig, &crl_siglen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	if (x509_tbs_crl_from_der(
		&tbs.version, &tbs.sig_alg,
		&tbs.issuer, &tbs.issuer_len,
		&tbs.this_update, &tbs.next_update,
		&tbs.revoked_certs, &tbs.revoked_certs_len,
		&tbs.exts, &tbs.exts_len, &crl_tbs, &crl_tbslen) != 1
		|| asn1_length_is_zero(crl_tbslen) != 1) {
		error_print();
		return -1;
	}

	if (version) *version = tbs.version;
	if (inner_sig_alg) *inner_sig_alg = tbs.sig_alg;
	if (issuer) *issuer = tbs.issuer;
	if (issuer_len) *issuer_len = tbs.issuer_len;
	if (this_update) *this_update = tbs.this_update;
	if (next_update) *next_update = tbs.next_update;
	if (revoked_certs) *revoked_certs = tbs.revoked_certs;
	if (revoked_certs_len) *revoked_certs_len = tbs.revoked_certs_len;
	if (exts) *exts = tbs.exts;
	if (exts_len) *exts_len = tbs.exts_len;
	if (sig_alg) *sig_alg = crl_sig_alg;
	if (sig) *sig = crl_sig;
	if (siglen) *siglen = crl_siglen;
	return 1;
}

int x509_crl_check(const uint8_t *a, size_t alen, time_t now)
{
	int version;
	int inner_sig_alg;
	const uint8_t *issuer;
	size_t issuer_len;
	time_t this_update;
	time_t next_update;
	const uint8_t *exts;
	size_t exts_len;
	int sig_alg;

	if (x509_crl_get_details(a, alen, &version, &inner_sig_alg,
		&issuer, &issuer_len, &this_update, &next_update,
		NULL, NULL, &exts, &exts_len, &sig_alg, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	if (inner_sig_alg != sig_alg) {
		error_print();
		return -1;
	}
	if (version != X509_version_v1 && version != X509_version_v2) {
		error_print();
		return -1;
	}
	// this_update <= now < next_update
	if (now < this_update) {
		error_print();
		return -1;
	}
	if (next_update >= 0) {
		if (now >= next_update) {
			error_print();
			return -1;
		}
	}
	if (x509_crl_exts_check(exts, exts_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_get_issuer(const uint8_t *crl, size_t crl_len,
	const uint8_t **issuer, size_t *issuer_len)
{
	if (x509_crl_get_details(crl, crl_len,
		NULL, // version
		NULL, // sig_alg
		issuer, issuer_len, // issuer, issuer_len
		NULL, NULL, // this_udpate, next_update
		NULL, NULL, // revoked_certs, revoked_certs_len
		NULL, NULL, // exts, exts_len,
		NULL, NULL, NULL // sig_alg, sig, siglen
		) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_get_revoked_certs(const uint8_t *a, size_t alen, const uint8_t **d, size_t *dlen)
{
	if (x509_crl_get_details(a, alen,
		NULL, // version
		NULL, // sig_alg
		NULL, NULL, // issuer, issuer_len
		NULL, NULL, // this_udpate, next_update
		d, dlen, // revoked_certs, revoked_certs_len
		NULL, NULL, // exts, exts_len
		NULL, NULL, NULL // sig_alg, sig, siglen
		) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_find_revoked_cert_by_serial_number(const uint8_t *a, size_t alen,
	const uint8_t *serial, size_t serial_len, time_t *revoke_date,
	const uint8_t **crl_entry_exts, size_t *crl_entry_exts_len)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if (x509_crl_get_revoked_certs(a, alen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_revoked_certs_find_revoked_cert_by_serial_number(d, dlen, serial, serial_len,
		revoke_date, crl_entry_exts, crl_entry_exts_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
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
