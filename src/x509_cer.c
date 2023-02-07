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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/pem.h>
#include <gmssl/asn1.h>
#include <gmssl/rsa.h>
#include <gmssl/file.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>


const char *x509_version_name(int version)
{
	switch (version) {
	case X509_version_v1: return "v1";
	case X509_version_v2: return "v2";
	case X509_version_v3: return "v3";
	}
	return NULL;
}

int x509_explicit_version_to_der(int index, int version, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (version == -1) {
		return 0;
	}
	if (!x509_version_name(version)) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| asn1_explicit_header_to_der(index, len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_explicit_version_from_der(int index, int *version, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_explicit_from_der(index, &d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *version = -1;
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (!x509_version_name(*version)) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_time_to_der(time_t tv, uint8_t **out, size_t *outlen)
{
	if (tv == -1) {
		return 0;
	}

	if (tv < -1 || tv > X509_MAX_GENERALIZED_TIME) {
		error_print();
		return -1;
	}
	if (tv <= X509_MAX_UTC_TIME) {
		if (asn1_utc_time_to_der(tv, out, outlen) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (asn1_generalized_time_to_der(tv, out, outlen) !=1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_time_from_der(time_t *tv, const uint8_t **in, size_t *inlen)
{
	int ret;
	int tag;

	if ((ret = asn1_tag_from_der_readonly(&tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *tv = -1;
		return ret;
	}
	switch (tag) {
	case ASN1_TAG_UTCTime:
		if (asn1_utc_time_from_der(tv, in, inlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_GeneralizedTime:
		if (asn1_generalized_time_from_der(tv, in, inlen) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		return 0;
	}
	return 1;
}

int x509_validity_add_days(time_t *not_after, time_t not_before, int days)
{
	if (days < X509_VALIDITY_MIN_DAYS
		|| days > X509_VALIDITY_MAX_DAYS) {
		error_print();
		return -1;
	}
	*not_after = not_before + (time_t)days * 24 * 60 * 60;
	return 1;
}

int x509_validity_to_der(time_t not_before, time_t not_after, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_time_to_der(not_before, NULL, &len) != 1
		|| x509_time_to_der(not_after, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_time_to_der(not_before, out, outlen) != 1
		|| x509_time_to_der(not_after, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_validity_from_der(time_t *not_before, time_t *not_after, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *not_before = *not_after = -1;
		return ret;
	}
	if (x509_time_from_der(not_before, &d, &dlen) != 1
		|| x509_time_from_der(not_after, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*not_before >= *not_after) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_validity_check(time_t not_before, time_t not_after, time_t now, int max_secs)
{
	if (!(not_before <= not_after)) {
		error_print();
		return -1;
	}
	if (!(not_after - not_before <= (unsigned int)max_secs)) {
		error_print();
		return -1;
	}
	if (!(not_before <= now && now <= not_after)) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_validity_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	time_t tv;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_time_from_der(&tv, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "notBefore: %s", ctime(&tv));
	if (x509_time_from_der(&tv, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "notAfter: %s", ctime(&tv));
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}


static uint32_t oid_at_name[] = { oid_at,41 };
static uint32_t oid_at_surname[] = { oid_at,4 };
static uint32_t oid_at_given_name[] = { oid_at,42 };
static uint32_t oid_at_initials[] = { oid_at,43 };
static uint32_t oid_at_generation_qualifier[] = { oid_at,44 };
static uint32_t oid_at_common_name[] = { oid_at,3 };
static uint32_t oid_at_locality_name[] = { oid_at,7 };
static uint32_t oid_at_state_or_province_name[] = { oid_at,8 };
static uint32_t oid_at_organization_name[] = { oid_at,10 };
static uint32_t oid_at_organizational_unit_name[] = { oid_at,11 };
static uint32_t oid_at_title[] = { oid_at,12 };
static uint32_t oid_at_dn_qualifier[] = { oid_at,46 };
static uint32_t oid_at_country_name[] = { oid_at,6 };
static uint32_t oid_at_serial_number[] = { oid_at,5 };
static uint32_t oid_at_pseudonym[] = { oid_at,65 };
static uint32_t oid_domain_component[] = { 0,9,2342,19200300,100,1,25 };
static uint32_t oid_email_address[] = { 1,2,840,113549,1,9,1 };

#define OID_AT_CNT (sizeof(oid_at_name)/sizeof(int))

static const ASN1_OID_INFO x509_name_types[] = {
	{ OID_at_name, "name", oid_at_name, OID_AT_CNT },
	{ OID_at_surname, "surname", oid_at_surname, OID_AT_CNT },
	{ OID_at_given_name, "givenName", oid_at_given_name, OID_AT_CNT },
	{ OID_at_initials, "initials", oid_at_initials, OID_AT_CNT },
	{ OID_at_generation_qualifier, "generationQualifier", oid_at_generation_qualifier, OID_AT_CNT },
	{ OID_at_common_name, "commonName", oid_at_common_name, OID_AT_CNT },
	{ OID_at_locality_name, "localityName", oid_at_locality_name, OID_AT_CNT },
	{ OID_at_state_or_province_name, "stateOrProvinceName", oid_at_state_or_province_name, OID_AT_CNT },
	{ OID_at_organization_name, "organizationName", oid_at_organization_name, OID_AT_CNT },
	{ OID_at_organizational_unit_name, "organizationalUnitName", oid_at_organizational_unit_name, OID_AT_CNT },
	{ OID_at_title, "title", oid_at_title, OID_AT_CNT },
	{ OID_at_dn_qualifier, "dnQualifier", oid_at_dn_qualifier, OID_AT_CNT },
	{ OID_at_country_name, "countryName", oid_at_country_name, OID_AT_CNT },
	{ OID_at_serial_number, "serialNumber", oid_at_serial_number, OID_AT_CNT },
	{ OID_at_pseudonym, "pseudonym", oid_at_pseudonym, OID_AT_CNT },
	{ OID_domain_component, "domainComponent", oid_domain_component, sizeof(oid_domain_component)/sizeof(int) },
	{ OID_email_address, "emailAddress", oid_email_address, sizeof(oid_email_address)/sizeof(int) },
};

static const int x509_name_types_count
	= sizeof(x509_name_types)/sizeof(x509_name_types[0]);

const char *x509_name_type_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_name_types, x509_name_types_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_name_type_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_name_types, x509_name_types_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_name_type_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_name_types, x509_name_types_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_name_type_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;

	if ((ret = asn1_oid_info_from_der(&info, x509_name_types, x509_name_types_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}

int x509_directory_name_check(int tag, const uint8_t *d, size_t dlen)
{
	if (dlen == 0) {
		return 0;
	}
	if (!d) {
		error_print();
		return -1;
	}

	switch (tag) {
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_UniversalString:
	case ASN1_TAG_UTF8String:
		if (strnlen((char *)d, dlen) != dlen) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_BMPString:
		if (dlen % 2) {
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

int x509_directory_name_check_ex(int tag, const uint8_t *d, size_t dlen, size_t minlen, size_t maxlen)
{
	int ret;

	if ((ret = x509_directory_name_check(tag, d, dlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (dlen < minlen || dlen > maxlen) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_directory_name_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	if (dlen == 0) {
		return 0;
	}
	if (x509_directory_name_check(tag, d, dlen) != 1) {
		error_print();
		return -1;
	}
	if (asn1_type_to_der(tag, d, dlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_directory_name_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_tag_from_der_readonly(tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	switch (*tag) {
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_UniversalString:
	case ASN1_TAG_UTF8String:
	case ASN1_TAG_BMPString:
		break;
	default:
		return 0;
	}
	if (asn1_any_type_from_der(tag, d, dlen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_directory_name_check(*tag, *d, *dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_directory_name_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen)
{
	return asn1_string_print(fp, fmt, ind, label, tag, d, dlen);
}

int x509_explicit_directory_name_to_der(int index, int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;
	size_t len = 0;

	if ((ret = x509_directory_name_to_der(tag, d, dlen, NULL, &len)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_explicit_header_to_der(index, len, out, outlen) != 1
		|| x509_directory_name_to_der(tag, d, dlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_explicit_directory_name_from_der(int index, int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	if ((ret = asn1_explicit_from_der(index, &p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_directory_name_from_der(tag, d, dlen, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static const struct {
	int oid;
	int is_printable_string_only;
	int minlen;
	int maxlen;
} x509_name_types_info[] = {
	{ OID_at_country_name,             1, 2, 2 },
	{ OID_at_state_or_province_name,   0, 1, X509_ub_state_name },
	{ OID_at_locality_name,            0, 1, X509_ub_locality_name },
	{ OID_at_organization_name,        0, 1, X509_ub_organization_name },
	{ OID_at_organizational_unit_name, 0, 1, X509_ub_organizational_unit_name },
	{ OID_at_common_name,              0, 1, X509_ub_common_name },
	{ OID_at_serial_number,            1, 1, X509_ub_serial_number },
	{ OID_at_dn_qualifier,             1, 1, 64 }, // max length unspecified in RFC 5280
	{ OID_at_title,                    0, 1, X509_ub_title },
	{ OID_at_surname,                  0, 1, X509_ub_name },
	{ OID_at_given_name,               0, 1, X509_ub_name },
	{ OID_at_initials,                 0, 1, X509_ub_name },
	{ OID_at_generation_qualifier,     0, 1, X509_ub_name },
	{ OID_at_pseudonym,                0, 1, X509_ub_pseudonym },
};

static const int x509_name_types_info_count
	= sizeof(x509_name_types_info)/sizeof(x509_name_types_info[0]);

int x509_attr_type_and_value_check(int oid, int tag, const uint8_t *val, size_t vlen)
{
	int i;
	for (i = 0; i < x509_name_types_info_count; i++) {
		if (oid == x509_name_types_info[i].oid) {
			if (x509_name_types_info[i].is_printable_string_only
				&& tag != ASN1_TAG_PrintableString) {
				error_print();
				return -1;
			}
			if (x509_directory_name_check_ex(tag, val, vlen,
				x509_name_types_info[i].minlen, x509_name_types_info[i].maxlen) != 1) {
				error_print();
				return -1;
			}
			return 1;
		}
	}
	error_print();
	return -1;
}

int x509_attr_type_and_value_to_der(int oid, int tag, const uint8_t *val, size_t vlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (vlen == 0) {
		return 0;
	}
	if (x509_attr_type_and_value_check(oid, tag, val, vlen) != 1
		|| x509_name_type_to_der(oid, NULL, &len) != 1
		|| x509_directory_name_to_der(tag, val, vlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_name_type_to_der(oid, out, outlen) != 1
		|| x509_directory_name_to_der(tag, val, vlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_attr_type_and_value_from_der(int *oid, int *tag, const uint8_t **val, size_t *vlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*tag = -1;
			*val = NULL;
			*vlen = 0;
		}
		return ret;
	}
	if (x509_name_type_from_der(oid, &d, &dlen) != 1
		|| x509_directory_name_from_der(tag, val, vlen, &d, &dlen) != 1
		|| x509_attr_type_and_value_check(*oid, *tag, *val, *vlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_attr_type_and_value_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int oid, tag;
	const uint8_t *val;
	size_t vlen;

	if (fmt & ASN1_FMT_FULL) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;

		if (x509_name_type_from_der(&oid, &d, &dlen) != 1) goto err;
		asn1_object_identifier_print(fp, fmt, ind, "type", x509_name_type_name(oid), NULL, 0);
		if (oid == OID_email_address) {
			if (asn1_ia5_string_from_der((const char **)&val, &vlen, &d, &dlen) != 1) goto err;
			format_string(fp, fmt, ind, "value", val, vlen);
		} else {
			if (x509_directory_name_from_der(&tag, &val, &vlen, &d, &dlen) != 1) goto err;
			x509_directory_name_print(fp, fmt, ind, "value", tag, val, vlen);
		}
	} else {
		if (x509_name_type_from_der(&oid, &d, &dlen) != 1) { error_print(); goto err; }
		if (oid == OID_email_address) {
			if (asn1_ia5_string_from_der((const char **)&val, &vlen, &d, &dlen) != 1) goto err;
			format_string(fp, fmt, ind, "emailAddress", val, vlen);
		} else {
			if (x509_directory_name_from_der(&tag, &val, &vlen, &d, &dlen) != 1) goto err;
			x509_directory_name_print(fp, fmt, ind, x509_name_type_name(oid), tag, val, vlen);
		}
	}
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_rdn_check(const uint8_t *d, size_t dlen)
{
	int oid;
	int tag;
	const uint8_t *val;
	size_t vlen;

	if (dlen == 0) {
		return 0;
	}
	while (dlen) {
		if (x509_attr_type_and_value_from_der(&oid, &tag, &val, &vlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (vlen == 0) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_rdn_to_der(int oid, int tag, const uint8_t *val, size_t vlen,
	const uint8_t *more, size_t morelen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (vlen == 0 && morelen == 0) {
		return 0;
	}
	if (x509_rdn_check(more, morelen) < 0) {
		error_print();
		return -1;
	}
	if (x509_attr_type_and_value_to_der(oid, tag, val, vlen, NULL, &len) < 0
		|| asn1_data_to_der(more, morelen, NULL, &len) < 0
		|| asn1_set_header_to_der(len, out, outlen) != 1
		|| x509_attr_type_and_value_to_der(oid, tag, val, vlen, out, outlen) < 0
		|| asn1_data_to_der(more, morelen, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_rdn_from_der(int *oid, int *tag, const uint8_t **val, size_t *vlen,
	const uint8_t **more, size_t *morelen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_set_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*oid = *tag = -1;
			*val = *more = NULL;
			*vlen = *morelen = 0;
		}
		return ret;
	}
	if (x509_attr_type_and_value_from_der(oid, tag, val, vlen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_rdn_check(d, dlen) < 0) {
		error_print();
		return -1;
	}
	*more = dlen ? d : NULL;
	*morelen = dlen;
	return 1;
}

int x509_rdn_get_value_by_type(const uint8_t *d, size_t dlen, int type, int *tag, const uint8_t **val, size_t *vlen)
{
	int oid;

	while (dlen) {
		if (x509_attr_type_and_value_from_der(&oid, tag, val, vlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (oid == type) {
			return 1;
		}
	}

	*tag = -1;
	*val = NULL;
	*vlen = 0;
	return 0;
}

int x509_rdn_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	if (fmt & ASN1_FMT_FULL) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	x509_attr_type_and_value_print(fp, fmt, ind, "AttributeTypeAndValue", p, len);
	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_attr_type_and_value_print(fp, fmt, ind + 4, "AttributeTypeAndValue", p, len);
	}
	return 1;
}

int x509_name_check(const uint8_t *d, size_t dlen)
{
	const uint8_t *rdn;
	size_t rdnlen;

	if (dlen == 0) {
		return 0;
	}
	while (dlen) {
		if (asn1_set_from_der(&rdn, &rdnlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_rdn_check(rdn, rdnlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_name_add_rdn(uint8_t *d, size_t *dlen, size_t maxlen,
	int oid, int tag, const uint8_t *val, size_t vlen,
	const uint8_t *more, size_t morelen)
{
	int ret;
	uint8_t *p;
	size_t len;

	if (!d || !dlen) {
		error_print();
		return -1;
	}
	p = d + (*dlen);
	if (x509_rdn_to_der(oid, tag, val, vlen, more, morelen, NULL, dlen) < 0
		|| asn1_length_le(*dlen, maxlen) != 1
		|| (ret = x509_rdn_to_der(oid, tag, val, vlen, more, morelen, &p, &len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int x509_name_add_country_name(uint8_t *d, size_t *dlen, size_t maxlen, const char val[2])
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen,
		OID_at_country_name, ASN1_TAG_PrintableString, (uint8_t *)val, val ? 2 : 0, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_state_or_province_name(uint8_t *d, size_t *dlen, size_t maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_state_or_province_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_locality_name(uint8_t *d, size_t *dlen, size_t maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_locality_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_organization_name(uint8_t *d, size_t *dlen, size_t maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_organization_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_organizational_unit_name(uint8_t *d, size_t *dlen, size_t maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_organizational_unit_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_common_name(uint8_t *d, size_t *dlen, size_t maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_common_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_domain_component(uint8_t *d, size_t *dlen, size_t maxlen,
	const char *val, size_t vlen)
{
	int ret;
	return x509_name_add_rdn(d, dlen, maxlen, OID_domain_component, ASN1_TAG_IA5String, (uint8_t *)val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

static size_t optstrlen(const char *s) { return s ? strlen(s) : 0; }

static int x509_name_tag(const char *str)
{
	if (str) {
		if (asn1_string_is_printable_string(str, strlen(str)) == 1)
			return ASN1_TAG_PrintableString;
		else	return ASN1_TAG_UTF8String;
	}
	return 0;
}

int x509_name_set(uint8_t *d, size_t *dlen, size_t maxlen,
	const char country[2], const char *state, const char *locality,
	const char *org, const char *org_unit, const char *common_name)
{
	if (country && strlen(country) != 2) {
		error_print();
		return -1;
	}
	*dlen = 0;
	if (x509_name_add_country_name(d, dlen, maxlen, country) < 0
		|| x509_name_add_state_or_province_name(d, dlen, maxlen, x509_name_tag(state), (uint8_t *)state, optstrlen(state)) < 0
		|| x509_name_add_locality_name(d, dlen, maxlen, x509_name_tag(locality), (uint8_t *)locality, optstrlen(locality)) < 0
		|| x509_name_add_organization_name(d, dlen, maxlen, x509_name_tag(org), (uint8_t *)org, optstrlen(org)) < 0
		|| x509_name_add_organizational_unit_name(d, dlen, maxlen, x509_name_tag(org_unit), (uint8_t *)org_unit, optstrlen(org_unit)) < 0
		|| x509_name_add_common_name(d, dlen, maxlen, x509_name_tag(common_name), (uint8_t *)common_name, optstrlen(common_name)) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_name_get_value_by_type(const uint8_t *d, size_t dlen, int oid, int *tag, const uint8_t **val, size_t *vlen)
{
	int ret;
	const uint8_t *rdn;
	size_t rdnlen;

	while (dlen) {
		if (asn1_set_from_der(&rdn, &rdnlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_rdn_get_value_by_type(rdn, rdnlen, oid, tag, val, vlen)) < 0) {
			error_print();
			return -1;
		}
		if (ret) {
			return 1;
		}
	}
	return 0;
}

int x509_name_get_common_name(const uint8_t *d, size_t dlen, int *tag, const uint8_t **val, size_t *vlen)
{
	int ret;
	ret = x509_name_get_value_by_type(d, dlen, OID_at_common_name, tag, val, vlen);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_equ(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	if (alen != blen || memcmp(a, b, blen) != 0) {
		return 0;
	}
	return 1;
}

int x509_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_rdn_print(fp, fmt, ind, "RelativeDistinguishedName", p, len);
	}
	return 1;
}

int x509_names_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
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
		x509_name_print(fp, fmt, ind, "Name", p, len);
	}
	return 1;
}

int x509_public_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p = d;
	size_t len = dlen;
	int alg;
	int params;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_public_key_algor_from_der(&alg, &params, &p, &len) != 1) goto err;
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_public_key_algor_print(fp, fmt, ind, "algorithm", p, len);
	format_print(fp, fmt, ind, "subjectPublicKey\n");
	ind += 4;
	if (asn1_bit_octets_from_der(&p, &len, &d, &dlen) != 1) goto err;
	switch (alg) {
	case OID_ec_public_key:
		format_bytes(fp, fmt, ind, "ECPoint", p, len);
		break;
	case OID_rsa_encryption:
		rsa_public_key_print(fp, fmt, ind, "RSAPublicKey", p, len);
		break;
	default:
		format_bytes(fp, fmt, ind, "raw_data", p, len);
	}
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_explicit_exts_to_der(int index, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (dlen == 0) {
		return 0;
	}
	if (asn1_sequence_to_der(d, dlen, NULL, &len) != 1
		|| asn1_explicit_header_to_der(index, len, out, outlen) != 1
		|| asn1_sequence_to_der(d, dlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_explicit_exts_from_der(int index, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	if ((ret = asn1_explicit_from_der(index, &p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*d = NULL;
			*dlen = 0;
		}
		return ret;
	}
	if (asn1_sequence_from_der(d, dlen, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_tbs_cert_to_der(
	int version,
	const uint8_t *serial, size_t serial_len,
	int signature_algor,
	const uint8_t *issuer, size_t issuer_len,
	time_t not_before, time_t not_after,
	const uint8_t *subject, size_t subject_len,
	const SM2_KEY *subject_public_key,
	const uint8_t *issuer_unique_id, size_t issuer_unique_id_len,
	const uint8_t *subject_unique_id, size_t subject_unique_id_len,
	const uint8_t *exts, size_t exts_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_explicit_version_to_der(0, version, NULL, &len) < 0
		|| asn1_integer_to_der(serial, serial_len, NULL, &len) != 1
		|| x509_signature_algor_to_der(signature_algor, NULL, &len) != 1
		|| asn1_sequence_to_der(issuer, issuer_len, NULL, &len) != 1
		|| x509_validity_to_der(not_before, not_after, NULL, &len) != 1
		|| asn1_sequence_to_der(subject, subject_len, NULL, &len) != 1
		|| x509_public_key_info_to_der(subject_public_key, NULL, &len) != 1
		|| asn1_implicit_bit_octets_to_der(1, issuer_unique_id, issuer_unique_id_len, NULL, &len) < 0
		|| asn1_implicit_bit_octets_to_der(2, subject_unique_id, subject_unique_id_len, NULL, &len) < 0
		|| x509_explicit_exts_to_der(3, exts, exts_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_explicit_version_to_der(0, version, out, outlen) < 0
		|| asn1_integer_to_der(serial, serial_len, out, outlen) != 1
		|| x509_signature_algor_to_der(signature_algor, out, outlen) != 1
		|| asn1_sequence_to_der(issuer, issuer_len, out, outlen) != 1
		|| x509_validity_to_der(not_before, not_after, out, outlen) != 1
		|| asn1_sequence_to_der(subject, subject_len, out, outlen) != 1
		|| x509_public_key_info_to_der(subject_public_key, out, outlen) != 1
		|| asn1_implicit_bit_octets_to_der(1, issuer_unique_id, issuer_unique_id_len, out, outlen) < 0
		|| asn1_implicit_bit_octets_to_der(2, subject_unique_id, subject_unique_id_len, out, outlen) < 0
		|| x509_explicit_exts_to_der(3, exts, exts_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_tbs_cert_from_der(
	int *version,
	const uint8_t **serial, size_t *serial_len,
	int *signature_algor,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *not_before, time_t *not_after,
	const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key,
	const uint8_t **issuer_unique_id, size_t *issuer_unique_id_len,
	const uint8_t **subject_unique_id, size_t *subject_unique_id_len,
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
	if (x509_explicit_version_from_der(0, version, &d, &dlen) < 0
		|| asn1_integer_from_der(serial, serial_len, &d, &dlen) != 1
		|| x509_signature_algor_from_der(signature_algor, &d, &dlen) != 1
		|| asn1_sequence_from_der(issuer, issuer_len, &d, &dlen) != 1
		|| x509_validity_from_der(not_before, not_after, &d, &dlen) != 1
		|| asn1_sequence_from_der(subject, subject_len, &d, &dlen) != 1
		|| x509_public_key_info_from_der(subject_public_key, &d, &dlen) != 1
		|| asn1_implicit_bit_octets_from_der(1, issuer_unique_id, issuer_unique_id_len, &d, &dlen) < 0
		|| asn1_implicit_bit_octets_from_der(2, subject_unique_id, subject_unique_id_len, &d, &dlen) < 0
		|| x509_explicit_exts_from_der(3, exts, exts_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_tbs_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if ((ret = x509_explicit_version_from_der(0, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "version: %s (%d)\n", x509_version_name(val), val);
	if (asn1_integer_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "serialNumber", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_signature_algor_print(fp, fmt, ind, "signature", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_name_print(fp, fmt, ind, "issuer", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_validity_print(fp, fmt, ind, "validity", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_name_print(fp, fmt, ind, "subject", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_public_key_info_print(fp, fmt, ind, "subjectPulbicKeyInfo", p, len);
	if ((ret = asn1_implicit_bit_octets_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "issuerUniqueID", p, len);
	if ((ret = asn1_implicit_bit_octets_from_der(2, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "subjectUniqueID", p, len);
	if ((ret = x509_explicit_exts_from_der(3, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_exts_print(fp, fmt, ind, "extensions", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_cert_sign_to_der(
	int version,
	const uint8_t *serial, size_t serial_len,
	int signature_algor,
	const uint8_t *issuer, size_t issuer_len,
	time_t not_before, time_t not_after,
	const uint8_t *subject, size_t subject_len,
	const SM2_KEY *subject_public_key,
	const uint8_t *issuer_unique_id, size_t issuer_unique_id_len,
	const uint8_t *subject_unique_id, size_t subject_unique_id_len,
	const uint8_t *exts, size_t exts_len,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t *tbs;
	int sig_alg = OID_sm2sign_with_sm3;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen = SM2_signature_typical_size;

	if (x509_tbs_cert_to_der(
		version,
		serial, serial_len,
		signature_algor,
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		subject_public_key,
		issuer_unique_id, issuer_unique_id_len,
		subject_unique_id, subject_unique_id_len,
		exts, exts_len,
		NULL, &len) != 1
		|| x509_signature_algor_to_der(sig_alg, NULL, &len) != 1
		|| asn1_bit_octets_to_der(sig, siglen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		tbs = *out;
	}

	if (x509_tbs_cert_to_der(
		version,
		serial, serial_len,
		signature_algor,
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		subject_public_key,
		issuer_unique_id, issuer_unique_id_len,
		subject_unique_id, subject_unique_id_len,
		exts, exts_len,
		out, outlen) != 1) {
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

int x509_signed_from_der(const uint8_t **tbs, size_t *tbslen,
	int *sig_alg, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*tbs = *sig = NULL;
			*tbslen = *siglen = 0;
			*sig_alg = -1;
		}
		return ret;
	}
	if (asn1_any_from_der(tbs, tbslen, &d, &dlen) != 1
		|| x509_signature_algor_from_der(sig_alg, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(sig, siglen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_signed_verify(const uint8_t *a, size_t alen,
	const SM2_KEY *pub_key, const char *signer_id, size_t signer_id_len)
{
	const uint8_t *tbs;
	size_t tbslen;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	SM2_SIGN_CTX verify_ctx;

	if (x509_signed_from_der(&tbs, &tbslen, &sig_alg, &sig, &siglen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	if (sig_alg != OID_sm2sign_with_sm3) {
		error_print();
		return -1;
	}
	if (sm2_verify_init(&verify_ctx, pub_key, signer_id, signer_id_len) != 1
		|| sm2_verify_update(&verify_ctx, tbs, tbslen) != 1
		|| sm2_verify_finish(&verify_ctx, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_signed_verify_by_ca_cert(const uint8_t *a, size_t alen,
	const uint8_t *cacert, size_t cacertlen,
	const char *signer_id, size_t signer_id_len)
{
	int ret;
	SM2_KEY public_key;

	if (x509_cert_get_subject_public_key(cacert, cacertlen, &public_key) != 1
		|| (ret = x509_signed_verify(a, alen, &public_key, signer_id, signer_id_len)) < 0) {
		error_print();
		return -1;
	}
	if (!ret) error_print();
	return ret;
}

int x509_cert_verify_by_ca_cert(const uint8_t *a, size_t alen,
	const uint8_t *cacert, size_t cacertlen,
	const char *signer_id, size_t signer_id_len)
{
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;

	if (x509_cert_get_issuer(a, alen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject(cacert, cacertlen, &subject, &subject_len) != 1
		|| x509_name_equ(issuer, issuer_len, subject, subject_len) != 1) {
		error_print();
		return -1;
	}
	if (x509_signed_verify_by_ca_cert(a, alen, cacert, cacertlen, signer_id, signer_id_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	int ret;
	if (x509_cert_get_subject(a, alen, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_any_to_der(a, alen, out, outlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_cert_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_any_from_der(a, alen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_cert_get_subject(*a, *alen, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_to_pem(const uint8_t *a, size_t alen, FILE *fp)
{
	if (x509_cert_get_subject(a, alen, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "CERTIFICATE", a, alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_from_pem(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp)
{
	int ret;
	if ((ret = pem_read(fp, "CERTIFICATE", a, alen, maxlen)) != 1) {
		if (ret < 0) error_print();
		else *alen = 0;
		return ret;
	}
	if (x509_cert_get_subject(a, *alen, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_from_pem_by_subject(uint8_t *a, size_t *alen, size_t maxlen, const uint8_t *name, size_t namelen, FILE *fp)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	for (;;) {
		if ((ret = x509_cert_from_pem(a, alen, maxlen, fp)) != 1) {
			if (ret < 0) error_print();
			else *alen = 0;
			return ret;
		}
		if (x509_cert_get_subject(a, *alen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_name_equ(d, dlen, name, namelen) == 1) {
			return 1;
		}
	}
	*alen = 0;
	return 0;
}

static int x509_certificate_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_tbs_cert_print(fp, fmt, ind, "tbsCertificate", p, len);
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

int x509_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *d;
	size_t dlen;

	if (asn1_sequence_from_der(&d, &dlen, &a, &alen) != 1) {
		error_print();
		return -1;
	}
	x509_certificate_print(fp, fmt, ind, label, d, dlen);
	if (asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_get_details(const uint8_t *a, size_t alen,
	int *version,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *inner_signature_algor,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *not_before, time_t *not_after,
	const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key,
	const uint8_t **issuer_unique_id, size_t *issuer_unique_id_len,
	const uint8_t **subject_unique_id, size_t *subject_unique_id_len,
	const uint8_t **extensions, size_t *extensions_len,
	int *signature_algor,
	const uint8_t **signature, size_t *signature_len)
{
	const uint8_t *tbs_a;
	size_t tbs_alen;
	int sig_alg;
	const uint8_t *sig;
	size_t sig_len;

	struct {
		int version;
		const uint8_t *serial; size_t serial_len;
		int sig_alg;
		const uint8_t *issuer; size_t issuer_len;
		time_t not_before; time_t not_after;
		const uint8_t *subject; size_t subject_len;
		SM2_KEY subject_public_key;
		const uint8_t *issuer_unique_id; size_t issuer_unique_id_len;
		const uint8_t *subject_unique_id; size_t subject_unique_id_len;
		const uint8_t *exts; size_t exts_len;
	} tbs;

	if (x509_signed_from_der(&tbs_a, &tbs_alen, &sig_alg, &sig, &sig_len, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	if (x509_tbs_cert_from_der(
		&tbs.version,
		&tbs.serial, &tbs.serial_len,
		&tbs.sig_alg,
		&tbs.issuer, &tbs.issuer_len,
		&tbs.not_before, &tbs.not_after,
		&tbs.subject, &tbs.subject_len,
		&tbs.subject_public_key,
		&tbs.issuer_unique_id, &tbs.issuer_unique_id_len,
		&tbs.subject_unique_id, &tbs.subject_unique_id_len,
		&tbs.exts, &tbs.exts_len, &tbs_a, &tbs_alen) != 1) {
		error_print();
		return -1;
	}

	if (version) *version = tbs.version;
	if (serial_number) *serial_number = tbs.serial;
	if (serial_number_len) *serial_number_len = tbs.serial_len;
	if (inner_signature_algor) *inner_signature_algor = tbs.sig_alg;
	if (issuer) *issuer = tbs.issuer;
	if (issuer_len) *issuer_len = tbs.issuer_len;
	if (not_before) *not_before = tbs.not_before;
	if (not_after) *not_after = tbs.not_after;
	if (subject) *subject = tbs.subject;
	if (subject_len) *subject_len = tbs.subject_len;
	if (subject_public_key) *subject_public_key = tbs.subject_public_key;
	if (issuer_unique_id) *issuer_unique_id = tbs.issuer_unique_id;
	if (issuer_unique_id_len) *issuer_unique_id_len = tbs.issuer_unique_id_len;
	if (subject_unique_id) *subject_unique_id = tbs.subject_unique_id;
	if (subject_unique_id_len) *subject_unique_id_len = tbs.subject_unique_id_len;
	if (extensions) *extensions = tbs.exts;
	if (extensions_len) *extensions_len = tbs.exts_len;
	if (signature_algor) *signature_algor = sig_alg;
	if (signature) *signature = sig;
	if (signature_len) *signature_len = sig_len;
	return 1;
}

int x509_cert_get_issuer_and_serial_number(const uint8_t *a, size_t alen,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len)
{
	return x509_cert_get_details(a, alen,
		NULL, // version
		serial_number, serial_number_len, // serial
		NULL, // signature_algor
		issuer, issuer_len, // issuer
		NULL, NULL, // validity
		NULL, NULL, // subject
		NULL, // subject_public_key
		NULL, NULL, // issuer_unique_id
		NULL, NULL, // subject_unique_id
		NULL, NULL, // extensions
		NULL, // signature_algor
		NULL, NULL); // signature
}

int x509_cert_get_subject_public_key(const uint8_t *a, size_t alen, SM2_KEY *public_key)
{
	return x509_cert_get_details(a, alen,
		NULL, // version
		NULL, NULL, // serial
		NULL, // signature_algor
		NULL, NULL, // issuer
		NULL, NULL, // validity
		NULL, NULL, // subject
		public_key, // subject_public_key
		NULL, NULL, // issuer_unique_id
		NULL, NULL, // subject_unique_id
		NULL, NULL, // extensions
		NULL, // signature_algor
		NULL, NULL); // signature
}

int x509_cert_get_subject(const uint8_t *a, size_t alen, const uint8_t **d, size_t *dlen)
{
	return x509_cert_get_details(a, alen,
		NULL, // version
		NULL, NULL, // serial
		NULL, // signature_algor
		NULL, NULL, // issuer
		NULL, NULL, // validity
		d, dlen, // subject
		NULL, // subject_public_key
		NULL, NULL, // issuer_unique_id
		NULL, NULL, // subject_unique_id
		NULL, NULL, // extensions
		NULL, // signature_algor
		NULL, NULL); // signature
}

int x509_cert_get_issuer(const uint8_t *a, size_t alen, const uint8_t **d, size_t *dlen)
{
	return x509_cert_get_details(a, alen,
		NULL, // version
		NULL, NULL, // serial
		NULL, // signature_algor
		d, dlen, // issuer
		NULL, NULL, // validity
		NULL, NULL, // subject
		NULL, // subject_public_key
		NULL, NULL, // issuer_unique_id
		NULL, NULL, // subject_unique_id
		NULL, NULL, // extensions
		NULL, // signature_algor
		NULL, NULL); // signature
}

int x509_cert_get_exts(const uint8_t *a, size_t alen, const uint8_t **d, size_t *dlen)
{
	if (x509_cert_get_details(a, alen,
		NULL, // version
		NULL, NULL, // serial
		NULL, // signature_algor
		NULL, NULL, // issuer
		NULL, NULL, // validity
		NULL, NULL, // subject
		NULL, // subject_public_key
		NULL, NULL, // issuer_unique_id
		NULL, NULL, // subject_unique_id
		d, dlen, // extensions
		NULL, // signature_algor
		NULL, NULL // signature
		) != 1) {
		error_print();
		return -1;
	}
	if (!d || !dlen) {
		return 0;
	}
	return 1;
}

int x509_certs_to_pem(const uint8_t *d, size_t dlen, FILE *fp)
{
	const uint8_t *a;
	size_t alen;

	while (dlen) {
		if (asn1_any_from_der(&a, &alen, &d, &dlen) != 1
			|| x509_cert_to_pem(a, alen, fp) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_certs_from_pem(uint8_t *d, size_t *dlen, size_t maxlen, FILE *fp)
{
	int ret;
	size_t len;

	*dlen = 0;

	for (;;) {
		if ((ret = x509_cert_from_pem(d, &len, maxlen, fp)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			break;
		}

		d += len;
		*dlen += len;
		maxlen -= len;
	}

	if (*dlen == 0) {
		return 0;
	}
	return 1;
}

int x509_certs_get_count(const uint8_t *d, size_t dlen, size_t *cnt)
{
	int ret;
	ret = asn1_types_get_count(d, dlen, ASN1_TAG_SEQUENCE, cnt);
	if (ret < 0) error_print();
	return ret;
}

int x509_certs_get_cert_by_index(const uint8_t *d, size_t dlen, int index, const uint8_t **cert, size_t *certlen)
{
	int i = 0;

	if (index < 0) {
		error_print();
		return -1;
	}
	while (dlen) {
		if (x509_cert_from_der(cert, certlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (i++ == index) {
			return 1;
		}
	}
	*cert = NULL;
	*certlen = 0;
	return 0;
}

int x509_certs_get_last(const uint8_t *d, size_t dlen, const uint8_t **cert, size_t *certlen)
{
	if (dlen == 0) {
		return 0;
	}
	while (dlen) {
		if (x509_cert_from_der(cert, certlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_certs_get_cert_by_subject(const uint8_t *d, size_t dlen,
	const uint8_t *subject, size_t subject_len, const uint8_t **cert, size_t *certlen)
{
	const uint8_t *subj;
	size_t subj_len;

	while (dlen) {
		if (x509_cert_from_der(cert, certlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_get_subject(*cert, *certlen, &subj, &subj_len) != 1) {
			error_print();
			return -1;
		}
		if (x509_name_equ(subj, subj_len, subject, subject_len) == 1) {
			return 1;
		}
	}
	*cert = NULL;
	*certlen = 0;
	return 0;
}

int x509_certs_get_cert_by_issuer_and_serial_number(const uint8_t *d, size_t dlen,
	const uint8_t *issuer, size_t issuer_len, const uint8_t *serial, size_t serial_len,
	const uint8_t **cert, size_t *cert_len)
{
	const uint8_t *cur_issuer;
	size_t cur_issuer_len;
	const uint8_t *cur_serial;
	size_t cur_serial_len;

	while (dlen) {
		if (x509_cert_from_der(cert, cert_len, &d, &dlen) != 1
			|| x509_cert_get_issuer_and_serial_number(*cert, *cert_len,
				&cur_issuer, &cur_issuer_len, &cur_serial, &cur_serial_len) != 1) {
			error_print();
			return -1;
		}
		if (x509_name_equ(cur_issuer, cur_issuer_len, issuer, issuer_len) == 1
			&& cur_serial_len == serial_len && memcmp(cur_serial, serial, serial_len) == 0) {
			return 1;
		}
	}
	*cert = NULL;
	*cert_len = 0;
	return 0;
}

int x509_cert_check(const uint8_t *cert, size_t certlen, int cert_type,
	int *path_len_constraint)
{
	int version;
	const uint8_t *serial;
	size_t serial_len;
	int tbs_sig_algor;
	const uint8_t *issuer;
	size_t issuer_len;
	time_t not_before;
	time_t not_after;
	time_t now;
	const uint8_t *subject;
	size_t subject_len;
	const uint8_t *exts;
	size_t extslen;
	int sig_algor;


	if (x509_cert_get_details(cert, certlen,
		&version, // version
		&serial, &serial_len, // serial
		&tbs_sig_algor, // signature_algor
		&issuer, &issuer_len, // issuer
		&not_before, &not_after, // validity
		&subject, &subject_len, // subject
		NULL, // subject_public_key
		NULL, NULL, // issuer_unique_id
		NULL, NULL, // subject_unique_id
		&exts, &extslen, // extensions
		&sig_algor, // signature_algor
		NULL, NULL // signature
		) != 1) {
		error_print();
		return -1;
	}

	if (version != X509_version_v3) {
		error_print();
		return -1;
	}
	if (!serial || !serial_len) {
		error_print();
		return -1;
	}
	if (serial_len < 4) {
		error_print(); // not enough randomness
	}

	time(&now);
	if (x509_validity_check(not_before, not_after, now, X509_VALIDITY_MAX_SECONDS) != 1) {
		error_print();
		return -1;
	}

	// check issuer and subject not empty
	if (x509_name_check(issuer, issuer_len) != 1) {
		error_print();
		return -1;
	}
	if (x509_name_check(subject, subject_len) != 1) {
		error_print();
		return -1;
	}

	if (x509_exts_check(exts, extslen, cert_type, path_len_constraint) != 1) {
		error_print();
		return -1;
	}
	if (tbs_sig_algor != sig_algor) {
		error_print();
		return -1;
	}

	return 1;
}

int x509_certs_verify(const uint8_t *certs, size_t certslen, int certs_type,
	const uint8_t *rootcerts, size_t rootcertslen, int depth, int *verify_result)
{
	int entity_cert_type;
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *cacert;
	size_t cacertlen;
	const uint8_t *name;
	size_t namelen;

	int path_len = 0;
	int path_len_constraint;

	switch (certs_type) {
	case X509_cert_chain_server:
		entity_cert_type = X509_cert_server_auth;
		break;
	case X509_cert_chain_client:
		entity_cert_type = X509_cert_client_auth;
		break;
	default:
		error_print();
		return -1;
	}

	// entity cert
	if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_check(cert, certlen, entity_cert_type, &path_len_constraint) != 1) {
		error_print();
		x509_cert_print(stderr, 0, 10, "Invalid Entity Certificate", cert, certlen);
		return -1;
	}

	while (certslen) {

		if (x509_cert_from_der(&cacert, &cacertlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_check(cacert, cacertlen, X509_cert_ca, &path_len_constraint) != 1) {
			error_print();
			x509_cert_print(stderr, 0, 10, "Invalid CA Certificate", cacert, cacertlen);
			return -1;
		}

		if (path_len == 0) {
			if (path_len_constraint != 0) {
				error_print();
				return -1;
			}
		}
		if ((path_len_constraint >= 0 && path_len > path_len_constraint)
			|| path_len > depth) {
			error_print();
			return -1;
		}

		if (x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen,
			SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
			error_print();
			return -1;
		}

		cert = cacert;
		certlen = cacertlen;
		path_len++;
	}

	if (x509_cert_get_issuer(cert, certlen, &name, &namelen) != 1) {
		error_print();
		return -1;
	}
	if (x509_certs_get_cert_by_subject(rootcerts, rootcertslen, name, namelen,
		&cacert, &cacertlen) != 1) {
		error_print();
		return -1;
	}

	if (x509_cert_check(cacert, cacertlen, X509_cert_ca, &path_len_constraint) != 1) {
		error_print();
		return -1;
	}
	if ((path_len_constraint >= 0 && path_len > path_len_constraint)
		|| path_len > depth) {
		error_print();
		return -1;
	}
	if (x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen,
		SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int x509_certs_verify_tlcp(const uint8_t *certs, size_t certslen, int certs_type,
	const uint8_t *rootcerts, size_t rootcertslen, int depth, int *verify_result)
{
	int sign_cert_type;
	int kenc_cert_type;
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *kenc_cert;
	size_t kenc_certlen;
	const uint8_t *cacert;
	size_t cacertlen;
	const uint8_t *name;
	size_t namelen;

	int path_len = 0;
	int path_len_constraint;

	switch (certs_type) {
	case X509_cert_chain_server:
		sign_cert_type = X509_cert_server_auth;
		kenc_cert_type = X509_cert_server_key_encipher;
		break;
	case X509_cert_chain_client:
		sign_cert_type = X509_cert_server_auth;
		kenc_cert_type = X509_cert_server_key_encipher;
		break;
	default:
		error_print();
		return -1;
	}

	if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_check(cert, certlen, sign_cert_type, &path_len_constraint) != 1) {
		error_print();
		return -1;
	}

	// entity key encipherment cert
	if (x509_cert_from_der(&kenc_cert, &kenc_certlen, &certs, &certslen) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_check(kenc_cert, kenc_certlen, kenc_cert_type, &path_len_constraint) != 1) {
		error_print();
		return -1;
	}

	while (certslen) {

		if (x509_cert_from_der(&cacert, &cacertlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_check(cacert, cacertlen, X509_cert_ca, &path_len_constraint) != 1) {
			error_print();
			return -1;
		}

		if (path_len == 0) {
			if (path_len_constraint != 0) {
				error_print();
				return -1;
			}

			// verify entity key encipherment cert
			if (x509_cert_verify_by_ca_cert(kenc_cert, kenc_certlen, cacert, cacertlen,
				SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
				error_print();
				return -1;
			}
		}
		if ((path_len_constraint >= 0 && path_len > path_len_constraint)
			|| path_len > depth) {
			error_print();
			return -1;
		}

		if (x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen,
			SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
			error_print();
			return -1;
		}

		cert = cacert;
		certlen = cacertlen;
		path_len++;
	}


	if (x509_cert_get_issuer(cert, certlen, &name, &namelen) != 1) {
		error_print();
		return -1;
	}
	if (x509_certs_get_cert_by_subject(rootcerts, rootcertslen, name, namelen, &cacert, &cacertlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_check(cacert, cacertlen, X509_cert_ca, &path_len_constraint) != 1) {
		error_print();
		return -1;
	}
	if ((path_len_constraint >= 0 && path_len > path_len_constraint)
		|| path_len > depth) {
		error_print();
		return -1;
	}

	// when no mid CA certs
	if (path_len == 0) {
		if (x509_cert_verify_by_ca_cert(kenc_cert, kenc_certlen, cacert, cacertlen,
			SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
			error_print();
			return -1;
		}
	}

	if (x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen,
		SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certs_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
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
		x509_certificate_print(fp, fmt, ind, "Certficate", p, len);
	}
	return 1;
}
