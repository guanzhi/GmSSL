/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/pem.h>
#include <gmssl/asn1.h>
#include <gmssl/rsa.h>
#include <gmssl/x509_oid.h>
#include <gmssl/x509_str.h>
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

	if (version < 0) {
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

/*
 from RFC 5280 section 4.1.2.5

   CAs conforming to this profile MUST always encode certificate
   validity dates through the year 2049 as UTCTime; certificate validity
   dates in 2050 or later MUST be encoded as GeneralizedTime.
   Conforming applications MUST be able to process validity dates that
   are encoded in either UTCTime or GeneralizedTime.

   To indicate that a certificate has no well-defined expiration date,
   the notAfter SHOULD be assigned the GeneralizedTime value of
   99991231235959Z.
*/
int x509_time_to_der(time_t tv, uint8_t **out, size_t *outlen)
{
	int ret;
	struct tm tm_val;

	gmtime_r(&tv, &tm_val);
	if (tm_val.tm_year < 2050 - 1900) {
		if ((ret = asn1_utc_time_to_der(tv, out, outlen)) != 1) {
			if (ret < 0) error_print();
		}
	} else {
		if ((ret = asn1_generalized_time_to_der(tv, out, outlen)) !=1) {
			if (ret < 0) error_print();
		}
	}
	return ret;
}

int x509_time_from_der(time_t *tv, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_utc_time_from_der(tv, in, inlen)) < 0) {
		error_print();
		return -1;
	} else if (ret) {
		return 1;
	}

	if ((ret = asn1_generalized_time_from_der(tv, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_validity_add_days(time_t *not_after, time_t not_before, int days)
{
	struct tm tm_val;
	if (days < X509_VALIDITY_MIN_DAYS
		|| days > X509_VALIDITY_MAX_DAYS) {
		error_print();
		return -1;
	}
	gmtime_r(&not_before, &tm_val);
	tm_val.tm_mday += days;
	*not_after = mktime(&tm_val);
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


static const struct {
	int oid;
	int is_printable_string_only;
	int minlen;
	int maxlen;
} x509_name_types[] = {
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

static const int x509_name_types_count
	= sizeof(x509_name_types)/sizeof(x509_name_types[0]);

int x509_attr_type_and_value_check(int oid, int tag, const uint8_t *val, size_t vlen)
{
	int i;
	for (i = 0; i < x509_name_types_count; i++) {
		if (oid == x509_name_types[i].oid) {
			if (x509_name_types[i].is_printable_string_only
				&& tag != ASN1_TAG_PrintableString) {
				error_print();
				return -1;
			}
			if (x509_directory_name_check_ex(tag, val, vlen,
				x509_name_types[i].minlen, x509_name_types[i].maxlen) != 1) {
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
	}
	if (x509_name_type_from_der(&oid, &d, &dlen) != 1) goto err;
	if (fmt & ASN1_FMT_FULL)
		asn1_object_identifier_print(fp, fmt, ind, "type", x509_name_type_name(oid), NULL, 0);

	if (x509_directory_name_from_der(&tag, &val, &vlen, &d, &dlen) != 1) goto err;
	if (fmt & ASN1_FMT_FULL)
		x509_directory_name_print(fp, fmt, ind, "value", tag, val, vlen);
	else	x509_directory_name_print(fp, fmt, ind, x509_name_type_name(oid), tag, val, vlen);

	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_rdn_to_der(int oid, int tag, const uint8_t *val, size_t vlen,
	const uint8_t *more, size_t morelen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_attr_type_and_value_to_der(oid, tag, val, vlen, NULL, &len) != 1
		|| asn1_data_to_der(more, morelen, NULL, &len) < 0
		|| asn1_set_header_to_der(len, out, outlen) != 1
		|| x509_attr_type_and_value_to_der(oid, tag, val, vlen, out, outlen) != 1
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
		return ret;
	}
	if (x509_attr_type_and_value_from_der(oid, tag, val, vlen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	if (dlen) {
		*more = d;
		*morelen = dlen;
		// TODO: check more,morelen
	} else {
		*more = NULL;
		*morelen = 0;
	}
	return 1;
}

int x509_rdn_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	if (fmt & ASN1_FMT_FULL) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_attr_type_and_value_print(fp, fmt, ind, "AttributeTypeAndValue", p, len);
	}
	return 1;
}

int x509_name_add_rdn(uint8_t *d, size_t *dlen, size_t maxlen,
	int oid, int tag, const uint8_t *val, size_t vlen,
	const uint8_t *more, size_t morelen)
{
	size_t len = 0;
	uint8_t *p = d + *dlen;
	if (!val && !more) {
		return 0;
	}
	if (x509_rdn_to_der(oid, tag, val, vlen, NULL, 0, NULL, &len) != 1
		|| asn1_length_le(*dlen + len, maxlen) != 1
		|| x509_rdn_to_der(oid, tag, val, vlen, NULL, 0, &p, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_name_add_country_name(uint8_t *d, size_t *dlen, int maxlen, const char val[2])
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen,
		OID_at_country_name, ASN1_TAG_PrintableString, (uint8_t *)val, 2, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_state_or_province_name(uint8_t *d, size_t *dlen, int maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_state_or_province_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_locality_name(uint8_t *d, size_t *dlen, int maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_locality_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_organization_name(uint8_t *d, size_t *dlen, int maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_organization_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_organizational_unit_name(uint8_t *d, size_t *dlen, int maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_organizational_unit_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_common_name(uint8_t *d, size_t *dlen, int maxlen,
	int tag, const uint8_t *val, size_t vlen)
{
	int ret;
	ret = x509_name_add_rdn(d, dlen, maxlen, OID_at_common_name, tag, val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

int x509_name_add_domain_component(uint8_t *d, size_t *dlen, int maxlen,
	const char *val, size_t vlen)
{
	int ret;
	return x509_name_add_rdn(d, dlen, maxlen, OID_domain_component, ASN1_TAG_IA5String, (uint8_t *)val, vlen, NULL, 0);
	if (ret < 0) error_print();
	return ret;
}

static size_t _strlen(const char *s) { return s ? strlen(s) : 0; }

int x509_name_set(uint8_t *d, size_t *dlen, size_t maxlen,
	const char *country, const char *state, const char *locality,
	const char *org, const char *org_unit, const char *common_name)
{
	int tag = ASN1_TAG_PrintableString;
	if (country && strlen(country) != 2) {
		error_print();
		return -1;
	}
	*dlen = 0;
	if (x509_name_add_country_name(d, dlen, maxlen, country) < 0
		|| x509_name_add_state_or_province_name(d, dlen, maxlen, tag, (uint8_t *)state, _strlen(state)) < 0
		|| x509_name_add_locality_name(d, dlen, maxlen, tag, (uint8_t *)locality, _strlen(locality)) < 0
		|| x509_name_add_organization_name(d, dlen, maxlen, tag, (uint8_t *)org, _strlen(org)) < 0
		|| x509_name_add_organizational_unit_name(d, dlen, maxlen, tag, (uint8_t *)org_unit, _strlen(org_unit)) < 0
		|| x509_name_add_common_name(d, dlen, maxlen, tag, (uint8_t *)common_name, _strlen(common_name)) != 1) {
		error_print();
		return -1;
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

int x509_name_get_printable(const uint8_t *d, size_t dlen, char *str, size_t maxlen)
{
	error_print();
	return -1;
}

int x509_name_get_value_by_type(const uint8_t *d, size_t dlen, int oid, int *tag, const uint8_t **val, size_t *vlen)
{
	error_print();
	return -1;
}

int x509_name_get_common_name(const uint8_t *d, size_t dlen, int *tag, const uint8_t **val, size_t *vlen)
{
	error_print();
	return -1;
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

int x509_ext_to_der(int oid, int critical, const uint8_t *val, size_t vlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_ext_id_to_der(oid, NULL, &len) != 1
		|| asn1_boolean_to_der(critical, NULL, &len) < 0
		|| asn1_octet_string_to_der(val, vlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_ext_id_to_der(oid, out, outlen) != 1
		|| asn1_boolean_to_der(critical, out, outlen) != 1
		|| asn1_octet_string_to_der(val, vlen, out, outlen) != 1) {
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
	*critical = 0;
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
	case OID_netscape_cert_comment: return format_string(fp, fmt, ind, name, p, len);
	default: format_bytes(fp, fmt, ind, "extnValue", p, len);
	}
	return 1;
err:
	error_print();
	return -1;
}

int x509_explicit_exts_to_der(int index, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (!d) {
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
		return ret;
	}
	if (asn1_sequence_from_der(d, dlen, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_exts_get_count(const uint8_t *d, size_t dlen, size_t *cnt)
{
	return asn1_types_get_count(d, dlen, ASN1_TAG_SEQUENCE, cnt);
}

int x509_exts_get_ext_by_index(const uint8_t *d, size_t dlen, int index,
	int *oid, uint32_t *nodes, size_t *nodes_cnt, int *critical,
	const uint8_t **val, size_t *vlen)
{
	error_print();
	return -1;
}

int x509_exts_get_ext_by_oid(const uint8_t *d, size_t dlen, int oid,
	int *critical, const uint8_t **val, size_t *vlen)
{
	return -1;
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
	if (x509_signature_algor_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "siganture: %s\n", x509_signature_algor_name(val));
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

int x509_certificate_to_der(
	const uint8_t *tbs, size_t tbslen, // full TLV
	int signature_algor,
	const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_data_to_der(tbs, tbslen, NULL, &len) != 1
		|| x509_signature_algor_to_der(signature_algor, NULL, &len) != 1
		|| asn1_bit_octets_to_der(sig, siglen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_data_to_der(tbs, tbslen, out, outlen) != 1
		|| x509_signature_algor_to_der(signature_algor, out, outlen) != 1
		|| asn1_bit_octets_to_der(sig, siglen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_from_der(
	const uint8_t **tbs, size_t *tbslen, // full TLV
	int *signature_algor,
	const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_any_from_der(tbs, tbslen, &d, &dlen) != 1
		|| x509_signature_algor_from_der(signature_algor, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(sig, siglen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;
	int val;

	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_tbs_cert_print(fp, fmt, ind, "tbsCertificate", p, len);
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

int x509_cert_sign(
	uint8_t *cert, size_t *certlen, size_t maxlen,
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
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len)
{
	uint8_t tbs[1024];
	size_t tbslen = 0;
	uint8_t *p = tbs;
	size_t len = 0;
	SM2_SIGN_CTX sign_ctx;
	int sig_alg = OID_sm2sign_with_sm3;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	if (x509_tbs_cert_to_der(version, serial, serial_len, signature_algor,
			issuer, issuer_len, not_before, not_after,
			subject, subject_len, subject_public_key,
			issuer_unique_id, issuer_unique_id_len,
			subject_unique_id, subject_unique_id_len,
			exts, exts_len, NULL, &len) != 1
		|| asn1_length_le(len, sizeof(tbs)) != 1
		|| x509_tbs_cert_to_der(version, serial, serial_len, signature_algor,
			issuer, issuer_len, not_before, not_after,
			subject, subject_len, subject_public_key,
			issuer_unique_id, issuer_unique_id_len,
			subject_unique_id, subject_unique_id_len,
			exts, exts_len, &p, &tbslen) != 1) {
		error_print();
		return -1;
	}

	if (sm2_sign_init(&sign_ctx, sign_key, signer_id, signer_id_len) != 1
		|| sm2_sign_update(&sign_ctx, tbs, tbslen) != 1
		|| sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		memset(&sign_ctx, 0, sizeof(sign_ctx));
		error_print();
		return -1;
	}
	memset(&sign_ctx, 0, sizeof(sign_ctx));

	*certlen = len = 0;
	if (x509_certificate_to_der(tbs, tbslen, sig_alg, sig, siglen, NULL, &len) != 1
		|| asn1_length_le(len, maxlen) != 1
		|| x509_certificate_to_der(tbs, tbslen, sig_alg, sig, siglen, &cert, certlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_verify(const uint8_t *a, size_t alen,
	const SM2_KEY *pub_key, const char *signer_id, size_t signer_id_len)
{
	int ret;
	const uint8_t *tbs;
	size_t tbslen;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	SM2_SIGN_CTX verify_ctx;

	if (x509_certificate_from_der(&tbs, &tbslen, &sig_alg, &sig, &siglen, &a, &alen) != 1
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
		|| (ret = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
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
	int ret;
	SM2_KEY public_key;

	if (x509_cert_get_subject_public_key(cacert, cacertlen, &public_key) != 1
		|| (ret = x509_cert_verify(a, alen, &public_key, signer_id, signer_id_len)) < 0) {
		error_print();
		return -1;
	}
	if (!ret) error_print();
	return ret;
}

int x509_cert_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	return asn1_any_to_der(a, alen, out, outlen);
}

int x509_cert_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	return asn1_any_from_der(a, alen, in, inlen);
}

int x509_cert_to_pem(const uint8_t *a, size_t alen, FILE *fp)
{
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
		return ret;
	}
	return 1;
}

int x509_cert_from_pem_by_index(uint8_t *a, size_t *alen, size_t maxlen, int index, FILE *fp)
{
	int i;
	for (i = 0; i <= index; i++) {
		if (x509_cert_from_pem(a, alen, maxlen, fp) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_cert_from_pem_by_subject(uint8_t *a, size_t *alen, size_t maxlen, const uint8_t *name, size_t namelen, FILE *fp)
{
	const uint8_t *d;
	size_t dlen;

	for (;;) {
		if (x509_cert_from_pem(a, alen, maxlen, fp) != 1) {
			error_print();
			return -1;
		}
		x509_cert_get_subject(a, *alen, &d, &dlen);

		if (dlen == namelen && memcmp(name, d, dlen) == 0) {
			return 1;
		}

	}
	return 0;
}

int x509_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
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
	x509_certificate_print(fp, fmt, ind, label, d, dlen);
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
	const uint8_t *tbs;
	size_t tbs_len;
	int sig_alg;
	const uint8_t *sig; size_t sig_len;

	const uint8_t *d;
	size_t dlen;

	int ver;
	const uint8_t *serial; size_t serial_len;
	int inner_sig_alg;
	const uint8_t *isur; size_t isur_len;
	time_t before, after;
	const uint8_t *subj; size_t subj_len;
	SM2_KEY sm2_key;
	const uint8_t *isur_uniq_id; size_t isur_uniq_id_len;
	const uint8_t *subj_uniq_id; size_t subj_uniq_id_len;
	const uint8_t *exts; size_t exts_len;

	if (x509_certificate_from_der(&tbs, &tbs_len, &sig_alg, &sig, &sig_len, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	if (asn1_sequence_from_der(&d, &dlen, &tbs, &tbs_len) != 1
		|| asn1_length_is_zero(tbs_len) != 1) {
		error_print();
		return -1;
	}

	if (x509_explicit_version_from_der(0, &ver, &d, &dlen) < 0
		|| asn1_integer_from_der(&serial, &serial_len, &d, &dlen) != 1
		|| x509_signature_algor_from_der(&inner_sig_alg, &d, &dlen) != 1
		|| asn1_sequence_from_der(&isur, &isur_len, &d, &dlen) != 1
		|| x509_validity_from_der(&before, &after, &d, &dlen) != 1
		|| asn1_sequence_from_der(&subj, &subj_len, &d, &dlen) != 1
		|| x509_public_key_info_from_der(&sm2_key, &d, &dlen) != 1
		|| asn1_implicit_bit_octets_from_der(1, &isur_uniq_id, &isur_uniq_id_len, &d, &dlen) < 0
		|| asn1_implicit_bit_octets_from_der(2, &subj_uniq_id, &subj_uniq_id_len, &d, &dlen) < 0
		|| x509_explicit_exts_from_der(3, &exts, &exts_len, &d, &dlen) < 0) {
		error_print();
		return -1;
	}

	if (version) *version = ver;
	if (serial_number) *serial_number = serial;
	if (serial_number_len) *serial_number_len = serial_len;
	if (inner_signature_algor) *inner_signature_algor = inner_sig_alg;
	if (issuer) *issuer = isur;
	if (issuer_len) *issuer_len = isur_len;
	if (not_before) *not_before = before;
	if (not_after) *not_after = after;
	if (subject) *subject = subj;
	if (subject_len) *subject_len = subj_len;
	if (subject_public_key) *subject_public_key = sm2_key;
	if (issuer_unique_id) *issuer_unique_id = isur_uniq_id;
	if (issuer_unique_id_len) *issuer_unique_id_len = isur_uniq_id_len;
	if (subject_unique_id) *subject_unique_id = subj_uniq_id;
	if (subject_unique_id_len) *subject_unique_id_len = subj_uniq_id_len;
	if (extensions) *extensions = exts;
	if (extensions_len) *extensions_len = exts_len;
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

int x509_certs_from_pem(const uint8_t *d, size_t *dlen, size_t maxlen, FILE *fp)
{
	error_print();
	return -1;
}

int x509_certs_get_count(const uint8_t *d, size_t dlen, size_t *cnt)
{
	if (asn1_types_get_count(d, dlen, ASN1_TAG_SEQUENCE, cnt) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certs_get_cert_by_index(const uint8_t *d, size_t dlen, int index, const uint8_t **cert, size_t *certlen)
{
	error_print();
	return -1;
}

int x509_certs_get_cert_by_subject(const uint8_t *d, size_t dlen,
	const uint8_t *subject, size_t subject_len, const uint8_t **cert, size_t *certlen)
{
	error_print();
	return -1;
}

int x509_certs_get_cert_by_issuer_and_serial_number(
	const uint8_t *certs, size_t certs_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len,
	const uint8_t **cert, size_t *cert_len)
{
	const uint8_t *cur_issuer;
	size_t cur_issuer_len;
	const uint8_t *cur_serial;
	size_t cur_serial_len;

	while (certs_len) {
		if (asn1_any_from_der(cert, cert_len, &certs, &certs_len) != 1
			|| x509_cert_get_issuer_and_serial_number(*cert, *cert_len,
				&cur_issuer, &cur_issuer_len,
				&cur_serial, &cur_serial_len) != 1) {
			error_print();
			return -1;
		}
		if (cur_issuer_len == issuer_len
			&& memcmp(cur_issuer, issuer, issuer_len) == 0
			&& cur_serial_len == serial_len
			&& memcmp(cur_serial, serial, serial_len) == 0) {
			return 1;
		}
	}
	return 0;
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
