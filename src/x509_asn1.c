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
#include <gmssl/x509.h>
#include <gmssl/error.h>


const char *x509_version_name(int version)
{
	switch (version) {
	case X509_version_v1: return "v1";
	case X509_version_v2: return "v2";
	case X509_version_v3: return "v3";
	default: return "<invalid>";
	}
}

int x509_version_to_der(int version, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	switch (version) {
	case X509_version_v1:
		return 0;
	case X509_version_v2:
	case X509_version_v3:
		break;
	default:
		error_print_msg("invalid version %d\n", version);
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| asn1_explicit_header_to_der(0, len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_version_from_der(int *version, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_explicit_from_der(0, &data, &datalen, in, inlen)) < 0) {
		error_print();
		return -1;
	} else if (ret == 0) {
		*version = X509_version_v1;
		return 1;
	}

	if (asn1_int_from_der(version, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	switch (*version) {
	case X509_version_v1:
		error_puts("warning: version v1 should not be encoded");
		break;
	case X509_version_v2:
	case X509_version_v3:
		break;
	default:
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

int x509_validity_set_days(X509_VALIDITY *a, time_t not_before, int days)
{
	struct tm tm_val;
	if (!a || not_before < 0 || days < 1 || days > 3650) {
		return 0;
	}
	a->not_before = not_before;
	gmtime_r(&not_before, &tm_val);
	tm_val.tm_mday += days;
	a->not_after = mktime(&tm_val);

	return 1;
}

int x509_time_to_der(time_t a, uint8_t **out, size_t *outlen)
{
	int ret;
	struct tm tm_val;

	gmtime_r(&a, &tm_val);
	if (tm_val.tm_year < 2050 - 1900) {
		ret = asn1_utc_time_to_der(a, out, outlen);
	} else {
		ret = asn1_generalized_time_to_der(a, out, outlen);
	}

	if (ret != 1) {
		error_print();
	}
	return ret;
}

int x509_time_from_der(time_t *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	if (!a || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if ((ret = asn1_utc_time_from_der(a, in, inlen)) == 0) {
		ret = asn1_generalized_time_from_der(a, in, inlen);
	}
	return ret;
}

int x509_validity_to_der(const X509_VALIDITY *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_time_to_der(a->not_before, NULL, &len) != 1
		|| x509_time_to_der(a->not_after, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_time_to_der(a->not_before, out, outlen) != 1
		|| x509_time_to_der(a->not_after, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_validity_from_der(X509_VALIDITY *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if (!a || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_time_from_der(&a->not_before, &data, &datalen) != 1
		|| x509_time_from_der(&a->not_after, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (a->not_before >= a->not_after) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_validity_print(FILE *fp, const X509_VALIDITY *validity, int format, int indent)
{
	format_print(fp, format, indent, "NotBefore : %s", ctime(&validity->not_before));
	format_print(fp, format, indent, "NotAfter : %s", ctime(&validity->not_after));
	return 1;
}



int x509_directory_string_to_der(int tag, const char *a, size_t alen, uint8_t **out, size_t *outlen)
{
	int ret = 0;

	switch (tag) {
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_UniversalString:
	case ASN1_TAG_UTF8String:
		if (strlen(a) != alen) {
			error_print();
			return -1;
		}
	}

	switch (tag) {
	case ASN1_TAG_PrintableString:
		ret = asn1_printable_string_to_der(a, out, outlen);
		break;
	case ASN1_TAG_UTF8String:
		ret = asn1_utf8_string_to_der(a, out, outlen);
		break;
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_UniversalString:
	case ASN1_TAG_BMPString:
		error_print();
		return -1;
	default:
		error_print();
		return -1;
	}

	if (ret < 0) {
		error_print();
		return -1;
	}
	return ret;
}


int x509_directory_string_from_der(int *tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_any_type_from_der(tag, (const uint8_t **)a, alen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	switch (*tag) {
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_UTF8String:
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_UniversalString:
		// FIXME: check no zero in string
		break;
	case ASN1_TAG_BMPString:
		break;
	default:
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
} x509_rdns[] = {
	{ OID_at_countryName,            1, 2, 2 },
	{ OID_at_stateOrProvinceName,    0, 1, X509_ub_state_name },
	{ OID_at_localityName,           0, 1, X509_ub_locality_name },
	{ OID_at_organizationName,       0, 1, X509_ub_state_name },
	{ OID_at_organizationalUnitName, 0, 1, X509_ub_organizational_unit_name },
	{ OID_at_organizationName,       0, 1, X509_ub_organization_name },
	{ OID_at_commonName,             0, 1, X509_ub_common_name },
	{ OID_at_serialNumber,           1, 1, X509_ub_serial_number },
	{ OID_at_dnQualifier,            1, 1, 64 }, // max length unspecified in RFC 5280
	{ OID_at_title,                  0, 1, X509_ub_title },
	{ OID_at_surname,                0, 1, X509_ub_name },
	{ OID_at_givenName,              0, 1, X509_ub_name },
	{ OID_at_initials,               0, 1, X509_ub_name },
	{ OID_at_generationQualifier,    0, 1, X509_ub_name },
	{ OID_at_pseudonym,              0, 1, X509_ub_pseudonym },
};

static int x509_rdn_check(int oid, int tag, const char *str, int len)
{
	int i;
	for (i = 0; i < sizeof(x509_rdns)/sizeof(x509_rdns[0]); i++) {
		if (oid == x509_rdns[i].oid) {
			switch (tag) {
			case ASN1_TAG_PrintableString:
			case ASN1_TAG_UTF8String:
			case ASN1_TAG_TeletexString:
			case ASN1_TAG_UniversalString:
			case ASN1_TAG_BMPString:
				break;
			default:
				error_print();
				return -1;
			}
			if (x509_rdns[i].is_printable_string_only && tag != ASN1_TAG_PrintableString) {
				error_print();
				return -1;
			}
			if (len < x509_rdns[i].minlen || len > x509_rdns[i].maxlen) {
				error_print();
				return -1;
			}
		}
	}
	return 1;
}


int x509_name_add_rdn_ex(X509_NAME *a, int oid, int tag, const char *str, size_t len)
{
	int i;

	if (a->count >= 8) {
		return -1;
	}
	for (i = 0; i < a->count; i++) {
		if (oid == a->oids[i]) {
			error_print();
			return -1;
		}
	}

	if (x509_rdn_check(oid, tag, str, len) != 1) {
		error_print();
		return -1;
	}

	switch (oid) {
	case OID_at_countryName:
		memcpy(a->country, str, len);
		break;
	case OID_at_stateOrProvinceName:
		memcpy(a->state_or_province, str, len);
		break;
	case OID_at_localityName:
		memcpy(a->locality, str, len);
		break;
	case OID_at_organizationName:
		memcpy(a->org, str, len);
		break;
	case OID_at_organizationalUnitName:
		memcpy(a->org_unit, str, len);
		break;
	case OID_at_commonName:
		memcpy(a->common_name, str, len);
		break;
	case OID_at_serialNumber:
		memcpy(a->serial_number, str, len);
		break;
	case OID_at_dnQualifier:
		memcpy(a->dn_qualifier, str, len);
		break;
	default:
		error_print();
		return -1;
	}

	a->oids[a->count] = oid;
	a->tags[a->count] = tag;
	a->count++;

	return 1;
}

// 这个函数可能是有问题的，因为RDN可能是bmp string，因此这里应该给一个长度
int x509_rdn_to_der(int oid, int tag, const char *str, uint8_t **out, size_t *outlen)
{
	size_t len = 0, seqlen = 0;

	if (asn1_object_identifier_to_der(oid, NULL, 0, NULL, &len) != 1
		|| x509_directory_string_to_der(tag, str, strlen(str), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, NULL, &seqlen) != 1) {
		error_print();
		return -1;
	}
	seqlen += len;
	if (asn1_set_header_to_der(seqlen, out, outlen) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid, NULL, 0, out, outlen) != 1
		|| x509_directory_string_to_der(tag, str, strlen(str), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_rdn_from_der(int *oid, int *tag, const char **str, size_t *slen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *seq, *data;
	size_t seqlen = 0, datalen = 0;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_set_from_der(&seq, &seqlen, in, inlen)) != 1) {
		error_print();
		return ret;
	}
	if (asn1_sequence_from_der(&data, &datalen, &seq, &seqlen) != 1
		|| seqlen > 0) {
		error_print();
		return -1;
	}

	if (asn1_object_identifier_from_der(oid, nodes, &nodes_count, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (x509_directory_string_from_der(tag, str, slen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (datalen > 0) {
		error_print();
		return -1;
	}
	if (x509_rdn_check(*oid, *tag, *str, *slen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_name_from_der(X509_NAME *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	memset(a, 0, sizeof(X509_NAME));
	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) <= 0) {
		error_print();
		return ret;
	}
	while (datalen) {
		int oid, tag;
		const char *str;
		size_t len;
		if (x509_rdn_from_der(&oid, &tag, &str, &len, &data, &datalen) != 1
			|| x509_name_add_rdn_ex(a, oid, tag, str, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

const char *x509_name_rdn(const X509_NAME *name, int oid)
{
	switch (oid) {
	case OID_at_countryName:
		return name->country;
	case OID_at_stateOrProvinceName:
		return name->state_or_province;
	case OID_at_localityName:
		return name->locality;
	case OID_at_organizationName:
		return name->org;
	case OID_at_organizationalUnitName:
		return name->org_unit;
	case OID_at_commonName:
		return name->common_name;
	case OID_at_serialNumber:
		return name->serial_number;
	case OID_at_dnQualifier:
		return name->dn_qualifier;
	}
	error_print();
	return NULL;
}

int x509_name_print(FILE *fp, const X509_NAME *name, int format, int indent)
{
	int i;
	for (i = 0; i < name->count; i++) {
		format_print(fp, format, indent, "%s : %s\n",
			asn1_object_identifier_name(name->oids[i]),
			//asn1_tag_name(name->tags[i]),
			x509_name_rdn(name, name->oids[i]));
	}
	return 1;
}

int x509_name_equ(const X509_NAME *a, const X509_NAME *b)
{
	uint8_t abuf[256];
	uint8_t bbuf[256];
	uint8_t *ap = abuf;
	uint8_t *bp = bbuf;
	size_t alen = 0, blen = 0;

	x509_name_to_der(a, &ap, &alen);
	x509_name_to_der(b, &bp, &blen);
	if (alen == blen && memcmp(abuf, bbuf, alen) == 0) {
		return 1;
	} else  return 0;
}

int x509_name_to_der(const X509_NAME *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	int oid, tag, i;

	// 在前面的循环中把输出字符串的指针做赋值，这样不需要重复这个循环

	for (i = 0; i < a->count; i++) {
		oid = a->oids[i];
		tag = a->tags[i];

		switch (oid) {
		case OID_at_countryName:
			x509_rdn_to_der(oid, tag, a->country, NULL, &len);
			break;
		case OID_at_stateOrProvinceName:
			x509_rdn_to_der(oid, tag, a->state_or_province, NULL, &len);
			break;
		case OID_at_localityName:
			x509_rdn_to_der(oid, tag, a->locality, NULL, &len);
			break;
		case OID_at_organizationName:
			x509_rdn_to_der(oid, tag, a->org, NULL, &len);
			break;
		case OID_at_organizationalUnitName:
			x509_rdn_to_der(oid, tag, a->org_unit, NULL, &len);
			break;
		case OID_at_commonName:
			x509_rdn_to_der(oid, tag, a->common_name, NULL, &len);
			break;
		case OID_at_serialNumber:
			x509_rdn_to_der(oid, tag, a->serial_number, NULL, &len);
			break;
		case OID_at_dnQualifier:
			x509_rdn_to_der(oid, tag, a->dn_qualifier, NULL, &len);
			break;
		default:
			error_print();
			return -1;
		}
	}
	asn1_sequence_header_to_der(len, out, outlen);
	for (i = 0; i < a->count; i++) {
		oid = a->oids[i];
		tag = a->tags[i];

		switch (oid) {
		case OID_at_countryName:
			x509_rdn_to_der(oid, tag, a->country, out, outlen);
			break;
		case OID_at_stateOrProvinceName:
			x509_rdn_to_der(oid, tag, a->state_or_province, out, outlen);
			break;
		case OID_at_localityName:
			x509_rdn_to_der(oid, tag, a->locality, out, outlen);
			break;
		case OID_at_organizationName:
			x509_rdn_to_der(oid, tag, a->org, out, outlen);
			break;
		case OID_at_organizationalUnitName:
			x509_rdn_to_der(oid, tag, a->org_unit, out, outlen);
			break;
		case OID_at_commonName:
			x509_rdn_to_der(oid, tag, a->common_name, out, outlen);
			break;
		case OID_at_serialNumber:
			x509_rdn_to_der(oid, tag, a->serial_number, out, outlen);
			break;
		case OID_at_dnQualifier:
			x509_rdn_to_der(oid, tag, a->dn_qualifier, out, outlen);
			break;
		default:
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_public_key_info_set_sm2(X509_PUBLIC_KEY_INFO *a, const SM2_KEY *sm2_key)
{
	if (!a || !sm2_key) {
		error_print();
		return -1;
	}
	memset(a, 0, sizeof(X509_PUBLIC_KEY_INFO));
	a->algor_oid = OID_x9_62_ecPublicKey;
	a->curve_oid = OID_sm2;
	sm2_set_public_key(&a->sm2_key, (uint8_t *)&sm2_key->public_key);
	return 1;
}

int x509_public_key_info_to_der(const X509_PUBLIC_KEY_INFO *a, uint8_t **out, size_t *outlen)
{
	if (sm2_public_key_info_to_der(&a->sm2_key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_info_from_der(X509_PUBLIC_KEY_INFO *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = sm2_public_key_info_from_der(&a->sm2_key, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	a->algor_oid = OID_x9_62_ecPublicKey;
	a->curve_oid = OID_sm2;
	return 1;
}

int x509_public_key_info_print(FILE *fp, const X509_PUBLIC_KEY_INFO *a, int format, int indent)
{
	format_print(fp, format, indent, "Algorithm : %s\n", asn1_object_identifier_name(a->algor_oid));
	format_print(fp, format, indent, "Parameters : %s\n", asn1_object_identifier_name(a->curve_oid));
	format_print(fp, format, indent, "PublicKey\n");
	sm2_point_print(fp, &a->sm2_key.public_key, format, indent + 4);
	return 1;
}


// X.509 扩展的OID实际上在OID模块中并没有，我们应该在这个模块中独立给出



// DER_id_ce[] =  0x55,0x1D,

static const uint8_t DER_x509_ce[] = { 0x55, 0x1d };


static const struct {
	int der;
	int oid;
	char *name;
} ce_oids[] = {
	{ 35, OID_ce_authorityKeyIdentifier, "AuthorityKeyIdentifier" },
	{ 14, OID_ce_subjectKeyIdentifier, "SubjectKeyIdentifier" },
	{ 15, OID_ce_keyUsage, "KeyUsage" },
	{ 32, OID_ce_certificatePolicies, "CertificatePolicies" },
	{ 33, OID_ce_policyMappings, "PolicyMappings" },
	{ 17, OID_ce_subjectAltName, "SubjectAltName" },
	{ 18, OID_ce_issuerAltName, "IssuerAltName" },
	{  9, OID_ce_subjectDirectoryAttributes, "SubjectDirectoryAttributes" },
	{ 19, OID_ce_basicConstraints, "BasicConstraints" },
	{ 30, OID_ce_nameConstraints, "NameConstraints" },
	{ 36, OID_ce_policyConstraints, "PolicyConstraints" },
	{ 37, OID_ce_extKeyUsage, "ExtKeyUsage" },
	{ 31, OID_ce_crlDistributionPoints, "CRLDistributionPoints" },
	{ 54, OID_ce_inhibitAnyPolicy, "InhibitAnyPolicy" },
	{ 46, OID_ce_freshestCRL, "FreshestCRL" },
};

const char *x509_extension_oid_name(int oid)
{
	int i;
	for (i = 0; i < sizeof(ce_oids)/sizeof(ce_oids[0]); i++) {
		if (oid == ce_oids[i].oid) {
			return ce_oids[i].name;
		}
	}
	return NULL;
}

int x509_extension_oid_to_der(int oid, uint8_t **out, size_t *outlen)
{
	uint8_t octets[3] = { 0x55, 0x1d, 0 };
	int i;

	for (i = 0; i < sizeof(ce_oids)/sizeof(ce_oids[0]); i++) {
		if (oid == ce_oids[i].oid) {
			octets[2] = ce_oids[i].der;
		}
	}
	if (octets[2] == 0) {
		return -1;
	}
	asn1_tag_to_der(ASN1_TAG_OBJECT_IDENTIFIER, out, outlen);
	asn1_length_to_der(sizeof(octets), out, outlen);
	asn1_data_to_der(octets, sizeof(octets), out, outlen);
	return 1;
}

/*
应该首先对OID进行基本的解析，判断正确性，并获得nodes用于显示
然后可以根据应用场景对octets进行解析，以获得name
*/
int x509_extension_oid_from_der(int *oid, uint32_t *nodes, size_t *nodes_count, const uint8_t **pin, size_t *pinlen)
{
	int ret;
	size_t len;
	const uint8_t *octets;
	int i;
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;

	if ((ret = asn1_object_identifier_from_der(oid, nodes, nodes_count, pin, pinlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if ((ret = asn1_tag_from_der(ASN1_TAG_OBJECT_IDENTIFIER, &in, &inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_length_from_der(&len, &in, &inlen) != 1
		|| asn1_data_from_der(&octets, len, &in, &inlen) != 1) {
		error_print();
		return -1;
	}
	if (len == 3 && octets[0] == 0x55 && octets[1] == 0x1d) {
		for (i = 0; i < sizeof(ce_oids)/sizeof(ce_oids[0]); i++) {
			if (octets[2] == ce_oids[i].der) {
				*oid = ce_oids[i].oid;
				return 1;
			}
		}
	}
	return ret;
}

// out != NULL 时，data 不可以为 NULL
int x509_extension_to_der(int oid, int is_critical, const uint8_t *data, size_t datalen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_extension_oid_to_der(oid, NULL, &len) != 1
		|| (is_critical >= 0 && asn1_boolean_to_der(is_critical, NULL, &len) != 1)
		|| asn1_octet_string_to_der(data, datalen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_extension_oid_to_der(oid, out, outlen) != 1
		|| (is_critical >= 0 && asn1_boolean_to_der(is_critical, out, outlen) != 1)
		|| asn1_octet_string_to_der(data, datalen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_extension_from_der(int *oid, uint32_t *nodes, size_t *nodes_count,
	int *is_critical, const uint8_t **data, size_t *datalen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *seq;
	size_t seqlen;

	if ((ret = asn1_sequence_from_der(&seq, &seqlen, in, inlen)) != 1) {
		return ret;
	}

	*is_critical = ASN1_FALSE;
	if (x509_extension_oid_from_der(oid, nodes, nodes_count, &seq, &seqlen) != 1 // FIXME:  这里检查OID应该是从一个子集里面检索
		|| asn1_boolean_from_der(is_critical, &seq, &seqlen) < 0
		|| asn1_octet_string_from_der(data, datalen, &seq, &seqlen) != 1
		|| asn1_length_is_zero(seqlen) != 1) {
		error_print();
		return -1;
	}
	if (*datalen <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_extension_print(FILE *fp, int oid, const uint32_t *nodes, size_t nodes_count,
	int is_critical, const uint8_t *data, size_t datalen,
	int format, int indent)
{
	const char *ext_name = x509_extension_oid_name(oid);
	if (!ext_name) {
		ext_name = "Unknown Extension";
	}
	format_print(fp, format, indent, "%s (", ext_name);
	while (nodes_count-- > 1) {
		fprintf(fp, "%d.", *nodes++);
	}
	fprintf(fp, "%d)\n", *nodes);
	indent += 4;

	if (is_critical >= 0) {
		format_print(fp, format, indent, "crtical: %s\n", is_critical ? "true" : "false");
	}

	switch (oid) {
	case OID_ce_authorityKeyIdentifier: return x509_authority_key_identifier_print(fp, data, datalen, format, indent);
	case OID_ce_basicConstraints: return x509_basic_constraints_print(fp, data, datalen, format, indent);
	case OID_ce_keyUsage: return x509_key_usage_print(fp, data, datalen, format, indent);
	case OID_ce_subjectKeyIdentifier: return x509_subject_key_identifier_print(fp, data, datalen, format, indent);
	case OID_ce_extKeyUsage: return x509_ext_key_usage_print(fp, data, datalen, format, indent);
	case OID_ce_policyConstraints: return x509_policy_constraints_print(fp, data, datalen, format, indent);
	default:
		format_bytes(fp, format, indent, "extnValue : ", data, datalen);
	}
	return 1;
}

int x509_extensions_print(FILE *fp, const X509_EXTENSIONS *a, int format, int indent)
{
	int ret;
	int oid;
	uint32_t nodes[32];
	size_t nodes_count;
	int is_critical;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *next = a->data;

	format_print(fp, format, indent, "Extensions\n"); indent += 4;
	for (;;) {
		if ((ret = x509_extensions_get_next_item(a, &next,
			&oid, nodes, &nodes_count, &is_critical, &data, &datalen)) != 1) {
			if (ret < 0) error_print();
			return ret;
		}
		x509_extension_print(fp, oid, nodes, nodes_count, is_critical, data, datalen, format, indent);
	}
	return 1;
}

int x509_extensions_to_der(const X509_EXTENSIONS *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	asn1_sequence_to_der(a->data, a->datalen, NULL, &len);
	asn1_explicit_header_to_der(3, len, out, outlen);
	asn1_sequence_to_der(a->data, a->datalen, out, outlen);
	return 1;
}

int x509_extensions_from_der(X509_EXTENSIONS *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_explicit_from_der(3, &data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_sequence_copy_from_der(512, a->data, &a->datalen, &data, &datalen) != 1
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	// FIXME：检查extensions的格式是否正确
	return 1;
}

int x509_extensions_add_item(X509_EXTENSIONS *a,
	int oid, int is_critical, const uint8_t *data, size_t datalen)
{
	uint8_t *p = a->data + a->datalen;
	size_t len = 0;
	if (x509_extension_to_der(oid, is_critical, data, datalen, &p, &len) != 1) {
		error_print();
		return -1;
	}
	a->datalen += len;
	return 1;
}

int x509_extensions_get_next_item(const X509_EXTENSIONS *a, const uint8_t **next,
	int *oid, uint32_t *nodes, size_t *nodes_count,
	int *is_critical, const uint8_t **data, size_t *datalen)
{
	int ret;
	size_t len = a->datalen; // FIXME: len赋值不对		
	if ((ret = x509_extension_from_der(oid, nodes, nodes_count, is_critical, data, datalen, next, &len)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_certificate_add_extension(X509_CERTIFICATE *a, int oid, int is_critical,
	const uint8_t *data, size_t datalen)
{
	if (x509_extensions_add_item(&a->tbs_certificate.extensions, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_extension_from_oid(const X509_CERTIFICATE *a, int oid,
	int *is_critical, const uint8_t **data, size_t *datalen)
{
	int ret;
	const X509_EXTENSIONS *ext;
	const uint8_t *next = NULL;
	int rid;
	uint32_t nodes[16];
	size_t nodes_count;

	for (;;) {
		if ((ret = x509_extensions_get_next_item(&a->tbs_certificate.extensions, &next,
			&rid, nodes, &nodes_count, is_critical, data, datalen)) != 1) {
			if (ret < 0) error_print();
			return ret;
		}
		if (rid == oid) {
			return 1;
		}
	}
	return 0;
}

// 这里用来打印的到底是解析后的内容，还是解析之前的DER呢？
// 而且这个打印函数应该能够支持所有类型的打印

int x509_tbs_certificate_to_der(const X509_TBS_CERTIFICATE *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (x509_version_to_der(a->version, NULL, &len) != 1
		|| asn1_integer_to_der(a->serial_number, a->serial_number_len, NULL, &len) != 1
		|| x509_signature_algor_to_der(a->signature_algor, NULL, &len) != 1
		|| x509_name_to_der(&a->issuer, NULL, &len) != 1
		|| x509_validity_to_der(&a->validity, NULL, &len) != 1
		|| x509_name_to_der(&a->subject, NULL, &len) != 1
		|| x509_public_key_info_to_der(&a->subject_public_key_info, NULL, &len) != 1
		|| asn1_implicit_bit_string_to_der(1, a->issuer_unique_id, a->issuer_unique_id_len * 8, NULL, &len) < 0
		|| asn1_implicit_bit_string_to_der(2, a->subject_unique_id, a->subject_unique_id_len * 8, NULL, &len) <0
		|| x509_extensions_to_der(&a->extensions, NULL, &len) < 0)  {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_version_to_der(a->version, out, outlen) != 1
		|| asn1_integer_to_der(a->serial_number, a->serial_number_len, out, outlen) != 1
		|| x509_signature_algor_to_der(a->signature_algor, out, outlen) != 1
		|| x509_name_to_der(&a->issuer, out, outlen) != 1
		|| x509_validity_to_der(&a->validity, out, outlen) != 1
		|| x509_name_to_der(&a->subject, out, outlen) != 1
		|| x509_public_key_info_to_der(&a->subject_public_key_info, out, outlen) != 1
		|| asn1_implicit_bit_string_to_der(1, a->issuer_unique_id, a->issuer_unique_id_len * 8, out, outlen) < 0
		|| asn1_implicit_bit_string_to_der(2, a->subject_unique_id, a->subject_unique_id_len * 8, out, outlen) < 0
		|| x509_extensions_to_der(&a->extensions, out, outlen) < 0) {
		error_print();
		return -1;
	}

	return 1;
}

int x509_tbs_certificate_from_der(X509_TBS_CERTIFICATE *a, const uint8_t **in, size_t *inlen)
{
	int is_ver, is_ext;
	const uint8_t *ver, *exts;
	size_t verlen, extslen;

	int ret;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *serial_number;
	const uint8_t *issuer_unique_id = NULL;
	const uint8_t *subject_unique_id = NULL;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	memset(a, 0, sizeof(*a));

	size_t issuer_unique_id_nbits;
	size_t subject_unique_id_nbits;

	if (x509_version_from_der(&a->version, &data, &datalen) != 1
		|| asn1_integer_from_der(&serial_number, &a->serial_number_len, &data, &datalen) != 1
		|| x509_signature_algor_from_der(&a->signature_algor, nodes, &nodes_count, &data, &datalen) != 1
		|| x509_name_from_der(&a->issuer, &data, &datalen) != 1
		|| x509_validity_from_der(&a->validity, &data, &datalen) != 1
		|| x509_name_from_der(&a->subject, &data, &datalen) != 1
		|| x509_public_key_info_from_der(&a->subject_public_key_info, &data, &datalen) != 1
		|| asn1_implicit_bit_string_from_der(1, &issuer_unique_id, &issuer_unique_id_nbits, &data, &datalen) < 0
		|| asn1_implicit_bit_string_from_der(2, &subject_unique_id, &subject_unique_id_nbits, &data, &datalen) < 0
		|| (is_ext = x509_extensions_from_der(&a->extensions, &data, &datalen)) < 0
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}

	// FIXME: 应该提供了检查函数，可以返回错误行数			
	if (a->serial_number_len > 20
		|| issuer_unique_id_nbits != 32 * 8
		|| subject_unique_id_nbits != 32 * 8) {

		error_print();
		return -1;
	}

	a->issuer_unique_id_len = issuer_unique_id_nbits/8;
	a->subject_unique_id_len = subject_unique_id_nbits/8;


	// asn1_implicit_bit_string_from_der 返回的是比特长度！
	// 应该改变 issue			


	// FIXME: 这几个都应该用copy的方式
	memcpy(a->serial_number, serial_number, a->serial_number_len);
	if (issuer_unique_id) {
		memcpy(a->issuer_unique_id, issuer_unique_id, a->issuer_unique_id_len);
	}
	if (subject_unique_id) {
		memcpy(a->subject_unique_id, subject_unique_id, a->subject_unique_id_len);
	}

	return 1;
}

int x509_certificate_to_der(const X509_CERTIFICATE *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_tbs_certificate_to_der(&a->tbs_certificate, NULL, &len) != 1
		|| x509_signature_algor_to_der(a->signature_algor, NULL, &len) != 1
		|| asn1_bit_string_to_der(a->signature, a->signature_len * 8, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_tbs_certificate_to_der(&a->tbs_certificate, out, outlen) != 1
		|| x509_signature_algor_to_der(a->signature_algor, out, outlen) != 1
		|| asn1_bit_string_to_der(a->signature, a->signature_len * 8, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_to_pem(const X509_CERTIFICATE *a, FILE *fp)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	if (x509_certificate_to_der(a, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "CERTIFICATE", buf, len) <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_from_der(X509_CERTIFICATE *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *sig;
	size_t sig_nbits;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	memset(a, 0, sizeof(X509_CERTIFICATE));
	if (x509_tbs_certificate_from_der(&a->tbs_certificate, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (x509_signature_algor_from_der(&a->signature_algor, nodes, &nodes_count, &data, &datalen) != 1) {
		error_print();
		int i;
		for (i = 0; i < nodes_count; i++) {
			printf("%d ", (int)nodes[i]);
		}
		printf("\n");
		return -1;
	}
	if (asn1_bit_string_from_der(&sig, &sig_nbits, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	a->signature_len = (sig_nbits + 7)/8;
	memcpy(a->signature, sig, a->signature_len);
	return 1;
}

int x509_certificate_from_pem(X509_CERTIFICATE *a, FILE *fp)
{
	int ret;
	uint8_t buf[1024];
	const uint8_t *cp = buf;
	size_t len;

	if ((ret = pem_read(fp, "CERTIFICATE", buf, &len)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_certificate_from_der(a, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_print(FILE *fp, const X509_CERTIFICATE *a, int format, int indent)
{
	const X509_TBS_CERTIFICATE *tbs = &a->tbs_certificate;
	size_t i;

	format_print(fp, format, indent, "Certificate\n");
	indent += 4;
	format_print(fp, format, indent, "Version : %s (%d)\n", x509_version_name(tbs->version), tbs->version);
	format_bytes(fp, format, indent, "SerialNumber : ", tbs->serial_number, tbs->serial_number_len);
	format_print(fp, format, indent, "SigantureAlgorithm : %s\n", asn1_object_identifier_name(tbs->signature_algor));
	format_print(fp, format, indent, "Issuer\n");
	x509_name_print(fp, &tbs->issuer, format, indent + 4);
	format_print(fp, format, indent, "Validity\n");
	x509_validity_print(fp, &tbs->validity, format, indent + 4);
	format_print(fp, format, indent, "Subject\n");
	x509_name_print(fp, &tbs->subject, format, indent + 4);
	format_print(fp, format, indent, "SubjectPublicKeyInfo\n");
	x509_public_key_info_print(fp, &tbs->subject_public_key_info, format, indent + 4);
	format_print(fp, format, indent, "SigantureAlgorithm : %s\n", asn1_object_identifier_name(a->signature_algor));
	format_bytes(fp, format, indent, "Signature : ", a->signature, a->signature_len);
	x509_extensions_print(fp, &a->tbs_certificate.extensions, format, indent);
	return 1;
}

int x509_signature_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	if (asn1_bit_string_to_der(a, alen * 8, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_signature_copy_from_der(size_t maxlen, uint8_t *a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *bits;
	size_t nbits;

	if ((ret = asn1_bit_string_from_der(&bits, &nbits, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (nbits % 8 != 0) {
		error_print();
		return -1;
	}
	*alen = nbits / 8;
	if (*alen > maxlen) {
		error_print();
		return -1;
	}
	memcpy(a, bits, *alen);
	return 1;
}



/*
from RFC 2986

CertificationRequest ::= SEQUENCE {
	certificationRequestInfo  CertificationRequestInfo,
	signatureAlgorithm        AlgorithmIdentifier,
	signature                 BIT STRING
}

CertificationRequestInfo ::= SEQUENCE {
	version                   INTEGER { v1(0) },
	subject                   Name,
	subjectPKInfo             SubjectPublicKeyInfo,
	attributes                [0] IMPLICIT SET OF Attribute
}
*/

int x509_cert_request_set_sm2(X509_CERT_REQUEST *a, const X509_NAME *subject, const SM2_KEY *sm2_key)
{
	memset(a, 0, sizeof(*a));
	a->req_info.version = X509_version_v1;
	a->req_info.subject = *subject;
	if (x509_public_key_info_set_sm2(&a->req_info.subject_public_key_info, sm2_key) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_request_info_to_der(const X509_CERT_REQUEST_INFO *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(a->version, NULL, &len) != 1
		|| x509_name_to_der(&a->subject, NULL, &len) != 1
		|| x509_public_key_info_to_der(&a->subject_public_key_info, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(a->version, out, outlen) != 1
		|| x509_name_to_der(&a->subject, out, outlen) != 1
		|| x509_public_key_info_to_der(&a->subject_public_key_info, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_request_info_from_der(X509_CERT_REQUEST_INFO *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *attrs;
	size_t attrslen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&a->version, &data, &datalen) != 1
		|| x509_name_from_der(&a->subject, &data, &datalen) != 1
		|| x509_public_key_info_from_der(&a->subject_public_key_info, &data, &datalen) != 1
		|| asn1_implicit_from_der(0, &attrs, &attrslen, &data, &datalen) < 0
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_request_info_print(FILE *fp, const X509_CERT_REQUEST_INFO *a, int format, int indent)
{
	format_print(fp, format, indent, "CertificationRequestInfo\n");
	indent += 4;
	format_print(fp, format, indent, "version: %s (%d)\n", x509_version_name(a->version), a->version);
	format_print(fp, format, indent, "subject\n");
	x509_name_print(fp, &a->subject, format, indent+4);
	format_print(fp, format, indent, "subjectPublicKeyInfo\n");
	x509_public_key_info_print(fp, &a->subject_public_key_info, format, indent+4);

	// FIXME: attributes 没有处理	
	return 1;
}

int x509_cert_request_to_der(const X509_CERT_REQUEST *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_cert_request_info_to_der(&a->req_info, NULL, &len) != 1
		|| x509_signature_algor_to_der(a->signature_algor, NULL, &len) != 1
		|| x509_signature_to_der(a->signature, a->signature_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_cert_request_info_to_der(&a->req_info, out, outlen) != 1
		|| x509_signature_algor_to_der(a->signature_algor, out, outlen) != 1
		|| x509_signature_to_der(a->signature, a->signature_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_request_from_der(X509_CERT_REQUEST *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *sig;
	size_t siglen;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_cert_request_info_from_der(&a->req_info, &data, &datalen) != 1
		|| x509_signature_algor_from_der(&a->signature_algor, nodes, &nodes_count, &data, &datalen) != 1
		|| x509_signature_copy_from_der(128, a->signature, &a->signature_len, &data, &datalen) != 1
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_request_to_pem(const X509_CERT_REQUEST *a, FILE *fp)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	size_t len = 0;

	if (x509_cert_request_to_der(a, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "CERTIFICATE REQUEST", buf, len) <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_request_from_pem(X509_CERT_REQUEST *a, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, "CERTIFICATE REQUEST", buf, &len) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_request_from_der(a, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_request_print(FILE *fp, const X509_CERT_REQUEST *a, int format, int indent)
{
	size_t i;

	format_print(fp, format, indent, "CertificationRequest\n");
	indent += 4;
	x509_cert_request_info_print(fp, &a->req_info, format, indent);
	format_print(fp, format, indent, "signatureAlgorithm: %s\n", asn1_object_identifier_name(a->signature_algor));
	format_bytes(fp, format, indent, "signature: ", a->signature, a->signature_len);
	return 1;
}

int x509_cert_request_sign_sm2(X509_CERT_REQUEST *a, const SM2_KEY *sm2_key)
{
	SM2_SIGN_CTX ctx;
	uint8_t tbs[1024];
	uint8_t *p = tbs;
	size_t tbslen = 0;

	a->signature_algor = OID_sm2sign_with_sm3;
	if (x509_cert_request_info_to_der(&a->req_info, &p, &tbslen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_sign_init(&ctx, sm2_key, SM2_DEFAULT_ID) != 1
		|| sm2_sign_update(&ctx, tbs, tbslen) != 1
		|| sm2_sign_finish(&ctx, a->signature, &a->signature_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_request_verify(const X509_CERT_REQUEST *a)
{
	int ret;
	const SM2_KEY *sm2_key;
	SM2_SIGN_CTX ctx;
	uint8_t tbs[1024];
	uint8_t *p = tbs;
	size_t tbslen = 0;

	if (x509_cert_request_info_to_der(&a->req_info, &p, &tbslen) != 1) {
		error_print();
		return -1;
	}

	sm2_key = &a->req_info.subject_public_key_info.sm2_key;

	if (sm2_verify_init(&ctx, sm2_key, SM2_DEFAULT_ID) != 1
		|| sm2_verify_update(&ctx, tbs, tbslen) != 1
		|| (ret = sm2_verify_finish(&ctx, a->signature, a->signature_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}
