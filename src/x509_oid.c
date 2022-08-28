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
#include <gmssl/error.h>


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
static uint32_t oid_cert_authority_info_access[] = { 1,3,6,1,5,5,7,1,1 };
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
	{ OID_cert_authority_info_access, "CertificateAuthorityInformationAccess", oid_cert_authority_info_access, sizeof(oid_cert_authority_info_access)/sizeof(int) },
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


#define oid_kp oid_pkix,3

static uint32_t oid_kp_server_auth[] = { oid_kp,1 };
static uint32_t oid_kp_client_auth[] = { oid_kp,2 };
static uint32_t oid_kp_code_signing[] = { oid_kp,3 };
static uint32_t oid_kp_email_protection[] = { oid_kp,4 };
static uint32_t oid_kp_time_stamping[] = { oid_kp,8 };
static uint32_t oid_kp_ocsp_signing[] = { oid_kp,9 };
#define OID_KP_CNT sizeof(oid_kp_server_auth)/sizeof(int)

static const ASN1_OID_INFO x509_key_purposes[] = {
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
