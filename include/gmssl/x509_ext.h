/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_X509_EXT_H
#define GMSSL_X509_EXT_H


#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif


enum {
	X509_non_critical = 0,
	X509_critical = 1,
};

/*
Extensions:

	1.  AuthorityKeyIdentifier	SEQUENCE			AuthorityKeyIdentifier		MUST non-critical
	2.  SubjectKeyIdentifier	OCTET STRING							MUST non-critical
	3.  KeyUsage			BIT STRING							SHOULD critical
	4.  CertificatePolicies		SEQUENCE OF SEQUENCE		CertificatePolicies
	5.  PolicyMappings		SEQUENCE OF SEQUENCE		PolicyMappings			SHOULD critical
	6.  SubjectAltName		SEQUENCE OF SEQUENCE		GeneralNames			SHOULD non-critical
	7.  IssuerAltName		SEQUENCE OF SEQUENCE		GeneralNames			SHOULD non-critical
	8.  SubjectDirectoryAttributes	SEQUENCE OF SEQUENCE		Attributes			MUST non-critical
	9.  BasicConstraints		SEQUENCE			BasicConstraints		CA: MUST critical, End-entity: MAY critical or non-critical
	10. NameConstraints		SEQUENCE			NameConstraints
	11. PolicyConstraints		SEQUENCE			PolicyConstraints		MUST critical
	12. ExtKeyUsageSyntax		SEQUENCE OF OBJECT IDENTIFIER					MAY critical or non-critical
	13. CRLDistributionPoints	SEQUENCE OF SEQUENCE		DistributionPoints
	14. InhibitAnyPolicy		INTEGER								MUST critical
	15. FreshestCRL			SEQUENCE OF SEQUENCE		DistributionPoints		MUST non-critical
*/

int x509_exts_add_authority_key_identifier(uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len);
int x509_exts_add_default_authority_key_identifier(uint8_t *exts, size_t *extslen, size_t maxlen,
	const SM2_KEY *public_key);
int x509_exts_add_subject_key_identifier(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const uint8_t *d, size_t dlen);
int x509_exts_add_subject_key_identifier_ex(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const SM2_KEY *subject_key);
int x509_exts_add_key_usage(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, int bits);
int x509_exts_add_certificate_policies(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const uint8_t *d, size_t dlen);
int x509_exts_add_policy_mappings(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const uint8_t *d, size_t dlen);
int x509_exts_add_subject_alt_name(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const uint8_t *d, size_t dlen);
int x509_exts_add_issuer_alt_name(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const uint8_t *d, size_t dlen);
int x509_exts_add_subject_directory_attributes(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const uint8_t *d, size_t dlen);
int x509_exts_add_name_constraints(uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const uint8_t *permitted_subtrees, size_t permitted_subtrees_len,
	const uint8_t *excluded_subtrees, size_t excluded_subtrees_len);
int x509_exts_add_policy_constraints(uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	int require_explicit_policy, int inhibit_policy_mapping);
int x509_exts_add_basic_constraints(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, int ca, int path_len_constraint);
int x509_exts_add_ext_key_usage(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const int *key_purposes, size_t key_purposes_cnt);
int x509_exts_add_crl_distribution_points_ex(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, int oid,
	const char *http_uri, size_t http_urilen, const char *ldap_uri, size_t ldap_urilen);
int x509_exts_add_crl_distribution_points(uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const char *http_uri, size_t http_urilen, const char *ldap_uri, size_t ldap_urilen);
int x509_exts_add_inhibit_any_policy(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, int skip_certs);
int x509_exts_add_freshest_crl(uint8_t *exts, size_t *extslen, size_t maxlen, int critical, const uint8_t *d, size_t dlen);
int x509_exts_add_authority_info_access(uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const char *ca_issuers_uri, size_t ca_issuers_urilen, // ca_issuers_uri is the URI (http://examaple.com/subCA.crt) of DER-encoded CA cert
	const char *ocsp_uri, size_t ocsp_urilen);

int x509_exts_add_sequence(uint8_t *exts, size_t *extslen, size_t maxlen,
	int oid, int critical, const uint8_t *d, size_t dlen);

/*
OtherName ::= SEQUENCE {
	type-id		OBJECT IDENTIFIER, -- known oid from x509_rdn_oid such as OID_at_common_name, or oid nodes
	value		[0] EXPLICIT ANY DEFINED BY type-id }
*/
int x509_other_name_to_der(
	const uint32_t *nodes, size_t nodes_count,
	const uint8_t *value, size_t value_len,
	uint8_t **out, size_t *outlen);
int x509_other_name_from_der(
	uint32_t *nodes, size_t *nodes_count,
	const uint8_t **value, size_t *valuelen,
	const uint8_t **in, size_t *inlen);
int x509_other_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
EDIPartyName ::= SEQUENCE {
	nameAssigner	[0] EXPLICIT DirectoryString OPTIONAL,
	partyName	[1] EXPLICIT DirectoryString }
*/
int x509_edi_party_name_to_der(
	int assigner_tag, const uint8_t *assigner, size_t assigner_len,
	int party_name_tag, const uint8_t *party_name, size_t party_name_len,
	uint8_t **out, size_t *outlen);
int x509_edi_party_name_from_der(
	int *assigner_tag, const uint8_t **assigner, size_t *assigner_len,
	int *party_name_tag, const uint8_t **party_name, size_t *party_name_len,
	const uint8_t **in, size_t *inlen);
int x509_edi_party_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
GeneralName ::= CHOICE {
	otherName			[0] IMPLICIT OtherName,	-- Only in GeneralName
	rfc822Name			[1] IMPLICIT IA5String,
	dNSName				[2] IMPLICIT IA5String,
	x400Address			[3] IMPLICIT ORAddress,
	directoryName			[4] IMPLICIT Name,	-- SEQENCE OF
	ediPartyName			[5] IMPLICIT EDIPartyName, -- Only in GeneralName
	uniformResourceIdentifier	[6] IMPLICIT IA5String,
	iPAddress			[7] IMPLICIT OCTET STRING, -- 4 bytes or string?
	registeredID			[8] IMPLICIT OBJECT IDENTIFIER }
*/
typedef enum {
	X509_gn_other_name = 0,
	X509_gn_rfc822_name = 1,
	X509_gn_dns_name = 2,
	X509_gn_x400_address = 3,
	X509_gn_directory_name = 4,
	X509_gn_edi_party_name = 5,
	X509_gn_uniform_resource_identifier = 6,
	X509_gn_ip_address = 7,
	X509_gn_registered_id = 8,
} X509_GENERAL_NAME_CHOICE;

int x509_general_name_to_der(int choice, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_general_name_from_der(int *choice, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int x509_general_name_print(FILE *fp, int fmt, int ind, const char *label, int choice, const uint8_t *d, size_t dlen);

/*
GeneralNames ::= SEQUENCE OF GeneralName
*/
#define x509_general_names_to_der(d,dlen,out,outlen) asn1_sequence_to_der(d,dlen,out,outlen)
#define x509_general_names_from_der(d,dlen,in,inlen) asn1_sequence_from_der(d,dlen,in,inlen)
int x509_general_names_add_general_name(uint8_t *gns, size_t *gnslen, size_t maxlen,
	int choice, const uint8_t *d, size_t dlen);
int x509_general_names_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_general_names_add_other_name(uint8_t *gns, size_t *gnslen, size_t maxlen,
	const uint32_t *nodes, size_t nodes_count,
	const uint8_t *value, size_t value_len);
#define x509_general_names_add_rfc822_name(a,alen,maxlen,s) x509_general_names_add_general_name(a,alen,maxlen,X509_gn_rfc822_name,(uint8_t*)s,strlen(s))
#define x509_general_names_add_dns_name(a,alen,maxlen,s) x509_general_names_add_general_name(a,alen,maxlen,X509_gn_dns_name,(uint8_t*)s,strlen(s))
#define x509_general_names_add_x400_address(a,alen,maxlen,d,dlen) x509_general_names_add_general_name(a,alen,maxlen,X509_gn_x400_address,d,dlen)
#define x509_general_names_add_directory_name(a,alen,maxlen,d,dlen) x509_general_names_add_general_name(a,alen,maxlen,X509_gn_directory_name,d,dlen)
int x509_general_names_add_edi_party_name(uint8_t *gns, size_t *gnslen, size_t maxlen,
	int assigner_tag, const uint8_t *assigner, size_t assigner_len,
	int party_name_tag, const uint8_t *party_name, size_t party_name_len);
#define x509_general_names_add_uniform_resource_identifier(a,alen,maxlen,s) x509_general_names_add_general_name(a,alen,maxlen,X509_gn_uniform_resource_identifier,(uint8_t*)s,strlen(s))
#define x509_general_names_add_ip_address(a,alen,maxlen,s) x509_general_names_add_general_name(a,alen,maxlen,X509_gn_ip_address,(uint8_t*)s,strlen(s))
int x509_general_names_add_registered_id(uint8_t *gns, size_t *gnslen, size_t maxlen,
	const uint32_t *nodes, size_t nodes_cnt);

int x509_uri_as_general_names_to_der_ex(int tag, const char *uri, size_t urilen, uint8_t **out, size_t *outlen);
#define x509_uri_as_general_names_to_der(uri,urilen,out,outlen) x509_uri_as_general_names_to_der_ex(ASN1_TAG_SEQUENCE,uri,urilen,out,outlen)

/*
AuthorityKeyIdentifier ::= SEQUENCE {
	keyIdentifier			[0] IMPLICIT OCTET STRING OPTIONAL,
	authorityCertIssuer		[1] IMPLICIT GeneralNames OPTIONAL,
	authorityCertSerialNumber	[2] IMPLICIT INTEGER OPTIONAL }
*/
int x509_authority_key_identifier_to_der(
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len,
	uint8_t **out, size_t *outlen);
int x509_authority_key_identifier_from_der(
	const uint8_t **keyid, size_t *keyid_len,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial, size_t *serial_len,
	const uint8_t **in, size_t *inlen);
int x509_authority_key_identifier_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
SubjectKeyIdentifier ::= OCTET STRING
*/
#define X509_SUBJECT_KEY_IDENTIFIER_MIN_LEN 16
#define X509_SUBJECT_KEY_IDENTIFIER_MAX_LEN 64

/*
KeyUsage ::= BIT STRING {
	digitalSignature	(0),
	nonRepudiation		(1), -- recent renamed contentCommitment
	keyEncipherment		(2),
	dataEncipherment	(3),
	keyAgreement		(4),
	keyCertSign		(5),
	cRLSign			(6),
	encipherOnly		(7),
	decipherOnly		(8) }
*/
#define X509_KU_DIGITAL_SIGNATURE	(1 << 0)
#define X509_KU_NON_REPUDIATION		(1 << 1)
#define X509_KU_KEY_ENCIPHERMENT	(1 << 2)
#define X509_KU_DATA_ENCIPHERMENT	(1 << 3)
#define X509_KU_KEY_AGREEMENT		(1 << 4)
#define X509_KU_KEY_CERT_SIGN		(1 << 5)
#define X509_KU_CRL_SIGN		(1 << 6)
#define X509_KU_ENCIPHER_ONLY		(1 << 7)
#define X509_KU_DECIPHER_ONLY		(1 << 8)

const char *x509_key_usage_name(int flag);
int x509_key_usage_from_name(int *flag, const char *name);
#define x509_key_usage_to_der(bits,out,outlen) asn1_bits_to_der(bits,out,outlen)
#define x509_key_usage_from_der(bits,in,inlen) asn1_bits_from_der(bits,in,inlen)
int x509_key_usage_check(int bits, int cert_type);
int x509_key_usage_print(FILE *fp, int fmt, int ind, const char *label, int bits);

/*
DisplayText ::= CHOICE {
	ia5String		IA5String	(SIZE (1..200)),
	visibleString		VisibleString	(SIZE (1..200)),
	bmpString		BMPString	(SIZE (1..200)),
	utf8String		UTF8String	(SIZE (1..200))
}
*/
#define X509_DISPLAY_TEXT_MIN_LEN 1
#define X509_DISPLAY_TEXT_MAX_LEN 200

int x509_display_text_check(int tag, const uint8_t *d, size_t dlen);
int x509_display_text_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_display_text_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int x509_display_text_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen);

/*
NoticeReference ::= SEQUENCE {
	organization	DisplayText,
	noticeNumbers	SEQUENCE OF INTEGER }

UserNotice ::= SEQUENCE {
        noticeRef	NoticeReference OPTIONAL,
        explicitText	DisplayText OPTIONAL }
*/
#define X509_MAX_NOTICE_NUMBERS	32

int x509_notice_reference_to_der(
	int org_tag, const uint8_t *org, size_t org_len,
	const int *notice_numbers, size_t notice_numbers_cnt,
	uint8_t **out, size_t *outlen);
int x509_notice_reference_from_der(
	int *org_tag, const uint8_t **org, size_t *org_len,
	int *notice_numbers, size_t *notice_numbers_cnt, size_t max_notice_numbers,
	const uint8_t **in, size_t *inlen);
int x509_notice_reference_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_user_notice_to_der(
	int notice_ref_org_tag, const uint8_t *notice_ref_org, size_t notice_ref_org_len,
	const int *notice_ref_notice_numbers, size_t notice_ref_notice_numbers_cnt,
	int explicit_text_tag, const uint8_t *explicit_text, size_t explicit_text_len,
	uint8_t **out, size_t *outlen);
int x509_user_notice_from_der(
	int *notice_ref_org_tag, const uint8_t **notice_ref_org, size_t *notice_ref_org_len,
	int *notice_ref_notice_numbers, size_t *notice_ref_notice_numbers_cnt, size_t max_notice_ref_notice_numbers,
	int *explicit_text_tag, const uint8_t **explicit_text, size_t *explicit_text_len,
	const uint8_t **in, size_t *inlen);
int x509_user_notice_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
PolicyQualifierInfo ::= SEQUENCE {
        policyQualifierId  PolicyQualifierId,
        qualifier          ANY DEFINED BY policyQualifierId }

id-qt
	OID_qt_cps
	OID_qt_unotice

	switch(policyQualifierId)
	case id-qt-cps		: qualifier ::= IA5String
	case id-qt-unotice	: qualifier ::= UserNotice
*/
const char *x509_qualifier_id_name(int oid);
int x509_qualifier_id_from_name(const char *name);
int x509_qualifier_id_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_qualifier_id_to_der(int oid, uint8_t **out, size_t *outlen);

int x509_policy_qualifier_info_to_der(
	int oid,
	const uint8_t *qualifier, size_t qualifier_len,
	uint8_t **out, size_t *outlen);
int x509_policy_qualifier_info_from_der(
	int *oid,
	const uint8_t **qualifier, size_t *qualifier_len,
	const uint8_t **in, size_t *inlen);
int x509_policy_qualifier_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

#define x509_policy_qualifier_infos_to_der(d,dlen,out,outlen) asn1_sequence_to_der(d,dlen,out,outlen)
#define x509_policy_qualifier_infos_from_der(d,dlen,in,ineln) asn1_sequence_from_der(d,dlen,in,inlen)
int x509_policy_qualifier_infos_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
PolicyInformation ::= SEQUENCE {
        policyIdentifier   CertPolicyId,
        policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }

CertPolicyId ::= OBJECT IDENTIFIER -- undefined

	OID_any_policy
*/
char *x509_cert_policy_id_name(int oid);
int x509_cert_policy_id_from_name(const char *name);
int x509_cert_policy_id_from_der(int *oid, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen);
int x509_cert_policy_id_to_der(int oid, const uint32_t *nodes, size_t nodes_cnt, uint8_t **out, size_t *outlen);

int x509_policy_information_to_der(
	int policy_oid, const uint32_t *policy_nodes, size_t policy_nodes_cnt,
	const uint8_t *qualifiers, size_t qualifiers_len,
	uint8_t **out, size_t *outlen);
int x509_policy_information_from_der(
	int *policy_oid, uint32_t *policy_nodes, size_t *policy_nodes_cnt,
	const uint8_t **qualifiers, size_t *qualifiers_len,
	const uint8_t **in, size_t *inlen);
int x509_policy_information_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
*/
int x509_certificate_policies_add_policy_information(uint8_t *d, size_t *dlen, size_t maxlen,
	int policy_oid, const uint32_t *policy_nodes, size_t policy_nodes_cnt,
	const uint8_t *qualifiers, size_t qualifiers_len);
int x509_certificate_policies_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
#define x509_certificate_policies_to_der(d,dlen,out,outlen) asn1_sequence_to_der(d,dlen,out,outlen)
#define x509_certificate_policies_from_der(d,dlen,in,inlen) asn1_sequence_from_der(d,dlen,in,inlen)

/*
PolicyMapping ::= SEQUENCE {
	issuerDomainPolicy	CertPolicyId, -- id-anyPolicy or other undefined
	subjectDomainPolicy	CertPolicyId }
*/
int x509_policy_mapping_to_der(
	int issuer_policy_oid, const uint32_t *issuer_policy_nodes, size_t issuer_policy_nodes_cnt,
	int subject_policy_oid, const uint32_t *subject_policy_nodes, size_t subject_policy_nodes_cnt,
	uint8_t **out, size_t *outlen);
int x509_policy_mapping_from_der(
	int *issuer_policy_oid, uint32_t *issuer_policy_nodes, size_t *issuer_policy_nodes_cnt,
	int *subject_policy_oid, uint32_t *subject_policy_nodes, size_t *subject_policy_nodes_cnt,
	const uint8_t **in, size_t *inlen);
int x509_policy_mapping_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
PolicyMappings ::= SEQUENCE OF PolicyMapping
*/
int x509_policy_mappings_add_policy_mapping(uint8_t *d, size_t *dlen, size_t maxlen,
	int issuer_policy_oid, const uint32_t *issuer_policy_nodes, size_t issuer_policy_nodes_cnt,
	int subject_policy_oid, const uint32_t *subject_policy_nodes, size_t subject_policy_nodes_cnt);
int x509_policy_mappings_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
#define x509_policy_mappings_to_der(d,dlen,out,outlen) asn1_sequence_to_der(d,dlen,out,outlen)
#define x509_policy_mappings_from_der(d,dlen,in,inlen) asn1_sequence_from_der(d,dlen,in,inlen)

/*
SubjectAltName ::= GeneralNames
*/
#define x509_subject_alt_name_print(fp,fmt,ind,label,d,dlen) x509_general_names_print(fp,fmt,ind,label,d,dlen)

/*
IssuerAltName ::= GeneralNames
*/
#define x509_issuer_alt_name_print(fp,fmt,ind,label,d,dlen) x509_general_names_print(fp,fmt,ind,label,d,dlen)

/*
SubjectDirectoryAttributes ::= SEQUENCE OF Attribute

Attribute ::= SEQUENCE {
	type		OBJECT IDENTIFIER,
	values		SET OF ANY }
*/
int x509_attribute_to_der(
	const uint32_t *nodes, size_t nodes_cnt,
	const uint8_t *values, size_t values_len,
	uint8_t **out, size_t *outlen);
int x509_attribute_from_der(
	int *oid, uint32_t *nodes, size_t *nodes_cnt,
	const uint8_t **values, size_t *values_len,
	const uint8_t **in, size_t *inlen);
int x509_attribute_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_attributes_add_attribute(uint8_t *d, size_t *dlen, size_t maxlen,
	const uint32_t *nodes, size_t nodes_cnt,
	const uint8_t *values, size_t values_len);
int x509_attributes_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
#define x509_attributes_to_der(d,dlen,out,outlen) asn1_sequence_to_der(d,dlen,out,outlen)
#define x509_attributes_from_der(d,dlen,in,inlen) asn1_sequence_from_der(d,dlen,in,inlen)

/*
BasicConstraints ::= SEQUENCE {
	cA			BOOLEAN DEFAULT FALSE,
	pathLenConstraint	INTEGER (0..MAX) OPTIONAL }
*/
#define X509_MAX_PATH_LEN_CONSTRAINT 6
int x509_basic_constraints_to_der(int ca, int path_len_cons, uint8_t **out, size_t *outlen);
int x509_basic_constraints_from_der(int *ca, int *path_len_cons, const uint8_t **in, size_t *inlen);
int x509_basic_constraints_check(int ca, int path_len_cons, int cert_type);
int x509_basic_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
GeneralSubtree ::= SEQUENCE {
	base		GeneralName,
	minimum		[0] IMPLICIT BaseDistance DEFAULT 0,
	maximum		[1] IMPLICIT BaseDistance OPTIONAL }

BaseDistance ::= INTEGER (0..MAX)
*/
int x509_general_subtree_to_der(
	int base_choice, const uint8_t *base, size_t base_len,
	int minimum, int maximum,
	uint8_t **out, size_t *outlen);
int x509_general_subtree_from_der(
	int *base_choice, const uint8_t **base, size_t *base_len,
	int *minimum, int *maximum,
	const uint8_t **in, size_t *inlen);
int x509_general_subtree_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
*/
int x509_general_subtrees_add_general_subtree(uint8_t *d, size_t *dlen, size_t maxlen,
	int base_choice, const uint8_t *base, size_t base_len,
	int minimum, int maximum);
int x509_general_subtrees_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
#define x509_general_subtrees_to_der(d,dlen,out,outlen) asn1_sequence_to_der(d,dlen,out,outlen)
#define x509_general_subtrees_from_der(d,dlen,in,inlen) asn1_sequence_from_der(d,dlen,in,inlen)

/*
NameConstraints ::= SEQUENCE {
	permittedSubtrees	[0] GeneralSubtrees OPTIONAL,
	excludedSubtrees	[1] GeneralSubtrees OPTIONAL }
*/
int x509_name_constraints_to_der(
	const uint8_t *permitted_subtrees, size_t permitted_subtrees_len,
	const uint8_t *excluded_subtrees, size_t excluded_subtrees_len,
	uint8_t **out, size_t *outlen);
int x509_name_constraints_from_der(
	const uint8_t **permitted_subtrees, size_t *permitted_subtrees_len,
	const uint8_t **excluded_subtrees, size_t *excluded_subtrees_len,
	const uint8_t **in, size_t *inlen);
int x509_name_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
PolicyConstraints ::= SEQUENCE {
	requireExplicitPolicy	[0] IMPLICIT SkipCerts OPTIONAL,
	inhibitPolicyMapping	[1] IMPLICIT SkipCerts OPTIONAL
}

SkipCerts ::= INTEGER (0..MAX)
*/
int x509_policy_constraints_to_der(int require_explicit_policy, int inhibit_policy_mapping, uint8_t **out, size_t *outlen);
int x509_policy_constraints_from_der(int *require_explicit_policy, int *inhibit_policy_mapping, const uint8_t **in, size_t *inlen);
int x509_policy_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

KeyPurposeId:
	OID_any_extended_key_usage
  id-kp
	OID_kp_server_auth
	OID_kp_client_auth
	OID_kp_code_signing
	OID_kp_email_protection
	OID_kp_time_stamping
	OID_kp_ocsp_signing
*/
#define X509_MAX_KEY_PURPOSES	7
const char *x509_key_purpose_name(int oid);
const char *x509_key_purpose_text(int oid);
int x509_key_purpose_from_name(const char *name);
int x509_key_purpose_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_key_purpose_to_der(int oid, uint8_t **out, size_t *outlen);

int x509_ext_key_usage_to_der(const int *oids, size_t oids_cnt, uint8_t **out, size_t *outlen);
int x509_ext_key_usage_from_der(int *oids, size_t *oids_cnt, size_t max_cnt, const uint8_t **in, size_t *inlen);
int x509_ext_key_usage_check(const int *oids, size_t oids_cnt, int cert_type);
int x509_ext_key_usage_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
ReasonFlags ::= BIT STRING {
	unused			(0),
	keyCompromise		(1),
	cACompromise		(2),
	affiliationChanged	(3),
	superseded		(4),
	cessationOfOperation	(5),
	certificateHold		(6),
	privilegeWithdrawn	(7),
	aACompromise		(8) }
*/
#define X509_RF_UNUSED			(1 << 0)
#define X509_RF_KEY_COMPROMISE		(1 << 1)
#define X509_RF_CA_COMPROMISE		(1 << 2)
#define X509_RF_AFFILIATION_CHANGED	(1 << 3)
#define X509_RF_SUPERSEDED		(1 << 4)
#define X509_RF_CESSATION_OF_OPERATION	(1 << 5)
#define X509_RF_CERTIFICATE_HOLD	(1 << 6)
#define X509_RF_PRIVILEGE_WITHDRAWN	(1 << 7)
#define X509_RF_AA_COMPROMISE		(1 << 8)

const char *x509_revoke_reason_flag_name(int flag);
int x509_revoke_reason_flag_from_name(int *flag, const char *name);
#define x509_revoke_reason_flags_to_der(bits,out,outlen) asn1_bits_to_der(bits,out,outlen)
#define x509_revoke_reason_flags_from_der(bits,in,inlen) asn1_bits_from_der(bits,in,inlen)
int x509_revoke_reason_flags_print(FILE *fp, int fmt, int ind, const char *label, int bits);

/*
DistributionPointName ::= CHOICE {
	fullName		[0] IMPLICIT GeneralNames, -- SEQUENCE OF
	nameRelativeToCRLIssuer	[1] IMPLICIT RelativeDistinguishedName } -- SET OF
*/
enum {
	X509_full_name = 0,
	X509_name_relative_to_crl_issuer = 1,
};

int x509_uri_as_distribution_point_name_to_der(const char *uri, size_t urilen, uint8_t **out, size_t *outlen);
int x509_distribution_point_name_from_der(int *choice, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int x509_uri_as_distribution_point_name_from_der(const char **uri, size_t *urilen, const uint8_t **in, size_t *inlen);
int x509_distribution_point_name_print(FILE *fp, int fmt, int ind, const char *label,const uint8_t *a, size_t alen);

int x509_uri_as_explicit_distribution_point_name_to_der(int index, const char *uri, size_t urilen, uint8_t **out, size_t *outlen);
int x509_uri_as_explicit_distribution_point_name_from_der(int index, const char **uri, size_t *urilen, const uint8_t **in, size_t *inlen);

/*
DistributionPoint ::= SEQUENCE {
	distributionPoint	[0] EXPLICIT DistributionPointName OPTIONAL,
	reasons			[1] IMPLICIT ReasonFlags OPTIONAL,
	cRLIssuer		[2] IMPLICIT GeneralNames OPTIONAL }
*/
int x509_uri_as_distribution_point_to_der(const char *uri, size_t urilen,
	int reasons, const uint8_t *crl_issuer, size_t crl_issuer_len,
	uint8_t **out, size_t *outlen);
int x509_uri_as_distribution_point_from_der(const char **uri, size_t *urilen,
	int *reasons, const uint8_t **crl_issuer, size_t *crl_issuer_len,
	const uint8_t **in, size_t *inlen);
int x509_distribution_point_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
DistributionPoints ::= SEQUENCE OF DistributionPoint
*/
int x509_uri_as_distribution_points_to_der(const char *uri, size_t urilen,
	int reasons, const uint8_t *crl_issuer, size_t crl_issuer_len,
	uint8_t **out, size_t *outlen);
int x509_uri_as_distribution_points_from_der(const char **uri, size_t *urilen,
	int *reasons, const uint8_t **crl_issuer, size_t *crl_issuer_len,
	const uint8_t **in, size_t *inlen);
int x509_distribution_points_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


/*
CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
*/
#define x509_crl_distribution_points_to_der(d,dlen,out,outlen) x509_distribution_points_to_der(d,dlen,out,outlen)
#define x509_crl_distribution_points_from_der(d,dlen,in,inlen) x509_distribution_points_from_der(d,dlen,in,inlen)
#define x509_crl_distribution_points_print(fp,fmt,ind,label,d,dlen) x509_distribution_points_print(fp,fmt,ind,label,d,dlen)


/*
InhibitAnyPolicy ::= SkipCerts
SkipCerts ::= INTEGER (0..MAX)
*/
#define x509_inhibit_any_policy_to_der(val,out,outlen) asn1_int_to_der(val,out,outlen)
#define x509_inhibit_any_policy_from_der(val,in,inlen) asn1_int_from_der(val,in,inlen)

/*
FreshestCRL ::= CRLDistributionPoints
 */
#define x509_freshest_crl_to_der(d,dlen,out,outlen) x509_crl_distribution_points_to_der(d,dlen,out,outlen)
#define x509_freshest_crl_from_der(d,dlen,in,inlen) x509_crl_distribution_points_from_der(d,dlen,in,inlen)
#define x509_freshest_crl_print(fp,fmt,ind,label,d,dlen) x509_crl_distribution_points_print(fp,fmt,ind,label,d,dlen)

/*
Netscape-Defined Certificate Extensions
https://docs.oracle.com/cd/E19957-01/816-5533-10/ext.htm#1023061

NetscapeCertType ::= BIT STRING

	bit 0: SSL Client certificate
	bit 1: SSL Server certificate
	bit 2: S/MIME certificate
	bit 3: Object-signing certificate
	bit 4: Reserved for future use
	bit 5: SSL CA certificate
	bit 6: S/MIME CA certificate
	bit 7: Object-signing CA certificate

NetscapeCertComment ::= IA5String
*/
int x509_netscape_cert_type_print(FILE *fp, int fmt, int ind, const char *label, int bits);

int x509_exts_check(const uint8_t *exts, size_t extslen, int cert_type,
	int *path_len_constraints);

/*
AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription

AccessDescription ::= SEQUENCE {
	accessMethod	OBJECT IDENTIFIER,
	accessLocation	GeneralName }

accessMethods:
	OID_ad_ca_issuers
	OID_ad_ocsp
*/
const char *x509_access_method_name(int oid);
int x509_access_method_from_name(const char *name);
int x509_access_method_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_access_method_from_der(int *oid, const uint8_t **in, size_t *inlen);

int x509_access_description_to_der(int oid, const char *uri, size_t urilen, uint8_t **out, size_t *outlen);
int x509_access_description_from_der(int *oid, const char **uri, size_t *urilen, const uint8_t **in, size_t *inlen);
int x509_access_description_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_authority_info_access_to_der(
	const char *ca_issuers_uri, size_t ca_issuers_urilen,
	const char *ocsp_uri, size_t ocsp_urilen,
	uint8_t **out, size_t *outlen);
int x509_authority_info_access_from_der(
	const char **ca_issuers_uri, size_t *ca_issuers_urilen,
	const char **ocsp_uri, size_t *ocsp_urilen,
	const uint8_t **in, size_t *inlen);
int x509_authority_info_access_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


#ifdef __cplusplus
}
#endif
#endif

