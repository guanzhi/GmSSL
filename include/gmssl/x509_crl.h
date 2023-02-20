/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_X509_CRL_H
#define GMSSL_X509_CRL_H


#include <time.h>
#include <stdint.h>
#include <gmssl/sm2.h>


#ifdef __cplusplus
extern "C" {
#endif


/*
CRLReason ::= ENUMERATED
*/
typedef enum {
	X509_cr_unspecified = 0,
	X509_cr_key_compromise = 1,
	X509_cr_ca_compromise = 2 ,
	X509_cr_affiliation_changed = 3,
	X509_cr_superseded = 4,
	X509_cr_cessation_of_operation = 5,
	X509_cr_certificate_hold = 6,
	X509_cr_not_assigned = 7,
	X509_cr_remove_from_crl = 8,
	X509_cr_privilege_withdrawn = 9,
	X509_cr_aa_compromise = 10,
} X509_CRL_REASON;

const char *x509_crl_reason_name(int reason);
int x509_crl_reason_from_name(int *reason, const char *name);
int x509_crl_reason_to_der(int reason, uint8_t **out, size_t *outlen);
int x509_crl_reason_from_der(int *reason, const uint8_t **in, size_t *inlen);
int x509_implicit_crl_reason_from_der(int index, int *reason, const uint8_t **in, size_t *inlen);

/*
CRL Entry Extensions:
	OID_ce_crl_reasons		ENUMERATED		non-critical
	OID_ce_invalidity_date		GeneralizedTime		non-critical
	OID_ce_certificate_issuer	GeneralNames		MUST critical
*/
const char *x509_crl_entry_ext_id_name(int oid);
int x509_crl_entry_ext_id_from_name(const char *name);
int x509_crl_entry_ext_id_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_crl_entry_ext_id_from_der(int *oid, const uint8_t **in, size_t *inlen);

int x509_crl_entry_ext_to_der(int oid, int critical, const uint8_t *val, size_t vlen, uint8_t **out, size_t *outlen);
int x509_crl_entry_ext_from_der(int *oid, int *critical, const uint8_t **val, size_t *vlen, const uint8_t **in, size_t *inlen);
int x509_crl_entry_ext_critical_check(int oid, int critical);
int x509_crl_entry_ext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_crl_reason_ext_to_der(int critical, int reason, uint8_t **out, size_t *outlen);
int x509_invalidity_date_ext_to_der(int critical, time_t date, uint8_t **out, size_t *outlen);
int x509_cert_issuer_ext_to_der(int critical, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_crl_entry_ext_from_der_ex(int *oid, int *critical,
	int *reason, time_t *invalid_date, const uint8_t **cert_issuer, size_t *cert_issuer_len,
	const uint8_t **in, size_t *inlen);

int x509_crl_entry_exts_to_der(
	int reason, time_t invalid_date, const uint8_t *cert_issuer, size_t cert_issuer_len,
	uint8_t **out, size_t *outlen);
int x509_crl_entry_exts_from_der(
	int *reason, time_t *invalid_date, const uint8_t **cert_issuer, size_t *cert_issuer_len,
	const uint8_t **in, size_t *inlen);
int x509_crl_entry_exts_get(const uint8_t *d, size_t dlen,
	int *reason, time_t *invalid_date, const uint8_t **cert_issuer, size_t *cert_issuer_len);
int x509_crl_entry_exts_check(const uint8_t *d, size_t dlen);
int x509_crl_entry_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
RevokedCertificate ::= SEQUENCE {
	userCertificate		CertificateSerialNumber,
	revocationDate		Time,
	crlEntryExtensions	Extensions OPTIONAL }
*/
int x509_revoked_cert_to_der(
	const uint8_t *serial, size_t serial_len, time_t revoke_date,
	const uint8_t *crl_entry_exts, size_t crl_entry_exts_len,
	uint8_t **out, size_t *outlen);
int x509_revoked_cert_from_der(
	const uint8_t **serial, size_t *serial_len, time_t *revoke_date,
	const uint8_t **crl_entry_exts, size_t *crl_entry_exts_len,
	const uint8_t **in, size_t *inlen);
int x509_revoked_cert_to_der_ex(
	const uint8_t *serial, size_t serial_len, time_t revoke_date,
	int reason, time_t invalid_date, const uint8_t *cert_issuer, size_t cert_issuer_len,
	uint8_t **out, size_t *outlen);
int x509_revoked_cert_from_der_ex(
	const uint8_t **serial, size_t *serial_len, time_t *revoke_date,
	int *reason, time_t *invalid_date, const uint8_t **cert_issuer, size_t *cert_issuer_len,
	const uint8_t **in, size_t *inlen);
int x509_revoked_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_cert_revoke_to_der(const uint8_t *cert, size_t certlen,
	time_t revoke_date, int reason, time_t invalid_date, const uint8_t *cert_issuer, size_t cert_issuer_len,
	uint8_t **out, size_t *outlen);

/*
RevokedCertificates ::= SEQUENCE OF RevokedCertificate
*/
int x509_revoked_certs_find_revoked_cert_by_serial_number(const uint8_t *d, size_t dlen,
	const uint8_t *serial, size_t serial_len, time_t *revoke_date,
	const uint8_t **crl_entry_exts, size_t *crl_entry_exts_len);
int x509_revoked_certs_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
CRL Extensions:
	OID_ce_authority_key_identifier		AuthorityKeyIdentifier		critical or non-critical
	OID_ce_issuer_alt_name			GeneralNames			SHOULD non-critical
	OID_ce_crl_number			INTEGER				MUST non-critical
	OID_ce_delta_crl_indicator		INTEGER				MUST critical
	OID_ce_issuing_distribution_point	IssuingDistributionPoint	critical
	OID_ce_freshest_crl			CRLDistributionPoints		MUST non-critical
	OID_pe_authority_info_access		AccessDescriptions		MUST non-critical
*/
const char *x509_crl_ext_id_name(int oid);
int x509_crl_ext_id_from_name(const char *name);
int x509_crl_ext_id_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_crl_ext_id_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_crl_ext_id_from_der_ex(int *oid, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen);

/*
IssuingDistributionPoint ::= SEQUENCE {
	distributionPoint		[0] EXPLICIT DistributionPointName OPTIONAL,
	onlyContainsUserCerts		[1] IMPLICIT BOOLEAN DEFAULT FALSE,
	onlyContainsCACerts		[2] IMPLICIT BOOLEAN DEFAULT FALSE,
	onlySomeReasons			[3] IMPLICIT ReasonFlags OPTIONAL,
	indirectCRL			[4] IMPLICIT BOOLEAN DEFAULT FALSE,
	onlyContainsAttributeCerts	[5] IMPLICIT BOOLEAN DEFAULT FALSE }
*/
int x509_issuing_distribution_point_to_der(
	const char *dist_point_uri, size_t dist_point_uri_len,
	int only_contains_user_certs,
	int only_contains_ca_certs,
	int only_some_reasons,
	int indirect_crl,
	int only_contains_attr_certs,
	uint8_t **out, size_t *outlen);
int x509_issuing_distribution_point_from_der(
	int *dist_point_choice, const uint8_t **dist_point, size_t *dist_point_len,
	int *only_contains_user_certs,
	int *only_contains_ca_certs,
	int *only_some_reasons,
	int *indirect_crl,
	int *only_contains_attr_certs,
	const uint8_t **in, size_t *inlen);
int x509_issuing_distribution_point_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_crl_ext_to_der(int oid, int critical, const uint8_t *val, size_t vlen, uint8_t **out, size_t *outlen);
int x509_crl_ext_from_der_ex(int *oid, uint32_t *nodes, size_t *nodes_cnt,
	int *critical, const uint8_t **val, size_t *vlen,
	const uint8_t **in, size_t *inlen);
int x509_crl_ext_critical_check(int oid, int critical);
int x509_crl_ext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


int x509_crl_exts_add_authority_key_identifier(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len);
int x509_crl_exts_add_default_authority_key_identifier(uint8_t *exts, size_t *extslen, size_t maxlen,
	const SM2_KEY *public_key);
int x509_crl_exts_add_issuer_alt_name(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *d, size_t dlen);
int x509_crl_exts_add_crl_number_ex(
 	uint8_t *exts, size_t *extslen, size_t maxlen,
	int oid, int critical, int num);
int x509_crl_exts_add_crl_number(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	int num);
int x509_crl_exts_add_delta_crl_indicator(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	int num);
int x509_crl_exts_add_issuing_distribution_point(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const char *dist_point_uri, size_t dist_point_uri_len,
	int only_contains_user_certs,
	int only_contains_ca_certs,
	int only_some_reasons,
	int indirect_crl,
	int only_contains_attr_certs);
int x509_crl_exts_add_freshest_crl(
	uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const char *http_uri, size_t http_urilen,
	const char *ldap_uri, size_t ldap_urilen);
int x509_crl_exts_add_authority_info_acess(
	uint8_t *exts, size_t *extslen, size_t maxlen, int critical,
	const char *ca_issuers_uri, size_t ca_issuers_urilen,
	const char *ocsp_uri, size_t ocsp_urilen);

#define x509_crl_exts_to_der(d,dlen,out,outlen) x509_explicit_exts_to_der(0,d,dlen,out,outlen)
#define x509_crl_exts_from_der(d,dlen,in,inlen) x509_explicit_exts_from_der(0,d,dlen,in,inlen)
int x509_crl_exts_check(const uint8_t *d, size_t dlen);
int x509_crl_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
TBSCertList ::= SEQUENCE {
	version			INTEGER OPTIONAL, -- if present, MUST be v2
	signature		AlgorithmIdentifier,
	issuer			Name,
	thisUpdate		Time,
	nextUpdate		Time OPTIONAL,
	revokedCertificates	RevokedCertificates OPTIONAL,
	crlExtensions		[0] EXPLICIT Extensions OPTIONAL, -- if present, MUST be v2 }
*/
int x509_tbs_crl_to_der(
	int version,
	int signature_algor,
	const uint8_t *issuer, size_t issuer_len,
	time_t this_update,
	time_t next_update,
	const uint8_t *revoked_certs, size_t revoked_certs_len,
	const uint8_t *exts, size_t exts_len,
	uint8_t **out, size_t *outlen);
int x509_tbs_crl_from_der(
	int *version,
	int *signature_algor,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update,
	time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	const uint8_t **exts, size_t *exts_len,
	const uint8_t **in, size_t *inlen);
int x509_tbs_crl_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
CertificateList ::= SEQUENCE {
	tbsCertList		TBSCertList,
	signatureAlgorithm	AlgorithmIdentifier,
	signatureValue		BIT STRING }
*/
int x509_crl_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen);
int x509_crl_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen);
int x509_crl_to_pem(const uint8_t *a, size_t alen, FILE *fp);
int x509_crl_from_pem(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp);
int x509_crl_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);


int x509_crl_sign_to_der(
	int version, int sig_alg,
	const uint8_t *issuer, size_t issuer_len,
	time_t this_update, time_t next_update,
	const uint8_t *revoked_certs, size_t revoked_certs_len,
	const uint8_t *crl_exts, size_t crl_exts_len,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len,
	uint8_t **out, size_t *outlen);
int x509_crl_from_der_ex(
	int *version,
	int *inner_sig_alg,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update, time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	const uint8_t **exts, size_t *exts_len,
	int *sig_alg, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen);
int x509_crl_check(const uint8_t *a, size_t alen, time_t now);
int x509_crl_verify(const uint8_t *a, size_t alen,
	const SM2_KEY *sign_pub_key, const char *signer_id, size_t signer_id_len);
int x509_crl_verify_by_ca_cert(const uint8_t *a, size_t alen, const uint8_t *cacert, size_t cacertlen,
	const char *signer_id, size_t signer_id_len);
int x509_crl_get_details(const uint8_t *crl, size_t crl_len,
	int *version,
	int *inner_sig_alg,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update,
	time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	const uint8_t **exts, size_t *exts_len,
	int *signature_algor,
	const uint8_t **sig, size_t *siglen);
int x509_crl_get_issuer(const uint8_t *crl, size_t crl_len,
	const uint8_t **issuer, size_t *issuer_len);
int x509_crl_get_revoked_certs(const uint8_t *a, size_t alen, const uint8_t **d, size_t *dlen);
int x509_crl_find_revoked_cert_by_serial_number(const uint8_t *a, size_t alen,
	const uint8_t *serial, size_t serial_len, time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len);

int x509_crls_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_crl_new_from_uri(uint8_t **crl, size_t *crl_len, const char *uri, size_t urilen);
int x509_crl_new_from_cert(uint8_t **crl, size_t *crl_len, const uint8_t *cert, size_t certlen);
int x509_cert_check_crl(const uint8_t *cert, size_t certlen, const uint8_t *cacert, size_t cacertlen,
	const char *ca_signer_id, size_t ca_signer_id_len);


#ifdef  __cplusplus
}
#endif
#endif
