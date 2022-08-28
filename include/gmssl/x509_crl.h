/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_X509_CRL_H
#define GMSSL_X509_CRL_H


#ifdef __cplusplus
extern "C" {
#endif

/*
X509 CRL Public API


*/



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

/*
CRL Entry Extensions:
	OID_ce_crl_reasons		ENUMERATED
	OID_ce_invalidity_date		GeneralizedTime
	OID_ce_certificate_issuer	SEQUENCE		GeneralNames
*/
const char *x509_crl_entry_ext_id_name(int oid);
int x509_crl_entry_ext_id_from_name(const char *name);
int x509_crl_entry_ext_id_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_crl_entry_ext_id_from_der(int *oid, const uint8_t **in, size_t *inlen);

int x509_crl_entry_exts_add_reason(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	int reason);
int x509_crl_entry_exts_add_invalidity_date(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	time_t tv);
int x509_crl_entry_exts_add_certificate_issuer(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *d, size_t dlen);
#define x509_crl_entry_exts_to_der(d,dlen,out,outlen) asn1_sequence_to_der(d,dlen,out,outlen)
#define x509_crl_entry_exts_from_der(d,dlen,in,inlen) asn1_sequence_from_der(d,dlen,in,inlen)
int x509_crl_entry_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
RevokedCertificate ::= SEQUENCE {
	userCertificate		CertificateSerialNumber,
	revocationDate		Time,
	crlEntryExtensions	Extensions OPTIONAL }
*/
int x509_revoked_cert_to_der(
	const uint8_t *serial, size_t serial_len,
	time_t revoke_date,
	const uint8_t *entry_exts, size_t entry_exts_len,
	uint8_t **out, size_t *outlen);
int x509_revoked_cert_from_der(
	const uint8_t **serial, size_t *serial_len,
	time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len,
	const uint8_t **in, size_t *inlen);
int x509_revoked_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
RevokedCertificates ::= SEQUENCE OF RevokedCertificate
*/
int x509_revoked_certs_add_revoked_cert(uint8_t *d, size_t *dlen, size_t maxlen,
	const uint8_t *serial, size_t serial_len,
	time_t revoke_date,
	const uint8_t *entry_exts, size_t entry_exts_len);
int x509_revoked_certs_get_revoked_cert_by_serial_number(const uint8_t *d, size_t dlen,
	const uint8_t *serial, size_t serial_len,
	time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len);
#define x509_revoked_certs_to_der(d,dlen,out,outlen) asn1_sequence_to_der(d,dlen,out,outlen)
#define x509_revoked_certs_from_der(d,dlen,in,inlen) asn1_sequence_from_der(d,dlen,in,inlen)
int x509_revoked_certs_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
CRL Extensions:
	OID_ce_authority_key_identifier		SEQUENCE	AuthorityKeyIdentifier
	OID_ce_issuer_alt_name			SEQUENCE	GeneralNames
	OID_ce_crl_number			INTEGER
	OID_ce_delta_crl_indicator		INTEGER
	OID_ce_issuing_distribution_point	SEQUENCE	IssuingDistributionPoint
*/
const char *x509_crl_ext_id_name(int oid);
int x509_crl_ext_id_from_name(const char *name);
int x509_crl_ext_id_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_crl_ext_id_from_der(int *oid, const uint8_t **in, size_t *inlen);


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
	int dist_point_choice, const uint8_t *dist_point, size_t dist_point_len,
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

int x509_crl_exts_add_authority_key_identifier(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len);
int x509_crl_exts_add_issuer_alt_name(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *d, size_t dlen);
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
	const uint8_t *dist_point, size_t dist_point_len,
	int only_contains_user_certs,
	int only_contains_ca_certs,
	int only_some_reasons,
	int indirect_crl,
	int only_contains_attr_certs);

#define x509_crl_exts_to_der(d,dlen,out,outlen) x509_explicit_exts_to_der(0,d,dlen,out,outlen)
#define x509_crl_exts_from_der(d,dlen,in,inlen) x509_explicit_exts_from_der(0,d,dlen,in,inlen)
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
int x509_cert_list_to_der(const uint8_t *tbs_crl, size_t tbs_crl_len,
	int signature_algor, const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen);
int x509_cert_list_from_der(const uint8_t **tbs_crl, size_t *tbs_crl_len,
	int *signature_algor, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen);
int x509_cert_list_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

// x509_crl_ functions
int x509_crl_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen);
int x509_crl_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen);
int x509_crl_to_pem(const uint8_t *a, size_t alen, FILE *fp);
int x509_crl_from_pem(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp);
int x509_crl_to_fp(const uint8_t *a, size_t alen, FILE *fp); // 去掉这个函数
int x509_crl_from_fp(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp); // 去掉这个函数


int x509_crl_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);

int x509_crl_sign(uint8_t *crl, size_t *crl_len,
	int version,
	int signature_algor,
	const uint8_t *issuer, size_t issuer_len,
	time_t this_update,
	time_t next_update,
	const uint8_t *revoked_certs, size_t revoked_certs_len,
	const uint8_t *exts, size_t exts_len,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len);
int x509_crl_verify(const uint8_t *a, size_t alen,
	const SM2_KEY *sign_pub_key, const char *signer_id, size_t signer_id_len);
int x509_crl_verify_by_ca_cert(const uint8_t *a, size_t alen, const uint8_t *cacert, size_t cacertlen,
	const char *signer_id, size_t signer_id_len);

int x509_crl_get_details(const uint8_t *crl, size_t crl_len,
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update,
	time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	const uint8_t **exts, size_t *exts_len,
	int *signature_algor,
	const uint8_t **sig, size_t *siglen);
int x509_crl_get_issuer(const uint8_t *crl, size_t crl_len,
	const uint8_t **issuer, size_t *issuer_len);

int x509_crl_find_revoked_cert_by_serial_number(const uint8_t *a, size_t alen,
	const uint8_t *serial, size_t serial_len, time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len);



int x509_crls_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

#ifdef  __cplusplus
}
#endif
#endif
