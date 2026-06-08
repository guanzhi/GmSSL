/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License);
 *  you may not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_OCSP_H
#define GMSSL_OCSP_H


#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_alg.h>
#include <gmssl/digest.h>


#ifdef __cplusplus
extern "C" {
#endif




/*
CertID ::= SEQUENCE {
	hashAlgorithm			AlgorithmIdentifier,
	issuerNameHash			OCTET STRING,
	issuerKeyHash			OCTET STRING,
	serialNumber			CertificateSerialNumber }

Request ::= SEQUENCE {
	reqCert				CertID,
	singleRequestExtensions		[0] EXPLICIT Extensions OPTIONAL }
*/
int ocsp_request_item_to_der(int hash_algor,
	const uint8_t *issuer_name_hash, size_t issuer_name_hash_len,
	const uint8_t *issuer_key_hash, size_t issuer_key_hash_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *single_request_exts, size_t single_request_exts_len,
	uint8_t **out, size_t *outlen);
int ocsp_request_item_from_der(int *hash_algor,
	const uint8_t **issuer_name_hash, size_t *issuer_name_hash_len,
	const uint8_t **issuer_key_hash, size_t *issuer_key_hash_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **single_request_exts, size_t *single_request_exts_len,
	const uint8_t **in, size_t *inlen);
int ocsp_request_item_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen);

/*
TBSRequest ::= SEQUENCE {
	version				[0] EXPLICIT Version DEFAULT v1,
	requestorName			[1] EXPLICIT GeneralName OPTIONAL,
	requestList			SEQUENCE OF Request,
	requestExtensions		[2] EXPLICIT Extensions OPTIONAL }

Signature ::= SEQUENCE {
	signatureAlgorithm		AlgorithmIdentifier,
	signature			BIT STRING,
	certs				[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

OCSPRequest ::= SEQUENCE {
	tbsRequest			TBSRequest,
	optionalSignature		[0] EXPLICIT Signature OPTIONAL }
*/
int ocsp_request_to_der(int version,
	const uint8_t *requestor_name, size_t requestor_name_len,
	const uint8_t *request_list, size_t request_list_len,
	const uint8_t *request_exts, size_t request_exts_len,
	const uint8_t *optional_signature, size_t optional_signature_len,
	uint8_t **out, size_t *outlen);
int ocsp_request_from_der(int *version,
	const uint8_t **requestor_name, size_t *requestor_name_len,
	const uint8_t **request_list, size_t *request_list_len,
	const uint8_t **request_exts, size_t *request_exts_len,
	const uint8_t **optional_signature, size_t *optional_signature_len,
	const uint8_t **in, size_t *inlen);
int ocsp_request_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen);
int ocsp_request_generate(uint8_t *req, size_t *reqlen, size_t maxlen,
	const uint8_t *cert, size_t certlen,
	const uint8_t *issuer_cert, size_t issuer_certlen,
	const DIGEST *digest);


/*
SingleResponse ::= SEQUENCE {
	certID				CertID,
	certStatus			CertStatus,
	thisUpdate			GeneralizedTime,
	nextUpdate			[0] EXPLICIT GeneralizedTime OPTIONAL,
	singleExtensions		[1] EXPLICIT Extensions OPTIONAL }

CertStatus ::= CHOICE {
	good				[0] IMPLICIT NULL,
	revoked				[1] IMPLICIT RevokedInfo,
	unknown				[2] IMPLICIT UnknownInfo }

RevokedInfo ::= SEQUENCE {
	revocationTime			GeneralizedTime,
	revocationReason		[0] EXPLICIT CRLReason OPTIONAL }

UnknownInfo ::= NULL
*/
enum {
	OCSP_cert_status_good,
	OCSP_cert_status_revoked,
	OCSP_cert_status_unknown,
};

int ocsp_single_response_to_der(int hash_algor,
	const uint8_t *issuer_name_hash, size_t issuer_name_hash_len,
	const uint8_t *issuer_key_hash, size_t issuer_key_hash_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int cert_status, time_t revocation_time, int revocation_reason,
	time_t this_update, time_t next_update,
	const uint8_t *exts, size_t extslen,
	uint8_t **out, size_t *outlen);
int ocsp_single_response_from_der(int *hash_algor,
	const uint8_t **issuer_name_hash, size_t *issuer_name_hash_len,
	const uint8_t **issuer_key_hash, size_t *issuer_key_hash_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *cert_status, time_t *revocation_time, int *revocation_reason,
	time_t *this_update, time_t *next_update,
	const uint8_t **exts, size_t *extslen,
	const uint8_t **in, size_t *inlen);
int ocsp_single_response_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen);


/*
OCSPResponse ::= SEQUENCE {
	responseStatus			OCSPResponseStatus,
	responseBytes			[0] EXPLICIT ResponseBytes OPTIONAL }
*/



/*
OCSPResponseStatus ::= ENUMERATED {
	successful			(0),
	malformedRequest		(1),
	internalError			(2),
	tryLater			(3),
	sigRequired			(5),
	unauthorized			(6) }
*/
enum {
	OCSP_response_status_successful		= 0,
	OCSP_response_status_malformed_request	= 1,
	OCSP_response_status_internal_error	= 2,
	OCSP_response_status_try_later		= 3,
	OCSP_response_status_sig_required	= 5,
	OCSP_response_status_unauthorized	= 6,
};


#define OCSP_responder_id_by_name			1
#define OCSP_responder_id_by_key			2





/*
ResponseBytes ::= SEQUENCE {
	responseType			OBJECT IDENTIFIER,
	response			OCTET STRING }

id-pkix-ocsp-basic OBJECT IDENTIFIER ::= { id-ad-ocsp 1 }

BasicOCSPResponse ::= SEQUENCE {
	tbsResponseData			ResponseData,
	signatureAlgorithm		AlgorithmIdentifier,
	signature			BIT STRING,
	certs				[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

ResponseData ::= SEQUENCE {
	version				[0] EXPLICIT Version DEFAULT v1,
	responderID			ResponderID,
	producedAt			GeneralizedTime,
	responses			SEQUENCE OF SingleResponse,
	responseExtensions		[1] EXPLICIT Extensions OPTIONAL }

ResponderID ::= CHOICE {
	byName				[1] Name,
	byKey				[2] KeyHash }

KeyHash ::= OCTET STRING
*/



int ocsp_response_data_to_der(
	int responder_id_type, const uint8_t *responder_id, size_t responder_id_len,
	time_t produced_at,
	const uint8_t *single_response, size_t single_response_len,
	const uint8_t *response_exts, size_t response_exts_len,
	uint8_t **out, size_t *outlen);
int ocsp_response_data_from_der(
	int *responder_id_type, const uint8_t **responder_id, size_t *responder_id_len,
	time_t *produced_at,
	const uint8_t **single_response_first, size_t *single_response_first_len,
	const uint8_t **single_response_others, size_t *single_response_others_len,
	const uint8_t **response_exts, size_t *response_exts_len,
	const uint8_t **in, size_t *inlen);
int ocsp_response_data_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen);


int ocsp_basic_response_to_der(
	const uint8_t *response_data, size_t response_data_len,
	int signature_algor,
	const uint8_t *signature, size_t signature_len,
	const uint8_t *certs, size_t certs_len,
	uint8_t **out, size_t *outlen);
int ocsp_basic_response_from_der(
	const uint8_t **response_data, size_t *response_data_len,
	int *signature_algor,
	const uint8_t **signature, size_t *signature_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **in, size_t *inlen);
int ocsp_basic_response_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen);


int ocsp_response_to_der(int response_status,
	const uint8_t *basic_response, size_t basic_response_len,
	uint8_t **out, size_t *outlen);
int ocsp_response_from_der(int *response_status,
	const uint8_t **basic_response, size_t *basic_response_len,
	const uint8_t **in, size_t *inlen);
int ocsp_response_print(FILE *fp, int fmt, int ind, const char *label,
	const uint8_t *d, size_t dlen);









/*
AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER

ServiceLocator ::= SEQUENCE {
	issuer				Name,
	locator				AuthorityInfoAccessSyntax OPTIONAL }

*/



/*
PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm

PreferredSignatureAlgorithm ::= SEQUENCE {
	sigIdentifier			AlgorithmIdentifier,
	certIdentifier			AlgorithmIdentifier OPTIONAL }

*/

















#ifdef __cplusplus
}
#endif
#endif
