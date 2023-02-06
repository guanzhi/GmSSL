/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_X509_REQ_H
#define GMSSL_X509_REQ_H


#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
from RFC 2986

CertificationRequestInfo ::= SEQUENCE {
	version                   INTEGER { v1(0) },
	subject                   Name,
	subjectPKInfo             SubjectPublicKeyInfo,
	attributes                [0] IMPLICIT SET OF Attribute }
*/
int x509_request_info_to_der(int version, const uint8_t *subject, size_t subject_len,
	const SM2_KEY *subject_public_key, const uint8_t *attrs, size_t attrs_len,
	uint8_t **out, size_t *outlen);
int x509_request_info_from_der(int *version, const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key, const uint8_t **attrs, size_t *attrs_len,
	const uint8_t **in, size_t *inlen);
int x509_request_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
CertificationRequest ::= SEQUENCE {
	certificationRequestInfo  CertificationRequestInfo,
	signatureAlgorithm        AlgorithmIdentifier,
	signature                 BIT STRING }
*/
int x509_req_sign_to_der(
	int version,
	const uint8_t *subject, size_t subject_len,
	const SM2_KEY *subject_public_key,
	const uint8_t *attrs, size_t attrs_len,
	int signature_algor,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len,
	uint8_t **out, size_t *outlen);
int x509_req_verify(const uint8_t *req, size_t reqlen,
	const char *signer_id, size_t signer_id_len);
int x509_req_get_details(const uint8_t *req, size_t reqlen,
	int *verison,
	const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key,
	const uint8_t **attributes, size_t *attributes_len,
	int *signature_algor,
	const uint8_t **signature, size_t *signature_len);
int x509_req_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen);
int x509_req_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen);
int x509_req_to_pem(const uint8_t *req, size_t reqlen, FILE *fp);
int x509_req_from_pem(uint8_t *req, size_t *reqlen, size_t maxlen, FILE *fp);
int x509_req_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *req, size_t reqlen);

int x509_req_new_from_pem(uint8_t **req, size_t *reqlen, FILE *fp);
int x509_req_new_from_file(uint8_t **req, size_t *reqlen, const char *file);


#ifdef __cplusplus
}
#endif
#endif
