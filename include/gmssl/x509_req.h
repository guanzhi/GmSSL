/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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
int x509_request_to_der(
	int version,
	const uint8_t *subject, size_t subject_len,
	const SM2_KEY *subject_public_key,
	const uint8_t *attrs, size_t attrs_len,
	int signature_algor,
	const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen);
int x509_request_from_der(
	int *version,
	const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key,
	const uint8_t **attrs, size_t *attrs_len,
	int *signature_algor,
	const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen);
int x509_request_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int x509_req_sign(uint8_t *req, size_t *reqlen, size_t maxlen,
	int version,
	const uint8_t *subject, size_t subject_len,
	const SM2_KEY *subject_public_key,
	const uint8_t *attrs, size_t attrs_len,
	int signature_algor,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len);
int x509_req_verify(const uint8_t *req, size_t reqlen,
	const SM2_KEY *sign_pubkey, const char *signer_id, size_t signer_id_len);
int x509_req_get_details(const uint8_t *req, size_t reqlen,
	int *verison,
	const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key,
	const uint8_t **attributes, size_t *attributes_len,
	int *signature_algor,
	const uint8_t **signature, size_t *signature_len);
int x509_req_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *req, size_t reqlen);
int x509_req_to_pem(const uint8_t *req, size_t reqlen, FILE *fp);
int x509_req_from_pem(uint8_t *req, size_t *reqlen, size_t maxlen, FILE *fp);


#ifdef __cplusplus
}
#endif
#endif
