/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_X509_ALG_H
#define GMSSL_X509_ALG_H


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

/*
AlgorithmIdentifier ::= SEQUENCE {
	algorithm	OBJECT IDENTIFIER,
	parameters	ANY }
*/

const char *x509_digest_algor_name(int oid);
int x509_digest_algor_from_name(const char *name);
int x509_digest_algor_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_digest_algor_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_digest_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

const char *x509_encryption_algor_name(int oid);
int x509_encryption_algor_from_name(const char *name);
int x509_encryption_algor_from_der(int *oid, const uint8_t **iv, size_t *ivlen, const uint8_t **in, size_t *inlen);
int x509_encryption_algor_to_der(int oid, const uint8_t *iv, size_t ivlen, uint8_t **out, size_t *outlen);
int x509_encryption_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

const char *x509_signature_algor_name(int oid);
int x509_signature_algor_from_name(const char *name);
int x509_signature_algor_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_signature_algor_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_signature_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

const char *x509_public_key_encryption_algor_name(int oid);
int x509_public_key_encryption_algor_from_name(const char *name);
int x509_public_key_encryption_algor_from_der(int *oid, const uint8_t **params, size_t *params_len, const uint8_t **in, size_t *inlen);
int x509_public_key_encryption_algor_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_public_key_encryption_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

const char *x509_public_key_algor_name(int oid);
int x509_public_key_algor_from_name(const char *name);
int x509_public_key_algor_to_der(int oid, int curve, uint8_t **out, size_t *outlen);
int x509_public_key_algor_from_der(int *oid, int *curve_or_null, const uint8_t **in, size_t *inlen);
int x509_public_key_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);



#ifdef __cplusplus
}
#endif
#endif
