/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

// RFC 5208: PKCS #8: Private-Key Information Syntax Specification version 1.2


#ifndef GMSSL_PKCS8_H
#define GMSSL_PKCS8_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/pem.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
id-PBKDF2 OBJECT IDENTIFIER ::= {pkcs-5 12}

PBKDF2-params ::= SEQUENCE {
	salt CHOICE {
		specified	OCTET STRING,
		otherSource	AlgorithmIdentifier {{PBKDF2-SaltSources}}
	},
	iterationCount		INTEGER (1..MAX),
	keyLength		INTEGER (1..MAX) OPTIONAL, -- 这个参数可以由函数指定
	prf			AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
}

prf must be OID_hmac_sm3
cipher must be OID_sm4_cbc
*/
int pbkdf2_params_to_der(const uint8_t *salt, size_t saltlen, int iter, int keylen, int prf,
	uint8_t **out, size_t *outlen);
int pbkdf2_params_from_der(const uint8_t **salt, size_t *saltlen, int *iter, int *keylen, int *prf,
	const uint8_t **in, size_t *inlen);
int pbkdf2_params_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int pbkdf2_algor_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen,
	int prf,
	uint8_t **out, size_t *outlen);
int pbkdf2_algor_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen,
	int *prf,
	const uint8_t **in, size_t *inlen);
int pbkdf2_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


/*
id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13}

PBES2-params ::= SEQUENCE {
	keyDerivationFunc	AlgorithmIdentifier {{PBES2-KDFs}}, -- id-PBKDF2
	encryptionScheme	AlgorithmIdentifier {{PBES2-Encs}}}

PBES2-Encs:
	AES-CBC-Pad [RFC2898]
	RC5-CBC-Pad
	DES-CBC-Pad		legacy
	DES-EDE3-CBC-Pad	legacy
	RC2-CBC-Pad		legacy
*/

int pbes2_enc_algor_to_der(
	int cipher,
	const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen);
int pbes2_enc_algor_from_der(
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen);
int pbes2_enc_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


int pbes2_params_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen);
int pbes2_params_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen);
int pbes2_params_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


int pbes2_algor_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen);
int pbes2_algor_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen);
int pbes2_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
from [RFC 5208]

EncryptedPrivateKeyInfo ::= SEQUENCE {
	encryptionAlgorithm	EncryptionAlgorithmIdentifier,
	encryptedData		OCTET STRING }

encryptionAlgorithm:
	id-PBES2

PrivateKeyInfo ::= SEQUENCE {
	version			INTEGER { v1(0) },
	privateKeyAlgorithm	AlgorithmIdentifier,
	privateKey		OCTET STRING,
	attributes		[0] Attributes OPTIONAL }
*/

int pkcs8_enced_private_key_info_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	const uint8_t *enced, size_t encedlen,
	uint8_t **out, size_t *outlen);
int pkcs8_enced_private_key_info_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **enced, size_t *encedlen,
	const uint8_t **in, size_t *inlen);
int pkcs8_enced_private_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


#ifdef __cplusplus
}
#endif
#endif
