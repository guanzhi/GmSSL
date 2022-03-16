/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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
