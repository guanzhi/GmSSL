/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

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


// EncryptedPrivateKeyInfo
int sm2_enced_private_key_info_to_der(const SM2_KEY *key, const char *pass, uint8_t **out, size_t *outlen);
int sm2_enced_private_key_info_from_der(SM2_KEY *key, const uint8_t **attrs, size_t *attrslen, const char *pass, const uint8_t **in, size_t *inlen);
int sm2_enced_private_key_info_to_pem(const SM2_KEY *key, const char *pass, FILE *fp);
int sm2_enced_private_key_info_from_pem(SM2_KEY *key, const char *pass, FILE *fp);

/*
	prf must be OID_hmac_sm3
	cipher must be OID_sm4_cbc
*/

int pbkdf2_params_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen, // optional, -1
	int prf,
	uint8_t **out, size_t *outlen);

int pbkdf2_params_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen, // -1, optional
	int *prf,
	const uint8_t **in, size_t *inlen);

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

int pbes2_enc_algor_to_der(
	int cipher,
	const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen);

int pbes2_enc_algor_from_der(
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen);

int pbes2_params_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen);

int pbes2_params_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen);

int pbes2_algor_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen);

int pbes2_algor_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen);

int pkcs8_enced_private_key_info_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	const uint8_t *enced, size_t encedlen,
	uint8_t **out, size_t *outlen);

int pkcs8_enced_private_key_info_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **enced, size_t *encedlen,
	const uint8_t **in, size_t *inlen);


#ifdef __cplusplus
}
#endif
#endif
