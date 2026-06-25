/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SECP384R1_KEY_H
#define GMSSL_SECP384R1_KEY_H


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/secp384r1.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	SECP384R1_POINT public_key;
	secp384r1_t private_key;
} SECP384R1_KEY;

int secp384r1_key_generate(SECP384R1_KEY *key);
int secp384r1_key_set_private_key(SECP384R1_KEY *key, const secp384r1_t private_key);
int secp384r1_public_key_equ(const SECP384R1_KEY *key, const SECP384R1_KEY *pub);

int secp384r1_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP384R1_KEY *key);
int secp384r1_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP384R1_KEY *key);

int secp384r1_public_key_to_bytes(const SECP384R1_KEY *key, uint8_t **out, size_t *outlen);
int secp384r1_public_key_from_bytes(SECP384R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp384r1_public_key_to_der(const SECP384R1_KEY *key, uint8_t **out, size_t *outlen);
int secp384r1_public_key_from_der(SECP384R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp384r1_private_key_to_der(const SECP384R1_KEY *key, uint8_t **out, size_t *outlen);
int secp384r1_private_key_from_der(SECP384R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp384r1_private_key_info_to_der(const SECP384R1_KEY *key, uint8_t **out, size_t *outlen);
int secp384r1_private_key_info_from_der(SECP384R1_KEY *key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen);
int secp384r1_private_key_info_encrypt_to_der(const SECP384R1_KEY *ec_key, const char *pass,
	uint8_t **out, size_t *outlen);
int secp384r1_private_key_info_decrypt_from_der(SECP384R1_KEY *ec_key,
	const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen);

int secp384r1_private_key_to_pem(const SECP384R1_KEY *key, FILE *fp);
int secp384r1_private_key_from_pem(SECP384R1_KEY *key, FILE *fp);
int secp384r1_private_key_info_encrypt_to_pem(const SECP384R1_KEY *key, const char *pass, FILE *fp);
int secp384r1_private_key_info_decrypt_from_pem(SECP384R1_KEY *key, const char *pass, FILE *fp);

int secp384r1_do_ecdh(const SECP384R1_KEY *key, const SECP384R1_KEY *pub, uint8_t out[48]);
int secp384r1_ecdh(const SECP384R1_KEY *key, const uint8_t uncompressed_point[97], uint8_t out[48]);


#ifdef __cplusplus
}
#endif
#endif
