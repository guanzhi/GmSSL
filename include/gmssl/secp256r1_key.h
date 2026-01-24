/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SECP256R1_KEY_H
#define GMSSL_SECP256R1_KEY_H


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/secp256r1.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	SECP256R1_POINT public_key;
	secp256r1_t private_key;
} SECP256R1_KEY;

int secp256r1_key_generate(SECP256R1_KEY *key);
int secp256r1_key_set_private_key(SECP256R1_KEY *key, const secp256r1_t private_key);
int secp256r1_public_key_equ(const SECP256R1_KEY *key, const SECP256R1_KEY *pub);
void secp256r1_key_cleanup(SECP256R1_KEY *key);

int secp256r1_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key);
int secp256r1_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key);

int secp256r1_public_key_to_bytes(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_public_key_from_bytes(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_public_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_public_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_private_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_private_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_private_key_info_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_private_key_info_from_der(SECP256R1_KEY *key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen);
int secp256r1_private_key_info_encrypt_to_der(const SECP256R1_KEY *ec_key, const char *pass,
	uint8_t **out, size_t *outlen);
int secp256r1_private_key_info_decrypt_from_der(SECP256R1_KEY *ec_key,
	const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen);


#ifdef __cplusplus
}
#endif
#endif
