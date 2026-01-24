/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_ECDSA_H
#define GMSSL_ECDSA_H


#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sha2.h>
#include <gmssl/secp256r1_key.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	secp256r1_t r;
	secp256r1_t s;
} ECDSA_SIGNATURE;

#define ECDSA_SIGNATURE_COMPACT_SIZE	70
#define ECDSA_SIGNATURE_TYPICAL_SIZE	71
#define ECDSA_SIGNATURE_MAX_SIZE	72

int ecdsa_signature_to_der(const ECDSA_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int ecdsa_signature_from_der(ECDSA_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int ecdsa_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const ECDSA_SIGNATURE *sig);
int ecdsa_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

int ecdsa_do_sign_ex(const SECP256R1_KEY *key, const secp256r1_t k, const uint8_t dgst[32], ECDSA_SIGNATURE *sig);
int ecdsa_do_sign(const SECP256R1_KEY *key, const uint8_t dgst[32], ECDSA_SIGNATURE *sig);
int ecdsa_do_verify(const SECP256R1_KEY *key, const uint8_t dgst[32], const ECDSA_SIGNATURE *sig);
int ecdsa_sign(const SECP256R1_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int ecdsa_sign_fixlen(const SECP256R1_KEY *key, const uint8_t dgst[32], size_t siglen, uint8_t *sig);
int ecdsa_verify(const SECP256R1_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen);


typedef struct {
	SHA256_CTX sha256_ctx;
	SECP256R1_KEY key;
	ECDSA_SIGNATURE sig;
} ECDSA_SIGN_CTX;

int ecdsa_sign_init(ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key);
int ecdsa_sign_update(ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int ecdsa_sign_finish(ECDSA_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int ecdsa_sign_finish_fixlen(ECDSA_SIGN_CTX *ctx, size_t siglen, uint8_t *sig);
int ecdsa_verify_init(ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const uint8_t *sig, size_t siglen);
int ecdsa_verify_update(ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int ecdsa_verify_finish(ECDSA_SIGN_CTX *ctx);



#ifdef __cplusplus
}
#endif
#endif
