/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SECP256R1_ECDSA_H
#define GMSSL_SECP256R1_ECDSA_H


#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/digest.h>
#include <gmssl/secp256r1_key.h>


#ifdef __cplusplus
extern "C" {
#endif


// 不应该在保留一个独立的SECP256R1_ECDSA_SIGNATURE类型，应该直接输出紧凑的二进制，实际上一般来说总是输出DER
typedef struct {
	secp256r1_t r;
	secp256r1_t s;
} SECP256R1_ECDSA_SIGNATURE;

#define SECP256R1_ECDSA_SIGNATURE_COMPACT_SIZE	70
#define SECP256R1_ECDSA_SIGNATURE_TYPICAL_SIZE	71
#define SECP256R1_ECDSA_SIGNATURE_MAX_SIZE	72

// 这几个函数应都去掉，不再开放底层的类型了
int secp256r1_ecdsa_signature_to_der(const SECP256R1_ECDSA_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int secp256r1_ecdsa_signature_from_der(SECP256R1_ECDSA_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int secp256r1_ecdsa_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_ECDSA_SIGNATURE *sig);



int secp256r1_ecdsa_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);


int secp256r1_ecdsa_do_sign_ex(const SECP256R1_KEY *key, const secp256r1_t k, const uint8_t dgst[32], SECP256R1_ECDSA_SIGNATURE *sig);
int secp256r1_ecdsa_do_sign(const SECP256R1_KEY *key, const uint8_t dgst[32], SECP256R1_ECDSA_SIGNATURE *sig);
int secp256r1_ecdsa_do_verify(const SECP256R1_KEY *key, const uint8_t dgst[32], const SECP256R1_ECDSA_SIGNATURE *sig);


// 这个函数应该改为将key的类型编程通用支持P256, P384的，摘要可以支持不同长度的
int secp256r1_ecdsa_sign(const SECP256R1_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int secp256r1_ecdsa_sign_fixlen(const SECP256R1_KEY *key, const uint8_t dgst[32], size_t siglen, uint8_t *sig);
int secp256r1_ecdsa_verify(const SECP256R1_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen);


// 后面的CTX就没有意义了
typedef struct {
	DIGEST_CTX digest_ctx;
	SECP256R1_KEY key;
	SECP256R1_ECDSA_SIGNATURE sig;
} SECP256R1_ECDSA_SIGN_CTX;

int secp256r1_ecdsa_sign_init(SECP256R1_ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const DIGEST *digest);
int secp256r1_ecdsa_sign_update(SECP256R1_ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int secp256r1_ecdsa_sign_finish(SECP256R1_ECDSA_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int secp256r1_ecdsa_sign_finish_fixlen(SECP256R1_ECDSA_SIGN_CTX *ctx, size_t siglen, uint8_t *sig);
int secp256r1_ecdsa_verify_init(SECP256R1_ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const DIGEST *digest,
	const uint8_t *sig, size_t siglen);
int secp256r1_ecdsa_verify_update(SECP256R1_ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int secp256r1_ecdsa_verify_finish(SECP256R1_ECDSA_SIGN_CTX *ctx);



#ifdef __cplusplus
}
#endif
#endif
