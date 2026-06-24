/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SHA3_H
#define GMSSL_SHA3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SHA3_256_DIGEST_SIZE 32
#define SHA3_512_DIGEST_SIZE 64

typedef struct {
	uint64_t state[25];
	uint8_t block[168];
	size_t rate;
	size_t num;
	int squeezing;
} SHAKE_CTX;

void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[SHA3_256_DIGEST_SIZE]);
void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[SHA3_512_DIGEST_SIZE]);

void shake128_init(SHAKE_CTX *ctx);
void shake256_init(SHAKE_CTX *ctx);
void shake_update(SHAKE_CTX *ctx, const uint8_t *in, size_t inlen);
void shake_finish(SHAKE_CTX *ctx);
void shake_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t outlen);

void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);


#ifdef __cplusplus
}
#endif
#endif
