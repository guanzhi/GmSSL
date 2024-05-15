/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_GHASH_H
#define GMSSL_GHASH_H


#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/gf128.h>


#ifdef __cplusplus
extern "C" {
#endif


#define GHASH_SIZE		(16)


// h = ENC_k(0^128)
void ghash(const uint8_t h[16], const uint8_t *aad, size_t aadlen,
	const uint8_t *c, size_t clen, uint8_t out[16]);

typedef struct {
	gf128_t H;
	gf128_t X;
	size_t aadlen;
	size_t clen;
	uint8_t block[16];
	size_t num;
} GHASH_CTX;

void ghash_init(GHASH_CTX *ctx, const uint8_t h[16], const uint8_t *aad, size_t aadlen);
void ghash_update(GHASH_CTX *ctx, const uint8_t *c, size_t clen);
void ghash_finish(GHASH_CTX *ctx, uint8_t out[16]);


#ifdef __cplusplus
}
#endif
#endif
