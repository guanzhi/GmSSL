/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

// TODO: a new header for coarse-grained parallelism SM3, implemented by sm3_avx2/avx512, sm3_sve/sve2, sm3_cl
// and used by sm3_xmss or other algors

#ifndef GMSSL_SM3_X8_AVX2_H  // GMSSL_SM3_MULTI_H ?
#define GMSSL_SM3_X8_AVX2_H

#include <stdint.h>
#include <immintrin.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	__m256i digest[8];
} SM3_X8_CTX;

void sm3_x8_init(SM3_X8_CTX *ctx);
void sm3_x8_compress_blocks(__m256i digest[8], const uint8_t *data, size_t datalen);
void sm3_x8_digest(const uint8_t *data, size_t datalen, uint8_t dgst[8][32]);


#ifdef __cplusplus
}
#endif
#endif
