/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef GMSSL_SM2_COMMIT_H
#define GMSSL_SM2_COMMIT_H


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


#ifdef __cplusplus
extern "C" {
#endif


int sm2_commit_generate(const uint8_t x[32], uint8_t r[32], uint8_t commit[65], size_t *commitlen);
int sm2_commit_open(const uint8_t x[32], const uint8_t r[32], const uint8_t *commit, size_t commitlen);
int sm2_commit_vector_generate(const sm2_bn_t *x, size_t count, uint8_t r[32], uint8_t commit[65], size_t *commitlen);
int sm2_commit_vector_open(const sm2_bn_t *x, size_t count, const uint8_t r[32], const uint8_t *commit, size_t commitlen);


#ifdef __cplusplus
}
#endif
#endif
