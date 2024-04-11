/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

// GF(2^128) defined by f(x) = x^128 + x^7 + x^2 + x + 1

#ifndef GMSSL_GF128_H
#define GMSSL_GF128_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef uint64_t gf128_t[2];

void gf128_set_zero(gf128_t r);
void gf128_set_one(gf128_t r);
void gf128_add(gf128_t r, const gf128_t a, const gf128_t b);
void gf128_mul(gf128_t r, const gf128_t a, const gf128_t b);
void gf128_mul_by_2(gf128_t r, const gf128_t a);
void gf128_from_bytes(gf128_t r, const uint8_t p[16]);
void gf128_to_bytes(const gf128_t a, uint8_t p[16]);
int gf128_from_hex(gf128_t r, const char *s);
int gf128_equ_hex(const gf128_t a, const char *s);
int gf128_print(FILE *fp, int fmt, int ind, const char *label, const gf128_t a);


#ifdef __cplusplus
}
#endif
#endif
