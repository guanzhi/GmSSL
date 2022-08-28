/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


/* GF(2^128) defined by f(x) = x^128 + x^7 + x^2 + x + 1
 * A + B mod f(x) = a xor b
 * A * 2 mod f(x)
 */

#ifndef GMSSL_GF128_H
#define GMSSL_GF128_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

//typedef unsigned __int128 gf128_t;

typedef struct {
	uint64_t hi;
	uint64_t lo;
} gf128_t;


// Note: send by value is comptabile with uint128_t and sse2
gf128_t gf128_from_hex(const char *s);
int gf128_equ_hex(gf128_t a, const char *s);
gf128_t gf128_zero(void);
gf128_t gf128_add(gf128_t a, gf128_t b);
gf128_t gf128_mul(gf128_t a, gf128_t b);
gf128_t gf128_mul2(gf128_t a);
gf128_t gf128_from_bytes(const uint8_t p[16]);
void gf128_to_bytes(gf128_t a, uint8_t p[16]);
int gf128_print(FILE *fp, int fmt ,int ind, const char *label, gf128_t a);


#ifdef __cplusplus
}
#endif
#endif
