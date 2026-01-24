/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_BN_H
#define GMSSL_BN_H


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif


void bn_set_word(uint32_t *r, uint32_t a, size_t k);
void bn_copy(uint32_t *r, const uint32_t *a, size_t k);
int  bn_cmp(const uint32_t *a, const uint32_t *b, size_t k);
int  bn_is_zero(const uint32_t *a, size_t k);
int  bn_is_one(const uint32_t *a, size_t k);
int  bn_add(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t k);
int  bn_sub(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t k);
void bn_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t k);
void bn_mul_lo(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t k);
void bn_to_bytes(const uint32_t *a, size_t k, uint8_t *out);
void bn_from_bytes(uint32_t *a, size_t k, const uint8_t *in);
int  bn_print(FILE *fp, int fmt, int ind, const char *label, const uint32_t *a, size_t k);

void bn_mod_add(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *p, size_t k);
void bn_mod_sub(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *p, size_t k);
void bn_mod_neg(uint32_t *r, const uint32_t *a, const uint32_t *p, size_t k);

// multiplication with barrett reduction, need caller prepare temp values
// u = floor(2^512 / p) for bn256
void bn_barrett_mod_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *p,
	const uint32_t *u, // uint32_t u[k + 1]
	uint32_t *tmp, // uint32_t tmp[6*k + 4]
	size_t k);
void bn_barrett_mod_sqr(uint32_t *r, const uint32_t *a, const uint32_t *p,
	const uint32_t *u, // uint32_t u[k + 1]
	uint32_t *tmp, // uint32_t tmp[6*k + 4]
	size_t k);
void bn_barrett_mod_exp(uint32_t *r, const uint32_t *a, const uint32_t *e, const uint32_t *p,
	const uint32_t *u, // uint32_t u[k + 1]
	uint32_t *tmp, // uint32_t tmp[7*k + 4]
	size_t k);
void bn_barrett_mod_inv(uint32_t *r, const uint32_t *a, const uint32_t *p,
	const uint32_t *u, // uint32_t u[k + 1]
	uint32_t *tmp, // uint32_t tmp[8*k + 4]
	size_t k);

// montgomery multiplication, all values in montgomery format, need caller prepare temp values
void bn_mont_mod_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *p, const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[5 * k]
	size_t k);
void bn_mont_mod_sqr(uint32_t *r, const uint32_t *a, const uint32_t *p, const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[5 * k]
	size_t k);
void bn_mont_mod_exp(uint32_t *r, const uint32_t *a, const uint32_t *e, const uint32_t *p, const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[6 * k]
	size_t k);
void bn_mont_mod_inv(uint32_t *r, const uint32_t *a, const uint32_t *p, const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[7 * k]
	size_t k);
void bn_mont_set(uint32_t *r, const uint32_t *a, const uint32_t *one_sqr, const uint32_t *p, const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[5 * k]
	size_t k);
void bn_mont_get(uint32_t *r, const uint32_t *a, const uint32_t *p, const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[5 * k]
	size_t k);


#ifdef __cplusplus
}
#endif
#endif
