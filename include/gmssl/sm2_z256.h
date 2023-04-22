/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_SM2_Z256_H
#define GMSSL_SM2_Z256_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif


void sm2_z256_copy(uint64_t r[4], const uint64_t a[4]);
void sm2_z256_copy_conditional(uint64_t dst[4], const uint64_t src[4], uint64_t move);
void sm2_z256_from_bytes(uint64_t r[4], const uint8_t in[32]);
void sm2_z256_to_bytes(const uint64_t a[4], uint8_t out[32]);
int sm2_z256_cmp(const uint64_t a[4], const uint64_t b[4]);
uint64_t sm2_z256_equ(const uint64_t a[4], const uint64_t b[4]);
uint64_t sm2_z256_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
uint64_t sm2_z256_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
void sm2_z256_mul(uint64_t r[8], const uint64_t a[4], const uint64_t b[4]);
uint64_t sm2_z512_add(uint64_t r[8], const uint64_t a[8], const uint64_t b[8]);
int sm2_z256_get_booth(const uint64_t a[4], unsigned int window_size, int i);
void sm2_z256_from_hex(uint64_t r[4], const char *hex);
int sm2_z256_print(FILE *fp, int ind, int fmt, const char *label, const uint64_t a[4]);
int sm2_z512_print(FILE *fp, int ind, int fmt, const char *label, const uint64_t a[8]);

void sm2_z256_modp_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
void sm2_z256_modp_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
void sm2_z256_modp_neg(uint64_t r[4], const uint64_t a[4]);
void sm2_z256_modp_mul_by_2(uint64_t r[4], const uint64_t a[4]);
void sm2_z256_modp_mul_by_3(uint64_t r[4], const uint64_t a[4]);
void sm2_z256_modp_div_by_2(uint64_t r[4], const uint64_t a[4]);

void sm2_z256_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
void sm2_z256_mont_sqr(uint64_t r[4], const uint64_t a[4]);
void sm2_z256_mont_inv(uint64_t r[4], const uint64_t a[4]);
void sm2_z256_from_mont(uint64_t r[4], const uint64_t a[4]);
void sm2_z256_to_mont(const uint64_t a[4], uint64_t r[4]);
int sm2_z256_mont_print(FILE *fp, int ind, int fmt, const char *label, const uint64_t a[4]);


typedef struct {
	uint64_t X[4];
	uint64_t Y[4];
	uint64_t Z[4];
} SM2_Z256_POINT;

void sm2_z256_point_dbl(SM2_Z256_POINT *R, const SM2_Z256_POINT *A);
void sm2_z256_point_add(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_POINT *b);
void sm2_z256_point_neg(SM2_Z256_POINT *R, const SM2_Z256_POINT *P);
void sm2_z256_point_sub(SM2_Z256_POINT *R, const SM2_Z256_POINT *A, const SM2_Z256_POINT *B);
void sm2_z256_point_get_affine(const SM2_Z256_POINT *P, uint64_t x[4], uint64_t y[4]);
int sm2_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT *P);


typedef struct {
	uint64_t x[4];
	uint64_t y[4];
} SM2_Z256_POINT_AFFINE;

void sm2_z256_point_copy_affine(SM2_Z256_POINT *R, const SM2_Z256_POINT_AFFINE *P);
void sm2_z256_point_add_affine(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_POINT_AFFINE *b);
void sm2_z256_point_sub_affine(SM2_Z256_POINT *R, const SM2_Z256_POINT *A, const SM2_Z256_POINT_AFFINE *B);
int sm2_z256_point_affine_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT_AFFINE *P);

void sm2_z256_point_mul_generator(SM2_Z256_POINT *R, const uint64_t k[4]);
void sm2_z256_point_mul(SM2_Z256_POINT *R, const SM2_Z256_POINT *P, const uint64_t k[4]);
void sm2_z256_point_mul_sum(SM2_Z256_POINT *R, const uint64_t t[4], const SM2_Z256_POINT *P, const uint64_t s[4]);

#ifdef __cplusplus
}
#endif
#endif
