/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM9_Z256_H
#define GMSSL_SM9_Z256_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef uint64_t sm9_z256_t[4];

void sm9_z256_set_one(sm9_z256_t r);
void sm9_z256_set_zero(sm9_z256_t r);
void sm9_z256_copy(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_copy_conditional(sm9_z256_t r, const sm9_z256_t a, uint64_t move);
int  sm9_z256_cmp(const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z256_is_zero(const sm9_z256_t a);
uint64_t sm9_z256_equ(const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z256_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z256_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_mul(uint64_t r[8], const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_from_bytes(sm9_z256_t r, const uint8_t in[32]);
void sm9_z256_to_bytes(const sm9_z256_t a, uint8_t out[32]);
int  sm9_z256_from_hex(sm9_z256_t r, const char *hex);
void sm9_z256_to_hex(const sm9_z256_t r, char hex[64]);
int  sm9_z256_equ_hex(const sm9_z256_t a, const char *hex);
void sm9_z256_to_bits(const sm9_z256_t a, char bits[256]);
int  sm9_z256_rand_range(sm9_z256_t r, const sm9_z256_t range);
void sm9_z256_print_bn(const char *prefix, const sm9_z256_t a);
int  sm9_z256_print(FILE *fp, int ind, int fmt, const char *label, const sm9_z256_t a);

const uint64_t *sm9_z256_prime(void);

void sm9_z256_modp_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modp_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modp_dbl(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_tri(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_haf(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_neg(sm9_z256_t r, const sm9_z256_t a);

void sm9_z256_modp_to_mont(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_from_mont(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_mont_mul(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modp_mont_sqr(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_mont_pow(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t e);
void sm9_z256_modp_mont_inv(sm9_z256_t r, const sm9_z256_t a);

const uint64_t *sm9_z256_order(void);

void sm9_z256_modn_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modn_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modn_mul(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modn_pow(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t e);
void sm9_z256_modn_inv(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modn_from_hash(sm9_z256_t h, const uint8_t Ha[40]);


typedef sm9_z256_t sm9_z256_fp2_t[2];

void sm9_z256_fp2_set_one(sm9_z256_fp2_t r);
void sm9_z256_fp2_set_zero(sm9_z256_fp2_t r);
int  sm9_z256_fp2_is_one(const sm9_z256_fp2_t a);
int  sm9_z256_fp2_is_zero(const sm9_z256_fp2_t a);
int  sm9_z256_fp2_equ(const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_copy(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
int  sm9_z256_fp2_rand(sm9_z256_fp2_t r);
void sm9_z256_fp2_to_bytes(const sm9_z256_fp2_t a, uint8_t buf[64]);
int  sm9_z256_fp2_from_bytes(sm9_z256_fp2_t r, const uint8_t buf[64]);
void sm9_z256_fp2_to_hex(const sm9_z256_fp2_t a, char hex[129]);
int  sm9_z256_fp2_from_hex(sm9_z256_fp2_t r, const char hex[129]);
void sm9_z256_fp2_add(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_dbl(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_tri(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_sub(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_neg(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_a_mul_u(sm9_z256_fp2_t r, sm9_z256_fp2_t a);
void sm9_z256_fp2_mul(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_mul_u(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_mul_fp(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_t k);
void sm9_z256_fp2_sqr(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_sqr_u(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_inv(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_div(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_haf(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_conjugate(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_frobenius(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);


typedef sm9_z256_fp2_t sm9_z256_fp4_t[2];

int  sm9_z256_fp4_is_zero(const sm9_z256_fp4_t a);
int  sm9_z256_fp4_equ(const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
int  sm9_z256_fp4_rand(sm9_z256_fp4_t r);
void sm9_z256_fp4_copy(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_to_bytes(const sm9_z256_fp4_t a, uint8_t buf[128]);
int  sm9_z256_fp4_from_bytes(sm9_z256_fp4_t r, const uint8_t buf[128]);
int  sm9_z256_fp4_from_hex(sm9_z256_fp4_t r, const char hex[259]);
void sm9_z256_fp4_to_hex(const sm9_z256_fp4_t a, char hex[259]);
void sm9_z256_fp4_add(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
void sm9_z256_fp4_dbl(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_sub(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
void sm9_z256_fp4_neg(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_haf(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_a_mul_v(sm9_z256_fp4_t r, sm9_z256_fp4_t a);
void sm9_z256_fp4_mul(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
void sm9_z256_fp4_mul_fp(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_t k);
void sm9_z256_fp4_mul_fp2(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp2_t b0);
void sm9_z256_fp4_mul_v(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
void sm9_z256_fp4_sqr(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_sqr_v(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_inv(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_frobenius(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_conjugate(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_frobenius2(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_frobenius3(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);


typedef sm9_z256_fp4_t sm9_z256_fp12_t[3];

void sm9_z256_fp12_set_one(sm9_z256_fp12_t r);
void sm9_z256_fp12_set_zero(sm9_z256_fp12_t r);
void sm9_z256_fp12_copy(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
int  sm9_z256_fp12_rand(sm9_z256_fp12_t r);
int  sm9_z256_fp12_from_hex(sm9_z256_fp12_t r, const char hex[779]); // 779 = 64*12 + 11
void sm9_z256_fp12_to_hex(const sm9_z256_fp12_t a, char hex[779]);
void sm9_z256_fp12_to_bytes(const sm9_z256_fp12_t a, uint8_t buf[384]);
int  sm9_z256_fp12_from_bytes(sm9_z256_fp12_t r, const uint8_t buf[384]);

void sm9_z256_fp12_print(const char *prefix, const sm9_z256_fp12_t a);
void sm9_z256_fp12_set(sm9_z256_fp12_t r, const sm9_z256_fp4_t a0, const sm9_z256_fp4_t a1, const sm9_z256_fp4_t a2);
int  sm9_z256_fp12_equ(const sm9_z256_fp12_t a, const sm9_z256_fp12_t b);
void sm9_z256_fp12_add(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_fp12_t b);
void sm9_z256_fp12_dbl(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_tri(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_sub(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_fp12_t b);
void sm9_z256_fp12_neg(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_mul(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_fp12_t b);
void sm9_z256_fp12_sqr(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_inv(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_pow(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_t k);
void sm9_z256_fp12_frobenius(sm9_z256_fp12_t r, const sm9_z256_fp12_t x);
void sm9_z256_fp12_frobenius2(sm9_z256_fp12_t r, const sm9_z256_fp12_t x);
void sm9_z256_fp12_frobenius3(sm9_z256_fp12_t r, const sm9_z256_fp12_t x);
void sm9_z256_fp12_frobenius6(sm9_z256_fp12_t r, const sm9_z256_fp12_t x);


// E(F_p): y^2 = x^3 + 5

typedef struct {
	sm9_z256_t X; // is mont(X)
	sm9_z256_t Y; // is mont(Y)
	sm9_z256_t Z; // is mont(Z)
} SM9_Z256_POINT;

const SM9_Z256_POINT *sm9_z256_generator(void);

int  sm9_z256_point_from_hex(SM9_Z256_POINT *R, const char hex[129]);
int  sm9_z256_point_is_at_infinity(const SM9_Z256_POINT *P);
void sm9_z256_point_set_infinity(SM9_Z256_POINT *R);
void sm9_z256_point_get_xy(const SM9_Z256_POINT *P, sm9_z256_t x, sm9_z256_t y);
int  sm9_z256_point_equ(const SM9_Z256_POINT *P, const SM9_Z256_POINT *Q);
int  sm9_z256_point_is_on_curve(const SM9_Z256_POINT *P);
void sm9_z256_point_dbl(SM9_Z256_POINT *R, const SM9_Z256_POINT *P);
void sm9_z256_point_neg(SM9_Z256_POINT *R, const SM9_Z256_POINT *P);
void sm9_z256_point_add(SM9_Z256_POINT *R, const SM9_Z256_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_point_sub(SM9_Z256_POINT *R, const SM9_Z256_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_point_mul(SM9_Z256_POINT *R, const sm9_z256_t k, const SM9_Z256_POINT *P);
void sm9_z256_point_mul_generator(SM9_Z256_POINT *R, const sm9_z256_t k);
int  sm9_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_Z256_POINT *P);
int  sm9_z256_point_to_uncompressed_octets(const SM9_Z256_POINT *P, uint8_t octets[65]);
int  sm9_z256_point_from_uncompressed_octets(SM9_Z256_POINT *P, const uint8_t octets[65]);


typedef struct {
	uint64_t X[4];
	uint64_t Y[4];
} SM9_Z256_AFFINE_POINT;

void sm9_z256_point_copy_affine(SM9_Z256_POINT *R, const SM9_Z256_AFFINE_POINT *P);
void sm9_z256_point_add_affine(SM9_Z256_POINT *R, const SM9_Z256_POINT *P, const SM9_Z256_AFFINE_POINT *Q);
void sm9_z256_point_sub_affine(SM9_Z256_POINT *R, const SM9_Z256_POINT *P, const SM9_Z256_AFFINE_POINT *Q);


typedef struct {
	sm9_z256_fp2_t X;
	sm9_z256_fp2_t Y;
	sm9_z256_fp2_t Z;
} SM9_Z256_TWIST_POINT;

const SM9_Z256_TWIST_POINT *sm9_z256_twist_generator(void);

int sm9_z256_twist_point_to_uncompressed_octets(const SM9_Z256_TWIST_POINT *P, uint8_t octets[129]);
int sm9_z256_twist_point_from_uncompressed_octets(SM9_Z256_TWIST_POINT *P, const uint8_t octets[129]);

int  sm9_z256_twist_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_from_hex(SM9_Z256_TWIST_POINT *R, const char hex[259]); // 259 = 64 * 4 + 3
int  sm9_z256_twist_point_is_at_infinity(const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_set_infinity(SM9_Z256_TWIST_POINT *R);
void sm9_z256_twist_point_get_xy(const SM9_Z256_TWIST_POINT *P, sm9_z256_fp2_t x, sm9_z256_fp2_t y);
int  sm9_z256_twist_point_equ(const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
int  sm9_z256_twist_point_is_on_curve(const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_neg(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_dbl(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_add(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_sub(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_add_full(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_mul(SM9_Z256_TWIST_POINT *R, const sm9_z256_t k, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_mul_generator(SM9_Z256_TWIST_POINT *R, const sm9_z256_t k);


void sm9_z256_point_to_affine(SM9_Z256_AFFINE_POINT *Q, const SM9_Z256_POINT *P);
void sm9_z256_eval_g_tangent(SM9_Z256_TWIST_POINT *R, sm9_z256_fp2_t lw[3],
	const SM9_Z256_TWIST_POINT *P, const SM9_Z256_AFFINE_POINT *Q);
void sm9_z256_eval_g_line(SM9_Z256_TWIST_POINT *R, sm9_z256_fp2_t lw[3], sm9_z256_fp2_t pre[5],
	const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *T, const SM9_Z256_AFFINE_POINT *Q);
void sm9_z256_eval_g_line_no_pre(SM9_Z256_TWIST_POINT *R, sm9_z256_fp2_t lw[3],
	const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *T, const SM9_Z256_AFFINE_POINT *Q);
void sm9_z256_fp12_line_mul(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_fp2_t lw[3]);
//void sm9_z256_eval_g_tangent(sm9_z256_fp12_t num, sm9_z256_fp12_t den, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_POINT *Q);
//void sm9_z256_eval_g_line(sm9_z256_fp12_t num, sm9_z256_fp12_t den, const SM9_Z256_TWIST_POINT *T, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_twist_point_pi1(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_pi2(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_neg_pi2(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_final_exponent_hard_part(sm9_z256_fp12_t r, const sm9_z256_fp12_t f);
void sm9_z256_final_exponent(sm9_z256_fp12_t r, const sm9_z256_fp12_t f);
void sm9_z256_pairing(sm9_z256_fp12_t r, const SM9_Z256_TWIST_POINT *Q, const SM9_Z256_POINT *P);


#ifdef  __cplusplus
}
#endif
#endif
