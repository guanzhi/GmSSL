/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_SM2_P256_H
#define GMSSL_SM2_P256_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t SM2_BN[8];

int sm2_bn_is_zero(const SM2_BN a);
int sm2_bn_is_one(const SM2_BN a);
int sm2_bn_is_odd(const SM2_BN a);
int sm2_bn_cmp(const SM2_BN a, const SM2_BN b);
int sm2_bn_from_hex(SM2_BN r, const char hex[64]);
int sm2_bn_from_asn1_integer(SM2_BN r, const uint8_t *d, size_t dlen);
int sm2_bn_equ_hex(const SM2_BN a, const char *hex);
int sm2_bn_print(FILE *fp, int fmt, int ind, const char *label, const SM2_BN a);
int sm2_bn_rshift(SM2_BN ret, const SM2_BN a, unsigned int nbits);

void sm2_bn_to_bytes(const SM2_BN a, uint8_t out[32]);
void sm2_bn_from_bytes(SM2_BN r, const uint8_t in[32]);
void sm2_bn_to_hex(const SM2_BN a, char hex[64]);
void sm2_bn_to_bits(const SM2_BN a, char bits[256]);
void sm2_bn_set_word(SM2_BN r, uint32_t a);
void sm2_bn_add(SM2_BN r, const SM2_BN a, const SM2_BN b);
void sm2_bn_sub(SM2_BN ret, const SM2_BN a, const SM2_BN b);
int  sm2_bn_rand_range(SM2_BN r, const SM2_BN range);

#define sm2_bn_init(r) memset((r),0,sizeof(SM2_BN))
#define sm2_bn_set_zero(r) memset((r),0,sizeof(SM2_BN))
#define sm2_bn_set_one(r) sm2_bn_set_word((r),1)
#define sm2_bn_copy(r,a) memcpy((r),(a),sizeof(SM2_BN))
#define sm2_bn_clean(r) memset((r),0,sizeof(SM2_BN))


// GF(p)
typedef SM2_BN SM2_Fp;

void sm2_fp_add(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_sub(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_mul(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_exp(SM2_Fp r, const SM2_Fp a, const SM2_Fp e);
void sm2_fp_dbl(SM2_Fp r, const SM2_Fp a);
void sm2_fp_tri(SM2_Fp r, const SM2_Fp a);
void sm2_fp_div2(SM2_Fp r, const SM2_Fp a);
void sm2_fp_neg(SM2_Fp r, const SM2_Fp a);
void sm2_fp_sqr(SM2_Fp r, const SM2_Fp a);
void sm2_fp_inv(SM2_Fp r, const SM2_Fp a);
int  sm2_fp_rand(SM2_Fp r);

int sm2_fp_sqrt(SM2_Fp r, const SM2_Fp a);

#define sm2_fp_init(r)		sm2_bn_init(r)
#define sm2_fp_set_zero(r)	sm2_bn_set_zero(r)
#define sm2_fp_set_one(r)	sm2_bn_set_one(r)
#define sm2_fp_copy(r,a)	sm2_bn_copy(r,a)
#define sm2_fp_clean(r)		sm2_bn_clean(r)

// GF(n)
typedef SM2_BN SM2_Fn;

void sm2_fn_add(SM2_Fn r, const SM2_Fn a, const SM2_Fn b);
void sm2_fn_sub(SM2_Fn r, const SM2_Fn a, const SM2_Fn b);
void sm2_fn_mul(SM2_Fn r, const SM2_Fn a, const SM2_Fn b);
void sm2_fn_mul_word(SM2_Fn r, const SM2_Fn a, uint32_t b);
void sm2_fn_exp(SM2_Fn r, const SM2_Fn a, const SM2_Fn e);
void sm2_fn_neg(SM2_Fn r, const SM2_Fn a);
void sm2_fn_sqr(SM2_Fn r, const SM2_Fn a);
void sm2_fn_inv(SM2_Fn r, const SM2_Fn a);
int  sm2_fn_rand(SM2_Fn r);

#define sm2_fn_init(r)		sm2_bn_init(r)
#define sm2_fn_set_zero(r)	sm2_bn_set_zero(r)
#define sm2_fn_set_one(r)	sm2_bn_set_one(r)
#define sm2_fn_copy(r,a)	sm2_bn_copy(r,a)
#define sm2_fn_clean(r)		sm2_bn_clean(r)


typedef struct {
	SM2_BN X;
	SM2_BN Y;
	SM2_BN Z;
} SM2_JACOBIAN_POINT;

void sm2_jacobian_point_init(SM2_JACOBIAN_POINT *R);
void sm2_jacobian_point_set_xy(SM2_JACOBIAN_POINT *R, const SM2_BN x, const SM2_BN y);
void sm2_jacobian_point_get_xy(const SM2_JACOBIAN_POINT *P, SM2_BN x, SM2_BN y);
void sm2_jacobian_point_neg(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_dbl(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_add(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q);
void sm2_jacobian_point_sub(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q);
void sm2_jacobian_point_mul(SM2_JACOBIAN_POINT *R, const SM2_BN k, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_to_bytes(const SM2_JACOBIAN_POINT *P, uint8_t out[64]);
void sm2_jacobian_point_from_bytes(SM2_JACOBIAN_POINT *P, const uint8_t in[64]);
void sm2_jacobian_point_mul_generator(SM2_JACOBIAN_POINT *R, const SM2_BN k);
void sm2_jacobian_point_mul_sum(SM2_JACOBIAN_POINT *R, const SM2_BN t, const SM2_JACOBIAN_POINT *P, const SM2_BN s);
void sm2_jacobian_point_from_hex(SM2_JACOBIAN_POINT *P, const char hex[64 * 2]); // for testing only

int sm2_jacobian_point_is_at_infinity(const SM2_JACOBIAN_POINT *P);
int sm2_jacobian_point_is_on_curve(const SM2_JACOBIAN_POINT *P);
int sm2_jacobian_point_equ_hex(const SM2_JACOBIAN_POINT *P, const char hex[128]); // for testing only
int sm2_jacobian_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_JACOBIAN_POINT *P);

#define sm2_jacobian_point_set_infinity(R) sm2_jacobian_point_init(R)
#define sm2_jacobian_point_copy(R, P) memcpy((R), (P), sizeof(SM2_JACOBIAN_POINT))

const uint64_t *sm2_bn_prime(void);
const uint64_t *sm2_bn_order(void);
const uint64_t *sm2_bn_one(void);


#ifdef __cplusplus
}
#endif
#endif

