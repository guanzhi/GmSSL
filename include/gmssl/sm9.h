/*
 * Copyright (c) 2016 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef GMSSL_SM9_H
#define GMSSL_SM9_H

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t sm9_bn_t[8];
typedef sm9_bn_t sm9_fp_t;
typedef sm9_bn_t sm9_fn_t;
typedef uint64_t sm9_barrett_bn_t[9];
typedef sm9_fp_t sm9_fp2_t[2];
typedef sm9_fp2_t sm9_fp4_t[2];
typedef sm9_fp4_t sm9_fp12_t[3];

typedef struct {
	sm9_fp_t X;
	sm9_fp_t Y;
	sm9_fp_t Z;
} sm9_point_t;

typedef struct {
	sm9_fp2_t X;
	sm9_fp2_t Y;
	sm9_fp2_t Z;
} sm9_twist_point_t;


#define sm9_bn_init(r)		memset((r),0,sizeof(sm9_bn_t))
#define sm9_bn_clean(r)		memset((r),0,sizeof(sm9_bn_t))
#define sm9_bn_set_zero(r)	memset((r),0,sizeof(sm9_bn_t))
#define sm9_bn_set_one(r)	memcpy((r),&SM9_ONE,sizeof(sm9_bn_t))
#define sm9_bn_copy(r,a)	memcpy((r),(a),sizeof(sm9_bn_t))
#define sm9_bn_is_zero(a)	(memcmp((a),&SM9_ZERO, sizeof(sm9_bn_t)) == 0)
#define sm9_bn_is_one(a)	(memcmp((a),&SM9_ONE, sizeof(sm9_bn_t)) == 0)

static void sm9_bn_to_bytes(const sm9_bn_t a, uint8_t out[32]);
static void sm9_bn_from_bytes(sm9_bn_t r, const uint8_t in[32]);
static int sm9_bn_from_hex(sm9_bn_t r, const char hex[65]);
static void sm9_bn_to_hex(const sm9_bn_t a, char hex[65]);
static void sm9_print_bn(const char *prefix, const sm9_bn_t a);
static void sm9_bn_to_bits(const sm9_bn_t a, char bits[256]);

static int sm9_bn_cmp(const sm9_bn_t a, const sm9_bn_t b);
static int sm9_bn_equ_hex(const sm9_bn_t a, const char *hex);
static void sm9_bn_set_word(sm9_bn_t r, uint32_t a);
static void sm9_bn_add(sm9_bn_t r, const sm9_bn_t a, const sm9_bn_t b);
static void sm9_bn_sub(sm9_bn_t ret, const sm9_bn_t a, const sm9_bn_t b);
static void sm9_bn_rand_range(sm9_bn_t r, const sm9_bn_t range);

#define sm9_fp_init(a)		sm9_bn_init(a)
#define sm9_fp_clean(a)		sm9_bn_clean(a)
#define sm9_fp_is_zero(a)	sm9_bn_is_zero(a)
#define sm9_fp_is_one(a)	sm9_bn_is_one(a)
#define sm9_fp_set_zero(a)	sm9_bn_set_zero(a)
#define sm9_fp_set_one(a)	sm9_bn_set_one(a)
#define sm9_fp_from_hex(a,s) 	sm9_bn_from_hex((a),(s))
#define sm9_fp_to_hex(a,s)	sm9_bn_to_hex((a),(s))
#define sm9_fp_copy(r,a)	sm9_bn_copy((r),(a))

static int sm9_fp_equ(const sm9_fp_t a, const sm9_fp_t b);
static void sm9_fp_add(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);
static void sm9_fp_sub(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);
static void sm9_fp_dbl(sm9_fp_t r, const sm9_fp_t a);
static void sm9_fp_tri(sm9_fp_t r, const sm9_fp_t a);
static void sm9_fp_div2(sm9_fp_t r, const sm9_fp_t a);
static void sm9_fp_neg(sm9_fp_t r, const sm9_fp_t a);
static void sm9_fp_mul(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);
static void sm9_fp_sqr(sm9_fp_t r, const sm9_fp_t a);
static void sm9_fp_pow(sm9_fp_t r, const sm9_fp_t a, const sm9_bn_t e);
static void sm9_fp_inv(sm9_fp_t r, const sm9_fp_t a);

static int sm9_barrett_bn_cmp(const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);
static void sm9_barrett_bn_add(sm9_barrett_bn_t r, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);
static void sm9_barrett_bn_sub(sm9_barrett_bn_t ret, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);

#define sm9_fp2_init(a)		memset((a), 0, sizeof(sm9_fp2_t))
#define sm9_fp2_clean(a)	memset((a), 0, sizeof(sm9_fp2_t))
#define sm9_fp2_is_zero(a)	(memcmp((a), &SM9_FP2_ZERO, sizeof(sm9_fp2_t)) == 0)
#define sm9_fp2_is_one(a)	(memcmp((a), &SM9_FP2_ONE, sizeof(sm9_fp2_t)) == 0)
#define sm9_fp2_copy(r,a)	memcpy((r), (a), sizeof(sm9_fp2_t))
#define sm9_fp2_equ(a,b)	(memcmp((a),(b),sizeof(sm9_fp2_t)) == 0)

static void sm9_fp2_from_hex(sm9_fp2_t r, const char hex[65 * 2]);
static void sm9_fp2_to_hex(const sm9_fp2_t a, char hex[65 * 2]);
static void sm9_fp2_print(const char *prefix, const sm9_fp2_t a);
#define sm9_fp2_set_zero(a)	memset((a), 0, sizeof(sm9_fp2_t))
#define sm9_fp2_set_one(a)	memcpy((a), &SM9_FP2_ONE, sizeof(sm9_fp2_t))
static void sm9_fp2_set_fp(sm9_fp2_t r, const sm9_fp_t a);
#define sm9_fp2_set_u(a)	memcpy((a), &SM9_FP2_U, sizeof(sm9_fp2_t))
static void sm9_fp2_set(sm9_fp2_t r, const sm9_fp_t a0, const sm9_fp_t a1);

static void sm9_fp2_add(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
static void sm9_fp2_dbl(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp2_tri(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp2_sub(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
static void sm9_fp2_neg(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp2_mul(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
static void sm9_fp2_mul_u(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
static void sm9_fp2_mul_fp(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp_t k);
static void sm9_fp2_sqr(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp2_sqr_u(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp2_inv(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp2_div(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
static void sm9_fp2_div2(sm9_fp2_t r, const sm9_fp2_t a);

#define sm9_fp4_init(r)	memcpy((r), &SM9_FP4_ZERO, sizeof(sm9_fp4_t))
#define sm9_fp4_clean(r)	memcpy((r), &SM9_FP4_ZERO, sizeof(sm9_fp4_t))
#define sm9_fp4_set_zero(r)	memcpy((r), &SM9_FP4_ZERO, sizeof(sm9_fp4_t))
#define sm9_fp4_set_one(r)	memcpy((r), &SM9_FP4_ONE, sizeof(sm9_fp4_t))
#define sm9_fp4_is_zero(a)	(memcmp((a), &SM9_FP4_ZERO, sizeof(sm9_fp4_t)) == 0)
#define sm9_fp4_is_one(a)	(memcmp((a), &SM9_FP4_ONE, sizeof(sm9_fp4_t)) == 0)
#define sm9_fp4_equ(a,b)	(memcmp((a), (b), sizeof(sm9_fp4_t)) == 0)
#define sm9_fp4_copy(r,a)	memcpy((r), (a), sizeof(sm9_fp4_t))

static void sm9_fp4_from_hex(sm9_fp4_t r, const char hex[65 * 4]);
static void sm9_fp4_to_hex(const sm9_fp4_t a, char hex[65 * 4]);
static void sm9_fp4_set_fp(sm9_fp4_t r, const sm9_fp_t a);
static void sm9_fp4_set_fp2(sm9_fp4_t r, const sm9_fp2_t a);
static void sm9_fp4_set(sm9_fp4_t r, const sm9_fp2_t a0, const sm9_fp2_t a1);
static void sm9_fp4_set_u(sm9_fp4_t r);
static void sm9_fp4_set_v(sm9_fp4_t r);

static void sm9_fp4_add(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);
static void sm9_fp4_dbl(sm9_fp4_t r, const sm9_fp4_t a);
static void sm9_fp4_sub(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);
static void sm9_fp4_neg(sm9_fp4_t r, const sm9_fp4_t a);
static void sm9_fp4_mul(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);
static void sm9_fp4_mul_fp(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp_t k);
static void sm9_fp4_mul_fp2(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp2_t b0);
static void sm9_fp4_mul_v(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);
static void sm9_fp4_sqr(sm9_fp4_t r, const sm9_fp4_t a);
static void sm9_fp4_sqr_v(sm9_fp4_t r, const sm9_fp4_t a);
static void sm9_fp4_inv(sm9_fp4_t r, const sm9_fp4_t a);

#define sm9_fp12_init(r)	memset((r), 0, sizeof(sm9_fp12_t))
#define sm9_fp12_clean(r)	memset((r), 0, sizeof(sm9_fp12_t))
#define sm9_fp12_set_zero(r)	memset((r), 0, sizeof(sm9_fp12_t))
#define sm9_fp12_copy(r, a)	memcpy((r), (a), sizeof(sm9_fp12_t))

static void sm9_fp12_set_one(sm9_fp12_t r);
static int sm9_fp12_is_one(const sm9_fp12_t a);
static int sm9_fp12_is_zero(const sm9_fp12_t a);
static void sm9_fp12_from_hex(sm9_fp12_t r, const char hex[65 * 12]);
static void sm9_fp12_to_hex(const sm9_fp12_t a, char hex[65 * 12]);
static void sm9_fp12_print(const char *prefix, const sm9_fp12_t a);
static void sm9_fp12_set(sm9_fp12_t r, const sm9_fp4_t a0, const sm9_fp4_t a1, const sm9_fp4_t a2);
static void sm9_fp12_set_fp(sm9_fp12_t r, const sm9_fp_t a);
static void sm9_fp12_set_fp2(sm9_fp12_t r, const sm9_fp2_t a);
static void sm9_fp12_set_fp4(sm9_fp12_t r, const sm9_fp4_t a);
static void sm9_fp12_set_u(sm9_fp12_t r);
static void sm9_fp12_set_v(sm9_fp12_t r);
static void sm9_fp12_set_w(sm9_fp12_t r);
static void sm9_fp12_set_w_sqr(sm9_fp12_t r);

static int sm9_fp12_equ(const sm9_fp12_t a, const sm9_fp12_t b);
static void sm9_fp12_add(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);
static void sm9_fp12_dbl(sm9_fp12_t r, const sm9_fp12_t a);
static void sm9_fp12_tri(sm9_fp12_t r, const sm9_fp12_t a);
static void sm9_fp12_sub(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);
static void sm9_fp12_neg(sm9_fp12_t r, const sm9_fp12_t a);
static void sm9_fp12_mul(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);
static void sm9_fp12_sqr(sm9_fp12_t r, const sm9_fp12_t a);
static void sm9_fp12_inv(sm9_fp12_t r, const sm9_fp12_t a);
static void sm9_fp12_pow(sm9_fp12_t r, const sm9_fp12_t a, const sm9_bn_t k);

static void sm9_fp2_conjugate(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp2_frobenius(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp4_frobenius(sm9_fp4_t r, const sm9_fp4_t a);
static void sm9_fp4_conjugate(sm9_fp4_t r, const sm9_fp4_t a);
static void sm9_fp4_frobenius2(sm9_fp4_t r, const sm9_fp4_t a);
static void sm9_fp4_frobenius3(sm9_fp4_t r, const sm9_fp4_t a);
static void sm9_fp12_frobenius(sm9_fp12_t r, const sm9_fp12_t x);
static void sm9_fp12_frobenius2(sm9_fp12_t r, const sm9_fp12_t x);
static void sm9_fp12_frobenius3(sm9_fp12_t r, const sm9_fp12_t x);
static void sm9_fp12_frobenius6(sm9_fp12_t r, const sm9_fp12_t x);

static void sm9_point_init(sm9_point_t *R);
static void sm9_point_from_hex(sm9_point_t *R, const char hex[65 * 2]);
#define sm9_point_copy(R, P)	memcpy((R), (P), sizeof(sm9_point_t))
static int sm9_point_is_at_infinity(const sm9_point_t *P);
static void sm9_point_set_infinity(sm9_point_t *R);
static void sm9_point_get_xy(const sm9_point_t *P, sm9_fp_t x, sm9_fp_t y);

static int sm9_point_equ(const sm9_point_t *P, const sm9_point_t *Q);
static int sm9_point_is_on_curve(const sm9_point_t *P);
static void sm9_point_dbl(sm9_point_t *R, const sm9_point_t *P);
static void sm9_point_add(sm9_point_t *R, const sm9_point_t *P, const sm9_point_t *Q);
static void sm9_point_neg(sm9_point_t *R, const sm9_point_t *P);
static void sm9_point_sub(sm9_point_t *R, const sm9_point_t *P, const sm9_point_t *Q);
static void sm9_point_mul(sm9_point_t *R, const sm9_bn_t k, const sm9_point_t *P);
static void sm9_point_mul_generator(sm9_point_t *R, const sm9_bn_t k);

static void sm9_twist_point_from_hex(sm9_twist_point_t *R, const char hex[65 * 4]);
#define sm9_twist_point_copy(R, P)	memcpy((R), (P), sizeof(sm9_twist_point_t))
static int sm9_twist_point_is_at_infinity(const sm9_twist_point_t *P);
static void sm9_twist_point_set_infinity(sm9_twist_point_t *R);
static void sm9_twist_point_get_xy(const sm9_twist_point_t *P, sm9_fp2_t x, sm9_fp2_t y);

static int sm9_twist_point_equ(const sm9_twist_point_t *P, const sm9_twist_point_t *Q);
static int sm9_twist_point_is_on_curve(const sm9_twist_point_t *P);
static void sm9_twist_point_neg(sm9_twist_point_t *R, const sm9_twist_point_t *P);
static void sm9_twist_point_dbl(sm9_twist_point_t *R, const sm9_twist_point_t *P);
static void sm9_twist_point_add(sm9_twist_point_t *R, const sm9_twist_point_t *P, const sm9_twist_point_t *Q);
static void sm9_twist_point_sub(sm9_twist_point_t *R, const sm9_twist_point_t *P, const sm9_twist_point_t *Q);
static void sm9_twist_point_add_full(sm9_twist_point_t *R, const sm9_twist_point_t *P, const sm9_twist_point_t *Q);
static void sm9_twist_point_mul(sm9_twist_point_t *R, const sm9_bn_t k, const sm9_twist_point_t *P);
static void sm9_twist_point_mul_G(sm9_twist_point_t *R, const sm9_bn_t k);

static void sm9_eval_g_tangent(sm9_fp12_t num, sm9_fp12_t den, const sm9_twist_point_t *P, const sm9_point_t *Q);
static void sm9_eval_g_line(sm9_fp12_t num, sm9_fp12_t den, const sm9_twist_point_t *T, const sm9_twist_point_t *P, const sm9_point_t *Q);

static void sm9_twist_point_pi1(sm9_twist_point_t *R, const sm9_twist_point_t *P);
static void sm9_twist_point_pi2(sm9_twist_point_t *R, const sm9_twist_point_t *P);
static void sm9_twist_point_neg_pi2(sm9_twist_point_t *R, const sm9_twist_point_t *P);

static void sm9_final_exponent_hard_part(sm9_fp12_t r, const sm9_fp12_t f);
static void sm9_final_exponent(sm9_fp12_t r, const sm9_fp12_t f);
static void sm9_pairing(sm9_fp12_t r, const sm9_twist_point_t *Q, const sm9_point_t *P);

void sm9_pairing_test();

#  ifdef  __cplusplus
}
#  endif
# endif
