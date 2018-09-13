/* ====================================================================
 * Copyright (c) 2018 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>


typedef uint64_t fp_t[4];
typedef fp_t fp2_t[2];
typedef fp2_t fp4_t[2];
typedef fp4_t fp12_t[3];

typedef struct {
	fp2_t X;
	fp2_t Y;
	fp2_t Z;
} point_t;

static const uint64_t sm9_prime[4] = {
	0xe56f9b27e351457dul, 0x21f2934b1a7aeedbul,
	0xd603ab4ff58ec745ul, 0xb640000002a3a6f1ul
};

static const uint64_t sm9_order[4] = {
	0xe56ee19cd69ecf25ul, 0x49f2934b18ea8beeul,
	0xd603ab4ff58ec744ul, 0xb640000002a3a6f1ul,
};

static const uint64_t sm9_a[2] = {
	0x400000000215d93eul, 0x02ul
};

static const fp2_t sm9_b = {{0, 0, 0, 0}, {5, 0, 0, 0}};

static const int abits = {
	0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,1,0,0,0,0,1,0,1,0,
	1,1,1,0,1,1,0,0,1,0,0,1,1,1,1,1,
	0, };

static const int ebits = {
	0, 0, 1, 0,
};

static int fp_is_zero(const fp_t a)
{
	return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

static int fp_is_one(const fp_t a)
{
	return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

static void fp_set_zero(fp_t r)
{
	r[0] = 0;
	r[1] = 0;
	r[2] = 0;
	r[3] = 0;
}

static void fp_set_one(fp_t r)
{
	r[0] = 1;
	r[1] = 0;
	r[2] = 0;
	r[3] = 0;
}

static void fp_add(fp_t r, const fp_t a)
{
	r[0] += a[0];
	r[1] += a[1];
	r[2] += a[2];
	r[3] += a[3];
}

static void fp_sub(fp_t r, const fp_t a)
{
}

static void fp_neg(fp_t r)
{
}

static int fp2_is_zero(const fp2_t a)
{
	return fp_is_zero(a[0]) && fp_is_zero(a[1]);
}

static int fp2_is_one(const fp2_t a)
{
	return fp_is_one(a[0]) && fp_is_zero(a[1]);
}

static void fp2_set_zero(fp2_t r)
{
	fp_set_zero(r[0]);
	fp_set_zero(r[1]);
}

static void fp2_set_one(fp2_t r)
{
	fp_set_one(r[0]);
	fp_set_zero(r[1]);
}

static void fp2_copy(fp2_t r, const fp2_t a)
{
	fp_copy(r[0], a[0]);
	fp_copy(r[1], a[1]);
}

static void fp2_set(fp2_t r, const fp_t a0, const fp_t a1)
{
	fp_copy(r[0], a0);
	fp_copy(r[1], a1);
}

static void fp2_set_fp(fp2_t r, const fp_t a)
{
	fp_copy(r[0], a);
	fp_set_zero(r[1]);
}

static void fp2_set_u(fp2_t r)
{
	fp_set_zero(r[0]);
	fp_set_one(r[1]);
}

static void fp2_add(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_add(r[0], a[0], b[0]);
	fp_add(r[1], a[1], b[1]);
}

static void fp2_dbl(fp2_t r, const fp2_t a)
{
	fp_dbl(r[0], a[0]);
	fp_dbl(r[1], a[1]);
}

static void fp2_sub(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_sub(r[0], a[0], b[0]);
	fp_sub(r[1], a[1], b[1]);
}

static void fp2_neg(fp2_t r, const fp2_t a)
{
	fp_neg(r[0], a[0]);
	fp_neg(r[1], a[1]);
}

static void fp2_conjugate(fp2_t r, const fp2_t a)
{
	fp2_copy(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

static void fp2_mul(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_t t0, t1, t2;

	fp_mul(t0, a[0], b[0]);
	fp_sqr(t1, a[1], b[1]);
	fp_dbl(t2, t1);
	fp_sub(r[0], t0, t2);

	fp_mul(t0, a[1], b[0]);
	fp_mul(t1, a[0], b[1]);
	fp_add(r[1], t0, t1);
}

static void fp2_mul_u(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_t t0, t1, t2;

	fp_mul(t0, a[1], b[0]);
	fp_mul(t1, a[0], b[1]);
	fp_add(r[0], t0, t1);
	fp_dbl(t0, r[0]);
	fp_neg(r[0], t0);

	fp_mul(t0, a[0], b[0]);
	fp_mul(t1, a[1], b[1]);
	fp_dbl(t2, t1);
	fp_sub(r[1], t0, t2);
}

static void fp2_sqr(fp2_t r, const fp2_t a)
{
	fp_t t0, t1, t2;

	fp_sqr(t0, a[0]);
	fp_sqr(t1, a[1]);
	fp_dbl(t2, t1);
	fp_sub(r[0], t0, t2);

	fp_mul(t0, a[0], a[1]);
	fp_dbl(r[1], t0);
}

static void fp2_sqr_u(fp2_t r, const fp2_t a)
{
	fp_t t0, t1, t2;

	fp_mul(t0, a[0], a[1]);
	fp_dbl(t1, t0);
	fp_dbl(t2, t1);
	fp_neg(r[0], t2);

	fp_sqr(t0, a[0]);
	fp_sqr(t1, a[1]);
	fp_dbl(t2, t1);
	fp_sub(r[1], t0, t2);
}

static void fp2_inv(fp2_t r, const fp2_t a)
{
	fp_t k, t0, t1, t2;

	if (fp_is_zero(a[1])) {
		fp_inv(r[0], a[0]);
		fp_set_zero(r[1])
	} else if (fp_is_zero(a[0])) {
		fp_set_zero(r[0]);
		fp_dbl(t0, a[1]);
		fp_inv(t1, t0);
		fp_neg(r[1], t1);
	} else {
		fp_sqr(t0, a[1]);
		fp_dbl(t1, t0);
		fp_sqr(t0, a[0]);
		fp_add(t2, t0, t1);
		fp_inv(k, t2);
	
		fp_mul(r[0], a[0], k);
		fp_mul(t0, a[1], k);
		fp_neg(r[1], t0);
	}
}

static int fp4_is_zero(const fp4_t a)
{
	return fp2_is_zero(a[0]) && fp2_is_zero(a[1]);
}

static int fp4_is_one(const fp4_t a)
{
	return fp2_is_one(a[0]) && fp2_is_zero(a[1]);
}

static void fp4_set_zero(fp4_t r)
{
	fp2_set_zero(r[0]);
	fp2_set_zero(r[1]);
}

static void fp4_set_one(fp4_t r)
{
	fp2_set_one(r[0]);
	fp2_set_zero(r[1]);
}

static void fp4_set_fp(fp4_t r, const fp_t a)
{
	fp2_set_fp(r[0], a);
	fp2_set_zero(r[1]);
}

static void fp4_set_fp2(fp4_t r, const fp2_t 0)
{
	fp2_copy(r[0], a);
	fp2_set_zero(r[1]);
}

static void fp4_set(fp4_t r, const fp2_t a0, const fp2_t a1)
{
	fp2_copy(r[0], a0);
	fp2_copy(r[1], a1);
}

static void fp4_copy(fp4_t r, const fp4_t a)
{
	fp2_copy(r[0], a[0]);
	fp2_copy(r[1], a[1]);
}

static void fp4_set_u(fp4_t r)
{
	fp2_set_u(r[0]);
	fp2_set_zero(r[1]);
}

static void fp4_set_v(fp4_t r)
{
	fp2_set_zero(r[0]);
	fp2_set_one(r[1]);
}

static void fp4_add(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp2_add(r[0], a[0], b[0]);
	fp2_add(r[1], a[1], b[1]);
}

static void fp4_dbl(fp4_t r, const fp4_t a)
{
	fp2_dbl(r[0], a[0]);
	fp2_dbl(r[1], a[1]);
}

static void fp4_sub(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp2_sub(r[0], a[0], b[0]);
	fp2_sub(r[1], a[1], b[1]);
}

static void fp4_neg(fp4_t r, const fp4_t a)
{
	fp2_neg(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

static void fp4_mul(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp4_t t0, t1;

	fp2_mul_u(t0, a[1], b[1]);
	fp2_mul(t1, a[0], b[0]);
	fp2_add(r[0], t0, t1);

	fp2_mul(t0, a[1], b[0]);
	fp2_mul(t1, a[0], b[1]);
	fp2_add(r[1], t0, t1);	
}

static void fp4_mul_v(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp2_t t0, t1;

	fp2_mul_u(t0, a[0], b[1]);
	fp2_mul_u(t1, a[1], b[0]);
	fp2_add(r[0], t0, t1);

	fp2_mul(t0, a[0], b[0]);
	fp2_mul_u(t1, a[1], b[1]);
	fp2_add(r[1], t0, t1);
}

static void fp4_sqr(fp4_t r, const fp4_t a)
{
	fp2_t t0, t1;

	fp2_sqr_u(t0, a[1]);
	fp2_sqr(t1, a[0]);
	fp2_add(r[0], t0, t1);

	fp2_mul(t0, a[0], a[1]);
	fp2_dbl(r[1], t0);
}

static void fp4_sqr_v(fp4_t r, const fp4_t a)
{
	fp2_t t0, t1;

	fp2_mul_u(t0, a[0], a[1]);
	fp2_dbl(r[0], t0);

	fp2_sqr(t0, a[0]);
	fp2_sqr_u(t1, a[1]);
	fp2_add(r[1], t0, t1);
}

static void fp4_inv(fp4_t r, const fp4_t a)
{
	fp2_t t0, t1, t2;

	fp2_sqr_u(t0, a[1]);
	fp2_sqr(t1, a[0]);
	fp2_sub(t2, t0, t1);
	fp2_inv(t0, t2);

	fp2_mul(t1, a[0], t0);
	fp2_neg(r[0], t1);
	fp2_mul(r[1], a[1], t0);
}

static int fp12_is_zero(const fp12_t a)
{
	return fp12_is_zero(a[0]) && fp12_is_zero(a[1]) && fp12_is_zero(a[2]);
}

static int fp12_is_one(const fp12_t a)
{
	return fp12_is_one(a[0]) && fp12_is_zero(a[1]) && fp12_is_zero(a[2]);
}

static void fp12_set_zero(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_one(fp12_t r)
{
	fp4_set_one(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_copy(fp12_t r, const fp12_t a)
{
	fp4_copy(r[0], a[0]);
	fp4_copy(r[1], a[1]);
	fp4_copy(r[2], a[2]);
}

static void fp12_set(fp12_t r, const fp4_t a0, const fp4_t a1, const fp4_t a2)
{
	fp4_copy(r[0], a0);
	fp4_copy(r[1], a1);
	fp4_copy(r[2], a2);
}

static void fp12_set_fp4(fp12_t r, const fp4_t a)
{
	fp4_copy(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_fp2(fp12_t r, const fp2_t a)
{
	fp4_set_fp2(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_fp(fp12_t r, const fp_t a)
{
	fp4_set_fp(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_add(fp12_t r, fp12_t a, const fp12_t b)
{
	fp4_add(r[0], a[0], b[0]);
	fp4_add(r[1], a[1], b[1]);
	fp4_add(r[2], a[2], b[2]);	
}

static void fp12_dbl(fp12_t r, fp12_t a)
{
	fp4_dbl(r[0], a[0]);
	fp4_dbl(r[1], a[1]);
	fp4_dbl(r[2], a[2]);
}

static void fp12_tri(fp12_t r, fp12_t a)
{
	fp12_t t;
	fp12_dbl(t, a);
	fp12_add(r, t, a);
}

static void fp12_sub(fp12_t r, const fp12_t a, const fp12_t b)
{
	fp4_sub(r[0], a[0], b[0]);
	fp4_sub(r[1], a[1], b[1]);
	fp4_sub(r[2], a[2], b[2]);
}

static void fp12_neg(fp12_t r, const fp12_t a)
{
	fp4_neg(r[0], a[0]);
	fp4_neg(r[1], a[1]);
	fp4_neg(r[2], a[2]);
}

static void fp12_mul(fp12_t r, const fp12_t a, const fp12_t b)
{
	fp4_mul(r[0], a[0], b[0]);
	fp4_mul_v(t, a[1], b[2]);
	fp4_add_to(r[0], t);
	fp4_mul_v(t, a[2], b[1]);
	fp4_add_to(r[0], t);

	fp4_mul(r[1], a[0], b[1]);
	fp4_mul(t, a[1], b[0]);
	fp4_add_to(r[1], t);	
	fp4_mul_v(t, a[2], b[2]);
	fp4_add_to(r[1], t);

	fp4_mul(r[2], a[0], b[2]);
	fp4_mul(t, a[1], b[1]);
	fp4_add_to(r[2], t);
	fp4_mul(t, a[2], b[0]);
	fp4_add_to(r[2], t);
}

static void fp12_sqr(fp12_t r, const fp12_t a)
{
	fp4_sqr(r[0], a[0]);
	fp4_mul_v(t, a[1], a[2]);
	fp4_dbl_to(t, t);
	fp4_add(r[0], t);

	fp4_mul(t, a[0], a[1]);
	fp4_dbl(r[0], t);
	fp4_sqr_v(t, a[2]);
	fp4_add(r[0], t);

	fp4_mul(t, a[0], a[2]);
	fp4_dbl(r[2], t);
	fp4_sqr(t, a[1]);
	fp4_add(r[2], t);
}

static void fp12_inv(fp12_t r, const fp12_t a)
{
	if (fp4_is_zero(a[2])) {
		fp4_sqr(t, a[0]);
		fp4_mul(k, t, a[0]);
		fp4_sqr_v(t, a[1]);
		fp4_mul_to(t, a[1]);
		fp4_add_to(k, t);
		fp4_inv_to(k);

		fp4_sqr(r[0], a[0]);
		fp4_mul(r[0], r[0], k);

		fp4_mul(r[0], a[0], a[1]);
		fp4_mul(r[0], r[0], k);
		fp4_neg(r[0], r[0]);

		fp4_sqr(r[2], a[1]);
		fp4_mul(r[2], r[2], k);
	} else {
		fp4_sqr(t0, a[1]);
		fp4_mul(t1, a[0], a[2]);
		fp4_sub(t0, t0, t1);

		fp4_mul(t1, a[0], a[1]);
		fp4_sqr_v(t2, a[2]);
		fp4_sub(t1, t1, t2);

		fp4_sqr(t2, a[0]);
		fp4_mul_v(t3, a[1], a[2]);
		fp4_sub(t2, t2, t3);

		fp4_sqr(t1, t1);
		fp4_mul(t4, t0, t2);
		fp4_sub(t1, t1, t5);
		fp4_mul(t3, a[2], t3)
		fp4_inv(t3, t3);
	
		fp4_mul(r[0], t2, t3);
		fp4_mul(r[1], t1, t3);
		fp4_inv(r[1], r[1]);
		fp4_mul(r[2], t0, t3);
	}
}

static void fp12_pow(fp12_t r, const fp12_t a, const fp_t k)
{
}

static int point_is_at_infinity(point_t P)
{
	return 0;
}

static int point_is_on_curve(point_t P)
{
	fp2_t x, y;
	point_get_affine_coordinates(P, x, y);
	fp2_sqr(t0, x);
	fp2_mul(t1, t0, x);
	fp2_add(t0, sm9_b);
	fp2_sqr(t1, y);
	return fp2_equ(t0, t1);
}

static void point_set_infinity(point_t P)
{
	fp2_set_zero(P.X);
	fp2_set_one(P.Y);
	fp2_set_zero(P.Z);
}

static void point_set_affine_coordinates(point_t P, const fp2_t x, const fp2_t y)
{
	fp2_copy(P.X, x);
	fp2_copy(P.Y, y);
	fp2_set_one(P.Z);
}

static void point_get_affine_coordinates(const point_t P, fp2_t x, fp2_t y)
{
	fp2_copy(x, P.X);
	fp2_copy(y, P.y);
}

static void point_dbl(point_t R, const point_t P)
{
	fp2_t x3, y3, x1, y1, lambda, t0, t1;

	if (point_is_at_infinity(P)) {
		point_set_infinity(R);
		return;
	}

	point_get_affine_coorindates(P, x1, y1);

	fp12_sqr(t0, x1);
	fp12_tri(t1, t0);
	fp12_dbl(t0, y1);
	fp12_div(lambda, t1, t0);

	fp12_sqr(t0, lambda);
	fp12_dbl(t1, x1);
	fp12_sub(x3, t0, t1);

	fp12_sub(t0, x1, x3);
	fp12_mul(t1, lambda, t0);
	fp12_sub(y3, t1, y1);

	point_set_affine_coordinates(R, x3, y3);	
}

static void point_add(point_t R, const point_t P, const point_t Q)
{
	if (point_is_at_infinity(P)) {
		point_copy(R, Q);
		return;
	}

	if (point_is_at_infinity(Q)) {
		point_copy(R, P);
		return;
	}

	point_get_affine_coordinates(P, x1, y1);
	point_get_affine_coordinates(Q, x2, y2);

	fp2_add(t0, y1, y2);
	if (fp2_equ(x1, x2) && fp2_is_zero(t0)) {
		point_set_infinity(R);
	}

	if (point_equ(P, Q)) {
		point_dbl(R, P);
		return;
	}

	fp2_sub(t0, y2, y1);
	fp2_sub(t1, x2, x1);
	fp2_div(lambda, t0, t1);

	fp2_sqr(t0, lambda);
	fp2_sub(t1, x1, x2);
	fp2_sub(x3, t0, t1);

	fp2_sub(t0, x1, x3);
	fp2_mul(t1, lambda, t0);
	fp2_sub(y3, t1, y1);

	point_set_affine_coordinates(R, x3, y3);
}

static void point_neg(point_t R, const point_t P)
{
	fp2_copy(R.X, P.X);
	fp2_neg(R.y, P.y);
	fp2_copy(R.Z, P.Z);
}

static void point_sub(point_t R, const point_t P, const point_t Q)
{
	point_t T;
	point_neg(T, Q);
	point_add(R, P, T);
}

static void point_mul(point_t R, const fp_t k, const point_t P)
{
}

static void eval_tangent(fp12_t r, const fp12_t xP, const fp12_t yP, const fp_t xQ, const fp_t yQ)
{
	fp12_t x, y, lambda, t0, t1;

	fp12_set_fp(x, xQ);
	fp12_set_fp(y, yQ);

	fp12_sqr(t0, xP);
	fp12_tri(t1, t0);
	fp12_dbl(t0, yP);
	fp12_inv(t2, t0);
	fp12_mul(lambda, t1, t2);

	fp12_sub(t0, x, xP);
	fp12_mul(t1, lambda, t0);
	fp12_sub(t0, y, yP);
	fp12_sub(r, t1, t0);
}

static void eval_line(fp12_t r, const fp12_t xT, const fp12_t yT,
	const fp12_t xP, const fp12_t yP, const fp_t xQ, const fp_t yQ)
{
	fp12_t x, y, lambda, t0, t1;

	fp12_set_fp(x, xQ);
	fp12_set_fp(y, yQ);

	fp12_sub(t0, yT, yP);
	fp12_sub(t1, xT, xP);
	fp12_div(lambda, t0, t1);

	fp12_sub(t0, x, xP);
	fp12_mul(t1, lambda, t0);
	fp12_sub(t0, y, yP);
	fp12_sub(r, t1, t0);
}

static void frob(fp12_t xR, fp12_t yR, const point_t P)
{
	fp2_t x, y;
	fp12_t t0, t1;

	point_get_affine_coordinates(x, y, R);

	fp2_conjugate(x);
	fp2_conjugate(y);
	fp12_set_fp(t0, x);
	fp12_set_fp(t1, y);
	fp12_mul(xR, t0, w2p);
	fp12_mul(yR, t1, w3p);
}

static void frob_twice(fp12_t xR, fp12_t yR, const point_t P)
{
	fp2_t x, y;
	fp12_t t0, t1;

	
	point_get_affine_coordinates(x, y, R);


}

static void final_expo(fp12_t r, const fp12_t a)
{
	fp12_copy(r, a);
	for (i = 0; i < sizeof(ebits); i++) {
		fp12_sqr_to(r);
		if (ebits[i]) {
			fp12_mul_to(r, a);
		}
	}
}

static void rate(fp12_t r, const point_t Q,  const fp_t xP, const fp_t yP)
{
	int i;

	fp12_t f, g;

	point_copy(T, Q);
	fp12_set_one(f);

	for (i = 0; i < sizeof(abits); i++) {
		eval(g, T, T, xP, yP);

		fp12_sqr(t0, f);
		fp12_mul(t1, t0, g);
		fp12_copy(f, t1);

		point_dbl(R, T);
		point_copy(T, R);

		if (abits[i]) {
			eval(g, T, Q, xP, yP);

			fp12_mul(t0, f, g);
			fp12_copy(f, t0);

			point_add(R, T, Q);
			point_copy(T, R);
		}
	}

	frob(Q, Q1);
	frob_twice(Q, Q2);

	eval(g, T, Q1, xP, yP);
	fp12_mul(t, f, g);
	fp12_copy(f, t);

	point_add(R, T, Q1);
	point_copy(T, R);

	point_neg(R, Q2);
	eval(g, T, R, xP, yP);
	fp12_mul(t, f, g);
	fp12_copy(f, t);

	final_expo(r, f);
}

int test()
{
	char *x_P1_str = "0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD";
	char *y_P1_str = "0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616";
	char *x_P2_1_str = "85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141";
	char *x_P2_0_str = "3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B";
	char *y_P2_1_str = "17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96";
	char *y_P2_0_str = "A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7";
	char *ks_str = "0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4";	
	char *x_Ppubs_1_str = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
	char *x_Ppubs_0_str = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
	char *y_Ppubs_1_str = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
	char *y_Ppubs_0_str = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";	
	char *g_str[] =  {
		"4E378FB5561CD0668F906B731AC58FEE25738EDF09CADC7A29C0ABC0177AEA6D",
		"28B3404A61908F5D6198815C99AF1990C8AF38655930058C28C21BB539CE0000",
		"38BFFE40A22D529A0C66124B2C308DAC9229912656F62B4FACFCED408E02380F",
		"A01F2C8BEE81769609462C69C96AA923FD863E209D3CE26DD889B55E2E3873DB",
		"67E0E0C2EED7A6993DCE28FE9AA2EF56834307860839677F96685F2B44D0911F",
		"5A1AE172102EFD95DF7338DBC577C66D8D6C15E0A0158C7507228EFB078F42A6",
		"1604A3FCFA9783E667CE9FCB1062C2A5C6685C316DDA62DE0548BAA6BA30038B",
		"93634F44FA13AF76169F3CC8FBEA880ADAFF8475D5FD28A75DEB83C44362B439",
		"B3129A75D31D17194675A1BC56947920898FBF390A5BF5D931CE6CBB3340F66D",
		"4C744E69C4A2E1C8ED72F796D151A17CE2325B943260FC460B9F73CB57C9014B",
		"84B87422330D7936EABA1109FA5A7A7181EE16F2438B0AEB2F38FD5F7554E57A",
		"AAB9F06A4EEBA4323A7833DB202E4E35639D93FA3305AF73F0F071D7D284FCFB"};
	char *r_str = "033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE";
	char *w_str[] = {
		"81377B8FDBC2839B4FA2D0E0F8AA6853BBBE9E9C4099608F8612C6078ACD7563",
		"815AEBA217AD502DA0F48704CC73CABB3C06209BD87142E14CBD99E8BCA1680F",
		"30DADC5CD9E207AEE32209F6C3CA3EC0D800A1A42D33C73153DED47C70A39D2E",
		"8EAF5D179A1836B359A9D1D9BFC19F2EFCDB829328620962BD3FDF15F2567F58",
		"A543D25609AE943920679194ED30328BB33FD15660BDE485C6B79A7B32B01398",
		"3F012DB04BA59FE88DB889321CC2373D4C0C35E84F7AB1FF33679BCA575D6765",
		"4F8624EB435B838CCA77B2D0347E65D5E46964412A096F4150D8C5EDE5440DDF",
		"0656FCB663D24731E80292188A2471B8B68AA993899268499D23C89755A1A897",
		"44643CEAD40F0965F28E1CD2895C3D118E4F65C9A0E3E741B6DD52C0EE2D25F5",
		"898D60848026B7EFB8FCC1B2442ECF0795F8A81CEE99A6248F294C82C90D26BD",
		"6A814AAF475F128AEF43A128E37F80154AE6CB92CAD7D1501BAE30F750B3A9BD",
		"1F96B08E97997363911314705BFB9A9DBB97F75553EC90FBB2DDAE53C8F68E42"};

	EC_POINT *P1 = NULL;

	EC_GROUP *group = NULL;


	if (!EC_POINT_set_affine_coordinates_GFp(group, P1, xP1, yP1, bn_ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}



	fp2_set(x_P2, x0, x1);
	fp2_set(y_P2, y0, y1);
	point_set_affine_coordinates(P2, x_P2, y_P2);

	point_mul(R, k, P2);
	point_is_at_infinity(R);

	
	point_mul(Ppubs, ks, P2);

	sm9_rate(g, Ppubs, P1);

}
