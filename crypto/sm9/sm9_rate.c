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
}

static void fp2_mul(fp2_t r, const fp2_t a, const fp2_t b)
{
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

static int fp12_set_zero(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static int fp12_set_one(fp12_t r)
{
	fp4_set_one(r[0]);
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
	fp12_dbl(r, a);
	fp12_add(r, a);
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

