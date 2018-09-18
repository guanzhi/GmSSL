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
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>

typedef BIGNUM *fp2_t[2];
typedef fp2_t fp4_t[2];
typedef fp4_t fp12_t[3];
typedef struct {
	fp2_t X;
	fp2_t Y;
	fp2_t Z;
} point_t;

static const uint64_t sm9_a[2] = {
	0x400000000215d93eul, 0x02ul
};

static int fp2_init(fp2_t a, BN_CTX *ctx)
{
	a[0] = NULL;
	a[1] = NULL;
	a[0] = BN_CTX_get(ctx);
	a[1] = BN_CTX_get(ctx);
	if (!a[1]) {
		BN_free(a[0]);
		a[0] = NULL;
		return 0;
	}
	return 1;
}

static void fp2_cleanup(fp2_t a)
{
	BN_free(a[0]);
	BN_free(a[1]);
	a[0] = NULL;
	a[1] = NULL;
}

static void fp2_clear_cleanup(fp2_t a)
{
	BN_clear_free(a[0]);
	BN_clear_free(a[1]);
	a[0] = NULL;
	a[1] = NULL;
}

static int fp2_is_zero(fp2_t a)
{
	return BN_is_zero(a[0])
		&& BN_is_zero(a[1]);
}

static int fp2_is_one(fp2_t a)
{
	return BN_is_one(a[0])
		&& BN_is_zero(a[1]);
}

static void fp2_set_zero(fp2_t r)
{
	BN_zero(r[0]);
	BN_zero(r[1]);
}

static int fp2_set_one(fp2_t r)
{
	BN_zero(r[1]);
	return BN_one(r[0]);
}

static int fp2_copy(fp2_t r, const fp2_t a)
{
	return BN_copy(r[0], a[0])
		&& BN_copy(r[1], a[1]);
}

static int fp2_set(fp2_t r, const BIGNUM *a0, const BIGNUM *a1)
{
	return BN_copy(r[0], a0)
		&& BN_copy(r[1], a1);
}

static int fp2_set_u(fp2_t r)
{
	BN_zero(r[0]);
	return BN_one(r[1]);
}

static int fp2_set_bn(fp2_t r, const BIGNUM *a)
{
	BN_zero(r[1]);
	return BN_copy(r[0], a);
}

static int fp2_set_word(fp2_t r, unsigned long a)
{
	BN_zero(r[1]);
	return BN_set_word(r[0], a);
}

static int fp2_equ(const fp2_t a, const fp2_t b)
{
	return !BN_cmp(a[0], b[0]) && !BN_cmp(a[1], b[1]);
}

static int fp2_add(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_add(r[0], a[0], b[0], p, ctx)
		&& BN_mod_add(r[1], a[1], b[1], p, ctx);
}

static int fp2_dbl(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_add(r[0], a[0], a[0], p, ctx)
		&& BN_mod_add(r[1], a[1], a[1], p, ctx);
}

static int fp2_sub(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_sub(r[0], a[0], b[0], p, ctx)
		&& BN_mod_sub(r[1], a[1], b[1], p, ctx);
}

static int fp2_neg(fp2_t r, const fp2_t a, const BIGNUM *p)
{
	return BN_sub(r[0], p, a[0])
		&& BN_sub(r[1], p, a[1]);
}

static void fp2_conjugate(fp2_t r, const fp2_t a, const BIGNUM *p)
{
	return fp2_copy(r[0], a[0])
		&& fp2_neg(r[1], a[1], p);
}

static int fp2_mul(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *t = NULL;
	if (!(t = BN_CTX_get(ctx))
		/* r0 = a0 * b0 - 2 * a1 * b1 */
		|| !BN_mod_mul(r[0], a[0], b[0], p, ctx)
		|| !BN_mod_sqr(t, a[1], b[1], p, ctx)
		|| !BN_mod_add(t, t, t, p, ctx)
		|| !BN_mod_sub(r[0], r[0], t, p, ctx)

		/* r1 = a0 * b1 + a1 * b0 */
		|| !BN_mod_mul(r[1], a[0], b[1], p, ctx)
		|| !BN_mod_mul(t, a[1], b[0], p, ctx)
		|| !BN_mod_add(r[1], r[1], t, p, ctx)) {
		BN_free(t);
		return 0;
	}
	BN_free(t);
	return 1;
}

static int fp2_mul_u(fp2_t r, fp2_t a, fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *t = NULL;
	if (!(t = BN_CTX_get(ctx))
		/* r0 = -2 * (a0 * b1 + a1 * b0) */
		|| !BN_mod_mul(r[0], a[0], b[1], p, ctx)
		|| !BN_mod_mul(t, a[1], b[0], p, ctx)
		|| !BN_mod_add(r[0], r[0], t, p, ctx)
		|| !BN_mod_add(r[0], r[0], r[0], p, ctx)
		|| !BN_mod_sub(r[0], p, r[0], p, ctx)

		/* r1 = a0 * b0 - 2 * a1 * b1 */
		|| !BN_mod_mul(r[1], a[0], b[0], p, ctx)
		|| !BN_mod_mul(t, a[1], b[1], p, ctx)
		|| !BN_mod_add(t, t, t, p, ctx)
		|| !BN_mod_sub(r[1], r[1], t, p, ctx)) {
		BN_free(t);
		return 0;
	}
	BN_free(t);
	return 1;
}

static int fp2_sqr(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *t = NULL;
	if (!(t = BN_CTX_get(ctx))
		/* r0 = a0^2 - 2 * a1^2 */
		|| !BN_mod_sqr(r[0], a[0], p, ctx)
		|| !BN_mod_sqr(t, a[1], p, ctx)
		|| !BN_mod_add(t, t, t, p, ctx)
		|| !BN_mod_sub(r[0], r[0], t, p, ctx)

		/* r1 = 2 * a0 * a1 */
		|| !BN_mod_mul(r[1], a[0], a[1], p, ctx)
		|| !BN_mod_add(r[1], r[1], r[1], p, ctx)) {
		BN_free(t);
		return 0;
	}
	BN_free(t);
	return 1;
}

static int fp2_sqr_u(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *t = NULL;
	if (!(t = BN_CTX_get(ctx))
		/* r0 = -4 * a0 * a1 */
		|| !BN_mod_mul(r[0], a[0], a[1], p, ctx)
		|| !BN_mod_add(r[0], r[0], r[0], p, ctx)
		|| !BN_mod_add(r[0], r[0], r[0], p, ctx)
		|| !BN_mod_sub(r[0], p, r[0], p, ctx)

		/* r1 = a0^2 - 2 * a1^2 */
		|| !BN_mod_sqr(r[1], a[0], p, ctx)
		|| !BN_mod_sqr(t, a[1], p, ctx)
		|| !BN_mod_add(t, t, t, p, ctx)
		|| !BN_mod_sub(r[1], r[1], t, p, ctx)) {
		BN_free(t);
		return 0;
	}
	BN_free(t);
	return 1;
}

static int fp2_inv(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	if (BN_is_zero(a[0])) {
		/* r0 = 0 */
		BN_zero(r[0]);
		/* r1 = -(2 * a1)^-1 */
		if (!BN_mod_add(r[0], a[1], a[1], p, ctx)
			|| !BN_mod_inverse(r[0], r[0], p, ctx)
			|| !BN_mod_sub(r[0], p, r[0], p, ctx)) {
			return 0;
		}

	} else if (BN_is_zero(a[1])) {
		/* r1 = 0 */
		BN_zero(r[1]);
		/* r0 = a0^-1 */
		if (!BN_mod_inverse(r[0], a[0], p, ctx)) {
			return 0;
		}

	} else {
		if (!(k = BN_CTX_get(ctx))
			|| !(t = BN_CTX_get(ctx))

			/* k = (a[0]^2 + 2 * a[1]^2)^-1 */
			|| !BN_mod_sqr(k, a[0], p, ctx)
			|| !BN_mod_sqr(t, a[1], p, ctx)
			|| !BN_mod_add(t, t, t, p, ctx)
			|| !BN_mod_add(k, k, t, p, ctx)
			|| !BN_mod_inverse(k, k, p, ctx)

			/* r[0] = a[0] * k, r[1] = -a[1] * k */
			|| !BN_mod_mul(r[0], a[0], k, p, ctx)
			|| !BN_mod_mul(r[1], a[1], k, p, ctx)
			|| !BN_mod_sub(r[1], p, r[1], p, ctx)) {
			BN_free(k);
			BN_free(t);
			return 0;
		}
		BN_free(k);
		BN_free(t);
	}

	return 1;
}

static int fp2_div(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_inv(r, b, p, ctx)
		&& fp2_mul(r, a, r, p, ctx);
}

static int fp4_init(fp4_t a, BN_CTX *ctx)
{
	int r;
	r = fp2_init(a[0], ctx);
	r &&= fp2_init(a[1], ctx);
	if (!r) {
		fp2_cleanup(a[0]);
		fp2_cleanup(a[1]);
	}
}

static void fp4_cleanup(fp4_t a)
{
	fp2_cleanup(a[0]);
	fp2_cleanup(a[1]);
}

static void fp4_clear_cleanup(fp4_t a)
{
	fp2_clear_cleanup(a[0]);
	fp2_clear_cleanup(a[1]);
}

static int fp4_is_zero(const fp4_t a)
{
	return fp2_is_zero(a[0])
		&& fp2_is_zero(a[1]);
}

static int fp4_is_one(const fp4_t a)
{
	return fp2_is_one(a[0])
		&& fp2_is_zero(a[1]);
}

static void fp4_set_zero(fp4_t r)
{
	fp2_set_zero(r[0]);
	fp2_set_zero(r[1]);
}

static int fp4_set_one(fp4_t r)
{
	fp2_set_zero(r[1]);
	return fd2_set_one(r[0]);
}

static int fp4_set_bn(fp4_t r, const BIGNUM *a)
{
	fp2_set_zero(r[1]);
	return fp2_set_bn(r[0], a);
}

static int fp4_set_word(fp4_t r, unsigned long a)
{
	fp2_set_zero(r[1]);
	return fp2_set_word(r[0], a);
}

static int fp4_set_fp2(fp4_t r, const fp2_t a)
{
	fp2_set_zero(r[1]);
	return fp2_copy(r[0], a);
}

static int fp4_set(fp4_t r, const fp2_t a0, const fp2_t a1)
{
	return fp2_copy(r[0], a0)
		&& fp2_copy(r[1], a1);
}

static int fp4_copy(fp4_t r, const fp4_t a)
{
	return fp2_copy(r[0], a[0])
		&& fp2_copy(r[1], a[1]);
}

static int fp4_set_u(fp4_t r)
{
	fp2_set_zero(r[1]);
	return fp2_set_u(r[0]);
}

static int fp4_set_v(fp4_t r)
{
	fp2_set_zero(r[0]);
	return fp2_set_one(r[1]);
}

static int fp4_equ(const fp4_t a, const fp4_t b)
{
	return fp2_equ(a[0], b[0])
		&& fp2_equ(a[1], b[1]);

static int fp4_add(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_add(r[0], a[0], b[0], p, ctx)
		&& fp2_add(r[1], a[1], b[1], p, ctx);
}

static int fp4_dbl(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_dbl(r[0], a[0], p, ctx)
		&& fp2_dbl(r[1], a[1], p, ctx);
}

static int fp4_sub(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_sub(r[0], a[0], b[0], p, ctx)
		&& fp2_sub(r[1], a[1], b[1], p, ctx);
}

static int fp4_neg(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_neg(r[0], a[0], p, ctx)
		&&fp2_neg(r[1], a[1], p, ctx);
}

static int fp4_mul(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t t;
	if (!fp2_init(t, ctx)
		/* r[0] = a[0] * b[0] + a[1] * b[1] * u */
		|| !fp2_mul(r[0], a[0], b[0], p, ctx)
		|| !fp2_mul_u(t, a[1], b[1], p, ctx)
		|| !fp2_add(r[0], r[0], t, p, ctx)

		/* r[1] = a[0] * b[1] + a[1] * b[0] */
		|| !fp2_mul(r[1], a[0], b[1], p, ctx)
		|| !fp2_mul(t, a[1], b[0], p, ctx)
		|| !fp2_add(r[1], r[1], t, p, ctx)) {
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(t);
	return 1;
}

static int fp4_mul_v(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t t;
	if (!fp2_init(t, ctx)
		/* r[0] = a[0] * b[1] * u + a[1] * b[0] * u */
		|| !fp2_mul_u(r[0], a[0], b[1], p, ctx)
		|| !fp2_mul_u(t, a[1], b[0], p, ctx)
		|| !fp2_add(r[0], r[0], t, p, ctx)

		/* r[1] = a[0] * b[0] + a[1] * b[1] * u */
		|| !fp2_mul(r[1], a[0], b[0], p, ctx)
		|| !fp2_mul_u(t, a[1], b[1], p, ctx)
		|| !fp2_add(r[1], r[1], t, p, ctx)) {
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(t);
	return 1;
}

static int fp4_sqr(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t t;
	if (!fp2_init(t, ctx)
		/* r[0] = a[0]^2 + a[1]^2 * u */
		|| !fp2_sqr(r[0], a[0], p, ctx)
		|| !fp2_sqr_u(t, a[1], p, ctx)
		|| !fp2_add(r[0], r[0], t, p, ctx)
		/* r[1] = 2 * (a[0] * a[1]) */
		|| !fp2_mul(r[1], a[0], a[1], p, ctx)
		|| !fp2_dbl(r[1], r[1], p, ctx)) {
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(t);
	return 1;
}

static int fp4_sqr_v(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t t;
	if (!fp2_init(t, ctx)
		/* r[0] = 2 * (a[0] * a[1]) */
		|| !fp2_mul_u(t0, a[0], a[1], p, ctx)
		|| !fp2_dbl(r[0], t0, p, ctx)

		/* r[1] = a[0]^2 + a[1]^2 * u */
		|| !fp2_sqr(r[1], a[0], p, ctx)
		|| !fp2_sqr_u(t, a[1], p, ctx)
		|| !fp2_add(r[1], r[1], t, p, ctx)) {
		fp_cleanup(t);
		return 0;
	}
	fp_cleanup(t);
	return 1;
}

static int fp4_inv(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t k;
	if (!fp2_init(k, ctx)
		/* k = (a[1]^2 * u - a[0]^2)^-1 */
		|| !fp2_sqr_u(k, a[1], p, ctx)
		|| !fp2_sqr(r[0], a[0], p, ctx)
		|| !fp2_sub(k, k, r[0], p, ctx)
		|| !fp2_inv(k, k, p, ctx)

		/* r[0] = -(a[0] * k) */
		|| !fp2_mul(r[0], a[0], k, p, ctx)
		|| !fp2_neg(r[0], r[0], p, ctx)

		/* r[1] = a[1] * k */
		|| !fp2_mul(r[1], a[1], k, p, ctx)) {
		fp2_cleanup(k);
		return 0;
	}
	fp2_cleanup(k);
	return 1;
}

static int fp12_init(fp12_t a, BN_CTX *ctx)
{
	int r;
	r = fp4_init(a[0], ctx);
	r &&= fp4_init(a[1], ctx);
	r &&= fp4_init(a[2], ctx);
	if (!r) {
		fp4_cleanup(a[0]);
		fp4_cleanup(a[1]);
		fp4_cleanup(a[2]);
	}
	return r;
}

static void fp12_cleanup(fp12_t a)
{
	fp4_cleanup(a[0]);
	fp4_cleanup(a[1]);
	fp4_cleanup(a[2]);
}

static void fp12_clear_cleanup(fp12_t a)
{
	fp4_clear_cleanup(a[0]);
	fp4_clear_cleanup(a[1]);
	fp4_clear_cleanup(a[2]);
}

static int fp12_is_zero(const fp12_t a)
{
	return fp12_is_zero(a[0])
		&& fp12_is_zero(a[1])
		&& fp12_is_zero(a[2]);
}

static int fp12_is_one(const fp12_t a)
{
	return fp12_is_one(a[0])
		&& fp12_is_zero(a[1])
		&& fp12_is_zero(a[2]);
}

static void fp12_set_zero(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static int fp12_set_one(fp12_t r)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_one(r[0]);
}

static int fp12_copy(fp12_t r, const fp12_t a)
{
	return fp4_copy(r[0], a[0])
		&& fp4_copy(r[1], a[1])
		&& fp4_copy(r[2], a[2]);
}

static int fp12_set(fp12_t r, const fp4_t a0, const fp4_t a1, const fp4_t a2)
{
	return fp4_copy(r[0], a0)
		&& fp4_copy(r[1], a1)
		&& fp4_copy(r[2], a2);
}

static int fp12_set_fp4(fp12_t r, const fp4_t a)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_copy(r[0], a);
}

static int fp12_set_fp2(fp12_t r, const fp2_t a)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_fp2(r[0], a);
}

static int fp12_set_bn(fp12_t r, const BIGNUM *a)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_bn(r[0], a);
}

static int fp12_set_word(fp12_t r, unsigned long a)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_word(r[0], a);
}

static int fp12_set_u(fp12_t r)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_u(r[0]);
}

static int fp12_set_v(fp12_t r)
{
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
	return fp4_set_v(r[0]);
}

static int fp12_set_w(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[2]);
	return fp4_set_one(r[1]);
}

static int fp12_set_w_sqr(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	return fp4_set_one(r[2]);
}

static int fp12_equ(const fp12_t a, const fp12_t b)
{
	return fp4_equ(a[0], b[0])
		&& fp4_equ(a[1], b[1])
		&& fp4_equ(a[2], b[2]);
}

static int fp12_add(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx)
{
	
	return fp4_add(r[0], a[0], b[0], p, ctx)
		&& fp4_add(r[1], a[1], b[1], p, ctx)
		&& fp4_add(r[2], a[2], b[2], p, ctx);
}

static int fp12_dbl(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp4_dbl(r[0], a[0], p, ctx)
		&& fp4_dbl(r[1], a[1], p, ctx)
		&& fp4_dbl(r[2], a[2], p, ctx);
}

static int fp12_tri(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp12_dbl(r, a, p, ctx)
		&& fp12_add(r, r, a, p, ctx);
}

static int fp12_sub(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp4_sub(r[0], a[0], b[0], p, ctx)
		&& fp4_sub(r[1], a[1], b[1], p, ctx)
		&& fp4_sub(r[2], a[2], b[2], p, ctx);
}

static int fp12_neg(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp4_neg(r[0], a[0], p, ctx)
		&& fp4_neg(r[1], a[1], p, ctx)
		&& fp4_neg(r[2], a[2], p, ctx);
}

static int fp12_mul(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx)
{
	fp4_t t;
	if (!fp4_init(t, ctx)
		/* r0 = a0 * b0 + a1 * b2 * v + a2 * b1 * v */
		|| !fp4_mul(r[0], a[0], b[0], p, ctx)
		|| !fp4_mul_v(t, a[1], b[2], p, ctx)
		|| !fp4_add(r[0], r[0], t, p, ctx)
		|| !fp4_mul_v(t, a[2], b[1], p, ctx)
		|| !fp4_add(r[0], r[0], t, p, ctx)

		/* r1 = a0*b1 + a1*b0 + a2*b2*v */
		|| !fp4_mul(r[1], a[0], b[1], p, ctx)
		|| !fp4_mul(t, a[1], b[0], p, ctx)
		|| !fp4_add(r[1], r[1], t, p, ctx)
		|| !fp4_mul_v(t, a[2], b[2], p, ctx)
		|| !fp4_add(r[1], r[1], t, p, ctx)

		/* r2 = a0*b2 + a1*b1 + a2*b0 */
		|| !fp4_mul(r[2], a[0], b[2], p, ctx)
		|| !fp4_mul(t, a[1], b[1], p, ctx)
		|| !fp4_add(r[2], r[2], t, p, ctx)
		|| !fp4_mul(t, a[2], b[0], p, ctx)
		|| !fp4_add(r[2], r[2], t, p, ctx)) {

		fp4_cleanup(t);
		return 0;
	}
	fp4_cleanup(t);
	return 1;
}

static int fp12_sqr(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp4_t t;
	if (!(fp4_init(t, ctx))
		/* r0 = a0^2 + 2*a1*a2*v */
		|| !fp4_sqr(r[0], a[0], p, ctx)
		|| ! fp4_mul_v(t, a[1], a[2], p, ctx)
		|| ! fp4_dbl(t, t, p, ctx)
		|| ! fp4_add(r[0], t, p, ctx)

		/* r1 = 2*a0*a1 + a^2 * v */
		|| ! fp4_mul(r[1], a[0], a[1], p, ctx)
		|| ! fp4_dbl(r[1], r[1], p, ctx)
		|| ! fp4_sqr_v(t, a[2], p, ctx)
		|| ! fp4_add(r[1], r[1], t, p, ctx)

		/* r2 = 2*a0*a2 + a1^2*/
		|| ! fp4_mul(r[2], a[0], a[2], p, ctx)
		|| ! fp4_dbl(r[2], r[2], p, ctx)
		|| ! fp4_sqr(t, a[1], p, ctx)
		|| ! fp4_add(r[2], t, p, ctx)) {

		fp4_cleanup(t);
		return 0;
	}
	fp4_cleanup(t);
	return 1;
}

static int fp12_inv(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	if (fp4_is_zero(a[2])) {
		fp4_t k;
		if (!(fp4_init(k, ctx))
			/* k = (a0^3 + a1^3 * v)^-1 */
			|| !fp4_sqr(k, a[0], p, ctx)
			|| !fp4_mul(k, k, a[0], p, ctx)
			|| !fp4_sqr_v(t, a[1], p, ctx)
			|| !fp4_mul(t, t, a[1], p, ctx)
			|| !fp4_add(k, k, t, p, ctx)
			|| !fp4_inv(k, k, p, ctx)

			/* r0 = a0^2 * k */
			|| !fp4_sqr(r[0], a[0], p, ctx)
			|| !fp4_mul(r[0], r[0], k, p, ctx)

			/* r1 = -(a0 * a1 * k) */
			|| !fp4_mul(r[0], a[0], a[1], p, ctx)
			|| !fp4_mul(r[0], r[0], k, p, ctx)
			|| fp4_neg(r[0], r[0], p, ctx)

			/* r2 = a1^2 * k */
			|| !fp4_sqr(r[2], a[1], p, ctx)
			|| !fp4_mul(r[2], r[2], k, p, ctx)) {

			fp4_cleanup(k);
			return 0;
		}
		fp4_cleanup(k);
		return 1;

	} else {
	
		fp4_t t0, t1, t2, t3;

		if (!(fp4_init(t0, ctx))
			|| !(fp4_init(t1, ctx))
			|| !(fp4_init(t2, ctx))
			|| !(fp4_init(t3, ctx))

			/* t0 = a1^2 - a0 * a1 */
			|| !fp4_sqr(t0, a[1], p, ctx)
			|| !fp4_mul(t1, a[0], a[2], p, ctx)
			|| !fp4_sub(t0, t0, t1, p, ctx)

			/* t1 = a0 * a1 - a2^2 * v */
			|| !fp4_mul(t1, a[0], a[1], p, ctx)
			|| !fp4_sqr_v(t2, a[2], p, ctx)
			|| !fp4_sub(t1, t1, t2, p, ctx)

			/* t2 = a0^2 - a1 * a2 * v */
			|| !fp4_sqr(t2, a[0], p, ctx)
			|| !fp4_mul_v(t3, a[1], a[2], p, ctx)
			|| !fp4_sub(t2, t2, t3, p, ctx)

			/* t3 = a2 * (t1^2 - t0 * t2)^-1 */
			|| !fp4_sqr(t1, t1, p, ctx)
			|| !fp4_mul(t4, t0, t2, p, ctx)
			|| !fp4_sub(t1, t1, t5, p, ctx)
			|| !fp4_mul(t3, a[2], t3, p, ctx)
			|| !fp4_inv(t3, t3, p, ctx)
	
			/* r0 = t2 * t3 */
			|| !fp4_mul(r[0], t2, t3, p, ctx)

			/* r1 = -(t1 * t3) */
			|| !fp4_mul(r[1], t1, t3, p, ctx)
			|| !fp4_inv(r[1], r[1], p, ctx)

			/* r2 = t0 * t3 */
			|| !fp4_mul(r[2], t0, t3, p, ctx)) {

			fp4_cleanup(t0);
			fp4_cleanup(t1);
			fp4_cleanup(t2);
			fp4_cleanup(t3);
			return 0;
		}

		fp4_cleanup(t0);
		fp4_cleanup(t1);
		fp4_cleanup(t2);
		fp4_cleanup(t3);
		return 1;
	}

	return 1;
}

static int fp12_pow(fp12_t r, const fp12_t a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	int n;

	if (BN_is_zero(k)) {
		return fp12_set_one(r);
	}

	n = BN_num_bits(k);
	if (n < 1 || n > 256 * 12) {
		return 0;
	}

	if (!fp12_copy(r, a)) {
		return 0;
	}
	for (i = n - 2; i >= 0; i--) {
		if (!fp12_sqr(r, r, p, ctx)) {
			return 0;
		}
		if (BN_is_bit_set(k, i)) {
			if (!fp12_mul(r, r, a, p, ctx)) {
				return 0;
			}
		}
	}
	return 1;
}

static int point_init(point_t P, BN_CTX *ctx)
{
	int r;
	r = fp2_init(P.X, ctx);
	r &&= fp2_init(P.Y, ctx);
	r &&= fp2_init(P.Z, ctx);
	r &&= fp2_set_one(P.Y, ctx);
	if (!r) {
		fp2_cleanup(P.X);
		fp2_cleanup(P.Y);
		fp2_cleanup(P.Z);
		return 0;
	}
	fp2_set_zero(P.X);
	fp2_set_zero(P.Z);
	return 1;
}

static void point_cleanup(point_t P)
{
	fp2_cleanup(P.X);
	fp2_cleanup(P.Y);
	fp2_cleanup(P.Z);
}

static int point_set_infinity(point_t P)
{
	fp2_set_zero(P.X);
	fp2_set_zero(P.Z);
	return fp2_set_one(P.Y);
}

static int point_is_at_infinity(point_t P)
{
	return fp2_is_zero(P.X)
		&& fp2_is_one(P.Y)
		&& fp2_is_zero(P.Z);
}

static int point_equ(const point_t P, const point_t Q)
{
	return fp2_equ(P.X, Q.X)
		&& fp2_equ(P.Y, Q.Y)
		&& fp2_equ(P.Z, Q.Z);
}

static int point_is_on_curve(point_t P, BN_CTX *ctx)
{
	int r;
	fp2_t x, y, t;

	r = fp2_init(x, ctx);
	r &&= fp2_init(y, ctx);
	r &&= fp2_init(t, ctx);
	if (!r) {
		goto end;
	}	

	if (!point_get_affine_coordinates(P, x, y, p, ctx)
		|| !fp2_sqr(t, x, p, ctx)
		|| !fp2_mul(x, x, t, p, ctx)
		|| !fp2_add_word(x, x, 5, p, ctx)
		|| !fp2_sqr(y, y, p, ctx)) {
		r = 0;
		goto end;
	}
	r = fp2_equ(x, y);

end:
	fp2_cleanup(x);
	fp2_cleanup(y);
	fp2_cleanup(t);
	return r;
}

static int point_set_affine_coordinates(point_t P, const fp2_t x, const fp2_t y)
{
	return fp2_copy(P.X, x)
		&& fp2_copy(P.Y, y)
		&& fp2_set_one(P.Z);
}

static int point_get_affine_coordinates(const point_t P, fp2_t x, fp2_t y)
{
	return fp2_copy(x, P.X)
		&& fp2_copy(y, P.y)
		&& fp2_is_one(P.Z);
}

static int point_dbl(point_t R, const point_t P, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t x3, y3, x1, y1, lambda, t;

	r = 1;
	r &&= fp2_init(x1, ctx);
	r &&= fp2_init(y1, ctx);
	r &&= fp2_init(x3, ctx);
	r &&= fp2_init(y3, ctx);
	r &&= fp2_init(t0, ctx);
	r &&= fp2_init(t1, ctx);
	r &&= fp2_init(lambda, ctx);
	if (!r) {
		goto end;
	}

	if (point_is_at_infinity(P)) {
		r = point_set_infinity(R);
		goto end;
	}

	if (!point_get_affine_coordinates(P, x1, y1)
		/* lambda = 3 * x1^2 / 2 * y1 */
		|| !fp2_sqr(lambda, x1, p, ctx)
		|| !fp2_tri(lambda, lambda, p, ctx)
		|| !fp2_dbl(t, y1, p, ctx)
		|| !fp2_div(lambda, lambda, t, p, ctx)

		/* x3 = lambda^2 - 2 * x1 */
		|| !fp2_sqr(x3, lambda, p, ctx)
		|| !fp2_dbl(t, x1, p, ctx)
		|| !fp2_sub(x3, x3, t, p, ctx)

		/* y3 = lambda * (x1 - x3) - y1 */
		|| !fp2_sub(y3, x1, x3, p, ctx)
		|| !fp2_mul(y3, lambda, y3, p, ctx)
		|| !fp2_sub(y3, y3, y1, p, ctx)) {
		r = 0;
		goto end;
	}

	r = point_set_affine_coordinates(R, x3, y3);

end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(x3);
	fp2_clenaup(y3);
	fp2_cleanup(lambda);
	fp2_cleanup(t);
	return r;
}

static int point_add(point_t R, const point_t P, const point_t Q, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t x1;
	fp2_t y1;
	fp2_t x2;
	fp2_t y2;
	fp2_t x3;
	fp2_t y3;
	fp2_t lambda;
	fp2_t t0;
	fp2_t t1;

	if (point_is_at_infinity(P)) {
		return point_copy(R, Q);

	}

	if (point_is_at_infinity(Q)) {
		return point_copy(R, P);
	}

	if (point_equ(P, Q)) {
		return point_dbl(R, P, p, ctx);
	}

	r = 1;
	r &&= fp2_init(x1, ctx);
	r &&= fp2_init(y1, ctx);
	r &&= fp2_init(x2, ctx);
	r &&= fp2_init(y2, ctx);
	r &&= fp2_init(x3, ctx);
	r &&= fp2_init(y3, ctx);
	r &&= fp2_init(lambda, ctx);
	r &&= fp2_init(t, ctx);
	if (!r) {
		goto end;
	}

	r = 0;

	if (!point_get_affine_coordinates(P, x1, y1)
		|| !point_get_affine_coordinates(Q, x2, y2)
		|| !fp2_add(t, y1, y2, p, ctx)) {	
		goto end;
	}

	if (fp2_equ(x1, x2) && fp2_is_zero(t)) {
		r = point_set_infinity(R);
		goto end;
	}

	/* lambda = (y2 - y1)/(x2 - x1) */
	if (!fp2_sub(lambda, y2, y1, p, ctx)
		|| !fp2_sub(t, x2, x1, p, ctx)
		|| !fp2_div(lambda, lambda, t, p, ctx)

		/* x3 = lambda^2 - x1 - x2 */
		|| !fp2_sqr(x3, lambda, p, ctx)
		|| !fp2_sub(x3, x3, x1, p, ctx)
		|| !fp2_sub(x3, x3, x2, p, ctx)

		/* y3 = lambda * (x1 - x3) - y1 */
		|| !fp2_sub(y3, x1, x3, p, ctx)
		|| !fp2_mul(y3, lambda, y3, p, ctx)
		|| !fp2_sub(y3, y3, y1, p, ctx)) {
		goto end;
	}

	r = point_set_affine_coordinates(R, x3, y3);

end:
	fp2_cleanup(x1);
	fp2_cleanup(y1);
	fp2_cleanup(x2);
	fp2_cleanup(y2);
	fp2_cleanup(x3);
	fp2_cleanup(y3);
	fp2_cleanup(lambda);
	fp2_cleanup(t);
	return r;
}

static int point_neg(point_t R, const point_t P)
{
	return fp2_copy(R.X, P.X)
		&& fp2_neg(R.y, P.y)
		&& fp2_copy(R.Z, P.Z);
}

static int point_sub(point_t R, const point_t P, const point_t Q, const BIGNUM *p, BN_CTX *ctx)
{
	point_t T;
	if (!point_init(T, ctx)
		|| !point_neg(T, Q)
		|| !point_add(R, P, T, p, ctx)) {
		point_cleanup(T);
		return 0;
	}
	point_cleanup(T);
	return 1;
}

static void point_mul_generator(point_t R, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
}

static int point_mul(point_t R, const BIGNUM *k, const point_t P, const BIGNUM *p, BN_CTX *ctx)
{
	if (BN_is_zero(k)) {
		return point_set_infinity(R);
	}

	if (!point_copy(R, P)) {
		return 0;
	}
	n = BN_num_bits(k);
	for (i = n - 2; i >= 0; i--) {
		if (!point_dbl(R, R, p, ctx)) {
			return 0;
		}
		if (BN_is_bit_set(k, i)) {
			if (!point_add(R, R, P, p, ctx)) {
				return 0;
			}
		}
	}

	return 1;
}

static int eval_tangent(fp12_t r, const fp12_t xP, const fp12_t yP,
	const BIGNUM *xQ, const BIGNUM *yQ,
	const BIGNUM *p, BN_CTX *ctx)
{
	int ret;
	fp12_t x, y, lambda, t;

	ret = 1;
	ret &&= fp12_init(x, ctx);
	ret &&= fp12_init(y, ctx);
	ret &&= fp12_init(lambda, ctx);
	ret &&= fp12_init(t, ctx);
	if (!ret) {
		goto end;
	}

	ret = 0;
	if (!fp12_set_bn(x, xQ)
		|| !fp12_set_bn(y, yQ)
		/* lambda = (3 * xP^2)/(2 * yP) */
		|| !fp12_sqr(lambda, xP, p, ctx)
		|| !fp12_tri(lambda, lambda, p, ctx)
		|| !fp12_dbl(t, yP, p, ctx)
		/* r = lambda * (x - xP) - y + yP */
		|| !fp12_div(lambda, lambda, t, p, ctx)
		|| !fp12_sub(r, x, xP, p, ctx)
		|| !fp12_mul(r, lambda, r, p, ctx)
		|| !fp12_sub(r, r, y, p, ctx)
		|| !fp12_add(r, r, yP, p, ctx)) {
		goto end;
	}
	ret = 1

end:
	fp12_cleanup(x);
	fp12_cleanup(y);
	fp12_cleanup(lambda);
	fp12_cleanup(t);
	return ret;
}

static int eval_line(fp12_t r, const fp12_t xT, const fp12_t yT,
	const fp12_t xP, const fp12_t yP,
	const BIGNUM *xQ, const BIGNUM *yQ,
	const BIGNUM *p, BN_CTX *ctx)
{
	int ret;
	fp12_t x, y, lambda, t;

	ret = 1;
	ret &&= fp12_init(x, ctx);
	ret &&= fp12_init(y, ctx);
	ret &&= fp12_init(lambda, ctx);
	ret &&= fp12_init(t, ctx);
	if (!ret) {
		goto end;
	}

	ret = 0;
	if (!fp12_set_bn(x, xQ)
		|| !fp12_set_bn(y, yQ)
		/* lambda = (yT - yP)/(xT - xP) */
		|| !fp12_sub(lambda, yT, yP, p, ctx)
		|| !fp12_sub(t, xT, xP, p, ctx)
		|| !fp12_div(lambda, lambda, t, p, ctx)
		/* r = lambda * (x - xP) - y + yP */
		|| !fp12_sub(r, x, xP, p, ctx)
		|| !fp12_mul(r, lambda, r, p, ctx)
		|| !fp12_sub(r, r, y, p, ctx)
		|| !fp12_add(r, r, yP, p, ctx)) {
		goto end;
	}
	ret = 1;

end:
	fp12_cleanup(x);
	fp12_cleanup(y);
	fp12_cleanup(lambda);
	fp12_cleanup(t);
	return ret;
}

static void frob(fp12_t xR, fp12_t yR, const point_t P, const BIGNUM *p, BN_CTX *ctx)
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

static void frob_twice(fp12_t xR, fp12_t yR, const point_t P, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t x, y;
	fp12_t t0, t1;

	
	point_get_affine_coordinates(x, y, R);


}

static void final_expo(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
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
		fp12_sqr_to(f);
		fp12_mul_to(f, g);
		point_dbl_to(T);

		if (abits[i]) {
			eval(g, T, Q, xP, yP);
			fp12_mul_to(f, g);
			point_add_to(T, Q);
		}
	}

	frob(Q, Q1);
	frob_twice(Q, Q2);

	eval(g, T, Q1, xP, yP);
	fp12_mul_to(f, g);
	point_add_to(T, Q1);

	point_neg_to(Q2);
	eval(g, T, Q, xP, yP);
	fp12_mul_to(f, g);
	//point_add_to(T, Q2); 

	final_expo(r, f);
}

/*
 * the following API should be exported:
 * 1. mul generator P2/or G2, over E'(F_p^2),
 * 2. e(P, G1) where G1 is a fixed generator over E(Fp)
 * 3. fp12_pow(), g^k, where g in Fp12, k is in Fp
 * 4. k * G2 same as 1
 *  
 *
 */

int test()
{
	char *x_P2_1_str = "85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141";
	char *x_P2_0_str = "3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B";
	char *y_P2_1_str = "17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96";
	char *y_P2_0_str = "A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7";


	if (!BN_hex2bn(&x_P2_1, x_P2_1_str)
		|| !BN_hex2bn(&x_P2_0, x_P2_0_str)
		|| !BN_hex2bn(&y1, y_P2_1_str)
		|| !BN_hex2bn(&y0, y_P2_0_str)
		|| !BN_hex2bn(ks, ks_str)) {

	}

	if (!fp2_set(x_P2, x0, x1)
		|| !fp2_set(y_P2, y0, y1)) {
	}

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

	const EC_GROUP *group;
	const EC_POINT *P1;
	
	group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);

	EC_GROUP_get_order();

	P1 = EC_GROUP_get0_generator(G1);

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
