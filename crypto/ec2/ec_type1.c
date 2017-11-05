/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
 *
 */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn_gfp2.h>


EC_GROUP *EC_GROUP_generate_type1curve(const BIGNUM *order, BN_CTX *bn_ctx)
{
	ECerr(EC_F_EC_GROUP_GENERATE_TYPE1CURVE, 0);
	return 0;
}

EC_GROUP *EC_GROUP_new_type1curve_ex(const BIGNUM *p, const BIGNUM *a,
	const BIGNUM *b, const unsigned char *point, size_t pointlen,
	const BIGNUM *order, const BIGNUM *cofactor, BN_CTX *bn_ctx)
{
	return NULL;
}

EC_GROUP *EC_GROUP_new_type1curve(const BIGNUM *p,
	const BIGNUM *x, const BIGNUM *y, const BIGNUM *order, BN_CTX *bn_ctx)
{
	int e = 1;
	EC_GROUP *ret = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	EC_POINT *point = NULL;

	if (!p || !x || !y || !order) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	/* check p = 11 (mod 12) */
	if (BN_mod_word(p, 12) != 11) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, EC_R_INVALID_TYPE1CURVE);
		return NULL;
	}

	BN_CTX_start(bn_ctx);
	a = BN_CTX_get(bn_ctx);
	b = BN_CTX_get(bn_ctx);

	if (!a || !b) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	BN_zero(a);
	BN_one(b);

	if (!(ret = EC_GROUP_new_curve_GFp(p, a, b, bn_ctx))) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, EC_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* prepare generator point from (x, y) */
	if (!(point = EC_POINT_new(ret))) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(ret, point, x, y, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, EC_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/*
	 * calculate cofactor h = (p + 1)/n
	 * check n|(p + 1) where n is the order
	 */
	if (!BN_copy(a, p)) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_add_word(a, 1)) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}
	/* check (p + 1)%n == 0 */
	if (!BN_div(a, b, a, order, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_is_zero(b)) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, EC_R_INVLID_TYPE1CURVE);
		goto end;
	}

	/* set order and cofactor */
	if (!EC_GROUP_set_generator(ret, point, order, a)) {
		ECerr(EC_F_EC_GROUP_NEW_TYPE1CURVE, EC_R_INVALID_TYPE1CURVE);
		goto end;
	}

	e = 0;

end:
	if (e && ret) {
		EC_GROUP_free(ret);
		ret = NULL;
	}
	BN_CTX_end(bn_ctx);
	EC_POINT_free(point);
	return ret;
}

int EC_GROUP_is_type1curve(const EC_GROUP *group, BN_CTX *bn_ctx)
{
	ECerr(EC_F_EC_GROUP_IS_TYPE1CURVE, 0);
	return 0;
}

/*
 * zeta = F_p((p-1)/2) + ((F_p(3)^((p + 1)/4))/2) * i, in F_p^2
 * which is used in phi() mapping in tate pairing over type1 curve
 */
BN_GFP2 *EC_GROUP_get_type1curve_zeta(const EC_GROUP *group, BN_CTX *bn_ctx)
{
	int e = 1;
	BN_GFP2 *ret = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *p = NULL;

	if (!group || !bn_ctx) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	BN_CTX_start(bn_ctx);

	ret = BN_GFP2_new();
	a = BN_CTX_get(bn_ctx);
	b = BN_CTX_get(bn_ctx);
	p = BN_CTX_get(bn_ctx);

	if (!ret || !a || !b || !p) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* get curve p, a, b and check it is type1 curve
	 * p is prime at least 512 bits, a == 0 and b == 1
	 */
	if (!EC_GROUP_get_curve_GFp(group, a, b, p, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_EC_LIB);
		goto end;
	}
	if (!BN_is_zero(a) || !BN_is_one(b)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, EC_R_INVALID_TYPE1_CURVE);
		goto end;
	}
	if (BN_num_bits(p) < 512) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, EC_R_INVALID_TYPE1_CURVE);
		goto end;
	}

	/*
	 * set ret->a0 = (p - 1)/2
	 */
	if (!BN_copy(ret->a0, p)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!BN_sub_word(ret->a0, 1)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_EC_LIB);
		goto end;
	}
	/* BN_div_word() return remainder, while (p - 1)%2 == 0 */
	if (BN_div_word(ret->a0, 2)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, EC_R_INVALID_TYPE1_CURVE);
		goto end;
	}

	/*
	 * ret->a1 = (p + 1)/4, (ret->a1 + 1)%4 == 0
	 */
	if (!BN_copy(ret->a1, p)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_add_word(ret->a1, 1)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_BN_LIB);
		goto end;
	}
	if (BN_div_word(ret->a1, 4)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, EC_R_INVALID_TYPE1_CURVE);
		goto end;
	}

	/*
	 * re-use a as 3
	 * ret->a1 = 3^(ret->a1) mod p = 3^((p + 1)/4) mod p
	 */
	if (!BN_set_word(a, 3)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_exp(ret->a1, a, ret->a1, p, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_BN_LIB);
		goto end;
	}

	/*
	 * re-use b as 1/2 mod p
	 * ret->a1 = ret->a1 / 2 mod p = (3^((p + 1)/4)) mod p
	 */
	if (!BN_set_word(b, 2)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_inverse(b, b, p, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(ret->a1, ret->a1, b, p, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ZETA, ERR_R_BN_LIB);
		goto end;
	}

	e = 0;
end:
	if (e && ret) {
		BN_GFP2_free(ret);
		ret = NULL;
	}
	BN_CTX_end(bn_ctx);
	return ret;
}

/*
 * eta = (p^2 - 1)/n
 * which is used in the final modular exponentiation of tate pairing over
 * type1 curve
 */
BIGNUM *EC_GROUP_get_type1curve_eta(const EC_GROUP *group, BN_CTX *bn_ctx)
{
	int e = 1;
	BIGNUM *ret = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *p = NULL;

	if (!group || !bn_ctx) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	BN_CTX_start(bn_ctx);

	ret = BN_new();
	a = BN_CTX_get(bn_ctx);
	b = BN_CTX_get(bn_ctx);
	p = BN_CTX_get(bn_ctx);

	if (!ret || !a || !b || !p) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* get curve p, a, b and check it is type1 curve
	 * p is prime at least 512 bits, a == 0 and b == 1
	 */
	if (!EC_GROUP_get_curve_GFp(group, a, b, p, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, ERR_R_EC_LIB);
		goto end;
	}
	if (!BN_is_zero(a) || !BN_is_one(b)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, EC_R_INVALID_TYPE1_CURVE);
		goto end;
	}
	if (BN_num_bits(p) < 512) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, EC_R_INVALID_TYPE1_CURVE);
		goto end;
	}

	/* get curve order n, re-use a for order n */
	if (!EC_GROUP_get_order(group, a, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, ERR_R_EC_LIB);
		goto end;
	}

	/*
	 * eta = (p^2 - 1)/n,
	 */
	if (!BN_sqr(ret, p, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_sub_word(ret, 1)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_div(ret, NULL, ret, a, bn_ctx)) {
		ECerr(EC_F_EC_GROUP_GET_TYPE1CURVE_ETA, ERR_R_BN_LIB);
		goto end;
	}

	e = 1;
end:
	if (e && ret) {
		BN_free(ret);
		ret = NULL;
	}
	BN_CTX_end(bn_ctx);
	return ret;
}

/* phi: (x, y) => (zeta * x, y) */
static int type1curve_phi(const EC_GROUP *group, const EC_POINT *point,
	BN_GFP2 *x, BN_GFP2 *y, const BIGNUM *p, BN_CTX *bn_ctx)
{
	int ret = 0;
	BN_GFP2 *zeta = NULL;
	BIGNUM *xP;
	BIGNUM *yP;

	if (!group || !point || !x || !y || !p || !bn_ctx) {
		ECerr(EC_F_TYPE1CURVE_PHI,
ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_CTX_start(bn_ctx);
	xP = BN_CTX_get(bn_ctx);
	yP = BN_CTX_get(bn_ctx);

	if (!xP || !yP) {
		ECerr(EC_F_TYPE1CURVE_PHI, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!(zeta = EC_GROUP_get_type1curve_zeta(group, bn_ctx))) {
		ECerr(EC_F_TYPE1CURVE_PHI,
EC_R_GET_TYPE1CURVE_ZETA_FAILURE);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, point, xP, yP, bn_ctx))
{
		ECerr(EC_F_TYPE1CURVE_PHI, ERR_R_EC_LIB);
		goto end;
	}

	/* return x = zeta * point->x */
	if (!BN_GFP2_mul_bn(x, zeta, xP, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_PHI, ERR_R_BN_LIB);
		goto end;
	}

	/* return y = point->y */
	if (!BN_GFP2_set_bn(y, yP, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_PHI, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;

end:
	BN_CTX_end(bn_ctx);
	BN_GFP2_free(zeta);
	return ret;
}

/*
 * eval the function defined by the line through point T and P,
 * with value Q = (xQ, yQ)
 */
static int type1curve_eval_line_textbook(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *T, const EC_POINT *P, const BN_GFP2 *xQ, const BN_GFP2
*yQ,
	BN_CTX *bn_ctx)
{
	int ret = 0;
	BN_GFP2 *num = NULL;
	BN_GFP2 *den = NULL;
	BIGNUM *p;
	BIGNUM *xT;
	BIGNUM *yT;
	BIGNUM *xP;
	BIGNUM *yP;
	BIGNUM *bn;
	BIGNUM *slope;

	if (!group || !r || !T || !P || !xQ || !yQ || !bn_ctx) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_CTX_start(bn_ctx);
	p = BN_CTX_get(bn_ctx);
	xT = BN_CTX_get(bn_ctx);
	yT = BN_CTX_get(bn_ctx);
	xP = BN_CTX_get(bn_ctx);
	yP = BN_CTX_get(bn_ctx);
	bn = BN_CTX_get(bn_ctx);
	slope = BN_CTX_get(bn_ctx);

	num = BN_GFP2_new();
	den = BN_GFP2_new();

	if (!p || !xT || !yT || !xP || !yP || !bn || !slope || !num || !den) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* get prime field p */
	if (!EC_GROUP_get_curve_GFp(group, p, xT, yT, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_EC_LIB);
		goto end;
	}

	/* get T and P */
	if (!EC_POINT_get_affine_coordinates_GFp(group, T, xT, yT, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, xP, yP, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_EC_LIB);
		goto end;
	}

#if 0
	/* if T == P, slope = (3 * x_T^2 + a)/(2 * y_T) */
	if (T == P || (BN_cmp(xT, xP) == 0  && BN_cmp(yT, yP) == 0)) {

		if (!BN_mod_sqr(bn, xT, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_add(slope, bn, bn, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_add(slope, slope, bn, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_add(den, yT, yT, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_inverse(den, den, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_mul(slope, slope, den, p, bn_ctx)) {
			goto end;
		}
	}

	/*
	 * if xT == xP and yT + yP == 0, return xQ - xT
	 */

	if (BN_cmp(xT, xP) == 0) {
		BIGNUM *t;
		if (!(t = BN_CTX_get(bn_ctx))) {
			goto end;
		}
		if (!BN_mod_add(t, yT, yP, p, ctx)) {
			goto end;
		}
		if (BN_is_zero(t)) {
			if (!BN_GFP2_sub_bn(r, xQ, xT, p, bn_ctx)) {
				goto end;
			}
		}
	}

	/*
	 * if T == P, slope = (3 * x_T^2 + a)/(2 * y_T)
	 * else slope = (y_T - y_P)/(x_T - x_P)
	 */
	if (!BN_mod_sub(num, yT, yP, p, bn_ctx)) {
		goto end;
	}
	if (!BN_mod_sub(den, xT, xP, p, bn_ctx)) {
		goto end;
	}
	if (!BN_mod_inverse(den, den, p, bn_ctx)) {
		goto end;
	}
	if (!BN_mod_mul(slope, num, den, p, bn_ctx)) {
		goto end;
	}
#endif

	/*
	 * num = (yQ - ((xQ - xT) * slope)) - yT
	 * den = xQ + (xT + (xP - slope^2))
	 * return  num/den
	 */

	if (!BN_GFP2_sub_bn(num, xQ, xT, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_mul_bn(num, num, slope, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_sub(num, yQ, num, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_sub_bn(num, num, yT, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_mod_sqr(bn, slope, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_sub(bn, xP, bn, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_add(bn, xT, bn, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_add_bn(den, xQ, bn, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}

#if 0
	//warning
	if (!BN_GFP2_div(ret, num, den, p, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
ERR_R_BN_LIB);
		goto end;
	}
#endif

	ret = 1;

end:
	BN_CTX_end(bn_ctx);
	BN_GFP2_free(num);
	BN_GFP2_free(den);
	return ret;
}

static int type1curve_eval_miller_textbook(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *P, const BN_GFP2 *xQ, const BN_GFP2 *yQ,
	const BIGNUM *p, BN_CTX *bn_ctx)
{
	int ret = 0;
	BN_GFP2 *f = NULL;
	BN_GFP2 *g = NULL;
	EC_POINT *T = NULL;
	BIGNUM *n;
	int nbits;
	int i;

	if (!group || !r || !P || !xQ || !yQ || !p || !bn_ctx) {
		ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_CTX_start(bn_ctx);
	n = BN_CTX_get(bn_ctx);

	f = BN_GFP2_new();
	g = BN_GFP2_new();
	T = EC_POINT_new(group);

	if (!n || !f || !g || !T) {
		ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!EC_GROUP_get_order(group, n, bn_ctx)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
			ERR_R_EC_LIB);
		goto end;
	}

	nbits = BN_num_bits(n);

	/* miller loop */
	for (i = nbits - 2; i >= 0; i--) {

		/* f = f^2 */
		if (!BN_GFP2_sqr(f, f, p, bn_ctx)) {
			ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
				ERR_R_BN_LIB);
			goto end;
		}

		/* compute g_{T,T}(Q) */
		if (!type1curve_eval_line_textbook(group, g, T, T, xQ, yQ,
			bn_ctx)) {
			ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
				ERR_R_EC_LIB);
			goto end;
		}

		/* f = f * g */
		if (!BN_GFP2_mul(f, f, g, p, bn_ctx)) {
			ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
				ERR_R_BN_LIB);
			goto end;
		}

		/* T = 2T */
		if (!EC_POINT_dbl(group, T, T, bn_ctx)) {
			ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
				ERR_R_EC_LIB);
			goto end;
		}

		if (BN_is_bit_set(n, i)) {

			/* g = g_{T,P}(Q) */
			if (!type1curve_eval_line_textbook(group, g, T, P, xQ,
				yQ, bn_ctx)) {
				ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
					ERR_R_EC_LIB);
				goto end;
			}

			/* f = f * g */
			if (!BN_GFP2_mul(f, f, g, p, bn_ctx)) {
				ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
					ERR_R_BN_LIB);
				goto end;
			}

			/* T = T + P */
			if (!EC_POINT_add(group, T, T, P, bn_ctx)) {
				ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK,
					ERR_R_EC_LIB);
				goto end;
			}
		}
	}

	/* set return value */
	if (!BN_GFP2_copy(r, f)) {
		ECerr(EC_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}
	ret = 1;

end:
	BN_CTX_end(bn_ctx);
	BN_GFP2_free(f);
	BN_GFP2_free(g);
	EC_POINT_free(T);
	return ret;
}

int EC_type1curve_tate(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *P, const EC_POINT *Q, BN_CTX *bn_ctx)
{
	int ret = 0;
	BN_GFP2 *xQ = NULL;
	BN_GFP2 *yQ = NULL;
	BIGNUM *eta = NULL;
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;

	if (!group || !ret || !P || !Q || !bn_ctx) {
		ECerr(EC_F_EC_TYPE1CURVE_TATE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_CTX_start(bn_ctx);

	xQ = BN_GFP2_new();
	yQ = BN_GFP2_new();
	p = BN_CTX_get(bn_ctx);
	a = BN_CTX_get(bn_ctx);
	b = BN_CTX_get(bn_ctx);

	if (!xQ || !yQ || !p || !a || !b) {
		ECerr(EC_F_EC_TYPE1CURVE_TATE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!EC_GROUP_get_curve_GFp(group, p, a, b, bn_ctx)) {
		ECerr(EC_F_EC_TYPE1CURVE_TATE, EC_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* (xQ, yQ) = phi(Q) */
	if (!type1curve_phi(group, Q, xQ, yQ, p, bn_ctx)) {
		ECerr(EC_F_EC_TYPE1CURVE_TATE, ERR_R_EC_LIB);
		goto end;
	}

	/* compute e(P, phi(Q)) */
	if (!type1curve_eval_miller_textbook(group, r, P, xQ, yQ, p, bn_ctx)) {
		ECerr(EC_F_EC_TYPE1CURVE_TATE, ERR_R_EC_LIB);
		goto end;
	}

	/* compute e(P, phi(Q))^eta, eta = (p^2 - 1)/q */
	if (!(eta = EC_GROUP_get_type1curve_eta(group, bn_ctx))) {
		ECerr(EC_F_EC_TYPE1CURVE_TATE, EC_R_INVALID_TYPE1CURVE);
		goto end;
	}

	ret = 1;

end:
	BN_GFP2_free(xQ);
	BN_GFP2_free(yQ);
	BN_CTX_end(bn_ctx);
	BN_free(eta);
	return ret;
}

int EC_type1curve_tate_ratio(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *P1, const EC_POINT *Q1,
	const EC_POINT *P2, const EC_POINT *Q2,
	BN_CTX *bn_ctx)
{
	return 0;
}

#if 0
typedef struct {
	int security_bits;
	int n_bits;
	int p_bits;
	int q_bits;
} TYPE1CURVE_SEC;

static TYPE1CURVE_SEC sec_tbl[] = {
	/* k    |n|   |p|  |q| */
	{ 80,  1024,  512, 160},
	{112,  2048, 1024, 224},
	{128,  3072, 1536, 256},
	{192,  7680, 3840, 384},
	{256, 15360, 7680, 512}
};
#endif

const EVP_MD *TYPE1CURVE_nbits_to_md(int nbits)
{
	switch (nbits) {
	case 1024: return EVP_sha1();
	case 2048: return EVP_sha224();
	case 3072: return EVP_sha256();
	case 7680: return EVP_sha384();
	case 15360: return EVP_sha512();
	}
	return NULL;
}

