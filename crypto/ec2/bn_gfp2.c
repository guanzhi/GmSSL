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
 */
/*
 * this file implement complex number over prime field
 * a = a0 + a1 * i, i^2 == -1
 * most of the routines should be replaced by macros
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn_gfp2.h>

/*
 * to make it simple, currently both a0 and a1 will be inited
  */

BN_GFP2 *BN_GFP2_new(void)
{
	int e = 1;
	BN_GFP2 *ret = NULL;

	if (!(ret = OPENSSL_malloc(sizeof(BN_GFP2)))) {
		BNerr(BN_F_BN_GFP2_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->a0 = BN_new();
	ret->a1 = BN_new();
	if (!ret->a0 || !ret->a1) {
		BNerr(BN_F_BN_GFP2_NEW, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	BN_zero(ret->a0);
	BN_zero(ret->a1);

	e = 0;
end:
	if (e && ret) {
		BN_GFP2_free(ret);
		ret = NULL;
	}
	return ret;
}

void BN_GFP2_free(BN_GFP2 *a)
{
	if (a) {
		BN_free(a->a0);
		BN_free(a->a1);
		OPENSSL_free(a);
	}
}

int BN_GFP2_copy(BN_GFP2 *r, const BN_GFP2 *a)
{
	if (!r || !r->a0 || !r->a1 || !a || !a->a0 || !a->a1) {
		BNerr(BN_F_BN_GFP2_COPY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!BN_copy(r->a0, a->a0)) {
		BNerr(BN_F_BN_GFP2_COPY, ERR_R_BN_LIB);
		return 0;
	}
	if (!BN_copy(r->a1, a->a1)) {
		BNerr(BN_F_BN_GFP2_COPY, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}

int BN_GFP2_one(BN_GFP2 *a)
{
	if (!a || !a->a0 || !a->a1) {
		BNerr(BN_F_BN_GFP2_ONE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_one(a->a0);
	BN_zero(a->a1);
	return 1;
}

int BN_GFP2_zero(BN_GFP2 *a)
{
	if (!a || !a->a0 || !a->a1) {
		BNerr(BN_F_BN_GFP2_ZERO, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_zero(a->a0);
	BN_zero(a->a1);
	return 1;
}

/* return 1 on success, so dont use !BN_GFP2_is_zero() to check return value */
int BN_GFP2_is_zero(const BN_GFP2 *a)
{
	if (!a || !a->a0 || !a->a1) {
		BNerr(BN_F_BN_GFP2_IS_ZERO, ERR_R_PASSED_NULL_PARAMETER);
		return -1;
	}

	return (BN_is_zero(a->a0) && BN_is_zero(a->a1));
}

int BN_GFP2_equ(const BN_GFP2 *a, const BN_GFP2 *b)
{
	if (!a || !b || !a->a0 || !a->a1 || !b->a0 || !b->a1) {
		BNerr(BN_F_BN_GFP2_EQU, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	return ((BN_cmp(a->a0, b->a0) == 0) && (BN_cmp(a->a1, b->a1) == 0));
}

int BN_GFP2_add(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	if (!a || !b || !a->a0 || !a->a1 || !b->a0 || !b->a1 || !p || !ctx) {
		BNerr(BN_F_BN_GFP2_ADD, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!BN_mod_add(r->a0, a->a0, b->a0, p, ctx)) {
		BNerr(BN_F_BN_GFP2_ADD, ERR_R_BN_LIB);
		return 0;
	}
	if (!BN_mod_add(r->a1, a->a1, b->a1, p, ctx)) {
		BNerr(BN_F_BN_GFP2_ADD, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}

int BN_GFP2_sub(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	if (!a || !b || !a->a0 || !a->a1 || !b->a0 || !b->a1 || !p || !ctx) {
		BNerr(BN_F_BN_GFP2_SUB, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!BN_mod_sub(r->a0, a->a0, b->a0, p, ctx)) {
		BNerr(BN_F_BN_GFP2_SUB, ERR_R_BN_LIB);
		return 0;
	}
	if (!BN_mod_sub(r->a1, a->a1, b->a1, p, ctx)) {
		BNerr(BN_F_BN_GFP2_SUB, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}

/*
 * (a0 + a1 * i) * (b0 + b1 * i)
 *	= a0 * b0 + a1 * b1 * i^2 + (a0 * b1 + a1 * b0) * i
 *	= (a0 * b0 - a1 * b1) + (a0 * b1 + a1 * b0) * i
 */
int BN_GFP2_mul(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	int ret = 0;
	BIGNUM *t = NULL;

	BN_CTX_start(ctx);

	if (!(t = BN_CTX_get(ctx))) {
		BNerr(BN_F_BN_GFP2_MUL, ERR_R_BN_LIB);
		goto end;
	}

	/* r->a0 = a->a0 * b->a0 - a->a1 * b->a1 (mod p) */
	if (!BN_mod_mul(r->a0, a->a0, b->a0, p, ctx)) {
		BNerr(BN_F_BN_GFP2_MUL, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(t, a->a1, b->a1, p, ctx)) {
		BNerr(BN_F_BN_GFP2_MUL, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_sub(r->a0, r->a0, t, p, ctx)) {
		BNerr(BN_F_BN_GFP2_MUL, ERR_R_BN_LIB);
		goto end;
	}

	/* r->a1 = a->a0 * b->a1 + a->a1 * b->a0 (mod p) */
	if (!BN_mod_mul(r->a1, a->a0, b->a1, p, ctx)) {
		BNerr(BN_F_BN_GFP2_MUL, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(t, a->a1, b->a0, p, ctx)) {
		BNerr(BN_F_BN_GFP2_MUL, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_add(r->a1, r->a1, t, p, ctx)) {
		BNerr(BN_F_BN_GFP2_MUL, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;
end:
	BN_CTX_end(ctx);
	return ret;
}

int BN_GFP2_sqr(BN_GFP2 *r, const BN_GFP2 *a,
	const BIGNUM *p, BN_CTX *ctx)
{
	return BN_GFP2_mul(r, a, a, p, ctx);
}

/*
 * (a0 + a1 * i) * (a0 - a1 * i)
 *	= a0^2 - a1^2 * i^2
 *	= a0^2 + a1^2
 * ==> (a0 + a1 * i) * (a0 - a1 * i) * (a0^2 + a1^2)^-1 == 1
 * ==> (a0 + a1 * i)^-1 == (a0 - a1 * i) * (a0^2 + a1^2)^-1
 */
int BN_GFP2_inv(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx)
{
	int ret = 0;
	BIGNUM *t = NULL;

	BN_CTX_start(ctx);

	if (!(t = BN_CTX_get(ctx))) {
		BNerr(BN_F_BN_GFP2_INV, ERR_R_BN_LIB);
		goto end;
	}

	/* t = (a0^2 + a1^2)^-1 */
	if (!BN_mod_sqr(r->a0, a->a0, p, ctx)) {
		BNerr(BN_F_BN_GFP2_INV, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_sqr(r->a1, a->a1, p, ctx)) {
		BNerr(BN_F_BN_GFP2_INV, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(t, r->a0, r->a1, p, ctx)) {
		BNerr(BN_F_BN_GFP2_INV, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_inverse(t, t, p, ctx)) {
		BNerr(BN_F_BN_GFP2_INV, ERR_R_BN_LIB);
		goto end;
	}

	/* r0 = a0^ t (mod p) */
	if (!BN_mod_mul(r->a0, a->a0, t, p, ctx)) {
		BNerr(BN_F_BN_GFP2_INV, ERR_R_BN_LIB);
		goto end;
	}

	/* r1 = p - a1^t (mod p) */
	if (!BN_mod_mul(r->a1, a->a1, t, p, ctx)) {
		BNerr(BN_F_BN_GFP2_INV, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_sub(r->a1, p, r->a1)) {
		BNerr(BN_F_BN_GFP2_INV, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;
end:
	BN_CTX_end(ctx);
	return ret;
}

int BN_GFP2_div(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx)
{
	if (!BN_GFP2_inv(r, b, p, ctx)) {
		return 0;
	}
	if (!BN_GFP2_mul(r, a, r, p, ctx)) {
		return 0;
	}
	return 1;
}

/* need a fast implementation. check if k is solinas */
int BN_GFP2_exp(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *k, const BIGNUM *p,
	BN_CTX *ctx)
{

	return 0;
}

int BN_GFP2_set_bn(BN_GFP2 *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
	if (!r || !a || !p) {
		BNerr(BN_F_BN_GFP2_SET_BN, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (!BN_copy(r->a0, a)) {
		BNerr(BN_F_BN_GFP2_SET_BN, ERR_R_BN_LIB);
		return 0;
	}
	BN_zero(r->a1);
	return 1;
}

int BN_GFP2_add_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_add(r->a0, a->a0, b, p, ctx);
}

int BN_GFP2_sub_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_sub(r->a0, a->a0, b, p, ctx);
}

int BN_GFP2_mul_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_mul(r->a0, a->a0, b, p, ctx);
}

int BN_GFP2_div_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	int ret = 0;
	BIGNUM *binv;

	if (!(binv = BN_CTX_get(ctx))) {
		BNerr(BN_F_BN_GFP2_DIV_BN, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!BN_mod_inverse(binv, b, p, ctx)) {
		BNerr(BN_F_BN_GFP2_DIV_BN, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(r->a0, a->a0, binv, p, ctx)) {
		BNerr(BN_F_BN_GFP2_DIV_BN, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(r->a1, a->a1, binv, p, ctx)) {
		BNerr(BN_F_BN_GFP2_DIV_BN, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;
end:
	BN_CTX_end(ctx);
	return ret;
}

int BN_bn2gfp2(const BIGNUM *bn, BN_GFP2 *gfp2, const BIGNUM *p, BN_CTX *ctx)
{
	int ret = 0;
	BIGNUM *a;

	if (!(a = BN_CTX_get(ctx))) {
		goto end;
	}

	BN_one(a);
	if (!BN_lshift(a, a, BN_num_bytes(p)*8)) {
		goto end;
	}

	if (!BN_rshift(gfp2->a1, bn, BN_num_bytes(p)*8)) {
		goto end;
	}
	if (!BN_mod(gfp2->a0, bn, a, ctx)) {
		goto end;
	}

	ret = 1;
end:
	BN_CTX_end(ctx);
	return ret;
}

/* return (a0 + a1 << 2^n), n = log_2(p), n % 8 == 0 */
int BN_gfp22bn(const BN_GFP2 *gfp2, BIGNUM *bn, const BIGNUM *p, BN_CTX *ctx)
{
	if (!BN_lshift(bn, gfp2->a1, BN_num_bytes(p) * 8)) {
		return 0;
	}
	if (!BN_add(bn, bn, gfp2->a0)) {
		return 0;
	}
	return 1;
}

int BN_GFP2_canonical(const BN_GFP2 *a, unsigned char *out, size_t *outlen,
	int order, const BIGNUM *p, BN_CTX *ctx)
{
	size_t len;

	if (!a || !a->a0 || !a->a1 || !outlen || !p) {
		BNerr(BN_F_BN_GFP2_CANONICAL, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	len = BN_num_bytes(p) * 2;
	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		BNerr(BN_F_BN_GFP2_CANONICAL, BN_R_BUFFER_TOO_SMALL);
		return 0;
	}

	memset(out, 0, len);
	if (order == 0) {
		/* low order first output (a0, a1) */
		if (!BN_bn2bin(a->a0, out + len/2 - BN_num_bytes(a->a0))) {
			BNerr(BN_F_BN_GFP2_CANONICAL, ERR_R_BN_LIB);
			return 0;
		}
		if (!BN_bn2bin(a->a1, out + len - BN_num_bytes(a->a1))) {
			BNerr(BN_F_BN_GFP2_CANONICAL, ERR_R_BN_LIB);
			return 0;
		}
	} else {
		/* high order first output (a1, a0) */
		if (!BN_bn2bin(a->a1, out + len/2 - BN_num_bytes(a->a1))) {
			BNerr(BN_F_BN_GFP2_CANONICAL, ERR_R_BN_LIB);
			return 0;
		}
		if (!BN_bn2bin(a->a0, out + len - BN_num_bytes(a->a0))) {
			BNerr(BN_F_BN_GFP2_CANONICAL, ERR_R_BN_LIB);
			return 0;
		}
	}

	*outlen = len;
	return 1;
}
