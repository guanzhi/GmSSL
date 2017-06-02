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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/bn_hash.h>

/* currently the EC_POINT_hash2point only support type1curve! */
int EC_POINT_hash2point(const EC_GROUP *group, const EVP_MD *md,
	const char *s, size_t slen, EC_POINT *point, BN_CTX *bn_ctx)
{
	int ret = 0;
	BIGNUM *p = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *k = NULL;
	BIGNUM *q = NULL;

	if (!group || !md || !point || !s || slen <= 0 || !bn_ctx) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) != NID_X9_62_prime_field) {
		ECerr(EC_F_EC_POINT_HASH2POINT, EC_R_INVALID_CURVE);
		return 0;
	}

	p = BN_new();
	x = BN_new();
	y = BN_new();
	k = BN_new();
	q = BN_new();

	if (!p || !x || !y || !k || !q) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!EC_GROUP_get_curve_GFp(group, p, x, y, bn_ctx)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_EC_LIB);
		goto end;
	}

	/* check group is type-1 curve */
	if (!BN_is_zero(x) || !BN_is_one(y) || BN_mod_word(p, 12) != 11) {
		ECerr(EC_F_EC_POINT_HASH2POINT, EC_R_INVALID_CURVE);
		goto end;
	}

	/* get order */
	if (!EC_GROUP_get_order(group, q, bn_ctx)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_EC_LIB);
		goto end;
	}

	/* y = HashToRange(s) in [0, p - 1] */
	if (!BN_hash_to_range(md, &y, s, slen, p, bn_ctx)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}

	/* x = (y + 1) * (y - 1) mod p */
	if (!BN_copy(x, y)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_copy(k, y)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_add_word(x, 1)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_sub_word(k, 1)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(x, x, k, p, bn_ctx)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}

	/* k = (p^2 - 1)/3 */
	if (!BN_lshift1(k, p)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_sub_word(k, 1)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_div_word(k, 3)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}

	/* compute x and point = (x, y) */
	if (!BN_mod_exp(x, x, k, p, bn_ctx)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, bn_ctx)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_EC_LIB);
		goto end;
	}

	/* compute [(p + 1)/q] * point */
	if (!BN_add_word(p, 1)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_div(k, NULL, p, q, bn_ctx)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_BN_LIB);
		goto end;
	}
	if (!EC_POINT_mul(group, point, NULL, point, k, bn_ctx)) {
		ECerr(EC_F_EC_POINT_HASH2POINT, ERR_R_EC_LIB);
		goto end;
	}

	ret = 1;
end:
	BN_free(p);
	BN_free(x);
	BN_free(y);
	BN_free(k);
	BN_free(q);
	return ret;
}

