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
#include "sm9_lcl.h"


static int fp2_init(fp2_t a, BN_CTX *ctx)
{
	a[0] = NULL;
	a[1] = NULL;
	a[0] = BN_CTX_get(ctx);
	a[1] = BN_CTX_get(ctx);
	/*
	if (!a[1]) {
		BN_free(a[0]);
		a[0] = NULL;
		return 0;
	}
	*/
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

static int fp2_is_zero(const fp2_t a)
{
	return BN_is_zero(a[0])
		&& BN_is_zero(a[1]);
}

static int fp2_print(const fp2_t a)
{
	printf("%s\n", BN_bn2hex(a[0]));
	printf("%s\n", BN_bn2hex(a[1]));
	return 1;
}

static int fp2_is_one(const fp2_t a)
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

static int fp2_set_hex(fp2_t r, const char *str[2])
{
	return BN_hex2bn(&r[0], str[0])
		&& BN_hex2bn(&r[1], str[1]);
}

static int fp2_set_u(fp2_t r)
{
	BN_zero(r[0]);
	return BN_one(r[1]);
}

static int fp2_set_5u(fp2_t r)
{
	BN_zero(r[0]);
	return BN_set_word(r[1], 5);
}

static int fp2_set_bn(fp2_t r, const BIGNUM *a)
{
	BN_zero(r[1]);
	return BN_copy(r[0], a) != NULL;
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

static int fp2_equ_hex(const fp2_t a, const char *str[2], BN_CTX *ctx)
{
	fp2_t t;
	fp2_init(t, ctx);
	fp2_set_hex(t, str);
	return fp2_equ(a, t);
}

static int fp2_add_word(fp2_t r, const fp2_t a, unsigned long b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *w = NULL;
	if (!(w = BN_CTX_get(ctx))
		|| !BN_set_word(w, b)
		|| !BN_mod_add(r[0], a[0], w, p, ctx)
		|| !BN_copy(r[1], a[1])) {
		BN_free(w);
		return 0;
	}
	BN_free(w);
	return 1;
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

static int fp2_tri(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t t;
	if (!fp2_init(t, ctx)
		|| !fp2_dbl(t, a, p, ctx)
		|| !fp2_add(r, t, a, p, ctx)) {
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(t);
	return 1;
}

static int fp2_sub(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_sub(r[0], a[0], b[0], p, ctx)
		&& BN_mod_sub(r[1], a[1], b[1], p, ctx);
}

static int fp2_neg(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_mod_sub(r[0], p, a[0], p, ctx)
		&& BN_mod_sub(r[1], p, a[1], p, ctx);
}

static int fp2_mul(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *t = NULL;
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	if (!(t = BN_CTX_get(ctx))
		|| !(r0 = BN_CTX_get(ctx))
		|| !(r1 = BN_CTX_get(ctx))

		/* r0 = a0 * b0 - 2 * a1 * b1 */
		|| !BN_mod_mul(r0, a[0], b[0], p, ctx)
		|| !BN_mod_mul(t, a[1], b[1], p, ctx)
		|| !BN_mod_add(t, t, t, p, ctx)
		|| !BN_mod_sub(r0, r0, t, p, ctx)

		/* r1 = a0 * b1 + a1 * b0 */
		|| !BN_mod_mul(r1, a[0], b[1], p, ctx)
		|| !BN_mod_mul(t, a[1], b[0], p, ctx)
		|| !BN_mod_add(r1, r1, t, p, ctx)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(t);
		BN_free(r0);
		BN_free(r1);
		return 0;
	}
	BN_free(t);
	BN_free(r0);
	BN_free(r1);
	return 1;
}

static int fp2_mul_u(fp2_t r, const fp2_t a, const fp2_t b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_CTX_get(ctx))
		|| !(r1 = BN_CTX_get(ctx))
		|| !(t = BN_CTX_get(ctx))

		/* r0 = -2 * (a0 * b1 + a1 * b0) */
		|| !BN_mod_mul(r0, a[0], b[1], p, ctx)
		|| !BN_mod_mul(t, a[1], b[0], p, ctx)
		|| !BN_mod_add(r0, r0, t, p, ctx)
		|| !BN_mod_add(r0, r0, r0, p, ctx)
		|| !BN_mod_sub(r0, p, r0, p, ctx)

		/* r1 = a0 * b0 - 2 * a1 * b1 */
		|| !BN_mod_mul(r1, a[0], b[0], p, ctx)
		|| !BN_mod_mul(t, a[1], b[1], p, ctx)
		|| !BN_mod_add(t, t, t, p, ctx)
		|| !BN_mod_sub(r1, r1, t, p, ctx)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}

static int fp2_mul_num(fp2_t r, const fp2_t a, const BIGNUM *n, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	if (!(r0 = BN_CTX_get(ctx))
		|| !(r1 = BN_CTX_get(ctx))
		
		|| !BN_mod_mul(r0, a[0], n, p, ctx)
		|| !BN_mod_mul(r1, a[1], n, p, ctx)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	return 1;
}

static int fp2_sqr(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_CTX_get(ctx))
		|| !(r1 = BN_CTX_get(ctx))
		||!(t = BN_CTX_get(ctx))
		/* r0 = a0^2 - 2 * a1^2 */
		|| !BN_mod_sqr(r0, a[0], p, ctx)
		|| !BN_mod_sqr(t, a[1], p, ctx)
		|| !BN_mod_add(t, t, t, p, ctx)
		|| !BN_mod_sub(r0, r0, t, p, ctx)

		/* r1 = 2 * a0 * a1 */
		|| !BN_mod_mul(r1, a[0], a[1], p, ctx)
		|| !BN_mod_add(r1, r1, r1, p, ctx)
		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}

static int fp2_sqr_u(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *t = NULL;
	if (!(r0 = BN_CTX_get(ctx))
		|| !(r1 = BN_CTX_get(ctx))
		|| !(t = BN_CTX_get(ctx))
		/* r0 = -4 * a0 * a1 */
		|| !BN_mod_mul(r0, a[0], a[1], p, ctx)
		|| !BN_mod_add(r0, r0, r0, p, ctx)
		|| !BN_mod_add(r0, r0, r0, p, ctx)
		|| !BN_mod_sub(r0, p, r0, p, ctx)

		/* r1 = a0^2 - 2 * a1^2 */
		|| !BN_mod_sqr(r1, a[0], p, ctx)
		|| !BN_mod_sqr(t, a[1], p, ctx)
		|| !BN_mod_add(t, t, t, p, ctx)
		|| !BN_mod_sub(r1, r1, t, p, ctx)

		|| !BN_copy(r[0], r0)
		|| !BN_copy(r[1], r1)) {
		BN_free(r0);
		BN_free(r1);
		BN_free(t);
		return 0;
	}
	BN_free(r0);
	BN_free(r1);
	BN_free(t);
	return 1;
}

static int fp2_inv(fp2_t r, const fp2_t a, const BIGNUM *p, BN_CTX *ctx)
{
	if (BN_is_zero(a[0])) {
		/* r0 = 0 */
		BN_zero(r[0]);
		/* r1 = -(2 * a1)^-1 */
		if (!BN_mod_add(r[1], a[1], a[1], p, ctx)
			|| !BN_mod_inverse(r[1], r[1], p, ctx)
			|| !BN_mod_sub(r[1], p, r[1], p, ctx)) {
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
		BIGNUM *k = NULL;
		BIGNUM *t = NULL;
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

static int fp2_to_bin(const fp2_t a, unsigned char to[64])
{
	memset(to, 0, 64);
	BN_bn2bin(a[1], to + 32 - BN_num_bytes(a[1]));
	BN_bn2bin(a[0], to + 64 - BN_num_bytes(a[0]));
	return 1;
}

static int fp2_from_bin(fp2_t a, const unsigned char from[64])
{
	return BN_bin2bn(from, 32, a[1])
		&& BN_bin2bn(from + 32, 32, a[0]);	
}

static int fp2_test(const BIGNUM *p, BN_CTX *ctx)
{
	const char *_a[] = {
		"5f25ce2083fc970a6b9fdcd819fb1966d300af2afd58d480c59e02b320852183",
		"9acddfef770bcdce452d72461f9d1482a8eff7662e1d591c70a7ce35f2f5710c"};
	const char *_b[] = {
		"7114f0b7f50ebb85c124558f76f10bd277f71c27384deb67f229e582befde3ee",
		"aa2714a30d7b8ae08b987fae8818881fb1952a1f53cda30a35c72841b174d7d"};
	const char *add_a_b[] = {
		"19fabed87667ab9e56c087179b5d5df4290538071b2bd10cd2584d0dfc31bff4",
		"a5705139a7e3867c4de6fa41081e9d04a4094a08235a334d140440ba0e0cbe89"};
	const char *dbl_a[] = {
		"80b9c4105558723013c0e603e676b88840ecb0ae036ba25a5cc6a3e5db8fd89",
		"7f5bbfdeeb73f4aab457393c49ab61c02fed5b8141bfc35cfbe0014402999c9b"};
	const char *tri_a[] = {
		"67316a6189521e2d6cdbeb38586284ef570f7a35dd8f8ea66b6a6cf17e3e1f0c",
		"63e99fce5fdc1b872381003273b9aefdb6eabf9c55622d9d87183452123dc82a"};
	const char *sub_a_b[] = {
		"a450dd6891918276807f32989898d4d97cfc264edf85d7f4b8e3b85844d88312",
		"902b6ea5463415203c73ea4b371b8c00add6a4c438e07eebcd4b5bb1d7de238f"};
	const char *neg_a[] = {
		"571a31df7ea70fe76a63ce77db93adde4ef1e4201d221a5b1fd19874c2cc23fa",
		"1b7220108b97d92390d63909d5f1b2c279029be4ec5d95bf74c7ccf1f05bd471"};
	const char *mul_a_b[] = {
		"87c654e6949d4f119504b210360cc580fc5365c6d34c1321aec27fcf5a1f15b1",
		"36e98d79d712f6a3d1bc6d5ac5a055ee0fcbf088c8744e6e943369538e863eb7"};
	const char *mulu_a_b[] = {
		"486ce50c547db9aa328ad09a6a4e1b69025ab239899251febd08c880c644c80f",
		"87c654e6949d4f119504b210360cc580fc5365c6d34c1321aec27fcf5a1f15b1"};
	const char *sqr_a[] = {
		"b6011ba4cb9f083149a717c7829eb292c31a0800caf88db28bc71f5a084a0405",
		"3a16d18809fca540de3543bdfa3317b45bd8117ce6e6a6be5837fbe70350b684"};
	const char *sqru_a[] = {
		"42125cefeeaa5c70199923d4012897dc6a4270514cada15f34ffa359dcafd875",
		"b6011ba4cb9f083149a717c7829eb292c31a0800caf88db28bc71f5a084a0405"};
	const char *inv_a[] = {
		"5d25a81c4b20b093804befda14731ad2dfa436a450e8b40cf91939ba94fe84be",
		"b317556351e184acb06cf1171069fcf3e9a36b60ca8cd718f55ff0c5769ad325"};
	const char *div_a_b[] = {
		"107048b3442ccc880691cbeb5005bbeb3e71fbe1ec3899971b6caecd224b7dd9",
		"7716a52c4911f52b519d9ec928b56561008469bf3403508d40a324bcd17f4a17"};
	const char *inv_1[] = {
		"1",
		"0"};
	const char *inv_u[] = {
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be"};


	fp2_t a, b, r;
	int ok;

	fp2_init(a, ctx);
	fp2_init(b, ctx);
	fp2_init(r, ctx);

	fp2_set_hex(a, _a);
	fp2_set_hex(b, _b);

	fp2_add(r, a, b, p, ctx);
	ok = fp2_equ_hex(r, add_a_b, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_dbl(r, a, p, ctx);
	ok = fp2_equ_hex(r, dbl_a, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_tri(r, a, p, ctx);
	ok = fp2_equ_hex(r, tri_a, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_sub(r, a, b, p, ctx);
	ok = fp2_equ_hex(r, sub_a_b, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_neg(r, a, p, ctx);
	ok = fp2_equ_hex(r, neg_a, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_mul(r, a, b, p, ctx);
	ok = fp2_equ_hex(r, mul_a_b, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_mul_u(r, a, b, p, ctx);
	ok = fp2_equ_hex(r, mulu_a_b, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_sqr(r, a, p, ctx);
	ok = fp2_equ_hex(r, sqr_a, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_sqr_u(r, a, p, ctx);
	ok = fp2_equ_hex(r, sqru_a, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");
	
	fp2_inv(r, a, p, ctx);
	ok = fp2_equ_hex(r, inv_a, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_div(r, a, b, p, ctx);
	ok = fp2_equ_hex(r, div_a_b, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_set_one(r);
	fp2_inv(r, r, p, ctx);
	ok = fp2_equ_hex(r, inv_1, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp2_set_u(r);
	fp2_inv(r, r, p, ctx);
	ok = fp2_equ_hex(r, inv_u, ctx);
	printf("fp2 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	return 1;
}

static int fp4_init(fp4_t a, BN_CTX *ctx)
{
	int r;
	r = fp2_init(a[0], ctx);
	r &= fp2_init(a[1], ctx);
	if (!r) {
		fp2_cleanup(a[0]);
		fp2_cleanup(a[1]);
	}
	return r;
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

static int fp4_print(const fp4_t a)
{
	fp2_print(a[0]);
	fp2_print(a[1]);
	printf("\n");
	return 1;
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
	return fp2_set_one(r[0]);
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

static int fp4_set_hex(fp4_t r, const char *str[4])
{
	return fp2_set_hex(r[0], str)
		&& fp2_set_hex(r[1], str+2);
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
}

static int fp4_equ_hex(const fp4_t a, const char *str[4], BN_CTX *ctx)
{
	fp4_t t;
	fp4_init(t, ctx);
	fp4_set_hex(t, str);
	return fp4_equ(a, t);
}

static int fp4_to_bin(const fp4_t a, unsigned char to[128])
{
	return fp2_to_bin(a[1], to)
		&& fp2_to_bin(a[0], to + 64);
}

static int fp4_from_bin(fp4_t a, const unsigned char from[128])
{
	return fp2_from_bin(a[1], from)
		&& fp2_from_bin(a[0], from + 64);
}

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
	fp2_t r0, r1, t;

	fp2_init(r0, ctx);
	fp2_init(r1, ctx);

	if (!fp2_init(t, ctx)
		/* r0 = a0 * b0 + a1 * b1 * u */
		|| !fp2_mul(r0, a[0], b[0], p, ctx)
		|| !fp2_mul_u(t, a[1], b[1], p, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)

		/* r[1] = a[0] * b[1] + a[1] * b[0] */
		|| !fp2_mul(r1, a[0], b[1], p, ctx)
		|| !fp2_mul(t, a[1], b[0], p, ctx)
		|| !fp2_add(r1, r1, t, p, ctx)

		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_mul_v(fp4_t r, const fp4_t a, const fp4_t b, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = a0 * b1 * u + a1 * b0 * u */
		|| !fp2_mul_u(r0, a[0], b[1], p, ctx)
		|| !fp2_mul_u(t, a[1], b[0], p, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)

		/* r1 = a0 * b0 + a1 * b1 * u */
		|| !fp2_mul(r1, a[0], b[0], p, ctx)
		|| !fp2_mul_u(t, a[1], b[1], p, ctx)
		|| !fp2_add(r1, r1, t, p, ctx)

		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_sqr(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = a0^2 + a1^2 * u */
		|| !fp2_sqr(r0, a[0], p, ctx)
		|| !fp2_sqr_u(t, a[1], p, ctx)
		|| !fp2_add(r0, r0, t, p, ctx)
		/* r1 = 2 * (a0 * a1) */
		|| !fp2_mul(r1, a[0], a[1], p, ctx)
		|| !fp2_dbl(r1, r1, p, ctx)
		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_sqr_v(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, t;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);
	if (!fp2_init(t, ctx)
		/* r0 = 2 * (a0 * a1) */
		|| !fp2_mul_u(t, a[0], a[1], p, ctx)
		|| !fp2_dbl(r0, t, p, ctx)

		/* r1 = a0^2 + a1^2 * u */
		|| !fp2_sqr(r1, a[0], p, ctx)
		|| !fp2_sqr_u(t, a[1], p, ctx)
		|| !fp2_add(r1, r1, t, p, ctx)
		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(t);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(t);
	return 1;
}

static int fp4_inv(fp4_t r, const fp4_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp2_t r0, r1, k;
	fp2_init(r0, ctx);
	fp2_init(r1, ctx);


	if (!fp2_init(k, ctx)
		/* k = (a1^2 * u - a0^2)^-1 */
		|| !fp2_sqr_u(k, a[1], p, ctx)
		|| !fp2_sqr(r0, a[0], p, ctx)
		|| !fp2_sub(k, k, r0, p, ctx)
		|| !fp2_inv(k, k, p, ctx)

		/* r0 = -(a0 * k) */
		|| !fp2_mul(r0, a[0], k, p, ctx)
		|| !fp2_neg(r0, r0, p, ctx)

		/* r1 = a1 * k */
		|| !fp2_mul(r1, a[1], k, p, ctx)

		|| !fp2_copy(r[0], r0)
		|| !fp2_copy(r[1], r1)) {
		fp2_cleanup(r0);
		fp2_cleanup(r1);
		fp2_cleanup(k);
		return 0;
	}
	fp2_cleanup(r0);
	fp2_cleanup(r1);
	fp2_cleanup(k);
	return 1;
}

static int fp4_test(const BIGNUM *p, BN_CTX *ctx)
{
	const char *_a[] = {
		"bec057c34cec656c05f236d9399cd00c64319632885d200f964e4591dd7ca77",
		"55a10432b9095a12c106019c97fa1ed2a484d84bbb750bcf6a378c3f85ba9d09",
		"9eb75c7b34e0259a59385602bd2210b844e6b9f6396443eed06dbd701b48a26c",
		"76f63f8fb8272b173eaf93cb79e57444c816ef099b3fb11057977d1f3f50eb8"};
	const char *_b[] = {
		"1dd8569e8b7d7a53a362334330ff5b4e3beeb180466cf7d268c157ff724c2de7",
		"48619106bcf6f34107318044223fa5ae3ec74573829f9873e4f06b41d0210762",
		"79fdcb2d33f115ef5405c62b509be15adc14cc82abbe6f89978ed0de987377c6",
		"71a8d1fd3d68cd689b9ed04872690c41858d98065b2535e70d1a6a8f2547f07e"};
	const char *add_a_b[] = {
		"29c45c1ac04c40aa63c156b0c499284f0231cae36ef2c9d362263c589023f85e",
		"9e02953976004d53c83781e0ba39c480e34c1dbf3e14a4434f27f78155dba46b",
		"627527a8662d9497d73a70de182f2acdff08f32dcaa7c49c828cf326d06ad4b5",
		"791835f638eb401a0f89c9852a076385d20f06f6f4d930f81293e261193cff36"};
	const char *dbl_a[] = {
		"17d80af8699d8cad80be46db27339a018c8632c6510ba401f2c9c8b23baf94ee",
		"ab4208657212b425820c03392ff43da54909b09776ea179ed46f187f0b753a12",
		"872eb8f6671ca442dc6d00b584b55a2b67dae0a1584d9901bb6bdfb8533fff5b",
		"edec7f1f704e562e7d5f2796f3cae889902dde13367f6220af2efa3e7ea1d70"};
	const char *sub_a_b[] = {
		"a453aeddabf4f2f4f3009b7a582938f7ac46fb2dfc93c90a761327818edce20d",
		"d3f732bfc1266d1b9d4815875ba792465bd92d838d5735b854720fdb59995a7",
		"24b9914e00ef0fab05328fd76c862f5d68d1ed738da5d46538deec9182d52aa6",
		"4c0691fbc0bd4c3aae4fd4443ac41247e8e66a355909b405ddcea86ab1fe63b7"};
	const char *neg_a[] = {
		"aa53fa83cdd4e09b15a487e261f4fa445baf79e7f1f51cdaec0ab6cec5797b06",
		"609efbcd499a4cdf14fda9b35d94a8727d6dbaff5f05e30c7b380ee85d96a874",
		"1788a384cdc381577ccb554d386cb68cdd0bd954e116aaed1501ddb7c808a311",
		"aed09c07072134406218b2133df07000d571245a80c6f3cadff62355ef5c36c5"};
	const char *mul_a_b[] = {
		"8e897a274c44e47c7db00d58bf08c020472e75f1e008a8a34975a6c947587f80",
		"e8b79955f768f30ab48aa1b12b305a71fd12e252f34345d7692d58adf908739",
		"a647307d347637d0525d62f9148d9bd7aabfb9c93ec03a7575404e5d4fa64310",
		"65cbf741cdf37a3459727a9fcd84b10cc8b1d4c1a3641556de11434b330daf04"};
	const char *mulv_a_b[] = {
		"a0e8117c6960597af922616050142c70b2817d12ee2db30a0ebcafb960872cf2",
		"a647307d347637d0525d62f9148d9bd7aabfb9c93ec03a7575404e5d4fa64310",
		"8e897a274c44e47c7db00d58bf08c020472e75f1e008a8a34975a6c947587f80",
		"e8b79955f768f30ab48aa1b12b305a71fd12e252f34345d7692d58adf908739"};
	const char *sqr_a[] = {
		"fb487bb1bee1c8d21956f8b5b7b1d93c5e7087b02666fc475f63b65cf5a2198",
		"3a4deaf2a26a4f42fdb3bd34ae1c866a2d1ae5f5d9739d66ec758a38661d7639",
		"a089b0d9a76cc56a2db2b56ab0df6e15f7a76ba8ad15e1f3b20accb2245bd827",
		"8ad9618cfbada9f4cb296b5f219267785bc4d9b4d3070048e5301972005bb37f"};
	const char *sqrv_a[] = {
		"56cd3ce60debf9fa15b47fe1a7f8bf998c5b732c8ee7dd26007f036bc5eb23fc",
		"a089b0d9a76cc56a2db2b56ab0df6e15f7a76ba8ad15e1f3b20accb2245bd827",
		"fb487bb1bee1c8d21956f8b5b7b1d93c5e7087b02666fc475f63b65cf5a2198",
		"3a4deaf2a26a4f42fdb3bd34ae1c866a2d1ae5f5d9739d66ec758a38661d7639"};
	const char *inv_a[] = {
		"7aa3d284401216d78e171627742b5a5dc3af41c15e112ceba1eb9e12ea3780cf",
		"99711ed85be3e353d43f87600a9f416b64e1778d92e6b3fc374bc94f59772f70",
		"8be97927776cbf6b7a162a5268df1d6a184ecd4ee56cc36273a7127ceabbebd4",
		"7b4b924e6c5e548d2c5467e6db40bf35858f690d312d35066821af199a81ff67"};
	const char *inv_1[] = {
		"1",
		"0",
		"0",
		"0"};
	const char *inv_u[] = {
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be",
		"0",
		"0"};
	const char *inv_v[] = {
		"0",
		"0",
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be"};

	fp4_t r, a, b;
	int ok;

	fp4_init(r, ctx);
	fp4_init(a, ctx);
	fp4_init(b, ctx);

	fp4_set_hex(a, _a);
	fp4_set_hex(b, _b);

	fp4_add(r, a, b, p, ctx);
	ok = fp4_equ_hex(r, add_a_b, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_dbl(r, a, p, ctx);
	ok = fp4_equ_hex(r, dbl_a, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_sub(r, a, b, p, ctx);
	ok = fp4_equ_hex(r, sub_a_b, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_neg(r, a, p, ctx);
	ok = fp4_equ_hex(r, neg_a, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_mul(r, a, b, p, ctx);
	ok = fp4_equ_hex(r, mul_a_b, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_mul_v(r, a, b, p, ctx);
	ok = fp4_equ_hex(r, mulv_a_b, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_sqr(r, a, p, ctx);
	ok = fp4_equ_hex(r, sqr_a, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_sqr_v(r, a, p, ctx);
	ok = fp4_equ_hex(r, sqrv_a, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_inv(r, a, p, ctx);
	ok = fp4_equ_hex(r, inv_a, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_set_one(r);
	fp4_inv(r, r, p, ctx);
	ok = fp4_equ_hex(r, inv_1, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_set_u(r);
	fp4_inv(r, r, p, ctx);
	ok = fp4_equ_hex(r, inv_u, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp4_set_v(r);
	fp4_inv(r, r, p, ctx);
	ok = fp4_equ_hex(r, inv_v, ctx);
	printf("fp4 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	return 0;
}

int fp12_init(fp12_t a, BN_CTX *ctx)
{
	int r;
	r = fp4_init(a[0], ctx);
	r &= fp4_init(a[1], ctx);
	r &= fp4_init(a[2], ctx);
	if (!r) {
		fp4_cleanup(a[0]);
		fp4_cleanup(a[1]);
		fp4_cleanup(a[2]);
	}
	return r;
}

void fp12_cleanup(fp12_t a)
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

int fp12_print(const fp12_t a)
{
	fp4_print(a[0]);
	fp4_print(a[1]);
	fp4_print(a[2]);
	return 1;
}

static int fp12_is_zero(const fp12_t a)
{
	return fp4_is_zero(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

static int fp12_is_one(const fp12_t a)
{
	return fp4_is_one(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
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

static int fp12_set_hex(fp12_t r, const char *str[12])
{
	return fp4_set_hex(r[0], str)
		&& fp4_set_hex(r[1], str + 4)
		&& fp4_set_hex(r[2], str + 8);
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

static int fp12_equ_hex(const fp12_t a, const char *str[12], BN_CTX *ctx)
{
	fp12_t t;
	fp12_init(t, ctx);
	fp12_set_hex(t, str);
	return fp12_equ(a, t);
}

int fp12_to_bin(const fp12_t a, unsigned char to[384])
{
	return fp4_to_bin(a[2], to)
		&& fp4_to_bin(a[1], to + 128)
		&& fp4_to_bin(a[0], to + 256);
}

static int fp12_from_bin(fp4_t a, const unsigned char from[384])
{
	return fp4_from_bin(a[2], from)
		&& fp4_from_bin(a[1], from + 128)
		&& fp4_from_bin(a[0], from + 256);
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
	fp12_t t;
	fp12_init(t, ctx);
	
	if (!fp12_dbl(t, a, p, ctx)
		|| !fp12_add(r, t, a, p, ctx)) {
		fp12_cleanup(t);
		return 0;
	}
	fp12_cleanup(t);
	return 1;
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

int fp12_mul(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx)
{
	fp4_t r0, r1, r2, t;
	fp4_init(r0, ctx);
	fp4_init(r1, ctx);
	fp4_init(r2, ctx);

	if (!fp4_init(t, ctx)
		/* r0 = a0 * b0 + a1 * b2 * v + a2 * b1 * v */
		|| !fp4_mul(r0, a[0], b[0], p, ctx)
		|| !fp4_mul_v(t, a[1], b[2], p, ctx)
		|| !fp4_add(r0, r0, t, p, ctx)
		|| !fp4_mul_v(t, a[2], b[1], p, ctx)
		|| !fp4_add(r0, r0, t, p, ctx)

		/* r1 = a0*b1 + a1*b0 + a2*b2*v */
		|| !fp4_mul(r1, a[0], b[1], p, ctx)
		|| !fp4_mul(t, a[1], b[0], p, ctx)
		|| !fp4_add(r1, r1, t, p, ctx)
		|| !fp4_mul_v(t, a[2], b[2], p, ctx)
		|| !fp4_add(r1, r1, t, p, ctx)

		/* r2 = a0*b2 + a1*b1 + a2*b0 */
		|| !fp4_mul(r2, a[0], b[2], p, ctx)
		|| !fp4_mul(t, a[1], b[1], p, ctx)
		|| !fp4_add(r2, r2, t, p, ctx)
		|| !fp4_mul(t, a[2], b[0], p, ctx)
		|| !fp4_add(r2, r2, t, p, ctx)

		|| !fp4_copy(r[0], r0)
		|| !fp4_copy(r[1], r1)
		|| !fp4_copy(r[2], r2)) {

		fp4_cleanup(r0);
		fp4_cleanup(r1);
		fp4_cleanup(r2);
		fp4_cleanup(t);
		return 0;
	}
	fp4_cleanup(r0);
	fp4_cleanup(r1);
	fp4_cleanup(r2);
	fp4_cleanup(t);
	return 1;
}

static int fp12_sqr(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	fp4_t r0, r1, r2, t;
	fp4_init(r0, ctx);
	fp4_init(r1, ctx);
	fp4_init(r2, ctx);
	if (!(fp4_init(t, ctx))
		/* r0 = a0^2 + 2*a1*a2*v */
		|| !fp4_sqr(r0, a[0], p, ctx)
		|| !fp4_mul_v(t, a[1], a[2], p, ctx)
		|| !fp4_dbl(t, t, p, ctx)
		|| !fp4_add(r0, r0, t, p, ctx)

		/* r1 = 2*a0*a1 + a^2 * v */
		|| !fp4_mul(r1, a[0], a[1], p, ctx)
		|| !fp4_dbl(r1, r1, p, ctx)
		|| !fp4_sqr_v(t, a[2], p, ctx)
		|| !fp4_add(r1, r1, t, p, ctx)

		/* r2 = 2*a0*a2 + a1^2*/
		|| !fp4_mul(r2, a[0], a[2], p, ctx)
		|| !fp4_dbl(r2, r2, p, ctx)
		|| !fp4_sqr(t, a[1], p, ctx)
		|| !fp4_add(r2, r2, t, p, ctx)

		|| !fp4_copy(r[0], r0)
		|| !fp4_copy(r[1], r1)
		|| !fp4_copy(r[2], r2)) {

		fp4_cleanup(r0);
		fp4_cleanup(r1);
		fp4_cleanup(r2);
		fp4_cleanup(t);
		return 0;
	}
	fp4_cleanup(r0);
	fp4_cleanup(r1);
	fp4_cleanup(r2);
	fp4_cleanup(t);
	return 1;
}

static int fp12_inv(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	if (fp4_is_zero(a[2])) {
		fp4_t k;
		fp4_t t;
		if (!fp4_init(t, ctx)) {
			return 0;
		}

		fp4_t r0, r1, r2;
		fp4_init(r0, ctx);
		fp4_init(r1, ctx);
		fp4_init(r2, ctx);

		if (!(fp4_init(k, ctx))
			/* k = (a0^3 + a1^3 * v)^-1 */
			|| !fp4_sqr(k, a[0], p, ctx)
			|| !fp4_mul(k, k, a[0], p, ctx)
			|| !fp4_sqr_v(t, a[1], p, ctx)
			|| !fp4_mul(t, t, a[1], p, ctx)
			|| !fp4_add(k, k, t, p, ctx)
			|| !fp4_inv(k, k, p, ctx)
		
			/* r2 = a1^2 * k */
			|| !fp4_sqr(r[2], a[1], p, ctx)
			|| !fp4_mul(r[2], r[2], k, p, ctx)

			/* r1 = -(a0 * a1 * k) */
			|| !fp4_mul(r[1], a[0], a[1], p, ctx)
			|| !fp4_mul(r[1], r[1], k, p, ctx)
			|| !fp4_neg(r[1], r[1], p, ctx)

			/* r0 = a0^2 * k */
			|| !fp4_sqr(r[0], a[0], p, ctx)
			|| !fp4_mul(r[0], r[0], k, p, ctx)

			) {

			fp4_cleanup(k);
			fp4_cleanup(t);
			return 0;
		}
		fp4_cleanup(k);
		fp4_cleanup(t);
		return 1;

	} else {
	
		fp4_t t0, t1, t2, t3;

		if (!(fp4_init(t0, ctx))
			|| !(fp4_init(t1, ctx)) //FIXME
			|| !(fp4_init(t2, ctx)) 
			|| !(fp4_init(t3, ctx))

			/* t0 = a1^2 - a0 * a2 */
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
			|| !fp4_sqr(t3, t1, p, ctx)
			|| !fp4_mul(r[0], t0, t2, p, ctx)
			|| !fp4_sub(t3, t3, r[0], p, ctx)
			|| !fp4_inv(t3, t3, p, ctx)
			|| !fp4_mul(t3, a[2], t3, p, ctx)
	
			/* r0 = t2 * t3 */
			|| !fp4_mul(r[0], t2, t3, p, ctx)

			/* r1 = -(t1 * t3) */
			|| !fp4_mul(r[1], t1, t3, p, ctx)
			|| !fp4_neg(r[1], r[1], p, ctx)

			/* r2 = t0 * t3 */
			|| !fp4_mul(r[2], t0, t3, p, ctx)
			) {
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

//TODO: check this!
static int fp12_div(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx)
{
	return fp12_inv(r, b, p, ctx)
		&& fp12_mul(r, a, r, p, ctx);
}

int fp12_pow(fp12_t r, const fp12_t a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	int n, i;
	fp12_t t;

	fp12_init(t, ctx);

	if (BN_is_zero(k)) {
		return fp12_set_one(r);
	}

	n = BN_num_bits(k);
	if (n < 1 || n > 256 * 12) {
		return 0;
	}

	if (!fp12_copy(t, a)) {
		return 0;
	}
	for (i = n - 2; i >= 0; i--) {
		if (!fp12_sqr(t, t, p, ctx)) {
			return 0;
		}
		if (BN_is_bit_set(k, i)) {
			if (!fp12_mul(t, t, a, p, ctx)) {
				return 0;
			}
		}
	}

	fp12_copy(r, t);
	return 1;
}

static int fp12_fast_expo_p1(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_copy(r[0][0], a[0][0])
		&& fp2_neg (r[0][1], a[0][1], p, ctx)
		&& fp2_neg (r[1][0], a[1][0], p, ctx)
		&& fp2_copy(r[1][1], a[1][1])
		&& fp2_copy(r[2][0], a[2][0])
		&& fp2_neg (r[2][1], a[2][1], p, ctx);
}

static int fp12_fast_expo_p2(fp12_t r, const fp12_t a, const BIGNUM *p, BN_CTX *ctx)
{
	const BIGNUM *pw20;
	const BIGNUM *pw21;
	const BIGNUM *pw22;
	const BIGNUM *pw23;
	pw20 = SM9_get0_fast_final_exponent_p20();
	pw21 = SM9_get0_fast_final_exponent_p21();
	pw22 = SM9_get0_fast_final_exponent_p22();
	pw23 = SM9_get0_fast_final_exponent_p23();
	
	if(!fp2_copy(r[0][0], a[0][0])
		|| !fp2_neg (r[0][1], a[0][1], p, ctx)
		|| !fp2_mul_num(r[1][0], a[1][0], pw20, p, ctx)
		|| !fp2_mul_num(r[1][1], a[1][1], pw21, p, ctx)
		|| !fp2_mul_num(r[2][0], a[2][0], pw22, p, ctx)
		|| !fp2_mul_num(r[2][1], a[2][1], pw23, p, ctx)) {
			
		return 0;
	}
	return 1;
}

static int fp12_test(const BIGNUM *p, BN_CTX *ctx)
{
	const char *_a[] = {
		"3a4b2fdf33cfe01aab98d17aefc8d38b0508061c3117685839bd0dfdeb5783a8",
		"88a9043bdc9abb43d241e7f62b0182d2c9f8de39d77d154a57e126d871e7bcc0",
		"cd2a13d8e31bc262757be16f34fab3632bfdf4c5be36e86799037305a73210f",
		"c407de563b8393c590e35b4df002bc9c79e3098558412a7d48bd62ca8723f3e",
		"66cbdec2300eebf35b0ab8637a93e0174a4182957b853b227c2a1612adbac39d",
		"481431cd7d6b54175b2b95e0036821ed9d757e383ae1a8d4b4ee95614271d328",
		"4b1d12f271aa058193adc626fa8dd7c510678cd9f6a330c69652deaf6287948d",
		"ab075f5760464947bdb5a644a1292776d5b6cfd735df54c3b4f1948f2cc1ac7",
		"b16b0b0bd0c14d693f2bcb13c738669ed806e67b7b18d6f0bb62a2e8d94aeff6",
		"7ca6249c1b6d5793aca0549ffaf1debe372a3c72129599afeae445865d0f53cd",
		"16390ad0d7dd96377a198a2c0736278a453e39f006275b64d2027ea1570eac51",
		"ab12e62fcda3b9e62074960a8b036f564b6d45bab4b183be000827a3183f2878"};
	const char *_b[] = {
		"7d09b50545b09312f786b5e0486de52aa79578b18961ede71e8e2e0b8a3aebb8",
		"280070ecb08554a8bb799271eb3214f2b582c69858e2771aec594d72cd067f66",
		"18ef945e265cc1a1b77a2c60db66a97b5365f939bd0dcf1cce578a822ce2fd74",
		"9b0690c98e2c054afc4ddb3cf9e6e45f2ed8dbbf1edfd8eae8950454dd2f5033",
		"540a59f0db96dba0c8efc44d50dc3b55b0b1a421ba8964b76759f5fa2db4604f",
		"2a17506aeb7ce73497db53143dedda0429d1430453ee17d743a7d1425c19b79e",
		"1ca32ffef87f1aeda06046ca9d345445424f00300daf0fd66d37b2620572db62",
		"18c11cc3b61d709d7ed976e3da5ba630bc49d17bda470c3aace50d4db3e8ae5d",
		"4b91ac95d741011137c66858ca98dbbcd5744b77c51894e1fda0c5b80959cfd3",
		"1d8e5cae7d4463ee8f37b73037066455b284cca92ca0255eef8b0733b1d7b7f",
		"839ea9892563527b6e653cd9ba665d6284c7696d5aedc884e469cb90e352a91c",
		"ad699cb305b6d98aaac6fdb684e59c0d194db0213214a7df4bbed0240545a520"};
	const char *add_a_b[] = {
		"114e4e476dccc3bcd1bdc0b42a7f1708aaaeb829ffe676372dba0e1924129e3",
		"b0a975288d200fec8dbb7a68163397c57f7ba4d2305f8c65443a744b3eee3c26",
		"25c2359bb48e7dc7ded1ea77ceb654b18625d88618f13da347e7c1b287561e83",
		"a7470eaef1e43e87555c10f1d8e71028f6770c577463eb92bd20da8185a18f71",
		"49638b3090220a24df6d160d5e15427d900936c1b93b0fdfe1470e4f81dde6f",
		"722b823868e83b4bf306e8f44155fbf1c746c13c8ecfc0abf89666a39e8b8ac6",
		"67c042f16a29206f340e0cf197c22c0a52b68d0a0452409d038a911167fa6fef",
		"237192b92c21d531fab4d148246e38a829a53e794da50186e8342696a6b4c924",
		"46bcb7a1a55ea788a0ee881c9c427b168b889ea825b67cf6d393cd78ff537a4c",
		"7e7f0a6703419dd29593d012fe6245039252893ca55f9c05d9dcf5f9982ccf4c",
		"99d7b459fd40e8b2e87ec705c19c84ecca05a35d611523e9b66c4a323a61556d",
		"a23c82e2d0b6ec7ef537e8711a5a441e42c86290cc4b3cc166575c9f3a33881b"};
	const char *dbl_a[] = {
		"74965fbe679fc0355731a2f5df91a7160a100c38622ed0b0737a1bfbd6af0750",
		"5b120877b691cf95ce80249c60743e6071ff2928947f3bb8ca52b289007e3403",
		"19a5427b1c63784c4eaf7c2de69f566c657fbe98b7c6dd0cf3206e60b4e6421e",
		"1880fbcac7707278b21c6b69be0057938f3c6130ab08254fa917ac5950e47e7c",
		"1757bd845d7a30f4e011c576ff98f8e9729071dfdc8f876912e490fd782441bd",
		"9028639afad6a82eb6572bc006d043db3aeafc7075c351a969dd2ac284e3a650",
		"963a25e4e3540b03275b8c4df51baf8a20cf19b3ed46618d2ca5bd5ec50f291a",
		"1560ebeaec08c928f7b6b4c8942524eedab6d9fae6bbea98769e3291e598358e",
		"ac9616179edef3e0a853ead798e205f88e1b39abdbb6bf059155aaa9cf449a6f",
		"430c493834370835833cfdf00054f6374c61e5990ab04483f058efe4d6cd621d",
		"2c7215a1afbb2c6ef43314580e6c4f148a7c73e00c4eb6c9a404fd42ae1d58a2",
		"9fe5cc5f98a3ccda6ae580c52078176774e7f82a4ee818a01aa0b41e4d2d0b73"};
	const char *tri_a[] = {
		"aee18f9d9b6fa05002ca7470cf5a7aa10f18125493463908ad3729f9c2068af8",
		"2d7b0cb39088e3e7cabe614295e6f9ee1a057417518162273cc43e398f14ab46",
		"2677e3b8aa95347276073a44d9ef01a2983f9de513aa4b936cb0a5910f59632d",
		"24c179b02b28abb50b2aa11e9d00835d56da91c9008c37f77da38285f956bdba",
		"7e239c468d891ce83b1c7dda7a2cd900bcd1f4755814c28b8f0ea71025df055a",
		"21fc9568759e55543b7f165014a99e83b66de75d962a0ba2395c24fbe40433fb",
		"2b1738d7525a6992e505a724fa1ac00a0f441342c96ea377dd8900e64445782a",
		"201161e0620d2dbd73920f2cde37b766481246f85a19dfe4b1ed4bdad8645055",
		"a7c121236cfc9a58117c0a9b6a8ba552442f8cdc3c54a71a6748b26ac53e44e8",
		"9726dd44d00b8d759d9a74005b80db061998ec002caef57f5cd9a43508b706d",
		"42ab20728798c2a66e4c9e8415a2769ecfbaadd01276122e76077be4052c04f3",
		"94b8b28f63a3dfceb5566b7fb5ecbf789e62aa99e91ead8235394099821aee6e"};
	const char *sub_a_b[] = {
		"73817ad9f0c2f3f98a15c6ea9ce9b5a57f6520b5c230694d009e7b1a446ddd6d",
		"60a8934f2c15669b16c855843fcf6de0147617a17e9a9e2f6b87d965a4e13d5a",
		"aa230cdf6a78a17645e13d060d77c900014c795db9508e4590a847d610e16918",
		"2779ed1bd82fdae332c405c7daa80eafbab7e824511f2898d1666cffae943488",
		"12c184d154781052921af41629b7a4c1998fde73c0fbd66b14d020188006634e",
		"1dfce16291ee6ce2c35042cbc57a47e973a43b33e6f390fd7146c41ee6581b8a",
		"2e79e2f3792aea93f34d7f5c5d59837fce188ca9e8f420f0291b2c4d5d14b92b",
		"a82f5931c28a9ae8d3058ed06545b38bd3042eccb391d7ed73d9a7232234b1e7",
		"65d95e75f9804c58076562bafc9f8ae202929b03b600420ebdc1dd30cff12023",
		"7acd3ed133991154c3acd92cf7817878dc01efa77fcb9759fbeb951321f1d84e",
		"48da6147b51deaade1b7f8a2425e916ce26963cdc5b481bbd3084e38570d48b2",
		"b3e9497cca90874d4bb143a3fbac9a8e541228e49d17caba99b8f2a6f64ac8d5"};
	const char *neg_a[] = {
		"7bf4d020ced3c6d72a6ad9d505c5f3ba1cea8d2ee9638683abb28d29f7f9c1d5",
		"2d96fbc42608ebae03c1c359ca8d447257f9b51142fdd9918d8e744f716988bd",
		"a96d5ec27471eacbaeabed39023f1c0eef32b3febe9780556bdf63f788de246e",
		"a9ff821a9eeb6db57cf5759b168e9b7b5a5462b2c4f6dc3410e3c4fb3adf063f",
		"4f74213dd294bafe7af8f2ec7afae72dd7b110b59ef5b3b969458515359681e0",
		"6e2bce32853852da7ad8156ff226a557847d1512df994607308105c6a0df7255",
		"6b22ed0d90f9a1704255e528fb00ef80118b067123d7be154f1cbc7880c9b0f0",
		"ab8f8a0a8c9f425d5a2850ebab7c34cdb497264da71cf98faa2081def0852ab6",
		"4d4f4f431e2598896d7e03c2e5660a649ebaccf9f6217eb2a0cf83f0a065587",
		"3999db63e7364f5e296356affa9ce886eac856d907e5552bfa8b55a18641f1b0",
		"a006f52f2ac610ba5bea2123ee589fbadcb4595b14539377136d1c868c42992c",
		"b2d19d034ffed0bb58f15456a8b57eed6854d9065c96b1de5677384cb121d05"};
	const char *mul_a_b[] = {
		"b053bed5afdc274ecf4d5ed22d464f121545c877192cb8bc2ee213fbd18c6a6d",
		"b5b637e1176fdc19fe6eca269ae7653766f4583d9cef7c4afdf479f9f90253d2",
		"b4f0bdbcf61a49b3d05760978b3f81ae2e14df914d39db2f9250d66a05dc6925",
		"acb2108b6694c3123885af6df5b9b3ab9b68930ec54b7fccfd7228bcb78e9fd3",
		"606eb0f669124e2afa06f4ed23bee5ca9445a1a9cc6f08202564ed69aab0dd2",
		"3f9ca64637e2ff3453e54a450a2f5a05c1d3254cd785d841cb16b6bad0879de5",
		"4c8165e6d96c598acee552bf0a98833af5e44dc867ca8fe7f48aa158bac619e0",
		"5d8c852ab5b21eec17dd9919a60e6d1ba24f9a8064af5675b6173ec6279dc35e",
		"3dca5d804536983f2d46853d58dd994a9212f18ef3e8df749342d71a9a92989c",
		"64af38a985084da07ccbae1a91d2c7f09e7779d0285a1b9b753860e9937c4a47",
		"77fe4dbaca161d0f7f99b4f186d8d12449201e7ba574ebbbb45bab99406b119c",
		"e9f3cfc4c197176ad588c1d3fa965172ff9f1046831a92490885af616c3edb4"};
	const char *sqr_a[] = {
		"1e92886bddb591a8f6ba96d288bdfd7f2e50f6c7151c58e3682628f1827a0a19",
		"a939f4ca345e7007c25484bb222cbac1877b3bc19fde66051c3b4ad1afcd3be3",
		"a911367ed1020dc600b229e755fd0e892035a7833feb5d1ec9735b0606bde3f7",
		"5064e0d6b9aa4c5d0b1a345f7e51de0789bd91753fbc92bd041733a0b5618b58",
		"426fddbc40017ef829487b9644308737cde22889931cd3c25d6d6b9c5a80eacc",
		"b2b8d0264942b6f2ba2fce697ffd663e1f7d2337d964a6a1f1d3a8f274293074",
		"ee7c6cd61ae3316b70d47c6e0ffffff18e7f9a11a1b1a3d4faee189c42946af",
		"4cd26db84bbad4051abfe8e65071eb45ae0cb9edad42fbaebc624a4ab1624c06",
		"59168d22a22f0e835aafb8e47f9e3ca3ac0787d75472f5bb2a3200d3d8fe8901",
		"916ad4377c2939b7fa7c9e4ca76c7191a60db21db13e028b411af8cac9305355",
		"816985d7bc47c4ebb55b186b8eefd2609d01623b7a9f034f31a2434d0d022e49",
		"b1f0bc64e20661ce1067112a7306ff9dcf2b2394b038062cfcb79652f92e4678"};
	const char *inv_a[] = {
		"76003429929c9970eb611b8579900f9806b1acb8955a8effea9c28a1156fe2f1",
		"90682a0a7b278173bb8aed9bd9fed33e1c36af5dc968f8f4e01c8133ce552e5f",
		"a29d8805baa933bd50ff7ba55ea3feb3df8811d773c7fa4f846bbbddbb9a5acf",
		"20b64affa212b98e4ea552f87be84ea52183bac9df7c4bdbe07212cc8b9654da",
		"addbc46339a3c49e7e856d73255974d0a5fd65da56a36f536a298a4d8082069e",
		"8c43a01e79cef927fc9b2ec58d63ecfdc720d47e3b9cfaf7edf1ec30fd9764ef",
		"46da195353db6d51fb72c9134f14db01552e84452b70109f1aa9c5bdca80d9b6",
		"8a72fe0032b82fab1e83b5cd8945fd6c9cbe14486a5b0b4b3ee0680d2ac38f15",
		"5270e560c6f81f183614c77e37bb9dba009b6769c91a856505ac3954ef244aa3",
		"8640186e2f43c293f19f3470645fbafcfe132b5eefc60b7e3004702f2e41b906",
		"2a46b3cb4d9484e9a20aa399e2a1a3895646f5784849abe5f251b6bb1394d135",
		"99c14f695f65df2b583f7669f30b60ce9b7f2b01036d89917f095792fd072788"};
	char *r_str =
		"033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE";
	char *w_str[] = { /* w = g^r */
		"1F96B08E97997363911314705BFB9A9DBB97F75553EC90FBB2DDAE53C8F68E42",
		"6A814AAF475F128AEF43A128E37F80154AE6CB92CAD7D1501BAE30F750B3A9BD",
		"898D60848026B7EFB8FCC1B2442ECF0795F8A81CEE99A6248F294C82C90D26BD",
		"44643CEAD40F0965F28E1CD2895C3D118E4F65C9A0E3E741B6DD52C0EE2D25F5",
		"0656FCB663D24731E80292188A2471B8B68AA993899268499D23C89755A1A897",
		"4F8624EB435B838CCA77B2D0347E65D5E46964412A096F4150D8C5EDE5440DDF",
		"3F012DB04BA59FE88DB889321CC2373D4C0C35E84F7AB1FF33679BCA575D6765",
		"A543D25609AE943920679194ED30328BB33FD15660BDE485C6B79A7B32B01398",
		"8EAF5D179A1836B359A9D1D9BFC19F2EFCDB829328620962BD3FDF15F2567F58",
		"30DADC5CD9E207AEE32209F6C3CA3EC0D800A1A42D33C73153DED47C70A39D2E",
		"815AEBA217AD502DA0F48704CC73CABB3C06209BD87142E14CBD99E8BCA1680F",
		"81377B8FDBC2839B4FA2D0E0F8AA6853BBBE9E9C4099608F8612C6078ACD7563"};
	const char *inv_1[] = {
		"1",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0"};
	const char *inv_u[] = {
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0"};
	const char *inv_v[] = {
		"0",
		"0",
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0"};
	const char *inv_w[] = {
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be"};
	const char *inv_w2[] = {
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be",
		"0",
		"0",
		"0",
		"0"};


	fp12_t r, a, b;
	int ok;

	fp12_init(r, ctx);
	fp12_init(a, ctx);
	fp12_init(b, ctx);

	fp12_set_hex(a, _a);
	fp12_set_hex(b, _b);

	fp12_add(r, a, b, p, ctx);
	ok = fp12_equ_hex(r, add_a_b, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_dbl(r, a, p, ctx);
	ok = fp12_equ_hex(r, dbl_a, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_tri(r, a, p, ctx);
	ok = fp12_equ_hex(r, tri_a, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_sub(r, a, b, p, ctx);
	ok = fp12_equ_hex(r, sub_a_b, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_neg(r, a, p, ctx);
	ok = fp12_equ_hex(r, neg_a, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_mul(r, a, b, p, ctx);
	ok = fp12_equ_hex(r, mul_a_b, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_sqr(r, a, p, ctx);
	ok = fp12_equ_hex(r, sqr_a, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_inv(r, a, p, ctx);
	ok = fp12_equ_hex(r, inv_a, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_set_one(r);
	fp12_inv(r, r, p, ctx);
	ok = fp12_equ_hex(r, inv_1, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_set_u(r);
	fp12_inv(r, r, p, ctx);
	ok = fp12_equ_hex(r, inv_u, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_set_v(r);
	fp12_inv(r, r, p, ctx);
	ok = fp12_equ_hex(r, inv_v, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_set_w(r);
	fp12_inv(r, r, p, ctx);
	ok = fp12_equ_hex(r, inv_w, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_set_w_sqr(r);
	fp12_inv(r, r, p, ctx);
	ok = fp12_equ_hex(r, inv_w2, ctx);
	printf("fp12 test %d: %s\n", __LINE__, ok ? "ok" : "error");

	return 0;
}

int point_init(point_t *P, BN_CTX *ctx)
{
	int r;
	r = fp2_init(P->X, ctx);
	r &= fp2_init(P->Y, ctx);
	r &= fp2_init(P->Z, ctx);
	r &= fp2_set_one(P->Y);
	if (!r) {
		fp2_cleanup(P->X);
		fp2_cleanup(P->Y);
		fp2_cleanup(P->Z);
		return 0;
	}
	fp2_set_zero(P->X);
	fp2_set_zero(P->Z);
	return 1;
}

void point_cleanup(point_t *P)
{
	fp2_cleanup(P->X);
	fp2_cleanup(P->Y);
	fp2_cleanup(P->Z);
}

void point_print(const point_t *P)
{
	printf(" X1: %s\n", BN_bn2hex((P->X)[1]));
	printf(" X0: %s\n", BN_bn2hex((P->X)[0]));
	printf(" Y1: %s\n", BN_bn2hex((P->Y)[1]));
	printf(" Y0: %s\n", BN_bn2hex((P->Y)[0]));
	printf(" Z1: %s\n", BN_bn2hex((P->Z)[1]));
	printf(" Z0: %s\n", BN_bn2hex((P->Z)[0]));
	printf("\n");
}

int point_copy(point_t *R, const point_t *P)
{
	return fp2_copy(R->X, P->X)
		&& fp2_copy(R->Y, P->Y)
		&& fp2_copy(R->Z, P->Z);
}

int point_set_to_infinity(point_t *P)
{
	fp2_set_zero(P->X);
	fp2_set_zero(P->Z);
	return fp2_set_one(P->Y);
}

int point_is_at_infinity(const point_t *P)
{
	return fp2_is_zero(P->X)
		&& fp2_is_one(P->Y)
		&& fp2_is_zero(P->Z);
}

int point_equ(const point_t *P, const point_t *Q)
{
	return fp2_equ(P->X, Q->X)
		&& fp2_equ(P->Y, Q->Y)
		&& fp2_equ(P->Z, Q->Z);
}

int point_set_affine_coordinates(point_t *P, const fp2_t x, const fp2_t y)
{
	return fp2_copy(P->X, x)
		&& fp2_copy(P->Y, y)
		&& fp2_set_one(P->Z);
}

int point_set_affine_coordinates_hex(point_t *P, const char *str[4])
{
	fp2_set_hex(P->X, str);
	fp2_set_hex(P->Y, str + 2);
	fp2_set_one(P->Z);
	return 1;
}

static int point_equ_hex(const point_t *P, const char *str[4], BN_CTX *ctx)
{
	point_t T;
	point_init(&T, ctx);
	point_set_affine_coordinates_hex(&T, str);
	return point_equ(P, &T);
}

int point_set_affine_coordinates_bignums(point_t *P,
	const BIGNUM *x0, const BIGNUM *x1, const BIGNUM *y0, const BIGNUM *y1)
{
	return fp2_set(P->X, x0, x1)
		&& fp2_set(P->Y, y0, y1)
		&& fp2_set_one(P->Z);
}

int point_get_affine_coordinates(const point_t *P, fp2_t x, fp2_t y)
{
	return fp2_copy(x, P->X)
		&& fp2_copy(y, P->Y)
		&& fp2_is_one(P->Z);
}

int point_get_ext_affine_coordinates(const point_t *P, fp12_t x, fp12_t y, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t xP;
	fp2_t yP;
	fp12_t wem2;
	fp12_t wem3;

	r = 1;
	r &= fp2_init(xP, ctx);
	r &= fp2_init(yP, ctx);
	r &= fp12_init(wem2, ctx);
	r &= fp12_init(wem3, ctx);
	if (!r) {
		goto end;
	}

	r = 0;
	if (!point_get_affine_coordinates(P, xP, yP)
		|| !fp12_set_fp2(x, xP)
		|| !fp12_set_fp2(y, yP)

		/* x = x * w^-2 */
		|| !fp12_set_w_sqr(wem2)
		|| !fp12_inv(wem2, wem2, p, ctx)
		|| !fp12_mul(x, x, wem2, p, ctx)

		/* y = y * w^-3 */
		|| !fp12_set_v(wem3)
		|| !fp12_inv(wem3, wem3, p, ctx)
		|| !fp12_mul(y, y, wem3, p, ctx)) {
		//goto end;
	}
	r = 1;

end:
	fp2_cleanup(xP);
	fp2_cleanup(yP);
	fp12_cleanup(wem2);
	fp12_cleanup(wem3);
	return r;
}

int point_set_ext_affine_coordinates(point_t *P, const fp12_t x, const fp12_t y, const BIGNUM *p, BN_CTX *ctx)
{
	fp12_t tx;
	fp12_t ty;

	fp12_init(tx, ctx);
	fp12_init(ty, ctx);

	fp12_set_w_sqr(tx);
	fp12_set_v(ty);
	fp12_mul(tx, x, tx, p, ctx);
	fp12_mul(ty, y, ty, p, ctx);

	point_set_affine_coordinates(P, tx[0][0], ty[0][0]);

	fp12_cleanup(tx);
	fp12_cleanup(ty);
	return 1;
}

int point_is_on_curve(point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t x, y, b, t;

	r = fp2_init(x, ctx);
	r &= fp2_init(y, ctx);
	r &= fp2_init(b, ctx);
	r &= fp2_init(t, ctx);
	if (!r) {
		goto end;
	}
	
	fp2_set_5u(b);

	if (!point_get_affine_coordinates(P, x, y)
		/* x^3 + 5 * u */
		|| !fp2_sqr(t, x, p, ctx)
		|| !fp2_mul(x, x, t, p, ctx)
		|| !fp2_add(x, x, b, p, ctx)
		/* y^2 */
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

int point_to_octets(const point_t *P, unsigned char to[129], BN_CTX *ctx)
{
	to[0] = 0x04;

	if (fp2_is_one(P->Z)) {
		fp2_to_bin(P->X, to + 1);
		fp2_to_bin(P->Y, to + 65);
	} else {
		fp2_t x, y;
		fp2_init(x, ctx);
		fp2_init(y, ctx);
		point_get_affine_coordinates(P, x, y);

		fp2_to_bin(x, to + 1);
		fp2_to_bin(y, to + 65);
		fp2_cleanup(x);
		fp2_cleanup(y);
	}	
	return 1;
}

int point_from_octets(point_t *P, const unsigned char from[129], const BIGNUM *p, BN_CTX *ctx)
{
	if (from[0] != 0x04) {
		return 0;
	}
	fp2_from_bin(P->X, from + 1);
	fp2_from_bin(P->Y, from + 65);
	fp2_set_one(P->Z);
	return point_is_on_curve(P, p, ctx);
}

int point_dbl(point_t *R, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t x3, y3, x1, y1, lambda, t;

	r = 1;
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(lambda, ctx);
	r &= fp2_init(t, ctx);
	if (!r) {
		goto end;
	}

	if (point_is_at_infinity(P)) {
		r = point_set_to_infinity(R);
		goto end;
	}

	if (!point_get_affine_coordinates(P, x1, y1)
		/* lambda = 3 * x1^2 / 2 * y1 */
		|| !fp2_sqr(lambda, x1, p, ctx)
		|| !fp2_tri(lambda, lambda, p, ctx)
		|| !fp2_dbl(t, y1, p, ctx)
		|| !fp2_inv(t, t, p, ctx)
		|| !fp2_mul(lambda, lambda, t, p, ctx)

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
	fp2_cleanup(y3);
	fp2_cleanup(lambda);
	fp2_cleanup(t);
	return r;
}

int point_add(point_t *R, const point_t *P, const point_t *Q, const BIGNUM *p, BN_CTX *ctx)
{
	int r;
	fp2_t x1;
	fp2_t y1;
	fp2_t x2;
	fp2_t y2;
	fp2_t x3;
	fp2_t y3;
	fp2_t lambda;
	fp2_t t;

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
	r &= fp2_init(x1, ctx);
	r &= fp2_init(y1, ctx);
	r &= fp2_init(x2, ctx);
	r &= fp2_init(y2, ctx);
	r &= fp2_init(x3, ctx);
	r &= fp2_init(y3, ctx);
	r &= fp2_init(lambda, ctx);
	r &= fp2_init(t, ctx);
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
		r = point_set_to_infinity(R);
		goto end;
	}

	/* lambda = (y2 - y1)/(x2 - x1) */
	if (!fp2_sub(lambda, y2, y1, p, ctx)
		|| !fp2_sub(t, x2, x1, p, ctx)
		|| !fp2_inv(t, t, p, ctx)
		|| !fp2_mul(lambda, lambda, t, p, ctx)

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

int point_neg(point_t *R, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	return fp2_copy(R->X, P->X)
		&& fp2_neg(R->Y, P->Y, p, ctx)
		&& fp2_copy(R->Z, P->Z);
}

int point_sub(point_t *R, const point_t *P, const point_t *Q, const BIGNUM *p, BN_CTX *ctx)
{
	point_t T;

	memset(&T, 0, sizeof(T));
	if (!point_init(&T, ctx)
		|| !point_neg(&T, Q, p, ctx)
		|| !point_add(R, P, &T, p, ctx)) {
		point_cleanup(&T);
		return 0;
	}
	point_cleanup(&T);
	return 1;
}

int point_mul(point_t *R, const BIGNUM *k, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	int i, n;

	if (BN_is_zero(k)) {
		return point_set_to_infinity(R);
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

int point_mul_generator(point_t *R, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	point_t G;

	memset(&G, 0, sizeof(G));
	point_init(&G, ctx);
	point_set_affine_coordinates_bignums(&G,
		SM9_get0_generator2_x0(),
		SM9_get0_generator2_x1(),
		SM9_get0_generator2_y0(),
		SM9_get0_generator2_y1());

	return point_mul(R, k, &G, p, ctx);
}

static int point_test(const BIGNUM *p, BN_CTX *ctx)
{
	const char *_G[] = {
		"3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b",
		"85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141",
		"a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7",
		"17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96"};
	const char *dbl_G[] = {
		"2a74f8561b91993205eb512576ad56221ea5963f3da078240d55594fb051ea86",
		"513f149ab53e94bb3a0367c61ff87670e025db30c57f84594e4ba4d7b3c656cf",
		"8e3d9ec4e63d5b9f83081fb97b715430c8bfc6f1a1321a89627b9a4e8961c7bd",
		"776de41db0511b8976d69c982dd4757d641487c68d13cbee7069396c20cd3459"};
	const char *tri_G[] = {
		"9e5437ea263653ea0617ca82c5ce5db4937dece2f762a6fbdae7fb3032f9b154",
		"4dd9b503b00f0e8334e5cbdc9ff80deb4b207a1b1fda2382f3812bd5687937c0",
		"3d491f4ffb2a4ab249e396fe8e58b6e8cb23ef935309e576bc5a9a3b4fd97090",
		"b1174c2d2b36cee03e1a7081eb71f60c35fac603f2b550218ec935c1e00bdd5b"};
	const char *neg_G[] = {
		"3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b",
		"85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141",
		"e70d72ae8e5694b76d23b3ab8673752da02d8b27360e6ca8359df8219b79db6",
		"9eef64f6d41f4adf6f499e29c8cfe0581abbe9db7733261e6001d3bc5e6559e7"};
	const char *sub_3G_G[] = {
		"2a74f8561b91993205eb512576ad56221ea5963f3da078240d55594fb051ea86",
		"513f149ab53e94bb3a0367c61ff87670e025db30c57f84594e4ba4d7b3c656cf",
		"8e3d9ec4e63d5b9f83081fb97b715430c8bfc6f1a1321a89627b9a4e8961c7bd",
		"776de41db0511b8976d69c982dd4757d641487c68d13cbee7069396c20cd3459"};
	const char *ten_G[] = {
		"1e3188d71ed78f5541bc77b3bdc75df1c93d9811e26793bba71a3f30de6ee9be",
		"b0a3030bffb5a431f593a2375865d04c8a83516c0af56c7c63fb17aacb96c44c",
		"8d7e1a49cddc2eccd0b757967e3fb669f66397ee4ba232562ed5a72850606471",
		"1d2a27fd716f0b2ab9c9a40191c5c7ac00c48f554b1e976dc4d25324f29a8531"};
	const char *ks =
		"0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4";
	const char *Ppubs[] = {
		"29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32",
		"9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408",
		"41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D",
		"69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25"};

	point_t G, P;
	BIGNUM *k = BN_new();
	int ok;

	point_init(&G, ctx);
	point_init(&P, ctx);

	point_set_affine_coordinates_bignums(&G,
		SM9_get0_generator2_x0(),
		SM9_get0_generator2_x1(),
		SM9_get0_generator2_y0(),
		SM9_get0_generator2_y1());

	ok = point_equ_hex(&G, _G, ctx);
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");

	ok = point_is_on_curve(&G, p, ctx);
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");

	point_dbl(&P, &G, p, ctx);
	ok = point_equ_hex(&P, dbl_G, ctx);
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");

	point_add(&P, &P, &G, p, ctx);
	ok = point_equ_hex(&P, tri_G, ctx);
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");

	point_sub(&P, &P, &G, p, ctx);
	ok = point_equ_hex(&P, sub_3G_G, ctx);	
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");

	point_neg(&P, &G, p, ctx);
	ok = point_equ_hex(&P, neg_G, ctx);
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");

	BN_set_word(k, 10);
	point_mul(&P, k, &G, p, ctx);
	ok = point_equ_hex(&P, ten_G, ctx);
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");

	BN_hex2bn(&k, ks);
	point_mul_generator(&P, k, p, ctx);
	ok = point_equ_hex(&P, Ppubs, ctx);
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_t x, y;

	fp12_init(x, ctx);
	fp12_init(y, ctx);

	point_get_ext_affine_coordinates(&G, x, y, p, ctx);
	point_set_ext_affine_coordinates(&P, x, y, p, ctx);

	ok = point_equ(&P, &G);
	printf("point test %d: %s\n", __LINE__, ok ? "ok" : "error");
	
	//fp12_cleanup(x);
	//fp12_cleanup(y);
	return 1;	
}

static int eval_tangent(fp12_t r, const point_t *T, const BIGNUM *xP, const BIGNUM *yP,
	const BIGNUM *p, BN_CTX *ctx)
{
	int ret;
	fp12_t x, y, lambda, t;
	fp12_t xT, yT;

	ret = 1;
	ret &= fp12_init(x, ctx);
	ret &= fp12_init(y, ctx);
	ret &= fp12_init(lambda, ctx);
	ret &= fp12_init(t, ctx);
	ret &= fp12_init(xT, ctx);
	ret &= fp12_init(yT, ctx);
	if (!ret) {
		goto end;
	}

	point_get_ext_affine_coordinates(T, xT, yT, p, ctx);
	
	ret = 0;
	if (!fp12_set_bn(x, xP)
		|| !fp12_set_bn(y, yP)
		/* lambda = (3 * xT^2)/(2 * yT) */
		|| !fp12_sqr(lambda, xT, p, ctx)
		|| !fp12_tri(lambda, lambda, p, ctx)
		|| !fp12_dbl(t, yT, p, ctx)
		|| !fp12_inv(t, t, p, ctx)
		|| !fp12_mul(lambda, lambda, t, p, ctx)

		/* r = lambda * (x - xT) - y + yT */
		|| !fp12_sub(r, x, xT, p, ctx)
		|| !fp12_mul(r, lambda, r, p, ctx)
		|| !fp12_sub(r, r, y, p, ctx)
		|| !fp12_add(r, r, yT, p, ctx)) {
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

static int eval_line(fp12_t r,  const point_t *T, const point_t *Q, 
	const BIGNUM *xP, const BIGNUM *yP,
	const BIGNUM *p, BN_CTX *ctx)
{
	int ret;
	fp12_t x, y, lambda, t;
	fp12_t xT, yT, xQ, yQ;
	
	ret = 1;
	ret &= fp12_init(x, ctx);
	ret &= fp12_init(y, ctx);
	ret &= fp12_init(lambda, ctx);
	ret &= fp12_init(t, ctx);
	ret &= fp12_init(xT, ctx);
	ret &= fp12_init(yT, ctx);
	ret &= fp12_init(xQ, ctx);
	ret &= fp12_init(yQ, ctx);
	if (!ret) {
		goto end;
	}

	point_get_ext_affine_coordinates(T, xT, yT, p, ctx);
	point_get_ext_affine_coordinates(Q, xQ, yQ, p, ctx);

	ret = 0;
	if (!fp12_set_bn(x, xP)
		|| !fp12_set_bn(y, yP)
		/* lambda = (yT - yQ)/(xT - xQ) */
		|| !fp12_sub(lambda, yT, yQ, p, ctx)
		|| !fp12_sub(t, xT, xQ, p, ctx)
		|| !fp12_inv(t, t, p, ctx)
		|| !fp12_mul(lambda, lambda, t, p, ctx)

		/* r = lambda * (x - xQ) - y + yQ */
		|| !fp12_sub(r, x, xQ, p, ctx)
		|| !fp12_mul(r, lambda, r, p, ctx)
		|| !fp12_sub(r, r, y, p, ctx)
		|| !fp12_add(r, r, yQ, p, ctx)) {
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

static int frobenius(point_t *R, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	fp12_t x, y;

	fp12_init(x, ctx);
	fp12_init(y, ctx);



	point_get_ext_affine_coordinates(P, x, y, p, ctx);

	fp12_pow(x, x, p, p, ctx);
	fp12_pow(y, y, p, p, ctx);

	point_set_ext_affine_coordinates(R, x, y, p, ctx);

	fp12_cleanup(x);
	fp12_cleanup(y);
	return 1;
}

static int frobenius_twice(point_t *R, const point_t *P, const BIGNUM *p, BN_CTX *ctx)
{
	frobenius(R, P, p, ctx);
	frobenius(R, R, p, ctx);
	return 1;
}


static int final_expo(fp12_t r, const fp12_t a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	int i, n;
	fp12_t t;

	fp12_init(t, ctx);

	if (!fp12_copy(t, a)) {
		return 0;
	}

	n = BN_num_bits(k);
	for (i = n - 2; i >= 0; i--) {
		if (!fp12_sqr(t, t, p, ctx)) {
			return 0;
		}
		if (BN_is_bit_set(k, i)) {
			if (!fp12_mul(t, t, a, p, ctx)) {
				return 0;
			}
		}
	}
	fp12_copy(r, t);
	return 1;
}


static int fast_final_expo(fp12_t r, const fp12_t a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	int i, n;
	fp12_t t;
	fp12_t t0;

	fp12_init(t, ctx);
	fp12_init(t0, ctx);

	if (!fp12_copy(t, a)) {
		return 0;
	}
	if (!fp12_copy(t0, a)) {
		return 0;
	}

	if (!fp12_inv(t0, t, p, ctx)) {
		return 0;
	}
	if (!fp12_fast_expo_p1(t, t, p, ctx)) {
		return 0;
	}
	if (!fp12_mul(t, t0, t, p, ctx)) {
		return 0;
	}

	if (!fp12_copy(t0, t)) {
		return 0;
	}
		
	if(!fp12_fast_expo_p2(t, t, p, ctx)){
		return 0;
	}
	
	if (!fp12_mul(t, t0, t, p, ctx)) {
		return 0;
	}

	if (!fp12_copy(t0, t)) {
		return 0;
	}

	n = BN_num_bits(k);
	for (i = n - 2; i >= 0; i--) {
		if (!fp12_sqr(t, t, p, ctx)) {
			return 0;
		}
		if (BN_is_bit_set(k, i)) {
			if (!fp12_mul(t, t, t0, p, ctx)) {
				return 0;
			}
		}
	}
	fp12_copy(r, t);
	return 1;
}

static int rate(fp12_t f, const point_t *Q, const BIGNUM *xP, const BIGNUM *yP,
	const BIGNUM *a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx)
{
	int ret = 0;
	int i, n;
	point_t T, Q1, Q2;
	fp12_t g;

	memset(&T, 0, sizeof(T));
	memset(&Q1, 0, sizeof(Q1));
	memset(&Q2, 0, sizeof(Q2));
	
	point_init(&T, ctx);
	point_init(&Q1, ctx);
	point_init(&Q2, ctx);
	fp12_init(g, ctx);

	fp12_set_one(f);
	point_copy(&T, Q);

	n = BN_num_bits(a);
	for (i = n - 2; i >= 0; i--) {
		//printf("miller loop %d\n", i);

		/* f = f^2 * g_{T,T}(P) */
		eval_tangent(g, &T, xP, yP, p, ctx);

		//printf("g\n");
		//fp12_print(g);

		fp12_sqr(f, f, p, ctx);
		fp12_mul(f, f, g, p, ctx);

		//printf("f\n");
		//fp12_print(f);

		/* T = 2 * T */
		point_dbl(&T, &T, p, ctx);

		if (BN_is_bit_set(a, i)) {
			/* f = f * g_{T,Q}(P) */
			eval_line(g, &T, Q, xP, yP, p, ctx);

			//printf("g\n");
			//fp12_print(g);


			fp12_mul(f, f, g, p, ctx);

			//printf("f\n");
			//fp12_print(f);

			/* T = T + Q */
			point_add(&T, &T, Q, p, ctx);
		}

	}

	/* Q1 = (x^p, y^p) */
	frobenius(&Q1, Q, p, ctx);

	/* Q2 = (x^(p^2), y^(p^2)) */
	frobenius_twice(&Q2, Q, p, ctx);

	/* f = f * g_{T, Q1}(P) */
	eval_line(g, &T, &Q1, xP, yP, p, ctx);
	fp12_mul(f, f, g, p, ctx);

	/* T = T + Q1 */
	point_add(&T, &T, &Q1, p, ctx);

	/* f = f * g_{T, -Q2}(P) */
	point_neg(&Q2, &Q2, p, ctx);
	eval_line(g, &T, &Q2, xP, yP, p, ctx);
	fp12_mul(f, f, g, p, ctx);

	/* T = T - Q2 */	
	point_add(&T, &T, &Q2, p, ctx);

#ifdef NOSM9_FAST
	/* f = f^((p^12 - 1)/n) */
	final_expo(f, f, k, p, ctx);
#else
	/* f = ((f ^ (p^6-1)) ^ (p^2+1)) ^ [(p^4-p^2+1)/n] */
	fast_final_expo(f, f, k, p, ctx);
#endif

	point_cleanup(&T);
	point_cleanup(&Q1);
	point_cleanup(&Q2);
	fp12_cleanup(g);
	return ret;
}

static int params_test(void)
{
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *a = SM9_get0_loop_count();
	const BIGNUM *k = SM9_get0_final_exponent();

	printf("p = %s\n", BN_bn2dec(p));
	printf("a = %s\n", BN_bn2dec(a));
	printf("k = %s\n", BN_bn2dec(k));

	return 1;
}

int rate_pairing(fp12_t r, const point_t *Q, const EC_POINT *P, BN_CTX *ctx)
{
	int ret = 1;
	const EC_GROUP *group;
	const BIGNUM *p;
	const BIGNUM *a;
	const BIGNUM *k;
	BIGNUM *xP = NULL;
	BIGNUM *yP = NULL;

	group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
	p = SM9_get0_prime();
	a = SM9_get0_loop_count();
#ifdef NOSM9_FAST
	k = SM9_get0_final_exponent();
#else
	k = SM9_get0_fast_final_exponent_p3();
#endif
	xP = BN_CTX_get(ctx);
	yP = BN_CTX_get(ctx);

	if (!P) {
		EC_POINT_get_affine_coordinates_GFp(group,
			EC_GROUP_get0_generator(group), xP, yP, ctx);
	} else {
		EC_POINT_get_affine_coordinates_GFp(group, P, xP, yP, ctx);
	}

	if (!Q) {
		point_t P2;
		point_init(&P2, ctx);
		point_set_affine_coordinates_bignums(&P2,
			SM9_get0_generator2_x0(),
			SM9_get0_generator2_x1(),
			SM9_get0_generator2_y0(),
			SM9_get0_generator2_y1());

		rate(r, &P2, xP, yP, a, k, p, ctx);

		point_cleanup(&P2);
	} else {
		rate(r, Q, xP, yP, a, k, p, ctx);
	}

	BN_free(xP);
	BN_free(yP);
	return ret;
}

static int rate_test(void)
{
	const char *Ppubs_str[] = {
		"29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32",
		"9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408",
		"41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D",
		"69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25"};
	const char *g_str[] = {
		"AAB9F06A4EEBA4323A7833DB202E4E35639D93FA3305AF73F0F071D7D284FCFB",
		"84B87422330D7936EABA1109FA5A7A7181EE16F2438B0AEB2F38FD5F7554E57A",
		"4C744E69C4A2E1C8ED72F796D151A17CE2325B943260FC460B9F73CB57C9014B",
		"B3129A75D31D17194675A1BC56947920898FBF390A5BF5D931CE6CBB3340F66D",
		"93634F44FA13AF76169F3CC8FBEA880ADAFF8475D5FD28A75DEB83C44362B439",
		"1604A3FCFA9783E667CE9FCB1062C2A5C6685C316DDA62DE0548BAA6BA30038B",
		"5A1AE172102EFD95DF7338DBC577C66D8D6C15E0A0158C7507228EFB078F42A6",
		"67E0E0C2EED7A6993DCE28FE9AA2EF56834307860839677F96685F2B44D0911F",
		"A01F2C8BEE81769609462C69C96AA923FD863E209D3CE26DD889B55E2E3873DB",
		"38BFFE40A22D529A0C66124B2C308DAC9229912656F62B4FACFCED408E02380F",
		"28B3404A61908F5D6198815C99AF1990C8AF38655930058C28C21BB539CE0000",
		"4E378FB5561CD0668F906B731AC58FEE25738EDF09CADC7A29C0ABC0177AEA6D"};

	BN_CTX *ctx = NULL;
	EC_GROUP *group = NULL;
	const EC_POINT *P1;
	point_t Ppubs;
	fp12_t g;
	int ok;

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
	P1 = EC_GROUP_get0_generator(group);

	point_init(&Ppubs, ctx);
	point_set_affine_coordinates_hex(&Ppubs, Ppubs_str);

	fp12_init(g, ctx);
	rate_pairing(g, &Ppubs, P1, ctx); 

	ok = fp12_equ_hex(g, g_str, ctx);
	printf("rate %d: %s\n", __LINE__, ok ? "ok" : "error");

	fp12_cleanup(g);
	point_cleanup(&Ppubs);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);

	return 1;
}

/* for SM9 sign, the (xP, yP) is the fixed generator of E(Fp)
 */
int SM9_rate_pairing(BIGNUM *r[12], const BIGNUM *xQ[2], const BIGNUM *yQ[2],
	const BIGNUM *xP, const BIGNUM *yP, BN_CTX *ctx)
{
	return 0;
}
