/* ====================================================================
 * Copyright (c) 2016 - 2019 The GmSSL Project.  All rights reserved.
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
#include <openssl/err.h>
#include <openssl/ecahe.h>

struct ECAHE_CIPHERTEXT_st {
	EC_POINT *A;
	EC_POINT *B;
};

ASN1_SEQUENCE(ECAHE_CIPHERTEXT) = {
	ASN1_SIMPLE(ECAHE_CIPHERTEXT, A, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ECAHE_CIPHERTEXT, B, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(ECAHE_CIPHERTEXT)
IMPLEMENT_ASN1_FUNCTIONS(ECAHE_CIPHERTEXT)
IMPLEMENT_ASN1_DUP_FUNCTION(ECAHE_CIPHERTEXT)


#define EC_MAX_PLAINTEXT	(65536)


int ECAHE_ciphertext_size(EC_KEY *pk)
{
	ECerr(EC_F_ECAHE_CIPHERTEXT_SIZE, ERR_R_EC_LIB);
	return 0;
}

int ECAHE_encrypt(unsigned char *out, size_t *outlen, const BIGNUM *in, EC_KEY *pk)
{
	ECerr(EC_F_ECAHE_ENCRYPT, ERR_R_EC_LIB);
	return 0;
}

int ECAHE_decrypt(unsigned long *out, const unsigned char *in, size_t inlen, EC_KEY *sk)
{
	ECerr(EC_F_ECAHE_DECRYPT, ERR_R_EC_LIB);
	return 0;
}

int ECAHE_do_encrypt(ECAHE_CIPHERTEXT *c, const BIGNUM *m, EC_KEY *pk)
{
	int ret = -1;
	const EC_GROUP *group;
	const EC_POINT *point;
	BIGNUM *order = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *r = NULL;

	OPENSSL_assert(c);
	OPENSSL_assert(m);
	OPENSSL_assert(pk);

	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(order = BN_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EC_GROUP_get_order(group, order, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(r = BN_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	do {
		if (!BN_rand_range(r, order)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

	} while (BN_is_zero(r));

	if (c->A == NULL) {
		if (!(c->A = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
	}

	/* c->A = [r]G */
	if (!EC_POINT_mul(group, c->A, r, NULL, NULL, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (c->B == NULL) {
		if (!(c->B = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
	}

	if (!(point = EC_KEY_get0_public_key(pk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	{
		//EC_POINT *T = EC_POINT_new(group);
		//EC_POINT_mul(group, T, m, NULL, NULL, ctx);
		//printf("[m]G = %s\n", EC_POINT_point2hex(group, T, EC_PUBKEY_FORMAT, ctx));
	}

	/* c->b = [m]G + [r]P */
	if (!EC_POINT_mul(group, c->B, m, point, r, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	ret = 0;

end:
	if (r) BN_free(r);
	if (order) BN_free(order);
	if (ctx) BN_CTX_free(ctx);

	return ret;
}

/* A == [r]G
 * B == [m]G + [r]P == [m]G + [rd]G
 * B - [d]A == B - [rd]G == [m]G
 */
int ECAHE_do_decrypt(BIGNUM *m, const ECAHE_CIPHERTEXT *c, EC_KEY *sk)
{
	int ret = -1;

	const EC_GROUP *group;
	const EC_POINT *G;
	const BIGNUM *d;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	EC_POINT *point = NULL;
	EC_POINT *point2 = NULL;
	unsigned int i;

	OPENSSL_assert(m);
	OPENSSL_assert(c && c->A && c->B);
	OPENSSL_assert(sk);

	if (!(group = EC_KEY_get0_group(sk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(G = EC_GROUP_get0_generator(group))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(d = EC_KEY_get0_private_key(sk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(order = BN_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EC_GROUP_get_order(group, order, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(point = EC_POINT_new(group))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!BN_one(order)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* point = [d]A = [rd]G */
	if (!EC_POINT_mul(group, point, NULL, c->A, d, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* point = -[rd]G */
	if (!EC_POINT_invert(group, point, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* point = B - [rd]G = [m]G + [rd]G - [rd]G = [m]G */
	if (!EC_POINT_add(group, point, point, c->B, ctx)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	{
		//printf("[m]G = %s\n", EC_POINT_point2hex(group, point, EC_PUBKEY_FORMAT, ctx));
	}

	if (!(point2 = EC_POINT_new(group))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EC_POINT_set_to_infinity(group, point2)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	for (i = 0; i < EC_MAX_PLAINTEXT; i++) {

		//printf("%03d ", i);
		//printf("     %s\n", EC_POINT_point2hex(group, point, EC_PUBKEY_FORMAT, ctx));
		//printf("     %s\n", EC_POINT_point2hex(group, point2, EC_PUBKEY_FORMAT, ctx));

		if (EC_POINT_cmp(group, point, point2, ctx) == 0) {
			if (!BN_set_word(m, i)) {
				ERR_print_errors_fp(stderr);
				goto end;
			}

			//printf("SUCCESS: %d\n", i+1);
			ret = 0;
			goto end;
		}

		EC_POINT_add(group, point2, point2, EC_GROUP_get0_generator(group), ctx);
	}


end:
	if (ctx) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (point) EC_POINT_free(point);
	if (point2) EC_POINT_free(point2);

	return ret;
}

int ECAHE_ciphertext_add(ECAHE_CIPHERTEXT *r,
	const ECAHE_CIPHERTEXT *a, const ECAHE_CIPHERTEXT *b,
	EC_KEY *pk)
{
	const EC_GROUP *group = EC_KEY_get0_group(pk);
	BN_CTX *ctx = NULL;

	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	OPENSSL_assert(a->A);
	OPENSSL_assert(b->A);
	OPENSSL_assert(a->B);
	OPENSSL_assert(b->B);

	if (r->A == NULL) {
		if (!(r->A = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}

	if (r->B == NULL) {
		if (!(r->B = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}


	if (!EC_POINT_add(group, r->A, a->A, b->A, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}


	if (!EC_POINT_add(group, r->B, a->B, b->B, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);

	return 0;
}

int ECAHE_ciphertext_sub(ECAHE_CIPHERTEXT *r,
	const ECAHE_CIPHERTEXT *a, const ECAHE_CIPHERTEXT *b,
	EC_KEY *pk)
{
	const EC_GROUP *group = EC_KEY_get0_group(pk);
	BN_CTX *ctx = NULL;

	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	OPENSSL_assert(a->A);
	OPENSSL_assert(b->A);
	OPENSSL_assert(a->B);
	OPENSSL_assert(b->B);

	if (ECAHE_ciphertext_neg(r, b, pk) < 0) {
		fprintf(stderr, "%s (%s %d): ec_ciphertext_neg failed\n",
		__FUNCTION__, __FILE__, __LINE__);
		return -1;
	}


	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}


	if (!EC_POINT_add(group, r->A, r->A, a->A, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	if (!EC_POINT_add(group, r->B, r->B, a->B, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);

	return 0;
}

int ECAHE_ciphertext_neg(ECAHE_CIPHERTEXT *r, const ECAHE_CIPHERTEXT *a,
	EC_KEY *pk)
{
	const EC_GROUP *group;
	BN_CTX *ctx = NULL;

	OPENSSL_assert(r && a && pk);
	OPENSSL_assert(a->A);
	OPENSSL_assert(a->B);


	if (!(group = EC_KEY_get0_group(pk))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}


	if (r->A)
		EC_POINT_free(r->A);
	if (!(r->A = EC_POINT_dup(a->A, group))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (r->B)
		EC_POINT_free(r->B);
	if (!(r->B = EC_POINT_dup(a->B, group))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (!EC_POINT_invert(group, r->A, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}
	if (!EC_POINT_invert(group, r->B, ctx)) {
		ERR_print_errors_fp(stderr);
		BN_CTX_free(ctx);
		return -1;
	}

	BN_CTX_free(ctx);

	return 0;
}
