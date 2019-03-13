/*
 * Copyright (c) 2015 - 2019 The GmSSL Project.  All rights reserved.
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

#include <openssl/err.h>
#include <openssl/ecrs.h>
#include "./ecrs_lcl.h"


ECRS_SIG *ECRS_do_sign(const EVP_MD *md, const unsigned char *dgst,
	int dgstlen, STACK_OF(EC_KEY) *pub_keys, EC_KEY *ec_key)
{
	ECRS_SIG *ret = NULL;
	ECRS_SIG *sig = NULL;
	const EC_GROUP *group;
	const BIGNUM *order;
	BIGNUM *ck = NULL; /* ref of STACK_OF(BIGNUM) elements, dont free */
	BIGNUM *a = NULL;
	BIGNUM *c = NULL;
	BIGNUM *z = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *R = NULL;
	EC_POINT *T = NULL;
	EVP_MD_CTX *mctx = NULL;
	int form = POINT_CONVERSION_UNCOMPRESSED;
	unsigned char buf[512];
	unsigned char *p = buf;
	unsigned int ulen;
	size_t siz;
	int len, i;

	group = EC_KEY_get0_group(ec_key);
	order = EC_GROUP_get0_order(group);

	if (!(sig = ECRS_SIG_new())
		|| !(sig->s = BN_new())
		|| !(sig->c = sk_BIGNUM_new(NULL))
		|| !(a = BN_new())
		|| !(c = BN_new())
		|| !(z = BN_new())
		|| !(bn_ctx = BN_CTX_new())
		|| !(R = EC_POINT_new(group))
		|| !(T = EC_POINT_new(group))
		|| !(mctx = EVP_MD_CTX_new())) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* hash update ECParameters */
	if (!(len = i2d_ECPKParameters(group, &p))) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_EC_LIB);
		goto end;
	}
	if (!EVP_DigestInit_ex(mctx, md, NULL)
		|| !EVP_DigestUpdate(mctx, buf, len)) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_EVP_LIB);
		goto end;
	}

	/* a = rand(1, order) */
	do {
		if (!BN_rand_range(a, order)) {
			ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(a));

	/* R = [a]G */
	if (!EC_POINT_mul(group, R, a, NULL, NULL, bn_ctx)) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_EC_LIB);
		goto end;
	}

	for (i = 0; i < sk_EC_KEY_num(pub_keys); i++) {
		const EC_KEY *pub_key = sk_EC_KEY_value(pub_keys, i);
		const EC_POINT *Pi = EC_KEY_get0_public_key(pub_key);
		BIGNUM *ci;

		/* check P_i */
		if (EC_GROUP_cmp(EC_KEY_get0_group(pub_key), group, bn_ctx) != 0) {
			ECRSerr(ECRS_F_ECRS_DO_SIGN, ECRS_R_EC_KEY_NOT_MATCH);
			goto end;
		}

		/* hash update P_i = (x_i, y_i) */
		if (!(siz = EC_POINT_point2oct(group, Pi, form, buf,
			sizeof(buf), bn_ctx))) {
			ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_EC_LIB);
			goto end;
		}
		if (!EVP_DigestUpdate(mctx, buf + 1, siz - 1)) {
			ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_EVP_LIB);
			goto end;
		}

		/* create c_i */
		if (!(ci = BN_new())) {
			ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		sk_BIGNUM_push(sig->c, ci);

		/* find signer's public key */
		if (EC_POINT_cmp(group, Pi, EC_KEY_get0_public_key(ec_key),
			bn_ctx) == 0) {
			if (ck) {
				ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_ECRS_LIB);
				goto end;
			}
			ck = ci;
			continue;
		}

		/* c_i = rand(1, order) */
		do {
			if (!BN_rand_range(ci, order)) {
				ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_BN_LIB);
				goto end;
			}
		} while (BN_is_zero(ci));

		/* R = R + [c_i]P_i */
		if (!EC_POINT_mul(group, T, NULL, Pi, ci, bn_ctx)
			|| !EC_POINT_add(group, R, R, T, bn_ctx)) {
			ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_EC_LIB);
			goto end;
		}

		/* z = z + c_i */
		if (!BN_mod_add(z, z, ci, order, bn_ctx)) {
			ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
	}
	/* no signing private key found */
	if (!ck) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ECRS_R_NO_SIGNING_KEY);
		goto end;
	}

	/* hash update dgst and R */
	if (!(siz = EC_POINT_point2oct(group, R, form, buf, sizeof(buf),
		bn_ctx))) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_EC_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(mctx, dgst, dgstlen)
		|| !EVP_DigestUpdate(mctx, buf + 1, siz - 1)
		|| !EVP_DigestFinal_ex(mctx, buf, &ulen)) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_EVP_LIB);
		goto end;
	}

	/* c = hash({Pi}, Hash(m), R) mod #G */
	if (!BN_bin2bn(buf, ulen, c)) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}

	/* c_k = c - (c_0 + ... + c_{k-1} + c_{k+1} + ... + c_{n-1}) mod #G */
	if (!BN_mod_sub(ck, c, z, order, bn_ctx)) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}

	/* sig->s = a - c_k * x_k mod #G */
	if (!BN_mod_mul(sig->s, ck, EC_KEY_get0_private_key(ec_key), order, bn_ctx)
		|| !BN_mod_sub(sig->s, a, sig->s, order, bn_ctx)) {
		ECRSerr(ECRS_F_ECRS_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}

	ret = sig;
	sig = NULL;

end:
	ECRS_SIG_free(sig);
	BN_free(a);
	BN_free(c);
	BN_CTX_free(bn_ctx);
	EC_POINT_free(R);
	EC_POINT_free(T);
	EVP_MD_CTX_free(mctx);
	return ret;
}

/*
 * Verify(m, sig=(s, c_0, ..., c_{n-1}, {P_i}):
 *	R = [s]G + [c_0]P_0 + ... + [c_{n-1}]P_{n-1}
 *	c = c_0 + ... + c_{n-1}
 *	h = Hash({P_i}, Hash(m), R)
 * return c =?= h
 */
int ECRS_do_verify(const EVP_MD *md, const unsigned char *dgst, int dgstlen,
	const ECRS_SIG *sig, STACK_OF(EC_KEY) *pub_keys)
{
	int ret = -1;
	const EC_GROUP *group = NULL;
	const BIGNUM *order = NULL;
	BIGNUM *c = NULL;
	BIGNUM *h = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *R = NULL;
	EC_POINT *T = NULL;
	EVP_MD_CTX *mctx = NULL;
	int form = POINT_CONVERSION_UNCOMPRESSED;
	unsigned char buf[512];
	unsigned char *p = buf;
	unsigned int ulen;
	size_t siz;
	int len, i;

	if (sk_BIGNUM_num(sig->c) != sk_EC_KEY_num(pub_keys)) {
		ECRSerr(ECRS_F_ECRS_DO_VERIFY, ECRS_R_PUBLIC_KEYS_NOT_MATCH_SIG);
		return -1;
	}

	group = EC_KEY_get0_group(sk_EC_KEY_value(pub_keys, 0));
	order = EC_GROUP_get0_order(group);

	if (!(c = BN_new())
		|| !(h = BN_new())
		|| !(bn_ctx = BN_CTX_new())
		|| !(R = EC_POINT_new(group))
		|| !(T = EC_POINT_new(group))
		|| !(mctx = EVP_MD_CTX_new())) {
		ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* hash update ECParameters */

	/* hash update ECParameters */
	if (!(len = i2d_ECPKParameters(group, &p))) {
		ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_EC_LIB);
		goto end;
	}
	if (!EVP_DigestInit_ex(mctx, md, NULL)
		|| !EVP_DigestUpdate(mctx, buf, len)) {
		ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_EVP_LIB);
		goto end;
	}

	/* R = [s]G */
	if (!EC_POINT_mul(group, R, sig->s, NULL, NULL, bn_ctx)) {
		ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_EC_LIB);
		goto end;
	}

	for (i = 0; i < sk_BIGNUM_num(sig->c); i++) {
		EC_KEY *ec_key = sk_EC_KEY_value(pub_keys, i);
		const EC_POINT *Pi = EC_KEY_get0_public_key(ec_key);
		BIGNUM *ci = sk_BIGNUM_value(sig->c, i);

		/* check Pi */
		if (EC_GROUP_cmp(EC_KEY_get0_group(ec_key), group, bn_ctx) != 0) {
			ECRSerr(ECRS_F_ECRS_DO_VERIFY, ECRS_R_PUBLIC_KEYS_NOT_MATCH);
			goto end;
		}

		/* hash update P_i = (x_i, y_i) */
		if (!(siz = EC_POINT_point2oct(group, Pi, form, buf,
			sizeof(buf), bn_ctx))) {
			ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_EC_LIB);
			goto end;
		}
		if (!EVP_DigestUpdate(mctx, buf + 1, siz - 1)) {
			ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_EVP_LIB);
			goto end;
		}

		/* R = R + [c_i]P_i */
		if (!EC_POINT_mul(group, T, NULL, Pi, ci, bn_ctx)
			|| !EC_POINT_add(group, R, R, T, bn_ctx)) {
			ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_EC_LIB);
			goto end;
		}

		/* c = c + c_i mod #G */
		if (!BN_mod_add(c, c, ci, order, bn_ctx)) {
			ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_BN_LIB);
			goto end;
		}
	}

	/* hash update dgst and R */
	if (!(siz = EC_POINT_point2oct(group, R, form, buf, sizeof(buf),
		bn_ctx))) {
		ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_EC_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(mctx, dgst, dgstlen)
		|| !EVP_DigestUpdate(mctx, buf + 1, siz - 1)
		|| !EVP_DigestFinal_ex(mctx, buf, &ulen)) {
		ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_EVP_LIB);
		goto end;
	}

	/* h = hash({Pi}, Hash(m), R) mod #G */
	if (!BN_bin2bn(buf, ulen, h)) {
		ECRSerr(ECRS_F_ECRS_DO_VERIFY, ERR_R_BN_LIB);
		goto end;
	}

	//FIXME: h mod #G */

	if (BN_cmp(h, c) == 0)
		ret = 1;
	else
		ret = 0;


end:
	BN_free(c);
	BN_free(h);
	BN_CTX_free(bn_ctx);
	EC_POINT_free(R);
	EC_POINT_free(T);
	EVP_MD_CTX_free(mctx);
	return ret;
}

int ECRS_sign(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen, STACK_OF(EC_KEY) *pub_keys,
	EC_KEY *ec_key)
{
	const EVP_MD *md;
	ECRS_SIG *s = NULL;

	if (!(md = EVP_get_digestbynid(type))) {
		ECRSerr(ECRS_F_ECRS_SIGN, ECRS_R_INVALID_DIGEST_ALGOR);
		return 0;
	}
	if (!(s = ECRS_do_sign(md, dgst, dgstlen, pub_keys, ec_key))) {
		ECRSerr(ECRS_F_ECRS_SIGN, ERR_R_ECRS_LIB);
		return 0;
	}

	*siglen = i2d_ECRS_SIG(s, &sig);
	ECRS_SIG_free(s);
	return 1;
}

int ECRS_verify(int type, const unsigned char *dgst, int dgstlen,
	const unsigned char *sig, int siglen, STACK_OF(EC_KEY) *pub_keys)
{
	const EVP_MD *md;
	ECRS_SIG *s = NULL;
	const unsigned char *p = sig;
	int ret = -1;

	if (!(s = d2i_ECRS_SIG(NULL, &p, siglen))) {
		ECRSerr(ECRS_F_ECRS_VERIFY, ECRS_R_PARSE_SIGNATURE_FAILURE);
		return -1;
	}

	if (p != sig + siglen) {
		ECRSerr(ECRS_F_ECRS_VERIFY, ECRS_R_PARSE_SIGNATURE_FAILURE);
		goto end;
	}

	ret = ECRS_do_verify(md, dgst, dgstlen, s, pub_keys);

end:
	ECRS_SIG_free(s);
	return ret;
}
