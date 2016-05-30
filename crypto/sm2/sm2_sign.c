/* crypto/sm2/sm2_sign.c */
/* ====================================================================
 * Copyright (c) 2015 The GmSSL Project.  All rights reserved.
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

#include <openssl/err.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sm2.h>

/* k in [1, n-1], (x, y) = kG */
static int sm2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **xp)
{
	int ret = 0;
	const EC_GROUP *ec_group;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL;
	BIGNUM *x = NULL;
	BIGNUM *order = NULL;
	EC_POINT *point = NULL;

	if (ec_key == NULL || (ec_group = EC_KEY_get0_group(ec_key)) == NULL) {
		SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ctx_in == NULL)  {
		if ((ctx = BN_CTX_new()) == NULL) {
			SM2err(SM2_F_SM2_SIGN_SETUP,ERR_R_MALLOC_FAILURE);
			return 0;
		}
	}
	else {
		ctx = ctx_in;
	}

	k = BN_new();	
	x = BN_new();
	order = BN_new();
	if (!k || !x || !order) {
		SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
		goto err;
	}
	
	if ((point = EC_POINT_new(ec_group)) == NULL) {
		SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
		goto err;
	}

	do {
		/* get random k */	
		do {
			if (!BN_rand_range(k, order)) {
				SM2err(SM2_F_SM2_SIGN_SETUP,
					SM2_R_RANDOM_NUMBER_GENERATION_FAILED);	
				goto err;
			}

		} while (BN_is_zero(k));

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(ec_group, point, k, NULL, NULL, ctx)) {
			SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
			goto err;
		}

		if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
			if (!EC_POINT_get_affine_coordinates_GFp(ec_group, point, x, NULL, ctx)) {
				SM2err(SM2_F_SM2_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		} else /* NID_X9_62_characteristic_two_field */ {
			if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, x, NULL, ctx)) {
				SM2err(SM2_F_SM2_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		}
		
		//FIXME: do we need this?
		if (!BN_nnmod(x, x, order, ctx)) {
			SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_BN_LIB);
			goto err;
		}
	
	} while (BN_is_zero(x));

	/* clear old values if necessary */
	if (*kp != NULL)
		BN_clear_free(*kp);
	if (*xp != NULL)
		BN_clear_free(*xp);

	/* save the pre-computed values  */
	*kp = k;
	*xp = x;
	ret = 1;

err:
	if (!ret) {
		if (k) BN_clear_free(k);
		if (x) BN_clear_free(x);
	}
	if (ctx_in == NULL) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (point) EC_POINT_free(point);

	return(ret);
}

static ECDSA_SIG *sm2_do_sign(const unsigned char *dgst, int dgst_len,
	const BIGNUM *in_k, const BIGNUM *in_x, EC_KEY *ec_key)
{
	int ok = 0;
	ECDSA_SIG *ret = NULL;
	const EC_GROUP *ec_group;
	const BIGNUM *priv_key;
	const BIGNUM *ck;
	BIGNUM *k = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	BIGNUM *e = NULL;
	BIGNUM *bn = NULL;
	int i;

	ec_group = EC_KEY_get0_group(ec_key);
	priv_key = EC_KEY_get0_private_key(ec_key);
	if (!ec_group || !priv_key) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!(ret = ECDSA_SIG_new())) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_MALLOC_FAILURE);
		return NULL;
	}	
	
	ctx = BN_CTX_new();
	order = BN_new();
	e = BN_new();
	bn = BN_new();
	if (!ctx || !order || !e || !bn) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_EC_LIB);
		goto err;
	}

	/* convert dgst to e */
	i = BN_num_bits(order);
#if 0
	if (8 * dgst_len > i) {
		dgst_len = (i + 7)/8;
	}
#endif
	if (!BN_bin2bn(dgst, dgst_len, e)) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}

#if 0
	if ((8 * dgst_len > i) && !BN_rshift(e, e, 8 - (i & 0x7))) {
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}
#endif

	do {
		/* use or compute k and (kG).x */
		if (!in_k || !in_x) {
			if (!sm2_sign_setup(ec_key, ctx, &k, &ret->r)) {
				SM2err(SM2_F_SM2_DO_SIGN,ERR_R_ECDSA_LIB);
				goto err;
			}
			ck = k;
		} else {
			ck = in_k;
			if (!BN_copy(ret->r, in_x)) {
				SM2err(SM2_F_SM2_DO_SIGN, ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}


		/* r = e + x (mod n) */	
		if (!BN_mod_add(ret->r, ret->r, e, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}


		if (!BN_mod_add(bn, ret->r, ck, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}

		/* check r != 0 && r + k != n */
		if (BN_is_zero(ret->r) || BN_is_zero(bn)) {
			if (in_k && in_x) {
				SM2err(SM2_F_SM2_DO_SIGN, SM2_R_NEED_NEW_SETUP_VALUES);
				goto err;
			} else
				continue;
		}

		/* s = ((1 + d)^-1 * (k - rd)) mod n */
		if (!BN_one(bn)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_add(ret->s, priv_key, bn, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_inverse(ret->s, ret->s, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}

		if (!BN_mod_mul(bn, ret->r, priv_key, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_sub(bn, ck, bn, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_mul(ret->s, ret->s, bn, order, ctx)) {
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}

		/* check s != 0 */
		if (BN_is_zero(ret->s)) {
			if (in_k && in_x) {
				SM2err(SM2_F_SM2_DO_SIGN, SM2_R_NEED_NEW_SETUP_VALUES);
				goto err;
			}
		} else
			break;

	} while (1);

	ok = 1;

err:
	if (!ok) {
		ECDSA_SIG_free(ret);
		ret = NULL;
	}
	if (k) BN_free(k);	
	if (ctx) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (e) BN_free(e);
	if (bn) BN_free(bn);	
	
	return ret;
}

int sm2_do_verify(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
	int ret = SM2_VERIFY_INNER_ERROR;
	const EC_GROUP *ec_group;
	const EC_POINT *pub_key;
	EC_POINT *point = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	BIGNUM *e = NULL;
	BIGNUM *t = NULL;
	int i;

	if (!sig || !ec_key ||
		!(ec_group = EC_KEY_get0_group(ec_key)) ||
		!(pub_key  = EC_KEY_get0_public_key(ec_key))) {

		SM2err(SM2_F_SM2_DO_VERIFY, SM2_R_MISSING_PARAMETERS);
		return -1;
	}

	ctx = BN_CTX_new();
	order = BN_new();
	e = BN_new();
	t = BN_new();

	if (!ctx || !order || !e || !t) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}

	/* check r, s in [1, n-1] and r + s != 0 (mod n) */ 
	if (BN_is_zero(sig->r) ||
		BN_is_negative(sig->r) ||
		BN_ucmp(sig->r, order) >= 0 || 
		BN_is_zero(sig->s) ||
		BN_is_negative(sig->s) || 
		BN_ucmp(sig->s, order) >= 0) {

		SM2err(SM2_F_SM2_DO_VERIFY, SM2_R_BAD_SIGNATURE);
		ret = 0;
		goto err;
	}

	/* check t = r + s != 0 */
	if (!BN_mod_add(t, sig->r, sig->s, order, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	if (BN_is_zero(t)) {
		ret = 0;
		goto err;
	}

	/* convert digest to e */
	i = BN_num_bits(order);
#if 0
	if (8 * dgstlen > i) {
		dgstlen = (i + 7)/8;
	}
#endif
	if (!BN_bin2bn(dgst, dgstlen, e)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
#if 0
	if ((8 * dgstlen > i) && !BN_rshift(e, e, 8 - (i & 0x7))) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
#endif

	/* compute (x, y) = sG + tP, P is pub_key */
	if (!(point = EC_POINT_new(ec_group))) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_POINT_mul(ec_group, point, sig->s, pub_key, t, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(ec_group, point, t, NULL, ctx)) {
			SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	} else /* NID_X9_62_characteristic_two_field */ { 
		if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, t, NULL, ctx)) {
			SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	}
	if (!BN_nnmod(t, t, order, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}

	/* check (sG + tP).x + e  == sig.r */
	if (!BN_mod_add(t, t, e, order, ctx)) {
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	if (BN_ucmp(t, sig->r) == 0) {
		ret = SM2_VERIFY_SUCCESS;
	} else {
		ret = SM2_VERIFY_FAILED;
	}

err:
	if (point) EC_POINT_free(point);
	if (order) BN_free(order);
	if (e) BN_free(e);
	if (t) BN_free(t);
	if (ctx) BN_CTX_free(ctx);
	return ret;
}

int SM2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **xp)
{
	return sm2_sign_setup(ec_key, ctx_in, kp, xp);
}

ECDSA_SIG *SM2_do_sign_ex(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kp, const BIGNUM *xp, EC_KEY *ec_key)
{
	return sm2_do_sign(dgst, dgstlen, kp, xp, ec_key);
}

ECDSA_SIG *SM2_do_sign(const unsigned char *dgst, int dgstlen, EC_KEY *ec_key)
{
	return SM2_do_sign_ex(dgst, dgstlen, NULL, NULL, ec_key);
}

int SM2_do_verify(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
	return sm2_do_verify(dgst, dgstlen, sig, ec_key);
}

int SM2_sign_ex(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key)
{
	ECDSA_SIG *s;

	RAND_seed(dgst, dgstlen);

	if (!(s = SM2_do_sign_ex(dgst, dgstlen, k, x, ec_key))) {
		*siglen = 0;
		return 0;
	}

    	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);

	return 1;
}

int SM2_sign(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen, EC_KEY *ec_key)
{
	return SM2_sign_ex(type, dgst, dgstlen, sig, siglen, NULL, NULL, ec_key);
}

int SM2_verify(int type, const unsigned char *dgst, int dgstlen,
	const unsigned char *sig, int siglen, EC_KEY *ec_key)
{
	ECDSA_SIG *s;
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	int derlen = -1;
	int ret = -1;

	if (!(s = ECDSA_SIG_new())) {
		return ret;
	}
	if (!d2i_ECDSA_SIG(&s, &p, siglen)) {
		goto err;
	}
	derlen = i2d_ECDSA_SIG(s, &der);
	if (derlen != siglen || memcmp(sig, der, derlen)) {
		goto err;
	}

	ret = SM2_do_verify(dgst, dgstlen, s, ec_key);

err:
	if (derlen > 0) {
		OPENSSL_cleanse(der, derlen);
		OPENSSL_free(der);
	}

	ECDSA_SIG_free(s);
	return ret;
}
