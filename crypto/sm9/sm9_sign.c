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

#include <string.h>
#include <openssl/err.h>
#include <openssl/sm9.h>
#include <openssl/ec.h>
#include <openssl/ec_type1.h>
#include <openssl/bn_gfp2.h>
#include "sm9_lcl.h"

int SM9_signature_size(SM9PublicParameters *mpk)
{
	return 0;
}

static SM9Signature *SM9_do_sign_type1curve(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen, SM9PrivateKey *sk)
{
	int e = 1;
	SM9Signature *ret = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BN_GFP2 *w = NULL;
	unsigned char *buf = NULL;
	BIGNUM *r;
	BIGNUM *l;
	const EVP_MD *md;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	size_t size;

	if (!mpk || !dgst || dgstlen <= 0 || !sk) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (dgstlen > EVP_MAX_MD_SIZE) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE,
			SM9_R_INVALID_DIGEST);
		return NULL;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve_ex(mpk->p,
		mpk->a, mpk->b, mpk->pointP1->data, mpk->pointP1->length,
		mpk->order, mpk->cofactor, bn_ctx))) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* malloc */
	ret = SM9Signature_new();
	point = EC_POINT_new(group);
	r = BN_CTX_get(bn_ctx);
	l = BN_CTX_get(bn_ctx);

	if (!ret || !point || !r || !l) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* md = mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, SM9_R_INVALID_MD);
		goto end;
	}

	do {
		/* rand r in [1, mpk->order - 1] */
		do {
			if (!BN_rand_range(r, mpk->order)) {
				SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_BN_LIB);
				goto end;
			}
		} while (BN_is_zero(r));

		/* get w = mpk->g = e(mpk->pointP1, mpk->pointPpub) */
		if (!BN_bn2gfp2(mpk->g1, w, mpk->p, bn_ctx)) {
			SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_BN_LIB);
			goto end;
		}

		/* w = w^r = (mpk->g)^r in F_p^2 */
		if (!BN_GFP2_exp(w, w, r, mpk->p, bn_ctx)) {
			SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_BN_LIB);
			goto end;
		}

		/* prepare w buf and canonical(w, order=0) */
		if (!BN_GFP2_canonical(w, NULL, &size, 0, mpk->p, bn_ctx)) {
			SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_BN_LIB);
			goto end;
		}
		if (!(buf = OPENSSL_malloc(size))) {
			SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!BN_GFP2_canonical(w, buf, &size, 0, mpk->p, bn_ctx)) {
			SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_BN_LIB);
			goto end;
		}

		/* ret->h = H2(H(m)||w) in range defined by mpk->order */
		if (!SM9_hash2(md, &ret->h, dgst, dgstlen, buf, size, mpk->order, bn_ctx)) {
			SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_SM9_LIB);
			goto end;
		}

		/* l = (r - ret->h) (mod mpk->order) */
		if (!BN_mod_sub(l, r, ret->h, mpk->order, bn_ctx)) {
			SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_BN_LIB);
			goto end;
		}

		/* if l == 0, re-generate r */
	} while (BN_is_zero(l));

	/* point = sk->prointPoint */
	if (!EC_POINT_oct2point(group, point,
		sk->privatePoint->data, sk->privatePoint->length, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}

	/* sig->pointS = sk->privatePoint * l */
	if (!EC_POINT_mul(group, point, NULL, point, l, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!(size = EC_POINT_point2oct(group, point, point_form,
		NULL, 0, bn_ctx))) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(ret->pointS, NULL, size)) {
		SM9err(SM9_F_SM9_DO_SIGN_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_point2oct(group, point, point_form,
		ret->pointS->data, ret->pointS->length, bn_ctx)) {
		goto end;
	}

	e = 0;

end:
	if (e && ret) {
		SM9Signature_free(ret);
		ret = NULL;
	}
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	BN_GFP2_free(w);
	OPENSSL_free(buf);
	return NULL;
}

SM9Signature *SM9_do_sign(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	SM9PrivateKey *sk)
{
	if (!mpk || !dgst || dgstlen <= 0 || !sk) {
		SM9err(SM9_F_SM9_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (OBJ_obj2nid(mpk->curve) == NID_type1curve) {
		return SM9_do_sign_type1curve(mpk, dgst, dgstlen, sk);
	}

	SM9err(SM9_F_SM9_DO_SIGN, SM9_R_INVALID_CURVE);
	return NULL;
}

int SM9_do_verify_type1curve_ex(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const SM9Signature *sig, SM9PublicKey *pk)
{
	return -1;
}

int SM9_do_verify_type1curve(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const SM9Signature *sig, const char *id, size_t idlen)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *pointS = NULL;
	EC_POINT *Ppub = NULL;
	BN_GFP2 *t = NULL;
	BN_GFP2 *u = NULL;
	BN_GFP2 *w = NULL;
	unsigned char *buf = NULL;
	BIGNUM *h1;
	BIGNUM *h2;
	size_t size;
	const EVP_MD *md;

	if (!mpk || !dgst || dgstlen <= 0 || !sig || !id || idlen <= 0) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (dgstlen > EVP_MAX_MD_SIZE) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_INVALID_DIGEST);
		return 0;
	}
	if (idlen > SM9_MAX_ID_LENGTH) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_INVALID_ID);
		return 0;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve_ex(mpk->p,
		mpk->a, mpk->b, mpk->pointP1->data, mpk->pointP1->length,
		mpk->order, mpk->cofactor, bn_ctx))) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* malloc */
	point = EC_POINT_new(group);
	pointS = EC_POINT_new(group);
	Ppub = EC_POINT_new(group);
	t = BN_GFP2_new();
	u = BN_GFP2_new();
	w = BN_GFP2_new();
	h1 = BN_CTX_get(bn_ctx);
	h2 = BN_CTX_get(bn_ctx);

	if (!point || !pointS || !Ppub || !t || !u || !w || !h1 || !h2) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* md = mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_INVALID_MD);
		goto end;
	}

	/* check sig->h in [1, mpk->order - 1] */
	//FIXME: do we need to check sig->h > 0 ?
	if (BN_is_zero(sig->h) || BN_cmp(sig->h, mpk->order) >= 0) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_INVALID_SIGNATURE);
		goto end;
	}

	/* pointS = sig->pointS */
	if (!EC_POINT_oct2point(group, pointS,
		sig->pointS->data, sig->pointS->length, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_INVALID_SIGNATURE);
		goto end;
	}

	/* decode t from mpk->g in F_p^2 */
	if (!BN_bn2gfp2(mpk->g1, t, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}

	/* t = t^(sig->h) = (mpk->g)^(sig->h) in F_p^2 */
	if (!BN_GFP2_exp(t, t, sig->h, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}

	/* h1 = H1(ID||hid) to range [0, mpk->order) */
	if (!SM9_hash1(md, &h1, id, idlen, SM9_HID_SIGN, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_SM9_LIB);
		goto end;
	}

	/* point = mpk->pointP2 * h1 + mpk->pointPpub */
	if (!EC_POINT_mul(group, point, h1, NULL, NULL, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_oct2point(group, Ppub,
		mpk->pointPpub->data, mpk->pointPpub->length, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}
	if (!EC_POINT_add(group, point, point, Ppub, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}

	/* u = e(sig->pointS, point) in F_p^2 */
	if (!EC_type1curve_tate(group, u, pointS, point, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_COMPUTE_PAIRING_FAILURE);
		goto end;
	}

	/* w = u * t in F_p^2 */
	if (!BN_GFP2_mul(w, u, t, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}

	/* buf = canonical(w) */
	if (!BN_GFP2_canonical(w, NULL, &size, 0, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}
	if (!(buf = OPENSSL_malloc(size))) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!BN_GFP2_canonical(w, buf, &size, 0, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}

	/* h2 = H2(M||w) in [0, mpk->order - 1] */
	if (!SM9_hash2(md, &h2, dgst, dgstlen, buf, size, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_HASH_FAILURE);
		goto end;
	}

	/* check if h2 == sig->h */
	if (BN_cmp(h2, sig->h) != 0) {
		SM9err(SM9_F_SM9_DO_VERIFY_TYPE1CURVE, SM9_R_INVALID_SIGNATURE);
		goto end;
	}

	//FIXME: return value of sig verify
	ret = 1;
end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	EC_POINT_free(pointS);
	EC_POINT_free(Ppub);
	BN_GFP2_free(t);
	BN_GFP2_free(u);
	BN_GFP2_free(w);
	OPENSSL_free(buf);
	return ret;
}

int SM9_do_verify_ex(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const SM9Signature *sig, SM9PublicKey *pk)
{
	return -1;
}

int SM9_do_verify(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const SM9Signature *sig, const char *id, size_t idlen)
{
	if (!mpk || !dgst || dgstlen <= 0 || !sig || !id || idlen <= 0) {
		SM9err(SM9_F_SM9_DO_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (OBJ_obj2nid(mpk->curve) == NID_type1curve) {
		return SM9_do_verify_type1curve(mpk, dgst, dgstlen, sig, id, idlen);
	}

	SM9err(SM9_F_SM9_DO_VERIFY, SM9_R_INVALID_CURVE);
	return 0;
}

int SM9PublicParmeters_get_signature_size(void *a, void *b)
{
	return 0;
}

int SM9_sign(SM9PublicParameters *mpk, const unsigned char *dgst,
	size_t dgstlen, unsigned char *sig, size_t *siglen,
	SM9PrivateKey *sk)
{
	int ret = 0;
	SM9Signature *sigobj = NULL;
	unsigned char *p;
	size_t sigsiz;

	if (!mpk || !dgst || !siglen || !sk) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (dgstlen <= 0 || dgstlen > EVP_MAX_MD_SIZE) {
		SM9err(SM9_F_SM9_SIGN, SM9_R_INVALID_DIGEST_LENGTH);
		return 0;
	}

	/* compute output signature size */
	if (!SM9PublicParmeters_get_signature_size(mpk, &sigsiz)) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_SM9_LIB);
		return 0;
	}

	if (!sig) {
		*siglen = sigsiz;
		return 1;
	}
	if (*siglen < sigsiz) {
		SM9err(SM9_F_SM9_SIGN, SM9_R_BUFFER_TOO_SMALL);
		return 0;
	}

	/* do_sign */
	if (!(sigobj = SM9_do_sign(mpk, dgst, dgstlen, sk))) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_SM9_LIB);
		return 0;
	}

	p = sig;
	if (i2d_SM9Signature(sigobj, &p) < 0) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_SM9_LIB);
		goto end;
	}

	*siglen = p - sig;
	ret = 1;

end:
	SM9Signature_free(sigobj);
	return ret;
}

int SM9_verify_ex(SM9PublicParameters *mpk, const unsigned char *dgst,
	size_t dgstlen, const unsigned char *sig, size_t siglen,
	SM9PublicKey *pk)
{
	return -1;
}

int SM9_verify(SM9PublicParameters *mpk, const unsigned char *dgst,
	size_t dgstlen, const unsigned char *sig, size_t siglen,
	const char *id, size_t idlen)
{
	int ret = -1;
	SM9Signature *sigobj = NULL;
	const unsigned char *p;

	if (!mpk || !dgst || !sig || !id) {
		SM9err(SM9_F_SM9_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (dgstlen <= 0 || dgstlen > EVP_MAX_MD_SIZE) {
		SM9err(SM9_F_SM9_VERIFY, SM9_R_INVALID_DIGEST_LENGTH);
		return 0;
	}
	if (idlen <= 0 || idlen > SM9_MAX_ID_LENGTH || strlen(id) != idlen) {
		SM9err(SM9_F_SM9_VERIFY, SM9_R_INVALID_ID_LENGTH);
		return 0;
	}

	p = sig;
	if (!(sigobj = d2i_SM9Signature(NULL, &p, siglen))) {
		SM9err(SM9_F_SM9_VERIFY, ERR_R_SM9_LIB);
		goto end;
	}

	ret = SM9_do_verify(mpk, dgst, dgstlen, sigobj, id, idlen);


end:
	SM9Signature_free(sigobj);
	return ret;
}
