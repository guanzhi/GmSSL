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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn_gfp2.h>
#include <openssl/bn_hash.h>
#include <openssl/ec_type1.h>
#include <openssl/bb1ibe.h>
#include "bb1ibe_lcl.h"


int BB1IBE_setup(const EC_GROUP *group, const EVP_MD *md,
	BB1PublicParameters **pmpk, BB1MasterSecret **pmsk)
{
	int ret = 0;
	BB1PublicParameters *mpk = NULL;
	BB1MasterSecret *msk = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *point = NULL;
	EC_POINT *point1 = NULL;
	BN_GFP2 *theta = NULL;
	BIGNUM *a;
	BIGNUM *b;

	if (!group || !pmpk || !pmsk) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	mpk = BB1PublicParameters_new();
	msk = BB1MasterSecret_new();
	point = EC_POINT_new(group);
	point1 = EC_POINT_new(group);
	theta = BN_GFP2_new();
	a = BN_CTX_get(bn_ctx);
	b = BN_CTX_get(bn_ctx);

	if (!mpk || !msk || !a || !b || !point || !point1 || !theta) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/*
	 * set mpk->version
	 * set mpk->curve
	 * set mpk->p
	 * set mpk->q
	 * set mpk->pointP
	 * set mpk->hashfcn
	 */

	mpk->version = BB1IBE_VERSION;

	OPENSSL_assert(mpk->curve);
	ASN1_OBJECT_free(mpk->curve);
	if (!(mpk->curve = OBJ_nid2obj(NID_type1curve))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, BB1IBE_R_NOT_NAMED_CURVE);
		goto end;
	}

	if (!EC_GROUP_get_curve_GFp(group, mpk->p, a, b, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, BB1IBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	if (!EC_GROUP_get_order(group, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, BB1IBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, EC_GROUP_get0_generator(group),
		mpk->pointP->x, mpk->pointP->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, BB1IBE_R_PARSE_PAIRING);
		goto end;
	}

	ASN1_OBJECT_free(mpk->hashfcn);
	if (!(mpk->hashfcn = OBJ_nid2obj(EVP_MD_type(md)))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, BB1IBE_R_PARSE_PAIRING);
		goto end;
	}

	/*
	 * set msk->version
	 * random msk->alpha in [1, q - 1]
	 * random msk->beta  in [1, q - 1]
	 * random msk->gamma in [1, q - 1]
	 */

	msk->version = BB1IBE_VERSION;

	do {
		if (!BN_rand_range(msk->alpha, mpk->q)) {
			BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->alpha));

	do {
		if (!BN_rand_range(msk->beta, mpk->q)) {
			BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->beta));

	do {
		if (!BN_rand_range(msk->gamma, mpk->q)) {
			BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->gamma));

	/*
	 * mpk->pointP1 = msk->alpha * mpk->pointP
	 * mpk->pointP2 = msk->beta  * mpk->pointP
	 */

	if (!EC_POINT_mul(group, point, msk->alpha, NULL, NULL, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		mpk->pointP1->x, mpk->pointP1->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_mul(group, point1, msk->beta, NULL, NULL, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point1,
		mpk->pointP2->x, mpk->pointP2->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	/*
	 * mpk->v = e(mpk->pointP1, mpk->pointP2) in GF(p^2)
	 * convert pairing result from BN_GFP2 to FpPoint
	 */

	if (!EC_type1curve_tate(group, theta, point, point1, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	if (!BN_copy(mpk->v->x, theta->a0)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_copy(mpk->v->y, theta->a1)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_BN_LIB);
		goto end;
	}

	/*
	 * mpk->pointP3 = msk->gamma * mpk->pointP
	 * (careful: re-use tmp variable `point1` for pointP3)
	 */

	if (!EC_POINT_mul(group, point, msk->gamma, NULL, NULL, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		mpk->pointP3->x, mpk->pointP3->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	*pmpk = mpk;
	*pmsk = msk;
	ret = 1;

end:
	if (!ret) {
		BB1PublicParameters_free(mpk);
		BB1MasterSecret_free(msk);
		*pmpk = NULL;
		*pmsk = NULL;
	}
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_POINT_free(point);
	EC_POINT_free(point1);
	BN_GFP2_free(theta);
	return ret;
}

BB1PrivateKeyBlock *BB1IBE_extract_private_key(BB1PublicParameters *mpk,
	BB1MasterSecret *msk, const char *id, size_t idlen)
{
	int e = 1;
	BB1PrivateKeyBlock *ret = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	const EVP_MD *md;
	BIGNUM *r;
	BIGNUM *y;
	BIGNUM *hid;

	if (!mpk || !msk || !id || idlen <= 0) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* get group */
	if (!(group = EC_GROUP_new_type1curve(mpk->p, mpk->pointP->x,
		mpk->pointP->y, mpk->q, bn_ctx))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, BB1IBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	ret = BB1PrivateKeyBlock_new();
	point = EC_POINT_new(group);
	r = BN_CTX_get(bn_ctx);
	y = BN_CTX_get(bn_ctx);
	hid = BN_CTX_get(bn_ctx);

	if (!ret || !point || !r || !y || !hid) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* set ret->version */
	ret->version = BB1IBE_VERSION;

	/* random r in [1, q - 1] */
	do {
		if (!BN_rand_range(r, mpk->q)) {
			BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY,
				ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(r));

	/* md = mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, BB1IBE_R_INVALID_MD);
		goto end;
	}

	/* hid = HashToRange(id), hid in [0, q - 1] */
	if (!BN_hash_to_range(md, &hid, id, idlen, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* y = msk->alpha * msk->beta + r * (msk->alpha * hid + msk->gamma) in F_q
	 *	hid = hid * msk->alpha
	 *	hid = hid + msk->gamma
	 *	hid = hid * r
	 *	y = msk->alpha * msk->beta
	 *	y = y + hid
	 */
	if (!BN_mod_mul(hid, hid, msk->alpha, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_add(hid, hid, msk->gamma, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(hid, hid, r, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(y, msk->alpha, msk->beta, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_add(y, y, hid, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* sk->pointD0 = y * mpk->pointP */
	if (!EC_POINT_mul(group, point, y, NULL, NULL, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->pointD0->x, ret->pointD0->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* sk->pointD1 = r * mpk->pointP */
	if (!EC_POINT_mul(group, point, r, NULL, NULL, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->pointD1->x, ret->pointD1->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	e = 0;

end:
	if (e && ret) {
		BB1PrivateKeyBlock_free(ret);
		ret = NULL;
	}
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_POINT_free(point);
	return ret;
}

/*
 * return H(H(m)||m) || H(m), return length is 2*hashlen
 */
static int BB1IBE_double_hash(const EVP_MD *md, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen)
{
	int ret = 0;
	EVP_MD_CTX *ctx = NULL;
	unsigned int len = EVP_MD_size(md);

	if (!md || !in || inlen <= 0 ||  !outlen) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (in == out) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, BB1IBE_R_INVALID_OUTPUT_BUFFER);
		return 0;
	}

	if (!out) {
		*outlen = EVP_MD_size(md) * 2;
		return 1;
	}
	if (*outlen < EVP_MD_size(md) * 2) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, BB1IBE_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!EVP_Digest(in, inlen, out + EVP_MD_size(md), &len, md, NULL)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EVP_DigestInit_ex(ctx, md, NULL)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(ctx, out + EVP_MD_size(md), EVP_MD_size(md))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(ctx, in, inlen)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}
	len = EVP_MD_size(md);
	if (!EVP_DigestFinal_ex(ctx, out, &len)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}

	*outlen = EVP_MD_size(md) * 2;
	ret = 1;
end:
	EVP_MD_CTX_free(ctx);
	return ret;
}

/*
 * c->u = HashToRange(DoubleHash(c->Chi0, c->Chi1, y, wbuf))
 */
int BB1CiphertextBlock_hash_to_range(BB1PublicParameters *mpk,
	BB1CiphertextBlock *c, const unsigned char *wbuf, size_t wbuflen,
	BIGNUM *bn, BN_CTX *bn_ctx)
{
	int ret = 0;
	unsigned char *buf = NULL;
	unsigned char *p;
	size_t buflen;
	unsigned char double_hash[EVP_MAX_MD_SIZE *2];
	int pbytes;

	const EVP_MD *md;

	if (!c || !wbuf || wbuflen <= 0 || !bn || !mpk || !bn_ctx) {
		BB1IBEerr(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		return 0;
	}


	/* prepare buffer */
	pbytes = BN_num_bytes(mpk->p);
	buflen = pbytes * 4 + c->y->length + wbuflen;

	if (!(buf = OPENSSL_zalloc(buflen))) {
		BB1IBEerr(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	p = buf;

	/* buf += y1 */
	if (!BN_bn2bin(c->pointChi1->y, p + pbytes - BN_num_bytes(c->pointChi1->y))) {
		BB1IBEerr(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}
	p += pbytes;

	/* buf += x1 */
	if (!BN_bn2bin(c->pointChi1->x, p + pbytes - BN_num_bytes(c->pointChi1->x))) {
		BB1IBEerr(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}
	p += pbytes;

	/* buf += y0 */
	if (!BN_bn2bin(c->pointChi0->y, p + pbytes - BN_num_bytes(c->pointChi0->y))) {
		BB1IBEerr(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}
	p += pbytes;

	/* buf += x0 */
	if (!BN_bn2bin(c->pointChi0->x, p + pbytes - BN_num_bytes(c->pointChi0->x))) {
		BB1IBEerr(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}
	p += pbytes;

	/* buf += ret->y */
	memcpy(p, c->y->data, c->y->length);
	p += c->y->length;

	/* buf += wbuf */
	memcpy(p, wbuf, wbuflen);
	p += wbuflen;

	OPENSSL_assert(p - buf == buflen);

	/* ret->u = HashToRange(DoubleHash(c)) */
	if (!BB1IBE_double_hash(md, buf, buflen, double_hash, &buflen)) {
		BB1IBEerr(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE, BB1IBE_R_DOUBLE_HASH_FAILURE);
		goto end;
	}
	if (!BN_hash_to_range(md, &c->nu, double_hash, buflen, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;

end:
	OPENSSL_free(buf);
	return ret;
}

/*
 * random s in [1, q - 1]
 * ret->pointChi0 = mpk->pointP *s
 * ret->pointChi1 = mpk->pointP1 * (s * H(ID)) + mpk->pointP3 * s
 * ret->nu = HashToRange(w || Chi0 || Chi1 || y) in Zq
 * ret->y = s + rho (mod q)
 */
BB1CiphertextBlock *BB1IBE_do_encrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	const char *id, size_t idlen)
{
	int e = 1;
	BB1CiphertextBlock *ret = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *point1 = NULL;
	BN_GFP2 *w = NULL;
	BIGNUM *s;
	BIGNUM *hid;
	unsigned char *wbuf = NULL;
	size_t wbuflen;
	unsigned char *cbuf = NULL;
	const EVP_MD *md;
	int i;

	if (!mpk || !in || inlen <= 0 || !id || idlen <= 0) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		goto end;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* get group */
	if (!(group = EC_GROUP_new_type1curve(mpk->p, mpk->pointP->x,
		mpk->pointP->y, mpk->q, bn_ctx))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, BB1IBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	ret = BB1CiphertextBlock_new();
	point = EC_POINT_new(group);
	point1 = EC_POINT_new(group);
	w = BN_GFP2_new();
	s = BN_CTX_get(bn_ctx);
	hid = BN_CTX_get(bn_ctx);

	if (!ret || !point || !point1 || !s || !hid || !w) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* random s in [1, q - 1] */
	do {
		if (!BN_rand_range(s, mpk->q)) {
			BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(s));

	/* ret->pointChi0 = mpk->pointP * s */
	if (!EC_POINT_mul(group, point, s, NULL, NULL, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->pointChi0->x, ret->pointChi0->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* get md */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, BB1IBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* hid = HashToRange(id) in F_q */
	if (!BN_hash_to_range(md, &hid, id, idlen, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_BN_LIB);
		goto end;
	}

	/*
	 * ret->pointChi1 = ((mpk->pointP1 * hid) + mpk->pointP3) * s
	 */
	if (!EC_POINT_set_affine_coordinates_GFp(group, point,
		mpk->pointP1->x, mpk->pointP1->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_mul(group, point, NULL, point, hid, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(group, point1,
		mpk->pointP3->x, mpk->pointP3->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_add(group, point, point, point1, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_mul(group, point, NULL, point, s, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->pointChi1->x, ret->pointChi1->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/*
	 * w = (mpk->v)^s in F_p^2
	 *	w = mpk->v, convert from FpPoint to BN_GFP2
	 *	w = w^s
	 *	wbuf = Canonical(w, order=1)
	 */

	if (!BN_copy(w->a0, mpk->v->x)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_copy(w->a1, mpk->v->y)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_GFP2_exp(w, w, s, mpk->p, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_GFP2_canonical(w, NULL, &wbuflen, 1, mpk->p, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_BN_LIB);
		goto end;
	}
	if (!(wbuf = OPENSSL_malloc(wbuflen))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!BN_GFP2_canonical(w, wbuf, &wbuflen, 1, mpk->p, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/*
	 * ret->y = HashBytes(DoubleHash(wbuf)) xor in
	 *	DoubleHash output length == hashlen * 2
	 *	HashBytes output length == inlen
	 */

	if (!ASN1_OCTET_STRING_set(ret->y, NULL, inlen)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	/*
	//FIXME:
	if (!bb1ibe_hash(md, wbuf, wbuflen, ret->y->data, inlen)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, BB1IBE_R_BB1IBE_HASH_FAILURE);
		goto end;
	}
	*/
	for (i = 0; i < inlen; i++) {
		ret->y->data[i] ^= in[i];
	}

	/*
	 * ret->u = s +  HashToRange(DoubleHash(y1||x1||y0||x0||ret->y||wbuf)) (mod q)
	 *	(x0, y0) = ret->pointChi0
	 *	(x1, y1) = ret->pointChi1
	 */


	/* ret->u += s (mod q) */
	if (!BN_mod_add(ret->nu, ret->nu, s, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_ENCRYPT, ERR_R_BN_LIB);
		goto end;
	}

	e = 0;

end:
	if (e && ret) {
		BB1CiphertextBlock_free(ret);
		ret = NULL;
	}
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	EC_POINT_free(point1);
	BN_GFP2_free(w);
	OPENSSL_free(wbuf);
	OPENSSL_free(cbuf);
	return ret;
}

int BB1IBE_do_decrypt(BB1PublicParameters *mpk,
	const BB1CiphertextBlock *in, unsigned char *out, size_t *outlen,
	BB1PrivateKeyBlock *sk)
{
	int ret = 0;
	EC_GROUP *group = NULL;
	EC_POINT *point_c0 = NULL;
	EC_POINT *point_c1 = NULL;
	EC_POINT *point_d0 = NULL;
	EC_POINT *point_d1 = NULL;
	BN_CTX *bn_ctx = NULL;
	BN_GFP2 *w = NULL;
	BN_GFP2 *w1 = NULL;
	BIGNUM *s = NULL;
	BIGNUM *h = NULL;
	unsigned char *wbuf = NULL;
	size_t wbuflen;
	size_t len;
	int i;

	/* check arguments */
	if (!mpk || !in || !outlen || !sk) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		goto end;
	}

	/* check output buffer */
	len = in->y->length;
	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, BB1IBE_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* init variables */
	if (!(group = EC_GROUP_new_type1curve(mpk->p, mpk->pointP->x,
		mpk->pointP->y, mpk->q, bn_ctx))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, BB1IBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	point_c0 = EC_POINT_new(group);
	point_c1 = EC_POINT_new(group);
	point_d0 = EC_POINT_new(group);
	point_d1 = EC_POINT_new(group);
	w = BN_GFP2_new();
	w1 = BN_GFP2_new();
	s = BN_CTX_get(bn_ctx);
	h = BN_CTX_get(bn_ctx);

	if (!point_c0 || !point_c1 || !point_d0 || !point_d1 || !w || !w1 || !s || !h) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/*
	 * w = e(in->C0, sk->D0)/e(in->C1, sk->D1)
	 */
	if (!EC_POINT_set_affine_coordinates_GFp(group, point_c0,
		in->pointChi0->x, in->pointChi0->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(group, point_c1,
		in->pointChi1->x, in->pointChi1->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(group, point_d0,
		sk->pointD0->x, sk->pointD0->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(group, point_d1,
		sk->pointD1->x, sk->pointD1->y, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_type1curve_tate_ratio(group, w, point_c0, point_d0,
		point_c1, point_d1, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, BB1IBE_R_COMPUTE_TATE_FAILURE);
		goto end;
	}

	/* wbuf = Canonical(w, order=1) */
	if (!BN_GFP2_canonical(w, NULL, &wbuflen, 1, mpk->p, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_BN_LIB);
		goto end;
	}
	if (!(wbuf = OPENSSL_malloc(wbuflen))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!BN_GFP2_canonical(w, wbuf, &wbuflen, 1, mpk->p, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* h = H(ciphertext||w) */
#if 0
	//remove warning
	if (!BB1CiphertextBlock_hash_to_range(mpk, in, wbuf, wbuflen, h, bn_ctx)) {
		goto end;
	}
#endif

	/* s = in->nu - H(c) */
	if (!BN_mod_sub(s, in->nu, h, mpk->q, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_BN_LIB);
		goto end;
	}

	/* check if w == v^s */
	if (!BN_copy(w1->a0, mpk->v->x)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_copy(w1->a1, mpk->v->y)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_exp(w1, w1, s, mpk->p, bn_ctx)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_equ(w, w1)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, BB1IBE_R_BB1CIPHERTEXT_INVALID_MAC);
		goto end;
	}

	/*
	 * out = HashBytes(DoubleHash(wbuf)) xor in->y
	 */
	/*
	if (!bb1ibe_hash(md, wbuf, wbuflen, out, in->y->length)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DO_DECRYPT, BB1IBE_R_BB1IBE_HASH_FAILURE);
		goto end;
	}
	*/
	for (i = 0; i < in->y->length; i++) {
		out[i] ^= in->y->data[i];
	}

	ret = 1;
end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point_c0);
	EC_POINT_free(point_c1);
	EC_POINT_free(point_d0);
	EC_POINT_free(point_d1);
	BN_GFP2_free(w);
	BN_GFP2_free(w1);
	OPENSSL_free(wbuf);
	return ret;
}

static int BB1PublicParameters_size(BB1PublicParameters *mpk,
	size_t inlen, size_t *outlen)
{
	size_t len = 0;
	len += (OPENSSL_ECC_MAX_FIELD_BITS/8) * 5;
	len += inlen;
	len += EVP_MAX_MD_SIZE;
	len += 256; /* caused by version and DER encoding */
	*outlen = len;
	return 1;
}

int BB1IBE_encrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen)
{
	int ret = 0;
	BB1CiphertextBlock *c = NULL;
	unsigned char *p;
	size_t len;

	if (!mpk || !in || inlen <= 0 || !outlen || !id || idlen <= 0) {
		BB1IBEerr(BB1IBE_F_BB1IBE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!BB1PublicParameters_size(mpk, inlen, &len)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_ENCRYPT, BB1IBE_R_COMPUTE_OUTLEN_FAILURE);
		return 0;
	}
	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		BB1IBEerr(BB1IBE_F_BB1IBE_ENCRYPT, BB1IBE_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!(c = BB1IBE_do_encrypt(mpk, in, inlen, id, idlen))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_ENCRYPT, BB1IBE_R_ENCRYPT_FAILURE);
		goto end;
	}

	p = out;
	if (!i2d_BB1CiphertextBlock(c, &p)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_ENCRYPT, BB1IBE_R_I2D_FAILURE);
		goto end;
	}
	len = p - out;

	*outlen = len;
	ret = 1;

end:
	BB1CiphertextBlock_free(c);
	return ret;
}

int BB1IBE_decrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	BB1PrivateKeyBlock *sk)
{
	int ret = 0;
	BB1CiphertextBlock *c = NULL;
	const unsigned char *p;

	if (!mpk || !in || inlen <= 0 || !outlen || !sk) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!out) {
		*outlen = inlen;
		return 1;
	}
	if (*outlen < inlen) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DECRYPT, BB1IBE_R_BUFFER_TOO_SMALL);
		return 0;
	}

	p = in;
	if (!(c = d2i_BB1CiphertextBlock(NULL, &p, inlen))) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DECRYPT, BB1IBE_R_D2I_FAILURE);
		goto end;
	}

	/* check that all input has been decoded */
	if (p - in != inlen) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DECRYPT, BB1IBE_R_INVALID_INPUT);
		goto end;
	}

	if (!BB1IBE_do_decrypt(mpk, c, out, outlen, sk)) {
		BB1IBEerr(BB1IBE_F_BB1IBE_DECRYPT, BB1IBE_R_DECRYPT_FAILURE);
		goto end;
	}

	ret = 1;
end:
	BB1CiphertextBlock_free(c);
	return ret;
}

