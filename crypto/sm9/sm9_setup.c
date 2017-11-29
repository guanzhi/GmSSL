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
#include <openssl/sm9.h>
#include "sm9_lcl.h"

//TODO: `hid` should be add to arguments
int SM9_setup_type1curve(const EC_GROUP *group, const EVP_MD *md,
	SM9PublicParameters **pmpk, SM9MasterSecret **pmsk)
{
	int ret = 0;
	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *point = NULL;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	size_t size;

	if (!group || !pmpk || !pmsk) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	mpk = SM9PublicParameters_new();
	msk = SM9MasterSecret_new();
	point = EC_POINT_new(group);

	if (!mpk || !msk || !point) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* set mpk->curve */
	OPENSSL_assert(mpk->curve);
	ASN1_OBJECT_free(mpk->curve);
	if (!(mpk->curve = OBJ_nid2obj(NID_type1curve))) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, SM9_R_NOT_NAMED_CURVE);
		goto end;
	}

	/* mpk->p = group->p
	 * mpk->a = group->a
	 * mpk->b = group->b
	 */
	if (!EC_GROUP_get_curve_GFp(group, mpk->p, mpk->a, mpk->b, bn_ctx)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!BN_is_zero(mpk->a) || !BN_is_one(mpk->b)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* mpk->beta = 0 */
	BN_zero(mpk->beta);

	/* mpk->order = group->order */
	if (!EC_GROUP_get_order(group, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* mpk->cofactor = group->cofactor */
	if (!EC_GROUP_get_cofactor(group, mpk->cofactor, bn_ctx)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* mpk->k = 2 */
	if (!BN_set_word(mpk->k, 2)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_BN_LIB);
		goto end;
	}

	/* mpk->pointP1 = group->generator
	 * mpk->pointP2 = group->generator
	 */
	if (!(size = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
		point_form, NULL, 0, bn_ctx))) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(mpk->pointP1, NULL, size)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
		point_form, mpk->pointP1->data, mpk->pointP1->length, bn_ctx)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(mpk->pointP2,
		mpk->pointP1->data, mpk->pointP1->length)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* mpk->pairing = "tate" */
	ASN1_OBJECT_free(mpk->pairing);
	if (!(mpk->pairing = OBJ_nid2obj(NID_tate_pairing))) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, SM9_R_PARSE_PAIRING);
		goto end;
	}

	/* set mpk->hashfcn */
	OPENSSL_assert(mpk->hashfcn);
	ASN1_OBJECT_free(mpk->hashfcn);
	if (!(mpk->hashfcn = OBJ_nid2obj(EVP_MD_type(md)))) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, SM9_R_PARSE_PAIRING);
		goto end;
	}

	/* set mpk->g1 = e(P1, Ppub) */
	//TODO

	/* set mpk->g2 = e(Ppub, P2) */
	//TODO

	/* random msk->masterSecret in [2, mpk->order - 1] */
	do {
		if (!BN_rand_range(msk->masterSecret, mpk->order)) {
			SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->masterSecret) || BN_is_one(msk->masterSecret));

	/* mpk->pointPpub = msk->masterSecret * mpk->pointP */
	if (!EC_POINT_mul(group, point, msk->masterSecret,
		NULL, NULL, bn_ctx)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!(size = EC_POINT_point2oct(group, point, point_form,
		NULL, 0, bn_ctx))) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(mpk->pointPpub, NULL, size)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_POINT_point2oct(group, point, point_form,
		mpk->pointPpub->data, mpk->pointPpub->length, bn_ctx)) {
		SM9err(SM9_F_SM9_SETUP_TYPE1CURVE, ERR_R_EC_LIB);
		goto end;
	}

	/* set return value */
	*pmpk = mpk;
	*pmsk = msk;
	ret = 1;

end:
	if (!ret) {
		SM9PublicParameters_free(mpk);
		SM9MasterSecret_free(msk);
		*pmpk = NULL;
		*pmsk = NULL;
	}
	BN_CTX_free(bn_ctx);
	EC_POINT_free(point);
	return ret;
}

int SM9_setup_by_pairing_name(int nid, int hid,
	SM9PublicParameters **mpk, SM9MasterSecret **msk)
{
	EC_GROUP *group = EC_GROUP_new_sm9s256t1();
	return SM9_setup_type1curve(group, EVP_sm3(), mpk, msk);
}

