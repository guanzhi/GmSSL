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
#include <openssl/ec_type1.h>
#include "sm9_lcl.h"

static int SM9PublicParameters_get_usage(SM9PublicParameters *mpk)
{
	//FIXME
	return SM9_HID_SIGN;
}

SM9PrivateKey *SM9_extract_private_key(SM9PublicParameters *mpk,
	SM9MasterSecret *msk, const char *id, size_t idlen)
{
	int e = 1;
	SM9PrivateKey *ret = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BIGNUM *h;
	const EVP_MD *md;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	size_t size;

	int hid = SM9PublicParameters_get_usage(mpk);

	if (!mpk || !msk || !id) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (strlen(id) != idlen || idlen <= 0 || idlen > SM9_MAX_ID_LENGTH) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			SM9_R_INVALID_ID);
		return NULL;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve_ex(mpk->p,
		mpk->a, mpk->b, mpk->pointP1->data, mpk->pointP1->length,
		mpk->order, mpk->cofactor, bn_ctx))) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* malloc */
	ret = SM9PrivateKey_new();
	point = EC_POINT_new(group);
	h = BN_CTX_get(bn_ctx);

	if (!ret || !point || !h) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* md = mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, SM9_R_INVALID_MD);
		goto end;
	}

	/* h = H1(ID||HID) in [0, mpk->order] */
	if (!SM9_hash1(md, &h, id, idlen, hid, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_SM9_LIB);
		goto end;
	}

	/* h = h + msk->masterSecret (mod mpk->order) */
	if (!BN_mod_add(h, h, msk->masterSecret, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* if h is zero, return failed */
	if (BN_is_zero(h)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, SM9_R_ZERO_ID);
		goto end;
	}

	/* h = msk->masterSecret * h^-1 (mod mpk->order) */
	if (!BN_mod_inverse(h, h, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(h, msk->masterSecret, h, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* sk->privatePoint = mpk->pointP1 * h */
	if (!EC_POINT_mul(group, point, h, NULL, NULL, bn_ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}
	if (!(size = EC_POINT_point2oct(group, point, point_form,
		NULL, 0, bn_ctx))) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(ret->privatePoint, NULL, size)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_POINT_point2oct(group, point, point_form,
		ret->privatePoint->data, ret->privatePoint->length, bn_ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	e = 0;

end:
	if (e && ret) {
		SM9PrivateKey_free(ret);
		ret = NULL;
	}
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	return NULL;
}

SM9PublicKey *SM9_extract_public_key(SM9PublicParameters *mpk,
	const char *id, size_t idlen)
{
	return NULL;
}

SM9PublicKey *SM9PrivateKey_get_public_key(SM9PublicParameters *mpk,
	SM9PrivateKey *sk)
{
	return NULL;
}
