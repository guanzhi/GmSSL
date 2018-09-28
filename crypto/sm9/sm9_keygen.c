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
#include <openssl/bn_hash.h>
#include "sm9_lcl.h"


int SM9_hash1(const EVP_MD *md, BIGNUM **r,
	const char *id, size_t idlen,
	unsigned char hid,
	const BIGNUM *range,
	BN_CTX *ctx)
{
	unsigned char *buf;

	if (!(buf = OPENSSL_malloc(idlen + 1))) {
		return 0;
	}
	memcpy(buf, id, idlen);
	buf[idlen] = hid;

	if (!BN_hash_to_range(md, r, buf, idlen + 1, range, ctx)) {
		OPENSSL_free(buf);
		return 0;
	}

	OPENSSL_free(buf);
	return 1;
}

SM9PrivateKey *SM9_extract_private_key(SM9MasterSecret *msk,
	const char *id, size_t idlen)
{
	SM9PrivateKey *ret = NULL;
	SM9PrivateKey *sk = NULL;
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *n = SM9_get0_order();
	int scheme;
	unsigned char hid;
	const EVP_MD *md;
	BN_CTX *ctx = NULL;
	BIGNUM *t = NULL;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	unsigned char buf[129];
	size_t len = sizeof(buf);

	/* check args */
	if (!msk || !id) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (strlen(id) != idlen || idlen <= 0 || idlen > SM9_MAX_ID_LENGTH) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			SM9_R_INVALID_ID);
		return NULL;
	}

	/* check pairing */
	if (OBJ_obj2nid(msk->pairing) != NID_sm9bn256v1) {
		return NULL;
	}

	/* check scheme */
	scheme = OBJ_obj2nid(msk->scheme);
	switch (scheme) {
	case NID_sm9sign:
		hid = SM9_HID_SIGN;
		break;
	case NID_sm9keyagreement:
		hid = SM9_HID_EXCH;
		break;
	case NID_sm9encrypt:
		hid = SM9_HID_ENC;
		break;
	default:
		return NULL;
	}


	/* check hash1 and set hash1 md */
	switch (OBJ_obj2nid(msk->hash1)) {
	case NID_sm9hash1_with_sm3:
		md = EVP_sm3();
		break;
	case NID_sm9hash1_with_sha256:
		md = EVP_sha256();
		break;
	default:
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, SM9_R_INVALID_HASH1);
		return NULL;
	}

	/* malloc */
	if (!(sk = SM9PrivateKey_new())
		|| !(ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(ctx);

	/* t1 = H1(ID||hid) + msk (mod n) */
	if (!SM9_hash1(md, &t, id, idlen, hid, n, ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_SM9_LIB);
		goto end;
	}
	if (!BN_mod_add(t, t, msk->masterSecret, n, ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* if t1 is zero, return failed */
	if (BN_is_zero(t)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, SM9_R_ZERO_ID);
		goto end;
	}

	/* t2 = msk * t1^-1 (mod n) */
	if (!BN_mod_inverse(t, t, n, ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(t, msk->masterSecret, t, n, ctx)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* generate ds or de */
	if (scheme == NID_sm9sign) {

		EC_GROUP *group = NULL;
		EC_POINT *ds = NULL;

		/* ds = t2 * P1 */
		if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
			|| !(ds = EC_POINT_new(group))
			|| !EC_POINT_mul(group, ds, t, NULL, NULL, ctx)
			|| !(len = EC_POINT_point2oct(group, ds, point_form, buf, len, ctx))) {
			EC_GROUP_free(group);
			EC_POINT_free(ds);
			goto end;
		}

		EC_GROUP_free(group);
		EC_POINT_free(ds);

	} else if (scheme == NID_sm9encrypt) {

		point_t de;
		
		/* de = t2 * P2 */
		if (!point_init(&de, ctx)
			|| !point_mul_generator(&de, t, p, ctx)
			|| !point_to_octets(&de, buf, ctx)) {
			point_cleanup(&de);
			goto end;
		}

		point_cleanup(&de);
	}

	ASN1_OBJECT_free(sk->pairing);
	ASN1_OBJECT_free(sk->scheme);
	ASN1_OBJECT_free(sk->hash1);
	sk->pairing = NULL;
	sk->scheme = NULL;
	sk->hash1 = NULL;

	if (!(sk->pairing = msk->pairing)
		|| !(sk->scheme = msk->scheme)
		|| !(sk->hash1 = msk->hash1)
		|| !ASN1_STRING_copy(sk->pointPpub, msk->pointPpub)
		|| !ASN1_STRING_set(sk->identity, id, idlen)
		/* FIXME: create publicPoint */
		|| !ASN1_STRING_set(sk->privatePoint, buf, len)) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_ASN1_LIB);
		goto end;
	}

	ret = sk;
	sk = NULL;
	
end:
	if (ctx) {
		BN_CTX_end(ctx);
	}
	BN_CTX_free(ctx);
	BN_clear_free(t);
	OPENSSL_cleanse(buf, sizeof(buf));
	return ret;
}

SM9PublicKey *SM9_extract_public_key(SM9PublicParameters *mpk,
	const char *id, size_t idlen)
{
	SM9PublicKey *ret = NULL;
	SM9PublicKey *pk = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *h1 = NULL;
	int scheme;
	unsigned char hid;
	const EVP_MD *md;
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *n = SM9_get0_order();
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	unsigned char buf[129];
	size_t len = sizeof(buf);

	if (!(pk = SM9PublicKey_new())
		|| !(ctx = BN_CTX_new())) {
		goto end;
	}

	/* check pairing */
	if (OBJ_obj2nid(mpk->pairing) != NID_sm9bn256v1) {
		goto end;
	}

	/* check scheme and set hash1 hid */
	scheme = OBJ_obj2nid(mpk->scheme);
	switch (scheme) {
	case NID_sm9sign:
		hid = SM9_HID_SIGN;
		break;
	case NID_sm9encrypt:
		hid = SM9_HID_ENC;
		break;
	case NID_sm9keyagreement:
		hid = SM9_HID_EXCH;
		break;
	default:
		goto end;
	}

	/* check hash1 and set hash1 md */
	switch (OBJ_obj2nid(mpk->hash1)) {
	case NID_sm9hash1_with_sm3:
		md = EVP_sm3();
		break;
	case NID_sm9hash1_with_sha256:
		md = EVP_sha256();
		break;
	default:
		goto end;
	}

	/* h1 = H1(ID || hid) in [1, n-1] */
	if (!SM9_hash1(md, &h1, id, idlen, hid, n, ctx)) {
		goto end;
	}

	if (scheme == NID_sm9sign) {
		/* publicPoint = h1 * P2 + Ppubs */
		point_t point;
		point_t Ppubs;


		if (!point_init(&point, ctx)
			|| !point_init(&Ppubs, ctx)
			|| ASN1_STRING_length(mpk->pointPpub) != sizeof(buf)
			|| !point_from_octets(&Ppubs, ASN1_STRING_get0_data(mpk->pointPpub), p, ctx)
			|| !point_mul_generator(&point, h1, p, ctx)
			|| !point_add(&point, &point, &Ppubs, p, ctx)
			|| !point_to_octets(&point, buf, ctx)) {
			point_cleanup(&point);
			point_cleanup(&Ppubs);
			goto end;
		}
		point_cleanup(&point);
		point_cleanup(&Ppubs);

	} else if (OBJ_obj2nid(mpk->scheme) == NID_sm9encrypt) {
		/* publicPoint = h1 * P1 + Ppube */
		EC_GROUP *group = NULL;
		EC_POINT *point = NULL;
		EC_POINT *Ppube = NULL;

		if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
			|| !(point = EC_POINT_new(group))
			|| !(Ppube = EC_POINT_new(group))
			|| !EC_POINT_oct2point(group, Ppube,
				ASN1_STRING_get0_data(mpk->pointPpub),
				ASN1_STRING_length(mpk->pointPpub), ctx)
			|| !EC_POINT_mul(group, point, h1, NULL, NULL, ctx)
			|| !EC_POINT_add(group, point, point, Ppube, ctx)
			|| !(len = EC_POINT_point2oct(group, point, point_form, buf, len, ctx))) {
			EC_GROUP_free(group);
			EC_POINT_free(point);
			EC_POINT_free(Ppube);
			goto end;
		}
		EC_GROUP_free(group);
		EC_POINT_free(point);
		EC_POINT_free(Ppube);
	}

	/* init object */
	ASN1_OBJECT_free(pk->pairing);
	ASN1_OBJECT_free(pk->scheme);
	ASN1_OBJECT_free(pk->hash1);
	pk->pairing = NULL;
	pk->scheme = NULL;
	pk->hash1 = NULL;

	if (!(pk->pairing = OBJ_dup(mpk->pairing))
		|| !(pk->scheme = OBJ_dup(mpk->scheme))
		|| !(pk->hash1 = OBJ_dup(mpk->hash1))
		|| !ASN1_STRING_copy(pk->pointPpub, mpk->pointPpub)
		|| !ASN1_STRING_set(pk->publicPoint, buf, len)
		|| !ASN1_STRING_set(pk->identity, id, idlen)) {
		goto end;
	}

	ret = pk;
	pk = NULL;

end:
	SM9PublicKey_free(pk);
	return ret;
}

SM9PublicKey *SM9PrivateKey_get_public_key(SM9PrivateKey *sk)
{
	SM9PublicKey *ret = NULL;
	SM9PublicKey *pk = NULL;

	if (!(pk = SM9PublicKey_new())) {
		return NULL;
	}

	ASN1_OBJECT_free(pk->pairing);
	ASN1_OBJECT_free(pk->scheme);
	ASN1_OBJECT_free(pk->hash1);
	pk->pairing = NULL;
	pk->scheme = NULL;
	pk->hash1 = NULL;

	if (!(pk->pairing = OBJ_dup(sk->pairing))
		|| !(pk->scheme = OBJ_dup(sk->scheme))
		|| !(pk->hash1 = OBJ_dup(sk->hash1))
		|| !ASN1_STRING_copy(pk->pointPpub, sk->pointPpub)
		|| !ASN1_STRING_copy(pk->publicPoint, sk->publicPoint)
		|| !ASN1_STRING_copy(pk->identity, sk->identity)) {
		goto end;
	}

	ret = pk;
	pk = NULL;

end:
	SM9PublicKey_free(pk);
	return ret;
}
