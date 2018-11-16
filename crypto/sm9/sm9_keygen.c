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


int SM9_hash1(const EVP_MD *md, BIGNUM **r, const char *id, size_t idlen,
	unsigned char hid, const BIGNUM *n, BN_CTX *ctx)
{
	int ret = 0;
	BIGNUM *h = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *ctx1 = NULL;
	EVP_MD_CTX *ctx2 = NULL;
	unsigned char prefix[1] = {0x01};
	unsigned char ct1[4] = {0x00, 0x00, 0x00, 0x01};
	unsigned char ct2[4] = {0x00, 0x00, 0x00, 0x02};
	unsigned char buf[128];
	unsigned int len;

	if (!(ctx1 = EVP_MD_CTX_new())
		|| !(ctx2 = EVP_MD_CTX_new())
		|| !(bn_ctx = BN_CTX_new())
		|| !(h = BN_new())) {
		goto end;
	}

	if (!EVP_DigestInit_ex(ctx1, md, NULL)
		|| !EVP_DigestUpdate(ctx1, prefix, sizeof(prefix))
		|| !EVP_DigestUpdate(ctx1, id, idlen)
		|| !EVP_DigestUpdate(ctx1, &hid, 1)
		|| !EVP_MD_CTX_copy(ctx2, ctx1)
		|| !EVP_DigestUpdate(ctx1, ct1, sizeof(ct1))
		|| !EVP_DigestUpdate(ctx2, ct2, sizeof(ct2))
		|| !EVP_DigestFinal_ex(ctx1, buf, &len)
		|| !EVP_DigestFinal_ex(ctx2, buf + len, &len)) {
		goto end;
	}

	if (!BN_bin2bn(buf, 40, h)
		|| !BN_mod(h, h, SM9_get0_order_minus_one(), bn_ctx)
		|| !BN_add_word(h, 1)) {
		goto end;
	}

	*r = h;
	h = NULL;
	ret = 1;

end:
	BN_free(h);
	BN_CTX_free(bn_ctx);
	EVP_MD_CTX_free(ctx1);
	EVP_MD_CTX_free(ctx2);
	return ret;
}

SM9_KEY *SM9_MASTER_KEY_extract_key(SM9_MASTER_KEY *master,
	const char *id, size_t idlen, int priv)
{
	SM9PrivateKey *ret = NULL;
	SM9PrivateKey *sk = NULL;
	EC_GROUP *group = NULL;
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
	if (!master || !id) {
		SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (strlen(id) != idlen || idlen <= 0 || idlen > SM9_MAX_ID_LENGTH) {
		SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY,
			SM9_R_INVALID_ID);
		return NULL;
	}

	/* check pairing */
	if (OBJ_obj2nid(master->pairing) != NID_sm9bn256v1) {
		return NULL;
	}

	/* check scheme */
	scheme = OBJ_obj2nid(master->scheme);
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

	/* check if master */
	if (priv && master->masterSecret == NULL) {
		SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, SM9_R_NO_MASTER_SECRET);
		return NULL;
	}

	/* check hash1 and set hash1 md */
	switch (OBJ_obj2nid(master->hash1)) {
	case NID_sm9hash1_with_sm3:
		md = EVP_sm3();
		break;
	case NID_sm9hash1_with_sha256:
		md = EVP_sha256();
		break;
	default:
		SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, SM9_R_INVALID_HASH1);
		return NULL;
	}

	/* malloc */
	if (!(sk = SM9PrivateKey_new())
		|| !(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(ctx);

	if (!(sk->pairing = master->pairing)
		|| !(sk->scheme = master->scheme)
		|| !(sk->hash1 = master->hash1)
		|| !(sk->pointPpub = ASN1_OCTET_STRING_dup(master->pointPpub))
		|| !(sk->identity = ASN1_OCTET_STRING_new())
		|| !ASN1_OCTET_STRING_set(sk->identity, (unsigned char *)id, idlen)
		|| !(sk->publicPoint = ASN1_OCTET_STRING_new())
		|| !(sk->privatePoint = ASN1_OCTET_STRING_new())) {
		SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_ASN1_LIB);
		goto end;
	}

	/* h1 = H1(id||HID) */
	if (!SM9_hash1(md, &t, id, idlen, hid, n, ctx)) {
		SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
		goto end;
	}

	/* generate (Ppubs, ds) or (Ppube, de) */
	if (scheme == NID_sm9sign) {

		/* publicPoint = h1 * P2 + Ppubs */
		point_t Ppubs;
		point_t point;
		if (!point_init(&point, ctx)
			|| !point_init(&Ppubs, ctx)
			|| ASN1_STRING_length(master->pointPpub) != sizeof(buf)
			|| !point_from_octets(&Ppubs, ASN1_STRING_get0_data(master->pointPpub), p, ctx)
			|| !point_mul_generator(&point, t, p, ctx)
			|| !point_add(&point, &point, &Ppubs, p, ctx)
			|| !point_to_octets(&point, buf, ctx)
			|| !ASN1_OCTET_STRING_set(sk->publicPoint, buf, sizeof(buf))) {
			SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
			point_cleanup(&Ppubs);
			point_cleanup(&point);
			goto end;
		}
		point_cleanup(&Ppubs);
		point_cleanup(&point);

	} else {

		/* publicPoint = h1 * P1 + Ppube */
		EC_POINT *Ppube = NULL;
		EC_POINT *point = NULL;
		if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
			|| !(point = EC_POINT_new(group))
			|| !(Ppube = EC_POINT_new(group))
			|| !EC_POINT_oct2point(group, Ppube,
				ASN1_STRING_get0_data(master->pointPpub),
				ASN1_STRING_length(master->pointPpub), ctx)
			|| !EC_POINT_mul(group, point, t, NULL, NULL, ctx)
			|| !EC_POINT_add(group, point, point, Ppube, ctx)
			|| !(len = EC_POINT_point2oct(group, point, point_form, buf, len, ctx))
			|| !ASN1_OCTET_STRING_set(sk->publicPoint, buf, len)) {
			SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
			EC_POINT_free(Ppube);
			EC_POINT_free(point);
			goto end;
		}
		EC_POINT_free(Ppube);
		EC_POINT_free(point);
	}

	if (priv) {

		/* t1 = H1(ID||hid) + master (mod n) */
		if (!BN_mod_add(t, t, master->masterSecret, n, ctx)) {
			SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_BN_LIB);
			goto end;
		}

		/* if t1 is zero, return failed */
		if (BN_is_zero(t)) {
			SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, SM9_R_ZERO_ID);
			goto end;
		}

		/* t2 = master * t1^-1 (mod n) */
		if (!BN_mod_inverse(t, t, n, ctx)) {
			SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_mod_mul(t, master->masterSecret, t, n, ctx)) {
			SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_BN_LIB);
			goto end;
		}

		if (scheme == NID_sm9sign) {
			/* ds = t2 * P1 */
			EC_POINT *ds = NULL;
			if (!(ds = EC_POINT_new(group))
				|| !EC_POINT_mul(group, ds, t, NULL, NULL, ctx)
				|| !(len = EC_POINT_point2oct(group, ds, point_form, buf, len, ctx))
				|| !ASN1_OCTET_STRING_set(sk->privatePoint, buf, len)) {
				SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
				EC_POINT_free(ds);
				goto end;
			}
			EC_POINT_free(ds);
		} else {
			/* de = t2 * P2 */
			point_t de;
			if (!point_init(&de, ctx)
				|| !point_mul_generator(&de, t, p, ctx)
				|| !point_to_octets(&de, buf, ctx)
				|| !ASN1_OCTET_STRING_set(sk->privatePoint, buf, sizeof(buf))) {
				SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
				point_cleanup(&de);
				goto end;
			}
			point_cleanup(&de);
		}
	}

	ret = sk;
	sk = NULL;

end:
	EC_GROUP_free(group);
	if (ctx) {
		BN_CTX_end(ctx);
	}
	BN_CTX_free(ctx);
	BN_clear_free(t);
	OPENSSL_cleanse(buf, sizeof(buf));
	return ret;
}

SM9PublicKey *SM9_extract_public_key(SM9PublicParameters *master,
	const char *id, size_t idlen)
{
	return SM9_MASTER_KEY_extract_key(master, id, idlen, 0);
}

SM9PrivateKey *SM9_extract_private_key(SM9MasterSecret *master,
	const char *id, size_t idlen)
{
	return SM9_MASTER_KEY_extract_key(master, id, idlen, 1);
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
