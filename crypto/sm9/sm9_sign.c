/* ====================================================================
 * Copyright (c) 2016 - 2018 The GmSSL Project.  All rights reserved.
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
#include "sm9_lcl.h"


SM9Signature *SM9_do_sign(const unsigned char *dgst, int dgstlen, SM9_KEY *sm9)
{
	return NULL;
}

int SM9_do_verify(const unsigned char *dgst, int dgstlen,
	const SM9Signature *sig, SM9_KEY *sm9)
{
	return -1;
}

int SM9_SignInit(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *eng)
{
	unsigned char prefix[1] = {0x02};

	if (!EVP_DigestInit_ex(ctx, md, eng)) {
		SM9err(SM9_F_SM9_SIGNINIT, ERR_R_EVP_LIB);
		return 0;
	}
	if (!EVP_DigestUpdate(ctx, prefix, sizeof(prefix))) {
		SM9err(SM9_F_SM9_SIGNINIT, ERR_R_EVP_LIB);
		return 0;
	}

	return 1;
}

SM9Signature *SM9_SignFinal(EVP_MD_CTX *ctx1, SM9PrivateKey *sk)
{
	SM9Signature *ret = NULL;
	SM9Signature *sig = NULL;
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *n = SM9_get0_order();
	int point_form = POINT_CONVERSION_COMPRESSED;
	/* buf for w and prefix zeros of ct1/2 */
	unsigned char buf[384] = {0};
	unsigned int len;
	const unsigned char ct1[4] = {0x00, 0x00, 0x00, 0x01};
	const unsigned char ct2[4] = {0x00, 0x00, 0x00, 0x02};
	EVP_MD_CTX *ctx2 = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *S = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *r = NULL;
	point_t Ppubs;
	fp12_t w;

	if (!(sig = SM9Signature_new())
		|| !(ctx2 = EVP_MD_CTX_new())
		|| !(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(S = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!(r = BN_CTX_get(bn_ctx))
		|| !fp12_init(w, bn_ctx)
		|| !point_init(&Ppubs, bn_ctx)) {
		SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}


	/* get Ppubs */
	if (ASN1_STRING_length(sk->pointPpub) != 129
		|| !point_from_octets(&Ppubs, ASN1_STRING_get0_data(sk->pointPpub), p, bn_ctx)) {
		SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_INVALID_POINTPPUB);
		goto end;
	}
	/* g = e(P1, Ppubs) */
	if (!rate_pairing(w, &Ppubs, EC_GROUP_get0_generator(group), bn_ctx)) {
		SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
		goto end;
	}

	do {
		/* r = rand(1, n - 1) */
		do {
			if (!BN_rand_range(r, n)) {
				SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_BN_LIB);
				goto end;
			}
		} while (BN_is_zero(r));

		/* w = g^r */
		if (!fp12_pow(w, w, r, p, bn_ctx)
			|| !fp12_to_bin(w, buf)) {
			SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_EXTENSION_FIELD_ERROR);
			goto end;
		}

		if (!EVP_DigestUpdate(ctx1, buf, sizeof(buf))
			|| !EVP_MD_CTX_copy(ctx2, ctx1)
			/* Ha1 = Hv(0x02||M||w||0x00000001) */
			|| !EVP_DigestUpdate(ctx1, ct1, sizeof(ct1))
		 	/* Ha2 = Hv(0x02||M||w||0x00000002) */
			|| !EVP_DigestUpdate(ctx2, ct2, sizeof(ct2))
			|| !EVP_DigestFinal_ex(ctx1, buf, &len)
			|| !EVP_DigestFinal_ex(ctx2, buf + len, &len)) {
			SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_DIGEST_FAILURE);
			goto end;
		}

		/* Ha = Ha1||Ha2[0..7] */
		if (!BN_bin2bn(buf, 40, sig->h)
			/* h = (Ha mod (n - 1)) + 1 */
			|| !BN_mod(sig->h, sig->h, SM9_get0_order_minus_one(), bn_ctx)
			|| !BN_add_word(sig->h, 1)
			/* l = r - h (mod n) */
			|| !BN_mod_sub(r, r, sig->h, n, bn_ctx)) {
			SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(r));

	/* get sk */
	if (!EC_POINT_oct2point(group, S, ASN1_STRING_get0_data(sk->privatePoint),
		ASN1_STRING_length(sk->privatePoint), bn_ctx)) {
		SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_INVALID_PRIVATE_POINT);
		goto end;
	}
	/* S = l * sk */
	len = sizeof(buf);
	if (!EC_POINT_mul(group, S, NULL, S, r, bn_ctx)
		|| !(len = EC_POINT_point2oct(group, S, point_form, buf, len, bn_ctx))
		|| !ASN1_OCTET_STRING_set(sig->pointS, buf, len)) {
		SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_EC_LIB);
		goto end;
	}

	ret = sig;
	sig = NULL;

end:
	SM9Signature_free(sig);
	EVP_MD_CTX_free(ctx2);
	EC_GROUP_free(group);
	EC_POINT_free(S);
	BN_free(r);
	point_cleanup(&Ppubs);
	fp12_cleanup(w);
	BN_CTX_end(bn_ctx);
	BN_CTX_free(bn_ctx);
	return ret;
}

int SM9_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *eng)
{
	unsigned char prefix[1] = {0x02};

	if (!EVP_DigestInit_ex(ctx, md, eng)) {
		SM9err(SM9_F_SM9_VERIFYINIT, ERR_R_EVP_LIB);
		return 0;
	}
	if (!EVP_DigestUpdate(ctx, prefix, sizeof(prefix))) {
		SM9err(SM9_F_SM9_VERIFYINIT, ERR_R_EVP_LIB);
		return 0;
	}

	return 1;
}

static const EVP_MD *sm9hash1_to_md(const ASN1_OBJECT *hash1obj)
{
	switch (OBJ_obj2nid(hash1obj)) {
	case NID_sm9hash1_with_sm3:
		return EVP_sm3();
	case NID_sm9hash1_with_sha256:
		return EVP_sha256();
	}
	return NULL;
}

int SM9_VerifyFinal(EVP_MD_CTX *ctx1, const SM9Signature *sig, SM9PublicKey *pk)
{
	int ret = -1;
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *n = SM9_get0_order();
	const EVP_MD *md;
	unsigned char buf[384] = {0};
	unsigned int len;
	const unsigned char ct1[4] = {0x00, 0x00, 0x00, 0x01};
	const unsigned char ct2[4] = {0x00, 0x00, 0x00, 0x02};
	EVP_MD_CTX *ctx2 = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *S = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *h = NULL;
	point_t Ppubs;
	point_t P;
	fp12_t w;
	fp12_t u;

	if (!(ctx2 = EVP_MD_CTX_new())
		|| !(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(S = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_VERIFYFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!(h = BN_CTX_get(bn_ctx))
		|| !point_init(&Ppubs, bn_ctx)
		|| !point_init(&P, bn_ctx)
		|| !fp12_init(w, bn_ctx)
		|| !fp12_init(u, bn_ctx)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* check signature (h, S) */
	if (BN_is_zero(sig->h) || BN_cmp(sig->h, SM9_get0_order()) >= 0) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_INVALID_SIGNATURE);
		goto end;
	}
	if (!EC_POINT_oct2point(group, S, ASN1_STRING_get0_data(sig->pointS),
		ASN1_STRING_length(sig->pointS), bn_ctx)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_INVALID_SIGNATURE);
		goto end;
	}

	/* g = e(P1, Ppubs) */
	if (ASN1_STRING_length(pk->pointPpub) != 129
		|| !point_from_octets(&Ppubs, ASN1_STRING_get0_data(pk->pointPpub), p, bn_ctx)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_INVALID_POINTPPUB);
		goto end;
	}
	if (!rate_pairing(w, &Ppubs, EC_GROUP_get0_generator(group), bn_ctx)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_PAIRING_ERROR);
		goto end;
	}

	/* t = g^(sig->h) */
	if (!fp12_pow(w, w, sig->h, p, bn_ctx)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_EXTENSION_FIELD_ERROR);
		goto end;
	}

	/* h1 = H1(ID||hid, N) */
	if (!(md = sm9hash1_to_md(pk->hash1))) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_INVALID_HASH1);
		goto end;
	}
	if (!SM9_hash1(md, &h, (const char *)ASN1_STRING_get0_data(pk->identity),
		ASN1_STRING_length(pk->identity), SM9_HID_SIGN, n, bn_ctx)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, ERR_R_SM9_LIB);
		goto end;
	}

	/* P = h1 * P2 + Ppubs */
	if (!point_mul_generator(&P, h, p, bn_ctx)
		|| !point_add(&P, &P, &Ppubs, p, bn_ctx)
		/* u = e(sig->S, P) */
		|| !rate_pairing(u, &P, S, bn_ctx)
		/* w = u * t */
		|| !fp12_mul(w, u, w, p, bn_ctx)
		|| !fp12_to_bin(w, buf)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_EXTENSION_FIELD_ERROR);
		goto end;
	}

	/* h2 = H2(M||w) mod n */
	if (!EVP_DigestUpdate(ctx1, buf, sizeof(buf))
		|| !EVP_MD_CTX_copy(ctx2, ctx1)
		/* Ha1 = Hv(0x02||M||w||0x00000001) */
		|| !EVP_DigestUpdate(ctx1, ct1, sizeof(ct1))
	 	/* Ha2 = Hv(0x02||M||w||0x00000002) */
		|| !EVP_DigestUpdate(ctx2, ct2, sizeof(ct2))
		|| !EVP_DigestFinal_ex(ctx1, buf, &len)
		|| !EVP_DigestFinal_ex(ctx2, buf + len, &len)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_DIGEST_FAILURE);
		goto end;
	}
	/* Ha = Ha1||Ha2[0..7] */
	if (!BN_bin2bn(buf, 40, h)
		/* h2 = (Ha mod (n - 1)) + 1 */
		|| !BN_mod(h, h, SM9_get0_order_minus_one(), bn_ctx)
		|| !BN_add_word(h, 1)) {
		SM9err(SM9_F_SM9_VERIFYFINAL, ERR_R_BN_LIB);
		goto end;
	}

	/* check if h2 == sig->h */
	if (BN_cmp(h, sig->h) != 0) {
		SM9err(SM9_F_SM9_VERIFYFINAL, SM9_R_VERIFY_FAILURE);
		ret = 0;
		goto end;
	}

	ret = 1;

end:
	EVP_MD_CTX_free(ctx2);
	EC_GROUP_free(group);
	EC_POINT_free(S);
	BN_free(h);
	point_cleanup(&Ppubs);
	point_cleanup(&P);
	fp12_cleanup(w);
	fp12_cleanup(u);
	BN_CTX_end(bn_ctx);
	BN_CTX_free(bn_ctx);
	return ret;
}

int SM9_sign(int type, /* NID_[sm3 | sha256] */
	const unsigned char *data, size_t datalen,
	unsigned char *sig, size_t *siglen,
	SM9PrivateKey *sk)
{
	int ret = 0;
	EVP_MD_CTX *ctx = NULL;
	SM9Signature *sm9sig = NULL;
	const EVP_MD *md;
	int len;

	if (!(md = EVP_get_digestbynid(type))
		|| EVP_MD_size(md) != EVP_MD_size(EVP_sm3())) {
		SM9err(SM9_F_SM9_SIGN, SM9_R_INVALID_HASH2_DIGEST);
		return 0;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!SM9_SignInit(ctx, md, NULL)
		|| !SM9_SignUpdate(ctx, data, datalen)
		|| !(sm9sig = SM9_SignFinal(ctx, sk))) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_SM9_LIB);
		goto end;
	}

	if ((len = i2d_SM9Signature(sm9sig, &sig)) <= 0) {
		SM9err(SM9_F_SM9_SIGN, ERR_R_SM9_LIB);
		goto end;
	}

	*siglen = len;
	ret = 1;

end:
	EVP_MD_CTX_free(ctx);
	SM9Signature_free(sm9sig);
	return ret;
}

int SM9_verify(int type, /* NID_[sm3 | sha256] */
	const unsigned char *data, size_t datalen,
	const unsigned char *sig, size_t siglen,
	SM9PublicParameters *mpk, const char *id, size_t idlen)
{
	int ret = -1;
	EVP_MD_CTX *ctx = NULL;
	SM9Signature *sm9sig = NULL;
	SM9PublicKey *pk = NULL;
	const EVP_MD *md;

	if (!(md = EVP_get_digestbynid(type))
		|| EVP_MD_size(md) != EVP_MD_size(EVP_sm3())) {
		SM9err(SM9_F_SM9_VERIFY, SM9_R_INVALID_HASH2_DIGEST);
		return -1;
	}

	if (!(sm9sig = d2i_SM9Signature(NULL, &sig, siglen))
		|| i2d_SM9Signature(sm9sig, NULL) != siglen) {
		SM9err(SM9_F_SM9_VERIFY, SM9_R_INVALID_SIGNATURE_FORMAT);
		goto end;
	}

	if (!(pk = SM9_extract_public_key(mpk, id, idlen))) {
		SM9err(SM9_F_SM9_VERIFY, ERR_R_SM9_LIB);
		goto end;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		SM9err(SM9_F_SM9_VERIFY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!SM9_VerifyInit(ctx, md, NULL)
		|| !SM9_VerifyUpdate(ctx, data, datalen)
		|| (ret = SM9_VerifyFinal(ctx, sm9sig, pk)) < 0) {
		SM9err(SM9_F_SM9_VERIFY, ERR_R_SM9_LIB);
		goto end;
	}

end:
	EVP_MD_CTX_free(ctx);
	SM9Signature_free(sm9sig);
	SM9PublicKey_free(pk);
	return ret;
}
