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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ec_type1.h>
#include <openssl/ec_hash.h>
#include <openssl/bfibe.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/bn_hash.h>
#include <openssl/bn_gfp2.h>
#include <openssl/kdf.h>
#include <openssl/kdf2.h>
#include "bfibe_lcl.h"


int BFIBE_setup(const EC_GROUP *group, const EVP_MD *md,
	BFPublicParameters **pmpk, BFMasterSecret **pmsk)
{
	int ret = 0;
	BFPublicParameters *mpk = NULL;
	BFMasterSecret *msk = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *point = NULL;
	BIGNUM *a;
	BIGNUM *b;

	if (!group || !pmpk || !pmsk) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	BN_CTX_start(bn_ctx);
	a = BN_CTX_get(bn_ctx);
	b = BN_CTX_get(bn_ctx);
	if (!b) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	mpk = BFPublicParameters_new();
	msk = BFMasterSecret_new();
	point = EC_POINT_new(group);

	if (!mpk || !msk || !point) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/*
	 * set mpk->version
	 * set mpk->curve
	 */

	mpk->version = BFIBE_VERSION;

	OPENSSL_assert(mpk->curve);
	ASN1_OBJECT_free(mpk->curve);
	if (!(mpk->curve = OBJ_nid2obj(NID_type1curve))) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, BFIBE_R_NOT_NAMED_CURVE);
		goto end;
	}

	/* mpk->p = group->p */
	if (!EC_GROUP_get_curve_GFp(group, mpk->p, a, b, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	if (!BN_is_zero(a) || !BN_is_one(b)) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, BFIBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* mpk->q = group->order */
	if (!EC_GROUP_get_order(group, mpk->q, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, BFIBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* mpk->pointP = group->generator */
	if (!EC_POINT_get_affine_coordinates_GFp(group, EC_GROUP_get0_generator(group),
		mpk->pointP->x, mpk->pointP->y, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	/* set mpk->hashfcn from F_p^2 element bits */
	OPENSSL_assert(mpk->hashfcn);
	ASN1_OBJECT_free(mpk->hashfcn);
	if (!(mpk->hashfcn = OBJ_nid2obj(EVP_MD_type(md)))) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, BFIBE_R_PARSE_PAIRING);
		goto end;
	}

	/*
	 * set msk->version
	 * random msk->masterSecret in [2, q - 1]
	 */

	msk->version = BFIBE_VERSION;

	do {
		if (!BN_rand_range(msk->masterSecret, mpk->q)) {
			BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->masterSecret) || BN_is_one(msk->masterSecret));

	/* mpk->pointPpub = msk->masterSecret * mpk->pointP */

	if (!EC_POINT_mul(group, point, msk->masterSecret, NULL, NULL, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		mpk->pointPpub->x, mpk->pointPpub->y, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	/* set return value */
	*pmpk = mpk;
	*pmsk = msk;
	ret = 1;

end:
	if (!ret) {
		BFPublicParameters_free(mpk);
		BFMasterSecret_free(msk);
		*pmpk = NULL;
		*pmsk = NULL;
	}
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_POINT_free(point);
	return ret;
}

BFPrivateKeyBlock *BFIBE_extract_private_key(BFPublicParameters *mpk,
	BFMasterSecret *msk, const char *id, size_t idlen)
{
	int e = 1;
	BFPrivateKeyBlock *ret = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BN_CTX *bn_ctx = NULL;
	const EVP_MD *md;

	if (!mpk || !msk || !id || idlen <= 0) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/*
	 * get EC_GROUP from mpk->{p, q, pointP}
	 * get EVP_MD from mpk->hashfcn
	 */
	if (!(group = EC_GROUP_new_type1curve(mpk->p, mpk->pointP->x,
		mpk->pointP->y, mpk->q, bn_ctx))) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY, BFIBE_R_PARSE_CURVE_FAILURE);
		goto end;
	}

	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY,
			BFIBE_R_INVALID_BFIBE_HASHFUNC);
		goto end;
	}

	/* prepare tmp variables */
	point = EC_POINT_new(group);
	if (!point) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/*
	 * set ret->version
	 * set ret->privateKey = msk->masterSecret * HashToPoint(ID)
	 */

	if (!(ret = BFPrivateKeyBlock_new())) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->version = BFIBE_VERSION;

	if (!EC_POINT_hash2point(group, md, id, idlen, point, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_mul(group, point, NULL, point, msk->masterSecret, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->privateKey->x, ret->privateKey->y, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	e = 0;
end:
	if (e && ret) {
		BFPrivateKeyBlock_free(ret);
		ret = NULL;
	}
	EC_GROUP_free(group);
	EC_POINT_free(point);
	BN_CTX_free(bn_ctx);
	return ret;
}

/*
 * r = rand(), |r| = hashlen
 * k = HashToRange(r||Hash(m), q), k in [0, q-1]
 * U = [k]P in E/F_p
 * Q = HashToPoint(ID) in E/F_p
 * v = Hash(e(Ppub, Q)^k) xor r, |v| == hashlen
 * w = HashBytes(r) xor m
 */
BFCiphertextBlock *BFIBE_do_encrypt(BFPublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	const char *id, size_t idlen)
{
	int e = 1;
	BFCiphertextBlock *ret = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *Ppub = NULL;
	EC_POINT *point = NULL;
	BN_GFP2 *theta = NULL;
	BIGNUM *k;
	const EVP_MD *md;
	KDF_FUNC hash_bytes;
	unsigned char rho[EVP_MAX_MD_SIZE * 2];
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned int len;
	size_t size;
	int i;

	if (!mpk || !in || inlen <= 0 || !id || idlen <= 0) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve(mpk->p, mpk->pointP->x,
		mpk->pointP->y, mpk->q, bn_ctx))) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, BFIBE_R_PARSE_MPK_FAILURE);
		goto end;
	}

	ret = BFCiphertextBlock_new();
	Ppub = EC_POINT_new(group);
	point = EC_POINT_new(group);
	theta = BN_GFP2_new();
	k = BN_CTX_get(bn_ctx);

	if (!ret || !point || !Ppub || !k || !theta) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}


	/* get kdf from mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, BFIBE_R_INVALID_BFIBE_HASHFUNC);
		goto end;
	}

	if (!(hash_bytes = KDF_get_ibcs(md))) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT,
			BFIBE_R_INVALID_BFIBE_HASHFUNC);
		goto end;
	}

	/* ret->version */
	ret->version = BFIBE_VERSION;

	/* rho = Rand(hashlen) */
	if (!RAND_bytes(rho, EVP_MD_size(md))) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, BFIBE_R_RAND_FAILURE);
		goto end;
	}

	/* k = HashToRange(rho||Hash(in), q) in [0, q - 1] */
	len = EVP_MD_size(md);
	if (!EVP_Digest(in, inlen, rho + EVP_MD_size(md), &len, md, NULL)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	if (!BN_hash_to_range(md, &k, rho, EVP_MD_size(md) * 2, mpk->q, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_BN_LIB);
		goto end;
	}

	/* ret->u = mpk->pointP * k in E/F_p, mpk->pointP is the generator */
	if (!EC_POINT_mul(group, point, k, NULL, NULL, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->u->x, ret->u->y, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* theta = e(mpk->pointPpub, HashToPoint(ID)) */
	if (!EC_POINT_set_affine_coordinates_GFp(group, Ppub,
		mpk->pointPpub->x, mpk->pointPpub->y, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_hash2point(group, md, id, idlen, point, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_type1curve_tate(group, theta, Ppub, point, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* theta = theta^k */
	if (!BN_GFP2_exp(theta, theta, k, mpk->p, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* ret->v = Hash(theta) xor rho */
	size = sizeof(buf);
	if (!BN_GFP2_canonical(theta, buf, &size, 0, mpk->p, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_BN_LIB);
		goto end;
	}
	len = sizeof(buf);
	if (!EVP_Digest(buf, size, buf, &len, md, NULL)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	for (i = 0; i < EVP_MD_size(md); i++) {
		buf[i] ^= rho[i];
	}
	if (!ASN1_OCTET_STRING_set(ret->v, buf, EVP_MD_size(md))) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_ASN1_LIB);
		goto end;
	}

	/*  ret->w = HashBytes(rho) xor m */
	if (!ASN1_OCTET_STRING_set(ret->w, NULL, inlen)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	size = inlen;
	if (!hash_bytes(rho, EVP_MD_size(md), ret->w->data, &size)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_ENCRYPT,
			BFIBE_R_HASH_BYTES_FAILURE);
		goto end;
	}
	for (i = 0; i < inlen; i++) {
		ret->w->data[i] ^= in[i];
	}

	e = 0;

end:
	if (e && ret) {
		BFCiphertextBlock_free(ret);
		ret = NULL;
	}
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(Ppub);
	EC_POINT_free(point);
	BN_GFP2_free(theta);
	return ret;
}

int BFIBE_do_decrypt(BFPublicParameters *mpk,
	const BFCiphertextBlock *in, unsigned char *out, size_t *outlen,
	BFPrivateKeyBlock *sk)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *point1 = NULL;
	BN_GFP2 *theta = NULL;
	BIGNUM *k;
	const EVP_MD *md;
	KDF_FUNC hash_bytes;
	unsigned char rho[EVP_MAX_MD_SIZE * 2];
	size_t size;
	unsigned int len;
	int i;

	if (!mpk || !in || !outlen || !sk) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!out) {
		*outlen = in->w->length;
		return 1;
	}
	if (*outlen < in->w->length) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT,
			BFIBE_R_BUFFER_TOO_SMALL);
		return 0;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve(mpk->p, mpk->pointP->x,
		mpk->pointP->y, mpk->q, bn_ctx))) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT,
			BFIBE_R_INVALID_TYPE1CURVE);
		goto end;
	}

	point = EC_POINT_new(group);
	point1 = EC_POINT_new(group);
	theta = BN_GFP2_new();
	k = BN_CTX_get(bn_ctx);

	if (!point || !point1 || !theta || !k) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* theta = e(ciphertext->u, sk->privateKey) */
	if (!EC_POINT_set_affine_coordinates_GFp(group, point,
		in->u->x, in->u->y, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(group, point1,
		sk->privateKey->x, sk->privateKey->y, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_type1curve_tate(group, theta, point, point1, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* md = mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, BFIBE_R_INVALID_BFIBE_HASHFUNC);
		goto end;
	}

	/* rho = Hash(Canoncial(theta)) xor ciphertext->v */
	size = sizeof(rho);
	if (!BN_GFP2_canonical(theta, rho, &size, 0, mpk->p, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	len = size;
	if (!EVP_Digest(rho, size, rho, &len, md, NULL)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	for (i = 0; i < EVP_MD_size(md); i++) {
		rho[i] ^= in->v->data[i];
	}

	/* function hash_bytes() = kdf(md) */
	if (!(hash_bytes = KDF_get_ibcs(md))) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT,
			BFIBE_R_INVALID_BFIBE_HASHFUNC);
		goto end;
	}

	/* out = HashBytes(rho) xor ciphertext->w */
	size = in->w->length;
	if (!hash_bytes(rho, EVP_MD_size(md), out, &size)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT,
			BFIBE_R_KDF_FAILURE);
		goto end;
	}
	for (i = 0; i < in->w->length; i++) {
		out[i] ^= in->w->data[i];
	}

	/* k = HashToRange(rho || Hash(out)) in [0, mpk->q) */
	len = EVP_MD_size(md);
	if (!EVP_Digest(out, in->w->length, rho + EVP_MD_size(md), &len, md, NULL)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	if (!BN_hash_to_range(md, &k, rho, EVP_MD_size(md) * 2, mpk->q, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_BN_LIB);
		goto end;
	}

	/* Verify that in->u == mpk->pointP * k */
	if (!EC_POINT_mul(group, point, k, NULL, NULL, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (1 != EC_POINT_cmp_fppoint(group, point, in->u, bn_ctx)) {
		BFIBEerr(BFIBE_F_BFIBE_DO_DECRYPT, BFIBE_R_BFIBE_CIPHERTEXT_FAILURE);
		goto end;
	}

	*outlen = in->w->length;
	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	EC_POINT_free(point1);
	BN_GFP2_free(theta);
	return ret;
}

/* estimation of the max length of DER encoded ciphertext */
static int BFCiphertextBlock_size(BFPublicParameters *mpk,
	size_t inlen, size_t *outlen)
{
	size_t len = 0;
	len += (OPENSSL_ECC_MAX_FIELD_BITS/8) * 2;
	len += inlen;
	len += EVP_MAX_MD_SIZE;
	len += 128; /* caused by version and DER encoding */
	*outlen = len;
	return 1;
}

int BFIBE_encrypt(BFPublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen)
{
	int ret = 0;
	BFCiphertextBlock *c = NULL;
	unsigned char *p;
	size_t len;

	if (!mpk || !in || inlen <= 0 || !outlen || !id || idlen <= 0) {
		BFIBEerr(BFIBE_F_BFIBE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!BFCiphertextBlock_size(mpk, inlen, &len)) {
		BFIBEerr(BFIBE_F_BFIBE_ENCRYPT, BFIBE_R_COMPUTE_OUTLEN_FAILURE);
		return 0;
	}
	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		BFIBEerr(BFIBE_F_BFIBE_ENCRYPT, BFIBE_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!(c = BFIBE_do_encrypt(mpk, in, inlen, id, idlen))) {
		BFIBEerr(BFIBE_F_BFIBE_ENCRYPT, BFIBE_R_ENCRYPT_FAILURE);
		goto end;
	}

	p = out;
	if (!i2d_BFCiphertextBlock(c, &p)) {
		BFIBEerr(BFIBE_F_BFIBE_ENCRYPT, BFIBE_R_I2D_FAILURE);
		goto end;
	}
	len = p - out;

	*outlen = len;
	ret = 1;

end:
	BFCiphertextBlock_free(c);
	return ret;
}

int BFIBE_decrypt(BFPublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	BFPrivateKeyBlock *sk)
{
	int ret = 0;
	BFCiphertextBlock *c = NULL;
	const unsigned char *p;

	if (!mpk || !in || inlen <= 0 || !outlen || !sk) {
		BFIBEerr(BFIBE_F_BFIBE_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!out) {
		*outlen = inlen;
		return 1;
	}
	if (*outlen < inlen) {
		BFIBEerr(BFIBE_F_BFIBE_DECRYPT, BFIBE_R_BUFFER_TOO_SMALL);
		return 0;
	}

	p = in;
	if (!(c = d2i_BFCiphertextBlock(NULL, &p, inlen))) {
		BFIBEerr(BFIBE_F_BFIBE_DECRYPT, BFIBE_R_D2I_FAILURE);
		goto end;
	}

	/* check no remaining ciphertext */
	if (p - in != inlen) {
		BFIBEerr(BFIBE_F_BFIBE_DECRYPT, BFIBE_R_INVALID_CIPHERTEXT);
		goto end;
	}

	if (!BFIBE_do_decrypt(mpk, c, out, outlen, sk)) {
		BFIBEerr(BFIBE_F_BFIBE_DECRYPT, BFIBE_R_DECRYPT_FAILURE);
		goto end;
	}

	ret = 1;
end:
	BFCiphertextBlock_free(c);
	return ret;
}

