/* crypto/sm2/sm2_enc.c */
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


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sm2.h>
#include "../o_str.h"

int SM2_CIPHERTEXT_VALUE_size(const EC_GROUP *group,
	const SM2_ENC_PARAMS *params, size_t mlen)
{
	int ret = 0;
	EC_KEY *ec_key = NULL;
	size_t len = 0;


	if (!(ec_key = EC_KEY_new())) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_SIZE, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_KEY_set_group(ec_key, group)) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_SIZE, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_KEY_generate_key(ec_key)) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_SIZE, ERR_R_EC_LIB);
		goto end;
	}

	len += EC_POINT_point2oct(group, EC_KEY_get0_public_key(ec_key),
		params->point_form, NULL, 0, NULL);
	len += mlen;
	len += params->mactag_size < 0 ? EVP_MD_size(params->mac_md) :
		params->mactag_size;

 	ret = (int)len;

end:
	EC_KEY_free(ec_key);
	return ret;
}

SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_new(const EC_GROUP *group)
{
	SM2_CIPHERTEXT_VALUE *cv;

	if (!(cv = OPENSSL_malloc(sizeof(*cv)))) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_NEW, SM2_R_MALLOC_FAILED);
		return NULL;
	}

	memset(cv, 0, sizeof(*cv));

	if (!(cv->ephem_point = EC_POINT_new(group))) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_NEW, SM2_R_POINT_NEW_FAILED);
		OPENSSL_free(cv);
		return NULL;
	}

	return cv;
}

void SM2_CIPHERTEXT_VALUE_free(SM2_CIPHERTEXT_VALUE *cv)
{
	if (cv->ephem_point) EC_POINT_free(cv->ephem_point);
	if (cv->ciphertext) OPENSSL_free(cv->ciphertext);
	memset(cv, 0, sizeof(*cv));
	OPENSSL_free(cv);
}

int SM2_CIPHERTEXT_VALUE_encode(const SM2_CIPHERTEXT_VALUE *cv,
	const EC_GROUP *ec_group, const SM2_ENC_PARAMS *params,
	unsigned char *buf, size_t *buflen)
{
	int ret = 0;
	BN_CTX *bn_ctx = BN_CTX_new();
	size_t ptlen, cvlen;

	OPENSSL_assert(cv);
	OPENSSL_assert(ec_group);
	OPENSSL_assert(buf);
	OPENSSL_assert(cv->ephem_point);

	if (!bn_ctx) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_ENCODE, ERR_R_BN_LIB);
		return 0;
	}

	if (!(ptlen = EC_POINT_point2oct(ec_group, cv->ephem_point,
		params->point_form, NULL, 0, bn_ctx))) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_ENCODE, SM2_R_POINT2OCT_FAILED);
		goto end;
	}
	cvlen = ptlen + cv->ciphertext_size + cv->mactag_size;

	if (!buf) {
		*buflen = cvlen;
		ret = 1;
		goto end;

	} else if (*buflen < cvlen) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_ENCODE, SM2_R_BUFFER_TOO_SMALL);
		goto end;
	}

	if (!(ptlen = EC_POINT_point2oct(ec_group, cv->ephem_point,
		params->point_form, buf, *buflen, bn_ctx))) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_ENCODE, SM2_R_POINT2OCT_FAILED);
		goto end;
	}
	buf += ptlen;
	memcpy(buf, cv->ciphertext, cv->ciphertext_size);
	buf += cv->ciphertext_size;
	if (cv->mactag_size > 0) {
		memcpy(buf, cv->mactag, cv->mactag_size);
	}

	*buflen = cvlen;
	ret = 1;
end:
	if (bn_ctx) BN_CTX_free(bn_ctx);
	return ret;
}

SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_decode(
	const EC_GROUP *ec_group, const SM2_ENC_PARAMS *params,
	const unsigned char *buf, size_t buflen)
{
	int ok = 0;
	SM2_CIPHERTEXT_VALUE *ret = NULL;
	BN_CTX *bn_ctx = BN_CTX_new();
	int ptlen;
	int fixlen;

	if (!bn_ctx) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_DECODE, ERR_R_BN_LIB);
		return NULL;
	}

	if (!(fixlen = SM2_CIPHERTEXT_VALUE_size(ec_group, params, 0))) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_DECODE, SM2_R_GET_CIPHERTEXT_SIZE_FAILED);
		goto end;
	}

	if (buflen <= fixlen) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_DECODE, SM2_R_BUFFER_TOO_SMALL);
		goto end;
	}

	if (!(ret = OPENSSL_malloc(sizeof(SM2_CIPHERTEXT_VALUE)))) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_DECODE, SM2_R_MALLOC_FAILED);
		goto end;
	}

	ret->ephem_point = EC_POINT_new(ec_group);
	ret->ciphertext_size = buflen - fixlen;
	ret->ciphertext = OPENSSL_malloc(ret->ciphertext_size);
	if (!ret->ephem_point || !ret->ciphertext) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_DECODE, SM2_R_INNOR_ERROR);
		goto end;
	}

	ptlen = fixlen - SM2_ENC_PARAMS_mactag_size(params);
	if (!EC_POINT_oct2point(ec_group, ret->ephem_point, buf, ptlen, bn_ctx)) {
		SM2err(SM2_F_SM2_CIPHERTEXT_VALUE_DECODE, SM2_R_OCT2POINT_FAILED);
		goto end;
	}

	memcpy(ret->ciphertext, buf + ptlen, ret->ciphertext_size);
	ret->mactag_size = SM2_ENC_PARAMS_mactag_size(params);
	if (ret->mactag_size > 0) {
		memcpy(ret->mactag, buf + buflen - ret->mactag_size, ret->mactag_size);
	}
	ok = 1;

end:
	if (!ok && ret) {
		SM2_CIPHERTEXT_VALUE_free(ret);
		ret = NULL;
	}
	if (bn_ctx) BN_CTX_free(bn_ctx);

	return ret;
}

int SM2_CIPHERTEXT_VALUE_print(BIO *out, const EC_GROUP *ec_group,
	const SM2_CIPHERTEXT_VALUE *cv, int indent, unsigned long flags)
{
	int ret = 0;
	char *hex = NULL;
	BN_CTX *ctx = BN_CTX_new();
	int i;

	if (!ctx) {
		goto end;
	}

	if (!(hex = EC_POINT_point2hex(ec_group, cv->ephem_point,
		POINT_CONVERSION_UNCOMPRESSED, ctx))) {
		goto end;
	}

	BIO_printf(out, "SM2_CIPHERTEXT_VALUE.ephem_point: %s\n", hex);
	BIO_printf(out, "SM2_CIPHERTEXT_VALUE.ciphertext : ");
	for (i = 0; i < cv->ciphertext_size; i++) {
		BIO_printf(out, "%02X", cv->ciphertext[i]);
	}
	BIO_printf(out, "\n");
	BIO_printf(out, "SM2_CIPHERTEXT_VALUE.mactag :");
	for (i = 0; i < cv->mactag_size; i++) {
		BIO_printf(out, "%02X", cv->mactag[i]);
	}
	BIO_printf(out, "\n");

	ret = 1;

end:
	OPENSSL_free(hex);
	BN_CTX_free(ctx);
	return 0;
}

int SM2_encrypt(const SM2_ENC_PARAMS *params,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen,
	EC_KEY *ec_key)
{
	int ret = 0;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	int len;

	if (!(len = SM2_CIPHERTEXT_VALUE_size(ec_group, params, inlen))) {
		SM2err(SM2_F_SM2_ENCRYPT, SM2_R_ERROR);
		goto end;
	}

	if (!out) {
		*outlen = (size_t)len;
		return 1;

	} else if (*outlen < (size_t)len) {
		SM2err(SM2_F_SM2_ENCRYPT, SM2_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!(cv = SM2_do_encrypt(params, in, inlen, ec_key))) {
		SM2err(SM2_F_SM2_ENCRYPT, SM2_R_ENCRYPT_FAILED);
		goto end;
	}

	if (!SM2_CIPHERTEXT_VALUE_encode(cv, ec_group, params, out, outlen)) {
		SM2err(SM2_F_SM2_ENCRYPT, SM2_R_CIPHERTEXT_ENCODE_FAILED);
		goto end;
	}

	ret = 1;
end:
	if (cv) SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

SM2_CIPHERTEXT_VALUE *SM2_do_encrypt(const SM2_ENC_PARAMS *params,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	int ok = 0;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
	KDF_FUNC kdf = KDF_get_x9_63(params->kdf_md);
	EC_POINT *point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BIGNUM *k = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	int nbytes;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	int mactag_size;
	size_t len;
	int i;

	if (!ec_group || !pub_key) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_INVALID_EC_KEY);
		goto end;
	}
	if (!kdf) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_GET_KDF_FAILED);
		goto end;
	}

	/* init ciphertext_value */
	if (!(cv = OPENSSL_malloc(sizeof(SM2_CIPHERTEXT_VALUE)))) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_MALLOC_FAILED);
		goto end;
	}
	memset(cv, 0, sizeof(*cv));
	cv->ephem_point = EC_POINT_new(ec_group);
	cv->ciphertext = OPENSSL_malloc(inlen);
	cv->ciphertext_size = inlen;
	if (!cv->ephem_point || !cv->ciphertext) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
		goto end;
	}

	point = EC_POINT_new(ec_group);
	n = BN_new();
	h = BN_new();
	k = BN_new();
	bn_ctx = BN_CTX_new();
	md_ctx = EVP_MD_CTX_create();
	if (!point || !n || !h || !k || !bn_ctx || !md_ctx) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
		goto end;
	}

	/* init ec domain parameters */
	if (!EC_GROUP_get_order(ec_group, n, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
		goto end;
	}
	if (!EC_GROUP_get_cofactor(ec_group, h, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
		goto end;
	}
	nbytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;

	do
	{
		/* A1: rand k in [1, n-1] */
		do {
			BN_rand_range(k, n);
		} while (BN_is_zero(k));


		/* A2: C1 = [k]G = (x1, y1) */
		if (!EC_POINT_mul(ec_group, cv->ephem_point, k, NULL, NULL, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}

		/* A3: check [h]P_B != O */
		if (!EC_POINT_mul(ec_group, point, NULL, pub_key, h, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}
		if (EC_POINT_is_at_infinity(ec_group, point)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}

		/* A4: compute ECDH [k]P_B = (x2, y2) */
		if (!EC_POINT_mul(ec_group, point, NULL, pub_key, k, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!(len = EC_POINT_point2oct(ec_group, point,
			POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}
		OPENSSL_assert(len == nbytes * 2 + 1);

		/* A5: t = KDF(x2 || y2, klen) */
		kdf(buf + 1, len - 1, cv->ciphertext, &cv->ciphertext_size);

		for (i = 0; i < cv->ciphertext_size; i++) {
			if (cv->ciphertext[i]) {
				break;
			}
		}
		if (i == cv->ciphertext_size) {
			continue;
		}

		break;

	} while (1);


	/* A6: C2 = M xor t */
	for (i = 0; i < inlen; i++) {
		cv->ciphertext[i] ^= in[i];
	}

	mactag_size = SM2_ENC_PARAMS_mactag_size(params);
	if (mactag_size) {

		/* A7: C3 = Hash(x2 || M || y2) */
		if (!EVP_DigestInit_ex(md_ctx, params->mac_md, NULL)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, buf + 1, nbytes)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, in, inlen)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!EVP_DigestFinal_ex(md_ctx, dgst, &dgstlen)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}

		/* GmSSL specific: reduce mactag size */
		if (mactag_size > dgstlen) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_ERROR);
			goto end;
		}

		cv->mactag_size = mactag_size;
		memcpy(cv->mactag, dgst, cv->mactag_size);
	}

	ok = 1;

end:
	if (!ok && cv) {
		SM2_CIPHERTEXT_VALUE_free(cv);
		cv = NULL;
	}

	if (point) EC_POINT_free(point);
	if (n) BN_free(n);
	if (h) BN_free(h);
	if (k) BN_free(k);
	if (bn_ctx) BN_CTX_free(bn_ctx);
	if (md_ctx) EVP_MD_CTX_destroy(md_ctx);

	return cv;
}

int SM2_decrypt(const SM2_ENC_PARAMS *params,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen,
	EC_KEY *ec_key)
{
	int ret = 0;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	int len;

	if (!(len = SM2_CIPHERTEXT_VALUE_size(ec_group, params, 0))) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	if (inlen <= len) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_ERROR);
		goto end;
	}

	if (!out) {
		*outlen = inlen - len;
		return 1;
	} else if (*outlen < inlen - len) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_ERROR);
		return 0;
	}

	if (!(cv = SM2_CIPHERTEXT_VALUE_decode(ec_group, params, in, inlen))) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	if (!SM2_do_decrypt(params, cv, out, outlen, ec_key)) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_ERROR);
		goto end;
	}

	ret = 1;
end:
	if (cv) SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

int SM2_do_decrypt(const SM2_ENC_PARAMS *params,
	const SM2_CIPHERTEXT_VALUE *cv, unsigned char *out, size_t *outlen,
	EC_KEY *ec_key)
{
	int ret = 0;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	const BIGNUM *pri_key = EC_KEY_get0_private_key(ec_key);
	KDF_FUNC kdf = KDF_get_x9_63(params->kdf_md);
	EC_POINT *point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen;
	int mactag_size;
	int nbytes;
	size_t size;
	int i;

	if (!ec_group || !pri_key) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	if (!kdf) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}

	if (!out) {
		*outlen = cv->ciphertext_size;
		return 1;
	}
	if (*outlen < cv->ciphertext_size) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}

	/* init vars */
	point = EC_POINT_new(ec_group);
	n = BN_new();
	h = BN_new();
	bn_ctx = BN_CTX_new();
	md_ctx = EVP_MD_CTX_create();
	if (!point || !n || !h || !bn_ctx || !md_ctx) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	
	/* init ec domain parameters */
	if (!EC_GROUP_get_order(ec_group, n, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	if (!EC_GROUP_get_cofactor(ec_group, h, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	nbytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;

	/* B2: check [h]C1 != O */
	if (!EC_POINT_mul(ec_group, point, NULL, cv->ephem_point, h, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	if (EC_POINT_is_at_infinity(ec_group, point)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}

	/* B3: compute ECDH [d]C1 = (x2, y2) */	
	if (!EC_POINT_mul(ec_group, point, NULL, cv->ephem_point, pri_key, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	if (!(size = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
		goto end;
	}
	OPENSSL_assert(size == 1 + nbytes * 2);

	/* B4: compute t = KDF(x2 || y2, clen) */

	*outlen = cv->ciphertext_size; //FIXME: duplicated code
	kdf(buf + 1, size - 1, out, outlen);


	/* B5: compute M = C2 xor t */
	for (i = 0; i < cv->ciphertext_size; i++) {
		out[i] ^= cv->ciphertext[i];
	}
	*outlen = cv->ciphertext_size;

	mactag_size = SM2_ENC_PARAMS_mactag_size(params);
	if (mactag_size) {

		/* B6: check Hash(x2 || M || y2) == C3 */
		if (!EVP_DigestInit_ex(md_ctx, params->mac_md, NULL)) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, buf + 1, nbytes)) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, out, *outlen)) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
			goto end;
		}
		if (!EVP_DigestFinal_ex(md_ctx, mac, &maclen)) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
			goto end;
		}

		/* GmSSL specific */
		if (mactag_size > maclen) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
			goto end;
		}
		if (cv->mactag_size != mactag_size ||
			OPENSSL_memcmp(mac, cv->mactag, cv->mactag_size)) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_ERROR);
			goto end;
		}
	}

	ret = 1;
end:
	EC_POINT_free(point);
	BN_free(n);
	BN_free(h);
	BN_CTX_free(bn_ctx);
	EVP_MD_CTX_destroy(md_ctx);

	return ret;
}

int SM2_ENC_PARAMS_init_with_recommended(SM2_ENC_PARAMS *params)
{
	if (!params) {
		SM2err(SM2_F_SM2_ENC_PARAMS_INIT_WITH_RECOMMENDED,
			SM2_R_NULL_ARGUMENT);
		return 0;
	}
	params->kdf_md = EVP_sm3();
	params->mac_md = EVP_sm3();
	params->mactag_size = -1;
	params->point_form = POINT_CONVERSION_UNCOMPRESSED;
	return 1;
}

int SM2_encrypt_with_recommended(unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	SM2_ENC_PARAMS params;
	SM2_ENC_PARAMS_init_with_recommended(&params);
	return SM2_encrypt(&params, out, outlen, in, inlen, ec_key);
}

int SM2_decrypt_with_recommended(unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	SM2_ENC_PARAMS params;
	SM2_ENC_PARAMS_init_with_recommended(&params);
	return SM2_decrypt(&params, out, outlen, in, inlen, ec_key);
}

int SM2_encrypt_elgamal(unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	SM2_ENC_PARAMS params;
	params.kdf_md = EVP_sm3();
	params.mac_md = EVP_sm3();
	params.mactag_size = 0;
	params.point_form = POINT_CONVERSION_COMPRESSED;
	return SM2_encrypt(&params, out, outlen, in, inlen, ec_key);
}

int SM2_decrypt_elgamal(unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	SM2_ENC_PARAMS params;
	params.kdf_md = EVP_sm3();
	params.mac_md = EVP_sm3();
	params.mactag_size = 0;
	params.point_form = POINT_CONVERSION_COMPRESSED;
	return SM2_decrypt(&params, out, outlen, in, inlen, ec_key);
}

