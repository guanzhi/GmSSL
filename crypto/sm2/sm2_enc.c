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
#include <strings.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include "sm2.h"

int SM2_CIPHERTEXT_VALUE_size(const EC_GROUP *ec_group,
	point_conversion_form_t point_form, size_t mlen,
	const EVP_MD *mac_md)
{
	int ret = 0;
	EC_POINT *point = EC_POINT_new(ec_group);
	BN_CTX *bn_ctx = BN_CTX_new();
	size_t len;

	if (!point || !bn_ctx) {
		goto end;
	}

#if 0	
	//FIXME: len will be 1 !!!
	if (!(len = EC_POINT_point2oct(ec_group, point, point_form,
		NULL, 0, bn_ctx))) {
		goto end;
	}
#endif
	len = 1 + 2 * ((EC_GROUP_get_degree(ec_group) + 7)/8);
	len += mlen + EVP_MD_size(mac_md);

	ret = len;
end:
	if (point) EC_POINT_free(point);
	if (bn_ctx) BN_CTX_free(bn_ctx);
 	return ret;
}

void SM2_CIPHERTEXT_VALUE_free(SM2_CIPHERTEXT_VALUE *cv)
{
	if (cv->ephem_point) EC_POINT_free(cv->ephem_point);
	if (cv->ciphertext) OPENSSL_free(cv->ciphertext);
	bzero(cv, sizeof(SM2_CIPHERTEXT_VALUE));
	OPENSSL_free(cv);
}

int SM2_CIPHERTEXT_VALUE_encode(const SM2_CIPHERTEXT_VALUE *cv,
	const EC_GROUP *ec_group, point_conversion_form_t point_form,
	unsigned char *buf, size_t *buflen)
{
	int ret = 0;
	BN_CTX *bn_ctx = BN_CTX_new();
	size_t ptlen, cvlen;

	if (!bn_ctx) {
		return 0;
	}

	if (!(ptlen = EC_POINT_point2oct(ec_group, cv->ephem_point,
		point_form, NULL, 0, bn_ctx))) {
		goto end;
	}
	cvlen = ptlen + cv->ciphertext_size + cv->mactag_size;

	if (!buf) {
		*buflen = cvlen;
		ret = 1;
		goto end;

	} else if (*buflen < cvlen) {
		goto end;
	}

	if (!(ptlen = EC_POINT_point2oct(ec_group, cv->ephem_point,
		point_form, buf, *buflen, bn_ctx))) {
		goto end;
	}
	buf += ptlen;
	memcpy(buf, cv->ciphertext, cv->ciphertext_size);
	buf += cv->ciphertext_size;
	memcpy(buf, cv->mactag, cv->mactag_size);

	*buflen = cvlen;
	ret = 1;
end:
	if (bn_ctx) BN_CTX_free(bn_ctx);
	return ret;
}

SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_decode(const EC_GROUP *ec_group,
	point_conversion_form_t point_form, const EVP_MD *mac_md,
	const unsigned char *buf, size_t buflen)
{
	int ok = 0;
	SM2_CIPHERTEXT_VALUE *ret = NULL;
	BN_CTX *bn_ctx = BN_CTX_new();
	int ptlen;
	int fixlen;

	if (!bn_ctx) {
		return NULL;
	}

	if (!(fixlen = SM2_CIPHERTEXT_VALUE_size(ec_group, point_form, 0, mac_md))) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (buflen <= fixlen) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!(ret = OPENSSL_malloc(sizeof(SM2_CIPHERTEXT_VALUE)))) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}

	ret->ephem_point = EC_POINT_new(ec_group);
	ret->ciphertext_size = buflen - fixlen;
	ret->ciphertext = OPENSSL_malloc(ret->ciphertext_size);
	if (!ret->ephem_point || !ret->ciphertext) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}

	ptlen = fixlen - EVP_MD_size(mac_md);
	if (!EC_POINT_oct2point(ec_group, ret->ephem_point, buf, ptlen, bn_ctx)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stdout);
		goto end;
	}

	memcpy(ret->ciphertext, buf + ptlen, ret->ciphertext_size);
	ret->mactag_size = EVP_MD_size(mac_md);
	memcpy(ret->mactag, buf + buflen - ret->mactag_size, ret->mactag_size);

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

int SM2_encrypt_ex(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	point_conversion_form_t point_form,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	int len;

	if (!(len = SM2_CIPHERTEXT_VALUE_size(ec_group, point_form, inlen, mac_md))) {
		goto end;
	}

	if (!out) {
		*outlen = (size_t)len;
		return 1;

	} else if (*outlen < (size_t)len) {
		return 0;
	}

	if (!(cv = SM2_do_encrypt(kdf_md, mac_md, in, inlen, ec_key))) {
		goto end;
	}
	if (!SM2_CIPHERTEXT_VALUE_encode(cv, ec_group, point_form, out, outlen)) {
		goto end;
	}
	
	ret = 1;
end:
	if (cv) SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

SM2_CIPHERTEXT_VALUE *SM2_do_encrypt(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	int ok = 0;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
	KDF_FUNC kdf = KDF_get_x9_63(kdf_md);
	EC_POINT *point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BIGNUM *k = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	int nbytes;
	size_t len;
	int i;

	if (!ec_group || !pub_key) {
		goto end;
	}
	if (!kdf) {
		goto end;
	}

	/* init ciphertext_value */
	if (!(cv = OPENSSL_malloc(sizeof(SM2_CIPHERTEXT_VALUE)))) {
		goto end;
	}
	bzero(cv, sizeof(SM2_CIPHERTEXT_VALUE));
	cv->ephem_point = EC_POINT_new(ec_group);
	cv->ciphertext = OPENSSL_malloc(inlen);
	cv->ciphertext_size = inlen;
	if (!cv->ephem_point || !cv->ciphertext) {
		goto end;
	}

	point = EC_POINT_new(ec_group);
	n = BN_new();
	h = BN_new();
	k = BN_new();
	bn_ctx = BN_CTX_new();
	md_ctx = EVP_MD_CTX_create();
	if (!point || !n || !h || !k || !bn_ctx || !md_ctx) {
		goto end;
	}

	/* init ec domain parameters */
	if (!EC_GROUP_get_order(ec_group, n, bn_ctx)) {
		goto end;
	}
	if (!EC_GROUP_get_cofactor(ec_group, h, bn_ctx)) {
		goto end;
	}
	nbytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;


	//OPENSSL_assert(nbytes == BN_num_bytes(n));

#if 0
	/* check sm2 curve and md is 256 bits */
	OPENSSL_assert(nbytes == 32);
	OPENSSL_assert(EVP_MD_size(kdf_md) == 32);
	OPENSSL_assert(EVP_MD_size(mac_md) == 32);
#endif

	do
	{
		/* A1: rand k in [1, n-1] */
		do {
			BN_rand_range(k, n);
		} while (BN_is_zero(k));

	
		/* A2: C1 = [k]G = (x1, y1) */
		if (!EC_POINT_mul(ec_group, cv->ephem_point, k, NULL, NULL, bn_ctx)) {
			goto end;
		}
		
		/* A3: check [h]P_B != O */
		if (!EC_POINT_mul(ec_group, point, NULL, pub_key, h, bn_ctx)) {
			goto end;
		}
		if (EC_POINT_is_at_infinity(ec_group, point)) {
			goto end;
		}

		/* A4: compute ECDH [k]P_B = (x2, y2) */
		if (!EC_POINT_mul(ec_group, point, NULL, pub_key, k, bn_ctx)) {
			goto end;
		}
		if (!(len = EC_POINT_point2oct(ec_group, point,
			POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
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
	
	/* A7: C3 = Hash(x2 || M || y2) */
	if (!EVP_DigestInit_ex(md_ctx, mac_md, NULL)) {
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, buf + 1, nbytes)) {
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, in, inlen)) {
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)) {
		goto end;
	}
	if (!EVP_DigestFinal_ex(md_ctx, cv->mactag, &cv->mactag_size)) {
		goto end;
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

int SM2_decrypt_ex(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	point_conversion_form_t point_form,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	int len;

	if (!(len = SM2_CIPHERTEXT_VALUE_size(ec_group, point_form, 0, mac_md))) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}
	if (inlen <= len) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!out) {
		*outlen = inlen - len;
		return 1;
	} else if (*outlen < inlen - len) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		return 0;
	}

	if (!(cv = SM2_CIPHERTEXT_VALUE_decode(ec_group, point_form, mac_md, in, inlen))) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}
	if (!SM2_do_decrypt(kdf_md, mac_md, cv, out, outlen, ec_key)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}

	ret = 1;
end:
	if (cv) SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

int SM2_do_decrypt(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	const SM2_CIPHERTEXT_VALUE *cv, unsigned char *out, size_t *outlen,
	EC_KEY *ec_key)
{
	int ret = 0;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	const BIGNUM *pri_key = EC_KEY_get0_private_key(ec_key);
	KDF_FUNC kdf = KDF_get_x9_63(kdf_md);
	EC_POINT *point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen;
	int nbytes;
	size_t size;
	int i;

	OPENSSL_assert(kdf_md && mac_md && cv && ec_key);
	OPENSSL_assert(cv->ephem_point && cv->ciphertext);

	if (!ec_group || !pri_key) {
		goto end;
	}
	if (!kdf) {
		goto end;
	}

	if (!out) {
		*outlen = cv->ciphertext_size;
		return 1;
	}
	if (*outlen < cv->ciphertext_size) {
		goto end;
	}

	/* init vars */
	point = EC_POINT_new(ec_group);
	n = BN_new();
	h = BN_new();
	bn_ctx = BN_CTX_new();
	md_ctx = EVP_MD_CTX_create();
	if (!point || !n || !h || !bn_ctx || !md_ctx) {
		goto end;
	}
	
	/* init ec domain parameters */
	if (!EC_GROUP_get_order(ec_group, n, bn_ctx)) {
		goto end;
	}
	if (!EC_GROUP_get_cofactor(ec_group, h, bn_ctx)) {
		goto end;
	}
	nbytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;
	//OPENSSL_assert(nbytes == BN_num_bytes(n));

#if 0
	/* check sm2 curve and md is 256 bits */
	OPENSSL_assert(nbytes == 32);
	OPENSSL_assert(EVP_MD_size(kdf_md) == 32);
	OPENSSL_assert(EVP_MD_size(mac_md) == 32);
#endif

	/* B2: check [h]C1 != O */
	if (!EC_POINT_mul(ec_group, point, NULL, cv->ephem_point, h, bn_ctx)) {
		goto end;
	}
	if (EC_POINT_is_at_infinity(ec_group, point)) {
		goto end;
	}

	/* B3: compute ECDH [d]C1 = (x2, y2) */	
	if (!EC_POINT_mul(ec_group, point, NULL, cv->ephem_point, pri_key, bn_ctx)) {
		goto end;
	}
	if (!(size = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
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

	/* B6: check Hash(x2 || M || y2) == C3 */
	if (!EVP_DigestInit_ex(md_ctx, mac_md, NULL)) {
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, buf + 1, nbytes)) {
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, out, *outlen)) {
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)) {
		goto end;
	}
	if (!EVP_DigestFinal_ex(md_ctx, mac, &maclen)) {
		goto end;
	}
	if (cv->mactag_size != maclen ||
		memcmp(cv->mactag, mac, maclen)) {
		goto end;
	}

	ret = 1;
end:
	if (point) EC_POINT_free(point);
	if (n) BN_free(n);	
	if (h) BN_free(h);
	if (bn_ctx) BN_CTX_free(bn_ctx);
	if (md_ctx) EVP_MD_CTX_destroy(md_ctx);

	return ret;
}


int SM2_encrypt(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	const EVP_MD *kdf_md = EVP_sm3();
	const EVP_MD *mac_md = EVP_sm3();
	point_conversion_form_t point_form = SM2_DEFAULT_POINT_CONVERSION_FORM;
	
	return SM2_encrypt_ex(kdf_md, mac_md, point_form,
		in, inlen, out, outlen, ec_key);
}

int SM2_decrypt(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	const EVP_MD *kdf_md = EVP_sm3();
	const EVP_MD *mac_md = EVP_sm3();
	point_conversion_form_t point_form = SM2_DEFAULT_POINT_CONVERSION_FORM;

	return SM2_decrypt_ex(kdf_md, mac_md, point_form,
		in, inlen, out, outlen, ec_key);	
}

