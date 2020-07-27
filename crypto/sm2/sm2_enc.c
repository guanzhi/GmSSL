/*
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include "internal/o_str.h"
#include "sm2_lcl.h"

SM2CiphertextValue *SM2_do_encrypt(const EVP_MD *md,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	SM2CiphertextValue *ret = NULL;
	SM2CiphertextValue *cv = NULL;
	const EC_GROUP *group;
	const EC_POINT *pub_key;
	KDF_FUNC kdf;
	EC_POINT *ephem_point = NULL;
	EC_POINT *share_point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BIGNUM *k = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;

	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	int nbytes;
	size_t len;
	size_t i;
	unsigned int hashlen;

	/* check arguments */
	if (!md || !in || !ec_key) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (inlen <= 0 || inlen > SM2_MAX_PLAINTEXT_LENGTH) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_INVALID_PLAINTEXT_LENGTH);
		return 0;
	}

	if (!(kdf = KDF_get_x9_63(md))) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_INVALID_DIGEST_ALGOR);
		return 0;
	}

	if (!(group = EC_KEY_get0_group(ec_key))
		|| !(pub_key = EC_KEY_get0_public_key(ec_key))) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_INVALID_EC_KEY);
		return 0;
	}

	/* malloc */
	if (!(cv = SM2CiphertextValue_new())
		|| !(ephem_point = EC_POINT_new(group))
		|| !(share_point = EC_POINT_new(group))
		|| !(n = BN_new())
		|| !(h = BN_new())
		|| !(k = BN_new())
		|| !(bn_ctx = BN_CTX_new())
		|| !(md_ctx = EVP_MD_CTX_new())) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!ASN1_OCTET_STRING_set(cv->ciphertext, NULL, (int)inlen)
		|| !ASN1_OCTET_STRING_set(cv->hash, NULL, EVP_MD_size(md))) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_ASN1_LIB);
		goto end;
	}

	/* init ec domain parameters */
	if (!EC_GROUP_get_order(group, n, bn_ctx)) {
		ECerr(EC_F_SM2_DO_ENCRYPT, EC_R_ERROR);
		goto end;
	}

	if (!EC_GROUP_get_cofactor(group, h, bn_ctx)) {
		ECerr(EC_F_SM2_DO_ENCRYPT, EC_R_ERROR);
		goto end;
	}

	nbytes = (EC_GROUP_get_degree(group) + 7) / 8;

	/* check [h]P_B != O */
	if (!EC_POINT_mul(group, share_point, NULL, pub_key, h, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (EC_POINT_is_at_infinity(group, share_point)) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_INVALID_PUBLIC_KEY);
		goto end;
	}

	do
	{
		size_t size;

		/* rand k in [1, n-1] */
		do {
			BN_rand_range(k, n);
		} while (BN_is_zero(k));

		/* compute ephem_point [k]G = (x1, y1) */
		if (!EC_POINT_mul(group, ephem_point, k, NULL, NULL, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
			goto end;
		}

		/* compute ECDH share_point [k]P_B = (x2, y2) */
		if (!EC_POINT_mul(group, share_point, NULL, pub_key, k, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
			goto end;
		}

		/* compute t = KDF(x2 || y2, klen) */
		if (!(len = EC_POINT_point2oct(group, share_point,
			POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
			goto end;
		}

		size = cv->ciphertext->length;
		kdf(buf + 1, len - 1, cv->ciphertext->data, &size);
		if (size != inlen) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_KDF_FAILURE);
			goto end;
		}

		/* ASN1_OCTET_STRING_is_zero in asn1.h and a_octet.c */
	} while (ASN1_OCTET_STRING_is_zero(cv->ciphertext));

	/* set x/yCoordinates as (x1, y1) */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, ephem_point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, ephem_point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
			goto end;
		}
	}

	/* ciphertext = t xor in */
	for (i = 0; i < inlen; i++) {
		cv->ciphertext->data[i] ^= in[i];
	}

	/* generate hash = Hash(x2 || M || y2) */
	hashlen = cv->hash->length;
	if (!EVP_DigestInit_ex(md_ctx, md, NULL)
		|| !EVP_DigestUpdate(md_ctx, buf + 1, nbytes)
		|| !EVP_DigestUpdate(md_ctx, in, inlen)
		|| !EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)
		|| !EVP_DigestFinal_ex(md_ctx, cv->hash->data, &hashlen)) {
		SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	ret = cv;
	cv = NULL;

end:
	SM2CiphertextValue_free(cv);
	EC_POINT_free(share_point);
	EC_POINT_free(ephem_point);
	BN_free(n);
	BN_free(h);
	BN_clear_free(k);
	BN_CTX_free(bn_ctx);
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

int SM2_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	const EVP_MD *md;
	SM2CiphertextValue *cv = NULL;
	int clen;

	// check type 					
	if (!(md = EVP_get_digestbynid(type))) {
		SM2err(SM2_F_SM2_ENCRYPT, SM2_R_INVALID_DIGEST_ALGOR);
		return 0;
	}

	if (!(clen = SM2_ciphertext_size(ec_key, inlen))) {
		SM2err(SM2_F_SM2_ENCRYPT, ERR_R_SM2_LIB);
		return 0;
	}
	if (!out) {
		*outlen = clen;
		return 1;
	} else if (*outlen < (size_t)clen) {
		SM2err(SM2_F_SM2_ENCRYPT, SM2_R_BUFFER_TOO_SMALL);
		return 0;
	}

	RAND_seed(in, inlen);
	if (!(cv = SM2_do_encrypt(md, in, inlen, ec_key))) {
		SM2err(SM2_F_SM2_ENCRYPT, ERR_R_SM2_LIB);
		*outlen = 0;
		return 0;
	}

	if ((clen = i2d_SM2CiphertextValue(cv, &out)) <= 0) {
		SM2err(SM2_F_SM2_ENCRYPT, ERR_R_SM2_LIB);
		goto end;
	}

	*outlen = clen;
	ret = 1;

end:
	SM2CiphertextValue_free(cv);
	return ret;
}

int SM2_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	const EVP_MD *md;
	const unsigned char *p;
	SM2CiphertextValue *cv = NULL;

	/* check arguments */
	if (!(md = EVP_get_digestbynid(type))) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_DIGEST_ALGOR);
		*outlen = 0;
		return 0;
	}

	if (!in) {
		SM2err(SM2_F_SM2_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		*outlen = 0;
		return 0;
	}
	if (inlen <= 0 || inlen > INT_MAX) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_INPUT_LENGTH);
		*outlen = 0;
		return 0;
	}

	/* decode asn.1 and check no data remaining */
	p = in;
	if (!(cv = d2i_SM2CiphertextValue(NULL, &p, (long)inlen))) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
		return 0;
	}
	if (p != in + inlen) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
		goto end;
	}

	/* return or check output length */
	if (!out) {
		*outlen = ASN1_STRING_length(cv->ciphertext);
		ret = 1;
		goto end;
	}
	/*
	else if (*outlen < ASN1_STRING_length(cv->ciphertext)) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_BUFFER_TOO_SMALL);
		ret = 0;
		goto end;
	}
	*/

	/* do decrypt */
	if (!SM2_do_decrypt(md, cv, out, outlen, ec_key)) {
		SM2err(SM2_F_SM2_DECRYPT, SM2_R_DECRYPT_FAILURE);
		goto end;
	}

	ret = 1;

end:
	SM2CiphertextValue_free(cv);
	return ret;
}

int SM2_do_decrypt(const EVP_MD *md, const SM2CiphertextValue *cv,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	const EC_GROUP *group;
	const BIGNUM *pri_key;
	KDF_FUNC kdf;
	EC_POINT *point = NULL;
	EC_POINT *tmp_point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen = sizeof(mac);
	int nbytes, len, i;

	/* check arguments */
	if (!md || !cv || !outlen || !ec_key) {
		SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(kdf = KDF_get_x9_63(md))) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_DIGEST_ALGOR);
		return 0;
	}

	if (!cv->xCoordinate || !cv->yCoordinate || !cv->hash || !cv->ciphertext) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
		return 0;
	}

	if (cv->hash->length != EVP_MD_size(md)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
		return 0;
	}

	if (cv->ciphertext->length <= 0
		|| cv->ciphertext->length > SM2_MAX_PLAINTEXT_LENGTH) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
		return 0;
	}

	if (!(group = EC_KEY_get0_group(ec_key))
		|| !(pri_key = EC_KEY_get0_private_key(ec_key))) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_EC_KEY);
		return 0;
	}

	if (!out) {
		*outlen = cv->ciphertext->length;
		return 1;
	}
	/*
	if (*outlen < cv->ciphertext->length) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_BUFFER_TOO_SMALL);
		return 0;
	}
	*/

	/* malloc */
	point = EC_POINT_new(group);
	tmp_point = EC_POINT_new(group);
	n = BN_new();
	h = BN_new();
	bn_ctx = BN_CTX_new();
	md_ctx = EVP_MD_CTX_new();
	if (!point || !n || !h || !bn_ctx || !md_ctx) {
		SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* init ec domain parameters */
	if (!EC_GROUP_get_order(group, n, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_GROUP_get_cofactor(group, h, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	nbytes = (EC_GROUP_get_degree(group) + 7) / 8;

	/* get x/yCoordinates as C1 = (x1, y1) */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_set_affine_coordinates_GFp(group, point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
			goto end;
		}
	} else {
		if (!EC_POINT_set_affine_coordinates_GF2m(group, point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
			goto end;
		}
	}

	/* check [h]C1 != O */
	if (!EC_POINT_mul(group, tmp_point, NULL, point, h, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (EC_POINT_is_at_infinity(group, tmp_point)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
		goto end;
	}

	/* compute ECDH [d]C1 = (x2, y2) */
	if (!EC_POINT_mul(group, point, NULL, point, pri_key, bn_ctx)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (!(len = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
		SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* compute t = KDF(x2 || y2, clen) */
	*outlen = cv->ciphertext->length;
	kdf(buf + 1, len - 1, out, outlen);


	/* compute M = C2 xor t */
	for (i = 0; i < cv->ciphertext->length; i++) {
		out[i] ^= cv->ciphertext->data[i];
	}

	/* check hash == Hash(x2 || M || y2) */
	if (!EVP_DigestInit_ex(md_ctx, md, NULL)
		|| !EVP_DigestUpdate(md_ctx, buf + 1, nbytes)
		|| !EVP_DigestUpdate(md_ctx, out, *outlen)
		|| !EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)
		|| !EVP_DigestFinal_ex(md_ctx, mac, &maclen)) {
		SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	if (OPENSSL_memcmp(cv->hash->data, mac, maclen) != 0) {
		SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
		goto end;
	}

	ret = 1;
end:
	EC_POINT_free(point);
	EC_POINT_free(tmp_point);
	BN_free(n);
	BN_free(h);
	BN_CTX_free(bn_ctx);
	EVP_MD_CTX_free(md_ctx);
	return ret;
}
