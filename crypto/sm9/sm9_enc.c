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
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sm9.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/kdf2.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <openssl/bn_gfp2.h>
#include <openssl/ec_type1.h>
#include "sm9_lcl.h"

/*
 * the encoded length of a point over E/F_p^k, k = 1, 2, 12 or others
 * the encoding method can be DER or canonical
 * the output is the about (2 * p * k) with some extra encoding bytes
 */
static int SM9PublicParameters_get_point_size(SM9PublicParameters *mpk,
	size_t *outlen)
{
	size_t size;
	int nbytes;
	BN_ULONG k;

	if (!mpk || !mpk->p || !mpk->k || !outlen) {
		SM9err(SM9_F_SM9PUBLICPARAMETERS_GET_POINT_SIZE,
			ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if ((nbytes = BN_num_bytes(mpk->p)) <= 0) {
		SM9err(SM9_F_SM9PUBLICPARAMETERS_GET_POINT_SIZE,
			SM9_R_INVALID_PARAMETER);
		return 0;
	}

	k = BN_get_word(mpk->k);
	if (k <= 0 || k > 12) {
		SM9err(SM9_F_SM9PUBLICPARAMETERS_GET_POINT_SIZE,
			SM9_R_INVALID_PARAMETER);
		return 0;
	}

	/* major length is from x, y coordintates over F_p^k */
	size = 2 * nbytes * k;

	/* extra length of TLV encoding
	 * hope 16-byte for every field element encoding is enough
	 */
	size += 16 * (k + 1);

	*outlen = size;
	return 1;
}

int SM9_wrap_key_ex(SM9PublicParameters *mpk, size_t keylen,
	unsigned char *outkey, unsigned char *outcipher, size_t *outcipherlen,
	SM9PublicKey *pk)
{
	return 0;
}

int SM9_wrap_key(SM9PublicParameters *mpk, size_t keylen,
	unsigned char *outkey, unsigned char *outcipher, size_t *outcipherlen,
	const char *id, size_t idlen)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *Ppub = NULL;
	BN_GFP2 *w = NULL;
	unsigned char *buf = NULL;
	BIGNUM *h;
	BIGNUM *r;
	unsigned char *pbuf;
	const EVP_MD *md;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	size_t size;
	size_t buflen;
	size_t outlen;
	size_t wlen;
	KDF_FUNC kdf_func;

	if (!mpk || !outkey || !outcipherlen || !id) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (keylen <= 0 || keylen > 4096) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_KEY_LENGTH);
		return 0;
	}
	if (idlen <= 0 || idlen > SM9_MAX_ID_LENGTH || strlen(id) != idlen) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_ID);
		return 0;
	}

	/*
	 * get outlen
	 * outcipher length is encoded point on curve E/F_p^k
	 */
	if (!SM9PublicParameters_get_point_size(mpk, &outlen)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_SM9_LIB);
		return 0;
	}
	if (!outcipher) {
		*outcipherlen = outlen;
		return 1;
	}
	if (*outcipherlen < outlen) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_BUFFER_TOO_SMALL);
		return 0;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve_ex(mpk->p,
		mpk->a, mpk->b, mpk->pointP1->data, mpk->pointP1->length,
		mpk->order, mpk->cofactor, bn_ctx))) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	point = EC_POINT_new(group);
	Ppub = EC_POINT_new(group);
	w = BN_GFP2_new();
	h = BN_CTX_get(bn_ctx);
	r = BN_CTX_get(bn_ctx);

	if (!point || !Ppub || !w || !h || !r) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* get md = mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* h = H1(ID||hid) in range [0, mpk->order] */
	if (!SM9_hash1(md, &h, id, idlen, SM9_HID_ENC, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_HASH_FAILURE);
		goto end;
	}

	/* point = mpk->pointP1 * h */
	if (!EC_POINT_mul(group, point, h, NULL, NULL, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* Ppub = mpk->pointPpub */
	if (!EC_POINT_oct2point(group, Ppub,
		mpk->pointPpub->data, mpk->pointPpub->length, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* point = point + Ppub = P1 * H1(ID||hid) + Ppub*/
	if (!EC_POINT_add(group, point, point, Ppub, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* rand r in (0, mpk->order) */
	do {
		if (!BN_rand_range(r, mpk->order)) {
			SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(r));

	/* point = point * r = (P1 * H(ID||hid) + Ppub) * r */
	if (!EC_POINT_mul(group, point, NULL, point, r, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* output outcipher = point */
	if (!(outlen = EC_POINT_point2oct(group, point, point_form,
		outcipher, outlen, bn_ctx))) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}
	*outcipherlen = outlen;

	/* get w = mpk->g2 = e(Ppub, P2) in F_p^2 */
	if (!BN_bn2gfp2(mpk->g2, w, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* w = w^r in F_p^2 */
	if (!BN_GFP2_exp(w, w, r, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* get wlen */
	if (!BN_GFP2_canonical(w, NULL, &wlen, 0, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* buflen = outlen + wlen + idlen
	 * buf is used for KDF to generate the output key
	 */
	buflen = outlen + wlen + idlen;

	/* malloc buf */
	if (!(buf = OPENSSL_malloc(buflen))) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* copy outcipher to buf */
	memcpy(buf, outcipher, outlen);

	/* canonical w to buf */
	pbuf = buf + outlen;
	size = wlen;
	if (!BN_GFP2_canonical(w, pbuf, &size, 0, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
		goto end;
	}
	pbuf += size;

	/* copy id to buf */
	memcpy(pbuf, id, idlen);

	/* output key = KDF(C||w||ID), |key| = keylen */
	if (!(kdf_func = KDF_get_x9_63(md))) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_MD);
		goto end;
	}
	size = keylen;
	if (!kdf_func(buf, buflen, outkey, &size)) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_KDF_FAILURE);
		goto end;
	}

	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	EC_POINT_free(Ppub);
	BN_GFP2_free(w);
	OPENSSL_free(buf);
	return ret;
}

int SM9_unwrap_key_ex(SM9PublicParameters *mpk, size_t keylen,
	const unsigned char *incipher, size_t incipherlen,
	unsigned char *outkey,
	SM9PublicKey *pk, SM9PrivateKey *sk)
{
	return 0;
}

int SM9_unwrap_key(SM9PublicParameters *mpk, size_t keylen,
	const unsigned char *incipher, size_t incipherlen,
	unsigned char *outkey,
	const char *id, size_t idlen, SM9PrivateKey *sk)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *point1 = NULL;
	BN_GFP2 *w = NULL;
	unsigned char *buf = NULL;
	unsigned char *pbuf;
	size_t buflen, wlen;
	const EVP_MD *md;
	KDF_FUNC kdf_func;
	int i;
	size_t outlen;

	if (!mpk || !incipher || !outkey || !id || !sk) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (keylen <= 0 || keylen >= 1024) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, SM9_R_INVALID_PARAMETER);
		return 0;
	}
	if (id <= 0 || idlen > SM9_MAX_ID_LENGTH || strlen(id) != idlen) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, SM9_R_INVALID_PARAMETER);
		return 0;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve_ex(mpk->p,
		mpk->a, mpk->b, mpk->pointP1->data, mpk->pointP1->length,
		mpk->order, mpk->cofactor, bn_ctx))) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* malloc */
	point = EC_POINT_new(group);
	point1 = EC_POINT_new(group);
	w = BN_GFP2_new();

	if (!point || !point1 || !w) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* point decoded from incipher in curve */
	if (!EC_POINT_oct2point(group, point, incipher, incipherlen, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* point1 decoded from sk->privatePoint */
	if (!EC_POINT_oct2point(group, point1,
		sk->privatePoint->data, sk->privatePoint->length, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* w = e(point, sk->privatePoint) in F_p^2 */
	if (!EC_type1curve_tate(group, w, point, point1, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* wbuflen is canonical w length */
	if (!BN_GFP2_canonical(w, NULL, &wlen, 0, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* buflen = incipherlen + wlen + idlen */
	buflen = incipherlen + wlen + idlen;

	/* buf = malloc(buflen) */
	if (!(buf = OPENSSL_malloc(buflen))) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}
	pbuf = buf;

	/* copy incipher to buf */
	memcpy(pbuf, incipher, incipherlen);
	pbuf += incipherlen;

	/* canonical w to buf */
	if (!BN_GFP2_canonical(w, pbuf, &wlen, 0, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}
	pbuf += wlen;

	/* copy id to buf */
	memcpy(pbuf, id, idlen);

	/* outkey = KDF(buf, outkeylen) */
	if (!(kdf_func = KDF_get_x9_63(md))) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}
	outlen = keylen;
	if (!kdf_func(buf, buflen, outkey, &outlen)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* is outkey is all zero, return failed */
	for (i = 0; (i < keylen) && (outkey[i] == 0); i++) {           
	}
	if (i == keylen) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	EC_POINT_free(point1);
	BN_GFP2_free(w);
	OPENSSL_free(buf);
	return ret;
}

static int SM9EncParameters_get_key_length(const SM9EncParameters *encparams,
	size_t inlen, size_t *enckeylen, size_t *mackeylen)
{
	int len;

	if (encparams->enc_cipher) {
		len = EVP_CIPHER_key_length(encparams->enc_cipher);
		if (len <= 0 || len > 256/8) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GET_KEY_LENGTH,
				SM9_R_INVALID_ENCPARAMETERS);
			return 0;
		}
		*enckeylen = (size_t)len;

	}  else {
		*enckeylen = inlen;
	}

	if (encparams->hmac_md &&
		!encparams->cmac_cipher && !encparams->cbcmac_cipher) {
		len = EVP_MD_size(encparams->hmac_md);
		if (len <= 0 || len > EVP_MAX_MD_SIZE) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GET_KEY_LENGTH,
				SM9_R_INVALID_ENCPARAMETERS);
			return 0;
		}
		*mackeylen = (size_t)len;
	} else if (encparams->cmac_cipher &&
		!encparams->hmac_md && !encparams->cbcmac_cipher) {
		len = EVP_CIPHER_key_length(encparams->cmac_cipher);
		if (len <= 0 || len > 256/8) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GET_KEY_LENGTH,
				SM9_R_INVALID_ENCPARAMETERS);
			return 0;
		}
		*enckeylen = (size_t)len;
	} else if (encparams->cbcmac_cipher &&
		!encparams->hmac_md && !encparams->cmac_cipher) {
		len = EVP_CIPHER_key_length(encparams->cbcmac_cipher);
		if (len <= 0 || len > 256/8) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GET_KEY_LENGTH,
				SM9_R_INVALID_ENCPARAMETERS);
			return 0;
		}
		*enckeylen = (size_t)len;
	} else {
		SM9err(SM9_F_SM9ENCPARAMETERS_GET_KEY_LENGTH,
			SM9_R_INVALID_ENCPARAMETERS);
		return 0;
	}

	return 1;
}

static int SM9EncParameters_encrypt(const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const unsigned char *key)
{
	int ret = 0;
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	size_t size;

	if (!encparams || !in || !outlen || !key) {
		SM9err(SM9_F_SM9ENCPARAMETERS_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (inlen <= 0 || inlen > 1024) {
		SM9err(SM9_F_SM9ENCPARAMETERS_ENCRYPT, SM9_R_INVALID_INPUT);
		return 0;
	}

	if (encparams->enc_cipher) {
		size = inlen + 16 * 3;
	} else {
		size = inlen;
	}

	if (!out) {
		*outlen = size;
		return 1;
	}
	if (*outlen < size) {
		SM9err(SM9_F_SM9ENCPARAMETERS_ENCRYPT, SM9_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (encparams->enc_cipher) {
		unsigned char *iv;
		unsigned char *p;
		int ivlen, len;

		/* output iv */
		iv = out;
		ivlen = EVP_CIPHER_iv_length(encparams->enc_cipher);
		RAND_bytes(iv, ivlen);

		/* encrypt */
		if (!(cipher_ctx = EVP_CIPHER_CTX_new())) {
			SM9err(SM9_F_SM9ENCPARAMETERS_ENCRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!EVP_EncryptInit(cipher_ctx, encparams->enc_cipher, key, iv)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_ENCRYPT, ERR_R_EVP_LIB);
			goto end;
		}

		p = out + ivlen;

		if (!EVP_EncryptUpdate(cipher_ctx, p, &len, in, inlen)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_ENCRYPT, ERR_R_EVP_LIB);
			goto end;
		}
		p += len;

		if (!EVP_EncryptFinal(cipher_ctx, p, &len)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_ENCRYPT, ERR_R_EVP_LIB);
			goto end;
		}
		p += len;

		size = p - out;

	} else {
		size_t i;

		for (i = 0; i < inlen; i++) {
			out[i] = key[i] ^ in[i];
		}

		size = inlen;
	}

	*outlen = size;
	ret = 1;

end:
	EVP_CIPHER_CTX_free(cipher_ctx);
	return ret;
}

static int SM9EncParameters_decrypt(const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const unsigned char *key)
{
	int ret = 0;
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	size_t size;

	if (!encparams || !in || !outlen || !key) {
		SM9err(SM9_F_SM9ENCPARAMETERS_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (inlen <= 0 || inlen > 1024) {
		SM9err(SM9_F_SM9ENCPARAMETERS_DECRYPT, SM9_R_INVALID_INPUT);
		return 0;
	}

	size = inlen;
	if (!out) {
		*outlen = size;
		return 1;
	}
	if (*outlen < size) {
		SM9err(SM9_F_SM9ENCPARAMETERS_DECRYPT, SM9_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (encparams->enc_cipher) {
		const unsigned char *iv;
		unsigned char *p;
		int ivlen, len;

		/* output iv */
		iv = in;
		ivlen = EVP_CIPHER_iv_length(encparams->enc_cipher);
		if (inlen <= (size_t)ivlen) {
			SM9err(SM9_F_SM9ENCPARAMETERS_DECRYPT, SM9_R_INVALID_CIPHERTEXT);
			goto end;
		}

		/* encrypt */
		if (!(cipher_ctx = EVP_CIPHER_CTX_new())) {
			SM9err(SM9_F_SM9ENCPARAMETERS_DECRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!EVP_DecryptInit(cipher_ctx, encparams->enc_cipher, key, iv)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_DECRYPT, ERR_R_EVP_LIB);
			goto end;
		}

		in = in + ivlen;
		inlen = inlen - ivlen;
		p = out;

		if (!EVP_DecryptUpdate(cipher_ctx, p, &len, in, inlen)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_DECRYPT, ERR_R_EVP_LIB);
			goto end;
		}
		p += len;

		if (!EVP_DecryptFinal(cipher_ctx, p, &len)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_DECRYPT, ERR_R_EVP_LIB);
			goto end;
		}
		p += len;

		size = p - out;

	} else  {
		size_t i;
		for (i = 0; i < inlen; i++) {
			out[i] = key[i] ^ in[i];
		}
		size = inlen;
	}

	*outlen = size;
	ret = 1;

end:
	EVP_CIPHER_CTX_free(cipher_ctx);
	return ret;
}

/*
 * don't need input keylen because keylen can be get from encparams,
 * this makes the API simpler and with less error
 */
static int SM9EncParameters_generate_mac(const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *mac, size_t *maclen,
	const unsigned char *key)
{
	int ret = 0;
	HMAC_CTX *hmac_ctx = NULL;
	CMAC_CTX *cmac_ctx = NULL;
	CMAC_CTX *cbcmac_ctx = NULL;
	size_t size;
	size_t mackeylen;
	unsigned int len;

	if (!encparams || !in || !maclen || !key) {
		SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!mac) {
		*maclen = EVP_MAX_MD_SIZE;
		return 1;
	}
	/* require outbuf enough to hold max HMAC tag */
	if (*maclen < EVP_MAX_MD_SIZE) {
		SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC,
			SM9_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!SM9EncParameters_get_key_length(encparams, inlen, &size, &mackeylen)) {
		SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, ERR_R_SM9_LIB);
		goto end;
	}

	if (encparams->hmac_md &&
		!encparams->cmac_cipher && !encparams->cbcmac_cipher) {
		if (!(hmac_ctx = HMAC_CTX_new())) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!HMAC_Init_ex(hmac_ctx, key, mackeylen, encparams->hmac_md, NULL)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		if (!HMAC_Update(hmac_ctx, in, inlen)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		if (!HMAC_Final(hmac_ctx, mac, &len)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		*maclen = (size_t)len;

	} else if (encparams->cmac_cipher &&
		!encparams->hmac_md && !encparams->cbcmac_cipher) {
		if (!(cmac_ctx = CMAC_CTX_new())) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(cmac_ctx, key, mackeylen, encparams->cmac_cipher, NULL)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		if (!CMAC_Update(cmac_ctx, in, inlen)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		if (!CMAC_Final(cmac_ctx, mac, &size)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		*maclen = size;

	} else if (encparams->cbcmac_cipher &&
		!encparams->hmac_md && !encparams->cmac_cipher) {
		if (!(cbcmac_ctx = CMAC_CTX_new())) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(cbcmac_ctx, key, mackeylen, encparams->cbcmac_cipher, NULL)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		if (!CMAC_Update(cbcmac_ctx, in, inlen)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		if (!CMAC_Final(cbcmac_ctx, mac, &size)) {
			SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_GENERATE_MAC_FAILURE);
			goto end;
		}
		*maclen = size;

	} else {
		SM9err(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC, SM9_R_INVALID_PARAMETER);
		goto end;
	}

	ret = 1;
end:
	HMAC_CTX_free(hmac_ctx);
	CMAC_CTX_free(cmac_ctx);
	CMAC_CTX_free(cbcmac_ctx);
	return ret;
}

SM9Ciphertext *SM9_do_encrypt_ex(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	SM9PublicKey *pk)
{
	return NULL;
}

SM9Ciphertext *SM9_do_encrypt(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	const char *id, size_t idlen)
{
	int e = 1;
	SM9Ciphertext *ret = NULL;
	unsigned char *key = NULL;
	unsigned char *enckey, *mackey;
	size_t keylen, enckeylen, mackeylen;
	size_t size;

	if (!mpk || !encparams || !in || !id) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (idlen <= 0 || idlen > SM9_MAX_ID_LENGTH || strlen(id) != idlen) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, SM9_R_INVALID_ID);
		return NULL;
	}
	if (inlen <= 0 || inlen > 1024) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, SM9_R_INVALID_INPUT);
		return NULL;
	}
	if (strlen(id) != idlen || idlen > SM9_MAX_ID_LENGTH) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, SM9_R_INVALID_ID);
		return NULL;
	}

	if (!(ret = SM9Ciphertext_new())) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* keylen = enckeylen + mackeylen */
	if (!SM9EncParameters_get_key_length(encparams, inlen, &enckeylen, &mackeylen)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	keylen = enckeylen + mackeylen;

	/* prepare key buffer */
	if (!(key = OPENSSL_malloc(keylen))) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* (enckey, mackey) = wrap_key() */
	if (!SM9_wrap_key(mpk, keylen, NULL, NULL, &size, id, idlen)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(ret->pointC1, NULL, size)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!SM9_wrap_key(mpk, keylen, key, ret->pointC1->data, &size, id, idlen)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	enckey = key;
	mackey = key + enckeylen;

	/* ret->c2 = encrypt(in, enckey) */
	if (!SM9EncParameters_encrypt(encparams, in, inlen, NULL, &size, enckey)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(ret->c2, NULL, size)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!SM9EncParameters_encrypt(encparams, in, inlen, ret->c2->data, &size, enckey)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	/* ret->c3 = mac(ret->c2, mackey) */
	if (!SM9EncParameters_generate_mac(encparams,
		ret->c2->data, ret->c2->length, NULL, &size, mackey)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(ret->c3, NULL, size)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!SM9EncParameters_generate_mac(encparams,
		ret->c2->data, ret->c2->length, ret->c3->data, &size, mackey)) {
		SM9err(SM9_F_SM9_DO_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	e = 0;

end:
	if (e && ret) {
		SM9Ciphertext_free(ret);
		ret = NULL;
	}
	if (key) {
		OPENSSL_cleanse(key, keylen);
		OPENSSL_free(key);
	}
	return ret;
}

#define SM9_MAX_CIPHERTEXT_LENGTH 1024
static int SM9Ciphertext_check(const SM9Ciphertext *in)
{
	if (!in->pointC1 || !in->c2 || !in->c3) {
		SM9err(SM9_F_SM9CIPHERTEXT_CHECK, SM9_R_INVALID_CIPHERTEXT);
		return 0;
	}
	if (!in->pointC1->data || in->pointC1->length <= 0) {
		SM9err(SM9_F_SM9CIPHERTEXT_CHECK, SM9_R_INVALID_CIPHERTEXT);
		return 0;
	}
	if (!in->c2 || in->c2->length <= 0) {
		SM9err(SM9_F_SM9CIPHERTEXT_CHECK, SM9_R_INVALID_CIPHERTEXT);
		return 0;
	}
	if (!in->c3 || in->c3->length <= 0) {
		SM9err(SM9_F_SM9CIPHERTEXT_CHECK, SM9_R_INVALID_CIPHERTEXT);
		return 0;
	}
	if (in->c2->length > SM9_MAX_CIPHERTEXT_LENGTH) {
		SM9err(SM9_F_SM9CIPHERTEXT_CHECK, SM9_R_INVALID_CIPHERTEXT);
		return 0;
	}
	return 1;
}

int SM9_do_decrypt(SM9PublicParameters *mpk, const SM9EncParameters *encparams,
	const SM9Ciphertext *in, unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk, const char *id, size_t idlen)
{
	int ret = 0;
	unsigned char *key = NULL;
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned char *enckey, *mackey;
	size_t keylen, enckeylen, mackeylen;
	size_t size;

	if (!mpk || !encparams || !in || !outlen || !sk) {
		SM9err(SM9_F_SM9_DO_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (!SM9Ciphertext_check(in)) {
		SM9err(SM9_F_SM9_DO_DECRYPT, SM9_R_INVALID_CIPHERTEXT);
		return 0;
	}

	if (!out) {
		*outlen = in->c2->length;
		return 1;
	}
	if (*outlen < in->c2->length) {             
		SM9err(SM9_F_SM9_DO_DECRYPT, SM9_R_BUFFER_TOO_SMALL);
		return 0;
	}

	/* keylen = enckeylen + mackeylen */
	if (!SM9EncParameters_get_key_length(encparams, in->c2->length,
		&enckeylen, &mackeylen)) {
		SM9err(SM9_F_SM9_DO_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	keylen = enckeylen + mackeylen;

	/* prepare key buffer */
	if (!(key = OPENSSL_malloc(keylen))) {
		SM9err(SM9_F_SM9_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* (enckey, mackey) = wrap_key() */
	if (!SM9_unwrap_key(mpk, keylen,
		in->pointC1->data, in->pointC1->length, key, id, idlen, sk)) {
		SM9err(SM9_F_SM9_DO_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	enckey = key;
	mackey = key + enckeylen;

	/* check in->c3 == mac(ret->c2, mackey) */
	if (!SM9EncParameters_generate_mac(encparams,
		in->c2->data, in->c2->length, mac, &size, mackey)) {
		SM9err(SM9_F_SM9_DO_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	if (in->c3->length != size || memcmp(in->c3->data, mac, size) != 0) {
		SM9err(SM9_F_SM9_DO_DECRYPT, SM9_R_INVALID_CIPHERTEXT);
		goto end;
	}

	/* ret->c2 = decrypt(in, enckey) */
	if (!SM9EncParameters_decrypt(encparams, in->c2->data, in->c2->length,
		out, &size, enckey)) {
		SM9err(SM9_F_SM9_DO_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	*outlen = size;

	ret = 1;

end:
	OPENSSL_cleanse(key, keylen);
	OPENSSL_free(key);
	return ret;
}

static int SM9Ciphertext_size(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams, size_t inlen, size_t *outlen)
{
	if (!outlen) {
		return 0;
	}
	*outlen = inlen + 4096;
}

int SM9_encrypt_ex(SM9PublicParameters *mpk, const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PublicKey *pk)
{
	return 0;
}

int SM9_encrypt(SM9PublicParameters *mpk, const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen)
{
	int ret = 0;
	SM9Ciphertext *c = NULL;

	if (!mpk || !encparams || !in || !outlen || !id) {
		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(c = SM9_do_encrypt(mpk, encparams, in, inlen, id, idlen))) {
		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	//TODO: ret!!

end:
	return ret;
}

int SM9_decrypt(SM9PublicParameters *mpk, const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk, const char *id, size_t idlen)
{
	int ret = 0;
	SM9Ciphertext *c = NULL;
	const unsigned char *p;

	if (!mpk || !encparams || !in || !outlen || !sk) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (inlen <= 0 || inlen > SM9_MAX_CIPHERTEXT_LENGTH) {
		SM9err(SM9_F_SM9_DECRYPT, SM9_R_INVALID_CIPHERTEXT);
		return 0;
	}
	if (idlen <= 0 || idlen > SM9_MAX_ID_LENGTH || strlen(id) != idlen) {
		SM9err(SM9_F_SM9_DECRYPT, SM9_R_INVALID_ID_LENGTH);
		return 0;
	}

	if (!out) {
		*outlen = inlen;
		return 1;
	}
	if (*outlen < inlen) {
		SM9err(SM9_F_SM9_DECRYPT, SM9_R_BUFFER_TOO_SMALL);
		return 0;
	}

	p = in;
	if (!(c = d2i_SM9Ciphertext(NULL, &p, inlen))) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	if (!(SM9_do_decrypt(mpk, encparams, c, out, outlen, sk, id, idlen))) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	ret = 1;
end:
	SM9Ciphertext_free(c);
	return ret;
}

static int SM9EncParameters_init_with_recommended(SM9EncParameters *encparams)
{
	if (!encparams) {
		return 0;
	}
	memset(encparams, 0, sizeof(*encparams));
	encparams->kdf_md = EVP_sm3();
	encparams->enc_cipher = EVP_sms4_cbc();
	encparams->cmac_cipher = NULL;
	encparams->hmac_md = EVP_sm3();
	return 1;
}

int SM9_encrypt_with_recommended_ex(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PublicKey *pk)
{
	return 0;
}

int SM9_encrypt_with_recommended(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen)
{
	SM9EncParameters encparams;
	SM9EncParameters_init_with_recommended(&encparams);
	return SM9_encrypt(mpk, &encparams, in, inlen, out, outlen, id, idlen);
}

int SM9_decrypt_with_recommended(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk, const char *id, size_t idlen)
{
	SM9EncParameters encparams;
	SM9EncParameters_init_with_recommended(&encparams);
	return SM9_decrypt(mpk, &encparams, in, inlen, out, outlen, sk, id, idlen);
}
