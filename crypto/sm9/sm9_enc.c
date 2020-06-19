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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sm2.h>
#include <openssl/sm9.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include "sm9_lcl.h"


int SM9_unwrap_key(int type,
	unsigned char *key, size_t keylen,
	const unsigned char *enced_key, size_t enced_len,
	SM9PrivateKey *sk)
{
	int ret = 0;
	EC_GROUP *group = NULL;
	EC_POINT *C = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	BN_CTX *bn_ctx = NULL;
	point_t de;
	fp12_t w;
	const BIGNUM *p = SM9_get0_prime();
	const EVP_MD *kdf_md;
	unsigned char wbuf[384];
	unsigned char *out = key;
	size_t outlen = keylen;
	unsigned char counter[4] = {0, 0, 0, 1};
	unsigned char dgst[64];
	unsigned int len;

	switch (type) {
	case NID_sm9kdf_with_sm3:
		kdf_md = EVP_sm3();
		break;
	case NID_sm9kdf_with_sha256:
		kdf_md = EVP_sha256();
		break;
	default:
		return 0;
	}

	/* malloc */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(C = EC_POINT_new(group))
		|| !(md_ctx = EVP_MD_CTX_new())
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!point_init(&de, bn_ctx) || !fp12_init(w, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* parse C on E(F_p) */
	if (!EC_POINT_oct2point(group, C, enced_key, enced_len, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* parse de on E'(E_p^2) */
	if (!point_from_octets(&de, ASN1_STRING_get0_data(sk->privatePoint), p, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* w = e(C, de) */
	if (!rate_pairing(w, &de, C, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!fp12_to_bin(w, wbuf)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* K = KDF(C||w||ID_B, klen) */
	while (outlen > 0) {
		if (!EVP_DigestInit_ex(md_ctx, kdf_md, NULL)
			|| !EVP_DigestUpdate(md_ctx, enced_key + 1, enced_len - 1)
			|| !EVP_DigestUpdate(md_ctx, wbuf, sizeof(wbuf))
			|| !EVP_DigestUpdate(md_ctx, ASN1_STRING_get0_data(sk->identity), ASN1_STRING_length(sk->identity))
			|| !EVP_DigestUpdate(md_ctx, counter, sizeof(counter))
			|| !EVP_DigestFinal_ex(md_ctx, dgst, &len)) {
			SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (len > outlen)
			len = outlen;
		memcpy(out, dgst, len);

		out += len;
		outlen -= len;
		counter[3]++;
	}

	ret = 1;

end:
	EC_GROUP_free(group);
	EC_POINT_free(C);
	EVP_MD_CTX_free(md_ctx);
	fp12_cleanup(w);
	point_cleanup(&de);
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;
}

int SM9_wrap_key(int type, /* NID_sm9kdf_with_sm3 */
	unsigned char *key, size_t keylen,
	unsigned char *enced_key, size_t *enced_len,
	SM9PublicParameters *mpk, const char *id, size_t idlen)
{
	int ret = 0;
	EC_GROUP *group = NULL;
	EC_POINT *Ppube = NULL;
	EC_POINT *C = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *r = NULL;
	BIGNUM *h = NULL;
	fp12_t w;
	const EVP_MD *kdf_md;
	const EVP_MD *hash1_md;
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *n = SM9_get0_order();
	unsigned char cbuf[65];
	unsigned char wbuf[384];
	unsigned char dgst[64];
	int all;

	switch (type) {
	case NID_sm9kdf_with_sm3:
		kdf_md = EVP_sm3();
		break;
	case NID_sm9kdf_with_sha256:
		kdf_md = EVP_sha256();
		break;
	default:
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_DIGEST_TYPE);
		return 0;
	}

	if (keylen > (size_t)EVP_MD_size(kdf_md) * 255) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_KEM_KEY_LENGTH);
		return 0;
	}

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(Ppube = EC_POINT_new(group))
		|| !(C = EC_POINT_new(group))
		|| !(md_ctx = EVP_MD_CTX_new())
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!(r = BN_CTX_get(bn_ctx)) || !fp12_init(w, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* parse Ppube */
	if (!EC_POINT_oct2point(group, Ppube, ASN1_STRING_get0_data(mpk->pointPpub),
		ASN1_STRING_length(mpk->pointPpub), bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_POINTPPUB);
		goto end;
	}

	/* g = e(Ppube, P2) */
	if (!rate_pairing(w, NULL, Ppube, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_RATE_PAIRING_ERROR);
		goto end;
	}

	switch (OBJ_obj2nid(mpk->hash1)) {
	case NID_sm9hash1_with_sm3:
		hash1_md = EVP_sm3();
		break;
	case NID_sm9hash1_with_sha256:
		hash1_md = EVP_sha256();
		break;
	default:
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_SM9_LIB);
		goto end;
	}

	/* parse Q_B = H1(ID_B||hid) * P1 + Ppube */
	// we should check mpk->hash1
	if (!SM9_hash1(hash1_md, &h, id, idlen, SM9_HID_ENC, n, bn_ctx)
		|| !EC_POINT_mul(group, C, h, NULL, NULL, bn_ctx)
		|| !EC_POINT_add(group, C, C, Ppube, bn_ctx)) {
		ERR_print_errors_fp(stderr);
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	do {
		unsigned char *out = key;
		size_t outlen = keylen;
		unsigned char counter[4] = {0, 0, 0, 1};
		unsigned int len;

		/* r = rand([1, n-1]) */
		do {
			if (!BN_rand_range(r, n)) {
				goto end;
			}
		} while (BN_is_zero(r));

		/* C = r * Q_B */
		if (!EC_POINT_mul(group, C, NULL, C, r, bn_ctx)
			|| EC_POINT_point2oct(group, C, POINT_CONVERSION_UNCOMPRESSED,
				cbuf, sizeof(cbuf), bn_ctx) != sizeof(cbuf)) {
			SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
			goto end;
		}

		/* w = g^r */
		if (!fp12_pow(w, w, r, p, bn_ctx) || !fp12_to_bin(w, wbuf)) {
			SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_EXTENSION_FIELD_ERROR);
			goto end;
		}

		/* K = KDF(C||w||ID_B, klen) */
		while (outlen > 0) {
			if (!EVP_DigestInit_ex(md_ctx, kdf_md, NULL)
				|| !EVP_DigestUpdate(md_ctx, cbuf + 1, sizeof(cbuf) - 1)
				|| !EVP_DigestUpdate(md_ctx, wbuf, sizeof(wbuf))
				|| !EVP_DigestUpdate(md_ctx, id, idlen)
				|| !EVP_DigestUpdate(md_ctx, counter, sizeof(counter))
				|| !EVP_DigestFinal_ex(md_ctx, dgst, &len)) {
				SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EVP_LIB);
				goto end;
			}

			if (len > outlen)
				len = outlen;
			memcpy(out, dgst, len);

			out += len;
			outlen -= len;
			counter[3]++;
		}

		all = 0;
		for (len = 0; len < keylen; len++) {
			all |= key[len];
		}

	} while (all == 0);

	memcpy(enced_key, cbuf, sizeof(cbuf));
	*enced_len = sizeof(cbuf);


	ret = 1;

end:
	EC_GROUP_free(group);
	EC_POINT_free(Ppube);
	EC_POINT_free(C);
	EVP_MD_CTX_free(md_ctx);
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_free(r);
	BN_free(h);
	BN_CTX_free(bn_ctx);
	OPENSSL_cleanse(cbuf, sizeof(cbuf));
	OPENSSL_cleanse(wbuf, sizeof(wbuf));
	OPENSSL_cleanse(dgst, sizeof(dgst));
	return ret;
}

int SM9_encrypt(int type,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PublicParameters *mpk, const char *id, size_t idlen)
{
	int ret = 0;
	SM9Ciphertext *sm9cipher = NULL;
	int kdf;
	const EVP_MD *md;
	unsigned char *key = NULL;
	size_t keylen;
	unsigned char C1[1 + 64];
	size_t C1_len;
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen = sizeof(mac);
	int len;
	size_t i;

	/* parse type */
	switch (type) {
	case NID_sm9encrypt_with_sm3_xor:
		kdf = NID_sm9kdf_with_sm3;
		md = EVP_sm3();
		break;
	/*
	case NID_sm9encrypt_with_sha256_xor:
		kdf = NID_sm9kdf_with_sha256;
		md = EVP_sha256();
		break;
	*/
	case NID_sm9encrypt_with_sm3_sms4_cbc:
	case NID_sm9encrypt_with_sm3_sms4_ctr:
	default:
		return 0;
	}

	keylen = inlen + EVP_MD_size(md);

	/* malloc */
	if (!(sm9cipher = SM9Ciphertext_new())
		|| !(key = OPENSSL_malloc(keylen))) {
		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* C1 */
	if (!SM9_wrap_key(kdf, key, keylen, C1, &C1_len, mpk, id, idlen)) {
		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	/* C2 = M xor K1 */
	for (i = 0; i < inlen; i++) {
		key[i] ^= in[i];
	}

	/* C3 = Hv(C2||K2) */
	if (!EVP_Digest(key, keylen, mac, &maclen, md, NULL)) {
		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	/* compose SM9Ciphertext */
	if (!ASN1_STRING_set(sm9cipher->pointC1, C1, C1_len)
		|| !ASN1_STRING_set(sm9cipher->c2, key, inlen)
		|| !ASN1_STRING_set(sm9cipher->c3, mac, maclen)) {
		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	/* encode sm9 ciphertext */
	if ((len = i2d_SM9Ciphertext(sm9cipher, &out)) <= 0) {
		SM9err(SM9_F_SM9_ENCRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	*outlen = len;

	ret = 1;

end:
	OPENSSL_free(sm9cipher);
	OPENSSL_clear_free(key, keylen);
	return ret;
}

int SM9_decrypt(int type,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk)
{
	int ret = 0;
	SM9Ciphertext *sm9cipher = NULL;
	unsigned char *key = NULL;
	size_t keylen;
	int kdf;
	const EVP_MD *md;
	const unsigned char *C2;
	int C2_len;
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen = sizeof(mac);
	int i;

	/* parse type */
	switch (type) {
	case NID_sm9encrypt_with_sm3_xor:
		kdf = NID_sm9kdf_with_sm3;
		md = EVP_sm3();
		break;
	/*
	case NID_sm9encrypt_with_sha256_xor:
		kdf = NID_sm9kdf_with_sha256;
		md = EVP_sha256();
		break;
	*/
	case NID_sm9encrypt_with_sm3_sms4_cbc:
	case NID_sm9encrypt_with_sm3_sms4_ctr:
	default:
		return 0;
	}

	if (!in || !outlen || !sk) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		goto end;
	}

	/* decode sm9 ciphertext */
	if (!(sm9cipher = d2i_SM9Ciphertext(NULL, &in, inlen))) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}
	C2 = ASN1_STRING_get0_data(sm9cipher->c2);
	C2_len = ASN1_STRING_length(sm9cipher->c2);

	/* check/return output length */
	if (!out) {
		*outlen = C2_len;
		ret = 1;
		goto end;
	} else if (*outlen < (size_t)C2_len) {
		SM9err(SM9_F_SM9_DECRYPT, SM9_R_BUFFER_TOO_SMALL);
		goto end;
	}

	/* unwrap key */
	keylen = C2_len + EVP_MD_size(md);
	if (!(key = OPENSSL_malloc(keylen))) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!SM9_unwrap_key(kdf, key, keylen,
		ASN1_STRING_get0_data(sm9cipher->pointC1),
		ASN1_STRING_length(sm9cipher->pointC1), sk)) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	/* M = C2 xor key */
	for (i = 0; i < C2_len; i++) {
		out[i] = C2[i] ^ key[i];
	}
	*outlen = C2_len;

	/* check mac length */
	if (ASN1_STRING_length(sm9cipher->c3) != EVP_MD_size(md)) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_SM9_LIB);
		goto end;
	}

	/* C3 = Hv(C2||K2) */
	memcpy(key, C2, C2_len);
	if (!EVP_Digest(key, keylen, mac, &maclen, md, NULL)) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	if (CRYPTO_memcmp(ASN1_STRING_get0_data(sm9cipher->c3), mac, maclen) != 0) {
		SM9err(SM9_F_SM9_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	ret = 1;

end:
	SM9Ciphertext_free(sm9cipher);
	if (key)
		OPENSSL_clear_free(key, keylen);
	return ret;
}
