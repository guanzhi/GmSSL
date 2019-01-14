/* ====================================================================
 * Copyright (c) 2007 - 2017 The GmSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_AES
# include <openssl/aes.h>
#endif
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_CMAC
# include <openssl/cmac.h>
#endif
#include <openssl/rand.h>
#include <openssl/ecdh.h>
#include <openssl/kdf2.h>
#include <openssl/ecies.h>
#include "internal/o_str.h"
#include "ecies_lcl.h"

#define ECIES_ENC_RANDOM_IV	1

int ECIES_PARAMS_init_with_type(ECIES_PARAMS *params, int type)
{
	if (!params) {
		ECerr(EC_F_ECIES_PARAMS_INIT_WITH_TYPE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	switch (type) {
#ifndef OPENSSL_NO_SHA
	case NID_ecies_with_x9_63_sha1_xor_hmac:
		params->kdf_nid = NID_x9_63_kdf;
		params->kdf_md = EVP_sha1();
		params->enc_nid = NID_xor_in_ecies;
		params->mac_nid = NID_hmac_full_ecies;
		params->hmac_md = EVP_sha1();
		break;
# ifndef OPENSSL_NO_SHA256
	case NID_ecies_with_x9_63_sha256_xor_hmac:
		params->kdf_nid = NID_x9_63_kdf;
		params->kdf_md = EVP_sha256();
		params->enc_nid = NID_xor_in_ecies;
		params->mac_nid = NID_hmac_full_ecies;
		params->hmac_md = EVP_sha256();
		break;
# endif
#endif
	default:
		ECerr(EC_F_ECIES_PARAMS_INIT_WITH_TYPE, EC_R_INVALID_ECIES_PARAMS);
		return 0;
	}

	return 1;
}

int ECIES_PARAMS_init_with_recommended(ECIES_PARAMS *param)
{
	if (!param) {
		ECerr(EC_F_ECIES_PARAMS_INIT_WITH_RECOMMENDED,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	memset(param, 0, sizeof(*param));
#ifndef OPENSSL_NO_SHA
	param->kdf_nid = NID_x9_63_kdf;
	param->kdf_md = EVP_sha256();
	param->enc_nid = NID_xor_in_ecies;
	param->mac_nid = NID_hmac_full_ecies;
	param->hmac_md = EVP_sha256();
	// we should return error when sha256 disabled				
#endif
	return 1;
}

KDF_FUNC ECIES_PARAMS_get_kdf(const ECIES_PARAMS *param)
{
	if (!param || !param->kdf_md) {
		ECerr(EC_F_ECIES_PARAMS_GET_KDF, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	switch (param->kdf_nid) {
	case NID_x9_63_kdf:
		return KDF_get_x9_63(param->kdf_md);
	case NID_nist_concatenation_kdf:
	case NID_tls_kdf:
	case NID_ikev2_kdf:
		ECerr(EC_F_ECIES_PARAMS_GET_KDF, EC_R_NOT_IMPLEMENTED);
		return NULL;
	}

	ECerr(EC_F_ECIES_PARAMS_GET_KDF, EC_R_INVALID_ECIES_PARAMETERS);
	return NULL;
}

int ECIES_PARAMS_get_enc(const ECIES_PARAMS *param, size_t inlen,
	const EVP_CIPHER **enc_cipher, size_t *enckeylen, size_t *ciphertextlen)
{
	const EVP_CIPHER *cipher = NULL;
	size_t keylen;
	size_t outlen;

	if (!param || !enc_cipher || !enckeylen || !ciphertextlen) {
		ECerr(EC_F_ECIES_PARAMS_GET_ENC, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	switch (param->enc_nid) {
	case NID_xor_in_ecies:
		cipher = NULL;
		keylen = inlen;
		break;
#ifndef OPENSSL_NO_DES
	case NID_tdes_cbc_in_ecies:
		cipher = EVP_des_ede_cbc();
		break;
#endif
#ifndef OPENSSL_NO_AES
	case NID_aes128_cbc_in_ecies:
		cipher = EVP_aes_128_cbc();
		break;
	case NID_aes192_cbc_in_ecies:
		cipher = EVP_aes_192_cbc();
		break;
	case NID_aes256_cbc_in_ecies:
		cipher = EVP_aes_256_cbc();
		break;
	case NID_aes128_ctr_in_ecies:
		cipher = EVP_aes_128_ctr();
		break;
	case NID_aes192_ctr_in_ecies:
		cipher = EVP_aes_192_ctr();
		break;
	case NID_aes256_ctr_in_ecies:
		cipher = EVP_aes_256_ctr();
		break;
#endif
	default:
		ECerr(EC_F_ECIES_PARAMS_GET_ENC, EC_R_INVALID_ECIES_PARAMETERS);
		return 0;
	}

	outlen = inlen;
	if (cipher) {
		int blocksize = EVP_CIPHER_block_size(cipher);
		keylen = EVP_CIPHER_key_length(cipher);
		if (ECIES_ENC_RANDOM_IV) {
			outlen += blocksize;
		}
		if (EVP_CIPHER_mode(cipher) == EVP_CIPH_CBC_MODE) {
			outlen += blocksize - inlen % blocksize;
		}
	}

	*enc_cipher = cipher;
	*enckeylen = keylen;
	*ciphertextlen = outlen;

	return 1;
}

int ECIES_PARAMS_get_mac(const ECIES_PARAMS *param,
	const EVP_MD **hmac_md, const EVP_CIPHER **cmac_cipher,
	unsigned int *mackeylen, unsigned int *maclen)
{
	const EVP_CIPHER *cipher = NULL;
	const EVP_MD *md = NULL;
	unsigned int keylen;
	unsigned int outlen;

	if (!param || !hmac_md || !cmac_cipher || !mackeylen || !maclen) {
		ECerr(EC_F_ECIES_PARAMS_GET_MAC, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	switch (param->mac_nid) {
	case NID_hmac_full_ecies:
		if (!(md = param->hmac_md)) {
			ECerr(EC_F_ECIES_PARAMS_GET_MAC,
				EC_R_INVALID_ECIES_PARAMETERS);
			return 0;
		}
		keylen = EVP_MD_size(md);
		outlen = EVP_MD_size(md);
		break;
	case NID_hmac_half_ecies:
		if (!(md = param->hmac_md)) {
			ECerr(EC_F_ECIES_PARAMS_GET_MAC,
				EC_R_INVALID_ECIES_PARAMETERS);
			return 0;
		}
		keylen = EVP_MD_size(md);
		outlen = EVP_MD_size(md)/2;
		break;
#ifndef OPENSSL_NO_AES
	case NID_cmac_aes128_ecies:
		cipher = EVP_aes_128_ecb();
		break;
	case NID_cmac_aes192_ecies:
		cipher = EVP_aes_192_ecb();
		break;
	case NID_cmac_aes256_ecies:
		cipher = EVP_aes_256_ecb();
		break;
#endif
	default:
		ECerr(EC_F_ECIES_PARAMS_GET_MAC,
			EC_R_INVALID_ECIES_PARAMETERS);
		return 0;
	}

	if (cipher) {
		keylen = EVP_CIPHER_key_length(cipher);
		outlen = EVP_CIPHER_block_size(cipher);
	}

	*hmac_md = md;
	*cmac_cipher = cipher;
	*mackeylen = keylen;
	*maclen = outlen;

	return 1;
}

int ECIES_CIPHERTEXT_VALUE_ciphertext_length(const ECIES_CIPHERTEXT_VALUE *a)
{
	return ASN1_STRING_length(a->ciphertext);
}

ECIES_CIPHERTEXT_VALUE *ECIES_do_encrypt(const ECIES_PARAMS *param,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	int e = 1;
	KDF_FUNC kdf_func;
	const EVP_CIPHER *enc_cipher = NULL;
	size_t enckeylen, ciphertextlen;
	const EVP_MD *hmac_md = NULL;
	const EVP_CIPHER *mac_cipher = NULL;
	unsigned int mackeylen, maclen;
	ECIES_CIPHERTEXT_VALUE *ret = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	EC_KEY *ephem_key = NULL;
	int point_form = POINT_CONVERSION_COMPRESSED;
	unsigned char *sharekey = NULL;
	unsigned int sharekeylen;
	unsigned char *enckey, *mackey;
	unsigned char mac[EVP_MAX_MD_SIZE];
	size_t len;

	if (!param || !in || !inlen || !ec_key || !group) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* parse parameters */
	if (!(kdf_func = ECIES_PARAMS_get_kdf(param))) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (!ECIES_PARAMS_get_enc(param, inlen, &enc_cipher, &enckeylen, &ciphertextlen)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (!ECIES_PARAMS_get_mac(param, &hmac_md, &mac_cipher, &mackeylen, &maclen)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}

	/* malloc ciphertext value */
	if (!(ret = ECIES_CIPHERTEXT_VALUE_new())) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	/* generate ephem keypair */
	if (!(ephem_key = EC_KEY_new())) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_KEY_set_group(ephem_key, group)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_KEY_generate_key(ephem_key)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* output ephem_point */
	len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(ephem_key),
		point_form, NULL, 0, NULL);
	if (!ASN1_OCTET_STRING_set(ret->ephem_point, NULL, len)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_ASN1_LIB);
		goto end;
	}
	if (EC_POINT_point2oct(group, EC_KEY_get0_public_key(ephem_key),
		point_form, ret->ephem_point->data, len, NULL) <= 0) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* ecdh to generate enckey and mackey */
	sharekeylen = enckeylen + mackeylen;
	if (!(sharekey = OPENSSL_malloc(sharekeylen))) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
 	if (!ECDH_compute_key(sharekey, sharekeylen,
		EC_KEY_get0_public_key(ec_key), ephem_key,
		kdf_func)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_ECDH_FAILED);
		goto end;
	}
	enckey = sharekey;
	mackey = sharekey + enckeylen;

	/* encrypt */
	if (!ASN1_OCTET_STRING_set(ret->ciphertext, NULL, ciphertextlen)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (enc_cipher) {
		EVP_CIPHER_CTX *cipher_ctx = NULL;
		unsigned char ivbuf[EVP_MAX_IV_LENGTH];
		unsigned char *iv, *pout;
		unsigned int ivlen, len;

		ivlen = EVP_CIPHER_iv_length(enc_cipher);
		if (ECIES_ENC_RANDOM_IV) {
			iv = ret->ciphertext->data;
			pout = ret->ciphertext->data + ivlen;
			RAND_bytes(iv, ivlen);
		} else {
			iv = ivbuf;
			pout = ret->ciphertext->data;
			memset(iv, 0, ivlen);
		}

		if (!(cipher_ctx = EVP_CIPHER_CTX_new())) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!EVP_EncryptInit(cipher_ctx, enc_cipher, enckey, iv)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_ENCRYPT_FAILED);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		if (!EVP_EncryptUpdate(cipher_ctx, pout, (int *)&len, in, inlen)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_ENCRYPT_FAILED);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		pout += len;
		if (!EVP_EncryptFinal(cipher_ctx, pout, (int *)&len)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_ENCRYPT_FAILED);
			goto end;
		}
		pout += len;

		OPENSSL_assert(pout - ret->ciphertext->data == ciphertextlen);

	} else {
		int i;
		for (i = 0; i < ret->ciphertext->length; i++) {
			ret->ciphertext->data[i] = in[i] ^ enckey[i];
		}
	}

	/* generate mac */
	if (mac_cipher) {
		CMAC_CTX *cmac_ctx;
		if (!(cmac_ctx = CMAC_CTX_new())) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(cmac_ctx, mackey, mackeylen, mac_cipher, NULL)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_INIT_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		if (!CMAC_Update(cmac_ctx, ret->ciphertext->data, ret->ciphertext->length)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_UPDATE_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		len = sizeof(mac);
		if (!CMAC_Final(cmac_ctx, mac, &len)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_FINAL_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		OPENSSL_assert(len == maclen);
		CMAC_CTX_free(cmac_ctx);

	} else {
		len = sizeof(mac);
		if (!HMAC(param->hmac_md, mackey, mackeylen,
			ret->ciphertext->data, ret->ciphertext->length,
			mac, &maclen)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_HMAC_FAILURE);
			goto end;
		}
		OPENSSL_assert(len == maclen || len/2 == maclen);
	}

	if (!ASN1_OCTET_STRING_set(ret->mactag, mac, maclen)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}


	e = 0;
end:
	EC_KEY_free(ephem_key);
	OPENSSL_free(sharekey);
	if (e && ret) {
		ECIES_CIPHERTEXT_VALUE_free(ret);
		ret = NULL;
	}
	return ret;
}

int ECIES_do_decrypt(const ECIES_PARAMS *param, const ECIES_CIPHERTEXT_VALUE *in,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	KDF_FUNC kdf_func;
	const EVP_CIPHER *enc_cipher = NULL;
	size_t enckeylen, ciphertextlen;
	const EVP_MD *hmac_md = NULL;
	const EVP_CIPHER *mac_cipher = NULL;
	unsigned int mackeylen, maclen;
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	EC_POINT *ephem_point = NULL;
	unsigned char *sharekey = NULL;
	unsigned int sharekeylen;
	unsigned char *enckey, *mackey;
	unsigned char mac[EVP_MAX_MD_SIZE];
	size_t len;

	if (!param || !in || !outlen || !ec_key || !group) {
		ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!out) {
		*outlen = in->ciphertext->length;
		return 1;
	}
	if (*outlen < in->ciphertext->length) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	/* parse parameters */
	if (!(kdf_func = ECIES_PARAMS_get_kdf(param))) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (!ECIES_PARAMS_get_enc(param, in->ciphertext->length,
		&enc_cipher, &enckeylen, &ciphertextlen)) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (!ECIES_PARAMS_get_mac(param, &hmac_md, &mac_cipher, &mackeylen, &maclen)) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}

	/* parse ephem_point */
	if (!in->ephem_point || !in->ephem_point->data || in->ephem_point->length <= 0) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
		goto end;
	}
	if (!(ephem_point = EC_POINT_new(group))) {
		ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_POINT_oct2point(group, ephem_point,
		in->ephem_point->data, in->ephem_point->length, NULL)) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
		goto end;
	}

	/* compute ecdh, get enckey and mackey */
	sharekeylen = enckeylen + mackeylen;
	if (!(sharekey = OPENSSL_malloc(sharekeylen))) {
		ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!ECDH_compute_key(sharekey, sharekeylen,
		ephem_point, ec_key, kdf_func)) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_ECDH_FAILURE);
		goto end;
	}
	enckey = sharekey;
	mackey = sharekey + enckeylen;

	/* generate and verify mac */
	if (!in->mactag || !in->mactag->data) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
		goto end;
	}

	if (mac_cipher) {
		CMAC_CTX *cmac_ctx;
		if (!(cmac_ctx = CMAC_CTX_new())) {
			ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(cmac_ctx, mackey, mackeylen, mac_cipher, NULL)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_CMAC_INIT_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		if (!CMAC_Update(cmac_ctx, in->ciphertext->data, in->ciphertext->length)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_CMAC_UPDATE_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		len = sizeof(mac);
		if (!CMAC_Final(cmac_ctx, mac, &len)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_CMAC_FINAL_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		OPENSSL_assert(len == maclen);
		CMAC_CTX_free(cmac_ctx);

	} else {
		unsigned int ulen;
		ulen = sizeof(mac);
		if (!HMAC(param->hmac_md, mackey, mackeylen,
			in->ciphertext->data, in->ciphertext->length,
			mac, &ulen)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_GEN_MAC_FAILED);
			goto end;
		}
		len = (size_t)ulen;
		OPENSSL_assert(len == maclen || len/2 == maclen);
	}

	if (maclen != in->mactag->length) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_ECIES_VERIFY_MAC_FAILURE);
		goto end;
	}
	if (OPENSSL_memcmp(in->mactag->data, mac, maclen)) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_ECIES_VERIFY_MAC_FAILURE);
		goto end;
	}

	/* decrypt */
	if (enc_cipher) {
		EVP_CIPHER_CTX *cipher_ctx = NULL;
		unsigned char ivbuf[EVP_MAX_IV_LENGTH];
		unsigned char *iv, *pin, *pout;
		unsigned int ivlen, inlen;
		int ilen;

		/* prepare iv */
		ivlen = EVP_CIPHER_iv_length(enc_cipher);
		if (ECIES_ENC_RANDOM_IV) {
			iv = in->ciphertext->data;
			pin = in->ciphertext->data + ivlen;
			if (in->ciphertext->length < ivlen) {
				ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
				goto end;
			}
			inlen = in->ciphertext->length - ivlen;
		} else {
			/* use fixed all-zero iv */
			memset(ivbuf, 0, ivlen);
			iv = ivbuf;
			pin = in->ciphertext->data;
			if (in->ciphertext->length <= 0) {
				ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
				goto end;
			}
			inlen = in->ciphertext->length;
		}

		/* decrypt */
		if (!(cipher_ctx = EVP_CIPHER_CTX_new())) {
			ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}

		if (!EVP_DecryptInit(cipher_ctx, enc_cipher, enckey, iv)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_ECIES_DECRYPT_INIT_FAILURE);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		pout = out;
		ilen = (int)*outlen; //FIXME: do we need to check it?
		if (!EVP_DecryptUpdate(cipher_ctx, pout, &ilen, pin, inlen)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_DECRYPT_FAILED);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		pout += ilen;
		if (!EVP_DecryptFinal(cipher_ctx, pout, &ilen)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_DECRYPT_FAILED);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		pout += ilen;
		EVP_CIPHER_CTX_free(cipher_ctx);
		*outlen = pout - out;

	} else {
		unsigned int i;
		for (i = 0; i < in->ciphertext->length; i++) {
			out[i] = in->ciphertext->data[i] ^ enckey[i];
		}
		*outlen = in->ciphertext->length;
	}

	ret = 1;
end:
	OPENSSL_free(sharekey);
	EC_POINT_free(ephem_point);
	return ret;
}

int ECIES_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	ECIES_PARAMS param;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	unsigned char *p = out;
	int len;

	if (!ECIES_PARAMS_init_with_type(&param, type)) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_INVALID_ENC_PARAM);
		return 0;
	}

	RAND_seed(in, inlen);
	if (!(cv = ECIES_do_encrypt(&param, in, inlen, ec_key))) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_ENCRYPT_FAILED);
		return 0;
	}

	if ((len = i2d_ECIES_CIPHERTEXT_VALUE(cv, NULL)) <= 0) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_ENCRYPT_FAILED);
		goto end;
	}

	if (!out) {
		*outlen = (size_t)len;
		ret = 1;
		goto end;
	} else if (*outlen < len) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_BUFFER_TOO_SMALL);
		*outlen = (size_t)len;
		goto end;
	}

	if ((len = i2d_ECIES_CIPHERTEXT_VALUE(cv, &p)) <= 0) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_ENCRYPT_FAILED);
		goto end;
	}

	*outlen = (size_t)len;
	ret = 1;

end:
	ECIES_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

int ECIES_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	ECIES_PARAMS param;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;

	if (!in) {
		ECerr(EC_F_ECIES_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (inlen <= 0 || inlen > INT_MAX) {
		ECerr(EC_F_ECIES_DECRYPT, EC_R_INVALID_INPUT_LENGTH);
		return 0;
	}

	if (!ECIES_PARAMS_init_with_type(&param, type)) {
		ECerr(EC_F_ECIES_DECRYPT, EC_R_INVALID_ENC_PARAM);
		return 0;
	}

	if (!(cv = d2i_ECIES_CIPHERTEXT_VALUE(NULL, &in, (long)inlen))) {
		ECerr(EC_F_ECIES_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
		return 0;
	}

	if (inlen != i2d_ECIES_CIPHERTEXT_VALUE(cv, NULL)) {
		ECerr(EC_F_ECIES_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
		goto end;
	}

	if (!ECIES_do_decrypt(&param, cv, out, outlen, ec_key)) {
		ECerr(EC_F_ECIES_DECRYPT, EC_R_ENCRYPT_FAILURE);
		goto end;
	}

	ret = 1;
end:
	ECIES_CIPHERTEXT_VALUE_free(cv);
	return ret;
}
