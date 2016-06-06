/* crypto/ecies/ecies_lib.c */
/* ====================================================================
 * Copyright (c) 2007 - 2015 The GmSSL Project.  All rights reserved.
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
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ecdh.h>
#include <openssl/kdf.h>
#include <openssl/ecies.h>
#include "../o_str.h"


static void *ecies_data_dup(void *data) {
	ECIES_PARAMS *ret = NULL;
	ECIES_PARAMS *param = (ECIES_PARAMS *)data;

	OPENSSL_assert(data);

	if (!(ret = OPENSSL_malloc(sizeof(ECIES_PARAMS)))) {
		return NULL;
	}

	memcpy(ret, param, sizeof(*param));

	return ret;
}

static void ecies_data_free(void *data) {
	OPENSSL_free(data);
	return;
}

int ECIES_set_parameters(EC_KEY *ec_key, const ECIES_PARAMS *param)
{
	ECIES_PARAMS *data = NULL;
	OPENSSL_assert(ec_key);
	OPENSSL_assert(param);

	data = (ECIES_PARAMS *)ecies_data_dup((void *)param);

	if (EC_KEY_insert_key_method_data(ec_key, data,
		ecies_data_dup, ecies_data_free, ecies_data_free)) {
		return 0;
	}

	return 1;
}

//FIXME: is is _get0_ ?
ECIES_PARAMS *ECIES_get_parameters(EC_KEY *ec_key)
{
	ECIES_PARAMS *ret;
	if (!(ret = EC_KEY_get_key_method_data(ec_key,
		ecies_data_dup, ecies_data_free, ecies_data_free))) {
		return NULL;
	}
	return ret;
}

ECIES_CIPHERTEXT_VALUE *ECIES_do_encrypt(const ECIES_PARAMS *param,
	const unsigned char *in, size_t inlen, EC_KEY *pub_key)
{
	int e = 1;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	EC_KEY *ephem_key = NULL;
	unsigned char *share = NULL;
	unsigned char *enckey, *mackey, *p;
	int sharelen, enckeylen, mackeylen, maclen, len;

	EVP_CIPHER_CTX cipher_ctx;
	EVP_CIPHER_CTX_init(&cipher_ctx);

	if (!(cv = ECIES_CIPHERTEXT_VALUE_new()))
		{
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	/*
	 * generate and encode ephem_point
	 */
	if (!(ephem_key = EC_KEY_new()))
		{
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!EC_KEY_set_group(ephem_key, EC_KEY_get0_group(pub_key)))
		{
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto err;
		}
	if (!EC_KEY_generate_key(ephem_key))
		{
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto err;
		}

	len = (int)EC_POINT_point2oct(EC_KEY_get0_group(ephem_key),
		EC_KEY_get0_public_key(ephem_key), POINT_CONVERSION_COMPRESSED,
		NULL, 0, NULL);
	if (!M_ASN1_OCTET_STRING_set(cv->ephem_point, NULL, len))
		{
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_ASN1_LIB);
		goto err;
		}
	if (EC_POINT_point2oct(EC_KEY_get0_group(ephem_key),
		EC_KEY_get0_public_key(ephem_key), POINT_CONVERSION_COMPRESSED,
		cv->ephem_point->data, len, NULL) <= 0)
		{
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto err;
		}

	/*
	 * use ecdh to compute enckey and mackey
	 */
	if (param->sym_cipher)
		enckeylen = EVP_CIPHER_key_length(param->sym_cipher);
	else	enckeylen = inlen;

	switch (param->mac_nid) {
	case NID_hmac_full_ecies:
		maclen = EVP_MD_size(param->mac_md);
		mackeylen = EVP_MD_size(param->mac_md);
		break;
	case NID_hmac_half_ecies:
		maclen = EVP_MD_size(param->mac_md)/2;
		mackeylen = EVP_MD_size(param->mac_md);
		break;
	case NID_cmac_aes128_ecies:
		maclen = AES_BLOCK_SIZE;
		mackeylen = 128/8;
		break;
	case NID_cmac_aes192_ecies:
		maclen = AES_BLOCK_SIZE;
		mackeylen = 192/8;
		break;
	default:
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto err;
	}

	sharelen = enckeylen + mackeylen;

	if (!(share = OPENSSL_malloc(sharelen)))
		{
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (!ECDH_compute_key(share, sharelen,
		EC_KEY_get0_public_key(pub_key), ephem_key,
		KDF_get_x9_63(param->kdf_md)))
		{
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ECIES_R_ECDH_FAILED);
		goto err;
		}
	enckey = share;
	mackey = share + enckeylen;

	/*
	 * encrypt data and encode result to ciphertext
	 */
	if (param->sym_cipher)
		len = (int)(inlen + EVP_MAX_BLOCK_LENGTH * 2);
	else	len = inlen;

	if (!M_ASN1_OCTET_STRING_set(cv->ciphertext, NULL, len))
		{
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
		}

	if (param->sym_cipher)
		{
		unsigned char iv[EVP_MAX_IV_LENGTH];
		memset(iv, 0, sizeof(iv));

		if (!EVP_EncryptInit(&cipher_ctx, param->sym_cipher, enckey, iv))
			{
			fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
			ECIESerr(ECIES_F_ECIES_DO_ENCRYPT,
				ECIES_R_ENCRYPT_FAILED);
			goto err;
			}
		p = cv->ciphertext->data;
		if (!EVP_EncryptUpdate(&cipher_ctx, p, &len, in, (int)inlen))
			{
			fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
			ECIESerr(ECIES_F_ECIES_DO_ENCRYPT,
				ECIES_R_ENCRYPT_FAILED);
			goto err;
			}
		p += len;
		if (!EVP_EncryptFinal(&cipher_ctx, p, &len))
			{
			fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
			ECIESerr(ECIES_F_ECIES_DO_ENCRYPT,
				ECIES_R_ENCRYPT_FAILED);
			goto err;
			}
		p += len;
		cv->ciphertext->length = (int)(p - cv->ciphertext->data);
		}
	else
		{
		int i;
		for (i = 0; i < len; i++)
			cv->ciphertext->data[i] = in[i] ^ enckey[i];
		cv->ciphertext->length = len;
		}

	/*
	 * calculate mactag of ciphertext and encode
	 */
	cv->mactag->length = maclen;

	if (!M_ASN1_OCTET_STRING_set(cv->mactag, NULL, cv->mactag->length))
		{
			fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!HMAC(param->mac_md, mackey, mackeylen,
		cv->ciphertext->data, (size_t)cv->ciphertext->length,
		cv->mactag->data, (unsigned int *)&len))
		{
			fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_DO_ENCRYPT, ECIES_R_GEN_MAC_FAILED);
		goto err;
		}

	e = 0;
err:
	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	if (share) OPENSSL_free(share);
	if (ephem_key) EC_KEY_free(ephem_key);
	if (e && cv)
		{
		ECIES_CIPHERTEXT_VALUE_free(cv);
		cv = NULL;
		}
	return cv;
}

int ECIES_do_decrypt(const ECIES_CIPHERTEXT_VALUE *cv,
	const ECIES_PARAMS *param, unsigned char *out, size_t *outlen,
	EC_KEY *pri_key)
{
	int r = 0;
	EC_POINT *ephem_point = NULL;
	unsigned char *share = NULL;
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned char *enckey, *mackey;
	int sharelen, enckeylen, mackeylen, len;
	unsigned char *p;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	// check output buffer size
	if (!out)
		{
		*outlen = cv->ciphertext->length;
		r = 1;
		goto err;
		}
	if ((int)(*outlen) < cv->ciphertext->length)
		{
		*outlen = cv->ciphertext->length;
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BUFFER_TOO_SMALL);
		goto err;
		}


	/*
	 * decode ephem_point
	 */
	if (!cv->ephem_point || !cv->ephem_point->data)
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
		}
	if (!(ephem_point = EC_POINT_new(EC_KEY_get0_group(pri_key))))
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!EC_POINT_oct2point(EC_KEY_get0_group(pri_key), ephem_point,
		cv->ephem_point->data, cv->ephem_point->length, NULL))
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
		}

	/*
	 * use ecdh to compute enckey and mackey
	 */
	if (param->sym_cipher)
		enckeylen = EVP_CIPHER_key_length(param->sym_cipher);
	else	enckeylen = cv->ciphertext->length;
	mackeylen = EVP_MD_size(param->mac_md);
	sharelen = enckeylen + mackeylen;

	if (!(share = OPENSSL_malloc(sharelen)))
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (!ECDH_compute_key(share, enckeylen + mackeylen,
		ephem_point, pri_key,
		KDF_get_x9_63(param->kdf_md)))
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_ECDH_FAILED);
		goto err;
		}
	enckey = share;
	mackey = share + enckeylen;

	/*
	 * generate and verify mac
	 */
	if (!cv->mactag || !cv->mactag->data)
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_BAD_DATA);
		goto err;
		}
	if (!HMAC(param->mac_md, mackey, mackeylen,
		cv->ciphertext->data, (size_t)cv->ciphertext->length,
		mac, (unsigned int *)&len))
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_GEN_MAC_FAILED);
		goto err;
		}
	if (len != cv->mactag->length)
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_VERIFY_MAC_FAILED);
		goto err;
		}
	if (OPENSSL_memcmp(cv->mactag->data, mac, len))
		{
		ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_VERIFY_MAC_FAILED);
		goto err;
		}

	/*
	 * decrypt ciphertext and output
	 */
	if (param->sym_cipher)
		{
		unsigned char iv[EVP_MAX_IV_LENGTH];
		memset(iv, 0, sizeof(iv));
		if (!EVP_DecryptInit(&ctx, param->sym_cipher, enckey, iv))
			{
			ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_DECRYPT_FAILED);
			goto err;
			}
		p = out;
		if (!EVP_DecryptUpdate(&ctx, p, &len,
			cv->ciphertext->data, cv->ciphertext->length))
			{
			ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_DECRYPT_FAILED);
			goto err;
			}
		p += len;
		if (!EVP_DecryptFinal(&ctx, p, &len))
			{
			ECIESerr(ECIES_F_ECIES_DO_DECRYPT, ECIES_R_DECRYPT_FAILED);
			goto err;
			}
		p += len;
		*outlen = (int)(p - out);
		}
		else
		{
		int i;
		for (i = 0; i < cv->ciphertext->length; i++)
			out[i] = cv->ciphertext->data[i] ^ enckey[i];
		*outlen = cv->ciphertext->length;
		}

	r = 1;
err:
	if (share) OPENSSL_free(share);
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (ephem_point) EC_POINT_free(ephem_point);

	return r;
}

int ECIES_encrypt(const ECIES_PARAMS *param,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen,
	EC_KEY *ec_key)
{
	int ret = 0;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	unsigned char *p = out;
	int len;

	if (!(cv = ECIES_do_encrypt(param, in, inlen, ec_key))) {
		ECIESerr(ECIES_F_ECIES_ENCRYPT, ECIES_R_ENCRYPT_FAILED);
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		return 0;
	}

	if ((len = i2d_ECIES_CIPHERTEXT_VALUE(cv, NULL)) <= 0) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ECIESerr(ECIES_F_ECIES_ENCRYPT, ECIES_R_ENCRYPT_FAILED);
		goto end;
	}

	if (!out) {
		*outlen = (size_t)len;
		ret = 1;
		goto end;
	}

	if (*outlen < len) {
		ECIESerr(ECIES_F_ECIES_ENCRYPT, ECIES_R_ENCRYPT_FAILED);
		*outlen = (size_t)len;
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if ((len = i2d_ECIES_CIPHERTEXT_VALUE(cv, &p)) <= 0) {
		ECIESerr(ECIES_F_ECIES_ENCRYPT, ECIES_R_ENCRYPT_FAILED);
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	*outlen = (size_t)len;
	ret = 1;

end:
	ECIES_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

int ECIES_decrypt(const ECIES_PARAMS *param,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen,
	EC_KEY *ec_key)
{
	int ret = 0;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	const unsigned char *p = in;

	if (!(cv = d2i_ECIES_CIPHERTEXT_VALUE(NULL, &p, (long)inlen))) {
		ECIESerr(ECIES_F_ECIES_DECRYPT, ECIES_R_ENCRYPT_FAILED);
		return 0;
	}

	if (!ECIES_do_decrypt(cv, param, out, outlen, ec_key)) {
		ECIESerr(ECIES_F_ECIES_DECRYPT, ECIES_R_ENCRYPT_FAILED);
		goto end;
	}

	ret = 1;
end:
	ECIES_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

int ECIES_PARAMS_init_with_recommended(ECIES_PARAMS *param)
{
	if (!param) {
		return 0;
	}
	param->kdf_nid = NID_undef;
	param->kdf_md = EVP_sha1(); //FIXME: EVP_sha256() will error
	param->sym_cipher = EVP_aes_128_cbc();
	param->mac_nid = NID_hmac_full_ecies;
	param->mac_md = EVP_sha1(); //FIXME: EVP_sha256() need test
	param->mac_cipher = NULL;
	return 1;
}

int ECIES_encrypt_with_recommended(unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen,
	EC_KEY *ec_key)
{
	ECIES_PARAMS param;
	ECIES_PARAMS_init_with_recommended(&param);
	return ECIES_encrypt(&param, out, outlen, in, inlen, ec_key);
}

int ECIES_decrypt_with_recommended(unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen,
	EC_KEY *ec_key)
{
	ECIES_PARAMS param;
	ECIES_PARAMS_init_with_recommended(&param);
	return ECIES_decrypt(&param, out, outlen, in, inlen, ec_key);
}

