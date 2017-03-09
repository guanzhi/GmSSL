/*
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
 */

#include <string.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/sm2.h>
#include <openssl/ecies.h>
#include "../ec/ec_lcl.h"
#include "sm2_lcl.h"

#define SM2_KMETH_FLAGS		0


int SM2_ENC_PARAMS_set_type(SM2_ENC_PARAMS *params, int type)
{
	const EVP_MD *md;
	if (!(md = EVP_get_digestbynid(type))) {
		ECerr(EC_F_SM2_ENC_PARAMS_SET_TYPE, EC_R_INVALID_DIGEST_TYPE);
		return 0;
	}
	params->kdf_md = md;
	params->mac_md = md;
	params->point_form = SM2_DEFAULT_POINT_CONVERSION_FORM;
	return 1;
}

SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_new_from_ECIES_CIPHERTEXT_VALUE(
	const ECIES_CIPHERTEXT_VALUE *in)
{
	ECerr(EC_F_SM2_CIPHERTEXT_VALUE_NEW_FROM_ECIES_CIPHERTEXT_VALUE,
		ERR_R_EC_LIB);
	return NULL;
}

int SM2_CIPHERTEXT_VALUE_set_ECIES_CIPHERTEXT_VALUE(SM2_CIPHERTEXT_VALUE *sm2,
	const ECIES_CIPHERTEXT_VALUE *in)
{
	ECerr(EC_F_SM2_CIPHERTEXT_VALUE_SET_ECIES_CIPHERTEXT_VALUE,
		ERR_R_EC_LIB);
	return 0;
}

int SM2_CIPHERTEXT_VALUE_get_ECIES_CIPHERTEXT_VALUE(
	const SM2_CIPHERTEXT_VALUE *sm2, ECIES_CIPHERTEXT_VALUE *out)
{
	ECerr(EC_F_SM2_CIPHERTEXT_VALUE_GET_ECIES_CIPHERTEXT_VALUE,
		ERR_R_EC_LIB);
	return 0;
}

static int sm2_compute_key(unsigned char **Pout, size_t *poutlen,
	const EC_POINT *pub_key, const EC_KEY *ec_key)
{
	return 0;
}

static int sm2_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	SM2_ENC_PARAMS param;
	if (!SM2_ENC_PARAMS_set_type(&param, type)) {
		return 0;
	}
	return SM2_encrypt(&param, in, inlen, out, outlen, ec_key);
}

ECIES_CIPHERTEXT_VALUE *sm2_do_encrypt(int type, const unsigned char *in,
	size_t inlen, EC_KEY *ec_key)
{
	ECIES_CIPHERTEXT_VALUE *ret = NULL;
	ECIES_CIPHERTEXT_VALUE *ecies = NULL;
	SM2_CIPHERTEXT_VALUE *sm2 = NULL;
	SM2_ENC_PARAMS param;

	if (!(ecies = ECIES_CIPHERTEXT_VALUE_new())) {
		goto end;
	}
	if (!SM2_ENC_PARAMS_set_type(&param, type)) {
		goto end;
	}
	if (!(sm2 = SM2_do_encrypt(&param, in, inlen, ec_key))) {
		goto end;
	}
	if (!SM2_CIPHERTEXT_VALUE_get_ECIES_CIPHERTEXT_VALUE(sm2, ecies)) {
		goto end;
	}

	ret = ecies;
	ecies = NULL;

end:
	ECIES_CIPHERTEXT_VALUE_free(ecies);
	SM2_CIPHERTEXT_VALUE_free(sm2);
	return ret;
}

int sm2_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	SM2_ENC_PARAMS param;
	if (!SM2_ENC_PARAMS_set_type(&param, type)) {
		return 0;
	}
	return SM2_decrypt(&param, in, inlen, out, outlen, ec_key);
}

int sm2_do_decrypt(int type, const ECIES_CIPHERTEXT_VALUE *in,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	SM2_CIPHERTEXT_VALUE *sm2 = NULL;
	SM2_ENC_PARAMS param;

	if (!SM2_ENC_PARAMS_set_type(&param, type)) {
		goto end;
	}
	// we might require type/param
	if (!(sm2 = SM2_CIPHERTEXT_VALUE_new_from_ECIES_CIPHERTEXT_VALUE(in))) {
		goto end;
	}
	if (!SM2_do_decrypt(&param, sm2, out, outlen, ec_key)) {
		goto end;
	}

	ret = 1;
end:
	SM2_CIPHERTEXT_VALUE_free(sm2);
	return ret;
}

static const EC_KEY_METHOD gmssl_ec_key_method = {
	"GmSSL EC_KEY method",
	EC_KEY_METHOD_SM2,
	0,0,0,0,0,0,
	ossl_ec_key_gen,
	sm2_compute_key,
	SM2_sign,
	SM2_sign_setup,
	SM2_do_sign,
	SM2_verify,
	SM2_do_verify,
	sm2_encrypt,
	sm2_do_encrypt,
	sm2_decrypt,
	sm2_do_decrypt,
};

const EC_KEY_METHOD *EC_KEY_GmSSL(void)
{
	return &gmssl_ec_key_method;
}

int EC_KEY_METHOD_type(const EC_KEY_METHOD *meth)
{
	if (meth->flags & EC_KEY_METHOD_SM2) {
		return NID_sm_scheme;
	} else {
		return NID_secg_scheme;
	}
}


void EC_KEY_METHOD_set_encrypt(EC_KEY_METHOD *meth,
                               int (*encrypt)(int type,
                                              const unsigned char *in,
                                              size_t inlen,
                                              unsigned char *out,
                                              size_t *outlen,
                                              EC_KEY *ec_key),
                               ECIES_CIPHERTEXT_VALUE *(*do_encrypt)(int type,
                                              const unsigned char *in,
                                              size_t inlen,
                                              EC_KEY *ec_key))
{
    meth->encrypt = encrypt;
    meth->do_encrypt = do_encrypt;
}

void EC_KEY_METHOD_set_decrypt(EC_KEY_METHOD *meth,
                               int (*decrypt)(int type,
                                              const unsigned char *in,
                                              size_t inlen,
                                              unsigned char *out,
                                              size_t *outlen,
                                              EC_KEY *ec_key),
                               int (do_decrypt)(int type,
                                                const ECIES_CIPHERTEXT_VALUE *in,
                                                unsigned char *out,
                                                size_t *outlen,
                                                EC_KEY *ec_key))
{
    meth->decrypt = decrypt;
    meth->do_decrypt = do_decrypt;
}

void EC_KEY_METHOD_get_encrypt(EC_KEY_METHOD *meth,
                               int (**pencrypt)(int type,
                                                const unsigned char *in,
                                                size_t inlen,
                                                unsigned char *out,
                                                size_t *outlen,
                                                EC_KEY *ec_key),
                               ECIES_CIPHERTEXT_VALUE *(**pdo_encrypt)(int type,
                                                const unsigned char *in,
                                                size_t inlen,
                                                EC_KEY *ec_key))
{
    if (pencrypt != NULL)
        *pencrypt = meth->encrypt;
    if (pdo_encrypt != NULL)
        *pdo_encrypt = meth->do_encrypt;
}

void EC_KEY_METHOD_get_decrypt(EC_KEY_METHOD *meth,
                               int (**pdecrypt)(int type,
                                                const unsigned char *in,
                                                size_t inlen,
                                                unsigned char *out,
                                                size_t *outlen,
                                                EC_KEY *ec_key),
                               int (**pdo_decrypt)(int type,
                                                   const ECIES_CIPHERTEXT_VALUE *in,
                                                   unsigned char *out,
                                                   size_t *outlen,
                                                   EC_KEY *ec_key))
{
	if (pdecrypt != NULL)
		*pdecrypt = meth->decrypt;
	if (pdo_decrypt != NULL)
		*pdo_decrypt = meth->do_decrypt;
}
