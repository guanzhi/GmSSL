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
#include <openssl/err.h>
#include <openssl/sm2.h>
#include <openssl/ecies.h>
#include "../ec/ec_lcl.h"
#include "sm2_lcl.h"

#define SM2_KMETH_FLAGS		0


int EC_KEY_is_sm2p256v1(const EC_KEY *ec_key)
{
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	if (group)
		return EC_GROUP_get_curve_name(group) == NID_sm2p256v1;
	return 0;
}

static const EC_KEY_METHOD gmssl_ec_key_method = {
	"SM2 method",		/* name */
	EC_KEY_METHOD_SM2,	/* flags */
	NULL,			/* init */
	NULL,			/* finish */
	0,			/* copy */
	0,			/* set_group */
	0,			/* set_private */
	0,			/* set_public */
	ossl_ec_key_gen,	/* keygen */
	NULL,			/* compute_key */
	SM2_sign_ex,		/* sign */
	SM2_sign_setup,		/* sign_setup */
	SM2_do_sign_ex,		/* sign_sig */
	SM2_verify,		/* verify */
	SM2_do_verify,		/* verify_sig */
	SM2_encrypt,		/* encrypt */
	NULL,			/* do_encrypt */
	SM2_decrypt,		/* decrypt */
	NULL,			/* do_decrypt */
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
