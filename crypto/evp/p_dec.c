/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#ifndef OPENSSL_NO_SM2
# include <openssl/sm2.h>
#endif

int EVP_PKEY_decrypt_old(unsigned char *key, const unsigned char *ek, int ekl,
                         EVP_PKEY *priv)
{
	int ret = 0;
	EVP_PKEY_CTX *ctx = NULL;
	size_t siz;

#ifndef OPENSSL_NO_RSA
	if (EVP_PKEY_id(priv) == EVP_PKEY_RSA) {
		if ((ret = RSA_private_decrypt(ekl, ek, key, EVP_PKEY_get0_RSA(priv), RSA_PKCS1_PADDING)) < 0) {
			EVPerr(EVP_F_EVP_PKEY_DECRYPT_OLD, ERR_R_RSA_LIB);
			return 0;
		}
	}
#endif

#ifndef OPENSSL_NO_SM2
	siz = ekl;
	if (!(ctx = EVP_PKEY_CTX_new(priv, NULL))
		|| !EVP_PKEY_decrypt_init(ctx)) {
		EVPerr(EVP_F_EVP_PKEY_DECRYPT_OLD, ERR_R_EVP_LIB);
		goto end;
	}

	if (EVP_PKEY_id(priv) == EVP_PKEY_EC && EC_GROUP_get_curve_name(
		EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(priv))) == NID_sm2p256v1) {
#  ifdef SM2_DEBUG
		fprintf(stderr, "[SM2_DEBUG] %s->EVP_PKEY_CTX_set_ec_scheme\n", __FUNCTION__);
#  endif
		if (EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) <= 0
			|| EVP_PKEY_CTX_set_ec_encrypt_param(ctx, NID_sm3) <= 0) {
			goto end;
		}
	}

	if (!EVP_PKEY_decrypt(ctx, key, &siz, ek, ekl)) {
		EVPerr(EVP_F_EVP_PKEY_DECRYPT_OLD, ERR_R_EVP_LIB);
		goto end;
	}

	ret = (int)siz;
#endif

end:
	EVP_PKEY_CTX_free(ctx);
	return (ret);
}
