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
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include "evp_locl.h"
#include "internal/evp_int.h"
#include "modes_lcl.h"

#ifndef OPENSSL_NO_SMS4
# include <openssl/sms4.h>

typedef struct {
    union {
        double align;
        sms4_key_t ks;
    } ks1, ks2;                 /* SMS4 key schedules to use */
    XTS128_CONTEXT xts;
    void (*stream) (const unsigned char *in,
                    unsigned char *out, size_t length,
                    const sms4_key_t *key1, const sms4_key_t *key2,
                    const unsigned char iv[16]);
} EVP_SMS4_XTS_CTX;

static int sms4_xts_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SMS4_XTS_CTX *xctx = EVP_C_DATA(EVP_SMS4_XTS_CTX,c);
    if (type == EVP_CTRL_COPY) {
        EVP_CIPHER_CTX *out = ptr;
        EVP_SMS4_XTS_CTX *xctx_out = EVP_C_DATA(EVP_SMS4_XTS_CTX,out);
        if (xctx->xts.key1) {
            if (xctx->xts.key1 != &xctx->ks1)
                return 0;
            xctx_out->xts.key1 = &xctx_out->ks1;
        }
        if (xctx->xts.key2) {
            if (xctx->xts.key2 != &xctx->ks2)
                return 0;
            xctx_out->xts.key2 = &xctx_out->ks2;
        }
        return 1;
    } else if (type != EVP_CTRL_INIT)
        return -1;
    /* key1 and key2 are used as an indicator both key and IV are set */
    xctx->xts.key1 = NULL;
    xctx->xts.key2 = NULL;
    return 1;
}

static int sms4_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    EVP_SMS4_XTS_CTX *xctx = EVP_C_DATA(EVP_SMS4_XTS_CTX, ctx);
    if (!iv && !key)
        return 1;

    if (key) {
        xctx->stream = NULL;
        if (enc) {
            sms4_set_encrypt_key(&xctx->ks1.ks, key);
        } else {
            sms4_set_decrypt_key(&xctx->ks1.ks, key);
        }
        sms4_set_encrypt_key(&xctx->ks2.ks, key + SMS4_KEY_LENGTH);
        xctx->xts.block1 = (block128_f)sms4_encrypt;
        xctx->xts.block2 = (block128_f)sms4_encrypt;
        xctx->xts.key1 = &xctx->ks1;
    }

    if (iv) {
        xctx->xts.key2 = &xctx->ks2;
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 16);
    }

    return 1;
}

static int sms4_xts_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    EVP_SMS4_XTS_CTX *xctx = EVP_C_DATA(EVP_SMS4_XTS_CTX,ctx);
    if (!xctx->xts.key1 || !xctx->xts.key2)
        return 0;
    if (!out || !in || len < SMS4_BLOCK_SIZE)
        return 0;
    if (xctx->stream)
        (*xctx->stream) (in, out, len,
                         xctx->xts.key1, xctx->xts.key2,
                         EVP_CIPHER_CTX_iv_noconst(ctx));
    else if (CRYPTO_xts128_encrypt(&xctx->xts, EVP_CIPHER_CTX_iv_noconst(ctx),
                                   in, out, len,
                                   EVP_CIPHER_CTX_encrypting(ctx)))
        return 0;
    return 1;
}

# define SMS4_XTS_BLOCK_SIZE	1

# define SMS4_XTS_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                         | EVP_CIPH_CUSTOM_COPY)

static const EVP_CIPHER sms4_xts = {
	NID_sms4_xts,
	SMS4_XTS_BLOCK_SIZE,
	SMS4_KEY_LENGTH * 2,
	SMS4_IV_LENGTH,
	SMS4_XTS_FLAGS,
	sms4_xts_init_key,
	sms4_xts_cipher,
	NULL,
	sizeof(EVP_SMS4_XTS_CTX),
	NULL, NULL, sms4_xts_ctrl, NULL
};

const EVP_CIPHER *EVP_sms4_xts(void) {
	return &sms4_xts;
}
#endif /* OPENSSL_NO_SMS4 */
