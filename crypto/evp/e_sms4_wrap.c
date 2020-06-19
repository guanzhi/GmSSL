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
    } ks;
    /* Indicates if IV has been set */
    unsigned char *iv;
} EVP_SMS4_WRAP_CTX;

static int sms4_wrap_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc)
{
    EVP_SMS4_WRAP_CTX *wctx = EVP_C_DATA(EVP_SMS4_WRAP_CTX,ctx);
    if (!iv && !key)
        return 1;
    if (key) {
        if (EVP_CIPHER_CTX_encrypting(ctx))
            sms4_set_encrypt_key(&wctx->ks.ks, key);
        else
            sms4_set_decrypt_key(&wctx->ks.ks, key);
        if (!iv)
            wctx->iv = NULL;
    }
    if (iv) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, EVP_CIPHER_CTX_iv_length(ctx));
        wctx->iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    }
    return 1;
}

static int sms4_wrap_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inlen)
{
    EVP_SMS4_WRAP_CTX *wctx = EVP_C_DATA(EVP_SMS4_WRAP_CTX,ctx);
    size_t rv;
    /* SMS4 wrap with padding has IV length of 4, without padding 8 */
    int pad = EVP_CIPHER_CTX_iv_length(ctx) == 4;
    /* No final operation so always return zero length */
    if (!in)
        return 0;
    /* Input length must always be non-zero */
    if (!inlen)
        return -1;
    /* If decrypting need at least 16 bytes and multiple of 8 */
    if (!EVP_CIPHER_CTX_encrypting(ctx) && (inlen < 16 || inlen & 0x7))
        return -1;
    /* If not padding input must be multiple of 8 */
    if (!pad && inlen & 0x7)
        return -1;
    if (!out) {
        if (EVP_CIPHER_CTX_encrypting(ctx)) {
            /* If padding round up to multiple of 8 */
            if (pad)
                inlen = (inlen + 7) / 8 * 8;
            /* 8 byte prefix */
            return inlen + 8;
        } else {
            /*
             * If not padding output will be exactly 8 bytes smaller than
             * input. If padding it will be at least 8 bytes smaller but we
             * don't know how much.
             */
            return inlen - 8;
        }
    }
    if (pad) {
        if (EVP_CIPHER_CTX_encrypting(ctx))
            rv = CRYPTO_128_wrap_pad(&wctx->ks.ks, wctx->iv,
                                     out, in, inlen,
                                     (block128_f)sms4_encrypt);
        else
            rv = CRYPTO_128_unwrap_pad(&wctx->ks.ks, wctx->iv,
                                       out, in, inlen,
                                       (block128_f)sms4_encrypt);
    } else {
        if (EVP_CIPHER_CTX_encrypting(ctx))
            rv = CRYPTO_128_wrap(&wctx->ks.ks, wctx->iv,
                                 out, in, inlen, (block128_f)sms4_encrypt);
        else
            rv = CRYPTO_128_unwrap(&wctx->ks.ks, wctx->iv,
                                   out, in, inlen, (block128_f)sms4_encrypt);
    }
    return rv ? (int)rv : -1;
}

# define SMS4_WRAP_FLAGS	    (EVP_CIPH_WRAP_MODE \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1)



static const EVP_CIPHER sms4_wrap = {
    NID_sms4_wrap,
    8, 16, 8, SMS4_WRAP_FLAGS,
    sms4_wrap_init_key, sms4_wrap_cipher,
    NULL,
    sizeof(EVP_SMS4_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sms4_wrap(void)
{
    return &sms4_wrap;
}

static const EVP_CIPHER sms4_wrap_pad = {
    NID_sms4_wrap_pad,
    8, 16, 4, SMS4_WRAP_FLAGS,
    sms4_wrap_init_key, sms4_wrap_cipher,
    NULL,
    sizeof(EVP_SMS4_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sms4_wrap_pad(void)
{
    return &sms4_wrap_pad;
}
#endif /* OPENSSL_NO_SMS4 */
