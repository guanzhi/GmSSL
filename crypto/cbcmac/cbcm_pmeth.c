/* crypto/cbcmac/cbcm_pmeth.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
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
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2010.
 */
/* ====================================================================
 * Copyright (c) 2010 The OpenSSL Project.  All rights reserved.
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
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
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
#include "cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/cbcmac.h>
#include "evp_locl.h"

static int pkey_cbcmac_init(EVP_PKEY_CTX *ctx)
{
    ctx->data = CBCMAC_CTX_new();
    if (!ctx->data)
        return 0;
    ctx->keygen_info_count = 0;
    return 1;
}

static int pkey_cbcmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    if (!pkey_cbcmac_init(dst))
        return 0;
    if (!CBCMAC_CTX_copy(dst->data, src->data))
        return 0;
    return 1;
}

static void pkey_cbcmac_cleanup(EVP_PKEY_CTX *ctx)
{
    CBCMAC_CTX_free(ctx->data);
}

static int pkey_cbcmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    CBCMAC_CTX *cmkey = CBCMAC_CTX_new();
    CBCMAC_CTX *cmctx = ctx->data;
    if (!cmkey)
        return 0;
    if (!CBCMAC_CTX_copy(cmkey, cmctx)) {
        CBCMAC_CTX_free(cmkey);
        return 0;
    }
    EVP_PKEY_assign(pkey, EVP_PKEY_CBCMAC, cmkey);

    return 1;
}

static int int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (!CBCMAC_Update(ctx->pctx->data, data, count))
        return 0;
    return 1;
}

static int cbcmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    mctx->update = int_update;
    return 1;
}

static int cbcmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        EVP_MD_CTX *mctx)
{
    return CBCMAC_Final(ctx->data, sig, siglen);
}

static int pkey_cbcmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    CBCMAC_CTX *cmctx = ctx->data;
    switch (type) {

    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if (!p2 || p1 < 0)
            return 0;
        if (!CMAC_Init(cmctx, p2, p1, NULL, NULL))
            return 0;
        break;

    case EVP_PKEY_CTRL_CIPHER:
        if (!CBCMAC_Init(cmctx, NULL, 0, p2, ctx->engine))
            return 0;
        break;

    case EVP_PKEY_CTRL_MD:
        if (ctx->pkey && !CBCMAC_CTX_copy(ctx->data,
                                        (CBCMAC_CTX *)ctx->pkey->pkey.ptr))
            return 0;
        if (!CBCMAC_Init(cmctx, NULL, 0, NULL, NULL))
            return 0;
        break;

    default:
        return -2;

    }
    return 1;
}

static int pkey_cbcmac_ctrl_str(EVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    if (!value) {
        return 0;
    }
    if (!strcmp(type, "key")) {
        void *p = (void *)value;
        return pkey_cbcmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, strlen(p), p);
    }
    if (!strcmp(type, "cipher")) {
        const EVP_CIPHER *c;
        c = EVP_get_cipherbyname(value);
        if (!c)
            return 0;
        return pkey_cbcmac_ctrl(ctx, EVP_PKEY_CTRL_CIPHER, -1, (void *)c);
    }
    if (!strcmp(type, "hexkey")) {
        unsigned char *key;
        int r;
        long keylen;
        key = string_to_hex(value, &keylen);
        if (!key)
            return 0;
        r = pkey_cbcmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, keylen, key);
        OPENSSL_free(key);
        return r;
    }
    return -2;
}

const EVP_PKEY_METHOD cbcmac_pkey_meth = {
    EVP_PKEY_CBCMAC,
    EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    pkey_cbcmac_init,
    pkey_cbcmac_copy,
    pkey_cbcmac_cleanup,

    0, 0,

    0,
    pkey_cbcmac_keygen,

    0, 0,

    0, 0,

    0, 0,

    cbcmac_signctx_init,
    cbcmac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_cbcmac_ctrl,
    pkey_cbcmac_ctrl_str
};
