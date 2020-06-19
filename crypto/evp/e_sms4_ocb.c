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

# ifndef OPENSSL_NO_OCB

typedef struct {
    union {
        double align;
        sms4_key_t ks;
    } ksenc;                    /* SMS4 key schedule to use for encryption */
    union {
        double align;
        sms4_key_t ks;
    } ksdec;                    /* SMS4 key schedule to use for decryption */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    OCB128_CONTEXT ocb;
    unsigned char *iv;          /* Temporary IV store */
    unsigned char tag[16];
    unsigned char data_buf[16]; /* Store partial data blocks */
    unsigned char aad_buf[16];  /* Store partial AAD blocks */
    int data_buf_len;
    int aad_buf_len;
    int ivlen;                  /* IV length */
    int taglen;
} EVP_SMS4_OCB_CTX;

static int sms4_ocb_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SMS4_OCB_CTX *octx = EVP_C_DATA(EVP_SMS4_OCB_CTX,c);
    EVP_CIPHER_CTX *newc;
    EVP_SMS4_OCB_CTX *new_octx;

    switch (type) {
    case EVP_CTRL_INIT:
        octx->key_set = 0;
        octx->iv_set = 0;
        octx->ivlen = EVP_CIPHER_CTX_iv_length(c);
        octx->iv = EVP_CIPHER_CTX_iv_noconst(c);
        octx->taglen = 16;
        octx->data_buf_len = 0;
        octx->aad_buf_len = 0;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        /* IV len must be 1 to 15 */
        if (arg <= 0 || arg > 15)
            return 0;

        octx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (!ptr) {
            /* Tag len must be 0 to 16 */
            if (arg < 0 || arg > 16)
                return 0;

            octx->taglen = arg;
            return 1;
        }
        if (arg != octx->taglen || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(octx->tag, ptr, arg);
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg != octx->taglen || !EVP_CIPHER_CTX_encrypting(c))
            return 0;

        memcpy(ptr, octx->tag, arg);
        return 1;

    case EVP_CTRL_COPY:
        newc = (EVP_CIPHER_CTX *)ptr;
        new_octx = EVP_C_DATA(EVP_SMS4_OCB_CTX,newc);
        return CRYPTO_ocb128_copy_ctx(&new_octx->ocb, &octx->ocb,
                                      &new_octx->ksenc.ks,
                                      &new_octx->ksdec.ks);

    default:
        return -1;

    }
}

static int sms4_ocb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    EVP_SMS4_OCB_CTX *octx = EVP_C_DATA(EVP_SMS4_OCB_CTX,ctx);
    if (!iv && !key)
        return 1;
    if (key) {
        do {
            /*
             * We set both the encrypt and decrypt key here because decrypt
             * needs both. We could possibly optimise to remove setting the
             * decrypt for an encryption operation.
             */
            sms4_set_encrypt_key(&octx->ksenc.ks, key);
            sms4_set_decrypt_key(&octx->ksdec.ks, key);
            if (!CRYPTO_ocb128_init(&octx->ocb,
                                    &octx->ksenc.ks, &octx->ksdec.ks,
                                    (block128_f)sms4_encrypt,
                                    (block128_f)sms4_encrypt,
                                    NULL))
                return 0;
        }
        while (0);

        /*
         * If we have an iv we can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && octx->iv_set)
            iv = octx->iv;
        if (iv) {
            if (CRYPTO_ocb128_setiv(&octx->ocb, iv, octx->ivlen, octx->taglen)
                != 1)
                return 0;
            octx->iv_set = 1;
        }
        octx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (octx->key_set)
            CRYPTO_ocb128_setiv(&octx->ocb, iv, octx->ivlen, octx->taglen);
        else
            memcpy(octx->iv, iv, octx->ivlen);
        octx->iv_set = 1;
    }
    return 1;
}

static int sms4_ocb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    unsigned char *buf;
    int *buf_len;
    int written_len = 0;
    size_t trailing_len;
    EVP_SMS4_OCB_CTX *octx = EVP_C_DATA(EVP_SMS4_OCB_CTX,ctx);

    /* If IV or Key not set then return error */
    if (!octx->iv_set)
        return -1;

    if (!octx->key_set)
        return -1;

    if (in) {
        /*
         * Need to ensure we are only passing full blocks to low level OCB
         * routines. We do it here rather than in EVP_EncryptUpdate/
         * EVP_DecryptUpdate because we need to pass full blocks of AAD too
         * and those routines don't support that
         */

        /* Are we dealing with AAD or normal data here? */
        if (out == NULL) {
            buf = octx->aad_buf;
            buf_len = &(octx->aad_buf_len);
        } else {
            buf = octx->data_buf;
            buf_len = &(octx->data_buf_len);
        }

        /*
         * If we've got a partially filled buffer from a previous call then
         * use that data first
         */
        if (*buf_len) {
            unsigned int remaining;

            remaining = 16 - (*buf_len);
            if (remaining > len) {
                memcpy(buf + (*buf_len), in, len);
                *(buf_len) += len;
                return 0;
            }
            memcpy(buf + (*buf_len), in, remaining);

            /*
             * If we get here we've filled the buffer, so process it
             */
            len -= remaining;
            in += remaining;
            if (out == NULL) {
                if (!CRYPTO_ocb128_aad(&octx->ocb, buf, 16))
                    return -1;
            } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
                if (!CRYPTO_ocb128_encrypt(&octx->ocb, buf, out, 16))
                    return -1;
            } else {
                if (!CRYPTO_ocb128_decrypt(&octx->ocb, buf, out, 16))
                    return -1;
            }
            written_len = 16;
            *buf_len = 0;
        }

        /* Do we have a partial block to handle at the end? */
        trailing_len = len % 16;

        /*
         * If we've got some full blocks to handle, then process these first
         */
        if (len != trailing_len) {
            if (out == NULL) {
                if (!CRYPTO_ocb128_aad(&octx->ocb, in, len - trailing_len))
                    return -1;
            } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
                if (!CRYPTO_ocb128_encrypt
                    (&octx->ocb, in, out, len - trailing_len))
                    return -1;
            } else {
                if (!CRYPTO_ocb128_decrypt
                    (&octx->ocb, in, out, len - trailing_len))
                    return -1;
            }
            written_len += len - trailing_len;
            in += len - trailing_len;
        }

        /* Handle any trailing partial block */
        if (trailing_len) {
            memcpy(buf, in, trailing_len);
            *buf_len = trailing_len;
        }

        return written_len;
    } else {
        /*
         * First of all empty the buffer of any partial block that we might
         * have been provided - both for data and AAD
         */
        if (octx->data_buf_len) {
            if (EVP_CIPHER_CTX_encrypting(ctx)) {
                if (!CRYPTO_ocb128_encrypt(&octx->ocb, octx->data_buf, out,
                                           octx->data_buf_len))
                    return -1;
            } else {
                if (!CRYPTO_ocb128_decrypt(&octx->ocb, octx->data_buf, out,
                                           octx->data_buf_len))
                    return -1;
            }
            written_len = octx->data_buf_len;
            octx->data_buf_len = 0;
        }
        if (octx->aad_buf_len) {
            if (!CRYPTO_ocb128_aad
                (&octx->ocb, octx->aad_buf, octx->aad_buf_len))
                return -1;
            octx->aad_buf_len = 0;
        }
        /* If decrypting then verify */
        if (!EVP_CIPHER_CTX_encrypting(ctx)) {
            if (octx->taglen < 0)
                return -1;
            if (CRYPTO_ocb128_finish(&octx->ocb,
                                     octx->tag, octx->taglen) != 0)
                return -1;
            octx->iv_set = 0;
            return written_len;
        }
        /* If encrypting then just get the tag */
        if (CRYPTO_ocb128_tag(&octx->ocb, octx->tag, 16) != 1)
            return -1;
        /* Don't reuse the IV */
        octx->iv_set = 0;
        return written_len;
    }
}

static int sms4_ocb_cleanup(EVP_CIPHER_CTX *c)
{
    EVP_SMS4_OCB_CTX *octx = EVP_C_DATA(EVP_SMS4_OCB_CTX,c);
    CRYPTO_ocb128_cleanup(&octx->ocb);
    return 1;
}

#  define SMS4_OCB_IV_LENGTH 12

#  define SMS4_OCB_FLAGS (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY \
		| EVP_CIPH_FLAG_AEAD_CIPHER)

static const EVP_CIPHER sms4_ocb = {
	NID_sms4_ocb,
	SMS4_BLOCK_SIZE,
	SMS4_KEY_LENGTH,
	SMS4_OCB_IV_LENGTH,
	SMS4_OCB_FLAGS,
	sms4_ocb_init_key,
	sms4_ocb_cipher,
	sms4_ocb_cleanup,
	sizeof(EVP_SMS4_OCB_CTX),
	NULL, NULL, sms4_ocb_ctrl, NULL
};

const EVP_CIPHER *EVP_sms4_ocb(void) {
	return &sms4_ocb;
}
# endif /* OPENSSL_NO_OCB */
#endif /* OPENSSL_NO_SMS4 */
