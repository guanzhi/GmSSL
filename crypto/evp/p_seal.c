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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 unsigned char **ek, int *ekl, unsigned char *iv,
                 EVP_PKEY **pubk, int npubk)
{
    unsigned char key[EVP_MAX_KEY_LENGTH];
    int i;

    if (type) {
        EVP_CIPHER_CTX_reset(ctx);
        if (!EVP_EncryptInit_ex(ctx, type, NULL, NULL, NULL))
            return 0;
    }
    if ((npubk <= 0) || !pubk)
        return 1;
    if (EVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
        return 0;
    if (EVP_CIPHER_CTX_iv_length(ctx)
        && RAND_bytes(iv, EVP_CIPHER_CTX_iv_length(ctx)) <= 0)
        return 0;

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return 0;

    for (i = 0; i < npubk; i++) {
        ekl[i] =
            EVP_PKEY_encrypt_old(ek[i], key, EVP_CIPHER_CTX_key_length(ctx),
                                 pubk[i]);
        if (ekl[i] <= 0)
            return (-1);
    }
    return (npubk);
}

/*- MACRO
void EVP_SealUpdate(ctx,out,outl,in,inl)
EVP_CIPHER_CTX *ctx;
unsigned char *out;
int *outl;
unsigned char *in;
int inl;
        {
        EVP_EncryptUpdate(ctx,out,outl,in,inl);
        }
*/

int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i;
    i = EVP_EncryptFinal_ex(ctx, out, outl);
    if (i)
        i = EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
    return i;
}
