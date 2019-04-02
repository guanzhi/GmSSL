/*
 * Copyright (C) 2017 Nagravision S.A.
 */

#include "../aes.h"
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>


int aesctr256 (uint8_t *out, const uint8_t *sk, const void *counter, int bytes) {
    static const uint8_t buffer[4096] = { 0 };
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ret = 0;

    if (bytes == 0) return 0;

    if (!(ctx = EVP_CIPHER_CTX_new ())) {
        ret = -2;
        goto label_exit_0;
    }

    if (1 != EVP_EncryptInit_ex (ctx, EVP_aes_256_ctr (), NULL, sk, counter)) {
        ret = -3;
        goto label_exit_1;
    }

    while (bytes >= (int)sizeof (buffer)) {
        if (1 != EVP_EncryptUpdate (ctx, out, &len, buffer, sizeof (buffer))) {
            ret = -4;
            goto label_exit_1;
        }
        out += sizeof (buffer);
        bytes -= sizeof (buffer);
    }
    if (bytes) {
        if (1 != EVP_EncryptUpdate (ctx, out, &len, buffer, bytes)) {
            ret = -4;
            goto label_exit_1;
        }
    }

    if (1 != EVP_EncryptFinal_ex (ctx, out + len, &len)) {
        ret = -5;
        goto label_exit_1;
    }

    ret = 0;
label_exit_1:
    EVP_CIPHER_CTX_free (ctx);
label_exit_0:
    return ret;
}

int aesctr256_zeroiv (uint8_t *out, const uint8_t *sk, int bytes) {
    uint8_t counter[16] = {0};
    return aesctr256(out, sk, counter, bytes);
}
