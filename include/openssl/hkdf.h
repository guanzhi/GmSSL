/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_HKDF_H
# define HEADER_HKDF_H

#include <string.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned char *HKDF(const EVP_MD *evp_md,
                    const unsigned char *salt, size_t salt_len,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *info, size_t info_len,
                    unsigned char *okm, size_t okm_len);

unsigned char *HKDF_Extract(const EVP_MD *evp_md,
                            const unsigned char *salt, size_t salt_len,
                            const unsigned char *key, size_t key_len,
                            unsigned char *prk, size_t *prk_len);

unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                           const unsigned char *prk, size_t prk_len,
                           const unsigned char *info, size_t info_len,
                           unsigned char *okm, size_t okm_len);

# ifdef  __cplusplus
}
# endif
#endif
