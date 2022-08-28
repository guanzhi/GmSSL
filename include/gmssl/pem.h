/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_PEM_H
#define GMSSL_PEM_H


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/base64.h>


#ifdef __cplusplus
extern "C" {
#endif


int pem_read(FILE *fp, const char *name, uint8_t *out, size_t *outlen, size_t maxlen);
int pem_write(FILE *fp, const char *name, const uint8_t *in, size_t inlen);


#ifdef __cplusplus
}
#endif
#endif
