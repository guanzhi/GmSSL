/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_HEX_H
#define GMSSL_HEX_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

int hex_to_bytes(const char *in, size_t inlen, uint8_t *out, size_t *outlen);


#ifdef __cplusplus
}
#endif
#endif
