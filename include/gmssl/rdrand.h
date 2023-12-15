/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_RDRAND_H
#define GMSSL_RDRAND_H

#include <stdint.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif


int rdrand_bytes(uint8_t *buf, size_t buflen);

#ifdef INTEL_RDSEED
int rdseed_bytes(uint8_t *buf, size_t buflen);
#endif


#ifdef __cplusplus
}
#endif
#endif
