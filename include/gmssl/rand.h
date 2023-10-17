/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_RAND_H
#define GMSSL_RAND_H

#include <stdint.h>
#include <stdlib.h>
#include <gmssl/api.h>

#ifdef __cplusplus
extern "C" {
#endif


#define RAND_BYTES_MAX_SIZE	(256)

_gmssl_export int rand_bytes(uint8_t *buf, size_t buflen);


#ifdef __cplusplus
}
#endif
#endif
