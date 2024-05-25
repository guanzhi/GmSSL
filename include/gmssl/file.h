/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_FILE_H
#define GMSSL_FILE_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


int file_size(FILE *fp, size_t *size);
int file_read_all(const char *file, uint8_t **out, size_t *outlen);


#ifdef __cplusplus
}
#endif
#endif
