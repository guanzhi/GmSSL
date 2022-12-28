/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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

#ifdef __cplusplus
extern "C" {
#endif


int file_size(FILE *fp, size_t *size);


#ifdef __cplusplus
}
#endif
#endif
