/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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


int pem_read(FILE *fp, const char *name, uint8_t *data, size_t *datalen);
int pem_write(FILE *fp, const char *name, const uint8_t *data, size_t datalen);



#ifdef __cplusplus
}
#endif
#endif
