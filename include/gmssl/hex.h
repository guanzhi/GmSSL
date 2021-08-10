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


int hex2bin(const char *in, size_t inlen, uint8_t *out);
//int OPENSSL_hexchar2int(unsigned char c);
//unsigned char *OPENSSL_hexstr2buf(const char *str, size_t *len);

#ifdef __cplusplus
}
#endif
#endif
