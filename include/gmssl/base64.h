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


#ifndef GMSSL_BASE64_H
#define GMSSL_BASE64_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* number saved in a partial encode/decode */
    int num;
    /*
     * The length is either the output line length (in input bytes) or the
     * shortest input line length that is ok.  Once decoding begins, the
     * length is adjusted up each time a longer line is decoded
     */
    int length;
    /* data to encode */
    unsigned char enc_data[80];
    /* number read on current line */
    int line_num;
    int expect_nl;
} BASE64_CTX;

# define BASE64_ENCODE_LENGTH(l)    (((l+2)/3*4)+(l/48+1)*2+80)
# define BASE64_DECODE_LENGTH(l)    ((l+3)/4*3+80)


void base64_encode_init(BASE64_CTX *ctx);
int  base64_encode_update(BASE64_CTX *ctx, const uint8_t *in, int inlen, uint8_t *out, int *outlen);
void base64_encode_finish(BASE64_CTX *ctx, uint8_t *out, int *outlen);

void base64_decode_init(BASE64_CTX *ctx);
int  base64_decode_update(BASE64_CTX *ctx, const uint8_t *in, int inlen, uint8_t *out, int *outlen);
int  base64_decode_finish(BASE64_CTX *ctx, uint8_t *out, int *outlen);


int base64_encode_block(unsigned char *t, const unsigned char *f, int dlen);
int base64_decode_block(unsigned char *t, const unsigned char *f, int n);


#ifdef __cplusplus
}
#endif
#endif
