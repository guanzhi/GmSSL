/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_BASE64_H
#define GMSSL_BASE64_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
BASE64 Public API

	BASE64_CTX
	base64_encode_init
	base64_encode_update
	base64_encode_finish
	base64_decode_init
	base64_decode_update
	base64_decode_finish

*/


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
