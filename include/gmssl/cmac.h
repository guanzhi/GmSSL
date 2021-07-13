/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* NIST SP 800-38B "Recommendation for Block Cipher Modes of Operation:
 * The CMAC Mode for Authentication"
 */

#ifndef GMSSL_CMAC_H
#define GMSSL_CMAC_H


#include <stdint.h>
#include <stdlib.h>
#include <gmssl/block_cipher.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	const BLOCK_CIPHER *cipher;
	BLOCK_CIPHER_KEY cipher_key;
	uint8_t k1[16];
	uint8_t k2[16];
	uint8_t temp_block[16];
	uint8_t last_block[16];
	int last_block_nbytes; /* -1 means context not initialised */
} CMAC_CTX;

int cmac_init(CMAC_CTX *ctx, const BLOCK_CIPHER *cipher, const uint8_t *key, size_t keylen);
int cmac_update(CMAC_CTX *ctx, const uint8_t *in, size_t inlen);
int cmac_finish(CMAC_CTX *ctx, uint8_t *out, size_t *outlen);
int cmac_finish_and_verify(CMAC_CTX *ctx, const uint8_t *mac, size_t maclen);


#ifdef  __cplusplus
}
#endif
#endif
