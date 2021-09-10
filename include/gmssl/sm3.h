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

#ifndef GMSSL_SM3_H
#define GMSSL_SM3_H

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SM3_IS_BIG_ENDIAN	1

#define SM3_DIGEST_SIZE		32
#define SM3_BLOCK_SIZE		64
#define SM3_STATE_WORDS		8
#define SM3_HMAC_SIZE		(SM3_DIGEST_SIZE)


typedef struct {
	uint32_t digest[SM3_STATE_WORDS];
	uint64_t nblocks;
	uint8_t block[SM3_BLOCK_SIZE];
	size_t num;
} SM3_CTX;

void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t datalen);
void sm3_finish(SM3_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE]);
void sm3_digest(const uint8_t *data, size_t datalen, uint8_t dgst[SM3_DIGEST_SIZE]);


typedef struct {
	SM3_CTX sm3_ctx;
	unsigned char key[SM3_BLOCK_SIZE];
} SM3_HMAC_CTX;

void sm3_hmac_init(SM3_HMAC_CTX *ctx, const uint8_t *key, size_t keylen);
void sm3_hmac_update(SM3_HMAC_CTX *ctx, const uint8_t *data, size_t datalen);
void sm3_hmac_finish(SM3_HMAC_CTX *ctx, uint8_t mac[SM3_HMAC_SIZE]);
void sm3_hmac(const uint8_t *key, size_t keylen,
	const uint8_t *data, size_t datalen,
	uint8_t mac[SM3_HMAC_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
