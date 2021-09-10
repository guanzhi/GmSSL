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


#ifndef GMSSL_SHA2_H
#define GMSSL_SHA2_H

#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SHA2_IS_BIG_ENDIAN	1


#define SHA224_DIGEST_SIZE	28
#define SHA224_BLOCK_SIZE	64
#define SHA224_STATE_WORDS	8

typedef struct {
	uint32_t state[SHA224_STATE_WORDS];
	uint64_t nblocks;
	unsigned char block[SHA224_BLOCK_SIZE];
	int num;
} SHA224_CTX;

void sha224_init(SHA224_CTX *ctx);
void sha224_update(SHA224_CTX *ctx, const unsigned char* data, size_t datalen);
void sha224_finish(SHA224_CTX *ctx, unsigned char dgst[SHA224_DIGEST_SIZE]);
void sha224_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA224_DIGEST_SIZE]);


#define SHA256_DIGEST_SIZE	32
#define SHA256_BLOCK_SIZE	64
#define SHA256_STATE_WORDS	8

typedef struct {
	uint32_t state[8];
	uint64_t nblocks;
	unsigned char block[64];
	int num;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const unsigned char* data, size_t datalen);
void sha256_finish(SHA256_CTX *ctx, unsigned char dgst[SHA256_DIGEST_SIZE]);
void sha256_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA256_DIGEST_SIZE]);


#define SHA384_DIGEST_SIZE	48
#define SHA384_BLOCK_SIZE	128
#define SHA384_STATE_WORDS	8

typedef struct {
	uint64_t state[8];
	uint64_t nblocks;
	unsigned char block[128];
	int num;
} SHA384_CTX;

void sha384_init(SHA384_CTX *ctx);
void sha384_update(SHA384_CTX *ctx, const unsigned char* data, size_t datalen);
void sha384_finish(SHA384_CTX *ctx, unsigned char dgst[SHA384_DIGEST_SIZE]);
void sha384_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA384_DIGEST_SIZE]);


#define SHA512_DIGEST_SIZE	64
#define SHA512_BLOCK_SIZE	128
#define SHA512_STATE_WORDS	8

typedef struct {
	uint64_t state[8];
	uint64_t nblocks;
	unsigned char block[128];
	int num;
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const unsigned char* data, size_t datalen);
void sha512_finish(SHA512_CTX *ctx, unsigned char dgst[SHA512_DIGEST_SIZE]);
void sha512_digest(const unsigned char *data, size_t datalen,
	unsigned char dgst[SHA512_DIGEST_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
