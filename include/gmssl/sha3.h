/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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


#ifndef GMSSL_SHA3_H
#define GMSSL_SHA3_H


#include <string.h>
#include <stdint.h>
#include <sys/types.h>


#ifdef __cplusplus
extern "C" {
#endif


#define SHA3_KECCAK_P_SIZE (1600/8)

#define SHA3_224_DIGEST_SIZE (224/8)
#define SHA3_256_DIGEST_SIZE (256/8)
#define SHA3_384_DIGEST_SIZE (384/8)
#define SHA3_512_DIGEST_SIZE (512/8)

#define SHA3_224_CAPACITY (SHA3_224_DIGEST_SIZE * 2)
#define SHA3_256_CAPACITY (SHA3_256_DIGEST_SIZE * 2)
#define SHA3_384_CAPACITY (SHA3_384_DIGEST_SIZE * 2)
#define SHA3_512_CAPACITY (SHA3_512_DIGEST_SIZE * 2)

#define SHA3_224_BLOCK_SIZE (SHA3_KECCAK_P_SIZE - SHA3_224_CAPACITY) // 144
#define SHA3_256_BLOCK_SIZE (SHA3_KECCAK_P_SIZE - SHA3_224_CAPACITY) // 136
#define SHA3_384_BLOCK_SIZE (SHA3_KECCAK_P_SIZE - SHA3_224_CAPACITY) // 104
#define SHA3_512_BLOCK_SIZE (SHA3_KECCAK_P_SIZE - SHA3_224_CAPACITY) // 72


typedef struct {
	uint64_t A[5][5];
	uint8_t buf[SHA3_224_BLOCK_SIZE];
	int num;
} SHA3_224_CTX;

void sha3_224_init(SHA3_224_CTX *ctx);
void sha3_224_update(SHA3_224_CTX *ctx, const uint8_t *data, size_t datalen);
void sha3_224_finish(SHA3_224_CTX *ctx, uint8_t dgst[SHA3_224_DIGEST_SIZE]);

typedef struct {
	uint64_t A[5][5];
	uint8_t buf[SHA3_256_BLOCK_SIZE];
	int num;
} SHA3_256_CTX;

void sha3_256_init(SHA3_256_CTX *ctx);
void sha3_256_update(SHA3_256_CTX *ctx, const uint8_t *data, size_t datalen);
void sha3_256_finish(SHA3_256_CTX *ctx, uint8_t dgst[SHA3_256_DIGEST_SIZE]);

typedef struct {
	uint64_t A[5][5];
	uint8_t buf[SHA3_384_BLOCK_SIZE];
	int num;
} SHA3_384_CTX;

void sha3_384_init(SHA3_384_CTX *ctx);
void sha3_384_update(SHA3_384_CTX *ctx, const uint8_t *data, size_t datalen);
void sha3_384_finish(SHA3_384_CTX *ctx, uint8_t dgst[SHA3_384_DIGEST_SIZE]);

typedef struct {
	uint64_t A[5][5];
	uint8_t buf[SHA3_512_BLOCK_SIZE];
	int num;
} SHA3_512_CTX;

void sha3_512_init(SHA3_512_CTX *ctx);
void sha3_512_update(SHA3_512_CTX *ctx, const uint8_t *data, size_t datalen);
void sha3_512_finish(SHA3_512_CTX *ctx, uint8_t dgst[SHA3_512_DIGEST_SIZE]);

void sha3_shake128(const uint8_t *in, size_t *inlen, size_t outlen, uint8_t *out);
void sha3_shake256(const uint8_t *in, size_t *inlen, size_t outlen, uint8_t *out);
void sha3_keccak_p(uint8_t state[SHA3_KECCAK_P_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
