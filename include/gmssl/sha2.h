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
