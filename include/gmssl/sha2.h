/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
	uint8_t block[SHA224_BLOCK_SIZE];
	size_t num;
} SHA224_CTX;

void sha224_init(SHA224_CTX *ctx);
void sha224_update(SHA224_CTX *ctx, const uint8_t* data, size_t datalen);
void sha224_finish(SHA224_CTX *ctx, uint8_t dgst[SHA224_DIGEST_SIZE]);
void sha224_digest(const uint8_t *data, size_t datalen,
	uint8_t dgst[SHA224_DIGEST_SIZE]);


#define SHA256_DIGEST_SIZE	32
#define SHA256_BLOCK_SIZE	64
#define SHA256_STATE_WORDS	8

typedef struct {
	uint32_t state[SHA256_STATE_WORDS];
	uint64_t nblocks;
	uint8_t block[SHA256_BLOCK_SIZE];
	size_t num;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t* data, size_t datalen);
void sha256_finish(SHA256_CTX *ctx, uint8_t dgst[SHA256_DIGEST_SIZE]);
void sha256_digest(const uint8_t *data, size_t datalen,
	uint8_t dgst[SHA256_DIGEST_SIZE]);


#define SHA384_DIGEST_SIZE	48
#define SHA384_BLOCK_SIZE	128
#define SHA384_STATE_WORDS	8

typedef struct {
	uint64_t state[SHA384_STATE_WORDS];
	uint64_t nblocks;
	uint8_t block[SHA384_BLOCK_SIZE];
	size_t num;
} SHA384_CTX;

void sha384_init(SHA384_CTX *ctx);
void sha384_update(SHA384_CTX *ctx, const uint8_t* data, size_t datalen);
void sha384_finish(SHA384_CTX *ctx, uint8_t dgst[SHA384_DIGEST_SIZE]);
void sha384_digest(const uint8_t *data, size_t datalen,
	uint8_t dgst[SHA384_DIGEST_SIZE]);


#define SHA512_DIGEST_SIZE	64
#define SHA512_BLOCK_SIZE	128
#define SHA512_STATE_WORDS	8

typedef struct {
	uint64_t state[SHA512_STATE_WORDS];
	uint64_t nblocks;
	uint8_t block[SHA512_BLOCK_SIZE];
	size_t num;
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t* data, size_t datalen);
void sha512_finish(SHA512_CTX *ctx, uint8_t dgst[SHA512_DIGEST_SIZE]);
void sha512_digest(const uint8_t *data, size_t datalen,
	uint8_t dgst[SHA512_DIGEST_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
