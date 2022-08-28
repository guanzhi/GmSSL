/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
