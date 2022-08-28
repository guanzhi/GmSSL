/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_MD5_H
#define GMSSL_MD5_H


#include <string.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


#define MD5_IS_BIG_ENDIAN	0

#define MD5_DIGEST_SIZE		16
#define MD5_BLOCK_SIZE		64
#define MD5_STATE_WORDS		(MD5_BLOCK_SIZE/sizeof(uint32_t))

typedef struct {
	uint32_t state[MD5_STATE_WORDS];
	uint64_t nblocks;
	uint8_t block[MD5_BLOCK_SIZE];
	size_t num;
} MD5_CTX;


void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t datalen);
void md5_finish(MD5_CTX *ctx, uint8_t dgst[MD5_DIGEST_SIZE]);
void md5_digest(const uint8_t *data, size_t datalen, uint8_t dgst[MD5_DIGEST_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
