/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SHA1_H
#define GMSSL_SHA1_H

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SHA1_IS_BIG_ENDIAN	1

#define SHA1_DIGEST_SIZE	20
#define SHA1_BLOCK_SIZE		64
#define SHA1_STATE_WORDS	(SHA1_DIGEST_SIZE/sizeof(uint32_t))


typedef struct {
	uint32_t state[SHA1_STATE_WORDS];
	uint64_t nblocks;
	uint8_t block[SHA1_BLOCK_SIZE];
	size_t num;
} SHA1_CTX;

void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t datalen);
void sha1_finish(SHA1_CTX *ctx, uint8_t dgst[SHA1_DIGEST_SIZE]);
void sha1_digest(const uint8_t *data, size_t datalen, uint8_t dgst[SHA1_DIGEST_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
