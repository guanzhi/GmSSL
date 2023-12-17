/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_DIGEST_H
#define GMSSL_DIGEST_H


#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#ifdef ENABLE_SHA1
#include <gmssl/sha1.h>
#endif
#ifdef ENABLE_SHA2
#include <gmssl/sha2.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


typedef struct DIGEST DIGEST;
typedef struct DIGEST_CTX DIGEST_CTX;


#define DIGEST_MAX_SIZE		64
#define DIGEST_MAX_BLOCK_SIZE (1024/8)


struct DIGEST_CTX {
	union {
		SM3_CTX sm3_ctx;
#ifdef ENABLE_SHA1
		SHA1_CTX sha1_ctx;
#endif
#ifdef ENABLE_SHA2
		SHA224_CTX sha224_ctx;
		SHA256_CTX sha256_ctx;
		SHA384_CTX sha384_ctx;
		SHA512_CTX sha512_ctx;
#endif
	} u;
	const DIGEST *digest;
};

struct DIGEST {
	int oid;
	size_t digest_size;
	size_t block_size;
	size_t ctx_size;
	int (*init)(DIGEST_CTX *ctx);
	int (*update)(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
	int (*finish)(DIGEST_CTX *ctx, uint8_t *dgst);
};

const DIGEST *DIGEST_sm3(void);
#ifdef ENABLE_SHA1
const DIGEST *DIGEST_sha1(void);
#endif
#ifdef ENABLE_SHA2
const DIGEST *DIGEST_sha224(void);
const DIGEST *DIGEST_sha256(void);
const DIGEST *DIGEST_sha384(void);
const DIGEST *DIGEST_sha512(void);
const DIGEST *DIGEST_sha512_224(void);
const DIGEST *DIGEST_sha512_256(void);
#endif

const DIGEST *digest_from_name(const char *name);
const char *digest_name(const DIGEST *digest);
int digest_init(DIGEST_CTX *ctx, const DIGEST *algor);
int digest_update(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
int digest_finish(DIGEST_CTX *ctx, uint8_t *dgst, size_t *dgstlen);
int digest(const DIGEST *digest, const uint8_t *data, size_t datalen, uint8_t *dgst, size_t *dgstlen);


#ifdef __cplusplus
}
#endif
#endif
