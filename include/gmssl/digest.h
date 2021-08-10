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


#ifndef GMSSL_DIGEST_H
#define GMSSL_DIGEST_H


#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <gmssl/md5.h>
#include <gmssl/sha1.h>
#include <gmssl/sha2.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct digest_st DIGEST;
typedef struct digest_ctx_st DIGEST_CTX;


#define DIGEST_MAX_SIZE		64
#define DIGEST_MAX_BLOCK_SIZE (1024/8)


struct digest_ctx_st {
	const DIGEST *digest;
	union {
		SM3_CTX sm3_ctx;
		MD5_CTX md5_ctx;
		SHA1_CTX sha1_ctx;
		SHA224_CTX sha224_ctx;
		SHA256_CTX sha256_ctx;
		SHA384_CTX sha384_ctx;
		SHA512_CTX sha512_ctx;
	} u;
};

struct digest_st {
	int nid;
	size_t digest_size;
	size_t block_size;
	size_t ctx_size;
	int (*init)(DIGEST_CTX *ctx);
	int (*update)(DIGEST_CTX *ctx, const unsigned char *data, size_t datalen);
	int (*finish)(DIGEST_CTX *ctx, unsigned char *dgst);
};

int digest_nid(const DIGEST *digest);
const char *digest_name(const DIGEST *digest);
size_t digest_size(const DIGEST *digest);
size_t digest_block_size(const DIGEST *digest);

const DIGEST *DIGEST_sm3(void);
const DIGEST *DIGEST_md5(void);
const DIGEST *DIGEST_sha1(void);
const DIGEST *DIGEST_sha224(void);
const DIGEST *DIGEST_sha256(void);
const DIGEST *DIGEST_sha384(void);
const DIGEST *DIGEST_sha512(void);
const DIGEST *DIGEST_sha512_224(void);
const DIGEST *DIGEST_sha512_256(void);

const DIGEST *digest_from_name(const char *name);

int digest_ctx_nid(const DIGEST_CTX *ctx);
const char *digest_ctx_name(const DIGEST_CTX *ctx);
size_t digest_ctx_size(const DIGEST_CTX *ctx);
size_t digest_ctx_block_size(const DIGEST_CTX *ctx);
const DIGEST *digest_ctx_digest(const DIGEST_CTX *ctx);

int digest_ctx_init(DIGEST_CTX *ctx);
int digest_init(DIGEST_CTX *ctx, const DIGEST *algor);
int digest_update(DIGEST_CTX *ctx, const unsigned char *data, size_t datalen);
int digest_finish(DIGEST_CTX *ctx, unsigned char *dgst, size_t *dgstlen);
void digest_ctx_cleanup(DIGEST_CTX *ctx);

int digest(const DIGEST *digest, const unsigned char *data, size_t datalen,
	unsigned char *dgst, size_t *dgstlen);

const char *digest_algor_name(int oid);
int digest_algor_to_der(int oid, uint8_t **out, size_t *outlen);
int digest_algor_from_der(int *oid, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **in, size_t *inlen);

#ifdef __cplusplus
}
#endif
#endif
