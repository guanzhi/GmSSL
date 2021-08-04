/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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
