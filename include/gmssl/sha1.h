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

#ifndef GMSSL_SHA1_H
#define GMSSL_SHA1_H

#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SHA1_IS_BIG_ENDIAN	1

#define SHA1_DIGEST_SIZE	20
#define SHA1_BLOCK_SIZE		64
#define SHA1_STATE_WORDS	(SHA1_DIGEST_SIZE/sizeof(uint32_t))


typedef struct {
	uint32_t state[SHA1_STATE_WORDS];
	uint64_t nblocks; /* num of processed blocks */
	uint8_t block[SHA1_BLOCK_SIZE]; /* buffer */
	size_t num; /* buffered bytes in |block| */
} SHA1_CTX;

void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t datalen);
void sha1_finish(SHA1_CTX *ctx, uint8_t dgst[SHA1_DIGEST_SIZE]);
void sha1_digest(const uint8_t *data, size_t datalen, uint8_t dgst[SHA1_DIGEST_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
