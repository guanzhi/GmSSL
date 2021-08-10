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


typedef struct {
	uint32_t state[4];
	uint64_t nblocks; /* num of processed blocks */
	uint8_t block[64]; /* buffer */
	size_t num; /* buffered bytes in |block| */
} MD5_CTX;


void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t datalen);
void md5_finish(MD5_CTX *ctx, uint8_t dgst[MD5_DIGEST_SIZE]);
void md5_digest(const uint8_t *data, size_t datalen, uint8_t dgst[MD5_DIGEST_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
