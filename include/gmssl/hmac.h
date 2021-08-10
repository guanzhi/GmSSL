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

#ifndef GMSSL_HMAC_H
#define GMSSL_HMAC_H

#include <string.h>
#include <gmssl/digest.h>


#ifdef  __cplusplus
extern "C" {
#endif

#define HMAC_MAX_SIZE	(DIGEST_MAX_SIZE)


typedef struct hmac_ctx_st {
	const DIGEST *digest;
	DIGEST_CTX digest_ctx;
	DIGEST_CTX i_ctx;
	DIGEST_CTX o_ctx;
} HMAC_CTX;


size_t hmac_size(const HMAC_CTX *ctx);

int hmac_init(HMAC_CTX *ctx, const DIGEST *digest, const unsigned char *key, size_t keylen);
int hmac_update(HMAC_CTX *ctx, const unsigned char *data, size_t datalen);
int hmac_finish(HMAC_CTX *ctx, unsigned char *mac, size_t *maclen);

int hmac(const DIGEST *md, const unsigned char *key, size_t keylen,
	const unsigned char *data, size_t dlen,
	unsigned char *mac, size_t *maclen);


#ifdef  __cplusplus
}
#endif
#endif
