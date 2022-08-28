/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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

int hmac_init(HMAC_CTX *ctx, const DIGEST *digest, const uint8_t *key, size_t keylen);
int hmac_update(HMAC_CTX *ctx, const uint8_t *data, size_t datalen);
int hmac_finish(HMAC_CTX *ctx, uint8_t *mac, size_t *maclen);

int hmac(const DIGEST *md, const uint8_t *key, size_t keylen,
	const uint8_t *data, size_t dlen,
	uint8_t *mac, size_t *maclen);


#ifdef  __cplusplus
}
#endif
#endif
