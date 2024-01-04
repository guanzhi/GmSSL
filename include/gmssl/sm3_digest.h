/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SM3_DIGEST_H
#define GMSSL_SM3_DIGEST_H

#include <string.h>
#include <stdint.h>
#include <gmssl/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	union {
		SM3_CTX sm3_ctx;
		SM3_HMAC_CTX hmac_ctx;
		void *handle;
	};
	int state;
} SM3_DIGEST_CTX;

int sm3_digest_init(SM3_DIGEST_CTX *ctx, const uint8_t *key, size_t keylen);
int sm3_digest_update(SM3_DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
int sm3_digest_finish(SM3_DIGEST_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE]);


#ifdef __cplusplus
}
#endif
#endif
