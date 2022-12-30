/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sm4_cbc_mac.h>


void sm4_cbc_mac_init(SM4_CBC_MAC_CTX *ctx, const uint8_t key[16])
{
	sm4_set_encrypt_key(&ctx->key, key);
	memset(ctx->iv, 0, 16);
	ctx->ivlen = 0;
}

void sm4_cbc_mac_update(SM4_CBC_MAC_CTX *ctx, const uint8_t *data, size_t datalen)
{
	while (datalen) {
		size_t ivleft = 16 - ctx->ivlen;
		size_t len = datalen < ivleft ? datalen : ivleft;
		gmssl_memxor(ctx->iv + ctx->ivlen, ctx->iv + ctx->ivlen, data, len);
		ctx->ivlen += len;
		if (ctx->ivlen >= 16) {
			sm4_encrypt(&ctx->key, ctx->iv, ctx->iv);
			ctx->ivlen = 0;
		}
		data += len;
		datalen -= len;
	}
}

void sm4_cbc_mac_finish(SM4_CBC_MAC_CTX *ctx, uint8_t mac[16])
{
	if (ctx->ivlen) {
		sm4_encrypt(&ctx->key, ctx->iv, ctx->iv);
	}
	memcpy(mac, ctx->iv, 16);
}
