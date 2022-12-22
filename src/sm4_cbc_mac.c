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

static int test_sm4_cbc_mac(void)
{
	SM4_KEY sm4_key;
	SM4_CBC_MAC_CTX ctx;
	uint8_t key[16];
	uint8_t iv[16] = {0};
	uint8_t m[128];
	uint8_t c[128];
	uint8_t mac1[16];
	uint8_t mac2[16];
	uint8_t *p;
	size_t len, left;

	rand_bytes(key, sizeof(key));
	rand_bytes(m, sizeof(m));
	sm4_set_encrypt_key(&sm4_key, key);

	// test 1
	sm4_cbc_encrypt(&sm4_key, iv, m, sizeof(m)/16, c);
	memcpy(mac1, c + sizeof(m) - 16, 16);

	sm4_cbc_mac_init(&ctx, key);
	p = m;
	len = 0;
	left = sizeof(m);
	while (left) {
		len = left < len ? left : len;
		sm4_cbc_mac_update(&ctx, p, len);
		p += len;
		left -= len;
		len++;
	}
	sm4_cbc_mac_finish(&ctx, mac2);
	if (memcmp(mac1, mac2, 16)) {
		error_print();
		return -1;
	}

	// test 2
	m[sizeof(m) - 1] = 0;
	sm4_cbc_encrypt(&sm4_key, iv, m, sizeof(m)/16, c);
	memcpy(mac1, c + sizeof(m) - 16, 16);

	sm4_cbc_mac_init(&ctx, key);
	p = m;
	len = 0;
	left = sizeof(m) - 1;
	while (left) {
		len = left < len ? left : len;
		sm4_cbc_mac_update(&ctx, p, len);
		p += len;
		left -= len;
		len++;
	}
	sm4_cbc_mac_finish(&ctx, mac2);
	if (memcmp(mac1, mac2, 16)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
