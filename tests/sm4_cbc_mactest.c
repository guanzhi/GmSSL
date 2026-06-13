/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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

static int test_sm4_cbc_mac(void)
{
	SM4_KEY sm4_key;
	SM4_CBC_MAC_CTX ctx;
	uint8_t key[16];
	const uint8_t civ[16] = {0};
	uint8_t iv[16];
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
	memcpy(iv, civ, 16);
	sm4_cbc_encrypt_blocks(&sm4_key, iv, m, sizeof(m)/16, c);
	memcpy(mac1, c + sizeof(m) - 16, 16);

	if (sm4_cbc_mac_init(&ctx, key) != 1) {
		error_print();
		return -1;
	}
	p = m;
	len = 0;
	left = sizeof(m);
	while (left) {
		len = left < len ? left : len;
		if (sm4_cbc_mac_update(&ctx, p, len) != 1) {
			error_print();
			return -1;
		}
		p += len;
		left -= len;
		len++;
	}
	if (sm4_cbc_mac_finish(&ctx, mac2) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(mac1, mac2, 16)) {
		error_print();
		return -1;
	}

	// test 2
	m[sizeof(m) - 1] = 0;
	memcpy(iv, civ, 16);
	sm4_cbc_encrypt_blocks(&sm4_key, iv, m, sizeof(m)/16, c);
	memcpy(mac1, c + sizeof(m) - 16, 16);

	if (sm4_cbc_mac_init(&ctx, key) != 1) {
		error_print();
		return -1;
	}
	p = m;
	len = 0;
	left = sizeof(m) - 1;
	while (left) {
		len = left < len ? left : len;
		if (sm4_cbc_mac_update(&ctx, p, len) != 1) {
			error_print();
			return -1;
		}
		p += len;
		left -= len;
		len++;
	}
	if (sm4_cbc_mac_finish(&ctx, mac2) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(mac1, mac2, 16)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_cbc_mac_args(void)
{
	SM4_CBC_MAC_CTX ctx;
	uint8_t key[16] = {0};
	uint8_t data[16] = {0};
	uint8_t mac[16];

	if (sm4_cbc_mac_init(NULL, key) != -1
		|| sm4_cbc_mac_init(&ctx, NULL) != -1) {
		error_print();
		return -1;
	}
	if (sm4_cbc_mac_init(&ctx, key) != 1
		|| sm4_cbc_mac_update(NULL, data, sizeof(data)) != -1
		|| sm4_cbc_mac_update(&ctx, NULL, sizeof(data)) != -1
		|| sm4_cbc_mac_update(&ctx, NULL, 0) != 1
		|| sm4_cbc_mac_finish(NULL, mac) != -1
		|| sm4_cbc_mac_finish(&ctx, NULL) != -1) {
		error_print();
		return -1;
	}

	ctx.ivlen = 16;
	if (sm4_cbc_mac_update(&ctx, data, sizeof(data)) != -1
		|| sm4_cbc_mac_finish(&ctx, mac) != -1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_cbc_mac_finish_repeat(void)
{
	SM4_CBC_MAC_CTX ctx;
	uint8_t key[16] = {0};
	uint8_t data[15] = {0};
	uint8_t mac1[16];
	uint8_t mac2[16];

	if (sm4_cbc_mac_init(&ctx, key) != 1
		|| sm4_cbc_mac_update(&ctx, data, sizeof(data)) != 1
		|| sm4_cbc_mac_finish(&ctx, mac1) != 1
		|| sm4_cbc_mac_finish(&ctx, mac2) != 1
		|| memcmp(mac1, mac2, sizeof(mac1)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm4_cbc_mac() != 1) { error_print(); return -1; }
	if (test_sm4_cbc_mac_args() != 1) { error_print(); return -1; }
	if (test_sm4_cbc_mac_finish_repeat() != 1) { error_print(); return -1; }
	return 0;
}
