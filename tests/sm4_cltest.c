/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <gmssl/sm4_cl.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_sm4_cl_ctr32_encrypt_blocks(void)
{
	const char *key_hex = "0123456789abcdeffedcba9876543210";
	const char *iv_hex =  "0123456789abcdeffedcba9876543210";
	const char *plain_hex = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa";
	const char *cipher_hex = "c2b4759e78ac3cf43d0852f4e8d5f9fd7256e8a5fcb65a350ee00630912e44492a0b17e1b85b060d0fba612d8a95831638b361fd5ffacd942f081485a83ca35d";

	int ret = -1;
	SM4_CL_CTX ctx;
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t ctr[16];
	size_t nblocks = 64;
	uint8_t *buf = NULL;
	uint8_t *ciphertext = NULL;
	size_t len;
	size_t i;

	if (!(buf = (uint8_t *)malloc(16  * nblocks))) {
		error_print();
		return -1;
	}
	if (!(ciphertext = (uint8_t *)malloc(16 * nblocks))) {
		error_print();
		goto end;
	}

	hex_to_bytes(key_hex, strlen(key_hex), key, &len);
	hex_to_bytes(iv_hex, strlen(iv_hex), iv, &len);
	hex_to_bytes(plain_hex, strlen(plain_hex), buf, &len);
	hex_to_bytes(cipher_hex, strlen(cipher_hex), ciphertext, &len);

	if (sm4_cl_set_encrypt_key(&ctx, key) != 1) {
		error_print();
		goto end;
	}

	memcpy(ctr, iv, sizeof(iv));
	if (sm4_cl_ctr32_encrypt_blocks(&ctx, ctr, buf, nblocks, buf) != 1) {
		error_print();
		goto end;
	}

	if (memcmp(buf, ciphertext, len) != 0) {
		error_print();
		goto end;
	}

	printf("%s() ok\n", __FUNCTION__);
	ret = 1;
end:
	sm4_cl_cleanup(&ctx);
	if (buf) free(buf);
	if (ciphertext) free(ciphertext);
	return ret;
}

static int speed_sm4_cl_ctr32_encrypt_blocks(void)
{
	const uint8_t key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	const uint8_t plaintext[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	const uint8_t ciphertext[16] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	};


	int ret = -1;
	SM4_CL_CTX ctx;
	uint8_t ctr[16];
	size_t nblocks = 1024*1024;
	uint8_t *buf = NULL;
	clock_t begin, end;
	double seconds;
	size_t i;

	if (!(buf = (uint8_t *)malloc(16  * nblocks))) {
		error_print();
		return -1;
	}
	for (i = 0; i < nblocks; i++) {
		memcpy(buf + 16 * i, plaintext, 16);
	}

	if (sm4_cl_set_encrypt_key(&ctx, key) != 1) {
		error_print();
		goto end;
	}

	begin = clock();
	if (sm4_cl_ctr32_encrypt_blocks(&ctx, ctr, buf, nblocks, buf) != 1) {
		error_print();
		goto end;
	}
	end = clock();

	seconds = (double)(end - begin)/CLOCKS_PER_SEC;
	fprintf(stderr, "%s: %f-MiB per seconds\n", __FUNCTION__, 16/seconds);

	ret = 1;
end:
	if (buf) free(buf);
	sm4_cl_cleanup(&ctx);
	return ret;
}

int main(void)
{
	if (test_sm4_cl_ctr32_encrypt_blocks() != 1) goto err;
#if ENABLE_TEST_SPEED
	if (speed_sm4_cl_ctr32_encrypt_blocks() != 1) goto err;
#endif
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
