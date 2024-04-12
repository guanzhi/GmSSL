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
#include <gmssl/sm4_cl.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>



int test_sm4_cl(void)
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
	size_t nblocks = 1024;
	uint8_t *buf = NULL;
	size_t i;


	if (!(buf = (uint8_t *)malloc(16  * nblocks))) {
		error_print();
		return -1;
	}
	for (i = 0; i < nblocks; i++) {
		memcpy(buf + 16 * i, plaintext, 16);
	}
	format_bytes(stderr, 0, 0, "in", buf, nblocks  * 16);

	if (sm4_cl_set_encrypt_key(&ctx, key) != 1) {
		error_print();
		goto end;
	}
	if (sm4_cl_encrypt(&ctx, buf, nblocks, buf) != 1) {
		error_print();
		goto end;
	}

	for (i = 0; i < nblocks; i++) {
		//fprintf(stderr, "%zu ", i);
		//format_bytes(stderr, 0, 0, "ciphertext", buf + 16*i, 16);
		if (memcmp(buf + 16 * i, ciphertext, 16) != 0) {
			error_print();
			goto end;
		}
	}

	ret = 1;
end:
	if (buf) free(buf);
	sm4_cl_cleanup(&ctx);
	return ret;
}

static int test_sm4_cl_ctr(void)
{
	return 1;
}

int main(void)
{
	if (test_sm4_cl() != 1) goto err;
	if (test_sm4_cl_ctr() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
