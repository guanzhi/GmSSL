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
#include <gmssl/sm9.h>
#include <gmssl/error.h>


int main(void)
{
	SM9_SIGN_MASTER_KEY sign_master;
	SM9_SIGN_MASTER_KEY sign_master_public;
	SM9_SIGN_KEY sign_key;
	SM9_SIGN_CTX sign_ctx;
	const char *id = "Alice";
	uint8_t sig[SM9_SIGNATURE_SIZE];
	size_t siglen;
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len;
	int ret;

	sm9_sign_master_key_generate(&sign_master);

	sm9_sign_master_key_extract_key(&sign_master, id, strlen(id), &sign_key);

	sm9_sign_init(&sign_ctx);
	sm9_sign_update(&sign_ctx, (uint8_t *)"hello world", strlen("hello world"));
	sm9_sign_finish(&sign_ctx, &sign_key, sig, &siglen);

	format_bytes(stdout, 0, 0, "signature", sig, siglen);


	sm9_sign_master_public_key_to_der(&sign_master, &p, &len);
	sm9_sign_master_public_key_from_der(&sign_master_public, &cp, &len);

	sm9_verify_init(&sign_ctx);
	sm9_verify_update(&sign_ctx, (uint8_t *)"hello world", strlen("hello world"));
	ret = sm9_verify_finish(&sign_ctx, sig, siglen, &sign_master_public, id, strlen(id));
	printf("verify %s\n", ret == 1 ? "success" : "failure");


	return 0;
}
