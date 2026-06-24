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
#include <gmssl/xmss_cl.h>
#include <gmssl/error.h>


static int test_xmss_cl_build_tree(XMSS_CL_CTX *cl_ctx)
{
	xmss_sm3_digest_t seed;
	xmss_sm3_digest_t secret;
	xmss_adrs_t adrs;
	xmss_sm3_digest_t *cpu_tree = NULL;
	xmss_sm3_digest_t *cl_tree = NULL;
	size_t height = 4;
	size_t tree_nodes = xmss_num_tree_nodes(height);
	size_t i;
	int ret = -1;

	for (i = 0; i < sizeof(seed); i++) {
		seed[i] = (uint8_t)i;
		secret[i] = (uint8_t)(0x80 + i);
	}
	xmss_adrs_set_layer_address(adrs, 0);
	xmss_adrs_set_tree_address(adrs, 0);

	if (!(cpu_tree = malloc(sizeof(xmss_sm3_digest_t) * tree_nodes))
		|| !(cl_tree = malloc(sizeof(xmss_sm3_digest_t) * tree_nodes))) {
		error_print();
		goto end;
	}
	xmss_build_tree(secret, seed, adrs, height, cpu_tree);
	if (xmss_cl_build_tree(cl_ctx, secret, seed, adrs, height, cl_tree) != 1) {
		error_print();
		goto end;
	}
	if (memcmp(cpu_tree, cl_tree, sizeof(xmss_sm3_digest_t) * tree_nodes) != 0) {
		error_print();
		goto end;
	}

	ret = 1;
end:
	free(cpu_tree);
	free(cl_tree);
	return ret;
}

static int test_xmss_cl_sign_verify(XMSS_CL_CTX *cl_ctx)
{
	XMSS_KEY key;
	XMSS_SIGN_CTX sign_ctx;
	XMSS_SIGN_CTX verify_ctx;
	uint8_t msg[] = "abc";
	uint8_t sig[XMSS_SIGNATURE_MAX_SIZE];
	size_t siglen = 0;
	int ret = -1;

	memset(&key, 0, sizeof(key));
	memset(&sign_ctx, 0, sizeof(sign_ctx));
	memset(&verify_ctx, 0, sizeof(verify_ctx));

	if (xmss_cl_key_generate(cl_ctx, &key, XMSS_SM3_10_256) != 1) {
		error_print();
		goto end;
	}
	if (xmss_sign_init(&sign_ctx, &key) != 1
		|| xmss_sign_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| xmss_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		goto end;
	}
	if (xmss_verify_init(&verify_ctx, &key, sig, siglen) != 1
		|| xmss_verify_update(&verify_ctx, msg, sizeof(msg)) != 1
		|| xmss_verify_finish(&verify_ctx) != 1) {
		error_print();
		goto end;
	}

	ret = 1;
end:
	xmss_key_cleanup(&key);
	return ret;
}

static int test_xmssmt_cl_sign_verify(XMSS_CL_CTX *cl_ctx)
{
	XMSSMT_KEY key;
	XMSSMT_SIGN_CTX sign_ctx;
	XMSSMT_SIGN_CTX verify_ctx;
	uint8_t msg[] = "abc";
	uint8_t sig[XMSSMT_SIGNATURE_MAX_SIZE];
	size_t siglen = 0;
	int ret = -1;

	memset(&key, 0, sizeof(key));
	memset(&sign_ctx, 0, sizeof(sign_ctx));
	memset(&verify_ctx, 0, sizeof(verify_ctx));

	if (xmssmt_cl_key_generate(cl_ctx, &key, XMSSMT_SM3_20_4_256) != 1) {
		error_print();
		goto end;
	}
	if (xmssmt_cl_sign_init(cl_ctx, &sign_ctx, &key) != 1
		|| xmssmt_sign_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| xmssmt_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		goto end;
	}
	if (xmssmt_verify_init(&verify_ctx, &key, sig, siglen) != 1
		|| xmssmt_verify_update(&verify_ctx, msg, sizeof(msg)) != 1
		|| xmssmt_verify_finish(&verify_ctx) != 1) {
		error_print();
		goto end;
	}

	ret = 1;
end:
	xmssmt_key_cleanup(&key);
	return ret;
}

int main(void)
{
	XMSS_CL_CTX cl_ctx;
	int ret = 1;

	memset(&cl_ctx, 0, sizeof(cl_ctx));
	if (xmss_cl_init(&cl_ctx) != 1) {
		error_print();
		return 1;
	}

	if (test_xmss_cl_build_tree(&cl_ctx) != 1) goto end;
	if (test_xmss_cl_sign_verify(&cl_ctx) != 1) goto end;
	if (test_xmssmt_cl_sign_verify(&cl_ctx) != 1) goto end;

	ret = 0;
end:
	xmss_cl_cleanup(&cl_ctx);
	return ret;
}
