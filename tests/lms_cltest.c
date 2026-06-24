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
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif
#include <gmssl/lms.h>
#include <gmssl/lms_cl.h>
#include <gmssl/error.h>


static int test_lms_cl_derive_merkle_tree(void)
{
	LMS_CL_CTX ctx;
	lms_sm3_digest_t seed = {0};
	uint8_t I[16] = {0};
	int h = 5;
	size_t n = (size_t)1 << h;
	lms_sm3_digest_t *tree = NULL;
	lms_sm3_digest_t *cl_tree = NULL;
	lms_sm3_digest_t root;
	int ret = -1;

	if (lms_cl_init(&ctx) != 1) {
		fprintf(stderr, "%s: OpenCL unavailable, skipped\n", __FUNCTION__);
		return 1;
	}
	if (!(tree = (lms_sm3_digest_t *)malloc(sizeof(lms_sm3_digest_t) * (2*n - 1)))) {
		error_print();
		goto end;
	}
	if (!(cl_tree = (lms_sm3_digest_t *)malloc(sizeof(lms_sm3_digest_t) * (2*n - 1)))) {
		error_print();
		goto end;
	}

	lms_derive_merkle_tree(seed, I, h, tree);
	if (lms_cl_derive_merkle_tree(&ctx, seed, I, h, cl_tree) != 1) {
		error_print();
		goto end;
	}
	if (memcmp(tree, cl_tree, sizeof(lms_sm3_digest_t) * (2*n - 1)) != 0) {
		error_print();
		goto end;
	}
	if (lms_cl_derive_merkle_root(&ctx, seed, I, h, root) != 1) {
		error_print();
		goto end;
	}
	if (memcmp(tree[0], root, 32) != 0) {
		error_print();
		goto end;
	}

	printf("%s() ok\n", __FUNCTION__);
	ret = 1;
end:
	if (tree) free(tree);
	if (cl_tree) free(cl_tree);
	lms_cl_cleanup(&ctx);
	return ret;
}

static int test_lms_cl_key_generate(void)
{
	LMS_CL_CTX ctx;
	lms_sm3_digest_t seed = {1};
	uint8_t I[16] = {2};
	LMS_KEY key;
	LMS_KEY cl_key;
	LMS_KEY key2;
	uint8_t keybuf[LMS_PRIVATE_KEY_SIZE];
	uint8_t *p = keybuf;
	const uint8_t *cp = keybuf;
	size_t keylen = 0;
	int ret = -1;

	memset(&key, 0, sizeof(key));
	memset(&cl_key, 0, sizeof(cl_key));
	memset(&key2, 0, sizeof(key2));

	if (lms_cl_init(&ctx) != 1) {
		fprintf(stderr, "%s: OpenCL unavailable, skipped\n", __FUNCTION__);
		return 1;
	}
	if (lms_key_generate_ex(&key, LMS_SM3_M32_H5, seed, I, 1) != 1) {
		error_print();
		goto end;
	}
	if (lms_cl_key_generate_ex(&ctx, &cl_key, LMS_SM3_M32_H5, seed, I, 1) != 1) {
		error_print();
		goto end;
	}
	if (memcmp(&key.public_key, &cl_key.public_key, sizeof(LMS_PUBLIC_KEY)) != 0) {
		error_print();
		goto end;
	}
	if (lms_private_key_to_bytes(&key, &p, &keylen) != 1) {
		error_print();
		goto end;
	}
	if (keylen != LMS_PRIVATE_KEY_SIZE) {
		error_print();
		goto end;
	}
	if (lms_cl_private_key_from_bytes(&ctx, &key2, &cp, &keylen) != 1 || keylen != 0) {
		error_print();
		goto end;
	}
	if (memcmp(&key.public_key, &key2.public_key, sizeof(LMS_PUBLIC_KEY)) != 0
		|| memcmp(key.tree, key2.tree, sizeof(lms_sm3_digest_t) * ((1 << 5)*2 - 1)) != 0) {
		error_print();
		goto end;
	}
	printf("%s() ok\n", __FUNCTION__);
	ret = 1;
end:
	lms_key_cleanup(&key);
	lms_key_cleanup(&cl_key);
	lms_key_cleanup(&key2);
	lms_cl_cleanup(&ctx);
	return ret;
}

static int test_hss_cl_key_generate(void)
{
	LMS_CL_CTX ctx;
	int lms_types[] = {
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
	};
	HSS_KEY key;
	HSS_KEY key2;
	HSS_SIGN_CTX sign_ctx;
	HSS_SIGN_CTX verify_ctx;
	uint8_t keybuf[HSS_PRIVATE_KEY_MAX_SIZE];
	uint8_t sig[HSS_SIGNATURE_MAX_SIZE];
	uint8_t *p = keybuf;
	const uint8_t *cp = keybuf;
	uint8_t msg[] = "abc";
	size_t keylen = 0;
	size_t siglen = 0;
	int ret = -1;

	memset(&key, 0, sizeof(key));
	memset(&key2, 0, sizeof(key2));
	memset(&sign_ctx, 0, sizeof(sign_ctx));
	memset(&verify_ctx, 0, sizeof(verify_ctx));

	if (lms_cl_init(&ctx) != 1) {
		fprintf(stderr, "%s: OpenCL unavailable, skipped\n", __FUNCTION__);
		return 1;
	}
	if (hss_cl_key_generate(&ctx, &key, lms_types, sizeof(lms_types)/sizeof(lms_types[0])) != 1) {
		error_print();
		goto end;
	}
	if (hss_private_key_to_bytes(&key, &p, &keylen) != 1) {
		error_print();
		goto end;
	}
	if (hss_cl_private_key_from_bytes(&ctx, &key2, &cp, &keylen) != 1 || keylen != 0) {
		error_print();
		goto end;
	}
	if (hss_public_key_equ(&key, &key2) != 1) {
		error_print();
		goto end;
	}
	key2.lms_key[1].q = 31;
	if (hss_cl_sign_init(&ctx, &sign_ctx, &key2) != 1
		|| hss_sign_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| hss_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		goto end;
	}
	if (key2.lms_key[0].q != 2 || key2.lms_key[1].q != 0) {
		error_print();
		goto end;
	}
	if (hss_verify_init(&verify_ctx, &key, sig, siglen) != 1
		|| hss_verify_update(&verify_ctx, msg, sizeof(msg)) != 1
		|| hss_verify_finish(&verify_ctx) != 1) {
		error_print();
		goto end;
	}

	printf("%s() ok\n", __FUNCTION__);
	ret = 1;
end:
	hss_key_cleanup(&key);
	hss_key_cleanup(&key2);
	lms_cl_cleanup(&ctx);
	return ret;
}

#if ENABLE_TEST_SPEED
static double get_seconds(void)
{
#ifdef _WIN32
	LARGE_INTEGER freq;
	LARGE_INTEGER count;

	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&count);
	return (double)count.QuadPart/(double)freq.QuadPart;
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec/1000000;
#endif
}

static int speed_lms_cl_derive_merkle_root(void)
{
	LMS_CL_CTX ctx;
	lms_sm3_digest_t seed = {0};
	uint8_t I[16] = {0};
	lms_sm3_digest_t root;
	lms_sm3_digest_t cl_root;
	double begin;
	double seconds;
	int h = 10;
	int cl_h = 15;

	if (lms_cl_init(&ctx) != 1) {
		fprintf(stderr, "%s: OpenCL unavailable, skipped\n", __FUNCTION__);
		return 1;
	}

	begin = get_seconds();
	lms_derive_merkle_root(seed, I, h, root);
	seconds = get_seconds() - begin;
	fprintf(stderr, "%s: CPU H%d %.3f seconds\n", __FUNCTION__, h, seconds);

	begin = get_seconds();
	if (lms_cl_derive_merkle_root(&ctx, seed, I, h, cl_root) != 1) {
		error_print();
		lms_cl_cleanup(&ctx);
		return -1;
	}
	seconds = get_seconds() - begin;
	fprintf(stderr, "%s: OpenCL H%d %.3f seconds\n", __FUNCTION__, h, seconds);
	if (memcmp(root, cl_root, 32) != 0) {
		error_print();
		lms_cl_cleanup(&ctx);
		return -1;
	}

	begin = get_seconds();
	if (lms_cl_derive_merkle_root(&ctx, seed, I, cl_h, cl_root) != 1) {
		error_print();
		lms_cl_cleanup(&ctx);
		return -1;
	}
	seconds = get_seconds() - begin;
	fprintf(stderr, "%s: OpenCL H%d %.3f seconds\n", __FUNCTION__, cl_h, seconds);
	lms_cl_cleanup(&ctx);
	return 1;
}
#endif

int main(void)
{
	if (test_lms_cl_derive_merkle_tree() != 1) goto err;
	if (test_lms_cl_key_generate() != 1) goto err;
	if (test_hss_cl_key_generate() != 1) goto err;
#if ENABLE_TEST_SPEED
	if (speed_lms_cl_derive_merkle_root() != 1) goto err;
#endif
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
