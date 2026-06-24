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
#include <stdint.h>
#include <gmssl/lms_cl.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/endian.h>
#include <gmssl/error.h>
#include "cl.h"


static const char *lms_cl_src;

#define LMS_CL_DEFAULT_LOCAL_WORK_SIZE 64
#define LMS_CL_DEFAULT_MAX_LEAF_BATCH (size_t)(32768)


void lms_cl_cleanup(LMS_CL_CTX *ctx)
{
	if (ctx) {
		if (ctx->internal_nodes_kernel) clReleaseKernel(ctx->internal_nodes_kernel);
		if (ctx->leafs_compact_kernel) clReleaseKernel(ctx->leafs_compact_kernel);
		if (ctx->leafs_tree_kernel) clReleaseKernel(ctx->leafs_tree_kernel);
		if (ctx->program) clReleaseProgram(ctx->program);
		if (ctx->queue) clReleaseCommandQueue(ctx->queue);
		if (ctx->context) clReleaseContext(ctx->context);
		memset(ctx, 0, sizeof(*ctx));
	}
}

int lms_cl_init(LMS_CL_CTX *ctx)
{
	cl_platform_id platform;
	cl_device_id device;
	cl_int err;
	size_t max_work_group_size;
	const char *build_opts = NULL;
	const char *sources[2];

	if (!ctx) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));

	if (gmssl_cl_get_gpu_device(&platform, &device) != 1) {
		error_print();
		return -1;
	}
	if (!(ctx->context = clCreateContext(NULL, 1, &device, NULL, NULL, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(ctx->queue = clCreateCommandQueue(ctx->context, device, 0, &err))) {
		cl_error_print(err);
		goto end;
	}
	sources[0] = sm3_cl_source();
	sources[1] = lms_cl_src;
	if (!(ctx->program = clCreateProgramWithSource(ctx->context, 2, sources, NULL, &err))) {
		cl_error_print(err);
		goto end;
	}
	if ((err = clBuildProgram(ctx->program, 1, &device, build_opts, NULL, NULL)) != CL_SUCCESS) {
		char *log = NULL;
		size_t loglen = 0;

		cl_error_print(err);
		(void)clGetProgramBuildInfo(ctx->program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &loglen);
		if (loglen && (log = (char *)malloc(loglen + 1))) {
			if (clGetProgramBuildInfo(ctx->program, device, CL_PROGRAM_BUILD_LOG, loglen, log, NULL) == CL_SUCCESS) {
				log[loglen] = 0;
				fprintf(stderr, "%s\n", log);
			}
			free(log);
		}
		goto end;
	}
	if (!(ctx->leafs_tree_kernel = clCreateKernel(ctx->program, "lms_leafs_tree", &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(ctx->leafs_compact_kernel = clCreateKernel(ctx->program, "lms_leafs_compact", &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(ctx->internal_nodes_kernel = clCreateKernel(ctx->program, "lms_internal_nodes", &err))) {
		cl_error_print(err);
		goto end;
	}

	ctx->local_work_size = LMS_CL_DEFAULT_LOCAL_WORK_SIZE;
	if (clGetKernelWorkGroupInfo(ctx->leafs_tree_kernel, device, CL_KERNEL_WORK_GROUP_SIZE,
		sizeof(max_work_group_size), &max_work_group_size, NULL) == CL_SUCCESS
		&& max_work_group_size > 0 && ctx->local_work_size > max_work_group_size) {
		ctx->local_work_size = max_work_group_size;
	}
	ctx->max_leaf_batch = LMS_CL_DEFAULT_MAX_LEAF_BATCH;
	return 1;

end:
	lms_cl_cleanup(ctx);
	return -1;
}

static int lms_cl_enqueue_leafs_tree(LMS_CL_CTX *ctx, cl_mem mem_seed, cl_mem mem_I,
	uint32_t leaf_offset, uint32_t leaf_count, uint32_t h, cl_mem mem_tree)
{
	cl_int err;
	cl_uint arg = 0;
	size_t global_work_size;
	size_t local_work_size;

	if ((err = clSetKernelArg(ctx->leafs_tree_kernel, arg++, sizeof(cl_mem), &mem_seed)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_tree_kernel, arg++, sizeof(cl_mem), &mem_I)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_tree_kernel, arg++, sizeof(leaf_offset), &leaf_offset)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_tree_kernel, arg++, sizeof(leaf_count), &leaf_count)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_tree_kernel, arg++, sizeof(h), &h)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_tree_kernel, arg++, sizeof(cl_mem), &mem_tree)) != CL_SUCCESS) {
		cl_error_print(err);
		return -1;
	}

	local_work_size = ctx->local_work_size;
	global_work_size = gmssl_cl_round_up(leaf_count, local_work_size);
	if ((err = clEnqueueNDRangeKernel(ctx->queue, ctx->leafs_tree_kernel, 1, NULL,
		&global_work_size, &local_work_size, 0, NULL, NULL)) != CL_SUCCESS) {
		cl_error_print(err);
		return -1;
	}
	return 1;
}

static int lms_cl_enqueue_leafs_compact(LMS_CL_CTX *ctx, cl_mem mem_seed, cl_mem mem_I,
	uint32_t leaf_offset, uint32_t leaf_count, uint32_t h, cl_mem mem_leafs)
{
	cl_int err;
	cl_uint arg = 0;
	size_t global_work_size;
	size_t local_work_size;

	if ((err = clSetKernelArg(ctx->leafs_compact_kernel, arg++, sizeof(cl_mem), &mem_seed)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_compact_kernel, arg++, sizeof(cl_mem), &mem_I)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_compact_kernel, arg++, sizeof(leaf_offset), &leaf_offset)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_compact_kernel, arg++, sizeof(leaf_count), &leaf_count)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_compact_kernel, arg++, sizeof(h), &h)) != CL_SUCCESS
		|| (err = clSetKernelArg(ctx->leafs_compact_kernel, arg++, sizeof(cl_mem), &mem_leafs)) != CL_SUCCESS) {
		cl_error_print(err);
		return -1;
	}

	local_work_size = ctx->local_work_size;
	global_work_size = gmssl_cl_round_up(leaf_count, local_work_size);
	if ((err = clEnqueueNDRangeKernel(ctx->queue, ctx->leafs_compact_kernel, 1, NULL,
		&global_work_size, &local_work_size, 0, NULL, NULL)) != CL_SUCCESS) {
		cl_error_print(err);
		return -1;
	}
	return 1;
}

int lms_cl_derive_merkle_tree(LMS_CL_CTX *ctx,
	const lms_sm3_digest_t seed, const uint8_t I[16], int height, lms_sm3_digest_t *tree)
{
	int ret = -1;
	cl_int err;
	cl_mem mem_seed = NULL;
	cl_mem mem_I = NULL;
	cl_mem mem_tree = NULL;
	size_t n;
	size_t tree_nodes;
	size_t tree_size;
	size_t level_nodes;
	size_t global_work_size;
	size_t local_work_size;
	uint32_t level_first;

	if (!ctx || !seed || !I || !tree || height < 0 || height > LMS_MAX_HEIGHT) {
		error_print();
		return -1;
	}

	n = (size_t)1 << height;
	tree_nodes = 2*n - 1;
	tree_size = tree_nodes * sizeof(lms_sm3_digest_t);

	if (!(mem_seed = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, 32, (void *)seed, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(mem_I = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, 16, (void *)I, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(mem_tree = clCreateBuffer(ctx->context, CL_MEM_READ_WRITE, tree_size, NULL, &err))) {
		cl_error_print(err);
		goto end;
	}

	if (lms_cl_enqueue_leafs_tree(ctx, mem_seed, mem_I, 0, (uint32_t)n, (uint32_t)height, mem_tree) != 1) {
		goto end;
	}

	local_work_size = ctx->local_work_size;
	for (level_nodes = n/2; level_nodes > 0; level_nodes >>= 1) {
		cl_uint arg = 0;
		level_first = (uint32_t)level_nodes;
		if ((err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(cl_mem), &mem_I)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(level_first), &level_first)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(uint32_t), &level_first)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(cl_mem), &mem_tree)) != CL_SUCCESS) {
			cl_error_print(err);
			goto end;
		}
		global_work_size = gmssl_cl_round_up(level_nodes, local_work_size);
		if ((err = clEnqueueNDRangeKernel(ctx->queue, ctx->internal_nodes_kernel, 1, NULL,
			&global_work_size, &local_work_size, 0, NULL, NULL)) != CL_SUCCESS) {
			cl_error_print(err);
			goto end;
		}
	}

	if ((err = clEnqueueReadBuffer(ctx->queue, mem_tree, CL_TRUE, 0, tree_size, tree, 0, NULL, NULL)) != CL_SUCCESS) {
		cl_error_print(err);
		goto end;
	}
	ret = 1;

end:
	if (mem_tree) clReleaseMemObject(mem_tree);
	if (mem_I) clReleaseMemObject(mem_I);
	if (mem_seed) clReleaseMemObject(mem_seed);
	return ret;
}

static void lms_cl_hash_internal(const uint8_t I[16], uint32_t r,
	const lms_sm3_digest_t left, const lms_sm3_digest_t right, lms_sm3_digest_t out)
{
	SM3_CTX sm3_ctx;
	uint8_t rbytes[4];
	static const uint8_t D_INTR[2] = { 0x83, 0x83 };

	PUTU32(rbytes, r);
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, I, 16);
	sm3_update(&sm3_ctx, rbytes, 4);
	sm3_update(&sm3_ctx, D_INTR, 2);
	sm3_update(&sm3_ctx, left, 32);
	sm3_update(&sm3_ctx, right, 32);
	sm3_finish(&sm3_ctx, out);
}

int lms_cl_derive_merkle_root(LMS_CL_CTX *ctx,
	const lms_sm3_digest_t seed, const uint8_t I[16], int height, lms_sm3_digest_t root)
{
	int ret = -1;
	cl_int err;
	cl_mem mem_seed = NULL;
	cl_mem mem_I = NULL;
	cl_mem mem_leafs = NULL;
	lms_sm3_digest_t *leafs = NULL;
	lms_sm3_digest_t stack[LMS_MAX_HEIGHT + 1];
	size_t n;
	size_t batch;
	size_t q;
	size_t i;
	int num = 0;

	if (!ctx || !seed || !I || !root || height < 0 || height > LMS_MAX_HEIGHT) {
		error_print();
		return -1;
	}

	n = (size_t)1 << height;
	batch = ctx->max_leaf_batch ? ctx->max_leaf_batch : LMS_CL_DEFAULT_MAX_LEAF_BATCH;
	if (batch > n) {
		batch = n;
	}
	if (!(leafs = (lms_sm3_digest_t *)malloc(sizeof(lms_sm3_digest_t) * batch))) {
		error_print();
		return -1;
	}

	if (!(mem_seed = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, 32, (void *)seed, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(mem_I = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, 16, (void *)I, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(mem_leafs = clCreateBuffer(ctx->context, CL_MEM_WRITE_ONLY,
		sizeof(lms_sm3_digest_t) * batch, NULL, &err))) {
		cl_error_print(err);
		goto end;
	}

	for (q = 0; q < n; ) {
		size_t count = n - q;
		if (count > batch) {
			count = batch;
		}
		if (lms_cl_enqueue_leafs_compact(ctx, mem_seed, mem_I,
			(uint32_t)q, (uint32_t)count, (uint32_t)height, mem_leafs) != 1) {
			goto end;
		}
		if ((err = clEnqueueReadBuffer(ctx->queue, mem_leafs, CL_TRUE, 0,
			sizeof(lms_sm3_digest_t) * count, leafs, 0, NULL, NULL)) != CL_SUCCESS) {
			cl_error_print(err);
			goto end;
		}
		for (i = 0; i < count; i++, q++) {
			uint32_t r = (uint32_t)(n + q);
			size_t qbits = q;

			memcpy(stack[num], leafs[i], 32);
			num++;
			while (qbits & 1) {
				r >>= 1;
				lms_cl_hash_internal(I, r, stack[num - 2], stack[num - 1], stack[num - 2]);
				num--;
				qbits >>= 1;
			}
		}
	}
	if (num != 1) {
		error_print();
		goto end;
	}
	memcpy(root, stack[0], 32);
	ret = 1;

end:
	if (mem_leafs) clReleaseMemObject(mem_leafs);
	if (mem_I) clReleaseMemObject(mem_I);
	if (mem_seed) clReleaseMemObject(mem_seed);
	if (leafs) free(leafs);
	return ret;
}

int lms_cl_key_generate_ex(LMS_CL_CTX *ctx, LMS_KEY *key, int lms_type,
	const lms_sm3_digest_t seed, const uint8_t I[16], int cache_tree)
{
	size_t h, n;

	if (!ctx || !key || !seed || !I) {
		error_print();
		return -1;
	}
	if (lms_type_to_height(lms_type, &h) != 1) {
		error_print();
		return -1;
	}
	n = (size_t)1 << h;

	memset(key, 0, sizeof(LMS_KEY));
	key->public_key.lms_type = lms_type;
	key->public_key.lmots_type = LMOTS_SM3_N32_W8;
	memcpy(key->public_key.I, I, 16);
	memcpy(key->seed, seed, 32);

	if (cache_tree) {
		if (!(key->tree = (lms_sm3_digest_t *)malloc(sizeof(lms_sm3_digest_t) * (2*n - 1)))) {
			error_print();
			return -1;
		}
		if (lms_cl_derive_merkle_tree(ctx, key->seed, key->public_key.I, (int)h, key->tree) != 1) {
			lms_key_cleanup(key);
			error_print();
			return -1;
		}
		memcpy(key->public_key.root, key->tree[0], 32);
	} else {
		if (lms_cl_derive_merkle_root(ctx, key->seed, key->public_key.I, (int)h, key->public_key.root) != 1) {
			lms_key_cleanup(key);
			error_print();
			return -1;
		}
	}
	key->q = 0;
	return 1;
}

int lms_cl_key_generate(LMS_CL_CTX *ctx, LMS_KEY *key, int lms_type)
{
	lms_sm3_digest_t seed;
	uint8_t I[16];
	int cache_tree = 1;

	if (rand_bytes(seed, sizeof(seed)) != 1) {
		error_print();
		return -1;
	}
	if (rand_bytes(I, sizeof(I)) != 1) {
		error_print();
		return -1;
	}
	if (lms_cl_key_generate_ex(ctx, key, lms_type, seed, I, cache_tree) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int lms_cl_private_key_from_bytes(LMS_CL_CTX *ctx, LMS_KEY *key, const uint8_t **in, size_t *inlen)
{
	size_t height;
	size_t n;

	if (!ctx || !key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < LMS_PRIVATE_KEY_SIZE) {
		error_print();
		return -1;
	}
	if (lms_public_key_from_bytes(key, in, inlen) != 1) {
		error_print();
		return -1;
	}

	memcpy(key->seed, *in, 32);
	*in += 32;
	*inlen -= 32;

	key->q = GETU32(*in);
	*in += 4;
	*inlen -= 4;

	if (lms_type_to_height(key->public_key.lms_type, &height) != 1) {
		error_print();
		goto err;
	}
	if (key->q >= ((uint32_t)1 << height)) {
		error_print();
		goto err;
	}

	n = (size_t)1 << height;
	if (!(key->tree = (lms_sm3_digest_t *)malloc(sizeof(lms_sm3_digest_t) * (2*n - 1)))) {
		error_print();
		goto err;
	}
	if (lms_cl_derive_merkle_tree(ctx, key->seed, key->public_key.I, (int)height, key->tree) != 1) {
		error_print();
		goto err;
	}
	memcpy(key->public_key.root, key->tree[0], 32);
	return 1;

err:
	lms_key_cleanup(key);
	return -1;
}

int hss_cl_key_generate(LMS_CL_CTX *ctx, HSS_KEY *key, const int *lms_types, size_t levels)
{
	int ret = -1;
	lms_sm3_digest_t seed;
	uint8_t I[16];
	LMS_SIGN_CTX sign_ctx;
	uint8_t buf[LMS_SIGNATURE_MAX_SIZE];
	int cache_tree = 1;
	size_t i;

	if (!ctx || !key || !lms_types) {
		error_print();
		return -1;
	}
	if (levels < 1 || levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}
	for (i = 0; i < levels; i++) {
		if (!lms_type_name(lms_types[i])) {
			error_print();
			return -1;
		}
	}

	memset(key, 0, sizeof(*key));
	memset(&sign_ctx, 0, sizeof(sign_ctx));
	key->levels = (uint32_t)levels;

	if (rand_bytes(seed, sizeof(seed)) != 1) {
		error_print();
		goto end;
	}
	if (rand_bytes(I, sizeof(I)) != 1) {
		error_print();
		goto end;
	}
	if (lms_cl_key_generate_ex(ctx, &key->lms_key[0], lms_types[0], seed, I, cache_tree) != 1) {
		error_print();
		goto end;
	}

	for (i = 1; i < levels; i++) {
		uint8_t *p = buf;
		size_t len = 0;

		if (rand_bytes(seed, sizeof(seed)) != 1) {
			error_print();
			goto end;
		}
		if (rand_bytes(I, sizeof(I)) != 1) {
			error_print();
			goto end;
		}
		if (lms_cl_key_generate_ex(ctx, &key->lms_key[i], lms_types[i], seed, I, cache_tree) != 1) {
			error_print();
			goto end;
		}
		if (lms_public_key_to_bytes(&key->lms_key[i], &p, &len) != 1) {
			error_print();
			goto end;
		}
		if (lms_sign_init(&sign_ctx, &key->lms_key[i - 1]) != 1
			|| lms_sign_update(&sign_ctx, buf, len) != 1
			|| lms_sign_finish(&sign_ctx, buf, &len) != 1) {
			error_print();
			goto end;
		}
		key->lms_sig[i - 1] = sign_ctx.lms_sig;
	}

	ret = 1;
end:
	gmssl_secure_clear(seed, sizeof(seed));
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	if (ret != 1) hss_key_cleanup(key);
	return ret;
}

int hss_cl_private_key_from_bytes(LMS_CL_CTX *ctx, HSS_KEY *key, const uint8_t **in, size_t *inlen)
{
	size_t i;

	if (!ctx || !key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < 4) {
		error_print();
		return -1;
	}

	key->levels = GETU32(*in);
	if (key->levels < 1 || key->levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}
	*in += 4;
	*inlen -= 4;

	if (lms_cl_private_key_from_bytes(ctx, &key->lms_key[0], in, inlen) != 1) {
		error_print();
		goto err;
	}

	for (i = 1; i < key->levels; i++) {
		LMS_SIGN_CTX sign_ctx;
		uint8_t buf[LMS_PUBLIC_KEY_SIZE];
		uint8_t *p = buf;
		size_t len = 0;

		if (lms_cl_private_key_from_bytes(ctx, &key->lms_key[i], in, inlen) != 1) {
			error_print();
			goto err;
		}
		if (lms_signature_from_bytes(&key->lms_sig[i - 1], in, inlen) != 1) {
			error_print();
			goto err;
		}

		if (lms_public_key_to_bytes(&key->lms_key[i], &p, &len) != 1) {
			error_print();
			goto err;
		}
		if (lms_verify_init_ex(&sign_ctx, &key->lms_key[i - 1], &key->lms_sig[i - 1]) != 1
			|| lms_verify_update(&sign_ctx, buf, len) != 1
			|| lms_verify_finish(&sign_ctx) != 1) {
			error_print();
			goto err;
		}
	}
	return 1;

err:
	hss_key_cleanup(key);
	return -1;
}

int hss_cl_key_update(LMS_CL_CTX *ctx, HSS_KEY *key)
{
	int level;
	LMS_KEY *lms_key;
	size_t count;

	if (!ctx || !key) {
		error_print();
		return -1;
	}

	for (level = key->levels; level > 0; level--) {
		lms_key = &key->lms_key[level - 1];
		if (lms_key_remaining_signs(lms_key, &count) != 1) {
			error_print();
			return -1;
		}
		if (count > 0) {
			break;
		}
	}
	if (level >= (int)key->levels) {
		error_print();
		return -1;
	}
	if (level == 0) {
		return 0;
	}

	for (; level < (int)key->levels; level++) {
		int lms_type = key->lms_key[level].public_key.lms_type;
		LMS_SIGN_CTX sign_ctx;
		uint8_t buf[LMS_PUBLIC_KEY_SIZE];
		uint8_t *p = buf;
		size_t len = 0;

		lms_key_cleanup(&key->lms_key[level]);

		if (lms_cl_key_generate(ctx, &key->lms_key[level], lms_type) != 1) {
			error_print();
			return -1;
		}
		if (lms_public_key_to_bytes(&key->lms_key[level], &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (lms_sign_init(&sign_ctx, &key->lms_key[level - 1]) != 1) {
			error_print();
			return -1;
		}
		if (lms_sign_update(&sign_ctx, buf, len) != 1) {
			error_print();
			return -1;
		}
		if (lms_sign_finish_ex(&sign_ctx, &key->lms_sig[level - 1]) != 1) {
			error_print();
			return -1;
		}
	}

	if (key->update_callback) {
		if (key->update_callback(key) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int hss_cl_sign_init(LMS_CL_CTX *ctx, HSS_SIGN_CTX *sign_ctx, HSS_KEY *key)
{
	size_t count;
	size_t i;

	if (!ctx || !sign_ctx || !key) {
		error_print();
		return -1;
	}
	if (key->levels < 1 || key->levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}

	memset(sign_ctx, 0, sizeof(*sign_ctx));

	if (lms_sign_init(&sign_ctx->lms_sign_ctx, &key->lms_key[key->levels - 1]) != 1) {
		error_print();
		return -1;
	}

	sign_ctx->levels = key->levels;

	for (i = 0; i < key->levels - 1; i++) {
		sign_ctx->lms_public_keys[i] = key->lms_key[i + 1].public_key;
		sign_ctx->lms_sigs[i] = key->lms_sig[i];
	}

	if (lms_key_remaining_signs(&key->lms_key[key->levels - 1], &count) != 1) {
		error_print();
		return -1;
	}
	if (count == 0) {
		if (hss_cl_key_update(ctx, key) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

static const char *lms_cl_src = KERNEL(

void sm3_hash_lmots_step(__global const uchar *I, uint q, ushort i, uchar j,
	__private const uchar in[32], __private uchar out[32])
{
	uint dgst[8];
	uint W[68];
	uint k;

	sm3_init_state(dgst);
	W[0] = load_be32(I);
	W[1] = load_be32(I + 4);
	W[2] = load_be32(I + 8);
	W[3] = load_be32(I + 12);
	W[4] = q;
	W[5] = ((uint)i << 16) | ((uint)j << 8) | (uint)in[0];
	for (k = 0; k < 7; k++) {
		W[6 + k] = load_be32_private(in + 1 + 4*k);
	}
	W[13] = ((uint)in[29] << 24) | ((uint)in[30] << 16) | ((uint)in[31] << 8) | 0x80U;
	W[14] = 0;
	W[15] = 440;
	sm3_compress_words(dgst, W);
	for (k = 0; k < 8; k++) {
		store_be32(out + 4*k, dgst[k]);
	}
}

void sm3_public_hash_update(__private uint dgst[8], __private uchar block[64],
	__private uint *num, __private ulong *nblocks, __private const uchar z[32])
{
	uint i;
	for (i = 0; i < 32; i++) {
		sm3_update_byte(dgst, block, num, nblocks, z[i]);
	}
}

void lms_compute_leaf(__global const uchar *seed, __global const uchar *I,
	uint q, uint h, __private uchar leaf[32])
{
	uchar z[32];
	uchar tmp[32];
	uint dgst[8];
	uchar block[64];
	uint num = 0;
	ulong nblocks = 0;
	uint i, j, k;
	uint r = (1U << h) + q;

	sm3_init_state(dgst);
	for (i = 0; i < 16; i++) {
		sm3_update_byte(dgst, block, &num, &nblocks, I[i]);
	}
	sm3_update_byte(dgst, block, &num, &nblocks, (uchar)(q >> 24));
	sm3_update_byte(dgst, block, &num, &nblocks, (uchar)(q >> 16));
	sm3_update_byte(dgst, block, &num, &nblocks, (uchar)(q >> 8));
	sm3_update_byte(dgst, block, &num, &nblocks, (uchar)q);
	sm3_update_byte(dgst, block, &num, &nblocks, 0x80);
	sm3_update_byte(dgst, block, &num, &nblocks, 0x80);

	for (i = 0; i < 34; i++) {
		for (k = 0; k < 32; k++) {
			tmp[k] = seed[k];
		}
		sm3_hash_lmots_step(I, q, (ushort)i, 0xff, tmp, z);
		for (j = 0; j < 255; j++) {
			for (k = 0; k < 32; k++) {
				tmp[k] = z[k];
			}
			sm3_hash_lmots_step(I, q, (ushort)i, (uchar)j, tmp, z);
		}
		sm3_public_hash_update(dgst, block, &num, &nblocks, z);
	}
	sm3_finish_ctx(dgst, block, num, nblocks, tmp);

	sm3_init_state(dgst);
	{
		uint W[68];
		W[0] = load_be32(I);
		W[1] = load_be32(I + 4);
		W[2] = load_be32(I + 8);
		W[3] = load_be32(I + 12);
		W[4] = r;
		W[5] = 0x82820000U | ((uint)tmp[0] << 8) | (uint)tmp[1];
		for (k = 0; k < 7; k++) {
			W[6 + k] = load_be32_private(tmp + 2 + 4*k);
		}
		W[13] = ((uint)tmp[30] << 24) | ((uint)tmp[31] << 16) | 0x8000U;
		W[14] = 0;
		W[15] = 432;
		sm3_compress_words(dgst, W);
		for (k = 0; k < 8; k++) {
			store_be32(leaf + 4*k, dgst[k]);
		}
	}
}

void sm3_hash_internal(__global const uchar *I, uint r,
	__global const uchar *left, __global const uchar *right, __global uchar *out)
{
	uint dgst[8];
	uint W[68];
	uint k;

	sm3_init_state(dgst);
	W[0] = load_be32(I);
	W[1] = load_be32(I + 4);
	W[2] = load_be32(I + 8);
	W[3] = load_be32(I + 12);
	W[4] = r;
	W[5] = 0x83830000U | ((uint)left[0] << 8) | (uint)left[1];
	for (k = 0; k < 7; k++) {
		W[6 + k] = load_be32(left + 2 + 4*k);
	}
	W[13] = ((uint)left[30] << 24) | ((uint)left[31] << 16)
		| ((uint)right[0] << 8) | (uint)right[1];
	W[14] = load_be32(right + 2);
	W[15] = load_be32(right + 6);
	sm3_compress_words(dgst, W);

	W[0] = load_be32(right + 10);
	W[1] = load_be32(right + 14);
	W[2] = load_be32(right + 18);
	W[3] = load_be32(right + 22);
	W[4] = load_be32(right + 26);
	W[5] = ((uint)right[30] << 24) | ((uint)right[31] << 16) | 0x8000U;
	for (k = 6; k < 15; k++) {
		W[k] = 0;
	}
	W[15] = 688;
	sm3_compress_words(dgst, W);
	for (k = 0; k < 8; k++) {
		out[4*k] = (uchar)(dgst[k] >> 24);
		out[4*k + 1] = (uchar)(dgst[k] >> 16);
		out[4*k + 2] = (uchar)(dgst[k] >> 8);
		out[4*k + 3] = (uchar)dgst[k];
	}
}

__kernel void lms_leafs_tree(__global const uchar *seed, __global const uchar *I,
	uint leaf_offset, uint leaf_count, uint h, __global uchar *tree)
{
	uint id = get_global_id(0);
	uint q;
	uint r;
	uchar leaf[32];
	uint i;

	if (id >= leaf_count) {
		return;
	}
	q = leaf_offset + id;
	r = (1U << h) + q;
	lms_compute_leaf(seed, I, q, h, leaf);
	for (i = 0; i < 32; i++) {
		tree[(r - 1)*32 + i] = leaf[i];
	}
}

__kernel void lms_leafs_compact(__global const uchar *seed, __global const uchar *I,
	uint leaf_offset, uint leaf_count, uint h, __global uchar *leafs)
{
	uint id = get_global_id(0);
	uchar leaf[32];
	uint i;

	if (id >= leaf_count) {
		return;
	}
	lms_compute_leaf(seed, I, leaf_offset + id, h, leaf);
	for (i = 0; i < 32; i++) {
		leafs[id*32 + i] = leaf[i];
	}
}

__kernel void lms_internal_nodes(__global const uchar *I, uint level_first,
	uint level_count, __global uchar *tree)
{
	uint id = get_global_id(0);
	uint r;

	if (id >= level_count) {
		return;
	}
	r = level_first + id;
	sm3_hash_internal(I, r, tree + (2*r - 1)*32, tree + (2*r)*32, tree + (r - 1)*32);
}

);
