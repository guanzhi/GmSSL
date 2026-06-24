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
#include <gmssl/xmss_cl.h>
#include <gmssl/rand.h>
#include <gmssl/mem.h>
#include <gmssl/endian.h>
#include <gmssl/error.h>
#include "cl.h"


static const char *xmss_cl_src;

#define XMSS_CL_DEFAULT_LOCAL_WORK_SIZE 32

static const uint8_t xmss_cl_sm3_digest_two[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
};

static const uint8_t xmss_cl_sm3_digest_three[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
};

static size_t xmss_cl_tree_root_offset(size_t height)
{
	return ((size_t)1 << (height + 1)) - 2;
}

static uint64_t xmssmt_cl_tree_address(uint64_t index, size_t height, size_t layers, size_t layer)
{
	return index >> ((height/layers) * (layer + 1));
}

static uint64_t xmssmt_cl_tree_index(uint64_t index, size_t height, size_t layers, size_t layer)
{
	return (index >> ((height/layers) * layer)) % ((uint64_t)1 << (height/layers));
}


void xmss_cl_cleanup(XMSS_CL_CTX *ctx)
{
	if (ctx) {
		if (ctx->internal_nodes_kernel) clReleaseKernel(ctx->internal_nodes_kernel);
		if (ctx->leafs_kernel) clReleaseKernel(ctx->leafs_kernel);
		if (ctx->program) clReleaseProgram(ctx->program);
		if (ctx->queue) clReleaseCommandQueue(ctx->queue);
		if (ctx->context) clReleaseContext(ctx->context);
		memset(ctx, 0, sizeof(*ctx));
	}
}

int xmss_cl_init(XMSS_CL_CTX *ctx)
{
	cl_platform_id platform;
	cl_device_id device;
	cl_int err;
	size_t max_work_group_size;
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
	sources[1] = xmss_cl_src;
	if (!(ctx->program = clCreateProgramWithSource(ctx->context, 2, sources, NULL, &err))) {
		cl_error_print(err);
		goto end;
	}
	if ((err = clBuildProgram(ctx->program, 1, &device, NULL, NULL, NULL)) != CL_SUCCESS) {
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
	if (!(ctx->leafs_kernel = clCreateKernel(ctx->program, "xmss_leafs", &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(ctx->internal_nodes_kernel = clCreateKernel(ctx->program, "xmss_internal_nodes", &err))) {
		cl_error_print(err);
		goto end;
	}

	ctx->local_work_size = XMSS_CL_DEFAULT_LOCAL_WORK_SIZE;
	if (clGetKernelWorkGroupInfo(ctx->leafs_kernel, device, CL_KERNEL_WORK_GROUP_SIZE,
		sizeof(max_work_group_size), &max_work_group_size, NULL) == CL_SUCCESS
		&& max_work_group_size > 0 && ctx->local_work_size > max_work_group_size) {
		ctx->local_work_size = max_work_group_size;
	}
	return 1;

end:
	xmss_cl_cleanup(ctx);
	return -1;
}

int xmss_cl_build_tree(XMSS_CL_CTX *ctx,
	const xmss_sm3_digest_t secret, const xmss_sm3_digest_t seed,
	const xmss_adrs_t adrs, size_t height, xmss_sm3_digest_t *tree)
{
	int ret = -1;
	cl_int err;
	cl_mem mem_secret = NULL;
	cl_mem mem_seed = NULL;
	cl_mem mem_adrs = NULL;
	cl_mem mem_tree = NULL;
	size_t n;
	size_t tree_nodes;
	size_t tree_size;
	size_t children_offset;
	size_t parents_offset;
	size_t level_nodes;
	size_t level_height;
	size_t local_work_size;
	size_t global_work_size;
	uint32_t u32_height;

	if (!ctx || !secret || !seed || !adrs || !tree || height > XMSS_MAX_HEIGHT) {
		error_print();
		return -1;
	}

	n = (size_t)1 << height;
	tree_nodes = xmss_num_tree_nodes(height);
	tree_size = tree_nodes * sizeof(xmss_sm3_digest_t);
	if (!(mem_secret = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, 32, (void *)secret, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(mem_seed = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, 32, (void *)seed, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(mem_adrs = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, 32, (void *)adrs, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(mem_tree = clCreateBuffer(ctx->context, CL_MEM_READ_WRITE, tree_size, NULL, &err))) {
		cl_error_print(err);
		goto end;
	}

	u32_height = (uint32_t)height;
	local_work_size = ctx->local_work_size;
	global_work_size = gmssl_cl_round_up(n, local_work_size);
	{
		cl_uint arg = 0;
		uint32_t leaf_count = (uint32_t)n;
		uint32_t leaf_offset = 0;
		if ((err = clSetKernelArg(ctx->leafs_kernel, arg++, sizeof(cl_mem), &mem_secret)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->leafs_kernel, arg++, sizeof(cl_mem), &mem_seed)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->leafs_kernel, arg++, sizeof(cl_mem), &mem_adrs)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->leafs_kernel, arg++, sizeof(leaf_offset), &leaf_offset)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->leafs_kernel, arg++, sizeof(leaf_count), &leaf_count)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->leafs_kernel, arg++, sizeof(u32_height), &u32_height)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->leafs_kernel, arg++, sizeof(cl_mem), &mem_tree)) != CL_SUCCESS) {
			cl_error_print(err);
			goto end;
		}
	}
	if ((err = clEnqueueNDRangeKernel(ctx->queue, ctx->leafs_kernel, 1, NULL,
		&global_work_size, &local_work_size, 0, NULL, NULL)) != CL_SUCCESS) {
		cl_error_print(err);
		goto end;
	}

	children_offset = 0;
	parents_offset = n;
	for (level_nodes = n/2, level_height = 1; level_nodes > 0; level_nodes >>= 1, level_height++) {
		cl_uint arg = 0;
		uint32_t u32_children_offset = (uint32_t)children_offset;
		uint32_t u32_parents_offset = (uint32_t)parents_offset;
		uint32_t u32_level_nodes = (uint32_t)level_nodes;
		uint32_t u32_level_height = (uint32_t)level_height;

		if ((err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(cl_mem), &mem_seed)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(cl_mem), &mem_adrs)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(u32_children_offset), &u32_children_offset)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(u32_parents_offset), &u32_parents_offset)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(u32_level_nodes), &u32_level_nodes)) != CL_SUCCESS
			|| (err = clSetKernelArg(ctx->internal_nodes_kernel, arg++, sizeof(u32_level_height), &u32_level_height)) != CL_SUCCESS
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
		children_offset = parents_offset;
		parents_offset += level_nodes;
	}

	if ((err = clEnqueueReadBuffer(ctx->queue, mem_tree, CL_TRUE, 0, tree_size, tree, 0, NULL, NULL)) != CL_SUCCESS) {
		cl_error_print(err);
		goto end;
	}
	ret = 1;

end:
	if (mem_tree) clReleaseMemObject(mem_tree);
	if (mem_adrs) clReleaseMemObject(mem_adrs);
	if (mem_seed) clReleaseMemObject(mem_seed);
	if (mem_secret) clReleaseMemObject(mem_secret);
	return ret;
}

int xmss_cl_key_generate_ex(XMSS_CL_CTX *ctx, XMSS_KEY *key, uint32_t xmss_type,
	const xmss_sm3_digest_t seed, const xmss_sm3_digest_t secret,
	const xmss_sm3_digest_t sk_prf)
{
	size_t height;
	xmss_adrs_t adrs;

	if (!ctx || !key || !seed || !secret || !sk_prf) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));
	if (!(key->tree = malloc(sizeof(xmss_sm3_digest_t) * xmss_num_tree_nodes(height)))) {
		error_print();
		return -1;
	}

	key->public_key.xmss_type = xmss_type;
	memcpy(key->public_key.seed, seed, sizeof(xmss_sm3_digest_t));
	memcpy(key->secret, secret, sizeof(xmss_sm3_digest_t));
	memcpy(key->sk_prf, sk_prf, sizeof(xmss_sm3_digest_t));

	xmss_adrs_set_layer_address(adrs, 0);
	xmss_adrs_set_tree_address(adrs, 0);
	if (xmss_cl_build_tree(ctx, key->secret, key->public_key.seed, adrs, height, key->tree) != 1) {
		xmss_key_cleanup(key);
		error_print();
		return -1;
	}
	memcpy(key->public_key.root, key->tree[xmss_cl_tree_root_offset(height)], sizeof(xmss_sm3_digest_t));
	key->index = 0;
	return 1;
}

int xmss_cl_key_generate(XMSS_CL_CTX *ctx, XMSS_KEY *key, uint32_t xmss_type)
{
	int ret = -1;
	xmss_sm3_digest_t seed;
	xmss_sm3_digest_t secret;
	xmss_sm3_digest_t sk_prf;

	if (rand_bytes(seed, sizeof(seed)) != 1
		|| rand_bytes(secret, sizeof(secret)) != 1
		|| rand_bytes(sk_prf, sizeof(sk_prf)) != 1) {
		error_print();
		goto end;
	}
	if (xmss_cl_key_generate_ex(ctx, key, xmss_type, seed, secret, sk_prf) != 1) {
		error_print();
		goto end;
	}
	ret = 1;

end:
	gmssl_secure_clear(seed, sizeof(seed));
	gmssl_secure_clear(secret, sizeof(secret));
	gmssl_secure_clear(sk_prf, sizeof(sk_prf));
	return ret;
}

int xmss_cl_private_key_from_bytes(XMSS_CL_CTX *ctx, XMSS_KEY *key,
	const uint8_t **in, size_t *inlen)
{
	size_t height;
	size_t tree_size;
	xmss_adrs_t adrs;

	if (!ctx || !key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (xmss_public_key_from_bytes(key, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (*inlen < sizeof(uint32_t) + sizeof(xmss_sm3_digest_t)*2) {
		error_print();
		return -1;
	}
	if (xmss_type_to_height(key->public_key.xmss_type, &height) != 1) {
		error_print();
		return -1;
	}
	tree_size = sizeof(xmss_sm3_digest_t) * xmss_num_tree_nodes(height);
	if (!(key->tree = malloc(tree_size))) {
		error_print();
		return -1;
	}

	key->index = GETU32(*in);
	*in += 4;
	*inlen -= 4;
	if (key->index > ((uint32_t)1 << height)) {
		error_print();
		goto err;
	}
	memcpy(key->secret, *in, sizeof(xmss_sm3_digest_t));
	*in += sizeof(xmss_sm3_digest_t);
	*inlen -= sizeof(xmss_sm3_digest_t);
	memcpy(key->sk_prf, *in, sizeof(xmss_sm3_digest_t));
	*in += sizeof(xmss_sm3_digest_t);
	*inlen -= sizeof(xmss_sm3_digest_t);

	if (*inlen) {
		if (*inlen < tree_size) {
			error_print();
			goto err;
		}
		memcpy(key->tree, *in, tree_size);
		*in += tree_size;
		*inlen -= tree_size;
	} else {
		xmss_adrs_set_layer_address(adrs, 0);
		xmss_adrs_set_tree_address(adrs, 0);
		if (xmss_cl_build_tree(ctx, key->secret, key->public_key.seed, adrs, height, key->tree) != 1) {
			error_print();
			goto err;
		}
	}

	if (memcmp(key->tree[xmss_cl_tree_root_offset(height)],
		key->public_key.root, sizeof(xmss_sm3_digest_t)) != 0) {
		error_print();
		goto err;
	}
	return 1;

err:
	xmss_key_cleanup(key);
	return -1;
}

int xmssmt_cl_key_generate_ex(XMSS_CL_CTX *ctx, XMSSMT_KEY *key, uint32_t xmssmt_type,
	const xmss_sm3_digest_t seed, const xmss_sm3_digest_t secret,
	const xmss_sm3_digest_t sk_prf)
{
	size_t height;
	size_t layers;
	size_t layer;
	size_t subtree_height;
	xmss_adrs_t adrs;
	xmss_sm3_digest_t *tree;
	xmss_sm3_digest_t *xmss_root = NULL;

	if (!ctx || !key || !seed || !secret || !sk_prf) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));

	key->public_key.xmssmt_type = xmssmt_type;
	memcpy(key->public_key.seed, seed, sizeof(xmss_sm3_digest_t));
	memcpy(key->secret, secret, sizeof(xmss_sm3_digest_t));
	memcpy(key->sk_prf, sk_prf, sizeof(xmss_sm3_digest_t));
	key->index = 0;

	if (!(key->trees = malloc(xmssmt_num_trees_nodes(height, layers) * sizeof(xmss_sm3_digest_t)))) {
		error_print();
		return -1;
	}

	subtree_height = height/layers;
	tree = key->trees;
	for (layer = 0; layer < layers; layer++) {
		xmss_adrs_set_layer_address(adrs, (uint32_t)layer);
		xmss_adrs_set_tree_address(adrs, xmssmt_cl_tree_address(0, height, layers, layer));
		if (xmss_cl_build_tree(ctx, key->secret, key->public_key.seed, adrs, subtree_height, tree) != 1) {
			xmssmt_key_cleanup(key);
			error_print();
			return -1;
		}
		xmss_root = tree + xmss_cl_tree_root_offset(subtree_height);
		tree += xmss_num_tree_nodes(subtree_height);

		if (layer < layers - 1) {
			xmss_adrs_set_layer_address(adrs, (uint32_t)(layer + 1));
			xmss_adrs_set_tree_address(adrs, xmssmt_cl_tree_address(0, height, layers, layer + 1));
			xmss_adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
			xmss_adrs_set_ots_address(adrs, (uint32_t)xmssmt_cl_tree_index(0, height, layers, layer + 1));
			xmss_wots_derive_sk(key->secret, key->public_key.seed, adrs, key->wots_sigs[layer]);
			xmss_wots_sign(key->wots_sigs[layer], key->public_key.seed, adrs, *xmss_root, key->wots_sigs[layer]);
		}
	}

	if (!xmss_root) {
		xmssmt_key_cleanup(key);
		error_print();
		return -1;
	}
	memcpy(key->public_key.root, *xmss_root, sizeof(xmss_sm3_digest_t));
	return 1;
}

int xmssmt_cl_key_generate(XMSS_CL_CTX *ctx, XMSSMT_KEY *key, uint32_t xmssmt_type)
{
	int ret = -1;
	xmss_sm3_digest_t seed;
	xmss_sm3_digest_t secret;
	xmss_sm3_digest_t sk_prf;

	if (rand_bytes(seed, sizeof(seed)) != 1
		|| rand_bytes(secret, sizeof(secret)) != 1
		|| rand_bytes(sk_prf, sizeof(sk_prf)) != 1) {
		error_print();
		goto end;
	}
	if (xmssmt_cl_key_generate_ex(ctx, key, xmssmt_type, seed, secret, sk_prf) != 1) {
		error_print();
		goto end;
	}
	ret = 1;

end:
	gmssl_secure_clear(seed, sizeof(seed));
	gmssl_secure_clear(secret, sizeof(secret));
	gmssl_secure_clear(sk_prf, sizeof(sk_prf));
	return ret;
}

int xmssmt_cl_key_update(XMSS_CL_CTX *ctx, XMSSMT_KEY *key)
{
	size_t height;
	size_t layers;
	size_t layer;
	size_t subtree_height;
	xmss_sm3_digest_t *tree;
	uint64_t next_index;
	xmss_adrs_t adrs;
	xmss_sm3_digest_t *xmss_root;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	if (key->index >= ((uint64_t)1 << height)) {
		if (key->index == ((uint64_t)1 << height)) {
			return 0;
		}
		error_print();
		return -1;
	}

	next_index = key->index + 1;
	subtree_height = height/layers;
	tree = key->trees;

	for (layer = 0; layer < layers - 1; layer++) {
		if (xmssmt_cl_tree_address(next_index, height, layers, layer) ==
			xmssmt_cl_tree_address(key->index, height, layers, layer)) {
			break;
		}

		xmss_adrs_set_layer_address(adrs, (uint32_t)layer);
		xmss_adrs_set_tree_address(adrs, xmssmt_cl_tree_address(next_index, height, layers, layer));
		if (xmss_cl_build_tree(ctx, key->secret, key->public_key.seed, adrs, subtree_height, tree) != 1) {
			error_print();
			return -1;
		}

		xmss_adrs_set_layer_address(adrs, (uint32_t)(layer + 1));
		xmss_adrs_set_tree_address(adrs, xmssmt_cl_tree_address(next_index, height, layers, layer + 1));
		xmss_adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
		xmss_adrs_set_ots_address(adrs, (uint32_t)xmssmt_cl_tree_index(next_index, height, layers, layer + 1));
		xmss_wots_derive_sk(key->secret, key->public_key.seed, adrs, key->wots_sigs[layer]);
		xmss_root = tree + xmss_cl_tree_root_offset(subtree_height);
		xmss_wots_sign(key->wots_sigs[layer], key->public_key.seed, adrs, *xmss_root, key->wots_sigs[layer]);
		tree += xmss_num_tree_nodes(subtree_height);
	}

	key->index++;
	if (key->update_callback) {
		if (key->update_callback(key) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int xmssmt_cl_sign_init(XMSS_CL_CTX *cl_ctx, XMSSMT_SIGN_CTX *sign_ctx, XMSSMT_KEY *key)
{
	size_t height;
	size_t layers;
	size_t layer;
	uint64_t tree_address;
	uint32_t tree_index;
	xmss_sm3_digest_t sm3_digest_index;
	xmss_adrs_t adrs;

	if (!cl_ctx || !sign_ctx || !key) {
		error_print();
		return -1;
	}
	if (xmssmt_type_to_height_and_layers(key->public_key.xmssmt_type, &height, &layers) != 1) {
		error_print();
		return -1;
	}
	if (key->index >= ((uint64_t)1 << height)) {
		error_print();
		return -1;
	}

	memset(sign_ctx, 0, sizeof(*sign_ctx));
	sign_ctx->xmssmt_public_key = key->public_key;
	sign_ctx->xmssmt_sig.index = key->index;

	for (layer = 1; layer < layers; layer++) {
		memcpy(sign_ctx->xmssmt_sig.wots_sigs[layer], key->wots_sigs[layer - 1], sizeof(xmss_wots_sig_t));
	}

	for (layer = 0; layer < layers; layer++) {
		xmss_sm3_digest_t *tree = key->trees + xmss_num_tree_nodes(height/layers) * layer;
		xmss_sm3_digest_t *auth_path = sign_ctx->xmssmt_sig.auth_path + (height/layers) * layer;
		tree_index = (uint32_t)xmssmt_cl_tree_index(sign_ctx->xmssmt_sig.index, height, layers, layer);
		xmss_build_auth_path(tree, height/layers, tree_index, auth_path);
	}

	memset(sm3_digest_index, 0, 24);
	PUTU64(sm3_digest_index + 24, sign_ctx->xmssmt_sig.index);
	sm3_init(&sign_ctx->sm3_ctx);
	sm3_update(&sign_ctx->sm3_ctx, xmss_cl_sm3_digest_three, sizeof(xmss_sm3_digest_t));
	sm3_update(&sign_ctx->sm3_ctx, key->sk_prf, sizeof(xmss_sm3_digest_t));
	sm3_update(&sign_ctx->sm3_ctx, sm3_digest_index, sizeof(xmss_sm3_digest_t));
	sm3_finish(&sign_ctx->sm3_ctx, sign_ctx->xmssmt_sig.random);

	layer = 0;
	tree_address = xmssmt_cl_tree_address(sign_ctx->xmssmt_sig.index, height, layers, layer);
	tree_index = (uint32_t)xmssmt_cl_tree_index(sign_ctx->xmssmt_sig.index, height, layers, layer);
	xmss_adrs_set_layer_address(adrs, (uint32_t)layer);
	xmss_adrs_set_tree_address(adrs, tree_address);
	xmss_adrs_set_type(adrs, XMSS_ADRS_TYPE_OTS);
	xmss_adrs_set_ots_address(adrs, tree_index);
	xmss_wots_derive_sk(key->secret, key->public_key.seed, adrs, sign_ctx->xmssmt_sig.wots_sigs[0]);

	sm3_init(&sign_ctx->sm3_ctx);
	sm3_update(&sign_ctx->sm3_ctx, xmss_cl_sm3_digest_two, sizeof(xmss_sm3_digest_t));
	sm3_update(&sign_ctx->sm3_ctx, sign_ctx->xmssmt_sig.random, sizeof(xmss_sm3_digest_t));
	sm3_update(&sign_ctx->sm3_ctx, key->public_key.root, sizeof(xmss_sm3_digest_t));
	sm3_update(&sign_ctx->sm3_ctx, sm3_digest_index, sizeof(xmss_sm3_digest_t));

	if (xmssmt_cl_key_update(cl_ctx, key) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static const char *xmss_cl_src = KERNEL(

void sm3_hash_parts_3(__private const uchar a[32], __private const uchar b[32],
	__private const uchar c[32], __private uchar out[32])
{
	uint dgst[8];
	uchar block[64];
	uint num = 0;
	ulong nblocks = 0;
	uint i;
	sm3_init_state(dgst);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, a[i]);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, b[i]);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, c[i]);
	sm3_finish_ctx(dgst, block, num, nblocks, out);
}

void sm3_hash_parts_4(__private const uchar a[32], __private const uchar b[32],
	__private const uchar c[32], __private const uchar d[32], __private uchar out[32])
{
	uint dgst[8];
	uchar block[64];
	uint num = 0;
	ulong nblocks = 0;
	uint i;
	sm3_init_state(dgst);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, a[i]);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, b[i]);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, c[i]);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, d[i]);
	sm3_finish_ctx(dgst, block, num, nblocks, out);
}

void sm3_hash_domain_secret_seed_adrs(__global const uchar *secret, __global const uchar *seed,
	__private const uchar adrs[32], __private uchar out[32])
{
	uint dgst[8];
	uchar block[64];
	uint num = 0;
	ulong nblocks = 0;
	uint i;

	sm3_init_state(dgst);
	for (i = 0; i < 31; i++) sm3_update_byte(dgst, block, &num, &nblocks, 0);
	sm3_update_byte(dgst, block, &num, &nblocks, 4);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, secret[i]);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, seed[i]);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, adrs[i]);
	sm3_finish_ctx(dgst, block, num, nblocks, out);
}

void sm3_prf_seed_adrs(__global const uchar *seed, __private const uchar adrs[32],
	__private uchar out[32])
{
	uint dgst[8];
	uchar block[64];
	uint num = 0;
	ulong nblocks = 0;
	uint i;

	sm3_init_state(dgst);
	for (i = 0; i < 31; i++) sm3_update_byte(dgst, block, &num, &nblocks, 0);
	sm3_update_byte(dgst, block, &num, &nblocks, 3);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, seed[i]);
	for (i = 0; i < 32; i++) sm3_update_byte(dgst, block, &num, &nblocks, adrs[i]);
	sm3_finish_ctx(dgst, block, num, nblocks, out);
}

void xmss_wots_chain_cl(__private uchar y[32], __global const uchar *seed,
	__private uchar adrs[32], uint start, uint steps)
{
	uchar key[32];
	uchar bitmask[32];
	uchar domain0[32];
	uint i, k;
	for (k = 0; k < 32; k++) domain0[k] = 0;
	for (i = 0; i < steps; i++) {
		set_be32(adrs + 24, start + i);
		set_be32(adrs + 28, 0);
		sm3_prf_seed_adrs(seed, adrs, key);
		set_be32(adrs + 28, 1);
		sm3_prf_seed_adrs(seed, adrs, bitmask);
		for (k = 0; k < 32; k++) y[k] ^= bitmask[k];
		sm3_hash_parts_3(domain0, key, y, y);
	}
}

void xmss_tree_hash_cl(__private const uchar left[32], __private const uchar right[32],
	__global const uchar *seed, __private uchar adrs[32], __private uchar parent[32])
{
	uchar key[32];
	uchar bm0[32];
	uchar bm1[32];
	uchar domain1[32];
	uint i;

	for (i = 0; i < 31; i++) domain1[i] = 0;
	domain1[31] = 1;
	set_be32(adrs + 28, 0);
	sm3_prf_seed_adrs(seed, adrs, key);
	set_be32(adrs + 28, 1);
	sm3_prf_seed_adrs(seed, adrs, bm0);
	set_be32(adrs + 28, 2);
	sm3_prf_seed_adrs(seed, adrs, bm1);
	for (i = 0; i < 32; i++) {
		bm0[i] ^= left[i];
		bm1[i] ^= right[i];
	}
	sm3_hash_parts_4(domain1, key, bm0, bm1, parent);
}

void xmss_derive_leaf_cl(__global const uchar *secret, __global const uchar *seed,
	__global const uchar *base_adrs, uint q, __private uchar root[32])
{
	uchar pk[67][32];
	uchar adrs[32];
	uint chain;
	uint len = 67;
	uint h = 0;
	uint i;

	for (i = 0; i < 12; i++) adrs[i] = base_adrs[i];
	set_be32(adrs + 12, 0);
	set_be32(adrs + 16, q);
	set_be32(adrs + 20, 0);
	set_be32(adrs + 24, 0);
	set_be32(adrs + 28, 0);

	for (chain = 0; chain < 67; chain++) {
		set_be32(adrs + 20, chain);
		set_be32(adrs + 24, 0);
		set_be32(adrs + 28, 0);
		sm3_hash_domain_secret_seed_adrs(secret, seed, adrs, pk[chain]);
		xmss_wots_chain_cl(pk[chain], seed, adrs, 0, 15);
	}

	for (i = 0; i < 12; i++) adrs[i] = base_adrs[i];
	set_be32(adrs + 12, 1);
	set_be32(adrs + 16, q);
	set_be32(adrs + 20, h++);
	set_be32(adrs + 24, 0);
	set_be32(adrs + 28, 0);

	while (len > 1) {
		for (i = 0; i < len/2; i++) {
			set_be32(adrs + 24, i);
			xmss_tree_hash_cl(pk[2*i], pk[2*i + 1], seed, adrs, pk[i]);
		}
		if (len & 1) {
			copy32(pk[len/2], pk[len - 1]);
		}
		len = (len + 1)/2;
		set_be32(adrs + 20, h++);
	}
	copy32(root, pk[0]);
}

__kernel void xmss_leafs(__global const uchar *secret, __global const uchar *seed,
	__global const uchar *base_adrs, uint leaf_offset, uint leaf_count,
	uint height, __global uchar *tree)
{
	uint id = get_global_id(0);
	uint q;
	uchar leaf[32];
	uint i;

	if (id >= leaf_count) return;
	q = leaf_offset + id;
	xmss_derive_leaf_cl(secret, seed, base_adrs, q, leaf);
	for (i = 0; i < 32; i++) tree[q*32 + i] = leaf[i];
}

__kernel void xmss_internal_nodes(__global const uchar *seed, __global const uchar *base_adrs,
	uint children_offset, uint parents_offset, uint level_nodes, uint level_height,
	__global uchar *tree)
{
	uint id = get_global_id(0);
	uchar adrs[32];
	uchar left[32];
	uchar right[32];
	uchar parent[32];
	uint i;

	if (id >= level_nodes) return;
	for (i = 0; i < 12; i++) adrs[i] = base_adrs[i];
	set_be32(adrs + 12, 2);
	set_be32(adrs + 16, 0);
	set_be32(adrs + 20, level_height);
	set_be32(adrs + 24, id);
	set_be32(adrs + 28, 0);
	copy32_from_global(left, tree + (children_offset + 2*id)*32);
	copy32_from_global(right, tree + (children_offset + 2*id + 1)*32);
	xmss_tree_hash_cl(left, right, seed, adrs, parent);
	for (i = 0; i < 32; i++) tree[(parents_offset + id)*32 + i] = parent[i];
}

);
