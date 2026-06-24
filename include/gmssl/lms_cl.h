/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_LMS_CL_H
#define GMSSL_LMS_CL_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/lms.h>
#ifdef MACOS
#include <OpenCL/OpenCL.h>
#else
#include <CL/cl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	cl_context context;
	cl_command_queue queue;
	cl_program program;
	cl_kernel leafs_tree_kernel;
	cl_kernel leafs_compact_kernel;
	cl_kernel internal_nodes_kernel;
	size_t local_work_size;
	size_t max_leaf_batch;
} LMS_CL_CTX;


int lms_cl_init(LMS_CL_CTX *ctx);
void lms_cl_cleanup(LMS_CL_CTX *ctx);

int lms_cl_derive_merkle_tree(LMS_CL_CTX *ctx,
	const lms_sm3_digest_t seed, const uint8_t I[16], int height, lms_sm3_digest_t *tree);
int lms_cl_derive_merkle_root(LMS_CL_CTX *ctx,
	const lms_sm3_digest_t seed, const uint8_t I[16], int height, lms_sm3_digest_t root);

int lms_cl_key_generate_ex(LMS_CL_CTX *ctx, LMS_KEY *key, int lms_type,
	const lms_sm3_digest_t seed, const uint8_t I[16], int cache_tree);
int lms_cl_key_generate(LMS_CL_CTX *ctx, LMS_KEY *key, int lms_type);
int lms_cl_private_key_from_bytes(LMS_CL_CTX *ctx, LMS_KEY *key, const uint8_t **in, size_t *inlen);

int hss_cl_key_generate(LMS_CL_CTX *ctx, HSS_KEY *key, const int *lms_types, size_t levels);
int hss_cl_private_key_from_bytes(LMS_CL_CTX *ctx, HSS_KEY *key, const uint8_t **in, size_t *inlen);
int hss_cl_key_update(LMS_CL_CTX *ctx, HSS_KEY *key);
int hss_cl_sign_init(LMS_CL_CTX *ctx, HSS_SIGN_CTX *sign_ctx, HSS_KEY *key);


#ifdef __cplusplus
}
#endif
#endif
