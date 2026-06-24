/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_XMSS_CL_H
#define GMSSL_XMSS_CL_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/xmss.h>
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
	cl_kernel leafs_kernel;
	cl_kernel internal_nodes_kernel;
	size_t local_work_size;
} XMSS_CL_CTX;


int xmss_cl_init(XMSS_CL_CTX *ctx);
void xmss_cl_cleanup(XMSS_CL_CTX *ctx);

int xmss_cl_build_tree(XMSS_CL_CTX *ctx,
	const xmss_sm3_digest_t secret, const xmss_sm3_digest_t seed,
	const xmss_adrs_t adrs, size_t height, xmss_sm3_digest_t *tree);

int xmss_cl_key_generate_ex(XMSS_CL_CTX *ctx, XMSS_KEY *key, uint32_t xmss_type,
	const xmss_sm3_digest_t seed, const xmss_sm3_digest_t secret,
	const xmss_sm3_digest_t sk_prf);
int xmss_cl_key_generate(XMSS_CL_CTX *ctx, XMSS_KEY *key, uint32_t xmss_type);
int xmss_cl_private_key_from_bytes(XMSS_CL_CTX *ctx, XMSS_KEY *key,
	const uint8_t **in, size_t *inlen);

int xmssmt_cl_key_generate_ex(XMSS_CL_CTX *ctx, XMSSMT_KEY *key, uint32_t xmssmt_type,
	const xmss_sm3_digest_t seed, const xmss_sm3_digest_t secret,
	const xmss_sm3_digest_t sk_prf);
int xmssmt_cl_key_generate(XMSS_CL_CTX *ctx, XMSSMT_KEY *key, uint32_t xmssmt_type);
int xmssmt_cl_key_update(XMSS_CL_CTX *ctx, XMSSMT_KEY *key);
int xmssmt_cl_sign_init(XMSS_CL_CTX *ctx, XMSSMT_SIGN_CTX *sign_ctx, XMSSMT_KEY *key);


#ifdef __cplusplus
}
#endif
#endif
