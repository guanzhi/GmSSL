/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM4_CL_H
#define GMSSL_SM4_CL_H


#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/sm4.h>


#ifdef APPLE
#include <OpenCL/OpenCL.h>
#else
#include <CL/cl.h>
#endif


typedef struct {
	uint32_t rk[32];
	cl_context context;
	cl_command_queue queue;
	cl_program program;
	cl_kernel kernel;
	cl_mem mem_rk;
	cl_mem mem_io;
	size_t workgroup_size;
} SM4_CL_CTX;


int sm4_cl_set_encrypt_key(SM4_CL_CTX *ctx, const uint8_t key[16]);
int sm4_cl_set_decrypt_key(SM4_CL_CTX *ctx, const uint8_t key[16]);
int sm4_cl_encrypt(SM4_CL_CTX *ctx, const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_cl_cleanup(SM4_CL_CTX *ctx);

int test_sm4_cl_encrypt(void);


#ifdef __cplusplus
}
#endif
#endif
