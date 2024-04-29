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
#include <stdint.h>
#include <gmssl/sm4_cl.h>
#include <gmssl/endian.h>
#include <gmssl/error.h>


static char *clErrorString(cl_uint err)
{
	switch (err) {
        case CL_SUCCESS:			return "CL_SUCCESS!";
        case CL_DEVICE_NOT_FOUND:		return "CL_DEVICE_NOT_FOUND";
        case CL_DEVICE_NOT_AVAILABLE:		return "CL_DEVICE_NOT_AVAILABLE";
        case CL_COMPILER_NOT_AVAILABLE:		return "CL_COMPILER_NOT_AVAILABLE";
        case CL_MEM_OBJECT_ALLOCATION_FAILURE:	return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
        case CL_OUT_OF_RESOURCES:		return "CL_OUT_OF_RESOURCES";
        case CL_OUT_OF_HOST_MEMORY:		return "CL_OUT_OF_HOST_MEMORY";
        case CL_PROFILING_INFO_NOT_AVAILABLE:	return "CL_PROFILING_INFO_NOT_AVAILABLE";
        case CL_MEM_COPY_OVERLAP:		return "CL_MEM_COPY_OVERLAP";
        case CL_IMAGE_FORMAT_MISMATCH:		return "CL_IMAGE_FORMAT_MISMATCH";
        case CL_IMAGE_FORMAT_NOT_SUPPORTED:	return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
        case CL_BUILD_PROGRAM_FAILURE:		return "CL_BUILD_PROGRAM_FAILURE";
        case CL_MAP_FAILURE:			return "CL_MAP_FAILURE";
        case CL_INVALID_VALUE:			return "CL_INVALID_VALUE";
        case CL_INVALID_DEVICE_TYPE:		return "CL_INVALID_DEVICE_TYPE";
        case CL_INVALID_PLATFORM:		return "CL_INVALID_PLATFORM";
        case CL_INVALID_DEVICE:			return "CL_INVALID_DEVICE";
        case CL_INVALID_CONTEXT:		return "CL_INVALID_CONTEXT";
        case CL_INVALID_QUEUE_PROPERTIES:	return "CL_INVALID_QUEUE_PROPERTIES";
        case CL_INVALID_COMMAND_QUEUE:		return "CL_INVALID_COMMAND_QUEUE";
        case CL_INVALID_HOST_PTR:		return "CL_INVALID_HOST_PTR";
        case CL_INVALID_MEM_OBJECT:		return "CL_INVALID_MEM_OBJECT";
        case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR:return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
        case CL_INVALID_IMAGE_SIZE:		return "CL_INVALID_IMAGE_SIZE";
        case CL_INVALID_SAMPLER:		return "CL_INVALID_SAMPLER";
        case CL_INVALID_BINARY:			return "CL_INVALID_BINARY";
        case CL_INVALID_BUILD_OPTIONS:		return "CL_INVALID_BUILD_OPTIONS";
        case CL_INVALID_PROGRAM:		return "CL_INVALID_PROGRAM";
        case CL_INVALID_PROGRAM_EXECUTABLE:	return "CL_INVALID_PROGRAM_EXECUTABLE";
        case CL_INVALID_KERNEL_NAME:		return "CL_INVALID_KERNEL_NAME";
        case CL_INVALID_KERNEL_DEFINITION:	return "CL_INVALID_KERNEL_DEFINITION";
        case CL_INVALID_KERNEL:			return "CL_INVALID_KERNEL";
        case CL_INVALID_ARG_INDEX:		return "CL_INVALID_ARG_INDEX";
        case CL_INVALID_ARG_VALUE:		return "CL_INVALID_ARG_VALUE";
        case CL_INVALID_ARG_SIZE:		return "CL_INVALID_ARG_SIZE";
        case CL_INVALID_KERNEL_ARGS:		return "CL_INVALID_KERNEL_ARGS";
        case CL_INVALID_WORK_DIMENSION:		return "CL_INVALID_WORK_DIMENSION";
        case CL_INVALID_WORK_GROUP_SIZE:	return "CL_INVALID_WORK_GROUP_SIZE";
        case CL_INVALID_WORK_ITEM_SIZE:		return "CL_INVALID_WORK_ITEM_SIZE";
        case CL_INVALID_GLOBAL_OFFSET:		return "CL_INVALID_GLOBAL_OFFSET";
        case CL_INVALID_EVENT_WAIT_LIST:	return "CL_INVALID_EVENT_WAIT_LIST";
        case CL_INVALID_EVENT:			return "CL_INVALID_EVENT";
        case CL_INVALID_OPERATION:		return "CL_INVALID_OPERATION";
        case CL_INVALID_GL_OBJECT:		return "CL_INVALID_GL_OBJECT";
        case CL_INVALID_BUFFER_SIZE:		return "CL_INVALID_BUFFER_SIZE";
        case CL_INVALID_MIP_LEVEL:		return "CL_INVALID_MIP_LEVEL";
	}
	return NULL;
}

static const char *sm4_cl_src;


#define cl_error_print(e) \
	do { fprintf(stderr, "%s: %d: %s()\n",__FILE__,__LINE__,clErrorString(e)); } while (0)


void sm4_cl_cleanup(SM4_CL_CTX *ctx)
{
	clReleaseContext(ctx->context);
	clReleaseCommandQueue(ctx->queue);
	clReleaseProgram(ctx->program);
	clReleaseKernel(ctx->kernel);
}

static void clPrintDeviceInfo(cl_device_id device)
{
	char deviceName[128];
	char vendorName[128];
	char deviceVersion[128];
	char driverVersion[128];
	char deviceProfile[128];
	cl_device_type deviceType;
	cl_uint vendorID;
	cl_ulong globalMemSize;
	cl_ulong localMemSize;
	size_t maxWorkGroupSize;
	cl_uint maxWorkItemDimensions;
	size_t maxWorkItemSizes[3];
	cl_uint maxComputeUnits;
	char openclCVersion[128];
	char extensions[4096];

	clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(deviceName), deviceName, NULL);
	clGetDeviceInfo(device, CL_DEVICE_VENDOR, sizeof(vendorName), vendorName, NULL);
	clGetDeviceInfo(device, CL_DEVICE_VERSION, sizeof(deviceVersion), deviceVersion, NULL);
	clGetDeviceInfo(device, CL_DRIVER_VERSION, sizeof(driverVersion), driverVersion, NULL);
	clGetDeviceInfo(device, CL_DEVICE_PROFILE, sizeof(deviceProfile), deviceProfile, NULL);
	clGetDeviceInfo(device, CL_DEVICE_TYPE, sizeof(deviceType), &deviceType, NULL);
	clGetDeviceInfo(device, CL_DEVICE_VENDOR_ID, sizeof(vendorID), &vendorID, NULL);
	clGetDeviceInfo(device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(globalMemSize), &globalMemSize, NULL);
	clGetDeviceInfo(device, CL_DEVICE_LOCAL_MEM_SIZE, sizeof(localMemSize), &localMemSize, NULL);
	clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(maxWorkGroupSize), &maxWorkGroupSize, NULL);
	clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS, sizeof(maxWorkItemDimensions), &maxWorkItemDimensions, NULL);
	clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_ITEM_SIZES, sizeof(maxWorkItemSizes), maxWorkItemSizes, NULL);
	clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(maxComputeUnits), &maxComputeUnits, NULL);
	clGetDeviceInfo(device, CL_DEVICE_OPENCL_C_VERSION, sizeof(openclCVersion), openclCVersion, NULL);
	clGetDeviceInfo(device, CL_DEVICE_EXTENSIONS, sizeof(extensions), extensions, NULL);

	printf("clGetDeviceInfo\n");
	printf("  Device Name: %s\n", deviceName);
	printf("  Vendor: %s\n", vendorName);
	printf("  Device Version: %s\n", deviceVersion);
	printf("  Driver Version: %s\n", driverVersion);
	printf("  Device Profile: %s\n", deviceProfile);
	printf("  Device Type: %s\n",
		(deviceType == CL_DEVICE_TYPE_CPU) ? "CPU" :
		(deviceType == CL_DEVICE_TYPE_GPU) ? "GPU" :
		(deviceType == CL_DEVICE_TYPE_ACCELERATOR) ? "Accelerator" :
		(deviceType == CL_DEVICE_TYPE_DEFAULT) ? "Default" : "Unknown");
	printf("  Vendor ID: %u\n", vendorID);
	printf("  Global Memory Size: %llu bytes\n", globalMemSize);
	printf("  Local Memory Size: %llu bytes\n", localMemSize);
	printf("  Max Work Group Size: %zu\n", maxWorkGroupSize);
	printf("  Max Work Item Dimensions: %u\n", maxWorkItemDimensions);
	printf("  Max Work Item Sizes: (%zu, %zu, %zu)\n", maxWorkItemSizes[0], maxWorkItemSizes[1], maxWorkItemSizes[2]);
	printf("  Max Compute Units: %u\n", maxComputeUnits);
	printf("  OpenCL C Version: %s\n", openclCVersion);
	printf("  Extensions: %s\n", extensions);
}

static int sm4_cl_set_key(SM4_CL_CTX *ctx, const uint8_t key[16], int enc)
{
	cl_platform_id platform;
	cl_device_id device;
	cl_uint device_cnt;
	cl_int err;
	char sval[256];
	size_t slen;
	cl_command_queue_properties queue_prop = 0;
	const char *build_opts = NULL;

	memset(ctx, 0, sizeof(*ctx));

	if ((err = clGetPlatformIDs(1, &platform, NULL)) != CL_SUCCESS) {
		cl_error_print(err);
		return -1;
	}
	if ((err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, &device_cnt)) != CL_SUCCESS) {
		cl_error_print(err);
		return -1;
	}
	//clPrintDeviceInfo(device);

	if (!(ctx->context = clCreateContext(NULL, 1, &device, NULL, NULL, &err))) {
		cl_error_print(err);
		return -1;
	}
	if (!(ctx->queue = clCreateCommandQueue(ctx->context, device, queue_prop, &err))) {
		cl_error_print(err);
		goto end;
	}
	if (!(ctx->program = clCreateProgramWithSource(ctx->context, 1, (const char **)&sm4_cl_src, NULL, &err))) {
		cl_error_print(err);
		goto end;
	}
	if ((err = clBuildProgram(ctx->program, 1, &device, build_opts, NULL, NULL)) != CL_SUCCESS) {
		char *log = NULL;
		size_t loglen;

		cl_error_print(err);

		if ((err = clGetProgramBuildInfo(ctx->program, device, CL_PROGRAM_BUILD_LOG, sizeof(log), NULL, &loglen)) != CL_SUCCESS) {
			cl_error_print(err);
			goto end;
		}
		if (!(log = (char *)malloc(loglen))) {
			goto end;
		}
		if ((err = clGetProgramBuildInfo(ctx->program, device, CL_PROGRAM_BUILD_LOG, sizeof(log), NULL, &loglen)) != CL_SUCCESS) {
			cl_error_print(err);
			free(log);
			goto end;
		}
		fprintf(stderr, "%s %d: %s\n", __FILE__, __LINE__, log);
		free(log);
		goto end;
	}
	if (!(ctx->kernel = clCreateKernel(ctx->program, "sm4_ctr32_encrypt_blocks", &err))) {
		cl_error_print(err);
		goto end;
	}
	/*
	// Apple M2 the CL_KERNEL_WORK_GROUP_SIZE is 256, but the valid work_group_size is 32
	if ((err = clGetKernelWorkGroupInfo(ctx->kernel, device, CL_KERNEL_WORK_GROUP_SIZE,
		sizeof(ctx->workgroup_size), &ctx->workgroup_size, NULL)) != CL_SUCCESS) {
		cl_error_print(err);
		goto end;
	}
	*/

	if (enc) {
		sm4_set_encrypt_key((SM4_KEY *)ctx->rk, key);
	} else {
		sm4_set_decrypt_key((SM4_KEY *)ctx->rk, key);
	}

	if (!(ctx->mem_rk = clCreateBuffer(ctx->context, CL_MEM_READ_WRITE|CL_MEM_USE_HOST_PTR, sizeof(SM4_KEY), ctx->rk, &err))) {
		cl_error_print(err);
		goto end;
	}
	if ((err = clSetKernelArg(ctx->kernel, 0, sizeof(cl_mem), &ctx->mem_rk)) != CL_SUCCESS) {
		cl_error_print(err);
		goto end;
	}

	return 1;


end:
	return -1;
}

int sm4_cl_set_encrypt_key(SM4_CL_CTX *ctx, const uint8_t key[16])
{
	return sm4_cl_set_key(ctx, key, 1);
}

int sm4_cl_set_decrypt_key(SM4_CL_CTX *ctx, const uint8_t key[16])
{
	return sm4_cl_set_key(ctx, key, 0);
}

int sm4_cl_ctr32_encrypt_blocks(SM4_CL_CTX *ctx, uint8_t iv[16], const uint8_t *in, size_t nblocks, uint8_t *out)
{
	int ret = -1;
	cl_int err;
	uint32_t ctr[4];
	cl_mem mem_ctr = NULL;
	size_t inlen = SM4_BLOCK_SIZE * nblocks;
	cl_mem mem_buf = NULL;
	cl_uint dim = 1;
	size_t global_work_size = nblocks;
	size_t local_work_size = 32;

	if (global_work_size % local_work_size) {
		error_print();
		return -1;
	}

	ctr[0] = GETU32(iv);
	ctr[1] = GETU32(iv + 4);
	ctr[2] = GETU32(iv + 8);
	ctr[3] = GETU32(iv + 12);

	if (!(mem_ctr = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(ctr), ctr, &err))) {
		cl_error_print(err);
		return -1;
	}
	if ((err = clSetKernelArg(ctx->kernel, 1, sizeof(cl_mem), &mem_ctr)) != CL_SUCCESS) {
		cl_error_print(err);
		goto end;
	}

	if (out != in) {
		memcpy(out, in, inlen);
	}
	if (!(mem_buf = clCreateBuffer(ctx->context, CL_MEM_READ_WRITE|CL_MEM_USE_HOST_PTR, inlen, out, &err))) {
		cl_error_print(err);
		return -1;
	}
	if ((err = clSetKernelArg(ctx->kernel, 2, sizeof(cl_mem), &mem_buf)) != CL_SUCCESS) {
		cl_error_print(err);
		goto end;
	}

	// on Apple M2, CL_KERNEL_WORK_GROUP_SIZE = 256
	// but kernel will fail when local_work_size > 32.
	// local_work_size might be restricted by the resources the kernel used.
	if ((err = clEnqueueNDRangeKernel(ctx->queue, ctx->kernel,
		dim, NULL, &global_work_size, &local_work_size, 0, NULL, NULL)) != CL_SUCCESS) {
		cl_error_print(err);
		goto end;
	}
	if (!clEnqueueMapBuffer(ctx->queue, mem_buf, CL_TRUE, 0, 0, inlen, 0, NULL, NULL, &err)) {
		cl_error_print(err);
		goto end;
	}

	ctr[3] += (uint32_t)nblocks;
	PUTU32(iv + 12, ctr[3]);
	ret = 1;
end:
	if (mem_ctr) clReleaseMemObject(mem_ctr);
	if (mem_buf) clReleaseMemObject(mem_buf);
	return ret;
}

#define KERNEL(...) #__VA_ARGS__
static const char *sm4_cl_src = KERNEL(

__constant unsigned char SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

__kernel void sm4_ctr32_encrypt_blocks(__global const unsigned int *rkey, __global const unsigned int *ctr, __global unsigned char *data)
{
	unsigned int x0, x1, x2, x3, x4, i, t;
	uint global_id = get_global_id(0);
	__global unsigned int *out = (__global unsigned int *)(data + 16 * global_id);

#if 0
	// use local mem is little slower on Apple M2
	__local unsigned char S[256];
	__local unsigned int rk[32];

	if (get_local_id(0) == 0) {
		for (i = 0; i < 256; i++) {
			S[i] = SBOX[i];
		}
		for (i = 0; i < 32; i++) {
			rk[i] = rkey[i];
		}
	}
#else
	__constant unsigned char *S = SBOX;
	__global const unsigned int *rk = rkey;
#endif

	x0 = ctr[0];
	x1 = ctr[1];
	x2 = ctr[2];
	x3 = ctr[3] + global_id;

	for (i = 0; i < 31; i++) {
		x4 = x1 ^ x2 ^ x3 ^ rk[i];
		x4 = (S[x4 >> 24] << 24) ^ (S[(x4 >> 16) & 0xff] << 16) ^ (S[(x4 >> 8) & 0xff] <<  8) ^ S[x4 & 0xff];

		x4 = x0 ^ (x4 ^
			((x4 <<  2) | (x4 >> (32 -  2))) ^
			((x4 << 10) | (x4 >> (32 - 10))) ^
			((x4 << 18) | (x4 >> (32 - 18))) ^
			((x4 << 24) | (x4 >> (32 - 24))));

		t = x0;
		x0 = x1;
		x1 = x2;
		x2 = x3;
		x3 = x4;
		x4 = t;
	}
	x4 = x1 ^ x2 ^ x3 ^ rk[i];
	x4 = (S[x4 >> 24] << 24) ^ (S[(x4 >> 16) & 0xff] << 16) ^ (S[(x4 >> 8) & 0xff] <<  8) ^ S[x4 & 0xff];

	x4 = x0 ^ (x4 ^
		((x4 <<  2) | (x4 >> (32 -  2))) ^
		((x4 << 10) | (x4 >> (32 - 10))) ^
		((x4 << 18) | (x4 >> (32 - 18))) ^
		((x4 << 24) | (x4 >> (32 - 24))));

	out[0] ^= (x4 >> 24) | ((x4 >> 8) & 0xff00) | ((x4 << 8) & 0xff0000) | (x4 << 24);
	out[1] ^= (x3 >> 24) | ((x3 >> 8) & 0xff00) | ((x3 << 8) & 0xff0000) | (x3 << 24);
	out[2] ^= (x2 >> 24) | ((x2 >> 8) & 0xff00) | ((x2 << 8) & 0xff0000) | (x2 << 24);
	out[3] ^= (x1 >> 24) | ((x1 >> 8) & 0xff00) | ((x1 << 8) & 0xff0000) | (x1 << 24);
}

);

