/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_INTERNAL_CL_H
#define GMSSL_INTERNAL_CL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef MACOS
#include <OpenCL/OpenCL.h>
#else
#include <CL/cl.h>
#endif


const char *gmssl_cl_error_string(cl_int err);
void gmssl_cl_error_print(const char *file, int line, cl_int err);
size_t gmssl_cl_round_up(size_t a, size_t b);
int gmssl_cl_get_gpu_device(cl_platform_id *platform, cl_device_id *device);

const char *sm3_cl_source(void);

#define cl_error_print(e) \
	do { gmssl_cl_error_print(__FILE__, __LINE__, (e)); } while (0)

#define KERNEL(...) #__VA_ARGS__

#endif
