/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SDF_H
#define GMSSL_SDF_H

#include <string.h>
#include <stdint.h>
#include <gmssl/sm2.h>


#ifdef __cplusplus
extern "C" {
#endif

/*
SDF Public API

	sdf_load_library
	sdf_unload_library

	SDF_DEVICE
	sdf_open_device
	sdf_close_device
	sdf_print_device_info
	sdf_rand_bytes
	sdf_load_sign_key

	SDF_KEY
	sdf_sign
	sdf_release_key
*/

typedef struct {
	void *handle;
	char issuer[41];
	char name[17];
	char serial[17];
} SDF_DEVICE;

typedef struct {
	SM2_KEY public_key;
	void *session;
	int index;
} SDF_KEY;


int sdf_load_library(const char *so_path, const char *vendor);
int sdf_open_device(SDF_DEVICE *dev);
int sdf_print_device_info(FILE *fp, int fmt, int ind, const char *lable, SDF_DEVICE *dev);
int sdf_rand_bytes(SDF_DEVICE *dev, uint8_t *buf, size_t len);
int sdf_load_sign_key(SDF_DEVICE *dev, SDF_KEY *key, int index, const char *pass);
int sdf_sign(SDF_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int sdf_release_key(SDF_KEY *key);
int sdf_close_device(SDF_DEVICE *dev);
void sdf_unload_library(void);


#ifdef __cplusplus
}
#endif
#endif
