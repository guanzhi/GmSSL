/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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


typedef struct {
	void *handle;
	char issuer[41];
	char name[17];
	char serial[17];
} SDF_DEVICE;

typedef struct {
	SM2_Z256_POINT public_key;
	void *session;
	int index;
} SDF_SIGN_KEY;

typedef struct {
	SM3_CTX sm3_ctx;
	SM3_CTX saved_sm3_ctx;
	SDF_SIGN_KEY key;
} SDF_SIGN_CTX;

/*
typedef struct {
	void *hSession;
} SDF_SM3_CTX;

typedef struct {
	void *hSession;
	void *hKey;
} SDF_SM4_KEY;

typedef struct {
	uint32_t index;
	uint8_t passlen;
	unsigned char pass[26 + 1];
} SDF_ENC_PRIVATE_KEY;

typedef struct {
	uint32_t index;
	uint8_t passlen;
	unsigned char pass[26 + 1];
} SDF_PRIVATE_KEY;
*/


int sdf_load_library(const char *so_path, const char *vendor);
int sdf_open_device(SDF_DEVICE *dev);
int sdf_print_device_info(FILE *fp, int fmt, int ind, const char *lable, SDF_DEVICE *dev);
int sdf_export_sign_public_key(SDF_DEVICE *dev, int key_index, SM2_KEY *public_key);
int sdf_load_sign_key(SDF_DEVICE *dev, SDF_SIGN_KEY *key, int key_index, const char *pass);
int sdf_sign(SDF_SIGN_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int sdf_sign_init(SDF_SIGN_CTX *ctx, const SDF_SIGN_KEY *key, const char *id, size_t idlen);
int sdf_sign_update(SDF_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sdf_sign_finish(SDF_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sdf_sign_reset(SDF_SIGN_CTX *ctx);
int sdf_release_sign_key(SDF_SIGN_KEY *key);
int sdf_close_device(SDF_DEVICE *dev);
void sdf_unload_library(void);


#ifdef __cplusplus
}
#endif
#endif
