/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/sm4.h>


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
	void *session;
} SDF_DIGEST_CTX;

typedef struct {
	void *session;
	void *handle;
} SDF_KEY;

typedef struct {
	SDF_KEY key;
	uint8_t iv[SM4_BLOCK_SIZE];
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
} SDF_CBC_CTX;

typedef struct {
	void *session;
	int index;
} SDF_PRIVATE_KEY;

typedef struct {
	SM3_CTX sm3_ctx;
	SM3_CTX saved_sm3_ctx;
	SDF_PRIVATE_KEY key;
} SDF_SIGN_CTX;


int sdf_load_library(const char *so_path, const char *vendor);
int sdf_open_device(SDF_DEVICE *dev);
int sdf_print_device_info(FILE *fp, int fmt, int ind, const char *lable, SDF_DEVICE *dev);
int sdf_digest_init(SDF_DIGEST_CTX *ctx, SDF_DEVICE *dev);
int sdf_digest_update(SDF_DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
int sdf_digest_finish(SDF_DIGEST_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE]);
int sdf_digest_reset(SDF_DIGEST_CTX *ctx);
int sdf_digest_cleanup(SDF_DIGEST_CTX *ctx);
int sdf_generate_key(SDF_DEVICE *dev, SDF_KEY *key, const SM2_KEY *sm2_key, uint8_t *wrappedkey, size_t *wrappedkey_len);
int sdf_import_key(SDF_DEVICE *dev, unsigned int key_index, const char *pass, const uint8_t *wrappedkey, size_t wrappedkey_len, SDF_KEY *key); // XXX: Is `pass` needed? see impl in sdf.c
int sdf_cbc_encrypt_init(SDF_CBC_CTX *ctx, const SDF_KEY *key, const uint8_t iv[16]);
int sdf_cbc_encrypt_update(SDF_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sdf_cbc_encrypt_finish(SDF_CBC_CTX *ctx, uint8_t *out, size_t *outlen);
int sdf_cbc_decrypt_init(SDF_CBC_CTX *ctx, const SDF_KEY *key, const uint8_t iv[16]);
int sdf_cbc_decrypt_update(SDF_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sdf_cbc_decrypt_finish(SDF_CBC_CTX *ctx, uint8_t *out, size_t *outlen);
int sdf_destroy_key(SDF_KEY *key);
int sdf_export_sign_public_key(SDF_DEVICE *dev, int key_index, SM2_KEY *public_key);
int sdf_export_encrypt_public_key(SDF_DEVICE *dev, int key_index, SM2_KEY *public_key);
int sdf_load_private_key(SDF_DEVICE *dev, SDF_PRIVATE_KEY *key, int key_index, const char *pass);
int sdf_decrypt(const SDF_PRIVATE_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sdf_sign(const SDF_PRIVATE_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int sdf_sign_init(SDF_SIGN_CTX *ctx, const SDF_PRIVATE_KEY *key, const char *id, size_t idlen);
int sdf_sign_update(SDF_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sdf_sign_finish(SDF_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sdf_sign_reset(SDF_SIGN_CTX *ctx);
int sdf_release_private_key(SDF_PRIVATE_KEY *key);
int sdf_close_device(SDF_DEVICE *dev);
void sdf_unload_library(void);


#ifdef __cplusplus
}
#endif
#endif
