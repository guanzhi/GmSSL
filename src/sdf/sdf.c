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
#include <gmssl/sdf.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>
#include "sdf.h"
#include "sdf_ext.h"


static int SDF_ECCrefPublicKey_to_SM2_Z256_POINT(const ECCrefPublicKey *ref, SM2_Z256_POINT *z256_point)
{
	static const uint8_t zeros[ECCref_MAX_LEN - 32] = {0};
	SM2_POINT point;

	if (ref->bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(ref->x, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(ref->y, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	memcpy(point.x, ref->x + sizeof(zeros), 32);
	memcpy(point.y, ref->y + sizeof(zeros), 32);
	if (sm2_z256_point_from_bytes(z256_point, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}
	return SDR_OK;
}

static int SDF_ECCSignature_to_SM2_SIGNATURE(const ECCSignature *ref, SM2_SIGNATURE *sig)
{
	static const uint8_t zeros[ECCref_MAX_LEN - 32] = {0};

	if (memcmp(ref->r, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(ref->s, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	memcpy(sig->r, ref->r + sizeof(zeros), 32);
	memcpy(sig->s, ref->s + sizeof(zeros), 32);
	return SDR_OK;
}

int sdf_load_library(const char *so_path, const char *vendor)
{
	if (SDF_LoadLibrary((char *)so_path, (char *)vendor) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

void sdf_unload_library(void)
{
	SDF_UnloadLibrary();
}

int sdf_open_device(SDF_DEVICE *dev)
{
	int ret = -1;
	void *hDevice = NULL;
	void *hSession = NULL;
	DEVICEINFO devInfo;

	if (SDF_OpenDevice(&hDevice) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_OpenSession(hDevice, &hSession) != SDR_OK) {
		(void)SDF_CloseDevice(hDevice);
		error_print();
		return -1;
	}
	if (SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		(void)SDF_CloseDevice(hDevice);
		error_print();
		return -1;
	}
	(void)SDF_CloseSession(hSession);

	memset(dev, 0, sizeof(SDF_DEVICE));
	dev->handle = hDevice;
	memcpy(dev->issuer, devInfo.IssuerName, 40);
	memcpy(dev->name, devInfo.DeviceName, 16);
	memcpy(dev->serial, devInfo.DeviceSerial, 16);
	return 1;
}

int sdf_print_device_info(FILE *fp, int fmt, int ind, const char *lable, SDF_DEVICE *dev)
{
	void *hSession = NULL;
	DEVICEINFO devInfo;

	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	(void)SDF_CloseSession(hSession);

	(void)SDF_PrintDeviceInfo(fp, &devInfo);
	return 1;
}

int sdf_export_sign_public_key(SDF_DEVICE *dev, int key_index, SM2_KEY *sm2_key)
{
	void *hSession;
	ECCrefPublicKey eccPublicKey;

	if (!dev || !sm2_key) {
		error_print();
		return -1;
	}

	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_ExportSignPublicKey_ECC(hSession, key_index, &eccPublicKey) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	(void)SDF_CloseSession(hSession);

	memset(sm2_key, 0, sizeof(SM2_KEY));
	if (SDF_ECCrefPublicKey_to_SM2_Z256_POINT(&eccPublicKey, &sm2_key->public_key) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_load_sign_key(SDF_DEVICE *dev, SDF_SIGN_KEY *key, int key_index, const char *pass)
{
	void *hSession = NULL;
	ECCrefPublicKey eccPublicKey;

	if (!dev || !key || !pass) {
		error_print();
		return -1;
	}
	if (key_index < 0) {
		error_print();
		return -1;
	}

	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_ExportSignPublicKey_ECC(hSession, key_index, &eccPublicKey) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	if (SDF_GetPrivateKeyAccessRight(hSession, key_index, (unsigned char *)pass, (unsigned int)strlen(pass)) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}

	if (SDF_ECCrefPublicKey_to_SM2_Z256_POINT(&eccPublicKey, &key->public_key) != SDR_OK) {
		error_print();
		return -1;
	}
	key->session = hSession;
	key->index = key_index;
	return 1;
}

int sdf_sign(SDF_SIGN_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
	ECCSignature ecc_sig;
	SM2_SIGNATURE sm2_sig;

	if (!key || !dgst || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (SDF_InternalSign_ECC(key->session, key->index, (unsigned char *)dgst, 32, &ecc_sig) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_ECCSignature_to_SM2_SIGNATURE(&ecc_sig, &sm2_sig) != SDR_OK) {
		error_print();
		return -1;
	}
	*siglen = 0;
	if (sm2_signature_to_der(&sm2_sig, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_sign_init(SDF_SIGN_CTX *ctx, const SDF_SIGN_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}

	sm3_init(&ctx->sm3_ctx);
	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];

		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}
	ctx->saved_sm3_ctx = ctx->sm3_ctx;

	ctx->key = *key;
	return 1;
}

int sdf_sign_update(SDF_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sdf_sign_finish(SDF_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	sm3_finish(&ctx->sm3_ctx, dgst);

	if (sdf_sign(&ctx->key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_sign_reset(SDF_SIGN_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	ctx->sm3_ctx = ctx->saved_sm3_ctx;
	return 1;
}

int sdf_release_key(SDF_SIGN_KEY *key)
{
	if (SDF_ReleasePrivateKeyAccessRight(key->session, key->index) != SDR_OK) {
		error_print();
	}
	if (SDF_CloseSession(key->session) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_close_device(SDF_DEVICE *dev)
{
	if (SDF_CloseDevice(dev->handle) != SDR_OK) {
		error_print();
		return -1;
	}
	memset(dev, 0, sizeof(SDF_DEVICE));
	return 1;
}
