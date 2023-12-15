/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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



static const uint8_t zeros[ECCref_MAX_LEN - 32] = {0};

static int SDF_ECCrefPublicKey_to_SM2_KEY(const ECCrefPublicKey *ref, SM2_KEY *sm2_key)
{
	SM2_POINT point;

	if (ref->bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(ref->x, zeros, sizeof(zeros)) != 0
		|| memcmp(ref->y, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}

	if (sm2_point_from_xy(&point, ref->x + ECCref_MAX_LEN - 32, ref->y + ECCref_MAX_LEN - 32) != 1
		|| sm2_key_set_public_key(sm2_key, &point) != 1) {
		error_print();
		return -1;
	}
	return SDR_OK;
}

static int SDF_ECCSignature_to_SM2_SIGNATURE(const ECCSignature *ref, SM2_SIGNATURE *sig)
{
	if (memcmp(ref->r, zeros, sizeof(zeros)) != 0
		|| memcmp(ref->s, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	memset(sig, 0, sizeof(SM2_SIGNATURE));
	memcpy(sig->r, ref->r + ECCref_MAX_LEN - 32, 32);
	memcpy(sig->s, ref->s + ECCref_MAX_LEN - 32, 32);
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

	if (SDF_OpenDevice(&hDevice) != SDR_OK
		|| SDF_OpenSession(hDevice, &hSession) != SDR_OK
		|| SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK) {
		error_print();
		goto end;
	}

	memset(dev, 0, sizeof(SDF_DEVICE));
	dev->handle = hDevice;
	hDevice = NULL;
	memcpy(dev->issuer, devInfo.IssuerName, 40);
	memcpy(dev->name, devInfo.DeviceName, 16);
	memcpy(dev->serial, devInfo.DeviceSerial, 16);
	ret = 1;
end:
	if (hSession) SDF_CloseSession(hSession);
	if (hDevice) SDF_CloseDevice(hDevice);
	return ret;
}

int sdf_print_device_info(FILE *fp, int fmt, int ind, const char *lable, SDF_DEVICE *dev)
{
	int ret = -1;
	void *hSession = NULL;
	DEVICEINFO devInfo;

	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK
		|| SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK) {
		error_print();
		goto end;
	}
	SDF_PrintDeviceInfo(fp, &devInfo);
	ret = 1;
end:
	if (hSession) SDF_CloseSession(hSession);
	return ret;
}

int sdf_rand_bytes(SDF_DEVICE *dev, uint8_t *buf, size_t len)
{
	int ret = -1;
	void *hSession = NULL;

	if (!dev || !buf || !len) {
		error_print();
		return -1;
	}
	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK
		|| SDF_GenerateRandom(hSession, (unsigned int)len, buf) != SDR_OK) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hSession) SDF_CloseSession(hSession);
	return ret;
}

int sdf_load_sign_key(SDF_DEVICE *dev, SDF_KEY *key, int index, const char *pass)
{
	int ret = -1;
	void *hSession = NULL;
	ECCrefPublicKey eccPublicKey;
	SM2_KEY public_key;

	if (!dev || !key || !pass) {
		error_print();
		return -1;
	}
	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK
		|| SDF_ExportSignPublicKey_ECC(hSession, index, &eccPublicKey) != SDR_OK
		|| SDF_ECCrefPublicKey_to_SM2_KEY(&eccPublicKey, &public_key) != SDR_OK
		|| SDF_GetPrivateKeyAccessRight(hSession, index, (unsigned char *)pass, (unsigned int)strlen(pass)) != SDR_OK) {
		error_print();
		goto end;
	}

	memset(key, 0, sizeof(SDF_KEY));
	key->public_key = public_key;
	key->session = hSession;
	key->index = index;
	hSession = NULL;
	ret = 1;
end:
	if (hSession) SDF_CloseSession(hSession);
	return ret;
}

int sdf_sign(SDF_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
	ECCSignature ecc_sig;
	SM2_SIGNATURE sm2_sig;

	if (!key || !dgst || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (SDF_InternalSign_ECC(key->session, key->index, (unsigned char *)dgst, 32, &ecc_sig) != SDR_OK
		|| SDF_ECCSignature_to_SM2_SIGNATURE(&ecc_sig, &sm2_sig) != SDR_OK) {
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

int sdf_release_key(SDF_KEY *key)
{
	if (SDF_ReleasePrivateKeyAccessRight(key->session, key->index) != SDR_OK
		|| SDF_CloseSession(key->session) != SDR_OK) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(SDF_KEY));
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
