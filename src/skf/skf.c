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
#include <gmssl/skf.h>
#include <gmssl/error.h>
#include "../sgd.h"
#include "skf.h"
#include "skf_ext.h"
#include "skf_int.h"


int skf_load_library(const char *so_path, const char *vendor)
{
	if (SKF_LoadLibrary((LPSTR)so_path, (LPSTR)vendor) != SAR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

void skf_unload_library(void)
{
	SKF_UnloadLibrary();
}


static int skf_open_app(SKF_DEVICE *dev, const char *appname, const char *pin, HAPPLICATION *phApp)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	ULONG ulPINType = USER_TYPE;
	ULONG numRetry;

	if (SKF_OpenApplication(dev->handle, (LPSTR)appname, &hApp) != SAR_OK) {
		error_print();
		return -1;
	}
	if (SKF_VerifyPIN(hApp, ulPINType, (CHAR *)pin, &numRetry) != SAR_OK) {
		fprintf(stderr, "Invalid user PIN, retry count = %u\n", numRetry);
		error_print();
		goto end;
	}
	*phApp = hApp;
	hApp = NULL;
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

static const uint8_t zeros[ECC_MAX_XCOORDINATE_BITS_LEN/8 - 32] = {0};

static int SKF_ECCPUBLICKEYBLOB_to_SM2_KEY(const ECCPUBLICKEYBLOB *blob, SM2_KEY *sm2_key)
{
	SM2_POINT point;

	if (blob->BitLen != 256) {
		error_print();
		return -1;
	}
	if (memcmp(blob->XCoordinate, zeros, sizeof(zeros)) != 0
		|| memcmp(blob->YCoordinate, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	if (sm2_point_from_xy(&point,
			blob->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/8 - 32,
			blob->YCoordinate + ECC_MAX_YCOORDINATE_BITS_LEN/8 - 32) != 1
		|| sm2_key_set_public_key(sm2_key, &point) != 1) {
		error_print();
		return -1;
	}
	return SAR_OK;
}

static int SKF_ECCSIGNATUREBLOB_to_SM2_SIGNATURE(const ECCSIGNATUREBLOB *blob, SM2_SIGNATURE *sig)
{
	if (memcmp(blob->r, zeros, sizeof(zeros)) != 0
		|| memcmp(blob->s, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	memset(sig, 0, sizeof(SM2_SIGNATURE));
	memcpy(sig->r, blob->r + ECC_MAX_XCOORDINATE_BITS_LEN/8 - 32, 32);
	memcpy(sig->s, blob->s + ECC_MAX_XCOORDINATE_BITS_LEN/8 - 32, 32);
	return SAR_OK;
}

int skf_rand_bytes(SKF_DEVICE *dev, uint8_t *buf, size_t len)
{
	if (SKF_GenRandom(dev->handle, buf, (ULONG)len) != SAR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int skf_load_sign_key(SKF_DEVICE *dev, const char *appname, const char *pin, const char *container_name, SKF_KEY *key)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	HCONTAINER hContainer = NULL;
	ULONG containerType = 0;
	BOOL bSign = SGD_TRUE;
	ECCPUBLICKEYBLOB publicKeyBlob;
	ULONG ulBlobLen = sizeof(ECCPUBLICKEYBLOB);
	SM2_KEY public_key;

	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_OpenContainer(hApp, (LPSTR)container_name, &hContainer) != SAR_OK
		|| SKF_GetContainerType(hContainer, &containerType) != SAR_OK) {
		error_print();
		goto end;
	}
	if (containerType != SKF_CONTAINER_TYPE_ECC) {
		error_print();
		goto end;
	}
	if (SKF_ExportPublicKey(hContainer, bSign, (BYTE *)&publicKeyBlob, &ulBlobLen) != SAR_OK) {
		error_print();
		goto end;
	}
	if (ulBlobLen != sizeof(ECCPUBLICKEYBLOB)) {
		error_print();
		goto end;
	}
	if (SKF_ECCPUBLICKEYBLOB_to_SM2_KEY(&publicKeyBlob, &public_key) != SAR_OK) {
		error_print();
		goto end;
	}
	memset(key, 0, sizeof(SKF_KEY));
	key->public_key = public_key;
	key->app_handle = hApp;
	hApp = NULL;
	strncpy(key->app_name, appname, 64);
	key->container_handle = hContainer;
	hContainer = NULL;
	strncpy(key->container_name, container_name, 64);
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	if (hContainer) SKF_CloseContainer(hContainer);
	return ret;
}

int skf_sign(SKF_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
	ECCSIGNATUREBLOB sigBlob;
	SM2_SIGNATURE sm2_sig;

	if (SKF_ECCSignData(key->container_handle, (BYTE *)dgst, 32, &sigBlob) != SAR_OK) {
		error_print();
		return -1;
	}
	if (SKF_ECCSIGNATUREBLOB_to_SM2_SIGNATURE(&sigBlob, &sm2_sig) != SAR_OK) {
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

int skf_release_key(SKF_KEY *key)
{
	if (key->app_handle) {
		if (SKF_ClearSecureState(key->app_handle) != SAR_OK
			|| SKF_CloseApplication(key->app_handle) != SAR_OK) {
			error_print();
			return -1;
		}
		key->app_handle = NULL;
	}
	if (key->container_handle) {
		if (SKF_CloseContainer(key->container_handle) != SAR_OK) {
			error_print();
			return -1;
		}
	}
	memset(key, 0, sizeof(SKF_KEY));
	return 1;
}

int skf_close_device(SKF_DEVICE *dev)
{
	if (SKF_UnlockDev(dev->handle) != SAR_OK
		|| SKF_DisConnectDev(dev->handle) != SAR_OK) {
		error_print();
		return -1;
	}
	memset(dev, 0, sizeof(SKF_DEVICE));
	return 1;
}







int skf_list_devices(FILE *fp, int fmt, int ind, const char *label)
{
	int ret = -1;
	BOOL bPresent = TRUE;
	char *nameList = NULL;
	ULONG nameListLen = 0;
	const char *name;
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (SKF_EnumDev(bPresent, NULL, &nameListLen) != SAR_OK) {
		error_print();
		return -1;
	}
	if (nameListLen == 0) {
		return 0;
	}
	if (!(nameList = malloc(nameListLen))) {
		error_print();
		return -1;
	}
	if (SKF_EnumDev(bPresent, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		error_print();
		goto end;
	}
	for (name = nameList, i = 0; *name; name += strlen(name) + 1, i++) {
		(void)format_print(fp, fmt, ind, "%s\n", name);
	}
	ret = 1;
end:
	free(nameList);
	return ret;
}

int skf_print_device_info(FILE *fp, int fmt, int ind, const char *devname)
{
	int ret = 0;
	DEVHANDLE hDev = NULL;
	ULONG devState = 0;
	LPSTR devStateName = NULL;
	DEVINFO devInfo = {{0,0}};

	format_print(fp, fmt, ind, "%s\n", devname);
	ind += 4;

	if (SKF_GetDevState((LPSTR)devname, &devState) != SAR_OK
		|| SKF_GetDevStateName(devState, &devStateName) != SAR_OK
		|| SKF_ConnectDev((LPSTR)devname, &hDev) != SAR_OK
		|| SKF_GetDevInfo(hDev, &devInfo) != SAR_OK) {
		error_print();
		goto end;
	}

	(void)format_print(fp, fmt, ind, "DeviceState: %s\n", (char *)devStateName);
	//(void)SKF_PrintDevInfo(fp, fmt, ind, "DeviceInfo", &devInfo);
	ret = 1;
end:
	if (hDev) SKF_DisConnectDev(hDev);
	return ret;
}

int skf_set_label(SKF_DEVICE *dev, const char *label)
{
	if (SKF_SetLabel(dev->handle, (LPSTR)label) != SAR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int skf_open_device(SKF_DEVICE *dev, const char *devname, const uint8_t authkey[16])
{
	DEVHANDLE hDev = NULL;
	DEVINFO devInfo = {{0,0}};
	ULONG ulTimeOut = 0xffffffff;
	BYTE authRand[16] = {0};
	BYTE authData[16] = {0};
	ULONG authRandLen = SKF_AUTHRAND_LENGTH;
	ULONG authDataLen = sizeof(authData);
	BLOCKCIPHERPARAM encParam = {{0}, 0, 0, 0};

	if (SKF_OpenDevice((LPSTR)devname, (BYTE *)authkey, &devInfo, &hDev) != SAR_OK
		|| SKF_LockDev(hDev, ulTimeOut) != SAR_OK) {
		error_print();
		return -1;
	}
	memset(dev, 0, sizeof(SKF_DEVICE));
	dev->handle = hDev;
	hDev = NULL;

	return 1;
}

int skf_change_authkey(SKF_DEVICE *dev, const uint8_t authkey[16])
{
	if (SKF_ChangeDevAuthKey(dev->handle, (BYTE *)authkey, 16) != SAR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int skf_list_apps(SKF_DEVICE *dev, int fmt, int ind, const char *label, FILE *fp)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	char *nameList = NULL;
	ULONG nameListLen = 0;
	const char *name;
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (SKF_EnumApplication(dev->handle, NULL, &nameListLen) != SAR_OK) {
		error_print();
		return -1;
	}
	if (nameListLen <= 1) {
		return 0;
	}
	if (!(nameList = malloc(nameListLen))) {
		error_print();
		return -1;
	}
	if (SKF_EnumApplication(dev->handle, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		error_print();
		goto end;
	}
	for (name = nameList, i = 0; *name; name += strlen(name) + 1, i++) {
		ULONG adminMaxRetry;
		ULONG adminMinRetry;
		ULONG userMaxRetry;
		ULONG userMinRetry;
		BOOL adminDefaultPin;
		BOOL userDefaultPin;

		if (SKF_OpenApplication(dev->handle, (LPSTR)name, &hApp) != SAR_OK
			|| SKF_GetPINInfo(hApp, ADMIN_TYPE, &adminMaxRetry, &adminMinRetry, &adminDefaultPin) != SAR_OK
			|| SKF_GetPINInfo(hApp, USER_TYPE, &userMaxRetry, &userMinRetry, &userDefaultPin) != SAR_OK
			|| SKF_CloseApplication(hApp) != SAR_OK) {
			error_print();
			goto end;
		}
		hApp = NULL;

		(void)format_print(fp, fmt, ind, "Application %d:\n", i);
		(void)format_print(fp, fmt, ind + 4, "ApplicationName", name);
		(void)format_print(fp, fmt, ind + 4, "AdminPinMaxRetry: %s\n", adminMaxRetry);
		(void)format_print(fp, fmt, ind + 4, "AdminPinMinRetry: %u\n", adminMinRetry);
		(void)format_print(fp, fmt, ind + 4, "AdminDefaultPin: %s\n", adminDefaultPin ? "True" : "False");
		(void)format_print(fp, fmt, ind + 4, "UserPinMaxRetry: %u\n", userMaxRetry);
		(void)format_print(fp, fmt, ind + 4, "UserPinMinRetry: %u\n", userMinRetry);
		(void)format_print(fp, fmt, ind + 4, "UserDefaultPin: %s\n", userDefaultPin ? "True" : "False");
	}
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_create_app(SKF_DEVICE *dev, const char *appname, const char *admin_pin, const char *user_pin)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	ULONG appRights = SECURE_ANYONE_ACCOUNT;

	if (SKF_CreateApplication(dev->handle, (LPSTR)appname,
		(CHAR *)admin_pin, SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT,
		(CHAR *)user_pin, SKF_DEFAULT_USER_PIN_RETRY_COUNT,
		appRights, &hApp) != SAR_OK) {
		error_print();
		return -1;
	}
	if (SKF_CloseApplication(hApp) != SAR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int skf_delete_app(SKF_DEVICE *dev, const char *appname)
{
	if (SKF_DeleteApplication(dev->handle, (LPSTR)appname) != SAR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int skf_change_app_admin_pin(SKF_DEVICE *dev, const char *appname, const char *oid_pin, const char *new_pin)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	ULONG ulPINType = ADMIN_TYPE;
	ULONG ulRetryCount = 0;

	if (SKF_OpenApplication(dev->handle, (LPSTR)appname, &hApp) != SAR_OK
		|| SKF_ChangePIN(hApp, ulPINType, (CHAR *)oid_pin, (CHAR *)new_pin, &ulRetryCount) != SAR_OK) {
		fprintf(stderr, "Retry Count = %u\n", ulRetryCount);
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_change_app_user_pin(SKF_DEVICE *dev, const char *appname, const char *oid_pin, const char *new_pin)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	ULONG ulPINType = USER_TYPE;
	ULONG ulRetryCount = 0;

	if (SKF_OpenApplication(dev->handle, (LPSTR)appname, &hApp) != SAR_OK
		|| SKF_ChangePIN(hApp, ulPINType, (CHAR *)oid_pin, (CHAR *)new_pin, &ulRetryCount) != SAR_OK) {
		fprintf(stderr, "Retry Count = %u\n", ulRetryCount);
		goto end;
	}
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_unblock_user_pin(SKF_DEVICE *dev, const char *appname, const char *admin_pin, const char *new_user_pin)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	ULONG ulRetryCount = 0;

	if (SKF_OpenApplication(dev->handle, (LPSTR)appname, &hApp) != SAR_OK
		|| SKF_UnblockPIN(hApp, (CHAR *)admin_pin, (CHAR *)new_user_pin, &ulRetryCount) != SAR_OK) {
		fprintf(stderr, "Invalid admin PIN, retry count = %u\n", ulRetryCount);
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_list_objects(FILE *fp, int fmt, int ind, const char *label,
	SKF_DEVICE *dev, const char *appname, const char *pin)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	char *nameList = NULL;
	ULONG nameListLen = 0;
	const char *name;
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_EnumFiles(hApp, NULL, &nameListLen) != SAR_OK) {
		error_print();
		goto end;
	}
	if (nameListLen <= 1) {
		ret = 0;
		goto end;
	}
	if (!(nameList = malloc(nameListLen))) {
		error_print();
		goto end;
	}
	if (SKF_EnumFiles(hApp, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		error_print();
		goto end;
	}
	for (name = nameList, i = 0; *name; name += strlen(name) + 1, i++) {
		FILEATTRIBUTE fileInfo;

		if (SKF_GetFileInfo(hApp, (LPSTR)name, &fileInfo) != SAR_OK) {
			error_print();
			goto end;
		}
		format_print(fp, fmt, ind, "Object:\n");
		format_print(fp, fmt, ind + 4, "Name: %s\n", (char *)&(fileInfo.FileName));
		format_print(fp, fmt, ind + 4, "Size: %u\n", fileInfo.FileSize);
		format_print(fp, fmt, ind + 4, "ReadRights: %08X\n", fileInfo.ReadRights);
		format_print(fp, fmt, ind + 4, "WriteRights: %08X\n", fileInfo.WriteRights);
	}

	ret = 1;

end:
	if (hApp) SKF_CloseApplication(hApp);
	if (nameList) free(nameList);
	return ret;
}

int skf_import_object(SKF_DEVICE *dev, const char *appname, const char *pin,
	const char *objname, const uint8_t *data, size_t datalen)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	ULONG ulReadRights = SECURE_ANYONE_ACCOUNT;
	ULONG ulWriteRights = SECURE_USER_ACCOUNT;

	if (!dev || !appname || !pin || !objname || !data || !datalen) {
		error_print();
		return -1;
	}
	if (datalen > SKF_MAX_FILE_SIZE) {
		error_print();
		return -1;
	}
	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_CreateFile(hApp, (LPSTR)objname, (ULONG)datalen, ulReadRights, ulWriteRights) != SAR_OK
		|| SKF_WriteFile(hApp, (LPSTR)objname, 0, (BYTE *)data, (ULONG)datalen) != SAR_OK) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_export_object(SKF_DEVICE *dev, const char *appname, const char *pin,
	const char *objname, uint8_t *out, size_t *outlen)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	FILEATTRIBUTE fileInfo;
	ULONG ulen;

	if (!dev || !appname || !pin || !objname || !outlen) {
		error_print();
		return -1;
	}
	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_GetFileInfo(hApp, (LPSTR)objname, &fileInfo) != SAR_OK) {
		error_print();
		goto end;
	}
	if (fileInfo.FileSize > SKF_MAX_FILE_SIZE) {
		error_print();
		goto end;
	}
	if (!out) {
		*outlen = (size_t)fileInfo.FileSize;
		ret = 1;
		goto end;
	}
	ulen = fileInfo.FileSize;
	if (SKF_ReadFile(hApp, (LPSTR)objname, 0, fileInfo.FileSize, out, &ulen) != SAR_OK) {
		goto end;
	}
	if (ulen != fileInfo.FileSize) {
		error_print();
		goto end;
	}
	*outlen = ulen;
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_delete_object(SKF_DEVICE *dev, const char *appname, const char *pin, const char *objname)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;

	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_DeleteFile(hApp, (LPSTR)objname) != SAR_OK) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_list_containers(FILE *fp, int fmt, int ind, const char *label,
	SKF_DEVICE *dev, const char *appname, const char *pin)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	HCONTAINER hContainer = NULL;
	char *nameList = NULL;
	ULONG nameListLen = 0;
	const char *name;
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_EnumContainer(hApp, NULL, &nameListLen) != SAR_OK) {
		error_print();
		goto end;
	}
	if (nameListLen <= 1) {
		ret = 0;
		goto end;
	}
	if (!(nameList = malloc(nameListLen))) {
		error_print();
		goto end;
	}
	if (SKF_EnumContainer(hApp, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		error_print();
		goto end;
	}
	for (name = nameList, i = 0; *name; name += strlen(name) + 1, i++) {
		ULONG containerType;
		LPSTR containerTypeName;

		if (SKF_OpenContainer(hApp, (LPSTR)name, &hContainer) != SAR_OK
			|| SKF_GetContainerType(hContainer, &containerType) != SAR_OK
			|| SKF_GetContainerTypeName(containerType, &containerTypeName) != SAR_OK
			|| SKF_CloseContainer(hContainer) != SAR_OK) {
			error_print();
			goto end;
		}
		hContainer = NULL;
		(void)format_print(fp, fmt, ind, "Container:\n");
		(void)format_print(fp, fmt, ind + 4, "Name: %s\n", name);
		(void)format_print(fp, fmt, ind + 4, "Type: %s\n", (char *)containerTypeName);
	}
	ret = 1;

end:
	if (hContainer) SKF_CloseContainer(hContainer);
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_create_container(SKF_DEVICE *dev, const char *appname, const char *pin, const char *container_name)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	HCONTAINER hContainer = NULL;
	ECCPUBLICKEYBLOB publicKey = {0, {0}, {0}};

	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_CreateContainer(hApp, (LPSTR)container_name, &hContainer) != SAR_OK
		|| SKF_GenECCKeyPair(hContainer, SGD_SM2_1, &publicKey) != SAR_OK) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hContainer) SKF_CloseContainer(hContainer);
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_delete_container(SKF_DEVICE *dev, const char *appname, const char *pin, const char *container_name)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;

	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_DeleteContainer(hApp, (LPSTR)container_name) != SAR_OK) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hApp) SKF_CloseApplication(hApp);
	return 1;
}

int skf_import_sign_cert(SKF_DEVICE *dev, const char *appname, const char *pin,
	const char *container_name, const uint8_t *cert, size_t certlen)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	HCONTAINER hContainer = NULL;
	ULONG containerType;
	BOOL bSign = SGD_TRUE;

	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_GetContainerType(hContainer, &containerType) != SAR_OK) {
		error_print();
		goto end;
	}
	if (containerType == SKF_CONTAINER_TYPE_UNDEF) {
		error_print();
		goto end;
	}
	if (containerType != SKF_CONTAINER_TYPE_ECC) {
		error_print();
		goto end;
	}
	// FIXME: 判断导入证书的类型是否为签名证书
	if (SKF_ImportCertificate(hContainer, bSign, (BYTE *)cert, (ULONG)certlen) != SAR_OK) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hContainer) SKF_CloseContainer(hContainer);
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}

int skf_export_sign_cert(SKF_DEVICE *dev, const char *appname, const char *pin,
	const char *container_name, uint8_t *cert, size_t *certlen)
{
	int ret = -1;
	HAPPLICATION hApp = NULL;
	HCONTAINER hContainer = NULL;
	ULONG containerType;
	BOOL bSign = SGD_TRUE;
	ULONG ulCertLen = 0;

	if (skf_open_app(dev, appname, pin, &hApp) != 1) {
		error_print();
		return -1;
	}
	if (SKF_GetContainerType(hContainer, &containerType) != SAR_OK) {
		error_print();
		goto end;
	}
	if (containerType != SKF_CONTAINER_TYPE_ECC) {
		error_print();
		goto end;
	}
	if (SKF_ExportCertificate(hContainer, bSign, (BYTE *)cert, &ulCertLen) != SAR_OK) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (hContainer) SKF_CloseContainer(hContainer);
	if (hApp) SKF_CloseApplication(hApp);
	return ret;
}
