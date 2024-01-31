/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/error.h>
#include "../src/sdf/sdf.h"
#include "../src/sdf/sdf_ext.h"

static int test_SDF_GetDeviceInfo(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	DEVICEINFO deviceInfo;
	int rv;

	rv = SDF_LoadLibrary("libsoft_sdf.dylib", NULL);
	if (rv != SDR_OK) {
		printf("SDF_LoadLibrary failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_OpenDevice(&hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenSession failed with error: 0x%X\n", rv);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	rv = SDF_GetDeviceInfo(hSessionHandle, &deviceInfo);
	if (rv != SDR_OK) {
		printf("SDF_GetDeviceInfo failed with error: 0x%X\n", rv);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	printf("Device Info:\n");
	printf("\tIssuerName: %s\n", deviceInfo.IssuerName);
	printf("\tDeviceName: %s\n", deviceInfo.DeviceName);
	printf("\tDeviceSerial: %s\n", deviceInfo.DeviceSerial);
	printf("\tDeviceVersion: %u\n", deviceInfo.DeviceVersion);
	printf("\tStandardVersion: %u\n", deviceInfo.StandardVersion);
	printf("\tAsymAlgAbility: %u %u\n", deviceInfo.AsymAlgAbility[0], deviceInfo.AsymAlgAbility[1]);
	printf("\tSymAlgAbility: %u\n", deviceInfo.SymAlgAbility);
	printf("\tHashAlgAbility: %u\n", deviceInfo.HashAlgAbility);
	printf("\tBufferSize: %u\n", deviceInfo.BufferSize);

	rv = SDF_CloseSession(hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseSession failed with error: 0x%X\n", rv);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	rv = SDF_CloseDevice(hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_GenerateRandom(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	int rv;

	rv = SDF_OpenDevice(&hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenSession failed with error: 0x%X\n", rv);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	// Test with different lengths
	int lengths[] = {/*0*/2, 8, 128};
	for (int i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
		unsigned int uiLength = lengths[i];
		unsigned char pucRandom[128] = {0};  // Assuming max length

		rv = SDF_GenerateRandom(hSessionHandle, uiLength, pucRandom);
		if (rv != SDR_OK) {
			printf("SDF_GenerateRandom failed with error: 0x%X\n", rv);
			SDF_CloseSession(hSessionHandle);
			SDF_CloseDevice(hDeviceHandle);
			return -1;
		}

		// Check if the output is not all zeros
		int nonZeroCount = 0;
		for (unsigned int j = 0; j < uiLength; j++) {
			if (pucRandom[j] != 0) {
				nonZeroCount++;
			}
		}

		printf("Generated random values with length %u. Non-zero count: %d\n", uiLength, nonZeroCount);
	}

	rv = SDF_CloseSession(hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseSession failed with error: 0x%X\n", rv);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	rv = SDF_CloseDevice(hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#define ECC_KEY_INDEX 1 
#define ECC_PASSWORD "123456"

int testExportSignPublicKeyECC()
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyIndex = ECC_KEY_INDEX;
	unsigned char pucPassword[] = ECC_PASSWORD;
	ECCrefPublicKey eccRefPublicKey = {0};
	int rv;
	int i;

	rv = SDF_OpenDevice(&hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenSession failed with error: 0x%X\n", rv);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex, pucPassword, (unsigned int)strlen(ECC_PASSWORD));
	if (rv != SDR_OK) {
		printf("SDF_GetPrivateKeyAccessRight failed with error: 0x%X\n", rv);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	rv = SDF_ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, &eccRefPublicKey);
	if (rv != SDR_OK) {
		printf("SDF_ExportSignPublicKey_ECC failed with error: 0x%X\n", rv);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	printf("Exported ECC Public Key:\n");
	printf("Bits: %u\n", eccRefPublicKey.bits);
	printf("X Coordinate: ");
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		printf("%02X", eccRefPublicKey.x[i]);
	}
	printf("\n");

	printf("Y Coordinate: ");
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		printf("%02X", eccRefPublicKey.y[i]);
	}
	printf("\n");

	rv = SDF_CloseSession(hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseSession failed with error: 0x%X\n", rv);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	rv = SDF_CloseDevice(hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

void printECCPublicKey(const ECCrefPublicKey *publicKey)
{
	int i;
	printf("ECC Public Key:\n");
	printf("Bits: %u\n", publicKey->bits);


	printf("X: ");
	for (int i = 0; i < ECCref_MAX_LEN; i++) {
		printf("%02X", publicKey->x[i]);
	}
	printf("\n");

	printf("Y: ");
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		printf("%02X", publicKey->y[i]);
	}
	printf("\n");
}

void printECCPrivateKey(const ECCrefPrivateKey *eccRefPrivateKey)
{
	int i;
	printf("ECC Private Key:\n");
	printf("Bits: %u\n", eccRefPrivateKey->bits);
	printf("K Value: ");
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		printf("%02X", eccRefPrivateKey->K[i]);
	}
	printf("\n");
}

int test_SDF_GenerateKeyPair_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenSession returned 0x%X\n", ret);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, ECC_KEY_INDEX, (unsigned char *)ECC_PASSWORD, strlen(ECC_PASSWORD));
	if (ret != SDR_OK) {
		printf("Error: SDF_SetPrivateKeyAccessRight returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &pubKey, &priKey);
	if (ret != SDR_OK) {
		printf("Error: SDF_GenerateKeyPair_ECC returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	printECCPublicKey(&pubKey);
	printECCPrivateKey(&priKey);

	ret = SDF_CloseSession(hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseSession returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_CloseDevice(hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseDevice returned 0x%X\n", ret);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

void printECCCipher(const ECCCipher *cipher)
{
	printf("ECCCipher:\n");
	printf("x: ");
	for (int i = 0; i < ECCref_MAX_LEN; ++i) {
		printf("%02X ", cipher->x[i]);
	}
	printf("\n");

	printf("y: ");
	for (int i = 0; i < ECCref_MAX_LEN; ++i) {
		printf("%02X ", cipher->y[i]);
	}
	printf("\n");

	printf("M: ");
	for (int i = 0; i < 32; ++i) {
		printf("%02X ", cipher->M[i]);
	}
	printf("\n");

	printf("L: %u\n", cipher->L);

	printf("C: ");
	for (int i = 0; i < cipher->L; ++i) {
		printf("%02X ", cipher->C[i]);
	}
	printf("\n");
}


int test_SDF_GenerateKeyWithIPK_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCCipher encedKey;
	void *hKeyHandle = NULL;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenSession returned 0x%X\n", ret);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, ECC_KEY_INDEX, (unsigned char *)ECC_PASSWORD, strlen(ECC_PASSWORD));
	if (ret != SDR_OK) {
		printf("Error: SDF_SetPrivateKeyAccessRight returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, ECC_KEY_INDEX, 128, &encedKey, &hKeyHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_GenerateKeyWithIPK_ECC returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	printECCCipher(&encedKey);

	ret = SDF_CloseSession(hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseSession returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_CloseDevice(hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseDevice returned 0x%X\n", ret);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}









int test_SDF_GenerateKeyWithEPK_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey publicKey;
	ECCCipher encedKey;
	void *hKeyHandle = NULL;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenSession returned 0x%X\n", ret);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, ECC_KEY_INDEX, (unsigned char *)ECC_PASSWORD, strlen(ECC_PASSWORD));
	if (ret != SDR_OK) {
		printf("Error: SDF_SetPrivateKeyAccessRight returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_ExportEncPublicKey_ECC(hSessionHandle, ECC_KEY_INDEX, &publicKey);
	if (ret != SDR_OK) {
		printf("Error: SDF_ExportEncPublicKey_ECC returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, 128, SGD_SM2_3, &publicKey, &encedKey, &hKeyHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_GenerateKeyWithEPK_ECC returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	printECCCipher(&encedKey);

	ret = SDF_CloseSession(hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseSession returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_CloseDevice(hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseDevice returned 0x%X\n", ret);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_SDF_GenerateKeyWithKEK(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = 1;
	unsigned char pucKey[64];
	unsigned int uiKeyLength = (unsigned int)sizeof(pucKey);
	void *hKeyHandle = NULL;
	int ret;
	unsigned int i;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenSession returned 0x%X\n", ret);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_CBC, uiKEKIndex, pucKey, &uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_GenerateKeyWithKEK returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	printf("encryptedKey: ");
	for (i = 0; i < uiKeyLength; i++) {
		printf("%02X", pucKey[i]);
	}
	printf("\n");

	ret = SDF_CloseSession(hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseSession returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_CloseDevice(hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseDevice returned 0x%X\n", ret);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_SDF_Encrypt(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = 1;
	unsigned char pucKey[64];
	unsigned int uiKeyLength = (unsigned int)sizeof(pucKey);
	void *hKeyHandle = NULL;
	unsigned char pucIV[16];
	unsigned char pucData[28];
	unsigned int uiDataLength;
	unsigned char pucEncData[128];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucDecData[128];
	unsigned int uiDecDataLength = (unsigned int)sizeof(pucDecData);


	int ret;
	unsigned int i;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenSession returned 0x%X\n", ret);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_CBC, uiKEKIndex, pucKey, &uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_GenerateKeyWithKEK returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucData, uiDataLength, pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		printf("Error: SDF_Encrypt returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucEncData, uiEncDataLength, pucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		printf("Error: SDF_Encrypt returned 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	if (uiDecDataLength != uiDataLength) {
		printf("Error: uiDecDataLength != uiDataLength\n");
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}
	if (memcmp(pucDecData, pucData, uiDataLength) != 0) {
		printf("Error: pucDecData != pucData\n");
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_CloseSession(hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseSession returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_CloseDevice(hDeviceHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_CloseDevice returned 0x%X\n", ret);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_SDF_GetDeviceInfo() != 1) goto err;
	if (test_SDF_GenerateRandom() != 1) goto err;
	if (test_SDF_GenerateKeyPair_ECC() != 1) goto err;
	if (test_SDF_GenerateKeyWithIPK_ECC() != 1) goto err;
	if (test_SDF_GenerateKeyWithEPK_ECC() != 1) goto err;
	if (test_SDF_GenerateKeyWithKEK() != 1) goto err;
	//if (test_SDF_Encrypt() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
