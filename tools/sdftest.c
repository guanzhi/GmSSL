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
#include <time.h>
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include "../src/sdf/sdf.h"
#include "../src/sdf/sdf_ext.h"


static const char *usage = "-lib so_path -kek num -key num -pass str";

static const char *options =
"\n"
"Options\n"
"\n"
"    -lib so_path        Path to vendor's SDF dynamic lib (.so or .dylib)\n"
"    -kek num            KEK index\n"
"    -key num            Private key index\n"
"    -pass str           Password for accessing the private key\n"
"\n"
"Examples\n"
"\n"
"  $ gmssl sdftest -lib soft_sdf.so -kek 1 -key 1 -pass P@ssw0rd\n"
"\n";


/*
static int test_SDF_GetDeviceInfo(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	DEVICEINFO deviceInfo;
	int rv;

	rv = SDF_OpenDevice(&hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenSession failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_GetDeviceInfo(hSessionHandle, &deviceInfo);
	if (rv != SDR_OK) {
		printf("SDF_GetDeviceInfo failed with error: 0x%X\n", rv);
		return -1;
	}

	fprintf(stderr, "Device Info:\n");
	fprintf(stderr, "    IssuerName: %s\n", deviceInfo.IssuerName);
	fprintf(stderr, "    DeviceName: %s\n", deviceInfo.DeviceName);
	fprintf(stderr, "    DeviceSerial: %s\n", deviceInfo.DeviceSerial);
	fprintf(stderr, "    DeviceVersion: %u\n", deviceInfo.DeviceVersion);
	fprintf(stderr, "    StandardVersion: %u\n", deviceInfo.StandardVersion);
	fprintf(stderr, "    AsymAlgAbility: 0x%08X 0x%08X\n", deviceInfo.AsymAlgAbility[0], deviceInfo.AsymAlgAbility[1]);
	fprintf(stderr, "    SymAlgAbility:");
	if (deviceInfo.SymAlgAbility & SGD_SM1) fprintf(stderr, " SM1");
	if (deviceInfo.SymAlgAbility & SGD_SM4) fprintf(stderr, " SM4");
	if (deviceInfo.SymAlgAbility & SGD_ZUC) fprintf(stderr, " ZUC");
	if (deviceInfo.SymAlgAbility & SGD_SSF33) fprintf(stderr, " SSF33");
	if (deviceInfo.SymAlgAbility & SGD_ECB) fprintf(stderr, " ECB");
	if (deviceInfo.SymAlgAbility & SGD_CBC) fprintf(stderr, " CBC");
	if (deviceInfo.SymAlgAbility & SGD_CFB) fprintf(stderr, " CFB");
	if (deviceInfo.SymAlgAbility & SGD_OFB) fprintf(stderr, " OFB");
	if (deviceInfo.SymAlgAbility & SGD_MAC) fprintf(stderr, " MAC");
	fprintf(stderr, " (0x%08X)\n", deviceInfo.SymAlgAbility);
	fprintf(stderr, "    HashAlgAbility:");
	if (deviceInfo.HashAlgAbility & SGD_SM3) fprintf(stderr, " SM3");
	if (deviceInfo.HashAlgAbility & SGD_SHA1) fprintf(stderr, " SHA1");
	if (deviceInfo.HashAlgAbility & SGD_SHA256) fprintf(stderr, " SHA256");
	fprintf(stderr, " (0x%08X)\n", deviceInfo.HashAlgAbility);
	fprintf(stderr, "    BufferSize: %u\n", deviceInfo.BufferSize);

	rv = SDF_CloseSession(hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseSession failed with error: 0x%X\n", rv);
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
*/

static int test_SDF_GenerateRandom(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	int lengths[] = { 1, 8, 128 };
	int ret, i;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
		unsigned int uiLength = lengths[i];
		unsigned char pucRandom[128] = {0}; // Assuming max length
		unsigned char zeros[sizeof(pucRandom)] = {0};

		ret = SDF_GenerateRandom(hSessionHandle, uiLength, pucRandom);
		if (ret != SDR_OK) {
			fprintf(stderr, "Error: SDF_GenerateRandom: 0x%X\n", ret);
			return -1;
		}

		// Check if the output is not all zeros
		if (memcmp(pucRandom, zeros, uiLength) == 0) {
			error_print();
			return -1;
		}
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// FIXME: check generated public key is not [n-1]G, i.e. -G
int test_SDF_ExportSignPublicKey_ECC(int key)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyIndex = (unsigned int)key;
	ECCrefPublicKey eccPublicKey;
	uint8_t zeros[ECCref_MAX_LEN] = {0};
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenDevice failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenSession failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, &eccPublicKey);
	if (ret != SDR_OK) {
		printf("SDF_ExportSignPublicKey_ECC failed with error: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	memcpy(point.x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_SDF_ExportEncPublicKey_ECC(int key)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyIndex = (unsigned int)key;
	ECCrefPublicKey eccPublicKey;
	uint8_t zeros[ECCref_MAX_LEN] = {0};
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenDevice failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenSession failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_ExportEncPublicKey_ECC(hSessionHandle, uiKeyIndex, &eccPublicKey);
	if (ret != SDR_OK) {
		printf("SDF_ExportEncPublicKey_ECC failed with error: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	memcpy(point.x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// FIXME: check generated public key is not [n-1]G, i.e. -G
static int test_SDF_GenerateKeyPair_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey;
	ECCrefPrivateKey eccPrivateKey;
	int ret;

	SM2_KEY sm2_key;
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	sm2_z256_t private_key;
	uint8_t zeros[ECCref_MAX_LEN] = {0};

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &eccPublicKey, &eccPrivateKey);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyPair_ECC: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	memcpy(point.x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}

	// check private key
	if (eccPrivateKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPrivateKey.K, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	sm2_z256_from_bytes(private_key, eccPrivateKey.K + ECCref_MAX_LEN - 32);
	if (sm2_key_set_private_key(&sm2_key, private_key) != 1) {
		error_print();
		return -1;
	}

	// check private/public key
	if (sm2_z256_point_equ(&sm2_key.public_key, &public_key) != 1) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_ExternalVerify_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey = {
		256,
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x12, 0xbd, 0x37, 0x95, 0x9d, 0xb3, 0x36,
		0x11, 0x33, 0x04, 0x44, 0x02, 0xfa, 0x83, 0xec,
		0x18, 0x47, 0x1b, 0x5b, 0x2c, 0x98, 0xb5, 0x0e,
		0x49, 0xa3, 0x29, 0x43, 0x92, 0xd1, 0xe5, 0x45,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x31, 0x17, 0xbe, 0x37, 0xef, 0x88, 0x82, 0x2d,
		0xf5, 0x53, 0xc6, 0xe2, 0xf2, 0x67, 0x77, 0x8a,
		0x80, 0xe0, 0xe1, 0xfa, 0x3c, 0x49, 0xd4, 0x8b,
		0xb0, 0xe4, 0xbe, 0xfd, 0x66, 0xbe, 0xcc, 0x4c,
		},
	};
	unsigned char ucData[] = {
		0xac, 0xba, 0xa9, 0x0f, 0xab, 0x42, 0x9f, 0x58,
		0x72, 0x05, 0xeb, 0x4a, 0xb3, 0xa2, 0x16, 0x70,
		0x1a, 0x0d, 0xef, 0xfe, 0x10, 0xea, 0x76, 0x8f,
		0x7d, 0x89, 0x33, 0x7a, 0xcc, 0xbe, 0x9b, 0x9e,
	};
	ECCSignature eccSignature = {
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x50, 0x52, 0x4e, 0xee, 0xa7, 0x6c, 0x91, 0x4e,
		0xd5, 0x75, 0xab, 0xa1, 0x74, 0xcf, 0x34, 0x18,
		0xae, 0xb0, 0x5e, 0x34, 0x29, 0xd5, 0xff, 0x90,
		0x09, 0x93, 0xaf, 0x6b, 0x4d, 0x1c, 0xf5, 0x4f,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x76, 0xf0, 0xba, 0xd1, 0x97, 0x4d, 0x2b, 0xa8,
		0x08, 0x9e, 0xc4, 0x7b, 0x75, 0x06, 0x05, 0x89,
		0x8f, 0xab, 0x60, 0xce, 0xc7, 0x27, 0x98, 0x41,
		0x3e, 0xb4, 0xb6, 0x66, 0x20, 0x52, 0x0c, 0xf4,
		},
	};
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice return 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// verify correct signature
	ret = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccSignature);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ExternalVerify_ECC returned 0x%X\n", ret);
		return -1;
	}

#if ENABLE_TEST_INVALID_INPUT
	// verify invalid signature
	eccSignature.r[32]++;
	fprintf(stderr, "<!--\n");
	ret = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccSignature);
	fprintf(stderr, "-->\n");
	if (ret == SDR_OK) {
		fprintf(stderr, "Error: SDF_ExternalVerify_ECC return SDR_OK on modified signature\n");
		return -1;
	}
	eccSignature.r[32]--;

	// verify modified data
	ucData[0]++;
	fprintf(stderr, "<!--\n");
	ret = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccSignature);
	fprintf(stderr, "-->\n");
	if (ret == SDR_OK) {
		fprintf(stderr, "Error: SDF_ExternalVerify_ECC return SDR_OK on modified data\n");
		return -1;
	}
	ucData[0]--;
#endif

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_ExternalEncrypt_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey;
	unsigned char ucData[48];
	ECCCipher eccCipher;
	int ret;

	SM2_KEY sm2_key;
	SM2_POINT point;
	SM2_CIPHERTEXT ciphertext;
	const uint8_t zeros[ECCref_MAX_LEN] = {0};
	uint8_t plaintext[SM2_MAX_PLAINTEXT_SIZE];
	size_t plaintext_len;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// generate SM2_KEY and convert public key to ECCrefPublicKey
	// Note: when testing SDF_ExternalEncrypt_ECC, we should not assume IPK exists
	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}
	eccPublicKey.bits = 256;
	memset(eccPublicKey.x, 0, ECCref_MAX_LEN - 32);
	memcpy(eccPublicKey.x + ECCref_MAX_LEN - 32, point.x, 32);
	memset(eccPublicKey.y, 0, ECCref_MAX_LEN - 32);
	memcpy(eccPublicKey.y + ECCref_MAX_LEN - 32, point.y, 32);

	// encrypt
	if (rand_bytes(ucData, sizeof(ucData)) != 1) {
		error_print();
		return -1;
	}
	ret = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccCipher);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// convert ECCCipher to SM2_CIPHERTEXT
	if (memcmp(eccCipher.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccCipher.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (eccCipher.L > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	memcpy(ciphertext.point.x, eccCipher.x + ECCref_MAX_LEN - 32, 32);
	memcpy(ciphertext.point.y, eccCipher.y + ECCref_MAX_LEN - 32, 32);
	memcpy(ciphertext.hash, eccCipher.M, 32);
	ciphertext.ciphertext_size = eccCipher.L;
	memcpy(ciphertext.ciphertext, eccCipher.C, eccCipher.L);

	// decrypt and check plaintext
	if (sm2_do_decrypt(&sm2_key, &ciphertext, plaintext, &plaintext_len) != 1) {
		error_print();
		return -1;
	}

	if (plaintext_len != sizeof(ucData)) {
		error_print();
		return -1;
	}
	if (memcmp(plaintext, ucData, sizeof(ucData)) != 0) {
		error_print();
		return -1;
	}


	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

/*
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
*/

int test_SDF_GenerateKeyWithEPK_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	ECCrefPublicKey eccPublicKey = {
		256,
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x12, 0xbd, 0x37, 0x95, 0x9d, 0xb3, 0x36,
		0x11, 0x33, 0x04, 0x44, 0x02, 0xfa, 0x83, 0xec,
		0x18, 0x47, 0x1b, 0x5b, 0x2c, 0x98, 0xb5, 0x0e,
		0x49, 0xa3, 0x29, 0x43, 0x92, 0xd1, 0xe5, 0x45,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x31, 0x17, 0xbe, 0x37, 0xef, 0x88, 0x82, 0x2d,
		0xf5, 0x53, 0xc6, 0xe2, 0xf2, 0x67, 0x77, 0x8a,
		0x80, 0xe0, 0xe1, 0xfa, 0x3c, 0x49, 0xd4, 0x8b,
		0xb0, 0xe4, 0xbe, 0xfd, 0x66, 0xbe, 0xcc, 0x4c,
		},
	};
	ECCCipher eccCipher;
	int ret;


	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, 128, SGD_SM2_3, &eccPublicKey, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_GenerateKeyWithEPK_ECC returned 0x%X\n", ret);
		return -1;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return -1;
	}

	if (SDF_DestroyKey(hSessionHandle, hKeyHandle) != SDR_OK) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_SDF_GenerateKeyWithKEK(int kek)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = (unsigned int)kek;
	unsigned char ucKey[64]; // encrypted key with SGD_SM4_CBC
	unsigned int uiKeyLength;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	uiKeyLength = (unsigned int)sizeof(ucKey); // SDF_GenerateKeyWithKEK might check output buffer size

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_CBC, uiKEKIndex, ucKey, &uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyWithKEK: 0x%X\n", ret);
		return -1;
	}
	if (hKeyHandle == NULL) {
		error_print();
		return -1;
	}
	// encrpyted key size should be larger
	if (uiKeyLength < uiKeyBits/8) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	hKeyHandle = NULL;

	ret = SDF_ImportKeyWithKEK(hSessionHandle, SGD_SM4_CBC, uiKEKIndex, ucKey, uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print();
		fprintf(stderr, "Error: SDF_ImportKeyWithKEK: 0x%X\n", ret);
		return -1;
	}
	if (hKeyHandle == NULL) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_Hash(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned char ucData[3] = { 0x61, 0x62, 0x63 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucHash[32];
	unsigned int uiHashLength;
	const unsigned char ucHashResult[32] = {
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
	};
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashInit(hSessionHandle, SGD_SM3, NULL, NULL, 0);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashInit: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashUpdate(hSessionHandle, ucData, uiDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashUpdate: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashFinal(hSessionHandle, ucHash, &uiHashLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashFinal: 0x%X\n", ret);
		return -1;
	}

	// check correctness
	if (uiHashLength != 32) {
		error_print();
		return -1;
	}
	if (memcmp(ucHash, ucHashResult, 32) != 0) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// TODO: change test vectors
static int test_SDF_Hash_Z(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey publicKeyRef = {
		256,
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xb6, 0xaf, 0x0c, 0xda, 0xba, 0xdc, 0x18, 0xb4,
		0x65, 0xf5, 0x3f, 0xc3, 0xde, 0x1e, 0x32, 0x87,
		0x89, 0xdc, 0x68, 0xde, 0x92, 0xf1, 0x20, 0xa4,
		0x0a, 0x2e, 0xbb, 0xdb, 0xf1, 0xbd, 0xa8, 0x39,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 0xff, 0x30, 0x5b, 0x95, 0xf9, 0x94, 0x1a,
		0x92, 0x74, 0x36, 0x42, 0x6f, 0xd2, 0xdf, 0xf2,
		0xfa, 0xf6, 0x08, 0x79, 0x57, 0x7a, 0x95, 0x96,
		0x54, 0xb3, 0xf1, 0x50, 0xba, 0x79, 0xdb, 0x86,
		},
	};
	unsigned char ucID[] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	};
	unsigned int uiIDLength = 16;
	unsigned char ucData[3] = { 0x61, 0x62, 0x63 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucHash[32];
	unsigned int uiHashLength;
	const unsigned char ucHashResult[32] = {
		0x87, 0xb7, 0xd6, 0x24, 0xce, 0x4b, 0xb0, 0x0a,
		0xc5, 0x6d, 0xb2, 0xb6, 0xc5, 0x06, 0xd5, 0xfc,
		0x9e, 0x38, 0xfd, 0x80, 0xc2, 0x4d, 0x1b, 0x99,
		0x1e, 0x8c, 0x38, 0xb3, 0x2b, 0xd6, 0xee, 0x5a,
	};
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashInit(hSessionHandle, SGD_SM3, &publicKeyRef, ucID, uiIDLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashInit: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashUpdate(hSessionHandle, ucData, uiDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashUpdate: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashFinal(hSessionHandle, ucHash, &uiHashLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashFinal: 0x%X\n", ret);
		return -1;
	}

	// check correctness
	if (uiHashLength != 32) {
		error_print();
		return -1;
	}
	if (memcmp(ucHash, ucHashResult, 32) != 0) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// FIXME: make test_SDF_GenerateKeyWithIPK_ECC test less APIs		
static int test_SDF_GenerateKeyWithIPK_ECC(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	uint8_t iv[16] = {1};
	unsigned int uiIPKIndex =(unsigned int)key;
	unsigned char *pucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	unsigned int uiKeyBits = 128;
	ECCCipher eccCipher;
	unsigned char ucIV[16];
	unsigned char ucData[32];
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucEncData[64];
	unsigned int uiEncDataLength;
	unsigned char ucDecData[64];
	unsigned int uiDecDataLength;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	// generate symmetric key and encrypt
	ret = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, uiIPKIndex, uiKeyBits, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyWithIPK_ECC return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	memcpy(ucIV, iv, 16);
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucData, uiDataLength, ucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_Encrypt return 0x%X\n", ret);
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_DestroyKey(hSessionHandle, hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_DestroyKey return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}
	hKeyHandle = NULL;

	// import symmetric key and decrypt
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, pucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiIPKIndex, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ImportKeyWithISK_ECC return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	memcpy(ucIV, iv, 16);
	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucEncData, uiEncDataLength, ucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		printf("Error: SDF_Encrypt returned 0x%X\n", ret);
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	if (uiDecDataLength != uiDataLength) {
		fprintf(stderr, "Error: uiDecDataLength != uiDataLength\n");
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}
	if (memcmp(ucDecData, ucData, uiDataLength) != 0) {
		fprintf(stderr, "Error: ucDecData != ucData\n");
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);
	return 1;
}

static int test_SDF_Encrypt_SM4_CBC(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned char pucKey[16];
	unsigned char pucIV[16];
	unsigned char pucData[32];
	unsigned char pucEncData[64];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucCiphertext[64];

	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *pucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	ECCCipher eccCipher;
	int ret;

	{
		char *key = "0123456789abcdeffedcba9876543210";
		char *iv  = "0123456789abcdeffedcba9876543210";
		char *plain = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
		char *cipher = "2677f46b09c122cc975533105bd4a22af6125f7275ce552c3a2bbcf533de8a3b"; // ciphertext without padding
		size_t len;

		hex_to_bytes(key, strlen(key), pucKey, &len);
		hex_to_bytes(iv, strlen(iv), pucIV, &len);
		hex_to_bytes(plain, strlen(plain), pucData, &len);
		hex_to_bytes(cipher, strlen(cipher), pucCiphertext, &len);
	}

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// SDF_ImportKey

	ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, pucKey, sizeof(pucKey), &eccCipher);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, pucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}
	ret = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiIPKIndex, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// encrypt
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucData, sizeof(pucData), pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// compare ciphertext-without-padding, compatible with padding
	if (memcmp(pucEncData, pucCiphertext, 32) != 0) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_Encrypt_SM4_ECB(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned char pucKey[16];
	unsigned char pucData[32];
	unsigned char pucEncData[sizeof(pucData)];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucCiphertext[sizeof(pucData)];
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *pucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	ECCCipher eccCipher;
	int ret;

	SM4_KEY sm4_key;
	rand_bytes(pucKey, sizeof(pucKey));
	rand_bytes(pucData, sizeof(pucData));
	sm4_set_encrypt_key(&sm4_key, pucKey);
	sm4_encrypt_blocks(&sm4_key, pucData, sizeof(pucData)/16, pucCiphertext);

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// SDF_ImportKey

	ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, pucKey, sizeof(pucKey), &eccCipher);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, pucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiIPKIndex, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// encrypt
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, NULL, pucData, (unsigned int)sizeof(pucData), pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	// compare
	if ((size_t)uiEncDataLength != sizeof(pucData)) {
		error_print();
		return -1;
	}
	if (memcmp(pucEncData, pucCiphertext, sizeof(pucCiphertext)) != 0) {
		error_print();
		return -1;
	}

	// decrypt
	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, NULL, pucEncData, uiEncDataLength, pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	// compare
	if ((size_t)uiEncDataLength != sizeof(pucData)) {
		error_print();
		return -1;
	}
	if (memcmp(pucEncData, pucData, sizeof(pucData)) != 0) {
		error_print();
		return -1;
	}

	// cleanup
	ret = SDF_DestroyKey(hSessionHandle, hKeyHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_CloseSession(hSessionHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_CloseDevice(hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#if ENABLE_SM4_CFB
static int test_SDF_Encrypt_SM4_CFB(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned char pucKey[16];
	unsigned char pucIV[16];
	unsigned char pucData[41];
	unsigned char pucEncData[sizeof(pucData)];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucCiphertext[sizeof(pucData)];
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *pucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	ECCCipher eccCipher;
	int ret;

	SM4_KEY sm4_key;
	uint8_t iv[16];
	rand_bytes(pucKey, sizeof(pucKey));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(pucData, sizeof(pucData));
	sm4_set_encrypt_key(&sm4_key, pucKey);
	memcpy(pucIV, iv, sizeof(iv));
	sm4_cfb_encrypt(&sm4_key, SM4_CFB_128, pucIV, pucData, sizeof(pucData), pucCiphertext);

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// SDF_ImportKey

	ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, pucKey, sizeof(pucKey), &eccCipher);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, pucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiIPKIndex, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// encrypt
	memcpy(pucIV, iv, sizeof(iv));
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CFB, pucIV, pucData, (unsigned int)sizeof(pucData), pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	// compare
	if ((size_t)uiEncDataLength != sizeof(pucData)) {
		error_print();
		return -1;
	}
	if (memcmp(pucEncData, pucCiphertext, sizeof(pucCiphertext)) != 0) {
		error_print();
		return -1;
	}

	// decrypt
	memcpy(pucIV, iv, sizeof(iv));
	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucEncData, uiEncDataLength, pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	// compare
	if ((size_t)uiEncDataLength != sizeof(pucData)) {
		error_print();
		return -1;
	}
	if (memcmp(pucEncData, pucData, sizeof(pucData)) != 0) {
		error_print();
		return -1;
	}

	// cleanup
	ret = SDF_DestroyKey(hSessionHandle, hKeyHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_CloseSession(hSessionHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_CloseDevice(hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

#if ENABLE_SM4_OFB
static int test_SDF_Encrypt_SM4_OFB(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned char pucKey[16];
	unsigned char pucIV[16];
	unsigned char pucData[41];
	unsigned char pucEncData[sizeof(pucData)];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucCiphertext[sizeof(pucData)];
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *pucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	ECCCipher eccCipher;
	int ret;

	SM4_KEY sm4_key;
	uint8_t iv[16];
	rand_bytes(pucKey, sizeof(pucKey));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(pucData, sizeof(pucData));
	sm4_set_encrypt_key(&sm4_key, pucKey);
	memcpy(pucIV, iv, sizeof(iv));
	sm4_ofb_encrypt(&sm4_key, pucIV, pucData, sizeof(pucData), pucCiphertext);

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// SDF_ImportKey

	ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, pucKey, sizeof(pucKey), &eccCipher);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, pucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiIPKIndex, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// encrypt
	memcpy(pucIV, iv, sizeof(iv));
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_OFB, pucIV, pucData, (unsigned int)sizeof(pucData), pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	// compare
	if ((size_t)uiEncDataLength != sizeof(pucData)) {
		error_print();
		return -1;
	}
	if (memcmp(pucEncData, pucCiphertext, sizeof(pucCiphertext)) != 0) {
		error_print();
		return -1;
	}

	// decrypt
	memcpy(pucIV, iv, sizeof(iv));
	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_OFB, pucIV, pucEncData, uiEncDataLength, pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	// compare
	if ((size_t)uiEncDataLength != sizeof(pucData)) {
		error_print();
		return -1;
	}
	if (memcmp(pucEncData, pucData, sizeof(pucData)) != 0) {
		error_print();
		return -1;
	}

	// cleanup
	ret = SDF_DestroyKey(hSessionHandle, hKeyHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_CloseSession(hSessionHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}
	ret = SDF_CloseDevice(hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

static int test_SDF_Encrypt(int kek)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = (unsigned int)kek;
	unsigned char pucKey[64];
	unsigned int uiKeyLength = (unsigned int)sizeof(pucKey);
	unsigned char ucIV[16] = {1};
	unsigned char pucIV[16];
	unsigned char pucData[32];
	unsigned int uiDataLength = sizeof(pucData);
	unsigned char pucEncData[128];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucDecData[128];
	unsigned int uiDecDataLength = (unsigned int)sizeof(pucDecData);
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_CBC, uiKEKIndex, pucKey, &uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// encrypt and decrypt
	memcpy(pucIV, ucIV, 16);
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucData, uiDataLength, pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// check SDF_Encrypt do Padding or Not
	/*
	if (uiEncDataLength == uiDataLength) {
		error_puts("SDF implement SM4-CBC without padding");
	} else if (uiEncDataLength == uiDataLength + 16) {
		error_puts("SDF implement SM4-CBC with padding");
	} else {
		error_print();
		return -1;
	}
	*/

	memcpy(pucIV, ucIV, 16);
	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucEncData, uiEncDataLength, pucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// check
	if (uiDecDataLength != uiDataLength) {
		error_print();
		return -1;
	}
	if (memcmp(pucDecData, pucData, uiDataLength) != 0) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// FIXME: correctness is not tested!			
static int test_SDF_CalculateMAC(int kek)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiHMACKeyBits = 256;
	unsigned int uiKeyEncAlgID = SGD_SM4_CBC;
	unsigned int uiKEKIndex = (unsigned int)kek;
	unsigned char ucEncedKey[256];
	unsigned int uiEncedKeyLength = (unsigned int)sizeof(ucEncedKey);
	unsigned int uiMACAlgID = SGD_SM3;
	unsigned char ucData[50]; // FIXME: put real test data			
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucMAC[32];
	unsigned int uiMACLength = (unsigned int)sizeof(ucMAC);
	int ret;


	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// FIXME: can not test correctness here		
	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiHMACKeyBits, uiKeyEncAlgID, uiKEKIndex, ucEncedKey, &uiEncedKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyWithKEK returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_CalculateMAC(hSessionHandle, hKeyHandle, uiMACAlgID, NULL, ucData, uiDataLength, ucMAC, &uiMACLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_CalculateMAC return 0x%X\n", ret);
		return -1;
	}

	if (uiMACLength != 32) {
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_InternalSign_ECC(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *ucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	unsigned char ucData[32] = { 1,2,3,4 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCSignature eccSignature;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// sign
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_InternalSign_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// verify
	ret = SDF_InternalVerify_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;

}

static int test_SDF_InternalEncrypt_ECC(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *ucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	unsigned char ucData[48] = { 1,2,3,4 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCCipher eccCipher;
	unsigned char ucDecData[256];
	unsigned int uiDecDataLength;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// encrypt
	ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, ucData, uiDataLength, &eccCipher);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_InternalEncrypt_ECC return 0x%X\n", ret);
		return -1;
	}


	// decrypt
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_InternalDecrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, &eccCipher, ucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_InternalDecrypt_ECC return 0x%X\n", ret);
		return -1;
	}

	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ReleasePrivateKeyAccessRight return 0x%X\n", ret);
		return -1;
	}

	// check
	if (uiDecDataLength != uiDataLength) {
		fprintf(stderr, "Error: invalid uiDecDataLength\n");
		return -1;
	}
	if (memcmp(ucDecData, ucData, uiDataLength) != 0) {
		fprintf(stderr, "Error: invalid ucDecData\n");
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int speed_SDF_Encrypt_SM4_CBC(int kek)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = (unsigned int)kek;
	unsigned char ucWrappedKey[64];
	unsigned int uiWrappedKeyLength = (unsigned int)sizeof(ucWrappedKey);
	unsigned char ucIV[16] = {0};
	unsigned char ucData[4096] = {0};
	unsigned int uiLength;
	int ret;
	clock_t begin, end;
	double seconds;
	size_t i;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_CBC, uiKEKIndex, ucWrappedKey, &uiWrappedKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseSession(hSessionHandle);
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	begin = clock();
	for (i = 0; i < 16; i++) {
		ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucData, sizeof(ucData), ucData, &uiLength);
		if (ret != SDR_OK) {
			(void)SDF_DestroyKey(hSessionHandle, hKeyHandle);
			(void)SDF_CloseSession(hSessionHandle);
			(void)SDF_CloseDevice(hDeviceHandle);
			error_print();
			return -1;
		}
	}
	for (i = 0; i < 4096; i++) {
		(void)SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucData, sizeof(ucData), ucData, &uiLength);
	}
	end = clock();
	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;

	(void)SDF_DestroyKey(hSessionHandle, hKeyHandle);
	(void)SDF_CloseSession(hSessionHandle);
	(void)SDF_CloseDevice(hDeviceHandle);

	printf("%s: %f MiB per second\n", __FUNCTION__, 16/seconds);
	return 1;
}

static int speed_SDF_Decrypt_SM4_CBC(int kek)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = (unsigned int)kek;
	unsigned char ucWrappedKey[64];
	unsigned int uiWrappedKeyLength = (unsigned int)sizeof(ucWrappedKey);
	unsigned char ucIV[16] = {0};
	unsigned char ucData[4096] = {0};
	unsigned int uiLength;
	clock_t begin, end;
	double seconds;
	int i, ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_CBC, uiKEKIndex, ucWrappedKey, &uiWrappedKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseSession(hSessionHandle);
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	begin = clock();
	for (i = 0; i < 16; i++) {
		ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucData, sizeof(ucData), ucData, &uiLength);
		if (ret != SDR_OK) {
			(void)SDF_DestroyKey(hSessionHandle, hKeyHandle);
			(void)SDF_CloseSession(hSessionHandle);
			(void)SDF_CloseDevice(hDeviceHandle);
			error_print();
			return -1;
		}
	}
	for (i = 16; i < 4096; i++) {
		(void)SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucData, sizeof(ucData), ucData, &uiLength);
	}
	end = clock();
	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;

	(void)SDF_DestroyKey(hSessionHandle, hKeyHandle);
	(void)SDF_CloseSession(hSessionHandle);
	(void)SDF_CloseDevice(hDeviceHandle);

	printf("%s: %f MiB per second\n", __FUNCTION__, 16/seconds);
	return 1;
}

static int speed_SDF_Hash(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned char ucData[4096] = {0};
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucHash[32];
	unsigned int uiHashLength;
	clock_t begin, end;
	double seconds;
	int i, ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	begin = clock();
	ret = SDF_HashInit(hSessionHandle, SGD_SM3, NULL, NULL, 0);
	if (ret != SDR_OK) {
		(void)SDF_CloseSession(hSessionHandle);
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}
	for (i = 0; i < 16; i++) {
		ret = SDF_HashUpdate(hSessionHandle, ucData, uiDataLength);
		if (ret != SDR_OK) {
			(void)SDF_CloseSession(hSessionHandle);
			(void)SDF_CloseDevice(hDeviceHandle);
			error_print();
			return -1;
		}
	}
	for (i = 16; i < 4096; i++) {
		(void)SDF_HashUpdate(hSessionHandle, ucData, uiDataLength);
	}
	end = clock();
	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;

	(void)SDF_HashFinal(hSessionHandle, ucHash, &uiHashLength);
	(void)SDF_CloseSession(hSessionHandle);
	(void)SDF_CloseDevice(hDeviceHandle);

	printf("%s: %f MiB per second\n", __FUNCTION__, 16/seconds);
	return 1;
}

static int speed_SDF_GenerateKeyPair_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey;
	ECCrefPrivateKey eccPrivateKey;
	clock_t begin, end;
	double seconds;
	int i, ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	begin = clock();
	for (i = 0; i < 16; i++) {
		ret = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &eccPublicKey, &eccPrivateKey);
		if (ret != SDR_OK) {
			(void)SDF_CloseSession(hSessionHandle);
			(void)SDF_CloseDevice(hDeviceHandle);
			error_print();
			return -1;
		}
	}
	for (i = 0; i < 4096; i++) {
		(void)SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &eccPublicKey, &eccPrivateKey);
	}
	end = clock();
	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;

	(void)SDF_CloseSession(hSessionHandle);
	(void)SDF_CloseDevice(hDeviceHandle);

	printf("%s: %f keypairs generated per second\n", __FUNCTION__, 4096/seconds);
	return 1;
}

// XXX: speed of `SDF_InternalSign_ECC` should be compared with `sm2_do_sign`
static int speed_SDF_InternalSign_ECC(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *ucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	unsigned char ucData[SM3_DIGEST_SIZE] = {1}; // XXX: `SDF_InternalSign_ECC` can only handle 32 bytes digest
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCSignature eccSignature;
	clock_t begin, end;
	double seconds;
	int i, ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		(void)SDF_CloseSession(hSessionHandle);
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	begin = clock();
	for (i = 0; i < 16; i++) {
		ret = SDF_InternalSign_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
		if (ret != SDR_OK) {
			(void)SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
			(void)SDF_CloseSession(hSessionHandle);
			(void)SDF_CloseDevice(hDeviceHandle);
			error_print();
			return -1;
		}
	}
	for (i = 16; i < 4096; i++) {
		(void)SDF_InternalSign_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	}
	end = clock();
	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;

	(void)SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	(void)SDF_CloseSession(hSessionHandle);
	(void)SDF_CloseDevice(hDeviceHandle);

	printf("%s: %f signs per second\n", __FUNCTION__, 4096/seconds);
	return 1;
}

// XXX: speed of `SDF_InternalVerify_ECC` should be compared with `sm2_do_verify`
static int speed_SDF_InternalVerify_ECC(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *ucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	unsigned char ucData[32] = {1}; // XXX: `SDF_InternalVerify_ECC` can only handle 32 bytes digest
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCSignature eccSignature;
	clock_t begin, end;
	double seconds;
	int i, ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		(void)SDF_CloseSession(hSessionHandle);
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}
	ret = SDF_InternalSign_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	if (ret != SDR_OK) {
		(void)SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
		(void)SDF_CloseSession(hSessionHandle);
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}
	(void)SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);

	begin = clock();
	for (i = 0; i < 16; i++) {
		ret = SDF_InternalVerify_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
		if (ret != SDR_OK) {
			(void)SDF_CloseSession(hSessionHandle);
			(void)SDF_CloseDevice(hDeviceHandle);
			error_print();
			return -1;
		}
	}
	for (i = 16; i < 4096; i++) {
		(void)SDF_InternalVerify_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	}
	end = clock();
	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;

	(void)SDF_CloseSession(hSessionHandle);
	(void)SDF_CloseDevice(hDeviceHandle);

	printf("%s: %f verifications per second\n", __FUNCTION__, 4096/seconds);
	return 1;
}

static int speed_SDF_InternalEncrypt_ECC(int key)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char ucData[32] = {1}; // same as sm2_enctest.c
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCCipher eccCipher;
	unsigned char ucDecData[256];
	unsigned int uiDecDataLength;
	clock_t begin, end;
	double seconds;
	int i, ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	begin = clock();
	for (i = 0; i < 16; i++) {
		ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, ucData, uiDataLength, &eccCipher);
		if (ret != SDR_OK) {
			(void)SDF_CloseSession(hSessionHandle);
			(void)SDF_CloseDevice(hDeviceHandle);
			error_print();
			return -1;
		}
	}
	for (i = 16; i < 4096; i++) {
		(void)SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, ucData, uiDataLength, &eccCipher);
	}
	end = clock();
	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;

	(void)SDF_CloseSession(hSessionHandle);
	(void)SDF_CloseDevice(hDeviceHandle);

	printf("%s: %f encryptions per second\n", __FUNCTION__, 4096/seconds);
	return 1;
}

static int speed_SDF_InternalDecrypt_ECC(int key, char *pass)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = (unsigned int)key;
	unsigned char *ucPassword = (unsigned char *)pass;
	unsigned int uiPwdLength = (unsigned int)strlen(pass);
	unsigned char ucData[32] = {1}; // same as sm2_enctest.c
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCCipher eccCipher;
	unsigned char ucDecData[256];
	unsigned int uiDecDataLength;
	clock_t begin, end;
	double seconds;
	int i, ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, ucData, uiDataLength, &eccCipher);
	if (ret != SDR_OK) {
		(void)SDF_CloseSession(hSessionHandle);
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}

	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		(void)SDF_CloseSession(hSessionHandle);
		(void)SDF_CloseDevice(hDeviceHandle);
		error_print();
		return -1;
	}


	begin = clock();
	for (i = 0; i < 16; i++) {
		ret = SDF_InternalDecrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, &eccCipher, ucDecData, &uiDecDataLength);
		if (ret != SDR_OK) {
			(void)SDF_CloseSession(hSessionHandle);
			(void)SDF_CloseDevice(hDeviceHandle);
			error_print();
			return -1;
		}
	}
	for (i = 16; i < 4096; i++) {
		(void)SDF_InternalDecrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, &eccCipher, ucDecData, &uiDecDataLength);
	}
	end = clock();
	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;

	(void)SDF_CloseSession(hSessionHandle);
	(void)SDF_CloseDevice(hDeviceHandle);

	printf("%s: %f decryptions per second\n", __FUNCTION__, 4096/seconds);
	return 1;
}

int sdftest_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *so_path = NULL;
	int kek = 1;
	int key = 1;
	char *pass = NULL;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-lib")) {
			if (--argc < 1) goto bad;
			so_path = *(++argv);
		} else if (!strcmp(*argv, "-kek")) {
			if (--argc < 1) goto bad;
			kek = atoi(*(++argv));
			if (kek < 1 || kek > 4096) {
				fprintf(stderr, "gmssl %s: `-kek` invalid index\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			key = atoi(*(++argv));
			if (key < 0 || key > 4096) {
				fprintf(stderr, "gmssl %s: `-key` invalid index\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else {
			fprintf(stderr, "gmssl %s: illegal option `%s`\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!so_path) {
		fprintf(stderr, "gmssl %s: option `-lib` missing\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: option `-pass` missing\n", prog);
		goto end;
	}

	if (SDF_LoadLibrary(so_path, NULL) != SDR_OK) {
		error_print();
		goto err;
	}

	if (test_SDF_GenerateRandom() != 1) goto err;
	if (test_SDF_Hash() != 1) goto err;
	if (test_SDF_Hash_Z() != 1) goto err;
	if (test_SDF_GenerateKeyWithKEK(kek) != 1) goto err;
	if (test_SDF_CalculateMAC(kek) != 1) goto err;
	if (test_SDF_Encrypt(kek) != 1) goto err;
	if (test_SDF_Encrypt_SM4_CBC(key, pass) != 1) goto err;
	if (test_SDF_Encrypt_SM4_ECB(key, pass) != 1) goto err;
#if ENABLE_SM4_CFB
	if (test_SDF_Encrypt_SM4_CFB(key, pass) != 1) goto err;
#endif
#if ENABLE_SM4_OFB
	if (test_SDF_Encrypt_SM4_OFB(key, pass) != 1) goto err;
#endif
	if (test_SDF_GenerateKeyPair_ECC() != 1) goto err;
	if (test_SDF_ExportSignPublicKey_ECC(key) != 1) goto err;
	if (test_SDF_ExportEncPublicKey_ECC(key) != 1) goto err;
	if (test_SDF_GenerateKeyWithEPK_ECC() != 1) goto err;
	if (test_SDF_GenerateKeyWithIPK_ECC(key, pass) != 1) goto err;
	if (test_SDF_ExternalVerify_ECC() != 1) goto err;
	if (test_SDF_ExternalEncrypt_ECC() != 1) goto err; //FIXME: test this before any ECCCipher used
	if (test_SDF_InternalSign_ECC(key, pass) != 1) goto err;
	if (test_SDF_InternalEncrypt_ECC(key, pass) != 1) goto err;

#if ENABLE_TEST_SPEED
	if (speed_SDF_Hash() != 1) goto err;
	if (speed_SDF_Encrypt_SM4_CBC(kek) != 1) goto err;
	if (speed_SDF_Decrypt_SM4_CBC(kek) != 1) goto err;
	if (speed_SDF_GenerateKeyPair_ECC() != 1) goto err;
	if (speed_SDF_InternalSign_ECC(key, pass) != 1) goto err;
	if (speed_SDF_InternalVerify_ECC(key, pass) != 1) goto err;
	if (speed_SDF_InternalEncrypt_ECC(key) != 1) goto err;
	if (speed_SDF_InternalDecrypt_ECC(key, pass) != 1) goto err;
#endif

	printf("%s all tests passed\n", __FILE__);
	return 0;

err:
	error_print();
	return 1;
end:
	return ret;
}
