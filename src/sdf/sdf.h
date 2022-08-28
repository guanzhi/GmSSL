/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * SDF API is a cryptographic API for PCI-E cards defined in standard
 * GM/T 0018-2012: Interface Specifications of Cryptography Device Application
 *
 * Note: this header file follows the specification of GM/T 0018-2012. As we
 * know, some vendors provide header files with some differences, especially
 * the definations of data structures. So be sure to check the file provided by
 * vendors and compare with this one.
 *
 * The implementations of SDF API from different vendors might have different
 * behaviors on the same function. The comments in this file will show
 * information and warnings on these issues. If the application developer use
 * the GmSSL implementation, see `crypto/gmapi/sdf_lcl.h` for more information.
 */

#ifndef HEADER_SDF_H
#define HEADER_SDF_H

#include <stdio.h>
#include "../sgd.h"


#ifdef __cplusplus
extern "C" {
#endif



#pragma pack(1)
typedef struct DeviceInfo_st {
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];	/* 8-char date +
					 * 3-char batch num +
					 * 5-char serial num
					 */
	unsigned int DeviceVersion;
	unsigned int StandardVersion;
	unsigned int AsymAlgAbility[2];	/* AsymAlgAbility[0] = algors
					 * AsymAlgAbility[1] = modulus lens
					 */
	unsigned int SymAlgAbility;
	unsigned int HashAlgAbility;
	unsigned int BufferSize;
} DEVICEINFO;

typedef struct RSArefPublicKey_st {
	unsigned int bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
	unsigned int bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

typedef struct ECCrefPublicKey_st {
	unsigned int bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st {
    unsigned int  bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st {
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	unsigned int L;
	unsigned char C[1];
} ECCCipher;

typedef struct ECCSignature_st {
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

typedef struct SDF_ENVELOPEDKEYBLOB {
	unsigned long Version;
	unsigned long ulSymmAlgID;
	ECCCipher ECCCipehrBlob;
	ECCrefPublicKey PubKey;
	unsigned char cbEncryptedPrivKey[64];
} EnvelopedKeyBlob, *PEnvelopedKeyBlob;
#pragma pack()

int SDF_OpenDevice(
	void **phDeviceHandle);

int SDF_CloseDevice(
	void *hDeviceHandle);

int SDF_OpenSession(
	void *hDeviceHandle,
	void **phSessionHandle);

int SDF_CloseSession(
	void *hSessionHandle);

int SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo);

int SDF_GenerateRandom(
	void *hSessionHandle,
	unsigned int uiLength,
	unsigned char *pucRandom);

int SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength);

int SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex);

int SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey);

int SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey);

int SDF_GenerateKeyPair_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey);

int SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle);

int SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle);

int SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle);

int SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength);

int SDF_ExportSignPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey);

int SDF_ExportEncPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey);

int SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int  uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey);

int SDF_GenerateKeyWithIPK_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	ECCCipher *pucKey,
	void **phKeyHandle);

int SDF_GenerateKeyWithEPK_ECC(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	void **phKeyHandle);

int SDF_ImportKeyWithISK_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle);

int SDF_GenerateAgreementDataWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	void **phAgreementHandle);

int SDF_GenerateKeyWithECC(
	void *hSessionHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	void **phKeyHandle);

int SDF_GenerateAgreementDataAndKeyWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void **phKeyHandle);

int SDF_ExchangeDigitEnvelopeBaseOnECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut);

int SDF_GenerateKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle);

int SDF_ImportKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle);

int SDF_DestroyKey(
	void *hSessionHandle,
	void *hKeyHandle);

int SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength);

int SDF_InternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength);

int SDF_InternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength);

int SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature);

int SDF_InternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature);

int SDF_InternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature);

int SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData);

int SDF_InternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiAlgID,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData);

int SDF_InternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiAlgID,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *uiDataLength);

int SDF_Encrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength);

int SDF_Decrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength);

int SDF_CalculateMAC(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucMAC,
	unsigned int *puiMACLength);

int SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength);

int SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength);

int SDF_HashFinal(void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength);

int SDF_CreateFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen, /* max 128-byte */
	unsigned int uiFileSize);

int SDF_ReadFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int *puiReadLength,
	unsigned char *pucBuffer);

int SDF_WriteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int uiWriteLength,
	unsigned char *pucBuffer);

int SDF_DeleteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen);

#define SDR_OK			0x0
#define SDR_BASE		0x01000000
#define SDR_UNKNOWERR		(SDR_BASE + 0x00000001)
#define SDR_NOTSUPPORT		(SDR_BASE + 0x00000002)
#define SDR_COMMFAIL		(SDR_BASE + 0x00000003)
#define SDR_HARDFAIL		(SDR_BASE + 0x00000004)
#define SDR_OPENDEVICE		(SDR_BASE + 0x00000005)
#define SDR_OPENSESSION		(SDR_BASE + 0x00000006)
#define SDR_PARDENY		(SDR_BASE + 0x00000007)
#define SDR_KEYNOTEXIST		(SDR_BASE + 0x00000008)
#define SDR_ALGNOTSUPPORT	(SDR_BASE + 0x00000009)
#define SDR_ALGMODNOTSUPPORT	(SDR_BASE + 0x0000000A)
#define SDR_PKOPERR		(SDR_BASE + 0x0000000B)
#define SDR_SKOPERR		(SDR_BASE + 0x0000000C)
#define SDR_SIGNERR		(SDR_BASE + 0x0000000D)
#define SDR_VERIFYERR		(SDR_BASE + 0x0000000E)
#define SDR_SYMOPERR		(SDR_BASE + 0x0000000F)
#define SDR_STEPERR		(SDR_BASE + 0x00000010)
#define SDR_FILESIZEERR		(SDR_BASE + 0x00000011)
#define SDR_FILENOEXIST		(SDR_BASE + 0x00000012)
#define SDR_FILEOFSERR		(SDR_BASE + 0x00000013)
#define SDR_KEYTYPEERR		(SDR_BASE + 0x00000014)
#define SDR_KEYERR		(SDR_BASE + 0x00000015)
#define SDR_ENCDATAERR		(SDR_BASE + 0x00000016)
#define SDR_RANDERR		(SDR_BASE + 0x00000017)
#define SDR_PRKRERR		(SDR_BASE + 0x00000018)
#define SDR_MACERR		(SDR_BASE + 0x00000019)
#define SDR_FILEEXSITS		(SDR_BASE + 0x0000001A)
#define SDR_FILEWERR		(SDR_BASE + 0x0000001B)
#define SDR_NOBUFFER		(SDR_BASE + 0x0000001C)
#define SDR_INARGERR		(SDR_BASE + 0x0000001D)
#define SDR_OUTARGERR		(SDR_BASE + 0x0000001E)


#ifdef __cplusplus
}
#endif
#endif
