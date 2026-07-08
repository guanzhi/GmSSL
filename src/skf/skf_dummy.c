/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"
#include "skf_ext.h"

static char *hDeviceHandle	= "hDeviceHandle";
static char *hApplication	= "hApplication";
static char *hContainer		= "hContainer";
static char *hAgreementHandle	= "AgreementHandle";
static char *hKeyHandle		= "KeyHandle";
static char *hHashHandle	= "HashHandle";
static char *hMacHandle		= "MacHandle";

static char *sm2cert_pemstr = "-----BEGIN CERTIFICATE-----\n"
"MIICHDCCAcOgAwIBAgIBIzAKBggqgRzPVQGDdTBRMQswCQYDVQQGEwJDTjELMAkG\n"
"A1UECAwCQkoxCzAJBgNVBAcMAkJKMQwwCgYDVQQKDANQS1UxCzAJBgNVBAsMAkNT\n"
"MQ0wCwYDVQQDDARHTUNBMB4XDTE3MDYxODA4NDMyN1oXDTE4MDYxODA4NDMyN1ow\n"
"UzELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAkJKMQwwCgYDVQQKDANQS1UxDTALBgNV\n"
"BAsMBFNpZ24xGjAYBgNVBAMMEWNsaWVudEBwa3UuZWR1LmNuMFkwEwYHKoZIzj0C\n"
"AQYIKoEcz1UBgi0DQgAEzsZMPwnZFCD75xb8IT02XJCyOShTaEL8o/iQ6ksmG2Ce\n"
"MKSPGUcRtlSAU/1hQcFv4j59Csdr03lXiDRfdD72AKOBiTCBhjAJBgNVHRMEAjAA\n"
"MAsGA1UdDwQEAwIHgDAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQg\n"
"Q2VydGlmaWNhdGUwHQYDVR0OBBYEFHbwURtb+xQrmxma7NnHe300//yuMB8GA1Ud\n"
"IwQYMBaAFMJhPpIHIHmrPQdEsiK3SaZ60qiPMAoGCCqBHM9VAYN1A0cAMEQCIBhO\n"
"uu7R3uMpVcy2r+t/OGYRs7JpQMnNwhGy9dwTm+h8AiA9y4o0fkRLQfuT3RPClX2o\n"
"B5vw09GcQVzsjKxhGgHLZw==\n"
"-----END CERTIFICATE-----\n";

static char *sm2key_pemstr = "-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIAMbqE0bEEoGoicBgR0VISmbbuInWUBMQBtZBFVPD0+aoAoGCCqBHM9V\n"
"AYItoUQDQgAEzsZMPwnZFCD75xb8IT02XJCyOShTaEL8o/iQ6ksmG2CeMKSPGUcR\n"
"tlSAU/1hQcFv4j59Csdr03lXiDRfdD72AA==\n"
"-----END EC PRIVATE KEY-----\n";

#define devNameList "DummyDev1\0DummyDev2\0"
#define appNameList "App1\0App2\0"
#define fileNameList "File1\0File2\0"
#define containerNameList "Container1\0Container2\0"


ULONG DEVAPI SKF_WaitForDevEvent(
	LPSTR szDevName,
	ULONG *pulDevNameLen,
	ULONG *pulEvent)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_CancelWaitForDevEvent(
	void)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumDev(BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize)
{
	if (!pulSize)
		return SAR_INVALIDPARAMERR;
	*pulSize = sizeof(devNameList);
	if (szNameList)
		memcpy(szNameList, devNameList, sizeof(devNameList));
	return SAR_OK;
}

ULONG DEVAPI SKF_ConnectDev(
	LPSTR szName,
	DEVHANDLE *phDev)
{
	if (!phDev)
		return SAR_INVALIDPARAMERR;
	*phDev = hDeviceHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_DisConnectDev(
	DEVHANDLE hDev)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevState(
	LPSTR szDevName,
	ULONG *pulDevState)
{
	if (!pulDevState)
		return SAR_INVALIDPARAMERR;
	*pulDevState = SKF_DEV_STATE_PRESENT;
	return SAR_OK;
}

ULONG DEVAPI SKF_SetLabel(
	DEVHANDLE hDev,
	LPSTR szLabel)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevInfo(DEVHANDLE hDev,
	DEVINFO *pDevInfo)
{
	DEVINFO devInfo;

	if (!pDevInfo) {
		return SAR_INVALIDPARAMERR;
	}

	memset(&devInfo, 0, sizeof(devInfo));
	devInfo.Version.major = 1;
	devInfo.Version.minor = 0;
	strcpy((char *)&devInfo.Manufacturer, "GmSSL Project (http://gmssl.org)");
	strcpy((char *)&devInfo.Issuer, "GmSSL Project (http://gmssl.org)");
	strcpy((char *)&devInfo.Label, "SKF Dummy Token");
	strcpy((char *)&devInfo.SerialNumber, "1");
	devInfo.HWVersion.major = 1;
	devInfo.HWVersion.minor = 0;
	devInfo.FirmwareVersion.major = 1;
	devInfo.FirmwareVersion.minor = 0;
	devInfo.AlgSymCap = SGD_SM1|SGD_SSF33|SGD_SM4|SGD_ECB|SGD_CBC|SGD_CFB|SGD_OFB;
	devInfo.AlgAsymCap = SGD_RSA|SGD_SM2|SGD_PK_SIGN|SGD_PK_ENC;
	devInfo.AlgHashCap = SGD_SM3|SGD_SHA1|SGD_SHA256;
	devInfo.DevAuthAlgId = SGD_SM4_ECB;
	devInfo.TotalSpace = 64*1024;
	devInfo.FreeSpace = 32*1024;
	devInfo.MaxECCBufferSize = 100;
	devInfo.MaxBufferSize = 128;

	memcpy(pDevInfo, &devInfo, sizeof(DEVINFO));
	return SAR_OK;
}

ULONG DEVAPI SKF_LockDev(
	DEVHANDLE hDev,
	ULONG ulTimeOut)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_UnlockDev(
	DEVHANDLE hDev)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_Transmit(
	DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	if (!pulDataLen)
		return SAR_INVALIDPARAMERR;
	*pulDataLen = ulCommandLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_ChangeDevAuthKey(
	DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DevAuth(
	DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ChangePIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount)
{
	if (!pulRetryCount)
		return SAR_INVALIDPARAMERR;
	*pulRetryCount = 100;
	return SAR_OK;
}

LONG DEVAPI SKF_GetPINInfo(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin)
{
	if (!pulMaxRetryCount || !pulRemainRetryCount || !pbDefaultPin)
		return SAR_INVALIDPARAMERR;
	*pulMaxRetryCount = 100;
	*pulRemainRetryCount = 100;
	*pbDefaultPin = TRUE;
	return SAR_OK;
}

ULONG DEVAPI SKF_VerifyPIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount)
{
	if (!pulRetryCount)
		return SAR_INVALIDPARAMERR;
	*pulRetryCount = 100;
	return SAR_OK;
}

ULONG DEVAPI SKF_UnblockPIN(
	HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount)
{
	if (!pulRetryCount)
		return SAR_INVALIDPARAMERR;
	*pulRetryCount = 100;
	return SAR_OK;
}

ULONG DEVAPI SKF_ClearSecureState(
	HAPPLICATION hApplication)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_CreateApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	LPSTR szAdminPin,
	DWORD dwAdminPinRetryCount,
	LPSTR szUserPin,
	DWORD dwUserPinRetryCount,
	DWORD dwCreateFileRights,
	HAPPLICATION *phApplication)
{
	if (!phApplication)
		return SAR_INVALIDPARAMERR;
	*phApplication = hApplication;
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize)
{
	if (!pulSize)
		return SAR_INVALIDPARAMERR;
	*pulSize = sizeof(appNameList);
	if (szAppName)
		memcpy(szAppName, appNameList, sizeof(appNameList));
	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteApplication(
	DEVHANDLE hDev,
	LPSTR szAppName)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_OpenApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication)
{
	if (!phApplication)
		return SAR_INVALIDPARAMERR;
	*phApplication = hApplication;
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseApplication(
	HAPPLICATION hApplication)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_CreateFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumFiles(
	HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize)
{
	if (!pulSize)
		return SAR_INVALIDPARAMERR;
	*pulSize = sizeof(fileNameList);
	if (szFileList)
		memcpy(szFileList, fileNameList, sizeof(fileNameList));
	return SAR_OK;
}

ULONG DEVAPI SKF_GetFileInfo(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo)
{
	if (!pFileInfo)
		return SAR_INVALIDPARAMERR;
	strcpy((char *)pFileInfo->FileName, "FileName");
	pFileInfo->FileSize = 1024;
	pFileInfo->ReadRights = SECURE_ANYONE_ACCOUNT;
	return SAR_OK;
}

ULONG DEVAPI SKF_ReadFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	ULONG ulSize,
	BYTE *pbOutData,
	ULONG *pulOutLen)
{
	if (!pbOutData || !pulOutLen)
		return SAR_INVALIDPARAMERR;
	memset(pbOutData, 'x', ulSize);
	*pulOutLen = ulSize;
	return SAR_OK;
}

ULONG DEVAPI SKF_WriteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	BYTE *pbData,
	ULONG ulSize)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_CreateContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	if (!phContainer)
		return SAR_INVALIDPARAMERR;
	*phContainer = hContainer;
	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize)
{
	if (!pulSize)
		return SAR_INVALIDPARAMERR;
	*pulSize = sizeof(containerNameList);
	if (szContainerName)
		memcpy(szContainerName, containerNameList, sizeof(containerNameList));
	return SAR_OK;
}

ULONG DEVAPI SKF_OpenContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	if (!phContainer)
		return SAR_INVALIDPARAMERR;
	*phContainer = hContainer;
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseContainer(
	HCONTAINER hContainer)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GetContainerType(
	HCONTAINER hContainer,
	ULONG *pulContainerType)
{
	if (!pulContainerType)
		return SAR_INVALIDPARAMERR;
	*pulContainerType = SKF_CONTAINER_TYPE_ECC;
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportCertificate(
	HCONTAINER hContainer,
	BOOL bExportSignKey,
	BYTE *pbCert,
	ULONG ulCertLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ExportCertificate(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG *pulCertLen)
{
	*pulCertLen = (ULONG)strlen(sm2cert_pemstr);
	memcpy(pbCert, sm2cert_pemstr, *pulCertLen);

	return SAR_OK;
}

ULONG DEVAPI SKF_ExportPublicKey(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen)
{
	if (!pulBlobLen)
		return SAR_INVALIDPARAMERR;
	*pulBlobLen = 2048/8;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenRandom(
	DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GenExtRSAKey(
	DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob)
{
	if (!pBlob)
		return SAR_INVALIDPARAMERR;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob)
{
	if (!pBlob)
		return SAR_INVALIDPARAMERR;
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulSymAlgId,
	BYTE *pbWrappedKey,
	ULONG ulWrappedKeyLen,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_RSASignData(
	HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen)
{
	if (!pulSignLen)
		return SAR_INVALIDPARAMERR;
	*pulSignLen = 2048/8;
	return SAR_OK;
}

ULONG DEVAPI SKF_RSAVerify(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_RSAExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	RSAPUBLICKEYBLOB *pPubKey,
	BYTE *pbData,
	ULONG *pulDataLen,
	HANDLE *phSessionKey)
{
	if (!pulDataLen || !phSessionKey)
		return SAR_INVALIDPARAMERR;
	*pulDataLen = 2048/8;
	*phSessionKey = hKeyHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtRSAPubKeyOperation(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	if (!pulOutputLen)
		return SAR_INVALIDPARAMERR;
	*pulOutputLen = 2048/8;
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtRSAPriKeyOperation(
	DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	if (!pulOutputLen)
		return SAR_INVALIDPARAMERR;
	*pulOutputLen = 2048/8;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenECCKeyPair(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob)
{
	if (!pBlob)
		return SAR_INVALIDPARAMERR;
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportECCKeyPair(
	HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ECCSignData(
	HCONTAINER hContainer,
	BYTE *pbDigest,
	ULONG ulDigestLen,
	ECCSIGNATUREBLOB *pSignature)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ECCVerify(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ECCExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	ECCCIPHERBLOB *pData,
	HANDLE *phSessionKey)
{
	if (!phSessionKey)
		return SAR_INVALIDPARAMERR;
	*phSessionKey = hKeyHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCEncrypt(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCDecrypt(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	if (!pulPlainTextLen)
		return SAR_INVALIDPARAMERR;
	*pulPlainTextLen = 1;
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCSign(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	if (!pSignature)
		return SAR_INVALIDPARAMERR;
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCVerify(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GenerateAgreementDataWithECC(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phAgreementHandle)
{
	if (!phAgreementHandle)
		return SAR_INVALIDPARAMERR;
	*phAgreementHandle = hAgreementHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(
	HANDLE hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	BYTE *pbSponsorID,
	ULONG ulSponsorIDLen,
	HANDLE *phKeyHandle)
{
	if (!phKeyHandle)
		return SAR_INVALIDPARAMERR;
	*phKeyHandle = hKeyHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenerateKeyWithECC(
	HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phKeyHandle)
{
	if (!phKeyHandle)
		return SAR_INVALIDPARAMERR;
	*phKeyHandle = hKeyHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey)
{
	if (!phKey)
		return SAR_INVALIDPARAMERR;
	*phKey = hKeyHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_SetSymmKey(
	DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey)
{
	if (!phKey)
		return SAR_INVALIDPARAMERR;
	*phKey = hKeyHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM EncryptParam)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_Encrypt(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	if (!pulEncryptedLen)
		return SAR_INVALIDPARAMERR;
	*pulEncryptedLen = ulDataLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptUpdate(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	if (!pulEncryptedLen)
		return SAR_INVALIDPARAMERR;
	*pulEncryptedLen = ulDataLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptFinal(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen)
{
	if (!pulEncryptedDataLen)
		return SAR_INVALIDPARAMERR;
	*pulEncryptedDataLen = 0;
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_Decrypt(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	if (!pulDataLen)
		return SAR_INVALIDPARAMERR;
	*pulDataLen = ulEncryptedLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptUpdate(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	if (!pulDataLen)
		return SAR_INVALIDPARAMERR;
	*pulDataLen = ulEncryptedLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptFinal(
	HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen)
{
	if (!pulDecryptedDataLen)
		return SAR_INVALIDPARAMERR;
	*pulDecryptedDataLen = 0;
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestInit(
	DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phHash)
{
	if (!phHash)
		return SAR_INVALIDPARAMERR;
	*phHash = hHashHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_Digest(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen)
{
	if (!pulHashLen)
		return SAR_INVALIDPARAMERR;
	*pulHashLen = 32;
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestUpdate(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestFinal(
	HANDLE hHash,
	BYTE *pbHashData,
	ULONG *pulHashLen)
{
	if (!pulHashLen)
		return SAR_INVALIDPARAMERR;
	*pulHashLen = 32;
	return SAR_OK;
}

ULONG DEVAPI SKF_MacInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac)
{
	if (!phMac)
		return SAR_INVALIDPARAMERR;
	*phMac = hMacHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_Mac(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMacData,
	ULONG *pulMacLen)
{
	if (!pulMacLen)
		return SAR_INVALIDPARAMERR;
	*pulMacLen = 16;
	return SAR_OK;
}

ULONG DEVAPI SKF_MacUpdate(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_MacFinal(
	HANDLE hMac,
	BYTE *pbMacData,
	ULONG *pulMacDataLen)
{
	if (!pulMacDataLen)
		return SAR_INVALIDPARAMERR;
	*pulMacDataLen = 16;
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseHandle(
	HANDLE hHandle)
{
	return SAR_OK;
}
