/* engines/skf/skf_dummy.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/skf.h>


#define DEV_NAME		"skf-soft-token"
#define DEV_NAME_LIST		DEV_NAME"\0"
#define APP_NAME		"default-app"
#define APP_NAME_LIST		APP_NAME"\0"
#define CONTAINER_NAME		"container0"
#define CONTAINER_NAME_LIST	CONTAINER_NAME"\0"


#define PRINT_LOG() \
	printf("skf_dummy engine: %s() called\n", __FUNCTION__)

ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName,
	ULONG *pulDevNameLen, ULONG *pulEvent)
{
	PRINT_LOG();
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CancelWaitForDevEvent()
{
	PRINT_LOG();
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumDev(BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize)
{
	PRINT_LOG();
	*pulSize = sizeof(DEV_NAME_LIST);
	if (szNameList) {
		memcpy(szNameList, DEV_NAME_LIST, sizeof(DEV_NAME_LIST));
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_ConnectDev(LPSTR szName,
	DEVHANDLE *phDev)
{
	PRINT_LOG();
	*phDev = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_DisConnectDev(DEVHANDLE hDev)
{
	PRINT_LOG();
	if (hDev) {
		free(hDev);
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevState(LPSTR szDevName,
	ULONG *pulDevState)
{
	PRINT_LOG();
	if (!pulDevState) {
		return SAR_INVALIDPARAMERR;
	}
	*pulDevState = DEV_PRESENT_STATE;
	return SAR_OK;
}

ULONG DEVAPI SKF_SetLabel(DEVHANDLE hDev,
	LPSTR szLabel)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevInfo(DEVHANDLE hDev,
	DEVINFO *pDevInfo)
{
	DEVINFO devInfo;
	PRINT_LOG();

	bzero(&devInfo, sizeof(DEVINFO));
	devInfo.Version.major = 1;
	devInfo.Version.minor = 0;
	strcpy((char *)&devInfo.Manufacturer, "GmSSL Project (http://gmssl.org)");
	strcpy((char *)&devInfo.Issuer, "GmSSL Project (http://gmssl.org)");
	strcpy((char *)&devInfo.Label, "SKF Softotken");
	strcpy((char *)&devInfo.SerialNumber, "000001");
	devInfo.HWVersion.major = 1;
	devInfo.HWVersion.minor = 0;
	devInfo.FirmwareVersion.major = 1;
	devInfo.FirmwareVersion.minor = 0;
	devInfo.AlgSymCap = 0x0000041F;
	devInfo.AlgAsymCap = 0x00030700;
	devInfo.AlgHashCap = 0x00000007;
	devInfo.DevAuthAlgId = SGD_SM4_CBC;
	devInfo.TotalSpace = 0;
	devInfo.FreeSpace = 0;
	devInfo.MaxECCBufferSize = 0; /* FIXME: max inlen of ECC encrypt */
	devInfo.MaxBufferSize = 0; /* FIXME: max inlen of SM4 encrypt */

	memcpy(pDevInfo, &devInfo, sizeof(DEVINFO));
	return SAR_OK;
}

ULONG DEVAPI SKF_LockDev(DEVHANDLE hDev,
	ULONG ulTimeOut)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_UnlockDev(DEVHANDLE hDev)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	PRINT_LOG();
	*pulDataLen = ulCommandLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_ChangeDevAuthKey(DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_DevAuth(DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ChangePIN(HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount)
{
	PRINT_LOG();
	*pulRetryCount = 10;
	return SAR_OK;
}

LONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin)
{
	PRINT_LOG();
	*pulMaxRetryCount = 10;
	*pulRemainRetryCount = 10;
	*pbDefaultPin = 0;
	return SAR_OK;
}

ULONG DEVAPI SKF_VerifyPIN(HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount)
{
	PRINT_LOG();
	*pulRetryCount = 10;
	return SAR_OK;
}

ULONG DEVAPI SKF_UnblockPIN(HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount)
{
	PRINT_LOG();
	*pulRetryCount = 10;
	return SAR_OK;
}

ULONG DEVAPI SKF_ClearSecureState(HAPPLICATION hApplication)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_CreateApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	LPSTR szAdminPin,
	DWORD dwAdminPinRetryCount,
	LPSTR szUserPin,
	DWORD dwUserPinRetryCount,
	DWORD dwCreateFileRights,
	HAPPLICATION *phApplication)
{
	PRINT_LOG();
	*phApplication = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize)
{
	PRINT_LOG();
	if (!szAppName) {
		*pulSize = sizeof(APP_NAME_LIST);
		return SAR_OK;
	}
	if (*pulSize < sizeof(APP_NAME_LIST)) {
		return SAR_BUFFER_TOO_SMALL;
	}
	memcpy(szAppName, APP_NAME_LIST, sizeof(APP_NAME_LIST));
	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev,
	LPSTR szAppName)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication)
{
	PRINT_LOG();
	*phApplication = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication)
{
	PRINT_LOG();
	if (hApplication) {
		free(hApplication);
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_CreateFile(HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteFile(HAPPLICATION hApplication,
	LPSTR szFileName)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumFiles(HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize)
{
	PRINT_LOG();
	*pulSize = sizeof("File1\0");
	if (szFileList) {
		memcpy(szFileList, "File1\0", sizeof("File1\0"));
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_GetFileInfo(HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo)
{
	PRINT_LOG();
	bzero(pFileInfo, sizeof(*pFileInfo));
	return SAR_OK;
}

ULONG DEVAPI SKF_ReadFile(HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	ULONG ulSize,
	BYTE * pbOutData,
	ULONG *pulOutLen)
{
	PRINT_LOG();
	*pulOutLen = ulSize;
	return SAR_OK;
}

ULONG DEVAPI SKF_WriteFile(HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG  ulOffset,
	BYTE *pbData,
	ULONG ulSize)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_CreateContainer(HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	PRINT_LOG();
	*phContainer = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication,
	LPSTR szContainerName)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumContainer(HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize)
{
	PRINT_LOG();
	if (!pulSize) {
		return SAR_INVALIDPARAMERR;
	}
	if (!szContainerName) {
		*pulSize = sizeof(CONTAINER_NAME_LIST);
		return SAR_OK;
	}
	if (*pulSize < sizeof(CONTAINER_NAME_LIST)) {
		return SAR_BUFFER_TOO_SMALL;
	}
	memcpy(szContainerName, CONTAINER_NAME_LIST, sizeof(CONTAINER_NAME_LIST));
	return SAR_OK;
}

ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	PRINT_LOG();
	*phContainer = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer)
{
	PRINT_LOG();
	free(hContainer);
	return SAR_OK;
}

ULONG DEVAPI SKF_GetContainerType(HCONTAINER hContainer,
	ULONG *pulContainerType)
{
	PRINT_LOG();
	*pulContainerType = CONTAINER_TYPE_ECC;
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportCertificate(HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG ulCertLen)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE* pbCert,
	ULONG *pulCertLen)
{
	PRINT_LOG();
	*pulCertLen = 2048;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenRandom(DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_GenExtRSAKey(DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_GenRSAKeyPair(HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportRSAKeyPair(HCONTAINER hContainer,
	ULONG ulSymAlgId,
	BYTE *pbWrappedKey,
	ULONG ulWrappedKeyLen,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedDataLen)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_RSASignData(HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen)
{
	PRINT_LOG();
	*pulSignLen = 256;
	return SAR_OK;
}

ULONG DEVAPI SKF_RSAVerify(DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_RSAExportSessionKey(HCONTAINER hContainer,
	ULONG ulAlgId,
	RSAPUBLICKEYBLOB *pPubKey,
	BYTE *pbData,
	ULONG *pulDataLen,
	HANDLE *phSessionKey)
{
	PRINT_LOG();
	*pulDataLen = 100;
	*phSessionKey = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtRSAPubKeyOperation(DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	PRINT_LOG();
	*pulOutputLen = ulInputLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtRSAPriKeyOperation(DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	PRINT_LOG();
	*pulOutputLen = ulInputLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenECCKeyPair(HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportECCKeyPair(HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ECCSignData(HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ECCVerify(DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ECCExportSessionKey(HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	PECCCIPHERBLOB pData,
	HANDLE *phSessionKey)
{
	PRINT_LOG();
	*phSessionKey = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCEncrypt(DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCDecrypt(DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	PRINT_LOG();
	*pulPlainTextLen = sizeof(ECCCIPHERBLOB) + pCipherText->CipherLen - 1;
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCSign(DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCVerify(DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	PECCSIGNATUREBLOB pSignature)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_GenerateAgreementDataWithECC(HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phAgreementHandle)
{
	PRINT_LOG();
	*phAgreementHandle = malloc(256);
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(HANDLE hContainer,
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
	PRINT_LOG();
	*phKeyHandle = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_GenerateKeyWithECC(HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phKeyHandle)
{
	PRINT_LOG();
	*phKeyHandle = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_ExportPublicKey(HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen)
{
	PRINT_LOG();
	*pulBlobLen = 1024;
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportSessionKey(HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey)
{
	PRINT_LOG();
	*phKey = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_SetSymmKey(DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey)
{
	PRINT_LOG();
	*phKey = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptInit(HANDLE hKey,
	BLOCKCIPHERPARAM EncryptParam)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_Encrypt(HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	PRINT_LOG();
	*pulEncryptedLen = ulDataLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	PRINT_LOG();
	*pulEncryptedLen = ulDataLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptFinal(HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen)
{
	PRINT_LOG();
	*pulEncryptedDataLen = 0;
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptInit(HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_Decrypt(HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	PRINT_LOG();
	*pulDataLen = ulEncryptedLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	PRINT_LOG();
	*pulDataLen = ulEncryptedLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptFinal(HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen)
{
	PRINT_LOG();
	*pulDecryptedDataLen = 0;
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pucID,
	ULONG ulIDLen,
	HANDLE *phHash)
{
	PRINT_LOG();
	*phHash = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_Digest(HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen)
{
	PRINT_LOG();
	*pulHashLen = 32;
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestUpdate(HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestFinal(HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen)
{
	PRINT_LOG();
	*pulHashLen = 32;
	return SAR_OK;
}

ULONG DEVAPI SKF_MacInit(HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac)
{
	PRINT_LOG();
	*phMac = malloc(256);
	return SAR_OK;
}

ULONG DEVAPI SKF_Mac(HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMac,
	ULONG *pulMacLen)
{
	PRINT_LOG();
	*pulMacLen = 16;
	return SAR_OK;
}

ULONG DEVAPI SKF_MacUpdate(HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen)
{
	PRINT_LOG();
	return SAR_OK;
}

ULONG DEVAPI SKF_MacFinal(HANDLE hMac,
	BYTE *pbMac,
	ULONG *pulMacLen)
{
	PRINT_LOG();
	*pulMacLen = 16;
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseHandle(HANDLE handle)
{
	PRINT_LOG();
	if (handle) {
		free(handle);
	}
	return SAR_OK;
}

