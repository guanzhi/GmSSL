/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/skf.h>

static char *hDeviceHandle = "hDeviceHandle";
static char *hApplication = "hApplication";
static char *hContainer = "hContainer";
static char *hAgreementHandle = "AgreementHandle";
static char *hKeyHandle = "KeyHandle";
static char *hHashHandle = "HashHandle";
static char *hMacHandle = "MacHandle";

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
	char *dev_list = "dev1\0dev2\0";
	if (!szNameList || !pulSize) {
		return SAR_INVALIDPARAMERR;
	}
	strcpy((char *)szNameList, dev_list);
	*pulSize = sizeof(dev_list);
	return SAR_OK;
}

ULONG DEVAPI SKF_ConnectDev(
	LPSTR szName,
	DEVHANDLE *phDev)
{
	if (!phDev) {
		return SAR_INVALIDPARAMERR;
	}
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
	*pulDevState = 0;
	return SAR_OK;
}

ULONG DEVAPI SKF_SetLabel(
	DEVHANDLE hDev,
	LPSTR szLabel)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevInfo(
	DEVHANDLE hDev,
	DEVINFO *pDevInfo)
{
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
	if (!pbData || !pulDataLen) {
		return SAR_INVALIDPARAMERR;
	}
	memcpy(pbData, pbCommand, ulCommandLen);
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
	if (!pulRetryCount) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!pulMaxRetryCount || !pulRemainRetryCount || !pbDefaultPin) {
		return SAR_INVALIDPARAMERR;
	}
	*pulMaxRetryCount = 100;
	*pulRemainRetryCount = 100;
	*pbDefaultPin = 0;
	return SAR_OK;
}

ULONG DEVAPI SKF_VerifyPIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount)
{
	if (!pulRetryCount) {
		return SAR_INVALIDPARAMERR;
	}
	*pulRetryCount = 100;
	return SAR_OK;
}

ULONG DEVAPI SKF_UnblockPIN(
	HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount)
{
	if (!pulRetryCount) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!phApplication) {
		return SAR_INVALIDPARAMERR;
	}
	*phApplication = hApplication;
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize)
{
	char *app_list = "app1\0app2\0";
	if (!szAppName || !pulSize) {
		return SAR_INVALIDPARAMERR;
	}
	strcpy((char *)szAppName, app_list);
	*pulSize = strlen(app_list);
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
	if (!phApplication) {
		return SAR_INVALIDPARAMERR;
	}
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
	char *file_list = "file1.txt\0file2.txt\0";
	if (!pulSize) {
		return SAR_INVALIDPARAMERR;
	}
	strcpy((char *)szFileList, file_list);
	*pulSize = strlen(file_list);
	return SAR_OK;
}

ULONG DEVAPI SKF_GetFileInfo(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo)
{
	if (!pFileInfo) {
		return SAR_INVALIDPARAMERR;
	}
	//TODO: set pFileInfo;
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
	if (!pbOutData || !pulOutLen) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!phContainer) {
		return SAR_INVALIDPARAMERR;
	}
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
	char *cont_list = "container1\0container2\0";
	if (!szContainerName || !pulSize) {
		return SAR_INVALIDPARAMERR;
	}
	strcpy((char *)szContainerName, cont_list);
	*pulSize = strlen(cont_list);
	return SAR_OK;
}

ULONG DEVAPI SKF_OpenContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	if (!phContainer) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!pulContainerType) {
		return SAR_INVALIDPARAMERR;
	}
	*pulContainerType = 0;
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
	if (!pbCert || !pulCertLen) {
		return SAR_INVALIDPARAMERR;
	}
	memset(pbCert, 'c', 512);
	*pulCertLen = 512;
	return SAR_OK;
}

ULONG DEVAPI SKF_ExportPublicKey(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen)
{
	if (!pbBlob || !pulBlobLen) {
		return SAR_INVALIDPARAMERR;
	}
	*pulBlobLen = 1024;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenRandom(
	DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen)
{
	if (!pbRandom) {
		return SAR_INVALIDPARAMERR;
	}
	memset(pbRandom, 'r', ulRandomLen);
	return SAR_OK;
}

ULONG DEVAPI SKF_GenExtRSAKey(
	DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob)
{
	if (!pBlob) {
		return SAR_INVALIDPARAMERR;
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_GenRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob)
{
	if (!pBlob) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!pbSignature || !pulSignLen) {
		return SAR_INVALIDPARAMERR;
	}
	*pulSignLen = 256;
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
	HANDLE *phSessionKey);

ULONG DEVAPI SKF_ExtRSAPubKeyOperation(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	if (!pbOutput || !pulOutputLen) {
		return SAR_INVALIDPARAMERR;
	}
	*pulOutputLen = 256;
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
	if (!pbOutput || !pulOutputLen) {
		return SAR_INVALIDPARAMERR;
	}
	*pulOutputLen = 256;
	return SAR_OK;
}

ULONG DEVAPI SKF_GenECCKeyPair(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob)
{
	if (!pBlob) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!pSignature) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!phSessionKey) {
		return SAR_INVALIDPARAMERR;
	}
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
	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCSign(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	if (!pSignature) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!phAgreementHandle) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!phKeyHandle) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!phKeyHandle) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!phKey) {
		return SAR_INVALIDPARAMERR;
	}
	*phKey = hKeyHandle;
	return SAR_OK;
}

ULONG DEVAPI SKF_SetSymmKey(
	DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey)
{
	if (!phKey) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!pbData || !pbEncryptedData || !pulEncryptedLen) {
		return SAR_INVALIDPARAMERR;
	}
	memcpy(pbEncryptedData, pbData, ulDataLen);
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
	if (!pbData || !pbEncryptedData || !pulEncryptedLen) {
		return SAR_INVALIDPARAMERR;
	}
	memcpy(pbEncryptedData, pbData, ulDataLen);
	*pulEncryptedLen = ulDataLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptFinal(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen)
{
	if (!pbEncryptedData || !pulEncryptedDataLen) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!pbEncryptedData || !pbData || !pulDataLen) {
		return SAR_INVALIDPARAMERR;
	}
	memcpy(pbData, pbEncryptedData, ulEncryptedLen);
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
	if (!pbEncryptedData || !pbData || !pulDataLen) {
		return SAR_INVALIDPARAMERR;
	}
	memcpy(pbData, pbEncryptedData, ulEncryptedLen);
	*pulDataLen = ulEncryptedLen;
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptFinal(
	HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen)
{
	if (!pulDecryptedDataLen) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!phHash) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!pbHashData || !pulHashLen) {
		return SAR_INVALIDPARAMERR;
	}
	memset(pbHashData, 'h', 32);
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
	if (!pbHashData || !pulHashLen) {
		return SAR_INVALIDPARAMERR;
	}
	memset(pbHashData, 'h', 32);
	*pulHashLen = 32;
	return SAR_OK;
}

ULONG DEVAPI SKF_MacInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac)
{
	if (!phMac) {
		return SAR_INVALIDPARAMERR;
	}
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
	if (!pbMacData || !pulMacLen) {
		return SAR_INVALIDPARAMERR;
	}
	memset(pbMacData, 'm', 32);
	*pulMacLen = 32;
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
	if (!pbMacData || !pulMacDataLen) {
		return SAR_INVALIDPARAMERR;
	}
	memset(pbMacData, 'm', 32);
	*pulMacDataLen = 32;
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseHandle(
	HANDLE hHandle)
{
	return SAR_OK;
}
