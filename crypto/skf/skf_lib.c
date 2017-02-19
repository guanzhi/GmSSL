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
#include "internal/dso.h"
#include "skf_meth.h"

static SKF_METHOD *skf_method = NULL;

ULONG SKF_LoadLibrary(const char *so_path)
{
	DSO *dso = NULL;

	dso = DSO_load(NULL, so_path);
	SKF_METHOD_load_library(skf_method, dso);

	return SAR_OK;
}

ULONG SKF_UnloadLibrary(void)
{
	skf_method = NULL;
}

ULONG DEVAPI SKF_WaitForDevEvent(
	LPSTR szDevName,
	ULONG *pulDevNameLen,
	ULONG *pulEvent)
{
	if (skf_method->WaitForDevEvent) {
		return skf_method->WaitForDevEvent(
			szDevName,
			pulDevNameLen,
			pulEvent);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CancelWaitForDevEvent(
	void)
{
	if (skf_method->CancelWaitForDevEvent) {
		return skf_method->CancelWaitForDevEvent();
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumDev(
	BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize)
{
	if (skf_method->EnumDev) {
		return skf_method->EnumDev(
			bPresent,
			szNameList,
			pulSize);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ConnectDev(
	LPSTR szName,
	DEVHANDLE *phDev)
{
	if (skf_method->ConnectDev) {
		return skf_method->ConnectDev(
			szName,
			phDev);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DisConnectDev(
	DEVHANDLE hDev)
{
	if (skf_method->DisConnectDev) {
		return skf_method->DisConnectDev(
			hDev);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GetDevState(
	LPSTR szDevName,
	ULONG *pulDevState)
{
	if (skf_method->GetDevState) {
		return skf_method->GetDevState(
			szDevName,
			pulDevState);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_SetLabel(
	DEVHANDLE hDev,
	LPSTR szLabel)
{
	if (skf_method->SetLabel) {
		return skf_method->SetLabel(
			hDev,
			szLabel);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GetDevInfo(
	DEVHANDLE hDev,
	DEVINFO *pDevInfo)
{
	if (skf_method->GetDevInfo) {
		return skf_method->GetDevInfo(
			hDev,
			pDevInfo);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_LockDev(
	DEVHANDLE hDev,
	ULONG ulTimeOut)
{
	if (skf_method->LockDev) {
		return skf_method->LockDev(
			hDev,
			ulTimeOut);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_UnlockDev(
	DEVHANDLE hDev)
{
	if (skf_method->UnlockDev) {
		return skf_method->UnlockDev(
			hDev);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_Transmit(
	DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	if (skf_method->Transmit) {
		return skf_method->Transmit(
			hDev,
			pbCommand,
			ulCommandLen,
			pbData,
			pulDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ChangeDevAuthKey(
	DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen)
{
	if (skf_method->ChangeDevAuthKey) {
		return skf_method->ChangeDevAuthKey(
			hDev,
			pbKeyValue,
			ulKeyLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DevAuth(
	DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen)
{
	if (skf_method->DevAuth) {
		return skf_method->DevAuth(
			hDev,
			pbAuthData,
			ulLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ChangePIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount)
{
	if (skf_method->ChangePIN) {
		return skf_method->ChangePIN(
			hApplication,
			ulPINType,
			szOldPin,
			szNewPin,
			pulRetryCount);
	}
	return SAR_NOTSUPPORTYETERR;
}

LONG DEVAPI SKF_GetPINInfo(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin)
{
	if (skf_method->GetPINInfo) {
		return skf_method->GetPINInfo(
			hApplication,
			ulPINType,
			pulMaxRetryCount,
			pulRemainRetryCount,
			pbDefaultPin);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_VerifyPIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount)
{
	if (skf_method->VerifyPIN) {
		return skf_method->VerifyPIN(
			hApplication,
			ulPINType,
			szPIN,
			pulRetryCount);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_UnblockPIN(
	HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount)
{
	if (skf_method->UnblockPIN) {
		return skf_method->UnblockPIN(
			hApplication,
			szAdminPIN,
			szNewUserPIN,
			pulRetryCount);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ClearSecureState(
	HAPPLICATION hApplication)
{
	if (skf_method->ClearSecureState) {
		return skf_method->ClearSecureState(
			hApplication);
	}
	return SAR_NOTSUPPORTYETERR;
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
	if (skf_method->CreateApplication) {
		return skf_method->CreateApplication(
			hDev,
			szAppName,
			szAdminPin,
			dwAdminPinRetryCount,
			szUserPin,
			dwUserPinRetryCount,
			dwCreateFileRights,
			phApplication);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize)
{
	if (skf_method->EnumApplication) {
		return skf_method->EnumApplication(
			hDev,
			szAppName,
			pulSize);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DeleteApplication(
	DEVHANDLE hDev,
	LPSTR szAppName)
{
	if (skf_method->DeleteApplication) {
		return skf_method->DeleteApplication(
			hDev,
			szAppName);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_OpenApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication)
{
	if (skf_method->OpenApplication) {
		return skf_method->OpenApplication(
			hDev,
			szAppName,
			phApplication);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CloseApplication(
	HAPPLICATION hApplication)
{
	if (skf_method->CloseApplication) {
		return skf_method->CloseApplication(
			hApplication);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CreateFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights)
{
	if (skf_method->CreateFile) {
		return skf_method->CreateFile(
			hApplication,
			szFileName,
			ulFileSize,
			ulReadRights,
			ulWriteRights);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DeleteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName)
{
	if (skf_method->DeleteFile) {
		return skf_method->DeleteFile(
			hApplication,
			szFileName);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumFiles(
	HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize)
{
	if (skf_method->EnumFiles) {
		return skf_method->EnumFiles(
			hApplication,
			szFileList,
			pulSize);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GetFileInfo(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo)
{
	if (skf_method->GetFileInfo) {
		return skf_method->GetFileInfo(
			hApplication,
			szFileName,
			pFileInfo);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ReadFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	ULONG ulSize,
	BYTE *pbOutData,
	ULONG *pulOutLen)
{
	if (skf_method->ReadFile) {
		return skf_method->ReadFile(
			hApplication,
			szFileName,
			ulOffset,
			ulSize,
			pbOutData,
			pulOutLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_WriteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	BYTE *pbData,
	ULONG ulSize)
{
	if (skf_method->WriteFile) {
		return skf_method->WriteFile(
			hApplication,
			szFileName,
			ulOffset,
			pbData,
			ulSize);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CreateContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	if (skf_method->CreateContainer) {
		return skf_method->CreateContainer(
			hApplication,
			szContainerName,
			phContainer);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DeleteContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName)
{
	if (skf_method->DeleteContainer) {
		return skf_method->DeleteContainer(
			hApplication,
			szContainerName);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize)
{
	if (skf_method->EnumContainer) {
		return skf_method->EnumContainer(
			hApplication,
			szContainerName,
			pulSize);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_OpenContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	if (skf_method->OpenContainer) {
		return skf_method->OpenContainer(
			hApplication,
			szContainerName,
			phContainer);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CloseContainer(
	HCONTAINER hContainer)
{
	if (skf_method->CloseContainer) {
		return skf_method->CloseContainer(
			hContainer);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GetContainerType(
	HCONTAINER hContainer,
	ULONG *pulContainerType)
{
	if (skf_method->GetContainerType) {
		return skf_method->GetContainerType(
			hContainer,
			pulContainerType);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ImportCertificate(
	HCONTAINER hContainer,
	BOOL bExportSignKey,
	BYTE *pbCert,
	ULONG ulCertLen)
{
	if (skf_method->ImportCertificate) {
		return skf_method->ImportCertificate(
			hContainer,
			bExportSignKey,
			pbCert,
			ulCertLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExportCertificate(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG *pulCertLen)
{
	if (skf_method->ExportCertificate) {
		return skf_method->ExportCertificate(
			hContainer,
			bSignFlag,
			pbCert,
			pulCertLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExportPublicKey(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen)
{
	if (skf_method->ExportPublicKey) {
		return skf_method->ExportPublicKey(
			hContainer,
			bSignFlag,
			pbBlob,
			pulBlobLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenRandom(
	DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen)
{
	if (skf_method->GenRandom) {
		return skf_method->GenRandom(
			hDev,
			pbRandom,
			ulRandomLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenExtRSAKey(
	DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob)
{
	if (skf_method->GenExtRSAKey) {
		return skf_method->GenExtRSAKey(
			hDev,
			ulBitsLen,
			pBlob);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob)
{
	if (skf_method->GenRSAKeyPair) {
		return skf_method->GenRSAKeyPair(
			hContainer,
			ulBitsLen,
			pBlob);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ImportRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulSymAlgId,
	BYTE *pbWrappedKey,
	ULONG ulWrappedKeyLen,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedDataLen)
{
	if (skf_method->ImportRSAKeyPair) {
		return skf_method->ImportRSAKeyPair(
			hContainer,
			ulSymAlgId,
			pbWrappedKey,
			ulWrappedKeyLen,
			pbEncryptedData,
			ulEncryptedDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_RSASignData(
	HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen)
{
	if (skf_method->RSASignData) {
		return skf_method->RSASignData(
			hContainer,
			pbData,
			ulDataLen,
			pbSignature,
			pulSignLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_RSAVerify(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen)
{
	if (skf_method->RSAVerify) {
		return skf_method->RSAVerify(
			hDev,
			pRSAPubKeyBlob,
			pbData,
			ulDataLen,
			pbSignature,
			ulSignLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_RSAExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	RSAPUBLICKEYBLOB *pPubKey,
	BYTE *pbData,
	ULONG *pulDataLen,
	HANDLE *phSessionKey)
{
	if (skf_method->RSAExportSessionKey) {
		return skf_method->RSAExportSessionKey(
			hContainer,
			ulAlgId,
			pPubKey,
			pbData,
			pulDataLen,
			phSessionKey);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtRSAPubKeyOperation(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	if (skf_method->ExtRSAPubKeyOperation) {
		return skf_method->ExtRSAPubKeyOperation(
			hDev,
			pRSAPubKeyBlob,
			pbInput,
			ulInputLen,
			pbOutput,
			pulOutputLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtRSAPriKeyOperation(
	DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	if (skf_method->ExtRSAPriKeyOperation) {
		return skf_method->ExtRSAPriKeyOperation(
			hDev,
			pRSAPriKeyBlob,
			pbInput,
			ulInputLen,
			pbOutput,
			pulOutputLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenECCKeyPair(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob)
{
	if (skf_method->GenECCKeyPair) {
		return skf_method->GenECCKeyPair(
			hContainer,
			ulAlgId,
			pBlob);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ImportECCKeyPair(
	HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob)
{
	if (skf_method->ImportECCKeyPair) {
		return skf_method->ImportECCKeyPair(
			hContainer,
			pEnvelopedKeyBlob);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ECCSignData(
	HCONTAINER hContainer,
	BYTE *pbDigest,
	ULONG ulDigestLen,
	ECCSIGNATUREBLOB *pSignature)
{
	if (skf_method->ECCSignData) {
		return skf_method->ECCSignData(
			hContainer,
			pbDigest,
			ulDigestLen,
			pSignature);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ECCVerify(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	if (skf_method->ECCVerify) {
		return skf_method->ECCVerify(
			hDev,
			pECCPubKeyBlob,
			pbData,
			ulDataLen,
			pSignature);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ECCExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	ECCCIPHERBLOB *pData,
	HANDLE *phSessionKey)
{
	if (skf_method->ECCExportSessionKey) {
		return skf_method->ECCExportSessionKey(
			hContainer,
			ulAlgId,
			pPubKey,
			pData,
			phSessionKey);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtECCEncrypt(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText)
{
	if (skf_method->ExtECCEncrypt) {
		return skf_method->ExtECCEncrypt(
			hDev,
			pECCPubKeyBlob,
			pbPlainText,
			ulPlainTextLen,
			pCipherText);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtECCDecrypt(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	if (skf_method->ExtECCDecrypt) {
		return skf_method->ExtECCDecrypt(
			hDev,
			pECCPriKeyBlob,
			pCipherText,
			pbPlainText,
			pulPlainTextLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtECCSign(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	if (skf_method->ExtECCSign) {
		return skf_method->ExtECCSign(
			hDev,
			pECCPriKeyBlob,
			pbData,
			ulDataLen,
			pSignature);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtECCVerify(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	if (skf_method->ExtECCVerify) {
		return skf_method->ExtECCVerify(
			hDev,
			pECCPubKeyBlob,
			pbData,
			ulDataLen,
			pSignature);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenerateAgreementDataWithECC(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phAgreementHandle)
{
	if (skf_method->GenerateAgreementDataWithECC) {
		return skf_method->GenerateAgreementDataWithECC(
			hContainer,
			ulAlgId,
			pTempECCPubKeyBlob,
			pbID,
			ulIDLen,
			phAgreementHandle);
	}
	return SAR_NOTSUPPORTYETERR;
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
	if (skf_method->GenerateAgreementDataAndKeyWithECC) {
		return skf_method->GenerateAgreementDataAndKeyWithECC(
			hContainer,
			ulAlgId,
			pSponsorECCPubKeyBlob,
			pSponsorTempECCPubKeyBlob,
			pTempECCPubKeyBlob,
			pbID,
			ulIDLen,
			pbSponsorID,
			ulSponsorIDLen,
			phKeyHandle);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenerateKeyWithECC(
	HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phKeyHandle)
{
	if (skf_method->GenerateKeyWithECC) {
		return skf_method->GenerateKeyWithECC(
			hAgreementHandle,
			pECCPubKeyBlob,
			pTempECCPubKeyBlob,
			pbID,
			ulIDLen,
			phKeyHandle);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ImportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey)
{
	if (skf_method->ImportSessionKey) {
		return skf_method->ImportSessionKey(
			hContainer,
			ulAlgId,
			pbWrapedData,
			ulWrapedLen,
			phKey);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_SetSymmKey(
	DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey)
{
	if (skf_method->SetSymmKey) {
		return skf_method->SetSymmKey(
			hDev,
			pbKey,
			ulAlgID,
			phKey);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EncryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM EncryptParam)
{
	if (skf_method->EncryptInit) {
		return skf_method->EncryptInit(
			hKey,
			EncryptParam);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_Encrypt(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	if (skf_method->Encrypt) {
		return skf_method->Encrypt(
			hKey,
			pbData,
			ulDataLen,
			pbEncryptedData,
			pulEncryptedLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EncryptUpdate(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	if (skf_method->EncryptUpdate) {
		return skf_method->EncryptUpdate(
			hKey,
			pbData,
			ulDataLen,
			pbEncryptedData,
			pulEncryptedLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EncryptFinal(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen)
{
	if (skf_method->EncryptFinal) {
		return skf_method->EncryptFinal(
			hKey,
			pbEncryptedData,
			pulEncryptedDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DecryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam)
{
	if (skf_method->DecryptInit) {
		return skf_method->DecryptInit(
			hKey,
			DecryptParam);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_Decrypt(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	if (skf_method->Decrypt) {
		return skf_method->Decrypt(
			hKey,
			pbEncryptedData,
			ulEncryptedLen,
			pbData,
			pulDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DecryptUpdate(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	if (skf_method->DecryptUpdate) {
		return skf_method->DecryptUpdate(
			hKey,
			pbEncryptedData,
			ulEncryptedLen,
			pbData,
			pulDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DecryptFinal(
	HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen)
{
	if (skf_method->DecryptFinal) {
		return skf_method->DecryptFinal(
			hKey,
			pbDecryptedData,
			pulDecryptedDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DigestInit(
	DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phHash)
{
	if (skf_method->DigestInit) {
		return skf_method->DigestInit(
			hDev,
			ulAlgID,
			pPubKey,
			pbID,
			ulIDLen,
			phHash);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_Digest(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen)
{
	if (skf_method->Digest) {
		return skf_method->Digest(
			hHash,
			pbData,
			ulDataLen,
			pbHashData,
			pulHashLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DigestUpdate(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen)
{
	if (skf_method->DigestUpdate) {
		return skf_method->DigestUpdate(
			hHash,
			pbData,
			ulDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DigestFinal(
	HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen)
{
	if (skf_method->DigestFinal) {
		return skf_method->DigestFinal(
			hHash,
			pHashData,
			pulHashLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_MacInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac)
{
	if (skf_method->MacInit) {
		return skf_method->MacInit(
			hKey,
			pMacParam,
			phMac);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_Mac(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMacData,
	ULONG *pulMacLen)
{
	if (skf_method->Mac) {
		return skf_method->Mac(
			hMac,
			pbData,
			ulDataLen,
			pbMacData,
			pulMacLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_MacUpdate(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen)
{
	if (skf_method->MacUpdate) {
		return skf_method->MacUpdate(
			hMac,
			pbData,
			ulDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_MacFinal(
	HANDLE hMac,
	BYTE *pbMacData,
	ULONG *pulMacDataLen)
{
	if (skf_method->MacFinal) {
		return skf_method->MacFinal(
			hMac,
			pbMacData,
			pulMacDataLen);
	}
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CloseHandle(
	HANDLE hHandle)
{
	if (skf_method->CloseHandle) {
		return skf_method->CloseHandle(
			hHandle);

	}
	return SAR_NOTSUPPORTYETERR;
}
