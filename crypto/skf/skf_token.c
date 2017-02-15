/* crypto/skf/skf_app.c */
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
#include <openssl/skf.h>

ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName,
	ULONG *pulDevNameLen,
	ULONG *pulEvent)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CancelWaitForDevEvent(void)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_SetLabel(DEVHANDLE hDev,
	LPSTR szLabel)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_LockDev(DEVHANDLE hDev,
		ULONG ulTimeOut)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_UnlockDev(DEVHANDLE hDev)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev,
	BYTE* pbCommand,
	ULONG ulCommandLen,
	BYTE* pbData,
	ULONG* pulDataLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ChangeDevAuthKey(DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DevAuth(DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen)
{
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
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev,
	LPSTR szAppName)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ChangePIN(HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount)
{
	return SAR_NOTSUPPORTYETERR;
}

LONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_VerifyPIN(HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_UnblockPIN(HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ClearSecureState(HAPPLICATION hApplication)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CreateContainer(HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication,
	LPSTR szContainerName)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumContainer(HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GetContainerType(HCONTAINER hContainer,
		ULONG *pulContainerType)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ImportCertificate(HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG ulCertLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG *pulCertLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CreateFile(HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumFiles(HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GetFileInfo(HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ReadFile(HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	ULONG ulSize,
	BYTE *pbOutData,
	ULONG *pulOutLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_WriteFile(HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	BYTE *pbData,
	ULONG ulSize)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DeleteFile(HAPPLICATION hApplication,
	LPSTR szFileName)
{
	return SAR_NOTSUPPORTYETERR;
}


ULONG DEVAPI SKF_GenECCKeyPair(HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ImportECCKeyPair(HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ECCSignData(HCONTAINER hContainer,
		BYTE *pbData,
		ULONG ulDataLen,
		ECCSIGNATUREBLOB *pSignature)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenerateAgreementDataWithECC(HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phAgreementHandle)
{
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
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenerateKeyWithECC(HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phKeyHandle)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenRSAKeyPair(HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ImportRSAKeyPair(HCONTAINER hContainer,
	ULONG ulSymAlgId,
	BYTE *pbWrappedKey,
	ULONG ulWrappedKeyLen,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedDataLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_RSASignData(HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ImportSessionKey(HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_RSAExportSessionKey(HCONTAINER hContainer,
	ULONG ulAlgId,
	RSAPUBLICKEYBLOB *pPubKey,
	BYTE *pbData,
	ULONG *pulDataLen,
	HANDLE *phSessionKey)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ECCExportSessionKey(HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	ECCCIPHERBLOB *pData,
	HANDLE *phSessionKey)
{
	return SAR_NOTSUPPORTYETERR;
}

