/* ====================================================================
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_SKF_METH_H
#define HEADER_SKF_METH_H

#include <openssl/skf.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef ULONG (*SKF_WaitForDevEvent_FuncPtr)(
	LPSTR szDevName,
	ULONG *pulDevNameLen,
	ULONG *pulEvent);

typedef ULONG (*SKF_CancelWaitForDevEvent_FuncPtr)(
	void);

typedef ULONG (*SKF_EnumDev_FuncPtr)(
	BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize);

typedef ULONG (*SKF_ConnectDev_FuncPtr)(
	LPSTR szName,
	DEVHANDLE *phDev);

typedef ULONG (*SKF_DisConnectDev_FuncPtr)(
	DEVHANDLE hDev);

typedef ULONG (*SKF_GetDevState_FuncPtr)(
	LPSTR szDevName,
	ULONG *pulDevState);

typedef ULONG (*SKF_SetLabel_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szLabel);

typedef ULONG (*SKF_GetDevInfo_FuncPtr)(
	DEVHANDLE hDev,
	DEVINFO *pDevInfo);

typedef ULONG (*SKF_LockDev_FuncPtr)(
	DEVHANDLE hDev,
	ULONG ulTimeOut);

typedef ULONG (*SKF_UnlockDev_FuncPtr)(
	DEVHANDLE hDev);

typedef ULONG (*SKF_Transmit_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen);

typedef ULONG (*SKF_ChangeDevAuthKey_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen);

typedef ULONG (*SKF_DevAuth_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen);

typedef ULONG (*SKF_ChangePIN_FuncPtr)(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount);

typedef LONG (*SKF_GetPINInfo_FuncPtr)(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin);

typedef ULONG (*SKF_VerifyPIN_FuncPtr)(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount);

typedef ULONG (*SKF_UnblockPIN_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount);

typedef ULONG (*SKF_ClearSecureState_FuncPtr)(
	HAPPLICATION hApplication);

typedef ULONG (*SKF_CreateApplication_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szAppName,
	LPSTR szAdminPin,
	DWORD dwAdminPinRetryCount,
	LPSTR szUserPin,
	DWORD dwUserPinRetryCount,
	DWORD dwCreateFileRights,
	HAPPLICATION *phApplication);

typedef ULONG (*SKF_EnumApplication_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize);

typedef ULONG (*SKF_DeleteApplication_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szAppName);

typedef ULONG (*SKF_OpenApplication_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication);

typedef ULONG (*SKF_CloseApplication_FuncPtr)(
	HAPPLICATION hApplication);

typedef ULONG (*SKF_CreateFile_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights);

typedef ULONG (*SKF_DeleteFile_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName);

typedef ULONG (*SKF_EnumFiles_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize);

typedef ULONG (*SKF_GetFileInfo_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo);

typedef ULONG (*SKF_ReadFile_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	ULONG ulSize,
	BYTE *pbOutData,
	ULONG *pulOutLen);

typedef ULONG (*SKF_WriteFile_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	BYTE *pbData,
	ULONG ulSize);

typedef ULONG (*SKF_CreateContainer_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer);

typedef ULONG (*SKF_DeleteContainer_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szContainerName);

typedef ULONG (*SKF_EnumContainer_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize);

typedef ULONG (*SKF_OpenContainer_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer);

typedef ULONG (*SKF_CloseContainer_FuncPtr)(
	HCONTAINER hContainer);

typedef ULONG (*SKF_GetContainerType_FuncPtr)(
	HCONTAINER hContainer,
	ULONG *pulContainerType);

typedef ULONG (*SKF_ImportCertificate_FuncPtr)(
	HCONTAINER hContainer,
	BOOL bExportSignKey,
	BYTE *pbCert,
	ULONG ulCertLen);

typedef ULONG (*SKF_ExportCertificate_FuncPtr)(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG *pulCertLen);

typedef ULONG (*SKF_ExportPublicKey_FuncPtr)(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen);

typedef ULONG (*SKF_GenRandom_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen);

typedef ULONG (*SKF_GenExtRSAKey_FuncPtr)(
	DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob);

typedef ULONG (*SKF_GenRSAKeyPair_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob);

typedef ULONG (*SKF_ImportRSAKeyPair_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulSymAlgId,
	BYTE *pbWrappedKey,
	ULONG ulWrappedKeyLen,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedDataLen);

typedef ULONG (*SKF_RSASignData_FuncPtr)(
	HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen);

typedef ULONG (*SKF_RSAVerify_FuncPtr)(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen);

typedef ULONG (*SKF_RSAExportSessionKey_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	RSAPUBLICKEYBLOB *pPubKey,
	BYTE *pbData,
	ULONG *pulDataLen,
	HANDLE *phSessionKey);

typedef ULONG (*SKF_ExtRSAPubKeyOperation_FuncPtr)(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen);

typedef ULONG (*SKF_ExtRSAPriKeyOperation_FuncPtr)(
	DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen);

typedef ULONG (*SKF_GenECCKeyPair_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob);

typedef ULONG (*SKF_ImportECCKeyPair_FuncPtr)(
	HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob);

typedef ULONG (*SKF_ECCSignData_FuncPtr)(
	HCONTAINER hContainer,
	BYTE *pbDigest,
	ULONG ulDigestLen,
	ECCSIGNATUREBLOB *pSignature);

typedef ULONG (*SKF_ECCVerify_FuncPtr)(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

typedef ULONG (*SKF_ECCExportSessionKey_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	ECCCIPHERBLOB *pData,
	HANDLE *phSessionKey);

typedef ULONG (*SKF_ExtECCEncrypt_FuncPtr)(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText);

typedef ULONG (*SKF_ExtECCDecrypt_FuncPtr)(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen);

typedef ULONG (*SKF_ExtECCSign_FuncPtr)(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

typedef ULONG (*SKF_ExtECCVerify_FuncPtr)(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

typedef ULONG (*SKF_GenerateAgreementDataWithECC_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phAgreementHandle);

typedef ULONG (*SKF_GenerateAgreementDataAndKeyWithECC_FuncPtr)(
	HANDLE hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	BYTE *pbSponsorID,
	ULONG ulSponsorIDLen,
	HANDLE *phKeyHandle);

typedef ULONG (*SKF_GenerateKeyWithECC_FuncPtr)(
	HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phKeyHandle);

typedef ULONG (*SKF_ImportSessionKey_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey);

typedef ULONG (*SKF_SetSymmKey_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey);

typedef ULONG (*SKF_EncryptInit_FuncPtr)(
	HANDLE hKey,
	BLOCKCIPHERPARAM EncryptParam);

typedef ULONG (*SKF_Encrypt_FuncPtr)(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen);

typedef ULONG (*SKF_EncryptUpdate_FuncPtr)(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen);

typedef ULONG (*SKF_EncryptFinal_FuncPtr)(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen);

typedef ULONG (*SKF_DecryptInit_FuncPtr)(
	HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam);

typedef ULONG (*SKF_Decrypt_FuncPtr)(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen);

typedef ULONG (*SKF_DecryptUpdate_FuncPtr)(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen);

typedef ULONG (*SKF_DecryptFinal_FuncPtr)(
	HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen);

typedef ULONG (*SKF_DigestInit_FuncPtr)(
	DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phHash);

typedef ULONG (*SKF_Digest_FuncPtr)(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen);

typedef ULONG (*SKF_DigestUpdate_FuncPtr)(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen);

typedef ULONG (*SKF_DigestFinal_FuncPtr)(
	HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen);

typedef ULONG (*SKF_MacInit_FuncPtr)(
	HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac);

typedef ULONG (*SKF_Mac_FuncPtr)(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMacData,
	ULONG *pulMacLen);

typedef ULONG (*SKF_MacUpdate_FuncPtr)(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen);

typedef ULONG (*SKF_MacFinal_FuncPtr)(
	HANDLE hMac,
	BYTE *pbMacData,
	ULONG *pulMacDataLen);

typedef ULONG (*SKF_CloseHandle_FuncPtr)(
	HANDLE hHandle);


typedef struct skf_method_st {
	char *name;
	SKF_WaitForDevEvent_FuncPtr WaitForDevEvent;
	SKF_CancelWaitForDevEvent_FuncPtr CancelWaitForDevEvent;
	SKF_EnumDev_FuncPtr EnumDev;
	SKF_ConnectDev_FuncPtr ConnectDev;
	SKF_DisConnectDev_FuncPtr DisConnectDev;
	SKF_GetDevState_FuncPtr GetDevState;
	SKF_SetLabel_FuncPtr SetLabel;
	SKF_GetDevInfo_FuncPtr GetDevInfo;
	SKF_LockDev_FuncPtr LockDev;
	SKF_UnlockDev_FuncPtr UnlockDev;
	SKF_Transmit_FuncPtr Transmit;
	SKF_ChangeDevAuthKey_FuncPtr ChangeDevAuthKey;
	SKF_DevAuth_FuncPtr DevAuth;
	SKF_ChangePIN_FuncPtr ChangePIN;
	SKF_GetPINInfo_FuncPtr GetPINInfo;
	SKF_VerifyPIN_FuncPtr VerifyPIN;
	SKF_UnblockPIN_FuncPtr UnblockPIN;
	SKF_ClearSecureState_FuncPtr ClearSecureState;
	SKF_CreateApplication_FuncPtr CreateApplication;
	SKF_EnumApplication_FuncPtr EnumApplication;
	SKF_DeleteApplication_FuncPtr DeleteApplication;
	SKF_OpenApplication_FuncPtr OpenApplication;
	SKF_CloseApplication_FuncPtr CloseApplication;
	SKF_CreateFile_FuncPtr CreateFileObject;
	SKF_DeleteFile_FuncPtr DeleteFileObject;
	SKF_EnumFiles_FuncPtr EnumFiles;
	SKF_GetFileInfo_FuncPtr GetFileInfo;
	SKF_ReadFile_FuncPtr ReadFileObject;
	SKF_WriteFile_FuncPtr WriteFileObject;
	SKF_CreateContainer_FuncPtr CreateContainer;
	SKF_DeleteContainer_FuncPtr DeleteContainer;
	SKF_EnumContainer_FuncPtr EnumContainer;
	SKF_OpenContainer_FuncPtr OpenContainer;
	SKF_CloseContainer_FuncPtr CloseContainer;
	SKF_GetContainerType_FuncPtr GetContainerType;
	SKF_ImportCertificate_FuncPtr ImportCertificate;
	SKF_ExportCertificate_FuncPtr ExportCertificate;
	SKF_ExportPublicKey_FuncPtr ExportPublicKey;
	SKF_GenRandom_FuncPtr GenRandom;
	SKF_GenExtRSAKey_FuncPtr GenExtRSAKey;
	SKF_GenRSAKeyPair_FuncPtr GenRSAKeyPair;
	SKF_ImportRSAKeyPair_FuncPtr ImportRSAKeyPair;
	SKF_RSASignData_FuncPtr RSASignData;
	SKF_RSAVerify_FuncPtr RSAVerify;
	SKF_RSAExportSessionKey_FuncPtr RSAExportSessionKey;
	SKF_ExtRSAPubKeyOperation_FuncPtr ExtRSAPubKeyOperation;
	SKF_ExtRSAPriKeyOperation_FuncPtr ExtRSAPriKeyOperation;
	SKF_GenECCKeyPair_FuncPtr GenECCKeyPair;
	SKF_ImportECCKeyPair_FuncPtr ImportECCKeyPair;
	SKF_ECCSignData_FuncPtr ECCSignData;
	SKF_ECCVerify_FuncPtr ECCVerify;
	SKF_ECCExportSessionKey_FuncPtr ECCExportSessionKey;
	SKF_ExtECCEncrypt_FuncPtr ExtECCEncrypt;
	SKF_ExtECCDecrypt_FuncPtr ExtECCDecrypt;
	SKF_ExtECCSign_FuncPtr ExtECCSign;
	SKF_ExtECCVerify_FuncPtr ExtECCVerify;
	SKF_GenerateAgreementDataWithECC_FuncPtr GenerateAgreementDataWithECC;
	SKF_GenerateAgreementDataAndKeyWithECC_FuncPtr GenerateAgreementDataAndKeyWithECC;
	SKF_GenerateKeyWithECC_FuncPtr GenerateKeyWithECC;
	SKF_ImportSessionKey_FuncPtr ImportSessionKey;
	SKF_SetSymmKey_FuncPtr SetSymmKey;
	SKF_EncryptInit_FuncPtr EncryptInit;
	SKF_Encrypt_FuncPtr Encrypt;
	SKF_EncryptUpdate_FuncPtr EncryptUpdate;
	SKF_EncryptFinal_FuncPtr EncryptFinal;
	SKF_DecryptInit_FuncPtr DecryptInit;
	SKF_Decrypt_FuncPtr Decrypt;
	SKF_DecryptUpdate_FuncPtr DecryptUpdate;
	SKF_DecryptFinal_FuncPtr DecryptFinal;
	SKF_DigestInit_FuncPtr DigestInit;
	SKF_Digest_FuncPtr Digest;
	SKF_DigestUpdate_FuncPtr DigestUpdate;
	SKF_DigestFinal_FuncPtr DigestFinal;
	SKF_MacInit_FuncPtr MacInit;
	SKF_Mac_FuncPtr Mac;
	SKF_MacUpdate_FuncPtr MacUpdate;
	SKF_MacFinal_FuncPtr MacFinal;
	SKF_CloseHandle_FuncPtr CloseHandle;
} SKF_METHOD;

SKF_METHOD *SKF_METHOD_load_library(const char *so_path);

#ifdef __cplusplus
}
#endif
#endif
