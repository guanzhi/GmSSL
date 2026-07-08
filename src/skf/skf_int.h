/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef SKFUTIL_SKF_INT_H
#define SKFUTIL_SKF_INT_H

#include <gmssl/dylib.h>
#include "../sgd.h"
#include "skf.h"



typedef ULONG (DEVAPI *SKF_WaitForDevEvent_FuncPtr)(
	LPSTR szDevName,
	ULONG *pulDevNameLen,
	ULONG *pulEvent);

typedef ULONG (DEVAPI *SKF_CancelWaitForDevEvent_FuncPtr)(
	void);

typedef ULONG (DEVAPI *SKF_EnumDev_FuncPtr)(
	BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize);

typedef ULONG (DEVAPI *SKF_ConnectDev_FuncPtr)(
	LPSTR szName,
	DEVHANDLE *phDev);

typedef ULONG (DEVAPI *SKF_DisConnectDev_FuncPtr)(
	DEVHANDLE hDev);

typedef ULONG (DEVAPI *SKF_GetDevState_FuncPtr)(
	LPSTR szDevName,
	ULONG *pulDevState);

typedef ULONG (DEVAPI *SKF_SetLabel_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szLabel);

typedef ULONG (DEVAPI *SKF_GetDevInfo_FuncPtr)(
	DEVHANDLE hDev,
	DEVINFO *pDevInfo);

typedef ULONG (DEVAPI *SKF_LockDev_FuncPtr)(
	DEVHANDLE hDev,
	ULONG ulTimeOut);

typedef ULONG (DEVAPI *SKF_UnlockDev_FuncPtr)(
	DEVHANDLE hDev);

typedef ULONG (DEVAPI *SKF_Transmit_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen);

typedef ULONG (DEVAPI *SKF_ChangeDevAuthKey_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen);

typedef ULONG (DEVAPI *SKF_DevAuth_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen);

typedef ULONG (DEVAPI *SKF_ChangePIN_FuncPtr)(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount);

typedef LONG (DEVAPI *SKF_GetPINInfo_FuncPtr)(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin);

typedef ULONG (DEVAPI *SKF_VerifyPIN_FuncPtr)(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount);

typedef ULONG (DEVAPI *SKF_UnblockPIN_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount);

typedef ULONG (DEVAPI *SKF_ClearSecureState_FuncPtr)(
	HAPPLICATION hApplication);

typedef ULONG (DEVAPI *SKF_CreateApplication_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szAppName,
	LPSTR szAdminPin,
	DWORD dwAdminPinRetryCount,
	LPSTR szUserPin,
	DWORD dwUserPinRetryCount,
	DWORD dwCreateFileRights,
	HAPPLICATION *phApplication);

typedef ULONG (DEVAPI *SKF_EnumApplication_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize);

typedef ULONG (DEVAPI *SKF_DeleteApplication_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szAppName);

typedef ULONG (DEVAPI *SKF_OpenApplication_FuncPtr)(
	DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication);

typedef ULONG (DEVAPI *SKF_CloseApplication_FuncPtr)(
	HAPPLICATION hApplication);

typedef ULONG (DEVAPI *SKF_CreateObject_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights);

typedef ULONG (DEVAPI *SKF_DeleteObject_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName);

typedef ULONG (DEVAPI *SKF_EnumObjects_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize);

typedef ULONG (DEVAPI *SKF_GetObjectInfo_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo);

typedef ULONG (DEVAPI *SKF_ReadObject_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	ULONG ulSize,
	BYTE *pbOutData,
	ULONG *pulOutLen);

typedef ULONG (DEVAPI *SKF_WriteObject_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	BYTE *pbData,
	ULONG ulSize);

typedef ULONG (DEVAPI *SKF_CreateContainer_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer);

typedef ULONG (DEVAPI *SKF_DeleteContainer_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szContainerName);

typedef ULONG (DEVAPI *SKF_EnumContainer_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize);

typedef ULONG (DEVAPI *SKF_OpenContainer_FuncPtr)(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer);

typedef ULONG (DEVAPI *SKF_CloseContainer_FuncPtr)(
	HCONTAINER hContainer);

typedef ULONG (DEVAPI *SKF_GetContainerType_FuncPtr)(
	HCONTAINER hContainer,
	ULONG *pulContainerType);

typedef ULONG (DEVAPI *SKF_ImportCertificate_FuncPtr)(
	HCONTAINER hContainer,
	BOOL bExportSignKey,
	BYTE *pbCert,
	ULONG ulCertLen);

typedef ULONG (DEVAPI *SKF_ExportCertificate_FuncPtr)(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG *pulCertLen);

typedef ULONG (DEVAPI *SKF_ExportPublicKey_FuncPtr)(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen);

typedef ULONG (DEVAPI *SKF_GenRandom_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen);

typedef ULONG (DEVAPI *SKF_GenExtRSAKey_FuncPtr)(
	DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob);

typedef ULONG (DEVAPI *SKF_GenRSAKeyPair_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob);

typedef ULONG (DEVAPI *SKF_ImportRSAKeyPair_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulSymAlgId,
	BYTE *pbWrappedKey,
	ULONG ulWrappedKeyLen,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedDataLen);

typedef ULONG (DEVAPI *SKF_RSASignData_FuncPtr)(
	HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen);

typedef ULONG (DEVAPI *SKF_RSAVerify_FuncPtr)(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen);

typedef ULONG (DEVAPI *SKF_RSAExportSessionKey_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	RSAPUBLICKEYBLOB *pPubKey,
	BYTE *pbData,
	ULONG *pulDataLen,
	HANDLE *phSessionKey);

typedef ULONG (DEVAPI *SKF_ExtRSAPubKeyOperation_FuncPtr)(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen);

typedef ULONG (DEVAPI *SKF_ExtRSAPriKeyOperation_FuncPtr)(
	DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen);

typedef ULONG (DEVAPI *SKF_GenECCKeyPair_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob);

typedef ULONG (DEVAPI *SKF_ImportECCKeyPair_FuncPtr)(
	HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob);

typedef ULONG (DEVAPI *SKF_ECCSignData_FuncPtr)(
	HCONTAINER hContainer,
	BYTE *pbDigest,
	ULONG ulDigestLen,
	ECCSIGNATUREBLOB *pSignature);

typedef ULONG (DEVAPI *SKF_ECCVerify_FuncPtr)(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

typedef ULONG (DEVAPI *SKF_ECCExportSessionKey_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	ECCCIPHERBLOB *pData,
	HANDLE *phSessionKey);

typedef ULONG (DEVAPI *SKF_ExtECCEncrypt_FuncPtr)(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText);

typedef ULONG (DEVAPI *SKF_ECCDecrypt_FuncPtr)(
	HCONTAINER hContainer,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen);

typedef ULONG (DEVAPI *SKF_ExtECCDecrypt_FuncPtr)(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen);

typedef ULONG (DEVAPI *SKF_ExtECCSign_FuncPtr)(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

typedef ULONG (DEVAPI *SKF_ExtECCVerify_FuncPtr)(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

typedef ULONG (DEVAPI *SKF_GenerateAgreementDataWithECC_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phAgreementHandle);

typedef ULONG (DEVAPI *SKF_GenerateAgreementDataAndKeyWithECC_FuncPtr)(
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

typedef ULONG (DEVAPI *SKF_GenerateKeyWithECC_FuncPtr)(
	HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phKeyHandle);

typedef ULONG (DEVAPI *SKF_ImportSessionKey_FuncPtr)(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey);

typedef ULONG (DEVAPI *SKF_SetSymmKey_FuncPtr)(
	DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey);

typedef ULONG (DEVAPI *SKF_EncryptInit_FuncPtr)(
	HANDLE hKey,
	BLOCKCIPHERPARAM EncryptParam);

typedef ULONG (DEVAPI *SKF_Encrypt_FuncPtr)(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen);

typedef ULONG (DEVAPI *SKF_EncryptUpdate_FuncPtr)(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen);

typedef ULONG (DEVAPI *SKF_EncryptFinal_FuncPtr)(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen);

typedef ULONG (DEVAPI *SKF_DecryptInit_FuncPtr)(
	HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam);

typedef ULONG (DEVAPI *SKF_Decrypt_FuncPtr)(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen);

typedef ULONG (DEVAPI *SKF_DecryptUpdate_FuncPtr)(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen);

typedef ULONG (DEVAPI *SKF_DecryptFinal_FuncPtr)(
	HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen);

typedef ULONG (DEVAPI *SKF_DigestInit_FuncPtr)(
	DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phHash);

typedef ULONG (DEVAPI *SKF_Digest_FuncPtr)(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen);

typedef ULONG (DEVAPI *SKF_DigestUpdate_FuncPtr)(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen);

typedef ULONG (DEVAPI *SKF_DigestFinal_FuncPtr)(
	HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen);

typedef ULONG (DEVAPI *SKF_MacInit_FuncPtr)(
	HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac);

typedef ULONG (DEVAPI *SKF_Mac_FuncPtr)(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMacData,
	ULONG *pulMacLen);

typedef ULONG (DEVAPI *SKF_MacUpdate_FuncPtr)(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen);

typedef ULONG (DEVAPI *SKF_MacFinal_FuncPtr)(
	HANDLE hMac,
	BYTE *pbMacData,
	ULONG *pulMacDataLen);

typedef ULONG (DEVAPI *SKF_CloseHandle_FuncPtr)(
	HANDLE hHandle);


typedef struct skf_method_st {
	char *name;
	dylib_handle_t dso;

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
	SKF_CreateObject_FuncPtr CreateObject;
	SKF_DeleteObject_FuncPtr DeleteObject;
	SKF_EnumObjects_FuncPtr EnumObjects;
	SKF_GetObjectInfo_FuncPtr GetObjectInfo;
	SKF_ReadObject_FuncPtr ReadObject;
	SKF_WriteObject_FuncPtr WriteObject;
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
	SKF_ECCDecrypt_FuncPtr ECCDecrypt;
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
void SKF_METHOD_free(SKF_METHOD *meth);


typedef struct skf_vendor_st {
	char *name;
	unsigned int authrand_length;
	ULONG (*get_cipher_algor)(ULONG vendor_id);
	ULONG (*get_cipher_cap)(ULONG vendor_cap);
	ULONG (*get_digest_algor)(ULONG vendor_id);
	ULONG (*get_digest_cap)(ULONG vendor_cap);
	ULONG (*get_pkey_algor)(ULONG vendor_id);
	ULONG (*get_pkey_cap)(ULONG vendor_cap);
	unsigned long (*get_error_reason)(ULONG err);
} SKF_VENDOR;

typedef struct {
	ULONG err;
	unsigned long reason;
} SKF_ERR_REASON;

#endif
