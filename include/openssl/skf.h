/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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
/* This header file is from the official specification with minor
 * modification.
 */

#ifndef HEADER_SKF_H
#define HEADER_SKF_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SKF

#include <openssl/sgd.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1)
typedef struct Struct_Version{
	BYTE major;
	BYTE minor;
} VERSION;

typedef struct Struct_DEVINFO {
	VERSION	Version;
	CHAR	Manufacturer[64];
	CHAR	Issuer[64];
	CHAR	Label[32];
	CHAR	SerialNumber[32];
	VERSION	HWVersion;
	VERSION	FirmwareVersion;
	ULONG	AlgSymCap;
	ULONG	AlgAsymCap;
	ULONG	AlgHashCap;
	ULONG	DevAuthAlgId;
	ULONG	TotalSpace;
	ULONG	FreeSpace;
	ULONG	MaxECCBufferSize;
	ULONG	MaxBufferSize;
	BYTE  	Reserved[64];
} DEVINFO, *PDEVINFO;

typedef struct Struct_RSAPUBLICKEYBLOB {
	ULONG	AlgID;
	ULONG	BitLen;
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

typedef struct Struct_RSAPRIVATEKEYBLOB {
	ULONG	AlgID;
	ULONG	BitLen;
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];
	BYTE	PrivateExponent[MAX_RSA_MODULUS_LEN];
	BYTE	Prime1[MAX_RSA_MODULUS_LEN/2];
	BYTE	Prime2[MAX_RSA_MODULUS_LEN/2];
	BYTE	Prime1Exponent[MAX_RSA_MODULUS_LEN/2];
	BYTE	Prime2Exponent[MAX_RSA_MODULUS_LEN/2];
	BYTE	Coefficient[MAX_RSA_MODULUS_LEN/2];
} RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

typedef struct Struct_ECCPUBLICKEYBLOB {
	ULONG	BitLen;
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

typedef struct Struct_ECCPRIVATEKEYBLOB {
	ULONG	BitLen;
	BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];
} ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

typedef struct Struct_ECCCIPHERBLOB {
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	HASH[32];
	ULONG	CipherLen;
	BYTE	Cipher[1];
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

typedef struct Struct_ECCSIGNATUREBLOB {
	BYTE	r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	s[ECC_MAX_XCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

typedef struct Struct_BLOCKCIPHERPARAM {
	BYTE	IV[MAX_IV_LEN];
	ULONG	IVLen;
	ULONG	PaddingType;
	ULONG	FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

typedef struct SKF_ENVELOPEDKEYBLOB {
	ULONG	Version;
	ULONG	ulSymmAlgID;
	ULONG	ulBits;
	BYTE	cbEncryptedPriKey[64];
	ECCPUBLICKEYBLOB	PubKey;
	ECCCIPHERBLOB		ECCCipherBlob;
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

typedef struct Struct_FILEATTRIBUTE {
	CHAR	FileName[MAX_FILE_NAME_SIZE];
	ULONG	FileSize;
	ULONG	ReadRights;
	ULONG	WriteRights;
} FILEATTRIBUTE, *PFILEATTRIBUTE;
#pragma pack()

/* 7.1.2 */
ULONG DEVAPI SKF_WaitForDevEvent(
	LPSTR szDevName,
	ULONG *pulDevNameLen,
	ULONG *pulEvent);

/* 7.1.3 */
ULONG DEVAPI SKF_CancelWaitForDevEvent(
	void);

/* 7.1.4 */
ULONG DEVAPI SKF_EnumDev(
	BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize);

/* 7.1.5 */
ULONG DEVAPI SKF_ConnectDev(
	LPSTR szName,
	DEVHANDLE *phDev);

/* 7.1.6 */
ULONG DEVAPI SKF_DisConnectDev(
	DEVHANDLE hDev);

/* 7.1.7 */
ULONG DEVAPI SKF_GetDevState(
	LPSTR szDevName,
	ULONG *pulDevState);

/* 7.1.8 */
ULONG DEVAPI SKF_SetLabel(
	DEVHANDLE hDev,
	LPSTR szLabel);

/* 7.1.9 */
ULONG DEVAPI SKF_GetDevInfo(
	DEVHANDLE hDev,
	DEVINFO *pDevInfo);

/* 7.1.10 */
ULONG DEVAPI SKF_LockDev(
	DEVHANDLE hDev,
	ULONG ulTimeOut);

/* 7.1.11 */
ULONG DEVAPI SKF_UnlockDev(
	DEVHANDLE hDev);

/* 7.1.12 */
ULONG DEVAPI SKF_Transmit(
	DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen);

/* 7.2.2 */
ULONG DEVAPI SKF_ChangeDevAuthKey(
	DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen);

/* 7.2.3 */
ULONG DEVAPI SKF_DevAuth(
	DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen);

/* 7.2.4 */
ULONG DEVAPI SKF_ChangePIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount);

/* 7.2.5 */
LONG DEVAPI SKF_GetPINInfo(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin);

/* 7.2.6 */
ULONG DEVAPI SKF_VerifyPIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount);

/* 7.2.7 */
ULONG DEVAPI SKF_UnblockPIN(
	HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount);

/* 7.2.8 */
ULONG DEVAPI SKF_ClearSecureState(
	HAPPLICATION hApplication);

/* 7.3.2 */
ULONG DEVAPI SKF_CreateApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	LPSTR szAdminPin,
	DWORD dwAdminPinRetryCount,
	LPSTR szUserPin,
	DWORD dwUserPinRetryCount,
	DWORD dwCreateFileRights,
	HAPPLICATION *phApplication);

/* 7.3.3 */
ULONG DEVAPI SKF_EnumApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize);

/* 7.3.4 */
ULONG DEVAPI SKF_DeleteApplication(
	DEVHANDLE hDev,
	LPSTR szAppName);

/* 7.3.5 */
ULONG DEVAPI SKF_OpenApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication);

/* 7.3.6 */
ULONG DEVAPI SKF_CloseApplication(
	HAPPLICATION hApplication);

/* 7.4.2 */
ULONG DEVAPI SKF_CreateFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights);

/* 7.4.3 */
ULONG DEVAPI SKF_DeleteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName);

/* 7.4.4 */
ULONG DEVAPI SKF_EnumFiles(
	HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize);

/* 7.4.5 */
ULONG DEVAPI SKF_GetFileInfo(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo);

/* 7.4.6 */
ULONG DEVAPI SKF_ReadFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	ULONG ulSize,
	BYTE *pbOutData,
	ULONG *pulOutLen);

/* 7.4.7 */
ULONG DEVAPI SKF_WriteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	BYTE *pbData,
	ULONG ulSize);

/* 7.5.2 */
ULONG DEVAPI SKF_CreateContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer);

/* 7.5.3 */
ULONG DEVAPI SKF_DeleteContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName);

/* 7.5.4 */
ULONG DEVAPI SKF_OpenContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer);

/* 7.5.5 */
ULONG DEVAPI SKF_CloseContainer(
	HCONTAINER hContainer);

/* 7.5.6 */
ULONG DEVAPI SKF_EnumContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize);

/* 7.5.7 */
ULONG DEVAPI SKF_GetContainerType(
	HCONTAINER hContainer,
	ULONG *pulContainerType);

/* 7.5.8 */
ULONG DEVAPI SKF_ImportCertificate(
	HCONTAINER hContainer,
	BOOL bExportSignKey,
	BYTE *pbCert,
	ULONG ulCertLen);

/* 7.5.9 */
ULONG DEVAPI SKF_ExportCertificate(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG *pulCertLen);

/* 7.6.2 */
ULONG DEVAPI SKF_GenRandom(
	DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen);

/* 7.6.3 */
ULONG DEVAPI SKF_GenExtRSAKey(
	DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob);

/* 7.6.4 */
ULONG DEVAPI SKF_GenRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob);

/* 7.6.5 */
ULONG DEVAPI SKF_ImportRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulSymAlgId,
	BYTE *pbWrappedKey,
	ULONG ulWrappedKeyLen,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedDataLen);

/* 7.6.6 */
ULONG DEVAPI SKF_RSASignData(
	HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen);

/* 7.6.7 */
ULONG DEVAPI SKF_RSAVerify(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen);

/* 7.6.8 */
ULONG DEVAPI SKF_RSAExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	RSAPUBLICKEYBLOB *pPubKey,
	BYTE *pbData,
	ULONG *pulDataLen,
	HANDLE *phSessionKey);

/* 7.6.9 */
ULONG DEVAPI SKF_ExtRSAPubKeyOperation(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen);

/* 7.6.10 */
ULONG DEVAPI SKF_ExtRSAPriKeyOperation(
	DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen);

/* 7.6.11 */
ULONG DEVAPI SKF_GenECCKeyPair(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob);

/* 7.6.12 */
ULONG DEVAPI SKF_ImportECCKeyPair(
	HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob);

/* 7.6.13 */
ULONG DEVAPI SKF_ECCSignData(
	HCONTAINER hContainer,
	BYTE *pbDigest,
	ULONG ulDigestLen,
	ECCSIGNATUREBLOB *pSignature);

#ifdef SKF_HAS_ECCDECRYPT
ULONG DEVAPI SKF_ECCDecrypt(
	HCONTAINER hContainer,
	ECCCIPHERBLOB *pCipherBlob,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen);
#endif

/* 7.6.14 */
ULONG DEVAPI SKF_ECCVerify(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

/* 7.6.15 */
ULONG DEVAPI SKF_ECCExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	ECCCIPHERBLOB *pData,
	HANDLE *phSessionKey);

/* 7.6.16 */
ULONG DEVAPI SKF_ExtECCEncrypt(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText);

/* 7.6.17 */
ULONG DEVAPI SKF_ExtECCDecrypt(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen);

/* 7.6.18 */
ULONG DEVAPI SKF_ExtECCSign(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

/* 7.6.19 */
ULONG DEVAPI SKF_ExtECCVerify(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature);

/* 7.6.20 */
ULONG DEVAPI SKF_GenerateAgreementDataWithECC(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phAgreementHandle);

/* 7.6.21 */
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
	HANDLE *phKeyHandle);

/* 7.6.22 */
ULONG DEVAPI SKF_GenerateKeyWithECC(
	HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phKeyHandle);

/* 7.6.23 */
ULONG DEVAPI SKF_ExportPublicKey(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen);

/* 7.6.24 */
ULONG DEVAPI SKF_ImportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey);

/* 7.6.25 */
ULONG DEVAPI SKF_SetSymmKey(
	DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey);

/* 7.6.26 */
ULONG DEVAPI SKF_EncryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM EncryptParam);

/* 7.6.27 */
ULONG DEVAPI SKF_Encrypt(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen);

/* 7.6.28 */
ULONG DEVAPI SKF_EncryptUpdate(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen);

/* 7.6.29 */
ULONG DEVAPI SKF_EncryptFinal(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen);

/* 7.6.30 */
ULONG DEVAPI SKF_DecryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam);

/* 7.6.31 */
ULONG DEVAPI SKF_Decrypt(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen);

/* 7.6.32 */
ULONG DEVAPI SKF_DecryptUpdate(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen);

/* 7.6.33 */
ULONG DEVAPI SKF_DecryptFinal(
	HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen);

/* 7.6.34 */
ULONG DEVAPI SKF_DigestInit(
	DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phHash);

/* 7.6.35 */
ULONG DEVAPI SKF_Digest(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen);

/* 7.6.36 */
ULONG DEVAPI SKF_DigestUpdate(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen);

/* 7.6.37 */
ULONG DEVAPI SKF_DigestFinal(
	HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen);

/* 7.6.38 */
ULONG DEVAPI SKF_MacInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac);

/* 7.6.39 */
ULONG DEVAPI SKF_Mac(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMacData,
	ULONG *pulMacLen);

/* 7.6.40 */
ULONG DEVAPI SKF_MacUpdate(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen);

/* 7.6.41 */
ULONG DEVAPI SKF_MacFinal(
	HANDLE hMac,
	BYTE *pbMacData,
	ULONG *pulMacDataLen);

/* 7.6.42 */
ULONG DEVAPI SKF_CloseHandle(
	HANDLE hHandle);


#define SAR_OK				0x00000000
#define SAR_FAIL			0x0A000001
#define SAR_UNKNOWNERR			0x0A000002
#define SAR_NOTSUPPORTYETERR		0x0A000003
#define SAR_FILEERR			0x0A000004
#define SAR_INVALIDHANDLEERR		0x0A000005
#define SAR_INVALIDPARAMERR		0x0A000006
#define SAR_READFILEERR			0x0A000007
#define SAR_WRITEFILEERR		0x0A000008
#define SAR_NAMELENERR			0x0A000009
#define SAR_KEYUSAGEERR			0x0A00000A
#define SAR_MODULUSLENERR		0x0A00000B
#define SAR_NOTINITIALIZEERR		0x0A00000C
#define SAR_OBJERR			0x0A00000D
#define SAR_MEMORYERR			0x0A00000E
#define SAR_TIMEOUTERR			0x0A00000F
#define SAR_INDATALENERR		0x0A000010
#define SAR_INDATAERR			0x0A000011
#define SAR_GENRANDERR			0x0A000012
#define SAR_HASHOBJERR			0x0A000013
#define SAR_HASHERR			0x0A000014
#define SAR_GENRSAKEYERR		0x0A000015
#define SAR_RSAMODULUSLENERR		0x0A000016
#define SAR_CSPIMPRTPUBKEYERR		0x0A000017
#define SAR_RSAENCERR			0x0A000018
#define SAR_RSADECERR			0x0A000019
#define SAR_HASHNOTEQUALERR		0x0A00001A
#define SAR_KEYNOTFOUNTERR		0x0A00001B
#define SAR_CERTNOTFOUNTERR		0x0A00001C
#define SAR_NOTEXPORTERR		0x0A00001D
#define SAR_DECRYPTPADERR		0x0A00001E
#define SAR_MACLENERR			0x0A00001F
#define SAR_BUFFER_TOO_SMALL		0x0A000020
#define SAR_KEYINFOTYPEERR		0x0A000021
#define SAR_NOT_EVENTERR		0x0A000022
#define SAR_DEVICE_REMOVED		0x0A000023
#define SAR_PIN_INCORRECT		0x0A000024
#define SAR_PIN_LOCKED			0x0A000025
#define SAR_PIN_INVALID			0x0A000026
#define SAR_PIN_LEN_RANGE		0x0A000027
#define SAR_USER_ALREADY_LOGGED_IN	0x0A000028
#define SAR_USER_PIN_NOT_INITIALIZED	0x0A000029
#define SAR_USER_TYPE_INVALID		0x0A00002A
#define SAR_APPLICATION_NAME_INVALID	0x0A00002B
#define SAR_APPLICATION_EXISTS		0x0A00002C
#define SAR_USER_NOT_LOGGED_IN		0x0A00002D
#define SAR_APPLICATION_NOT_EXISTS	0x0A00002E
#define SAR_FILE_ALREADY_EXIST		0x0A00002F
#define SAR_NO_ROOM			0x0A000030
#define SAR_FILE_NOT_EXIST		0x0A000031
#define SAR_REACH_MAX_CONTAINER_COUNT	0x0A000032


#ifdef __cplusplus
}
#endif
#endif
#endif
