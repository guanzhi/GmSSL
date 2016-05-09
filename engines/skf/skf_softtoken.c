#include <stdio.h>
#include <string.h>
#include "skf.h"

#define DEV_NAME		"skf-soft-token"
#define DEV_NAME_LIST		DEV_NAME"\0"
#define APP_NAME		"default-app"
#define APP_NAME_LIST		APP_NAME"\0"
#define CONTAINER_NAME		"container0"
#define CONTAINER_NAME_LIST	CONTAINER_NAME"\0"



ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName,
	ULONG *pulDevNameLen, ULONG *pulEvent)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CancelWaitForDevEvent()
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_EnumDev(BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ConnectDev(LPSTR szName,
	DEVHANDLE *phDev)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DisConnectDev(DEVHANDLE hDev)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevState(LPSTR szDevName,
	ULONG *pulDevState)
{
	if (!pulDevState) {
		return SAR_INVALIDPARAMERR;
	}
	*pulDevState = DEV_PRESENT_STATE;
	return SAR_OK;
}

ULONG DEVAPI SKF_SetLabel(DEVHANDLE hDev,
	LPSTR szLabel)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevInfo(DEVHANDLE hDev,
	DEVINFO *pDevInfo)
{
	DEVINFO devInfo;

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
	return SAR_OK;
}

ULONG DEVAPI SKF_UnlockDev(DEVHANDLE hDev)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ChangeDevAuthKey(DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DevAuth(DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ChangePIN(HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount)
{
	return SAR_OK;
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
	return SAR_OK;
}

ULONG DEVAPI SKF_UnblockPIN(HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ClearSecureState(HAPPLICATION hApplication)
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
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize)
{
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
	return SAR_OK;
}

ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication)
{
	if (!phApplication) {
		return SAR_INVALIDPARAMERR;
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_CreateFile(HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize, 
	ULONG ulReadRights,
	ULONG ulWriteRights)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_DeleteFile(HAPPLICATION hApplication,
	LPSTR szFileName)
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
	BYTE * pbOutData, 
	ULONG *pulOutLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_WriteFile(HAPPLICATION hApplication, 
	LPSTR szFileName,
	ULONG  ulOffset, 
	BYTE *pbData,
	ULONG ulSize)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CreateContainer(HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication, 
	LPSTR szContainerName)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_EnumContainer(HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize)
{
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
	return SAR_OK;
}

ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GetContainerType(HCONTAINER hContainer,
	ULONG *pulContainerType)
{
	if (!pulContainerType) {
		return SAR_INVALIDPARAMERR;
	}
	*pulContainerType = CONTAINER_TYPE_ECC;
	return SAR_OK;
}

ULONG DEVAPI SKF_ImportCertificate(HCONTAINER hContainer, 
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG ulCertLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE* pbCert,
	ULONG *pulCertLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_GenRandom(DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GenExtRSAKey(DEVHANDLE hDev, 
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob)
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

ULONG DEVAPI SKF_RSAVerify(DEVHANDLE hDev, 
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen)
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

ULONG DEVAPI SKF_ExtRSAPubKeyOperation(DEVHANDLE hDev, 
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtRSAPriKeyOperation(DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
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
	PENVELOPEDKEYBLOB pEnvelopedKeyBlob)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ECCSignData(HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	PECCSIGNATUREBLOB pSignature)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ECCVerify(DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	PECCSIGNATUREBLOB pSignature)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ECCExportSessionKey(HCONTAINER hContainer, 
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	PECCCIPHERBLOB pData,
	HANDLE *phSessionKey)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtECCEncrypt(DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	PECCCIPHERBLOB pCipherText)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtECCDecrypt(DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	PECCCIPHERBLOB pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtECCSign(DEVHANDLE hDev, 
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	PECCSIGNATUREBLOB pSignature)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_ExtECCVerify(DEVHANDLE hDev, 
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData, 
	ULONG ulDataLen, 
	PECCSIGNATUREBLOB pSignature)
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

ULONG DEVAPI SKF_ExportPublicKey(HCONTAINER hContainer, 
	BOOL bSignFlag,
	BYTE* pbBlob, 
	ULONG* pulBlobLen)
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

ULONG DEVAPI SKF_SetSymmKey(DEVHANDLE hDev, 
	BYTE *pbKey,
	ULONG ulAlgID, 
	HANDLE *phKey)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptInit(HANDLE hKey, 
	BLOCKCIPHERPARAM EncryptParam)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_Encrypt(HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen, 
	BYTE *pbEncryptedData, 
	ULONG *pulEncryptedLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptFinal(HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptInit(HANDLE hKey, 
	BLOCKCIPHERPARAM DecryptParam)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_Decrypt(HANDLE hKey, 
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen, 
	BYTE *pbData, 
	ULONG *pulDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey, 
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen, 
	BYTE *pbData, 
	ULONG *pulDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptFinal(HANDLE hKey, 
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pucID,
	ULONG ulIDLen,
	HANDLE *phHash)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_Digest(HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestUpdate(HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DigestFinal(HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_MacInit(HANDLE hKey, 
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_Mac(HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen, 
	BYTE *pbMacData, 
	ULONG *pulMacLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_MacUpdate(HANDLE hMac, 
	BYTE *pbData,
	ULONG ulDataLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_MacFinal(HANDLE hMac, 
	BYTE *pbMacData,
	ULONG *pulMacDataLen)
{
	return SAR_NOTSUPPORTYETERR;
}

ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle)
{
	return SAR_NOTSUPPORTYETERR;
}

