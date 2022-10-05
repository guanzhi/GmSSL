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
#include "skf_int.h"



SKF_METHOD *skf_method = NULL;
SKF_VENDOR *skf_vendor = NULL;
extern SKF_VENDOR skf_wisec;


#define SKFerr(f,e)


ULONG DEVAPI SKF_LoadLibrary(LPSTR so_path, LPSTR vendor)
{
	if (skf_method) {
		SKF_METHOD_free(skf_method);
		skf_method = NULL;
	}

	if (!(skf_method = SKF_METHOD_load_library((char *)so_path))) {
		SKFerr(SKF_F_SKF_LOADLIBRARY, SKF_R_LOAD_LIBRARY_FAILURE);
		return SAR_FAIL;
	}

	if (vendor) {
		if (strcmp((char *)vendor, skf_wisec.name) == 0) {
			skf_vendor = &skf_wisec;
		} else {
			SKFerr(SKF_F_SKF_LOADLIBRARY, SKF_R_UNKNOWN_VENDOR);
			return SAR_FAIL;
		}
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_UnloadLibrary(void)
{
	SKF_METHOD_free(skf_method);
	skf_method = NULL;
	skf_vendor = NULL;
	return SAR_OK;
}

/*
static SKF_ERR_REASON skf_errors[] = {
	{ SAR_OK,			SKF_R_SUCCESS },
	{ SAR_FAIL,			SKF_R_FAILURE },
	{ SAR_UNKNOWNERR,		SKF_R_UNKNOWN_ERROR },
	{ SAR_NOTSUPPORTYETERR,		SKF_R_OPERATION_NOT_SUPPORTED },
	{ SAR_FILEERR,			SKF_R_FILE_ERROR },
	{ SAR_INVALIDHANDLEERR,		SKF_R_INVALID_HANDLE },
	{ SAR_INVALIDPARAMERR,		SKF_R_INVALID_PARAMETER },
	{ SAR_READFILEERR,		SKF_R_READ_FILE_FAILURE },
	{ SAR_WRITEFILEERR,		SKF_R_WRITE_FILE_FAILURE },
	{ SAR_NAMELENERR,		SKF_R_INVALID_NAME_LENGTH },
	{ SAR_KEYUSAGEERR,		SKF_R_INVALID_KEY_USAGE },
	{ SAR_MODULUSLENERR,		SKF_R_INVALID_MODULUS_LENGTH },
	{ SAR_NOTINITIALIZEERR,		SKF_R_NOT_INITIALIZED },
	{ SAR_OBJERR,			SKF_R_INVALID_OBJECT },
	{ SAR_MEMORYERR,		SKF_R_MEMORY_ERROR },
	{ SAR_TIMEOUTERR,		SKF_R_TIMEOUT },
	{ SAR_INDATALENERR,		SKF_R_INVALID_INPUT_LENGTH },
	{ SAR_INDATAERR,		SKF_R_INVALID_INPUT_VALUE },
	{ SAR_GENRANDERR,		SKF_R_RANDOM_GENERATION_FAILED },
	{ SAR_HASHOBJERR,		SKF_R_INVALID_DIGEST_HANDLE },
	{ SAR_HASHERR,			SKF_R_DIGEST_ERROR },
	{ SAR_GENRSAKEYERR,		SKF_R_RSA_KEY_GENERATION_FAILURE },
	{ SAR_RSAMODULUSLENERR,		SKF_R_INVALID_RSA_MODULUS_LENGTH },
	{ SAR_CSPIMPRTPUBKEYERR,	SKF_R_CSP_IMPORT_PUBLIC_KEY_ERROR },
	{ SAR_RSAENCERR,		SKF_R_RSA_ENCRYPTION_FAILURE },
	{ SAR_RSADECERR,		SKF_R_RSA_DECRYPTION_FAILURE },
	{ SAR_HASHNOTEQUALERR,		SKF_R_HASH_NOT_EQUAL },
	{ SAR_KEYNOTFOUNTERR,		SKF_R_KEY_NOT_FOUND },
	{ SAR_CERTNOTFOUNTERR,		SKF_R_CERTIFICATE_NOT_FOUND },
	{ SAR_NOTEXPORTERR,		SKF_R_EXPORT_FAILED },
	{ SAR_DECRYPTPADERR,		SKF_R_DECRYPT_INVALID_PADDING },
	{ SAR_MACLENERR,		SKF_R_INVALID_MAC_LENGTH },
	{ SAR_BUFFER_TOO_SMALL,		SKF_R_BUFFER_TOO_SMALL },
	{ SAR_KEYINFOTYPEERR,		SKF_R_INVALID_KEY_INFO_TYPE },
	{ SAR_NOT_EVENTERR,		SKF_R_NO_EVENT },
	{ SAR_DEVICE_REMOVED,		SKF_R_DEVICE_REMOVED },
	{ SAR_PIN_INCORRECT,		SKF_R_PIN_INCORRECT },
	{ SAR_PIN_LOCKED,		SKF_R_PIN_LOCKED },
	{ SAR_PIN_INVALID,		SKF_R_INVALID_PIN },
	{ SAR_PIN_LEN_RANGE,		SKF_R_INVALID_PIN_LENGTH },
	{ SAR_USER_ALREADY_LOGGED_IN,	SKF_R_USER_ALREADY_LOGGED_IN },
	{ SAR_USER_PIN_NOT_INITIALIZED,	SKF_R_USER_PIN_NOT_INITIALIZED },
	{ SAR_USER_TYPE_INVALID,	SKF_R_INVALID_USER_TYPE },
	{ SAR_APPLICATION_NAME_INVALID, SKF_R_INVALID_APPLICATION_NAME },
	{ SAR_APPLICATION_EXISTS,	SKF_R_APPLICATION_ALREADY_EXIST },
	{ SAR_USER_NOT_LOGGED_IN,	SKF_R_USER_NOT_LOGGED_IN },
	{ SAR_APPLICATION_NOT_EXISTS,	SKF_R_APPLICATION_NOT_EXIST },
	{ SAR_FILE_ALREADY_EXIST,	SKF_R_FILE_ALREADY_EXIST },
	{ SAR_NO_ROOM,			SKF_R_NO_SPACE },
	{ SAR_FILE_NOT_EXIST,		SKF_R_FILE_NOT_EXIST },
};
*/

static unsigned long skf_get_error_reason(ULONG ulError)
{
/*
	int i;
	for (i = 0; i < OSSL_NELEM(skf_errors); i++) {
		if (ulError == skf_errors[i].err) {
			return skf_errors[i].reason;
		}
	}
	if (skf_vendor) {
		return skf_vendor->get_error_reason(ulError);
	}
*/
	return 0;
}

ULONG DEVAPI SKF_GetErrorString(ULONG ulError, LPSTR *szErrorStr)
{
	unsigned long reason;

	if ((reason = skf_get_error_reason(ulError)) != 0) {
		//*szErrorStr = (LPSTR)ERR_reason_error_string(reason);
	} else {
		*szErrorStr = (LPSTR)"(unknown)";
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_WaitForDevEvent(
	LPSTR szDevName,
	ULONG *pulDevNameLen,
	ULONG *pulEvent)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_WAITFORDEVEVENT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->WaitForDevEvent) {
		SKFerr(SKF_F_SKF_WAITFORDEVEVENT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->WaitForDevEvent(
		szDevName,
		pulDevNameLen,
		pulEvent)) != SAR_OK) {
		SKFerr(SKF_F_SKF_WAITFORDEVEVENT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CancelWaitForDevEvent(
	void)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CANCELWAITFORDEVEVENT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CancelWaitForDevEvent) {
		SKFerr(SKF_F_SKF_CANCELWAITFORDEVEVENT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_method->CancelWaitForDevEvent) {
		return skf_method->CancelWaitForDevEvent();
	}

	if ((rv = skf_method->CancelWaitForDevEvent()) != SAR_OK) {
		SKFerr(SKF_F_SKF_CANCELWAITFORDEVEVENT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EnumDev(
	BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize)
{
	ULONG rv;

				
	// check output of all enum functions !!!!

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ENUMDEV,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EnumDev) {
		SKFerr(SKF_F_SKF_ENUMDEV,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (szNameList) {
		memset(szNameList, 0, *pulSize);
	}

	if ((rv = skf_method->EnumDev(
		bPresent,
		szNameList,
		pulSize)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENUMDEV, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ConnectDev(
	LPSTR szName,
	DEVHANDLE *phDev)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CONNECTDEV,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ConnectDev) {
		SKFerr(SKF_F_SKF_CONNECTDEV,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ConnectDev(
		szName,
		phDev)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CONNECTDEV, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DisConnectDev(
	DEVHANDLE hDev)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DISCONNECTDEV,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DisConnectDev) {
		SKFerr(SKF_F_SKF_DISCONNECTDEV,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DisConnectDev(
		hDev)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DISCONNECTDEV, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevState(
	LPSTR szDevName,
	ULONG *pulDevState)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GETDEVSTATE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetDevState) {
		SKFerr(SKF_F_SKF_GETDEVSTATE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GetDevState(
		szDevName,
		pulDevState)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GETDEVSTATE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_SetLabel(
	DEVHANDLE hDev,
	LPSTR szLabel)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_SETLABEL,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->SetLabel) {
		SKFerr(SKF_F_SKF_SETLABEL,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->SetLabel(
		hDev,
		szLabel)) != SAR_OK) {
		SKFerr(SKF_F_SKF_SETLABEL, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevInfo(
	DEVHANDLE hDev,
	DEVINFO *pDevInfo)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GETDEVINFO,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetDevInfo) {
		SKFerr(SKF_F_SKF_GETDEVINFO,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	memset(pDevInfo, 0, sizeof(DEVINFO));

	if ((rv = skf_method->GetDevInfo(
		hDev,
		pDevInfo)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GETDEVINFO, skf_get_error_reason(rv));
		printf("rv = %8x\n", rv);
		return rv;
	}

	if (skf_vendor) {
		pDevInfo->AlgSymCap = skf_vendor->get_cipher_cap(pDevInfo->AlgSymCap);
		pDevInfo->AlgAsymCap = skf_vendor->get_pkey_cap(pDevInfo->AlgAsymCap);
		pDevInfo->AlgHashCap = skf_vendor->get_digest_cap(pDevInfo->AlgHashCap);
		pDevInfo->DevAuthAlgId = skf_vendor->get_cipher_cap(pDevInfo->DevAuthAlgId);
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_LockDev(
	DEVHANDLE hDev,
	ULONG ulTimeOut)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_LOCKDEV,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->LockDev) {
		SKFerr(SKF_F_SKF_LOCKDEV,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->LockDev(
		hDev,
		ulTimeOut)) != SAR_OK) {
		SKFerr(SKF_F_SKF_LOCKDEV, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_UnlockDev(
	DEVHANDLE hDev)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_UNLOCKDEV,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->UnlockDev) {
		SKFerr(SKF_F_SKF_UNLOCKDEV,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->UnlockDev(
		hDev)) != SAR_OK) {
		SKFerr(SKF_F_SKF_UNLOCKDEV, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Transmit(
	DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_TRANSMIT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Transmit) {
		SKFerr(SKF_F_SKF_TRANSMIT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Transmit(
		hDev,
		pbCommand,
		ulCommandLen,
		pbData,
		pulDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_TRANSMIT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ChangeDevAuthKey(
	DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CHANGEDEVAUTHKEY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ChangeDevAuthKey) {
		SKFerr(SKF_F_SKF_CHANGEDEVAUTHKEY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ChangeDevAuthKey(
		hDev,
		pbKeyValue,
		ulKeyLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CHANGEDEVAUTHKEY, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DevAuth(
	DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DEVAUTH,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DevAuth) {
		SKFerr(SKF_F_SKF_DEVAUTH,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DevAuth(
		hDev,
		pbAuthData,
		ulLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DEVAUTH, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ChangePIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CHANGEPIN,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ChangePIN) {
		SKFerr(SKF_F_SKF_CHANGEPIN,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ChangePIN(
		hApplication,
		ulPINType,
		szOldPin,
		szNewPin,
		pulRetryCount)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CHANGEPIN, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

LONG DEVAPI SKF_GetPINInfo(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GETPININFO,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetPINInfo) {
		SKFerr(SKF_F_SKF_GETPININFO,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GetPINInfo(
		hApplication,
		ulPINType,
		pulMaxRetryCount,
		pulRemainRetryCount,
		pbDefaultPin)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GETPININFO, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_VerifyPIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_VERIFYPIN,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->VerifyPIN) {
		SKFerr(SKF_F_SKF_VERIFYPIN,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->VerifyPIN(
		hApplication,
		ulPINType,
		szPIN,
		pulRetryCount)) != SAR_OK) {
		SKFerr(SKF_F_SKF_VERIFYPIN, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_UnblockPIN(
	HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_UNBLOCKPIN,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->UnblockPIN) {
		SKFerr(SKF_F_SKF_UNBLOCKPIN,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->UnblockPIN(
		hApplication,
		szAdminPIN,
		szNewUserPIN,
		pulRetryCount)) != SAR_OK) {
		SKFerr(SKF_F_SKF_UNBLOCKPIN, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ClearSecureState(
	HAPPLICATION hApplication)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CLEARSECURESTATE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ClearSecureState) {
		SKFerr(SKF_F_SKF_CLEARSECURESTATE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ClearSecureState(
		hApplication)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CLEARSECURESTATE, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CREATEAPPLICATION,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CreateApplication) {
		SKFerr(SKF_F_SKF_CREATEAPPLICATION,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CreateApplication(
		hDev,
		szAppName,
		szAdminPin,
		dwAdminPinRetryCount,
		szUserPin,
		dwUserPinRetryCount,
		dwCreateFileRights,
		phApplication)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CREATEAPPLICATION, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EnumApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ENUMAPPLICATION,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EnumApplication) {
		SKFerr(SKF_F_SKF_ENUMAPPLICATION,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EnumApplication(
		hDev,
		szAppName,
		pulSize)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENUMAPPLICATION, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteApplication(
	DEVHANDLE hDev,
	LPSTR szAppName)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DELETEAPPLICATION,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DeleteApplication) {
		SKFerr(SKF_F_SKF_DELETEAPPLICATION,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DeleteApplication(
		hDev,
		szAppName)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DELETEAPPLICATION, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_OpenApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_OPENAPPLICATION,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->OpenApplication) {
		SKFerr(SKF_F_SKF_OPENAPPLICATION,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->OpenApplication(
		hDev,
		szAppName,
		phApplication)) != SAR_OK) {
		SKFerr(SKF_F_SKF_OPENAPPLICATION, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CloseApplication(
	HAPPLICATION hApplication)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CLOSEAPPLICATION,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CloseApplication) {
		SKFerr(SKF_F_SKF_CLOSEAPPLICATION,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CloseApplication(
		hApplication)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CLOSEAPPLICATION, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CreateFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CREATEFILE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CreateObject) {
		SKFerr(SKF_F_SKF_CREATEFILE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CreateObject(
		hApplication,
		szFileName,
		ulFileSize,
		ulReadRights,
		ulWriteRights)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CREATEFILE, skf_get_error_reason(rv));

		//LPSTR str = NULL;
		//printf("error = %08X\n", rv);
		//SKF_GetErrorString(rv, &str);
		//printf("error = %s\n", (char *)str);
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DELETEFILE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DeleteObject) {
		SKFerr(SKF_F_SKF_DELETEFILE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DeleteObject(
		hApplication,
		szFileName)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DELETEFILE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EnumFiles(
	HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ENUMFILES,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EnumObjects) {
		SKFerr(SKF_F_SKF_ENUMFILES,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EnumObjects(
		hApplication,
		szFileList,
		pulSize)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENUMFILES, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GetFileInfo(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GETFILEINFO,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetObjectInfo) {
		SKFerr(SKF_F_SKF_GETFILEINFO,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	memset(pFileInfo, 0, sizeof(FILEATTRIBUTE));

	if ((rv = skf_method->GetObjectInfo(
		hApplication,
		szFileName,
		pFileInfo)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GETFILEINFO, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_READFILE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ReadObject) {
		SKFerr(SKF_F_SKF_READFILE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ReadObject(
		hApplication,
		szFileName,
		ulOffset,
		ulSize,
		pbOutData,
		pulOutLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_READFILE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_WriteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	BYTE *pbData,
	ULONG ulSize)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_WRITEFILE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->WriteObject) {
		SKFerr(SKF_F_SKF_WRITEFILE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->WriteObject(
		hApplication,
		szFileName,
		ulOffset,
		pbData,
		ulSize)) != SAR_OK) {
		SKFerr(SKF_F_SKF_WRITEFILE, skf_get_error_reason(rv));

		printf("error = %08X\n", rv);

		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CreateContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CREATECONTAINER,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CreateContainer) {
		SKFerr(SKF_F_SKF_CREATECONTAINER,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CreateContainer(
		hApplication,
		szContainerName,
		phContainer)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CREATECONTAINER, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DELETECONTAINER,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DeleteContainer) {
		SKFerr(SKF_F_SKF_DELETECONTAINER,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DeleteContainer(
		hApplication,
		szContainerName)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DELETECONTAINER, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EnumContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ENUMCONTAINER,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EnumContainer) {
		SKFerr(SKF_F_SKF_ENUMCONTAINER,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EnumContainer(
		hApplication,
		szContainerName,
		pulSize)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENUMCONTAINER, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_OpenContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_OPENCONTAINER,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->OpenContainer) {
		SKFerr(SKF_F_SKF_OPENCONTAINER,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->OpenContainer(
		hApplication,
		szContainerName,
		phContainer)) != SAR_OK) {
		SKFerr(SKF_F_SKF_OPENCONTAINER, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CloseContainer(
	HCONTAINER hContainer)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CLOSECONTAINER,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CloseContainer) {
		SKFerr(SKF_F_SKF_CLOSECONTAINER,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CloseContainer(
		hContainer)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CLOSECONTAINER, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GetContainerType(
	HCONTAINER hContainer,
	ULONG *pulContainerType)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GETCONTAINERTYPE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetContainerType) {
		SKFerr(SKF_F_SKF_GETCONTAINERTYPE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GetContainerType(
		hContainer,
		pulContainerType)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GETCONTAINERTYPE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ImportCertificate(
	HCONTAINER hContainer,
	BOOL bExportSignKey,
	BYTE *pbCert,
	ULONG ulCertLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_IMPORTCERTIFICATE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ImportCertificate) {
		SKFerr(SKF_F_SKF_IMPORTCERTIFICATE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ImportCertificate(
		hContainer,
		bExportSignKey,
		pbCert,
		ulCertLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTCERTIFICATE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExportCertificate(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG *pulCertLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_EXPORTCERTIFICATE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExportCertificate) {
		SKFerr(SKF_F_SKF_EXPORTCERTIFICATE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExportCertificate(
		hContainer,
		bSignFlag,
		pbCert,
		pulCertLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXPORTCERTIFICATE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExportPublicKey(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen)
{
	ULONG rv;

	// TODO: check the output length, clear the memmory.
	// if pbBlob is NULL, return the length

	if (!skf_method) {
		SKFerr(SKF_F_SKF_EXPORTPUBLICKEY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExportPublicKey) {
		SKFerr(SKF_F_SKF_EXPORTPUBLICKEY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExportPublicKey(
		hContainer,
		bSignFlag,
		pbBlob,
		pulBlobLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXPORTPUBLICKEY, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenRandom(
	DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GENRANDOM,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenRandom) {
		SKFerr(SKF_F_SKF_GENRANDOM,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GenRandom(
		hDev,
		pbRandom,
		ulRandomLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GENRANDOM, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenExtRSAKey(
	DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GENEXTRSAKEY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenExtRSAKey) {
		SKFerr(SKF_F_SKF_GENEXTRSAKEY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GenExtRSAKey(
		hDev,
		ulBitsLen,
		pBlob)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GENEXTRSAKEY, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GENRSAKEYPAIR,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenRSAKeyPair) {
		SKFerr(SKF_F_SKF_GENRSAKEYPAIR,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	memset(pBlob, 0, sizeof(RSAPUBLICKEYBLOB));
	if ((rv = skf_method->GenRSAKeyPair(
		hContainer,
		ulBitsLen,
		pBlob)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GENRSAKEYPAIR, skf_get_error_reason(rv));
		return rv;
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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_IMPORTRSAKEYPAIR,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ImportRSAKeyPair) {
		SKFerr(SKF_F_SKF_IMPORTRSAKEYPAIR,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulSymAlgId = skf_vendor->get_cipher_algor(ulSymAlgId))) {
			SKFerr(SKF_F_SKF_IMPORTRSAKEYPAIR,
				SKF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->ImportRSAKeyPair(
		hContainer,
		ulSymAlgId,
		pbWrappedKey,
		ulWrappedKeyLen,
		pbEncryptedData,
		ulEncryptedDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTRSAKEYPAIR, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_RSASignData(
	HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_RSASIGNDATA,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->RSASignData) {
		SKFerr(SKF_F_SKF_RSASIGNDATA,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->RSASignData(
		hContainer,
		pbData,
		ulDataLen,
		pbSignature,
		pulSignLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_RSASIGNDATA, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_RSAVERIFY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->RSAVerify) {
		SKFerr(SKF_F_SKF_RSAVERIFY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->RSAVerify(
		hDev,
		pRSAPubKeyBlob,
		pbData,
		ulDataLen,
		pbSignature,
		ulSignLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_RSAVERIFY, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_RSAEXPORTSESSIONKEY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->RSAExportSessionKey) {
		SKFerr(SKF_F_SKF_RSAEXPORTSESSIONKEY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			SKFerr(SKF_F_SKF_RSAEXPORTSESSIONKEY,
				SKF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->RSAExportSessionKey(
		hContainer,
		ulAlgId,
		pPubKey,
		pbData,
		pulDataLen,
		phSessionKey)) != SAR_OK) {
		SKFerr(SKF_F_SKF_RSAEXPORTSESSIONKEY, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtRSAPubKeyOperation) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtRSAPubKeyOperation(
		hDev,
		pRSAPubKeyBlob,
		pbInput,
		ulInputLen,
		pbOutput,
		pulOutputLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtRSAPriKeyOperation) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtRSAPriKeyOperation(
		hDev,
		pRSAPriKeyBlob,
		pbInput,
		ulInputLen,
		pbOutput,
		pulOutputLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenECCKeyPair(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GENECCKEYPAIR,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenECCKeyPair) {
		SKFerr(SKF_F_SKF_GENECCKEYPAIR,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_pkey_algor(ulAlgId))) {
			SKFerr(SKF_F_SKF_GENECCKEYPAIR,
				SKF_R_NOT_SUPPORTED_PKEY_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	memset(pBlob, 0, sizeof(ECCPUBLICKEYBLOB));
	if ((rv = skf_method->GenECCKeyPair(
		hContainer,
		ulAlgId,
		pBlob)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GENECCKEYPAIR, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ImportECCKeyPair(
	HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_IMPORTECCKEYPAIR,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ImportECCKeyPair) {
		SKFerr(SKF_F_SKF_IMPORTECCKEYPAIR,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ImportECCKeyPair(
		hContainer,
		pEnvelopedKeyBlob)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTECCKEYPAIR, skf_get_error_reason(rv));
		printf("%s %d: error = %08X\n", __FILE__, __LINE__, rv);
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ECCSignData(
	HCONTAINER hContainer,
	BYTE *pbDigest,
	ULONG ulDigestLen,
	ECCSIGNATUREBLOB *pSignature)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ECCSIGNDATA,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ECCSignData) {
		SKFerr(SKF_F_SKF_ECCSIGNDATA,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ECCSignData(
		hContainer,
		pbDigest,
		ulDigestLen,
		pSignature)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ECCSIGNDATA, skf_get_error_reason(rv));
		return rv;
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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ECCVERIFY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ECCVerify) {
		SKFerr(SKF_F_SKF_ECCVERIFY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ECCVerify(
		hDev,
		pECCPubKeyBlob,
		pbData,
		ulDataLen,
		pSignature)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ECCVERIFY, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ECCExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	ECCCIPHERBLOB *pData,
	HANDLE *phSessionKey)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ECCEXPORTSESSIONKEY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ECCExportSessionKey) {
		SKFerr(SKF_F_SKF_ECCEXPORTSESSIONKEY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			SKFerr(SKF_F_SKF_ECCEXPORTSESSIONKEY,
				SKF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->ECCExportSessionKey(
		hContainer,
		ulAlgId,
		pPubKey,
		pData,
		phSessionKey)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ECCEXPORTSESSIONKEY, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ECCDecrypt(
	HCONTAINER hContainer,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ECCDECRYPT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ECCDecrypt) {
		SKFerr(SKF_F_SKF_ECCDECRYPT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ECCDecrypt(
		hContainer,
		pCipherText,
		pbPlainText,
		pulPlainTextLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ECCDECRYPT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCEncrypt(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_EXTECCENCRYPT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtECCEncrypt) {
		SKFerr(SKF_F_SKF_EXTECCENCRYPT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtECCEncrypt(
		hDev,
		pECCPubKeyBlob,
		pbPlainText,
		ulPlainTextLen,
		pCipherText)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXTECCENCRYPT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCDecrypt(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_EXTECCDECRYPT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtECCDecrypt) {
		SKFerr(SKF_F_SKF_EXTECCDECRYPT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtECCDecrypt(
		hDev,
		pECCPriKeyBlob,
		pCipherText,
		pbPlainText,
		pulPlainTextLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXTECCDECRYPT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCSign(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_EXTECCSIGN,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtECCSign) {
		SKFerr(SKF_F_SKF_EXTECCSIGN,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtECCSign(
		hDev,
		pECCPriKeyBlob,
		pbData,
		ulDataLen,
		pSignature)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXTECCSIGN, skf_get_error_reason(rv));
		return rv;
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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_EXTECCVERIFY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtECCVerify) {
		SKFerr(SKF_F_SKF_EXTECCVERIFY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtECCVerify(
		hDev,
		pECCPubKeyBlob,
		pbData,
		ulDataLen,
		pSignature)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXTECCVERIFY, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GENERATEAGREEMENTDATAWITHECC,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenerateAgreementDataWithECC) {
		SKFerr(SKF_F_SKF_GENERATEAGREEMENTDATAWITHECC,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			SKFerr(SKF_F_SKF_GENERATEAGREEMENTDATAWITHECC,
				SKF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->GenerateAgreementDataWithECC(
		hContainer,
		ulAlgId,
		pTempECCPubKeyBlob,
		pbID,
		ulIDLen,
		phAgreementHandle)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GENERATEAGREEMENTDATAWITHECC, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GENERATEAGREEMENTDATAANDKEYWITHECC,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenerateAgreementDataAndKeyWithECC) {
		SKFerr(SKF_F_SKF_GENERATEAGREEMENTDATAANDKEYWITHECC,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			SKFerr(SKF_F_SKF_GENERATEAGREEMENTDATAANDKEYWITHECC,
				SKF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->GenerateAgreementDataAndKeyWithECC(
		hContainer,
		ulAlgId,
		pSponsorECCPubKeyBlob,
		pSponsorTempECCPubKeyBlob,
		pTempECCPubKeyBlob,
		pbID,
		ulIDLen,
		pbSponsorID,
		ulSponsorIDLen,
		phKeyHandle)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GENERATEAGREEMENTDATAANDKEYWITHECC, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_GENERATEKEYWITHECC,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenerateKeyWithECC) {
		SKFerr(SKF_F_SKF_GENERATEKEYWITHECC,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GenerateKeyWithECC(
		hAgreementHandle,
		pECCPubKeyBlob,
		pTempECCPubKeyBlob,
		pbID,
		ulIDLen,
		phKeyHandle)) != SAR_OK) {
		SKFerr(SKF_F_SKF_GENERATEKEYWITHECC, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ImportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_IMPORTSESSIONKEY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ImportSessionKey) {
		SKFerr(SKF_F_SKF_IMPORTSESSIONKEY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			SKFerr(SKF_F_SKF_IMPORTSESSIONKEY,
				SKF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->ImportSessionKey(
		hContainer,
		ulAlgId,
		pbWrapedData,
		ulWrapedLen,
		phKey)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTSESSIONKEY, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_SetSymmKey(
	DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_SETSYMMKEY,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->SetSymmKey) {
		SKFerr(SKF_F_SKF_SETSYMMKEY,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgID = skf_vendor->get_cipher_algor(ulAlgID))) {
			SKFerr(SKF_F_SKF_SETSYMMKEY,
				SKF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->SetSymmKey(
		hDev,
		pbKey,
		ulAlgID,
		phKey)) != SAR_OK) {
		SKFerr(SKF_F_SKF_SETSYMMKEY, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM EncryptParam)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ENCRYPTINIT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EncryptInit) {
		SKFerr(SKF_F_SKF_ENCRYPTINIT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EncryptInit(
		hKey,
		EncryptParam)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENCRYPTINIT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Encrypt(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ENCRYPT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Encrypt) {
		SKFerr(SKF_F_SKF_ENCRYPT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Encrypt(
		hKey,
		pbData,
		ulDataLen,
		pbEncryptedData,
		pulEncryptedLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENCRYPT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptUpdate(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ENCRYPTUPDATE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EncryptUpdate) {
		SKFerr(SKF_F_SKF_ENCRYPTUPDATE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EncryptUpdate(
		hKey,
		pbData,
		ulDataLen,
		pbEncryptedData,
		pulEncryptedLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENCRYPTUPDATE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptFinal(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_ENCRYPTFINAL,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EncryptFinal) {
		SKFerr(SKF_F_SKF_ENCRYPTFINAL,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EncryptFinal(
		hKey,
		pbEncryptedData,
		pulEncryptedDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_ENCRYPTFINAL, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DECRYPTINIT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DecryptInit) {
		SKFerr(SKF_F_SKF_DECRYPTINIT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DecryptInit(
		hKey,
		DecryptParam)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DECRYPTINIT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Decrypt(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DECRYPT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Decrypt) {
		SKFerr(SKF_F_SKF_DECRYPT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Decrypt(
		hKey,
		pbEncryptedData,
		ulEncryptedLen,
		pbData,
		pulDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DECRYPT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptUpdate(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DECRYPTUPDATE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DecryptUpdate) {
		SKFerr(SKF_F_SKF_DECRYPTUPDATE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DecryptUpdate(
		hKey,
		pbEncryptedData,
		ulEncryptedLen,
		pbData,
		pulDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DECRYPTUPDATE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptFinal(
	HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DECRYPTFINAL,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DecryptFinal) {
		SKFerr(SKF_F_SKF_DECRYPTFINAL,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DecryptFinal(
		hKey,
		pbDecryptedData,
		pulDecryptedDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DECRYPTFINAL, skf_get_error_reason(rv));
		return rv;
	}

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
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DIGESTINIT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DigestInit) {
		SKFerr(SKF_F_SKF_DIGESTINIT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgID = skf_vendor->get_digest_algor(ulAlgID))) {
			SKFerr(SKF_F_SKF_DIGESTINIT,
				SKF_R_NOT_SUPPORTED_DIGEST_ALGOR);
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->DigestInit(
		hDev,
		ulAlgID,
		pPubKey,
		pbID,
		ulIDLen,
		phHash)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DIGESTINIT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Digest(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DIGEST,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Digest) {
		SKFerr(SKF_F_SKF_DIGEST,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Digest(
		hHash,
		pbData,
		ulDataLen,
		pbHashData,
		pulHashLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DIGEST, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DigestUpdate(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DIGESTUPDATE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DigestUpdate) {
		SKFerr(SKF_F_SKF_DIGESTUPDATE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DigestUpdate(
		hHash,
		pbData,
		ulDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DIGESTUPDATE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DigestFinal(
	HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_DIGESTFINAL,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DigestFinal) {
		SKFerr(SKF_F_SKF_DIGESTFINAL,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DigestFinal(
		hHash,
		pHashData,
		pulHashLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_DIGESTFINAL, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_MacInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_MACINIT,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->MacInit) {
		SKFerr(SKF_F_SKF_MACINIT,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->MacInit(
		hKey,
		pMacParam,
		phMac)) != SAR_OK) {
		SKFerr(SKF_F_SKF_MACINIT, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Mac(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMacData,
	ULONG *pulMacLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_MAC,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Mac) {
		SKFerr(SKF_F_SKF_MAC,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Mac(
		hMac,
		pbData,
		ulDataLen,
		pbMacData,
		pulMacLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_MAC, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_MacUpdate(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_MACUPDATE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->MacUpdate) {
		SKFerr(SKF_F_SKF_MACUPDATE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->MacUpdate(
		hMac,
		pbData,
		ulDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_MACUPDATE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_MacFinal(
	HANDLE hMac,
	BYTE *pbMacData,
	ULONG *pulMacDataLen)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_MACFINAL,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->MacFinal) {
		SKFerr(SKF_F_SKF_MACFINAL,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->MacFinal(
		hMac,
		pbMacData,
		pulMacDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_MACFINAL, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CloseHandle(
	HANDLE hHandle)
{
	ULONG rv;

	if (!skf_method) {
		SKFerr(SKF_F_SKF_CLOSEHANDLE,
			SKF_R_SKF_METHOD_NOT_INITIALIZED);
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CloseHandle) {
		SKFerr(SKF_F_SKF_CLOSEHANDLE,
			SKF_R_FUNCTION_NOT_SUPPORTED);
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CloseHandle(
		hHandle)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CLOSEHANDLE, skf_get_error_reason(rv));
		return rv;
	}

	return SAR_OK;
}

