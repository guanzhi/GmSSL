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

#include <openssl/err.h>
#include "internal/dso.h"
#include "internal/sdf_meth.h"


SKF_METHOD *SKF_METHOD_load_library(const char *so_path)
{
	SKF_METHOD *ret = NULL;
	SKF_METHOD *skf = NULL;
	DSO *dso = NULL;
	void *func;
	int i;

	if (!(dso = DSO_load(NULL, so_path, NULL, 0))) {
		goto end;
	}
	if (!(skf = OPENSSL_zalloc(sizeof(*skf)))) {
		goto end;
	}

	skf->SKF_WaitForDevEvent = (SKF_WaitForDevEvent_FuncPtr)DSO_bind_func(dso, "SKF_WaitForDevEvent");
	skf->SKF_CancelWaitForDevEvent = (SKF_CancelWaitForDevEvent_FuncPtr)DSO_bind_func(dso, "SKF_CancelWaitForDevEvent");
	skf->SKF_EnumDev = (SKF_EnumDev_FuncPtr)DSO_bind_func(dso, "SKF_EnumDev");
	skf->SKF_ConnectDev = (SKF_ConnectDev_FuncPtr)DSO_bind_func(dso, "SKF_ConnectDev");
	skf->SKF_DisConnectDev = (SKF_DisConnectDev_FuncPtr)DSO_bind_func(dso, "SKF_DisConnectDev");
	skf->SKF_GetDevState = (SKF_GetDevState_FuncPtr)DSO_bind_func(dso, "SKF_GetDevState");
	skf->SKF_SetLabel = (SKF_SetLabel_FuncPtr)DSO_bind_func(dso, "SKF_SetLabel");
	skf->SKF_GetDevInfo = (SKF_GetDevInfo_FuncPtr)DSO_bind_func(dso, "SKF_GetDevInfo");
	skf->SKF_LockDev = (SKF_LockDev_FuncPtr)DSO_bind_func(dso, "SKF_LockDev");
	skf->SKF_UnlockDev = (SKF_UnlockDev_FuncPtr)DSO_bind_func(dso, "SKF_UnlockDev");
	skf->SKF_Transmit = (SKF_Transmit_FuncPtr)DSO_bind_func(dso, "SKF_Transmit");
	skf->SKF_ChangeDevAuthKey = (SKF_ChangeDevAuthKey_FuncPtr)DSO_bind_func(dso, "SKF_ChangeDevAuthKey");
	skf->SKF_DevAuth = (SKF_DevAuth_FuncPtr)DSO_bind_func(dso, "SKF_DevAuth");
	skf->SKF_ChangePIN = (SKF_ChangePIN_FuncPtr)DSO_bind_func(dso, "SKF_ChangePIN");
	skf->SKF_GetPINInfo = (SKF_GetPINInfo_FuncPtr)DSO_bind_func(dso, "SKF_GetPINInfo");
	skf->SKF_VerifyPIN = (SKF_VerifyPIN_FuncPtr)DSO_bind_func(dso, "SKF_VerifyPIN");
	skf->SKF_UnblockPIN = (SKF_UnblockPIN_FuncPtr)DSO_bind_func(dso, "SKF_UnblockPIN");
	skf->SKF_ClearSecureState = (SKF_ClearSecureState_FuncPtr)DSO_bind_func(dso, "SKF_ClearSecureState");
	skf->SKF_CreateApplication = (SKF_CreateApplication_FuncPtr)DSO_bind_func(dso, "SKF_CreateApplication");
	skf->SKF_EnumApplication = (SKF_EnumApplication_FuncPtr)DSO_bind_func(dso, "SKF_EnumApplication");
	skf->SKF_DeleteApplication = (SKF_DeleteApplication_FuncPtr)DSO_bind_func(dso, "SKF_DeleteApplication");
	skf->SKF_OpenApplication = (SKF_OpenApplication_FuncPtr)DSO_bind_func(dso, "SKF_OpenApplication");
	skf->SKF_CloseApplication = (SKF_CloseApplication_FuncPtr)DSO_bind_func(dso, "SKF_CloseApplication");
	skf->SKF_CreateFile = (SKF_CreateFile_FuncPtr)DSO_bind_func(dso, "SKF_CreateFile");
	skf->SKF_DeleteFile = (SKF_DeleteFile_FuncPtr)DSO_bind_func(dso, "SKF_DeleteFile");
	skf->SKF_EnumFiles = (SKF_EnumFiles_FuncPtr)DSO_bind_func(dso, "SKF_EnumFiles");
	skf->SKF_GetFileInfo = (SKF_GetFileInfo_FuncPtr)DSO_bind_func(dso, "SKF_GetFileInfo");
	skf->SKF_ReadFile = (SKF_ReadFile_FuncPtr)DSO_bind_func(dso, "SKF_ReadFile");
	skf->SKF_WriteFile = (SKF_WriteFile_FuncPtr)DSO_bind_func(dso, "SKF_WriteFile");
	skf->SKF_CreateContainer = (SKF_CreateContainer_FuncPtr)DSO_bind_func(dso, "SKF_CreateContainer");
	skf->SKF_DeleteContainer = (SKF_DeleteContainer_FuncPtr)DSO_bind_func(dso, "SKF_DeleteContainer");
	skf->SKF_EnumContainer = (SKF_EnumContainer_FuncPtr)DSO_bind_func(dso, "SKF_EnumContainer");
	skf->SKF_OpenContainer = (SKF_OpenContainer_FuncPtr)DSO_bind_func(dso, "SKF_OpenContainer");
	skf->SKF_CloseContainer = (SKF_CloseContainer_FuncPtr)DSO_bind_func(dso, "SKF_CloseContainer");
	skf->SKF_GetContainerType = (SKF_GetContainerType_FuncPtr)DSO_bind_func(dso, "SKF_GetContainerType");
	skf->SKF_ImportCertificate = (SKF_ImportCertificate_FuncPtr)DSO_bind_func(dso, "SKF_ImportCertificate");
	skf->SKF_ExportCertificate = (SKF_ExportCertificate_FuncPtr)DSO_bind_func(dso, "SKF_ExportCertificate");
	skf->SKF_ExportPublicKey = (SKF_ExportPublicKey_FuncPtr)DSO_bind_func(dso, "SKF_ExportPublicKey");
	skf->SKF_GenRandom = (SKF_GenRandom_FuncPtr)DSO_bind_func(dso, "SKF_GenRandom");
	skf->SKF_GenExtRSAKey = (SKF_GenExtRSAKey_FuncPtr)DSO_bind_func(dso, "SKF_GenExtRSAKey");
	skf->SKF_GenRSAKeyPair = (SKF_GenRSAKeyPair_FuncPtr)DSO_bind_func(dso, "SKF_GenRSAKeyPair");
	skf->SKF_ImportRSAKeyPair = (SKF_ImportRSAKeyPair_FuncPtr)DSO_bind_func(dso, "SKF_ImportRSAKeyPair");
	skf->SKF_RSASignData = (SKF_RSASignData_FuncPtr)DSO_bind_func(dso, "SKF_RSASignData");
	skf->SKF_RSAVerify = (SKF_RSAVerify_FuncPtr)DSO_bind_func(dso, "SKF_RSAVerify");
	skf->SKF_RSAExportSessionKey = (SKF_RSAExportSessionKey_FuncPtr)DSO_bind_func(dso, "SKF_RSAExportSessionKey");
	skf->SKF_ExtRSAPubKeyOperation = (SKF_ExtRSAPubKeyOperation_FuncPtr)DSO_bind_func(dso, "SKF_ExtRSAPubKeyOperation");
	skf->SKF_ExtRSAPriKeyOperation = (SKF_ExtRSAPriKeyOperation_FuncPtr)DSO_bind_func(dso, "SKF_ExtRSAPriKeyOperation");
	skf->SKF_GenECCKeyPair = (SKF_GenECCKeyPair_FuncPtr)DSO_bind_func(dso, "SKF_GenECCKeyPair");
	skf->SKF_ImportECCKeyPair = (SKF_ImportECCKeyPair_FuncPtr)DSO_bind_func(dso, "SKF_ImportECCKeyPair");
	skf->SKF_ECCSignData = (SKF_ECCSignData_FuncPtr)DSO_bind_func(dso, "SKF_ECCSignData");
	skf->SKF_ECCVerify = (SKF_ECCVerify_FuncPtr)DSO_bind_func(dso, "SKF_ECCVerify");
	skf->SKF_ECCExportSessionKey = (SKF_ECCExportSessionKey_FuncPtr)DSO_bind_func(dso, "SKF_ECCExportSessionKey");
	skf->SKF_ExtECCEncrypt = (SKF_ExtECCEncrypt_FuncPtr)DSO_bind_func(dso, "SKF_ExtECCEncrypt");
	skf->SKF_ExtECCDecrypt = (SKF_ExtECCDecrypt_FuncPtr)DSO_bind_func(dso, "SKF_ExtECCDecrypt");
	skf->SKF_ExtECCSign = (SKF_ExtECCSign_FuncPtr)DSO_bind_func(dso, "SKF_ExtECCSign");
	skf->SKF_ExtECCVerify = (SKF_ExtECCVerify_FuncPtr)DSO_bind_func(dso, "SKF_ExtECCVerify");
	skf->SKF_GenerateAgreementDataWithECC = (SKF_GenerateAgreementDataWithECC_FuncPtr)DSO_bind_func(dso, "SKF_GenerateAgreementDataWithECC");
	skf->SKF_GenerateAgreementDataAndKeyWithECC = (SKF_GenerateAgreementDataAndKeyWithECC_FuncPtr)DSO_bind_func(dso, "SKF_GenerateAgreementDataAndKeyWithECC");
	skf->SKF_GenerateKeyWithECC = (SKF_GenerateKeyWithECC_FuncPtr)DSO_bind_func(dso, "SKF_GenerateKeyWithECC");
	skf->SKF_ImportSessionKey = (SKF_ImportSessionKey_FuncPtr)DSO_bind_func(dso, "SKF_ImportSessionKey");
	skf->SKF_SetSymmKey = (SKF_SetSymmKey_FuncPtr)DSO_bind_func(dso, "SKF_SetSymmKey");
	skf->SKF_EncryptInit = (SKF_EncryptInit_FuncPtr)DSO_bind_func(dso, "SKF_EncryptInit");
	skf->SKF_Encrypt = (SKF_Encrypt_FuncPtr)DSO_bind_func(dso, "SKF_Encrypt");
	skf->SKF_EncryptUpdate = (SKF_EncryptUpdate_FuncPtr)DSO_bind_func(dso, "SKF_EncryptUpdate");
	skf->SKF_EncryptFinal = (SKF_EncryptFinal_FuncPtr)DSO_bind_func(dso, "SKF_EncryptFinal");
	skf->SKF_DecryptInit = (SKF_DecryptInit_FuncPtr)DSO_bind_func(dso, "SKF_DecryptInit");
	skf->SKF_Decrypt = (SKF_Decrypt_FuncPtr)DSO_bind_func(dso, "SKF_Decrypt");
	skf->SKF_DecryptUpdate = (SKF_DecryptUpdate_FuncPtr)DSO_bind_func(dso, "SKF_DecryptUpdate");
	skf->SKF_DecryptFinal = (SKF_DecryptFinal_FuncPtr)DSO_bind_func(dso, "SKF_DecryptFinal");
	skf->SKF_DigestInit = (SKF_DigestInit_FuncPtr)DSO_bind_func(dso, "SKF_DigestInit");
	skf->SKF_Digest = (SKF_Digest_FuncPtr)DSO_bind_func(dso, "SKF_Digest");
	skf->SKF_DigestUpdate = (SKF_DigestUpdate_FuncPtr)DSO_bind_func(dso, "SKF_DigestUpdate");
	skf->SKF_DigestFinal = (SKF_DigestFinal_FuncPtr)DSO_bind_func(dso, "SKF_DigestFinal");
	skf->SKF_MacInit = (SKF_MacInit_FuncPtr)DSO_bind_func(dso, "SKF_MacInit");
	skf->SKF_Mac = (SKF_Mac_FuncPtr)DSO_bind_func(dso, "SKF_Mac");
	skf->SKF_MacUpdate = (SKF_MacUpdate_FuncPtr)DSO_bind_func(dso, "SKF_MacUpdate");
	skf->SKF_MacFinal = (SKF_MacFinal_FuncPtr)DSO_bind_func(dso, "SKF_MacFinal");
	skf->SKF_CloseHandle = (SKF_CloseHandle_FuncPtr)DSO_bind_func(dso, "SKF_CloseHandle");

	ret = skf;
	skf = NULL;

end:
	OPENSSL_free(skf);
	DSO_free(dso);
	return ret;
}

