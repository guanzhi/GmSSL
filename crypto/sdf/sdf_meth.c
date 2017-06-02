/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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

#include <openssl/crypto.h>
#include "internal/dso.h"
#include "internal/sdf_meth.h"

SDF_METHOD *SDF_METHOD_load_library(const char *so_path)
{
	SDF_METHOD *ret = NULL;
	SDF_METHOD *sdf = NULL;
	DSO *dso = NULL;

	if (!(dso = DSO_load(NULL, so_path, NULL, 0))) {
		goto end;
	}
	if (!(sdf = OPENSSL_zalloc(sizeof(*sdf)))) {
		goto end;
	}

	sdf->OpenDevice = (SDF_OpenDevice_FuncPtr)DSO_bind_func(dso, "SDF_OpenDevice");
	sdf->CloseDevice = (SDF_CloseDevice_FuncPtr)DSO_bind_func(dso, "SDF_CloseDevice");
	sdf->OpenSession = (SDF_OpenSession_FuncPtr)DSO_bind_func(dso, "SDF_OpenSession");
	sdf->CloseSession = (SDF_CloseSession_FuncPtr)DSO_bind_func(dso, "SDF_CloseSession");
	sdf->GetDeviceInfo = (SDF_GetDeviceInfo_FuncPtr)DSO_bind_func(dso, "SDF_GetDeviceInfo");
	sdf->GenerateRandom = (SDF_GenerateRandom_FuncPtr)DSO_bind_func(dso, "SDF_GenerateRandom");
	sdf->GetPrivateKeyAccessRight = (SDF_GetPrivateKeyAccessRight_FuncPtr)DSO_bind_func(dso, "SDF_GetPrivateKeyAccessRight");
	sdf->ReleasePrivateKeyAccessRight = (SDF_ReleasePrivateKeyAccessRight_FuncPtr)DSO_bind_func(dso, "SDF_ReleasePrivateKeyAccessRight");
	sdf->ExportSignPublicKey_RSA = (SDF_ExportSignPublicKey_RSA_FuncPtr)DSO_bind_func(dso, "SDF_ExportSignPublicKey_RSA");
	sdf->ExportEncPublicKey_RSA = (SDF_ExportEncPublicKey_RSA_FuncPtr)DSO_bind_func(dso, "SDF_ExportEncPublicKey_RSA");
	sdf->GenerateKeyPair_RSA = (SDF_GenerateKeyPair_RSA_FuncPtr)DSO_bind_func(dso, "SDF_GenerateKeyPair_RSA");
	sdf->GenerateKeyWithIPK_RSA = (SDF_GenerateKeyWithIPK_RSA_FuncPtr)DSO_bind_func(dso, "SDF_GenerateKeyWithIPK_RSA");
	sdf->GenerateKeyWithEPK_RSA = (SDF_GenerateKeyWithEPK_RSA_FuncPtr)DSO_bind_func(dso, "SDF_GenerateKeyWithEPK_RSA");
	sdf->ImportKeyWithISK_RSA = (SDF_ImportKeyWithISK_RSA_FuncPtr)DSO_bind_func(dso, "SDF_ImportKeyWithISK_RSA");
	sdf->ExchangeDigitEnvelopeBaseOnRSA = (SDF_ExchangeDigitEnvelopeBaseOnRSA_FuncPtr)DSO_bind_func(dso, "SDF_ExchangeDigitEnvelopeBaseOnRSA");
	sdf->ExportSignPublicKey_ECC = (SDF_ExportSignPublicKey_ECC_FuncPtr)DSO_bind_func(dso, "SDF_ExportSignPublicKey_ECC");
	sdf->ExportEncPublicKey_ECC = (SDF_ExportEncPublicKey_ECC_FuncPtr)DSO_bind_func(dso, "SDF_ExportEncPublicKey_ECC");
	sdf->GenerateKeyPair_ECC = (SDF_GenerateKeyPair_ECC_FuncPtr)DSO_bind_func(dso, "SDF_GenerateKeyPair_ECC");
	sdf->GenerateKeyWithIPK_ECC = (SDF_GenerateKeyWithIPK_ECC_FuncPtr)DSO_bind_func(dso, "SDF_GenerateKeyWithIPK_ECC");
	sdf->GenerateKeyWithEPK_ECC = (SDF_GenerateKeyWithEPK_ECC_FuncPtr)DSO_bind_func(dso, "SDF_GenerateKeyWithEPK_ECC");
	sdf->ImportKeyWithISK_ECC = (SDF_ImportKeyWithISK_ECC_FuncPtr)DSO_bind_func(dso, "SDF_ImportKeyWithISK_ECC");
	sdf->GenerateAgreementDataWithECC = (SDF_GenerateAgreementDataWithECC_FuncPtr)DSO_bind_func(dso, "SDF_GenerateAgreementDataWithECC");
	sdf->GenerateKeyWithECC = (SDF_GenerateKeyWithECC_FuncPtr)DSO_bind_func(dso, "SDF_GenerateKeyWithECC");
	sdf->GenerateAgreementDataAndKeyWithECC = (SDF_GenerateAgreementDataAndKeyWithECC_FuncPtr)DSO_bind_func(dso, "SDF_GenerateAgreementDataAndKeyWithECC");
	sdf->ExchangeDigitEnvelopeBaseOnECC = (SDF_ExchangeDigitEnvelopeBaseOnECC_FuncPtr)DSO_bind_func(dso, "SDF_ExchangeDigitEnvelopeBaseOnECC");
	sdf->GenerateKeyWithKEK = (SDF_GenerateKeyWithKEK_FuncPtr)DSO_bind_func(dso, "SDF_GenerateKeyWithKEK");
	sdf->ImportKeyWithKEK = (SDF_ImportKeyWithKEK_FuncPtr)DSO_bind_func(dso, "SDF_ImportKeyWithKEK");
	sdf->DestroyKey = (SDF_DestroyKey_FuncPtr)DSO_bind_func(dso, "SDF_DestroyKey");
	sdf->ExternalPublicKeyOperation_RSA = (SDF_ExternalPublicKeyOperation_RSA_FuncPtr)DSO_bind_func(dso, "SDF_ExternalPublicKeyOperation_RSA");
	sdf->InternalPublicKeyOperation_RSA = (SDF_InternalPublicKeyOperation_RSA_FuncPtr)DSO_bind_func(dso, "SDF_InternalPublicKeyOperation_RSA");
	sdf->InternalPrivateKeyOperation_RSA = (SDF_InternalPrivateKeyOperation_RSA_FuncPtr)DSO_bind_func(dso, "SDF_InternalPrivateKeyOperation_RSA");
	sdf->ExternalVerify_ECC = (SDF_ExternalVerify_ECC_FuncPtr)DSO_bind_func(dso, "SDF_ExternalVerify_ECC");
	sdf->InternalSign_ECC = (SDF_InternalSign_ECC_FuncPtr)DSO_bind_func(dso, "SDF_InternalSign_ECC");
	sdf->InternalVerify_ECC = (SDF_InternalVerify_ECC_FuncPtr)DSO_bind_func(dso, "SDF_InternalVerify_ECC");
	sdf->ExternalEncrypt_ECC = (SDF_ExternalEncrypt_ECC_FuncPtr)DSO_bind_func(dso, "SDF_ExternalEncrypt_ECC");
	sdf->ExternalDecrypt_ECC = (SDF_ExternalDecrypt_ECC_FuncPtr)DSO_bind_func(dso, "SDF_ExternalDecrypt_ECC");
	sdf->InternalEncrypt_ECC = (SDF_InternalEncrypt_ECC_FuncPtr)DSO_bind_func(dso, "SDF_InternalEncrypt_ECC");
	sdf->InternalDecrypt_ECC = (SDF_InternalDecrypt_ECC_FuncPtr)DSO_bind_func(dso, "SDF_InternalDecrypt_ECC");
	sdf->Encrypt = (SDF_Encrypt_FuncPtr)DSO_bind_func(dso, "SDF_Encrypt");
	sdf->Decrypt = (SDF_Decrypt_FuncPtr)DSO_bind_func(dso, "SDF_Decrypt");
	sdf->CalculateMAC = (SDF_CalculateMAC_FuncPtr)DSO_bind_func(dso, "SDF_CalculateMAC");
	sdf->HashInit = (SDF_HashInit_FuncPtr)DSO_bind_func(dso, "SDF_HashInit");
	sdf->HashUpdate = (SDF_HashUpdate_FuncPtr)DSO_bind_func(dso, "SDF_HashUpdate");
	sdf->HashFinal = (SDF_HashFinal_FuncPtr)DSO_bind_func(dso, "SDF_HashFinal");
	sdf->CreateFileObject = (SDF_CreateFile_FuncPtr)DSO_bind_func(dso, "SDF_CreateFile");
	sdf->ReadFileObject = (SDF_ReadFile_FuncPtr)DSO_bind_func(dso, "SDF_ReadFile");
	sdf->WriteFileObject = (SDF_WriteFile_FuncPtr)DSO_bind_func(dso, "SDF_WriteFile");
	sdf->DeleteFileObject = (SDF_DeleteFile_FuncPtr)DSO_bind_func(dso, "SDF_DeleteFile");


	ret = sdf;
	sdf = NULL;

end:
	OPENSSL_free(sdf);
	DSO_free(dso);
	return ret;
}
