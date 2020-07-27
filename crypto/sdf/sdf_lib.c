/* ====================================================================
 * Copyright (c) 2016 - 2017 The GmSSL Project.  All rights reserved.
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

#include <string.h>
#include <openssl/err.h>
#include <openssl/gmsdf.h>
#include "internal/sdf_int.h"
#include "../../e_os.h"

SDF_METHOD *sdf_method = NULL;
SDF_VENDOR *sdf_vendor = NULL;
extern SDF_VENDOR sdf_sansec;


int SDF_LoadLibrary(char *so_path, char *vendor)
{
	if (sdf_method) {
		SDF_METHOD_free(sdf_method);
		sdf_method = NULL;
	}

	if (!(sdf_method = SDF_METHOD_load_library(so_path))) {
		SDFerr(SDF_F_SDF_LOADLIBRARY, SDF_R_LOAD_LIBRARY_FAILURE);
		return SDR_BASE;
	}

	if (vendor) {
		if (strcmp(vendor, sdf_sansec.name) == 0) {
			sdf_vendor = &sdf_sansec;
		}
	}

	return SDR_OK;
}

int SDF_UnloadLibrary(void)
{
	SDF_METHOD_free(sdf_method);
	sdf_method = NULL;
	sdf_vendor = NULL;
	return SDR_OK;
}

static SDF_ERR_REASON sdf_errors[] = {
	{ SDR_OK,		SDF_R_SUCCESS },
	{ SDR_BASE,		SDF_R_ERROR },
	{ SDR_UNKNOWERR,	SDF_R_UNNOWN_ERROR },
	{ SDR_NOTSUPPORT,	SDF_R_OPERATION_NOT_SUPPORTED },
	{ SDR_COMMFAIL,		SDF_R_COMMUNICATION_FAILURE },
	{ SDR_HARDFAIL,		SDF_R_HARDWARE_ERROR },
	{ SDR_OPENDEVICE,	SDF_R_OPEN_DEVICE_FAILURE },
	{ SDR_OPENSESSION,	SDF_R_OPEN_SESSION_FAILURE },
	{ SDR_PARDENY,		SDF_R_NO_PRIVATE_KEY_ACCESS_RIGHT },
	{ SDR_KEYNOTEXIST,	SDF_R_KEY_NOT_EXIST },
	{ SDR_ALGNOTSUPPORT,	SDF_R_ALGORITHM_NOT_SUPPORTED },
	{ SDR_ALGMODNOTSUPPORT,	SDF_R_ALGORITHM_MODE_NOT_SUPPORTED },
	{ SDR_PKOPERR,		SDF_R_PUBLIC_KEY_OPERATION_FAILURE },
	{ SDR_SKOPERR,		SDF_R_PRIVATE_KEY_OPERATION_FAILURE },
	{ SDR_SIGNERR,		SDF_R_SIGNING_FAILURE },
	{ SDR_VERIFYERR,	SDF_R_VERIFICATION_FAILURE },
	{ SDR_SYMOPERR,		SDF_R_SYMMETRIC_OPERATION_FAILURE },
	{ SDR_STEPERR,		SDF_R_MULTI_STEP_OPERATION_ERROR },
	{ SDR_FILESIZEERR,	SDF_R_INVALID_FILE_SIZE },
	{ SDR_FILENOEXIST,	SDF_R_FILE_NOT_EXIST },
	{ SDR_FILEOFSERR,	SDF_R_INVALID_FILE_OFFSET },
	{ SDR_KEYTYPEERR,	SDF_R_INVALID_KEY_TYPE },
	{ SDR_KEYERR,		SDF_R_INVALID_KEY },
	{ SDR_ENCDATAERR,	SDF_R_ENCRYPT_DATA_ERROR },
	{ SDR_RANDERR,		SDF_R_RANDOM_GENERATION_ERROR },
	{ SDR_PRKRERR,		SDF_R_PRKERR },
	{ SDR_MACERR,		SDF_R_MAC_ERROR },
	{ SDR_FILEEXSITS,	SDF_R_FILE_ALREADY_EXIST },
	{ SDR_FILEWERR,		SDF_R_WRITE_FILE_FAILURE },
	{ SDR_NOBUFFER,		SDF_R_BUFFER_TOO_SMALL },
	{ SDR_INARGERR,		SDF_R_INVALID_INPUT_ARGUMENT },
	{ SDR_OUTARGERR,	SDF_R_INVALID_OUTPUT_ARGUMENT },
};

static unsigned long sdf_get_error_reason(int err)
{
	size_t i;
	for (i = 0; i < OSSL_NELEM(sdf_errors); i++) {
		if (err == sdf_errors[i].err) {
			return sdf_errors[i].reason;
		}
	}
	if (sdf_vendor) {
		return sdf_vendor->get_error_reason(err);
	}
	return 0;
}

int SDF_GetErrorString(int err, char **str)
{
	unsigned long reason;

	if ((reason = sdf_get_error_reason(err)) != 0) {
		*str = (char*)ERR_reason_error_string(reason);
	} else {
		*str = "(unknown)";
	}

	return SDR_OK;
}

int SDF_OpenDevice(
	void **phDeviceHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method  || !sdf_method->OpenDevice) {
		SDFerr(SDF_F_SDF_OPENDEVICE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->OpenDevice(
		phDeviceHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_OPENDEVICE, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_CloseDevice(
	void *hDeviceHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->CloseDevice) {
		SDFerr(SDF_F_SDF_CLOSEDEVICE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->CloseDevice(
		hDeviceHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_CLOSEDEVICE, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_OpenSession(
	void *hDeviceHandle,
	void **phSessionHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->OpenSession) {
		SDFerr(SDF_F_SDF_OPENSESSION, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->OpenSession(
		hDeviceHandle,
		phSessionHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_OPENSESSION, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_CloseSession(
	void *hSessionHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->CloseSession) {
		SDFerr(SDF_F_SDF_CLOSESESSION, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->CloseSession(
		hSessionHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_CLOSESESSION, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GetDeviceInfo) {
		SDFerr(SDF_F_SDF_GETDEVICEINFO, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GetDeviceInfo(
		hSessionHandle,
		pstDeviceInfo)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GETDEVICEINFO, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateRandom(
	void *hSessionHandle,
	unsigned int uiLength,
	unsigned char *pucRandom)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateRandom) {
		SDFerr(SDF_F_SDF_GENERATERANDOM, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateRandom(
		hSessionHandle,
		uiLength,
		pucRandom)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATERANDOM, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GetPrivateKeyAccessRight) {
		SDFerr(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GetPrivateKeyAccessRight(
		hSessionHandle,
		uiKeyIndex,
		pucPassword,
		uiPwdLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ReleasePrivateKeyAccessRight) {
		SDFerr(SDF_F_SDF_RELEASEPRIVATEKEYACCESSRIGHT,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ReleasePrivateKeyAccessRight(
		hSessionHandle,
		uiKeyIndex)) != SDR_OK) {
		SDFerr(SDF_F_SDF_RELEASEPRIVATEKEYACCESSRIGHT,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExportSignPublicKey_RSA) {
		SDFerr(SDF_F_SDF_EXPORTSIGNPUBLICKEY_RSA, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExportSignPublicKey_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXPORTSIGNPUBLICKEY_RSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExportEncPublicKey_RSA) {
		SDFerr(SDF_F_SDF_EXPORTENCPUBLICKEY_RSA, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExportEncPublicKey_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXPORTENCPUBLICKEY_RSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateKeyPair_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateKeyPair_RSA) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_RSA, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyPair_RSA(
		hSessionHandle,
		uiKeyBits,
		pucPublicKey,
		pucPrivateKey)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_RSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateKeyWithIPK_RSA) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHIPK_RSA,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyWithIPK_RSA(
		hSessionHandle,
		uiIPKIndex,
		uiKeyBits,
		pucKey,
		puiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHIPK_RSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateKeyWithEPK_RSA) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_RSA, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyWithEPK_RSA(
		hSessionHandle,
		uiKeyBits,
		pucPublicKey,
		pucKey,
		puiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_RSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ImportKeyWithISK_RSA) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHISK_RSA, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ImportKeyWithISK_RSA(
		hSessionHandle,
		uiISKIndex,
		pucKey,
		uiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHISK_RSA, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExchangeDigitEnvelopeBaseOnRSA) {
		SDFerr(SDF_F_SDF_EXCHANGEDIGITENVELOPEBASEONRSA,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExchangeDigitEnvelopeBaseOnRSA(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey,
		pucDEInput,
		uiDELength,
		pucDEOutput,
		puiDELength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXCHANGEDIGITENVELOPEBASEONRSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExportSignPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExportSignPublicKey_ECC) {
		SDFerr(SDF_F_SDF_EXPORTSIGNPUBLICKEY_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExportSignPublicKey_ECC(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXPORTSIGNPUBLICKEY_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExportEncPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExportEncPublicKey_ECC) {
		SDFerr(SDF_F_SDF_EXPORTENCPUBLICKEY_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExportEncPublicKey_ECC(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXPORTENCPUBLICKEY_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int  uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateKeyPair_ECC) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_GENERATEKEYPAIR_ECC,
				SDF_R_NOT_SUPPORTED_ECC_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->GenerateKeyPair_ECC(
		hSessionHandle,
		uiAlgID,
		uiKeyBits,
		pucPublicKey,
		pucPrivateKey)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_ECC, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateKeyWithIPK_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateKeyWithIPK_ECC) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHIPK_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyWithIPK_ECC(
		hSessionHandle,
		uiIPKIndex,
		uiKeyBits,
		pucKey,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHIPK_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateKeyWithEPK_ECC(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateKeyWithEPK_ECC) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_ECC,
				SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->GenerateKeyWithEPK_ECC(
		hSessionHandle,
		uiKeyBits,
		uiAlgID,
		pucPublicKey,
		pucKey,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ImportKeyWithISK_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ImportKeyWithISK_ECC) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHISK_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ImportKeyWithISK_ECC(
		hSessionHandle,
		uiISKIndex,
		pucKey,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHISK_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateAgreementDataWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	void **phAgreementHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateAgreementDataWithECC) {
		SDFerr(SDF_F_SDF_GENERATEAGREEMENTDATAWITHECC,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateAgreementDataWithECC(
		hSessionHandle,
		uiISKIndex,
		uiKeyBits,
		pucSponsorID,
		uiSponsorIDLength,
		pucSponsorPublicKey,
		pucSponsorTmpPublicKey,
		phAgreementHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEAGREEMENTDATAWITHECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateKeyWithECC(
	void *hSessionHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateKeyWithECC) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyWithECC(
		hSessionHandle,
		pucResponseID,
		uiResponseIDLength,
		pucResponsePublicKey,
		pucResponseTmpPublicKey,
		hAgreementHandle,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateAgreementDataAndKeyWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateAgreementDataAndKeyWithECC) {
		SDFerr(SDF_F_SDF_GENERATEAGREEMENTDATAANDKEYWITHECC,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateAgreementDataAndKeyWithECC(
		hSessionHandle,
		uiISKIndex,
		uiKeyBits,
		pucResponseID,
		uiResponseIDLength,
		pucSponsorID,
		uiSponsorIDLength,
		pucSponsorPublicKey,
		pucSponsorTmpPublicKey,
		pucResponsePublicKey,
		pucResponseTmpPublicKey,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEAGREEMENTDATAANDKEYWITHECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExchangeDigitEnvelopeBaseOnECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExchangeDigitEnvelopeBaseOnECC) {
		SDFerr(SDF_F_SDF_EXCHANGEDIGITENVELOPEBASEONECC,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_EXCHANGEDIGITENVELOPEBASEONECC,
				SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->ExchangeDigitEnvelopeBaseOnECC(
		hSessionHandle,
		uiKeyIndex,
		uiAlgID,
		pucPublicKey,
		pucEncDataIn,
		pucEncDataOut)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXCHANGEDIGITENVELOPEBASEONECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_GenerateKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->GenerateKeyWithKEK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHKEK,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_GENERATEKEYWITHKEK,
				SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->GenerateKeyWithKEK(
		hSessionHandle,
		uiKeyBits,
		uiAlgID,
		uiKEKIndex,
		pucKey,
		puiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHKEK,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ImportKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ImportKeyWithKEK) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHKEK, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_IMPORTKEYWITHKEK,
				SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->ImportKeyWithKEK(
		hSessionHandle,
		uiAlgID,
		uiKEKIndex,
		pucKey,
		uiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHKEK, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_DestroyKey(
	void *hSessionHandle,
	void *hKeyHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->DestroyKey) {
		SDFerr(SDF_F_SDF_DESTROYKEY, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_DESTROYKEY, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExternalPublicKeyOperation_RSA) {
		SDFerr(SDF_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExternalPublicKeyOperation_RSA(
		hSessionHandle,
		pucPublicKey,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_InternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->InternalPublicKeyOperation_RSA) {
		SDFerr(SDF_F_SDF_INTERNALPUBLICKEYOPERATION_RSA,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->InternalPublicKeyOperation_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_INTERNALPUBLICKEYOPERATION_RSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_InternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->InternalPrivateKeyOperation_RSA) {
		SDFerr(SDF_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA,
			SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->InternalPrivateKeyOperation_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExternalVerify_ECC) {
		SDFerr(SDF_F_SDF_EXTERNALVERIFY_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_EXTERNALVERIFY_ECC,
				SDF_R_NOT_SUPPORTED_PKEY_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->ExternalVerify_ECC(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucDataInput,
		uiInputLength,
		pucSignature)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXTERNALVERIFY_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_InternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->InternalSign_ECC) {
		SDFerr(SDF_F_SDF_INTERNALSIGN_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->InternalSign_ECC(
		hSessionHandle,
		uiISKIndex,
		pucData,
		uiDataLength,
		pucSignature)) != SDR_OK) {
		SDFerr(SDF_F_SDF_INTERNALSIGN_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_InternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->InternalVerify_ECC) {
		SDFerr(SDF_F_SDF_INTERNALVERIFY_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->InternalVerify_ECC(
		hSessionHandle,
		uiIPKIndex,
		pucData,
		uiDataLength,
		pucSignature)) != SDR_OK) {
		SDFerr(SDF_F_SDF_INTERNALVERIFY_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ExternalEncrypt_ECC) {
		SDFerr(SDF_F_SDF_EXTERNALENCRYPT_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_EXTERNALENCRYPT_ECC,
				SDF_R_NOT_SUPPORTED_PKEY_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->ExternalEncrypt_ECC(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucData,
		uiDataLength,
		pucEncData)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXTERNALENCRYPT_ECC,
			sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_InternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiAlgID,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	int ret = SDR_UNKNOWERR;
	ECCCipher *buf = pucEncData;

	if (!sdf_method || !sdf_method->InternalEncrypt_ECC) {
		SDFerr(SDF_F_SDF_INTERNALENCRYPT_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (pucEncData->L < uiDataLength) {
		SDFerr(SDF_F_SDF_INTERNALENCRYPT_ECC, SDF_R_BUFFER_TOO_SMALL);
		return SDR_NOBUFFER;
	}

	if (sdf_vendor && sdf_vendor->decode_ecccipher) {
		if (SDF_NewECCCipher(&buf, uiDataLength) != SDR_OK) {
			SDFerr(SDF_F_SDF_INTERNALENCRYPT_ECC, ERR_R_SDF_LIB);
			return SDR_UNKNOWERR;
		}
	}

	if (sdf_vendor && sdf_vendor->pkey_std2vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_INTERNALENCRYPT_ECC,
				SDF_R_NOT_SUPPORTED_PKEY_ALGOR);
			ret = SDR_ALGNOTSUPPORT;
			goto end;
		}
	}

	if ((ret = sdf_method->InternalEncrypt_ECC(
		hSessionHandle,
		uiIPKIndex,
		uiAlgID,
		pucData,
		uiDataLength,
		buf)) != SDR_OK) {
		SDFerr(SDF_F_SDF_INTERNALENCRYPT_ECC,
			sdf_get_error_reason(ret));
		goto end;
	}

	if (sdf_vendor && sdf_vendor->decode_ecccipher) {
		if (!sdf_vendor->decode_ecccipher(pucEncData, buf)) {
			SDFerr(SDF_F_SDF_INTERNALENCRYPT_ECC, ERR_R_SDF_LIB);
			ret = SDR_UNKNOWERR;
			goto end;
		}
	}

	/*
	{
		int i;
		unsigned char *p = (unsigned char *)pucEncData;
		for (i = 0; i < sizeof(ECCCipher) -1 + uiDataLength; i++) {
			printf("%02x", p[i]);
		}
		printf("\n");
	}
	*/

	ret = SDR_OK;

end:
	if (sdf_vendor && sdf_vendor->decode_ecccipher && buf) {
		SDF_FreeECCCipher(buf);
	}
	return ret;
}

int SDF_InternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiAlgID,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *uiDataLength)
{
	int ret = SDR_UNKNOWERR;
	ECCCipher *buf = pucEncData;

	if (!sdf_method || !sdf_method->InternalDecrypt_ECC) {
		SDFerr(SDF_F_SDF_INTERNALDECRYPT_ECC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor && sdf_vendor->pkey_std2vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_INTERNALDECRYPT_ECC,
				SDF_R_NOT_SUPPORTED_PKEY_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if (sdf_vendor && sdf_vendor->encode_ecccipher) {
		if (SDF_NewECCCipher(&buf, pucEncData->L) != SDR_OK) {
			SDFerr(SDF_F_SDF_INTERNALDECRYPT_ECC, ERR_R_SDF_LIB);
			return SDR_UNKNOWERR;
		}

		if (!sdf_vendor->encode_ecccipher(pucEncData, buf)) {
			SDFerr(SDF_F_SDF_INTERNALDECRYPT_ECC, ERR_R_SDF_LIB);
			ret = SDR_UNKNOWERR;
			goto end;
		}
	}

	if ((ret = sdf_method->InternalDecrypt_ECC(
		hSessionHandle,
		uiISKIndex,
		uiAlgID,
		buf,
		pucData,
		uiDataLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_INTERNALDECRYPT_ECC,
			sdf_get_error_reason(ret));
		goto end;
	}

end:
	if (sdf_vendor && sdf_vendor->encode_ecccipher && buf) {
		SDF_FreeECCCipher(buf);
	}
	return ret;
}

int SDF_Encrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->Encrypt) {
		SDFerr(SDF_F_SDF_ENCRYPT, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_ENCRYPT,
				SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->Encrypt(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucData,
		uiDataLength,
		pucEncData,
		puiEncDataLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_ENCRYPT, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_Decrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->Decrypt) {
		SDFerr(SDF_F_SDF_DECRYPT, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_DECRYPT, SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->Decrypt(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucEncData,
		uiEncDataLength,
		pucData,
		puiDataLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_DECRYPT, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_CalculateMAC(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucMAC,
	unsigned int *puiMACLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->CalculateMAC) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_CALCULATEMAC,
				SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->CalculateMAC(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucData,
		uiDataLength,
		pucMAC,
		puiMACLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->HashInit) {
		SDFerr(SDF_F_SDF_HASHINIT, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->digest_std2vendor(uiAlgID))) {
			SDFerr(SDF_F_SDF_HASHINIT, SDF_R_NOT_SUPPORTED_DIGEST_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->HashInit(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucID,
		uiIDLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_HASHINIT, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->HashUpdate) {
		SDFerr(SDF_F_SDF_HASHUPDATE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->HashUpdate(
		hSessionHandle,
		pucData,
		uiDataLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_HASHUPDATE, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_HashFinal(
	void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->HashFinal) {
		SDFerr(SDF_F_SDF_HASHFINAL, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->HashFinal(
		hSessionHandle,
		pucHash,
		puiHashLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_HASHFINAL, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_CreateFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiFileSize)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->CreateObject) {
		SDFerr(SDF_F_SDF_CREATEFILE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->CreateObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiFileSize)) != SDR_OK) {
		SDFerr(SDF_F_SDF_CREATEFILE, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_ReadFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int *puiReadLength,
	unsigned char *pucBuffer)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->ReadObject) {
		SDFerr(SDF_F_SDF_READFILE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ReadObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		puiReadLength,
		pucBuffer)) != SDR_OK) {
		SDFerr(SDF_F_SDF_READFILE, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_WriteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int uiWriteLength,
	unsigned char *pucBuffer)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->WriteObject) {
		SDFerr(SDF_F_SDF_WRITEFILE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->WriteObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		uiWriteLength,
		pucBuffer)) != SDR_OK) {
		SDFerr(SDF_F_SDF_WRITEFILE, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_DeleteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->DeleteObject) {
		SDFerr(SDF_F_SDF_DELETEFILE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->DeleteObject(
		hSessionHandle,
		pucFileName,
		uiNameLen)) != SDR_OK) {
		SDFerr(SDF_F_SDF_DELETEFILE, sdf_get_error_reason(ret));
		return ret;
	}

	return SDR_OK;
}
