/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include "sdf_ext.h"
#include "sdf_int.h"

SDF_METHOD *sdf_method = NULL;
SDF_VENDOR *sdf_vendor = NULL;
extern SDF_VENDOR sdf_sansec;


#define SDFerr(reason) fprintf(stderr,"sdfutil: %s %d: %s %s\n", __FILE__, __LINE__, __FUNCTION__, reason)


#define SDF_R_LOAD_LIBRARY_FAILURE	"SDF_R_LOAD_LIBRARY_FAILURE"
#define SDF_R_NOT_INITIALIZED		"SDF_R_NOT_INITIALIZED"
#define SDF_R_NOT_SUPPORTED_ECC_ALGOR	"SDF_R_NOT_SUPPORTED_ECC_ALGOR"
#define SDF_R_NOT_SUPPORTED_CIPHER_ALGOR "SDF_R_NOT_SUPPORTED_CIPHER_ALGOR"
#define SDF_R_BUFFER_TOO_SMALL		"SDF_R_BUFFER_TOO_SMALL"
#define SDF_R_NOT_SUPPORTED_PKEY_ALGOR	"SDF_R_NOT_SUPPORTED_PKEY_ALGOR"
#define SDF_R_NOT_SUPPORTED_DIGEST_ALGOR "SDF_R_NOT_SUPPORTED_DIGEST_ALGOR"
#define ERR_R_SDF_LIB			"ERR_R_SDF_LIB"



int SDF_LoadLibrary(char *so_path, char *vendor)
{
	if (sdf_method) {
		SDF_METHOD_free(sdf_method);
		sdf_method = NULL;
	}

	if (!(sdf_method = SDF_METHOD_load_library(so_path))) {
		SDFerr(SDF_R_LOAD_LIBRARY_FAILURE);
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

int SDF_OpenDevice(
	void **phDeviceHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method  || !sdf_method->OpenDevice) {
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->OpenDevice(
		phDeviceHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_CloseDevice(
	void *hDeviceHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->CloseDevice) {
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->CloseDevice(
		hDeviceHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->OpenSession(
		hDeviceHandle,
		phSessionHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
		return ret;
	}

	return SDR_OK;
}

int SDF_CloseSession(
	void *hSessionHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->CloseSession) {
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->CloseSession(
		hSessionHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GetDeviceInfo(
		hSessionHandle,
		pstDeviceInfo)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateRandom(
		hSessionHandle,
		uiLength,
		pucRandom)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GetPrivateKeyAccessRight(
		hSessionHandle,
		uiKeyIndex,
		pucPassword,
		uiPwdLength)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ReleasePrivateKeyAccessRight(
		hSessionHandle,
		uiKeyIndex)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExportSignPublicKey_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExportEncPublicKey_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyPair_RSA(
		hSessionHandle,
		uiKeyBits,
		pucPublicKey,
		pucPrivateKey)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyWithIPK_RSA(
		hSessionHandle,
		uiIPKIndex,
		uiKeyBits,
		pucKey,
		puiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyWithEPK_RSA(
		hSessionHandle,
		uiKeyBits,
		pucPublicKey,
		pucKey,
		puiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ImportKeyWithISK_RSA(
		hSessionHandle,
		uiISKIndex,
		pucKey,
		uiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExportSignPublicKey_ECC(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExportEncPublicKey_ECC(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_ECC_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->GenerateKeyPair_ECC(
		hSessionHandle,
		uiAlgID,
		uiKeyBits,
		pucPublicKey,
		pucPrivateKey)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->GenerateKeyWithIPK_ECC(
		hSessionHandle,
		uiIPKIndex,
		uiKeyBits,
		pucKey,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ImportKeyWithISK_ECC(
		hSessionHandle,
		uiISKIndex,
		pucKey,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ExternalPublicKeyOperation_RSA(
		hSessionHandle,
		pucPublicKey,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->InternalPublicKeyOperation_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->InternalPrivateKeyOperation_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_PKEY_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->InternalSign_ECC(
		hSessionHandle,
		uiISKIndex,
		pucData,
		uiDataLength,
		pucSignature)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->InternalVerify_ECC(
		hSessionHandle,
		uiIPKIndex,
		pucData,
		uiDataLength,
		pucSignature)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_PKEY_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (pucEncData->L < uiDataLength) {
		SDFerr(SDF_R_BUFFER_TOO_SMALL);
		return SDR_NOBUFFER;
	}

	if (sdf_vendor && sdf_vendor->decode_ecccipher) {
		if (SDF_NewECCCipher(&buf, uiDataLength) != SDR_OK) {
			SDFerr(ERR_R_SDF_LIB);
			return SDR_UNKNOWERR;
		}
	}

	if (sdf_vendor && sdf_vendor->pkey_std2vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_PKEY_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
		goto end;
	}

	if (sdf_vendor && sdf_vendor->decode_ecccipher) {
		if (!sdf_vendor->decode_ecccipher(pucEncData, buf)) {
			SDFerr(ERR_R_SDF_LIB);
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor && sdf_vendor->pkey_std2vendor) {
		if (!(uiAlgID = sdf_vendor->pkey_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_PKEY_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if (sdf_vendor && sdf_vendor->encode_ecccipher) {
		if (SDF_NewECCCipher(&buf, pucEncData->L) != SDR_OK) {
			SDFerr(ERR_R_SDF_LIB);
			return SDR_UNKNOWERR;
		}

		if (!sdf_vendor->encode_ecccipher(pucEncData, buf)) {
			SDFerr(ERR_R_SDF_LIB);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->cipher_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_CIPHER_ALGOR);
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
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if (sdf_vendor) {
		if (!(uiAlgID = sdf_vendor->digest_std2vendor(uiAlgID))) {
			SDFerr(SDF_R_NOT_SUPPORTED_DIGEST_ALGOR);
			return SDR_ALGNOTSUPPORT;
		}
	}

	if ((ret = sdf_method->HashInit(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucID,
		uiIDLength)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->HashUpdate(
		hSessionHandle,
		pucData,
		uiDataLength)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->HashFinal(
		hSessionHandle,
		pucHash,
		puiHashLength)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->CreateObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiFileSize)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ReadObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		puiReadLength,
		pucBuffer)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->WriteObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		uiWriteLength,
		pucBuffer)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
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
		SDFerr(SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->DeleteObject(
		hSessionHandle,
		pucFileName,
		uiNameLen)) != SDR_OK) {
		SDFerr(SDF_GetErrorReason(ret));
		return ret;
	}

	return SDR_OK;
}
