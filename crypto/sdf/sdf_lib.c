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

#include <openssl/err.h>
#include <openssl/gmsdf.h>
#include "internal/sdf_meth.h"

static SDF_METHOD *sdf_method = NULL;

int SDF_OpenDevice(
	void **phDeviceHandle)
{
	int ret = SDR_UNKNOWERR;

	if (!sdf_method || !sdf_method->OpenDevice) {
		SDFerr(SDF_F_SDF_OPENDEVICE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->OpenDevice(
		phDeviceHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_OPENDEVICE, SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_CLOSEDEVICE, SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_OPENSESSION, SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_CLOSESESSION, SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_GETDEVICEINFO, SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_GENERATERANDOM, SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT, SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_IMPORTKEYWITHISK_RSA,
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->GenerateKeyPair_ECC(
		hSessionHandle,
		uiAlgID,
		uiKeyBits,
		pucPublicKey,
		pucPrivateKey)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_ECC,
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->GenerateKeyWithEPK_ECC(
		hSessionHandle,
		uiKeyBits,
		uiAlgID,
		pucPublicKey,
		pucKey,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_ECC,
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->ExchangeDigitEnvelopeBaseOnECC(
		hSessionHandle,
		uiKeyIndex,
		uiAlgID,
		pucPublicKey,
		pucEncDataIn,
		pucEncDataOut)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXCHANGEDIGITENVELOPEBASEONECC,
			SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->GenerateKeyWithKEK(
		hSessionHandle,
		uiKeyBits,
		uiAlgID,
		uiKEKIndex,
		pucKey,
		puiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHKEK,
			SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->ImportKeyWithKEK(
		hSessionHandle,
		uiAlgID,
		uiKEKIndex,
		pucKey,
		uiKeyLength,
		phKeyHandle)) != SDR_OK) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHKEK,
			SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_DESTROYKEY, SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->ExternalVerify_ECC(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucDataInput,
		uiInputLength,
		pucSignature)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXTERNALVERIFY_ECC,
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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
			SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->ExternalEncrypt_ECC(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucData,
		uiDataLength,
		pucEncData)) != SDR_OK) {
		SDFerr(SDF_F_SDF_EXTERNALENCRYPT_ECC,
			SDF_R_METHOD_OPERATION_FAILURE);
		return ret;
	}

	return SDR_OK;
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

	if ((ret = sdf_method->Encrypt(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucData,
		uiDataLength,
		pucEncData,
		puiEncDataLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_ENCRYPT, SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->Decrypt(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucEncData,
		uiEncDataLength,
		pucData,
		puiDataLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_DECRYPT, SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->CalculateMAC(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucData,
		uiDataLength,
		pucMAC,
		puiMACLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_CALCULATEMAC, SDF_R_METHOD_OPERATION_FAILURE);
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

	if ((ret = sdf_method->HashInit(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucID,
		uiIDLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_HASHINIT, SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_HASHUPDATE, SDF_R_METHOD_OPERATION_FAILURE);
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
		SDFerr(SDF_F_SDF_HASHFINAL, SDF_R_METHOD_OPERATION_FAILURE);
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

	if (!sdf_method || !sdf_method->CreateFileObject) {
		SDFerr(SDF_F_SDF_CREATEFILE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->CreateFileObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiFileSize)) != SDR_OK) {
		SDFerr(SDF_F_SDF_CREATEFILE, SDF_R_METHOD_OPERATION_FAILURE);
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

	if (!sdf_method || !sdf_method->ReadFileObject) {
		SDFerr(SDF_F_SDF_READFILE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->ReadFileObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		puiReadLength,
		pucBuffer)) != SDR_OK) {
		SDFerr(SDF_F_SDF_READFILE, SDF_R_METHOD_OPERATION_FAILURE);
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

	if (!sdf_method || !sdf_method->WriteFileObject) {
		SDFerr(SDF_F_SDF_WRITEFILE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->WriteFileObject(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		uiWriteLength,
		pucBuffer)) != SDR_OK) {
		SDFerr(SDF_F_SDF_WRITEFILE, SDF_R_METHOD_OPERATION_FAILURE);
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

	if (!sdf_method || !sdf_method->DeleteFileObject) {
		SDFerr(SDF_F_SDF_DELETEFILE, SDF_R_NOT_INITIALIZED);
		return SDR_NOTSUPPORT;
	}

	if ((ret = sdf_method->DeleteFileObject(
		hSessionHandle,
		pucFileName,
		uiNameLen)) != SDR_OK) {
		SDFerr(SDF_F_SDF_DELETEFILE, SDF_R_METHOD_OPERATION_FAILURE);
		return ret;
	}

	return SDR_OK;
}

/* helpers */
const char *SDF_GetErrorString(int err)
{
	return NULL;
}

int SDF_PrintDeviceInfo(FILE *fp, DEVICEINFO *devInfo)
{
	return 0;
}

int SDF_PrintECCPrivateKey(FILE *fp, ECCrefPrivateKey *privateKey)
{
	return 0;
}

int SDF_PrintECCPublicKey(FILE *fp, ECCrefPublicKey *publicKey)
{
	return 0;
}

int SDF_PrintRSAPrivateKey(FILE *fp, RSArefPrivateKey *privateKey)
{
	return 0;
}

int SDF_PrintRSAPublicKey(FILE *fp, RSArefPublicKey *publicKey)
{
	return 0;
}





