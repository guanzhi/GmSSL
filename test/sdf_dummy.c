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

/*                       Dummy SDF Library
 *
 * This is the **dummy** implementation of the SDF API, used by the SDF
 * ENGINE for compiling and basic testing. For products this should be
 * replaced by the library provided by hardware vendors.
 *
 * Design principles:
 * 1. All the functions of this dummy library will return success, which
 *    is `SDR_OK`.
 * 2. If there are return value pointers, such as handles, output length
 *    or generated key data types, the output will be filled with valid
 *    data. Such that the caller can parse these data without errors.
 * 3. The implementation should not relay on any other libraries, source
 *    files or header files except the `sdf.h`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sgd.h>
#include <openssl/sdf.h>

static char *deviceHandle = "SDF Device Handle";
static char *sessionHandle = "SDF Session Handle";
static char *keyHandle = "SDF Key Handle";
static char *agreementHandle = "SDF Agreement Handle";
static int hashAlgor;
/*
static unsigned char certificate[] = {
	0x03, 0x04,
};
*/

static unsigned char rsaPublicKey[] = {
	0x03, 0x04,
};

static unsigned char rsaPrivateKey[] = {
	0x03, 0x04,
};

static unsigned char ecPublicKey[] = {
	0x03, 0x04,
};

static unsigned char ecPrivateKey[] = {
	0x03, 0x04,
};

static unsigned char ecCiphertext[] = {
	0x03,
};

static unsigned char ecSignature[] = {
	0x03,
};

/* 6.2.1 */
int SDF_OpenDevice(
	void **phDeviceHandle)
{
	*phDeviceHandle = deviceHandle;
	return SDR_OK;
}

/* 6.2.2 */
int SDF_CloseDevice(
	void *hDeviceHandle)
{
	return SDR_OK;
}

/* 6.2.3 */
int SDF_OpenSession(
	void *hDeviceHandle,
	void **phSessionHandle)
{
	*phSessionHandle = sessionHandle;
	return SDR_OK;
}

/* 6.2.4 */
int SDF_CloseSession(
	void *hSessionHandle)
{
	return SDR_OK;
}

/* 6.2.5 */
int SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo)
{
	memset(pstDeviceInfo, 0, sizeof(*pstDeviceInfo));
	strcpy((char *)pstDeviceInfo->IssuerName, "GmSSL");
	strcpy((char *)pstDeviceInfo->DeviceName, "Dummy SDF");
	strcpy((char *)pstDeviceInfo->DeviceSerial, "000001");
	pstDeviceInfo->DeviceVersion = 2;
	pstDeviceInfo->StandardVersion = 1;
	pstDeviceInfo->AsymAlgAbility[0] = SGD_RSA|SGD_SM2_1;
	pstDeviceInfo->AsymAlgAbility[1] = SGD_RSA|SGD_SM2_3;
	pstDeviceInfo->SymAlgAbility = SGD_SM1|SGD_SSF33|SGD_SM4|SGD_ZUC;
	pstDeviceInfo->HashAlgAbility = SGD_SM3|SGD_SHA1|SGD_SHA256;
	pstDeviceInfo->BufferSize = 0;
	return SDR_OK;
}

/* 6.2.6 */
int SDF_GenerateRandom(
	void *hSessionHandle,
	unsigned int uiLength,
	unsigned char *pucRandom)
{
	memset(pucRandom, 'R', uiLength);
	return SDR_OK;
}

/* 6.2.7 */
int SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength)
{
	return SDR_OK;
}

/* 6.2.8 */
int SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex)
{
	return SDR_OK;
}

/* 6.3.1 */
int SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	memcpy(pucPublicKey, rsaPublicKey, sizeof(*pucPublicKey));
	return SDR_OK;
}

/* 6.3.2 */
int SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	memcpy(pucPublicKey, rsaPublicKey, sizeof(*pucPublicKey));
	return SDR_OK;
}

/* 6.3.3 */
int SDF_GenerateKeyPair_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey)
{
	memcpy(pucPublicKey, rsaPublicKey, sizeof(*pucPublicKey));
	memcpy(pucPrivateKey, rsaPrivateKey, sizeof(*pucPrivateKey));
	return SDR_OK;
}

/* 6.3.4 */
int SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.5 */
int SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.6 */
int SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.7 */
int SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength)
{
	*puiDELength = 256; // correct?
	return SDR_OK;
}

/* 6.3.8 */
int SDF_ExportSignPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	memcpy(pucPublicKey, ecPublicKey, sizeof(*pucPublicKey));
	return SDR_OK;
}

/* 6.3.9 */
int SDF_ExportEncPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	memcpy(pucPublicKey, ecPublicKey, sizeof(*pucPublicKey));
	return SDR_OK;
}
/* 6.3.10 */
int SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int  uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey)
{
	memcpy(pucPublicKey, ecPublicKey, sizeof(*pucPublicKey));
	memcpy(pucPrivateKey, ecPrivateKey, sizeof(*pucPrivateKey));
	return SDR_OK;
}

/* 6.3.11 */
int SDF_GenerateKeyWithIPK_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.12 */
int SDF_GenerateKeyWithEPK_ECC(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.13 */
int SDF_ImportKeyWithISK_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.14 */
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
	*phAgreementHandle = agreementHandle;
	return SDR_OK;
}

/* 6.3.15 */
int SDF_GenerateKeyWithECC(
	void *hSessionHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.16 */
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
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.17 */
int SDF_ExchangeDigitEnvelopeBaseOnECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut)
{
	return SDR_OK;
}

/* 6.3.18 */
int SDF_GenerateKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.19 */
int SDF_ImportKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	*phKeyHandle = keyHandle;
	return SDR_OK;
}

/* 6.3.20 */
int SDF_DestroyKey(
	void *hSessionHandle,
	void *hKeyHandle)
{
	return SDR_OK;
}

/* 6.4.1 */
int SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	*puiOutputLength = 2048/8;
	return SDR_OK;
}

/* 6.4.2 */
int SDF_ExternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPrivateKey *pucPrivateKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	*puiOutputLength = 2048/8;
	return SDR_OK;
}

/* 6.4.3 */
int SDF_InternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	*puiOutputLength = 2048/8;
	return SDR_OK;
}

/* 6.4.4 */
int SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature)
{
	return SDR_OK;
}

/* 6.4.5 */
int SDF_InternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	memcpy(pucSignature, ecSignature, sizeof(*pucSignature));
	return SDR_OK;
}

/* 6.4.6 */
int SDF_InternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	return SDR_OK;
}

/* 6.4.7 */
int SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	memcpy(pucEncData, ecCiphertext, sizeof(*pucEncData));
	return SDR_OK;
}

/* 6.5.1 */
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
	*puiEncDataLength = uiDataLength + 16;
	return SDR_OK;
}

/* 6.5.2 */
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
	*puiDataLength = uiEncDataLength;
	return SDR_OK;
}

/* 6.5.3 */
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
	*puiMACLength = 128/8;
	return SDR_OK;
}

/* 6.6.1 */
int SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	return SDR_OK;
}

/* 6.6.2 */
int SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	return SDR_OK;
}

/* 6.6.3 */
int SDF_HashFinal(void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength)
{
	switch (hashAlgor) {
	case SGD_SM3:
		*puiHashLength = 256/8;
		break;
	case SGD_SHA1:
		*puiHashLength = 160/8;
		break;
	case SGD_SHA256:
		*puiHashLength = 256/8;
		break;
	}
	return SDR_OK;
}

/* 6.7.1 */
int SDF_CreateFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiFileSize)
{
	return SDR_OK;
}

/* 6.7.2 */
int SDF_ReadFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int *puiReadLength,
	unsigned char *pucBuffer)
{
	// return a certificate
	return SDR_OK;
}

/* 6.7.3 */
int SDF_WriteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int uiWriteLength,
	unsigned char *pucBuffer)
{
	return SDR_OK;
}

/* 6.7.4 */
int SDF_DeleteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen)
{
	return SDR_OK;
}
