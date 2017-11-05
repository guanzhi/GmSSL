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

#include <string.h>
#include <openssl/gmapi.h>
#include <openssl/gmsdf.h>
#include <openssl/gmsaf.h>
#include "saf_lcl.h"


/* 7.3.23 */
int SAF_GenEccKeyPair(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned int uiKeyUsage,
	unsigned int uiExportFlag)
{
	int ret = -1;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *pkey = NULL;

	/* check arguments */
	if (!hAppHandle || !pucContainerName) {
		SAFerr(SAF_F_SAF_GENECCKEYPAIR,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiContainerNameLen <= 0 || uiContainerNameLen > SGD_MAX_NAME_SIZE ||
		strlen((char *)pucContainerName) != uiContainerNameLen) {
		SAFerr(SAF_F_SAF_GENECCKEYPAIR,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_NameLenErr;
	}
	if (uiKeyBits < 160 || uiKeyBits > ECCref_MAX_BITS) {
		SAFerr(SAF_F_SAF_GENECCKEYPAIR,
			SAF_R_INVALID_KEY_LENGTH);
		return SAR_ModulusLenErr;
	}
	if (uiKeyUsage != SGD_SM2_1 && uiKeyUsage != SGD_SM2_2 &&
		uiKeyUsage != SGD_SM2_3) {
		SAFerr(SAF_F_SAF_GENECCKEYPAIR,
			SAF_R_INVALID_KEY_USAGE);
		return SAR_KeyUsageErr;
	}

	/* process */

	if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, app->engine))
		|| EVP_PKEY_keygen_init(pctx) <= 0
		|| EVP_PKEY_keygen(pctx, &pkey) <= 0) {
		SAFerr(SAF_F_SAF_GENECCKEYPAIR, ERR_R_EVP_LIB);
		goto end;
	}

	ret = SAR_Ok;
end:
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pkey);
	return ret;
}

const char *SGD_GetKeyUsageName(unsigned int uiKeyUsage)
{
	switch (uiKeyUsage) {
	case SGD_PK_SIGN:
		return "sign";
	case SGD_PK_ENC:
		return "enc";
	case SGD_PK_DH:
		return "dh";
	}
	return NULL;
}

/* 7.3.24 */
int SAF_GetEccPublicKey(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyUsage,
	unsigned char *pucPublicKey,
	unsigned int *puiPublicKeyLen)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	EVP_PKEY *pkey = NULL;
	char key_id[1024];
	int len;

	/* check arguments */
	if (!hAppHandle || !pucContainerName || !pucPublicKey ||
		!puiPublicKeyLen) {
		SAFerr(SAF_F_SAF_GETECCPUBLICKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiContainerNameLen <= 0 ||
		uiContainerNameLen > SGD_MAX_NAME_SIZE ||
		strlen((char *)pucContainerName) != uiContainerNameLen) {
		SAFerr(SAF_F_SAF_GETECCPUBLICKEY,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_NameLenErr;
	}
	if (uiKeyUsage != SGD_SM2_1 && uiKeyUsage != SGD_SM2_2 &&
		uiKeyUsage != SGD_SM2_3) {
		SAFerr(SAF_F_SAF_GETECCPUBLICKEY,
			SAF_R_INVALID_KEY_USAGE);
		return SAR_KeyUsageErr;
	}
	if ((size_t)*puiPublicKeyLen != sizeof(ECCrefPublicKey)) {
		SAFerr(SAF_F_SAF_GETECCPUBLICKEY,
			SAF_R_BUFFER_TOO_SMALL);
		return SAR_IndataErr;
	}

	/* process */

	/*
			
	snprintf(key_id, sizeof(key_id), "%s.%s", (char *)pucContainerName,
		SGD_GetKeyUsageName(uiKeyUsage));
	*/

	if (!(pkey = ENGINE_load_public_key(app->engine, key_id, NULL, NULL))) {
		SAFerr(SAF_F_SAF_GETECCPUBLICKEY, ERR_R_ENGINE_LIB);
		goto end;
	}
	if ((len = i2d_PUBKEY(pkey, &pucPublicKey)) <= 0) {
		SAFerr(SAF_F_SAF_GETECCPUBLICKEY, ERR_R_X509_LIB);
		goto end;
	}

	*puiPublicKeyLen = (unsigned int)len;

	/* set return value */
	ret = SAR_Ok;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

/* 7.3.25 */
int SAF_EccSign(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiAlgorithmID, /* SGD_SM2_1 */
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignData,
	unsigned int *puiSignDataLen)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	char key_id[1024];
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t siglen;

	/* check arguments */
	if (!hAppHandle || !pucContainerName || !pucInData ||
		!pucSignData || !puiSignDataLen) {
		SAFerr(SAF_F_SAF_ECCSIGN,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiContainerNameLen <= 0 ||
		uiContainerNameLen > SGD_MAX_NAME_SIZE ||
		strlen((char *)pucContainerName) != uiContainerNameLen) {
		SAFerr(SAF_F_SAF_ECCSIGN, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_NameLenErr;
	}
	if (uiAlgorithmID != SGD_SM2_1) {
		SAFerr(SAF_F_SAF_ECCSIGN, SAF_R_INVALID_ALGOR);
		return SAR_AlgoTypeErr;
	}
	if (uiInDataLen != SM3_DIGEST_LENGTH) {
		SAFerr(SAF_F_SAF_ECCSIGN, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if ((size_t)*puiSignDataLen != sizeof(ECCSignature)) {
		SAFerr(SAF_F_SAF_ECCSIGN, SAF_R_BUFFER_TOO_SMALL);
		return SAR_IndataErr;
	}

	/* process */

	/*		
	snprintf(key_id, sizeof(key_id), "%s.sign", (char *)pucContainerName);
	*/

	if (!(pkey = ENGINE_load_private_key(app->engine, key_id, NULL, NULL))
		|| !(pctx = EVP_PKEY_CTX_new(pkey, app->engine))
		|| EVP_PKEY_sign_init(pctx) <= 0
		|| EVP_PKEY_sign(pctx, pucSignData, &siglen, pucInData, (size_t)uiInDataLen) <= 0) {
		SAFerr(SAF_F_SAF_ECCSIGN, ERR_R_EVP_LIB);
		goto end;
	}

	*puiSignDataLen = (unsigned int)siglen;

	ret = SAR_Ok;
end:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
	return ret;
}

/* 7.3.26 */
int SAF_EccVerifySign(
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned int uiAlgorithmID,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignData,
	unsigned int uiSignDataLen)
{
	int ret = SAR_UnknownErr;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;

	/* check arguments */
	if (!pucPublicKey || !pucInData || !pucSignData) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGN, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiPublicKeyLen != sizeof(ECCrefPublicKey)) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGN, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (uiAlgorithmID != SGD_SM2_1) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGN, SAF_R_INVALID_ALGOR);
		return SAR_AlgoTypeErr;
	}
	if (uiInDataLen != SM3_DIGEST_LENGTH) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGN, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (uiSignDataLen != sizeof(ECCSignature)) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGN, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	/* process */

	if (!(pkey = d2i_PUBKEY(NULL, (const unsigned char **)&pucPublicKey, (long)uiPublicKeyLen))
		|| !(pctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| EVP_PKEY_verify_init(pctx) <= 0
		|| EVP_PKEY_verify(pctx, pucSignData, uiSignDataLen, pucInData, uiInDataLen) <= 0) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGN, ERR_R_EVP_LIB);
		goto end;
	}

	ret = SAR_Ok;
end:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
	return ret;
}

/* 7.3.27 */
int SAF_EccPublicKeyEnc(
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned int uiAlgorithmID,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = -1;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t outlen = *puiOutDataLen;

	/* check arguments */
	if (!pucPublicKey || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiPublicKeyLen != sizeof(ECCrefPublicKey)) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (uiAlgorithmID != SGD_SM2_3) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			SAF_R_INVALID_ALGOR);
		return SAR_AlgoTypeErr;
	}
	if (uiInDataLen <= 0 || uiInDataLen > SAF_MAX_EC_CIPHERTEXT_LENGTH) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (*puiOutDataLen != sizeof(ECCCipher)) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	/* precess */

	if (!(pkey = d2i_PUBKEY(NULL, (const unsigned char **)&pucPublicKey, (long)uiPublicKeyLen))
		|| !(pctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| EVP_PKEY_decrypt_init(pctx) <= 0
		|| EVP_PKEY_decrypt(pctx, pucOutData, &outlen, pucInData, uiInDataLen) <= 0) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC, ERR_R_EVP_LIB);
		goto end;
	}

	*puiOutDataLen = (unsigned int)outlen;

	ret = SAR_Ok;
end:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
	return ret;
}

/* 7.3.28 */
int SAF_EccPublicKeyEncByCert(
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned int uiAlgorithmID,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = SAR_UnknownErr;
	X509 *x509 = NULL;
	unsigned char pubkey[1024];
	unsigned char *p = pubkey;
	int len;

	/* check arguments */
	if (!pucCertificate || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiCertificateLen <= 0 || uiCertificateLen > INT_MAX) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (uiAlgorithmID != SGD_SM2_3) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			SAF_R_INVALID_ALGOR);
		return SAR_AlgoTypeErr;
	}
	if (uiInDataLen <= 0 || uiInDataLen > SAF_MAX_EC_CIPHERTEXT_LENGTH) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (*puiOutDataLen != sizeof(ECCCipher)) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	/* process */

	if (!(x509 = d2i_X509(NULL, (const unsigned char **)&pucCertificate, (long)uiCertificateLen))) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT, ERR_R_X509_LIB);
		goto end;
	}

	if ((len = i2d_PUBKEY(X509_get0_pubkey(x509), &p)) <= 0) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT, ERR_R_X509_LIB);
		goto end;
	}

	ret = SAF_EccPublicKeyEnc(
		pubkey,
		(unsigned int)len,
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucOutData,
		puiOutDataLen);


	/* set return value */
	ret = SAR_Ok;
end:
	X509_free(x509);
	return ret;
}

/* 7.3.29 */
int SAF_EccVerifySignByCert(
	unsigned int uiAlgorithmID,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignData,
	unsigned int uiSignDataLen)
{
	int ret = SAR_UnknownErr;
	X509 *x509 = NULL;
	unsigned char pucPublicKey[1024];
	unsigned int uiPublicKeyLen;
	unsigned char *p = pucPublicKey;
	int len;

	/* check arguments */
	if (!pucCertificate || !pucInData || !pucSignData) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiCertificateLen <= 0 || uiCertificateLen > INT_MAX) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (uiAlgorithmID != SGD_SM2_1) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT,
			SAF_R_INVALID_ALGOR);
		return SAR_AlgoTypeErr;
	}
	if (uiInDataLen != SM3_DIGEST_LENGTH) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (uiSignDataLen != sizeof(ECCSignature)) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	/* process */

	if (!(x509 = d2i_X509(NULL, (const unsigned char **)&pucCertificate, (long)uiCertificateLen))) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT, ERR_R_X509_LIB);
		goto end;
	}

	if ((len = i2d_PUBKEY(X509_get0_pubkey(x509), &p)) <= 0) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT, ERR_R_X509_LIB);
		goto end;
	}

	uiPublicKeyLen = (unsigned int)len;

	ret = SAF_EccVerifySign(
		pucPublicKey,
		uiPublicKeyLen,
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucSignData,
		uiSignDataLen);


	/* set return value */
	ret = SAR_Ok;
end:
	X509_free(x509);
	return ret;
}

/* 7.3.33 */
int SAF_GenerateAgreementDataWithECC(
	void *hSymmKeyObj,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	unsigned char *pucSponsorPublicKey,
	unsigned int *puiSponsorPublicKeyLen,
	unsigned char *pucSponsorTmpPublicKey,
	unsigned int *puiSponsorTmpPublicKeyLen,
	void **phAgreementHandle)
{
	int ret = -1;

	ret = SAR_Ok;

	return ret;
}

/* 7.3.34 */
int SAF_GenerateKeyWithECC(
	void *phAgreementHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucResponsePublicKey,
	unsigned int uiResponsePublicKeyLen,
	unsigned char *pucResponseTmpPublicKey,
	unsigned int uiResponseTmpPublicKeyLen,
	void **phKeyHandle)
{
	int ret = -1;

	return ret;
}

/* 7.3.35 */
int SAF_GenerateAgreementDataAdnKeyWithECC(
	void *hSymmKeyObj,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	unsigned char *pucSponsorPublicKey,
	unsigned int *puiSponsorPublicKeyLen,
	unsigned char *pucSponsorTmpPublicKey,
	unsigned int *puiSponsorTmpPublicKeyLen,
	unsigned char *pucResponsePublicKey,
	unsigned int uiResponsePublicKeyLen,
	unsigned char *pucResponseTmpPublicKey,
	unsigned int uiResponseTmpPublicKeyLen,
	void **phKeyHandle)
{
	int ret;
	void *hAgreementHandle = NULL;

	if ((ret = SAF_GenerateAgreementDataWithECC(
		hSymmKeyObj,
		pucContainerName,
		uiContainerNameLen,
		uiKeyBits,
		pucSponsorID,
		uiSponsorIDLength,
		pucSponsorPublicKey,
		puiSponsorPublicKeyLen,
		pucSponsorTmpPublicKey,
		puiSponsorTmpPublicKeyLen,
		&hAgreementHandle)) != SAR_OK) {
	}

	if ((ret = SAF_GenerateKeyWithECC(
		hAgreementHandle,
		pucResponseID,
		uiResponseIDLength,
		pucResponsePublicKey,
		uiResponsePublicKeyLen,
		pucResponseTmpPublicKey,
		uiResponseTmpPublicKeyLen,
		phKeyHandle)) != SAR_OK) {
	}

	return 0;
}

/* GmSSL Extension  */
int SAF_EccSignFile(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiHashAlgoType,
	unsigned char *pucFileName,
	unsigned char *pucSignature,
	unsigned int *puiSignatureLen)
{
	return SAR_OK;
}

int SAF_EccVerifySignFile(
	unsigned int uiHashAlgoType,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucFileName,
	unsigned char *pucSignature,
	unsigned int uiSignatureLen)
{
	return SAR_OK;
}
