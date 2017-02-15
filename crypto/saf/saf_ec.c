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

/* GM/T 0019-2012: 7.3.23 */
/*
 * uiKeyUsage in {SGD_SM2_1, SGD_SM2_2, SGD_SM2_3}
 * uiExportFlag = 1 means exportable, 0 means non-exportable
 * we will generate a key pair and import into ENGINE
 * or use ENGINE to generate key pair
 */

#include <openssl/gmapi.h>
#include <openssl/gmsdf.h>
#include <openssl/gmsaf.h>

int saf_save_ec_keypair(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned int uiKeyUsage,
	unsigned int uiExportFlag,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey)
{
	return -1;
}

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
	ECCrefPublicKey publicKey;
	ECCrefPrivateKey privateKey;

	/* check arguments */
	if (!hAppHandle || !pucContainerName) {
		SAFerr(SAF_F_SAF_GENECCKEYPAIR,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiContainerNameLen <= 0 || uiContainerName > SGD_MAX_NAME_SIZE ||
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

	/* generate keypair */
	if (SDF_GenerateKeyPair_ECC(
		NULL,
		uiKeyUsage,
		uiKeyBits,
		&publicKey,
		&privateKey) != SDR_OK) {

		SAFerr(SAF_F_SAF_GENECCKEYPAIR, SAF_R_SAF_ERROR);
		goto end;
	}

	/* save keypair */
	if (saf_save_ec_keypair(
		hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiKeyBits,
		uiKeyUsage,
		uiExportFlag,
		&publicKey,
		&privateKey) != SAR_Ok) {

		SAFerr(SAF_F_SAF_GENECCKEYPAIR, ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	ret = SAR_Ok;

end:
	/* clear private key */
	memset(&privateKey, 0, sizeof(ECCrefPrivateKey));
	return ret;
}

int saf_get_sdf_session_and_keyindex(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyUsage,
	void *phSessionHandle,
	unsigned int puiKeyIndex)
{
	return -1;
}

void saf_release_sdf_session(
	void *hSessionHandle)
{
}

/*
 * `crypto/ec` only support `i2o_ECPublicKey` and `o2i_ECPublicKey`, there
 * are no DER encoding/decoding routines for EC public key. The encoding of
 * `i2o` is just the result of `EC_POINT_point2oct` on the public key point.
 */
/* 7.3.24 */
int SAF_GetEccPublicKey(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyUsage,
	unsigned char *pucPublicKey,
	unsigned int *puiPublicKeyLen)
{
	int ret = -1;
	void *hSessionHandle = NULL;
	unsigned int uiKeyIndex;
	int rv;

	/* check arguments */
	if (!hAppHandle || !pucContainerNamae || !pucPUblicKey ||
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

	/* get session and key index*/
	if ((rv = saf_get_sdf_session_and_keyindex(
		hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiKeyUsage,
		&hSessionHandle,
		&uiKeyIndex)) != SAR_Ok) {

		SAFerr(SAF_F_SAF_GETECCPUBLICKEY, ERR_R_GMAPI_LIB);
		ret = rv;
		goto end;
	}

	/* load key */
	if (uiKeyUsage == SGD_SM2_1) {
		if (SDF_ExportSignPublicKey_ECC(
			hSessionHandle,
			uiKeyIndex,
			(ECCrefPublicKey *)pucPublicKey) != SDR_OK) {

			SAFerr(SAF_F_SAF_GETECCPUBLICKEY, ERR_R_GMAPI_LIB);
			goto end;
		}
	} else {
		if (SDF_ExportEncPublicKey_ECC(
			hSessionHandle,
			uiKeyIndex,
			(ECCrefPublicKey *)pucPublicKey) != SDR_OK) {

			SAFerr(SAF_F_SAF_GETECCPUBLICKEY, ERR_R_GMAPI_LIB);
			goto end;
		}
	}

	/* set return value */
	*puiPublicKeyLen = (unsigned int)sizeof(ECCrefPublicKey);
	ret = SAR_Ok;

end:
	sdf_release_sdf_session(hSessionHandle);
	return ret;
}

/* 7.3.25 */
/* input data is message, not digest
 * otuput is the DER encoding of the signature
 *
 * WHY do we need a seperate function for EC and RSA?
 */
int saf_get_sdf_session_and_ecsignkey(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiAlgorithmID, /* SGD_SM2_1 */
	void **phSessionhandle,
	unsigned int *puiISKIndex);

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
	void *hSessionHandle = NULL;
	unsigned int uiISKIndex;

	/* check arguments */
	if (!hAppHandle || !pucContainerNamae || !pucPUblicKey ||
		!pucSignData || !pucSignDataLen) {
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

	/* get session and ec sign key */
	if ((rv = saf_get_sdf_session_and_ecsignkey(
		hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiAlgorithmID,
		&hSessionHandle,
		&uiISKIndex)) != SAR_Ok) {
		
		SAFerr(SAF_F_SAF_ECCSIGN, ERR_R_GMAPI_LIB);
		ret = rv;
		goto end;
	}

	/* sign */
	if (SDF_InternalSign_ECC(
		hSessionHandle,
		uiISKIndex,
		pucInData,
		uiInDataLen,
		(ECCSignature *)pucSignData) != SDR_OK) {
		
		SAFerr(SAF_F_SAF_ECCSIGN, ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	*puiSignDataLen = (unsigned int)sizeof(ECCSignature);
	ret = SAR_Ok;
	
end:
	saf_release_sdf_session(hSessionhandle);
	return ret;
}

/* 7.3.26 */
/* it seems that we need the public key has more info */
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
	
	/* check arguments */
	if (!pucPublicKey || !pucInData || !pucSignData) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGN, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr);
	}
	if (uiPublicKeyLen != sizeof(ECCrefPublic)) {
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

	if (SDF_ExternalVerify_ECC(
		NULL, /* hSessionHandle */
		uiAlgorithmID,
		(ECCrefPublicKey *)pucPublicKey,
		pucInData,
		uiInDataLen,
		(ECCSignature *)pucSignData) != SDR_OK) {

		SAFerr(SAF_F_SAF_ECCVERIFYSIGN, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SAR_Ok;

end:
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
	/* check arguments */
	if (!pucPublicKey || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiPublicKeyLen != sizeof(ECCrefPublic)) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (uiAlgorithmID != SGD_SM2_3) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			SAF_R_INVALID_ALGOR);
		return SAR_AlgoTypeErr;
	}
	if (uiInDataLen <= 0 || uiInDataLen > ECCref_MAX_CIPHER_LEN) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (*puiOutDataLen != sizeof(ECCCipher)) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	/* encrypt */
	if (SDF_ExternalEncrypt_ECC(
		NULL, /* hSessionHandle */
		uiAlgorithmID,
		(ECCrefPublicKey *)pucPublicKey,
		pucInData,
		uiInDataLen,
		(ECCCipher *)pucOutData) != SDR_OK) {
		
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENC, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SAR_Ok;
	
end:
	return ret;
}

int saf_get_ec_public_key_from_cert(
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	ECCrefPublicKey *pucPublicKey)
{
	return -1;
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
	ECCrefPublicKey publicKey;
	int rv;

	/* check arguments */
	if (!pucCertificate || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr);
	}
	if (uiCertificateLen <= 0 || uiCertificate > INT_MAX) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (uiAlgorithmID != SGD_SM2_3) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			SAF_R_INVALID_ALGOR);
		return SAR_AlgoTypeErr;
	}
	if (uiInDataLen <= 0 || uiInDataLen > ECCref_MAX_CIPHER_LEN) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}
	if (*puiOutDataLen != sizeof(ECCCipher)) {
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT,
			SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	/* get public key from cert */
	if ((rv = saf_get_ec_public_key_from_cert(
		pucCertificate,
		uiCertificateLen,
		&publicKey)) != SAR_OK) {
		
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT, ERR_R_GMAPI_LIB);
		ret = rv;
		goto end;
	}

	/* encrypt */
	if (SAF_EccPublicKeyEnc(
		(unsigned char *)&publicKey,
		(unsigned int)sizeof(ECCrefPublicKey),
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucOutData,
		puiOutDataLen) != SAR_OK) {
		
		SAFerr(SAF_F_SAF_ECCPUBLICKEYENCBYCERT, ERR_R_GMAPI_LIB);
		goto end;
	}
	
	/* set return value */
	ret = SAR_Ok;
	
end:
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
	ECCrefPublicKey publicKey;
	int rv;

	/* check arguments */
	if (!pucCertificate || !pucInData || !pucSignData) {
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT,
			ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr);
	}
	if (uiCertificateLen <= 0 || uiCertificate > INT_MAX) {
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

	/* load public key form cert */
	if ((rv = saf_get_ec_public_key_from_cert(
		pucCertificate,
		uiCertificateLen,
		&publicKey))!= SAR_OK) {
		
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT, ERR_R_GMAPI_LIB);
		ret = rv;
		goto end;
	}

	/* verify */
	if (SAF_EccVerifySign(
		(unsigned char *)&publicKey,
		(unsigned int )sizeof(ECCrefPublicKey),
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucSignData,
		uiSignDataLen)!= SAR_Ok) {
		
		SAFerr(SAF_F_SAF_ECCVERIFYSIGNBYCERT, ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	ret = SAR_Ok;
	
end:
	return ret;
}

/* 7.3.33 */
int SAF_GenerateAgreementDataWithECC(
	void *hSymmKeyObj,
	unsigned int uiISKIndex,
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
	void *hSessionHandle = NULL;
	unsigned int uiISKIndex;
	

	if (SDF_GenerateAgreementDataWithECC(
		hSessionHandle,
		uiISKIndex,
		uiKeyBits,
		pucSponsorID,
		uiSponsorIDLength,
		(ECCrefPublicKey *)pucSponsorPublicKey,
		(ECCrefPublicKey *)pucSponsorTmpPublicKey,
		phAgreementHandle) != SDR_OK) {

		SAFerr(SAF_F_SAF_GENERATEAGREEMENTDATAWITHECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SAR_Ok;
end:
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

	if (SDF_GenerateKeyWithECC(
		NULL, /*hSessionHandle */
		pucResponseID,
		uiResponseIDLength,
		(ECCrefPublicKey *)pucResponsePublicKey,
		(ECCrefPublicKey *)pucResponseTmpPublicKey,
		phAgreementHandle,
		phKeyHandle) != SDR_OK) {

		SAFerr(SAF_F_SAF_GENERATEKEYWITHECC, ERR_R_GMAPI_LIB);
		goto end;
	}

	return 0;
}

/* 7.3.35 */
int SAF_GenerateAgreementDataAdnKeyWithECC(
	void *hSymmKeyObj,
	unsigned int uiISKIndex,
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
		uiISKIndex,
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
