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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/gmsaf.h>
#include <openssl/gmsof.h>
#include <openssl/crypto.h>
#include "../../e_os.h"

static SOF_LONG sof_sign_method = SGD_SM2;
static SOF_LONG sof_enc_method = SGD_SM4_CBC;
static SOF_LONG sof_last_error = SOR_OK;
static void *sof_app = NULL;
static int sof_user_type = SGD_ROLE_USER;

static int sof_read_file(const char *path, unsigned char **pdata,
	unsigned int *pdatalen)
{
	return 0;
}

static char *sof_encode(const unsigned char *bin, unsigned int binlen)
{
	return NULL;
}

#if 0
static int sof_decode(const char *b64, unsigned char **pdata, unsigned int *pdatalen)
{
	return 0;
}
#endif

SOF_BSTR SOF_GetVersion(void)
{
	return OPENSSL_strdup(OpenSSL_version(0));
}

SOF_LONG SOF_SetSignMethod(SOF_LONG SignMethod)
{
	sof_sign_method = SignMethod;
	return SOR_OK;
}

SOF_LONG SOF_GetSignMethod(void)
{
	return sof_sign_method;
}

SOF_LONG SOF_SetEncryptMethod(SOF_LONG EncryptMethod)
{
	sof_enc_method = EncryptMethod;
	return SOR_OK;
}

SOF_LONG SOF_GetEncryptMethod(void)
{
	return sof_enc_method;
}

/* list installed client's certificates */
SOF_BSTR SOF_GetUserList(void)
{
	SOFerr(SOF_F_SOF_GETUSERLIST, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

/* we need an reference to engine */
SOF_BSTR SOF_ExportUserCert(SOF_BSTR ContainerName)
{
	SOFerr(SOF_F_SOF_EXPORTUSERCERT, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BOOL SOF_Login(SOF_BSTR ContainerName, SOF_BSTR PassWd)
{
	unsigned int uiRemainCount;
	int rv;

	if ((rv = SAF_Login(
		sof_app,
		sof_user_type,
		(unsigned char *)ContainerName,
		(unsigned int)strlen(ContainerName),
		(unsigned char *)PassWd,
		(unsigned int)strlen(PassWd),
		&uiRemainCount)) != SAR_Ok) {
		SOFerr(SOF_F_SOF_LOGIN, ERR_R_SAF_LIB);
		return SGD_FALSE;
	}

	return SGD_TRUE;
}

SOF_LONG SOF_GetPinRetryCount(SOF_BSTR ContainerName)
{
	SOFerr(SOF_F_SOF_GETPINRETRYCOUNT, SOF_R_NOT_IMPLEMENTED);
	return SOR_NotSupportYetErr;
}

SOF_BOOL SOF_ChangePassWd(SOF_BSTR ContainerName, SOF_BSTR OldPassWd, SOF_BSTR NewPassWd)
{
	int rv;
	unsigned int uiRemainCount;

	if ((rv = SAF_ChangePin(
		sof_app,
		sof_user_type,
		(unsigned char *)ContainerName,
		(unsigned int)strlen(ContainerName),
		(unsigned char *)OldPassWd,
		(unsigned int)strlen(OldPassWd),
		(unsigned char *)NewPassWd,
		(unsigned int)strlen(NewPassWd),
		&uiRemainCount)) != SAR_Ok) {
		SOFerr(SOF_F_SOF_CHANGEPASSWD, ERR_R_SAF_LIB);
		return SGD_FALSE;
	}

	return SGD_TRUE;
}

SOF_BSTR SOF_ExportExchangeUserCert(SOF_BSTR ContainerName)
{
	SOFerr(SOF_F_SOF_EXPORTEXCHANGEUSERCERT, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

/* `type` defined as SGD_CERT_XXX, SGD_EXT_XXX in sgd.h */
SOF_BSTR SOF_GetCertInfo(SOF_BSTR Base64EncodeCert, SOF_SHORT Type)
{
	char *ret = NULL;

	switch (Type) {
	case SGD_CERT_VERSION:
	case SGD_CERT_SERIAL:
	case SGD_CERT_ISSUER:
	case SGD_CERT_VALID_TIME:
	case SGD_CERT_SUBJECT:
	case SGD_CERT_DER_PUBLIC_KEY:
	case SGD_CERT_DER_EXTENSIONS:
	case SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO:
	case SGD_EXT_SUBJECTKEYIDENTIFIER_INFO:
	case SGD_EXT_KEYUSAGE_INFO:
	case SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO:
	case SGD_EXT_CERTIFICATEPOLICIES_INFO:
	case SGD_EXT_POLICYMAPPINGS_INFO:
	case SGD_EXT_BASICCONSTRAINTS_INFO:
	case SGD_EXT_POLICYCONSTRAINTS_INFO:
	case SGD_EXT_EXTKEYUSAGE_INFO:
	case SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO:
	case SGD_EXT_NETSCAPE_CERT_TYPE_INFO:
	case SGD_EXT_SELFDEFINED_EXTENSION_INFO:
	case SGD_CERT_ISSUER_CN:
	case SGD_CERT_ISSUER_O:
	case SGD_CERT_ISSUER_OU:
	case SGD_CERT_SUBJECT_CN:
	case SGD_CERT_SUBJECT_O:
	case SGD_CERT_SUBJECT_OU:
	case SGD_CERT_SUBJECT_EMAIL:
	case SGD_CERT_NOTBEFORE_TIME:
	case SGD_CERT_NOTAFTER_TIME:
		SOFerr(SOF_F_SOF_GETCERTINFO, SOF_R_NOT_IMPLEMENTED);
		goto end;
	default:
		SOFerr(SOF_F_SOF_GETCERTINFO, SOF_R_INVALID_CERT_ATTRIBUTE);
		goto end;
	}

end:
	SOFerr(SOF_F_SOF_GETCERTINFO, SOF_R_NOT_IMPLEMENTED);
	return ret;
}

SOF_BSTR SOF_GetCertInfoByOid(SOF_BSTR Base64EncodeCert, SOF_BSTR Oid)
{
	SOFerr(SOF_F_SOF_GETCERTINFOBYOID, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BSTR SOF_GetDeviceInfo(SOF_BSTR ContainerName, SOF_LONG Type)
{
	SOFerr(SOF_F_SOF_GETDEVICEINFO, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_LONG SOF_ValidateCert(SOF_BSTR Base64EncodeCert)
{
	SOFerr(SOF_F_SOF_VALIDATECERT, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

SOF_BSTR SOF_SignData(SOF_BSTR ContainerName, SOF_BSTR InData)
{
	char *ret = NULL;
	char *b64 = NULL;
	unsigned int uiHashAlgoType = SGD_SM3;
	unsigned char *pucInData = NULL;
	unsigned int uiInDataLen = strlen(InData) + 128;
	unsigned char pucSignature[256];
	unsigned int uiSignatureLen = (unsigned int)sizeof(pucSignature);
	int rv;

	if (!(pucInData = OPENSSL_malloc(uiInDataLen))) {
		SOFerr(SOF_F_SOF_SIGNDATA, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (SAF_Base64_Decode((unsigned char *)InData, (unsigned int)strlen(InData),
		pucInData, &uiInDataLen) != SOR_OK) {
		SOFerr(SOF_F_SOF_SIGNDATA, SOF_R_DECODE_FAILURE);
		goto end;
	}

	if (SOF_GetSignMethod() == SGD_SM2) {
		if ((rv = SAF_RsaSign(
			sof_app,
			(unsigned char *)ContainerName,
			(unsigned int)strlen(ContainerName),
			uiHashAlgoType,
			pucInData,
			uiInDataLen,
			pucSignature,
			&uiSignatureLen)) != SAR_Ok) {
			SOFerr(SOF_F_SOF_SIGNDATA, ERR_R_SAF_LIB);
			goto end;
		}
	} else {
		if ((rv = SAF_EccSign(
			sof_app,
			(unsigned char *)ContainerName,
			(unsigned int)strlen(ContainerName),
			uiHashAlgoType,
			pucInData,
			uiInDataLen,
			pucSignature,
			&uiSignatureLen)) != SAR_Ok) {
			SOFerr(SOF_F_SOF_SIGNDATA, ERR_R_SAF_LIB);
			goto end;
		}
	}

	ret = SOR_OK;
end:
	OPENSSL_free(b64);
	OPENSSL_free(pucInData);
	return ret;
}

SOF_BOOL SOF_VerifySignedData(SOF_BSTR Base64EncodeCert, SOF_BSTR InData, SOF_BSTR SignValue)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDDATA, SOF_R_NOT_IMPLEMENTED);
	return 0;
}


SOF_BSTR SOF_SignFile(SOF_BSTR ContainerName, SOF_BSTR InFile)
{
	SOF_BSTR ret = NULL;
	char *b64 = NULL;
	unsigned int uiHashAlgoType = SGD_SM3;
	unsigned char *pucInData = NULL;
	unsigned int uiInDataLen;
	unsigned char pucSignature[256];
	unsigned int uiSignatureLen = (unsigned int)sizeof(pucSignature);
	int rv;

	if (!sof_read_file(InFile, &pucInData, &uiInDataLen)) {
		SOFerr(SOF_F_SOF_SIGNFILE, SOF_R_READ_FILE_FAILURE);
		return NULL;
	}

	if ((rv = SAF_EccSign(
		sof_app,
		(unsigned char *)ContainerName,
		(unsigned int)strlen(ContainerName),
		uiHashAlgoType,
		pucInData,
		uiInDataLen,
		pucSignature,
		&uiSignatureLen)) != SAR_Ok) {
		SOFerr(SOF_F_SOF_SIGNFILE, ERR_R_SAF_LIB);
		goto end;
	}

	if (!(b64 = sof_encode(pucSignature, uiSignatureLen))) {
		SOFerr(SOF_F_SOF_SIGNFILE, ERR_R_SOF_LIB);
		goto end;
	}

	ret = b64;
	b64 = NULL;

end:
	OPENSSL_free(b64);
	OPENSSL_free(pucInData);
	return ret;
}

SOF_BOOL SOF_VerifySignedFile(SOF_BSTR Base64EncodeCert, SOF_BSTR InFile, SOF_BSTR SignValue)
{
	return SGD_FALSE;
}

SOF_BSTR SOF_EncryptData(SOF_BSTR Base64EncodeCert, SOF_BSTR InData)
{
#if 0
	char *ret = NULL;
	unsigned char *pucCertificate = NULL;
	unsigned int uiCertificateLen;
	unsigned char *pucInData = NULL;
	unsigned int uiInDataLen;
	int rv;

	if (SOF_Decode(Base64EncodeCert, &pucCertificate, &uiCertificateLen) != SOR_OK
		|| SOF_Decode(InData, &pucInData, &uiInDataLen) != SOR_OK
		|| (rv = SAF_EccPublicKeyEncByCert(
			pucCertificate,
			uiCertificateLen,
			uiAlgorithmID,
			pucInData,
			uiInDataLen,
			pucOutData,
			puiOutDataLen)) != SAR_Ok) {
	}
#endif
	return NULL;
}

SOF_BSTR SOF_DecryptData(SOF_BSTR ContainerName, SOF_BSTR InData)
{
	SOFerr(SOF_F_SOF_DECRYPTDATA, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BOOL SOF_EncryptFile(SOF_BSTR Base64EncodeCert, SOF_BSTR InFile, SOF_BSTR OutFile)
{
	int ret = SGD_FALSE;
#if 0
	unsigned char *pucCertificate = NULL;
	unsigned int uiCertificateLen;
	int rv;

	if (SOF_Decode(Base64EncodeCert, &pucCertificate, &uiCertificateLen) != SOR_OK) {
		SOFerr(SOF_F_SOF_ENCRYPTFILE, SOF_R_DECODE_FAILURE);
		goto end;
	}

	if ((rv = SAF_EccPublicKeyEncByCert(
		pucCertificate,
		uiCertificateLen,
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucOutData,
		puiOutDataLen)) != SAR_Ok) {
		SOFerr(SOF_F_SOF_ENCRYPTFILE, ERR_R_SAF_LIB);
		goto end;
	}

	ret = SGD_TRUE;

end:
	OPENSSL_free(pucCertificate);
#endif
	return ret;
}

SOF_BOOL SOF_DecryptFile(SOF_BSTR ContainerName, SOF_BSTR InFile, SOF_BSTR OutFile)
{
	int ret = SGD_FALSE;
	return ret;
}

SOF_BSTR SOF_SignMessage(SOF_SHORT flag, SOF_BSTR ContainerName, SOF_BSTR InData)
{
	SOFerr(SOF_F_SOF_SIGNMESSAGE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BOOL SOF_VerifySignedMessage(SOF_BSTR MessageData, SOF_BSTR InData)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDMESSAGE, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

SOF_BSTR SOF_GetInfoFromSignedMessage(SOF_BSTR SignedMessage, SOF_SHORT Type)
{
	SOFerr(SOF_F_SOF_GETINFOFROMSIGNEDMESSAGE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BSTR SOF_SignDataXML(SOF_BSTR ContainerName, SOF_BSTR InData)
{
	return NULL;
}

SOF_BOOL SOF_VerifySignedDataXML(SOF_BSTR InData)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDDATAXML, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

SOF_BSTR SOF_GetXMLSignatureInfo(SOF_BSTR XMLSignedData, SOF_SHORT Type)
{
	SOFerr(SOF_F_SOF_GETXMLSIGNATUREINFO, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BSTR SOF_GenRandom(SOF_SHORT RandomLen)
{
	char *ret = NULL;
	char *b64 = NULL;
	unsigned char *bin = NULL;
	int rv;

	if (!(bin = OPENSSL_malloc(RandomLen))
		|| (rv = SAF_GenRandom(RandomLen, bin)) != SAR_Ok
		|| !(b64 = sof_encode(bin, RandomLen))) {
		SOFerr(SOF_F_SOF_GENRANDOM, ERR_R_SOF_LIB);
		goto end;
	}

end:
	OPENSSL_free(bin);
	OPENSSL_free(b64);
	return ret;
}

SOF_LONG SOF_GetLastError(void)
{
	return sof_last_error;
}

SOF_LONG SOF_SetCertTrustList(SOF_BSTR CTLAltName, SOF_BSTR CTLContent, SOF_SHORT CTLContentLen)
{
	SOFerr(SOF_F_SOF_SETCERTTRUSTLIST, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

SOF_BSTR SOF_GetCertTrustListAltNames(void)
{
	SOFerr(SOF_F_SOF_GETCERTTRUSTLISTALTNAMES, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BSTR SOF_GetCertTrustList(SOF_BSTR CTLAltName)
{
	SOFerr(SOF_F_SOF_GETCERTTRUSTLIST, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_LONG SOF_DelCertTrustList(SOF_BSTR CTLAltName)
{
	SOFerr(SOF_F_SOF_DELCERTTRUSTLIST, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

SOF_LONG SOF_InitCertAppPolicy(SOF_BSTR PolicyName)
{
	SOFerr(SOF_F_SOF_INITCERTAPPPOLICY, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

SOF_BSTR SOF_GetServerCertificate(SOF_SHORT CertUsage)
{
	SOFerr(SOF_F_SOF_GETSERVERCERTIFICATE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BSTR SOF_SignMessageDetach(SOF_BSTR InData)
{
	SOFerr(SOF_F_SOF_SIGNMESSAGEDETACH, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_LONG SOF_VerifySignedMessageDetach(SOF_BSTR InData, SOF_BSTR SignedMessage)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDMESSAGEDETACH, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

SOF_BSTR SOF_CreateTimeStampRequest(SOF_BSTR InData)
{
	SOFerr(SOF_F_SOF_CREATETIMESTAMPREQUEST, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_BSTR SOF_CreateTimeStampResponse(SOF_BSTR TimeStampRequest)
{
	SOFerr(SOF_F_SOF_CREATETIMESTAMPRESPONSE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

SOF_LONG SOF_VerifyTimeStamp(SOF_BSTR InData, SOF_BSTR tsResponseData)
{
	SOFerr(SOF_F_SOF_VERIFYTIMESTAMP, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

SOF_BSTR SOF_GetTimeStampInfo(SOF_BSTR tsResponseData, SOF_SHORT type)
{
	SOFerr(SOF_F_SOF_GETTIMESTAMPINFO, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

static ERR_STRING_DATA sof_errstr[] = {
	{ SOR_OK,		"Success" },
	{ SOR_UnknownErr,	"Unknown error" },
	{ SOR_FileErr,		"File error" },
	{ SOR_ProviderTypeErr,	"Provider type error" },
	{ SOR_LoadProviderErr,	"Load provider error" },
};

const char *SOF_GetErrorString(int err)
{
	int i;
	for (i = 0; i < OSSL_NELEM(sof_errstr); i++) {
		if (err == sof_errstr[i].error) {
			return sof_errstr[i].string;
		}
	}
	return "(undef)";
}
