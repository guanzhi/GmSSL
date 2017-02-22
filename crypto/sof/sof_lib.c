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

#include <openssl/err.h>
#include <openssl/gmsof.h>
#include "../../e_os.h"

static long sof_sign_method = SGD_SM2;
static long sof_enc_method = SGD_SM4_CBC;
static long sof_last_error = SOR_OK;


BSTR SOF_GetVersion(void)
{
	return OpenSSL_version(0);
}

long SOF_SetSignMethod(long SignMethod)
{
	sof_sign_method = SignMethod;
	return SOR_OK;
}

long SOF_GetSignMethod(void)
{
	return sof_sign_method;
}

long SOF_SetEncryptMethod(long EncryptMethod)
{
	sof_enc_method = EncryptMethod;
	return SOR_OK;
}

long SOF_GetEncryptMethod(void)
{
	return sof_enc_method;
}

/* list installed client's certificates */
BSTR SOF_GetUserList(void)
{
	SOFerr(SOF_F_SOF_GETUSERLIST, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

/* we need an reference to engine */
BSTR SOF_ExportUserCert(BSTR ContainerName)
{
	SOFerr(SOF_F_SOF_EXPORTUSERCERT, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

/* LOGIN CMD ? */
BOOL SOF_Login(BSTR ContainerName, BSTR PassWd)
{
	SOFerr(SOF_F_SOF_LOGIN, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

long SOF_GetPinRetryCount(BSTR ContainerName)
{
	SOFerr(SOF_F_SOF_GETPINRETRYCOUNT, SOF_R_NOT_IMPLEMENTED);
	return SOR_NotSupportYetErr;
}

BOOL SOF_ChangePassWd(BSTR ContainerName, BSTR OldPassWd, BSTR NewPassWd)
{
	SOFerr(SOF_F_SOF_CHANGEPASSWD, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BSTR SOF_ExportExchangeUserCert(BSTR ContainerName)
{
	SOFerr(SOF_F_SOF_EXPORTEXCHANGEUSERCERT, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

/* `type` defined as SGD_CERT_XXX, SGD_EXT_XXX in sgd.h */
BSTR SOF_GetCertInfo(BSTR Base64EncodeCert, short Type)
{
	SOFerr(SOF_F_SOF_GETCERTINFO, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BSTR SOF_GetCertInfoByOid(BSTR Base64EncodeCert, BSTR Oid)
{
	SOFerr(SOF_F_SOF_GETCERTINFOBYOID, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BSTR SOF_GetDeviceInfo(BSTR ContainerName, long Type)
{
	SOFerr(SOF_F_SOF_GETDEVICEINFO, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

long SOF_ValidateCert(BSTR Base64EncodeCert)
{
	SOFerr(SOF_F_SOF_VALIDATECERT, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

/* PKCS #7 or CMS ? */
BSTR SOF_SignData(BSTR ContainerName, BSTR InData)
{
	SOFerr(SOF_F_SOF_SIGNDATA, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BOOL SOF_VerifySignedData(BSTR Base64EncodeCert, BSTR InData, BSTR SignValue)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDDATA, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_SignFile(BSTR ContainerName, BSTR InFile)
{
	SOFerr(SOF_F_SOF_SIGNFILE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BOOL SOF_VerifySignedFile(BSTR Base64EncodeCert, BSTR InFile, BSTR SignValue)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDFILE, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_EncryptData(BSTR Base64EncodeCert, BSTR InData)
{
	SOFerr(SOF_F_SOF_ENCRYPTDATA, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BSTR SOF_DecryptData(BSTR ContainerName, BSTR InData)
{
	SOFerr(SOF_F_SOF_DECRYPTDATA, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BOOL SOF_EncryptFile(BSTR Base64EncodeCert, BSTR InFile, BSTR OutFile)
{
	SOFerr(SOF_F_SOF_ENCRYPTFILE, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BOOL SOF_DecryptFile(BSTR ContainerName, BSTR InFile, BSTR OutFile)
{
	SOFerr(SOF_F_SOF_DECRYPTFILE, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_SignMessage(short flag, BSTR ContainerName, BSTR InData)
{
	SOFerr(SOF_F_SOF_SIGNMESSAGE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BOOL SOF_VerifySignedMessage(BSTR MessageData, BSTR InData)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDMESSAGE, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_GetInfoFromSignedMessage(BSTR SignedMessage, short Type)
{
	SOFerr(SOF_F_SOF_GETINFOFROMSIGNEDMESSAGE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BSTR SOF_SignDataXML(BSTR ContainerName, BSTR InData)
{
	SOFerr(SOF_F_SOF_SIGNDATAXML, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BOOL SOF_VerifySignedDataXML(BSTR InData)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDDATAXML, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_GetXMLSignatureInfo(BSTR XMLSignedData, short Type)
{
	SOFerr(SOF_F_SOF_GETXMLSIGNATUREINFO, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

/* return base64 encoded data */
BSTR SOF_GenRandom(short RandomLen)
{
	SOFerr(SOF_F_SOF_GENRANDOM, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

long SOF_GetLastError(void)
{
	return sof_last_error;
}

long SOF_SetCertTrustList(BSTR CTLAltName, BSTR CTLContent, short CTLContentLen)
{
	SOFerr(SOF_F_SOF_SETCERTTRUSTLIST, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_GetCertTrustListAltNames(void)
{
	SOFerr(SOF_F_SOF_GETCERTTRUSTLISTALTNAMES, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BSTR SOF_GetCertTrustList(BSTR CTLAltName)
{
	SOFerr(SOF_F_SOF_GETCERTTRUSTLIST, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

long SOF_DelCertTrustList(BSTR CTLAltName)
{
	SOFerr(SOF_F_SOF_DELCERTTRUSTLIST, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

long SOF_InitCertAppPolicy(BSTR PolicyName)
{
	SOFerr(SOF_F_SOF_INITCERTAPPPOLICY, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_GetServerCertificate(short CertUsage)
{
	SOFerr(SOF_F_SOF_GETSERVERCERTIFICATE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BSTR SOF_SignMessageDetach(BSTR InData)
{
	SOFerr(SOF_F_SOF_SIGNMESSAGEDETACH, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

long SOF_VerifySignedMessageDetach(BSTR InData, BSTR SignedMessage)
{
	SOFerr(SOF_F_SOF_VERIFYSIGNEDMESSAGEDETACH, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_CreateTimeStampRequest(BSTR InData)
{
	SOFerr(SOF_F_SOF_CREATETIMESTAMPREQUEST, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

BSTR SOF_CreateTimeStampResponse(BSTR TimeStampRequest)
{
	SOFerr(SOF_F_SOF_CREATETIMESTAMPRESPONSE, SOF_R_NOT_IMPLEMENTED);
	return NULL;
}

long SOF_VerifyTimeStamp(BSTR InData, BSTR tsResponseData)
{
	SOFerr(SOF_F_SOF_VERIFYTIMESTAMP, SOF_R_NOT_IMPLEMENTED);
	return 0;
}

BSTR SOF_GetTimeStampInfo(BSTR tsResponseData, short type)
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

char *SOF_GetErrorString(int err)
{
	int i;
	for (i = 0; i < OSSL_NELEM(sof_errstr); i++) {
		if (err == sof_errstr[i].error) {
			return sof_errstr[i].string;
		}
	}
	return "(undef)";
}
