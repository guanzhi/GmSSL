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

#ifndef HEADER_SOF_H
#define HEADER_SOF_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SOF

#include <openssl/sgd.h>

typedef char *			SOF_BSTR;
typedef long			SOF_LONG;
typedef short			SOF_SHORT;
typedef SOF_LONG		SOF_BOOL;

#ifdef __cplusplus
extern "C" {
#endif


SOF_BSTR SOF_GetVersion(void);
SOF_LONG SOF_SetSignMethod(SOF_LONG SignMethod);
SOF_LONG SOF_GetSignMethod(void);
SOF_LONG SOF_SetEncryptMethod(SOF_LONG EncryptMethod);
SOF_LONG SOF_GetEncryptMethod(void);
SOF_BSTR SOF_GetUserList(void);
SOF_BSTR SOF_ExportUserCert(SOF_BSTR ContainerName);
SOF_BOOL SOF_Login(SOF_BSTR ContainerName, SOF_BSTR PassWd);
SOF_LONG SOF_GetPinRetryCount(SOF_BSTR ContainerName);
SOF_BOOL SOF_ChangePassWd(SOF_BSTR ContainerName, SOF_BSTR OldPassWd, SOF_BSTR NewPassWd);
SOF_BSTR SOF_ExportExchangeUserCert(SOF_BSTR ContainerName);
SOF_BSTR SOF_GetCertInfo(SOF_BSTR Base64EncodeCert, SOF_SHORT Type);
SOF_BSTR SOF_GetCertInfoByOid(SOF_BSTR Base64EncodeCert, SOF_BSTR Oid);
SOF_BSTR SOF_GetDeviceInfo(SOF_BSTR ContainerName, SOF_LONG Type);
SOF_LONG SOF_ValidateCert(SOF_BSTR Base64EncodeCert);
SOF_BSTR SOF_SignData(SOF_BSTR ContainerName, SOF_BSTR InData);
SOF_BOOL SOF_VerifySignedData(SOF_BSTR Base64EncodeCert, SOF_BSTR InData, SOF_BSTR SignValue);
SOF_BSTR SOF_SignFile(SOF_BSTR ContainerName, SOF_BSTR InFile);
SOF_BOOL SOF_VerifySignedFile(SOF_BSTR Base64EncodeCert, SOF_BSTR InFile, SOF_BSTR SignValue);
SOF_BSTR SOF_EncryptData(SOF_BSTR Base64EncodeCert, SOF_BSTR InData);
SOF_BSTR SOF_DecryptData(SOF_BSTR ContainerName, SOF_BSTR InData);
SOF_BOOL SOF_EncryptFile(SOF_BSTR Base64EncodeCert, SOF_BSTR InFile, SOF_BSTR OutFile);
SOF_BOOL SOF_DecryptFile(SOF_BSTR ContainerName, SOF_BSTR InFile, SOF_BSTR OutFile);
SOF_BSTR SOF_SignMessage(SOF_SHORT flag, SOF_BSTR ContainerName, SOF_BSTR InData);
SOF_BOOL SOF_VerifySignedMessage(SOF_BSTR MessageData, SOF_BSTR InData);
SOF_BSTR SOF_GetInfoFromSignedMessage(SOF_BSTR SignedMessage, SOF_SHORT Type);
SOF_BSTR SOF_SignDataXML(SOF_BSTR ContainerName, SOF_BSTR InData);
SOF_BOOL SOF_VerifySignedDataXML(SOF_BSTR InData);
SOF_BSTR SOF_GetXMLSignatureInfo(SOF_BSTR XMLSignedData, SOF_SHORT Type);
SOF_BSTR SOF_GenRandom(SOF_SHORT RandomLen);
SOF_LONG SOF_GetLastError(void);

SOF_LONG SOF_SetCertTrustList(SOF_BSTR CTLAltName, SOF_BSTR CTLContent, SOF_SHORT CTLContentLen);
SOF_BSTR SOF_GetCertTrustListAltNames(void);
SOF_BSTR SOF_GetCertTrustList(SOF_BSTR CTLAltName);
SOF_LONG SOF_DelCertTrustList(SOF_BSTR CTLAltName);
SOF_LONG SOF_InitCertAppPolicy(SOF_BSTR PolicyName);
SOF_BSTR SOF_GetServerCertificate(SOF_SHORT CertUsage);
SOF_BSTR SOF_SignMessageDetach(SOF_BSTR InData);
SOF_LONG SOF_VerifySignedMessageDetach(SOF_BSTR InData, SOF_BSTR SignedMessage);
SOF_BSTR SOF_CreateTimeStampRequest(SOF_BSTR InData);
SOF_BSTR SOF_CreateTimeStampResponse(SOF_BSTR TimeStampRequest);
SOF_LONG SOF_VerifyTimeStamp(SOF_BSTR InData, SOF_BSTR tsResponseData);
SOF_BSTR SOF_GetTimeStampInfo(SOF_BSTR tsResponseData, SOF_SHORT type);

#define SOR_OK			0x00000000
#define SOR_UnknownErr		0x0B000001
#define SOR_NotSupportYetErr	0x0B000002
#define SOR_FileErr		0x0B000003
#define SOR_ProviderTypeErr	0x0B000004
#define SOR_LoadProviderErr	0x0B000005
#define SOR_LoadDevMngApiErr	0x0B000006
#define SOR_AlgoTypeErr		0x0B000007
#define SOR_NameLenErr		0x0B000008
#define SOR_KeyUsageErr		0x0B000009
#define SOR_ModulusLenErr	0x0B000010
#define SOR_NotInitializeErr	0x0B000011
#define SOR_ObjErr		0x0B000012
#define SOR_MemoryErr		0x0B000100
#define SOR_TimeoutErr		0x0B000101
#define SOR_IndataLenErr	0x0B000200
#define SOR_IndataErr		0x0B000201
#define SOR_GenRandErr		0x0B000300
#define SOR_HashObjErr		0x0B000301
#define SOR_HashErr		0x0B000302
#define SOR_GenRsaKeyErr	0x0B000303
#define SOR_RsaModulusLenErr	0x0B000304
#define SOR_CspImprtPubKeyErr	0x0B000305
#define SOR_RsaEncErr		0x0B000306
#define SOR_RsaDecErr		0x0B000307
#define SOR_HashNotEqualErr	0x0B000308
#define SOR_KeyNotFountErr	0x0B000309
#define SOR_CertNotFountErr	0x0B000310
#define SOR_NotExportErr	0x0B000311
#define SOR_VerifyPolicyErr	0x0B000312
#define SOR_DecryptPadErr	0x0B000400
#define SOR_MacLenErr		0x0B000401
#define SOR_KeyInfoTypeErr	0x0B000402
#define SOR_NullPointerErr	0x0B000403
#define SOR_AppNotFoundErr	0x0B000404
#define SOR_CertEncodeErr	0x0B000405
#define SOR_CertInvalidErr	0x0B000406
#define SOR_CertHasExpiredErr	0x0B000407
#define SOR_CertRevokedErr	0x0B000408
#define SOR_SignDataErr		0x0B000409
#define SOR_VerifySignDataErr	0x0B000410
#define SOR_ReadFileErr		0x0B000411
#define SOR_WriteFileErr	0x0B000412
#define SOR_SecretSegmentErr	0x0B000413
#define SOR_SecretRecoverErr	0x0B000414
#define SOR_EncryptDataErr	0x0B000415
#define SOR_DecryptDataErr	0x0B000416
#define SOR_PKCS7EncodeErr	0x0B000417
#define SOR_XMLEncodeErr	0x0B000418
#define SOR_ParameterNotSupportErr 0x0B000419
#define SOR_CTLNotFound		0x0B000420
#define SOR_AppNotFound		0x0B000421

#ifdef __cplusplus
}
#endif
#endif
#endif
