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

#ifdef __cplusplus
extern "C" {
#endif

BSTR SOF_GetVersion(void);
long SOF_SetSignMethod(long SignMethod);
long SOF_GetSignMethod(void);
long SOF_SetEncryptMethod(long EncryptMethod);
long SOF_GetEncryptMethod(void);
BSTR SOF_GetUserList(void);
BSTR SOF_ExportUserCert(BSTR ContainerName);
BOOL SOF_Login(BSTR ContainerName, BSTR PassWd);
long SOF_GetPinRetryCount(BSTR ContainerName);
BOOL SOF_ChangePassWd(BSTR ContainerName, BSTR OldPassWd, BSTR NewPassWd);
BSTR SOF_ExportExchangeUserCert(BSTR ContainerName);
BSTR SOF_GetCertInfo(BSTR Base64EncodeCert, short Type);
BSTR SOF_GetCertInfoByOid(BSTR Base64EncodeCert, BSTR Oid);
BSTR SOF_GetDeviceInfo(BSTR ContainerName, long Type);
long SOF_ValidateCert(BSTR Base64EncodeCert);
BSTR SOF_SignData(BSTR ContainerName, BSTR InData);
BOOL SOF_VerifySignedData(BSTR Base64EncodeCert, BSTR InData, BSTR SignValue);
BSTR SOF_SignFile(BSTR ContainerName, BSTR InFile);
BOOL SOF_VerifySignedFile(BSTR Base64EncodeCert, BSTR InFile, BSTR SignValue);
BSTR SOF_EncryptData(BSTR Base64EncodeCert, BSTR InData);
BSTR SOF_DecryptData(BSTR ContainerName, BSTR InData);
BOOL SOF_EncryptFile(BSTR Base64EncodeCert, BSTR InFile, BSTR OutFile);
BOOL SOF_DecryptFile(BSTR ContainerName, BSTR InFile, BSTR OutFile);
BSTR SOF_SignMessage(short flag, BSTR ContainerName, BSTR InData);
BOOL SOF_VerifySignedMessage(BSTR MessageData, BSTR InData);
BSTR SOF_GetInfoFromSignedMessage(BSTR SignedMessage, short Type);
BSTR SOF_SignDataXML(BSTR ContainerName, BSTR InData);
BOOL SOF_VerifySignedDataXML(BSTR InData);
BSTR SOF_GetXMLSignatureInfo(BSTR XMLSignedData, short Type);
BSTR SOF_GenRandom(short RandomLen);
long SOF_GetLastError(void);

long SOF_SetCertTrustList(BSTR CTLAltName, BSTR CTLContent, short CTLContentLen);
BSTR SOF_GetCertTrustListAltNames(void);
BSTR SOF_GetCertTrustList(BSTR CTLAltName);
long SOF_DelCertTrustList(BSTR CTLAltName);
long SOF_InitCertAppPolicy(BSTR PolicyName);
BSTR SOF_GetServerCertificate(short CertUsage);
BSTR SOF_SignMessageDetach(BSTR InData);
long SOF_VerifySignedMessageDetach(BSTR InData, BSTR SignedMessage);
BSTR SOF_CreateTimeStampRequest(BSTR InData);
BSTR SOF_CreateTimeStampResponse(BSTR TimeStampRequest);
long SOF_VerifyTimeStamp(BSTR InData, BSTR tsResponseData);
BSTR SOF_GetTimeStampInfo(BSTR tsResponseData, short type);

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
