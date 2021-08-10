/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef HEADER_GMSKF_H
#define HEADER_GMSKF_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SKF

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/sgd.h>
#include <openssl/skf.h>

#define SKF_NO_PADDING		0
#define SKF_PKCS5_PADDING	1

#define SKF_DEV_STATE_ABSENT	0x00000000
#define SKF_DEV_STATE_PRESENT	0x00000001
#define SKF_DEV_STATE_UNKNOW	0x00000010

#define SKF_CONTAINER_TYPE_UNDEF	0
#define SKF_CONTAINER_TYPE_RSA		1
#define SKF_CONTAINER_TYPE_ECC		2

#define SKF_ENVELOPEDKEYBLOB_VERSION	1
#define SKF_AUTHKEY_LENGTH		16
#define SKF_AUTHRAND_LENGTH		16
#define SKF_MAX_FILE_SIZE		(256*1024)
#define SKF_MAX_CERTIFICATE_SIZE	(8*1024)


#define SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT	6
#define SKF_DEFAULT_USER_PIN_RETRY_COUNT	6

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	union {
		ECCPUBLICKEYBLOB ecc;
		RSAPUBLICKEYBLOB rsa;
	} u;
} SKF_PUBLICKEYBLOB;
#define SKF_MAX_PUBLICKEYBOLB_LENGTH sizeof(SKF_PUBLICKEYBLOB)

typedef struct {
	char *name;
	unsigned char *buf;
	int offset;
	int length;
} SKF_FILE_OP_PARAMS;


ULONG DEVAPI SKF_LoadLibrary(LPSTR so_path, LPSTR vendor);
ULONG DEVAPI SKF_UnloadLibrary(void);
ULONG DEVAPI SKF_OpenDevice(LPSTR devName, BYTE authKey[16], DEVINFO *devInfo, DEVHANDLE *phDev);
ULONG DEVAPI SKF_CloseDevice(DEVHANDLE hDev);
ULONG DEVAPI SKF_GetDevStateName(ULONG ulDevState, LPSTR *szName);
ULONG DEVAPI SKF_GetContainerTypeName(ULONG ulContainerType, LPSTR *szName);
ULONG DEVAPI SKF_GetAlgorName(ULONG ulAlgID, LPSTR *szName);
ULONG DEVAPI SKF_PrintDevInfo(BIO *out, DEVINFO *devInfo);
ULONG DEVAPI SKF_PrintRSAPublicKey(BIO *out, RSAPUBLICKEYBLOB *blob);
ULONG DEVAPI SKF_PrintRSAPrivateKey(BIO *out, RSAPRIVATEKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCPublicKey(BIO *out, ECCPUBLICKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCPrivateKey(BIO *out, ECCPRIVATEKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCCipher(BIO *out, ECCCIPHERBLOB *blob);
ULONG DEVAPI SKF_PrintECCSignature(BIO *out, ECCSIGNATUREBLOB *blob);
ULONG DEVAPI SKF_GetErrorString(ULONG ulError, LPSTR *szErrorStr);
ULONG DEVAPI SKF_NewECCCipher(ULONG ulCipherLen, ECCCIPHERBLOB **cipherBlob);
ULONG DEVAPI SKF_NewEnvelopedKey(ULONG ulCipherLen, ENVELOPEDKEYBLOB **envelopedKeyBlob);
ULONG DEVAPI SKF_ImportECCPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, EC_KEY *ec_key, ULONG symmAlgId);
ULONG DEVAPI SKF_ImportRSAPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, RSA *rsa, ULONG symmAlgId);
ULONG DEVAPI SKF_ImportPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, EVP_PKEY *pkey, ULONG symmAlgId);
ULONG DEVAPI SKF_ExportECCPublicKey(HCONTAINER hContainer, BOOL bSign, EC_KEY **pp);
ULONG DEVAPI SKF_ExportRSAPublicKey(HCONTAINER hContainer, BOOL bSign, RSA **pp);
ULONG DEVAPI SKF_ExportEVPPublicKey(HCONTAINER hContainer, BOOL bSign, EVP_PKEY **pp);
ULONG DEVAPI SKF_ImportX509CertificateByKeyUsage(HCONTAINER hContainer, X509 *x509);
ULONG DEVAPI SKF_ImportX509Certificate(HCONTAINER hContainer, BOOL bSign, X509 *x509);
ULONG DEVAPI SKF_ExportX509Certificate(HCONTAINER hContainer, BOOL bSign, X509 **px509);


