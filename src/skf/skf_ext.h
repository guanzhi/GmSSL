/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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

#ifndef SKFUTIL_SKF_EXT_H
#define SKFUTIL_SKF_EXT_H


#include <stdio.h>
#include "skf.h"


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
ULONG DEVAPI SKF_PrintDevInfo(FILE *fp, const DEVINFO *devInfo);
ULONG DEVAPI SKF_PrintRSAPublicKey(FILE *fp, const RSAPUBLICKEYBLOB *blob);
ULONG DEVAPI SKF_PrintRSAPrivateKey(FILE *fp, const RSAPRIVATEKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCPublicKey(FILE *fp, const ECCPUBLICKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCPrivateKey(FILE *fp, const ECCPRIVATEKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCCipher(FILE *fp, const ECCCIPHERBLOB *blob);
ULONG DEVAPI SKF_PrintECCSignature(FILE *fp, const ECCSIGNATUREBLOB *blob);
ULONG DEVAPI SKF_GetErrorString(ULONG ulError, LPSTR *szErrorStr);
ULONG DEVAPI SKF_NewECCCipher(ULONG ulCipherLen, ECCCIPHERBLOB **cipherBlob);
ULONG DEVAPI SKF_NewEnvelopedKey(ULONG ulCipherLen, ENVELOPEDKEYBLOB **envelopedKeyBlob);

/*
ULONG DEVAPI SKF_ImportECCPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, EC_KEY *ec_key, ULONG symmAlgId);
ULONG DEVAPI SKF_ImportRSAPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, RSA *rsa, ULONG symmAlgId);
ULONG DEVAPI SKF_ImportPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, EVP_PKEY *pkey, ULONG symmAlgId);
ULONG DEVAPI SKF_ExportECCPublicKey(HCONTAINER hContainer, BOOL bSign, EC_KEY **pp);
ULONG DEVAPI SKF_ExportRSAPublicKey(HCONTAINER hContainer, BOOL bSign, RSA **pp);
ULONG DEVAPI SKF_ExportEVPPublicKey(HCONTAINER hContainer, BOOL bSign, EVP_PKEY **pp);
ULONG DEVAPI SKF_ImportX509CertificateByKeyUsage(HCONTAINER hContainer, X509 *x509);
ULONG DEVAPI SKF_ImportX509Certificate(HCONTAINER hContainer, BOOL bSign, X509 *x509);
ULONG DEVAPI SKF_ExportX509Certificate(HCONTAINER hContainer, BOOL bSign, X509 **px509);
*/


#ifdef __cplusplus
}
#endif
#endif
