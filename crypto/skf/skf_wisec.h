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

#ifndef HEADER_SKF_WISEC_H
#define HEADER_SKF_WISEC_H

#include <openssl/err.h>
#include <openssl/gmskf.h>


#define WISEC_SM1		(SGD_SM1)
#define WISEC_SM1_ECB		(SGD_SM1_ECB)
#define WISEC_SM1_CBC		(SGD_SM1_CBC)
#define WISEC_SM1_CFB		(SGD_SM1_CFB)
#define WISEC_SM1_OFB		(SGD_SM1_OFB)
#define WISEC_SM1_MAC		(SGD_SM1_MAC)

#define WISEC_SSF33		(SGD_SSF33)
#define WISEC_SSF33_ECB		(SGD_SSF33_ECB)
#define WISEC_SSF33_CBC		(SGD_SSF33_CBC)
#define WISEC_SSF33_CFB		(SGD_SSF33_CFB)
#define WISEC_SSF33_OFB		(SGD_SSF33_OFB)
#define WISEC_SSF33_MAC		(SGD_SSF33_MAC)

#define WISEC_SM4		(SGD_SM4)
#define WISEC_SM4_ECB		(WISEC_SM4|SGD_ECB)
#define WISEC_SM4_CBC		(WISEC_SM4|SGD_CBC)
#define WISEC_SM4_CFB		(WISEC_SM4|SGD_CFB)
#define WISEC_SM4_OFB		(WISEC_SM4|SGD_OFB)
#define WISEC_SM4_MAC		(WISEC_SM4|SGD_MAC)

#define WISEC_AES		0x00000800
#define WISEC_128		0x00000000
#define WISEC_192		0x00000010
#define WISEC_256		0x00000020
#define WISEC_AES128		(WISEC_AES|WISEC_128)
#define WISEC_AES192		(WISEC_AES|WISEC_192)
#define WISEC_AES256		(WISEC_AES|WISEC_256)
#define WISEC_AES128_ECB	(WISEC_AES128|SGD_ECB)
#define WISEC_AES128_CBC	(WISEC_AES128|SGD_CBC)
#define WISEC_AES128_CFB	(WISEC_AES128|SGD_CFB)
#define WISEC_AES128_OFB	(WISEC_AES128|SGD_OFB)
#define WISEC_AES128_MAC	(WISEC_AES128|SGD_MAC)
#define WISEC_AES192_ECB	(WISEC_AES192|SGD_ECB)
#define WISEC_AES192_CBC	(WISEC_AES192|SGD_CBC)
#define WISEC_AES192_CFB	(WISEC_AES192|SGD_CFB)
#define WISEC_AES192_OFB	(WISEC_AES192|SGD_OFB)
#define WISEC_AES192_MAC	(WISEC_AES192|SGD_MAC)
#define WISEC_AES256_ECB	(WISEC_AES256|SGD_ECB)
#define WISEC_AES256_CBC	(WISEC_AES256|SGD_CBC)
#define WISEC_AES256_CFB	(WISEC_AES256|SGD_CFB)
#define WISEC_AES256_OFB	(WISEC_AES256|SGD_OFB)
#define WISEC_AES256_MAC	(WISEC_AES256|SGD_MAC)

#define WISEC_DES		0x00001000
#define WISEC_DES_ECB		(WISEC_DES|SGD_ECB)
#define WISEC_DES_CBC		(WISEC_DES|SGD_CBC)
#define WISEC_DES_CFB		(WISEC_DES|SGD_CFB)
#define WISEC_DES_OFB		(WISEC_DES|SGD_OFB)
#define WISEC_DES_MAC		(WISEC_DES|SGD_MAC)

#define WISEC_D3DES		0x00001010
#define WISEC_D3DES_ECB		(WISEC_D3DES|SGD_ECB)
#define WISEC_D3DES_CBC		(WISEC_D3DES|SGD_CBC)
#define WISEC_D3DES_CFB		(WISEC_D3DES|SGD_CFB)
#define WISEC_D3DES_OFB		(WISEC_D3DES|SGD_OFB)
#define WISEC_D3DES_MAC		(WISEC_D3DES|SGD_MAC)

#define WISEC_T3DES		0x00001020
#define WISEC_T3DES_ECB		(WISEC_T3DES|SGD_ECB)
#define WISEC_T3DES_CBC		(WISEC_T3DES|SGD_CBC)
#define WISEC_T3DES_CFB		(WISEC_T3DES|SGD_CFB)
#define WISEC_T3DES_OFB		(WISEC_T3DES|SGD_OFB)
#define WISEC_T3DES_MAC		(WISEC_T3DES|SGD_MAC)

#define WISEC_SM3		(SGD_SM3)
#define WISEC_SHA1		(SGD_SHA1)
#define WISEC_SHA256		(SGD_SHA256)

#define WISEC_RSA		(SGD_RSA)
#define WISEC_RSA_SIGN		(SGD_RSA_SIGN)
#define WISEC_RSA_ENC		(SGD_RSA_ENC)
#define WISEC_SM2		(SGD_SM2)
#define WISEC_SM2_1		(SGD_SM2_1)
#define WISEC_SM2_2		(SGD_SM2_2)
#define WISEC_SM2_3		(SGD_SM2_3)


#define WISEC_AUTH_BLOCKED		0x0A000033
#define WISEC_CERTNOUSAGEERR		0x0A000034
#define WISEC_INVALIDCONTAINERERR	0x0A000035
#define WISEC_CONTAINER_NOT_EXISTS	0x0A000036
#define WISEC_CONTAINER_EXISTS		0x0A000037
#define WISEC_CERTUSAGEERR		0x0A000038
#define WISEC_KEYNOUSAGEERR		0x0A000039
#define WISEC_FILEATTRIBUTEERR		0x0A00003A
#define WISEC_DEVNOAUTH			0x0A00003B

/*
ULONG DEVAPI SKFE_SetSN(DEVHANDLE hDev, CHAR *SN, UINT SNLen);
ULONG DEVAPI SKFE_GenExtECCKey(DEVHANDLE hDev, PECCPRIVATEKEYBLOB pPriBlob, PECCPUBLICKEYBLOB pPubBlob);
ULONG DEVAPI SKF_ECCDecrypt(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlainText,ULONG *pulPlainTextLen);
ULONG DEVAPI SKF_GenerateKey(HCONTAINER hContainer, ULONG ulAlgId, HANDLE *phSessionKey) ;
ULONG DEVAPI SKF_ECCExportSessionKeyByHandle(HANDLE phSessionKey, ECCPUBLICKEYBLOB *pPubKey,PECCCIPHERBLOB pData);
ULONG DEVAPI SKF_RSAExportSessionKeyByHandle(HANDLE phSessionKey, RSAPUBLICKEYBLOB*pPubKey,BYTE *pbData, ULONG *pulDataLen);
ULONG DEVAPI SKF_PrvKeyDecrypt(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbData, ULONG *pbDataLen);
ULONG DEVAPI SKF_PrvKeyDecrypt(HCONTAINER hContainer, ULONG ulType, PECCCIPHERBLOB pCipherText, BYTE *pbData, ULONG *pbDataLen);
ULONG DEVAPI SKF_RSAPrvKeyDecrypt(HCONTAINER hContainer, BYTE *pCipherData, ULONG pCipherDataLen, BYTE *pbData, ULONG *pbDataLen);
*/

#endif
