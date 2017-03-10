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

#include <openssl/evp.h>
#include <openssl/gmapi.h>
#include <openssl/gmsaf.h>
#include "saf_lcl.h"

/* 7.4.10 */
int SAF_SM2_EncodeSignedAndEnvelopedData(
	void *hAppHandle,
	unsigned char *pucSignContainerName,
	unsigned int uiSignContainerNameLen,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucEncCertificate,
	unsigned int uiEncCertificateLen,
	unsigned int uiSymmAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerSignedAndEnvelopedData,
	unsigned int *puiDerSignedAndEnvelopedDataLen)
{
	return SAF_Pkcs7_EncodeData(
		hAppHandle,
		pucSignContainerName,
		uiSignContainerNameLen,
		pucSignerCertificate,
		uiSignerCertificateLen,
		uiDigestAlgorithm,
		pucEncCertificate,
		uiEncCertificateLen,
		uiSymmAlgorithm,
		pucData,
		uiDataLen,
		pucDerSignedAndEnvelopedData,
		puiDerSignedAndEnvelopedDataLen);
}

/* 7.4.11 */
int SAF_SM2_DecodeSignedAndEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDerContainerName,
	unsigned int uiDerContainerNameLen,
	unsigned char *pucDerSignedAndEnvelopedData,
	unsigned int uiDerSignedAndEnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned int *puiDigestAlgorithm)
{
	return SAF_Pkcs7_DecodeData(
		hAppHandle,
		pucDerContainerName,
		uiDerContainerNameLen,
		pucDerSignedAndEnvelopedData,
		uiDerSignedAndEnvelopedDataLen,
		pucData,
		puiDataLen,
		pucSignerCertificate,
		puiSignerCertificateLen,
		puiDigestAlgorithm);
}

/* 7.4.12 */
int SAF_SM2_EncodeSignedData(
	void *hAppHandle,
	unsigned char *pucSignContainerName,
	unsigned int uiSignContainerNameLen,
	unsigned int uiSignKeyUsage,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerSignedData,
	unsigned int *puiDerSignedDataLen)
{
	return SAF_Pkcs7_EncodeSignedData(
		hAppHandle,
		pucSignContainerName,
		uiSignContainerNameLen,
		uiSignKeyUsage,
		pucSignerCertificate,
		uiSignerCertificateLen,
		uiDigestAlgorithm,
		pucData,
		uiDataLen,
		pucDerSignedData,
		puiDerSignedDataLen);
}

/* 7.4.13 */
int SAF_SM2_DecodeSignedData(
	void *hAppHandle,
	unsigned char *pucDerSignedData,
	unsigned int uiDerSignedDataLen,
	unsigned int *puiDigestAlgorithm,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSign,
	unsigned int *puiSignLen)
{
	return SAF_Pkcs7_DecodeSignedData(
		hAppHandle,
		pucDerSignedData,
		uiDerSignedDataLen,
		puiDigestAlgorithm,
		pucSignerCertificate,
		puiSignerCertificateLen,
		pucData,
		puiDataLen,
		pucSign,
		puiSignLen);
}

/* 7.4.14 */
int SAF_SM2_EncodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucEncCertificate,
	unsigned int uiEncCertificateLen,
	unsigned int uiSymmAlgorithm,
	unsigned char *pucDerEnvelopedData,
	unsigned int *puiDerEnvelopedDataLen)
{
	return SAF_Pkcs7_EncodeEnvelopedData(
		hAppHandle,
		pucData,
		uiDataLen,
		pucEncCertificate,
		uiEncCertificateLen,
		uiSymmAlgorithm,
		pucDerEnvelopedData,
		puiDerEnvelopedDataLen);
}

/* 7.4.15 */
int SAF_SM2_DecodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDecContainerName,
	unsigned int uiDecContainerNameLen,
	unsigned char *pucDerEnvelopedData,
	unsigned int uiDerEnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen)
{
	return SAF_Pkcs7_DecodeEnvelopedData(
		hAppHandle,
		pucDecContainerName,
		uiDecContainerNameLen,
		pucDerEnvelopedData,
		uiDerEnvelopedDataLen,
		pucData,
		puiDataLen);
}
