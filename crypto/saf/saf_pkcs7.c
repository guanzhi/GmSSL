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
#include <openssl/pkcs7.h>
#include <openssl/gmapi.h>
#include <openssl/gmsaf.h>
#include "saf_lcl.h"

/* 7.4.2 */
int SAF_Pkcs7_EncodeData(
	void *hAppHandle,
	unsigned char *pucSignContainerName,
	unsigned int uiSignContainerNameLen,
	unsigned int uiSignKeyUsage,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucEncCertificate,
	unsigned int uiEncCertificateLen,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerP7Data,
	unsigned int *puiDerP7DataLen)
{
	int ret = SAR_UnknownErr;
	return ret;
}


/* 7.4.3 */
int SAF_Pkcs7_DecodeData(
	void *hAppHandle)
{
	int ret = SAR_UnknownErr;
	return ret;
}

/* 7.4.4 */
int SAF_Pkcs7_EncodeSignedData(
	void *hAppHandle,
	unsigned char *pucSignContainerName,
	unsigned int uiSignContainerNameLen,
	unsigned int uiSignKeyUsage,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerP7Data,
	unsigned int *puiDerP7DataLen)
{
	int ret = SAR_UnknownErr;
	return ret;
}

/* 7.4.5 */
int SAF_Pkcs7_DecodeSignedData(
	void *hAppHandle,
	unsigned char *pucDerP7SignedData,
	unsigned int uiDerP7SignedDataLen,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucSign,
	unsigned int *puiSignLen)
{
	int ret = SAR_UnknownErr;
	return ret;
}

/* 7.4.6 */
int SAF_Pkcs7_EncodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucEncCertificate,
	unsigned int uiEncCertificateLen,
	unsigned int uiSymmAlgorithm,
	unsigned char *pucDerP7EnvelopedData,
	unsigned int *puiDerP7EnvelopedDataLen)
{
	int ret = SAR_UnknownErr;
	PKCS7 *p7 = NULL;
	X509 *x509 = NULL;
	STACK_OF(X509) *certs = NULL;
	BIO *bio = NULL;
	const EVP_CIPHER *cipher;
	int len;

	/* check arguments */
	if (!hAppHandle || !pucData || !pucEncCertificate || !puiDerP7EnvelopedDataLen) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEENVELOPEDDATA, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiDataLen <= 0 || uiDataLen > INT_MAX
		|| uiEncCertificateLen <= 0 || uiEncCertificateLen > INT_MAX) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEENVELOPEDDATA, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!(cipher = EVP_get_cipherbysgd(uiSymmAlgorithm))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEENVELOPEDDATA, SAF_R_UNSUPPORTED_ALGOR);
		return SAR_AlgoTypeErr;
	}

	/* process */
	if (!(bio = BIO_new_mem_buf(pucData, (int)uiDataLen))
		|| !(certs = sk_X509_new_null())
		|| !(x509 = X509_new())) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEENVELOPEDDATA, ERR_R_MALLOC_FAILURE);
		ret = SAR_MemoryErr;
		goto end;
	}

	if (!d2i_X509(&x509, &pucEncCertificate, (long)uiEncCertificateLen)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEENVELOPEDDATA, SAF_R_INVALID_CERTIFICATE);
		ret = SAR_CertEncodeErr;
		goto end;
	}
	// FIXME: check usage, valid time of x509

	sk_X509_push(certs, x509);
	x509 = NULL;

	if (!(p7 = PKCS7_encrypt(certs, bio, cipher, PKCS7_BINARY))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEENVELOPEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	if ((len = i2d_PKCS7(p7, NULL)) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEENVELOPEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	if (!pucDerP7EnvelopedData) {
		*puiDerP7EnvelopedDataLen = (unsigned int)len;
		ret = SAR_Ok;
		goto end;
	}

	if (*puiDerP7EnvelopedDataLen < (unsigned int)len) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEENVELOPEDDATA, SAF_R_BUFFER_TOO_SMALL);
		ret = SAR_IndataLenErr;
		goto end;
	}

	len = i2d_PKCS7(p7, pucDerP7EnvelopedData);
	*puiDerP7EnvelopedDataLen = (unsigned int)len;

	ret = SAR_OK;

end:
	PKCS7_free(p7);
	X509_free(x509);
	sk_X509_free(certs);
	BIO_free(bio);
	return ret;
}

/* 7.4.7 */
int SAF_Pkcs7_DecodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDecContainerName,
	unsigned int uiDecContainerNameLen,
	unsigned int uiDecKeyUsage,
	unsigned char *pucDerP7EnvelopedData,
	unsigned int uiDerP7EnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen)
{
	int ret = SAR_UnknownErr;
	return ret;
}

/* 7.4.8 */
int SAF_Pkcs7_EncodeDigestedData(
	void *hAppHandle,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerP7DigestedData,
	unsigned int *puiDerP7DigestedDataLen)
{
	int ret = SAR_UnknownErr;
	return ret;
}

/* 7.4.9 */
int SAF_Pkcs7_DecodeDigestedData(
	void *hAppHandle,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucDerP7DigestedData,
	unsigned int uiDerP7DigestedDataLen,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDigest,
	unsigned int *puiDigestLen)
{
	int ret = SAR_UnknownErr;
	return ret;
}
