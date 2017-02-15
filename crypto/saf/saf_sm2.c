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
	unsigned int uiSignKeyUsage,
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
	int ret = SAR_UnknownErr;
	PKCS7 *p7 = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md;

	p7 = PKCS7_new();

	pkey = saf_load_private_key(hAppHandle,
		pucSignContainerName, uiSignContainerNameLen
		uiSignKeyUsage);

	PKCS7_set_type(p7, 0);
	return 0;
}

/* 7.4.11 */
int SAF_SM2_DecodeSignedAndEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDerContainerName,
	unsigned int uiDerContainerNameLen,
	unsigned int uiDecKeyUsage,
	unsigned char *pucDerSignedAndEnvelopedData,
	unsigned int uiDerSignedAndEnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned int *puiDigestAlgorithms)
{
	return 0;
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

	int flags;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	unsigned char *p;

	if (!(pkey = saf_load_private_key(hAppHandle, pucSignContainerName,
		uiSignContainerNameLen, uiSignKeyUsage))) {
	}

	/* decode certificate, check no extra input */
	p = pucSignerCertificate;
	if (!(cert = d2i_X509(NULL, &p, (long)uiSignerCertificateLen))) {
	}
	if (p - pucSignerCertificate != uiSignerCertificateLen) {
	}

	/* data bio */
	if (!(bio = BIO_new_mem_buf(pucData, (int)uiDataLen))) {
	}

	/* set digest */
	if (!(md = EVP_get_digestbysgd(uiDigestAlgorithm))) {
	}

	flags = PKCS7_BINARY;
	p7 = PKCS7_sign(cert, pkey, NULL, bio, flags);


	p = pucDerP7Data;
	if (i2d_PKCS7(p7, &p) < 0) {
	}

	*puiDerP7DataLen = p - pucDerP7Data;

	return 0;
}

/* 7.4.13 */
int SAF_SM2_DecodeSignedData(
	void *hAppHandle,
	unsigned char *pucDerSignedData,
	unsigned int uiDerSignedDataLen,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucSign,
	unsigned int *puiSignLen)
{
	int ret;
	PKCS7 *p7 = NULL;
	X509 *cert = NULL;
	const EVP_MD *md;
	BIO *bio = NULL;
	STACK_OF(X509) *certs = NULL;
	X509_STORE *store = NULL;
	int flags = 0;

	p = pucDerP7SignedData;
	if (!(p7 = d2i_PKCS7(NULL, &p, (long)uiDerP7SignedDataLen))) {
	}
	if (p - pucDerP7SignedData != uiDerP7SignedDataLen) {
	}

	p = pucSignerCertificate;
	if (!(cert = d2i_X509(NULL, &p, (long)uiSignerCertificateLen))) {
	}
	if (p - pucSignerCertificate != uiSignerCertificateLen) {
	}

	if (!(md = EVP_get_digestbysgd(uiDigestAlgorithm))) {
	}
	if (!PKCS7_set_digest(p7, md)) {
	}

	if (!PKCS7_verify(p7, cert, store, bio, NULL, flags)) {
	}


	return 0;
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
	int ret = SAR_UnknownErr;
	PKCS7 *p7 = NULL;
	X509 *cert = NULL;
	BIO *bio = NULL;
	const EVP_CIPHER *cipher;
	int flags;

	cipher = EVP_get_cipherbysgd(uiSymmAlgorithm);
	bio = BIO_new(BIO_s_mem());
	// set data to bio

	p = pucEncCertificate;
	cert = d2i_X509(NULL, &p, uiEncCertificateLen);

	p7 = PKCS7_encrypt(cert, bio, cipher, flags);
end:
	PKCS7_free(p7);
	return ret;
}

/* 7.4.15 */
int SAF_SM2_DecodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDecContainerName,
	unsigned int uiDecContainerNameLen,
	unsigned int uiDecKeyUsage,
	unsigned char *pucDerEnvelopedData,
	unsigned int uiDerEnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen)
{
	PKCS7 *p7 = NULL;
	BIO *bio = NULL;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;

	// get cert and pkey from App.Container.KeyUsage

	PKCS7_decrypt(p7, pkey, cert, bio, flags);

	return 0;
}
