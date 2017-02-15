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
#incluce "saf_lcl.h"

/*

In GMAPI we will use private keys handled by ENGINE, the keys in ENGINE
is referenced by ENGINE and key label `key_id`
*/

EVP_PKEY *saf_load_private_key(	void *hAppHandle,
	unsigned char *containerName, unsigned int containerNameLen,
	unsigned int keyUsage)
{
	return NULL;
}

int GMAPI_CONTAINER_get_cert_and_key(GMAPI_CONTAINER *container,
	int key_usage, X509 **cert, EVP_PKEY **pkey)
{
	return 0;
}

/* 7.4.2 */
/* we need AppHandle before doing this
 * App + Container + KeyUsage => sign_key
 * the private key is referenced by a string label `key_id`
 */
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


/* 7.4.3 */
int SAF_Pkcs7_DecodeData(
	void *hAppHandle)
{
	return 0;
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

/* 7.4.5 */
/*
 * The content data in PKCS #7 SignedData format is optional, as the
 * `SAF_Pkcs7_DecodeSignedData` function has explicit content data input
 * with parameter `pucData`, the `SAF_Pkcs7_EncodeSignedData` will not carry
 * content data, with the `PKCS7_DETACHED` flag bit set.
 */
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

/* 7.4.7 */
/* key is referenced by App.Container.KeyUsage */
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
	PKCS7 *p7 = NULL;
	BIO *bio = NULL;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;

	// get cert and pkey from App.Container.KeyUsage

	PKCS7_decrypt(p7, pkey, cert, bio, flags);

	return 0;
}

/* 7.4.8 */
/* the `hAppHandle` and key is not required in digest */
int SAF_Pkcs7_EncodeDigestedData(
	void *hAppHandle,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerP7DigestedData,
	unsigned int *puiDerP7DigestedDataLen)
{
	int ret = SAR_UnknownErr;
	PKCS7 *p7 = NULL;
	BIO *bio = NULL;
	const EVP_MD *md;
	unsigned char *p;
	int len;

	if (!hAppHandle || !pucData || !pucDerP7DigestedData || !puiDerP7DigestedDataLen) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (!(md = EVP_get_digestbysgd(uiDigestAlgorithm))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, SAF_R_INVALID_DIGEST_ALGOR);
		return SAR_AlgoTypeErr;
	}
	if (uiDataLen > INT_MAX) {
		return SAR_IndataLenErr;
	}
	len = (int)uiDataLen;

	if (!(p7 = PKCS7_new())) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!PKCS7_set_type(p7, NID_pkcs7_digest)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	/* set digest */
	if (!PKCS7_set_digest(p7, md)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	/* set content */
	if (!PKCS7_content_new(p7, NID_pkcs7_data)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}
	if (!(bio = PKCS7_dataInit(p7, NULL))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}
	if (!BIO_write(bio, pucData, len)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_GMAPI_LIB);
		goto end;
	}
	if (!BIO_flush(bio)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_GMAPI_LIB);
		goto end;
	}
	if (!PKCS7_dataFinal(p7, bio)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	/* check output buffer length */
	if ((len = i2d_PKCS7(p7, NULL)) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}
	if (*puiDerP7DigestedDataLen < len) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, SAF_R_BUFFER_TOO_SMALL);
		goto end;
	}

	/* der encoding */
	p = pucDerP7DigestedData;
	if ((len = i2d_PKCS7(p7, &p)) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	*puiDerP7DigestedDataLen = (unsigned int)len;
	ret = SAR_OK;

end:
	PKCS7_free(p7);
	return ret;
}

/* 7.4.9 */
/* parse pkcs7 and get data and digest */
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
	PKCS7 *p7 = NULL;
	unsigned char *p;
	long len;

	if (!(md = EVP_get_digestbysgd(uiDigestAlgorithm))) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_INVALID_DIGEST_ALGOR);
		return SAR_AlgoTypeErr;
	}

	p = pucDerP7DigestedData;
	len = uiDerP7DigestedDataLen;
	if (!(p7 = d2i_PKCS7(NULL, &p, len))) {
		goto end;
	}


	return ret;
}

