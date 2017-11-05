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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/gmapi.h>
#include <openssl/gmsaf.h>
#include "saf_lcl.h"

/* 7.4.2 */
int SAF_Pkcs7_EncodeData(
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
	unsigned char *pucDerP7Data,
	unsigned int *puiDerP7DataLen)
{
	int ret = SAR_UnknownErr;
	return ret;
}

/* 7.4.3 */
int SAF_Pkcs7_DecodeData(
	void *hAppHandle,
	unsigned char *pucDecContainerName,
	unsigned int uiDecContainerNameLen,
	unsigned char *pucDerP7Data,
	unsigned int uiDerP7DataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned int *puiDigestAlgorithm)
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
	SAF_APP *app = (SAF_APP *)hAppHandle;
	PKCS7 *p7 = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	BIO *data = NULL;
	int len;

	if (!hAppHandle || !pucSignContainerName || !pucSignerCertificate
		|| !pucData || !pucDerP7Data || !puiDerP7DataLen) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODESIGNEDDATA, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiSignContainerNameLen <= 0 || uiSignContainerNameLen > INT_MAX
		|| strlen((char *)pucSignContainerName) != uiSignContainerNameLen
		|| uiSignerCertificateLen <= 0 || uiSignerCertificateLen > INT_MAX
		|| uiDataLen <= 0 || uiDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODESIGNEDDATA, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!(pkey = SAF_load_private_key(app, (char *)pucSignContainerName,
		EVP_PK_EC|EVP_PKT_SIGN))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODESIGNEDDATA, SAF_R_LOAD_KEY_FAILURE);
		goto end;
	}

	if (!(x509 = d2i_X509(NULL, (const unsigned char **)&pucSignerCertificate,
		uiSignerCertificateLen))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODESIGNEDDATA, ERR_R_X509_LIB);
		goto end;
	}

	if (!(data = BIO_new_mem_buf(pucData, uiDataLen))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODESIGNEDDATA, ERR_R_BIO_LIB);
		goto end;
	}

	if (!(p7 = PKCS7_sign(x509, pkey, NULL, data, PKCS7_BINARY))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODESIGNEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	if (*puiDerP7DataLen < i2d_PKCS7(p7, NULL)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODESIGNEDDATA, SAF_R_BUFFER_TOO_SMALL);
		ret = SAR_IndataLenErr;
		goto end;
	}

	if ((len = i2d_PKCS7(p7, &pucDerP7Data)) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODESIGNEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	*puiDerP7DataLen = len;
	ret = SAR_Ok;

end:
	PKCS7_free(p7);
	X509_free(x509);
	BIO_free(data);
	return ret;
}

/* 7.4.5 */
int SAF_Pkcs7_DecodeSignedData(
	void *hAppHandle,
	unsigned char *pucDerP7SignedData,
	unsigned int uiDerP7SignedDataLen,
	unsigned int *puiDigestAlgorithm,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSig,
	unsigned int *puiSigLen)
{
	int ret = SAR_UnknownErr;
#if 0
	PKCS7 *p7 = NULL;
	PKCS7_SIGNED *p7signed;
	X509 *x509 = NULL;
	PKCS7_SIGNER_INFO *signer_info;
	X509_ALGOR *algor;
	BIO *bio = NULL;

	if (!hAppHandle || !pucDerP7SignedData || !puiDigestAlgorithm
		|| !puiSignerCertificateLen || !puiDataLen || !puiSigLen) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiDerP7SignedDataLen <= 0 || uiDerP7SignedDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	/* process */
	if (!(p7 = d2i_PKCS7(NULL, (const unsigned char **)&pucDerP7SignedData,
		uiDerP7SignedDataLen))) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_INVALID_PKCS7_DATA);
		goto end;
	}

	if (!(bio = BIO_new(BIO_s_mem()))) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!PKCS7_type_is_signed(p7)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_INVALID_PKCS7_TYPE);
		goto end;
	}

	if (!PKCS7_verify(p7, NULL, NULL, NULL, bio, 0)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_PKCS7_VERIFY_FAILURE);
		goto end;
	}

	if (!(p7signed = p7->d.sign)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_INVALID_PKCS7_DATA);
		goto end;
	}

	/* get digest algor */
	if (sk_X509_ALGOR_num(p7signed->md_algs) != 1
		|| !(algor = sk_X509_ALGOR_value(p7signed->md_algs, 0))
		|| (*puiDigestAlgorithm = EVP_MD_sgd(EVP_get_digestbyobj(algor->algorithm))) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_INVALID_PKCS7_DATA);
		goto end;
	}

	/* get signer's certificate */
	if (sk_X509_ALGOR_num(p7signed->cert) != 1
		|| !(x509 = sk_X509_ALGOR_value(p7signed->cert, 0))) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_INVALID_PKCS7_DATA);
		goto end;
	}
	if ((len = i2d_X509(x509, NULL)) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, ERR_R_X509_LIB);
		goto end;
	}
	if (*puiSignerCertificateLen < len) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_BUFFER_TOO_SMALL);
		goto end;
	}
	if ((len = i2d_X509(x509, &pucSignerCertficate)) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, ERR_R_X509_LIB);
		goto end;
	}
	*puiSignerCertificateLen = len;

	/* get data */
	if (!(p7signed->contents)
		|| !PKCS7_type_is_data(p7signed->contents)
		|| !(data = p7signed->contents->d.data)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_INVALID_PKCS7_DATA);
		goto end;
	}

	if (*puiDataLen < ASN1_STRING_length(data)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_BUFFER_TOO_SMALL);
		goto end;
	}

	memcpy(pucData, ASN1_STRING_get0_data(data), ASN1_STRING_length(data));
	*puiDataLen = ASN1_STRING_length(data);

	/* get signature */
	if (sk_SIGNER_INFO_num(p7signed->signer_info) <= 0
		|| !(signer_info = sk_SIGNER_INFO_value(p7signed->signer_info, 0))) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_INVALID_PKCS7_DATA);
		goto end;
	}

	if (*puiSigLen < ASN1_STRING_length(signer_info->enc_digest)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODESIGNEDDATA, SAF_R_BUFFER_TOO_SMALL);
		goto end;
	}
	memcpy(pucSig, ASN1_STRING_get0_data(signer_info->enc_digest),
		ASN1_STRING_length(signer_info->enc_digest));
	*puiSigLen = ASN1_STRING_length(signer_info->enc_digest);

	ret = SAR_Ok;
end:
	PKCS7_free(p7);
	X509_free(x509);
	BIO_free(bio);
#endif
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
#if 0
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
#endif
	return ret;
}

/* 7.4.7 */
int SAF_Pkcs7_DecodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDecContainerName,
	unsigned int uiDecContainerNameLen,
	unsigned char *pucDerP7EnvelopedData,
	unsigned int uiDerP7EnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen)
{
	int ret = SAR_UnknownErr;
#if 0
	SAF_APP *app = (SAF_APP *)hAppHandle;
	PKCS7 *p7 = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	BUF_MEM *buf = NULL;

	if (!hAppHandle || !pucDecContainerName || !pucDerP7EnvelopedData || !pucData)
		SAFerr(SAF_F_SAF_PKCS7_DECODEENVELOPEDDATA, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiDecContainerNameLen <= 0 || uiDecContainerNameLen > INT_MAX
		|| uiDerP7EnvelopedDataLen <= 0 || uiDerP7EnvelopedDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEENVELOPEDDATA, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!pucData) {
		*puiDataLen = uiDerP7EnvelopedDataLen;
		return SAR_Ok;
	} else if (*puiDataLen <= 0 || *puiDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEENVELOPEDDATA, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!(pkey = SAF_load_private_key(app, (char *)pucDecContainerName,
		EVP_PK_EC|EVP_PKT_ENC))) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEENVELOPEDDATA, SAF_R_LOAd_PUBLIC_KEY_FAILURE);
		goto end;
	}

	if (!(x509 = SAF_LoadCertificate(app, pucDecContainerName,
		uiDecContainerNameLen, SGD_PK_ENC))) {
		goto end;
	}

	if (!(bio = BIO_new(BIO_s_membuf()))) {
		goto end;
	}

	if (!PKCS7_decrypt(p7, pkey, x509, bio, 0)) {
		goto end;
	}

	if (!BIO_get_mem_buf(bio, &buf)) {
		goto end;
	}

	memcpy(pucData, buf->data, buf->length);
	*puiDataLen = buf->length;

	ret = SAR_Ok;
end:
	PKCS7_free(p7);
	EVP_PKEY_free(pkey);
	X509_free(x509);
	BIO_free(bio);
#endif
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
	const EVP_MD *md;
	PKCS7 *p7 = NULL;
	BIO *p7bio = NULL;
	int len;

	if (!hAppHandle || !pucData || !pucDerP7DigestedData
		|| !puiDerP7DigestedDataLen) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (uiDataLen <= 0 || uiDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!(md = EVP_get_digestbysgd(uiDigestAlgorithm))) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, SAF_R_INVALID_DIGEST_ALGOR);
		return SAR_AlgoTypeErr;
	}

	if (!(p7 = PKCS7_new())
		|| !PKCS7_set_type(p7, NID_pkcs7_digest)
		|| !PKCS7_set_digest(p7, md)
		|| !PKCS7_content_new(p7, NID_pkcs7_data)
		|| !(p7bio = PKCS7_dataInit(p7, NULL))
		|| BIO_write(p7bio, pucData, (int)uiDataLen) != uiDataLen
		|| !PKCS7_dataFinal(p7, p7bio)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	if (*puiDerP7DigestedDataLen < i2d_PKCS7(p7, NULL)) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, SAF_R_BUFFER_TOO_SMALL);
		ret = SAR_IndataLenErr;
		goto end;
	}

	if ((len = i2d_PKCS7(p7, &pucDerP7DigestedData)) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_ENCODEDIGESTEDDATA, ERR_R_PKCS7_LIB);
		goto end;
	}

	ret = SAR_Ok;

end:
	PKCS7_free(p7);
	BIO_free(p7bio);
	return ret;
}

/* 7.4.9 */
int SAF_Pkcs7_DecodeDigestedData(
	void *hAppHandle,
	unsigned char *pucDerP7DigestedData,
	unsigned int uiDerP7DigestedDataLen,
	unsigned int *puiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucDigest,
	unsigned int *puiDigestLen)
{
	int ret = SAR_UnknownErr;
	PKCS7 *p7 = NULL;
	PKCS7_DIGEST *p7dgst;
	ASN1_OCTET_STRING *data;

	if (!hAppHandle || !puiDigestAlgorithm || !puiDataLen || !puiDigestLen) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!pucData) {
		*puiDataLen = uiDerP7DigestedDataLen;
		return SAR_Ok;
	}

	if (!pucDigest) {
		*puiDigestLen = EVP_MAX_MD_SIZE;
		return SAR_Ok;
	}

	if (uiDerP7DigestedDataLen <= 0 || uiDerP7DigestedDataLen > INT_MAX
		|| *puiDataLen <= 0 || *puiDataLen > INT_MAX
		|| *puiDigestLen <= 0 || *puiDigestLen > INT_MAX) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	/* process */
	if (!(p7 = d2i_PKCS7(NULL, (const unsigned char **)&pucDerP7DigestedData,
		uiDerP7DigestedDataLen))) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_INVALID_PKCS7);
		ret = SAR_IndataErr;
		goto end;
	}

	if (!PKCS7_type_is_digest(p7)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_INVALID_PKCS7_TYPE);
		ret = SAR_IndataErr;
		goto end;
	}
	p7dgst = p7->d.digest;

	/* output digset algor */
	//EVP_MD_sgd			
#if 0
	if ((*puiDigestAlgorithm = EVP_MD_sgd(
		EVP_get_digestbyobj(p7dgst->md->algorithm))) <= 0) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_UNSUPPORTED_DIGEST_ALGOR);
		ret = SAR_IndataErr;
		goto end;
	}
#endif

	/* output digested data */
	if (!PKCS7_type_is_data(p7dgst->contents)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_INVALID_PKCS7_DATA);
		ret = SAR_IndataErr;
		goto end;
	}

	if (!(data = p7dgst->contents->d.data)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_INVALID_PKCS7_DATA);
		ret = SAR_IndataErr;
		goto end;
	}

	if (*puiDataLen < ASN1_STRING_length(data)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_BUFFER_TOO_SMALL);
		ret = SAR_IndataLenErr;
		goto end;
	}
	memcpy(pucData, ASN1_STRING_get0_data(data), ASN1_STRING_length(data));
	*puiDataLen = ASN1_STRING_length(data);

	/* output digest */
	if (!p7dgst->digest) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_INVALID_PKCS7_DATA);
		ret = SAR_IndataErr;
		goto end;
	}

	if (*puiDigestLen < ASN1_STRING_length(p7dgst->digest)) {
		SAFerr(SAF_F_SAF_PKCS7_DECODEDIGESTEDDATA, SAF_R_BUFFER_TOO_SMALL);
		ret = SAR_IndataLenErr;
		goto end;
	}
	memcpy(pucDigest, ASN1_STRING_get0_data(p7dgst->digest), ASN1_STRING_length(p7dgst->digest));
	*puiDigestLen = ASN1_STRING_length(p7dgst->digest);

	ret = SAR_Ok;
end:
	PKCS7_free(p7);
	return ret;
}
