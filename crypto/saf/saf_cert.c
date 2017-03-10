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
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES
 * LOSS OF USE, DATA, OR PROFITS OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/gmsaf.h>
#include "saf_lcl.h"
#include "../../apps/apps.h"

int load_certs(const char *file, STACK_OF(X509) **certs, int format,
               const char *pass, const char *cert_descrip)
{
	return 0;
}

/* 7.2.2 */
int SAF_AddTrustedRootCaCertificate(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	X509 *x509 = NULL;
	BIO *bio = NULL;

	if (!hAppHandle || !pucCertificate) {
		SAFerr(SAF_F_SAF_ADDTRUSTEDROOTCACERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiCertificateLen <= 0 || uiCertificateLen > INT_MAX) {
		SAFerr(SAF_F_SAF_ADDTRUSTEDROOTCACERTIFICATE, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!(bio = BIO_new_file(app->rootcacerts, "a"))) {
		SAFerr(SAF_F_SAF_ADDTRUSTEDROOTCACERTIFICATE, ERR_R_BIO_LIB);
		goto end;
	}

	if (!(x509 = d2i_X509(NULL, (const unsigned char **)&pucCertificate, uiCertificateLen))) {
		SAFerr(SAF_F_SAF_ADDTRUSTEDROOTCACERTIFICATE, SAF_R_LOAD_CERTS_FAILURE);
		goto end;
	}

	if (!PEM_write_bio_X509(bio, x509)) {
		SAFerr(SAF_F_SAF_ADDTRUSTEDROOTCACERTIFICATE, ERR_R_PEM_LIB);
		goto end;
	}

	ret = SAR_Ok;

end:
	X509_free(x509);
	BIO_free(bio);
	return ret;
}

/* 7.2.3 */
int SAF_GetRootCaCertificateCount(
	void *hAppHandle,
	unsigned int *puiCount)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	STACK_OF(X509) *certs = NULL;

	if (!hAppHandle || !puiCount) {
		SAFerr(SAF_F_SAF_GETROOTCACERTIFICATECOUNT, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!load_certs(app->rootcacerts, &certs, FORMAT_PEM, NULL, "root ca certificates")) {
		SAFerr(SAF_F_SAF_GETROOTCACERTIFICATECOUNT, SAF_R_LOAD_CERTS_FAILURE);
		goto end;
	}

	*puiCount = sk_X509_num(certs);
	ret = SAR_Ok;

end:
	sk_X509_free(certs);
	return ret;
}

/* 7.2.4 */
int SAF_GetRootCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex,
	unsigned char *pucCertificate,
	unsigned int *puiCertificateLen)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	STACK_OF(X509) *certs = NULL;
	X509 *x509;
	int len;

	if (!hAppHandle || !pucCertificate || !puiCertificateLen) {
		SAFerr(SAF_F_SAF_GETROOTCACERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!load_certs(app->rootcacerts, &certs, FORMAT_PEM, NULL,
		"root ca certificates")) {
		SAFerr(SAF_F_SAF_GETROOTCACERTIFICATE, SAF_R_LOAD_CERTS_FAILURE);
		goto end;
	}

	if (!(x509 = sk_X509_value(certs, uiIndex))) {
		SAFerr(SAF_F_SAF_GETROOTCACERTIFICATE, SAF_R_INVALID_INDEX);
		goto end;
	}

	if (*puiCertificateLen < i2d_X509(x509, NULL)) {
		SAFerr(SAF_F_SAF_GETROOTCACERTIFICATE, SAF_R_BUFFER_TOO_SMALL);
		ret = SAR_IndataLenErr;
		goto end;
	}

	if ((len = i2d_X509(x509, &pucCertificate)) <= 0) {
		SAFerr(SAF_F_SAF_GETROOTCACERTIFICATE, ERR_R_X509_LIB);
		goto end;
	}

	*puiCertificateLen = len;
	ret = SAR_Ok;
end:
	sk_X509_free(certs);
	return ret;
}

/* 7.2.5 */
int SAF_RemoveRootCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	STACK_OF(X509) *certs = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	int i, err = 0;

	if (!hAppHandle) {
		SAFerr(SAF_F_SAF_REMOVEROOTCACERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!load_certs(app->rootcacerts, &certs, FORMAT_PEM, NULL, "root ca certificates")) {
		SAFerr(SAF_F_SAF_REMOVEROOTCACERTIFICATE, SAF_R_LOAD_CERTS_FAILURE);
		goto end;
	}

	if (!(bio = BIO_new_file(app->rootcacerts, "w"))) {
		SAFerr(SAF_F_SAF_REMOVEROOTCACERTIFICATE, ERR_R_BIO_LIB);
		goto end;
	}

	if (!(x509 = sk_X509_delete(certs, uiIndex))) {
		SAFerr(SAF_F_SAF_REMOVEROOTCACERTIFICATE, SAF_R_INVALID_INDEX);
		goto end;
	}

	for (i = 0; i < sk_X509_num(certs); i++) {
		if (!PEM_write_bio_X509(bio, sk_X509_value(certs, i))) {
			SAFerr(SAF_F_SAF_REMOVEROOTCACERTIFICATE, ERR_R_PEM_LIB);
			err++;
		}
	}

	ret = SAR_Ok;

end:
	X509_free(x509);
	sk_X509_free(certs);
	BIO_free(bio);
	return ret;
}

/* 7.2.6 */
int SAF_AddCaCertificate(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	X509 *x509 = NULL;
	BIO *bio = NULL;

	if (!hAppHandle || !pucCertificate) {
		SAFerr(SAF_F_SAF_ADDCACERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (uiCertificateLen <= 0 || uiCertificateLen > INT_MAX) {
		SAFerr(SAF_F_SAF_ADDCACERTIFICATE, SAF_R_INVALID_INPUT_LENGTH);
		return SAR_IndataLenErr;
	}

	if (!(bio = BIO_new_file(app->cacerts, "a"))) {
		SAFerr(SAF_F_SAF_ADDCACERTIFICATE, ERR_R_BIO_LIB);
		goto end;
	}

	if (!(x509 = d2i_X509(NULL, (const unsigned char **)&pucCertificate, uiCertificateLen))) {
		SAFerr(SAF_F_SAF_ADDCACERTIFICATE, SAF_R_LOAD_CERTS_FAILURE);
		goto end;
	}

	if (!PEM_write_bio_X509(bio, x509)) {
		SAFerr(SAF_F_SAF_ADDCACERTIFICATE, ERR_R_PEM_LIB);
		goto end;
	}

	ret = SAR_Ok;

end:
	X509_free(x509);
	BIO_free(bio);
	return ret;
}

/* 7.2.7 */
int SAF_GetCaCertificateCount(
	void *hAppHandle,
	unsigned int *puiCount)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	STACK_OF(X509) *certs = NULL;

	if (!hAppHandle || !puiCount) {
		SAFerr(SAF_F_SAF_GETCACERTIFICATECOUNT, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!load_certs(app->cacerts, &certs, FORMAT_PEM, NULL, "ca certificates")) {
		SAFerr(SAF_F_SAF_GETCACERTIFICATECOUNT, SAF_R_LOAD_CERTS_FAILURE);
		goto end;
	}

	*puiCount = sk_X509_num(certs);
	ret = SAR_Ok;

end:
	sk_X509_free(certs);
	return ret;
}

/* 7.2.8 */
int SAF_GetCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex,
	unsigned char *pucCertificate,
	unsigned int *puiCertificateLen)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	STACK_OF(X509) *certs = NULL;
	X509 *x509;
	int len;

	if (!hAppHandle || !pucCertificate || !puiCertificateLen) {
		SAFerr(SAF_F_SAF_GETCACERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!load_certs(app->cacerts, &certs, FORMAT_PEM, NULL, "ca certificates")) {
		SAFerr(SAF_F_SAF_GETCACERTIFICATE, SAF_R_LOAD_CERTS_FAILURE);
		goto end;
	}

	if (!(x509 = sk_X509_value(certs, uiIndex))) {
		SAFerr(SAF_F_SAF_GETCACERTIFICATE, SAF_R_INVALID_INDEX);
		goto end;
	}

	if (*puiCertificateLen < i2d_X509(x509, NULL)) {
		SAFerr(SAF_F_SAF_GETCACERTIFICATE, SAF_R_BUFFER_TOO_SMALL);
		ret = SAR_IndataLenErr;
		goto end;
	}

	if ((len = i2d_X509(x509, &pucCertificate)) <= 0) {
		SAFerr(SAF_F_SAF_GETCACERTIFICATE, ERR_R_X509_LIB);
		goto end;
	}

	*puiCertificateLen = len;
	ret = SAR_Ok;
end:
	sk_X509_free(certs);
	return ret;
}

/* 7.2.9 */
int SAF_RemoveCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex)
{
	int ret = SAR_UnknownErr;
	SAF_APP *app = (SAF_APP *)hAppHandle;
	STACK_OF(X509) *certs = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	int i, err = 0;

	if (!hAppHandle) {
		SAFerr(SAF_F_SAF_REMOVECACERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if (!load_certs(app->cacerts, &certs, FORMAT_PEM, NULL, "ca certificates")) {
		SAFerr(SAF_F_SAF_REMOVECACERTIFICATE, SAF_R_LOAD_CERTS_FAILURE);
		goto end;
	}

	if (!(bio = BIO_new_file(app->rootcacerts, "w"))) {
		SAFerr(SAF_F_SAF_REMOVECACERTIFICATE, ERR_R_BIO_LIB);
		goto end;
	}

	if (!(x509 = sk_X509_delete(certs, uiIndex))) {
		SAFerr(SAF_F_SAF_REMOVECACERTIFICATE, SAF_R_INVALID_INDEX);
		goto end;
	}

	for (i = 0; i < sk_X509_num(certs); i++) {
		if (!PEM_write_bio_X509(bio, sk_X509_value(certs, i))) {
			SAFerr(SAF_F_SAF_REMOVECACERTIFICATE, ERR_R_PEM_LIB);
			err++;
		}
	}

	ret = SAR_Ok;

end:
	X509_free(x509);
	sk_X509_free(certs);
	BIO_free(bio);
	return ret;
}

/* 7.2.10 */
int SAF_AddCrl(
	void *hAppHandle,
	unsigned char *pucDerCrl,
	unsigned int uiDerCrlLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.11 */
int SAF_VerifyCertificate(
	void *hAppHandle,
	unsigned char *pucUsrCertificate,
	unsigned int uiUsrCertificateLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.12 */
int SAF_VerifyCertificateByCrl(
	void *hAppHandle,
	unsigned char *pucUsrCertificate,
	unsigned int uiUsrCertificateLen,
	unsigned char *pucDerCrl,
	unsigned int uiDerCrlLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.13 */
int SAF_GetCertificateStateByOCSP(
	void *hAppHandle,
	unsigned char *pcOcspHostURL,
	unsigned int uiOcspHostURLLen,
	unsigned char *pucUsrCertificate,
	unsigned int uiUsrCertificateLen,
	unsigned char *pucCACertificate,
	unsigned int uiCACertficateLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.14 */
int SAF_GetCertFromLdap(
	void *hAppHandle,
	char *pcLdapHostURL,
	unsigned int uiLdapHostURLLen,
	unsigned char *pucQueryDN,
	unsigned int uiQueryDNLen,
	unsigned char *pucOutCert,
	unsigned int *puiOutCertLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.15 */
int SAF_GetCrlFromLdap(
	void *hAppHandle,
	char *pcLdapHostURL,
	unsigned int uiLdapHostURLLen,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned char *pucCrlData,
	unsigned int *puiCrlDataLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.16 */
int SAF_GetCertificateInfo(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned int uiInfoType,
	unsigned char *pucInfo,
	unsigned int *puiInfoLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.17 */
int SAF_GetExtTypeInfo(
	void *hAppHandle,
	unsigned char *pucDerCert,
	unsigned int uiDerCertLen,
	unsigned int uiInfoType,
	unsigned char *pucPriOid,
	unsigned int uiPriOidLen,
	unsigned char *pucInfo,
	unsigned int *puiInfoLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.18 */
int SAF_EnumCertificates(
	void *hAppHandle,
	SGD_USR_CERT_ENUMLIST *usrCerts)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.19 */
int SAF_EnumKeyContainerInfo(
	void *hAppHandle,
	SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.20 */
int SAF_EnumCertificatesFree(
	void *hAppHandle,
	SGD_USR_CERT_ENUMLIST *usrCerts)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.21 */
int SAF_EnumKeyContainerInfoFree(
	void *hAppHandle,
	SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo)
{
	return SAR_NotSupportYetErr;
}
