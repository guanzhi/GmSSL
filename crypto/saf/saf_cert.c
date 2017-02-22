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
#include <openssl/conf.h>
#include <openssl/gmsaf.h>
#include "saf_lcl.h"


/* 7.2.2 */
int SAF_AddTrustedRootCaCertificate(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.3 */
int SAF_GetRootCaCertificateCount(
	void *hAppHandle,
	unsigned int *puiCount)
{
	*puiCount = 0;
	return SAR_Ok;
}

/* 7.2.4 */
int SAF_GetRootCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex,
	unsigned char *pucCertificate,
	unsigned int *puiCertificateLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.5 */
int SAF_RemoveRootCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.6 */
int SAF_AddCaCertificate(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int *puiCertificateLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.7 */
int SAF_GetCaCertificateCount(
	void *hAppHandle,
	unsigned int *puiCount)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.8 */
int SAF_GetCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex,
	unsigned char *pucCertificate,
	unsigned int *puiCertificateLen)
{
	return SAR_NotSupportYetErr;
}

/* 7.2.9 */
int SAF_RemoveCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex)
{
	return SAR_NotSupportYetErr;
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

