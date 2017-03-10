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


#include <openssl/gmsaf.h>
#include <openssl/gmapi.h>
#include "saf_lcl.h"


/* 7.3.16 */
int SAF_GenRsaKeyPair(void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned int uiKeyUsage,
	unsigned int uiExportFlag)
{
	int ret = SAR_UnknownErr;
#if 0
	SAF_APP *app = (SAF_APP *)hAppHandle;

	/* process */
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *pkey = NULL;

	if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, app->engine))
		|| EVP_PKEY_keygen_init(pctx) <= 0
		|| EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, uiKeyBits) <= 0
		|| EVP_PKEY_keygen(pctx, &pkey) <= 0) {
		SAFerr(SAF_F_SAF_GENRSAKEYPAIR, ERR_R_EVP_LIB);
		goto end;
	}

	ret = SAR_Ok;
end:
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pkey);
#endif
	return ret;
}

/* 7.3.17 */
int SAF_GetRsaPublicKey(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyUsage,
	unsigned char *pucPublicKey,
	unsigned int *puiPublicKeyLen)
{
	int ret = SAR_UnknownErr;
#if 0
	SAF_APP *app = (SAF_APP *)hAppHandle;

	/* process */
	EVP_PKEY *pkey = NULL;
	char key_id[1024];
	int len;

	snprintf(key_id, sizeof(key_id), "%s.%s", (char *)pucContainerName,
		SGD_GetKeyUsageName(uiKeyUsage));

	if (!(pkey = ENGINE_load_public_key(app->engine, key_id, NULL, NULL))) {
		SAFerr(SAF_F_SAF_GETRSAPUBLICKEY, ERR_R_ENGINE_LIB);
		goto end;
	}
	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
		SAFerr(SAF_F_SAF_GETRSAPUBLICKEY, ERR_R_ENGINE_LIB);
		goto end;
	}
	if ((len = i2d_PUBKEY(pkey, &pucPublicKey)) <= 0) {
		SAFerr(SAF_F_SAF_GETRSAPUBLICKEY, ERR_R_X509_LIB);
		goto end;
	}

	*puiPublicKeyLen = (unsigned int)len;

	/* set return value */
	ret = SAR_Ok;

end:
	EVP_PKEY_free(pkey);
#endif
	return ret;
}

/* 7.3.18 */
int SAF_RsaSign(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiHashAlgoType,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignature,
	unsigned int *puiSignatureLen)
{
	int ret = SAR_UnknownErr;

#if 0
	SAF_APP *app = (SAF_APP *)hAppHandle;

	/* process */
	char key_id[1024];
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t siglen;

	snprintf(key_id, sizeof(key_id), "%s.sign", (char *)pucContainerName);

	if (!(pkey = ENGINE_load_private_key(app->engine, key_id, NULL, NULL))
		|| !(pctx = EVP_PKEY_CTX_new(pkey, app->engine))
		|| EVP_PKEY_sign_init(pctx) <= 0
		|| EVP_PKEY_sign(pctx, pucSignData, &siglen, pucInData, (size_t)uiInDataLen) <= 0) {
		SAFerr(SAF_F_SAF_RSASIGN, ERR_R_EVP_LIB);
		goto end;
	}

	*puiSignDataLen = (unsigned int)siglen;

	ret = SAR_Ok;
end:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
#endif
	return ret;
}

/* 7.3.19 */
int SAF_RsaSignFile(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiHashAlgoType,
	unsigned char *pucFileName,
	unsigned char *pucSignature,
	unsigned int *puiSignatureLen)
{
	return SAR_OK;
}

/* 7.3.20 */
int SAF_RsaVerifySign(
	unsigned int uiHashAlgoType,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignature,
	unsigned int uiSignatureLen)
{
	int ret = SAR_UnknownErr;
#if 0
	/* process */
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;

	if (!(pkey = d2i_PUBKEY(NULL, (const unsigned char **)&pucPublicKey, (long)uiPublicKeyLen))
		|| !(pctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| EVP_PKEY_verify_init(pctx) <= 0
		|| EVP_PKEY_verify(pctx, pucSignData, uiSignDataLen, pucInData, uiInDataLen) <= 0) {
		SAFerr(SAF_F_SAF_RSAVERIFYSIGN, ERR_R_EVP_LIB);
		goto end;
	}

	ret = SAR_Ok;
end:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
#endif
	return ret;
}

/* 7.3.21 */
int SAF_RsaVerifySignFile(
	unsigned int uiHashAlgoType,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucFileName,
	unsigned char *pucSignature,
	unsigned int uiSignatureLen)
{
	return SAR_OK;
}

/* 7.3.22 */
int SAF_VerifySignByCert(
	unsigned int uiHashAlgoType,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignature,
	unsigned int uiSignatureLen)
{
	int ret = SAR_UnknownErr;
#if 0
	/* process */
	X509 *x509 = NULL;
	unsigned char pucPublicKey[1024];
	unsigned int uiPublicKeyLen;
	unsigned char *p = pucPublicKey;
	int len;

	if (!(x509 = d2i_X509(NULL, (const unsigned char **)&pucCertificate, (long)uiCertificateLen))) {
		SAFerr(SAF_F_SAF_VERIFYSIGNBYCERT, ERR_R_X509_LIB);
		goto end;
	}

	if ((len = i2d_PUBKEY(X509_get0_pubkey(x509), &p)) <= 0) {
		SAFerr(SAF_F_SAF_VERIFYSIGNBYCERT, ERR_R_X509_LIB);
		goto end;
	}

	uiPublicKeyLen = (unsigned int)len;

	ret = SAF_RsaVerifySign(
		pucPublicKey,
		uiPublicKeyLen,
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucSignData,
		uiSignDataLen);


	/* set return value */
	ret = SAR_Ok;
end:
	X509_free(x509);
#endif
	return ret;
}
