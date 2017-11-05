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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sgd.h>
#include <openssl/gmapi.h>
#include "../../e_os.h"

typedef struct {
	int nid;
	ULONG ulAlgId;
	ULONG ulFeedBitLen;
} GMAPI_CIPHER_ITEM;

static GMAPI_CIPHER_ITEM gmapi_ciphers[] = {
	{NID_sm1_ecb, SGD_SM1_ECB, 0},
	{NID_sm1_cbc, SGD_SM1_CBC, 0},
	{NID_sm1_cfb1, SGD_SM1_CFB, 1},
	{NID_sm1_cfb8, SGD_SM1_CFB, 8},
	{NID_sm1_cfb128, SGD_SM1_CFB, 128},
	{NID_sm1_ofb128, SGD_SM1_OFB, 128},
	{NID_sms4_ecb, SGD_SM4_ECB, 0},
	{NID_sms4_cbc, SGD_SM4_CBC, 0},
	{NID_sms4_cfb1, SGD_SM4_CFB, 1},
	{NID_sms4_cfb8, SGD_SM4_CFB, 8},
	{NID_sms4_cfb128, SGD_SM4_CFB, 128},
	{NID_sms4_ofb128, SGD_SM4_OFB, 128},
	{NID_ssf33_ecb, SGD_SSF33_ECB, 0},
	{NID_ssf33_cbc, SGD_SSF33_CBC, 0},
	{NID_ssf33_cfb1, SGD_SSF33_CFB, 1},
	{NID_ssf33_cfb8, SGD_SSF33_CFB, 8},
	{NID_ssf33_cfb128, SGD_SSF33_CFB, 128},
	{NID_ssf33_ofb128, SGD_SSF33_OFB, 128},
	{NID_zuc_128eea3, SGD_ZUC_EEA3, 0},
};

const EVP_CIPHER *EVP_get_cipherbysgd(ULONG ulAlgId, ULONG ulFeedBitLen)
{
	size_t i;

	for (i = 0; i < OSSL_NELEM(gmapi_ciphers); i++) {
		if (gmapi_ciphers[i].ulAlgId == ulAlgId
			&& gmapi_ciphers[i].ulFeedBitLen == ulFeedBitLen) {
			return EVP_get_cipherbynid(gmapi_ciphers[i].nid);
		}
	}

	return NULL;	
}

int EVP_CIPHER_get_sgd(const EVP_CIPHER *cipher, ULONG *pulAlgId, ULONG *pulFeedBits)
{
	size_t i;

	if (!cipher || !pulAlgId || !pulFeedBits) {
		GMAPIerr(GMAPI_F_EVP_CIPHER_GET_SGD, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	for (i = 0; i < OSSL_NELEM(gmapi_ciphers); i++) {
		if (EVP_CIPHER_nid(cipher) == gmapi_ciphers[i].nid) {
			*pulAlgId = gmapi_ciphers[i].ulAlgId;
			*pulFeedBits = gmapi_ciphers[i].ulFeedBitLen;
			return 1;
		}
	}

	/* caller can clear this error */
	GMAPIerr(GMAPI_F_EVP_CIPHER_GET_SGD, GMAPI_R_NOT_SUPPORTED_GMAPI_CIPHER);
	*pulAlgId = 0;
	*pulFeedBits = 0;
	return 0;
}

int EVP_CIPHER_CTX_get_sgd(const EVP_CIPHER_CTX *ctx,
	ULONG *pulAlgId, ULONG *pulFeedBits)
{
	if (!ctx || !pulAlgId || !pulFeedBits) {
		GMAPIerr(GMAPI_F_EVP_CIPHER_CTX_GET_SGD,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	return EVP_CIPHER_get_sgd(EVP_CIPHER_CTX_cipher(ctx), pulAlgId, pulFeedBits);
}

typedef struct {
	int nid;
	ULONG ulAlgId;
} GMAPI_ALGOR_ITEM;


static GMAPI_ALGOR_ITEM gmapi_digests[] = {
	{NID_sm3, SGD_SM3},
	{NID_sha1, SGD_SHA1},
	{NID_sha256, SGD_SHA256},
};

const EVP_MD *EVP_get_digestbysgd(ULONG ulAlgId)
{
	size_t i;

	for (i = 0; i < OSSL_NELEM(gmapi_digests); i++) {
		if (gmapi_digests[i].ulAlgId == ulAlgId) {
			return EVP_get_digestbynid(gmapi_digests[i].nid);
		}
	}

	return NULL;
}

int EVP_MD_get_sgd(const EVP_MD *md, ULONG *ulAlgId)
{
	size_t i;

	if (!md || !ulAlgId) {
		GMAPIerr(GMAPI_F_EVP_MD_GET_SGD, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	for (i = 0; i < OSSL_NELEM(gmapi_digests); i++) {
		if (gmapi_digests[i].nid == EVP_MD_nid(md)) {
			*ulAlgId = gmapi_digests[i].ulAlgId;
			return 1;
		}
	}

	*ulAlgId = 0;
	return 0;
}

int EVP_MD_CTX_get_sgd(const EVP_MD_CTX *ctx, ULONG *ulAlgId)
{
	return EVP_MD_get_sgd(EVP_MD_CTX_md(ctx), ulAlgId);
}

static GMAPI_ALGOR_ITEM gmapi_pkeys[] = {
	{NID_rsa, SGD_RSA_SIGN},
	{NID_rsaEncryption, SGD_RSA_ENC},
	{NID_sm2sign, SGD_SM2_1},
	{NID_sm2exchange, SGD_SM2_2},
	{NID_sm2encrypt, SGD_SM2_3}
};

int EVP_PKEY_get_sgd(const EVP_PKEY *pkey, ULONG *ulAlgId)
{
	size_t i;

	if (!pkey || !ulAlgId) {
		GMAPIerr(GMAPI_F_EVP_PKEY_GET_SGD, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	for (i = 0; i < OSSL_NELEM(gmapi_pkeys); i++) {
		if (gmapi_pkeys[i].nid == EVP_PKEY_base_id(pkey)) {
			*ulAlgId = gmapi_pkeys[i].ulAlgId;
			return 1;
		}
	}

	GMAPIerr(GMAPI_F_EVP_PKEY_GET_SGD, GMAPI_R_NOT_SUPPORTED_PKEY);
	return 0;
}

int EVP_PKEY_CTX_get_sgd(const EVP_PKEY_CTX *ctx, ULONG *ulAlgId)
{
	return EVP_PKEY_get_sgd(EVP_PKEY_CTX_get0_pkey((EVP_PKEY_CTX *)ctx), ulAlgId);
}
