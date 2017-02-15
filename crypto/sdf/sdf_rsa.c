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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/gmsdf.h>
#include <openssl/gmapi.h>
#include "sdf_lcl.h"

/* As there are two APIs for export signing key and decryption key, this
 * means that keys with different usage can be referenced by the same
 * `uiKeyIndex`, and `uiKeyIndex` is the index of a key container.
 */
int SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	unsigned int uiKeyUsage = 0;

	if (!hSessionHandle || !pucPublicKey) {
		SDFerr(SDF_F_SDF_EXPORTSIGNPUBLICKEY_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(pkey = sdf_load_rsa_public_key((SDF_SESSION *)hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		SDFerr(SDF_F_SDF_EXPORTSIGNPUBLICKEY_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	if (!RSA_get_RSArefPublicKey(EVP_PKEY_get0_RSA(pkey), pucPublicKey)) {
		SDFerr(SDF_F_SDF_EXPORTSIGNPUBLICKEY_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

int SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	unsigned int uiKeyUsage = 1; //FIXME

	if (!hSessionHandle || !pucPublicKey) {
		SDFerr(SDF_F_SDF_EXPORTENCPUBLICKEY_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(pkey = sdf_load_rsa_public_key((SDF_SESSION *)hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		SDFerr(SDF_F_SDF_EXPORTENCPUBLICKEY_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	if (!RSA_get_RSArefPublicKey(EVP_PKEY_get0_RSA(pkey), pucPublicKey)) {
		SDFerr(SDF_F_SDF_EXPORTENCPUBLICKEY_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

/*
 * Generate RSA key pair.
 * The MAX RSA bits is defined as 2048 in GM/T 0018-2012. As 1024 is not very
 * secure, applications should always use 2048-bit. Use 1024-bit only for
 * legacy applications.
 */
int SDF_GenerateKeyPair_RSA(
	void *hSessionHandle, /* not used */
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey)
{
	int ret = 0;
	RSA *rsa = NULL;

	if (!hSessionHandle || !pucPublicKey || !pucPrivateKey) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(rsa = RSA_new())) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_RSA,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!RSA_generate_key_ex(rsa, uiKeyBits, NULL, NULL)) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_RSA, ERR_R_RSA_LIB);
		goto end;
	}

	if (!RSA_get_RSArefPublicKey(rsa, pucPublicKey)) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}
	if (!RSA_get_RSArefPrivateKey(rsa, pucPrivateKey)) {
		SDFerr(SDF_F_SDF_GENERATEKEYPAIR_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	RSA_free(rsa);
	return ret;
}

/*
 * In a cryptographic API the symmetric keys (and otehr keys) can be
 * classified into session keys and storage keys. The storage keys will be
 * persistantly stored in the secure storage of a cryptograhic hardware
 * device. While the session keys only exist in the session period, after
 * the session is finished, it will be destroyed even if the symmetric key
 * operations are performed inside the hardware.
 *
 * The `gmapi` module only support session keys.
 */
/*
 * In the current version of GmSSL (2.x), the session keys will be kept in
 * the host memory intead of the cryptographic hardware's internal memory.
 * So the key handle will suffer memory attacks.
 */

/*
 * Generate a symmetric key with bit length `uiKeyBits`, encrypt the key data
 * with an internal RSA public key with index `uiIPKIndex`, output the
 * encrypted key data to buffer `pucKey` and length `puiKeyLength`, also return
 * the handle of the generated key `phKeyHandle`.
 */

/* generate session key and encrypt with internal public key */
int SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits, /* generate key length */
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	int ret = 0;
	SDF_KEY *hkey = NULL;

	if (!hSessionHandle || !pucKey || !puiKeyLength || !phKeyHandle) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHIPK_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (uiKeyBits <= 0 || uiKeyBits % 8 || uiKeyBits > EVP_MAX_KEY_LENGTH) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHIPK_RSA,
			SDF_R_INVALID_KEY_LENGTH);
		return 0;
	}

	if (!(hkey = OPENSSL_zalloc(sizeof(*hkey)))) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHIPK_RSA,
			ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if ((ret = SDF_InternalPublicKeyOperation_RSA(
		hSessionHandle,
		uiIPKIndex,
		hkey->key,
		hkey->keylen,
		pucKey,
		puiKeyLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHIPK_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	*phKeyHandle = hkey;
	hkey = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(hkey, sizeof(*hkey));
	return ret;
}

/*
 * Generate a symmetric key with bit length `uiKeyBits`, encrypt the key data
 * with an external RSA public key with data `pucPublicKey` in format
 * `RSArefPublickey`, output the encrypted key data to buffer `pucKey` and
 * length `puiKeyLength`, also return the handle `phKeyHandle` of the generated
 * key.
 */
int SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	int ret = 0;
	SDF_KEY *key = NULL;

	if (!hSessionHandle || !pucPublicKey || !pucKey || !puiKeyLength ||
		!phKeyHandle) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (uiKeyBits <= 0 || uiKeyBits % 8 || uiKeyBits >
		EVP_MAX_KEY_LENGTH) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_RSA,
			SDF_R_INVALID_KEY_LENGTH);
		return 0;
	}

	if (!(key = OPENSSL_zalloc(sizeof(*key)))) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_RSA,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if ((ret = SDF_ExternalPublicKeyOperation_RSA(
		hSessionHandle,
		pucPublicKey,
		key->key,
		key->keylen,
		pucKey,
		puiKeyLength)) != SDR_OK) {
		SDFerr(SDF_F_SDF_GENERATEKEYWITHEPK_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	*phKeyHandle = key;
	key = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(key, sizeof(*key));
	return ret;
}

/*
 * Import the encrypted key generated from `SDF_GenerateKeyWithIPK_RSA` to the
 * session context, the internal RSA key index `uiISKIndex` should be the same
 * index of the parameter `uiIPKIndex` of `SDF_GenerateKeyWithIPK_RSA`.
 */

/* Import session key `pucKey` encrypted by the internal public key indexed
 * by `uiISKIndex`. As there are no session key in device, we need to
 * decrypt the `pucKey` with the internal key `uiISKIndex`.
 */
int SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	int ret = 0;
	SDF_KEY *key = NULL;

	if (!hSessionHandle || !pucKey || !phKeyHandle) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHISK_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(key = OPENSSL_zalloc(sizeof(*key)))) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHISK_RSA,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	key->keylen = EVP_MAX_KEY_LENGTH;
	if ((ret = SDF_InternalPrivateKeyOperation_RSA(
		hSessionHandle,
		uiISKIndex,
		pucKey,
		uiKeyLength,
		key->key,
		&key->keylen)) != SDR_OK) {
		SDFerr(SDF_F_SDF_IMPORTKEYWITHISK_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	*phKeyHandle = key;
	key = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(key, sizeof(*key));
	return ret;
}

/*
 * Convert internal public key encrypted symmetric key into ciphertext
 * encrypted by external public key. The input `pucDEInput` is the symmetric
 * key encrypted by internal public key `uiKeyIndex`. The output `pucDEOutput`
 * is encrypted under the external public key `pucPublicKey`.
 *
 * Note: This function is very dangerous. It convert a well protected symmetric
 * key into a state with security unknown. If the external private key is not
 * well protected, this function is the same as to unwrap of the symmetric key
 * and output the plaintext.
 */

/*
 * convert the `pucDEInput` encrypted by internal RSA public key
 * `uiKeyIndex` to `pucDEOutput` encrypted by the external RSA public key
 * `pucPublicKey`
 */
int SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength)
{
	return 0;
}

int SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = 0;
	RSA *rsa = NULL;
	int outlen;

	if (!hSessionHandle || !pucPublicKey || !pucDataInput ||
		!pucDataOutput || !puiOutputLength) {
		SDFerr(SDF_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(rsa = RSA_new_from_RSArefPublicKey(pucPublicKey))) {
		SDFerr(SDF_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	if ((outlen = RSA_public_encrypt((int)uiInputLength, pucDataInput,
		pucDataOutput, rsa, RSA_NO_PADDING)) < 0) {
		SDFerr(SDF_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_RSA_LIB);
		goto end;
	}

	*puiOutputLength = (unsigned int)outlen;
	ret = SDR_OK;

end:
	RSA_free(rsa);
	return ret;
}

/*
 * The RSA Operations include
 *	`SDF_ExternalPublicKeyOperation_RSA`
 *	`SDF_InternalPublicKeyOperation_RSA`
 *	`SDF_InternalPrivateKeyOperation_RSA`
 *
 * Noramlly RSA operations should be working with some padding methods, such
 * as PKCS #1 OAEP padding or PSS padding. As the SDF API does not provide any
 * parameter to set padding method, and it is neither specified in the GM/T
 * 0018-2012 standard, application developers need to ask the vendor or try
 * testing. The GmSSL SDF implementation will always try to use the PKCS #1
 * padding, but the underlying ENGINEs might not support this padding options.
 *
 * It should be noted that the SDF API does not support external private key
 * operations.
 */

int SDF_ExternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPrivateKey *pucPrivateKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = 0;
	RSA *rsa = NULL;
	int outlen;

	if (!hSessionHandle || !pucPrivateKey || !pucDataInput ||
		!pucDataOutput || !puiOutputLength) {
		SDFerr(SDF_F_SDF_EXTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(rsa = RSA_new_from_RSArefPrivateKey(pucPrivateKey))) {
		SDFerr(SDF_F_SDF_EXTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	if ((outlen = RSA_private_decrypt((int)uiInputLength, pucDataInput,
		pucDataOutput, rsa, RSA_NO_PADDING)) < 0) {
		SDFerr(SDF_F_SDF_EXTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_RSA_LIB);
		goto end;
	}

	*puiOutputLength = (unsigned int)outlen;
	ret = SDR_OK;

end:
	RSA_free(rsa);
	return ret;
}


int SDF_InternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	int outlen;
	unsigned int uiKeyUsage = -12345; //FIXME: which key should we use?

	if (!hSessionHandle || !pucDataInput || !pucDataOutput ||
		!puiOutputLength) {
		SDFerr(SDF_F_SDF_INTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(pkey = sdf_load_rsa_public_key((SDF_SESSION *)hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		SDFerr(SDF_F_SDF_INTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	if ((outlen = RSA_public_encrypt((int)uiInputLength, pucDataInput,
		pucDataOutput, EVP_PKEY_get0_RSA(pkey), RSA_NO_PADDING)) < 0) {
		SDFerr(SDF_F_SDF_INTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_RSA_LIB);
		goto end;
	}

	*puiOutputLength = (unsigned int)outlen;
	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

int SDF_InternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	int outlen;
	unsigned int uiKeyUsage; //FIXME

	if (!hSessionHandle || !pucDataInput || !pucDataOutput ||
		!puiOutputLength) {
		SDFerr(SDF_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(pkey = sdf_load_rsa_private_key((SDF_SESSION *)hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		SDFerr(SDF_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	if ((outlen = RSA_private_decrypt(uiInputLength, pucDataInput,
		pucDataOutput, EVP_PKEY_get0_RSA(pkey), RSA_NO_PADDING)) < 0) {
		SDFerr(SDF_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_RSA_LIB);
		goto end;
	}

	*puiOutputLength = (unsigned int)outlen;
	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

