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


#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/gmsdf.h>
#include <openssl/gmsaf.h>


typedef struct {
	const char *config_path;
	ENGINE *engine;
} SAF_APP;

typedef struct {
	EVP_ENCODE_CTX *ctx;
	int inited;
} SAF_BASE64OBJ;

typedef struct {
	void *hAppHandle;
	unsigned char *pucContainerName;
	unsigned int uiContainerLen;
	unsigned char *pucIV;
	unsigned int uiIVLen;
	unsigned int uiEncOrDec;
	unsigned int uiCryptoAlgID;
} SAF_SymmKeyObj;

typedef struct {
	unsigned char *key;
	size_t keylen;

	/* used by `SAF_SymmEncryptUpdate`, `SAF_SymmEncryptFinal`,
	 * `SAF_SymmDecryptUpdate`, `SAF_SymmDecryptFinal`
	 */
	EVP_CIPHER_CTX *cipher_ctx;
	const EVP_CIPHER *cipher;
	CMAC_CTX *cmac_ctx;
} SAF_KEY_HANDLE;

int saf_readfile(
	const char *file,
	unsigned char **pout,
	size_t *len);

int saf_save_ec_keypair(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned int uiKeyUsage,
	unsigned int uiExportFlag,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey);

int saf_save_rsa_keypair(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned int uiKeyUsage,
	unsigned int uiExportFlag,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey);

int saf_get_sdf_session_and_keyindex(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyUsage,
	void *phSessionHandle,
	unsigned int puiKeyIndex);

int saf_get_sdf_session_and_ecsignkey(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiAlgorithmID, /* SGD_SM2_1 */
	void **phSessionhandle,
	unsigned int *puiISKIndex);

void saf_release_sdf_session(
	void *hSessionHandle);

int saf_get_ec_public_key_from_cert(
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	ECCrefPublicKey *pucPublicKey);

