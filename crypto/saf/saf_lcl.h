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
#include <openssl/engine.h>
#include <openssl/err.h>

typedef struct saf_app_st {
	ENGINE *engine;
	char *rootcacerts;
	char *cacerts;
} SAF_APP;

typedef struct {
	EVP_ENCODE_CTX *ctx;
	int inited;
} SAF_BASE64OBJ;

typedef struct {
	SAF_APP *app;
	unsigned char *pucContainerName;
	unsigned int uiContainerLen;
	unsigned char *pucIV;
	unsigned int uiIVLen;
	unsigned int uiEncOrDec;
	unsigned int uiCryptoAlgID;
} SAF_SYMMKEYOBJ;

typedef struct {
	SAF_SYMMKEYOBJ *hSymmKeyObj;
	unsigned char key[64];
	size_t keylen;
	EVP_CIPHER_CTX *cipher_ctx;
	CMAC_CTX *cmac_ctx;
} SAF_KEY;

SAF_KEY *SAF_KEY_new(const SAF_SYMMKEYOBJ *obj);
void SAF_KEY_free(SAF_KEY *key);

SAF_SYMMKEYOBJ *SAF_SYMMKEYOBJ_dup(const SAF_SYMMKEYOBJ *a);
void SAF_SYMMKEYOBJ_free(SAF_SYMMKEYOBJ *a);


EVP_PKEY *SAF_load_private_key(SAF_APP *app, const char *container, int flags);
EVP_PKEY *SAF_load_public_key(SAF_APP *app, const char *container, int flags);

