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
#include <openssl/e_os2.h>

extern char *deviceHandle;

#define SDF_ENGINE_ID		"openssl"
#define SDF_SESSION_MAGIC	0x12345678

typedef struct {
	uint32_t magic;
	char *app;
	ENGINE *engine;
	char *password[SDF_MAX_KEY_INDEX];
	EVP_MD_CTX *md_ctx;
} SDF_SESSION;

typedef struct {
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned int keylen;
} SDF_KEY;

const EVP_CIPHER *sdf_get_cipher(SDF_SESSION *session, unsigned int uiAlgoID);
const EVP_MD *sdf_get_digest(SDF_SESSION *session, unsigned int uiAlgoID);
EVP_PKEY *sdf_load_rsa_public_key(SDF_SESSION *session, unsigned int uiKeyIndex, unsigned int uiKeyUsage);
EVP_PKEY *sdf_load_rsa_private_key(SDF_SESSION *session, unsigned int uiKeyIndex, unsigned int uiKeyUsage);
EVP_PKEY *sdf_load_ec_public_key(SDF_SESSION *session, unsigned int uiKeyIndex, unsigned int uiKeyUsage);
EVP_PKEY *sdf_load_ec_private_key(SDF_SESSION *session, unsigned int uiKeyIndex, unsigned int uiKeyUsage);
int sdf_encode_ec_signature(ECCSignature *ref, unsigned char *out, size_t *outlen);
int sdf_decode_ec_signature(ECCSignature *ref, const unsigned char *in, size_t inlen);


