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

#include <openssl/sgd.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/gmsdf.h>
#include <openssl/gmapi.h>
#include "sdf_lcl.h"

/*
 * We always get these objects from engine, hardware-based engine,
 * software-based engine with storage, or just ossl default engine.
 */

const EVP_CIPHER *sdf_get_cipher(SDF_SESSION *session,
	unsigned int uiAlgoID)
{
	int nid;

	if (!session->engine) {
		SDFerr(SDF_F_SDF_GET_CIPHER,
			SDF_R_SDF_SESSION_NO_ENGINE);
		return NULL;
	}
	if ((nid = GMAPI_sgd2ciphernid(uiAlgoID)) == NID_undef) {
		SDFerr(SDF_F_SDF_GET_CIPHER,
			SDF_R_INVALID_ALGOR);
		return NULL;
	}

	return ENGINE_get_cipher(session->engine, nid);
}

const EVP_MD *sdf_get_digest(SDF_SESSION *session,
	unsigned int uiAlgoID)
{
	int nid;

	if (!session->engine) {
		SDFerr(SDF_F_SDF_GET_DIGEST,
			SDF_R_SDF_SESSION_NO_ENGINE);
		return NULL;
	}
	if ((nid = GMAPI_sgd2mdnid(uiAlgoID)) == NID_undef) {
		SDFerr(SDF_F_SDF_GET_DIGEST,
			SDF_R_INVALID_ALGOR);
		return NULL;
	}

	return ENGINE_get_digest(session->engine, nid);
}

/* we assume that the SDF ENGINE implementations follow the same design of
 * the SKF key storage model: app/container/keyusage. And we assume the
 * session is binded with app, the container is refered by key index, and
 * the key usage is the same. So the `key_id` string used for ENGINE is as
 * follows:
 *             "AppName/ContainerNameOrIndex/KeyUsage"
 */
//FIXME: we should change the following 4 functions into 1 and 4 macros
EVP_PKEY *sdf_load_rsa_public_key(SDF_SESSION *session,
	unsigned int uiKeyIndex, unsigned int uiKeyUsage)
{
	EVP_PKEY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	char key_id[256];
	char *app = "";
	char *usage;

	if (!session->engine) {
		SDFerr(SDF_F_SDF_LOAD_RSA_PUBLIC_KEY,
			SDF_R_SDF_SESSION_NO_ENGINE);
		return NULL;
	}
	if (!(usage = GMAPI_keyusage2str(uiKeyUsage))) {
		SDFerr(SDF_F_SDF_LOAD_RSA_PUBLIC_KEY,
			SDF_R_INVALID_KEY_USAGE);
		return NULL;
	}

	snprintf(key_id, sizeof(key_id), "%s/%u/%s", app, uiKeyIndex, usage);

	if (!(pkey = ENGINE_load_public_key(session->engine, key_id,
		NULL, NULL))) {
		SDFerr(SDF_F_SDF_LOAD_RSA_PUBLIC_KEY,
			SDF_R_ENGINE_LOAD_KEY_FAILURE);
		goto end;
	}

	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
		SDFerr(SDF_F_SDF_LOAD_RSA_PUBLIC_KEY,
			SDF_R_KEY_TYPE_NOT_MATCH);
		goto end;
	}

	ret = pkey;
	pkey = NULL;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

EVP_PKEY *sdf_load_rsa_private_key(SDF_SESSION *session,
	unsigned int uiKeyIndex, unsigned int uiKeyUsage)
{
	EVP_PKEY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	char key_id[256];
	char *app = "";
	char *usage;

	if (!session->engine) {
		SDFerr(SDF_F_SDF_LOAD_RSA_PRIVATE_KEY,
			SDF_R_SDF_SESSION_NO_ENGINE);
		return NULL;
	}
	if (!(usage = GMAPI_keyusage2str(uiKeyUsage))) {
		SDFerr(SDF_F_SDF_LOAD_RSA_PRIVATE_KEY,
			SDF_R_INVALID_KEY_USAGE);
		return NULL;
	}

	snprintf(key_id, sizeof(key_id), "%s/%u/%s", app, uiKeyIndex, usage);

	if (!(pkey = ENGINE_load_private_key(session->engine, key_id,
		NULL, NULL))) {
		SDFerr(SDF_F_SDF_LOAD_RSA_PRIVATE_KEY,
			SDF_R_ENGINE_LOAD_KEY_FAILURE);
		goto end;
	}

	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
		SDFerr(SDF_F_SDF_LOAD_RSA_PRIVATE_KEY,
			SDF_R_KEY_TYPE_NOT_MATCH);
		goto end;
	}

	ret = pkey;
	pkey = NULL;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

EVP_PKEY *sdf_load_ec_public_key(SDF_SESSION *session,
	unsigned int uiKeyIndex, unsigned int uiKeyUsage)
{
	EVP_PKEY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	char key_id[256];
	char *app = "";
	char *usage;

	if (!session->engine) {
		SDFerr(SDF_F_SDF_LOAD_EC_PUBLIC_KEY,
			SDF_R_SDF_SESSION_NO_ENGINE);
		return NULL;
	}
	if (!(usage = GMAPI_keyusage2str(uiKeyUsage))) {
		SDFerr(SDF_F_SDF_LOAD_EC_PUBLIC_KEY,
			SDF_R_INVALID_KEY_USAGE);
		return NULL;
	}

	snprintf(key_id, sizeof(key_id), "%s/%u/%s", app, uiKeyIndex, usage);

	if (!(pkey = ENGINE_load_public_key(session->engine, key_id,
		NULL, NULL))) {
		SDFerr(SDF_F_SDF_LOAD_EC_PUBLIC_KEY,
			SDF_R_ENGINE_LOAD_KEY_FAILURE);
		goto end;
	}
	if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
		SDFerr(SDF_F_SDF_LOAD_EC_PUBLIC_KEY,
			SDF_R_KEY_TYPE_NOT_MATCH);
		goto end;
	}

	ret = pkey;
	pkey = NULL;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

EVP_PKEY *sdf_load_ec_private_key(SDF_SESSION *session,
	unsigned int uiKeyIndex, unsigned int uiKeyUsage)
{
	EVP_PKEY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	char key_id[256];
	char *app = "";
	char *usage;

	if (!session->engine) {
		SDFerr(SDF_F_SDF_LOAD_EC_PRIVATE_KEY,
			SDF_R_SDF_SESSION_NO_ENGINE);
		return NULL;
	}
	if (!(usage = GMAPI_keyusage2str(uiKeyUsage))) {
		SDFerr(SDF_F_SDF_LOAD_EC_PRIVATE_KEY,
			SDF_R_INVALID_KEY_USAGE);
		return NULL;
	}

	snprintf(key_id, sizeof(key_id), "%s/%u/%s", app, uiKeyIndex, usage);

	if (!(pkey = ENGINE_load_private_key(session->engine, key_id,
		NULL, NULL))) {
		SDFerr(SDF_F_SDF_LOAD_EC_PRIVATE_KEY,
			SDF_R_ENGINE_LOAD_KEY_FAILURE);
		goto end;
	}
	if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
		SDFerr(SDF_F_SDF_LOAD_EC_PRIVATE_KEY,
			SDF_R_KEY_TYPE_NOT_MATCH);
		goto end;
	}

	ret = pkey;
	pkey = NULL;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

int sdf_encode_ec_signature(ECCSignature *ref, unsigned char *out,
	size_t *outlen)
{
	int ret = 0;
	ECDSA_SIG *sig = NULL;
	unsigned char *p;
	int len;

	if (!(sig = ECDSA_SIG_new_from_ECCSignature(ref))) {
		SDFerr(SDF_F_SDF_ENCODE_EC_SIGNATURE, ERR_R_GMAPI_LIB);
		goto end;
	}

	p = out;
	if ((len = i2d_ECDSA_SIG(sig, &p)) <= 0) {
		SDFerr(SDF_F_SDF_ENCODE_EC_SIGNATURE, ERR_R_EC_LIB);
		goto end;
	}

	ret = 1;

end:
	ECDSA_SIG_free(sig);
	return ret;
}

int sdf_decode_ec_signature(ECCSignature *ref, const unsigned char *in,
	size_t inlen)
{
	int ret = 0;
	ECDSA_SIG *sig = NULL;
	const unsigned char *p;

	p = in;
	if (!(sig = d2i_ECDSA_SIG(NULL, &p, inlen))) {
		SDFerr(SDF_F_SDF_DECODE_EC_SIGNATURE, ERR_R_EC_LIB);
		goto end;
	}

	if (!ECDSA_SIG_get_ECCSignature(sig, ref)) {
		SDFerr(SDF_F_SDF_DECODE_EC_SIGNATURE, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = 1;

end:
	ECDSA_SIG_free(sig);
	return ret;
}
