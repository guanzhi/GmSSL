/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
#include <assert.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/engine.h>


static const SDF_METHOD *sdf_meth;

static const char *sdf_id = "sdf";
static const char *sdf_name = "ENGINE connect to SDF Devices";

#define SDF_CMD_SO_PATH		ENGINE_CMD_BASE

static const ENGINE_CMD_DEFN sdf_cmd_defns[] = {
	{SDF_CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the vendor's SDF shared library",
	 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0},
};

static int sdf_load_library(const char *so_path)
{
	sdf_meth = SDF_METHOD_load_library(so_path);
	return 1;
}

static int sdf_open_device()
{
	int rv;
	if ((rv = sdf_meth->OpenDevice(&hDevice)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_OPEN_DEVICE, ESDF_R_OPEN_DEVICE_FAILURE);
		fprintf(stderr, "so_path: %s\n", SDF_GetErrorString(rv));
		return 0;
	}
	if ((rv = sdf_meth->OpenSession(hDevice, &hSession)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_OPEN_DEVICE, ESDF_R_OPEN_SESSION_FAILURE);
		fprintf(stderr, "so_path: %s\n", SDF_GetErrorString(rv));
		return 0;
	}

	return 1;
}

static int sdf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
	switch (cmd) {
	case SDF_CMD_SO_PATH:
		so_path = (char *)p;
		sdf_load_library(so_path);
		break;
	default:
		printf("unknown cmd\n");
		return 0;
	}
	return 1;
}

static int sdf_ec_idx = -1;
static const EC_KEY_METHOD *sdf_ec_method = NULL;

static ECDSA_SIG *sdf_ec_sign_sig(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kinv, const BIGNUM *r,
	EC_KEY *ec_key)
{
	unsigned int key_index;
	ECCSignature sigbuf;

	rv = sdf_meth->InternalSign_ECC(
		hSession,
		key_index,
		dgst,
		dgstlen,
		&sigbuf);

	return ret;
}

const EC_KEY_METHOD *sdf_get_ec_method(void)
{
	EC_KEY_METHOD *ret = NULL;

	if (sdf_ec_method) {
		return sdf_ec_method;
	}

	if (!(ret = EC_KEY_METHOD_new(EC_KEY_OpenSSL()))) {
		return NULL;
	}

	EC_KEY_METHOD_set_sign(ret, NULL, NULL, sdf_ec_sign_sig);

	sdf_ec_method = ret;
	return ret;
}

static EVP_PKEY *sdf_load_privkey(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
	UI *ui = NULL;
	char buf1[256];
	char buf2[256];
	int r;
	char *password;
	ECCrefPublicKey keybuf;

	ui = UI_new_method(ui_method);

	if ((r = UI_add_input_string(ui, "> ", 0, buf1, 0, sizeof(buf1)-1)) < 0) {
		goto end;
	}
	if (UI_process(ui) < 0) {
	}

	password = UI_get0_result(ui, 0);


	sdf_meth->GetPrivateKeyAccessRight(
		hSession,
		key_index,
		password,
		strlen(password));

	sdf_meth->ExportSignPublicKey_ECC(
		hSession,
		key_index,
		&keybuf);

	ec_key = EC_KEY_new_by_ECCrefPublicKey(&keybuf);

	EVP_PKEY_set0_EC(ret, ec_key);

	return NULL;
}

static EVP_PKEY *sdf_load_pubkey(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *ret = NULL;
	int rv;

	unsigned int index;
	int is_sign_key;
	RSArefPublicKey publicKey;

	parse_key_id(key_id, &index, &is_sign_key);

	rv = SDF_OpenSession(hDevice, &hSession);

	if (is_sign_key) {
		rv = SDF_ExportSignPublicKey_RSA(hSession, index, &publicKey);
	} else {
		rv = SDF_ExportEncPublicKey_RSA(hSession, index, &publicKey);
	}

	return NULL;
}

static int sdf_destroy(ENGINE *e)
{
	return 1;
}

static void *hDevice = NULL;
static void *hSession = NULL;

static int sdf_init(ENGINE *e)
{
	sdf_meth = NULL;
	return 1;
}

static int sdf_finish(ENGINE *e)
{
	if (hSession) {
		sdf_meth->CloseSession(hSession);
		hSession = NULL;
	}

	if (hDevice) {
		sdf_meth->CloseDevice(hDevice);
	}
	return 1;
}

static int bind_sdf(ENGINE *e)
{
	if (!ENGINE_set_id(e, sdf_id)
		|| !ENGINE_set_name(e, sdf_name)
		|| !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL)
		|| !ENGINE_set_cmd_defns(e, sdf_cmd_defns)
		|| !ENGINE_set_ctrl_function(e, sdf_ctrl)
		|| !ENGINE_set_init_function(e, sdf_init)
		|| !ENGINE_set_finish_function(e, sdf_finish)
		|| !ENGINE_set_destroy_function(e, sdf_destroy)
		|| !ENGINE_set_load_privkey_function(e, sdf_load_privkey)
		|| !ENGINE_set_load_pubkey_function(e, sdf_load_pubkey)
		|| !ENGINE_set_EC(e, sdf_get_ec_method())) {
		return 0;
	}

	return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
	if (id && strcmp(id, sdf_id) != 0) {
		return 0;
	}
	if (!bind_sdf(e)) {
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

#else

static ENGINE *engine_sdf(void)
{
	ENGINE *ret = NULL;
	if (!(ret = ENGINE_new())) {
		return NULL;
	}
	if (!bind_sdf(ret)) {
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void engine_load_sdf_int(void)
{
	ENGINE *eng = NULL;
	if (!(eng = engine_sdf())) {
		return;
	}
	ENGINE_add(eng);
	ENGINE_free(eng);
	ERR_clear_error();
}
#endif /* OPENSSL_NO_DYNAMIC_ENGINE */
