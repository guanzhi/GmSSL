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

static int sdf_rand_bytes(unsigned char *out, int outlen)
{
	if (sdf_meth->GenerateRandom) {
		if ((sdf_meth->GenerateRandom(hSession, out, outlen)) != SDR_OK) {
			ESDFerr(ESDF_F_SDF_RAND_BYTES, ESDF_R_OPERATION_FAILURE);
			return 0;
		}
	}
	return 1;
}

static int sdf_rand_status(void)
{
	return 1;
}

static RAND_METHOD sdf_rand_method = {
	NULL,
	sdf_rand_bytes,
	NULL,
	NULL,
	sdf_rand_bytes,
	sdf_rand_status,
};

const RAND_METHOD *sdf_get_rand_method(void)
{
	return &sdf_rand_method;
}

static int sdf_ec_idx = -1;
static const EC_KEY_METHOD *sdf_ec_method = NULL;

static int sdf_ec_sign(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *kinv, const BIGNUM *r,
	EC_KEY *ec_key)
{
	printf(" call %s()\n", __func__);
	return 1;
}

static int sdf_ec_sign_setup(EC_KEY *ec_key, BN_CTX *ctx,
	BIGNUM **kinvp, BIGNUM **rp)
{
	printf(" call %s()\n", __func__);
	return 1;
}

static ECDSA_SIG *sdf_ec_sign_sig(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kinv, const BIGNUM *r,
	EC_KEY *ec_key)
{
	ECDSA_SIG *ret = ECDSA_SIG_new();
	printf(" call %s()\n", __func__);
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

	EC_KEY_METHOD_set_sign(ret, sdf_ec_sign, sdf_ec_sign_setup, sdf_ec_sign_sig);

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

	ui = UI_new_method(ui_method);

	r = UI_add_input_string(ui, "> ", 0, buf1, 0, sizeof(buf1)-1);
	assert(r >= 0);
	r = UI_process(ui);
	assert(r >= 0);

	printf("password = %s\n", UI_get0_result(ui, 0));

	printf("%s\n", __func__);
	return NULL;
}

static EVP_PKEY *sdf_load_pubkey(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
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

	printf("%s\n", __func__);
	return NULL;
}

/****************************************************************************/

static int sdf_destroy(ENGINE *e)
{
	return 1;
}

static void *hDevice = NULL;
static void *hSession = NULL;

static int sdf_init(ENGINE *e)
{
	int rv;
	rv = sdf_meth->OpenDevice(&hDevice);
	rv = sdf_meth->OpenSession(hDevice, &hSession);
	return 1;
}

static int sdf_finish(ENGINE *e)
{
	sdf_meth->CloseSession(hSession);
	sdf_meth->CloseDevice(hDevice);
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
		|| !ENGINE_set_RAND(e, sdf_get_rand_method())
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
