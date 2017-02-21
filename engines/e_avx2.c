/* ====================================================================
 * Copyright (c) 2016 - 2017 The GmSSL Project.  All rights reserved.
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
#include <openssl/engine.h>


static const char *avx2_id = "avx2";
static const char *avx2_name = "ENGINE with Intel AVX2 Intructions";

#define SDF_CMD_STRING		ENGINE_CMD_BASE
#define SDF_CMD_NUMERIC		(ENGINE_CMD_BASE + 1)
#define SDF_CMD_NO_INPUT	(ENGINE_CMD_BASE + 2)

static const ENGINE_CMD_DEFN avx2_cmd_defns[] = {
	{SDF_CMD_STRING,
	 "STRING",
	 "Specifies the path to the vendor's SDF shared library",
	 ENGINE_CMD_FLAG_STRING},
	{SDF_CMD_NUMERIC,
	 "NUMERIC",
	 "Connect SKF device with device name",
	 ENGINE_CMD_FLAG_NUMERIC},
	{SDF_CMD_NO_INPUT,
	 "NO_INPUT",
	 "Example NO_INPUT",
	 ENGINE_CMD_FLAG_NO_INPUT},
	{0, NULL, NULL, 0},
};

static int avx2_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
	switch (cmd) {
	case SDF_CMD_STRING:
		printf("cmd = %s\n", (char *)p);
		break;
	case SDF_CMD_NUMERIC:
		printf("cmd = %d\n", (int)i);
		break;
	case SDF_CMD_NO_INPUT:
		printf("cmd = (null)\n");
		break;
	default:
		printf("unknown cmd\n");
		return 0;
	}

	return 1;
}

/****************************************************************************/

static int avx2_cipher_nids[] = {NID_sms4_ecb, NID_sms4_ctr, 0};
static int avx2_num_ciphers = OSSL_NELEM(avx2_cipher_nids) - 1;

static EVP_CIPHER *avx2_sms4_ecb = NULL;
static EVP_CIPHER *avx2_sms4_ctr = NULL;

static int avx2_sms4_ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	printf("  %s\n", __FUNCTION__);
	return 1;
}

static int avx2_sms4_ecb_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t inlen)
{
	printf("  %s\n", __FUNCTION__);
	memcpy(out, in, inlen);
	return 1;
}

static int avx2_sms4_ecb_cleanup(EVP_CIPHER_CTX *ctx)
{
	printf("  %s\n", __FUNCTION__);
	return 1;
}

static const EVP_CIPHER *avx2_get_sms4_ecb(void)
{
	EVP_CIPHER *ret = NULL;

	if (avx2_sms4_ecb) {
		return avx2_sms4_ecb;
	}

	if (!(ret = EVP_CIPHER_meth_new(NID_sms4_ecb, 16, 16))
		|| !EVP_CIPHER_meth_set_iv_length(ret, 0)
		|| !EVP_CIPHER_meth_set_flags(ret, EVP_CIPH_ECB_MODE|EVP_CIPH_FLAG_DEFAULT_ASN1)
		|| !EVP_CIPHER_meth_set_impl_ctx_size(ret, sizeof(struct sms4_cipher_ctx))
		|| !EVP_CIPHER_meth_set_init(ret, avx2_sms4_ecb_init)
		|| !EVP_CIPHER_meth_set_do_cipher(ret, avx2_sms4_ecb_do_cipher)
		|| !EVP_CIPHER_meth_set_cleanup(ret, avx2_sms4_ecb_cleanup)) {
		EVP_CIPHER_meth_free(ret);
		return NULL;
	}

	avx2_sms4_ecb = ret;
	return ret;
}

static int avx2_sms4_ctr_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	printf("  %s\n", __FUNCTION__);
	return 1;
}

static int avx2_sms4_ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t inlen)
{
	printf("  %s\n", __FUNCTION__);
	memcpy(out, in, inlen);
	return 1;
}

static int avx2_sms4_ctr_cleanup(EVP_CIPHER_CTX *ctx)
{
	printf("  %s\n", __FUNCTION__);
	return 1;
}

static const EVP_CIPHER *avx2_get_sms4_ctr(void)
{
	EVP_CIPHER *ret = NULL;

	if (avx2_sms4_ctr) {
		return avx2_sms4_ctr;
	}

	if (!(ret = EVP_CIPHER_meth_new(NID_sms4_ctr, 16, 16))
		|| !EVP_CIPHER_meth_set_iv_length(ret, 16)
		|| !EVP_CIPHER_meth_set_flags(ret, EVP_CIPH_CTR_MODE|EVP_CIPH_FLAG_DEFAULT_ASN1)
		|| !EVP_CIPHER_meth_set_impl_ctx_size(ret, sizeof(struct sms4_cipher_ctx))
		|| !EVP_CIPHER_meth_set_init(ret, avx2_sms4_ctr_init)
		|| !EVP_CIPHER_meth_set_do_cipher(ret, avx2_sms4_ctr_do_cipher)
		|| !EVP_CIPHER_meth_set_cleanup(ret, avx2_sms4_ctr_cleanup)) {
		EVP_CIPHER_meth_free(ret);
		return NULL;
	}

	avx2_sms4_ctr = ret;
	return ret;
}

static int avx2_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
	const int **nids, int nid)
{
	if (!cipher) {
		*nids = avx2_cipher_nids;
		return avx2_num_ciphers;
	}

	switch (nid) {
	case NID_sms4_ecb:
		*cipher = avx2_get_sms4_ecb();
		return 1;
	case NID_sms4_ctr:
		*cipher = avx2_get_sms4_ctr();
		return 1;
	}

	return 0;
}

static void avx2_destroy_ciphers(void)
{
	EVP_CIPHER_meth_free(avx2_sms4_ecb);
	EVP_CIPHER_meth_free(avx2_sms4_ctr);
	avx2_sms4_ecb = NULL;
	avx2_sms4_ctr = NULL;
}

static int avx2_destroy(ENGINE *e)
{
	avx2_destroy_ciphers();
	return 1;
}

static int avx2_init(ENGINE *e)
{
	return 1;
}

static int avx2_finish(ENGINE *e)
{
	return 1;
}

static int bind_avx2(ENGINE *e)
{
	if (!ENGINE_set_id(e, avx2_id)
		|| !ENGINE_set_name(e, avx2_name)
		|| !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL)
		|| !ENGINE_set_cmd_defns(e, avx2_cmd_defns)
		|| !ENGINE_set_ctrl_function(e, avx2_ctrl)
		|| !ENGINE_set_init_function(e, avx2_init)
		|| !ENGINE_set_finish_function(e, avx2_finish)
		|| !ENGINE_set_destroy_function(e, avx2_destroy)
		|| !ENGINE_set_ciphers(e, avx2_ciphers)) {
		return 0;
	}

	if (!(avx2_sms4_ecb = avx2_get_sms4_ecb())
		|| !(avx2_sms4_ctr = avx2_get_sms4_ctr())) {
		return 0;
	}

	return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
	if (id && strcmp(id, avx2_id) != 0) {
		return 0;
	}
	if (!bind_avx2(e)) {
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

#else

static ENGINE *engine_avx2(void)
{
	ENGINE *ret = NULL;
	if (!(ret = ENGINE_new())) {
		return NULL;
	}
	if (!bind_avx2(ret)) {
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void engine_load_avx2_int(void)
{
	ENGINE *eng = NULL;
	if (!(eng = engine_avx2())) {
		return;
	}
	ENGINE_add(eng);
	ENGINE_free(eng);
	ERR_clear_error();
}
#endif /* OPENSSL_NO_DYNAMIC_ENGINE */
