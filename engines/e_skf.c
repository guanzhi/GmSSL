/* engines/e_skf.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ssf33.h>
#include <openssl/sm1.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sms4.h>
#include <openssl/sm9.h>
#include <openssl/ossl_typ.h>
#include <openssl/skf.h>
#include <openssl/skf_ex.h>
#include "e_skf_err.c"
#include "../crypto/ecdsa/ecs_locl.h"

static DEVHANDLE hDev = NULL;
static HAPPLICATION hApp = NULL;
static HCONTAINER hContainer = NULL;
static int isDevAuthenticated = 0;
static int isPinVerified = 0;

#define SKF_CMD_SO_PATH			ENGINE_CMD_BASE
#define SKF_CMD_OPEN_DEV		(ENGINE_CMD_BASE + 1)
#define SKF_CMD_DEV_AUTH		(ENGINE_CMD_BASE + 2)
#define SKF_CMD_OPEN_APP		(ENGINE_CMD_BASE + 3)
#define SKF_CMD_VERIFY_PIN		(ENGINE_CMD_BASE + 4)
#define SKF_CMD_OPEN_CONTAINER		(ENGINE_CMD_BASE + 5)

static const ENGINE_CMD_DEFN skf_cmd_defns[] = {
	{SKF_CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the vendor's SKF shared library",
	 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_OPEN_DEV,
	 "OPEN_DEVICE",
	 "Connect SKF device with device name",
	 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_DEV_AUTH,
	 "DEV_AUTH",
	 "Authenticate to device with authentication key",
	 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_OPEN_APP,
	 "OPEN_APP",
	 "Open application with specified application name",
	 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_VERIFY_PIN,
	 "VERIFY_PIN",
	 "Authenticate to application with USER PIN",
	 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_OPEN_CONTAINER,
	 "OPEN_CONTAINER",
	 "Open container with specified container name",
	 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0},
};

static int open_dev(const char *devname)
{
	ULONG rv;
	DEVINFO devInfo;

	if (hDev) {
		ESKFerr(ESKF_F_OPEN_DEV, ESKF_R_DEV_ALREADY_CONNECTED);
		return 0;
	}
	if ((rv = SKF_ConnectDev((LPSTR)devname, &hDev)) != SAR_OK) {
		ESKFerr(ESKF_F_OPEN_DEV, ESKF_R_SKF_CONNECT_DEV_FAILED);
		return 0;
	}
	if ((rv = SKF_GetDevInfo(hDev, &devInfo)) != SAR_OK) {
		ESKFerr(ESKF_F_OPEN_DEV, ESKF_R_SKF_GET_DEV_INFO_FAILED);
		return 0;
	}

	return 1;
}

static int dev_auth(const char *hexauthkey)
{
	int ret = 0;
	ULONG rv;
	const EVP_CIPHER *cipher = EVP_sms4_ecb();
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char authkey[EVP_MAX_KEY_LENGTH];
	unsigned char authrand[SMS4_BLOCK_SIZE];
	unsigned char authdata[SMS4_BLOCK_SIZE];
	unsigned int len;

	if (!hDev) {
		ESKFerr(ESKF_F_DEV_AUTH, ESKF_R_DEV_IS_NOT_CONNECTED);
		return 0;
	}

	if (!isDevAuthenticated) {
		ESKFerr(ESKF_F_DEV_AUTH, ESKF_R_DEV_ALREADY_AUTHENTICATED);
		return 0;
	}

	len = 16; //FIXME: or 8?
	memset(authrand, 0, sizeof(authrand));
	if ((rv = SKF_GenRandom(hDev, authrand, len)) != SAR_OK) {
		ESKFerr(ESKF_F_DEV_AUTH, ESKF_R_SKF_GEN_RANDOM_FAILED);
		goto end;
	}

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		ESKFerr(ESKF_F_DEV_AUTH, ERR_R_EVP_LIB);
		goto end;
	}

	if (!EVP_EncryptInit(ctx, cipher, authkey, NULL)) {
		ESKFerr(ESKF_F_DEV_AUTH, ERR_R_EVP_LIB);
		goto end;
	}

	if (!EVP_Cipher(ctx, authdata, authrand, sizeof(authrand))) {
		ESKFerr(ESKF_F_DEV_AUTH, ERR_R_EVP_LIB);
		goto end;
	}

	if ((rv = SKF_DevAuth(hDev, authdata, sizeof(authdata))) != SAR_OK) {
		ESKFerr(ESKF_F_DEV_AUTH, ESKF_R_SKF_DEV_AUTH_FAILED);
		goto end;
	}

	isDevAuthenticated = 1;
	ret = 1;
end:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

static int open_app(const char *appname)
{
	ULONG rv;

	if (!hDev) {
		ESKFerr(ESKF_F_OPEN_APP, ESKF_R_DEV_NOT_CONNECTED);
		return 0;
	}

	if (!isDevAuthenticated) {
		ESKFerr(ESKF_F_OPEN_APP, ESKF_R_DEV_NOT_AUTHENTICATED);
		return 0;
	}

	if (hApp) {
		ESKFerr(ESKF_F_OPEN_APP, ESKF_R_APP_ALREADY_OPENED);
		return 0;
	}

	if ((rv = SKF_OpenApplication(hDev, (LPSTR)appname, &hApp)) != SAR_OK) {
		ESKFerr(ESKF_F_OPEN_APP, ESKF_R_SKF_OPEN_APPLICATION_FAILED);
		return 0;
	}

	return 1;
}

static int verify_pin(const char *userpin)
{
	ULONG rv;
	ULONG retryCount;

	if (!hDev) {
		ESKFerr(ESKF_F_VERIFY_PIN, ESKF_R_DEV_NOT_CONNECTED);
		return 0;
	}

	if (!isDevAuthenticated) {
		ESKFerr(ESKF_F_VERIFY_PIN, ESKF_R_DEV_NOT_AUTHENCATED);
		return 0;
	}

	if (!hApp) {
		ESKFerr(ESKF_F_VERIFY_PIN, ESKF_R_APP_NOT_OPENED);
		return 0;
	}

	if ((rv = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)userpin, &retryCount)) != SAR_OK) {
		ESKFerr(ESKF_F_VERIFY_PIN, ESKF_R_SKF_VERIFY_PIN_FAILED);
		return 0;
	}

	isPinVerified = 1;
	return 1;
}

static int open_container(const char *containername)
{
	ULONG rv;

	if (!hDev) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_DEV_NOT_CONNECTED);
		return 0;
	}

	if (!isDevAuthenticated) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_DEV_NOT_AUTHENTICATED);
		return 0;
	}

	if (!hApp) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_APP_NOT_OPENED);
		return 0;
	}

	if (!isPinVerified) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_PIN_NOT_VERIFIED);
		return 0;
	}

	if (hContainer) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_CONTAINER_ALREADY_OPENED);
		return 0;
	}

	if ((rv = SKF_OpenContainer(hApp, (LPSTR)containername, &hContainer)) != SAR_OK) {
		ESKFerr(ESKF_F_OPEN_CONTAINER, ESKF_R_SKF_OPEN_CONTAINER_FAILED);
		return 0;
	}

	/*
	*/

	return 1;
}

static int skf_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
{
	switch (cmd) {
	case SKF_CMD_OPEN_DEV:
		return open_dev(p);
	case SKF_CMD_DEV_AUTH:
		return dev_auth(p);
	case SKF_CMD_OPEN_APP:
		return open_app(p);
	case SKF_CMD_VERIFY_PIN:
		return verify_pin(p);
	case SKF_CMD_OPEN_CONTAINER:
		return open_container(p);
	}

	ESKFerr(ESKF_F_SKF_ENGINE_CTRL, ESKF_R_INVALID_CTRL_CMD);
	return 0;
}

static EVP_PKEY *skf_load_pubkey(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
	ULONG rv, len;
	EVP_PKEY *ret = NULL;
	EC_KEY *ec_key = NULL;
	RSA *rsa = NULL;
	ECCPUBLICKEYBLOB eccblob;
	RSAPUBLICKEYBLOB rsablob;
	ULONG containerType;

	if (!hContainer) {
		ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_CONTAINER_NOT_OPENED);
		return 0;
	}

	if ((rv = SKF_GetContainerType(hContainer, &containerType)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_SKF_GET_CONTAINER_TYPE_FAILED);
		return 0;
	}

	if (containerType == CONTAINER_TYPE_ECC) {
		len = sizeof(eccblob);
		if ((rv = SKF_ExportPublicKey(hContainer, TRUE, (BYTE *)&eccblob, &len)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED);
			return 0;
		}
		if (!(ec_key = EC_KEY_new_from_ECCPUBLICKEYBLOB(&eccblob))) {
			return 0;
		}
		EVP_PKEY_set1_EC_KEY(ret, ec_key);
		ec_key = NULL;

	} else if (containerType == CONTAINER_TYPE_RSA) {
		len = sizeof(rsablob);
		if ((rv = SKF_ExportPublicKey(hContainer, TRUE, (BYTE *)&rsablob, &len)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_SKF_EXPORT_PUBLIC_KEY_FAILED);
			return 0;
		}
		if (!(rsa = RSA_new_from_RSAPUBLICKEYBLOB(&rsablob))) {
			return 0;
		}
		EVP_PKEY_set1_RSA(ret, rsa);
		rsa = NULL;

	} else {
		ESKFerr(ESKF_F_SKF_LOAD_PUBKEY, ESKF_R_INVALID_CONTAINER_TYPE);
		return 0;
	}

	return ret;
}

static int skf_init(ENGINE *e)
{
	return 1;
}

static int skf_finish(ENGINE *e)
{
	ULONG rv;

	if (hDev) {
		if ((rv = SKF_DisConnectDev(hDev)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_FINISH, ESKF_R_SKF_DIS_CONNNECT_DEV_FAILED);
			return 0;
		}
	}

	return 1;
}

static int skf_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	ULONG rv;
	ULONG ulAlgID;

	if (!SKF_nid_to_encparam(EVP_CIPHER_CTX_nid(ctx), &ulAlgID, NULL)) {
		return 0;
	}
	if ((rv = SKF_SetSymmKey(hDev, (BYTE *)key, ulAlgID, &(ctx->cipher_data))) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_INIT_KEY, ESKF_R_SKF_SET_SYMMKEY_FAILED);
		return 0;
	}
	return 1;
}

static int skf_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	ULONG rv;
	BLOCKCIPHERPARAM param;
	ULONG ulDataLen, ulEncryptedLen;
	BYTE block[MAX_IV_LEN] = {0};

	memcpy(&(param.IV), ctx->iv, ctx->cipher->block_size);
	param.IVLen = ctx->cipher->block_size;
	param.PaddingType = SKF_NO_PADDING;
	param.FeedBitLen = 0;

	if (ctx->encrypt) {
		if ((rv = SKF_EncryptInit(ctx->cipher_data, param)) != SAR_OK) {
			return 0;
		}
	} else {
		if ((rv = SKF_DecryptInit(ctx->cipher_data, param)) != SAR_OK) {
			return 0;
		}
	}

	ulDataLen = len - len % ctx->cipher->block_size;

	if (ctx->encrypt) {
		if ((rv = SKF_EncryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,
			(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
			return 0;
		}
	} else {
		if ((rv = SKF_DecryptUpdate(ctx->cipher_data, (BYTE *)in, ulDataLen,
			(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
			return 0;
		}
	}

	in += ulDataLen;
	out += ulEncryptedLen;

	memcpy(block, in, len - ulDataLen);

	if (ctx->encrypt) {
		if ((rv = SKF_EncryptUpdate(ctx->cipher_data, block, ctx->cipher->block_size,
			out, &ulEncryptedLen)) != SAR_OK) {
			return 0;
		}
	} else {
		return 0;
	}
	return 1;
}

#define BLOCK_CIPHER_generic(cipher,mode,MODE)	\
static const EVP_CIPHER skf_##cipher##_##mode = { \
	NID_##cipher##_##mode,	\
	16,16,16,		\
	EVP_CIPH_##MODE##_MODE,	\
	skf_init_key,		\
	skf_cipher,		\
	NULL,			\
	sizeof(HANDLE),		\
	NULL,NULL,NULL,NULL };


BLOCK_CIPHER_generic(ssf33,ecb,ECB)
BLOCK_CIPHER_generic(ssf33,cbc,CBC)
BLOCK_CIPHER_generic(ssf33,cfb1,CFB)
BLOCK_CIPHER_generic(ssf33,cfb8,CFB)
BLOCK_CIPHER_generic(ssf33,cfb128,CFB)
BLOCK_CIPHER_generic(ssf33,ofb128,OFB)
BLOCK_CIPHER_generic(sm1,ecb,ECB)
BLOCK_CIPHER_generic(sm1,cbc,CBC)
BLOCK_CIPHER_generic(sm1,cfb1,CFB)
BLOCK_CIPHER_generic(sm1,cfb8,CFB)
BLOCK_CIPHER_generic(sm1,cfb128,CFB)
BLOCK_CIPHER_generic(sm1,ofb128,OFB)
BLOCK_CIPHER_generic(sms4,ecb,ECB)
BLOCK_CIPHER_generic(sms4,cbc,CBC)
BLOCK_CIPHER_generic(sms4,cfb1,CFB)
BLOCK_CIPHER_generic(sms4,cfb8,CFB)
BLOCK_CIPHER_generic(sms4,cfb128,CFB)
BLOCK_CIPHER_generic(sms4,ofb128,OFB)


static int skf_cipher_nids[] = {
	NID_ssf33_ecb,
	NID_ssf33_cbc,
	NID_ssf33_cfb1,
	NID_ssf33_cfb8,
	NID_ssf33_cfb128,
	NID_ssf33_ofb128,
	NID_sm1_ecb,
	NID_sm1_cbc,
	NID_sm1_cfb1,
	NID_sm1_cfb8,
	NID_sm1_cfb128,
	NID_sm1_ofb128,
	NID_sms4_ecb,
	NID_sms4_cbc,
	NID_sms4_cfb1,
	NID_sms4_cfb8,
	NID_sms4_cfb128,
	NID_sms4_ofb128,
};

static int skf_num_ciphers = sizeof(skf_cipher_nids)/sizeof(skf_cipher_nids[0]);
static int skf_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	if (!cipher) {
		*nids = skf_cipher_nids;
		return skf_num_ciphers;
	}

	switch (nid) {

	case NID_ssf33_ecb:
		*cipher = &skf_ssf33_ecb;
		break;
	case NID_ssf33_cbc:
		*cipher = &skf_ssf33_cbc;
		break;
	case NID_ssf33_cfb128:
		*cipher = &skf_ssf33_cfb128;
		break;
	case NID_ssf33_ofb128:
		*cipher = &skf_ssf33_ofb128;
		break;
	case NID_sm1_ecb:
		*cipher = &skf_sm1_ecb;
		break;
	case NID_sm1_cbc:
		*cipher = &skf_sm1_cbc;
		break;
	case NID_sm1_cfb128:
		*cipher = &skf_sm1_cfb128;
		break;
	case NID_sm1_ofb128:
		*cipher = &skf_sm1_ofb128;
		break;
	case NID_sms4_ecb:
		*cipher = &skf_sms4_ecb;
		break;
	case NID_sms4_cbc:
		*cipher = &skf_sms4_cbc;
		break;
	case NID_sms4_cfb128:
		*cipher = &skf_sms4_cfb128;
		break;
	case NID_sms4_ofb128:
		*cipher = &skf_sms4_ofb128;
		break;

	default:
		*cipher = NULL;
		return 0;
	}

	return 1;
}


int skf_rand_bytes(unsigned char *buf, int num)
{
	ULONG rv;
	if ((rv = SKF_GenRandom(hDev, buf, (ULONG)num)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_RAND_BYTES, ESKF_R_GEN_RANDOM_FAILED);
		return 0;
	}
	return 1;
}

static RAND_METHOD skf_rand = {
	NULL,
	skf_rand_bytes,
	NULL,
	NULL,
	skf_rand_bytes,
	NULL,
};

static int skf_sm3_init(EVP_MD_CTX *ctx)
{
	ULONG rv;
	if ((rv = SKF_DigestInit(hDev, SGD_SM3, NULL, NULL, 0, &(ctx->md_data))) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_INIT, ESKF_R_SKF_DIGEST_INIT_FAILED);
		return 0;
	}
	return 1;
}

static int skf_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	ULONG rv;
	BYTE *pbData = (BYTE *)data;
	ULONG ulDataLen = (ULONG)count;

	if ((rv = SKF_DigestUpdate(ctx->md_data, pbData, ulDataLen)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_UPDATE, ESKF_R_SKF_DIGEST_UPDATE_FAILED);
		return 0;
	}

	return 1;
}

static int skf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	ULONG rv;
	BYTE *pHashData = (BYTE *)md;
	ULONG ulHashLen = SM3_DIGEST_LENGTH;

	if ((rv = SKF_DigestFinal(ctx->md_data, pHashData, &ulHashLen)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_FINAL, ESKF_R_SKF_DIGEST_FINAL_FAILED);
		return 0;
	}
	if ((rv = SKF_CloseHandle(ctx->md_data)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_SM3_FINAL, ESKF_R_SKF_CLOSE_HANDLE_FAILED);
		return 0;
	}

	ctx->md_data = NULL;
	return 1;
}

static const EVP_MD skf_sm3 = {
	NID_sm3,
	0,
	SM3_DIGEST_LENGTH,
	0,
	skf_sm3_init,
	skf_sm3_update,
	skf_sm3_final,
	NULL,
	NULL,
	EVP_PKEY_NULL_method,
	SM3_BLOCK_SIZE,
	sizeof(EVP_MD *) + sizeof(HANDLE),
	NULL,
};

static int skf_digest_nids[] = { NID_sm3, };
static int skf_num_digests = sizeof(skf_digest_nids)/sizeof(skf_digest_nids[0]);

static int skf_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	if (!digest) {
		*nids = skf_digest_nids;
		return skf_num_digests;
	}

	switch (nid) {
	case NID_sm3:
		*digest = &skf_sm3;
		break;
	default:
		*digest = NULL;
		return 0;
	}

	return 1;
}


static int skf_rsa_sign(int type, const unsigned char *m, unsigned int mlen,
	unsigned char *sig, unsigned int *siglen, const RSA *rsa)
{
	ULONG rv;
	BYTE *data = (BYTE *)m;
	ULONG dataLen = (ULONG)mlen;
	BYTE signature[1024];
	ULONG sigLen;

	/* we need to check if container type is RSA */

	sigLen = (ULONG)sizeof(signature);
	if ((rv = SKF_RSASignData(hContainer, data, dataLen, signature, &sigLen)) != SAR_OK) {
		ESKFerr(ESKF_F_SKF_RSA_SIGN, ESKF_R_SIGN_FAILED);
		return 0;
	}

	/* do we need to convert signature format? */
	memcpy(sig, signature, sigLen);
	*siglen = (unsigned int)sigLen;
	return 1;
}

static RSA_METHOD skf_rsa = {
	"SKF RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	RSA_FLAG_SIGN_VER,
	NULL,
	skf_rsa_sign,
	NULL,
	NULL,
};

static ECDSA_METHOD skf_sm2sign = {
	"SKF ECDSA method (SM2 signature)",
	NULL,
	NULL,
	NULL,
	0,
	NULL,
};



static ECDSA_SIG *skf_sm2_do_sign(const unsigned char *dgst, int dgstlen,
	const BIGNUM *a, const BIGNUM *b, EC_KEY *ec_key)
{
	ECDSA_SIG *ret = NULL;
	BYTE *pbDigest = (BYTE *)dgst;
	ULONG ulDigestLen = (ULONG)dgstlen;
	ECCSIGNATUREBLOB sigBlob;
	ULONG rv;
	int ok = 0;

	if (a || b) {
	}
	if ((rv = SKF_ECCSignData(hContainer, pbDigest, ulDigestLen, &sigBlob)) != SAR_OK) {
		goto end;
	}
	if (!(ret = ECDSA_SIG_new())) {
		goto end;
	}
	if (!ECDSA_SIG_set_ECCSIGNATUREBLOB(ret, &sigBlob)) {
		goto end;
	}

	ok = 1;
end:
	if (!ok && ret) {
		ECDSA_SIG_free(ret);
		ret = NULL;
	}

	return ret;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_skf(void)
{
	ENGINE *ret = ENGINE_new();
	if (!ret) {
		return NULL;
	}

	if (!bind_helper(ret)) {
		ENGINE_free(ret);
		return NULL;
	}


	return ret;
}

void ENGINE_load_skf(void)
{
	ENGINE *e_skf = engine_skf();
	if (!e_skf) {
		return;
	}

	ENGINE_add(e_skf);
	ENGINE_free(e_skf);
	ERR_clear_error();
}
#endif

static const char *engine_skf_id = "SKF";
static const char *engine_skf_name = "SKF API Hardware Engine";

static int bind(ENGINE *e, const char *id)
{
	if (id && strcmp(id, engine_skf_id)) {
		return 0;
	}

	if (!ENGINE_set_id(e, engine_skf_id) ||
		!ENGINE_set_name(e, engine_skf_name) ||
		!ENGINE_set_init_function(e, skf_init) ||
		!ENGINE_set_finish_function(e, skf_finish) ||
		!ENGINE_set_ctrl_function(e, skf_engine_ctrl) ||
		!ENGINE_set_destroy_function(e, NULL) || //FIXME
		!ENGINE_set_digests(e, skf_digests) ||
		!ENGINE_set_ciphers(e, skf_ciphers) ||
		!ENGINE_set_load_pubkey_function(e, skf_load_pubkey) ||
		!ENGINE_set_ECDSA(e, NULL) || //FIXME
		!ENGINE_set_RSA(e, &skf_rsa) ||
		!ENGINE_set_RAND(e, &skf_rand)) {

		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind);
IMPLEMENT_DYNAMIC_CHECK_FN();
