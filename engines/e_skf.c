#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
#include "skf/skf.h"
#include "e_skf_err.h"

static DEVHANDLE skf_dev_handle = NULL;
static HAPPLICATION skf_app_handle = NULL;
static HCONTAINER skf_container_handle = NULL;


static int skf_init(ENGINE *e);
static int skf_finish(ENGINE *e);
static int skf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));
static int skf_destroy(ENGINE *e);


#define SKF_CMD_LIST_DEVS	ENGINE_CMD_BASE




static int skf_init(ENGINE *e)
{
	ULONG rv;
	ULONG len;
	BOOL bPresent = TRUE;
	CHAR *devNameList = NULL;
	LPSTR devName;
	ULONG devState;
	DEVINFO devInfo;
	BYTE authData[16];

	CHAR appNameList[256];
	LPSTR appName;
	HAPPLICATION hApp;

	CHAR containerNameList[256];
	LPSTR containerName; 
	HCONTAINER hContainer;
	ULONG containerType;

	if ((rv = SKF_EnumDev(bPresent, NULL, &len)) != SAR_OK) {
		SKFerr(SKF_F_SKF_INIT, skf_err2openssl(rv));
		goto end;
	}
	if (!(devNameList = OPENSSL_malloc(len))) {
		goto end;
	}
	if ((rv = SKF_EnumDev(bPresent, devNameList, &len)) != SAR_OK) {
		goto end;
	}
	if (devNameList[0] = 0) {
		return -1;
	}
	devName = devNameList;

	if ((rv = SKF_ConnectDev(devName, &hDev)) != SAR_OK) {
		return -1;
	}
	if ((rv = SKF_GetDevInfo(hDev, &devInfo)) != SAR_OK) {
		return -1;
	}
	if ((rv = SKF_DevAuth(hDev, authData, sizeof(authData))) != SAR_OK) {
		return -1;
	}
	
	if ((rv = SKF_EnumApplication(hDev, NULL, &len)) != SAR_OK) {
		return -1;
	}
	if (!(appNameList = OPENSSL_malloc(len))) {
		return -1;
	}
	if ((rv = SKF_EnumApplication(hDev, appNameList, &len)) != SAR_OK) {
		return -1;
	}
	if (appNameList[0] = 0) {
		return -1;
	}
	appName = appNameList;

	if ((rv = SKF_OpenApplication(hDev, appName, &hApp)) != SAR_OK) {
		return -1;
	}

	for (p = containerNameList; p; p += strlen(p)) {
		// check container type
	}
	return 0;
}

static int skf_finish(ENGINE *e)
{	
	return 0;
}


typedef struct {
	HANDLE hKey;
} EVP_SKF_KEY;


static int skf_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	EVP_SKF_KEY *dat = (EVP_SKF_KEY *)ctx->cipher_data;
	ULONG ulAlgID;

	switch (EVP_CIPHER_CTX_nid(ctx)) {
	case NID_ssf33_ecb:
		ulAlgID = SGD_SSF33_ECB;
		break;
	case NID_ssf33_cbc:	
		ulAlgID = SGD_SSF33_CBC;
		break;
	case NID_ssf33_cfb128:
		ulAlgID = SGD_SSF33_CFB;
		break;
	case NID_ssf33_ofb128:
		ulAlgID = SGD_SSF33_OFB;
		break;

	case NID_sm1_ecb:
		ulAlgID = SGD_SM1_ECB;
		break;
	case NID_sm1_cbc:
		ulAlgID = SGD_SM1_CBC;
		break;
	case NID_sm1_cfb128:
		ulAlgID = SGD_SM1_CFB;
		break;
	case NID_sm1_ofb128:
		ulAlgID = SGD_SM1_OFB;
		break;

	case NID_sms4_ecb:
		ulAlgID = SGD_SM4_ECB;
		break;
	case NID_sms4_cbc:
		ulAlgID = SGD_SM4_CBC;
		break;
	case NID_sms4_cfb128:
		ulAlgID = SGD_SM4_CFB;
		break;
	case NID_sms4_ofb128:
		ulAlgID = SGD_SM4_OFB;
		break;

	default:
		OPENSSL_assert(0);
		return 0;
	}

	if ((rv = SKF_SetSymmKey(skf_dev_handle, (BYTE *)key, ulAlgID,
		&(dat->hKey))) != SAR_OK) {
		SKFerr(SKF_F_SKF_INIT_KEY, 0);
		return 0;
	}

	return 1;
}

static int skf_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	ULONG rv;
	EVP_SKF_KEY *dat = (EVP_SKF_KEY *)ctx->cipher_data;
	BLOCKCIPHERPARAM param;
	ULONG ulDataLen, ulEncryptedLen;
	BYTE block[MAX_IV_LEN] = {0};
	int i;

	memcpy(&(param.IV), ctx->iv, ctx->cipher->block_size);
	param.IVLen = ctx->cipher->block_size;
	param.PaddingType = SKF_NO_PADDING;
	param.FeedBitLen = 0;

	if (ctx->encrypt) {
		if ((rv = SKF_EncryptInit(dat->hKey, &param)) != SAR_OK) {
			return 0;
		}
	} else {
		if ((rv = SKF_DecryptInit(dat->hKey, &param)) != SAR_OK) {
			return 0;
		}
	}

	ulDataLen = len - len % ctx->cipher->block_size;

	if (ctx->encrypt) {
		if ((rv = SKF_EncryptUpdate(hKey, in, ulDataLen,
			(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
			return 0;
		}
	} else {
		if ((rv = SKF_DecryptUpdate(hKey, in, ulDataLen,
			(BYTE *)out, &ulEncryptedLen)) != SAR_OK) {
			return 0;
		}
	}

	in += ulDataLen;
	out += ulEncryptedLen;

	memcpy(block, in, len - ulDataLen);

	if (ctx->encrypt) {
		if ((rv = SKF_EncryptUpdate(hKey, block, ctx->cipher->block_size,
			out, &ulEncryptedLen)) != SAR_OK) {
			return 0;
		}
	} else {

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
	sizeof(EVP_SKF_KEY),	\
	NULL,NULL,NULL,NULL };


BLOCK_CIPHER_generic(ssf33,ecb,ECB)
BLOCK_CIPHER_generic(ssf33,cbc,CBC)
BLOCK_CIPHER_generic(ssf33,cfb,CFB)
BLOCK_CIPHER_generic(ssf33,ofb,OFB)
BLOCK_CIPHER_generic(sm1,ecb,ECB)
BLOCK_CIPHER_generic(sm1,cbc,CBC)
BLOCK_CIPHER_generic(sm1,cfb,CFB)
BLOCK_CIPHER_generic(sm1,ofb,OFB)
BLOCK_CIPHER_generic(sm4,ecb,ECB)
BLOCK_CIPHER_generic(sm4,cbc,CBC)
BLOCK_CIPHER_generic(sm4,cfb,CFB)
BLOCK_CIPHER_generic(sm4,ofb,OFB)


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

	if ((rv = SKF_GenRandom(skf_dev_handle, buf, (ULONG)num)) != SAR_OK) {
		SKFerr(SKF_F_SKF_RAND_BYTES, skf_err2openssl(rv));
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
	DEVHANDLE hDev = skf_dev_handle;
	HANDLE hHash;

	if ((rv = SKF_DigestInit(hDev, SGD_SM3, NULL, NULL, 0,
		(HANDLE *)&ctx->md_data)) != SAR_OK) {
		SKFerr(SKF_F_SM3_INIT, skf_err2openssl(rv));
		return 0;
	}

	return 1;
}

static int skf_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	ULONG rv;
	BYTE *pbData = (BYTE *)data;
	ULONG ulDataLen = (ULONG)count;

	if ((rv = SKF_DigestUpdate((HANDLE)ctx->md_data, pbData, ulDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_SM3_UPDATE, skf_err2openssl(rv));
		return 0;
	}

	return 1;
}

static int skf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	ULONG rv;
	BYTE *pHashData = (BYTE *)md;
	ULONG ulHashLen = SM3_DIGEST_LENGTH;

	if ((rv = SKF_DigestFinal(hHash, pHashData, &ulHashLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_SM3_FINAL, skf_err2openssl(rv));
		return 0;
	}

	if ((rv = SKF_CloseHandle(hHash)) != SAR_OK) {
		SKFerr(SKF_F_SKF_SM3_FINAL, skf_err2openssl(rv));
		return 0;
	}

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


static RSA_METHOD skf_rsa = {
	"SKF RSA method",
	skf_rsa_pub_enc,
	NULL,
	NULL,
	skf_rsa_priv_dec,
	NULL,
	NULL,
	NULL,
	NULL,
	RSA_FLAG_SIGN_VER,
	NULL,
	skf_rsa_sign,
	skf_rsa_verify,
	NULL
};



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

void ENGINE_load_4758cca(void)
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
		!ENGINE_set_digests(e, skf_digests) ||
		!ENGINE_set_ciphers(e, skf_ciphers) ||
		!ENGINE_set_RAND(e, &skf_random)) {
		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind);
IMPLEMENT_DYNAMIC_CHECK_FN();

