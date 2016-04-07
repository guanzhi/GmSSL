#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/sm1.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sms4.h>
#include <openssl/ssf33.h>
#include "skf.h"
#include "e_skf_err.h"

static DEVHANDLE skf_dev_handle = NULL;
static HAPPLICATION skf_app_handle = NULL;
static HCONTAINER skf_container_handle = NULL;


static int skf_init(ENGINE *e)
{
	ULONG rv;
	ULONG len;
/*
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
		return -1;
	}
	if (!(devNameList = OPENSSL_malloc(len))) {
		return -1;
	}
	if ((rv = SKF_EnumDev(bPresent, devNameList, &len)) != SAR_OK) {
		return -1;
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
*/
	return 0;
}

static int skf_finish(ENGINE *e)
{	
	return 0;
}

#if 0
void ENGINE_load_skf(void)
{
}

static int skf_bind_helper(ENGINE *e)
{
	if (!ENGINE_set_id(e, SKF_ENGINE_ID) ||
	    !ENGINE_set_name(e, SKF_ENGINE_NAME) ||
	    !ENGINE_set_init_function(e, skf_init) ||
	    !ENGINE_set_ciphers(e, skf_ciphers) ||
	    !ENGINE_set_RSA(e, SKF_get_rsa_method()) ||
	    !ENGINE_set_SM2(e, SKF_get_sm2_method()) ||
	    !ENGINE_set_RAND(e, skf_rand)) {
		return 0;
	}

	return 1;
}

static ENGINE *ENGINE_skf(void)
{
	ENGINE *eng = ENGINE_new();

	if (!eng) {
		return NULL;
	}

	if (!skf_bind_helper(eng)) {
		ENGINE_free(eng);
		return NULL;
	}

	return eng;
}

static int skf_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
	const int **nids, int nid)
{
	if (!cipher) {
		*nid = skf_cipher_nids;
		return skf_num_cipher_nids;	
	}

	switch (nid) {
	case NID_ssf33_ecb:
		*cipher = &skf_ssf33_ecb;
		break;
	default:
		*cipher = NULL;
		return 0;
	}

	return 1;
}

#endif


#define SSF33_IV_LENGTH		SSF33_BLOCK_SIZE
#define SM1_IV_LENGTH		SM1_BLOCK_SIZE
#define SMS4_IV_LENGTH		SMS4_BLOCK_SIZE


static int skf_ssf33_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	DEVHANDLE hDev = skf_dev_handle;
	BYTE *pbKey = key;
	ULONG ulAlgID = SGD_SSF33_ECB;
	HANDLE *phKey;

	if ((rv = SKF_SetSymmKey(hDev, pbKey, ulAlgID, (HANDLE *)ctx->cipher_data)) != SAR_OK) {
		SKFerr(SKF_F_SKF_SSF33_INIT_KEY, 0);
		return 0;
	}

	return 1;
}

static const EVP_CIPHER skf_ssf33_ecb = {
	NID_ssf33_ecb,
	SSF33_BLOCK_SIZE,
	SSF33_KEY_LENGTH,
	SSF33_IV_LENGTH,
	0,
	skf_ssf33_init_key,
	skf_ssf33_ecb_cipher,
	NULL,
	sizeof(EVP_SMS4_CTX),
	NULL,
	NULL,
	NULL,
	NULL,
};

static int skf_cipher_nids[] = {
	NID_ssf33_ecb,
	NID_ssf33_cbc,
	NID_ssf33_cfb128,
	NID_ssf33_ofb128,
	NID_sm1_ecb,
	NID_sm1_cbc,
	NID_sm1_cfb128,
	NID_sm1_ofb128,
	NID_sms4_ecb,
	NID_sms4_cbc,
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

int skf_err2openssl(ULONG rv)
{
	return 0;
}


/* RAND_METHOD */

int skf_rand_bytes(unsigned char *buf, int num)
{
	ULONG rv;

	if ((rv = SKF_GenRandom(skf_dev_handle, buf, num)) != SAR_OK) {
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

/* EVP_MD */

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

/* Dynamic ENGINE */

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
		//!ENGINE_set_ciphers(e, skf_ciphers) ||
		!ENGINE_set_RAND(e, &skf_random)) {
		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind);
IMPLEMENT_DYNAMIC_CHECK_FN();

