#include <stdio.h>



#define SKF_ENGINE_ID	"skf"
#define SKF_ENGINE_NAME	"skf engine"



static int skf_init(ENGINE *e)
{
	ULONG rv;

	rv = SKF_EnumDev(TRUE, szNameList, &ulSize);
	rv = SKF_ConnectDev(szName, &hDev);
	rv = SKF_DevAuth(hDev, pbAuthData, ulLen);
	rv = SKF_EnumApplication(hDev, szAppName, &ulSize);
	rv = SKF_OpenApplication(hDev, szAppName, &hApp);

	rv = SKF_SetSymmKey(hDev, pbKey, ulAlgID, &hKey);
	
	rv = SKF_EncryptInit(hKey, encParam);
}



static int skf_finish(ENGINE *e)
{
	
}

void ENGINE_load_skf(void)
{
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


static int skf_cipher_nids[] = {
	NID_ssf33_ecb,
	NID_ssf33_cbc,
	NID_ssf33_cfb,
	NID_ssf33_ofb,
	NID_sm1_ecb,
	NID_sm1_cbc,
	NID_sm1_cfb,
	NID_sm1_ofb,
	NID_sm4_ecb,
	NID_sm4_cbc,
	NID_sm4_cfb,
	NID_sm4_ofb,
};

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


static RAND_METHOD skf_rand = {
	NULL,		/* seed */
	skf_rand_bytes,	/* bytes */
	NULL,		/* cleanup */
	NULL,		/* add */
	skf_rand_bytes,	/* pseudorand */
	NULL,		/* rand status */
};



static int bind_fn(ENGINE *e, const char *id)
{
	if (id && (strcmp(id, SKF_ENGINE_ID) != 0)) {
		fprintf(stderr, "bad engine id\n");
		return 0;
	}
	if (!bind_helper(e)) {
		return 0;
	}

	return 1;
}



IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn);

