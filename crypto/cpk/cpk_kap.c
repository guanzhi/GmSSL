#include <openssl/evp.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include "cpk.h"

int CPK_PUBLIC_PARAMS_compute_share_key(CPK_PUBLIC_PARAMS *params,
	void *out, size_t outlen, const char *id, EVP_PKEY *priv_key,
	void *(*kdf)(const void *in, size_t inlen, void *out, size_t *outlen))
{
	int ret = 0;
	EVP_PKEY *pub_key = NULL;
	int pkey_type = OBJ_obj2nid(params->pkey_algor->algorithm);

	OPENSSL_assert(kdf != NULL);

	printf("%d\n", __LINE__);
	if (EVP_PKEY_id(priv_key) != pkey_type) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY,
			ERR_R_MALLOC_FAILURE); //FIXME: ERR_R_XXX
		goto err;
	}
	if (!(pub_key = CPK_PUBLIC_PARAMS_extract_public_key(params, id))) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY,
			ERR_R_MALLOC_FAILURE); //FIXME: ERR_R_XXX
		goto err;
	}
	if (pkey_type == EVP_PKEY_EC) {

		if (!ECDH_compute_key(out, outlen,
			EC_KEY_get0_public_key((EC_KEY *)EVP_PKEY_get0(pub_key)),
			(EC_KEY *)EVP_PKEY_get0(priv_key), kdf)) {
			CPKerr(CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY,
				ERR_R_MALLOC_FAILURE); //FIXME: ERR_R_XXX
			goto err;
		}
	} else if (pkey_type == EVP_PKEY_DH) {
		// not supported yet
		goto err;	
	}

	
	ret = 1;
err:
	return ret;
}

