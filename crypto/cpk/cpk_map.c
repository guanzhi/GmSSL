#include <string.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "cpk.h"

X509_ALGOR *CPK_MAP_new_default()
{
	X509_ALGOR *algor = NULL;
	const EVP_MD *md = EVP_sha1();
	
	if (md != EVP_sha1() && md != EVP_sha384()) {
		CPKerr(CPK_F_CPK_MAP_NEW_DEFAULT, CPK_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(algor = X509_ALGOR_new())) {
		CPKerr(CPK_F_CPK_MAP_NEW_DEFAULT, ERR_R_X509_LIB);
		goto end;
	}
	if (!X509_ALGOR_set0(algor, OBJ_nid2obj(EVP_MD_nid(md)), 
		V_ASN1_UNDEF, NULL)) {
		X509_ALGOR_free(algor);
		algor = NULL;
		CPKerr(CPK_F_CPK_MAP_NEW_DEFAULT, ERR_R_X509_LIB);
		goto end;
	}
end:
	return algor;
}

int CPK_MAP_is_valid(const X509_ALGOR *algor)
{
	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	switch (OBJ_obj2nid(algor->algorithm)) {
	case NID_sha1:
	case NID_sha384:
		return 1;
	}
	return 0;
}

int CPK_MAP_num_subset(const X509_ALGOR *algor)
{
	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	switch (OBJ_obj2nid(algor->algorithm)) {
	case NID_sha1:
		return 32;
	case NID_sha384:
		return 4096;
	}
	return -1;
}

int CPK_MAP_num_factors(const X509_ALGOR *algor)
{
	return 1024;
}

int CPK_MAP_num_indexes(const X509_ALGOR *algor)
{
	return 32;
}

int CPK_MAP_num_index(const X509_ALGOR *algor)
{
	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	switch (OBJ_obj2nid(algor->algorithm)) {
	case NID_sha1:
		return 32;
	case NID_sha384:
		return 32;
	}
	return -1;
}

int CPK_MAP_str2index(const X509_ALGOR *algor, const char *str, int *index)
{
	int ret = 0;
	const EVP_MD *md;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	BIGNUM *bn = NULL;
	int i, num_index, num_subset;
	
	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	OPENSSL_assert(str);
	OPENSSL_assert(strlen(str) > 0);
	
	if (!CPK_MAP_is_valid(algor)) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, CPK_R_INVALID_MAP_ALGOR);
		goto err;
	}
	if (!index) {
		ret = CPK_MAP_num_index(algor);
		goto err;
	}
	if (!(md = EVP_get_digestbyobj(algor->algorithm))) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_EVP_LIB);
		goto err;
	}
	if (!EVP_Digest(str, strlen(str), dgst, &dgstlen, md, NULL)) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_EVP_LIB);
		return 0;
	}
	if (!(bn = BN_new())) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_BN_LIB);
		goto err;
	}
	if (!BN_bin2bn(dgst, dgstlen, bn)) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_BN_LIB);
		goto err;
	}
	num_index = CPK_MAP_num_index(algor);
	num_subset = CPK_MAP_num_subset(algor);
	
	for (i = 0; i < num_index; i++) {
		int r = BN_mod_word(bn, num_subset);
		index[i] = num_subset * i + r;
	}
	ret = num_index;
err:	
	if (bn) BN_free(bn);
	return ret;
}

