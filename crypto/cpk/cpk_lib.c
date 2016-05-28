/* crypto/cpk/cpk_lib.c */
/* ====================================================================
 * Copyright (c) 2007 - 2015 The GmSSL Project.  All rights reserved.
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

#include <string.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include "cpk.h"


static DSA *X509_ALGOR_get1_DSA(X509_ALGOR *algor);
static int extract_dsa_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *param);
static DSA *extract_dsa_priv_key(CPK_MASTER_SECRET *master, const char *id);
static DSA *extract_dsa_pub_key(CPK_PUBLIC_PARAMS *param, const char *id);

static EC_KEY *X509_ALGOR_get1_EC_KEY(X509_ALGOR *algor);
static int extract_ec_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *param);
static EC_KEY *extract_ec_priv_key(CPK_MASTER_SECRET *master, const char *id);
static EC_KEY *extract_ec_pub_key(CPK_PUBLIC_PARAMS *param, const char *id);



CPK_MASTER_SECRET *CPK_MASTER_SECRET_create(const char *domain_id,
	EVP_PKEY *pkey, X509_ALGOR *map_algor)
{
	int e = 1;
	CPK_MASTER_SECRET *master = NULL;
	BIGNUM *bn = NULL, *order = NULL;
	X509_PUBKEY *pubkey = NULL;
	int pkey_type;
	int i, bn_size, num_factors;
	unsigned char *bn_ptr;
	
	if (strlen(domain_id) <= 0 || strlen(domain_id) > CPK_MAX_ID_LENGTH) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, CPK_R_INVALID_ID_LENGTH);
		goto err;
	}
	
	pkey_type = EVP_PKEY_id(pkey);
	if (pkey_type == EVP_PKEY_DSA) {
		if (!(order = ((DSA *)EVP_PKEY_get0(pkey))->q)) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, CPK_R_BAD_ARGUMENT);
			goto err;
		}
	} else if (pkey_type == EVP_PKEY_EC) {
		const EC_GROUP *ec_group;
		if (!(order = BN_new())) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_MALLOC_FAILURE);
			goto err;
		}
		ec_group = EC_KEY_get0_group((EC_KEY *)EVP_PKEY_get0(pkey));
		if (!EC_GROUP_get_order(ec_group, order, NULL)) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_X509_LIB);
			goto err;
		}
		//FIXME OPENSSL_assert
		assert(EC_KEY_get0_public_key((EC_KEY *)EVP_PKEY_get0(pkey)) != NULL);
	} else {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, CPK_R_INVALID_PKEY_TYPE);
		goto err;		
	}

	if (!(master = CPK_MASTER_SECRET_new())) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	
	master->version = 1;
	if (!X509_NAME_add_entry_by_NID(master->id, NID_organizationName,
		MBSTRING_UTF8, (unsigned char *)domain_id, -1, -1, 0)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_X509_LIB);
		goto err;
	}
	
	/* 
	 * convert EVP_PKEY to X509_ALGOR through X509_PUBKEY_set
	 * X509_ALGOR_set0() is another choice but require more code
	 */
	// FIXME: X509_PUBKEY require pkey has a public key
	if (!X509_PUBKEY_set(&pubkey, pkey)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_X509_LIB);
		goto err;
	}
	X509_ALGOR_free(master->pkey_algor);
	if (!(master->pkey_algor = X509_ALGOR_dup(pubkey->algor))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_X509_LIB);
		goto err;
	}
		
	//FIXME: check the validity of CPK_MAP
	X509_ALGOR_free(master->map_algor);
	if (!(master->map_algor = X509_ALGOR_dup(map_algor))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if ((num_factors = CPK_MAP_num_factors(map_algor)) <= 0) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, CPK_R_INVALID_MAP_ALGOR);
		goto err;
	}
	
	/*
	 * create secret factors, for both DSA and EC,
	 * the private keys are both big integers, 
	 */
	bn_size = BN_num_bytes(order);
	if (!ASN1_STRING_set(master->secret_factors, NULL, bn_size * num_factors)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_ASN1_LIB);
		goto err;
	}
	bn_ptr = M_ASN1_STRING_data(master->secret_factors);
	memset(bn_ptr, 0, M_ASN1_STRING_length(master->secret_factors));
	
	if (!(bn = BN_new())) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	for (i = 0; i < num_factors; i++) {
		do {
			if (!BN_rand_range(bn, order)) {
				CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE,
					ERR_R_RAND_LIB);
				goto err;
			}
		} while (BN_is_zero(bn));
		
		if (!BN_bn2bin(bn, bn_ptr + bn_size - BN_num_bytes(bn))) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_BN_LIB);
			goto err;
		}
		bn_ptr += bn_size;
	}
	
	e = 0;
err:
	if (e && master) {
		CPK_MASTER_SECRET_free(master);
		master = NULL;
	}
	if (pubkey) X509_PUBKEY_free(pubkey);
	if (order && pkey_type == EVP_PKEY_EC) BN_free(order);
	if (bn) BN_free(bn);
	return master;
}

CPK_PUBLIC_PARAMS *CPK_MASTER_SECRET_extract_public_params(CPK_MASTER_SECRET *master)
{
	CPK_PUBLIC_PARAMS *param = NULL;
	int pkey_type;
	pkey_type = OBJ_obj2nid(master->pkey_algor->algorithm);
	
	
	if (!(param = CPK_PUBLIC_PARAMS_new())) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}
	
	param->version = master->version;
	
	X509_NAME_free(param->id);
	if (!(param->id = X509_NAME_dup(master->id))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}
	
	X509_ALGOR_free(param->pkey_algor);
	if (!(param->pkey_algor = X509_ALGOR_dup(master->pkey_algor))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}
		
	X509_ALGOR_free(param->map_algor);
	if (!(param->map_algor = X509_ALGOR_dup(master->map_algor))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}
	
	switch (pkey_type) {
	case EVP_PKEY_DSA:
		if (!extract_dsa_params(master, param)) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
				ERR_R_CPK_LIB);
			goto err;
		}
		break;
	
	case EVP_PKEY_EC:
		if (!extract_ec_params(master, param)) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
				ERR_R_CPK_LIB);
			goto err;
		}
		break;

	default:
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS, CPK_R_INVALID_PKEY_TYPE);
		goto err;
	}
	return param;
	
err:
	if (param) CPK_PUBLIC_PARAMS_free(param);
	return NULL;
}

EVP_PKEY *CPK_MASTER_SECRET_extract_private_key(
	CPK_MASTER_SECRET *master, const char *id)
{
	EVP_PKEY *pkey = NULL;
	int pkey_type;
	
	if (!(pkey = EVP_PKEY_new())) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}	
	
	pkey_type = OBJ_obj2nid(master->pkey_algor->algorithm);
	
	if (pkey_type == EVP_PKEY_DSA) {
		DSA *dsa;
		if (!(dsa = extract_dsa_priv_key(master, id))) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
				ERR_R_CPK_LIB);
			goto err;
		}
		if (!EVP_PKEY_assign_DSA(pkey, dsa)) {
			DSA_free(dsa);
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
				ERR_R_EVP_LIB);
			goto err;
		}
	
	} else if (pkey_type == EVP_PKEY_EC) {
		EC_KEY *ec_key;
		if (!(ec_key = extract_ec_priv_key(master, id))) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
				ERR_R_CPK_LIB);
			goto err;
		}
		if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
			EC_KEY_free(ec_key);
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
				ERR_R_EVP_LIB);
			goto err;
		}
	
	} else {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
			CPK_R_INVALID_PKEY_TYPE);
		goto err;
	}
	
	/*
	 * add id to EVP_PKEY attributes
	 */
	/*
	if(!X509_NAME_get_text_by_NID(master->id, NID_organizationName,
		domain_id, sizeof(domain_id))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
			ERR_R_X509_LIB);
		goto err;
	}
	if (!EVP_PKEY_add1_attr_by_NID(pkey, NID_organizationName, V_ASN1_PRINTABLESTRING,
		(const unsigned char *)domain_id, strlen(domain_id))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY, ERR_R_EVP_LIB);
		goto err;
	}
	if (!EVP_PKEY_add1_attr_by_NID(pkey, NID_commonName, V_ASN1_PRINTABLESTRING,
		(const unsigned char *)id, strlen(id))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
			ERR_R_EVP_LIB);
		goto err;
	}
	*/

	return pkey;

err:
	if (pkey) EVP_PKEY_free(pkey);
	return NULL;
}

EVP_PKEY *CPK_PUBLIC_PARAMS_extract_public_key(CPK_PUBLIC_PARAMS *param,
	const char *id)
{
	EVP_PKEY *pkey = NULL;
	int pkey_type;
	//char domain_id[CPK_MAX_ID_LENGTH + 1];
	
	if (!(pkey = EVP_PKEY_new())) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}
	
	pkey_type = OBJ_obj2nid(param->pkey_algor->algorithm);
	
	if (pkey_type == EVP_PKEY_DSA) {
		DSA *dsa = NULL;
		if (!(dsa = extract_dsa_pub_key(param, id))) {
			CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
				ERR_R_CPK_LIB);
			goto err;
		}
		if (!EVP_PKEY_assign_DSA(pkey, dsa)) {
			DSA_free(dsa);
			CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
				ERR_R_EVP_LIB);
			goto err;
		}
	
	} else if (pkey_type == EVP_PKEY_EC) {
		EC_KEY *ec_key = NULL;
		if (!(ec_key = extract_ec_pub_key(param, id))) {
			CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
				ERR_R_CPK_LIB);
			goto err;
		}
		if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
			EC_KEY_free(ec_key);
			CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
				ERR_R_EVP_LIB);
			goto err;
		}
	
	} else {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
			CPK_R_INVALID_PKEY_TYPE);
		goto err;
	}
	
	/*
	 * add id to EVP_PKEY attributes
	 */
	/*
	if(!X509_NAME_get_text_by_NID(param->id, NID_organizationName, 
		domain_id, sizeof(domain_id) - 1)) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
			ERR_R_X509_LIB);
		goto err;
	}
	if (!EVP_PKEY_add1_attr_by_NID(pkey, NID_organizationName, MBSTRING_UTF8,
		(const unsigned char *)domain_id, strlen(domain_id))) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
			ERR_R_X509_LIB);
		goto err;
	}
	if (!EVP_PKEY_add1_attr_by_NID(pkey, NID_commonName,
		MBSTRING_UTF8, (const unsigned char *)id, strlen(id))) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
			ERR_R_X509_LIB);
		goto err;
	}
	*/
	return pkey;
	
err:
	if (pkey) EVP_PKEY_free(pkey);
	return NULL;
}

int CPK_MASTER_SECRET_digest(CPK_MASTER_SECRET *master, const EVP_MD *md,
	unsigned char *dgst, unsigned int *dgstlen)
{
	if (!EVP_Digest(M_ASN1_STRING_data(master->secret_factors),
		M_ASN1_STRING_length(master->secret_factors),
		dgst, dgstlen, md, NULL)) {
		return 0;
	}
	return 1;
}

int CPK_PUBLIC_PARAMS_digest(CPK_PUBLIC_PARAMS *params, const EVP_MD *md,
	unsigned char *dgst, unsigned int *dgstlen)
{
	if (!EVP_Digest(M_ASN1_STRING_data(params->public_factors),
		M_ASN1_STRING_length(params->public_factors),
		dgst, dgstlen, md, NULL)) {
		return 0;
	}
	return 1;
}

char *CPK_MASTER_SECRET_get_name(CPK_MASTER_SECRET *master, char *buf, int size)
{
	return X509_NAME_oneline(master->id, buf, size);
}

char *CPK_PUBLIC_PARAMS_name(CPK_PUBLIC_PARAMS *params, char *buf, int size)
{
	return X509_NAME_oneline(params->id, buf, size);
}

int CPK_MASTER_SECRET_validate_public_params(CPK_MASTER_SECRET *master,
	CPK_PUBLIC_PARAMS *params)
{
	int ret = 0;
	CPK_PUBLIC_PARAMS *tmp = NULL;
	
	if (!(tmp = CPK_MASTER_SECRET_extract_public_params(master))) {
		fprintf(stderr, "shit1\n");
		goto err;
	}	
	if (tmp->version != params->version) {
		fprintf(stderr, "shit2\n");
		goto err;
	}
	if (X509_NAME_cmp(tmp->id, params->id)) {
		fprintf(stderr, "shit3\n");
		goto err;
	}

	/*
	 * two ASN_OBJECT * with different address may have same NID
	 * thus we can not check with:
	 * tmp->pkey_algor->algorithm != params->pkey_algor->algorithm
	 */
	if (OBJ_obj2nid(tmp->pkey_algor->algorithm) != 
	    OBJ_obj2nid(params->pkey_algor->algorithm)) {
		fprintf(stderr, "shit4\n");	
		goto err;
	}
	// FIXME: pkey_algor->parameters
	if (OBJ_obj2nid(tmp->map_algor->algorithm) != 
	    OBJ_obj2nid(params->map_algor->algorithm)) {
		fprintf(stderr, "shit5\n");
		goto err;
	}
	if (ASN1_STRING_cmp(tmp->public_factors, params->public_factors)) {
		fprintf(stderr, "shit6\n");
		goto err;
	}

	ret = 1;
err:
	if (tmp) CPK_PUBLIC_PARAMS_free(tmp);
	return ret;
}

int CPK_PUBLIC_PARAMS_validate_private_key(CPK_PUBLIC_PARAMS *params,
	const char *id, const EVP_PKEY *priv_key)
{
	int ret = -3;
	EVP_PKEY *pub_key = NULL;
	
	if (!(pub_key = CPK_PUBLIC_PARAMS_extract_public_key(params, id))) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_VALIDATE_PRIVATE_KEY,
			ERR_R_EVP_LIB);
		goto err;
	}
	ret = EVP_PKEY_cmp(pub_key, priv_key);
err:
	if (pub_key) EVP_PKEY_free(pub_key);
	return ret;
}

/*
 * static functions
 */
#if 0
// FIXME: check DSA and EC_KEY 
static int X509_ALGOR_cmp(X509_ALGOR *a, X509_ALGOR *b)
{
	int pkey_type = OBJ_obj2nid(a->algorithm);
	if (pkey_type != EVP_PKEY_DSA || pkey_type != EVP_PKEY_EC)
		return 1;
	if (a->algorithm != b->algorithm)
		return -1;
	return 0;
}
#endif

static DSA *X509_ALGOR_get1_DSA(X509_ALGOR *algor)
{
	DSA *dsa = NULL;
	int ptype;
	void *pval;
	ASN1_OCTET_STRING *pstr;
	const unsigned char *p;	

	X509_ALGOR_get0(NULL, &ptype, &pval, algor);
	if (ptype != V_ASN1_SEQUENCE) {
		CPKerr(CPK_F_X509_ALGOR_GET1_DSA, CPK_R_BAD_DATA);
		return NULL;
	}
	pstr = (ASN1_OCTET_STRING *)pval;
	p = pstr->data;
	if (!(dsa = d2i_DSAparams(NULL, &p, pstr->length))) {
		CPKerr(CPK_F_X509_ALGOR_GET1_DSA, ERR_R_DSA_LIB);
		return NULL;
	}
	return dsa;
}

static int extract_dsa_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *param)
{
	int ret = 0;
	DSA *dsa = NULL;
	BIGNUM *pri = BN_new();
	BIGNUM *pub = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int i, pri_size, pub_size, num_factors;
	const unsigned char *pri_ptr;
	unsigned char *pub_ptr;
	
	if (!pri || !pub || !ctx) {
		goto err;
	}
	
	if (!(dsa = (DSA *)X509_ALGOR_get1_DSA(master->pkey_algor))) {
		goto err;
	}
	pri_size = BN_num_bytes(dsa->q);
	pub_size = BN_num_bytes(dsa->p);
	
	if ((num_factors = CPK_MAP_num_factors(master->map_algor)) <= 0) {
		goto err;
	}
	if (M_ASN1_STRING_length(master->secret_factors) != pri_size * num_factors) {
		goto err;
	}
	
	ASN1_STRING_free(param->public_factors);
	if (!ASN1_STRING_set(param->public_factors, NULL, pub_size * num_factors)) {
		goto err;
	}
	
	pri_ptr = M_ASN1_STRING_data(master->secret_factors);
	pub_ptr = M_ASN1_STRING_data(param->public_factors);
	memset(pub_ptr, 0, M_ASN1_STRING_length(param->public_factors));
	
	for (i = 0; i < num_factors; i++) {
	
		if (!BN_bin2bn(pri_ptr, pri_size, pri)) {
			goto err;
		}
		if (BN_is_zero(pri) || BN_cmp(pri, dsa->q) >= 0) {
			goto err;
		}
		
		if (!BN_mod_exp(pub, dsa->g, pri, dsa->p, ctx)) {
			goto err;
		}
		if (!BN_bn2bin(pub, pub_ptr + pub_size - BN_num_bytes(pub))) {
			goto err;
		}
		
		pri_ptr += pri_size;
		pub_ptr += pub_size;
	}
	
	ret = 1;
err:	
	if (dsa) DSA_free(dsa);
	if (pri) BN_free(pri);
	if (pub) BN_free(pub);
	if (ctx) BN_CTX_free(ctx);
	return ret;
}

static DSA *extract_dsa_priv_key(CPK_MASTER_SECRET *master, const char *id)
{
	int e = 1;
	DSA *dsa = NULL;
	BIGNUM *bn = BN_new();
	BN_CTX *ctx = BN_CTX_new();	
	const unsigned char *p;
	int *index = NULL;
	int i, num_indexes, bn_size;

	
	if (!bn || !ctx) {
		goto err;
	}
	if (!(dsa = X509_ALGOR_get1_DSA(master->pkey_algor))) {
		goto err;
	}
	
	if ((num_indexes = CPK_MAP_num_indexes(master->map_algor)) <= 0) {
		goto err;
	}
	if (!(index = OPENSSL_malloc(sizeof(int) * num_indexes))) {
		goto err;
	}		
	if (!CPK_MAP_str2index(master->map_algor, id, index)) {
		goto err;
	}
	if (!dsa->priv_key) {
		if (!(dsa->priv_key = BN_new())) {
			goto err;
		}
	}
	BN_zero(dsa->priv_key);
	bn_size = BN_num_bytes(dsa->q);
	
	for (i = 0; i < num_indexes; i++) {
		p = M_ASN1_STRING_data(master->secret_factors) + bn_size * index[i];
		if (!BN_bin2bn(p, bn_size, bn)) {
			goto err;
		}
		if (BN_is_zero(bn) || BN_cmp(bn, dsa->q) >= 0) {
			goto err;
		}
		if (!BN_mod_add(dsa->priv_key, dsa->priv_key, bn, dsa->q, ctx)) {
			goto err;
		}
	}
	
	if (!(dsa->pub_key))
		if (!(dsa->pub_key = BN_new())) {
			goto err;
		}
	if (!BN_mod_exp(dsa->pub_key, dsa->g, dsa->priv_key, dsa->p, ctx)) {
		goto err;
	}
	e = 0;
	
err:
	if (e && dsa) {
		DSA_free(dsa);
		dsa = NULL;
	}
	if (bn) BN_free(bn);
	if (ctx) BN_CTX_free(ctx);
	if (index) OPENSSL_free(index);
	return dsa;
}

static DSA *extract_dsa_pub_key(CPK_PUBLIC_PARAMS *param, const char *id)
{
	int e = 1;
	DSA *dsa = NULL;
	BIGNUM *bn = BN_new();
	BN_CTX *ctx = BN_CTX_new();	
	const unsigned char *p;
	int *index = NULL;
	int i, num_indexes, bn_size;

	
	if (!bn || !ctx) {
		goto err;
	}
	if (!(dsa = X509_ALGOR_get1_DSA(param->pkey_algor))) {
		goto err;
	}
	
	if ((num_indexes = CPK_MAP_num_indexes(param->map_algor)) <= 0) {
		goto err;
	}
	if (!(index = OPENSSL_malloc(sizeof(int) * num_indexes))) {
		goto err;
	}		
	if (!CPK_MAP_str2index(param->map_algor, id, index)) {
		goto err;
	}
	if (!dsa->pub_key) {
		if (!(dsa->pub_key = BN_new())) {
			goto err;
		}
	}
	BN_zero(dsa->pub_key);
	bn_size = BN_num_bytes(dsa->p);
	
	for (i = 0; i < num_indexes; i++) {
		p = M_ASN1_STRING_data(param->public_factors) + bn_size * index[i];
		if (!BN_bin2bn(p, bn_size, bn)) {
			goto err;
		}
		if (BN_is_zero(bn) || BN_cmp(bn, dsa->p) >= 0) {
			goto err;
		}
		if (!BN_mod_add(dsa->pub_key, dsa->pub_key, bn, dsa->p, ctx)) {
			goto err;
		}
	}
	e = 0;
	
err:
	if (e && dsa) {
		DSA_free(dsa);
		dsa = NULL;
	}
	if (bn) BN_free(bn);
	if (ctx) BN_CTX_free(ctx);
	if (index) OPENSSL_free(index);
	return dsa;
}

static EC_KEY *X509_ALGOR_get1_EC_KEY(X509_ALGOR *algor)
{
	EC_KEY *ec_key = NULL;
	int ptype;
	void *pval;
	const unsigned char *p;
	
	X509_ALGOR_get0(NULL, &ptype, &pval, algor);
	
	if (ptype == V_ASN1_SEQUENCE) {
		ASN1_OCTET_STRING *pstr = (ASN1_OCTET_STRING *)pval;
		p = pstr->data;
		if (!(ec_key = d2i_ECParameters(NULL, &p, pstr->length))) {
			CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, ERR_R_EC_LIB);
			return NULL;
		}
	
	} else if (ptype == V_ASN1_OBJECT) {
		ASN1_OBJECT *poid = (ASN1_OBJECT *)pval;
		EC_GROUP *group;
		if (!(ec_key = EC_KEY_new())) {	
			CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, ERR_R_MALLOC_FAILURE);
			return NULL;
		}	
		if (!(group = EC_GROUP_new_by_curve_name(OBJ_obj2nid(poid)))) {
			EC_KEY_free(ec_key);
			CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, ERR_R_EC_LIB);
			return NULL;
		}
		EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
		if (!EC_KEY_set_group(ec_key, group)) {
			EC_GROUP_free(group);
			EC_KEY_free(ec_key);
			CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, ERR_R_EC_LIB);
			return NULL;
		}
		EC_GROUP_free(group);
	
	} else {
		CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, CPK_R_BAD_DATA);
		return NULL;
	}
	return ec_key;	
}

static int extract_ec_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *param)
{
	int ret = 0;
	EC_KEY *ec_key = NULL;
	const EC_GROUP *ec_group;
	BIGNUM *bn = BN_new();
	BIGNUM *order = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	EC_POINT *pt = NULL;
	int i, bn_size, pt_size, num_factors;
	const unsigned char *bn_ptr;
	unsigned char *pt_ptr;
	
	if (!bn || !order || !ctx) {
		goto err;
	}
	
	if (!(ec_key = X509_ALGOR_get1_EC_KEY(master->pkey_algor))) {
		goto err;
	}
	ec_group = EC_KEY_get0_group(ec_key);
	if (!(EC_GROUP_get_order(ec_group, order, ctx))) {
		goto err;
	}
	bn_size = BN_num_bytes(order);
	pt_size = bn_size + 1;
	
	if ((num_factors = CPK_MAP_num_factors(master->map_algor)) <= 0) {
		goto err;
	}
	if (M_ASN1_STRING_length(master->secret_factors) != bn_size * num_factors) {
		goto err;
	}
	if (!ASN1_STRING_set(param->public_factors, NULL, pt_size * num_factors)) {
		goto err;
	}
	
	bn_ptr = M_ASN1_STRING_data(master->secret_factors);
	pt_ptr = M_ASN1_STRING_data(param->public_factors);
	memset(pt_ptr, 0, M_ASN1_STRING_length(param->public_factors));
	
	if (!(pt = EC_POINT_new(ec_group))) {
		goto err;			
	}
	for (i = 0; i < num_factors; i++) {
		if (!BN_bin2bn(bn_ptr, bn_size, bn)) {
			goto err;
		}
		if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0) {
			goto err;
		}
		if (!EC_POINT_mul(ec_group, pt, bn, NULL, NULL, ctx)) {
			goto err;
		}
		
		if (!EC_POINT_point2oct(ec_group, pt, 
			POINT_CONVERSION_COMPRESSED, pt_ptr, pt_size, ctx)) {
			goto err;
		}
		bn_ptr += bn_size;
		pt_ptr += pt_size;
	}
	
	ret = 1;
err:	
	if (ec_key) EC_KEY_free(ec_key);
	if (bn) BN_free(bn);
	if (order) BN_free(order);
	if (ctx) BN_CTX_free(ctx);
	if (pt) EC_POINT_free(pt);
	return ret;
}



static EC_KEY *extract_ec_priv_key(CPK_MASTER_SECRET *master, const char *id)
{
	int e = 1;
	EC_KEY *ec_key = NULL;
	const EC_GROUP *ec_group;
	EC_POINT *pub_key = NULL;
	BIGNUM *priv_key = BN_new();
	BIGNUM *order = BN_new();
	BIGNUM *bn = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int *index = NULL;
	int i, num_indexes, bn_size;

	
	if (!priv_key || !bn || !order || !ctx) {
		goto err;
	}
	
	if (!(ec_key = X509_ALGOR_get1_EC_KEY(master->pkey_algor))) {
		goto err;
	}
	ec_group = EC_KEY_get0_group(ec_key);
	if (!(pub_key = EC_POINT_new(ec_group))) {
		goto err;
	}

	if ((num_indexes = CPK_MAP_num_indexes(master->map_algor)) <= 0) {
		goto err;
	}
	if (!(index = OPENSSL_malloc(sizeof(int) * num_indexes))) {
		goto err;
	}		
	if (!CPK_MAP_str2index(master->map_algor, id, index)) {
		goto err;
	}
	
	BN_zero(priv_key);
	if (!(EC_GROUP_get_order(EC_KEY_get0_group(ec_key), order, ctx))) {
		goto err;
	}
	bn_size = BN_num_bytes(order);
	
	for (i = 0; i < num_indexes; i++) {
		const unsigned char *p = 
			M_ASN1_STRING_data(master->secret_factors) + 
			bn_size * index[i];
		
		if (!BN_bin2bn(p, bn_size, bn)) {
			goto err;
		}
		if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0) {
			goto err;
		}		
		if (!BN_mod_add(priv_key, priv_key, bn, order, ctx)) {
			goto err;
		}
	}
	if (!EC_KEY_set_private_key(ec_key, priv_key)) {
		goto err;
	}

	if (!EC_POINT_mul(ec_group, pub_key, priv_key, NULL, NULL, ctx)) {
		goto err;
	}
	if (!EC_KEY_set_public_key(ec_key, pub_key)) {
		goto err;
	}
	e = 0;
	
err:
	if (e && ec_key) {
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	if (priv_key) BN_free(priv_key);
	if (pub_key) EC_POINT_free(pub_key);
	if (order) BN_free(order);
	if (bn) BN_free(bn);
	if (ctx) BN_CTX_free(ctx);
	if (index) OPENSSL_free(index);
	return ec_key;
}

static EC_KEY *extract_ec_pub_key(CPK_PUBLIC_PARAMS *param, const char *id)
{
	int e = 1;
	EC_KEY *ec_key = NULL;
	const EC_GROUP *ec_group;
	EC_POINT *pub_key = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *order = BN_new();
	BIGNUM *bn = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int *index = NULL;
	int i, bn_size, pt_size, num_indexes, num_factors;
	
	if (!(ec_key = X509_ALGOR_get1_EC_KEY(param->pkey_algor))) {
		goto err;		
	}
	ec_group = EC_KEY_get0_group(ec_key);
	
	if (!(pub_key = EC_POINT_new(ec_group))) {
		goto err;
	}
	if (!(pt = EC_POINT_new(ec_group))) {
		goto err;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		goto err;
	}
	bn_size = BN_num_bytes(order);
	pt_size = bn_size + 1;
	if ((num_factors = CPK_MAP_num_factors(param->map_algor)) <= 0) {
		goto err;
	}
	if (M_ASN1_STRING_length(param->public_factors) != pt_size * num_factors) {
		goto err;
	}

	if ((num_indexes = CPK_MAP_num_indexes(param->map_algor)) <= 0) {
		goto err;
	}
	if (!(index = OPENSSL_malloc(sizeof(int) * num_indexes))) {
		goto err;
	}		
	if (!CPK_MAP_str2index(param->map_algor, id, index)) {
		goto err;
	}

	if (!EC_POINT_set_to_infinity(ec_group, pub_key)) {
		goto err;
	}
	for (i = 0; i < num_indexes; i++) {
		const unsigned char *p = 
			M_ASN1_STRING_data(param->public_factors) + 
			pt_size * index[i];		

		if (!EC_POINT_oct2point(ec_group, pt, p, pt_size, ctx)) {
			goto err;
		}
		if (!EC_POINT_add(ec_group, pub_key, pub_key, pt, ctx)) {
			goto err;
		}
	}

	if (!EC_KEY_set_public_key(ec_key, pub_key)) {
		goto err;
	}
	e = 0;
err:
	if (e && ec_key) {
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	if (pub_key) EC_POINT_free(pub_key);
	if (order) BN_free(order);
	if (bn) BN_free(bn);
	if (ctx) BN_CTX_free(ctx);
	if (index) OPENSSL_free(index);
	return ec_key;
}


